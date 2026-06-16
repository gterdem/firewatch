"""Supervisor orchestrator — registration, lifecycle, signal handling, task bookkeeping.

Implements ADR-0023 (Collector Supervisor — Lifecycle & Concurrency Model).
Extends with ADR-0031 §C/§D runtime-control surface (issue #136).
Extends with ADR-0034 action seam: run_action_for / action_status_for (issue #167).

This module owns the ``Supervisor`` class: the single lifecycle object that
registers pull/push instances, manages the asyncio task set (one_for_one
isolation), drives the restart/backoff/park cluster, handles shutdown, and
exposes convenience accessors.  Per-instance coroutines live in ``runners``;
pure decision logic lives in ``policy``.

Public class: Supervisor
"""
from __future__ import annotations

import asyncio
import logging
import signal
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

if TYPE_CHECKING:
    from firewatch_sdk.actions import ActionResult, ActionStatus

from firewatch_sdk import PluginContext
from firewatch_sdk.ports import PushSource, SourcePlugin

from .config import SupervisorConfig
from .models import (
    DLQEntry,
    InstanceRecord,
    InstanceState,
    SupervisorAlert,
    _RECORD_FAILURES_MAX_SIZE,
)
from .policy import (
    build_dlq_alert,
    build_storm_alert,
    compute_backoff_sleep,
    compute_record_key,
    should_park,
    track_record_failure,
)
from .runners import run_pull_instance, run_push_instance
from .status import InstanceStatus

logger = logging.getLogger("firewatch.supervisor")


class Supervisor:
    """Long-running lifecycle owner for all source instances (ADR-0023).

    Usage::

        sup = Supervisor(pipeline, notifier=my_notifier, cfg=SupervisorConfig())
        sup.add_pull(plugin, cfg, source_id="pi-home")
        sup.add_push(plugin, cfg, source_id="syslog-1", transport="udp")
        await sup.run()        # installs signal handlers, blocks until SIGTERM/SIGINT
        # or in tests:
        await sup.startup()    # start all instances (no signal handlers)
        await sup.shutdown()   # bounded-grace stop

    The supervisor is a lifecycle object; it should not be reused after ``shutdown()``.
    """

    def __init__(
        self,
        pipeline: Any,
        *,
        notifier: Any | None = None,
        cfg: SupervisorConfig | None = None,
    ) -> None:
        """Create the supervisor.

        Args:
            pipeline: A Pipeline-like object exposing ``ingest``,
                      ``run_pull_cycle``, and ``store`` (for watermark advance).
                      The supervisor uses only these three surface points.
            notifier: Optional Notifier-like object for alert dispatch. Alerts are
                      always logged regardless; notifier dispatch is best-effort.
            cfg: Supervisor configuration (defaults = ADR-0023 table).
        """
        self._pipeline = pipeline
        self._notifier = notifier
        self._cfg = cfg or SupervisorConfig()

        # Registered instances (order of add_pull / add_push)
        self._instances: list[InstanceRecord] = []

        # DLQ sink: list of dead-lettered entries (M2 in-memory; M6 durable)
        self.dlq: list[DLQEntry] = []

        # Alerts emitted (for testing/observability)
        self.alerts: list[SupervisorAlert] = []

        # Shutdown coordination
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._running: bool = False

        # NB-2: single-flight guard for run_action_for.
        # A frozenset (type_key, source_id, action_id) triple that is currently
        # executing.  A concurrent call for the same triple raises RuntimeError
        # so the caller can surface HTTP 409 without the plugin running twice.
        self._actions_in_flight: set[tuple[str, str, str]] = set()

        # Public stop-condition seam (ADR-0023 §D.1).
        # Set when EITHER shutdown() is called OR the all-parked predicate fires.
        # Distinct from _shutdown_event (which signals teardown completion).
        self._stopped_event: asyncio.Event = asyncio.Event()

        # Strong task references (asyncio keeps only weak refs internally).
        self._tasks: set[asyncio.Task[None]] = set()

    # ------------------------------------------------------------------ #
    # Registration API                                                     #
    # ------------------------------------------------------------------ #

    def add_pull(
        self,
        plugin: SourcePlugin,
        cfg: BaseModel,
        *,
        source_id: str,
        interval: float = 60.0,
    ) -> InstanceRecord:
        """Register a PullSource instance to be supervised.

        Args:
            plugin: The source plugin instance (must satisfy PullSource protocol).
            cfg: The validated plugin config.
            source_id: The user-assigned instance name (ADR-0016).
            interval: Pull interval in seconds (default 60s, config-overridable).

        Returns:
            The InstanceRecord for inspection/testing.
        """
        rec = InstanceRecord(
            source_id=source_id,
            plugin=plugin,
            cfg=cfg,
            last_known_good_cfg=cfg,
            flavor="pull",
            transport="file",  # pull is file/TCP-like; BLOCK is the right backpressure
            _pull_interval=interval,
        )
        self._instances.append(rec)
        return rec

    def add_push(
        self,
        plugin: SourcePlugin,
        cfg: BaseModel,
        *,
        source_id: str,
        transport: str = "tcp",
    ) -> InstanceRecord:
        """Register a PushSource instance to be supervised.

        Args:
            plugin: The source plugin instance (must satisfy PushSource protocol).
            cfg: The validated plugin config.
            source_id: The user-assigned instance name (ADR-0016).
            transport: Transport type ("udp" | "tcp" | "file") for backpressure policy.

        Returns:
            The InstanceRecord for inspection/testing.
        """
        rec = InstanceRecord(
            source_id=source_id,
            plugin=plugin,
            cfg=cfg,
            last_known_good_cfg=cfg,
            flavor="push",
            transport=transport,
        )
        self._instances.append(rec)
        return rec

    # ------------------------------------------------------------------ #
    # Runtime-control surface (ADR-0031 §D / issue #136)                  #
    # ------------------------------------------------------------------ #

    def register_idle(
        self,
        plugin: SourcePlugin,
        cfg: BaseModel,
        *,
        source_id: str,
        flavor: str,
        interval: float = 60.0,
        transport: str = "tcp",
    ) -> InstanceRecord:
        """Register a source instance in IDLE state (configured, not scheduled).

        ADR-0031 §C/§D: an IDLE instance exists in the supervisor so manual
        ``run_pull_cycle_for`` works without auto-sync being enabled.

        Idempotent per ``(type_key, source_id)``: if the instance already exists
        (regardless of state), the existing record is returned unchanged.

        Args:
            plugin:    The source plugin instance.
            cfg:       The validated plugin config.
            source_id: The user-assigned instance name (ADR-0016).
            flavor:    ``"pull"`` or ``"push"``.
            interval:  Pull interval in seconds (pull flavor only; default 60 s).
            transport: Transport type for push instances (``"udp"`` | ``"tcp"`` | ``"file"``).

        Returns:
            The InstanceRecord (new or pre-existing).
        """
        type_key = plugin.metadata().type_key
        existing = self.get_instance(type_key, source_id)
        if existing is not None:
            return existing

        rec = InstanceRecord(
            source_id=source_id,
            plugin=plugin,
            cfg=cfg,
            last_known_good_cfg=cfg,
            flavor=flavor,
            transport=transport,
            state=InstanceState.IDLE,
            _pull_interval=interval,
        )
        self._instances.append(rec)
        logger.debug(
            "supervisor.register_idle source=%s/%s flavor=%s interval=%.1f",
            type_key, source_id, flavor, interval,
        )
        return rec

    def enable_pull(
        self,
        source_type: str,
        source_id: str,
        *,
        interval: float,
    ) -> None:
        """Transition an IDLE pull instance to RUNNING and begin scheduling.

        ADR-0031 §D: idle→running; sets ``_pull_interval``, then ``_launch``.
        Idempotent: calling on an already-RUNNING instance is a no-op.

        Raises ``KeyError`` when ``(source_type, source_id)`` is not registered.
        Raises ``ValueError`` when the instance is a push flavor (no auto-sync).

        Args:
            source_type: Plugin ``type_key`` (e.g. ``"suricata"``).
            source_id:   Instance name (e.g. ``"pi-home"``).
            interval:    Pull interval in seconds (applied live).
        """
        rec = self.get_instance(source_type, source_id)
        if rec is None:
            raise KeyError(f"instance not found: {source_type}/{source_id}")
        if rec.flavor != "pull":
            raise ValueError(
                f"enable_pull called on push instance {source_type}/{source_id}; "
                "push sources have no auto-sync interval."
            )
        if rec.state == InstanceState.RUNNING:
            return  # idempotent
        rec._pull_interval = interval
        self._launch(rec)
        logger.info(
            "supervisor.enable_pull source=%s/%s interval=%.1fs",
            source_type, source_id, interval,
        )

    async def disable(self, source_type: str, source_id: str) -> None:
        """Cancel the instance's task and return it to IDLE state.

        ADR-0031 §D: graceful cancel per ADR-0023 §E cancellation semantics.
        The instance stays registered so manual Sync still works.

        Raises ``KeyError`` when ``(source_type, source_id)`` is not registered.

        Args:
            source_type: Plugin ``type_key``.
            source_id:   Instance name.
        """
        rec = self.get_instance(source_type, source_id)
        if rec is None:
            raise KeyError(f"instance not found: {source_type}/{source_id}")

        task = rec.task
        if task is not None and not task.done():
            # Set IDLE before cancelling so that when _on_task_done fires (during the
            # await below) it sees IDLE and _maybe_signal_stopped does not incorrectly
            # treat this as "all-parked terminal" (ADR-0031 §C).
            rec.state = InstanceState.IDLE
            task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=self._cfg.shutdown_grace)
            except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                pass

        rec.state = InstanceState.IDLE
        rec.task = None
        logger.info(
            "supervisor.disable source=%s/%s — returned to idle",
            source_type, source_id,
        )

    def set_interval(
        self,
        source_type: str,
        source_id: str,
        interval: float,
    ) -> None:
        """Change a running pull instance's interval live (no task restart).

        ADR-0031 §D: mutates ``rec._pull_interval``; the runner loop reads the
        interval at the top of each sleep so the change applies on the next cycle
        without cancelling the in-flight pull.

        Raises ``KeyError`` when ``(source_type, source_id)`` is not registered.

        Args:
            source_type: Plugin ``type_key``.
            source_id:   Instance name.
            interval:    New pull interval in seconds.
        """
        rec = self.get_instance(source_type, source_id)
        if rec is None:
            raise KeyError(f"instance not found: {source_type}/{source_id}")
        rec._pull_interval = interval
        logger.info(
            "supervisor.set_interval source=%s/%s interval=%.1fs",
            source_type, source_id, interval,
        )

    def reload_config(self, rec: InstanceRecord, new_cfg: BaseModel) -> bool:
        """Attempt to update a running instance's config (last-known-good seam).

        ADR-0023 §Steals (OpAMP last-known-good): the new config is validated by
        calling ``plugin.validate_config``; if it passes, ``rec.cfg`` and
        ``rec.last_known_good_cfg`` are both updated.  If validation fails, the
        supervisor logs a warning and the instance continues with its last good config.

        Returns True if the config was accepted, False if it was rejected (fallback).
        """
        try:
            rec.plugin.validate_config(new_cfg.model_dump())
            rec.cfg = new_cfg
            rec.last_known_good_cfg = new_cfg
            logger.info(
                "supervisor.reload_config source=%s/%s — accepted",
                rec.plugin.metadata().type_key, rec.source_id,
            )
            return True
        except Exception as exc:
            logger.warning(
                "supervisor.reload_config source=%s/%s — rejected (bad config: %s); "
                "continuing with last-known-good",
                rec.plugin.metadata().type_key, rec.source_id, exc,
            )
            rec.cfg = rec.last_known_good_cfg
            return False

    # ------------------------------------------------------------------ #
    # Public stop-condition seam (ADR-0023 §D.1)                         #
    # ------------------------------------------------------------------ #

    async def wait_until_stopped(self) -> None:
        """Block until the supervisor has stopped making forward progress.

        Resolves on EITHER:
        1. ``shutdown()`` has been initiated (explicit call or captured signal), OR
        2. ``≥1 instance was ever registered`` AND ``no instance is in RUNNING or
           BACKOFF`` (i.e. every instance is PARKED or STOPPED — the all-parked
           terminal condition).

        The zero-instance exception: a supervisor with **no** registered instances
        never resolves on condition (2); it serves indefinitely until ``shutdown()``.

        This is the ONLY supported way for a host to learn the supervisor has
        stopped.  Hosts MUST NOT reach into supervisor internals.  Level-triggered
        and idempotent: a second ``await wait_until_stopped()`` returns immediately.
        Does NOT perform teardown — that is the host's responsibility (ADR-0023 §F).
        """
        await self._stopped_event.wait()

    @property
    def is_stopped(self) -> bool:
        """Return True if the supervisor has stopped making forward progress."""
        return self._stopped_event.is_set()

    def _maybe_signal_stopped(self) -> None:
        """Re-evaluate the §D.1 stop predicate; set _stopped_event on first match.

        Called at every terminal-transition site (park, stop-on-shutdown,
        normal-completion) to detect the all-parked / all-stopped condition.

        ADR-0031 §C: IDLE is treated like PARKED/STOPPED for this predicate —
        it is not a progress-capable state.  However, the zero-instance exception
        and the "API-host sibling" exception both apply: an all-idle supervisor
        that hosts an API is the zero-forward-progress-but-serving case, which
        must NOT stop (it keeps serving).  This predicate fires only when every
        instance that was ever RUNNING or BACKOFF has crashed/parked, NOT when all
        instances were registered idle from the start (those were never in progress).

        Implementation: progress-capable = RUNNING | BACKOFF.  The predicate
        checks whether any instance *was ever* in a progress-capable state and is
        now past it.  For simplicity we track this via ``rec.total_crashes > 0 or
        rec.attempt > 0`` as a "was ever launched" proxy, OR by examining whether
        the current run of startup() launched any non-idle instances.

        Simpler equivalent (correct): only set the stopped event when at least one
        instance has a task history (was launched) AND none are now progress-capable.
        IDLE instances that were *never* launched do not count as "progress lost."

        Zero-instance exception: if no instances were ever registered, the predicate
        never fires.

        Idempotent: once set, subsequent calls are no-ops (guard at top).
        """
        if self._stopped_event.is_set():
            return
        if not self._instances:  # zero-instance exception (§D.1)
            return
        if any(
            r.state in (InstanceState.RUNNING, InstanceState.BACKOFF)
            for r in self._instances
        ):
            return
        # ADR-0031 §C / ADR-0023 §D.1 zero-forward-progress-but-serving exception:
        # if every registered instance is IDLE (was never launched as RUNNING), do NOT
        # fire — the process is legitimately serving the API with no auto-sync enabled.
        # Only fire when at least one instance was ever launched (has crash/attempt
        # history or was successfully running before parking/stopping).
        if all(r.state == InstanceState.IDLE for r in self._instances):
            return
        logger.error(
            "supervisor.stopping all %d instance(s) parked/stopped/idle; "
            "no forward progress possible — signalling run loop to shut down",
            len(self._instances),
        )
        self._stopped_event.set()

    # ------------------------------------------------------------------ #
    # Lifecycle                                                            #
    # ------------------------------------------------------------------ #

    async def run(self) -> None:
        """Start all instances and block until SIGTERM/SIGINT.

        Installs signal handlers; calls ``shutdown()`` on signal reception.
        For programmatic control (e.g. tests) prefer ``startup()`` + ``shutdown()``.
        """
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))

        await self.startup()
        await self._shutdown_event.wait()

    async def startup(self) -> None:
        """Start all registered instances (no signal handlers).

        Each instance gets its own asyncio.Task (one_for_one, ADR-0023 §A).

        ADR-0031 §C: IDLE instances are NOT launched here — they stay idle until
        ``enable_pull`` is called.  Only STOPPED instances (registered via
        ``add_pull``/``add_push`` before startup) are launched.

        Issue #707: before launching, restore any persisted last-sync stamps from
        the durable KV store into IDLE/STOPPED InstanceRecords so status() never
        returns ``last_sync_at=None`` for a source that has already ingested.
        """
        self._running = True
        await self._restore_sync_stamps()
        for rec in self._instances:
            if rec.state == InstanceState.STOPPED:
                self._launch(rec)
        logger.info(
            "supervisor.startup instances=%d pull=%d push=%d idle=%d",
            len(self._instances),
            sum(1 for r in self._instances if r.flavor == "pull"),
            sum(1 for r in self._instances if r.flavor == "push"),
            sum(1 for r in self._instances if r.state == InstanceState.IDLE),
        )

    async def shutdown(self) -> None:
        """Bounded-grace graceful shutdown (ADR-0023 §E / 12-Factor IX).

        Steps (per ADR-0023 §E):
        1. Stop accepting new work — set self._running = False.
        2. Call stop() on every PushSource listener (cooperative).
        3. Cancel all in-flight pull tasks (cooperative CancelledError).
        4. Wait up to shutdown_grace for tasks to finish.
        5. Force-cancel whatever remains at the hard deadline.
        """
        if self._shutdown_event.is_set():
            return  # idempotent

        # Signal the run loop (§D.1 / §F): teardown has begun, stop waiting.
        # Set BEFORE cancelling tasks so a wait_until_stopped() waiter releases
        # promptly.  _shutdown_event is set at the END (teardown-complete signal).
        self._stopped_event.set()

        logger.info("supervisor.shutdown grace=%.1fs", self._cfg.shutdown_grace)
        self._running = False

        # Step 2: stop push listeners — only call stop() when the plugin is actually
        # running (NB-7: calling stop() on a BACKOFF instance may call it on a plugin
        # that was never started, which violates the PushSource contract).
        for rec in self._instances:
            if rec.flavor == "push" and rec.state == InstanceState.RUNNING:
                try:
                    push_plugin: PushSource = rec.plugin  # type: ignore[assignment]
                    await push_plugin.stop()
                except Exception:
                    logger.warning(
                        "supervisor.shutdown stop() failed for %s/%s",
                        rec.plugin.metadata().type_key, rec.source_id,
                        exc_info=True,
                    )

        # Step 3: cancel all tasks
        for task in list(self._tasks):
            if not task.done():
                task.cancel()

        # Step 4: wait up to grace period
        if self._tasks:
            try:
                await asyncio.wait(self._tasks, timeout=self._cfg.shutdown_grace)
            except Exception:
                pass

        # Step 5: force-cancel whatever remains
        for task in list(self._tasks):
            if not task.done():
                logger.warning(
                    "supervisor.shutdown force-cancelling task=%s after grace period",
                    task.get_name(),
                )
                task.cancel()

        # Mark all non-idle instances stopped (IDLE instances have no task and their
        # state is preserved — they were never running and can be re-enabled later).
        for rec in self._instances:
            if rec.state != InstanceState.IDLE:
                rec.state = InstanceState.STOPPED
            rec.task = None

        self._tasks.clear()
        self._shutdown_event.set()
        logger.info("supervisor.shutdown complete")

    # ------------------------------------------------------------------ #
    # Internal — startup stamp restore (issue #707)                       #
    # ------------------------------------------------------------------ #

    async def _restore_sync_stamps(self) -> None:
        """Restore persisted last-sync stamps into InstanceRecords on startup.

        Called once from ``startup()`` before any task is launched.  For each
        registered pull instance whose ``last_sync_at`` is currently ``None``
        (fresh process), attempts to read the durable KV stamp written by a
        prior run and populates the InstanceRecord fields so ``status()``
        never returns ``last_sync_at=None`` for a source with stored events.

        Fail-safe (ADR-0003): any per-instance restore error is caught and
        logged at WARNING; other instances are always attempted.  A failing
        restore means the instance shows "Last sync: Never" until its next
        cycle — not a correctness failure.
        """
        from firewatch_core.sync_state import restore_sync_state

        store = getattr(self._pipeline, "store", None)
        if store is None:
            return

        for rec in self._instances:
            if rec.last_sync_at is not None:
                continue  # already stamped (e.g. supervisor was never restarted)
            source_type = rec.plugin.metadata().type_key
            try:
                saved = await restore_sync_state(store, source_type, rec.source_id)
                if saved is None:
                    continue
                rec.last_sync_at = saved["last_sync_at"]
                rec.last_sync_ingested = saved["last_sync_ingested"]
                rec.last_sync_status = saved["last_sync_status"]
                rec.last_error = saved["last_error"]
                logger.debug(
                    "supervisor.restore_sync source=%s/%s last_sync_at=%.0f status=%s",
                    source_type, rec.source_id,
                    rec.last_sync_at, rec.last_sync_status,
                )
            except Exception:
                logger.warning(
                    "supervisor.restore_sync: failed for %s/%s — "
                    "showing 'Last sync: Never' until next cycle",
                    source_type, rec.source_id,
                    exc_info=True,
                )

    # ------------------------------------------------------------------ #
    # Internal — task launching                                            #
    # ------------------------------------------------------------------ #

    def _launch(self, rec: InstanceRecord) -> None:
        """Create and register an asyncio.Task for the given instance record.

        The task holds a strong reference in self._tasks (ADR-0023 §A: asyncio keeps
        only weak refs; un-referenced tasks can be GC'd mid-flight).
        """
        if rec.flavor == "pull":
            coro = run_pull_instance(
                rec,
                self._pipeline,
                self._cfg,
                lambda: self._running,
                self._handle_poison_record,
            )
        else:
            coro = run_push_instance(
                rec,
                self._pipeline,
                self._cfg,
                self._park_instance,
                self._tasks.add,
                self._make_discard_callback,
            )

        source_type = rec.plugin.metadata().type_key
        task = asyncio.create_task(
            coro,
            name=f"supervisor-{rec.flavor}-{source_type}/{rec.source_id}",
        )
        rec.task = task
        self._tasks.add(task)
        task.add_done_callback(self._on_task_done)
        rec.state = InstanceState.RUNNING
        logger.debug(
            "supervisor._launch source=%s/%s flavor=%s",
            source_type, rec.source_id, rec.flavor,
        )

    def _on_task_done(self, task: asyncio.Task[None]) -> None:
        """Callback fired when any instance task finishes (success, crash, cancel).

        Implements one_for_one restart logic (ADR-0023 §A + §C/D-revised).
        """
        self._tasks.discard(task)

        # Find which instance this task belongs to
        rec = next((r for r in self._instances if r.task is task), None)
        if rec is None:
            return  # already cleaned up or a backoff/alert task

        if task.cancelled():
            # Cancellation is expected during shutdown or disable() — do not restart.
            # ADR-0031 §C: if disable() already transitioned the instance to IDLE,
            # preserve IDLE (don't stomp to STOPPED); disable() controls the final state.
            if rec.state != InstanceState.IDLE:
                rec.state = InstanceState.STOPPED
            rec.task = None
            self._maybe_signal_stopped()
            return

        exc = task.exception()
        if exc is None:
            # Normal completion (e.g. pull finished its loop on shutdown or
            # a pull runner whose loop ended without needing a restart).
            rec.state = InstanceState.STOPPED
            rec.task = None
            self._maybe_signal_stopped()
            return

        # Exception path — a crash.
        source_type = rec.plugin.metadata().type_key
        logger.warning(
            "supervisor: instance %s/%s crashed (attempt=%d): %s: %s",
            source_type, rec.source_id, rec.attempt,
            type(exc).__name__, exc,
        )

        now = time.monotonic()
        rec.record_crash(now)
        rec.state = InstanceState.BACKOFF
        rec.task = None

        if not self._running:
            # Supervisor is shutting down; do not restart.
            rec.state = InstanceState.STOPPED
            self._maybe_signal_stopped()
            return

        # Storm-cap check (ADR-0023 §D-revised / OTP max-restart-intensity)
        park, crashes_in_window = should_park(rec, self._cfg, now)
        if park:
            self._park_instance(rec, crashes_in_window)
            return

        # Schedule backoff-then-restart as a new task in the strong-reference set.
        # The task is NOT in self._instances (it's a transient backoff task), so
        # _on_task_done won't interpret its completion as an instance crash.
        backoff_task = asyncio.create_task(
            self._backoff_and_restart(rec),
            name=f"supervisor-backoff-{source_type}/{rec.source_id}",
        )
        self._tasks.add(backoff_task)
        backoff_task.add_done_callback(self._make_discard_callback(backoff_task))

    def _park_instance(self, rec: InstanceRecord, crashes_in_window: int) -> None:
        """Park an instance (ADR-0023 §D-revised / OTP max-restart-intensity).

        Stops auto-restarting, emits an alert, marks state=PARKED.
        Operator/config action is required to resume (M2 scope).

        Args:
            rec: The instance record to park.
            crashes_in_window: The actual windowed crash count that triggered the
                park.  NB-F: callers pass the value from ``crashes_in_window()``
                so the log and alert detail reflect the windowed count, not the
                unbounded lifetime total.
        """
        source_type = rec.plugin.metadata().type_key
        rec.state = InstanceState.PARKED
        rec.task = None
        logger.error(
            "supervisor.park source=%s/%s crashes_in_window=%d — PARKED; "
            "operator action required to resume",
            source_type, rec.source_id, crashes_in_window,
        )
        alert = build_storm_alert(source_type, rec.source_id, crashes_in_window, self._cfg)
        alert_task = asyncio.create_task(
            self._emit_alert(alert),
            name=f"supervisor-alert-park-{source_type}/{rec.source_id}",
        )
        self._tasks.add(alert_task)
        alert_task.add_done_callback(self._make_discard_callback(alert_task))
        # §D.1: re-evaluate the all-parked stop predicate on every park transition.
        self._maybe_signal_stopped()

    def _resume_parked(self, rec: InstanceRecord) -> None:
        """Resume a storm-parked instance after a successful manual Sync.

        ADR-0023 §D resume path (Maintainer's walkthrough decision, 2026-06-11): a
        successful ``run_pull_cycle_for`` clears the storm-park and relaunches the
        supervised pull loop so auto-sync resumes.  Resets the crash window and
        backoff attempt so the resumed instance starts clean — otherwise the stale
        pre-park crash timestamps could immediately re-trip the storm cap.

        Only pull instances that were auto-sync RUNNING can park (an IDLE instance
        has no loop to crash-storm), so resume always returns to the RUNNING loop
        via ``_launch``.  No-op when the supervisor is shutting down.

        Args:
            rec: The parked instance record to resume.
        """
        if not self._running:
            return
        source_type = rec.plugin.metadata().type_key
        rec.crash_timestamps.clear()
        rec.attempt = 0
        self._launch(rec)
        logger.info(
            "supervisor.resume source=%s/%s — storm-park cleared by successful "
            "manual sync; auto-sync loop relaunched",
            source_type, rec.source_id,
        )

    def _make_discard_callback(
        self, task: asyncio.Task[None]
    ) -> Callable[[asyncio.Task[None]], None]:
        """Return a done-callback that discards the task from _tasks and logs unexpected errors.

        NB-6: the plain ``self._tasks.discard`` callback silently swallows unexpected
        exceptions (e.g. a bug in _backoff_and_restart), which can strand an instance in
        BACKOFF forever.  This wrapper checks task.exception() and logs it so bugs are
        visible.
        """
        def _callback(t: asyncio.Task[None]) -> None:
            self._tasks.discard(t)
            if not t.cancelled():
                exc = t.exception()
                if exc is not None:
                    logger.error(
                        "supervisor: unexpected exception in transient task %s: %s: %s",
                        t.get_name(), type(exc).__name__, exc,
                        exc_info=False,
                    )

        return _callback

    async def _backoff_and_restart(self, rec: InstanceRecord) -> None:
        """Sleep for the full-jitter backoff period, then restart the instance.

        ADR-0023 §C — Full Jitter formula (AWS "Exponential Backoff And Jitter"):
            sleep = random.uniform(0, min(backoff_cap, backoff_base * 2**attempt))
        Attempt counter is NOT reset here; it resets on a successful cycle.
        """
        if not self._running:
            return

        source_type = rec.plugin.metadata().type_key
        attempt = rec.attempt
        sleep_s = compute_backoff_sleep(self._cfg, attempt)

        logger.info(
            "supervisor.backoff source=%s/%s attempt=%d sleep=%.2fs",
            source_type, rec.source_id, attempt, sleep_s,
        )

        try:
            await asyncio.sleep(sleep_s)
        except asyncio.CancelledError:
            # B2: must re-raise to honour the asyncio cancellation contract; set state first.
            rec.state = InstanceState.STOPPED
            raise

        if not self._running or rec.state == InstanceState.PARKED:
            rec.state = InstanceState.STOPPED
            return

        # Increment attempt before relaunch (reset happens on success in runner)
        rec.attempt += 1
        self._launch(rec)

    # ------------------------------------------------------------------ #
    # Internal — DLQ path                                                  #
    # ------------------------------------------------------------------ #

    async def _handle_poison_record(
        self, rec: InstanceRecord, raw: Any
    ) -> None:
        """Track failure count for a raw record; dead-letter after dlq_threshold.

        ADR-0023 §D-revised: if the same record fails dlq_threshold times, route it
        to the DLQ, advance the watermark past it, and emit an alert.

        record_key uses received_at + data content hash for stable identity across
        retries.
        """
        key = compute_record_key(raw)
        source_type = rec.plugin.metadata().type_key

        # NB-5: log eviction when record_failures is at capacity before tracking.
        if key not in rec.record_failures and len(rec.record_failures) >= _RECORD_FAILURES_MAX_SIZE:
            logger.warning(
                "supervisor.dlq_evict source=%s/%s evicted oldest near-miss record "
                "(record_failures at cap=%d)",
                source_type, rec.source_id, _RECORD_FAILURES_MAX_SIZE,
            )

        count, do_dlq = track_record_failure(
            rec, key, self._cfg.dlq_threshold, _RECORD_FAILURES_MAX_SIZE
        )

        logger.warning(
            "supervisor.dlq_track source=%s/%s record=%s fail_count=%d threshold=%d",
            source_type, rec.source_id, key, count, self._cfg.dlq_threshold,
        )

        if do_dlq:
            entry = DLQEntry(
                raw=raw,
                source_type=source_type,
                source_id=rec.source_id,
                failure_count=count,
            )
            self.dlq.append(entry)
            rec.total_dlq += 1
            del rec.record_failures[key]

            # Advance the watermark past this record so the stream is unblocked
            # (ADR-0023 §D-revised: "advance the watermark past it")
            try:
                await self._pipeline.store.set_watermark(
                    raw.received_at.isoformat(),
                    source_type,
                    rec.source_id,
                )
            except Exception:
                logger.error(
                    "supervisor.dlq watermark advance failed for %s/%s",
                    source_type, rec.source_id, exc_info=True,
                )

            logger.error(
                "supervisor.dlq source=%s/%s record=%s dead-lettered "
                "(fail_count=%d); watermark advanced",
                source_type, rec.source_id, key, count,
            )

            watermark_ts = raw.received_at.isoformat()
            alert = build_dlq_alert(
                source_type, rec.source_id, count, watermark_ts, self._cfg
            )
            await self._emit_alert(alert)

    # ------------------------------------------------------------------ #
    # Internal — alert dispatch                                            #
    # ------------------------------------------------------------------ #

    async def _emit_alert(self, alert: SupervisorAlert) -> None:
        """Log the alert (always) and attempt notifier dispatch (best-effort).

        ADR-0023 §D-revised: "neither is ever silent" — both storm-park and DLQ
        alerts are logged at ERROR level regardless of notifier availability.
        """
        self.alerts.append(alert)
        logger.error(
            "supervisor.alert kind=%s source=%s/%s detail=%s",
            alert.kind, alert.source_type, alert.source_id, alert.detail,
        )
        if self._notifier is not None:
            try:
                if hasattr(self._notifier, "send_supervisor_alert"):
                    await self._notifier.send_supervisor_alert(alert)
            except Exception:
                logger.warning(
                    "supervisor._emit_alert notifier dispatch failed", exc_info=True
                )

    # ------------------------------------------------------------------ #
    # Convenience accessors                                                #
    # ------------------------------------------------------------------ #

    def get_instance(self, source_type: str, source_id: str) -> InstanceRecord | None:
        """Return the InstanceRecord for (source_type, source_id), or None."""
        for rec in self._instances:
            if rec.plugin.metadata().type_key == source_type and rec.source_id == source_id:
                return rec
        return None

    def parked_instances(self) -> list[InstanceRecord]:
        """Return all parked instances."""
        return [r for r in self._instances if r.state == InstanceState.PARKED]

    def running_instances(self) -> list[InstanceRecord]:
        """Return all instances in RUNNING state."""
        return [r for r in self._instances if r.state == InstanceState.RUNNING]

    async def run_pull_cycle_for(self, source_type: str, source_id: str) -> int:
        """Run one idempotent pull cycle for a specific instance (MB.4, issue #56).

        Called by the ``POST /sync/{type_key}`` route to trigger an on-demand
        pull without scheduling a periodic tick.  The watermark semantics ensure
        the cycle is idempotent: a concurrent second call will read from the same
        watermark and produce no duplicate events (at-most-once from the pipeline's
        perspective, at-least-once with dedup in the store — ADR-0023 Consequences).

        ADR-0031 §F: records last-sync outcome (last_sync_at, last_sync_ingested,
        last_sync_status, last_error) on the instance record after the cycle.

        Returns the number of net-new rows inserted this cycle (post-dedup count
        from ``store.save_many``).  The API route includes this value in its
        response body as ``events_ingested``.

        Raises ``KeyError`` when the ``(source_type, source_id)`` pair is not
        registered — the API route must translate this to a 404.

        Args:
            source_type: The plugin's ``type_key`` (e.g. ``"suricata"``).
            source_id:   The user-assigned instance name (e.g. ``"pi-home"``).
        """
        rec = self.get_instance(source_type, source_id)
        if rec is None:
            raise KeyError(f"instance not found: {source_type}/{source_id}")
        # Mint ctx per ADR-0027 §3: source_type from the plugin constant, never the
        # path-param argument (capability isolation, ADR-0025 addendum).  Mirror the
        # exact pattern used in runners.py so the two minting sites are consistent.
        from firewatch_core.scoped_kv import scoped_kv
        type_key = rec.plugin.metadata().type_key
        kv = scoped_kv(self._pipeline.store, type_key)
        ctx = PluginContext(kv=kv, source_id=rec.source_id)

        try:
            # pipeline.run_pull_cycle returns the net-new rows inserted (post-dedup)
            # from store.save_many — the real count, not a test-only attribute.
            cycle_ingested: int = await self._pipeline.run_pull_cycle(
                rec.plugin, rec.cfg, rec.source_id, ctx
            )
        except Exception as exc:
            rec.last_sync_at = time.time()
            rec.last_sync_status = "error"
            # NB-6: store a bounded, typed error string so internal paths/secrets
            # cannot leak into the /sources diagnostics endpoint.  The format
            # "ExcType: message[:200]" matches the pattern used in runners.py.
            rec.last_error = f"{type(exc).__name__}: {str(exc)[:200]}"
            rec.last_sync_ingested = 0
            raise
        rec.last_sync_at = time.time()
        rec.last_sync_ingested = cycle_ingested
        rec.last_sync_status = "ok" if cycle_ingested > 0 else "no_data"
        rec.last_error = None

        # A successful manual Sync resumes a storm-parked instance (ADR-0023 §D
        # resume; Maintainer's walkthrough decision 2026-06-11). Only auto-sync RUNNING
        # pull instances can storm and park, so resume relaunches the supervised
        # loop. A FAILED cycle takes the ``except`` branch above and leaves the park
        # intact — a genuinely bad config correctly stays/re-parks.
        if rec.state == InstanceState.PARKED:
            self._resume_parked(rec)

        return cycle_ingested

    # ------------------------------------------------------------------ #
    # Action seam (ADR-0034 / issue #167)                                  #
    # ------------------------------------------------------------------ #

    async def run_action_for(
        self,
        source_type: str,
        source_id: str,
        action_id: str,
    ) -> "ActionResult":
        """Run a plugin-declared maintenance action for a specific instance.

        Mirrors ``run_pull_cycle_for`` (ADR-0031) in structure:
        - Validates ``(source_type, source_id)`` via ``get_instance`` — raises
          ``KeyError`` on unknown instance (route translates to 404).
        - Validates ``action_id`` against ``metadata().actions`` — raises
          ``ValueError`` on undeclared action (route translates to 404).
        - Mints ``PluginContext`` per ADR-0027 §3 (supervisor is the single
          minter; ``source_type`` taken from ``metadata().type_key``, never
          from path-param input — capability isolation, ADR-0025 addendum).
        - Calls ``plugin.run_action(action_id, cfg, ctx)`` — execution policy
          lives entirely in the plugin (ADR-0034).
        - On success, runs the post-action KV promotion (same call the pull
          pipeline executes after each cycle) so action products are visible
          without a separate collect cycle.

        Args:
            source_type: Plugin ``type_key`` (e.g. ``"suricata"``).
            source_id:   Instance name (e.g. ``"pi-home"``).
            action_id:   The action to run (must be declared in ``metadata().actions``).

        Returns:
            ``ActionResult`` from the plugin.

        Raises:
            KeyError:   Instance not found — caller maps to 404.
            ValueError: ``action_id`` not declared — caller maps to 404.
        """
        from firewatch_core.scoped_kv import scoped_kv
        from firewatch_sdk.actions import ActionCapable, ActionResult

        rec = self.get_instance(source_type, source_id)
        if rec is None:
            raise KeyError(f"instance not found: {source_type}/{source_id}")

        # Validate action_id against the declared set — never reach plugin code
        # with an undeclared id (ADR-0034 §security / EARS unwanted criterion).
        type_key = rec.plugin.metadata().type_key
        declared_ids = {a.id for a in rec.plugin.metadata().actions}
        if action_id not in declared_ids:
            raise ValueError(
                f"action {action_id!r} not declared by plugin {type_key!r}; "
                f"declared: {sorted(declared_ids)}"
            )

        # NB-2: single-flight guard — reject concurrent calls for the same triple.
        # Raised BEFORE acquiring the slot so the caller never reaches plugin code.
        flight_key = (type_key, rec.source_id, action_id)
        if flight_key in self._actions_in_flight:
            raise RuntimeError("in_progress")
        self._actions_in_flight.add(flight_key)

        try:
            # Mint ctx per ADR-0027 §3: source_type from the plugin constant, never
            # the path-param argument (capability isolation, ADR-0025 addendum).
            kv = scoped_kv(self._pipeline.store, type_key)
            ctx = PluginContext(kv=kv, source_id=rec.source_id)

            # Plugin must satisfy ActionCapable — checked by the loader at serve time
            # (EARS state-driven), but we guard here too for belt-and-suspenders.
            if not isinstance(rec.plugin, ActionCapable):
                return ActionResult(
                    ok=False,
                    message=(
                        f"Plugin {type_key!r} declares actions but does not satisfy "
                        "ActionCapable protocol — cannot run action."
                    ),
                )

            # NB-1: wrap plugin.run_action in try/except — an unexpected exception
            # must NOT propagate as a 500; return a sanitised ActionResult instead.
            try:
                result: ActionResult = await rec.plugin.run_action(action_id, rec.cfg, ctx)
            except Exception:
                logger.error(
                    "supervisor.run_action source=%s/%s action=%s raised an unexpected "
                    "exception — returning ok=False",
                    type_key, rec.source_id, action_id,
                    exc_info=True,
                )
                return ActionResult(
                    ok=False,
                    message="Action raised an unexpected exception — see server logs.",
                )

            # Post-action KV promotion — same as pipeline._promote_rule_descriptions.
            # Runs only on success to avoid promoting stale data on a failed action.
            if result.ok:
                await self._pipeline._promote_rule_descriptions(type_key)

            logger.info(
                "supervisor.run_action source=%s/%s action=%s ok=%s",
                type_key, rec.source_id, action_id, result.ok,
            )
            return result
        finally:
            # NB-2: always release the slot — even on NB-1 exception path.
            self._actions_in_flight.discard(flight_key)

    async def action_status_for(
        self,
        source_type: str,
        source_id: str,
        action_id: str,
    ) -> "ActionStatus":
        """Return the current status of a plugin-declared action.

        Mirrors ``run_action_for`` validation but calls ``plugin.action_status``
        instead.  A raising plugin is caught and replaced with
        ``NULL_ACTION_STATUS`` (resilient degradation — no 500 on a bad
        status read; ADR-0034 §resilience).

        ``action_status`` MUST NOT trigger network calls or SSH connections —
        this is called on the request path for GET /sources/{type}/actions and
        cannot tolerate network latency (ADR-0034 §long-running-semantics).

        Args:
            source_type: Plugin ``type_key``.
            source_id:   Instance name.
            action_id:   The declared action whose status is requested.

        Returns:
            ``ActionStatus`` snapshot, or ``NULL_ACTION_STATUS`` if the plugin
            raises.

        Raises:
            KeyError:   Instance not found — caller maps to 404.
            ValueError: ``action_id`` not declared — caller maps to 404.
        """
        from firewatch_core.scoped_kv import scoped_kv
        from firewatch_sdk.actions import ActionCapable, NULL_ACTION_STATUS

        rec = self.get_instance(source_type, source_id)
        if rec is None:
            raise KeyError(f"instance not found: {source_type}/{source_id}")

        type_key = rec.plugin.metadata().type_key
        declared_ids = {a.id for a in rec.plugin.metadata().actions}
        if action_id not in declared_ids:
            raise ValueError(
                f"action {action_id!r} not declared by plugin {type_key!r}; "
                f"declared: {sorted(declared_ids)}"
            )

        if not isinstance(rec.plugin, ActionCapable):
            return NULL_ACTION_STATUS

        kv = scoped_kv(self._pipeline.store, type_key)
        ctx = PluginContext(kv=kv, source_id=rec.source_id)

        try:
            status = await rec.plugin.action_status(action_id, rec.cfg, ctx)
        except Exception:
            logger.warning(
                "supervisor.action_status_for source=%s/%s action=%s raised — "
                "degrading to null-status (ADR-0034 §resilience)",
                type_key, rec.source_id, action_id,
                exc_info=True,
            )
            return NULL_ACTION_STATUS

        return status

    def status(self) -> list[InstanceStatus]:
        """Return a read-only snapshot of every registered instance (MB.4, issue #56).

        Maps each ``InstanceRecord`` to a frozen ``InstanceStatus`` DTO so the
        API layer can read instance state without accessing private supervisor
        internals (``InstanceRecord``, ``InstanceState``, ``_instances``).

        A failing/parked instance contributes its status normally — it does NOT
        raise. This satisfies the crash-isolation EARS criterion: no single
        instance's state breaks the response for others.

        Returns:
            A new list of frozen ``InstanceStatus`` objects, one per registered
            instance, in registration order.
        """
        result: list[InstanceStatus] = []
        for rec in self._instances:
            result.append(
                InstanceStatus(
                    source_type=rec.plugin.metadata().type_key,
                    source_id=rec.source_id,
                    flavor=rec.flavor,
                    state=rec.state.value,
                    attempt=rec.attempt,
                    total_crashes=rec.total_crashes,
                    total_dlq=rec.total_dlq,
                    dropped_count=rec.dropped_count,
                    last_success_at=rec.last_success_at,
                    # ADR-0031 §F: last-sync surfacing
                    last_sync_at=rec.last_sync_at,
                    last_sync_ingested=rec.last_sync_ingested,
                    last_sync_status=rec.last_sync_status,  # type: ignore[arg-type]
                    last_error=rec.last_error,
                )
            )
        return result
