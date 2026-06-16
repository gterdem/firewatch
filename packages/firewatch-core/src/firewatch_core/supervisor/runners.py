"""Per-instance coroutines for pull and push sources (ADR-0023).

Each runner owns the lifecycle of a single source instance.  Orchestrator
callbacks are injected at call time so runners remain testable in isolation
and free of direct Supervisor references.

Public coroutines:
  - run_pull_instance  — interval loop calling pipeline.run_pull_cycle
  - run_push_instance  — PushSource.start() wrapper with backpressure queue
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from firewatch_sdk import PluginContext, SecurityEvent
from firewatch_sdk.ports import PushSource

from .config import SupervisorConfig
from .models import (
    BackpressurePolicy,
    InstanceRecord,
    InstanceState,
    PoisonRecordError,
    _policy_for_transport,
)
from .policy import should_park
from firewatch_core.sync_state import persist_sync_state

logger = logging.getLogger("firewatch.supervisor")


# Type aliases for the orchestrator callbacks injected into the runners.
_ParkFn = Callable[[InstanceRecord, int], None]
_AddTaskFn = Callable[[asyncio.Task[Any]], None]
_MakeDiscardCbFn = Callable[[asyncio.Task[Any]], Callable[[asyncio.Task[Any]], None]]


async def run_pull_instance(
    rec: InstanceRecord,
    pipeline: Any,
    cfg: SupervisorConfig,
    is_running: Callable[[], bool],
    handle_poison: Callable[[InstanceRecord, Any], Awaitable[None]],
) -> None:
    """Supervise one PullSource instance: periodic collect → ingest loop.

    Drives ``pipeline.run_pull_cycle`` on the configured interval.
    The watermark is owned by the pipeline/store (ADR-0007/0016); the supervisor
    calls run_pull_cycle but never re-keys the watermark.

    DLQ path (ADR-0023 §D-revised): the pipeline's run_pull_cycle raises a
    ``PoisonRecordError`` (annotated with the offending raw event) when ingest
    fails for the same record dlq_threshold times.  The supervisor dead-letters
    that record and advances the watermark past it so the stream is unblocked.

    State-driven guard (EARS): while in BACKOFF state no new cycle is started.

    Args:
        rec:           The InstanceRecord for this pull instance.
        pipeline:      Pipeline exposing ``run_pull_cycle`` and ``store``.
        cfg:           Supervisor configuration.
        is_running:    Callable returning True while the supervisor is running.
        handle_poison: Coroutine factory for the DLQ path (called on PoisonRecordError).
    """
    from firewatch_core.scoped_kv import scoped_kv

    # NB-4/ADR-0031 §D: do NOT cache interval in a local variable here.
    # Read rec._pull_interval at the top of each sleep so set_interval() applies
    # on the next tick without cancelling the in-flight pull.

    # source_type from the plugin constant only — never from a call argument
    # (capability isolation, ADR-0025 addendum / ADR-0027 §3).  Hoisted out of
    # the inner try so it is always bound for the except Exception stamp path.
    source_type = rec.plugin.metadata().type_key

    try:
        while is_running() and rec.state == InstanceState.RUNNING:
            cycle_start = time.monotonic()
            try:
                # Mint ctx per cycle (ADR-0027 §3).  The raw EventStore is never
                # handed to the plugin; only the derived ScopedKV view is.
                kv = scoped_kv(pipeline.store, source_type)
                ctx = PluginContext(kv=kv, source_id=rec.source_id)
                cycle_ingested: int = await pipeline.run_pull_cycle(
                    rec.plugin, rec.cfg, rec.source_id, ctx
                )
                # Successful cycle → reset attempt counter (ADR-0023 §C) and
                # record last-sync outcome (ADR-0031 §F) so auto-sync status is
                # surfaced via status() the same way the manual-sync path does.
                rec.attempt = 0
                rec.last_success_at = time.monotonic()
                now_wall = time.time()
                rec.last_sync_at = now_wall
                rec.last_sync_ingested = cycle_ingested
                rec.last_sync_status = "ok" if cycle_ingested > 0 else "no_data"
                rec.last_error = None
                # Note: pipeline.run_pull_cycle already persisted the success stamp
                # to the durable KV store (issue #707).  No duplicate write here.
            except asyncio.CancelledError:
                raise
            except PoisonRecordError as exc:
                # DLQ path: poison record identified by the pipeline
                await handle_poison(rec, exc.raw)
            except Exception as exc:
                # Generic cycle failure — record stamp before re-raising so the
                # UI shows "error" rather than "Never" (issue #707).
                # Fail-safe: stamp write must not mask the original exception.
                now_wall = time.time()
                rec.last_sync_at = now_wall
                rec.last_sync_status = "error"
                rec.last_error = f"{type(exc).__name__}: {str(exc)[:200]}"
                rec.last_sync_ingested = 0
                try:
                    await persist_sync_state(
                        store=pipeline.store,
                        source_type=source_type,
                        source_id=rec.source_id,
                        ts=now_wall,
                        ingested=0,
                        status="error",
                        last_error=rec.last_error,
                    )
                except Exception:
                    pass  # never mask the original exception
                raise

            elapsed = time.monotonic() - cycle_start
            # ADR-0031 §D: read _pull_interval here (not at loop entry) so
            # set_interval() takes effect on the very next tick.
            remaining = rec._pull_interval - elapsed
            if remaining > 0 and is_running() and rec.state == InstanceState.RUNNING:
                await asyncio.sleep(remaining)

    except asyncio.CancelledError:
        rec.state = InstanceState.STOPPED
        raise


async def run_push_instance(
    rec: InstanceRecord,
    pipeline: Any,
    cfg: SupervisorConfig,
    park_fn: _ParkFn,
    add_task_fn: _AddTaskFn,
    make_discard_cb_fn: _MakeDiscardCbFn,
) -> None:
    """Supervise one PushSource instance: call start(cfg, emit) and keep it running.

    The emit callback routes batches into the pipeline (via ingest).
    Backpressure is transport-aware (ADR-0023 §Steals):
    - UDP: drop when the queue is full (Drop-newest + counter).
    - TCP/file: block (asyncio.Queue.put() — propagates backpressure upstream).

    Args:
        rec:               The InstanceRecord for this push instance.
        pipeline:          Pipeline exposing ``ingest`` and ``store``.
        cfg:               Supervisor configuration.
        park_fn:           Orchestrator callback to park an instance (sets state, emits alert).
        add_task_fn:       Orchestrator callback to register a task in the strong-ref set.
        make_discard_cb_fn: Orchestrator callback factory for done-callbacks that log errors.
    """
    source_type = rec.plugin.metadata().type_key
    policy = _policy_for_transport(rec.transport)
    queue: asyncio.Queue[list[Any]] = asyncio.Queue(maxsize=cfg.push_queue_maxsize)

    async def emit(batch: list[Any]) -> None:
        """Emit callback passed to PushSource.start(); applies backpressure."""
        if policy == BackpressurePolicy.DROP:
            # UDP: non-blocking put; drop and count if full
            try:
                queue.put_nowait(batch)
            except asyncio.QueueFull:
                rec.dropped_count += 1
                if rec.dropped_count % 100 == 1:
                    logger.warning(
                        "supervisor UDP backpressure: dropped %d batch(es) "
                        "for %s/%s — downstream too slow",
                        rec.dropped_count, source_type, rec.source_id,
                    )
        else:
            # TCP/file: block until queue has space (backpressure upstream)
            await queue.put(batch)

    # Consumer coroutine: drain queue → normalize → ingest
    consumer_stop = asyncio.Event()
    # NB-3: when the consumer parks the instance due to ingest failures, it needs
    # to signal the plugin to stop() so start() returns and the task completes.
    should_stop_plugin = asyncio.Event()

    async def consumer() -> None:
        while not consumer_stop.is_set() or not queue.empty():
            try:
                batch = await asyncio.wait_for(queue.get(), timeout=0.1)
            except asyncio.TimeoutError:
                continue
            try:
                events: list[SecurityEvent] = [
                    rec.plugin.normalize(raw, rec.source_id) for raw in batch
                ]
                await pipeline.ingest(events)
                # Success — reset failure counter and attempt counter (ADR-0023 §C)
                rec.push_ingest_failures = 0
                rec.attempt = 0
                rec.last_success_at = time.monotonic()
            except asyncio.CancelledError:
                raise
            except Exception:
                # NB-3: count consecutive ingest failures and feed the SAME storm cap
                # so a push instance with failing ingest is treated consistently with
                # the pull path (park + alert instead of silent log-and-drop).
                rec.push_ingest_failures += 1
                logger.error(
                    "supervisor.push_consumer ingest error for %s/%s "
                    "(consecutive_failures=%d)",
                    source_type, rec.source_id, rec.push_ingest_failures,
                    exc_info=True,
                )
                now = time.monotonic()
                rec.record_crash(now)
                park, crashes = should_park(rec, cfg, now)
                if park:
                    # Park the instance via the same path as pull crashes, then
                    # signal the plugin to stop so start() returns cleanly.
                    consumer_stop.set()
                    park_fn(rec, crashes)
                    should_stop_plugin.set()
                    return
            finally:
                queue.task_done()

    push_plugin: PushSource = rec.plugin  # type: ignore[assignment]

    # Mint ctx for this push instance (ADR-0027 §3): source_type from the plugin
    # constant only — never from a call argument (capability isolation, ADR-0025
    # addendum).  The raw EventStore is never handed to the plugin; only the
    # derived ScopedKV view is.
    from firewatch_core.scoped_kv import scoped_kv
    push_kv = scoped_kv(pipeline.store, source_type)
    push_ctx = PluginContext(kv=push_kv, source_id=rec.source_id)

    consumer_task = asyncio.create_task(
        consumer(),
        name=f"supervisor-push-consumer-{source_type}/{rec.source_id}",
    )
    # NB-1: track consumer_task in self._tasks so shutdown() drains it within the
    # global shutdown_grace budget instead of the hard-coded 5s finally clause.
    # NB-B: use _make_discard_callback (not plain self._tasks.discard) so unexpected
    # exceptions in the consumer coroutine are logged rather than silently swallowed.
    add_task_fn(consumer_task)
    consumer_task.add_done_callback(make_discard_cb_fn(consumer_task))

    # NB-3: monitor should_stop_plugin and call push_plugin.stop() if the consumer
    # parks the instance — this unblocks start() so the outer task can complete.
    async def _stop_watcher() -> None:
        await should_stop_plugin.wait()
        try:
            await push_plugin.stop()
        except Exception:
            logger.warning(
                "supervisor.push_consumer stop() failed for %s/%s after park",
                source_type, rec.source_id, exc_info=True,
            )

    stop_watcher_task = asyncio.create_task(
        _stop_watcher(),
        name=f"supervisor-push-stop-watcher-{source_type}/{rec.source_id}",
    )
    # NB-B: use _make_discard_callback so unexpected exceptions in the watcher
    # coroutine are logged rather than silently swallowed.
    add_task_fn(stop_watcher_task)
    stop_watcher_task.add_done_callback(make_discard_cb_fn(stop_watcher_task))

    try:
        await push_plugin.start(rec.cfg, emit, push_ctx)
        # start() returns only when stop() is called (PushSource contract)
    except asyncio.CancelledError:
        consumer_stop.set()
        consumer_task.cancel()
        stop_watcher_task.cancel()
        rec.state = InstanceState.STOPPED
        raise
    except Exception:
        consumer_stop.set()
        consumer_task.cancel()
        stop_watcher_task.cancel()
        raise
    finally:
        # NB-A: cancel stop_watcher_task BEFORE setting should_stop_plugin.
        # On normal shutdown, shutdown() already called push_plugin.stop() while
        # the instance was RUNNING, which caused start() to return here.  If we
        # set should_stop_plugin first the watcher would wake up and call
        # push_plugin.stop() a second time — violating the PushSource contract
        # (stop() must be called at most once).  Cancelling the watcher task
        # before the event is set means the watcher is interrupted at its
        # ``await should_stop_plugin.wait()`` before it can issue the second
        # stop().  On the PARK path the consumer already set should_stop_plugin
        # (and the watcher has already called stop() or is about to); cancelling
        # here is a safe no-op because the event is already set and the watcher
        # has already exited or will be cancelled cleanly.
        stop_watcher_task.cancel()
        should_stop_plugin.set()  # wake the watcher if park path didn't already
        consumer_stop.set()
        consumer_task.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(consumer_task), timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            pass
