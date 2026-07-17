"""``firewatch run`` — load plugins, start supervisor, serve API on loopback.

Implements EARS-1 (issue #35):
  When ``firewatch run`` starts, it shall load plugins via entry points, start
  the supervisor (#22), and serve the API on a loopback bind.

And EARS-3:
  When SIGTERM/SIGINT is received, the process shall shut down within the
  bounded grace period (ADR-0023 §E).

Design notes — single event loop (fix #75)
-------------------------------------------
aiosqlite connections are loop-bound: every Future they return belongs to the
loop on which the connection was opened.  The previous design (WIP #80)
opened the connection on the supervisor loop then ran uvicorn in a separate-
loop daemon thread via ``asyncio.run(server.serve())`` → cross-loop crash
("got Future attached to a different loop") on every read-route await.

Fix: run supervisor + uvicorn on ONE asyncio event loop.  The API server is
launched as ``asyncio.create_task(server.serve())`` on the same loop as the
supervisor, so all coroutines share the same aiosqlite connection without any
cross-loop handoff.

Signal model (ADR-0023 §F):
  uvicorn's ``Server.serve()`` unconditionally wraps execution inside
  ``capture_signals()`` which installs ``signal.signal(SIGTERM/SIGINT, ...)``
  while serving.  FireWatch therefore does NOT install an asyncio-level
  ``loop.add_signal_handler`` for these signals — it would be silently
  clobbered by ``capture_signals`` the moment the server task runs, so it is
  dead code that merely looks live.

  Instead, uvicorn owns signal capture: a signal sets ``should_exit``; the
  server task completes; and the ordered shutdown runs from cmd_run's
  ``finally``.  uvicorn is the trigger; cmd_run is the sequencer.

  No-op re-raise guard (ADR-0023 §F):
    Before the server task is created, cmd_run installs a no-op
    ``signal.signal`` handler (SIG_IGN) for SIGTERM and SIGINT, saving the
    previous handlers.  On clean exit, uvicorn's ``capture_signals`` calls
    ``signal.raise_signal()`` against the handler installed BEFORE the server
    started — which is now the no-op — so the re-raise lands safely rather
    than on SIG_DFL (which would terminate the process before our ordered
    cleanup runs).  The true previous handlers are restored in the ``finally``
    block AFTER ordered shutdown completes.

    signal.signal must be called from the main thread; cmd_run is driven by
    asyncio.run() on the main thread, so this is safe.

Startup sequence (ADR-0023 §F ordering invariant):
  1. Bind guard FIRST (pure host+api_key check, no side effects — BEFORE any
     store, supervisor, or socket is created; guard failure leaks nothing).
  2. ``await store.init()`` (connection born on THIS loop).
  3. Register instances; ``await supervisor.startup()`` (starts tasks, no signals).
  4. Install no-op signal.signal handlers (save previous handlers).
  5. Build uvicorn Config + Server; ``create_task(server.serve())`` on THIS loop.
  6. Create ``supervisor_stopped`` task (status-only — does NOT exit the server);
     ``await server_task`` (blocks until uvicorn exits on SIGTERM/SIGINT).
     FIX #622: supervisor_stopped no longer races server_task; the all-parked
     predicate is a STATUS signal only, never an exit trigger.
  7. finally: drain HTTP → supervisor.shutdown() → store.close() →
     restore previous signal handlers.

Sources are configured only through the MA.2 config service (EARS-4):
  ``load_instances(config_file)`` reads ``_instances`` from
  ``firewatch_config.json``.
Loopback bind (ADR-0026 Decision 1) enforced by ``DEFAULT_HOST``.
"""
from __future__ import annotations

import asyncio
import logging
import signal
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from firewatch_sdk import SourcePlugin

from firewatch_core.instance_loader import load_instances
from firewatch_core.supervisor import Supervisor

from firewatch_api.app import create_app
from firewatch_api.server import _check_bind_guard, _resolve_startup_config

from firewatch_cli.commands._pipeline_factory import _build_pipeline

# ADR-0026 Decision 1: loopback-only default for MA.
DEFAULT_HOST: str = "127.0.0.1"
DEFAULT_PORT: int = 8000

logger = logging.getLogger("firewatch.cli.run")


async def cmd_run(
    registry: dict[str, SourcePlugin],
    config_file: Path | str | None = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> None:
    """Start the supervisor and the API server on one event loop, block until shutdown.

    All asyncio objects (store connection, supervisor tasks, uvicorn server task)
    share a single event loop.  This prevents the cross-loop crash that occurs
    when an aiosqlite connection is opened on one loop and awaited on another.

    Parameters
    ----------
    registry:
        Plugin registry — ``{type_key: plugin_instance}``.  Obtained from
        ``load_source_plugins()`` in production; injected as a fake in tests.
    config_file:
        Path to ``firewatch_config.json``.  Instance list is read from
        ``_instances`` in this file.
    host:
        API bind address.  Default: loopback ``127.0.0.1`` (ADR-0026).
    port:
        API listen port.  Default: 8000.
    """
    import uvicorn

    config_path = Path(config_file) if config_file else Path("firewatch_config.json")
    instances = load_instances(config_path)

    # Step 1: bind guard FIRST — pure host+api_key check with no dependency on
    # store/supervisor.  Fail-closed BEFORE any side effect (store.init, startup).
    # This mirrors serve.py (guard-before-uvicorn) and ensures a legit guard
    # failure leaks nothing: when it raises, nothing has been created yet.
    # Resolve bind_address + api_key from ADR-0006 chain (env > file > default).
    # Pass host as cli_host so an explicit CLI --host flag wins over config.
    effective_host, api_key = _resolve_startup_config(config_file=config_path, cli_host=host)
    _check_bind_guard(host=effective_host, api_key=api_key)

    # Declare all resources before the try/finally so _graceful_shutdown sees
    # them even if construction raises partway through.
    store: Any = None
    ledger: Any = None  # MK-2 verdict ledger (ADR-0044) — closed in _graceful_shutdown
    case_store: Any = None  # ADR-0053 D4 (issue #534) — closed in _graceful_shutdown
    decision_store: Any = None  # ADR-0072 D2 (issue #47) — closed in _graceful_shutdown
    supervisor: Supervisor | None = None
    server: uvicorn.Server | None = None
    server_task: asyncio.Task[None] | None = None
    supervisor_stopped: asyncio.Task[None] | None = None
    _prev_sigterm: Any = None
    _prev_sigint: Any = None

    # Everything from store.init() onward is wrapped in try/finally so that a
    # raise at any point (supervisor.startup, server task, etc.) still triggers
    # ordered teardown.  Nothing leaks.
    try:
        # Step 2: build pipeline + store; init connection on THIS loop.
        # Issue #75 (ADR-0067 D6): pass registry so the pipeline can wire each
        # loaded plugin's declared enforcement-posture default.
        pipeline = _build_pipeline(config_path, registry=registry)
        store = pipeline.store  # type: ignore[attr-defined]
        # MK-2 (ADR-0044): same verdict-ledger instance the pipeline writes to;
        # its aiosqlite connection is born on THIS loop (ADR-0023 §F) so the read
        # API / attestation strip read live data.
        ledger = getattr(pipeline, "ledger", None)
        if hasattr(store, "init"):
            await store.init()
        if ledger is not None and hasattr(ledger, "init"):
            await ledger.init()

        # ADR-0053 D4 (issue #534): case store — separate aiosqlite connection
        # on THIS loop (ADR-0023 §F) so the /cases routes read/write live data.
        from firewatch_core.adapters.cases.sqlite_cases import SqliteCaseStore
        db_path = getattr(store, "db_path", None)
        if db_path is not None:
            case_store = SqliteCaseStore(db_path=db_path)
            await case_store.init()

        # ADR-0072 D2 (issue #47): decision store — separate aiosqlite
        # connection on THIS loop (ADR-0023 §F) so /decisions and the
        # triage_decision annotation / queue_size exclusion read/write live data.
        from firewatch_core.adapters.decisions.sqlite_decisions import SqliteDecisionStore
        if db_path is not None:
            decision_store = SqliteDecisionStore(db_path=db_path)
            await decision_store.init()

        # Step 3: build supervisor, register instances, call startup() (no signals).
        supervisor = Supervisor(pipeline)
        _register_instances(supervisor, registry, instances, config_path)

        logger.info(
            "run: registered %d instance(s); starting supervisor + API on %s:%d",
            len(instances), effective_host, port,
        )
        await supervisor.startup()

        # Step 3b: backfill geo for historical IPs (issue #637).
        # Called AFTER supervisor.startup() (store ready, enrichers wired) and
        # BEFORE the server task.  Startup-only concern: resolves IPs ingested
        # before geo was working (e.g. before the MMDB files were present),
        # decoupled from the hot pull cycle.  Per-enricher exceptions are caught
        # inside startup_backfill() (fail-safe, ADR-0003).
        # iscoroutinefunction (not a plain getattr) is the guard on purpose: the
        # real Pipeline defines startup_backfill as an async method (-> True), but
        # several cmd_run tests stub _build_pipeline with a MagicMock whose
        # auto-created `.startup_backfill` child is a non-awaitable sync mock
        # (-> False, skipped).  It is also False for None, so no separate guard.
        startup_backfill = getattr(pipeline, "startup_backfill", None)
        if asyncio.iscoroutinefunction(startup_backfill):
            await startup_backfill()

        # Step 4: install no-op signal handlers BEFORE creating the server task
        # (ADR-0023 §F no-op re-raise guard).
        # SIG_IGN is the no-op: uvicorn's raise_signal() on clean exit lands on
        # this instead of SIG_DFL, which would kill the process before cleanup.
        _prev_sigterm, _prev_sigint = _install_noop_signal_guard()

        # Step 5: build app + uvicorn server on THIS loop.
        # Pass config_store so the auto-sync write routes (ADR-0031 option A)
        # can reach the same file path that the supervisor booted from.
        from firewatch_core.config_store import JsonFileConfigStore
        config_store = JsonFileConfigStore(config_file=config_path)
        app = create_app(
            registry=registry,
            config_store=config_store,
            event_store=store,
            pipeline=pipeline,
            supervisor=supervisor,
            analysis_ledger=ledger,
            case_store=case_store,
            decision_store=decision_store,
        )
        config = uvicorn.Config(app, host=effective_host, port=port, log_level="info")
        server = uvicorn.Server(config)
        server_task = asyncio.create_task(server.serve(), name="firewatch-api")

        # Step 6: await server_task — the server runs until uvicorn is told to
        # stop (SIGTERM / SIGINT / explicit supervisor.shutdown() path).
        #
        # FIX #622: the previous design raced server_task against
        # supervisor_stopped (supervisor.wait_until_stopped()) and set
        # server.should_exit=True when the all-parked predicate fired first.
        # That killed the API whenever all sources went parked/idle — leaving
        # the operator with 502s and no way to revive sources from Settings.
        #
        # ``run`` ALWAYS serves an API/UI, so its lifetime MUST NOT be tied to
        # the all-parked predicate.  The predicate's only role now is status:
        # the supervisor exposes is_stopped / wait_until_stopped() for the UI
        # to surface "collection idle — sources parked", but the process stays
        # alive.  The server exits only when uvicorn's own signal handler fires
        # (SIGTERM/SIGINT), which is still the exclusive signal owner per the
        # ADR-0023 §F signal model.
        #
        # supervisor_stopped is still created (strong-ref it in self to prevent
        # GC before the finally block cancels it) so the supervisor's public
        # §D.1 seam (wait_until_stopped / is_stopped) keeps working for status.
        supervisor_stopped = asyncio.create_task(
            supervisor.wait_until_stopped(),
            name="firewatch-supervisor-stopped",
        )

        # Block until the HTTP server exits naturally (signal/explicit shutdown).
        # supervisor_stopped runs in the background for status only; it never
        # causes server.should_exit to be set from this path.
        await server_task

    finally:
        await _graceful_shutdown(
            server=server,
            server_task=server_task,
            supervisor=supervisor,
            store=store,
            ledger=ledger,
            case_store=case_store,
            decision_store=decision_store,
        )
        # Cancel supervisor_stopped if it was created but not yet done.
        if supervisor_stopped is not None and not supervisor_stopped.done():
            supervisor_stopped.cancel()
        # Restore previous signal handlers AFTER ordered shutdown (ADR-0023 §F).
        _restore_signal_guard(_prev_sigterm, _prev_sigint)


def _install_noop_signal_guard() -> tuple[Any, Any]:
    """Install no-op SIGTERM/SIGINT handlers; return (prev_sigterm, prev_sigint).

    Called BEFORE creating the uvicorn server task so that uvicorn's
    ``capture_signals()`` exit-time ``raise_signal()`` lands on SIG_IGN instead
    of the default SIG_DFL (process kill before cleanup).

    Must be called from the main thread (signal.signal requirement).
    """
    prev_sigterm = signal.signal(signal.SIGTERM, signal.SIG_IGN)
    prev_sigint = signal.signal(signal.SIGINT, signal.SIG_IGN)
    return prev_sigterm, prev_sigint


def _restore_signal_guard(prev_sigterm: Any, prev_sigint: Any) -> None:
    """Restore SIGTERM/SIGINT to the handlers saved by _install_noop_signal_guard.

    Called in cmd_run's finally block AFTER ordered shutdown completes.
    No-ops if either previous handler is None (guard was never installed).
    """
    if prev_sigterm is not None:
        try:
            signal.signal(signal.SIGTERM, prev_sigterm)
        except Exception:
            logger.warning("run: could not restore SIGTERM handler", exc_info=True)
    if prev_sigint is not None:
        try:
            signal.signal(signal.SIGINT, prev_sigint)
        except Exception:
            logger.warning("run: could not restore SIGINT handler", exc_info=True)


async def _graceful_shutdown(
    server: Any,
    server_task: asyncio.Task[None] | None,
    supervisor: Supervisor | None,
    store: Any,
    ledger: Any = None,
    case_store: Any = None,
    decision_store: Any = None,
) -> None:
    """Ordered graceful shutdown: drain HTTP -> supervisor -> ledger -> case_store
    -> decision_store -> store.

    None-safe: called from cmd_run's finally block so it handles partial-startup
    (store inited but supervisor never started, or server never created).

    Ordering (ADR-0023 §F):
      1. Drain uvicorn (if present) — stop new connections; await in-flight requests.
      2. supervisor.shutdown() — bounded-grace stop (ADR-0023 §E).
      3. ledger.close() — release the verdict-ledger connection (MK-2, ADR-0044).
      4. case_store.close() — release the case store connection (ADR-0053, #534).
      5. decision_store.close() — release the decision store connection (ADR-0072, #47).
      6. store.close() — ALWAYS last (both API and supervisor must release connection first).
    """
    logger.info("run: shutdown — draining HTTP then supervisor")

    # 1. Ensure uvicorn knows to exit and drain in-flight requests.
    if server is not None:
        server.should_exit = True
    if server_task is not None and not server_task.done():
        # Cancel the task so it does not block indefinitely.
        # uvicorn exits its serve loop when should_exit=True; if for any reason
        # it does not (e.g. a test mock), cancellation ensures we do not hang.
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, Exception):
            pass

    # 2. ADR-0023 §E bounded-grace supervisor shutdown.
    if supervisor is not None:
        try:
            await supervisor.shutdown()
        except Exception:
            logger.warning("run: supervisor.shutdown() raised", exc_info=True)

    # 3. Close the verdict-ledger connection (MK-2, ADR-0044) — before the store.
    if ledger is not None and hasattr(ledger, "close"):
        try:
            await ledger.close()
        except Exception:
            logger.warning("run: ledger.close() raised; ignoring", exc_info=True)

    # 4. Close the case store connection (ADR-0053, issue #534) — before the store.
    if case_store is not None and hasattr(case_store, "close"):
        try:
            await case_store.close()
        except Exception:
            logger.warning("run: case_store.close() raised; ignoring", exc_info=True)

    # 5. Close the decision store connection (ADR-0072, issue #47) — before the store.
    if decision_store is not None and hasattr(decision_store, "close"):
        try:
            await decision_store.close()
        except Exception:
            logger.warning("run: decision_store.close() raised; ignoring", exc_info=True)

    # 6. Close the store connection cleanly — always last.
    if store is not None and hasattr(store, "close"):
        try:
            await store.close()
        except Exception:
            logger.warning("run: store.close() raised; ignoring", exc_info=True)

    logger.info("run: shutdown complete")


def _register_instances(
    supervisor: Supervisor,
    registry: dict[str, SourcePlugin],
    instances: list[Any],
    config_path: Path,
) -> None:
    """Register loaded instances with the supervisor and idle configured extras.

    Two passes (ADR-0031 §C):

    Pass 1 — _instances entries (auto-sync ON or pre-configured):
        Each entry in the ``_instances`` list maps to ``add_pull``/``add_push``
        so the supervisor starts them during ``startup()``.

    Pass 2 — configured-but-not-in-_instances pull sources (auto-sync OFF):
        Any plugin whose config section is present in ``firewatch_config.json``
        but has NO matching ``_instances`` entry is registered as ``idle`` so
        that ``POST /sync/{type}`` works without auto-sync being enabled (the
        seam ADR-0031 §C mandates).  Push sources are skipped — configuring a
        push source already starts its listener; there is no idle-push concept.

    Logs a warning (and skips) if a source_type has no matching registry entry.
    """
    # Track which type_keys were registered in Pass 1.
    registered_types: set[str] = set()

    # Pass 1: _instances entries.
    for inst in instances:
        plugin = registry.get(inst.source_type)
        if plugin is None:
            logger.warning(
                "run: source_type=%r (source_id=%r) not found in registry; "
                "skipping — is the plugin installed?",
                inst.source_type, inst.source_id,
            )
            continue
        cfg = _resolve_config(plugin, inst.extra_cfg, config_path)
        if inst.flavor == "pull":
            supervisor.add_pull(plugin, cfg, source_id=inst.source_id, interval=inst.interval)
        else:
            supervisor.add_push(plugin, cfg, source_id=inst.source_id, transport=inst.transport)
        registered_types.add(inst.source_type)

    # Pass 2: configured-but-not-in-_instances pull sources (ADR-0031 §C).
    # Only pull sources get an idle record; push sources have no auto-sync concept.
    _register_idle_configured_pulls(supervisor, registry, registered_types, config_path)


def _register_idle_configured_pulls(
    supervisor: Supervisor,
    registry: dict[str, SourcePlugin],
    already_registered: set[str],
    config_path: Path,
) -> None:
    """Register idle supervisor records for configured-but-not-scheduled pull sources.

    ADR-0031 §C: a pull source whose config section is present in
    ``firewatch_config.json`` but has no ``_instances`` entry (auto-sync OFF)
    SHALL have a supervisor record in IDLE state so that ``POST /sync/{type}``
    runs one cycle without requiring auto-sync to be enabled first.

    Reads the config file once (via JsonFileConfigStore) to discover which
    source types have a config section.  Only pull-flavored sources that are
    NOT already in ``already_registered`` are registered idle.
    """
    from firewatch_core.config_store import JsonFileConfigStore

    try:
        store = JsonFileConfigStore(config_file=config_path)
    except Exception:
        logger.warning(
            "run: could not open config store for idle-registration pass; "
            "manual Sync may not work for auto-sync-OFF sources",
            exc_info=True,
        )
        return

    for type_key, plugin in registry.items():
        if type_key in already_registered:
            continue  # already handled in Pass 1

        meta = plugin.metadata()
        if meta.flavor != "pull":
            continue  # push sources have no idle concept

        # Check if a config section exists for this type.
        # get_source with defaults returns a model whether or not the section
        # exists, so we use the public has_source() seam instead of probing
        # the private _file_data attribute (issue #155 NB-2: a non-file store
        # would silently return {} via getattr, causing silent mis-registration).
        try:
            if not store.has_source(type_key):
                continue  # no config section — source not configured yet
        except Exception:
            continue

        # Config section present but no _instances entry: register idle.
        try:
            cfg = store.get_source(type_key, plugin.config_schema())
            supervisor.register_idle(
                plugin,
                cfg,
                source_id=type_key,  # ADR-0031 §B: default source_id = type_key
                flavor="pull",
                interval=60.0,
                transport="file",
            )
            logger.info(
                "run: registered idle instance for configured-but-not-scheduled "
                "pull source %r (auto-sync OFF — manual Sync available)",
                type_key,
            )
        except Exception:
            logger.warning(
                "run: could not register idle instance for %r; "
                "manual Sync may not work",
                type_key, exc_info=True,
            )


def _resolve_config(
    plugin: SourcePlugin,
    extra_cfg: dict[str, Any],
    config_path: Path,
) -> BaseModel:
    """Resolve per-instance config: type-level defaults + extra_cfg overrides.

    Mirrors ``sync_once._resolve_config`` — kept here separately to avoid
    importing sync_once (clean concern separation, each command module is
    self-contained).
    """
    schema = plugin.config_schema()
    source_type = plugin.metadata().type_key

    try:
        from firewatch_core.config_store import JsonFileConfigStore
        store_cfg = JsonFileConfigStore(config_file=config_path)
        base_cfg = store_cfg.get_source(source_type, schema)
        if extra_cfg:
            merged = {**base_cfg.model_dump(), **extra_cfg}
            return schema.model_validate(merged)
        return base_cfg
    except Exception:
        logger.error(
            "run._resolve_config: could not load config for %r; "
            "using schema defaults + extra_cfg",
            source_type, exc_info=True,
        )
        return schema.model_validate(extra_cfg)
