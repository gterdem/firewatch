"""``firewatch serve`` — API only, no supervisor loops.

Implements the serve path of EARS-1 (issue #35):
  When ``firewatch serve`` is invoked, it shall start the FireWatch REST API
  without starting the supervisor or any pull/push instance loops.

Intended for the UI-only demo ("Settings UI reachable on loopback").

Single-loop wiring (fix #75)
-----------------------------
aiosqlite connections are loop-bound.  The naive approach —
``asyncio.run(store.init())`` followed by ``uvicorn.run(app)`` — silently
creates two separate event loops: the first loop is closed by ``asyncio.run``
before uvicorn starts its own loop.  Any route handler that awaits the store
then gets "Future attached to a different loop".

Fix: wrap both ``store.init()`` and ``server.serve()`` in ONE async function
run by a single ``asyncio.run(_serve(...))``.  The connection is born and
used on the same loop.

ADR-0026 bind posture:
  The API binds ``127.0.0.1`` (loopback) by default (Decision 1).
  The fail-closed binding guard (Decision 4) fires here before uvicorn is
  called: if the operator sets a non-loopback host without FIREWATCH_API_KEY,
  startup fails loudly.  The single guard implementation lives in
  ``firewatch_api.server._check_bind_guard``.

  NOTE: per-route bearer-token auth enforcement (Decisions 2–3) is DEFERRED
  to MP.3 (ADR-0026 / issue #548).

serve injects NO supervisor (serve starts no instance loops), so ``/sources``
action routes correctly return 503; ``/stats`` and other store-backed routes
return 200.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import uvicorn

from firewatch_sdk import SourcePlugin

from firewatch_api.app import create_app
from firewatch_api.server import _check_bind_guard, _resolve_startup_config

from firewatch_cli.commands._pipeline_factory import _build_pipeline

# ADR-0026 Decision 1: loopback-only default for MA.
DEFAULT_HOST: str = "127.0.0.1"
DEFAULT_PORT: int = 8000

logger = logging.getLogger("firewatch.cli.serve")


async def _serve(
    registry: dict[str, Any],
    host: str,
    port: int,
) -> None:
    """Run the store init and uvicorn server on ONE event loop.

    Critical: both ``store.init()`` and ``server.serve()`` MUST run on the
    same loop.  Calling ``asyncio.run(store.init())`` and then
    ``uvicorn.run(app)`` creates two loops — the first is closed before the
    second starts, binding the aiosqlite connection to a dead loop and causing
    a cross-loop crash on every await inside a route handler.

    This coroutine is invoked via a single ``asyncio.run(_serve(...))``.
    """
    # Issue #75 (ADR-0067 D6): pass registry so the pipeline can wire each
    # loaded plugin's declared enforcement-posture default.
    pipeline = _build_pipeline(registry=registry)
    store = pipeline.store  # type: ignore[attr-defined]
    # MK-2 (ADR-0044): same verdict-ledger instance the pipeline writes to, born on
    # THIS loop (ADR-0023 §F) so the read API / attestation strip see live data.
    ledger = getattr(pipeline, "ledger", None)
    if hasattr(store, "init"):
        await store.init()
    if ledger is not None and hasattr(ledger, "init"):
        await ledger.init()

    # ADR-0053 D4 (issue #534): case store — separate aiosqlite connection on
    # THIS loop (ADR-0023 §F) so the /cases routes read/write live data.
    from firewatch_core.adapters.cases.sqlite_cases import SqliteCaseStore
    db_path = getattr(store, "db_path", None)
    case_store: Any | None = None
    if db_path is not None:
        case_store = SqliteCaseStore(db_path=db_path)
        await case_store.init()

    # ADR-0072 D2 (issue #47): decision store — separate aiosqlite connection
    # on THIS loop (ADR-0023 §F) so /decisions and the triage_decision
    # annotation / queue_size exclusion read/write live data.
    from firewatch_core.adapters.decisions.sqlite_decisions import SqliteDecisionStore
    decision_store: Any | None = None
    if db_path is not None:
        decision_store = SqliteDecisionStore(db_path=db_path)
        await decision_store.init()

    app = create_app(
        registry=registry,
        event_store=store,
        pipeline=pipeline,
        analysis_ledger=ledger,
        case_store=case_store,
        decision_store=decision_store,
        # No supervisor — serve starts no instance loops (read-only API).
    )

    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)

    logger.info("serve: starting API on %s:%d (ADR-0026)", host, port)
    try:
        await server.serve()
    finally:
        # Close both connections (release before process exit); ledger first.
        if ledger is not None and hasattr(ledger, "close"):
            try:
                await ledger.close()
            except Exception:
                logger.warning("serve: ledger.close() raised; ignoring", exc_info=True)
        if case_store is not None and hasattr(case_store, "close"):
            try:
                await case_store.close()
            except Exception:
                logger.warning("serve: case_store.close() raised; ignoring", exc_info=True)
        if decision_store is not None and hasattr(decision_store, "close"):
            try:
                await decision_store.close()
            except Exception:
                logger.warning("serve: decision_store.close() raised; ignoring", exc_info=True)
        if hasattr(store, "close"):
            try:
                await store.close()
            except Exception:
                logger.warning("serve: store.close() raised; ignoring", exc_info=True)


def cmd_serve(
    registry: dict[str, SourcePlugin] | None = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> None:
    """Start the FireWatch API with uvicorn (no supervisor).

    Runs the fail-closed bind guard (ADR-0026 Decision 4) before calling
    uvicorn: if *host* is non-loopback and FIREWATCH_API_KEY is unset,
    startup fails with a clear RuntimeError.

    The guard resolves ``bind_address`` and ``api_key`` from the full ADR-0006
    precedence chain (env > file > default) via ``_resolve_startup_config``.
    The explicit *host* parameter (from the CLI ``--host`` flag) overrides the
    config-resolved ``bind_address`` when provided.

    The store is built and initialised inside a single ``asyncio.run`` call
    so the aiosqlite connection and all route-handler coroutines share one
    event loop (fix #75 — cross-loop crash prevention).

    Parameters
    ----------
    registry:
        Plugin registry injected into the app for ``/sources/types``
        discovery.  When *None*, an empty registry is used.
    host:
        Bind address.  Default: ``127.0.0.1`` (loopback, ADR-0026 D1).
        When a CLI ``--host`` flag is used, this value overrides the
        config-file/env ``bind_address`` field (CLI flag wins).
    port:
        Listen port.  Default: 8000.

    Raises
    ------
    RuntimeError
        If the resolved bind address is non-loopback and ``api_key`` is unset
        (ADR-0026 Decision 4 fail-closed guard).
    """
    # Resolve bind_address + api_key from ADR-0006 chain (env > file > default).
    # Pass host as cli_host so the explicit CLI --host flag wins over config.
    effective_host, api_key = _resolve_startup_config(cli_host=host)
    _check_bind_guard(host=effective_host, api_key=api_key)

    _registry: dict[str, Any] = registry if registry is not None else {}
    asyncio.run(_serve(registry=_registry, host=effective_host, port=port))
