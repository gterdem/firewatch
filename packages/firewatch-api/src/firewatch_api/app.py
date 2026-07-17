"""FireWatch FastAPI application factory.

``create_app`` is the single entry point for both the production server
(``firewatch_api.server``) and the test client (``TestClient(create_app(...))``.

MB.1 refactor (ADR-0029 D5):
    The MA closure-based handlers are replaced with ``APIRouter`` inclusions.
    ``deps.py`` providers replace the ``app.state.*`` closures so route handlers
    receive their dependencies via ``Depends()`` rather than capturing mutable
    ``app.state`` references.  The ``app.state.*`` attributes are still set
    for backward compatibility; the ``Depends()`` providers read them from
    ``request.app.state``.

The registry is injected at creation time so tests can pass a fake registry
without touching the real loader or any concrete plugin.  In production, the
caller (``server.py`` / MA.6 CLI) calls ``firewatch_core.loader.load_source_plugins``
and passes the result here.

The ``config_store`` is injected the same way — tests pass a fake store; production
passes a ``JsonFileConfigStore`` instance from ``firewatch_core``.

``event_store`` and ``pipeline`` are optional injections for the read routes
(MB.1).  When omitted the routes that need them return 503.

Dependency rule (CLAUDE.md non-negotiable #2):
  This module imports firewatch-core and firewatch-sdk.
  firewatch-core never imports this module; the dependency arrow is one-way.
"""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from firewatch_sdk import SourcePlugin

from pathlib import Path

from firewatch_api.auth.wiring import wire_auth
from firewatch_api.body_limit import BodyLimitMiddleware
from firewatch_api.routes import config as config_routes
from firewatch_api.routes.ai import router as ai_router
from firewatch_api.routes.ai_baseline import router as ai_baseline_router
from firewatch_api.routes.ai_ledger import router as ai_ledger_router
from firewatch_api.routes.ai_stream import router as ai_stream_router
from firewatch_api.routes.analytics import router as analytics_router
from firewatch_api.routes.banner import router as banner_router
from firewatch_api.routes.cases import router as cases_router
from firewatch_api.routes.config import router as config_router
from firewatch_api.routes.discovery import router as discovery_router
from firewatch_api.routes.escalation import router as escalation_router
from firewatch_api.routes.export import router as export_router
from firewatch_api.routes.graph import router as graph_router
from firewatch_api.routes.ingest import router as ingest_router
from firewatch_api.routes.logs import router as logs_router
from firewatch_api.routes.meta import router as meta_router
from firewatch_api.routes.nl_query import router as nl_query_router
from firewatch_api.routes.source_actions import router as source_actions_router
from firewatch_api.routes.sources import router as sources_router
from firewatch_api.routes.threats import router as threats_router


def create_app(
    registry: dict[str, SourcePlugin] | None = None,
    config_store: Any | None = None,
    event_store: Any | None = None,
    pipeline: Any | None = None,
    supervisor: Any | None = None,
    baseline_path: Path | None = None,
    drift_report_path: Path | None = None,
    analysis_ledger: Any | None = None,
    case_store: Any | None = None,
) -> FastAPI:
    """Create and configure the FireWatch FastAPI application.

    Args:
        registry: Mapping of ``type_key`` → plugin instance. When *None*, an
            empty registry is used.  In production this is populated by
            ``firewatch_core.loader.load_source_plugins()``.
        config_store: A ``ConfigStore``-conforming instance. When *None*, a
            default ``JsonFileConfigStore`` is created.  In tests, pass a fake
            store to avoid file I/O.
        event_store: An ``EventStore``-conforming instance (``SQLiteEventStore``).
            When *None*, read routes that need it return 503.
        pipeline: A ``Pipeline`` instance.  When *None*, threat routes return 503.
        supervisor: A ``Supervisor`` instance (MB.4).  When *None*, the instance
            control routes (GET /sources, POST /sources/*/test, POST /sync/*)
            return 503.
        baseline_path: Optional path to ``firewatch_verdict_baseline.json``.
            When *None*, the ``GET /ai/baseline`` route resolves the default
            (same convention as the CLI -- cwd / firewatch_verdict_baseline.json).
        drift_report_path: Optional path to ``firewatch_drift_report.json``.
            When *None*, the ``GET /ai/baseline/drift`` route resolves the
            default (cwd / firewatch_drift_report.json).
        analysis_ledger: Optional ``SqliteAnalysisLedger`` instance (MK-2 /
            ADR-0044).  When *None*, ``GET /ai/analyses`` returns 503 and the
            attestation strip counter fields degrade to ``null`` (pre-#407
            behaviour).  Wiring it here also lights up the ``analyses_count``
            and ``last_analysis_at`` fields in ``GET /ai/engine`` (ADR-0047).
        case_store: Optional ``SqliteCaseStore`` instance (ADR-0053 D4 /
            issue #534).  When *None*, all ``/cases`` routes return 503.
            Wired by the CLI commands (serve.py / run.py) on the same event
            loop as the other stores (ADR-0023 §F).

    Returns:
        A configured ``FastAPI`` application ready to be served.

    ADR-0026 auth (Decision 2-3 + Amendment 1 / issue #548):
        Per-route bearer-token auth is wired centrally by wire_auth(app)
        at the end of this function.  When api_key is set (non-empty),
        ALL routes (class A, B, and C) require a matching Authorization:
        Bearer <key> header or return 401 with WWW-Authenticate: Bearer
        (RFC 6750 sec 3).  When api_key is unset the loopback trust
        boundary applies and no credential is required (ADR-0026 Decision 1).
    """
    _registry: dict[str, SourcePlugin] = registry if registry is not None else {}

    if config_store is None:
        from firewatch_core.config_store import JsonFileConfigStore

        _config_store: Any = JsonFileConfigStore()
    else:
        _config_store = config_store

    app = FastAPI(
        title="FireWatch API",
        description=(
            "FireWatch REST API — plugin discovery, config, threat scores, "
            "logs, analytics, and source instance controls.  Binds loopback "
            "by default (ADR-0026). Auth seam present; full API-key auth "
            "wired at MB.7 when non-loopback exposure is introduced."
        ),
        version="0.2.0",
    )

    # ── State: providers in deps.py read these via request.app.state ─────────
    app.state.registry = _registry
    app.state.config_store = _config_store
    app.state.event_store = event_store
    app.state.pipeline = pipeline
    app.state.supervisor = supervisor  # MB.4: None → control routes return 503
    # MK-8: optional paths for baseline / drift-report file reads.
    # None → routes fall back to cwd / CLI-default filenames.
    app.state.baseline_path = baseline_path
    app.state.drift_report_path = drift_report_path
    # MK-2 (ADR-0044): optional analysis ledger.
    # None → /ai/analyses returns 503; /ai/engine counter fields degrade to null.
    app.state.analysis_ledger = analysis_ledger
    # ADR-0053 D4 (issue #534): optional case store.
    # None → all /cases routes return 503.
    app.state.case_store = case_store

    # ── Router registration ───────────────────────────────────────────────────
    # Behavior-preserving moves (MA routes — existing tests unchanged):
    app.include_router(discovery_router)   # GET /sources/types
    app.include_router(config_router)      # GET/PUT /config/*

    # New read surface (MB.1 / ADR-0029 D1):
    app.include_router(threats_router)     # GET /threats, /threats/{ip}, /threats/{ip}/detailed
    app.include_router(logs_router)        # GET /logs/*
    app.include_router(graph_router)       # GET /logs/graph (ML-8, issue #436)
    app.include_router(analytics_router)   # GET /analytics/*
    app.include_router(meta_router)        # GET /health, /rules, /stats

    # Local AI panel (issue #135, ADR-0022):
    app.include_router(ai_router)          # GET /ai/models, /ai/engine

    # AI baseline read routes (MK-8 / issue #413):
    app.include_router(ai_baseline_router)  # GET /ai/baseline, /ai/baseline/drift

    # AI verdict ledger read routes (MK-2 / issue #407, ADR-0044):
    app.include_router(ai_ledger_router)   # GET /ai/analyses, /ai/analyses/{id}

    # AI pipeline stage-ticker SSE (MK-10 / issue #415, ADR-0046):
    app.include_router(ai_stream_router)   # GET /threats/{ip}/detailed/stream

    # Source instance controls (MB.4 / issue #56):
    app.include_router(sources_router)     # GET /sources, POST /sources/*/test, POST /sync/*

    # Source maintenance actions (ADR-0034 / issue #167):
    app.include_router(source_actions_router)  # GET/POST /sources/{type}/actions[/{id}]

    # Write/ingest door (MC.3 / ADR-0029 D7 / issue #88):
    # POST /logs (single) and POST /logs/batch (bounded list).
    # Registered after the read logs_router — FastAPI routes by method+path so
    # the GET /logs/* and POST /logs coexist without conflict.
    app.include_router(ingest_router)      # POST /logs, POST /logs/batch

    # OCSF 1.8.0 read-only export surface (ADR-0040 / MI-5 #386):
    app.include_router(export_router)      # GET /export/ocsf/events, /export/ocsf/findings

    # NL→FilterSpec query (ML-6 / ADR-0049 / issue #434):
    app.include_router(nl_query_router)    # POST /logs/nl-query

    # Case file CRUD (ADR-0053 D4 / issue #534):
    app.include_router(cases_router)       # /cases and /cases/{id}/...

    # Escalation policy registry + 24h hit-counts (issue #650, ADR-0058 D1/D6, ADR-0059 D6):
    app.include_router(escalation_router)  # GET /escalation/policy

    # Banner attempts summary (issue #55 Part 1/backend, ADR-0070 D1/D3/D5):
    app.include_router(banner_router)      # GET /banner/summary

    # ── Backward-compat re-export for tests that call config_routes helpers ──
    # The existing test_config_routes.py imports config_routes helpers directly
    # (not via HTTP). Those functions remain in routes/config.py unchanged.
    _ = config_routes  # noqa: F841 — keep import alive for type checkers

    # ── Body-size guard (ADR-0026 / OWASP API4 / issue #581) ─────────────────
    # Caps the raw request body on the ingest write door (POST /logs,
    # /logs/batch) with 413 before normalization.  Added BEFORE wire_auth so
    # AuthMiddleware stays OUTERMOST — an unauthenticated request is 401'd on
    # its headers before any body is streamed (DoS posture when a key is set).
    app.add_middleware(BodyLimitMiddleware)

    # ── Auth wiring (ADR-0026 D2-3 + Amendment 1 / issue #548) ───────────────
    # Stamps each route with its RouteClass (A/B/C) and injects the
    # require_auth dependency.  Must run AFTER all routers are included.
    wire_auth(app)

    return app
