"""Meta routes — GET /health, GET /rules, GET /stats (ADR-0029 D1, MB.1 + ADR-0032, issue #133).

Thin controllers delegating to store methods.  No business logic here.

Imports only firewatch-sdk and firewatch-api internals. Never imports legacy/.

issue #135: GET /health restores ``ollama_connected`` and ``ollama_model`` fields.
The AI status probe hits ``GET {base_url}/v1/models`` (OpenAI-compatible health path,
ADR-0022) with a 5-second timeout; any failure yields ``ollama_connected=False``
without raising (health endpoints must always return 200).

ADR-0066 (issue #39): additive ``ai`` field — Layer 1 engine state
(``"active"``/``"disabled"``/``"unreachable"``).  Inertness principle: WHEN
``ai_enabled=false``, this endpoint MUST NOT dial the inference endpoint at
all — an off subsystem is inert, mirroring the config-validator and
factory-construction inertness fixed in issue #40.  ``ollama_connected`` is
retained for compatibility (deprecated): ``true`` iff ``ai == "active"``.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException

from firewatch_api.deps import (
    get_config_store,
    get_event_store,
    get_registry,
    get_supervisor,
)
from firewatch_api.health_assembler import FRESHNESS_MINUTES, assemble_source_health
from firewatch_api.schemas import HealthResponse

logger = logging.getLogger("firewatch.api.meta")

router = APIRouter(tags=["meta"])

# Timeout (seconds) for the AI endpoint reachability probe in GET /health.
# Short because health checks must be non-blocking (issue #135).
_AI_PROBE_TIMEOUT = 5.0


async def _probe_ai_connected(base_url: str) -> bool:
    """Return True if the OpenAI-compatible endpoint at ``base_url`` is reachable.

    Hits ``GET {base_url}/v1/models`` — the standard health-check path for all
    supported local runtimes (Ollama, vLLM, llama.cpp, LM Studio — ADR-0022).
    Any exception (connection refused, timeout, non-200) returns False.
    Never raises.
    """
    try:
        async with httpx.AsyncClient(timeout=_AI_PROBE_TIMEOUT) as client:
            response = await client.get(f"{base_url}/v1/models")
            return response.status_code == 200
    except Exception:
        return False


@router.get(
    "/health",
    summary="API liveness and component status",
    response_model=HealthResponse,
)
async def get_health(
    store: Any = Depends(get_event_store),
    config_store: Any = Depends(get_config_store),
) -> dict[str, Any]:
    """Return liveness status, store reachability, and AI engine status.

    ``store`` status is ``"ok"`` when an event store is injected, ``"unavailable"``
    otherwise.  The HTTP status is always 200 — health endpoints must not block
    (the caller decides what to do with a degraded component status).

    ``ollama_connected`` (bool) and ``ollama_model`` (str|null) are restored per
    issue #135 — the frontend reads these to render the Local AI panel.
    The base_url is read from the runtime config (``ollama_base_url``); the local-first
    invariant is enforced at config-write time by the SDK validator (ADR-0022).

    ``ai`` (ADR-0066): WHEN ``ai_enabled=false``, the inference endpoint is
    NEVER dialed (inertness) and ``ai="disabled"`` is reported immediately.
    Otherwise the endpoint is probed and ``ai`` is ``"active"`` or
    ``"unreachable"``.
    """
    store_status = "unavailable"
    if store is not None:
        try:
            # A lightweight ping: obtain the DB connection without running a query.
            await store._conn()
            store_status = "ok"
        except Exception:
            logger.warning("health check: store connection failed", exc_info=True)
            store_status = "error"

    # AI status: probe the configured local endpoint ONLY when ai_enabled=true
    # (issue #135, ADR-0022; inertness fix ADR-0066/issue #39 — an off
    # subsystem must never dial).
    ollama_model: str | None = None
    ai_status: str = "disabled"
    if config_store is not None:
        try:
            runtime = config_store.get_runtime()
            ollama_model = runtime.ollama_model
            if getattr(runtime, "ai_enabled", True):
                connected = await _probe_ai_connected(runtime.ollama_base_url)
                ai_status = "active" if connected else "unreachable"
            else:
                ai_status = "disabled"
        except Exception:
            logger.warning("health check: AI status probe failed", exc_info=True)
            ai_status = "unreachable"

    return {
        "status": "ok",
        "store": store_status,
        "ollama_connected": ai_status == "active",
        "ollama_model": ollama_model,
        "ai": ai_status,
    }


@router.get(
    "/rules",
    summary="Rule descriptions catalogue",
)
async def get_rules(
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return rule descriptions as a ``RuleDescription[]`` array.

    Each element has the shape expected by the frontend ``RulePopup`` component
    (issue #132 DC-3):

    .. code-block:: json

        [{"rule_id": "942001", "name": "SQL Injection attempt",
          "description": "SQL Injection attempt", "category": null,
          "severity": null, "source_type": null}]

    The backing store returns ``{rule_id: description}``; this route transforms
    that dict into the array shape the frontend's ``fetchRules()`` consumes.
    The ``name`` field mirrors ``description`` (the store only records one string
    per rule; a richer catalog is a future enhancement).
    """
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")
    raw: dict[str, str] = await store.get_rule_descriptions()
    return [
        {
            "rule_id": rule_id,
            "name": description,
            "description": description,
            "category": None,
            "severity": None,
            "source_type": None,
        }
        for rule_id, description in raw.items()
    ]


@router.get(
    "/stats",
    summary="Global aggregate stats + per-source health",
)
async def get_stats(
    store: Any = Depends(get_event_store),
    registry: dict[str, Any] = Depends(get_registry),
    supervisor: Any = Depends(get_supervisor),
    config_store: Any = Depends(get_config_store),
) -> dict[str, Any]:
    """Return global stats and per-source health array.

    Extends the base stats dict (ADR-0029 D1) with:
    - ``source_health[]``  — one entry per installed plugin (ADR-0032 A/B/C/E).
    - ``last_updated``     — ISO timestamp of the most recent event, or null.

    The supervisor dependency is optional (503-safe degradation, ADR-0032 E):
    when absent, ``supervisor_state`` is null and health falls back to
    grey/amber/green (red is unavailable without supervisor data).

    Security (ADR-0029 D3 / issue #133): ``source_health[]`` carries only
    identity/health fields — no secrets are echoed.
    """
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")

    base_stats: dict[str, Any] = await store.get_stats()  # type: ignore[assignment]

    try:
        store_rows: list[dict[str, Any]] = await store.source_health()  # type: ignore[assignment]
    except Exception:
        logger.warning("stats: source_health() failed; using empty list", exc_info=True)
        store_rows = []

    source_health = assemble_source_health(
        registry=registry,
        store_rows=store_rows,
        supervisor=supervisor,
        config_store=config_store,
    )

    return {
        **base_stats,
        "source_health": source_health,
        # R1 (ADR-0032 Amendment 1 #377): live freshness threshold so the
        # legend has exactly ONE source of truth and never hardcodes a copy.
        "freshness_minutes": FRESHNESS_MINUTES,
    }
