"""Ingest routes — POST /logs (single) and POST /logs/batch (bounded list).

Implements the HTTP write door defined in ADR-0029 D7 (MC.3, issue #88).

Design notes:
- Source-agnostic: the route dispatches to the registered plugin for the
  given ``source_type``; no Azure-specific or Suricata-specific code here.
  Adding a new shipper requires zero edits to this file (ADR-0024 / CLAUDE.md #1).
- Server-side normalization: the ingest body carries a ``RawEvent`` + ``source_type``
  discriminator; we route to that plugin's ``normalize()`` — the same path the pull
  collectors use — and persist the resulting canonical ``SecurityEvent``.  Pre-normalized
  ``SecurityEvent`` ingest is rejected (ADR-0029 D7.1 / ADR-0024 / ADR-0025).
- Batch bound: ``POST /logs/batch`` is bounded by a config-overridable max size
  (ADR-0029 D7.2 / ADR-0006).  Over-limit bodies are rejected with 422 before
  any persistence.
- Dedup: the store's unique index absorbs replays; the response reports
  inserted-vs-deduped counts (mirroring ``save_many``).
- Background analyze: on successful ingest, ``pipeline.background_analyze_and_alert``
  is scheduled via FastAPI ``BackgroundTasks`` for each distinct ``source_ip`` in the
  batch, so the response is returned promptly without blocking on AI (ADR-0003).
- Write-door posture: loopback-only in MC (ADR-0026 / ADR-0029 D7.3).  Same fail-closed
  bind guard as the read surface; no new exposure.

Security posture:
- ``data`` (the vendor payload) is attacker-controlled. It flows opaquely into
  ``normalize()`` and lands in ``raw_log`` — never interpolated into log messages
  as a format string, never eval/exec'd.
- ``source_type`` and ``source_id`` are constrained by Pydantic Field patterns
  (see IngestRequest in schemas.py) that exclude CR/LF and control characters,
  preventing log-injection via those fields.
- There is currently NO server-enforced request-body size limit. Pydantic validates
  the schema structure, but does not cap raw body bytes.  This is acceptable only
  under the loopback-only deployment posture (ADR-0026 / ADR-0029 D7.3).
  An explicit body-size guard MUST be added before any non-loopback exposure.
  # TODO(D7.3): add body-size middleware before non-loopback exposure milestone.
- Batch size is explicitly enforced here (ADR-0029 D7.2 / ADR-0006).
- Typed errors on all fault paths — no bare ``except`` swallowing.

Imports only firewatch-sdk and firewatch-core. Never imports a plugin or legacy/.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import ValidationError

from firewatch_sdk.models import RawEvent

from firewatch_api.deps import get_event_store, get_pipeline, get_registry
from firewatch_api.schemas import (
    DEFAULT_MAX_BATCH_SIZE,
    BatchIngestRequest,
    IngestRequest,
    IngestResponse,
)

logger = logging.getLogger("firewatch.api.ingest")

router = APIRouter(prefix="/logs", tags=["ingest"])

# ---------------------------------------------------------------------------
# Config-overridable batch limit (ADR-0006 / ADR-0029 D7.2)
# ---------------------------------------------------------------------------

_ENV_MAX_BATCH = "FIREWATCH_MAX_BATCH_SIZE"


def _max_batch_size() -> int:
    """Return the effective max batch size (env override > default).

    ADR-0006: env vars take precedence over built-in defaults.  The env var
    ``FIREWATCH_MAX_BATCH_SIZE`` overrides ``DEFAULT_MAX_BATCH_SIZE`` (100).
    Invalid / non-positive values fall back to the default.
    """
    raw = os.environ.get(_ENV_MAX_BATCH, "")
    if raw:
        try:
            val = int(raw)
            if val > 0:
                return val
        except ValueError:
            logger.warning(
                "ingest: invalid %s=%r — using default %d",
                _ENV_MAX_BATCH, raw, DEFAULT_MAX_BATCH_SIZE,
            )
    return DEFAULT_MAX_BATCH_SIZE


# ---------------------------------------------------------------------------
# Guards / helpers
# ---------------------------------------------------------------------------


def _require_store(store: Any) -> Any:
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")
    return store


def _require_pipeline(pipeline: Any) -> Any:
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not available")
    return pipeline


def _resolve_plugin(source_type: str, registry: dict[str, Any]) -> Any:
    """Return the plugin for *source_type* or raise 422 (ADR-0029 D7.1).

    Unknown source_type always returns 422, never 500.
    """
    plugin = registry.get(source_type)
    if plugin is None:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Unknown source_type {source_type!r} — "
                "no registered plugin to normalize with (ADR-0029 D7.1)."
            ),
        )
    return plugin


def _build_raw_event(req: IngestRequest) -> RawEvent:
    """Build a ``RawEvent`` from an ``IngestRequest``.

    ``received_at`` defaults to the server's UTC timestamp when the caller omits it.
    ``data`` is passed as-is — attacker-controlled; never interpolated into logs.
    """
    return RawEvent(
        source_type=req.source_type,
        received_at=req.received_at or datetime.now(tz=timezone.utc),
        data=req.data,
    )


def _normalize_or_422(
    plugin: Any,
    raw: RawEvent,
    source_id: str,
    source_type: str,
    idx: int | None = None,
) -> Any:
    """Normalize a raw event via ``plugin.normalize()``, raising 422 on failure.

    Returns the normalized ``SecurityEvent``.

    Catches ``pydantic.ValidationError`` first (before the broad Exception handler)
    and returns a sanitized 422 detail that does NOT echo attacker-controlled input
    values.  The full exception is still logged server-side at WARNING level.

    ``idx`` is included in the detail for batch endpoints (event index); for the
    single endpoint it is ``None`` and omitted from the detail string.
    """
    prefix = f"event[{idx}] " if idx is not None else ""
    try:
        return plugin.normalize(raw, source_id)
    except ValidationError as exc:
        logger.warning(
            "ingest: normalize() schema validation failed for %ssource_type=%s: %s",
            prefix, source_type, exc,
        )
        raise HTTPException(
            status_code=422,
            detail=(
                f"Normalization failed for {prefix}source_type={source_type!r}: "
                "schema validation error"
            ),
        ) from exc
    except Exception as exc:
        # Normalization failures are a client-side data problem, not a server fault.
        raise HTTPException(
            status_code=422,
            detail=(
                f"Normalization failed for {prefix}source_type={source_type!r}: {exc}"
            ),
        ) from exc


# ---------------------------------------------------------------------------
# Single-event ingest (POST /logs)
# ---------------------------------------------------------------------------


@router.post(
    "",
    summary="Ingest one raw event (server-side normalization)",
    response_model=IngestResponse,
    status_code=201,
)
async def post_log(
    body: IngestRequest,
    background_tasks: BackgroundTasks,
    registry: dict[str, Any] = Depends(get_registry),
    store: Any = Depends(get_event_store),
    pipeline: Any = Depends(get_pipeline),
) -> IngestResponse:
    """POST /logs — ingest a single raw event.

    Accepts ``{source_type, source_id, data, received_at?}``.  Normalizes
    server-side via the owning plugin's ``normalize()`` (ADR-0029 D7.1 —
    pre-normalized ``SecurityEvent`` bodies are rejected by schema).

    On success, schedules ``background_analyze_and_alert`` for the source IP
    via FastAPI's ``BackgroundTasks`` mechanism and returns promptly.

    Status codes:
    - 201 Created  — event ingested (may be deduped).
    - 422           — unknown source_type or malformed body.
    - 503           — store or pipeline not available.
    """
    _require_store(store)
    _require_pipeline(pipeline)
    plugin = _resolve_plugin(body.source_type, registry)

    raw = _build_raw_event(body)
    event = _normalize_or_422(plugin, raw, body.source_id, body.source_type)

    # Storage failures propagate (fatal per pipeline policy — not swallowed).
    inserted = await pipeline.ingest([event])
    total = 1
    deduped = total - inserted

    logger.info(
        "ingest.post_log source_type=%s source_id=%s source_ip=%s inserted=%d deduped=%d",
        body.source_type, body.source_id, event.source_ip, inserted, deduped,
    )

    background_tasks.add_task(pipeline.background_analyze_and_alert, event.source_ip)

    return IngestResponse(inserted=inserted, deduped=deduped)


# ---------------------------------------------------------------------------
# Batch ingest (POST /logs/batch)
# ---------------------------------------------------------------------------


@router.post(
    "/batch",
    summary="Ingest a bounded batch of raw events (server-side normalization)",
    response_model=IngestResponse,
    status_code=201,
)
async def post_log_batch(
    body: BatchIngestRequest,
    background_tasks: BackgroundTasks,
    registry: dict[str, Any] = Depends(get_registry),
    store: Any = Depends(get_event_store),
    pipeline: Any = Depends(get_pipeline),
) -> IngestResponse:
    """POST /logs/batch — ingest a bounded list of raw events.

    Accepts ``{events: [{source_type, source_id, data, received_at?}, ...]}``.
    Bounded by ``FIREWATCH_MAX_BATCH_SIZE`` env var (default 100; ADR-0029 D7.2 /
    ADR-0006).  Over-limit bodies are rejected with 422 before any persistence.

    All events are normalized server-side via their respective plugin's ``normalize()``.
    A single unknown or unnormalizable event in the batch fails the entire batch with 422
    (transactional semantics — partial ingest is not reported; the caller retries
    the corrected batch).

    On success, schedules ``background_analyze_and_alert`` for each distinct
    ``source_ip`` in the batch.

    Status codes:
    - 201 Created  — batch ingested (deduped events are absorbed, not counted as errors).
    - 422           — batch exceeds limit, unknown source_type, or malformed event.
    - 503           — store or pipeline not available.
    """
    _require_store(store)
    _require_pipeline(pipeline)

    # Batch-size gate (ADR-0029 D7.2 / ADR-0006 config-overridable).
    max_size = _max_batch_size()
    if len(body.events) > max_size:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Batch size {len(body.events)} exceeds the maximum of {max_size} "
                "(ADR-0029 D7.2). Split the batch and retry."
            ),
        )

    # Normalize all events before any persistence (fail-fast on bad source_type / data).
    normalized = []
    for idx, req in enumerate(body.events):
        plugin = _resolve_plugin(req.source_type, registry)
        raw = _build_raw_event(req)
        event = _normalize_or_422(plugin, raw, req.source_id, req.source_type, idx=idx)
        normalized.append(event)

    # Storage failures propagate (fatal per pipeline policy).
    inserted = await pipeline.ingest(normalized)
    total = len(normalized)
    deduped = total - inserted

    logger.info(
        "ingest.post_log_batch events=%d inserted=%d deduped=%d",
        total, inserted, deduped,
    )

    # Schedule background analyze for each distinct source IP (deduplicated).
    for ip in {e.source_ip for e in normalized}:
        background_tasks.add_task(pipeline.background_analyze_and_alert, ip)

    return IngestResponse(inserted=inserted, deduped=deduped)
