"""OCSF 1.8.0 export routes (ADR-0040 / MI-5 #386).

  GET /export/ocsf/events   — normalized events serialized to OCSF 1.8.0
  GET /export/ocsf/findings — scored threats serialized as Detection Finding 2004

Both routes are read-only (ADR-0040, ADR-0020) and use cursor-pagination
mirroring the existing logs.py paginated pattern (ADR-0029 D2).

Route class: read (ADR-0026).  No auth gating in this milestone (loopback-only).

Imports only firewatch-sdk and firewatch-api.ocsf.*. Never imports legacy/.
"""
from __future__ import annotations

import base64
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from firewatch_sdk.models import FilterSpec, SecurityEvent, ThreatScore

from firewatch_api.deps import get_event_store, get_pipeline
from firewatch_api.ocsf import serializer as ocsf_ser

logger = logging.getLogger("firewatch.api.export")

router = APIRouter(prefix="/export/ocsf", tags=["export"])

# Maximum evidences per finding (DoS guard — ADR-0040 / BLOCKING-1).
# Matches the default limit of get_events_for_timeline (200).
# When the true event count exceeds this, finding_info.total_evidence_count
# signals the true total so consumers know evidences were capped.
_EVIDENCES_CAP = 200

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_store(store: Any) -> Any:
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")
    return store


def _require_pipeline(pipeline: Any) -> Any:
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not available")
    return pipeline


def _row_to_security_event(row: dict[str, Any]) -> SecurityEvent | None:
    """Convert a store log row dict to a SecurityEvent for OCSF serialization.

    Log rows come from store.get_paginated / get_recent — they contain the
    canonical SecurityEvent fields persisted by the normalizer.  Fields that
    were not persisted default to None.

    Returns None for rows that are structurally invalid (missing source_ip or
    source_type) — callers skip these silently.
    """
    source_ip = row.get("source_ip") or ""
    source_type = row.get("source_type") or ""
    if not source_ip or not source_type:
        return None

    # Timestamps stored as ISO-8601 strings — parse with fromisoformat.
    from datetime import datetime, timezone

    raw_ts = row.get("timestamp")
    try:
        if raw_ts:
            ts_str = str(raw_ts).replace("Z", "+00:00")
            timestamp = datetime.fromisoformat(ts_str)
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)
    except (ValueError, AttributeError):
        timestamp = datetime.now(timezone.utc)

    action_str = str(row.get("action") or "ALLOW")

    # ocsf_class / ocsf_category stored in the logs table (ADR-0020)
    ocsf_class = row.get("ocsf_class")
    ocsf_category = row.get("ocsf_category")

    return SecurityEvent(
        source_type=source_type,
        source_id=str(row.get("source_id") or ""),
        timestamp=timestamp,
        source_ip=source_ip,
        source_port=_int_or_none(row.get("source_port")),
        destination_ip=row.get("destination_ip") or None,
        destination_port=_int_or_none(row.get("destination_port")),
        protocol=row.get("protocol") or None,
        action=action_str,  # type: ignore[arg-type]
        category=row.get("category") or None,
        severity=row.get("severity") or None,  # type: ignore[arg-type]
        rule_id=row.get("rule_id") or None,
        rule_name=row.get("rule_name") or None,
        payload_snippet=row.get("payload_snippet") or None,
        attack_technique=row.get("attack_technique") or None,
        attack_tactic=row.get("attack_tactic") or None,
        ocsf_class=int(ocsf_class) if ocsf_class is not None else None,
        ocsf_category=int(ocsf_category) if ocsf_category is not None else None,
        raw_log=row.get("raw_log") if isinstance(row.get("raw_log"), dict) else None,
    )


def _int_or_none(value: Any) -> int | None:
    """Safely convert a value to int, returning None on failure."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# GET /export/ocsf/events
# ---------------------------------------------------------------------------


@router.get(
    "/events",
    summary="Export normalized events in OCSF 1.8.0 format",
)
async def export_ocsf_events(
    cursor: str | None = Query(default=None, description="Opaque continuation token"),
    limit: int = Query(default=100, ge=1, le=1000, description="Page size"),
    source_type: str | None = Query(default=None),
    severity: str | None = Query(default=None, description="critical/high/medium/low"),
    ip: str | None = Query(default=None, description="Substring match on source_ip"),
    store: Any = Depends(get_event_store),
) -> dict[str, Any]:
    """Return cursor-paginated OCSF 1.8.0 events.

    Each item is a dict representing the OCSF activity class for the event:
      Azure WAF events  → HTTP Activity (class_uid=4002)
      Suricata IDS      → Detection Finding (class_uid=2004)
      Suricata network  → Network Activity (class_uid=4001)

    The pagination envelope mirrors GET /logs/paginated:
      {items, next_cursor, has_more, total_matching}

    Read-only (ADR-0040, ADR-0026).
    """
    _require_store(store)

    filters = FilterSpec(
        cursor=cursor,
        source_type=source_type,
        severity=severity,
        ip=ip,
    )
    raw_page: dict[str, Any] = await store.get_paginated(limit=limit, filters=filters)

    rows: list[dict[str, Any]] = raw_page.get("logs") or []
    ocsf_items: list[dict[str, Any]] = []

    for row in rows:
        ev = _row_to_security_event(row)
        if ev is None:
            continue
        try:
            ocsf_items.append(ocsf_ser.event_to_ocsf(ev))
        except Exception:
            logger.exception("Failed to serialize event row to OCSF: %r", row.get("id"))
            # Skip malformed rows rather than failing the whole page.

    return {
        "items": ocsf_items,
        "next_cursor": raw_page.get("next_cursor"),
        "has_more": raw_page.get("has_more", False),
        "total_matching": raw_page.get("total_matching", 0),
    }


# ---------------------------------------------------------------------------
# GET /export/ocsf/findings
# ---------------------------------------------------------------------------


def _decode_cursor(cursor: str | None) -> int:
    """Decode an opaque findings cursor to an integer offset.

    The cursor is base64(str(offset)) — a plain integer encoded to keep the raw
    IP out of the API surface (ADR-0029 D2 opaque-token requirement).  Any
    malformed cursor silently falls back to offset 0 (first page) so the caller
    never receives a 500 (ADR-0029 EARS unwanted criterion).
    """
    if not cursor:
        return 0
    try:
        return int(base64.b64decode(cursor).decode())
    except Exception:
        return 0


def _encode_cursor(offset: int) -> str:
    """Encode an integer offset as an opaque base64 continuation token."""
    return base64.b64encode(str(offset).encode()).decode()


@router.get(
    "/findings",
    summary="Export scored threats as OCSF 1.8.0 Detection Findings",
)
async def export_ocsf_findings(
    cursor: str | None = Query(default=None, description="Opaque continuation token"),
    limit: int = Query(default=100, ge=1, le=1000, description="Page size"),
    store: Any = Depends(get_event_store),
    pipeline: Any = Depends(get_pipeline),
) -> dict[str, Any]:
    """Return scored IPs as OCSF 1.8.0 Detection Findings (class_uid=2004).

    Each finding:
      - class_uid=2004, category_uid=2, type_uid=200401, activity_id=1 (Create)
      - metadata.version="1.8.0"
      - severity_id from threat_level
      - disposition_id from dominant action in contributing events
      - evidences populated from the actor's contributing events (recomputed at
        read time — ADR-0041; reuses get_events_with_row_ids path from MI-6)
        CAPPED at _EVIDENCES_CAP (200) to bound response size (DoS guard).
        finding_info.total_evidence_count signals the true event count.
      - attacks from MITRE ATT&CK data on contributing events (ADR-0014)

    The pagination envelope mirrors GET /logs/paginated:
      {items, next_cursor, has_more, total_matching}

    Cursor: opaque base64-encoded integer offset into the lexicographically
    sorted distinct-IP list (ADR-0029 D2 opaque-token pattern). A malformed
    cursor falls back to the first page — never 500.

    Read-only (ADR-0040, ADR-0026).
    """
    _require_store(store)
    _require_pipeline(pipeline)

    # Fetch distinct IPs — the findings surface is one finding per IP.
    # Sort lexicographically for a stable, resumable order (cursor relies on this).
    all_ips: list[str] = sorted(await store.get_all_ips())
    total_ips = len(all_ips)

    # Decode the opaque cursor into an integer offset; invalid cursor -> 0 (first page).
    offset = _decode_cursor(cursor)
    page_ips = all_ips[offset : offset + limit]

    ocsf_items: list[dict[str, Any]] = []

    for ip in page_ips:
        try:
            # Score the IP (rules-only — no AI call; consistent with MI-6 evidence path).
            score: ThreatScore = await pipeline.analyze_ip(ip, use_ai=False)
            if score.total_events == 0:
                continue

            # Fetch contributing events with row ids (ADR-0041 / MI-6 reuse path).
            # Cap at _EVIDENCES_CAP to bound response size (DoS guard — BLOCKING-1).
            all_rows: list[dict[str, Any]] = await store.get_events_with_row_ids(ip)
            rows = all_rows[:_EVIDENCES_CAP]
            true_event_count = len(all_rows)

            # Convert rows to SecurityEvents for evidences and MITRE extraction.
            contributing: list[SecurityEvent] = []
            for r in rows:
                ev = _row_to_security_event(r)
                if ev is not None:
                    contributing.append(ev)

            finding = ocsf_ser.threat_to_detection_finding(
                threat=score,
                contributing_events=contributing,
                total_evidence_count=true_event_count,
            )
            ocsf_items.append(finding)
        except Exception:
            logger.exception("Failed to serialize finding for IP %s", ip)
            continue

    next_offset = offset + limit
    has_more = next_offset < total_ips
    next_cursor = _encode_cursor(next_offset) if has_more else None

    return {
        "items": ocsf_items,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "total_matching": total_ips,
    }
