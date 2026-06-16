"""Log routes — GET /logs/* (ADR-0029 D1, MB.1).

Thin controllers delegating entirely to store methods.  No business logic here.

Cursor-pagination (ADR-0029 D2):
  ``GET /logs/paginated`` returns the store's ``{logs, next_cursor, has_more,
  total_matching}`` envelope verbatim — keys are NEVER renamed.  Filter params
  are 1:1 with ``FilterSpec`` fields (ADR-0029 D2 constraint: no API-only filters
  invented here).

``raw_log`` and native source fields in log rows are attacker-controlled telemetry
(ADR-0029 D3 untrusted data).  The API emits them as opaque data; consumers MUST
escape on render.

ML-12 (issue #440): GET /logs/dga-suspects returns DNS rows whose dns_query scored
above the DGA FLAG_THRESHOLD via local heuristic analysis (zero-egress).
Rows with NULL dns_query are excluded (EARS-2).

Imports only firewatch-sdk and firewatch-core. Never imports legacy/.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from firewatch_sdk.models import FilterSpec

from firewatch_core.analytics.dga import DEFAULT_TOP_N, MAX_TOP_N, get_dga_suspects

from firewatch_api.deps import get_event_store, logs_filterspec, parse_iso_or_422
from firewatch_api.schemas import LogsStatsResponse, PaginatedLogsResponse

logger = logging.getLogger("firewatch.api.logs")

router = APIRouter(prefix="/logs", tags=["logs"])


def _require_store(store: Any) -> Any:
    """Raise 503 if the event store is not available."""
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")
    return store


@router.get(
    "/paginated",
    summary="Cursor-paginated logs with facet filters",
    response_model=PaginatedLogsResponse,
)
async def get_paginated(
    cursor: str | None = Query(default=None, description="Opaque continuation token"),
    limit: int = Query(default=100, ge=1, le=1000, description="Page size"),
    source_type: str | None = Query(default=None),
    source_id: str | None = Query(default=None),
    category: str | None = Query(
        default=None,
        description=(
            "Canonical stored category value (exact match) or legacy shorthand alias "
            "(sqli/xss/lfi/cmdi/proto/anomaly/bot/ratelimit/geo); 'all' = no filter (issue #325)."
        ),
    ),
    category_name: str | None = Query(
        default=None,
        description="DEPRECATED — synonym for category= exact match; use category= instead.",
    ),
    severity: str | None = Query(default=None, description="critical/high/medium/low"),
    ip: str | None = Query(default=None, description="Substring match on source_ip"),
    action: str | None = Query(
        default=None,
        description=(
            "Exact action value (ALLOW/BLOCK/DROP/ALERT) or the shorthand "
            "'blocked' (case-insensitive) which matches action ∈ {BLOCK, DROP} (issue #252)."
        ),
    ),
    rule: str | None = Query(default=None, description="Substring match on rule_id"),
    q: str | None = Query(default=None, description="Free-text search"),
    # ML-3 (issue #431) — destination dimension filters (EARS-1)
    destination_ip: str | None = Query(
        default=None,
        description="Substring match on destination_ip (ML-3, issue #431).",
    ),
    protocol: str | None = Query(
        default=None,
        description=(
            "Exact match on protocol (e.g. TCP/UDP/ICMP). "
            "Sources that do not populate protocol (e.g. Azure WAF) will not match. "
            "(ML-3, issue #431)."
        ),
    ),
    # ML-13 (issue #441) — JA4+ fingerprint facet (EARS-1, consume-only)
    tls_ja4: str | None = Query(
        default=None,
        description=(
            "Exact match on JA4 TLS fingerprint (ML-13, issue #441). "
            "Consume-only: only non-null sensor rows participate. "
            "NULL tls_ja4 means the sensor did not emit JA4 — never fabricated."
        ),
    ),
    store: Any = Depends(get_event_store),
) -> dict[str, Any]:
    """Return cursor-paginated logs.

    The response envelope ``{logs, next_cursor, has_more, total_matching}`` is
    the store's envelope verbatim (ADR-0029 D2 — one source of truth).

    A malformed ``cursor`` yields a well-formed first/empty-page envelope rather
    than a 500 (the store tolerates this; ADR-0029 D2 EARS unwanted criterion).

    ML-3 (issue #431): ``destination_ip`` (substring) and ``protocol`` (exact) are
    additive filters backed 1:1 by store WHERE clauses.  Both are optional.

    ML-13 (issue #441): ``tls_ja4`` (exact) facets by JA4 fingerprint — consume-only;
    only sensor-populated rows participate (NULL = sensor did not emit JA4).
    """
    _require_store(store)
    filters = FilterSpec(
        cursor=cursor,
        source_type=source_type,
        source_id=source_id,
        category=category,
        category_name=category_name,
        severity=severity,
        ip=ip,
        action=action,
        rule=rule,
        q=q,
        destination_ip=destination_ip,
        protocol=protocol,
        tls_ja4=tls_ja4,
    )
    return await store.get_paginated(limit=limit, filters=filters)  # type: ignore[return-value]


@router.get(
    "/top-pairs",
    summary="Top source→destination IP pairs by event count (ML-3, issue #431)",
)
async def get_top_pairs(
    top_n: int = Query(
        default=10,
        ge=1,
        le=1000,
        description="Maximum number of pairs to return (1–1000, default 10).",
    ),
    filters: FilterSpec = Depends(logs_filterspec),
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return the top ``top_n`` (source_ip → destination_ip) pairs by event count.

    Pairs where ``destination_ip`` is NULL are excluded (they carry no
    destination-dimension signal — e.g. Azure WAF rows whose L7-only source
    does not populate a destination IP).

    Response: ``[{source_ip: str, destination_ip: str, count: int}]``
    ordered by count descending.  Bounded by ``top_n`` (default 10, max 1 000).

    SECURITY (ADR-0029 D3): ``source_ip`` and ``destination_ip`` are
    attacker-controlled telemetry — consumers MUST render them as text nodes only.
    """
    _require_store(store)
    return await store.get_top_pairs(top_n=top_n, filters=filters)  # type: ignore[return-value]


@router.get(
    "/recent",
    summary="Most-recent logs (split attack / non-attack)",
)
async def get_recent(
    limit: int = Query(default=100, ge=1, le=1000),
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return the most-recent log rows (50/50 attack vs non-attack, legacy parity)."""
    _require_store(store)
    return await store.get_recent(limit=limit)  # type: ignore[return-value]


@router.get(
    "/ip/{ip}",
    summary="All logs for a specific IP",
)
async def get_logs_by_ip(
    ip: str,
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return all log rows for *ip* as raw dicts (drill-down)."""
    _require_store(store)
    return await store.get_by_ip_raw(ip)  # type: ignore[return-value]


@router.get(
    "/categories",
    summary="Blocked-event counts grouped by stored category (canonical, issue #325)",
)
async def get_categories(
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return blocked-event counts grouped by the stored ``category`` column.

    Response: ``[{category: str, count: int}]`` ordered by count descending.
    Each label is the canonical ``SecurityEvent.category`` value stored at
    normalize-time.  NULL/empty category rows are aggregated under ``'Other'``.
    One entry per distinct stored value — structural guarantee from GROUP BY
    (no merge pass needed; fixes #322 class of duplicates structurally).
    Every label is a value that ``?category=<label>`` will filter against
    (shared-vocabulary contract, EARS-2 of issue #325).
    """
    _require_store(store)
    return await store.get_categories()  # type: ignore[return-value]


@router.get(
    "/category-summary",
    summary="Unique categories with counts (filter dropdown data)",
)
async def get_category_summary(
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return unique category names with event counts.

    Drives the Network Logs category filter dropdown.
    Backing method: ``store.get_category_summary`` (added in MB.1).
    """
    _require_store(store)
    return await store.get_category_summary()  # type: ignore[return-value]


@router.get(
    "/timeline",
    summary="Event counts over time (daily/hourly)",
)
async def get_timeline(
    start: str | None = Query(default=None, description="ISO datetime or date string"),
    end: str | None = Query(default=None, description="ISO datetime or date string"),
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return event counts over time.  Daily if span > 48 h, else hourly.

    Raises 422 when ``start`` or ``end`` is not a valid ISO-8601 datetime
    (ADR-0029 D3: query-validation failures must return 422, not 500).
    """
    _require_store(store)
    start = parse_iso_or_422("start", start)
    end = parse_iso_or_422("end", end)
    return await store.get_timeline(start=start, end=end)  # type: ignore[return-value]


@router.get(
    "/ips",
    summary="Distinct source IPs",
)
async def get_ips(
    store: Any = Depends(get_event_store),
) -> list[str]:
    """Return all distinct source IP addresses in the store."""
    _require_store(store)
    return await store.get_all_ips()  # type: ignore[return-value]


@router.get(
    "/top-talkers",
    summary="Top source IPs by event count (ML-4, issue #432)",
)
async def get_top_talkers(
    top_n: int = Query(
        default=10,
        ge=1,
        le=1000,
        description="Maximum number of IPs to return (1–1000, default 10).",
    ),
    filters: FilterSpec = Depends(logs_filterspec),
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return the top ``top_n`` source IPs by total event count.

    Response: ``[{source_ip: str, count: int, blocked: int}]``
    ordered by count descending.  Bounded by ``top_n`` (default 10, max 1 000).

    SECURITY (ADR-0029 D3): ``source_ip`` is attacker-controlled telemetry —
    consumers MUST render it as a text node only.
    """
    _require_store(store)
    return await store.get_top_talkers(top_n=top_n, filters=filters)  # type: ignore[return-value]


@router.get(
    "/protocol-mix",
    summary="Event counts grouped by protocol (ML-4, issue #432)",
)
async def get_protocol_mix(
    top_n: int = Query(
        default=10,
        ge=1,
        le=100,
        description="Maximum number of protocol rows to return (1–100, default 10).",
    ),
    filters: FilterSpec = Depends(logs_filterspec),
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return event counts grouped by protocol, bounded to ``top_n`` rows.

    NULL ``protocol`` values (e.g. Azure WAF rows) are aggregated under the
    sentinel value ``'(unknown)'`` — honest representation of L7-only sources.

    Response: ``[{protocol: str, count: int}]`` ordered by count descending.
    Bounded by ``top_n`` (default 10, max 100).

    SECURITY (ADR-0029 D3): ``protocol`` values are attacker-controlled telemetry
    normalised from plugin logs — consumers MUST render as text nodes only.
    """
    _require_store(store)
    return await store.get_protocol_mix(top_n=top_n, filters=filters)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# ML-12 (issue #440) — DGA suspects
# ---------------------------------------------------------------------------

#: Hard ceiling on top_n for the DGA suspects endpoint.
_DGA_TOP_N_CEILING: int = MAX_TOP_N


@router.get(
    "/dga-suspects",
    summary=(
        "DNS rows whose dns_query is DGA-suspected — local heuristic only "
        "(zero-egress, ML-12, issue #440)"
    ),
)
async def get_dga_suspects_route(
    top_n: int = Query(
        default=DEFAULT_TOP_N,
        ge=1,
        le=_DGA_TOP_N_CEILING,
        description=(
            f"Maximum number of DGA suspect rows to return "
            f"(1-{_DGA_TOP_N_CEILING}, default {DEFAULT_TOP_N})."
        ),
    ),
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return DNS log rows whose ``dns_query`` is likely DGA-generated.

    Detection is purely local, deterministic, and zero-egress — no DNS lookups
    or external reputation calls are made (EARS-2 / out-of-scope clause in
    issue #440).

    Heuristic signals (see ``firewatch_core.analytics.dga`` for citations):
      - Shannon entropy of the leftmost label
      - Consonant cluster ratio (DGA labels are typically unpronounceable)
      - Digit ratio (hash-derived DGA labels interleave digits)
      - Label length (empirical DGA range: 12-32 chars)
      - Unique-character ratio (DGA labels rarely repeat characters)
      - No-vowel bonus (near-zero vowels strongly indicates DGA)

    Provenance is RULE (deterministic), never AI.  The ``dga_score`` field in
    each row exposes the composite score for glass-box honesty.

    Rows where ``dns_query`` is NULL are excluded (EARS-2 — honest absence).

    Response: ``[dns_query, source_ip, timestamp, dga_score, entropy,
    consonant_ratio, digit_ratio, label_length]`` ordered by ``dga_score``
    descending.  Bounded by ``top_n`` (default 50, max 1000).

    Returns 503 when the event store is unavailable.
    Returns 422 when ``top_n`` is out of the valid range.

    SECURITY (ADR-0029 D3): ``dns_query`` and ``source_ip`` are
    attacker-controlled telemetry — consumers MUST render as text nodes only.
    """
    _require_store(store)
    return await get_dga_suspects(store, top_n=top_n)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# ML-13 (issue #441) — JA4 TLS fingerprint facet
# ---------------------------------------------------------------------------

@router.get(
    "/top-ja4",
    summary="Top JA4 TLS fingerprints by event count (ML-13, issue #441)",
)
async def get_top_ja4(
    top_n: int = Query(
        default=10,
        ge=1,
        le=100,
        description="Maximum number of fingerprints to return (1–100, default 10).",
    ),
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return the top ``top_n`` JA4 fingerprints by event count.

    Consume-only (ADR-0048 sub-decision): only rows where the sensor populated
    ``tls_ja4`` participate.  When all rows have NULL ``tls_ja4`` (e.g. older
    Suricata builds without JA4 support) this returns an empty list — honest
    absence, not an error.

    The value of this facet: pivot/group traffic by client TLS fingerprint to
    spot a single tool or malware family across many source IPs.

    Response: ``[{tls_ja4: str, count: int}]`` ordered by count descending.
    Bounded by ``top_n`` (default 10, max 100).

    SECURITY (ADR-0029 D3): ``tls_ja4`` is a fingerprint string normalised from
    attacker-controlled telemetry — consumers MUST render as text nodes only.
    """
    _require_store(store)
    return await store.get_top_ja4(top_n=top_n)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Issue #663 — filter-scoped totals for the Network Logs header strip
# ---------------------------------------------------------------------------


@router.get(
    "/stats",
    summary="Filter-scoped totals for the Network Logs header strip (issue #663)",
    response_model=LogsStatsResponse,
)
async def get_logs_stats(
    filters: FilterSpec = Depends(logs_filterspec),
    start: str | None = Query(default=None, description="ISO datetime or date string"),
    end: str | None = Query(default=None, description="ISO datetime or date string"),
    store: Any = Depends(get_event_store),
) -> LogsStatsResponse:
    """Return filter-scoped event totals for the Network Logs header strip.

    Counts are computed from a full table scan over the filtered scope — NOT
    summed from any top-N talker list (which was the previous front-end hack
    that understated real totals; issue #663 EARS-3).

    Response fields:
    - ``total_events``: COUNT(*) over the filtered scope.
    - ``blocked_events``: count where action IN (BLOCK, DROP).
    - ``distinct_ips``: COUNT(DISTINCT source_ip).
    - ``present_source_types``: sorted list of DISTINCT ``source_type`` values
      in scope (consumed by the source-type facet strip, issue #664).

    Accepts the same facet query params as ``/logs/paginated`` and
    ``/logs/top-talkers`` (via the shared ``logs_filterspec`` dependency, #662).
    Optional ``start``/``end`` ISO-8601 datetime strings narrow the time window;
    a malformed value returns 422 (ADR-0029 D3).

    Store unavailable → 503.
    """
    _require_store(store)
    start = parse_iso_or_422("start", start)
    end = parse_iso_or_422("end", end)
    result = await store.get_logs_stats(filters=filters, start=start, end=end)
    return LogsStatsResponse(**result)
