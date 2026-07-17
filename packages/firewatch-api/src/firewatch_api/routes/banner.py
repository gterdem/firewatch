"""Banner route — GET /banner/summary (issue #55 Part 1/backend).

Extends #43's aggregate "N detections on the record" banner-feed line (same
slot) with the ADR-0070 attempt vocabulary — attempt_count, actor_count,
succeeded_count, queue_size, and a bounded top-N pressure strip. All counts
are computed server-side from ``firewatch_core.attempts`` (the D1 attempt
predicate) plus the existing ``detect()``/``decide()`` verdicts — this route
never re-derives what qualifies; ``firewatch_api.banner_assembler`` only
aggregates (read-only consumer of the escalation engine).

Window slicing mirrors ``pipeline.analyze_ip`` exactly (ADR-0070 D4) so this
endpoint's counts are always consistent with the per-actor ``ThreatScore``
verdicts already shown in the triage-banner chips: each actor's full lifetime
event list is fetched once, then sliced into ``W_STATE`` (24h, feeds
``decide()``) and ``W_CAMPAIGN`` (7d, feeds ``detect()``) at this seam only —
same pattern as ``pipeline.py`` and ``routes/escalation.py``.

Imports firewatch-sdk and firewatch-core only. Never imports legacy/.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from firewatch_sdk.models import SecurityEvent

from firewatch_core.detector import detect
from firewatch_core.escalation.decider import decide
from firewatch_core.pipeline import W_CAMPAIGN, W_STATE

from firewatch_api.banner_assembler import (
    ActorAttemptStats,
    assemble_banner_attempt_summary,
    compute_actor_attempt_stats,
)
from firewatch_api.deps import get_event_store
from firewatch_api.schemas import BannerAttemptSummary, PressureEntry

logger = logging.getLogger("firewatch.api.banner")

router = APIRouter(prefix="/banner", tags=["banner"])


def _window_slice(
    events: list[SecurityEvent], now: datetime, window: timedelta
) -> list[SecurityEvent]:
    """Return the subset of *events* at or after ``now - window``.

    Duplicated (not imported) from ``pipeline._window_slice`` — the same
    trivial, stable filter, kept local to avoid a firewatch-api -> internal
    ``pipeline`` private-symbol dependency across the package boundary. Naive
    timestamps are treated as UTC, matching the canonical implementation.
    """
    cutoff = now - window
    return [
        e for e in events
        if (e.timestamp if e.timestamp.tzinfo is not None else e.timestamp.replace(tzinfo=timezone.utc))
        >= cutoff
    ]


async def _collect_actor_stats(store: Any, now: datetime) -> list[ActorAttemptStats]:
    """Fetch every actor's lifetime events and derive its ActorAttemptStats.

    One store round-trip per actor (``get_by_ip``) — the same N+1 pattern
    ``GET /threats`` and ``GET /escalation/policy`` already use for
    per-actor aggregation; no new table, no persisted state.
    """
    ips: list[str] = await store.get_all_ips()
    stats: list[ActorAttemptStats] = []
    for ip in ips:
        try:
            events = await store.get_by_ip(ip)
        except Exception:
            logger.exception("banner.summary: get_by_ip failed for ip=%s", ip)
            continue
        if not events:
            continue

        state_events = _window_slice(events, now, W_STATE)
        campaign_events = _window_slice(events, now, W_CAMPAIGN)

        # detect()/decide() called exactly as pipeline.analyze_ip calls them
        # (ADR-0070 D4) — detections over the campaign window, decide() over
        # the state window + those same detections — so this actor's tier
        # here is IDENTICAL to the tier already shown in its triage chip.
        detections = detect(campaign_events, now=now)
        verdict = decide(state_events, detections)

        stats.append(
            compute_actor_attempt_stats(
                ip,
                state_events=state_events,
                campaign_events=campaign_events,
                detections=detections,
                verdict=verdict,
                now=now,
            )
        )
    return stats


@router.get(
    "/summary",
    summary="Attempt/actor/succeeded/queue counts and top-N pressure strip for the triage banner",
    response_model=BannerAttemptSummary,
)
async def get_banner_summary(
    store: Any = Depends(get_event_store),
) -> BannerAttemptSummary:
    """Return the additive banner-feed attempt summary (issue #55).

    Empty store -> all-zero summary, empty ``top_pressure`` (200 OK, not an
    error) — the existing calm/all-clear banner state renders unchanged
    (EARS: WHEN no attempts exist, the calm state SHALL render unchanged).

    Returns **503** when the event store is not available.
    """
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")

    now = datetime.now(timezone.utc)
    stats = await _collect_actor_stats(store, now)
    summary = assemble_banner_attempt_summary(stats)

    return BannerAttemptSummary(
        attempt_count=summary.attempt_count,
        actor_count=summary.actor_count,
        succeeded_count=summary.succeeded_count,
        queue_size=summary.queue_size,
        top_pressure=[
            PressureEntry(
                source_ip=row.source_ip,
                attempt_count=row.attempt_count,
                span_minutes=row.span_minutes,
            )
            for row in summary.top_pressure
        ],
        generated_at=now.isoformat(),
    )
