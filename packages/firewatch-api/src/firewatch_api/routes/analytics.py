"""Analytics routes — GET /analytics/* (ADR-0029 D1, MB.1).

Thin controllers delegating to store methods.  No business logic here.

OCSF field mapping is preserved in the store's output (ADR-0029 D4 / ADR-0020):
the API is the view at the boundary, not a second mapping layer.

Issue #533 (A2): adds /analytics/asn (ranked ASN aggregation) and
/analytics/asn/{asn}/narration (one-click local-LLM narrative for an ASN,
reusing ML-7 narration helpers from firewatch_core.ai.narration).

Imports only firewatch-sdk and firewatch-core. Never imports legacy/.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from firewatch_api.deps import get_event_store, get_pipeline, parse_iso_or_422

logger = logging.getLogger("firewatch.api.analytics")

router = APIRouter(prefix="/analytics", tags=["analytics"])


def _require_store(store: Any) -> Any:
    """Raise 503 if the event store is not available."""
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")
    return store


@router.get(
    "/geo",
    summary="Server-side geo points for mapped IPs",
)
async def get_analytics_geo(
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return geo-enriched IP points from the ip_geo cache."""
    _require_store(store)
    return await store.get_analytics_geo()  # type: ignore[return-value]


@router.get(
    "/summary",
    summary="Analytics aggregate (total IPs, events, blocked, top country/rule)",
)
async def get_analytics_summary(
    store: Any = Depends(get_event_store),
) -> dict[str, Any]:
    """Return an analytics aggregate dict."""
    _require_store(store)
    return await store.get_analytics_summary()  # type: ignore[return-value]


@router.get(
    "/categories-timeline",
    summary="Blocked events per category per time period",
)
async def get_categories_timeline(
    start: str | None = Query(default=None, description="ISO datetime or date string"),
    end: str | None = Query(default=None, description="ISO datetime or date string"),
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return blocked events per category per period (daily/hourly).

    Raises 422 when ``start`` or ``end`` is not a valid ISO-8601 datetime
    (ADR-0029 D3: query-validation failures must return 422, not 500).
    """
    _require_store(store)
    start = parse_iso_or_422("start", start)
    end = parse_iso_or_422("end", end)
    return await store.get_categories_timeline(start=start, end=end)  # type: ignore[return-value]


@router.get(
    "/attack-dispositions",
    summary="Cross-tab of attack category × disposition (action) — top-5 + Other",
)
async def get_attack_dispositions(
    top_n: int = Query(default=5, ge=1, le=20, description="Top N attack categories to return"),
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return [{attack_type, action, count}] rows for the top-N attack categories.

    Bounded to top_n categories plus an "Other" bucket for the tail (issue #214).
    Covers all observed actions (BLOCK, DROP, ALERT, ALLOW, LOG).
    Returns an empty list when no categorized events exist.

    Additive endpoint — no existing response shapes are changed (ADR-0029 D1).
    """
    _require_store(store)
    return await store.get_attack_dispositions(top_n=top_n)  # type: ignore[return-value]


@router.get(
    "/asn",
    summary="Ranked ASN / infrastructure aggregation (issue #533, A2)",
)
async def get_analytics_asn(
    top_n: int = Query(
        default=15,
        ge=1,
        le=100,
        description="Top N ASNs to return, ordered by total_events descending.",
    ),
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return [{asn, as_name, total_events, distinct_ips, blocked, blocked_pct}] rows.

    Groups ip_geo JOIN logs by asn/as_name to expose the infrastructure-level
    threat lens.  Bounded to top_n ASNs (default 15).

    Issue #533 A2 — EARS-2.  Additive endpoint — no existing shapes changed.
    Zero-egress: all data comes from the local ip_geo cache (ADR-0022/0047).
    """
    _require_store(store)
    return await store.get_analytics_asn(top_n=top_n)  # type: ignore[return-value]


@router.get(
    "/asn/{asn}/narration",
    summary="One-click local-LLM narrative for an ASN (issue #533, A2 EARS-5)",
)
async def get_asn_narration(
    asn: int,
    ai: bool = Query(
        default=True,
        description=(
            "Set to false to skip the LLM and return a rule-only summary "
            "(ai_status='skipped', provenance='rule'). "
            "ML-7 EARS-4 degrade contract."
        ),
    ),
    store: Any = Depends(get_event_store),
    pipeline: Any = Depends(get_pipeline),
) -> dict[str, Any]:
    """Return a SHORT narrative for the given ASN grounded in its analytics row.

    Reuses the ML-7 narration helpers (firewatch_core.ai.narration) generalised
    for an ASN entity rather than a single IP.  Degrades to a rule-only narrative
    when the LLM is unavailable (same degrade contract as /threats/{ip}/narration).

    **ADR-0035 provenance:**
        - ``"rule"``  — LLM not called (offline / ai=false).
        - ``"ai"``    — LLM authored the narrative.

    **ADR-0015:** advisory only — no SOAR/block actions.
    **ADR-0022/0047:** zero-egress — local LLM only.

    Returns **404** when the ASN has no stored events.
    Returns **503** when the store is unavailable.
    """
    _require_store(store)

    # Fetch the aggregated row for this ASN (scan top-100 to find it).
    rows: list[dict[str, Any]] = await store.get_analytics_asn(top_n=100)
    asn_row: dict[str, Any] | None = next(
        (r for r in rows if r.get("asn") == asn), None
    )
    if asn_row is None:
        raise HTTPException(
            status_code=404,
            detail=f"ASN {asn} has no stored events.",
        )

    from firewatch_core.ai.narration import (  # local import — no circular risk
        build_asn_narration_prompt,
        build_rule_only_asn_narration,
    )

    if not ai:
        # Caller opted out of AI — return rule-only immediately.
        result = build_rule_only_asn_narration(asn_row)
        result["asn"] = asn
        result["ai_status"] = "skipped"
        return result

    # Determine whether the LLM is available.
    ai_engine = getattr(pipeline, "ai_engine", None) if pipeline is not None else None
    ai_available = ai_engine is not None

    if ai_available:
        try:
            narration_prompt = build_asn_narration_prompt(asn_row)
            asn_label = f"AS{asn}"
            total_events = int(asn_row.get("total_events", 0))
            blocked = int(asn_row.get("blocked", 0))
            samples = [{"rule_id": "asn_narration", "category": "asn_narration",
                        "count": 1, "payload": ""}]
            raw: dict[str, Any] = await ai_engine.analyze_concise(
                ip=asn_label,
                total_events=total_events,
                blocked_events=blocked,
                rules_triggered=1,
                first_seen="",
                last_seen="",
                samples=samples,
                security_mode=False,
                _narration_prompt=narration_prompt,
            )
            narrative_text: str = (
                raw.get("narrative")
                or raw.get("intent")
                or raw.get("executive_summary")
                or ""
            )
            collected: list[str] = []
            if "PROVENANCE:" in narrative_text:
                parts_split = narrative_text.split("PROVENANCE:", 1)
                narrative_text = parts_split[0].strip()
                prov_line = parts_split[1].strip() if len(parts_split) > 1 else ""
                collected = [f.strip() for f in prov_line.split(",") if f.strip()]
            return {
                "asn": asn,
                "narrative": narrative_text,
                "provenance": "ai",
                "collected_fields": collected,
                "ai_status": "ok",
            }
        except Exception:
            logger.warning(
                "analytics.get_asn_narration: LLM call failed for ASN %s — degrading to rule-only",
                asn,
            )

    # Rule-only fallback (AI unavailable or LLM call failed).
    result = build_rule_only_asn_narration(asn_row)
    result["asn"] = asn
    return result
