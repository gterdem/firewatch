"""Escalation policy route — GET /escalation/policy (issue #650, ADR-0058 D1/D6, ADR-0059 D6).

Exposes a read-only view of the ``ESCALATION_POLICY`` registry (declared severity +
``auto_escalate`` per detection rule) together with a rolling 24h hit-count derived
by running the detector against persisted events in the event store.

Design constraints
------------------
- Read-only.  The registry is finalized at module import time; no mutation path here.
- No new table.  Hit-counts are computed by fetching per-IP events from the ``logs``
  table (via ``store.get_by_ip_since``) and running ``detector.detect()`` in-process.
- Every registered detection appears in the response even with a count of 0.
- Empty store → all zeros, no error.

ADR-0058 D1/D6: exposes the policy registry.
ADR-0059 D6: Triage threshold lives in RuntimeConfig; this endpoint is read-only data.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from firewatch_api.deps import get_event_store
from firewatch_core.detector import detect
from firewatch_core.escalation.policy import ESCALATION_POLICY
from firewatch_sdk.models import SeverityLiteral

logger = logging.getLogger("firewatch.api.escalation")

router = APIRouter(prefix="/escalation", tags=["escalation"])

_WINDOW_HOURS: int = 24


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class PolicyRow(BaseModel):
    """One entry in the escalation policy registry view."""

    rule_name: str = Field(description="Correlation rule identifier.")
    severity: SeverityLiteral | None = Field(
        description="Sigma-anchored severity declared by the rule, or null if undeclared."
    )
    auto_escalate: bool = Field(
        description="True when the rule jumps the triage queue without volume/AI confirmation."
    )
    hit_count_24h: int = Field(
        description="Number of times this rule fired across all IPs in the last 24 hours."
    )


class EscalationPolicyResponse(BaseModel):
    """Response for GET /escalation/policy."""

    policy: list[PolicyRow] = Field(
        description="One row per registered detection rule."
    )
    generated_at: str = Field(
        description="ISO-8601 UTC timestamp when this response was generated."
    )


# ---------------------------------------------------------------------------
# Hit-count aggregation helper
# ---------------------------------------------------------------------------


async def _count_rule_hits_24h(store: Any) -> dict[str, int]:
    """Return a mapping of rule_name → hit count for the last 24 hours.

    Iterates every IP in the store, fetches its events since the 24h cutoff,
    runs the detector, and tallies detections by rule name.

    Returns an empty dict when the store has no events — callers apply the
    zero-default for registered rules that did not fire.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_WINDOW_HOURS)
    hits: dict[str, int] = defaultdict(int)

    try:
        ips: list[str] = await store.get_all_ips()
    except Exception:
        logger.exception("escalation/policy: get_all_ips failed")
        return {}

    for ip in ips:
        try:
            events = await store.get_by_ip_since(ip, cutoff)
        except Exception:
            logger.exception("escalation/policy: get_by_ip_since failed for ip=%s", ip)
            continue
        for detection in detect(events):
            hits[detection.rule_name] += 1

    return dict(hits)


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@router.get(
    "/policy",
    summary="Escalation policy registry with 24h detection hit-counts",
    response_model=EscalationPolicyResponse,
)
async def get_escalation_policy(
    store: Any = Depends(get_event_store),
) -> EscalationPolicyResponse:
    """Return the escalation policy registry (severity + auto_escalate per rule) and
    rolling 24h detection hit-counts.

    The registry is read-only — finalized at import time in ``detector.py``.
    Hit-counts are derived from stored events; no new table is created.
    Every registered detection appears even when its hit_count_24h is 0.
    """
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")

    hits = await _count_rule_hits_24h(store)
    now_iso = datetime.now(timezone.utc).isoformat()

    # Iterate the registry's internal dict to emit all registered rules.
    # _policies is the authoritative source; get_or_default covers unregistered
    # rule names but here we only emit rules that were explicitly registered.
    rows: list[PolicyRow] = [
        PolicyRow(
            rule_name=rule_name,
            severity=policy.severity,
            auto_escalate=policy.auto_escalate,
            hit_count_24h=hits.get(rule_name, 0),
        )
        for rule_name, policy in ESCALATION_POLICY._policies.items()
    ]

    return EscalationPolicyResponse(policy=rows, generated_at=now_iso)
