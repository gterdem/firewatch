"""Pure deterministic escalation decider — ADR-0058 D2 / Amendment 1 (A3-A5).

``decide(events, detections) -> EscalationVerdict``

Single home of the 4-tier action model.  **No I/O, no LLM, no side effects.**
Unit-testable in isolation; called from ``pipeline.analyze_ip``.

4-tier model (ADR-0058 §D2 / §4a):

| Tier | Action(s)                        | Disposition              | block_status |
|------|----------------------------------|--------------------------|--------------|
|  1   | ALLOW (with high-fidelity det.)  | allowed_through          | allowed      |
|  2   | ALERT / LOG                      | block_status_unknown     | unknown      |
|  3   | BLOCK/DROP — persistent          | blocked_persistent       | blocked      |
|  4   | BLOCK/DROP — one-off             | blocked_one_off          | blocked      |

Amendment 1 (ADR-0058 A3-A5) — full-tally rewrite:
- ``decide()`` no longer short-circuits on the first non-empty partition.
- All three partitions (allow / alert_log / block_drop) are counted before the
  verdict is assembled.
- ``block_status="partial"`` is emitted when events span more than one terminal
  disposition class (e.g. some ALERT/LOG AND some BLOCK/DROP).
- ``disposition_counts`` (structured integers) is attached to every verdict.
- Tier still derives from the loudest present action — priority UNCHANGED.
- A RULE-tagged mixed justification is built from engine integers only (no
  attacker-controlled fields — ADR-0035 / #648 / #642 discipline).

Standard alignment:
- OCSF disposition_id: ALLOW ≈ Allowed (id=1), BLOCK/DROP ≈ Blocked (id=2),
  ALERT/LOG ≈ non-terminating (no explicit OCSF disposition — "block status unknown").
  Ref: https://schema.ocsf.io/ (1.8.0).
- ADR-0035 provenance: ``justification`` is a RULE-tagged string (never LLM).
- ADR-0012: ALERT is an honest IDS non-blocking disposition.
- ``"partial"`` is a FireWatch extension (no OCSF equivalent) — ADR-0058 A1.

Persistence threshold: ≥ 3 BLOCK/DROP events for the same IP in the window.
This matches the brute-force threshold in scoring.py (10 is higher; 3 is the
lowest operationally meaningful "the adversary is persisting" bar).
"""
from __future__ import annotations

from firewatch_sdk.models import (
    Detection,
    DispositionCounts,
    EscalationVerdict,
    SecurityEvent,
)

# Number of BLOCK/DROP events required to classify the adversary as "persistent"
# (Tier 3 rather than Tier 4 informational).  Consistent with the "adversary tried
# more than once" definition in ADR-0058 §D2.
_PERSISTENCE_THRESHOLD = 3


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _tally(events: list[SecurityEvent]) -> tuple[int, int, int]:
    """Return (block_drop_count, alert_log_count, allow_count) for *events*.

    One concern: partition the event list into three mutually exclusive terminal
    classes and return their sizes.  Pure; no side effects.
    """
    block_drop = sum(1 for e in events if e.action in ("BLOCK", "DROP"))
    alert_log = sum(1 for e in events if e.action in ("ALERT", "LOG"))
    allow = sum(1 for e in events if e.action == "ALLOW")
    return block_drop, alert_log, allow


def _is_mixed(block_drop: int, alert_log: int, allow: int) -> bool:
    """Return True when events span more than one terminal disposition class."""
    # Count how many classes have at least one event.
    present = sum(1 for n in (block_drop, alert_log, allow) if n > 0)
    return present > 1


def _disposition_counts(block_drop: int, alert_log: int, allow: int) -> DispositionCounts:
    return DispositionCounts(
        blocked=block_drop,
        alert_unknown=alert_log,
        allowed=allow,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def decide(
    events: list[SecurityEvent],
    detections: list[Detection],
) -> EscalationVerdict:
    """Map (events, detections) to a deterministic EscalationVerdict.

    Pure function — no I/O, no LLM.  Returns the loudest applicable tier.

    Amendment 1: all three partitions are tallied before producing the verdict.
    Mixed actors (events span >1 terminal class) receive ``block_status="partial"``
    and a RULE-tagged mixed justification.  Single-class actors keep the exact
    pre-amendment behaviour (EARS-4).

    Tier selection priority (highest-urgency first, priority UNCHANGED):
    1. Any ALLOW event where a high-fidelity detection fired → Tier 1.
    2. Any ALERT or LOG event (detection or inherently non-asserting) → Tier 2.
    3. BLOCK/DROP events where the adversary has persisted (≥ threshold) → Tier 3.
    4. BLOCK/DROP events, one-off → Tier 4 (informational).

    For mixed actors the tier is still the loudest present action's tier; only
    ``block_status`` and ``justification`` change to reflect the mixed truth.

    Args:
        events:     All SecurityEvents for the IP in the analysis window.
        detections: All Detection objects produced by ``detector.detect(events)``.

    Returns:
        EscalationVerdict: always a valid verdict (never raises).
    """
    has_detections = bool(detections)

    # Partition events by action (needed for per-tier justification builders).
    allow_events = [e for e in events if e.action == "ALLOW"]
    alert_log_events = [e for e in events if e.action in ("ALERT", "LOG")]
    block_drop_events = [e for e in events if e.action in ("BLOCK", "DROP")]

    # Amendment 1 (A3): tally counts for ALL partitions before deciding.
    n_block_drop, n_alert_log, n_allow = _tally(events)
    counts = _disposition_counts(n_block_drop, n_alert_log, n_allow)
    mixed = _is_mixed(n_block_drop, n_alert_log, n_allow)

    # --- Tier 1: ALLOW + detection -------------------------------------------
    if allow_events and has_detections:
        if mixed:
            justification = _build_justification_partial(n_block_drop, n_alert_log, n_allow)
        else:
            justification = _build_justification_tier1(detections)
        return EscalationVerdict(
            tier=1,
            disposition="allowed_through",
            justification=justification,
            block_status="partial" if mixed else "allowed",
            disposition_counts=counts,
        )

    # --- Tier 2: ALERT/LOG (detection or inherently non-asserting) -----------
    # ALERT/LOG is Tier 2 whenever a detection fired, OR whenever ALERT/LOG events
    # are present (the action itself is non-asserting: OCSF non-terminating disposition).
    if alert_log_events and has_detections:
        if mixed:
            justification = _build_justification_partial(n_block_drop, n_alert_log, n_allow)
        else:
            justification = _build_justification_tier2_detected(detections)
        return EscalationVerdict(
            tier=2,
            disposition="block_status_unknown",
            justification=justification,
            block_status="partial" if mixed else "unknown",
            disposition_counts=counts,
        )
    if alert_log_events:
        if mixed:
            justification = _build_justification_partial(n_block_drop, n_alert_log, n_allow)
        else:
            justification = _build_justification_tier2_bare()
        return EscalationVerdict(
            tier=2,
            disposition="block_status_unknown",
            justification=justification,
            block_status="partial" if mixed else "unknown",
            disposition_counts=counts,
        )

    # --- Tier 3 / 4: BLOCK/DROP ----------------------------------------------
    if block_drop_events:
        is_persistent = len(block_drop_events) >= _PERSISTENCE_THRESHOLD
        if is_persistent:
            justification = _build_justification_tier3(block_drop_events, detections)
            return EscalationVerdict(
                tier=3,
                disposition="blocked_persistent",
                justification=justification,
                block_status="blocked",
                disposition_counts=counts,
            )
        justification = _build_justification_tier4(block_drop_events)
        return EscalationVerdict(
            tier=4,
            disposition="blocked_one_off",
            justification=justification,
            block_status="blocked",
            disposition_counts=counts,
        )

    # --- Fallback: ALLOW-only without detections (informational) -------------
    # Reaches here only when all events are ALLOW and no detection fired.
    # Tier 4 informational. disposition must agree with block_status="allowed"
    # (N-C): the traffic passed and nothing fired — it is not a block.
    return EscalationVerdict(
        tier=4,
        disposition="allowed_through",
        justification=(
            "[RULE] Traffic observed (ALLOW, no detection fired) — informational only."
        ),
        block_status="allowed",
        disposition_counts=counts,
    )


# ---------------------------------------------------------------------------
# Justification builders (RULE-tagged per ADR-0035)
# ---------------------------------------------------------------------------

def _top_rule_name(detections: list[Detection]) -> str:
    """Return the rule name from the highest-``score_delta`` detection."""
    if not detections:
        return "correlation rule"
    top = max(detections, key=lambda d: d.score_delta)
    return top.rule_name or "correlation rule"


def _auto_escalate_wording(detections: list[Detection]) -> str:
    """Return an elevated wording suffix when any detection has auto_escalate=True."""
    if any(d.auto_escalate for d in detections):
        return " (auto-escalate)"
    return ""


def _build_justification_tier1(detections: list[Detection]) -> str:
    # SECURITY (issue #648): the justification renders in the triage banner (#649).
    # It must contain ONLY operator-controlled text (the FireWatch correlation rule
    # name), never attacker-influenceable event fields. Event `category` is NOT
    # embedded: at least one source (CEF) derives it from attacker-controlled header
    # fields — see #642. Keep this string rule-derived only.
    rule = _top_rule_name(detections)
    ae = _auto_escalate_wording(detections)
    return (
        f"[RULE] {rule}{ae} matched on an ALLOW request"
        " — request passed the firewall; possible success."
    )


def _build_justification_tier2_detected(detections: list[Detection]) -> str:
    # SECURITY (issue #648): rule-derived text only — no attacker-influenceable
    # event `category` (see _build_justification_tier1 + #642).
    rule = _top_rule_name(detections)
    ae = _auto_escalate_wording(detections)
    return (
        f"[RULE] {rule}{ae} fired on an ALERT/LOG event"
        " — block status unknown; defence termination not confirmed."
    )


def _build_justification_tier2_bare() -> str:
    # SECURITY (issue #648): static, rule-derived text only (no attacker `category`).
    return (
        "[RULE] ALERT/LOG event observed"
        " — detection fired but block status is unknown."
    )


def _build_justification_tier3(
    events: list[SecurityEvent],
    detections: list[Detection],
) -> str:
    n = len(events)
    rule = _top_rule_name(detections) if detections else "volume rule"
    ae = _auto_escalate_wording(detections)
    return (
        f"[RULE] {rule}{ae}: {n} BLOCK/DROP events — adversary persisting;"
        " consider persistent IP-level enforcement."
    )


def _build_justification_tier4(events: list[SecurityEvent]) -> str:
    n = len(events)
    return (
        f"[RULE] {n} BLOCK/DROP event(s) — firewall held; one-off or low-volume;"
        " informational."
    )


def _build_justification_partial(
    n_block_drop: int,
    n_alert_log: int,
    n_allow: int,
) -> str:
    """Build a RULE-tagged mixed-disposition justification.

    SECURITY (ADR-0035 / #648 / #642): built from engine integers ONLY.
    No attacker-controlled event fields (category, rule_name, payload) are
    embedded.  The counts are internal engine numerics — always safe to render.

    Example output:
        "[RULE] 307 ALERT/LOG (block unknown) + 9 BLOCK/DROP — most traffic not
        terminally blocked; 9 confirmed blocked."
    """
    parts: list[str] = []
    if n_alert_log > 0:
        parts.append(f"{n_alert_log} ALERT/LOG (block unknown)")
    if n_block_drop > 0:
        parts.append(f"{n_block_drop} BLOCK/DROP")
    if n_allow > 0:
        parts.append(f"{n_allow} ALLOW")

    summary = " + ".join(parts)

    # Determine the dominant non-terminal class for the tail sentence.
    if n_block_drop > 0 and n_alert_log > 0:
        tail = (
            f"most traffic not terminally blocked; {n_block_drop} confirmed blocked."
        )
    elif n_block_drop > 0 and n_allow > 0:
        tail = f"{n_block_drop} confirmed blocked; {n_allow} allowed through."
    else:
        tail = "mixed disposition — review individual events."

    return f"[RULE] {summary} — {tail}"
