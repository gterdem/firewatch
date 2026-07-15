"""Pure deterministic escalation decider — ADR-0058 D2 / Amendment 1 (A3-A5) /
ADR-0067 (assertion-gated Tier-2 entry + the observed stratum).

``decide(events, detections) -> EscalationVerdict``

Single home of the tiered action model. **No I/O, no LLM, no side effects.**
Unit-testable in isolation; called from ``pipeline.analyze_ip``.

Tier model (ADR-0058 §D2/§4a, gated per ADR-0067 D1):

| Tier | Action(s)                        | Disposition              | block_status |
|------|-----------------------------------|--------------------------|--------------|
|  1   | ALLOW (with any detection)       | allowed_through          | allowed      |
|  2   | ALERT / LOG **+ qualifying signal**| block_status_unknown   | unknown      |
|  3   | BLOCK/DROP — persistent           | blocked_persistent       | blocked      |
|  4   | BLOCK/DROP — one-off              | blocked_one_off          | blocked      |
| None | unqualified ALERT/LOG, or ALLOW-only with no detection | observed | unknown / allowed |

ADR-0067 D1 — the assertion gate (``escalation.qualify.qualify()``):
Tier 2 now requires a *qualifying signal*, not bare ALERT/LOG presence:
(a) a Detection with ``auto_escalate=True`` or declared severity high/critical
(the ADR-0058 D1 registry, finally consumed for routing), or (b) a source-declared
``ALERT`` severity of high/critical. ``LOG`` never self-qualifies (ECS
``kind:event`` is telemetry, not an assertion). Everything below the gate — and
today's ALLOW-only/no-detection fallback — becomes the **observed** stratum:
``tier=None``, ``disposition="observed"`` (ADR-0067 D2). Tier 1 is untouched and
stays unconditional (ADR-0067 D1); Tiers 3/4 are unchanged.

Amendment 1 (ADR-0058 A3-A5) — full-tally rewrite, unchanged by ADR-0067:
- ``decide()`` does not short-circuit on the first non-empty partition.
- All three partitions (allow / alert_log / block_drop) are counted before the
  verdict is assembled.
- ``block_status="partial"`` is emitted when events span more than one terminal
  disposition class (e.g. some ALERT/LOG AND some BLOCK/DROP).
- ``disposition_counts`` (structured integers) is attached to every verdict.
- A RULE-tagged mixed justification is built from engine integers only (no
  attacker-controlled fields — ADR-0035 / #648 / #642 discipline). ADR-0067
  applies this mixed-justification treatment uniformly across all branches
  (Tier 1/2/3/4/observed) — previously Tier 3/4 always used the single-class
  justification even when mixed, silently dropping the alert/allow counts.

Standard alignment:
- OCSF disposition_id: ALLOW ≈ Allowed (id=1), BLOCK/DROP ≈ Blocked (id=2),
  ALERT/LOG ≈ non-terminating ("block status unknown" when qualified) or
  ``action_id=3 Observed`` when unqualified (ADR-0067 D2). Ref: schema.ocsf.io (1.8.0).
- ADR-0035 provenance: ``justification`` is a RULE-tagged string (never LLM).
- ADR-0012: ALERT is an honest IDS non-blocking disposition.
- ``"partial"`` is a FireWatch extension (no OCSF equivalent) — ADR-0058 A1.

Persistence threshold: ≥ 3 BLOCK/DROP events for the same IP in the window.
This matches the brute-force threshold in scoring.py (10 is higher; 3 is the
lowest operationally meaningful "the adversary is persisting" bar).
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from firewatch_sdk.models import (
    Detection,
    DispositionCounts,
    EscalationBlockStatusLiteral,
    EscalationVerdict,
    SecurityEvent,
)

from firewatch_core.escalation.qualify import QualifyResult, qualify

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


@dataclass(frozen=True)
class _PartitionTally:
    """Bundles the Amendment-1 full-tally state shared by every ``decide()`` branch.

    One concern: carry (counts, mixed-ness) so each per-tier verdict builder
    takes one parameter instead of four. Pure data; no behaviour.
    """

    n_block_drop: int
    n_alert_log: int
    n_allow: int
    mixed: bool
    counts: DispositionCounts


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def decide(
    events: list[SecurityEvent],
    detections: list[Detection],
) -> EscalationVerdict:
    """Map (events, detections) to a deterministic EscalationVerdict.

    Pure function — no I/O, no LLM.  Returns the loudest applicable tier, or
    the observed verdict (``tier=None``) when nothing qualifies (ADR-0067 D2).

    Amendment 1: all three partitions are tallied before producing the verdict.
    Mixed actors (events span >1 terminal class) receive ``block_status="partial"``
    and a RULE-tagged mixed justification. Single-class actors keep the exact
    pre-amendment behaviour (EARS-4).

    Tier selection priority (highest-urgency first, priority UNCHANGED by ADR-0067):
    1. Any ALLOW event where any detection fired → Tier 1 (unconditional; ADR-0067 D1).
    2. Any ALERT or LOG event WITH a qualifying signal (ADR-0067 D1) → Tier 2.
    3. BLOCK/DROP events where the adversary has persisted (≥ threshold) → Tier 3.
    4. BLOCK/DROP events, one-off → Tier 4 (informational).
    5. Otherwise (unqualified ALERT/LOG, or ALLOW-only with no detection) →
       observed (``tier=None``, ``disposition="observed"``; ADR-0067 D2).

    For mixed actors the tier is still the loudest *qualifying* present action's
    tier; only ``block_status`` and ``justification`` change to reflect the
    mixed truth. An unqualified ALERT/LOG mass never outranks a qualifying
    or terminal (BLOCK/DROP) class — the loudest *qualifying* class decides.

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
    tally = _PartitionTally(
        n_block_drop=n_block_drop,
        n_alert_log=n_alert_log,
        n_allow=n_allow,
        mixed=_is_mixed(n_block_drop, n_alert_log, n_allow),
        counts=_disposition_counts(n_block_drop, n_alert_log, n_allow),
    )

    # ADR-0067 D1: the assertion gate. Computed once; consumed by Tier 2 and
    # by the observed fallback's justification.
    qualify_result = qualify(events, detections)

    # --- Tier 1: ALLOW + detection (unconditional — ADR-0067 D1 leaves this alone) ---
    if allow_events and has_detections:
        return _tier1_verdict(detections, tally)

    # --- Tier 2: ALERT/LOG with a qualifying assertion (ADR-0067 D1) ---------
    if alert_log_events and qualify_result.qualified:
        return _tier2_verdict(qualify_result, tally)

    # --- Tier 3 / 4: BLOCK/DROP ------------------------------------------------
    # Reached also by actors whose ALERT/LOG mass failed the D1 gate — the
    # loudest *qualifying* class (the confirmed blocks) decides the tier.
    if block_drop_events:
        return _tier3_or_4_verdict(block_drop_events, detections, tally)

    # --- Observed: no BLOCK/DROP, and nothing qualified (ADR-0067 D2) --------
    # Reaches here when: (a) all events are ALLOW with no detection [today's
    # tier-4 fallback], or (b) the ALERT/LOG population failed the D1 gate,
    # possibly mixed with ALLOW. Never claims a tier — no assertion was made.
    return _observed_verdict(tally)


# ---------------------------------------------------------------------------
# Per-tier verdict builders — one concern each, all pure
# ---------------------------------------------------------------------------

def _tier1_verdict(detections: list[Detection], tally: _PartitionTally) -> EscalationVerdict:
    if tally.mixed:
        justification = _build_justification_partial(
            tally.n_block_drop, tally.n_alert_log, tally.n_allow
        )
    else:
        justification = _build_justification_tier1(detections)
    return EscalationVerdict(
        tier=1,
        disposition="allowed_through",
        justification=justification,
        block_status="partial" if tally.mixed else "allowed",
        disposition_counts=tally.counts,
    )


def _tier2_verdict(qualify_result: QualifyResult, tally: _PartitionTally) -> EscalationVerdict:
    if tally.mixed:
        justification = _build_justification_partial(
            tally.n_block_drop, tally.n_alert_log, tally.n_allow
        )
    else:
        justification = _build_justification_tier2_qualified(qualify_result)
    return EscalationVerdict(
        tier=2,
        disposition="block_status_unknown",
        justification=justification,
        block_status="partial" if tally.mixed else "unknown",
        disposition_counts=tally.counts,
    )


def _tier3_or_4_verdict(
    block_drop_events: list[SecurityEvent],
    detections: list[Detection],
    tally: _PartitionTally,
) -> EscalationVerdict:
    is_persistent = len(block_drop_events) >= _PERSISTENCE_THRESHOLD
    if tally.mixed:
        justification = _build_justification_partial(
            tally.n_block_drop, tally.n_alert_log, tally.n_allow
        )
    elif is_persistent:
        justification = _build_justification_tier3(block_drop_events, detections)
    else:
        justification = _build_justification_tier4(block_drop_events)

    block_status: EscalationBlockStatusLiteral = "partial" if tally.mixed else "blocked"
    if is_persistent:
        return EscalationVerdict(
            tier=3,
            disposition="blocked_persistent",
            justification=justification,
            block_status=block_status,
            disposition_counts=tally.counts,
        )
    return EscalationVerdict(
        tier=4,
        disposition="blocked_one_off",
        justification=justification,
        block_status=block_status,
        disposition_counts=tally.counts,
    )


def _observed_verdict(tally: _PartitionTally) -> EscalationVerdict:
    """ADR-0067 D2: tier=None, disposition='observed' — no escalation claim."""
    block_status: EscalationBlockStatusLiteral
    if tally.mixed:
        justification = _build_justification_partial(
            tally.n_block_drop, tally.n_alert_log, tally.n_allow
        )
        block_status = "partial"
    elif tally.n_alert_log:
        justification = _build_justification_observed_alert_log(tally.n_alert_log)
        block_status = "unknown"
    else:
        justification = _build_justification_observed_allow()
        block_status = "allowed"

    return EscalationVerdict(
        tier=None,
        disposition="observed",
        justification=justification,
        block_status=block_status,
        disposition_counts=tally.counts,
    )


# ---------------------------------------------------------------------------
# Justification builders (RULE-tagged per ADR-0035)
# ---------------------------------------------------------------------------

def _top_rule_name(detections: Sequence[Detection]) -> str:
    """Return the rule name from the highest-``score_delta`` detection."""
    if not detections:
        return "correlation rule"
    top = max(detections, key=lambda d: d.score_delta)
    return top.rule_name or "correlation rule"


def _auto_escalate_wording(detections: Sequence[Detection]) -> str:
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


def _build_justification_tier2_qualified(qualify_result: QualifyResult) -> str:
    """Tier-2 justification when the ADR-0067 D1 gate is open (not mixed).

    Prefers detection-based evidence (D1a) when present — engine-authored
    ``Detection.rule_name`` only (ADR-0035 / #648 / #642). Falls back to the
    source-declared event severity (D1b) — a validated, bounded
    ``SeverityLiteral``, safe to render — when qualification came from an
    ``ALERT`` event alone.
    """
    if qualify_result.qualifying_detections:
        rule = _top_rule_name(qualify_result.qualifying_detections)
        ae = _auto_escalate_wording(qualify_result.qualifying_detections)
        return (
            f"[RULE] {rule}{ae} fired on an ALERT/LOG event"
            " — block status unknown; defence termination not confirmed."
        )
    severity = qualify_result.qualifying_event_severity or "high"
    return (
        f"[RULE] ALERT event with source-declared severity '{severity}'"
        " — block status unknown; defence termination not confirmed."
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


def _build_justification_observed_alert_log(n_alert_log: int) -> str:
    """Observed justification for an unqualified, pure ALERT/LOG population.

    SECURITY (ADR-0035 / #648 / #642): built from an engine integer only — no
    attacker-controlled event field is embedded.
    """
    return (
        f"[RULE] {n_alert_log} ALERT/LOG event(s) observed"
        " — no qualifying detection or declared high/critical severity;"
        " on the record only."
    )


def _build_justification_observed_allow() -> str:
    """Observed justification for the ALLOW-only / empty-window fallback (D2)."""
    return (
        "[RULE] Traffic observed (ALLOW, no detection fired) — informational only."
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

    Applied uniformly across every branch of ``decide()`` (Tier 1/2/3/4 and
    observed) whenever the actor's events span more than one terminal
    disposition class — ADR-0067 fixes the prior asymmetry where Tier 3/4
    silently dropped the alert/allow counts from the justification.

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
