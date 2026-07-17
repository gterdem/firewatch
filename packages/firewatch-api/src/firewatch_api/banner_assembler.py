"""Banner attempts-summary assembler — GET /banner/summary (issue #55, Part 1/backend).

ADR-0070 D1 (the attempt predicate) / D3 (queue entry, tier attribution corrected
2026-07-16) / D5 (constants, engine integers only — ADR-0035). Extends #43's
aggregate record line (same banner slot) with four additive, server-computed
integers plus a bounded top-N pressure list:

  - ``attempt_count``  — D1-qualifying events across all actors, state window.
  - ``actor_count``    — distinct actors with >=1 qualifying attempt, state window.
  - ``succeeded_count`` — see ``_succeeded`` below; THE correctness crux of #55.
  - ``queue_size``     — actors carrying a Tier-1/Tier-2 escalation verdict.
  - ``top_pressure``   — bounded (<= ``TOP_PRESSURE_N``) (actor, attempt_count,
                          span_minutes) rows, ranked by peak decayed intensity
                          (never itself rendered — ADR-0035: engine integers only).

This module is pure aggregation over ALREADY-COMPUTED verdicts/detections
(``firewatch_core.escalation.decider.decide`` / ``firewatch_core.detector.detect``)
and the shared attempt predicate (``firewatch_core.attempts``). It never
re-derives what qualifies as an attempt, a tier, or a detection — the banner
must never count differently than the engine (issue #55 hard constraint).

Callers (``routes/banner.py``) are responsible for building each actor's
``(state_events, campaign_events, detections, verdict)`` tuple with the SAME
window slicing ``pipeline.analyze_ip`` uses (ADR-0070 D4: ``W_STATE`` = 24h
feeds ``decide()``, ``W_CAMPAIGN`` = 7d feeds ``detect()``) — this module only
aggregates what it is handed.

No I/O; no store access; pure functions over already-fetched data.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from firewatch_sdk.models import Detection, EscalationVerdict, SecurityEvent

from firewatch_core.attempts import HALF_LIFE, is_attempt, peak_intensity
from firewatch_core.pipeline import W_STATE

#: N <= 5 — the pressure-strip bound (issue #55 acceptance criterion).
TOP_PRESSURE_N = 5


# ---------------------------------------------------------------------------
# Per-actor stats — pure data
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActorAttemptStats:
    """One actor's window-scoped attempt/verdict facts.

    ``peak_intensity`` (lambda_hat) is an internal ranking key ONLY — it ranks
    the top-N pressure list and is NEVER itself serialized or rendered
    (ADR-0035: reason strings/wire fields carry engine integers, never a raw
    decayed-intensity float). The two fields that DO leave this module via
    ``PressureRow`` (``attempt_count``, ``span_minutes``) are plain engine
    integers.
    """

    source_ip: str
    attempt_count: int
    span_minutes: int
    peak_intensity: float
    succeeded: bool
    queued: bool


@dataclass(frozen=True)
class PressureRow:
    """One row of the bounded top-N pressure strip — (actor, attempt_count, span)."""

    source_ip: str
    attempt_count: int
    span_minutes: int


@dataclass(frozen=True)
class BannerAttemptSummaryData:
    """The additive banner-feed aggregate (issue #55 acceptance criteria)."""

    attempt_count: int
    actor_count: int
    succeeded_count: int
    queue_size: int
    top_pressure: tuple[PressureRow, ...]


# ---------------------------------------------------------------------------
# Success-set correctness — the ADR-0070 D3 tier-attribution correction
# ---------------------------------------------------------------------------


def _succeeded(verdict: EscalationVerdict, detections: list[Detection]) -> bool:
    """Success set (issue #55, ADR-0070 D3 correction, 2026-07-16): Tier-1
    verdicts UNION actors carrying a critical-severity qualifying detection —
    **never Tier-1 alone**.

    Why the union, and why each arm is needed (worked partition, ADR-0070 D3):

    - **Traffic-source actor** (ALLOW + any detection): reaches Tier 1 via the
      untouched ADR-0067 D1(a) gate — first arm.
    - **Mixed-telemetry actor** (e.g. a CEF firewall ``act=permitted`` ALLOW
      alongside SSH brute-force events, same IP): the Tier-1 gate is
      per-actor, not per-rule (``decider.py:147,188``), so this actor ALSO
      reaches Tier 1 through the unrelated ALLOW — first arm again.
    - **Pure host-auth actor** (syslog/linux_auth — sources that never emit
      ALLOW) whose window fires ``brute_force_then_login``: Tier 1 is
      structurally unreachable (no ALLOW event exists anywhere in the
      partition), so the verdict is Tier 2 — caught ONLY by the second arm.
      Binding "succeeded" to ``tier == 1`` alone would read "0 succeeded"
      here WHILE the compromise rule is firing — the exact false-calm defect
      this correction exists to prevent.

    ``severity == "critical"`` is checked directly (not re-run through
    ``qualify()``) because today's registry makes the two equivalent:
    ``brute_force_then_login`` — the product's only critical-severity rule
    (``detector.py`` ``ESCALATION_POLICY.register(..., severity="critical",
    auto_escalate=True)``) — is always ``auto_escalate=True``, which
    independently satisfies the ADR-0067 D1(a) qualifying-signal gate. A
    critical-severity ``Detection`` is therefore always a *qualifying*
    critical-severity detection under the current policy registry.
    """
    if verdict.tier == 1:
        return True
    return any(d.severity == "critical" for d in detections)


def _queued(verdict: EscalationVerdict, *, suppressed: bool) -> bool:
    """K = queue size: actors carrying a Tier-1 or Tier-2 escalation verdict.

    This is the ADR-0067 D1(a) assertion-gated queue population — core-owned
    and deterministic (not gated by the operator-tunable Triage threshold's
    band half, ADR-0059 D1). Matches the CRITICAL / HIGH ALERT states in
    ADR-0070 D3's table; INFORM (``tier is None``) never counts, by design
    (ADR-0067 D2 — the observed stratum makes no escalation claim).

    ADR-0072 finding 2: a Tier-1/Tier-2 actor that is currently SUPPRESSED
    (an active `expected`/`dismissed` decision, or a `false_positive` row
    covering every qualifying rule — ``firewatch_core.triage.suppression.
    evaluate``) no longer counts toward the queue — the SAME evaluator the
    ``triage_decision`` annotation on ``GET /threats`` uses, via
    ``firewatch_api.decision_annotator.is_suppressed`` (the caller passes
    *suppressed* in; this module never re-derives it).
    """
    return verdict.tier in (1, 2) and not suppressed


# ---------------------------------------------------------------------------
# Per-actor derivation
# ---------------------------------------------------------------------------


def compute_actor_attempt_stats(
    source_ip: str,
    *,
    state_events: list[SecurityEvent],
    campaign_events: list[SecurityEvent],
    detections: list[Detection],
    verdict: EscalationVerdict,
    now: datetime,
    suppressed: bool = False,
) -> ActorAttemptStats:
    """Derive one actor's :class:`ActorAttemptStats`.

    Args:
        source_ip: The actor's IP.
        state_events: This actor's events sliced to the trailing ``W_STATE``
            (24h) window (ADR-0070 D4) — the SAME slice ``pipeline.analyze_ip``
            passes to ``run_rules``/``decide()``. ``attempt_count``/
            ``span_minutes`` (the two integers rendered on the banner) are
            computed from this window.
        campaign_events: This actor's events sliced to the trailing
            ``W_CAMPAIGN`` (7d) window — the SAME slice ``pipeline.analyze_ip``
            passes to ``detect()``. Used only to compute the internal
            ``peak_intensity`` ranking key with the identical input the
            product's own ``attempt_pressure`` (R1) rule sees — never rendered.
        detections: ``detect(campaign_events, now=now)`` output for this actor
            — MUST be the same list used to build this actor's ``ThreatScore``
            and passed to ``decide()`` below (the banner must never count
            differently than the engine — issue #55 hard constraint).
        verdict: ``decide(state_events, detections)`` output for this actor.
        now: The pipeline's anchored evaluation instant (ADR-0070 D2/D3) —
            threaded through, never read locally.
        suppressed: ADR-0072 finding 2 — whether this actor's CURRENT verdict
            is suppressed (``firewatch_api.decision_annotator.is_suppressed``,
            over ``firewatch_core.triage.suppression.evaluate``). Defaults to
            ``False`` (today's behaviour) when the caller has no decision
            store wired.
    """
    timestamps = sorted(e.timestamp for e in state_events if is_attempt(e))
    attempt_count = len(timestamps)
    span_minutes = (
        int((timestamps[-1] - timestamps[0]).total_seconds() // 60)
        if attempt_count >= 2
        else 0
    )
    # Rank by the SAME peak-intensity measure R1 (attempt_pressure) checks —
    # campaign_events as input, W_STATE as the peak-check window (matches
    # detector.py's _PRESSURE_WINDOW = W_STATE exactly). Internal only.
    peak = peak_intensity(campaign_events, W_STATE, now, half_life=HALF_LIFE)

    return ActorAttemptStats(
        source_ip=source_ip,
        attempt_count=attempt_count,
        span_minutes=span_minutes,
        peak_intensity=peak,
        succeeded=_succeeded(verdict, detections),
        queued=_queued(verdict, suppressed=suppressed),
    )


# ---------------------------------------------------------------------------
# Aggregate assembly
# ---------------------------------------------------------------------------


def assemble_banner_attempt_summary(
    stats: list[ActorAttemptStats],
    *,
    top_n: int = TOP_PRESSURE_N,
) -> BannerAttemptSummaryData:
    """Aggregate every actor's :class:`ActorAttemptStats` into the banner summary.

    ``top_pressure`` is bounded to ``top_n`` (<= 5, issue #55) rows, ranked by
    peak decayed intensity (descending), broken by attempt_count then IP for
    a deterministic order. Actors with zero attempts in the state window are
    excluded from the ranking (nothing to show) but still count toward
    ``succeeded_count``/``queue_size`` when applicable.
    """
    attempt_count = sum(s.attempt_count for s in stats)
    actor_count = sum(1 for s in stats if s.attempt_count > 0)
    succeeded_count = sum(1 for s in stats if s.succeeded)
    queue_size = sum(1 for s in stats if s.queued)

    ranked = sorted(
        (s for s in stats if s.attempt_count > 0),
        key=lambda s: (-s.peak_intensity, -s.attempt_count, s.source_ip),
    )[:top_n]

    top_pressure = tuple(
        PressureRow(
            source_ip=s.source_ip,
            attempt_count=s.attempt_count,
            span_minutes=s.span_minutes,
        )
        for s in ranked
    )

    return BannerAttemptSummaryData(
        attempt_count=attempt_count,
        actor_count=actor_count,
        succeeded_count=succeeded_count,
        queue_size=queue_size,
        top_pressure=top_pressure,
    )
