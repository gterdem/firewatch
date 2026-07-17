"""Pure deterministic escalation decider — ADR-0058 D2 / Amendment 1 (A3-A5) /
ADR-0067 (assertion-gated Tier-2 entry + the observed stratum + D6/Amendment 1
enforcement posture, issue #75).

``decide(events, detections, posture_map=None) -> EscalationVerdict``

Single home of the tiered action model. **No I/O, no LLM, no side effects.**
Unit-testable in isolation; called from ``pipeline.analyze_ip``.

Tier model (ADR-0058 §D2/§4a, gated per ADR-0067 D1):

| Tier | Action(s)                        | Disposition              | block_status |
|------|-----------------------------------|--------------------------|--------------|
|  1   | ALLOW (with any detection)       | allowed_through          | allowed      |
|  2   | ALERT / LOG **+ qualifying signal**| posture-derived — see below | unknown / partial |
|  3   | BLOCK/DROP — persistent           | blocked_persistent       | blocked      |
|  4   | BLOCK/DROP — one-off              | blocked_one_off          | blocked      |
| None | unqualified ALERT/LOG, or ALLOW-only with no detection | observed | unknown / allowed |

Tier-2 disposition (ADR-0067 D6 + Amendment 1, issue #75 — the label table lives
in ``escalation.posture.qualified_tier2_disposition``, consulted here via
``posture_map``): the generic ``block_status_unknown`` narrows to an honest,
posture-specific label the moment the actor's contributing instances declare a
SINGLE, uniform ``enforcement`` posture. ``posture_map`` is additive and
defaulted (``None`` -> every instance undeclared, today's behaviour, zero
shipped-label movement).

Safety property (verified, pinned by tests): no posture value can ever change a
tier or produce ``block_status="blocked"`` — those derive solely from the
per-event BLOCK/DROP tallies below, never from posture.

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
- OCSF disposition_id: ALLOW ≈ Allowed (id=1), BLOCK/DROP ≈ Blocked (id=2).
  ALERT has an explicit OCSF disposition — id=19 Alert: "detected as a threat and
  resulted in a notification but request was not blocked" — it asserts NOT-blocked,
  not unknown (ADR-0067 RC3). ``block_status_unknown`` is therefore NOT an OCSF
  mapping: it is D6's conservative label for undeclared/mixed posture — see
  ``escalation/posture.py`` for the full per-posture label table (issue #75).
  Unqualified ALERT/LOG ≈ ``action_id=3 Observed`` (ADR-0067 D2). Ref: schema.ocsf.io.
- ADR-0035 provenance: ``justification`` is a RULE-tagged string (never LLM).
- ADR-0012: ALERT is an honest IDS non-blocking disposition.
- ``"partial"`` is a FireWatch extension (no OCSF equivalent) — ADR-0058 A1.

Persistence threshold: ≥ 3 BLOCK/DROP events for the same IP in the window.
This matches the brute-force threshold in scoring.py (10 is higher; 3 is the
lowest operationally meaningful "the adversary is persisting" bar).
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from firewatch_sdk.models import (
    Detection,
    DispositionCounts,
    EnforcementPostureLiteral,
    EscalationBlockStatusLiteral,
    EscalationDispositionLiteral,
    EscalationVerdict,
    SecurityEvent,
)

from firewatch_core.escalation.posture import InstanceKey, qualified_tier2_disposition
from firewatch_core.escalation.qualify import QualifyResult, qualify

# Number of BLOCK/DROP events required to classify the adversary as "persistent"
# (Tier 3 rather than Tier 4 informational).  Consistent with the "adversary tried
# more than once" definition in ADR-0058 §D2.
_PERSISTENCE_THRESHOLD = 3


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _qualifying_rule_names(qualify_result: QualifyResult) -> list[str]:
    """Build ``EscalationVerdict.qualifying_rules`` (ADR-0072 D1).

    Deduped, order-preserving union of ``qualifying_detections[].rule_name``
    (D1a — always a non-empty ``str`` on ``Detection``) and the D1(b)
    qualifying ALERT events' ``rule_name`` (``SecurityEvent.rule_name`` is
    optional — ``None`` values are dropped so an anonymous-source ALERT
    contributes nothing, per ADR-0072 D4's fail-toward-visibility boundary 1).
    """
    names: list[str] = []
    seen: set[str] = set()
    for detection in qualify_result.qualifying_detections:
        if detection.rule_name not in seen:
            seen.add(detection.rule_name)
            names.append(detection.rule_name)
    for event in qualify_result.qualifying_alert_events:
        if event.rule_name and event.rule_name not in seen:
            seen.add(event.rule_name)
            names.append(event.rule_name)
    return names


def _attach_qualifying_rules(
    verdict: EscalationVerdict, qualifying_rules: list[str]
) -> EscalationVerdict:
    """Attach the ADR-0072 D1 rule-identity set to *verdict* — additive only.

    A no-op copy when *qualifying_rules* is empty (the common case); otherwise
    returns a shallow copy of *verdict* with ``qualifying_rules`` set. Never
    changes ``tier``/``score``/any other field — the golden oracle is
    unaffected (``qualifying_rules`` carries no score weight).
    """
    if not qualifying_rules:
        return verdict
    return verdict.model_copy(update={"qualifying_rules": qualifying_rules})


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
    posture_map: Mapping[InstanceKey, EnforcementPostureLiteral | None] | None = None,
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
        events:      All SecurityEvents for the IP in the analysis window.
        detections:  All Detection objects produced by ``detector.detect(events)``.
        posture_map: ``(source_type, source_id) -> enforcement posture`` — resolved
                     by the caller (the pipeline) via ``escalation.posture.
                     resolve_posture_map`` from (instance override OR plugin
                     metadata default). Additive, defaulted to ``None`` — treated
                     as an empty map (every instance undeclared), the exact
                     pre-#75 behaviour: qualified Tier-2 verdicts keep
                     ``block_status_unknown`` when no posture is known
                     (ADR-0067 D6 + Amendment 1, issue #75).

    Returns:
        EscalationVerdict: always a valid verdict (never raises).
    """
    has_detections = bool(detections)
    resolved_posture_map: Mapping[InstanceKey, EnforcementPostureLiteral | None] = (
        posture_map or {}
    )

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

    # ADR-0072 D1: the rule-identity set the D1 gate found for this actor —
    # attached to whichever verdict branch below returns, regardless of tier,
    # so false-positive suppression (ADR-0072 D4) can scope to it even on a
    # verdict the gate did not itself route (e.g. a Tier-3/4 actor that also
    # carries a qualifying detection). Never influences score or tier.
    qualifying_rules = _qualifying_rule_names(qualify_result)

    # --- Tier 1: ALLOW + detection (unconditional — ADR-0067 D1 leaves this alone) ---
    if allow_events and has_detections:
        return _attach_qualifying_rules(_tier1_verdict(detections, tally), qualifying_rules)

    # --- Tier 2: ALERT/LOG with a qualifying assertion (ADR-0067 D1) ---------
    if alert_log_events and qualify_result.qualified:
        return _attach_qualifying_rules(
            _tier2_verdict(qualify_result, tally, alert_log_events, resolved_posture_map),
            qualifying_rules,
        )

    # --- Tier 3 / 4: BLOCK/DROP ------------------------------------------------
    # Reached also by actors whose ALERT/LOG mass failed the D1 gate — the
    # loudest *qualifying* class (the confirmed blocks) decides the tier.
    if block_drop_events:
        return _attach_qualifying_rules(
            _tier3_or_4_verdict(block_drop_events, detections, tally), qualifying_rules
        )

    # --- Observed: no BLOCK/DROP, and nothing qualified (ADR-0067 D2) --------
    # Reaches here when: (a) all events are ALLOW with no detection [today's
    # tier-4 fallback], or (b) the ALERT/LOG population failed the D1 gate,
    # possibly mixed with ALLOW. Never claims a tier — no assertion was made.
    return _attach_qualifying_rules(_observed_verdict(tally), qualifying_rules)


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


def _tier2_verdict(
    qualify_result: QualifyResult,
    tally: _PartitionTally,
    alert_log_events: list[SecurityEvent],
    posture_map: Mapping[InstanceKey, EnforcementPostureLiteral | None],
) -> EscalationVerdict:
    if tally.mixed:
        justification = _build_justification_partial(
            tally.n_block_drop, tally.n_alert_log, tally.n_allow
        )
    else:
        justification = _build_justification_tier2_qualified(qualify_result)

    # ADR-0067 D6 + Amendment 1 (issue #75): narrow the generic label to an
    # honest, posture-specific one when the actor's contributing instances
    # declare a single, uniform enforcement posture. DISPOSITION-LABEL ONLY —
    # block_status/tier below are computed exactly as before, from the tally
    # alone (the #75 safety property: posture never moves tier/block_status).
    instance_keys = {(e.source_type, e.source_id) for e in alert_log_events}
    # Explicit annotation (not just inferred): pyright otherwise widens the
    # Mapping.get() literal-union result type to plain `str | None`.
    postures: list[EnforcementPostureLiteral | None] = [
        posture_map.get(key) for key in instance_keys
    ]
    disposition: EscalationDispositionLiteral = qualified_tier2_disposition(
        postures, tally.n_block_drop
    )

    return EscalationVerdict(
        tier=2,
        disposition=disposition,
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
    # Wording (issue #6): plain language, no SOC dialect — "got through" instead
    # of "passed the firewall"; "may have reached your system" instead of
    # "possible success".
    rule = _top_rule_name(detections)
    ae = _auto_escalate_wording(detections)
    return (
        f"[RULE] {rule}{ae} matched, and the request got through"
        " — this may have reached your system."
    )


def _build_justification_tier2_qualified(qualify_result: QualifyResult) -> str:
    """Tier-2 justification when the ADR-0067 D1 gate is open (not mixed).

    Prefers detection-based evidence (D1a) when present — engine-authored
    ``Detection.rule_name`` only (ADR-0035 / #648 / #642). Falls back to the
    source-declared event severity (D1b) — a validated, bounded
    ``SeverityLiteral``, safe to render — when qualification came from an
    ``ALERT`` event alone.

    Wording ruled on PR #38 (architect ruling, superseding the prior
    "block status unknown" sentence RC3 indicts): both branches below are
    reached only in the non-mixed case, so ``n_block_drop == 0`` is a tally
    fact — "no block was recorded in this window" is engine-attested, not a
    claim about downstream controls FireWatch cannot see (ADR-0067 D6: "a
    passive sensor cannot see a downstream block"). It also stays true for
    LOG-qualified populations where "not blocked" would be a category error
    (e.g. a failed login has an attested outcome, not a block status).
    """
    if qualify_result.qualifying_detections:
        rule = _top_rule_name(qualify_result.qualifying_detections)
        ae = _auto_escalate_wording(qualify_result.qualifying_detections)
        return (
            f"[RULE] {rule}{ae} flagged this traffic"
            " — no block was recorded in this window."
        )
    severity = qualify_result.qualifying_event_severity or "high"
    return (
        f"[RULE] Source-declared severity '{severity}' flagged this traffic"
        " — no block was recorded in this window."
    )


def _build_justification_tier3(
    events: list[SecurityEvent],
    detections: list[Detection],
) -> str:
    # Wording (issue #6): "blocked N times" / "keeps coming back" replaces the
    # SOC-dialect "adversary persisting; consider persistent IP-level enforcement".
    n = len(events)
    rule = _top_rule_name(detections) if detections else "volume rule"
    ae = _auto_escalate_wording(detections)
    return (
        f"[RULE] {rule}{ae}: blocked {n} times"
        " — this attacker keeps coming back; consider a longer-term IP block."
    )


def _build_justification_tier4(events: list[SecurityEvent]) -> str:
    # Wording (issue #6, maintainer-approved): "didn't keep trying" pairs with
    # Tier 3's "kept trying" — the two labels differ on exactly the one fact
    # (persistence) that actually distinguishes the tiers. Real pluralization
    # (not "attempt(s)") because n is a trusted engine integer, not a template
    # placeholder. The number already speaks for itself — no paraphrase like
    # "a single try", which goes stale/false the moment n != 1. No hard-coded
    # reference to _PERSISTENCE_THRESHOLD: this copy stays true if that value
    # ever moves.
    n = len(events)
    return (
        f"[RULE] Blocked {n} attempt{'' if n == 1 else 's'}"
        " — didn't keep trying; no action needed."
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

    Wording (issue #6): plain language — "unconfirmed" replaces "ALERT/LOG
    (block unknown)"; "confirmed blocked" / "got through" replace SOC dialect.

    Applied uniformly across every branch of ``decide()`` (Tier 1/2/3/4 and
    observed) whenever the actor's events span more than one terminal
    disposition class — ADR-0067 fixes the prior asymmetry where Tier 3/4
    silently dropped the alert/allow counts from the justification.

    Example output:
        "[RULE] 307 unconfirmed + 9 blocked — most traffic unconfirmed;
        9 confirmed blocked."
    """
    parts: list[str] = []
    if n_alert_log > 0:
        parts.append(f"{n_alert_log} unconfirmed")
    if n_block_drop > 0:
        parts.append(f"{n_block_drop} blocked")
    if n_allow > 0:
        parts.append(f"{n_allow} got through")

    summary = " + ".join(parts)

    # Determine the dominant non-terminal class for the tail sentence.
    if n_block_drop > 0 and n_alert_log > 0:
        tail = f"most traffic unconfirmed; {n_block_drop} confirmed blocked."
    elif n_block_drop > 0 and n_allow > 0:
        tail = f"{n_block_drop} confirmed blocked; {n_allow} got through."
    else:
        tail = "mixed disposition — review individual events."

    return f"[RULE] {summary} — {tail}"
