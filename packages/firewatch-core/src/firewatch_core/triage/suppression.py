"""The D4 pure evaluator (ADR-0072) — decisions × current verdict -> DecisionEvaluation.

``evaluate(decisions, verdict) -> DecisionEvaluation`` is the SINGLE source of
truth every read surface consults (via ``firewatch_api.decision_annotator``):
``GET /threats``/``GET /threats/{ip}`` (the ``triage_decision`` annotation) and
``GET /banner/summary`` (``queue_size`` exclusion) — ADR-0072 finding 2, "one
evaluator, every surface." No I/O; pure function of its two arguments.

D4 formula (quoted from the ADR)::

    F = {rule_name of active false_positive rows}
    A = latest active row with verb in {expected, dismissed}   (may be None)

    suppressed_by_actor = A exists AND NOT reentry(A, verdict)
        where reentry = (A.decided_tier IS None AND verdict.tier IS NOT None)
                     OR (both non-None AND verdict.tier < A.decided_tier)   # #56
    suppressed_by_fp   = verdict.tier IS NOT None
                     AND verdict.qualifying_rules != {}
                     AND set(verdict.qualifying_rules) <= F

    suppressed = suppressed_by_actor OR suppressed_by_fp

Two fail-toward-visibility boundaries (deliberate, ADR-0072 D4):

1. An actor whose only qualifying signal is an anonymous-source ALERT
   (``rule_name=None`` -> empty ``qualifying_rules``) can never be
   FP-suppressed — ``qualifying <= F`` is vacuously false-guarded by the
   explicit non-empty check below (an empty set IS a subset of anything in
   set theory, so the emptiness check is REQUIRED, not redundant).
2. Score/volume deltas never enter suppression: ``decided_score`` is recorded
   as a #49 input, never read by this module.

#56 seam: ``reentry`` is ALWAYS ``False`` in this module (the ADR-0072 D4
"Interim between #47 and #56" clause) — ``suppressed_by_actor`` reduces to
"an active actor-scoped decision exists". Issue #56 implements the tier-based
``reentry`` predicate quoted above and wires it in where marked below.
"""
from __future__ import annotations

from collections.abc import Sequence

from firewatch_sdk.models import EscalationVerdict

from firewatch_core.triage.models import DecisionEvaluation, TriageDecision

#: Verbs that suppress by actor identity (fail2ban ``ignoreip`` precedent,
#: ADR-0070 D6) — ``false_positive`` is rule-scoped and excluded here.
_ACTOR_VERBS = frozenset({"expected", "dismissed"})


def _active_rows(decisions: Sequence[TriageDecision]) -> list[TriageDecision]:
    """Return only non-revoked rows — revoked rows never affect evaluation."""
    return [d for d in decisions if d.revoked_at is None]


def _latest_actor_decision(active: list[TriageDecision]) -> TriageDecision | None:
    """D4's ``A`` — latest active actor-scoped row, tie-broken by id."""
    candidates = [d for d in active if d.verb in _ACTOR_VERBS]
    if not candidates:
        return None
    return max(candidates, key=lambda d: (d.decided_at, d.id))


def _fp_rule_set(active: list[TriageDecision]) -> frozenset[str]:
    """D4's ``F`` — rule_name identities carrying an active false_positive row."""
    return frozenset(
        d.rule_name for d in active if d.verb == "false_positive" and d.rule_name
    )


def evaluate(
    decisions: Sequence[TriageDecision],
    verdict: EscalationVerdict | None,
) -> DecisionEvaluation:
    """Evaluate one actor's decision history against its CURRENT verdict (D4).

    Pure: no I/O, no clock reads — ``decided_at``/``revoked_at`` are
    pre-computed strings already on *decisions*; "current" means whatever
    *verdict* the caller passes (recomputed at read time, ADR-0041).

    ``verdict=None`` (no escalation verdict is available for this actor, e.g.
    the decider was not invoked) is treated as a verdict with ``tier=None``
    and no qualifying rules: ``suppressed_by_fp`` can never be True without a
    real verdict (fail-toward-visibility), while ``suppressed_by_actor`` is
    unaffected — actor-identity suppression does not consult the verdict at
    all under the #47 interim (reentry ≡ False).
    """
    active = _active_rows(decisions)
    actor_decision = _latest_actor_decision(active)

    # --- suppressed_by_actor -------------------------------------------------
    # SEAM (#56): D4 defines `suppressed_by_actor = A exists AND NOT
    # reentry(A, verdict)`. The ADR-0072 D4 "Interim between #47 and #56"
    # clause hardcodes reentry ≡ False until #56 lands, so this reduces to
    # "A exists". Replace with the full reentry predicate when #56 ships.
    suppressed_by_actor = actor_decision is not None

    # --- suppressed_by_fp -----------------------------------------------------
    fp_rules = _fp_rule_set(active)
    qualifying = frozenset(verdict.qualifying_rules) if verdict is not None else frozenset()
    verdict_tier = verdict.tier if verdict is not None else None
    # The `bool(qualifying)` check is REQUIRED, not redundant: an empty set is
    # a subset of any set, so `qualifying <= fp_rules` alone would let an
    # actor with no named qualifying rule (an anonymous ALERT) be
    # FP-suppressed by an unrelated FP row — exactly boundary 1 forbids.
    suppressed_by_fp = (
        verdict_tier is not None
        and bool(qualifying)
        and qualifying <= fp_rules
    )

    return DecisionEvaluation(
        suppressed=suppressed_by_actor or suppressed_by_fp,
        suppressed_by_actor=suppressed_by_actor,
        suppressed_by_fp=suppressed_by_fp,
        active_actor_decision=actor_decision,
        reentry=None,
    )
