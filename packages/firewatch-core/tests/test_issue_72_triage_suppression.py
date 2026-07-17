"""Tests for ``firewatch_core.triage.suppression.evaluate`` (ADR-0072 D4).

EARS criteria -> test mapping:

- D4 actor verbs: WHEN an active `expected` OR `dismissed` row exists for an
  actor, `suppressed_by_actor` (and therefore `suppressed`) SHALL be True.
  -> TestActorScopedSuppression

- D4 revocation: a revoked actor-scoped row SHALL NOT suppress.
  -> test_revoked_actor_decision_does_not_suppress

- D4 false_positive scoping: WHEN the verdict's qualifying_rules are a
  non-empty subset of the actor's active FP rule set, suppressed_by_fp SHALL
  be True; a DIFFERENT qualifying rule SHALL still queue the actor.
  -> TestFalsePositiveScoping

- D4 boundary 1 (fail-toward-visibility): an anonymous-qualifying verdict
  (qualifying_rules=[]) SHALL NEVER be FP-suppressed, even with an active FP
  row on file for the actor.
  -> test_empty_qualifying_rules_never_fp_suppressed

- D4 boundary 2: decided_score/volume SHALL NEVER affect suppression.
  -> test_decided_score_does_not_affect_suppression

- #56 reentry: WHEN a decided actor's tier was None and a tier now appears,
  suppressed_by_actor SHALL become False and `reentry` SHALL be populated.
  -> TestReentry.test_tier_appears_reenters
- #56 reentry: WHEN the current tier is numerically LOWER (louder) than the
  decided tier, suppressed_by_actor SHALL become False and `reentry` SHALL be
  populated.
  -> TestReentry.test_louder_tier_reenters
- #56 must-NOT: the SAME tier as decided_tier SHALL NOT reenter.
  -> TestReentry.test_same_tier_does_not_reenter
- #56 must-NOT: a HIGHER (quieter) tier number than decided_tier SHALL NOT
  reenter (only a strictly LOWER tier number qualifies).
  -> TestReentry.test_quieter_tier_does_not_reenter
- #56 must-NOT: a score increase ALONE (tier unchanged) SHALL NOT reenter —
  volume is never a re-entry trigger.
  -> TestReentry.test_score_increase_alone_does_not_reenter
- #56 must-NOT: a `false_positive` row (rule-scoped) never participates in
  snapshot reentry — only the actor-scoped `A` row is compared.
  -> TestReentry.test_false_positive_row_never_reenters
- #56 payload: the `reentry` payload carries decided_tier/decided_score/
  current_tier/current_score/decided_at as engine integers when it fires.
  -> TestReentry.test_reentry_payload_shape
- #56 re-decide semantics: the evaluator uses the LATEST active actor-scoped
  row as the baseline — a fresh decision after reentry stops the reentry.
  -> TestReentry.test_fresh_decision_after_reentry_uses_new_baseline

- verdict.tier is None (observed): suppressed_by_fp SHALL be False (the D4
  formula requires tier IS NOT None).
  -> test_observed_verdict_never_fp_suppressed

- verdict=None: suppressed_by_fp SHALL be False; suppressed_by_actor
  unaffected.
  -> TestNoneVerdict

- active_actor_decision surfaces the correct row (latest, tie-broken by id).
  -> test_latest_active_actor_decision_wins

Fixture IPs are RFC 5737 documentation ranges only (192.0.2.0/24).
"""
from __future__ import annotations

from firewatch_sdk.models import EscalationVerdict

from firewatch_core.triage.models import TriageDecision
from firewatch_core.triage.suppression import evaluate

_IP = "192.0.2.40"


def _decision(
    *,
    id: int = 1,
    verb: str = "expected",
    rule_name: str | None = None,
    decided_tier: int | None = 2,
    decided_score: int = 40,
    decided_at: str = "2026-07-01T00:00:00+00:00",
    revoked_at: str | None = None,
) -> TriageDecision:
    return TriageDecision(
        id=id,
        actor_ip=_IP,
        verb=verb,  # type: ignore[arg-type]
        rule_name=rule_name,
        decided_tier=decided_tier,
        decided_score=decided_score,
        decided_at=decided_at,
        revoked_at=revoked_at,
        author="local operator",
        note=None,
    )


def _verdict(
    *,
    tier: int | None = 2,
    qualifying_rules: list[str] | None = None,
) -> EscalationVerdict:
    return EscalationVerdict(
        tier=tier,
        disposition="observed" if tier is None else "block_status_unknown",
        justification="[RULE] test",
        block_status="unknown",
        qualifying_rules=qualifying_rules or [],
    )


# ---------------------------------------------------------------------------
# Actor-scoped suppression (expected / dismissed)
# ---------------------------------------------------------------------------


class TestActorScopedSuppression:
    def test_expected_suppresses(self):
        result = evaluate([_decision(verb="expected")], _verdict())
        assert result.suppressed_by_actor is True
        assert result.suppressed is True

    def test_dismissed_suppresses_same_as_expected(self):
        result = evaluate([_decision(verb="dismissed")], _verdict())
        assert result.suppressed_by_actor is True
        assert result.suppressed is True

    def test_no_decisions_does_not_suppress(self):
        result = evaluate([], _verdict())
        assert result.suppressed_by_actor is False
        assert result.suppressed is False
        assert result.active_actor_decision is None

    def test_revoked_actor_decision_does_not_suppress(self):
        decision = _decision(verb="expected", revoked_at="2026-07-02T00:00:00+00:00")
        result = evaluate([decision], _verdict())
        assert result.suppressed_by_actor is False
        assert result.active_actor_decision is None

    def test_latest_active_actor_decision_wins(self):
        older = _decision(id=1, verb="expected", decided_at="2026-07-01T00:00:00+00:00")
        newer = _decision(id=2, verb="dismissed", decided_at="2026-07-05T00:00:00+00:00")
        result = evaluate([older, newer], _verdict())
        assert result.active_actor_decision is not None
        assert result.active_actor_decision.id == 2
        assert result.active_actor_decision.verb == "dismissed"


# ---------------------------------------------------------------------------
# False-positive scoping (D4 — identity, not threshold)
# ---------------------------------------------------------------------------


class TestFalsePositiveScoping:
    def test_matching_fp_rule_suppresses(self):
        fp = _decision(id=1, verb="false_positive", rule_name="waf_sqli")
        verdict = _verdict(tier=2, qualifying_rules=["waf_sqli"])
        result = evaluate([fp], verdict)
        assert result.suppressed_by_fp is True
        assert result.suppressed is True

    def test_different_qualifying_rule_still_queues_actor(self):
        """ADR-0070 D6: a different qualifying signal still queues the actor."""
        fp = _decision(id=1, verb="false_positive", rule_name="waf_sqli")
        verdict = _verdict(tier=2, qualifying_rules=["waf_xss"])
        result = evaluate([fp], verdict)
        assert result.suppressed_by_fp is False
        assert result.suppressed is False

    def test_partial_rule_coverage_still_queues_actor(self):
        """Only ONE of two qualifying rules has an active FP row -> not fully
        covered -> the actor still re-queues (subset check, not intersection)."""
        fp = _decision(id=1, verb="false_positive", rule_name="waf_sqli")
        verdict = _verdict(tier=2, qualifying_rules=["waf_sqli", "waf_xss"])
        result = evaluate([fp], verdict)
        assert result.suppressed_by_fp is False

    def test_revoked_fp_row_does_not_suppress(self):
        fp = _decision(
            id=1, verb="false_positive", rule_name="waf_sqli",
            revoked_at="2026-07-02T00:00:00+00:00",
        )
        verdict = _verdict(tier=2, qualifying_rules=["waf_sqli"])
        result = evaluate([fp], verdict)
        assert result.suppressed_by_fp is False

    def test_empty_qualifying_rules_never_fp_suppressed(self):
        """D4 boundary 1 — an anonymous-source qualifying verdict can never be
        FP-suppressed, even with an (unrelated) active FP row on file."""
        fp = _decision(id=1, verb="false_positive", rule_name="waf_sqli")
        verdict = _verdict(tier=2, qualifying_rules=[])
        result = evaluate([fp], verdict)
        assert result.suppressed_by_fp is False
        assert result.suppressed is False


class TestObservedAndNoneVerdicts:
    def test_observed_verdict_never_fp_suppressed(self):
        """tier=None (observed) — D4 requires verdict.tier IS NOT None."""
        fp = _decision(id=1, verb="false_positive", rule_name="waf_sqli")
        verdict = _verdict(tier=None, qualifying_rules=["waf_sqli"])
        result = evaluate([fp], verdict)
        assert result.suppressed_by_fp is False

    def test_none_verdict_never_fp_suppressed(self):
        fp = _decision(id=1, verb="false_positive", rule_name="waf_sqli")
        result = evaluate([fp], None)
        assert result.suppressed_by_fp is False

    def test_none_verdict_actor_suppression_unaffected(self):
        result = evaluate([_decision(verb="expected")], None)
        assert result.suppressed_by_actor is True
        assert result.suppressed is True


# ---------------------------------------------------------------------------
# Boundary 2: score/volume never enters suppression
# ---------------------------------------------------------------------------


def test_decided_score_does_not_affect_suppression():
    low = evaluate([_decision(verb="expected", decided_score=1)], _verdict())
    high = evaluate([_decision(verb="expected", decided_score=100)], _verdict())
    assert low.suppressed == high.suppressed is True


# ---------------------------------------------------------------------------
# #56 — the reentry clause (ADR-0072 D4)
# ---------------------------------------------------------------------------


class TestReentry:
    def test_tier_appears_reenters(self):
        """decided_tier=None (observed at decision time) -> a tier now exists
        -> the actor re-enters the queue."""
        decision = _decision(verb="expected", decided_tier=None, decided_score=0)
        verdict = _verdict(tier=2)
        result = evaluate([decision], verdict)
        assert result.suppressed_by_actor is False
        assert result.suppressed is False
        assert result.reentry is not None
        assert result.reentry.decided_tier is None
        assert result.reentry.current_tier == 2

    def test_louder_tier_reenters(self):
        """decided_tier=2 -> current tier=1 (numerically lower = louder) ->
        the actor re-enters the queue."""
        decision = _decision(verb="dismissed", decided_tier=2, decided_score=40)
        verdict = _verdict(tier=1)
        result = evaluate([decision], verdict)
        assert result.suppressed_by_actor is False
        assert result.suppressed is False
        assert result.reentry is not None
        assert result.reentry.decided_tier == 2
        assert result.reentry.current_tier == 1

    def test_same_tier_does_not_reenter(self):
        """must-NOT: an unchanged tier holds the decision — no reentry."""
        decision = _decision(verb="expected", decided_tier=2, decided_score=40)
        verdict = _verdict(tier=2)
        result = evaluate([decision], verdict)
        assert result.suppressed_by_actor is True
        assert result.suppressed is True
        assert result.reentry is None

    def test_quieter_tier_does_not_reenter(self):
        """must-NOT: a numerically HIGHER (quieter) tier than decided_tier is
        not a reentry — only a strictly LOWER tier number qualifies."""
        decision = _decision(verb="expected", decided_tier=2, decided_score=40)
        verdict = _verdict(tier=3)
        result = evaluate([decision], verdict)
        assert result.suppressed_by_actor is True
        assert result.reentry is None

    def test_score_increase_alone_does_not_reenter(self):
        """must-NOT (the EARS WHILE clause): volume/score growth alone, with
        the tier held constant, is NEVER a re-entry trigger."""
        decision = _decision(verb="expected", decided_tier=2, decided_score=10)
        verdict = _verdict(tier=2)
        result = evaluate([decision], verdict, current_score=95)
        assert result.suppressed_by_actor is True
        assert result.suppressed is True
        assert result.reentry is None

    def test_false_positive_row_never_reenters(self):
        """must-NOT: a `false_positive` row is rule-scoped, not actor-scoped —
        it never participates in snapshot reentry (only `A`, the latest
        active expected/dismissed row, is compared)."""
        fp = _decision(id=1, verb="false_positive", rule_name="waf_sqli", decided_tier=3)
        verdict = _verdict(tier=1, qualifying_rules=["waf_sqli"])
        result = evaluate([fp], verdict)
        assert result.active_actor_decision is None
        assert result.reentry is None
        # Still FP-suppressed via coverage, not snapshot reentry (§2/D4).
        assert result.suppressed_by_fp is True

    def test_reentry_payload_shape(self):
        """The reentry payload carries engine integers only — decided_tier/
        decided_score/current_tier/current_score/decided_at."""
        decision = _decision(
            verb="expected", decided_tier=None, decided_score=15,
            decided_at="2026-07-10T00:00:00+00:00",
        )
        verdict = _verdict(tier=2)
        result = evaluate([decision], verdict, current_score=61)
        assert result.reentry is not None
        assert result.reentry.decided_tier is None
        assert result.reentry.decided_score == 15
        assert result.reentry.current_tier == 2
        assert result.reentry.current_score == 61
        assert result.reentry.decided_at == "2026-07-10T00:00:00+00:00"

    def test_fresh_decision_after_reentry_uses_new_baseline(self):
        """Re-decide semantics: a NEW decision row (a fresh server snapshot,
        e.g. after an operator re-decides a re-entered actor) becomes the
        evaluator's baseline — the latest active row always wins."""
        stale = _decision(
            id=1, verb="expected", decided_tier=None,
            decided_at="2026-07-01T00:00:00+00:00",
        )
        fresh = _decision(
            id=2, verb="expected", decided_tier=2,
            decided_at="2026-07-05T00:00:00+00:00",
        )
        verdict = _verdict(tier=2)  # matches the FRESH baseline, not the stale one
        result = evaluate([stale, fresh], verdict)
        assert result.active_actor_decision is not None
        assert result.active_actor_decision.id == 2
        assert result.suppressed_by_actor is True
        assert result.reentry is None
