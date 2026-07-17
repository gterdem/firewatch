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

- D4 interim (#47, reentry ≡ False): an actor-scoped decision SHALL suppress
  regardless of any tier change until #56 lands.
  -> test_reentry_is_always_false_in_this_module

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
# #47 interim: reentry is always False (the #56 seam)
# ---------------------------------------------------------------------------


def test_reentry_is_always_false_in_this_module():
    """Even a verdict at a LOWER (louder) tier than decided_tier must stay
    suppressed under the #47 interim — #56 is the only PR allowed to change
    this (ADR-0072 D4 'Interim between #47 and #56')."""
    decision = _decision(verb="expected", decided_tier=None, decided_score=0)
    verdict = _verdict(tier=1)  # would satisfy the #56 reentry predicate
    result = evaluate([decision], verdict)
    assert result.suppressed_by_actor is True
    assert result.reentry is None
