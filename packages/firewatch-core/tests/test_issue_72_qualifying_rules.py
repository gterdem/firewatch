"""Tests for ADR-0072 D1 — additive ``qualifying_rules`` on ``EscalationVerdict``.

EARS criteria -> test mapping:

- D1: WHEN a qualifying Detection (D1a) fires, its ``rule_name`` SHALL appear
  in ``EscalationVerdict.qualifying_rules``.
  -> TestQualifyingRulesFromDetections

- D1: WHEN a qualifying ALERT event (D1b) carries a ``rule_name``, it SHALL
  appear in ``qualifying_rules``.
  -> TestQualifyingRulesFromAlertEvents

- D1/D4 boundary 1: WHEN the only qualifying signal is an anonymous ALERT
  (``rule_name=None``), ``qualifying_rules`` SHALL be empty even though the
  verdict is qualified/escalated.
  -> test_anonymous_alert_yields_empty_qualifying_rules

- Dedup: repeated rule identities SHALL appear once in ``qualifying_rules``.
  -> test_duplicate_rule_names_are_deduped

- Must-NOT (golden oracle): adding ``qualifying_rules`` SHALL NOT change
  ``tier``/``score_derivation``-relevant fields — verified by the existing
  ``tests/golden`` suite staying green (not re-asserted here; this module
  only pins the new field's population rules).

- Independent of chosen tier: qualifying_rules is populated from the SAME D1
  gate computation regardless of which tier branch the verdict took (ADR-0072
  D1 "produced queue entry" — the gate is computed once per actor).
  -> TestQualifyingRulesAcrossTiers

Fixture IPs are RFC 5737 documentation ranges only (203.0.113.0/24).
"""
from __future__ import annotations

from datetime import datetime, timezone

from firewatch_sdk.models import Detection, SecurityEvent

from firewatch_core.escalation.decider import decide
from firewatch_core.escalation.qualify import qualify

_IP = "203.0.113.30"
_T0 = datetime(2026, 6, 15, 8, 0, 0, tzinfo=timezone.utc)


def _ev(action: str, *, severity: str | None = None, rule_name: str | None = None) -> SecurityEvent:
    return SecurityEvent(
        source_type="suricata",
        source_id="pi-home",
        source_ip=_IP,
        action=action,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        rule_name=rule_name,
        timestamp=_T0,
    )


def _det(
    *,
    rule_name: str = "test_rule",
    severity: str | None = None,
    auto_escalate: bool = False,
) -> Detection:
    return Detection(
        source_ip=_IP,
        rule_name=rule_name,
        score_delta=10,
        reason="test",
        severity=severity,  # type: ignore[arg-type]
        auto_escalate=auto_escalate,
    )


# ---------------------------------------------------------------------------
# qualify.py: qualifying_alert_events (the new evidence field)
# ---------------------------------------------------------------------------


class TestQualifyingAlertEvents:
    def test_qualifying_alert_events_captures_high_severity_alert(self):
        event = _ev("ALERT", severity="high", rule_name="waf_sqli")
        result = qualify([event], [])
        assert result.qualifying_alert_events == (event,)

    def test_non_qualifying_events_are_excluded(self):
        low = _ev("ALERT", severity="low", rule_name="waf_low")
        log = _ev("LOG", severity="high", rule_name="log_only")
        result = qualify([low, log], [])
        assert result.qualifying_alert_events == ()


# ---------------------------------------------------------------------------
# decider.py: EscalationVerdict.qualifying_rules — D1(a) detections
# ---------------------------------------------------------------------------


class TestQualifyingRulesFromDetections:
    def test_auto_escalate_detection_rule_name_appears(self):
        det = _det(rule_name="brute_force_then_login", auto_escalate=True)
        verdict = decide([_ev("ALERT")], [det])
        assert verdict.qualifying_rules == ["brute_force_then_login"]

    def test_high_severity_detection_rule_name_appears(self):
        det = _det(rule_name="sqli_rule", severity="high")
        verdict = decide([_ev("ALERT")], [det])
        assert verdict.qualifying_rules == ["sqli_rule"]

    def test_non_qualifying_detection_contributes_nothing(self):
        det = _det(rule_name="low_rule", severity="low")
        verdict = decide([_ev("ALLOW")], [det])
        # ALLOW + detection -> Tier 1 (unconditional); the detection itself
        # never satisfied D1a, so it contributes no qualifying_rules entry.
        assert verdict.tier == 1
        assert verdict.qualifying_rules == []


# ---------------------------------------------------------------------------
# decider.py: EscalationVerdict.qualifying_rules — D1(b) ALERT events
# ---------------------------------------------------------------------------


class TestQualifyingRulesFromAlertEvents:
    def test_qualifying_alert_rule_name_appears(self):
        event = _ev("ALERT", severity="critical", rule_name="waf_xss")
        verdict = decide([event], [])
        assert verdict.tier == 2
        assert verdict.qualifying_rules == ["waf_xss"]

    def test_anonymous_alert_yields_empty_qualifying_rules(self):
        """ADR-0072 D4 fail-toward-visibility boundary 1."""
        event = _ev("ALERT", severity="high", rule_name=None)
        verdict = decide([event], [])
        assert verdict.tier == 2  # still escalates — D1(b) only needs severity
        assert verdict.qualifying_rules == []

    def test_duplicate_rule_names_are_deduped(self):
        det = _det(rule_name="shared_rule", auto_escalate=True)
        event = _ev("ALERT", severity="high", rule_name="shared_rule")
        verdict = decide([event], [det])
        assert verdict.qualifying_rules == ["shared_rule"]


# ---------------------------------------------------------------------------
# qualifying_rules is populated from the SAME D1 computation regardless of
# which tier branch ultimately wins (ADR-0072 D1).
# ---------------------------------------------------------------------------


class TestQualifyingRulesAcrossTiers:
    def test_tier3_persistent_block_actor_with_incidental_qualifying_detection(self):
        """A Tier-3 (persistent BLOCK) actor that ALSO carries a qualifying
        detection still gets qualifying_rules populated — the gate is
        computed once per actor, independent of which tier decide() emits.
        """
        blocks = [_ev("BLOCK") for _ in range(3)]
        det = _det(rule_name="auto_escalate_rule", auto_escalate=True)
        verdict = decide(blocks, [det])
        assert verdict.tier == 3
        assert verdict.qualifying_rules == ["auto_escalate_rule"]

    def test_observed_verdict_has_empty_qualifying_rules_when_nothing_qualifies(self):
        verdict = decide([_ev("ALERT", severity="low")], [])
        assert verdict.tier is None
        assert verdict.qualifying_rules == []
