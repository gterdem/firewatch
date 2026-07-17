"""Tests for issue #647 — Per-detection declared severity + escalation policy (ADR-0058 C foundation).

EARS criteria → test mapping:
- EARS-1: WHERE a rule declares severity, Detection SHALL have severity + auto_escalate attached.
- EARS-2: WHEN a rule has no declared metadata, Detection SHALL default severity=None,
          auto_escalate=False, with zero change to score/threat_level/existing fields.
- EARS-3: WHERE Detection model is extended, the two additive fields SHALL default-conform so
          existing plugins remain conformant (backward-compat).
- EARS-4: WHILE existing golden tests run, scores SHALL be byte-identical (no oracle movement).

Tests cover:
  - Detection model new fields + defaults (EARS-2, EARS-3)
  - SeverityOrder total ordering (model.py)
  - EscalationPolicyRegistry: register, lookup, default when absent (EARS-1, EARS-2)
  - detector.py rules carry declared severities via policy registry (EARS-1)
  - Undeclared rules default to (None, False) (EARS-2)
  - Detection.severity + auto_escalate populated by detector when rule is registered (EARS-1)
"""

from datetime import datetime, timedelta, timezone

from firewatch_sdk import Detection
from firewatch_sdk.models import SeverityLiteral

from firewatch_core.escalation.model import SeverityOrder, SEVERITY_RANKS
from firewatch_core.escalation.policy import EscalationPolicyRegistry, RulePolicy

from firewatch_core.detector import detect
from _fakes import make_event

T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# EARS-3 — Detection model additive fields are backward-compatible defaults
# ---------------------------------------------------------------------------

class TestDetectionModelDefaults:
    """Detection constructed without new fields keeps old behavior (EARS-2, EARS-3)."""

    def test_detection_default_severity_is_none(self):
        d = Detection(
            source_ip="203.0.113.1",
            rule_name="some_rule",
            score_delta=10,
            reason="test",
        )
        assert d.severity is None

    def test_detection_default_auto_escalate_is_false(self):
        d = Detection(
            source_ip="203.0.113.1",
            rule_name="some_rule",
            score_delta=10,
            reason="test",
        )
        assert d.auto_escalate is False

    def test_detection_explicit_severity_accepted(self):
        d = Detection(
            source_ip="203.0.113.1",
            rule_name="some_rule",
            score_delta=10,
            reason="test",
            severity="high",
        )
        assert d.severity == "high"

    def test_detection_explicit_auto_escalate_accepted(self):
        d = Detection(
            source_ip="203.0.113.1",
            rule_name="some_rule",
            score_delta=10,
            reason="test",
            auto_escalate=True,
        )
        assert d.auto_escalate is True

    def test_detection_existing_fields_unchanged(self):
        """score_delta, reason, matched_event_ids are not affected by the new fields."""
        d = Detection(
            source_ip="198.51.100.5",
            rule_name="brute_force_then_login",
            score_delta=30,
            reason="SSH brute-force compromise",
            matched_event_ids=["a", "b"],
            severity="critical",
            auto_escalate=True,
        )
        assert d.score_delta == 30
        assert d.reason == "SSH brute-force compromise"
        assert d.matched_event_ids == ["a", "b"]


# ---------------------------------------------------------------------------
# escalation/model.py — SeverityOrder total ordering (Sigma level anchoring)
# ---------------------------------------------------------------------------

class TestSeverityOrder:
    """SeverityOrder must implement total ordering consistent with Sigma level vocabulary."""

    def test_info_is_lowest(self):
        assert SeverityOrder("info") < SeverityOrder("low")

    def test_low_less_than_medium(self):
        assert SeverityOrder("low") < SeverityOrder("medium")

    def test_medium_less_than_high(self):
        assert SeverityOrder("medium") < SeverityOrder("high")

    def test_high_less_than_critical(self):
        assert SeverityOrder("high") < SeverityOrder("critical")

    def test_critical_is_highest(self):
        assert SeverityOrder("critical") > SeverityOrder("high")

    def test_equal_severity(self):
        assert SeverityOrder("high") == SeverityOrder("high")

    def test_not_equal(self):
        assert SeverityOrder("low") != SeverityOrder("high")

    def test_sort_order(self):
        levels: list[SeverityLiteral] = ["critical", "info", "high", "low", "medium"]
        sorted_levels = [s.level for s in sorted(SeverityOrder(lv) for lv in levels)]
        assert sorted_levels == ["info", "low", "medium", "high", "critical"]

    def test_severity_ranks_has_all_five_sigma_levels(self):
        """SEVERITY_RANKS must cover all five Sigma level vocabulary entries."""
        assert set(SEVERITY_RANKS.keys()) == {"info", "low", "medium", "high", "critical"}

    def test_severity_ranks_monotonically_increasing(self):
        """Rank integers must be strictly ordered: info < low < medium < high < critical."""
        levels = ["info", "low", "medium", "high", "critical"]
        ranks = [SEVERITY_RANKS[lv] for lv in levels]
        assert ranks == sorted(ranks) and len(set(ranks)) == 5


# ---------------------------------------------------------------------------
# escalation/policy.py — EscalationPolicyRegistry
# ---------------------------------------------------------------------------

class TestEscalationPolicyRegistry:
    """Registry correctly stores and retrieves per-rule severity + auto_escalate."""

    def test_register_and_lookup(self):
        reg = EscalationPolicyRegistry()
        reg.register("brute_force_then_login", severity="critical", auto_escalate=True)
        policy = reg.get("brute_force_then_login")
        assert policy is not None
        assert policy.severity == "critical"
        assert policy.auto_escalate is True

    def test_unregistered_rule_returns_none(self):
        reg = EscalationPolicyRegistry()
        assert reg.get("nonexistent_rule") is None

    def test_default_policy_no_severity_no_escalate(self):
        """EARS-2: absent rule defaults to (None, False)."""
        reg = EscalationPolicyRegistry()
        policy = reg.get_or_default("any_rule")
        assert policy.severity is None
        assert policy.auto_escalate is False

    def test_register_low_severity_no_escalate(self):
        reg = EscalationPolicyRegistry()
        reg.register("noisy_rule", severity="low", auto_escalate=False)
        policy = reg.get("noisy_rule")
        assert policy is not None
        assert policy.severity == "low"
        assert policy.auto_escalate is False

    def test_register_multiple_rules(self):
        reg = EscalationPolicyRegistry()
        reg.register("rule_a", severity="high", auto_escalate=True)
        reg.register("rule_b", severity="low", auto_escalate=False)
        assert reg.get("rule_a").severity == "high"   # type: ignore[union-attr]
        assert reg.get("rule_b").severity == "low"    # type: ignore[union-attr]

    def test_rule_policy_dataclass_fields(self):
        """RulePolicy must expose severity and auto_escalate fields."""
        p = RulePolicy(severity="medium", auto_escalate=False)
        assert p.severity == "medium"
        assert p.auto_escalate is False

    def test_rule_policy_default_auto_escalate_false(self):
        p = RulePolicy(severity="info")
        assert p.auto_escalate is False

    def test_rule_policy_none_severity(self):
        p = RulePolicy(severity=None)
        assert p.severity is None


# ---------------------------------------------------------------------------
# detector.py — declared severities populated on Detection output (EARS-1)
# ---------------------------------------------------------------------------

class TestDetectorDeclaredSeverity:
    """The built-in rules in detector.py must produce Detections with declared severity
    metadata from the policy registry (EARS-1).  Rules not in the registry default
    to (None, False) and must not change any score field (EARS-2).
    """

    def _make_ids_then_bf_events(self):
        events = [make_event(source_type="suricata", category="IDS Alert", timestamp=T0, action="ALERT")]
        events += [
            make_event(
                source_type="syslog", category="SSH Brute Force",
                timestamp=T0 + timedelta(minutes=i), action="ALERT",
            )
            for i in range(3)
        ]
        return events

    def _make_brute_force_login_events(self):
        events = [
            make_event(category="SSH Brute Force", timestamp=T0 + timedelta(minutes=i))
            for i in range(3)
        ]
        events.append(make_event(category="SSH Login", timestamp=T0 + timedelta(minutes=10)))
        return events

    def _make_multi_source_events(self):
        return [
            make_event(source_type="suricata", timestamp=T0, action="ALERT"),
            make_event(source_type="syslog", timestamp=T0 + timedelta(minutes=5), action="ALERT"),
        ]

    def _make_attempt_pressure_events(self):
        return [
            make_event(action="BLOCK", timestamp=T0 + timedelta(minutes=4 * i))
            for i in range(10)  # spans 36 min; decayed mass clears theta_press
        ]

    def _find(self, detections, rule_name):
        return next((d for d in detections if d.rule_name == rule_name), None)

    def test_ids_then_brute_force_has_severity(self):
        detections = detect(self._make_ids_then_bf_events(), now=T0 + timedelta(hours=1))
        d = self._find(detections, "ids_then_brute_force")
        assert d is not None
        assert d.severity is not None, "ids_then_brute_force must declare a severity"

    def test_ids_then_brute_force_severity_is_sigma_level(self):
        detections = detect(self._make_ids_then_bf_events(), now=T0 + timedelta(hours=1))
        d = self._find(detections, "ids_then_brute_force")
        assert d is not None
        assert d.severity in ("info", "low", "medium", "high", "critical")

    def test_brute_force_then_login_has_severity(self):
        detections = detect(self._make_brute_force_login_events(), now=T0 + timedelta(hours=1))
        d = self._find(detections, "brute_force_then_login")
        assert d is not None
        assert d.severity is not None

    def test_brute_force_then_login_auto_escalate_is_bool(self):
        detections = detect(self._make_brute_force_login_events(), now=T0 + timedelta(hours=1))
        d = self._find(detections, "brute_force_then_login")
        assert d is not None
        assert isinstance(d.auto_escalate, bool)

    def test_multi_source_attack_has_severity(self):
        detections = detect(self._make_multi_source_events(), now=T0 + timedelta(hours=1))
        d = self._find(detections, "multi_source_attack")
        assert d is not None
        assert d.severity is not None

    def test_attempt_pressure_has_severity(self):
        events = self._make_attempt_pressure_events()
        detections = detect(events, now=T0 + timedelta(minutes=36))
        d = self._find(detections, "attempt_pressure")
        assert d is not None
        assert d.severity is not None

    def test_brute_force_then_login_is_high_severity_or_critical(self):
        """Credential compromise is at minimum high per Sigma level conventions."""
        detections = detect(self._make_brute_force_login_events(), now=T0 + timedelta(hours=1))
        d = self._find(detections, "brute_force_then_login")
        assert d is not None
        # EARS-1: rule must declare a meaningful level (not just 'info')
        assert d.severity in ("high", "critical")

    def test_brute_force_then_login_auto_escalates(self):
        """Credential-compromise detection should auto-escalate (EARS-1)."""
        detections = detect(self._make_brute_force_login_events(), now=T0 + timedelta(hours=1))
        d = self._find(detections, "brute_force_then_login")
        assert d is not None
        assert d.auto_escalate is True

    def test_score_delta_unchanged_by_severity_metadata(self):
        """EARS-2: adding severity metadata must NOT alter score_delta values."""
        detections = detect(self._make_brute_force_login_events(), now=T0 + timedelta(hours=1))
        d = self._find(detections, "brute_force_then_login")
        assert d is not None
        assert d.score_delta == 30  # verbatim from original rule

    def test_ids_then_brute_force_score_delta_unchanged(self):
        detections = detect(self._make_ids_then_bf_events(), now=T0 + timedelta(hours=1))
        d = self._find(detections, "ids_then_brute_force")
        assert d is not None
        assert d.score_delta == 20  # verbatim from original rule


# ---------------------------------------------------------------------------
# EARS-2 — Unregistered rules default to (None, False)
# ---------------------------------------------------------------------------

class TestUnregisteredRuleDefaults:
    """EARS-2: a rule not in the registry must produce severity=None, auto_escalate=False."""

    def test_unknown_rule_default_severity(self):
        """Detection created without registry lookup keeps defaults."""
        d = Detection(
            source_ip="203.0.113.1",
            rule_name="future_unknown_rule",
            score_delta=5,
            reason="some match",
        )
        assert d.severity is None
        assert d.auto_escalate is False

    def test_policy_registry_default_fallback(self):
        """get_or_default always returns a non-None RulePolicy with safe defaults."""
        reg = EscalationPolicyRegistry()
        p = reg.get_or_default("totally_unknown")
        assert p.severity is None
        assert p.auto_escalate is False
