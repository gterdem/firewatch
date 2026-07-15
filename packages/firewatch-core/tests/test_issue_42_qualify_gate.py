"""Tests for issue #42 — the assertion gate (ADR-0067 D1).

EARS criteria -> test mapping (from ADR-0067 D1 / issue #42):

- D1a: WHEN a Detection has auto_escalate=True OR declared severity in
  {high, critical}, qualify() SHALL report qualified=True and include that
  Detection in qualifying_detections.
  -> TestQualifyDetectionGate

- D1b: WHEN an ALERT event carries source-declared severity in {high, critical},
  qualify() SHALL report qualified=True even with zero detections.
  -> TestQualifyEventSeverityGate

- D1/RC4: LOG events SHALL never self-qualify, regardless of declared severity.
  -> TestLogNeverSelfQualifies

- D3 (fail-quiet): severity=None (event or detection) with no auto_escalate
  SHALL NOT qualify.
  -> TestFailQuietOnUndeclaredSeverity

- Evidence: qualifying_detections / qualifying_event_severity carry the
  evidence used to build the justification (pure, testable in isolation).
  -> TestQualifyResultEvidence

Fixture IPs are RFC 5737 documentation ranges only (203.0.113.0/24).
"""
from __future__ import annotations

from datetime import datetime, timezone

from firewatch_sdk.models import Detection, SecurityEvent

from firewatch_core.escalation.qualify import QualifyResult, qualify

_IP = "203.0.113.20"
_T0 = datetime(2026, 6, 15, 8, 0, 0, tzinfo=timezone.utc)


def _ev(action: str, *, severity: str | None = None) -> SecurityEvent:
    return SecurityEvent(
        source_type="suricata",
        source_id="pi-home",
        source_ip=_IP,
        action=action,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
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
# D1(a) — detection-based qualification
# ---------------------------------------------------------------------------

class TestQualifyDetectionGate:
    """D1(a): auto_escalate=True OR declared severity in {high, critical}."""

    def test_auto_escalate_true_qualifies(self):
        result = qualify([], [_det(auto_escalate=True)])
        assert result.qualified is True

    def test_severity_high_qualifies(self):
        result = qualify([], [_det(severity="high")])
        assert result.qualified is True

    def test_severity_critical_qualifies(self):
        result = qualify([], [_det(severity="critical")])
        assert result.qualified is True

    def test_severity_medium_does_not_qualify(self):
        """Medium severity without auto_escalate is below the D1a bar."""
        result = qualify([], [_det(severity="medium")])
        assert result.qualified is False

    def test_severity_low_does_not_qualify(self):
        result = qualify([], [_det(severity="low")])
        assert result.qualified is False

    def test_no_severity_no_auto_escalate_does_not_qualify(self):
        """Default Detection() — the ADR-0058 non-escalating default — must not qualify."""
        result = qualify([], [_det()])
        assert result.qualified is False

    def test_qualifying_detection_included_in_evidence(self):
        det = _det(rule_name="brute_force_then_login", auto_escalate=True)
        result = qualify([], [det])
        assert det in result.qualifying_detections

    def test_non_qualifying_detection_excluded_from_evidence(self):
        det = _det(severity="medium")
        result = qualify([], [det])
        assert det not in result.qualifying_detections

    def test_mixed_detections_only_qualifying_ones_in_evidence(self):
        weak = _det(rule_name="weak_rule", severity="medium")
        strong = _det(rule_name="strong_rule", auto_escalate=True)
        result = qualify([], [weak, strong])
        assert result.qualified is True
        assert strong in result.qualifying_detections
        assert weak not in result.qualifying_detections

    def test_no_detections_no_events_does_not_qualify(self):
        result = qualify([], [])
        assert result.qualified is False


# ---------------------------------------------------------------------------
# D1(b) — event-severity-based qualification (zero detections)
# ---------------------------------------------------------------------------

class TestQualifyEventSeverityGate:
    """D1(b): ALERT with source-declared severity high/critical, zero detections."""

    def test_alert_high_severity_qualifies_with_zero_detections(self):
        result = qualify([_ev("ALERT", severity="high")], [])
        assert result.qualified is True

    def test_alert_critical_severity_qualifies_with_zero_detections(self):
        result = qualify([_ev("ALERT", severity="critical")], [])
        assert result.qualified is True

    def test_alert_medium_severity_does_not_qualify(self):
        result = qualify([_ev("ALERT", severity="medium")], [])
        assert result.qualified is False

    def test_alert_low_severity_does_not_qualify(self):
        result = qualify([_ev("ALERT", severity="low")], [])
        assert result.qualified is False

    def test_qualifying_severity_recorded_in_evidence(self):
        result = qualify([_ev("ALERT", severity="high")], [])
        assert result.qualifying_event_severity == "high"

    def test_highest_severity_wins_when_multiple_qualifying_events(self):
        events = [_ev("ALERT", severity="high"), _ev("ALERT", severity="critical")]
        result = qualify(events, [])
        assert result.qualifying_event_severity == "critical"

    def test_single_unmistakable_alert_qualifies_alone(self):
        """D1(b) rationale: a single unmistakable attack banners now, unconditionally."""
        result = qualify([_ev("ALERT", severity="critical")], [])
        assert result.qualified is True
        assert len(result.qualifying_detections) == 0


# ---------------------------------------------------------------------------
# D1 / RC4 — LOG never self-qualifies
# ---------------------------------------------------------------------------

class TestLogNeverSelfQualifies:
    """LOG is ECS kind:event (telemetry) — never an assertion, even with high severity."""

    def test_log_high_severity_does_not_qualify(self):
        result = qualify([_ev("LOG", severity="high")], [])
        assert result.qualified is False

    def test_log_critical_severity_does_not_qualify(self):
        result = qualify([_ev("LOG", severity="critical")], [])
        assert result.qualified is False

    def test_log_never_recorded_as_qualifying_severity(self):
        result = qualify([_ev("LOG", severity="critical")], [])
        assert result.qualifying_event_severity is None

    def test_log_qualifies_only_via_detection(self):
        """LOG escalates only via D1(a) — a qualifying detection alongside it."""
        result = qualify([_ev("LOG", severity="critical")], [_det(auto_escalate=True)])
        assert result.qualified is True
        # The qualification comes from the detection, not the LOG event's severity.
        assert result.qualifying_event_severity is None


# ---------------------------------------------------------------------------
# D3 — fail-quiet on undeclared severity
# ---------------------------------------------------------------------------

class TestFailQuietOnUndeclaredSeverity:
    """D3: severity=None with no auto_escalate -> does not qualify (maintainer ruling 1)."""

    def test_alert_with_severity_none_does_not_qualify(self):
        result = qualify([_ev("ALERT", severity=None)], [])
        assert result.qualified is False

    def test_bare_alert_no_detection_does_not_qualify(self):
        result = qualify([_ev("ALERT")], [])
        assert result.qualified is False

    def test_bare_log_no_detection_does_not_qualify(self):
        result = qualify([_ev("LOG")], [])
        assert result.qualified is False

    def test_many_unqualified_alerts_still_does_not_qualify(self):
        """Volume alone never substitutes for a qualifying assertion (D1)."""
        events = [_ev("ALERT") for _ in range(500)]
        result = qualify(events, [])
        assert result.qualified is False


# ---------------------------------------------------------------------------
# QualifyResult evidence shape
# ---------------------------------------------------------------------------

class TestQualifyResultEvidence:
    def test_qualify_returns_qualify_result(self):
        result = qualify([], [])
        assert isinstance(result, QualifyResult)

    def test_unqualified_result_has_empty_detections_and_none_severity(self):
        result = qualify([_ev("ALERT")], [])
        assert result.qualifying_detections == ()
        assert result.qualifying_event_severity is None

    def test_qualify_result_is_frozen(self):
        from dataclasses import FrozenInstanceError

        import pytest

        result = qualify([], [])
        with pytest.raises(FrozenInstanceError):
            result.qualified = True  # type: ignore[misc]

    def test_qualify_is_pure_no_mutation_of_inputs(self):
        events = [_ev("ALERT", severity="high")]
        detections = [_det(auto_escalate=True)]
        events_copy = list(events)
        detections_copy = list(detections)
        qualify(events, detections)
        assert events == events_copy
        assert detections == detections_copy

    def test_allow_events_never_qualify_via_severity(self):
        """D1(b) is scoped to ALERT only — ALLOW carrying severity is not an assertion path."""
        result = qualify([_ev("ALLOW", severity="critical")], [])
        assert result.qualified is False

    def test_block_events_never_qualify_via_severity(self):
        """D1(b) is scoped to ALERT only — BLOCK/DROP route through tiers 3/4, not the gate."""
        result = qualify([_ev("BLOCK", severity="critical")], [])
        assert result.qualified is False
