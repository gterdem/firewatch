"""Tests for issues #723 + #724 — partial block_status + disposition_counts.
Updated for issue #42 (ADR-0067 D1/D2) — the assertion-gated Tier-2 entry means
an unqualified ALERT/LOG mass no longer outranks a confirmed BLOCK/DROP class;
see the ADR-0067 D8 re-bless note on ``TestDeciderMixedActor`` below.

ADR-0058 Amendment 1 (A1-A5):
- #723: SDK EscalationBlockStatusLiteral += 'partial'; DispositionCounts model;
        EscalationVerdict.disposition_counts optional field.
- #724: Decider full-tally rewrite — no more short-circuit; partial block_status
        + disposition_counts on every verdict; mixed justification builder.

EARS criteria → test mapping
─────────────────────────────
#723 EARS-1: block_status='partial' is a valid EscalationVerdict value.
  → TestSDKPartialLiteral.test_partial_literal_accepted

#723 EARS-2: disposition_counts serialises to JSON with integer counts.
  → TestSDKDispositionCounts.test_json_serialisation

#723 EARS-3: EscalationVerdict without disposition_counts is still valid (additive).
  → TestSDKDispositionCounts.test_optional_field_defaults_none

#724 EARS-1: Mixed actor → block_status='partial'.
  → TestDeciderMixedActor.test_block_status_partial

#724 EARS-2: block_status='partial' → disposition_counts has correct integers.
  → TestDeciderMixedActor.test_disposition_counts_*

#724 EARS-3: BLOCK events must NOT be discarded when ALERT events are also present.
  → TestDeciderMixedActor.test_block_events_not_discarded

#724 EARS-4: Single-class actors keep exact pre-amendment behaviour (subject to the
  #42/ADR-0067 D1 gate — a single-class ALERT/LOG actor with no qualifying signal is
  now 'observed', not Tier 2; see TestDeciderSingleClassRegression).
  → TestDeciderSingleClassRegression.*

#724 EARS-5: Mixed actor tier = loudest *qualifying* action's tier (priority unchanged
  by #42; only which classes are eligible to be "loudest" changed).
  → TestDeciderMixedActor.test_tier_is_loudest_qualifying_action

#724 EARS-6: Mixed justification is RULE-tagged, integers only, no attacker fields.
  → TestDeciderMixedActor.test_justification_rule_tagged
  → TestDeciderMixedActor.test_justification_no_attacker_fields
  → TestDeciderMixedActor.test_justification_contains_counts

Test IPs are RFC 5737 documentation ranges only (192.0.2.x, 198.51.100.x, 203.0.113.x).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from firewatch_sdk.models import (
    Detection,
    DispositionCounts,
    EscalationVerdict,
    SecurityEvent,
)
from firewatch_core.escalation.decider import (
    _PERSISTENCE_THRESHOLD,
    _build_justification_partial,
    _is_mixed,
    _tally,
    decide,
)

_T0 = datetime(2026, 6, 15, 9, 0, 0, tzinfo=timezone.utc)
# RFC 5737 TEST-NET-3
_IP_A = "203.0.113.10"
# RFC 5737 TEST-NET-2
_IP_B = "198.51.100.20"
# RFC 5737 TEST-NET-1
_IP_C = "192.0.2.30"


def _ev(action: str, *, ip: str = _IP_A, severity: str | None = None) -> SecurityEvent:
    return SecurityEvent(
        source_type="suricata",
        source_id="pi-home",
        source_ip=ip,
        action=action,  # type: ignore[arg-type]
        timestamp=_T0,
        severity=severity,  # type: ignore[arg-type]
    )


def _det(*, auto_escalate: bool = False) -> Detection:
    return Detection(
        source_ip=_IP_A,
        rule_name="test_rule",
        score_delta=10,
        reason="test detection",
        auto_escalate=auto_escalate,
    )


# ===========================================================================
# SDK model tests (#723)
# ===========================================================================

class TestSDKPartialLiteral:
    """#723 EARS-1 — 'partial' is a valid EscalationBlockStatusLiteral."""

    def test_partial_literal_accepted(self):
        """EscalationVerdict must accept block_status='partial' without validation error."""
        verdict = EscalationVerdict(
            tier=2,
            disposition="block_status_unknown",
            justification="[RULE] test",
            block_status="partial",
        )
        assert verdict.block_status == "partial"

    def test_existing_literals_still_valid(self):
        """Pre-amendment literals (blocked/allowed/unknown) must still be accepted."""
        for status in ("blocked", "allowed", "unknown"):
            v = EscalationVerdict(
                tier=4,
                disposition="blocked_one_off",
                justification="[RULE] test",
                block_status=status,  # type: ignore[arg-type]
            )
            assert v.block_status == status

    def test_invalid_literal_rejected(self):
        """An invalid block_status must raise a Pydantic ValidationError."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            EscalationVerdict(
                tier=2,
                disposition="block_status_unknown",
                justification="[RULE] test",
                block_status="completely_wrong",  # type: ignore[arg-type]
            )


class TestSDKDispositionCounts:
    """#723 EARS-2/3 — DispositionCounts model + EscalationVerdict.disposition_counts."""

    def test_disposition_counts_defaults(self):
        """DispositionCounts must default all fields to 0."""
        dc = DispositionCounts()
        assert dc.blocked == 0
        assert dc.alert_unknown == 0
        assert dc.allowed == 0

    def test_disposition_counts_construction(self):
        """DispositionCounts must accept explicit integer values."""
        dc = DispositionCounts(blocked=9, alert_unknown=307, allowed=0)
        assert dc.blocked == 9
        assert dc.alert_unknown == 307
        assert dc.allowed == 0

    def test_json_serialisation(self):
        """disposition_counts must serialise to JSON with integer fields."""
        dc = DispositionCounts(blocked=3, alert_unknown=9, allowed=1)
        data = dc.model_dump()
        assert data == {"blocked": 3, "alert_unknown": 9, "allowed": 1}

    def test_optional_field_defaults_none(self):
        """#723 EARS-3: EscalationVerdict without disposition_counts is still valid."""
        v = EscalationVerdict(
            tier=3,
            disposition="blocked_persistent",
            justification="[RULE] test",
            block_status="blocked",
        )
        assert v.disposition_counts is None  # additive — not a required field

    def test_verdict_with_disposition_counts(self):
        """EscalationVerdict with disposition_counts set must serialise correctly."""
        dc = DispositionCounts(blocked=3, alert_unknown=9, allowed=0)
        v = EscalationVerdict(
            tier=2,
            disposition="block_status_unknown",
            justification="[RULE] mixed",
            block_status="partial",
            disposition_counts=dc,
        )
        data = v.model_dump()
        assert data["block_status"] == "partial"
        assert data["disposition_counts"] == {"blocked": 3, "alert_unknown": 9, "allowed": 0}


# ===========================================================================
# Decider internal helpers
# ===========================================================================

class TestTallyHelper:
    """Unit tests for the _tally() helper."""

    def test_pure_block(self):
        events = [_ev("BLOCK"), _ev("DROP")]
        assert _tally(events) == (2, 0, 0)

    def test_pure_alert(self):
        events = [_ev("ALERT"), _ev("LOG")]
        assert _tally(events) == (0, 2, 0)

    def test_pure_allow(self):
        events = [_ev("ALLOW"), _ev("ALLOW")]
        assert _tally(events) == (0, 0, 2)

    def test_mixed_alert_and_block(self):
        events = [_ev("ALERT")] * 9 + [_ev("BLOCK")] * 3
        assert _tally(events) == (3, 9, 0)

    def test_empty(self):
        assert _tally([]) == (0, 0, 0)


class TestIsMixedHelper:
    """Unit tests for the _is_mixed() helper."""

    def test_single_class_not_mixed(self):
        assert _is_mixed(5, 0, 0) is False
        assert _is_mixed(0, 5, 0) is False
        assert _is_mixed(0, 0, 5) is False

    def test_two_classes_is_mixed(self):
        assert _is_mixed(3, 9, 0) is True
        assert _is_mixed(0, 5, 2) is True
        assert _is_mixed(2, 0, 1) is True

    def test_three_classes_is_mixed(self):
        assert _is_mixed(1, 1, 1) is True

    def test_all_zero_not_mixed(self):
        assert _is_mixed(0, 0, 0) is False


# ===========================================================================
# Decider mixed-actor tests (#724)
# ===========================================================================

class TestDeciderMixedActor:
    """#724 EARS-1 through EARS-6 — mixed actor behaviour.

    ADR-0067 D8 re-bless (issue #42): ``alert_and_block_verdict`` below is the
    same fixture shape as ``tests/golden/test_mixed_actor_escalation.py``'s
    mixed-actor pin — 9 unqualified ALERT + 3 confirmed BLOCK/DROP, no
    detections. It moves from tier=2/block_status_unknown to
    tier=3/blocked_persistent for the same reason documented there: the 9
    ALERT events assert nothing (no detection, no declared severity — ADR-0067
    D1), so the loudest *qualifying* class is the 3 confirmed blocks.
    ``block_status='partial'`` and ``disposition_counts`` are unchanged.
    """

    @pytest.fixture(scope="class")
    def alert_and_block_verdict(self):
        """9 ALERT + 3 BLOCK events — mirrors the real-world 142.x actor shape."""
        events = [_ev("ALERT")] * 9 + [_ev("BLOCK")] * 3
        return decide(events, [])

    # EARS-1
    def test_block_status_partial(self, alert_and_block_verdict):
        assert alert_and_block_verdict.block_status == "partial"

    # EARS-3: BLOCK events must NOT be discarded
    def test_block_events_not_discarded(self, alert_and_block_verdict):
        """Blocked count in disposition_counts must reflect the actual BLOCK events."""
        assert alert_and_block_verdict.disposition_counts is not None
        assert alert_and_block_verdict.disposition_counts.blocked == 3

    # EARS-2: correct integer counts
    def test_disposition_counts_alert_unknown(self, alert_and_block_verdict):
        assert alert_and_block_verdict.disposition_counts.alert_unknown == 9

    def test_disposition_counts_allowed_zero(self, alert_and_block_verdict):
        assert alert_and_block_verdict.disposition_counts.allowed == 0

    # EARS-5 / ADR-0067 D8: tier is the loudest QUALIFYING action. The 9 ALERT
    # events are unqualified (no detection, no declared severity); the 3
    # confirmed BLOCK/DROP events are the loudest qualifying class → Tier 3.
    def test_tier_is_loudest_qualifying_action(self, alert_and_block_verdict):
        """Tier must be 3: the unqualified ALERT mass cannot outrank confirmed blocks."""
        assert alert_and_block_verdict.tier == 3

    def test_disposition_is_blocked_persistent(self, alert_and_block_verdict):
        """Disposition is 'blocked_persistent' — the confirmed-block headline."""
        assert alert_and_block_verdict.disposition == "blocked_persistent"

    # EARS-6: RULE-tagged, integers only, no attacker fields
    def test_justification_rule_tagged(self, alert_and_block_verdict):
        assert alert_and_block_verdict.justification.startswith("[RULE]")

    def test_justification_no_attacker_fields(self, alert_and_block_verdict):
        jst = alert_and_block_verdict.justification
        assert "category" not in jst
        assert "rule_name" not in jst
        assert "payload_snippet" not in jst

    def test_justification_contains_counts(self, alert_and_block_verdict):
        jst = alert_and_block_verdict.justification
        assert "9" in jst   # ALERT count
        assert "3" in jst   # BLOCK count

    def test_allow_block_mixed_is_partial(self):
        """ALLOW + BLOCK events → block_status='partial'."""
        events = [_ev("ALLOW")] * 2 + [_ev("BLOCK")] * 2
        det = [_det()]  # detection needed to trigger Tier 1
        verdict = decide(events, det)
        assert verdict.block_status == "partial"
        assert verdict.disposition_counts is not None
        assert verdict.disposition_counts.allowed == 2
        assert verdict.disposition_counts.blocked == 2

    def test_alert_allow_mixed_no_detection_is_observed(self):
        """ADR-0067 D1: unqualified ALERT + ALLOW, no detection -> observed, partial."""
        events = [_ev("ALERT")] * 3 + [_ev("ALLOW")] * 2
        verdict = decide(events, [])
        assert verdict.block_status == "partial"
        assert verdict.tier is None
        assert verdict.disposition == "observed"

    def test_alert_allow_mixed_qualified_is_tier2(self):
        """Same shape, but the ALERT carries a qualifying severity -> Tier 2, partial."""
        events = [_ev("ALERT", severity="high")] * 3 + [_ev("ALLOW")] * 2
        verdict = decide(events, [])
        assert verdict.block_status == "partial"
        assert verdict.tier == 2


# ===========================================================================
# Decider single-class regression guard (#724 EARS-4)
# ===========================================================================

class TestDeciderSingleClassRegression:
    """Existing single-class behaviour must be byte-identical post-amendment,
    subject to the #42/ADR-0067 D1 assertion gate on the ALERT/LOG and
    ALLOW-only branches (Tiers 1/3/4 are untouched by ADR-0067)."""

    def test_pure_alert_no_qualifying_signal_is_observed(self):
        """ADR-0067 D1: no detection, no declared severity -> observed, not Tier 2."""
        events = [_ev("ALERT")] * 5
        v = decide(events, [])
        assert v.tier is None
        assert v.disposition == "observed"
        assert v.block_status == "unknown"

    def test_pure_alert_severity_qualified_tier2_unknown(self):
        """ADR-0067 D1(b): a declared high/critical severity ALERT reaches Tier 2."""
        events = [_ev("ALERT", severity="high")] * 5
        v = decide(events, [])
        assert v.tier == 2
        assert v.disposition == "block_status_unknown"
        assert v.block_status == "unknown"

    def test_pure_alert_with_non_qualifying_detection_is_observed(self):
        """ADR-0067 D1: the D1 non-escalating default detection does not qualify."""
        events = [_ev("ALERT")] * 3
        v = decide(events, [_det()])
        assert v.tier is None
        assert v.disposition == "observed"
        assert v.block_status == "unknown"

    def test_pure_alert_with_qualifying_detection_tier2_unknown(self):
        events = [_ev("ALERT")] * 3
        v = decide(events, [_det(auto_escalate=True)])
        assert v.tier == 2
        assert v.block_status == "unknown"

    def test_pure_block_persistent_tier3_blocked(self):
        events = [_ev("BLOCK")] * _PERSISTENCE_THRESHOLD
        v = decide(events, [])
        assert v.tier == 3
        assert v.disposition == "blocked_persistent"
        assert v.block_status == "blocked"

    def test_pure_block_oneoff_tier4_blocked(self):
        events = [_ev("BLOCK")]
        v = decide(events, [])
        assert v.tier == 4
        assert v.disposition == "blocked_one_off"
        assert v.block_status == "blocked"

    def test_allow_with_detection_tier1_allowed(self):
        events = [_ev("ALLOW")]
        v = decide(events, [_det()])
        assert v.tier == 1
        assert v.disposition == "allowed_through"
        assert v.block_status == "allowed"

    def test_allow_no_detection_is_observed(self):
        """ADR-0067 D2: replaces the pre-#42 tier-4 ALLOW-only fallback."""
        events = [_ev("ALLOW")]
        v = decide(events, [])
        assert v.tier is None
        assert v.disposition == "observed"
        assert v.block_status == "allowed"

    def test_empty_events_is_observed(self):
        v = decide([], [])
        assert v.tier is None
        assert v.disposition == "observed"
        assert v.block_status == "allowed"

    def test_single_class_disposition_counts_attached(self):
        """Amendment 1: disposition_counts must be present on every verdict."""
        events = [_ev("BLOCK")] * _PERSISTENCE_THRESHOLD
        v = decide(events, [])
        assert v.disposition_counts is not None
        assert v.disposition_counts.blocked == _PERSISTENCE_THRESHOLD
        assert v.disposition_counts.alert_unknown == 0
        assert v.disposition_counts.allowed == 0

    def test_log_action_counts_as_alert_unknown(self):
        """LOG events must count as alert_unknown (same terminal class as ALERT)."""
        events = [_ev("LOG")] * 4
        v = decide(events, [])
        assert v.block_status == "unknown"
        assert v.disposition_counts is not None
        assert v.disposition_counts.alert_unknown == 4

    def test_drop_action_counts_as_blocked(self):
        """DROP events must count as blocked (same terminal class as BLOCK)."""
        events = [_ev("DROP")] * _PERSISTENCE_THRESHOLD
        v = decide(events, [])
        assert v.block_status == "blocked"
        assert v.disposition_counts is not None
        assert v.disposition_counts.blocked == _PERSISTENCE_THRESHOLD


# ===========================================================================
# Justification builder unit tests
# ===========================================================================

class TestBuildJustificationPartial:
    """Unit tests for the _build_justification_partial() helper (#724 EARS-6)."""

    def test_rule_tagged(self):
        jst = _build_justification_partial(9, 307, 0)
        assert jst.startswith("[RULE]")

    def test_contains_alert_count(self):
        jst = _build_justification_partial(9, 307, 0)
        assert "307" in jst

    def test_contains_block_count(self):
        jst = _build_justification_partial(9, 307, 0)
        assert "9" in jst

    def test_alert_block_tail_mentions_confirmed_blocked(self):
        jst = _build_justification_partial(9, 307, 0)
        assert "confirmed blocked" in jst

    def test_allow_block_tail_mentions_got_through(self):
        # Wording (issue #6): "got through" replaces "allowed" in plain-language copy.
        jst = _build_justification_partial(5, 0, 3)
        assert "got through" in jst
        assert "5" in jst
        assert "3" in jst

    def test_no_attacker_fields_in_output(self):
        jst = _build_justification_partial(9, 307, 0)
        assert "category" not in jst
        assert "rule_name" not in jst
        assert "payload" not in jst
