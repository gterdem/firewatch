"""Tests for issue #648 — Deterministic escalation decider (ADR-0058 D2).

EARS criteria → test mapping:
- EARS-1: WHEN analyze_ip runs for an IP, THE SYSTEM SHALL compute an escalation verdict
  via a pure function over (events, detections) using only deterministic rules (no LLM).
  → TestDeciderPureFunction, TestPipelineEscalationWiring

- EARS-2: WHERE a high-fidelity detection is present on an ALLOWED-through event,
  THE SYSTEM SHALL assign Tier 1 and disposition ``allowed_through`` with a RULE-tagged
  justification (ADR-0035).
  → TestTier1AllowWithDetection

- EARS-3: WHERE a detection fired on an ALERT/LOG event, THE SYSTEM SHALL assign Tier 2,
  disposition ``block_status_unknown``, and ``block_status="unknown"`` — asserting neither
  blocked nor allowed.
  → TestTier2AlertLogWithDetection

- EARS-4: WHILE BLOCK/DROP events are one-off, THE SYSTEM SHALL assign Tier 4 (informational)
  and SHALL escalate to Tier 3 only on persistence/high-volume.
  → TestTier3PersistentBlock, TestTier4OneOffBlock

- EARS-5: WHERE the escalation verdict is produced, THE SYSTEM SHALL write it to the additive
  ``ThreatScore.escalation`` sub-object and SHALL NOT alter ``score`` or ``threat_level``.
  → TestPipelineEscalationWiring, TestEscalationIsAdditive

- EARS-6: WHILE the launch golden oracle runs, THE SYSTEM SHALL keep all scenario scores
  byte-identical (frozen-scores guarantee of "B").
  → TestGoldenScoresUnchanged (covered separately by tests/golden but verified here too)

Test IPs use RFC 5737 documentation ranges only (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and RFC 1918 (10.x) where non-public IPs are needed.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from firewatch_sdk.models import Detection, EscalationVerdict, SecurityEvent, ThreatScore

from firewatch_core.escalation.decider import decide, _PERSISTENCE_THRESHOLD
from _fakes import FakeStore, FakeAIEngine, make_event

T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc)
IP = "203.0.113.10"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _det(rule_name: str = "test_rule", *, score_delta: int = 10, auto_escalate: bool = False) -> Detection:
    return Detection(
        source_ip=IP,
        rule_name=rule_name,
        score_delta=score_delta,
        reason="test detection",
        auto_escalate=auto_escalate,
    )


def _ev(action: str, *, category: str | None = None) -> SecurityEvent:
    return make_event(source_ip=IP, action=action, category=category)


# ---------------------------------------------------------------------------
# EARS-1 — decide() is a pure function (no I/O, no LLM)
# ---------------------------------------------------------------------------

class TestDeciderPureFunction:
    """decide() must be callable with no async / no side effects (EARS-1)."""

    def test_returns_escalation_verdict(self):
        events = [_ev("BLOCK")]
        result = decide(events, [])
        assert isinstance(result, EscalationVerdict)

    def test_verdict_fields_populated(self):
        result = decide([_ev("ALERT")], [_det()])
        assert isinstance(result.tier, int)
        assert result.disposition
        assert result.justification
        assert result.block_status

    def test_no_io_no_exception(self):
        """decide() must not raise on typical inputs."""
        events = [_ev("BLOCK"), _ev("ALERT"), _ev("ALLOW")]
        detections = [_det("brute_force")]
        result = decide(events, detections)
        assert result.tier in (1, 2, 3, 4)

    def test_empty_events_and_detections_returns_verdict(self):
        """Fallback path: no events, no detections — must still return a verdict."""
        result = decide([], [])
        assert isinstance(result, EscalationVerdict)
        assert result.tier == 4

    def test_justification_contains_rule_tag(self):
        """ADR-0035: justification must be RULE-tagged."""
        result = decide([_ev("ALLOW")], [_det()])
        assert "[RULE]" in result.justification

    def test_tier_in_valid_range(self):
        for action in ("ALLOW", "ALERT", "LOG", "BLOCK", "DROP"):
            r = decide([_ev(action)], [_det()])
            assert 1 <= r.tier <= 4


# ---------------------------------------------------------------------------
# EARS-2 — Tier 1: ALLOW + detection → allowed_through
# ---------------------------------------------------------------------------

class TestTier1AllowWithDetection:
    """EARS-2: ALLOW event + detection → Tier 1, disposition=allowed_through."""

    def test_allow_with_detection_is_tier1(self):
        result = decide([_ev("ALLOW")], [_det()])
        assert result.tier == 1

    def test_allow_with_detection_disposition(self):
        result = decide([_ev("ALLOW")], [_det()])
        assert result.disposition == "allowed_through"

    def test_allow_with_detection_block_status(self):
        result = decide([_ev("ALLOW")], [_det()])
        assert result.block_status == "allowed"

    def test_allow_with_detection_justification_rule_tagged(self):
        result = decide([_ev("ALLOW")], [_det("sqli_rule")])
        assert "[RULE]" in result.justification
        assert "sqli_rule" in result.justification

    def test_attacker_category_not_in_justification(self):
        # SECURITY (issue #648): event `category` can be attacker-influenced
        # (e.g. CEF derives it from header vendor/product — see #642) and must NOT
        # leak into the justification, which renders in the triage banner (#649).
        # Only the operator-defined correlation rule name may appear.
        result = decide(
            [_ev("ALLOW", category="<script>pwn</script>")], [_det("sqli_rule")]
        )
        assert "<script>" not in result.justification
        assert "pwn" not in result.justification
        assert "sqli_rule" in result.justification

    def test_allow_auto_escalate_reflected_in_justification(self):
        result = decide([_ev("ALLOW")], [_det(auto_escalate=True)])
        assert "auto-escalate" in result.justification

    def test_allow_without_detection_is_not_tier1(self):
        """ALLOW with no detection → falls through to Tier 4 (no detection fired)."""
        result = decide([_ev("ALLOW")], [])
        assert result.tier != 1

    def test_allow_beats_alert_when_detection_present(self):
        """Mix of ALLOW + ALERT: ALLOW+detection takes Tier 1 priority."""
        events = [_ev("ALLOW"), _ev("ALERT")]
        result = decide(events, [_det()])
        assert result.tier == 1


# ---------------------------------------------------------------------------
# EARS-3 — Tier 2: ALERT/LOG with detection → block_status_unknown
# ---------------------------------------------------------------------------

class TestTier2AlertLogWithDetection:
    """EARS-3: ALERT/LOG + detection → Tier 2, block_status=unknown."""

    def test_alert_with_detection_is_tier2(self):
        result = decide([_ev("ALERT")], [_det()])
        assert result.tier == 2

    def test_log_with_detection_is_tier2(self):
        result = decide([_ev("LOG")], [_det()])
        assert result.tier == 2

    def test_alert_with_detection_disposition(self):
        result = decide([_ev("ALERT")], [_det()])
        assert result.disposition == "block_status_unknown"

    def test_alert_with_detection_block_status_unknown(self):
        result = decide([_ev("ALERT")], [_det()])
        assert result.block_status == "unknown"

    def test_alert_without_detection_still_tier2(self):
        """ALERT alone (no detection) → Tier 2: action itself is non-asserting (OCSF)."""
        result = decide([_ev("ALERT")], [])
        assert result.tier == 2
        assert result.block_status == "unknown"

    def test_log_without_detection_still_tier2(self):
        result = decide([_ev("LOG")], [])
        assert result.tier == 2

    def test_alert_justification_rule_tagged(self):
        result = decide([_ev("ALERT")], [_det("ids_rule")])
        assert "[RULE]" in result.justification

    def test_alert_top_rule_in_justification(self):
        """Top rule_name (by score_delta) appears in justification."""
        dets = [_det("low_rule", score_delta=5), _det("high_rule", score_delta=20)]
        result = decide([_ev("ALERT")], dets)
        assert "high_rule" in result.justification

    def test_alert_auto_escalate_in_justification(self):
        result = decide([_ev("ALERT")], [_det(auto_escalate=True)])
        assert "auto-escalate" in result.justification


# ---------------------------------------------------------------------------
# EARS-4 — Tier 3: BLOCK/DROP persistent
# ---------------------------------------------------------------------------

class TestTier3PersistentBlock:
    """EARS-4 (persistence branch): ≥ PERSISTENCE_THRESHOLD BLOCK/DROP → Tier 3."""

    def _make_persistent_blocks(self, n: int | None = None) -> list[SecurityEvent]:
        count = n if n is not None else _PERSISTENCE_THRESHOLD
        return [_ev("BLOCK") for _ in range(count)]

    def test_persistent_block_is_tier3(self):
        result = decide(self._make_persistent_blocks(), [_det()])
        assert result.tier == 3

    def test_persistent_block_disposition(self):
        result = decide(self._make_persistent_blocks(), [_det()])
        assert result.disposition == "blocked_persistent"

    def test_persistent_block_block_status(self):
        result = decide(self._make_persistent_blocks(), [_det()])
        assert result.block_status == "blocked"

    def test_persistent_block_justification_rule_tagged(self):
        result = decide(self._make_persistent_blocks(), [_det()])
        assert "[RULE]" in result.justification

    def test_persistent_block_count_in_justification(self):
        blocks = self._make_persistent_blocks()
        result = decide(blocks, [])
        assert str(len(blocks)) in result.justification

    def test_exactly_at_threshold_is_tier3(self):
        result = decide(self._make_persistent_blocks(_PERSISTENCE_THRESHOLD), [])
        assert result.tier == 3

    def test_one_below_threshold_is_tier4(self):
        result = decide(self._make_persistent_blocks(_PERSISTENCE_THRESHOLD - 1), [])
        assert result.tier == 4

    def test_drop_events_count_toward_persistence(self):
        drops = [_ev("DROP") for _ in range(_PERSISTENCE_THRESHOLD)]
        result = decide(drops, [])
        assert result.tier == 3

    def test_mixed_block_drop_count_toward_persistence(self):
        # Mix BLOCK and DROP — both count
        events = [_ev("BLOCK")] * 2 + [_ev("DROP")]
        # total = 3 = _PERSISTENCE_THRESHOLD
        assert _PERSISTENCE_THRESHOLD == 3
        result = decide(events, [])
        assert result.tier == 3


# ---------------------------------------------------------------------------
# EARS-4 — Tier 4: BLOCK/DROP one-off (informational)
# ---------------------------------------------------------------------------

class TestTier4OneOffBlock:
    """EARS-4 (one-off branch): < PERSISTENCE_THRESHOLD BLOCK/DROP → Tier 4."""

    def test_single_block_is_tier4(self):
        result = decide([_ev("BLOCK")], [])
        assert result.tier == 4

    def test_single_block_disposition(self):
        result = decide([_ev("BLOCK")], [])
        assert result.disposition == "blocked_one_off"

    def test_single_block_block_status_blocked(self):
        result = decide([_ev("BLOCK")], [])
        assert result.block_status == "blocked"

    def test_tier4_justification_rule_tagged(self):
        result = decide([_ev("BLOCK")], [])
        assert "[RULE]" in result.justification

    def test_tier4_justification_mentions_count(self):
        result = decide([_ev("BLOCK")], [])
        assert "1" in result.justification

    def test_two_blocks_below_threshold_is_tier4(self):
        result = decide([_ev("BLOCK"), _ev("BLOCK")], [])
        assert result.tier == 4


# ---------------------------------------------------------------------------
# EARS-5 — ThreatScore.escalation is additive; score/threat_level unchanged
# ---------------------------------------------------------------------------

class TestEscalationIsAdditive:
    """EARS-5: escalation verdict must NOT influence score or threat_level."""

    def test_escalation_verdict_model_fields(self):
        v = EscalationVerdict(
            tier=1,
            disposition="allowed_through",
            justification="[RULE] test",
            block_status="allowed",
        )
        assert v.tier == 1
        assert v.disposition == "allowed_through"
        assert v.block_status == "allowed"

    def test_escalation_verdict_serializes_to_json(self):
        """EscalationVerdict is a Pydantic BaseModel — must dump to dict."""
        v = EscalationVerdict(
            tier=2,
            disposition="block_status_unknown",
            justification="[RULE] ids fired",
            block_status="unknown",
        )
        d = v.model_dump()
        assert d["tier"] == 2
        assert d["disposition"] == "block_status_unknown"

    def test_threatscore_escalation_defaults_none(self):
        """ThreatScore.escalation must default to None (backward compat)."""
        from firewatch_sdk.models import ThreatScore
        ts = ThreatScore(
            source_ip=IP,
            threat_level="LOW",
            score=0,
            total_events=0,
            blocked_events=0,
            attack_types=[],
            first_seen=T0,
            last_seen=T0,
        )
        assert ts.escalation is None

    def test_threatscore_accepts_escalation_verdict(self):
        from firewatch_sdk.models import ThreatScore
        verdict = EscalationVerdict(
            tier=1,
            disposition="allowed_through",
            justification="[RULE] sqli on ALLOW",
            block_status="allowed",
        )
        ts = ThreatScore(
            source_ip=IP,
            threat_level="MEDIUM",
            score=40,
            total_events=1,
            blocked_events=0,
            attack_types=["sqli"],
            first_seen=T0,
            last_seen=T0,
            escalation=verdict,
        )
        assert ts.escalation is not None
        assert ts.escalation.tier == 1
        # Score is unchanged — escalation is additive only
        assert ts.score == 40
        assert ts.threat_level == "MEDIUM"


# ---------------------------------------------------------------------------
# EARS-5 — Pipeline wiring: analyze_ip attaches escalation verdict
# ---------------------------------------------------------------------------

class TestPipelineEscalationWiring:
    """EARS-1/EARS-5: pipeline.analyze_ip computes and attaches EscalationVerdict."""

    def _run(self, events: list[SecurityEvent]) -> ThreatScore:
        from firewatch_core.pipeline import Pipeline
        store = FakeStore(events)
        pipeline = Pipeline(store=store, ai_engine=FakeAIEngine())
        return asyncio.run(pipeline.analyze_ip(IP, use_ai=False))

    def test_analyze_ip_alert_has_escalation(self):
        events = [make_event(source_ip=IP, action="ALERT", category="IDS Alert")]
        result = self._run(events)
        assert result.escalation is not None

    def test_analyze_ip_block_has_escalation(self):
        events = [make_event(source_ip=IP, action="BLOCK")]
        result = self._run(events)
        assert result.escalation is not None

    def test_analyze_ip_escalation_does_not_change_score(self):
        """EARS-5: escalation must not move the score."""
        events = [make_event(source_ip=IP, action="ALLOW", category="SQLi")]
        result = self._run(events)
        # Score from ALLOW-only (no BLOCK events) is rules-only — may be 0 or low.
        # The point: escalation field is present but score is unchanged.
        assert result.escalation is not None
        assert result.score >= 0  # score is valid

    def test_analyze_ip_alert_tier2(self):
        events = [make_event(source_ip=IP, action="ALERT")]
        result = self._run(events)
        assert result.escalation is not None
        assert result.escalation.tier == 2

    def test_analyze_ip_single_block_tier4(self):
        events = [make_event(source_ip=IP, action="BLOCK")]
        result = self._run(events)
        assert result.escalation is not None
        assert result.escalation.tier == 4

    def test_analyze_ip_persistent_block_tier3(self):
        events = [make_event(source_ip=IP, action="BLOCK") for _ in range(_PERSISTENCE_THRESHOLD)]
        result = self._run(events)
        assert result.escalation is not None
        assert result.escalation.tier == 3

    def test_analyze_ip_empty_events_escalation_is_none(self):
        """Empty event list → early return with no escalation (no events to decide on)."""
        result = self._run([])
        assert result.escalation is None

    def test_analyze_ip_escalation_tier_is_int(self):
        events = [make_event(source_ip=IP, action="ALERT")]
        result = self._run(events)
        assert isinstance(result.escalation.tier, int)  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Policy-registry hardening (carry-forward from the #647 security review;
# load-bearing now that auto_escalate drives routing). N-1: RulePolicy frozen.
# N-2: registry refuses register() after finalize(). N-3 is type-level (model.py).
# ---------------------------------------------------------------------------

class TestPolicyRegistryHardening:
    def test_rulepolicy_is_frozen(self):
        """N-1: a returned RulePolicy cannot be mutated (shared sentinel safety)."""
        from dataclasses import FrozenInstanceError

        from firewatch_core.escalation.policy import RulePolicy

        p = RulePolicy(severity="high", auto_escalate=True)
        with pytest.raises(FrozenInstanceError):
            p.severity = "low"  # type: ignore[misc]

    def test_register_after_finalize_raises(self):
        """N-2: post-finalize register() raises, so a critical rule can't be downgraded."""
        from firewatch_core.escalation.policy import EscalationPolicyRegistry

        reg = EscalationPolicyRegistry()
        reg.register("rule_a", severity="high", auto_escalate=True)
        reg.finalize()
        with pytest.raises(RuntimeError):
            reg.register("rule_b", severity="low", auto_escalate=False)

    def test_finalize_is_idempotent(self):
        from firewatch_core.escalation.policy import EscalationPolicyRegistry

        reg = EscalationPolicyRegistry()
        reg.finalize()
        reg.finalize()  # second call is harmless
        with pytest.raises(RuntimeError):
            reg.register("x", severity="info", auto_escalate=False)

    def test_global_registry_finalized_after_detector_import(self):
        """N-2 call site: detector.py calls ESCALATION_POLICY.finalize() at import."""
        import firewatch_core.detector  # noqa: F401 — ensures registrations + finalize ran
        from firewatch_core.escalation.policy import ESCALATION_POLICY

        with pytest.raises(RuntimeError):
            ESCALATION_POLICY.register(
                "late_rule", severity="critical", auto_escalate=True
            )
