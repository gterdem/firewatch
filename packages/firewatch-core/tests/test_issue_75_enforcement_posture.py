"""Enforcement-posture axis — ADR-0067 D6 + Amendment 1, issue #75 Phase A.

EARS criterion -> test mapping
==============================

AC-1 (`SourceMetadata.enforcement` additive field): covered in
  packages/firewatch-sdk/tests/test_enforcement_posture.py — not repeated here.

AC-2 (the resolver ships at full Phase-B signature width; an override wins
  when supplied; Phase A never supplies one in production):
  -> TestResolvePostureMap

AC-3 (qualified Tier-2 disposition-label table, D6 + Amendment 1):
  -> TestQualifiedTier2DispositionTable (posture.py, unit-level)
  -> TestDeciderPostureIntegration (decider.decide(), integration-level)

AC-4 (safety property — no posture value changes tier or produces
  block_status="blocked"; pinned across posture values x tally shapes):
  -> TestSafetyProperty

Concrete shipped case (ClamAV FOUND -> ALERT/severity=high -> qualifies Tier 2;
must read "detected — no action taken; file present" instead of the generic
"block status unknown"):
  -> TestClamAVConcreteCase

Pipeline wiring (the posture map is actually resolved core-side and reaches
the decider — not just unit-testable in isolation):
  -> TestPipelineWiring

Fixture IPs are RFC 5737 documentation ranges only — not real/routable.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from firewatch_sdk import AIEngine, EventStore

from firewatch_core.escalation.decider import decide
from firewatch_core.escalation.posture import qualified_tier2_disposition, resolve_posture_map
from firewatch_core.pipeline import Pipeline

from _fakes import FakeAIEngine, FakeStore, make_event

# RFC 5737 TEST-NET-3 — documentation use only; not routable.
IP = "203.0.113.75"
T0 = datetime(2026, 6, 15, 8, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# AC-2: resolve_posture_map — full Phase-B signature width, plugin defaults +
# instance overrides (override wins when supplied; Phase A never supplies one
# in production but the interface exists NOW so Phase B is additive-only).
# ---------------------------------------------------------------------------

class TestResolvePostureMap:
    def test_plugin_default_used_when_no_override(self):
        resolved = resolve_posture_map(
            [("clamav", "home")],
            plugin_defaults={"clamav": "detect_only"},
        )
        assert resolved == {("clamav", "home"): "detect_only"}

    def test_undeclared_source_type_resolves_to_none(self):
        """A source_type absent from plugin_defaults (e.g. no loaded plugin
        declared it) resolves to None — the fail-permissive default."""
        resolved = resolve_posture_map(
            [("unknown_source", "x")],
            plugin_defaults={"clamav": "detect_only"},
        )
        assert resolved == {("unknown_source", "x"): None}

    def test_instance_override_wins_over_plugin_default(self):
        """Phase B pin: when instance_overrides supplies a value for a key, it
        wins over that instance's plugin default (unit-tested per the #75
        acceptance criterion, even though Phase A never supplies one in
        production)."""
        resolved = resolve_posture_map(
            [("suricata", "edge-1")],
            plugin_defaults={"suricata": "observe"},
            instance_overrides={("suricata", "edge-1"): "enforce"},
        )
        assert resolved == {("suricata", "edge-1"): "enforce"}

    def test_instance_override_absent_for_phase_a(self):
        """The Phase-A production call path never supplies instance_overrides —
        omitting it entirely falls back to plugin defaults only."""
        resolved = resolve_posture_map(
            [("suricata", "edge-1")],
            plugin_defaults={"suricata": "observe"},
        )
        assert resolved == {("suricata", "edge-1"): "observe"}

    def test_multiple_instances_resolved_independently(self):
        resolved = resolve_posture_map(
            [("clamav", "home"), ("suricata", "edge-1"), ("aws_network_firewall", "vpc-1")],
            plugin_defaults={
                "clamav": "detect_only",
                "suricata": "observe",
                "aws_network_firewall": "enforce",
            },
        )
        assert resolved == {
            ("clamav", "home"): "detect_only",
            ("suricata", "edge-1"): "observe",
            ("aws_network_firewall", "vpc-1"): "enforce",
        }

    def test_empty_instance_keys_returns_empty_map(self):
        assert resolve_posture_map([], plugin_defaults={"clamav": "detect_only"}) == {}


# ---------------------------------------------------------------------------
# AC-3: the D6 + Amendment 1 disposition-label table (posture.py unit level)
# ---------------------------------------------------------------------------

class TestQualifiedTier2DispositionTable:
    def test_observe_maps_to_not_blocked_passive(self):
        assert qualified_tier2_disposition(["observe"], n_block_drop=0) == "not_blocked_passive"

    def test_detect_only_maps_to_detected_no_action(self):
        assert qualified_tier2_disposition(["detect_only"], n_block_drop=0) == "detected_no_action"

    def test_enforce_with_zero_block_drop_maps_to_not_blocked_enforcing(self):
        """Amendment 1 A1.1: enforce + zero BLOCK/DROP -> not_blocked_enforcing."""
        assert (
            qualified_tier2_disposition(["enforce"], n_block_drop=0) == "not_blocked_enforcing"
        )

    def test_enforce_with_block_drop_present_stays_unknown(self):
        """Amendment 1 A1.1's gate: enforce only narrows when n_block_drop == 0."""
        assert qualified_tier2_disposition(["enforce"], n_block_drop=1) == "block_status_unknown"

    def test_undeclared_none_stays_unknown(self):
        assert qualified_tier2_disposition([None], n_block_drop=0) == "block_status_unknown"

    def test_mixed_postures_stay_unknown(self):
        """Must-NOT (issue #75): postures that differ across contributing
        instances keep block_status_unknown — genuinely unknown."""
        assert (
            qualified_tier2_disposition(["observe", "enforce"], n_block_drop=0)
            == "block_status_unknown"
        )

    def test_mixed_declared_and_undeclared_stays_unknown(self):
        assert (
            qualified_tier2_disposition(["observe", None], n_block_drop=0)
            == "block_status_unknown"
        )

    def test_empty_postures_stays_unknown(self):
        """Defensive: no contributing instance at all -> unknown (never raises)."""
        assert qualified_tier2_disposition([], n_block_drop=0) == "block_status_unknown"

    def test_duplicate_postures_deduplicate_to_single_value(self):
        """Repeated identical posture entries are still a SINGLE distinct value."""
        assert (
            qualified_tier2_disposition(["observe", "observe", "observe"], n_block_drop=0)
            == "not_blocked_passive"
        )


# ---------------------------------------------------------------------------
# AC-3 (integration): decider.decide() consumes the posture_map parameter
# ---------------------------------------------------------------------------

def _alert(source_type: str, severity: str = "high", source_id: str = "inst-1"):
    return make_event(
        source_type=source_type, source_id=source_id, source_ip=IP,
        action="ALERT", severity=severity, timestamp=T0,
    )


class TestDeciderPostureIntegration:
    def test_no_posture_map_keeps_pre_75_behaviour(self):
        """decide() with posture_map omitted (None) is byte-identical to
        pre-#75 behaviour — no shipped label moves (A1.4)."""
        verdict = decide([_alert("suricata")], [])
        assert verdict.tier == 2
        assert verdict.disposition == "block_status_unknown"
        assert verdict.block_status == "unknown"

    def test_empty_posture_map_keeps_pre_75_behaviour(self):
        verdict = decide([_alert("suricata")], [], posture_map={})
        assert verdict.disposition == "block_status_unknown"

    def test_observe_posture_narrows_to_not_blocked_passive(self):
        verdict = decide(
            [_alert("suricata")], [],
            posture_map={("suricata", "inst-1"): "observe"},
        )
        assert verdict.tier == 2
        assert verdict.disposition == "not_blocked_passive"
        assert verdict.block_status == "unknown"

    def test_detect_only_posture_narrows_to_detected_no_action(self):
        verdict = decide(
            [_alert("clamav")], [],
            posture_map={("clamav", "inst-1"): "detect_only"},
        )
        assert verdict.disposition == "detected_no_action"

    def test_enforce_posture_zero_blocks_narrows_to_not_blocked_enforcing(self):
        verdict = decide(
            [_alert("aws_network_firewall")], [],
            posture_map={("aws_network_firewall", "inst-1"): "enforce"},
        )
        assert verdict.disposition == "not_blocked_enforcing"

    def test_undeclared_posture_stays_block_status_unknown(self):
        verdict = decide(
            [_alert("suricata")], [],
            posture_map={("suricata", "inst-1"): None},
        )
        assert verdict.disposition == "block_status_unknown"

    def test_mixed_postures_across_two_instances_stays_unknown(self):
        """Two different source_types both qualify Tier 2 with differing
        declared postures -> block_status_unknown (genuinely unknown)."""
        events = [
            _alert("suricata", source_id="edge-1"),
            _alert("aws_network_firewall", source_id="vpc-1"),
        ]
        verdict = decide(
            events, [],
            posture_map={
                ("suricata", "edge-1"): "observe",
                ("aws_network_firewall", "vpc-1"): "enforce",
            },
        )
        assert verdict.tier == 2
        assert verdict.disposition == "block_status_unknown"

    def test_justification_stays_rule_tagged_regardless_of_posture(self):
        """Posture changes the disposition LABEL only — the justification stays
        RULE-tagged, engine/rule-text only (ADR-0035), unaffected."""
        verdict = decide(
            [_alert("clamav")], [],
            posture_map={("clamav", "inst-1"): "detect_only"},
        )
        assert verdict.justification.startswith("[RULE]")


# ---------------------------------------------------------------------------
# AC-4 / the #75 safety property: no posture value changes tier or produces
# block_status="blocked" — parametrized across posture values x tally shapes.
# ---------------------------------------------------------------------------

_ALL_POSTURES = ["observe", "enforce", "detect_only", None]


class TestSafetyProperty:
    @pytest.mark.parametrize("posture", _ALL_POSTURES)
    def test_pure_qualifying_alert_tier_and_block_status_unaffected(self, posture):
        """Single-class qualifying ALERT actor: tier stays 2 and block_status
        stays 'unknown' for every posture value — only disposition varies."""
        verdict = decide(
            [_alert("src")], [],
            posture_map={("src", "inst-1"): posture},
        )
        assert verdict.tier == 2
        assert verdict.block_status == "unknown"

    @pytest.mark.parametrize("posture", _ALL_POSTURES)
    def test_mixed_tally_with_block_drop_present_stays_partial_never_blocked(self, posture):
        """Qualifying ALERT + some BLOCK/DROP present (tally.mixed=True): tier
        stays 2, block_status stays 'partial' — NEVER 'blocked' — for every
        posture value (posture cannot manufacture a block)."""
        events = [_alert("src"), make_event(
            source_type="src", source_id="inst-1", source_ip=IP,
            action="BLOCK", timestamp=T0,
        )]
        verdict = decide(events, [], posture_map={("src", "inst-1"): posture})
        assert verdict.tier == 2
        assert verdict.block_status == "partial"
        assert verdict.block_status != "blocked"

    @pytest.mark.parametrize("posture", _ALL_POSTURES)
    def test_mixed_tally_with_allow_present_stays_partial_never_blocked(self, posture):
        """Qualifying ALERT + ALLOW present (tally.mixed=True, zero BLOCK/DROP):
        tier stays 2, block_status stays 'partial' for every posture value."""
        events = [_alert("src"), make_event(
            source_type="src", source_id="inst-1", source_ip=IP,
            action="ALLOW", timestamp=T0,
        )]
        verdict = decide(events, [], posture_map={("src", "inst-1"): posture})
        assert verdict.tier == 2
        assert verdict.block_status == "partial"

    @pytest.mark.parametrize("posture", _ALL_POSTURES)
    def test_unqualified_observed_stratum_unaffected_by_posture(self, posture):
        """An unqualified (severity-less) ALERT population lands 'observed'
        (tier=None) regardless of posture — posture only applies to QUALIFIED
        Tier-2 verdicts, never to the observed stratum or its tier."""
        events = [make_event(
            source_type="src", source_id="inst-1", source_ip=IP,
            action="ALERT", timestamp=T0,
        )]
        verdict = decide(events, [], posture_map={("src", "inst-1"): posture})
        assert verdict.tier is None
        assert verdict.disposition == "observed"

    @pytest.mark.parametrize("posture", _ALL_POSTURES)
    def test_persistent_block_actor_unaffected_by_posture(self, posture):
        """A pure, persistent BLOCK/DROP actor (Tier 3) is untouched by any
        posture_map entry — posture only ever narrows a QUALIFIED Tier-2 label."""
        events = [make_event(
            source_type="src", source_id="inst-1", source_ip=IP,
            action="BLOCK", timestamp=T0,
        ) for _ in range(3)]
        verdict = decide(events, [], posture_map={("src", "inst-1"): posture})
        assert verdict.tier == 3
        assert verdict.block_status == "blocked"
        assert verdict.disposition == "blocked_persistent"


# ---------------------------------------------------------------------------
# Concrete shipped case (issue #75): ClamAV FOUND -> ALERT/severity=high
# qualifies Tier 2; must read "detected — no action taken; file present"
# (disposition key detected_no_action), not the generic "block status unknown".
# ---------------------------------------------------------------------------

class TestClamAVConcreteCase:
    def test_clamav_found_detection_reads_detected_no_action(self):
        clamav_found_event = make_event(
            source_type="clamav", source_id="workstation-1", source_ip=IP,
            action="ALERT", severity="high", timestamp=T0,
        )
        verdict = decide(
            [clamav_found_event], [],
            posture_map={("clamav", "workstation-1"): "detect_only"},
        )
        assert verdict.tier == 2
        assert verdict.disposition == "detected_no_action"
        # Safety pin: still NOT "blocked" — ClamAV detects, it does not remove.
        assert verdict.block_status == "unknown"


# ---------------------------------------------------------------------------
# Pipeline wiring: the posture map is actually resolved core-side (from
# Pipeline's posture_defaults) and reaches the decider — proves the mechanism
# end-to-end, not just unit-testable in isolation (ADR-0067 D6: "supplied by
# the pipeline").
# ---------------------------------------------------------------------------

class TestPipelineWiring:
    async def test_analyze_ip_resolves_posture_from_plugin_defaults(self):
        clamav_found_event = make_event(
            source_type="clamav", source_id="workstation-1", source_ip=IP,
            action="ALERT", severity="high", timestamp=T0,
        )
        store: EventStore = FakeStore([clamav_found_event])
        ai: AIEngine = FakeAIEngine()
        pipeline = Pipeline(
            store, ai,
            clock=lambda: T0,
            posture_defaults={"clamav": "detect_only"},
        )
        score = await pipeline.analyze_ip(IP)
        assert score.escalation is not None
        assert score.escalation.disposition == "detected_no_action"

    async def test_analyze_ip_without_posture_defaults_keeps_generic_label(self):
        """Omitting posture_defaults entirely (pre-#75 callers) is byte-identical:
        the generic block_status_unknown label, unchanged."""
        clamav_found_event = make_event(
            source_type="clamav", source_id="workstation-1", source_ip=IP,
            action="ALERT", severity="high", timestamp=T0,
        )
        store: EventStore = FakeStore([clamav_found_event])
        ai: AIEngine = FakeAIEngine()
        pipeline = Pipeline(store, ai, clock=lambda: T0)
        score = await pipeline.analyze_ip(IP)
        assert score.escalation is not None
        assert score.escalation.disposition == "block_status_unknown"

    async def test_analyze_ip_undeclared_plugin_default_keeps_generic_label(self):
        """A registered plugin default of None (undeclared, e.g. azure_waf)
        keeps the generic label — not a KeyError, not a crash."""
        event = make_event(
            source_type="azure_waf", source_id="front-door-1", source_ip=IP,
            action="ALERT", severity="high", timestamp=T0,
        )
        store: EventStore = FakeStore([event])
        ai: AIEngine = FakeAIEngine()
        pipeline = Pipeline(
            store, ai,
            clock=lambda: T0,
            posture_defaults={"azure_waf": None},
        )
        score = await pipeline.analyze_ip(IP)
        assert score.escalation is not None
        assert score.escalation.disposition == "block_status_unknown"
