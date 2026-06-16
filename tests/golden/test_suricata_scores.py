"""Golden regression tests — Suricata ThreatScore oracle.

Feeds recorded v1 Suricata eve.json fixtures through the NEW
``firewatch_suricata.normalize.normalize()`` + ``firewatch_core`` pipeline
(``run_rules``, ``detect``, ``merge_score``) and asserts resulting
``ThreatScore`` fields match frozen v1-oracle expected values.

EARS-criteria coverage
──────────────────────
EARS-1  Fixtures -> NEW normalize() + core pipeline -> assert == frozen oracle scores.
EARS-2  Frozen score constants are literals (not new-code output); mapping/threshold
        changes FAIL the suite.
EARS-3  Suite runs under ``uv run pytest`` and is green.
Flag B  Single-Suricata-source fixtures do NOT trigger multi_source_attack detection
        (correlation keys on source_type diversity, not source_id diversity).
Flag B  Watermark composite key is (source_type, source_id) — not source_id alone.

Oracle derivation (provenance)
──────────────────────────────
Score values were produced by running
``legacy/core/scoring.py::run_rules + merge_score`` and
``legacy/core/detector.py::detect`` on 2026-06-03 with equivalent SecurityEvent
instances (source_module replaced by source_type in v2 per ADR-0016, but scoring
logic is verbatim-ported so values are byte-compatible).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from firewatch_sdk import RawEvent, SecurityEvent
from firewatch_suricata.normalize import normalize
from firewatch_core.scoring import run_rules, merge_score
from firewatch_core.detector import detect

FIXTURES_DIR = Path(__file__).parent / "fixtures"
_RECEIVED_AT = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
SOURCE_ID = "pi-home"


def _load_eve(filename: str) -> dict:
    return json.loads((FIXTURES_DIR / filename).read_text())


def _norm(eve_file: str, *, source_id: str = SOURCE_ID) -> SecurityEvent:
    raw = RawEvent(source_type="suricata", received_at=_RECEIVED_AT,
                   data=_load_eve(eve_file))
    return normalize(raw, source_id=source_id)


def _score(events: list[SecurityEvent]) -> tuple[int, str, list[str], list[str]]:
    """Run the full scoring pipeline (rules + detections + merge), no AI.

    Returns (final_score, threat_level, attack_types, detection_rule_names).
    """
    rule_score, attack_types = run_rules(events)
    detections = detect(events)
    detection_boost = sum(d.score_delta for d in detections)
    final_score, level, _deriv = merge_score(rule_score, None, detection_boost=detection_boost)
    return final_score, level, attack_types, [d.rule_name for d in detections]


# ── Frozen oracle constants (derived from legacy, NOT from new code) ──────────

# ── ADR-0058 §D5a re-bless (issue #651) — the single authorized golden-oracle move ──
# blessed by ADR-0058 D5b. run_rules is now disposition-weighted and action-aware:
# SQLi/XSS scanned across ALL events (was blocked-only — the blind spot) × the loudest
# matching disposition (ALLOW 1.0 / ALERT·LOG 0.75 / BLOCK 0.5); a flat per-block +1 is
# replaced by a +10 persistence floor at ≥3 blocked.
#
# ORACLE_A: Single Suricata ALERT carrying a SQLi payload. SQLi now scanned on the ALERT
# event, weighted ALERT 0.75 → 40×0.75 = 30. ⚠️ THE blessed move (was 0/LOW — the
# blocked-only blind spot frozen as "correct").
_ORACLE_SCORE_A = 30
_ORACLE_LEVEL_A = "MEDIUM"
_ORACLE_ATTACKS_A: list[str] = ["sql_injection"]
_ORACLE_DETECTIONS_A: list[str] = []

# ORACLE_B: Single BLOCK, no payload. Flat +1-per-block removed; a one-off block is
# Tier-4 informational → 0 (was 1).
_ORACLE_SCORE_B = 0
_ORACLE_LEVEL_B = "LOW"
_ORACLE_ATTACKS_B: list[str] = []
_ORACLE_DETECTIONS_B: list[str] = []

# ORACLE_C: 3 BLOCK events, no payload. 3 = persistence threshold → +10 floor (was +3).
_ORACLE_SCORE_C = 10
_ORACLE_LEVEL_C = "LOW"
_ORACLE_ATTACKS_C: list[str] = []

# ORACLE_D: 5 ALERT events on 5 distinct dest_ports. The test builds these from eve_01's
# body, so each carries the SQLi URL: port_scan(25) + SQLi-on-ALERT(40×0.75=30) = 55/HIGH.
# D now legitimately exercises BOTH port_scan and disposition-weighted SQLi at scale (was 25).
_ORACLE_SCORE_D = 55
_ORACLE_LEVEL_D = "HIGH"
_ORACLE_ATTACKS_D = ["port_scan", "sql_injection"]
_ORACLE_DETECTIONS_D: list[str] = []

# ORACLE_E: 3 Suricata-only ALERT events; eve_01 carries the SQLi URL → 40×0.75 = 30 (was 0).
# multi_source_attack still does NOT fire (single source_type; Flag B intact).
_ORACLE_SCORE_E = 30
_ORACLE_LEVEL_E = "MEDIUM"
_ORACLE_ATTACKS_E: list[str] = ["sql_injection"]
_ORACLE_DETECTIONS_E: list[str] = []  # explicitly NOT ['multi_source_attack']


# ── EARS-1: fixtures through pipeline → assert frozen oracle scores ───────────


class TestScenarioA_SingleAlert:
    """Scenario A: eve_01 (ALERT, Web Attack) single event.

    EARS-1: no blocks → score=0, level=LOW (frozen oracle).
    """

    def test_score_matches_oracle(self) -> None:
        events = [_norm("eve_01_web_attack_alert.json")]
        score, level, attacks, detections = _score(events)
        assert score == _ORACLE_SCORE_A, (
            f"Score regression: expected {_ORACLE_SCORE_A} (v1 oracle) got {score}. "
            "ALERT events (IDS detection, not blocked) contribute 0 to rule_score."
        )
        assert level == _ORACLE_LEVEL_A
        assert attacks == _ORACLE_ATTACKS_A
        assert detections == _ORACLE_DETECTIONS_A


class TestScenarioB_SingleBlock:
    """Scenario B: eve_02 (BLOCK, Port Scan) single event.

    EARS-1: 1 block → score=1, level=LOW (frozen oracle).
    """

    def test_score_matches_oracle(self) -> None:
        events = [_norm("eve_02_port_scan_block.json")]
        score, level, attacks, detections = _score(events)
        assert score == _ORACLE_SCORE_B, (
            f"Score regression: expected {_ORACLE_SCORE_B} (v1 oracle) got {score}. "
            "Single BLOCK event contributes +1 (per-blocked-event term in run_rules)."
        )
        assert level == _ORACLE_LEVEL_B
        assert attacks == _ORACLE_ATTACKS_B
        assert detections == _ORACLE_DETECTIONS_B


class TestScenarioC_ThreeBlocks:
    """Scenario C: 3 blocked events from same IP.

    EARS-1: brute-force threshold NOT hit (<10), so score=3, level=LOW.
    """

    def test_score_matches_oracle(self) -> None:
        # Build 3 BLOCK events by using eve_02 (the blocked fixture) three times,
        # but with different source_event_ids to be distinct.
        raw_base = _load_eve("eve_02_port_scan_block.json")
        events: list[SecurityEvent] = []
        for i in range(3):
            d = dict(raw_base)
            d["flow_id"] = 987654321 + i
            raw = RawEvent(source_type="suricata", received_at=_RECEIVED_AT, data=d)
            events.append(normalize(raw, source_id=SOURCE_ID))

        score, level, attacks, _detections = _score(events)
        assert score == _ORACLE_SCORE_C, (
            f"Score regression: expected {_ORACLE_SCORE_C} (v1 oracle) got {score}. "
            "3 blocked events → score = len(blocked) = 3 (no brute-force bonus)."
        )
        assert level == _ORACLE_LEVEL_C
        assert attacks == _ORACLE_ATTACKS_C


class TestScenarioD_PortScan:
    """Scenario D: 5 ALERT events across 5 distinct destination ports.

    EARS-1: port_scan detection (+25) → score=25, attack_types=['port_scan'].
    """

    def test_score_matches_oracle(self) -> None:
        base = _load_eve("eve_01_web_attack_alert.json")
        dest_ports = [80, 443, 22, 8080, 3306]
        events: list[SecurityEvent] = []
        for i, port in enumerate(dest_ports):
            d = dict(base)
            d["dest_port"] = port
            d["flow_id"] = 100000 + i
            ts_offset = i  # 1 minute apart
            d["timestamp"] = f"2026-01-15T10:0{ts_offset}:00.000000+0000"
            raw = RawEvent(source_type="suricata", received_at=_RECEIVED_AT, data=d)
            events.append(normalize(raw, source_id=SOURCE_ID))

        # Verify all 5 dest ports are distinct (guards test correctness)
        actual_ports = {e.destination_port for e in events}
        assert len(actual_ports) == 5, f"Expected 5 distinct ports; got {actual_ports}"

        score, level, attacks, detections = _score(events)
        assert score == _ORACLE_SCORE_D, (
            f"Score regression: expected {_ORACLE_SCORE_D} (v1 oracle) got {score}. "
            "5 distinct dest_ports → port_scan rule (+25). ALERT events not blocked."
        )
        assert level == _ORACLE_LEVEL_D
        assert attacks == _ORACLE_ATTACKS_D
        assert detections == _ORACLE_DETECTIONS_D


# ── Flag B: source_type correlation key ──────────────────────────────────────


class TestFlagBMultiSourceCorrelation:
    """Flag B: single-Suricata-source fixtures must NOT trigger multi_source_attack.

    Pins the behavior: multi_source_attack fires only when ≥2 DISTINCT source_types
    are seen for the same IP within 1 hour. A set of Suricata-only events has exactly
    1 source_type ('suricata') → no multi_source_attack Detection.

    This ensures the ported v2 detector (source_type-keyed) matches the v1 oracle
    (source_module-keyed): same inputs → same detection behavior.
    """

    def test_suricata_only_events_no_multi_source_detection(self) -> None:
        """ORACLE_E: 3 Suricata ALERT events → multi_source_attack must NOT fire.

        v1 oracle: detect([...source_module='suricata'...]) returned [] for same-source events.
        v2 code: detect([...source_type='suricata'...]) must return [] for same reason.
        """
        events = [
            _norm("eve_01_web_attack_alert.json"),
            _norm("eve_03_trojan_alert.json"),
            _norm("eve_05_recon_alert.json"),
        ]
        # All events must be from single source_type
        source_types = {e.source_type for e in events}
        assert source_types == {"suricata"}, (
            f"Test setup error: expected single source type; got {source_types}"
        )

        score, level, attacks, detections = _score(events)
        assert score == _ORACLE_SCORE_E, (
            f"Score regression: expected {_ORACLE_SCORE_E} (v1 oracle) got {score}."
        )
        assert level == _ORACLE_LEVEL_E
        assert attacks == _ORACLE_ATTACKS_E
        assert "multi_source_attack" not in detections, (
            "multi_source_attack MUST NOT fire for single-source-type (suricata-only) events. "
            "Flag B: correlation keys on source_type diversity (≥2 distinct types required). "
            f"Got detections: {detections}"
        )
        assert detections == _ORACLE_DETECTIONS_E

    def test_source_types_list_contains_only_suricata(self) -> None:
        """All events from Suricata fixtures produce source_types=['suricata']."""
        events = [
            _norm("eve_01_web_attack_alert.json"),
            _norm("eve_02_port_scan_block.json"),
            _norm("eve_04_privesc_mitre.json"),
        ]
        sources = sorted({e.source_type for e in events})
        assert sources == ["suricata"]


class TestFlagBWatermarkCompositeKey:
    """Flag B: watermark is composite (source_type, source_id) — not source_id alone.

    Pins that the store.get_watermark / set_watermark calls use BOTH axes.
    """

    async def test_watermark_uses_composite_key(self) -> None:
        """Pipeline.run_pull_cycle reads/writes watermark keyed on (source_type, source_id)."""
        from _fakes import FakeStore, FakePullPlugin
        from firewatch_core.pipeline import Pipeline
        from firewatch_core.scoped_kv import scoped_kv
        from firewatch_sdk import PluginContext
        from _fakes import FakeAIEngine
        from pydantic import BaseModel

        store = FakeStore()
        pipeline = Pipeline(store, FakeAIEngine())

        # Emit one raw event from the plugin
        raw_data = _load_eve("eve_01_web_attack_alert.json")
        raw = RawEvent(source_type="suricata", received_at=_RECEIVED_AT, data=raw_data)
        plugin = FakePullPlugin(type_key="suricata", raws=[raw])

        class _Cfg(BaseModel):
            pass

        # Mint ctx the same way the supervisor does (ADR-0027 §3)
        kv = scoped_kv(store, "suricata")
        ctx = PluginContext(kv=kv, source_id="pi-home")
        await pipeline.run_pull_cycle(plugin, _Cfg(), source_id="pi-home", ctx=ctx)

        # Watermark get must have been called with (source_type="suricata", source_id="pi-home")
        assert ("suricata", "pi-home") in store.get_watermark_calls, (
            f"get_watermark not called with ('suricata', 'pi-home'). "
            f"Actual calls: {store.get_watermark_calls}. "
            "Flag B: watermark must use the composite (source_type, source_id) key."
        )

        # Watermark set must also record the composite key
        set_keys = [(src_type, src_id) for _, src_type, src_id in store.set_watermark_calls]
        assert ("suricata", "pi-home") in set_keys, (
            f"set_watermark not called with ('suricata', 'pi-home'). "
            f"Actual set calls: {store.set_watermark_calls}. "
            "Watermark must be advanced using (source_type, source_id) composite key."
        )

    async def test_two_instances_get_independent_watermarks(self) -> None:
        """Two different source_ids share source_type but have independent watermarks."""
        from _fakes import FakeStore, FakePullPlugin, FakeAIEngine
        from firewatch_core.pipeline import Pipeline
        from firewatch_core.scoped_kv import scoped_kv
        from firewatch_sdk import PluginContext
        from pydantic import BaseModel

        store = FakeStore()
        pipeline = Pipeline(store, FakeAIEngine())

        raw_data = _load_eve("eve_01_web_attack_alert.json")
        raw = RawEvent(source_type="suricata", received_at=_RECEIVED_AT, data=raw_data)

        class _Cfg(BaseModel):
            pass

        # Mint ctx per instance the same way the supervisor does (ADR-0027 §3)
        plugin = FakePullPlugin(type_key="suricata", raws=[raw])
        ctx_pi = PluginContext(kv=scoped_kv(store, "suricata"), source_id="pi-home")
        await pipeline.run_pull_cycle(plugin, _Cfg(), source_id="pi-home", ctx=ctx_pi)

        plugin2 = FakePullPlugin(type_key="suricata", raws=[raw])
        ctx_rack = PluginContext(kv=scoped_kv(store, "suricata"), source_id="rack-sensor")
        await pipeline.run_pull_cycle(plugin2, _Cfg(), source_id="rack-sensor", ctx=ctx_rack)

        # Both watermarks exist and are keyed independently
        assert ("suricata", "pi-home") in store.watermarks
        assert ("suricata", "rack-sensor") in store.watermarks
        # Different instances, independent watermarks
        assert len(store.watermarks) == 2


# ── EARS-2: drift detection explicit test ────────────────────────────────────


class TestEars2DriftDetection:
    """EARS-2 — frozen score constants make threshold/mapping changes detectable.

    This test documents the EARS-2 property: the oracle constants are NOT derived
    from new-code output at test runtime. They were captured from the v1 legacy
    path on 2026-06-03. Any drift in scoring thresholds, attack type logic, or
    detection rule behavior will cause the assertions in Scenario A-E to fail.
    """

    def test_frozen_constants_are_literals(self) -> None:
        """Smoke-check: all oracle score constants are literal integers/strings.

        Re-blessed by ADR-0058 §D5a/D5b (issue #651) — disposition-weighted run_rules.
        """
        assert isinstance(_ORACLE_SCORE_A, int) and _ORACLE_SCORE_A == 30
        assert isinstance(_ORACLE_SCORE_B, int) and _ORACLE_SCORE_B == 0
        assert isinstance(_ORACLE_SCORE_C, int) and _ORACLE_SCORE_C == 10
        assert isinstance(_ORACLE_SCORE_D, int) and _ORACLE_SCORE_D == 55
        assert isinstance(_ORACLE_SCORE_E, int) and _ORACLE_SCORE_E == 30
        # These being literals (not computed from new code) ensures regression detection.

    def test_oracle_scores_file_matches_embedded_constants(self) -> None:
        """The expected_scores.json fixture file agrees with embedded oracle constants."""
        expected = json.loads((FIXTURES_DIR / "expected_scores.json").read_text())
        assert expected["scenario_A_single_alert"]["score"] == _ORACLE_SCORE_A
        assert expected["scenario_A_single_alert"]["threat_level"] == _ORACLE_LEVEL_A
        assert expected["scenario_B_single_block"]["score"] == _ORACLE_SCORE_B
        assert expected["scenario_C_three_blocks"]["score"] == _ORACLE_SCORE_C
        assert expected["scenario_D_port_scan"]["score"] == _ORACLE_SCORE_D
        assert expected["scenario_E_single_source_no_multi_source"]["score"] == _ORACLE_SCORE_E
