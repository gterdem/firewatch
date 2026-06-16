"""Scoring tests (EARS-3 — verbatim rule math + merge)."""
import pytest

from firewatch_core.scoring import (
    CONFIDENCE_BOOST_THRESHOLD,
    MAX_PAYLOAD_LEN,
    MAX_SAMPLES,
    build_samples,
    merge_score,
    run_rules,
)
from _fakes import make_event


def test_brute_force_threshold():
    events = [make_event(action="BLOCK") for _ in range(10)]
    score, attack_types = run_rules(events)
    # +30 brute-force + persistence floor +10 (10≥3 blocked) = 40 (#651)
    assert score == 40
    assert "brute_force" in attack_types


def test_brute_force_below_threshold():
    events = [make_event(action="BLOCK") for _ in range(9)]
    score, attack_types = run_rules(events)
    assert score == 10  # no +30 (9<10); persistence floor +10 (9≥3 blocked) — #651
    assert "brute_force" not in attack_types


def test_port_scan_threshold():
    events = [make_event(action="ALLOW", destination_port=p) for p in range(5)]
    score, attack_types = run_rules(events)
    assert score == 25  # +25 port-scan, 0 blocked
    assert "port_scan" in attack_types


def test_sqli_payload():
    events = [make_event(action="BLOCK", payload_snippet="' OR '1'='1")]
    score, attack_types = run_rules(events)
    assert score == 20  # sqli on a BLOCK = round(40×0.5); 1 block < persistence threshold — #651
    assert "sql_injection" in attack_types


def test_xss_payload():
    events = [make_event(action="BLOCK", payload_snippet="<script>alert(1)</script>")]
    score, attack_types = run_rules(events)
    assert score == 18  # xss on a BLOCK = round(35×0.5)=18; 1 block < persistence — #651
    assert "xss" in attack_types


def test_sqli_scored_once():
    events = [make_event(action="BLOCK", payload_snippet="UNION SELECT 1") for _ in range(3)]
    score, attack_types = run_rules(events)
    assert attack_types.count("sql_injection") == 1
    assert score == 30  # sqli on BLOCK (round(40×0.5)=20) + persistence floor (3≥3 → +10) — #651


def test_build_samples_groups_caps_and_truncates():
    long_payload = "A" * 250
    events = (
        [make_event(action="BLOCK", rule_id="942100", payload_snippet=long_payload)] * 3
        + [make_event(action="BLOCK", rule_id="941110", payload_snippet="<script")]
    )
    samples = build_samples(events)
    assert [s["rule_id"] for s in samples] == ["942100", "941110"]  # sorted by count desc
    assert samples[0]["count"] == 3
    assert samples[0]["category"] == "SQL Injection"
    assert len(samples[0]["payload"]) == MAX_PAYLOAD_LEN


def test_build_samples_cap():
    events = [
        make_event(action="BLOCK", rule_id=f"9{i:05d}", payload_snippet="x")
        for i in range(20)
    ]
    assert len(build_samples(events)) == MAX_SAMPLES


@pytest.mark.parametrize(
    "score_in, expected_level",
    [(0, "LOW"), (25, "LOW"), (26, "MEDIUM"), (50, "MEDIUM"),
     (51, "HIGH"), (75, "HIGH"), (76, "CRITICAL"), (100, "CRITICAL")],
)
def test_merge_score_levels(score_in, expected_level):
    score, level, _deriv = merge_score(score_in, None, 0)
    assert (score, level) == (score_in, expected_level)


def test_merge_detection_boost_capped_at_30():
    score, _, _deriv = merge_score(0, None, detection_boost=100)
    assert score == 30


def test_merge_detection_boost_negative_floored():
    score, _, _deriv = merge_score(10, None, detection_boost=-5)
    assert score == 10


def test_merge_ai_critical_boost():
    score, level, _deriv = merge_score(60, {"threat_level": "CRITICAL", "confidence": 0.8})
    assert (score, level) == (80, "CRITICAL")


def test_merge_ai_high_boost():
    score, _, _deriv = merge_score(40, {"threat_level": "HIGH", "confidence": 0.71})
    assert score == 50


def test_merge_ai_below_confidence_no_boost():
    score, _, _deriv = merge_score(40, {"threat_level": "CRITICAL", "confidence": 0.7})
    assert score == 40  # 0.7 is not > 0.7


def test_merge_score_clamped_to_100():
    score, _, _deriv = merge_score(95, {"threat_level": "CRITICAL", "confidence": 0.9})
    assert score == 100


# EARS: the boost gate SHALL read from a single named constant (issue #460).
def test_confidence_boost_threshold_value():
    """Constant is exported and holds the canonical 0.7 gate value."""
    assert CONFIDENCE_BOOST_THRESHOLD == 0.7


def test_confidence_boost_threshold_is_strict_boundary():
    """Exactly-at-threshold is NOT a boost; one epsilon above IS (strict > comparison)."""
    at_threshold = CONFIDENCE_BOOST_THRESHOLD
    just_above = CONFIDENCE_BOOST_THRESHOLD + 1e-9

    score_at, _, _ = merge_score(40, {"threat_level": "CRITICAL", "confidence": at_threshold})
    score_above, _, _ = merge_score(40, {"threat_level": "CRITICAL", "confidence": just_above})

    assert score_at == 40           # exactly at threshold — no boost
    assert score_above == 60        # just above — CRITICAL +20 applied
