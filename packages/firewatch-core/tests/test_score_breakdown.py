"""Tests for build_score_breakdown (issue #209 / ADR-0036 D4).

EARS acceptance criteria → test mapping:

  EARS-1 — WHEN /threats/{ip} (or /detailed) is fetched, the response SHALL
           include score_breakdown whose points sum (after the documented cap)
           equals the returned score.
           → test_breakdown_sum_equals_score_rules_only
           → test_breakdown_sum_equals_score_with_ai_boost
           → test_breakdown_sum_equals_score_detection_boost
           → test_breakdown_sum_equals_score_all_factors
           → test_breakdown_sum_equals_score_cap_case

  EARS-2 — Ubiquitous: existing fields and all scores SHALL be unchanged;
           golden tests still green (enforced by golden suite; mirrored here).
           → test_breakdown_does_not_change_merge_score_output
           → test_breakdown_does_not_change_run_rules_output

  EARS-3 — WHEN the AI boost was applied, the breakdown SHALL contain an
           ai_boost entry; otherwise it SHALL NOT.
           → test_breakdown_contains_ai_boost_when_applied
           → test_breakdown_no_ai_boost_when_ai_none
           → test_breakdown_no_ai_boost_when_low_confidence
           → test_breakdown_no_ai_boost_when_ai_medium_level

  EARS-4 — IF the score hit the 100 cap, THEN the breakdown SHALL represent
           the cap explicitly rather than silently mis-summing.
           → test_breakdown_cap_item_present_when_capped
           → test_breakdown_cap_item_absent_when_not_capped
           → test_breakdown_sum_equals_100_when_capped

  EARS-5 — Labels SHALL be human-readable and safe to render as text nodes
           (no HTML, no raw attacker data embedded).
           → test_breakdown_labels_are_strings
           → test_breakdown_labels_do_not_contain_html

  Structural invariants:
           → test_breakdown_factor_keys_are_unique_per_ip
           → test_breakdown_all_points_non_negative_except_cap
           → test_breakdown_empty_events_yields_empty_breakdown
"""
from __future__ import annotations

from typing import Any

import pytest

from firewatch_core.scoring import build_score_breakdown, merge_score, run_rules
from _fakes import make_event


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sum_points(breakdown: list[Any]) -> int:
    """Sum the ``points`` field across all breakdown items."""
    return sum(item.points for item in breakdown)


def _factors(breakdown: list[Any]) -> list[str]:
    return [item.factor for item in breakdown]


# ---------------------------------------------------------------------------
# EARS-1 — breakdown points sum equals the final score
# ---------------------------------------------------------------------------


def test_breakdown_sum_equals_score_rules_only() -> None:
    """EARS-1: rules-only path — breakdown points sum == merge_score output."""
    events = [make_event(action="BLOCK") for _ in range(10)]  # brute_force + 10 blocked
    rule_score, _ = run_rules(events)
    score, _, _ = merge_score(rule_score, None, 0)
    breakdown = build_score_breakdown(events, None, 0)
    assert _sum_points(breakdown) == score, (
        f"Breakdown sum {_sum_points(breakdown)} != final score {score}. "
        "EARS-1: points must sum to the returned score."
    )


def test_breakdown_sum_equals_score_with_ai_boost() -> None:
    """EARS-1 + EARS-3: AI boost applied — breakdown sum == final score."""
    events = [make_event(action="BLOCK") for _ in range(5)]
    ai_result = {"threat_level": "CRITICAL", "confidence": 0.8}
    rule_score, _ = run_rules(events)
    score, _, _ = merge_score(rule_score, ai_result, 0)
    breakdown = build_score_breakdown(events, ai_result, 0)
    assert _sum_points(breakdown) == score, (
        f"Breakdown sum {_sum_points(breakdown)} != final score {score}. "
        "EARS-1: must include AI boost contribution."
    )


def test_breakdown_sum_equals_score_detection_boost() -> None:
    """EARS-1: detection boost included in breakdown sum."""
    events = [make_event(action="ALERT")]
    rule_score, _ = run_rules(events)
    detection_boost = 15
    score, _, _ = merge_score(rule_score, None, detection_boost=detection_boost)
    breakdown = build_score_breakdown(events, None, detection_boost=detection_boost)
    assert _sum_points(breakdown) == score


def test_breakdown_sum_equals_score_all_factors() -> None:
    """EARS-1: all factors combined — sum still equals final score."""
    # 10 blocked → brute_force; 5 distinct ports → port_scan; sqli payload
    events = [
        make_event(action="BLOCK", destination_port=p, payload_snippet="UNION SELECT 1")
        for p in range(10)
    ]
    ai_result = {"threat_level": "HIGH", "confidence": 0.75}
    rule_score, _ = run_rules(events)
    detection_boost = 20
    score, _, _ = merge_score(rule_score, ai_result, detection_boost=detection_boost)
    breakdown = build_score_breakdown(events, ai_result, detection_boost=detection_boost)
    assert _sum_points(breakdown) == score


def test_breakdown_sum_equals_score_cap_case() -> None:
    """EARS-1 + EARS-4: when score is capped at 100, sum still equals 100."""
    # Construct a scenario that forces the cap
    events = [
        make_event(action="BLOCK", destination_port=p, payload_snippet="UNION SELECT 1")
        for p in range(15)
    ]
    # brute_force=30, port_scan=25, sqli=40, blocked=15 → raw=110 → capped to 100
    ai_result = {"threat_level": "CRITICAL", "confidence": 0.9}
    rule_score, _ = run_rules(events)
    score, _, _ = merge_score(rule_score, ai_result, 0)
    assert score == 100, f"Expected score=100 for this scenario, got {score}"
    breakdown = build_score_breakdown(events, ai_result, 0)
    assert _sum_points(breakdown) == 100, (
        f"Capped breakdown sum {_sum_points(breakdown)} != 100. "
        "EARS-1+EARS-4: cap item must adjust sum to equal the final score."
    )


# ---------------------------------------------------------------------------
# EARS-2 — existing scores / run_rules / merge_score UNCHANGED
# ---------------------------------------------------------------------------


def test_breakdown_does_not_change_merge_score_output() -> None:
    """EARS-2: calling build_score_breakdown does not mutate merge_score inputs or output."""
    events = [make_event(action="BLOCK") for _ in range(10)]
    ai_result: dict[str, Any] = {"threat_level": "HIGH", "confidence": 0.8}
    rule_score, _ = run_rules(events)

    score_before, level_before, deriv_before = merge_score(rule_score, ai_result, 0)
    _ = build_score_breakdown(events, ai_result, 0)
    score_after, level_after, deriv_after = merge_score(rule_score, ai_result, 0)

    assert score_before == score_after
    assert level_before == level_after
    assert deriv_before == deriv_after


def test_breakdown_does_not_change_run_rules_output() -> None:
    """EARS-2: calling build_score_breakdown does not mutate run_rules inputs or output."""
    events = [make_event(action="BLOCK") for _ in range(10)]
    rule_score_before, attacks_before = run_rules(events)
    _ = build_score_breakdown(events, None, 0)
    rule_score_after, attacks_after = run_rules(events)
    assert rule_score_before == rule_score_after
    assert attacks_before == attacks_after


# ---------------------------------------------------------------------------
# EARS-3 — AI boost entry present iff boost was actually applied
# ---------------------------------------------------------------------------


def test_breakdown_contains_ai_boost_when_applied() -> None:
    """EARS-3: ai_boost factor present when CRITICAL + conf > 0.7."""
    events = [make_event(action="BLOCK")]
    ai_result = {"threat_level": "CRITICAL", "confidence": 0.8}
    breakdown = build_score_breakdown(events, ai_result)
    assert "ai_boost" in _factors(breakdown), (
        "EARS-3: 'ai_boost' factor must be present when AI boost was applied."
    )


def test_breakdown_ai_boost_points_critical() -> None:
    """EARS-3: ai_boost points == 20 for CRITICAL + conf > 0.7."""
    events = [make_event(action="BLOCK")]
    ai_result = {"threat_level": "CRITICAL", "confidence": 0.9}
    breakdown = build_score_breakdown(events, ai_result)
    ai_item = next(i for i in breakdown if i.factor == "ai_boost")
    assert ai_item.points == 20


def test_breakdown_ai_boost_points_high() -> None:
    """EARS-3: ai_boost points == 10 for HIGH + conf > 0.7."""
    events = [make_event(action="BLOCK")]
    ai_result = {"threat_level": "HIGH", "confidence": 0.75}
    breakdown = build_score_breakdown(events, ai_result)
    ai_item = next(i for i in breakdown if i.factor == "ai_boost")
    assert ai_item.points == 10


def test_breakdown_no_ai_boost_when_ai_none() -> None:
    """EARS-3: no ai_boost entry when ai_result is None."""
    events = [make_event(action="BLOCK")]
    breakdown = build_score_breakdown(events, None)
    assert "ai_boost" not in _factors(breakdown), (
        "EARS-3: 'ai_boost' factor must NOT be present when ai_result is None."
    )


def test_breakdown_no_ai_boost_when_low_confidence() -> None:
    """EARS-3: no ai_boost entry when confidence <= 0.7."""
    events = [make_event(action="BLOCK")]
    ai_result = {"threat_level": "CRITICAL", "confidence": 0.7}  # exactly 0.7 — not > 0.7
    breakdown = build_score_breakdown(events, ai_result)
    assert "ai_boost" not in _factors(breakdown)


def test_breakdown_no_ai_boost_when_ai_medium_level() -> None:
    """EARS-3: no ai_boost entry for MEDIUM level even with high confidence."""
    events = [make_event(action="BLOCK")]
    ai_result = {"threat_level": "MEDIUM", "confidence": 0.95}
    breakdown = build_score_breakdown(events, ai_result)
    assert "ai_boost" not in _factors(breakdown)


# ---------------------------------------------------------------------------
# EARS-4 — cap item explicit when score hit 100
# ---------------------------------------------------------------------------


def test_breakdown_cap_item_present_when_capped() -> None:
    """EARS-4: 'cap' factor present when raw sum exceeds 100.

    New math (#651): brute_force(30) + port_scan(25) + sqli_BLOCK(20) +
    persistence(10) + detection_boost(20) = 105 → cap fires.
    """
    # 30 BLOCK events across 30 distinct ports, all with SQLi payload:
    #   brute_force=30 (≥10 blocked), port_scan=25 (≥5 distinct ports),
    #   sqli on BLOCK = round(40×0.5) = 20, persistence=10 (≥3 blocked),
    #   detection_boost=20 → raw=105 → capped to 100 (#651)
    events = [
        make_event(action="BLOCK", destination_port=i, payload_snippet="UNION SELECT 1")
        for i in range(30)
    ]
    breakdown = build_score_breakdown(events, None, detection_boost=20)
    assert "cap" in _factors(breakdown), (
        "EARS-4: 'cap' factor must be present when raw score exceeded 100."
    )


def test_breakdown_cap_item_absent_when_not_capped() -> None:
    """EARS-4: 'cap' factor absent when score did not hit 100."""
    events = [make_event(action="BLOCK")]  # score = 1
    breakdown = build_score_breakdown(events, None)
    assert "cap" not in _factors(breakdown), (
        "EARS-4: 'cap' factor must NOT be present when score < 100."
    )


def test_breakdown_sum_equals_100_when_capped() -> None:
    """EARS-4: with cap item included, total points == 100 (not the raw sum).

    New math (#651): 30 BLOCK events across 30 distinct ports + SQLi payload:
    brute_force(30) + port_scan(25) + sqli_BLOCK(20) + persistence(10) +
    detection_boost(20) = raw 105 → cap brings sum to 100.
    """
    events = [
        make_event(action="BLOCK", destination_port=i, payload_snippet="UNION SELECT 1")
        for i in range(30)
    ]
    breakdown = build_score_breakdown(events, None, detection_boost=20)
    # raw=105 > 100, so cap item (−5) should bring sum to 100 (#651)
    assert _sum_points(breakdown) == 100


# ---------------------------------------------------------------------------
# EARS-5 — labels are human-readable strings with no HTML
# ---------------------------------------------------------------------------


def test_breakdown_labels_are_strings() -> None:
    """EARS-5: every item has a non-empty string label."""
    events = [
        make_event(action="BLOCK", destination_port=p, payload_snippet="<script>x</script>")
        for p in range(12)
    ]
    ai_result = {"threat_level": "HIGH", "confidence": 0.8}
    breakdown = build_score_breakdown(events, ai_result)
    for item in breakdown:
        assert isinstance(item.label, str), f"label is not a string: {item!r}"
        assert len(item.label) > 0, f"label is empty: {item!r}"


def test_breakdown_labels_do_not_contain_html() -> None:
    """EARS-5: labels must not contain HTML tags (safe for text-node rendering)."""
    events = [make_event(action="BLOCK", payload_snippet="<script>alert(1)</script>")]
    breakdown = build_score_breakdown(events, None)
    for item in breakdown:
        assert "<" not in item.label and ">" not in item.label, (
            f"Label contains HTML-like content (unsafe for text rendering): {item.label!r}"
        )


# ---------------------------------------------------------------------------
# Structural invariants
# ---------------------------------------------------------------------------


def test_breakdown_empty_events_yields_empty_breakdown() -> None:
    """No events → empty breakdown (score is 0, no factors to explain)."""
    breakdown = build_score_breakdown([], None)
    assert breakdown == []


def test_breakdown_all_points_non_negative_except_cap() -> None:
    """All factor points are >= 0; only 'cap' may be negative."""
    events = [
        make_event(action="BLOCK", destination_port=p, payload_snippet="UNION SELECT 1")
        for p in range(20)
    ]
    breakdown = build_score_breakdown(events, None, detection_boost=50)
    for item in breakdown:
        if item.factor != "cap":
            assert item.points >= 0, f"Non-cap item has negative points: {item!r}"


def test_breakdown_individual_rule_factors() -> None:
    """Each triggered rule contributes its expected factor key.

    (#651) The old 'blocked_events' per-event factor is RENAMED to 'persistence';
    it fires as a flat +10 floor when ≥3 blocked events are present, not per-event.
    """
    # brute_force: 10+ blocked; persistence: ≥3 blocked → flat +10 (#651)
    bf_events = [make_event(action="BLOCK") for _ in range(10)]
    breakdown = build_score_breakdown(bf_events, None)
    assert "brute_force" in _factors(breakdown)
    assert "persistence" in _factors(breakdown)  # renamed from 'blocked_events' (#651)
    assert "blocked_events" not in _factors(breakdown)  # old factor removed (#651)

    # port_scan: 5+ distinct dest ports (ALERT, not blocked)
    ps_events = [make_event(action="ALERT", destination_port=p) for p in range(5)]
    breakdown = build_score_breakdown(ps_events, None)
    assert "port_scan" in _factors(breakdown)

    # sql_injection: any event (incl. ALERT/ALLOW) with SQL payload (#651 R1)
    sqli_events = [make_event(action="BLOCK", payload_snippet="' OR '1'='1")]
    breakdown = build_score_breakdown(sqli_events, None)
    assert "sql_injection" in _factors(breakdown)

    # xss: any event with XSS payload (#651 R1)
    xss_events = [make_event(action="BLOCK", payload_snippet="<script>x</script>")]
    breakdown = build_score_breakdown(xss_events, None)
    assert "xss" in _factors(breakdown)


@pytest.mark.parametrize("n_blocked,expect_present,expected_points", [
    (1, False, None),    # 1 blocked < threshold (3) → no persistence factor (#651)
    (2, False, None),    # 2 blocked < threshold (3) → no persistence factor (#651)
    (3, True, 10),       # 3 blocked = threshold → persistence floor +10 (#651)
    (5, True, 10),       # 5 blocked > threshold → flat +10, not +5 (#651)
    (9, True, 10),       # 9 blocked > threshold → flat +10, not +9 (#651)
])
def test_breakdown_persistence_factor(
    n_blocked: int, expect_present: bool, expected_points: int | None
) -> None:
    """persistence factor replaces per-event blocked_events: flat +10 when ≥3 blocked (#651).

    Old behavior (removed): blocked_events points == number of blocked events.
    New behavior: persistence fires as a flat +10 floor at ≥3 blocked; absent otherwise.
    """
    events = [make_event(action="BLOCK") for _ in range(n_blocked)]
    breakdown = build_score_breakdown(events, None)
    p_item = next((i for i in breakdown if i.factor == "persistence"), None)
    if expect_present:
        assert p_item is not None, (
            f"persistence factor must be present when n_blocked={n_blocked} ≥ 3 (#651)"
        )
        assert p_item.points == expected_points, (
            f"persistence points must be flat {expected_points} (not per-event) (#651)"
        )
    else:
        assert p_item is None, (
            f"persistence factor must be ABSENT when n_blocked={n_blocked} < 3 (#651)"
        )


def test_breakdown_detection_boost_capped_at_30() -> None:
    """Detection boost in breakdown is capped at +30, matching merge_score."""
    events = [make_event(action="ALERT")]
    breakdown = build_score_breakdown(events, None, detection_boost=100)
    det_item = next((i for i in breakdown if i.factor == "detection_boost"), None)
    assert det_item is not None
    assert det_item.points == 30, (
        "detection_boost in breakdown must be capped at 30, matching merge_score."
    )
