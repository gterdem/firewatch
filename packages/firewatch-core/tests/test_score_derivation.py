"""Tests for score_derivation field (issue #201 / ADR-0035).

EARS acceptance criteria → test mapping:

  E1 — WHEN an IP's final score includes an applied AI boost,
       the API SHALL return score_derivation: "ai+rule" for that IP.
       → test_merge_score_derivation_critical_boost
       → test_merge_score_derivation_high_boost

  E2 — WHEN AI was disabled/unavailable/low-confidence (no boost applied),
       the API SHALL return score_derivation: "rule".
       → test_merge_score_derivation_ai_none
       → test_merge_score_derivation_low_confidence
       → test_merge_score_derivation_critical_exactly_threshold (boundary)

  Ubiquitous (additive): score values MUST be byte-identical to pre-change oracle.
       → test_merge_score_scores_unchanged_no_ai
       → test_merge_score_scores_unchanged_critical_boost
       → test_merge_score_scores_unchanged_high_boost
       → test_merge_score_scores_unchanged_clamped

  IF ai_result is None or malformed, THEN derivation SHALL be "rule" (graceful).
       → test_merge_score_derivation_ai_none
       → test_merge_score_derivation_malformed_no_level
       → test_merge_score_derivation_malformed_empty_dict
       → test_merge_score_derivation_malformed_bad_level

  _ai_boost helper: pure function contract.
       → test_ai_boost_critical_high_confidence
       → test_ai_boost_high_high_confidence
       → test_ai_boost_none
       → test_ai_boost_low_confidence_no_boost
       → test_ai_boost_exactly_threshold_no_boost
       → test_ai_boost_medium_no_boost
       → test_ai_boost_malformed_returns_zero
"""
from __future__ import annotations

import pytest

from firewatch_core.scoring import _ai_boost, merge_score


# ===========================================================================
# _ai_boost pure helper (no boost = 0, CRITICAL/HIGH+conf>0.7 = 20/10)
# ===========================================================================


def test_ai_boost_critical_high_confidence() -> None:
    """CRITICAL with conf > 0.7 -> boost = 20."""
    assert _ai_boost({"threat_level": "CRITICAL", "confidence": 0.8}) == 20


def test_ai_boost_critical_minimum_qualifying_confidence() -> None:
    """CRITICAL with conf just above threshold (0.71) -> boost = 20."""
    assert _ai_boost({"threat_level": "CRITICAL", "confidence": 0.71}) == 20


def test_ai_boost_high_high_confidence() -> None:
    """HIGH with conf > 0.7 -> boost = 10."""
    assert _ai_boost({"threat_level": "HIGH", "confidence": 0.9}) == 10


def test_ai_boost_none() -> None:
    """None input -> boost = 0 (graceful, mirrors merge_score tolerance)."""
    assert _ai_boost(None) == 0


def test_ai_boost_low_confidence_no_boost() -> None:
    """CRITICAL with conf < 0.7 -> no boost (strict >)."""
    assert _ai_boost({"threat_level": "CRITICAL", "confidence": 0.5}) == 0


def test_ai_boost_exactly_threshold_no_boost() -> None:
    """CRITICAL with conf == 0.7 -> no boost (threshold is strictly >0.7)."""
    assert _ai_boost({"threat_level": "CRITICAL", "confidence": 0.7}) == 0


def test_ai_boost_medium_no_boost() -> None:
    """MEDIUM threat level with high confidence -> no boost (only CRITICAL/HIGH)."""
    assert _ai_boost({"threat_level": "MEDIUM", "confidence": 0.95}) == 0


def test_ai_boost_low_no_boost() -> None:
    """LOW threat level -> no boost."""
    assert _ai_boost({"threat_level": "LOW", "confidence": 0.99}) == 0


def test_ai_boost_malformed_returns_zero() -> None:
    """Malformed ai_result (missing keys) -> boost = 0, no exception."""
    assert _ai_boost({}) == 0
    assert _ai_boost({"threat_level": "CRITICAL"}) == 0  # missing confidence
    assert _ai_boost({"confidence": 0.9}) == 0  # missing threat_level


def test_ai_boost_case_insensitive() -> None:
    """threat_level is uppercased internally -- lowercase input still works."""
    assert _ai_boost({"threat_level": "critical", "confidence": 0.9}) == 20
    assert _ai_boost({"threat_level": "high", "confidence": 0.9}) == 10


# ===========================================================================
# merge_score -- score values MUST be byte-identical to pre-change oracle
# (Ubiquitous additive invariant -- golden tests must stay green)
# ===========================================================================


def test_merge_score_scores_unchanged_no_ai() -> None:
    """Score + level unchanged when ai_result is None."""
    score, level, _deriv = merge_score(40, None, 0)
    assert score == 40
    assert level == "MEDIUM"


def test_merge_score_scores_unchanged_critical_boost() -> None:
    """Score + level unchanged: CRITICAL + conf 0.8 -> +20 (oracle: 60+20=80, CRITICAL)."""
    score, level, _deriv = merge_score(60, {"threat_level": "CRITICAL", "confidence": 0.8})
    assert score == 80
    assert level == "CRITICAL"


def test_merge_score_scores_unchanged_high_boost() -> None:
    """Score + level unchanged: HIGH + conf 0.71 -> +10 (oracle: 40+10=50, MEDIUM)."""
    score, level, _deriv = merge_score(40, {"threat_level": "HIGH", "confidence": 0.71})
    assert score == 50
    assert level == "MEDIUM"


def test_merge_score_scores_unchanged_clamped() -> None:
    """Score clamped at 100 (oracle: 95+20 -> 100, CRITICAL)."""
    score, level, _deriv = merge_score(95, {"threat_level": "CRITICAL", "confidence": 0.9})
    assert score == 100
    assert level == "CRITICAL"


def test_merge_score_scores_unchanged_detection_boost() -> None:
    """Detection boost capped at 30 (oracle: 0 + min(100,30) = 30, MEDIUM)."""
    score, _level, _deriv = merge_score(0, None, detection_boost=100)
    assert score == 30


def test_merge_score_detection_boost_negative_floored() -> None:
    """Negative detection boost is floored to 0 (oracle: 10 + 0 = 10)."""
    score, _level, _deriv = merge_score(10, None, detection_boost=-5)
    assert score == 10


@pytest.mark.parametrize(
    "score_in, expected_level",
    [
        (0, "LOW"), (25, "LOW"), (26, "MEDIUM"), (50, "MEDIUM"),
        (51, "HIGH"), (75, "HIGH"), (76, "CRITICAL"), (100, "CRITICAL"),
    ],
)
def test_merge_score_levels_unchanged(score_in: int, expected_level: str) -> None:
    """Level thresholds unchanged (oracle: same as pre-change test_merge_score_levels)."""
    score, level, _deriv = merge_score(score_in, None, 0)
    assert (score, level) == (score_in, expected_level)


# ===========================================================================
# merge_score -- score_derivation field (EARS E1 / E2)
# ===========================================================================


def test_merge_score_derivation_critical_boost() -> None:
    """E1: CRITICAL + conf > 0.7 -> boost applied -> derivation = "ai+rule"."""
    _score, _level, derivation = merge_score(
        60, {"threat_level": "CRITICAL", "confidence": 0.8}
    )
    assert derivation == "ai+rule"


def test_merge_score_derivation_high_boost() -> None:
    """E1: HIGH + conf > 0.7 -> boost applied -> derivation = "ai+rule"."""
    _score, _level, derivation = merge_score(
        40, {"threat_level": "HIGH", "confidence": 0.75}
    )
    assert derivation == "ai+rule"


def test_merge_score_derivation_ai_none() -> None:
    """E2 / graceful: ai_result is None -> no boost -> derivation = "rule"."""
    _score, _level, derivation = merge_score(40, None)
    assert derivation == "rule"


def test_merge_score_derivation_low_confidence() -> None:
    """E2: CRITICAL but conf <= 0.7 -> no boost -> derivation = "rule"."""
    _score, _level, derivation = merge_score(
        60, {"threat_level": "CRITICAL", "confidence": 0.5}
    )
    assert derivation == "rule"


def test_merge_score_derivation_critical_exactly_threshold() -> None:
    """E2 boundary: conf == 0.7 is NOT > 0.7 -> no boost -> derivation = "rule"."""
    _score, _level, derivation = merge_score(
        60, {"threat_level": "CRITICAL", "confidence": 0.7}
    )
    assert derivation == "rule"


def test_merge_score_derivation_malformed_no_level() -> None:
    """IF malformed (missing threat_level) -> derivation = "rule" (graceful)."""
    _score, _level, derivation = merge_score(40, {"confidence": 0.9})
    assert derivation == "rule"


def test_merge_score_derivation_malformed_empty_dict() -> None:
    """IF malformed (empty dict) -> derivation = "rule" (graceful)."""
    _score, _level, derivation = merge_score(40, {})
    assert derivation == "rule"


def test_merge_score_derivation_malformed_bad_level() -> None:
    """IF malformed (unknown level string) -> derivation = "rule" (graceful)."""
    _score, _level, derivation = merge_score(
        40, {"threat_level": "UNKNOWN_LEVEL", "confidence": 0.9}
    )
    assert derivation == "rule"


def test_merge_score_derivation_medium_no_boost() -> None:
    """MEDIUM + high confidence -> no boost -> derivation = "rule"."""
    _score, _level, derivation = merge_score(
        40, {"threat_level": "MEDIUM", "confidence": 0.95}
    )
    assert derivation == "rule"
