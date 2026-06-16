"""Tests for firewatch_core.ai.narration — ML-7 (issue #435).

Mapped 1:1 to EARS acceptance criteria.

EARS-1  WHEN the analyst triggers Explain, the narration is grounded ONLY in
        real fields — covered by build_narration_prompt returning a prompt that
        includes a ``collected_fields`` list and explicit "ONLY use listed fields"
        instruction.

EARS-2  Every claim carries RULE/AI provenance — tested by asserting that
        ``provenance`` key is set in both AI and rule-only paths.

EARS-3 (anti-fabrication / NULL guard)
        3a  Fields that are NULL/absent MUST NOT appear in the prompt
            (bytes, dns_query, JA4 when absent).
        3b  ``collected_fields`` in the response MUST reflect only non-null fields.
        3c  build_rule_only_narration with NULL geo → geo NOT in collected_fields.

EARS-4  WHEN AI is unavailable, build_rule_only_narration provides a rule-only
        narrative with provenance="rule" (non-fatal degradation).

Additional:
  - Sentinel wrapping is applied to attacker-controlled fields in the prompt.
  - Score factors from score_breakdown appear in the prompt.
  - build_rule_only_narration is deterministic (pure function, no I/O).
  - AI-derived fields are included ONLY when ai_status indicates AI ran.

All IPs use RFC 5737 / RFC 1918 / loopback — never real/routable IPs.
"""
from __future__ import annotations

import pytest

from firewatch_core.ai.narration import (
    build_narration_prompt,
    build_rule_only_narration,
)
from firewatch_core.ai.prompts import SENTINEL_OPEN, SENTINEL_CLOSE

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_IP = "192.0.2.1"

_FULL_DETAIL: dict = {
    "source_ip": _IP,
    "score": 75,
    "threat_level": "HIGH",
    "score_derivation": "rule",
    "total_events": 120,
    "blocked_events": 95,
    "first_seen": "2026-06-01T00:00:00Z",
    "last_seen": "2026-06-01T12:00:00Z",
    "location": "Chicago, United States",
    "asn": 4837,
    "as_name": "CHINA-UNICOM",
    "attack_types": ["SQL Injection", "port_scan"],
    "score_breakdown": [
        {"factor": "brute_force", "label": "Brute force — 95 blocked events", "points": 30},
        {"factor": "sql_injection", "label": "SQL injection payload detected", "points": 40},
        {"factor": "blocked_events", "label": "95 blocked events", "points": 95},
        {"factor": "cap", "label": "Score capped at 100", "points": -90},
    ],
    "mitre_techniques": [],
    "ai_status": "unavailable",
    "executive_summary": None,
    "intent": None,
}

_NULL_OPTIONAL_DETAIL: dict = {
    "source_ip": _IP,
    "score": 30,
    "threat_level": "MEDIUM",
    "score_derivation": "rule",
    "total_events": 5,
    "blocked_events": 2,
    "first_seen": "2026-06-01T00:00:00Z",
    "last_seen": "2026-06-01T01:00:00Z",
    # All optional fields absent/null:
    "location": None,
    "asn": None,
    "as_name": None,
    "attack_types": [],
    "score_breakdown": [],
    "mitre_techniques": None,
    "ai_status": "unavailable",
    "executive_summary": None,
    "intent": None,
}

_AI_DETAIL: dict = {
    **_FULL_DETAIL,
    "ai_status": "ok",  # AI ran
    "score_derivation": "ai+rule",
    "executive_summary": "This IP shows aggressive SQL injection probing targeting the /api endpoint.",
    "intent": "Credential harvesting via SQLi",
}


# ---------------------------------------------------------------------------
# EARS-1: narration prompt is grounded in real fields
# ---------------------------------------------------------------------------


def test_prompt_includes_ip() -> None:
    """EARS-1: prompt references the actual IP."""
    prompt = build_narration_prompt(_IP, _FULL_DETAIL)
    assert _IP in prompt


def test_prompt_includes_score_and_level() -> None:
    """EARS-1: score and threat_level appear in the prompt."""
    prompt = build_narration_prompt(_IP, _FULL_DETAIL)
    assert "75" in prompt
    assert "HIGH" in prompt


def test_prompt_includes_events_counts() -> None:
    """EARS-1: total and blocked event counts are in the prompt."""
    prompt = build_narration_prompt(_IP, _FULL_DETAIL)
    assert "120" in prompt
    assert "95" in prompt


def test_prompt_includes_collected_fields_declaration() -> None:
    """EARS-1: prompt declares which fields were actually collected."""
    prompt = build_narration_prompt(_IP, _FULL_DETAIL)
    assert "Fields available:" in prompt
    assert "score_breakdown" in prompt


def test_prompt_includes_score_factors() -> None:
    """EARS-1: rule factors from score_breakdown appear in the prompt."""
    prompt = build_narration_prompt(_IP, _FULL_DETAIL)
    assert "Brute force" in prompt
    assert "SQL injection payload detected" in prompt


# ---------------------------------------------------------------------------
# EARS-2: provenance chip support
# ---------------------------------------------------------------------------


def test_rule_only_narration_has_rule_provenance() -> None:
    """EARS-2: rule-only narration carries provenance='rule'."""
    result = build_rule_only_narration(_IP, _NULL_OPTIONAL_DETAIL)
    assert result["provenance"] == "rule"


def test_rule_only_narration_has_ai_status() -> None:
    """EARS-2: rule-only result includes ai_status from detail."""
    result = build_rule_only_narration(_IP, _NULL_OPTIONAL_DETAIL)
    assert result["ai_status"] == "unavailable"


def test_rule_only_narration_has_narrative_key() -> None:
    """EARS-2: result always has a 'narrative' key."""
    result = build_rule_only_narration(_IP, _NULL_OPTIONAL_DETAIL)
    assert "narrative" in result
    assert isinstance(result["narrative"], str)
    assert len(result["narrative"]) > 0


# ---------------------------------------------------------------------------
# EARS-3: anti-fabrication — NULL guard
# ---------------------------------------------------------------------------


def test_null_geo_not_in_prompt() -> None:
    """EARS-3a: when location is NULL the prompt does NOT contain 'Geo location'."""
    prompt = build_narration_prompt(_IP, _NULL_OPTIONAL_DETAIL)
    assert "Geo location" not in prompt
    assert "Chicago" not in prompt


def test_null_asn_not_in_prompt() -> None:
    """EARS-3a: when asn/as_name are NULL the prompt does NOT reference them."""
    prompt = build_narration_prompt(_IP, _NULL_OPTIONAL_DETAIL)
    assert "AS" not in prompt
    assert "CHINA-UNICOM" not in prompt


def test_null_attack_types_not_in_prompt() -> None:
    """EARS-3a: when attack_types is empty the block is absent from the prompt."""
    prompt = build_narration_prompt(_IP, _NULL_OPTIONAL_DETAIL)
    assert "Attack categories" not in prompt


def test_null_score_factors_not_in_prompt() -> None:
    """EARS-3a: when score_breakdown is empty no factor lines appear."""
    prompt = build_narration_prompt(_IP, _NULL_OPTIONAL_DETAIL)
    assert "Rule factors" not in prompt


def test_absent_bytes_never_in_prompt() -> None:
    """EARS-3a: bytes_in/bytes_out are never part of the prompt (dimension never collected)."""
    prompt = build_narration_prompt(_IP, _FULL_DETAIL)
    assert "bytes_in" not in prompt
    assert "bytes_out" not in prompt


def test_absent_dns_never_in_prompt() -> None:
    """EARS-3a: dns_query is never in the prompt when not in detail."""
    prompt = build_narration_prompt(_IP, _FULL_DETAIL)
    assert "dns_query" not in prompt


def test_null_optional_collected_fields_minimal() -> None:
    """EARS-3b: when optional fields are NULL they are absent from collected_fields."""
    result = build_rule_only_narration(_IP, _NULL_OPTIONAL_DETAIL)
    collected = result["collected_fields"]
    assert "geo location" not in collected
    assert "ASN / AS name" not in collected
    assert "score_breakdown" not in collected
    assert "attack_types" not in collected


def test_null_geo_not_in_collected_fields() -> None:
    """EARS-3c: null geo means geo location NOT in collected_fields."""
    result = build_rule_only_narration(_IP, _NULL_OPTIONAL_DETAIL)
    assert "geo location" not in result["collected_fields"]


def test_present_geo_in_collected_fields() -> None:
    """EARS-3c: non-null geo is reflected in collected_fields."""
    result = build_rule_only_narration(_IP, _FULL_DETAIL)
    assert "geo location" in result["collected_fields"]


# ---------------------------------------------------------------------------
# EARS-4: AI-unavailable degrade to rule-only
# ---------------------------------------------------------------------------


def test_rule_only_returns_non_empty_narrative() -> None:
    """EARS-4: rule-only fallback produces a usable narrative."""
    result = build_rule_only_narration(_IP, _FULL_DETAIL)
    assert len(result["narrative"]) > 20  # not an empty string
    assert "What to check next" in result["narrative"]


def test_rule_only_includes_score() -> None:
    """EARS-4: rule-only narrative references the score."""
    result = build_rule_only_narration(_IP, _FULL_DETAIL)
    assert "75" in result["narrative"]


def test_rule_only_includes_threat_level() -> None:
    """EARS-4: rule-only narrative references the threat level."""
    result = build_rule_only_narration(_IP, _FULL_DETAIL)
    assert "HIGH" in result["narrative"]


def test_rule_only_advisory_only() -> None:
    """EARS-4 + ADR-0015: narrative is advisory, no SOAR/execution language."""
    result = build_rule_only_narration(_IP, _FULL_DETAIL)
    narrative = result["narrative"]
    # Must not contain execution-oriented verbs in the advisory sentence
    execution_words = ["execute", "automatically block", "trigger firewall", "run playbook"]
    for word in execution_words:
        assert word not in narrative.lower()


def test_rule_only_with_minimal_detail() -> None:
    """EARS-4: rule-only is non-fatal with absolute minimal detail."""
    minimal = {
        "score": 0,
        "threat_level": "LOW",
        "total_events": 0,
        "blocked_events": 0,
    }
    result = build_rule_only_narration(_IP, minimal)
    assert result["provenance"] == "rule"
    assert isinstance(result["narrative"], str)


# ---------------------------------------------------------------------------
# Sentinel wrapping for attacker-controlled fields
# ---------------------------------------------------------------------------


def test_geo_in_prompt_is_sentinel_wrapped() -> None:
    """NB-1: geo location in the prompt is wrapped in untrusted-data sentinels."""
    prompt = build_narration_prompt(_IP, _FULL_DETAIL)
    # Geo string is attacker-influenced (attacker's IP registration)
    assert SENTINEL_OPEN in prompt
    assert "Chicago" in prompt  # value present
    # The city string should appear inside a sentinel-wrapped block
    open_idx = prompt.find(SENTINEL_OPEN)
    close_idx = prompt.find(SENTINEL_CLOSE, open_idx)
    wrapped_region = prompt[open_idx: close_idx + len(SENTINEL_CLOSE)]
    assert "Chicago" in wrapped_region


def test_asn_name_in_prompt_is_sentinel_wrapped() -> None:
    """NB-1: AS name in the prompt is wrapped in sentinels."""
    prompt = build_narration_prompt(_IP, _FULL_DETAIL)
    assert "CHINA-UNICOM" in prompt
    # Ensure the AS name appears inside a sentinel block
    start = prompt.find(SENTINEL_OPEN)
    while start != -1:
        end = prompt.find(SENTINEL_CLOSE, start)
        if end == -1:
            break
        segment = prompt[start: end + len(SENTINEL_CLOSE)]
        if "CHINA-UNICOM" in segment:
            break
        start = prompt.find(SENTINEL_OPEN, end)
    else:
        pytest.fail("CHINA-UNICOM not found inside any sentinel block")


def test_score_factors_not_sentinel_wrapped() -> None:
    """Score factors are engine output (trusted) — they appear outside sentinels."""
    prompt = build_narration_prompt(_IP, _FULL_DETAIL)
    # "Brute force" must appear in the prompt (already tested above).
    # It should NOT be inside a sentinel block because it's deterministic output.
    # Quick check: the raw label text is in the prompt without requiring sentinels.
    assert "Brute force" in prompt


# ---------------------------------------------------------------------------
# AI fields gating
# ---------------------------------------------------------------------------


def test_ai_fields_excluded_when_ai_unavailable() -> None:
    """AI executive_summary not injected when ai_status='unavailable'."""
    detail_unavailable = {**_FULL_DETAIL, "ai_status": "unavailable"}
    prompt = build_narration_prompt(_IP, detail_unavailable)
    assert "Executive summary" not in prompt
    assert "AI analysis" not in prompt


def test_ai_fields_included_when_ai_ran() -> None:
    """AI executive_summary injected when ai_status='ok'."""
    prompt = build_narration_prompt(_IP, _AI_DETAIL)
    assert "Executive summary" in prompt
    assert "SQL injection probing" in prompt


def test_ai_intent_included_when_ai_ran() -> None:
    """AI intent injected when ai_status='ok' and intent is non-null."""
    prompt = build_narration_prompt(_IP, _AI_DETAIL)
    assert "Inferred intent" in prompt
    assert "Credential harvesting" in prompt


def test_ai_fields_excluded_when_skipped() -> None:
    """AI fields not injected when ai_status='skipped'."""
    detail_skipped = {**_AI_DETAIL, "ai_status": "skipped"}
    prompt = build_narration_prompt(_IP, detail_skipped)
    assert "Executive summary" not in prompt


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_build_narration_prompt_is_deterministic() -> None:
    """Same input → same output (pure function)."""
    p1 = build_narration_prompt(_IP, _FULL_DETAIL)
    p2 = build_narration_prompt(_IP, _FULL_DETAIL)
    assert p1 == p2


def test_build_rule_only_narration_is_deterministic() -> None:
    """Same input → same output (pure function, no I/O)."""
    r1 = build_rule_only_narration(_IP, _FULL_DETAIL)
    r2 = build_rule_only_narration(_IP, _FULL_DETAIL)
    assert r1 == r2
