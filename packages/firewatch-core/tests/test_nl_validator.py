"""Tests for nl_query/validator.py — EARS-1, EARS-2 (strict validation + degrade).

EARS mapping:
  EARS-1: LLM output validated against vocabulary before execution.
  EARS-2: OOV field/value or low-confidence → degrade to q= free-text.
"""
from __future__ import annotations

from firewatch_sdk.models import FilterSpec

from firewatch_core.nl_query.validator import (
    CONFIDENCE_THRESHOLD,
    MAX_VALUE_LEN,
    validate_candidate,
    validate_candidate_strict,
)
from firewatch_core.nl_query.vocabulary import get_vocabulary


VOCAB = get_vocabulary()


class TestValidateCandidateStrict:
    """validate_candidate_strict returns cleaned dict or None."""

    # ---- confidence threshold (EARS-2) ----

    def test_low_confidence_returns_none(self) -> None:
        """Confidence below threshold → None (degrade)."""
        candidate = {
            "confidence": CONFIDENCE_THRESHOLD - 0.01,
            "filters": {"action": "BLOCK"},
        }
        assert validate_candidate_strict(candidate, VOCAB) is None

    def test_zero_confidence_returns_none(self) -> None:
        """Zero confidence → None."""
        assert validate_candidate_strict({"confidence": 0.0, "filters": {}}, VOCAB) is None

    def test_exact_threshold_is_accepted(self) -> None:
        """Exactly at threshold → accepted (boundary)."""
        candidate = {"confidence": CONFIDENCE_THRESHOLD, "filters": {"action": "BLOCK"}}
        result = validate_candidate_strict(candidate, VOCAB)
        assert result is not None
        assert result["action"] == "BLOCK"

    def test_missing_confidence_degrades(self) -> None:
        """Missing confidence key defaults to 0.0 → degrade."""
        assert validate_candidate_strict({"filters": {"action": "BLOCK"}}, VOCAB) is None

    # ---- OOV field rejection (EARS-4 / EARS-1) ----

    def test_oov_field_is_dropped(self) -> None:
        """A field not in the vocabulary is silently dropped (strict allowlist)."""
        candidate = {
            "confidence": 0.9,
            "filters": {
                "action": "BLOCK",
                "not_a_real_field": "evil_value",  # OOV
            },
        }
        result = validate_candidate_strict(candidate, VOCAB)
        assert result is not None
        assert "action" in result
        assert "not_a_real_field" not in result

    def test_all_oov_fields_returns_none(self) -> None:
        """All fields OOV → None (no valid fields remain)."""
        candidate = {
            "confidence": 0.9,
            "filters": {"fake_col": "val", "another_fake": "x"},
        }
        assert validate_candidate_strict(candidate, VOCAB) is None

    def test_cursor_field_is_oov(self) -> None:
        """cursor is not in the vocabulary — must be rejected."""
        candidate = {
            "confidence": 0.9,
            "filters": {"cursor": "2026-01-01T00:00:00|42"},
        }
        assert validate_candidate_strict(candidate, VOCAB) is None

    def test_sql_injection_attempt_oov(self) -> None:
        """A fabricated field that looks like SQL injection is rejected."""
        candidate = {
            "confidence": 0.9,
            "filters": {"action": "BLOCK; DROP TABLE logs; --"},
        }
        # 'action' key exists but value is not in the enum — rejected
        assert validate_candidate_strict(candidate, VOCAB) is None

    # ---- enum field validation (EARS-1) ----

    def test_valid_action_enum(self) -> None:
        """Valid action value passes."""
        for action in ("BLOCK", "DROP", "ALERT", "ALLOW", "LOG", "blocked"):
            candidate = {"confidence": 0.9, "filters": {"action": action}}
            result = validate_candidate_strict(candidate, VOCAB)
            assert result is not None, f"action={action!r} should be valid"
            assert "action" in result

    def test_invalid_action_enum(self) -> None:
        """Unknown action value is rejected."""
        candidate = {"confidence": 0.9, "filters": {"action": "EXPLODE"}}
        assert validate_candidate_strict(candidate, VOCAB) is None

    def test_valid_severity_enum_case_insensitive(self) -> None:
        """Severity is normalised to lowercase."""
        candidate = {"confidence": 0.9, "filters": {"severity": "HIGH"}}
        result = validate_candidate_strict(candidate, VOCAB)
        assert result is not None
        assert result["severity"] == "high"  # normalised

    def test_invalid_severity_enum(self) -> None:
        """Unknown severity value is rejected."""
        candidate = {"confidence": 0.9, "filters": {"severity": "EXTREME"}}
        assert validate_candidate_strict(candidate, VOCAB) is None

    # ---- value length cap ----

    def test_oversized_value_rejected(self) -> None:
        """Values longer than MAX_VALUE_LEN are rejected."""
        long_val = "x" * (MAX_VALUE_LEN + 1)
        candidate = {"confidence": 0.9, "filters": {"ip": long_val}}
        assert validate_candidate_strict(candidate, VOCAB) is None

    def test_value_at_max_len_accepted(self) -> None:
        """Values exactly at MAX_VALUE_LEN are accepted."""
        ok_val = "1" * MAX_VALUE_LEN
        candidate = {"confidence": 0.9, "filters": {"ip": ok_val}}
        result = validate_candidate_strict(candidate, VOCAB)
        assert result is not None

    # ---- flat candidate shape (no "filters" sub-key) ----

    def test_flat_candidate_shape(self) -> None:
        """Flat dict (without a 'filters' key) is also accepted."""
        candidate = {"confidence": 0.8, "action": "ALERT", "severity": "high"}
        result = validate_candidate_strict(candidate, VOCAB)
        assert result is not None
        assert result["action"] == "ALERT"
        assert result["severity"] == "high"

    # ---- substring/exact fields ----

    def test_substring_ip_accepted(self) -> None:
        """IP prefix passes as substring match."""
        candidate = {"confidence": 0.9, "filters": {"ip": "192.0.2"}}
        result = validate_candidate_strict(candidate, VOCAB)
        assert result is not None
        assert result["ip"] == "192.0.2"

    def test_destination_ip_accepted(self) -> None:
        """destination_ip (ADR-0048 persisted column) is in vocabulary."""
        candidate = {"confidence": 0.9, "filters": {"destination_ip": "10.0.0"}}
        result = validate_candidate_strict(candidate, VOCAB)
        assert result is not None
        assert result["destination_ip"] == "10.0.0"

    def test_protocol_exact_accepted(self) -> None:
        """protocol exact-match field accepted."""
        candidate = {"confidence": 0.9, "filters": {"protocol": "TCP"}}
        result = validate_candidate_strict(candidate, VOCAB)
        assert result is not None
        assert result["protocol"] == "TCP"

    def test_tls_ja4_exact_accepted(self) -> None:
        """tls_ja4 exact-match field accepted (ML-13 persisted column)."""
        candidate = {
            "confidence": 0.9,
            "filters": {"tls_ja4": "t13d1517h2_8daaf6152771_b0da82dd1658"},
        }
        result = validate_candidate_strict(candidate, VOCAB)
        assert result is not None
        assert "tls_ja4" in result

    def test_mixed_valid_and_oov_fields(self) -> None:
        """Valid fields pass; OOV fields are dropped; result is non-None."""
        candidate = {
            "confidence": 0.8,
            "filters": {
                "action": "BLOCK",
                "severity": "critical",
                "nonexistent_col": "val",  # OOV — dropped
            },
        }
        result = validate_candidate_strict(candidate, VOCAB)
        assert result is not None
        assert "action" in result
        assert "severity" in result
        assert "nonexistent_col" not in result


class TestValidateCandidate:
    """validate_candidate always returns (FilterSpec, degraded) — never raises."""

    def test_valid_candidate_returns_filterspec(self) -> None:
        """Valid parse → FilterSpec with ai fields, not degraded."""
        candidate = {"confidence": 0.9, "filters": {"action": "BLOCK", "severity": "high"}}
        spec, degraded = validate_candidate(candidate, "show blocked high severity", VOCAB)
        assert not degraded
        assert isinstance(spec, FilterSpec)
        assert spec.action == "BLOCK"
        assert spec.severity == "high"

    def test_low_confidence_degrades_to_q(self) -> None:
        """Low confidence → FilterSpec(q=nl_text), degraded=True (EARS-2)."""
        candidate = {"confidence": 0.1, "filters": {"action": "BLOCK"}}
        nl = "show me blocked traffic"
        spec, degraded = validate_candidate(candidate, nl, VOCAB)
        assert degraded
        assert spec.q == nl
        assert spec.action is None

    def test_oov_only_candidate_degrades_to_q(self) -> None:
        """Candidate with only OOV fields → degrade to q= (EARS-2)."""
        candidate = {"confidence": 0.9, "filters": {"bad_field": "val"}}
        nl = "show me bad stuff"
        spec, degraded = validate_candidate(candidate, nl, VOCAB)
        assert degraded
        assert spec.q == nl

    def test_empty_filters_degrades_to_q(self) -> None:
        """Empty filters dict → degrade."""
        candidate = {"confidence": 0.8, "filters": {}}
        nl = "everything"
        spec, degraded = validate_candidate(candidate, nl, VOCAB)
        assert degraded
        assert spec.q == nl

    def test_degraded_filterspec_has_no_other_fields(self) -> None:
        """Degraded FilterSpec must not carry any filter fields besides q."""
        candidate = {"confidence": 0.0, "filters": {"action": "BLOCK"}}
        spec, degraded = validate_candidate(candidate, "query text", VOCAB)
        assert degraded
        assert spec.action is None
        assert spec.severity is None
        assert spec.ip is None

    def test_multiple_valid_fields(self) -> None:
        """Multiple valid fields produce a multi-facet FilterSpec."""
        candidate = {
            "confidence": 0.95,
            "filters": {
                "action": "ALERT",
                "severity": "critical",
                "source_type": "suricata",
                "protocol": "TCP",
            },
        }
        spec, degraded = validate_candidate(candidate, "IDS alerts", VOCAB)
        assert not degraded
        assert spec.action == "ALERT"
        assert spec.severity == "critical"
        assert spec.source_type == "suricata"
        assert spec.protocol == "TCP"

    def test_cursor_never_in_filterspec_from_candidate(self) -> None:
        """Even if LLM hallucinates a cursor field, it must be dropped."""
        candidate = {
            "confidence": 0.9,
            "filters": {
                "action": "BLOCK",
                "cursor": "2026-01-01T00:00:00|99",  # must be stripped
            },
        }
        spec, degraded = validate_candidate(candidate, "blocked traffic", VOCAB)
        # cursor is OOV so it's dropped; action is valid → not degraded
        assert not degraded
        assert spec.action == "BLOCK"
        assert spec.cursor is None
