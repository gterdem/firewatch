"""Tests for issue #42 — SDK: EscalationVerdict.tier widens to int | None;
EscalationDispositionLiteral gains "observed" (ADR-0067 D2).

EARS criteria -> test mapping:
- WHEN EscalationVerdict is constructed with tier=None and disposition="observed",
  THE SDK SHALL accept it without a validation error.
  -> TestObservedVerdictConstruction

- WHEN EscalationVerdict.tier is omitted, THE SDK SHALL default it to None
  (additive, ADR-0048/0055 pattern -- existing serialized verdicts without a
  "tier" key remain valid).
  -> TestTierDefaultsToNone

- WHEN EscalationVerdict.tier is an int outside [1, 4], THE SDK SHALL still
  reject it (the ge/le constraint applies to the int branch; unaffected by
  the widen).
  -> TestTierRangeConstraintUnaffected

- WHEN EscalationVerdict is constructed with the four pre-existing tier/
  disposition combinations, THE SDK SHALL accept them unchanged (backward
  compatibility of the widen).
  -> TestPreExistingLiteralsUnaffected

- WHEN an EscalationVerdict with tier=None is serialised via model_dump /
  model_dump_json, THE SDK SHALL round-trip tier as null/None.
  -> TestObservedVerdictSerialization
"""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from firewatch_sdk.models import EscalationVerdict


# ---------------------------------------------------------------------------
# Observed verdict construction (tier=None, disposition="observed")
# ---------------------------------------------------------------------------

class TestObservedVerdictConstruction:
    def test_tier_none_disposition_observed_accepted(self):
        v = EscalationVerdict(
            tier=None,
            disposition="observed",
            justification="[RULE] test",
            block_status="unknown",
        )
        assert v.tier is None
        assert v.disposition == "observed"

    def test_observed_with_allowed_block_status(self):
        v = EscalationVerdict(
            tier=None,
            disposition="observed",
            justification="[RULE] test",
            block_status="allowed",
        )
        assert v.block_status == "allowed"

    def test_observed_with_partial_block_status(self):
        v = EscalationVerdict(
            tier=None,
            disposition="observed",
            justification="[RULE] test",
            block_status="partial",
        )
        assert v.block_status == "partial"

    def test_observed_disposition_with_non_none_tier_is_not_forbidden_by_schema(self):
        """The SDK does not couple tier/disposition consistency (decider.py's job);
        the type system alone permits any tier with any disposition literal."""
        v = EscalationVerdict(
            tier=2,
            disposition="observed",
            justification="[RULE] test",
            block_status="unknown",
        )
        assert v.tier == 2
        assert v.disposition == "observed"


# ---------------------------------------------------------------------------
# tier defaults to None (additive backward compat)
# ---------------------------------------------------------------------------

class TestTierDefaultsToNone:
    def test_tier_omitted_defaults_to_none(self):
        v = EscalationVerdict(
            disposition="observed",
            justification="[RULE] test",
            block_status="unknown",
        )
        assert v.tier is None

    def test_model_validate_dict_without_tier_key(self):
        """Deserializing a payload with no 'tier' key (pre-widen external shape,
        or a hand-built dict) must not raise -- additive pattern (ADR-0048/0055)."""
        payload = {
            "disposition": "observed",
            "justification": "[RULE] test",
            "block_status": "unknown",
        }
        v = EscalationVerdict.model_validate(payload)
        assert v.tier is None


# ---------------------------------------------------------------------------
# ge=1, le=4 constraint still applies to the int branch
# ---------------------------------------------------------------------------

class TestTierRangeConstraintUnaffected:
    def test_tier_zero_rejected(self):
        with pytest.raises(ValidationError):
            EscalationVerdict(
                tier=0,
                disposition="allowed_through",
                justification="[RULE] test",
                block_status="allowed",
            )

    def test_tier_five_rejected(self):
        """Tier 5 is deliberately never valid (ADR-0067 D2 -- observed is tier=None,
        not tier=5)."""
        with pytest.raises(ValidationError):
            EscalationVerdict(
                tier=5,
                disposition="observed",
                justification="[RULE] test",
                block_status="unknown",
            )

    def test_negative_tier_rejected(self):
        with pytest.raises(ValidationError):
            EscalationVerdict(
                tier=-1,
                disposition="allowed_through",
                justification="[RULE] test",
                block_status="allowed",
            )

    @pytest.mark.parametrize("tier", [1, 2, 3, 4])
    def test_valid_tiers_1_through_4_accepted(self, tier: int):
        v = EscalationVerdict(
            tier=tier,
            disposition="allowed_through",
            justification="[RULE] test",
            block_status="allowed",
        )
        assert v.tier == tier


# ---------------------------------------------------------------------------
# Pre-existing literal combinations unaffected by the widen
# ---------------------------------------------------------------------------

class TestPreExistingLiteralsUnaffected:
    @pytest.mark.parametrize(
        ("tier", "disposition", "block_status"),
        [
            (1, "allowed_through", "allowed"),
            (2, "block_status_unknown", "unknown"),
            (3, "blocked_persistent", "blocked"),
            (4, "blocked_one_off", "blocked"),
        ],
    )
    def test_pre_existing_combination_still_valid(
        self, tier: int, disposition: str, block_status: str
    ):
        v = EscalationVerdict(
            tier=tier,
            disposition=disposition,  # type: ignore[arg-type]
            justification="[RULE] test",
            block_status=block_status,  # type: ignore[arg-type]
        )
        assert v.tier == tier
        assert v.disposition == disposition
        assert v.block_status == block_status

    def test_invalid_disposition_still_rejected(self):
        with pytest.raises(ValidationError):
            EscalationVerdict(
                tier=1,
                disposition="totally_made_up",  # type: ignore[arg-type]
                justification="[RULE] test",
                block_status="allowed",
            )


# ---------------------------------------------------------------------------
# Serialization round-trip with tier=None
# ---------------------------------------------------------------------------

class TestObservedVerdictSerialization:
    def test_model_dump_tier_is_none(self):
        v = EscalationVerdict(
            tier=None,
            disposition="observed",
            justification="[RULE] test",
            block_status="unknown",
        )
        d = v.model_dump()
        assert d["tier"] is None
        assert d["disposition"] == "observed"

    def test_model_dump_json_tier_is_null(self):
        v = EscalationVerdict(
            tier=None,
            disposition="observed",
            justification="[RULE] test",
            block_status="unknown",
        )
        parsed = json.loads(v.model_dump_json())
        assert parsed["tier"] is None
        assert parsed["disposition"] == "observed"

    def test_round_trip_via_model_validate_json(self):
        v = EscalationVerdict(
            tier=None,
            disposition="observed",
            justification="[RULE] test",
            block_status="unknown",
        )
        raw = v.model_dump_json()
        rebuilt = EscalationVerdict.model_validate_json(raw)
        assert rebuilt == v
