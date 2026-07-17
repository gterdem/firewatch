"""Tests for SourceMetadata.enforcement (ADR-0067 D6, issue #75 Phase A).

EARS criterion -> test mapping
==============================

EARS-E-1 (ubiquitous — additive, defaulted to None):
  SourceMetadata SHALL accept construction without specifying `enforcement`;
  the default SHALL be None ("undeclared").
  -> test_enforcement_defaults_to_none
  -> test_metadata_without_enforcement_loads_fine (byte-compatibility)

EARS-E-2 (ubiquitous — the three declared values are accepted):
  SourceMetadata SHALL accept `enforcement` set to "observe", "enforce", or
  "detect_only".
  -> test_observe_accepted / test_enforce_accepted / test_detect_only_accepted

EARS-E-3 (ubiquitous — an unknown value is rejected):
  WHEN `enforcement` is not one of the three declared values (and not None),
  construction SHALL raise ValidationError (closed Literal, fail-closed).
  -> test_unknown_enforcement_value_rejected

EARS-E-4 (ubiquitous — frozen model stays frozen):
  SourceMetadata remains frozen (immutable) when enforcement is set.
  -> test_metadata_with_enforcement_is_frozen

EARS-E-5 (ubiquitous — exported from SDK root):
  EnforcementPostureLiteral is importable from firewatch_sdk (no-regression).
  -> test_enforcement_posture_literal_imported_from_sdk

EARS-E-6 (ubiquitous — EscalationVerdict.disposition grows additively):
  EscalationVerdict SHALL accept each of the three new posture-derived
  disposition values (ADR-0067 D6 + Amendment 1).
  -> TestEscalationVerdictPostureDispositions
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from firewatch_sdk import EnforcementPostureLiteral, EscalationVerdict, SourceMetadata


# --------------------------------------------------------------------------- #
# EARS-E-1: default None ("undeclared"), byte-compatible construction         #
# --------------------------------------------------------------------------- #

def test_enforcement_defaults_to_none():
    """SourceMetadata.enforcement defaults to None (undeclared)."""
    meta = SourceMetadata(
        type_key="testsrc",
        display_name="Test Source",
        version="1.0.0",
        flavor="pull",
    )
    assert meta.enforcement is None


def test_metadata_without_enforcement_loads_fine():
    """Existing-style construction without enforcement does not break (every
    existing plugin stays byte-compatible — ADR-0048/0055 additive pattern)."""
    meta = SourceMetadata(
        type_key="oldsrc",
        display_name="Old Source",
        version="0.1.0",
        flavor="push",
    )
    assert meta.enforcement is None


# --------------------------------------------------------------------------- #
# EARS-E-2: the three declared values are accepted                            #
# --------------------------------------------------------------------------- #

def test_observe_accepted():
    meta = SourceMetadata(
        type_key="testsrc",
        display_name="Test",
        version="1.0.0",
        flavor="pull",
        enforcement="observe",
    )
    assert meta.enforcement == "observe"


def test_enforce_accepted():
    meta = SourceMetadata(
        type_key="testsrc",
        display_name="Test",
        version="1.0.0",
        flavor="pull",
        enforcement="enforce",
    )
    assert meta.enforcement == "enforce"


def test_detect_only_accepted():
    meta = SourceMetadata(
        type_key="testsrc",
        display_name="Test",
        version="1.0.0",
        flavor="pull",
        enforcement="detect_only",
    )
    assert meta.enforcement == "detect_only"


# --------------------------------------------------------------------------- #
# EARS-E-3: unknown values rejected (closed Literal, fail-closed)              #
# --------------------------------------------------------------------------- #

def test_unknown_enforcement_value_rejected():
    """A value outside the closed 3-member Literal (+ None) raises ValidationError."""
    with pytest.raises(ValidationError):
        SourceMetadata(
            type_key="testsrc",
            display_name="Test",
            version="1.0.0",
            flavor="pull",
            enforcement="prevent",  # type: ignore[arg-type]
        )


# --------------------------------------------------------------------------- #
# EARS-E-4: frozen model stays frozen                                          #
# --------------------------------------------------------------------------- #

def test_metadata_with_enforcement_is_frozen():
    meta = SourceMetadata(
        type_key="testsrc",
        display_name="Test",
        version="1.0.0",
        flavor="pull",
        enforcement="observe",
    )
    with pytest.raises(Exception):
        meta.enforcement = "enforce"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# EARS-E-5: no-regression SDK import                                           #
# --------------------------------------------------------------------------- #

def test_enforcement_posture_literal_imported_from_sdk():
    """EnforcementPostureLiteral is importable from the SDK root."""
    assert EnforcementPostureLiteral is not None


# --------------------------------------------------------------------------- #
# EARS-E-6: EscalationVerdict.disposition grows additively (D6 + Amendment 1)  #
# --------------------------------------------------------------------------- #

class TestEscalationVerdictPostureDispositions:
    """EscalationVerdict accepts each new posture-derived disposition value.

    Every verdict pins tier=2 / block_status='unknown' — posture only ever
    relabels a qualified Tier-2 disposition (the #75 safety property).
    """

    @pytest.mark.parametrize(
        "disposition",
        ["not_blocked_passive", "detected_no_action", "not_blocked_enforcing"],
    )
    def test_accepts_each_posture_disposition(self, disposition: str) -> None:
        verdict = EscalationVerdict(
            tier=2,
            disposition=disposition,  # type: ignore[arg-type]
            justification="[RULE] test",
            block_status="unknown",
        )
        assert verdict.disposition == disposition
        assert verdict.tier == 2
