"""Tests for firewatch_core.ai.baseline.drift_report (MK-8 / issue #413).

EARS criterion -> test(s) mapping
----------------------------------
EARS-1  Event-driven: firewatch ai-baseline --compare SHALL persist a
        machine-readable drift report JSON with the required fields.

        Serializer shape:
        test_build_drift_report_required_fields
        test_build_drift_report_no_drift
        test_build_drift_report_with_drift
        test_build_drift_report_escalation_counted
        test_build_drift_report_deescalation_counted
        test_build_drift_report_scenario_count

        Validation:
        test_validate_report_ok
        test_validate_report_missing_key
        test_validate_report_diffs_not_list

        load_and_validate:
        test_load_and_validate_ok
        test_load_and_validate_oversized
        test_load_and_validate_bad_json
        test_load_and_validate_not_dict
        test_load_and_validate_missing_key

Security / gitleaks compliance:
        All IPs in this file are RFC 5737 documentation ranges only.
        192.0.2.x, 198.51.100.x, 203.0.113.x -- gitleaks-clean.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from firewatch_core.ai.baseline.drift_report import (
    MAX_REPORT_BYTES,
    build_drift_report,
    load_and_validate,
    validate_report,
)
from firewatch_core.ai.baseline.report import VerdictDrift


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_drift(
    category: str,
    saved_threat: str,
    current_threat: str,
    saved_action: str = "block",
    current_action: str = "monitor",
) -> VerdictDrift:
    field_drifts = [("threat_level", saved_threat, current_threat)]
    if saved_action != current_action:
        field_drifts.append(("recommended_action", saved_action, current_action))
    saved = {
        "threat_level": saved_threat,
        "recommended_action": saved_action,
        "attack_stage": "exploitation",
        "confidence": 0.85,
    }
    current = {
        "threat_level": current_threat,
        "recommended_action": current_action,
        "attack_stage": "reconnaissance",
        "confidence": 0.6,
    }
    return VerdictDrift(
        category=category,
        field_drifts=field_drifts,
        saved=saved,
        current=current,
    )


_BASELINE = {
    "sc1": {
        "threat_level": "HIGH",
        "recommended_action": "block",
        "attack_stage": "exploitation",
        "confidence": 0.85,
    },
    "sc2": {
        "threat_level": "LOW",
        "recommended_action": "monitor",
        "attack_stage": "reconnaissance",
        "confidence": 0.5,
    },
}

_CANDIDATE_NO_DRIFT = dict(_BASELINE)

_CANDIDATE_WITH_DRIFT = {
    "sc1": {
        "threat_level": "MEDIUM",          # drifted from HIGH
        "recommended_action": "monitor",   # drifted from block
        "attack_stage": "reconnaissance",
        "confidence": 0.6,
    },
    "sc2": {
        "threat_level": "LOW",
        "recommended_action": "monitor",
        "attack_stage": "reconnaissance",
        "confidence": 0.5,
    },
}


# ---------------------------------------------------------------------------
# EARS-1: build_drift_report shape
# ---------------------------------------------------------------------------


class TestBuildDriftReport:
    def test_build_drift_report_required_fields(self) -> None:
        """Report dict must contain all required top-level keys."""
        report = build_drift_report(
            drifts=[],
            baseline_verdicts=_BASELINE,
            candidate_verdicts=_CANDIDATE_NO_DRIFT,
            baseline_model="llama3.2",
            candidate_model="llama3.2",
        )
        required = {
            "baseline_model", "candidate_model", "run_at",
            "scenarios", "changed", "escalations", "deescalations", "diffs",
        }
        for key in required:
            assert key in report, f"Required key '{key}' missing from report"

    def test_build_drift_report_no_drift(self) -> None:
        """When there are no drifts, changed=0, diffs=[], escalations=0."""
        report = build_drift_report(
            drifts=[],
            baseline_verdicts=_BASELINE,
            candidate_verdicts=_CANDIDATE_NO_DRIFT,
            baseline_model="llama3.2",
            candidate_model="llama3.2",
        )
        assert report["changed"] == 0
        assert report["diffs"] == []
        assert report["escalations"] == 0
        assert report["deescalations"] == 0

    def test_build_drift_report_with_drift(self) -> None:
        """When there is a drift, changed equals the number of drifted scenarios."""
        drift = _make_drift("sc1", saved_threat="HIGH", current_threat="MEDIUM")
        report = build_drift_report(
            drifts=[drift],
            baseline_verdicts=_BASELINE,
            candidate_verdicts=_CANDIDATE_WITH_DRIFT,
            baseline_model="llama3.2",
            candidate_model="qwen3:14b",
        )
        assert report["changed"] == 1
        assert len(report["diffs"]) == 1
        diff = report["diffs"][0]
        assert diff["scenario"] == "sc1"
        assert diff["baseline_verdict"] == "HIGH"
        assert diff["candidate_verdict"] == "MEDIUM"

    def test_build_drift_report_escalation_counted(self) -> None:
        """A threat_level increase (LOW->HIGH) increments escalations."""
        drift = _make_drift("sc1", saved_threat="LOW", current_threat="HIGH")
        report = build_drift_report(
            drifts=[drift],
            baseline_verdicts={"sc1": drift.saved},
            candidate_verdicts={"sc1": drift.current},
            baseline_model="m1",
            candidate_model="m2",
        )
        assert report["escalations"] == 1
        assert report["deescalations"] == 0

    def test_build_drift_report_deescalation_counted(self) -> None:
        """A threat_level decrease (HIGH->LOW) increments deescalations."""
        drift = _make_drift("sc1", saved_threat="HIGH", current_threat="LOW")
        report = build_drift_report(
            drifts=[drift],
            baseline_verdicts={"sc1": drift.saved},
            candidate_verdicts={"sc1": drift.current},
            baseline_model="m1",
            candidate_model="m2",
        )
        assert report["deescalations"] == 1
        assert report["escalations"] == 0

    def test_build_drift_report_scenario_count(self) -> None:
        """scenarios field reflects the total number of verdicts evaluated."""
        report = build_drift_report(
            drifts=[],
            baseline_verdicts=_BASELINE,
            candidate_verdicts=_CANDIDATE_NO_DRIFT,
            baseline_model="m1",
            candidate_model="m1",
        )
        assert report["scenarios"] == len(_BASELINE)

    def test_build_drift_report_model_ids(self) -> None:
        """baseline_model and candidate_model are passed through unchanged."""
        report = build_drift_report(
            drifts=[],
            baseline_verdicts=_BASELINE,
            candidate_verdicts=_CANDIDATE_NO_DRIFT,
            baseline_model="llama3.2",
            candidate_model="qwen3:14b",
        )
        assert report["baseline_model"] == "llama3.2"
        assert report["candidate_model"] == "qwen3:14b"

    def test_build_drift_report_run_at_is_iso(self) -> None:
        """run_at must be a non-empty string (ISO-8601 UTC timestamp)."""
        from datetime import datetime
        report = build_drift_report(
            drifts=[],
            baseline_verdicts=_BASELINE,
            candidate_verdicts=_CANDIDATE_NO_DRIFT,
            baseline_model="m",
            candidate_model="m",
        )
        run_at = report["run_at"]
        assert isinstance(run_at, str) and len(run_at) > 0
        # Must be parseable as ISO datetime
        datetime.fromisoformat(run_at)

    def test_diff_entry_has_required_keys(self) -> None:
        """Each diff entry must have the required keys."""
        drift = _make_drift("sc1", saved_threat="HIGH", current_threat="LOW")
        report = build_drift_report(
            drifts=[drift],
            baseline_verdicts={"sc1": drift.saved},
            candidate_verdicts={"sc1": drift.current},
            baseline_model="m",
            candidate_model="m",
        )
        required_diff_keys = {
            "scenario", "baseline_verdict", "candidate_verdict",
            "baseline_confidence", "candidate_confidence",
            "baseline_summary", "candidate_summary",
        }
        diff = report["diffs"][0]
        for key in required_diff_keys:
            assert key in diff, f"Required diff key '{key}' missing"


# ---------------------------------------------------------------------------
# EARS-1: validate_report
# ---------------------------------------------------------------------------


class TestValidateReport:
    def _valid_report(self) -> dict[str, Any]:
        return {
            "baseline_model": "llama3.2",
            "candidate_model": "qwen3:14b",
            "run_at": "2026-06-12T14:00:00+00:00",
            "scenarios": 8,
            "changed": 0,
            "escalations": 0,
            "deescalations": 0,
            "diffs": [],
        }

    def test_validate_report_ok(self) -> None:
        """A well-formed report does not raise."""
        validate_report(self._valid_report())  # must not raise

    def test_validate_report_missing_key(self) -> None:
        """A report missing a required key raises ValueError."""
        report = self._valid_report()
        del report["diffs"]
        with pytest.raises(ValueError, match="missing required keys"):
            validate_report(report)

    def test_validate_report_diffs_not_list(self) -> None:
        """diffs being a non-list raises ValueError."""
        report = self._valid_report()
        report["diffs"] = "not a list"  # type: ignore[assignment]
        with pytest.raises(ValueError, match="list"):
            validate_report(report)

    def test_validate_report_scenarios_not_int(self) -> None:
        """scenarios being a non-int raises ValueError."""
        report = self._valid_report()
        report["scenarios"] = "eight"  # type: ignore[assignment]
        with pytest.raises(ValueError, match="integer"):
            validate_report(report)


# ---------------------------------------------------------------------------
# EARS-1: load_and_validate
# ---------------------------------------------------------------------------


class TestLoadAndValidate:
    def _valid_bytes(self) -> bytes:
        return json.dumps({
            "baseline_model": "llama3.2",
            "candidate_model": "qwen3:14b",
            "run_at": "2026-06-12T14:00:00+00:00",
            "scenarios": 8,
            "changed": 0,
            "escalations": 0,
            "deescalations": 0,
            "diffs": [],
        }).encode("utf-8")

    def test_load_and_validate_ok(self) -> None:
        """Valid bytes deserialise and validate cleanly."""
        report = load_and_validate(self._valid_bytes())
        assert report["scenarios"] == 8
        assert report["diffs"] == []

    def test_load_and_validate_oversized(self) -> None:
        """Bytes exceeding MAX_REPORT_BYTES raise ValueError."""
        oversized = b"x" * (MAX_REPORT_BYTES + 1)
        with pytest.raises(ValueError, match="size cap"):
            load_and_validate(oversized)

    def test_load_and_validate_bad_json(self) -> None:
        """Non-JSON bytes raise ValueError."""
        with pytest.raises(ValueError, match="not valid JSON"):
            load_and_validate(b"not-json{{{")

    def test_load_and_validate_not_dict(self) -> None:
        """A JSON array (not object) at the top level raises ValueError."""
        with pytest.raises(ValueError, match="JSON object"):
            load_and_validate(b"[1, 2, 3]")

    def test_load_and_validate_missing_key(self) -> None:
        """A JSON object missing required keys raises ValueError."""
        bad = json.dumps({"baseline_model": "x"}).encode("utf-8")
        with pytest.raises(ValueError):
            load_and_validate(bad)
