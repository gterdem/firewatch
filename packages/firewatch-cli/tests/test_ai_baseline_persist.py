"""Tests for MK-8 drift-report persistence in the ai-baseline CLI (issue #413).

These tests verify the NEW behavior: ``firewatch ai-baseline --compare``
additionally persists a machine-readable drift report JSON alongside the
baseline file.

EARS criterion -> test(s) mapping
----------------------------------
EARS-1  --compare SHALL persist a drift report JSON.
        test_compare_writes_drift_report
        test_compare_drift_report_has_required_fields
        test_compare_no_drift_report_has_empty_diffs
        test_compare_drift_report_has_correct_diffs
        test_compare_report_out_custom_path
        test_compare_persist_failure_does_not_change_exit_code

EARS-4  Scenario count in report matches SCENARIOS registry.
        test_compare_drift_report_scenario_count

Security: all IPs are RFC 5737 documentation ranges.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

# ---------------------------------------------------------------------------
# Shared mock helpers (same as test_ai_baseline.py)
# ---------------------------------------------------------------------------

_VERDICT_CONCISE_A: dict[str, Any] = {
    "threat_level": "HIGH",
    "confidence": 0.85,
    "intent": "SQL injection probe",
    "attack_stage": "exploitation",
    "insights": ["pattern: SQLi detected"],
    "recommended_action": "block",
}

_VERDICT_CONCISE_DRIFTED: dict[str, Any] = {
    "threat_level": "MEDIUM",
    "confidence": 0.6,
    "intent": "Automated scanning",
    "attack_stage": "reconnaissance",
    "insights": ["pattern: scan probe"],
    "recommended_action": "monitor",
}

_VERDICT_DETAILED_A: dict[str, Any] = {
    "threat_level": "CRITICAL",
    "confidence": 0.9,
    "executive_summary": "Sustained attack.",
    "intent": "Data exfil",
    "attack_stage": "data_exfiltration",
    "attack_progression": ["Step 1: probe"],
    "insights": {"patterns": [], "risks": [], "mitigations": []},
    "ioc_indicators": [],
    "recommended_action": "block",
    "false_positive_likelihood": 0.05,
}


def _make_mock_engine(
    concise_verdict: dict[str, Any] = _VERDICT_CONCISE_A,
    detailed_verdict: dict[str, Any] = _VERDICT_DETAILED_A,
    available: bool = True,
    model: str = "llama3.2",
) -> MagicMock:
    """Build a mock AI engine that returns fixed verdicts without any network call."""
    engine = MagicMock()
    engine.model = model
    engine.is_available = AsyncMock(return_value=available)
    engine.analyze_concise = AsyncMock(return_value=dict(concise_verdict))
    engine.analyze_detailed = AsyncMock(return_value=dict(detailed_verdict))
    return engine


# ---------------------------------------------------------------------------
# EARS-1: --compare writes drift report
# ---------------------------------------------------------------------------


class TestComparePersistsDriftReport:
    async def test_compare_writes_drift_report(self, tmp_path: Path) -> None:
        """--compare SHALL write a drift report JSON alongside the baseline."""
        from firewatch_cli.commands.ai_baseline import cmd_ai_baseline

        engine = _make_mock_engine()
        baseline_path = tmp_path / "baseline.json"
        report_out = tmp_path / "drift_report.json"

        # Save a baseline first
        await cmd_ai_baseline(
            mode="save",
            engine=engine,
            out_path=baseline_path,
            baseline_path=None,
        )

        # Run compare; report_out must be created
        await cmd_ai_baseline(
            mode="compare",
            engine=engine,
            out_path=None,
            baseline_path=baseline_path,
            report_out=report_out,
        )

        assert report_out.exists(), "Drift report file was not written by --compare"

    async def test_compare_drift_report_has_required_fields(self, tmp_path: Path) -> None:
        """The persisted drift report must contain all required top-level fields."""
        from firewatch_cli.commands.ai_baseline import cmd_ai_baseline

        engine = _make_mock_engine()
        baseline_path = tmp_path / "baseline.json"
        report_out = tmp_path / "drift_report.json"

        await cmd_ai_baseline(
            mode="save", engine=engine, out_path=baseline_path, baseline_path=None
        )
        await cmd_ai_baseline(
            mode="compare",
            engine=engine,
            out_path=None,
            baseline_path=baseline_path,
            report_out=report_out,
        )

        data = json.loads(report_out.read_text(encoding="utf-8"))
        required = {
            "baseline_model", "candidate_model", "run_at",
            "scenarios", "changed", "escalations", "deescalations", "diffs",
        }
        for key in required:
            assert key in data, f"Required field '{key}' missing from drift report"

    async def test_compare_no_drift_report_has_empty_diffs(self, tmp_path: Path) -> None:
        """When verdicts are identical, diffs=[] and changed=0 in the report."""
        from firewatch_cli.commands.ai_baseline import cmd_ai_baseline

        engine = _make_mock_engine()
        baseline_path = tmp_path / "baseline.json"
        report_out = tmp_path / "drift_report.json"

        await cmd_ai_baseline(
            mode="save", engine=engine, out_path=baseline_path, baseline_path=None
        )
        exit_code = await cmd_ai_baseline(
            mode="compare",
            engine=engine,
            out_path=None,
            baseline_path=baseline_path,
            report_out=report_out,
        )
        assert exit_code == 0

        data = json.loads(report_out.read_text(encoding="utf-8"))
        assert data["diffs"] == [], "No diffs expected when verdicts are identical"
        assert data["changed"] == 0

    async def test_compare_drift_report_has_correct_diffs(self, tmp_path: Path) -> None:
        """When verdicts change, the diffs list reflects the changed scenarios."""
        from firewatch_cli.commands.ai_baseline import cmd_ai_baseline

        engine_saved = _make_mock_engine(concise_verdict=_VERDICT_CONCISE_A)
        engine_drifted = _make_mock_engine(concise_verdict=_VERDICT_CONCISE_DRIFTED)

        baseline_path = tmp_path / "baseline.json"
        report_out = tmp_path / "drift_report.json"

        await cmd_ai_baseline(
            mode="save", engine=engine_saved, out_path=baseline_path, baseline_path=None
        )
        exit_code = await cmd_ai_baseline(
            mode="compare",
            engine=engine_drifted,
            out_path=None,
            baseline_path=baseline_path,
            report_out=report_out,
        )
        assert exit_code != 0, "Expected nonzero exit when verdicts drifted"

        data = json.loads(report_out.read_text(encoding="utf-8"))
        assert data["changed"] > 0, "changed must be nonzero when drifts detected"
        assert len(data["diffs"]) == data["changed"]

    async def test_compare_report_out_custom_path(self, tmp_path: Path) -> None:
        """A custom --report-out path is honoured."""
        from firewatch_cli.commands.ai_baseline import cmd_ai_baseline

        engine = _make_mock_engine()
        baseline_path = tmp_path / "baseline.json"
        custom_report = tmp_path / "custom" / "my_report.json"

        await cmd_ai_baseline(
            mode="save", engine=engine, out_path=baseline_path, baseline_path=None
        )
        await cmd_ai_baseline(
            mode="compare",
            engine=engine,
            out_path=None,
            baseline_path=baseline_path,
            report_out=custom_report,
        )

        assert custom_report.exists(), (
            "Drift report was not written to the custom path"
        )

    async def test_compare_persist_failure_does_not_change_exit_code(
        self, tmp_path: Path
    ) -> None:
        """If the drift report cannot be written, the exit code is still correct.

        Persistence failures are fail-safe -- they must not turn a zero exit
        code into non-zero or vice versa.
        """
        from firewatch_cli.commands.ai_baseline import cmd_ai_baseline

        engine = _make_mock_engine()
        baseline_path = tmp_path / "baseline.json"
        # Use a path that cannot be created (non-existent parent on a read-only root)
        # We simulate this by patching Path.write_text to raise on the report.
        # Actually, we just use a path inside a file (which can't be a dir parent).
        bad_dir = tmp_path / "not_a_dir.txt"
        bad_dir.write_text("I am a file", encoding="utf-8")
        bad_report = bad_dir / "report.json"  # parent is a file, write will fail

        await cmd_ai_baseline(
            mode="save", engine=engine, out_path=baseline_path, baseline_path=None
        )
        # No drift expected, so exit code should be 0 regardless of persist failure
        exit_code = await cmd_ai_baseline(
            mode="compare",
            engine=engine,
            out_path=None,
            baseline_path=baseline_path,
            report_out=bad_report,
        )
        assert exit_code == 0, (
            "Persist failure must not change exit code (fail-safe)"
        )


# ---------------------------------------------------------------------------
# EARS-4: scenario count matches SCENARIOS registry
# ---------------------------------------------------------------------------


class TestDriftReportScenarioCount:
    async def test_compare_drift_report_scenario_count(self, tmp_path: Path) -> None:
        """scenarios in the report equals the number of entries in SCENARIOS."""
        from firewatch_cli.commands.ai_baseline import cmd_ai_baseline
        from firewatch_core.ai.baseline.fixtures import SCENARIOS

        engine = _make_mock_engine()
        baseline_path = tmp_path / "baseline.json"
        report_out = tmp_path / "drift_report.json"

        await cmd_ai_baseline(
            mode="save", engine=engine, out_path=baseline_path, baseline_path=None
        )
        await cmd_ai_baseline(
            mode="compare",
            engine=engine,
            out_path=None,
            baseline_path=baseline_path,
            report_out=report_out,
        )

        data = json.loads(report_out.read_text(encoding="utf-8"))
        assert data["scenarios"] == len(SCENARIOS), (
            f"Expected {len(SCENARIOS)} scenarios in report; got {data['scenarios']}"
        )
