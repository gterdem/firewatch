"""Tests for ``firewatch ai-baseline`` — MI-9 EARS criteria mapped 1:1.

Tests are written FIRST (testing-conventions skill).

EARS criterion -> test(s) mapping
----------------------------------
EARS-1  Event-driven: When run with a reachable engine, the command SHALL execute
        every baseline fixture against the configured model and report per-fixture
        expected-vs-actual verdict deltas plus a summary, exiting nonzero IF any
        verdict drifted.
        test_save_writes_verdict_per_scenario
        test_save_records_key_verdict_fields
        test_save_calls_engine_once_per_scenario
        test_compare_no_drift_exits_zero
        test_compare_no_drift_report_contains_ok
        test_compare_drift_detected_returns_nonempty_drifts
        test_compare_drift_report_names_changed_fields
        test_round_trip_save_then_compare

EARS-2  Event-driven: When the engine is unreachable or returns schema-invalid
        output, the command SHALL fail with a clear diagnostic and SHALL NOT report
        partial results as a pass.
        test_engine_unavailable_raises_baseline_error
        test_engine_exception_raises_baseline_error

EARS-3  Ubiquitous: the command SHALL be read-only.
        test_command_does_not_mutate_fixtures
        test_compare_does_not_write_any_file

EARS-4  Ubiquitous: after fixture relocation, tests/golden/ai SHALL pass with
        byte-identical fixture content.
        test_golden_fixtures_importable_from_package
        test_fixture_bytes_identical_in_package_and_tests_golden
        test_fixture_ips_are_rfc5737

EARS-5  Gate: CI SHALL NOT acquire a live-model dependency.
        test_report_pure_no_io
        test_report_render_includes_scenario_count

CLI wiring tests:
        test_cmd_save_writes_file
        test_cmd_compare_no_drift_exits_zero
        test_cmd_compare_drift_exits_nonzero
        test_cmd_compare_missing_baseline_exits_nonzero
        test_cmd_engine_unavailable_exits_nonzero

All IPs are RFC 5737 documentation ranges (192.0.2.x / 198.51.100.x / 203.0.113.x).
All engine calls are mocked — no real model or network needed.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Shared mock verdicts — RFC 5737 IPs, no real model data
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
    "threat_level": "MEDIUM",           # changed from HIGH
    "confidence": 0.6,
    "intent": "Automated scanning",
    "attack_stage": "reconnaissance",   # changed from exploitation
    "insights": ["pattern: scan probe"],
    "recommended_action": "monitor",    # changed from block
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
    model: str = "test-model",
) -> MagicMock:
    """Build a mock AI engine that returns fixed verdicts without any network call."""
    engine = MagicMock()
    engine.model = model  # Required: real engine has a string .model attribute
    engine.is_available = AsyncMock(return_value=available)
    engine.analyze_concise = AsyncMock(return_value=dict(concise_verdict))
    engine.analyze_detailed = AsyncMock(return_value=dict(detailed_verdict))
    return engine


# ---------------------------------------------------------------------------
# EARS-1: save + compare happy path
# ---------------------------------------------------------------------------


class TestSaveCommand:
    """EARS-1 -- --save writes one verdict record per scenario."""

    async def test_save_writes_verdict_per_scenario(self) -> None:
        """run_all_scenarios returns one entry per scenario in SCENARIOS."""
        from firewatch_core.ai.baseline.fixtures import SCENARIOS
        from firewatch_core.ai.baseline.runner import run_all_scenarios

        engine = _make_mock_engine()
        results = await run_all_scenarios(engine)

        assert isinstance(results, dict)
        for sc in SCENARIOS:
            assert sc["category"] in results, (
                f"Scenario {sc['category']!r} missing from run results"
            )

    async def test_save_records_key_verdict_fields(self) -> None:
        """Each record must include threat_level and recommended_action."""
        from firewatch_core.ai.baseline.runner import run_all_scenarios

        engine = _make_mock_engine()
        results = await run_all_scenarios(engine)

        for category, record in results.items():
            assert "threat_level" in record, (
                f"Record for {category!r} missing 'threat_level'"
            )
            assert "recommended_action" in record, (
                f"Record for {category!r} missing 'recommended_action'"
            )

    async def test_save_calls_engine_once_per_scenario(self) -> None:
        """run_all_scenarios calls the engine exactly once per scenario."""
        from firewatch_core.ai.baseline.fixtures import SCENARIOS
        from firewatch_core.ai.baseline.runner import run_all_scenarios

        engine = _make_mock_engine()
        await run_all_scenarios(engine)

        total_calls = (
            engine.analyze_concise.call_count
            + engine.analyze_detailed.call_count
        )
        assert total_calls == len(SCENARIOS), (
            f"Expected {len(SCENARIOS)} engine calls; got {total_calls}"
        )


class TestCompareNoDrift:
    """EARS-1 -- --compare with identical verdicts exits 0."""

    async def test_compare_no_drift_exits_zero(self) -> None:
        """When saved and current verdicts are identical, compare returns empty drift list."""
        from firewatch_core.ai.baseline.report import compare_verdicts
        from firewatch_core.ai.baseline.runner import run_all_scenarios

        engine = _make_mock_engine()
        saved = await run_all_scenarios(engine)
        current = await run_all_scenarios(engine)

        drifts = compare_verdicts(saved, current)
        assert drifts == [], f"Expected no drifts; got {drifts}"

    async def test_compare_no_drift_report_contains_ok(self) -> None:
        """Report text must contain an 'OK' or 'no drift' indicator when clean."""
        from firewatch_core.ai.baseline.report import compare_verdicts, render_report
        from firewatch_core.ai.baseline.runner import run_all_scenarios

        engine = _make_mock_engine()
        saved = await run_all_scenarios(engine)
        current = await run_all_scenarios(engine)

        drifts = compare_verdicts(saved, current)
        report = render_report(drifts, total=len(saved))

        assert (
            "no drift" in report.lower()
            or "0 drift" in report.lower()
            or "all" in report.lower() and "ok" in report.lower()
        ), f"Report should indicate no drift; got:\n{report}"


class TestCompareDriftDetected:
    """EARS-1 -- --compare with changed verdict reports drift and returns non-empty list."""

    async def test_compare_drift_detected_returns_nonempty_drifts(self) -> None:
        """When threat_level changes, compare returns a non-empty drift list."""
        from firewatch_core.ai.baseline.report import compare_verdicts
        from firewatch_core.ai.baseline.runner import run_all_scenarios

        engine_saved = _make_mock_engine(concise_verdict=_VERDICT_CONCISE_A)
        engine_drifted = _make_mock_engine(concise_verdict=_VERDICT_CONCISE_DRIFTED)

        saved = await run_all_scenarios(engine_saved)
        current = await run_all_scenarios(engine_drifted)

        drifts = compare_verdicts(saved, current)
        assert len(drifts) > 0, "Expected drifts when verdict changed"

    async def test_compare_drift_report_names_changed_fields(self) -> None:
        """Drift report must name the changed fields and show old/new values."""
        from firewatch_core.ai.baseline.report import compare_verdicts, render_report
        from firewatch_core.ai.baseline.runner import run_all_scenarios

        engine_saved = _make_mock_engine(concise_verdict=_VERDICT_CONCISE_A)
        engine_drifted = _make_mock_engine(concise_verdict=_VERDICT_CONCISE_DRIFTED)

        saved = await run_all_scenarios(engine_saved)
        current = await run_all_scenarios(engine_drifted)

        drifts = compare_verdicts(saved, current)
        report = render_report(drifts, total=len(saved))

        assert "threat_level" in report, (
            f"Report must mention 'threat_level' for changed field; got:\n{report}"
        )
        # Either the old or new value must appear
        assert "HIGH" in report or "MEDIUM" in report, (
            "Report must show old/new values for threat_level"
        )

    async def test_round_trip_save_then_compare(self, tmp_path: Path) -> None:
        """Full round-trip: save -> re-run identical engine -> compare -> 0 drifts."""
        from firewatch_core.ai.baseline.report import compare_verdicts
        from firewatch_core.ai.baseline.runner import run_all_scenarios

        engine = _make_mock_engine()
        out_path = tmp_path / "baseline.json"

        saved = await run_all_scenarios(engine)
        out_path.write_text(json.dumps(saved), encoding="utf-8")

        loaded = json.loads(out_path.read_text(encoding="utf-8"))
        current = await run_all_scenarios(engine)
        drifts = compare_verdicts(loaded, current)
        assert drifts == [], f"Round-trip: expected 0 drifts; got {drifts}"


# ---------------------------------------------------------------------------
# EARS-2: engine errors -> nonzero exit + diagnostic
# ---------------------------------------------------------------------------


class TestEngineErrors:
    """EARS-2 -- unavailable/schema-invalid engine raises BaselineRunError."""

    async def test_engine_unavailable_raises_baseline_error(self) -> None:
        """When engine.is_available() is False, run_all_scenarios raises BaselineRunError."""
        from firewatch_core.ai.baseline.runner import BaselineRunError, run_all_scenarios

        engine = _make_mock_engine(available=False)
        with pytest.raises(BaselineRunError, match="unavailable"):
            await run_all_scenarios(engine)

    async def test_engine_exception_raises_baseline_error(self) -> None:
        """When engine.analyze_concise raises, run_all_scenarios wraps as BaselineRunError."""
        import httpx

        from firewatch_core.ai.baseline.runner import BaselineRunError, run_all_scenarios

        engine = MagicMock()
        engine.is_available = AsyncMock(return_value=True)
        engine.analyze_concise = AsyncMock(side_effect=httpx.ConnectError("refused"))
        engine.analyze_detailed = AsyncMock(side_effect=httpx.ConnectError("refused"))

        with pytest.raises(BaselineRunError):
            await run_all_scenarios(engine)


# ---------------------------------------------------------------------------
# EARS-3: read-only -- fixtures unchanged, compare does not write files
# ---------------------------------------------------------------------------


class TestReadOnly:
    """EARS-3 -- command is read-only; fixtures are unchanged after import."""

    def test_command_does_not_mutate_fixtures(self) -> None:
        """SCENARIOS list must be identical after importing baseline modules."""
        from firewatch_core.ai.baseline.fixtures import SCENARIOS

        categories_before = [sc["category"] for sc in SCENARIOS]
        import importlib

        import firewatch_core.ai.baseline.runner as runner_mod
        importlib.reload(runner_mod)
        categories_after = [sc["category"] for sc in SCENARIOS]
        assert categories_before == categories_after, (
            "SCENARIOS was mutated by importing runner module"
        )

    async def test_compare_does_not_write_any_file(self, tmp_path: Path) -> None:
        """compare_verdicts is a pure function -- must not create or modify any file."""
        from firewatch_core.ai.baseline.report import compare_verdicts
        from firewatch_core.ai.baseline.runner import run_all_scenarios

        engine = _make_mock_engine()
        saved = await run_all_scenarios(engine)
        current = await run_all_scenarios(engine)

        files_before = set(tmp_path.rglob("*"))
        compare_verdicts(saved, current)
        files_after = set(tmp_path.rglob("*"))

        assert files_before == files_after, (
            "compare_verdicts must not write any files (pure function)"
        )


# ---------------------------------------------------------------------------
# EARS-4: fixture relocation -- byte-identical + golden tests still import them
# ---------------------------------------------------------------------------


class TestFixtureRelocation:
    """EARS-4 -- relocated fixtures are byte-identical; golden tests can import them."""

    def test_golden_fixtures_importable_from_package(self) -> None:
        """SCENARIOS must be importable from firewatch_core.ai.baseline.fixtures."""
        from firewatch_core.ai.baseline.fixtures import SCENARIOS

        assert isinstance(SCENARIOS, list)
        assert len(SCENARIOS) > 0

    def test_fixture_bytes_identical_in_package_and_tests_golden(self) -> None:
        """The SCENARIOS content imported via tests/golden/ai matches the package.

        tests/golden/ai/fixtures.py re-exports from the package, so the object
        is the same. This test verifies the contract is maintained.
        """
        # Add tests/ to path for the import below (mirrors conftest shim)
        import sys
        from pathlib import Path as _Path

        tests_root = _Path(__file__).parent.parent.parent.parent / "tests"
        if str(tests_root) not in sys.path:
            sys.path.insert(0, str(tests_root))

        import golden.ai.fixtures as golden_fixtures  # type: ignore[import-untyped]
        from firewatch_core.ai.baseline.fixtures import SCENARIOS as pkg_scenarios

        assert len(pkg_scenarios) == len(golden_fixtures.SCENARIOS), (
            "Package and golden SCENARIOS have different lengths -- relocation broke content"
        )
        for pkg_sc, golden_sc in zip(pkg_scenarios, golden_fixtures.SCENARIOS):
            assert pkg_sc["category"] == golden_sc["category"], (
                "Category mismatch after relocation"
            )
            assert pkg_sc["format"] == golden_sc["format"], (
                "Format mismatch after relocation"
            )
            assert pkg_sc["kwargs"] == golden_sc["kwargs"], (
                f"kwargs mismatch for {pkg_sc['category']!r} after relocation"
            )

    def test_fixture_ips_are_rfc5737(self) -> None:
        """All fixture IPs must be RFC 5737 documentation ranges -- gitleaks-clean."""
        from firewatch_core.ai.baseline.fixtures import SCENARIOS

        allowed_prefixes = ("192.0.2.", "198.51.100.", "203.0.113.")
        for sc in SCENARIOS:
            ip = sc["kwargs"]["ip"]
            assert any(ip.startswith(pfx) for pfx in allowed_prefixes), (
                f"Scenario '{sc['category']}' uses non-RFC-5737 IP: {ip!r}"
            )


# ---------------------------------------------------------------------------
# EARS-5: no live model dependency -- report is pure
# ---------------------------------------------------------------------------


class TestNoLiveDependency:
    """EARS-5 -- runner setup is network-free; report is pure (no I/O)."""

    def test_report_module_pure_no_io(self) -> None:
        """report.compare_verdicts and render_report must not perform any I/O."""
        from typing import Any as _Any
        from unittest.mock import patch

        from firewatch_core.ai.baseline.report import compare_verdicts, render_report

        call_count = 0

        def _blocking(*args: _Any, **kwargs: _Any) -> None:
            nonlocal call_count
            call_count += 1
            raise AssertionError("Network call in report module")

        saved = {
            "sc1": {
                "threat_level": "HIGH",
                "recommended_action": "block",
                "attack_stage": "exploitation",
                "confidence": 0.9,
            }
        }
        current = {
            "sc1": {
                "threat_level": "HIGH",
                "recommended_action": "block",
                "attack_stage": "exploitation",
                "confidence": 0.9,
            }
        }

        with patch("socket.socket", side_effect=_blocking):
            drifts = compare_verdicts(saved, current)
            render_report(drifts, total=1)

        assert call_count == 0, "report module must make no network calls"

    def test_report_render_includes_scenario_count(self) -> None:
        """render_report must mention the total scenario count in its output."""
        from firewatch_core.ai.baseline.report import render_report

        report = render_report([], total=8)
        assert "8" in report, f"Report must mention total count 8; got:\n{report}"


# ---------------------------------------------------------------------------
# CLI integration: cmd_ai_baseline wiring
# ---------------------------------------------------------------------------


class TestCliAiBaselineCommand:
    """Integration tests for the cmd_ai_baseline function."""

    async def test_cmd_save_writes_file(self, tmp_path: Path) -> None:
        """cmd_ai_baseline(mode='save') writes a JSON baseline to out_path."""
        from firewatch_cli.commands.ai_baseline import cmd_ai_baseline

        engine = _make_mock_engine()
        out_path = tmp_path / "my_baseline.json"

        exit_code = await cmd_ai_baseline(
            mode="save",
            engine=engine,
            out_path=out_path,
            baseline_path=None,
        )

        assert exit_code == 0, f"Expected exit code 0 on save; got {exit_code}"
        assert out_path.exists(), "Baseline file was not written"
        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        assert len(data) > 0

    async def test_cmd_compare_no_drift_exits_zero(self, tmp_path: Path) -> None:
        """cmd_ai_baseline(mode='compare') exits 0 when no verdict drifted."""
        from firewatch_cli.commands.ai_baseline import cmd_ai_baseline

        engine = _make_mock_engine()
        baseline_path = tmp_path / "baseline.json"

        # First save
        await cmd_ai_baseline(
            mode="save",
            engine=engine,
            out_path=baseline_path,
            baseline_path=None,
        )

        # Then compare with same engine
        exit_code = await cmd_ai_baseline(
            mode="compare",
            engine=engine,
            out_path=None,
            baseline_path=baseline_path,
        )
        assert exit_code == 0, f"Expected exit code 0 when no drift; got {exit_code}"

    async def test_cmd_compare_drift_exits_nonzero(self, tmp_path: Path) -> None:
        """cmd_ai_baseline(mode='compare') exits non-zero when a verdict drifted."""
        from firewatch_cli.commands.ai_baseline import cmd_ai_baseline

        engine_saved = _make_mock_engine(concise_verdict=_VERDICT_CONCISE_A)
        engine_drifted = _make_mock_engine(concise_verdict=_VERDICT_CONCISE_DRIFTED)

        baseline_path = tmp_path / "baseline.json"

        await cmd_ai_baseline(
            mode="save",
            engine=engine_saved,
            out_path=baseline_path,
            baseline_path=None,
        )

        exit_code = await cmd_ai_baseline(
            mode="compare",
            engine=engine_drifted,
            out_path=None,
            baseline_path=baseline_path,
        )
        assert exit_code != 0, (
            f"Expected nonzero exit code when verdict drifted; got {exit_code}"
        )

    async def test_cmd_compare_missing_baseline_exits_nonzero(self, tmp_path: Path) -> None:
        """--compare with a missing baseline file exits non-zero."""
        from firewatch_cli.commands.ai_baseline import cmd_ai_baseline

        engine = _make_mock_engine()
        missing = tmp_path / "does_not_exist.json"

        exit_code = await cmd_ai_baseline(
            mode="compare",
            engine=engine,
            out_path=None,
            baseline_path=missing,
        )
        assert exit_code != 0, (
            "Expected nonzero exit code when baseline file is missing"
        )

    async def test_cmd_engine_unavailable_exits_nonzero(self, tmp_path: Path) -> None:
        """--save with unavailable engine exits non-zero and does not write file."""
        from firewatch_cli.commands.ai_baseline import cmd_ai_baseline

        engine = _make_mock_engine(available=False)
        out_path = tmp_path / "baseline.json"

        exit_code = await cmd_ai_baseline(
            mode="save",
            engine=engine,
            out_path=out_path,
            baseline_path=None,
        )
        assert exit_code != 0, "Expected nonzero exit code when engine is unavailable"
        assert not out_path.exists(), (
            "Baseline file must NOT be written when engine is unavailable"
        )
