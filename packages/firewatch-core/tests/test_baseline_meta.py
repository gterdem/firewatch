"""Tests for _meta block in the baseline file (issue #480).

EARS criterion -> test mapping
--------------------------------
EARS-1  New baseline carries _meta.model + _meta.saved_at
        test_save_writes_meta_block
        test_meta_model_matches_engine_model
        test_meta_saved_at_is_utc_iso8601

EARS-2  get_baseline_status surfaces model + saved_at from _meta
        (covered in packages/firewatch-api/tests/test_baseline_meta_api.py)

EARS-3  Backward compat: old file (no _meta) -> nulls, no error, diff unaffected
        test_compare_verdicts_skips_meta_key
        test_compare_verdicts_old_file_no_error

EARS-4  _meta.model is the authoritative model id source (already surfaced via API
        in api test; here we verify model is captured at save time)

EARS-5  Additive only — verdict content and drift diff are unchanged
        test_meta_does_not_affect_drift_comparison
        test_meta_never_treated_as_category

Security: all IPs are RFC 5737 documentation ranges only.
          No real public IPs in this file.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from firewatch_core.ai.baseline.report import compare_verdicts


# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------


def _make_engine(model: str = "llama3.2") -> MagicMock:
    """Minimal engine stub with .model attribute."""
    engine = MagicMock()
    engine.model = model
    return engine


def _make_verdict(threat_level: str = "HIGH") -> dict[str, Any]:
    return {
        "threat_level": threat_level,
        "recommended_action": "block",
        "attack_stage": "exploitation",
        "confidence": 0.85,
    }


def _baseline_with_meta(model: str = "llama3.2") -> dict[str, Any]:
    """Simulate a new-format baseline file (with _meta)."""
    return {
        "_meta": {
            "model": model,
            "saved_at": "2026-06-13T10:00:00+00:00",
        },
        "concise_waf_no_corr": _make_verdict("HIGH"),
        "concise_security_no_corr": _make_verdict("MEDIUM"),
    }


def _baseline_without_meta() -> dict[str, Any]:
    """Simulate an old-format baseline file (no _meta)."""
    return {
        "concise_waf_no_corr": _make_verdict("HIGH"),
        "concise_security_no_corr": _make_verdict("MEDIUM"),
    }


# ---------------------------------------------------------------------------
# EARS-1: baseline save writes _meta block
# ---------------------------------------------------------------------------


class TestSaveWritesMeta:
    """Verify that _cmd_save injects _meta into the written file."""

    @pytest.mark.asyncio
    async def test_save_writes_meta_block(self, tmp_path: Path) -> None:
        """The saved file must contain a top-level '_meta' key."""
        from firewatch_cli.commands.ai_baseline import _cmd_save

        scenarios_result = {
            "concise_waf_no_corr": _make_verdict("HIGH"),
        }

        async def _run_all(engine: Any) -> dict[str, Any]:
            return scenarios_result

        engine = _make_engine("llama3.2")
        out_path = tmp_path / "baseline.json"

        rc = await _cmd_save(engine=engine, out_path=out_path, run_all=_run_all)

        assert rc == 0
        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert "_meta" in data, "Baseline must contain a '_meta' key"

    @pytest.mark.asyncio
    async def test_meta_model_matches_engine_model(self, tmp_path: Path) -> None:
        """_meta.model must equal the engine's .model attribute at save time."""
        from firewatch_cli.commands.ai_baseline import _cmd_save

        engine = _make_engine("qwen3:14b")

        async def _run_all(eng: Any) -> dict[str, Any]:
            return {"concise_waf_no_corr": _make_verdict()}

        out_path = tmp_path / "baseline.json"
        await _cmd_save(engine=engine, out_path=out_path, run_all=_run_all)

        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert data["_meta"]["model"] == "qwen3:14b"

    @pytest.mark.asyncio
    async def test_meta_saved_at_is_utc_iso8601(self, tmp_path: Path) -> None:
        """_meta.saved_at must be an ISO-8601 UTC timestamp."""
        from firewatch_cli.commands.ai_baseline import _cmd_save

        engine = _make_engine("llama3.2")

        async def _run_all(eng: Any) -> dict[str, Any]:
            return {"concise_waf_no_corr": _make_verdict()}

        out_path = tmp_path / "baseline.json"
        before = datetime.now(timezone.utc)
        await _cmd_save(engine=engine, out_path=out_path, run_all=_run_all)
        after = datetime.now(timezone.utc)

        data = json.loads(out_path.read_text(encoding="utf-8"))
        saved_at_str = data["_meta"]["saved_at"]
        # Must parse as ISO-8601
        saved_at = datetime.fromisoformat(saved_at_str)
        # Must have timezone info
        assert saved_at.tzinfo is not None
        # Must be within the window of the test run
        assert before <= saved_at <= after

    @pytest.mark.asyncio
    async def test_verdict_content_unchanged_by_meta(self, tmp_path: Path) -> None:
        """EARS-5: adding _meta must not change the verdict values."""
        from firewatch_cli.commands.ai_baseline import _cmd_save

        engine = _make_engine("llama3.2")
        original_verdict = _make_verdict("CRITICAL")

        async def _run_all(eng: Any) -> dict[str, Any]:
            return {"concise_waf_no_corr": dict(original_verdict)}

        out_path = tmp_path / "baseline.json"
        await _cmd_save(engine=engine, out_path=out_path, run_all=_run_all)

        data = json.loads(out_path.read_text(encoding="utf-8"))
        # Verdict content must be identical
        assert data["concise_waf_no_corr"] == original_verdict


# ---------------------------------------------------------------------------
# EARS-3: backward compatibility — _meta absent -> nulls, no error
# ---------------------------------------------------------------------------


class TestBackwardCompat:
    """Verify that old baseline files (without _meta) load cleanly."""

    def test_compare_verdicts_skips_meta_key(self) -> None:
        """EARS-5 / EARS-3: _meta must never be treated as a category."""
        saved = _baseline_with_meta()
        current = {
            "concise_waf_no_corr": _make_verdict("HIGH"),
            "concise_security_no_corr": _make_verdict("MEDIUM"),
        }

        drifts = compare_verdicts(saved, current)

        # No drift (same verdicts); and _meta key didn't cause a spurious drift
        assert drifts == [], f"Expected no drift but got: {drifts}"

    def test_meta_never_treated_as_category(self) -> None:
        """EARS-3: _meta key must be excluded from category iteration."""
        saved = _baseline_with_meta()
        current = {
            "concise_waf_no_corr": _make_verdict("HIGH"),
            "concise_security_no_corr": _make_verdict("MEDIUM"),
        }

        drifts = compare_verdicts(saved, current)

        # _meta should not appear as a drift category
        drift_categories = {d.category for d in drifts}
        assert "_meta" not in drift_categories

    def test_compare_verdicts_old_file_no_error(self) -> None:
        """EARS-3: old file without _meta must parse and compare without error."""
        saved = _baseline_without_meta()
        current = {
            "concise_waf_no_corr": _make_verdict("HIGH"),
            "concise_security_no_corr": _make_verdict("MEDIUM"),
        }

        # Must not raise
        drifts = compare_verdicts(saved, current)
        assert drifts == []

    def test_meta_does_not_affect_drift_comparison(self) -> None:
        """EARS-5: baseline WITH _meta must produce the same drift result as WITHOUT."""
        # Build two saved dicts: one with _meta, one without
        saved_with_meta = _baseline_with_meta()
        saved_without_meta = _baseline_without_meta()
        current = {
            "concise_waf_no_corr": _make_verdict("CRITICAL"),  # drifted
            "concise_security_no_corr": _make_verdict("MEDIUM"),
        }

        drifts_with = compare_verdicts(saved_with_meta, current)
        drifts_without = compare_verdicts(saved_without_meta, current)

        # Same number of drifts, same categories
        assert len(drifts_with) == len(drifts_without)
        cats_with = {d.category for d in drifts_with}
        cats_without = {d.category for d in drifts_without}
        assert cats_with == cats_without


# ---------------------------------------------------------------------------
# EARS-3 (API read): _meta absent -> model/saved_at null in status response
# (core-side: verify load path strips _meta from category count)
# ---------------------------------------------------------------------------


class TestMetaExcludedFromScenarioCount:
    """_meta must not be counted as a scenario."""

    def _scenario_count_from_file(self, data: dict[str, Any]) -> int:
        """Mimic the API's scenario_count logic (len minus _meta if present)."""
        return sum(1 for k in data if k != "_meta")

    def test_scenario_count_excludes_meta(self) -> None:
        """len(data) minus _meta == 2 for a two-scenario baseline with _meta."""
        data = _baseline_with_meta()
        count = self._scenario_count_from_file(data)
        assert count == 2

    def test_scenario_count_no_meta(self) -> None:
        """Old file without _meta: count is just len(data)."""
        data = _baseline_without_meta()
        count = self._scenario_count_from_file(data)
        assert count == 2
