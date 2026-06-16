"""API tests for _meta block surfacing in GET /ai/baseline (issue #480).

EARS criterion -> test mapping
--------------------------------
EARS-2  GET /ai/baseline surfaces model + saved_at from _meta block
        test_get_baseline_status_surfaces_meta_model
        test_get_baseline_status_surfaces_meta_saved_at

EARS-3  Old baseline (no _meta) -> model/saved_at null, no error
        test_get_baseline_status_no_meta_returns_nulls

EARS-5  _meta is excluded from scenario_count
        test_scenario_count_excludes_meta_key

Security: no real public IPs; RFC 5737 only.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from firewatch_api.app import create_app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeConfigStore:
    def get_runtime(self) -> Any:
        from firewatch_sdk import RuntimeConfig
        return RuntimeConfig.model_validate({})

    def set_runtime(self, updates: Any) -> None:
        pass

    def get_source(self, source_type: str, schema: Any) -> Any:
        return schema.model_validate({})

    def set_source(self, *args: Any, **kwargs: Any) -> None:
        pass


def _make_client(baseline_path: Path) -> TestClient:
    app = create_app(
        registry={},
        config_store=_FakeConfigStore(),
        baseline_path=baseline_path,
    )
    return TestClient(app)


def _baseline_with_meta(model: str = "llama3.2") -> dict[str, Any]:
    """New-format baseline with _meta block."""
    return {
        "_meta": {
            "model": model,
            "saved_at": "2026-06-13T10:00:00+00:00",
        },
        "concise_waf_no_corr": {
            "threat_level": "HIGH",
            "recommended_action": "block",
            "attack_stage": "exploitation",
            "confidence": 0.85,
        },
        "concise_security_no_corr": {
            "threat_level": "MEDIUM",
            "recommended_action": "monitor",
            "attack_stage": "reconnaissance",
            "confidence": 0.6,
        },
    }


def _baseline_without_meta() -> dict[str, Any]:
    """Old-format baseline without _meta block."""
    return {
        "concise_waf_no_corr": {
            "threat_level": "HIGH",
            "recommended_action": "block",
            "attack_stage": "exploitation",
            "confidence": 0.85,
        },
        "concise_security_no_corr": {
            "threat_level": "MEDIUM",
            "recommended_action": "monitor",
            "attack_stage": "reconnaissance",
            "confidence": 0.6,
        },
    }


# ---------------------------------------------------------------------------
# EARS-2: GET /ai/baseline surfaces _meta fields
# ---------------------------------------------------------------------------


class TestGetBaselineStatusMeta:
    def test_get_baseline_status_surfaces_meta_model(self, tmp_path: Path) -> None:
        """EARS-2: model is read from _meta.model when present."""
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(
            json.dumps(_baseline_with_meta("qwen3:14b")), encoding="utf-8"
        )

        client = _make_client(baseline_path)
        resp = client.get("/ai/baseline")

        assert resp.status_code == 200
        data = resp.json()
        assert data["exists"] is True
        assert data["model"] == "qwen3:14b"

    def test_get_baseline_status_surfaces_meta_saved_at(self, tmp_path: Path) -> None:
        """EARS-2: saved_at is read from _meta.saved_at when present."""
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(
            json.dumps(_baseline_with_meta()), encoding="utf-8"
        )

        client = _make_client(baseline_path)
        resp = client.get("/ai/baseline")

        assert resp.status_code == 200
        data = resp.json()
        assert data["saved_at"] == "2026-06-13T10:00:00+00:00"

    def test_get_baseline_status_no_meta_returns_nulls(self, tmp_path: Path) -> None:
        """EARS-3: old baseline without _meta -> model=null, saved_at=null, no error."""
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(
            json.dumps(_baseline_without_meta()), encoding="utf-8"
        )

        client = _make_client(baseline_path)
        resp = client.get("/ai/baseline")

        assert resp.status_code == 200
        data = resp.json()
        assert data["exists"] is True
        assert data["model"] is None
        assert data["saved_at"] is None

    def test_scenario_count_excludes_meta_key(self, tmp_path: Path) -> None:
        """EARS-5: _meta does not inflate scenario_count."""
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(
            json.dumps(_baseline_with_meta()), encoding="utf-8"
        )

        client = _make_client(baseline_path)
        resp = client.get("/ai/baseline")

        assert resp.status_code == 200
        data = resp.json()
        # 2 real scenarios; _meta must not be counted
        assert data["scenario_count"] == 2
