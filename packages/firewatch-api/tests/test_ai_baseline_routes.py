"""Tests for GET /ai/baseline and GET /ai/baseline/drift (MK-8 / issue #413).

EARS criterion -> test(s) mapping
----------------------------------
EARS-2  GET /ai/baseline SHALL return baseline status.
        test_get_baseline_status_exists
        test_get_baseline_status_not_found
        test_get_baseline_status_corrupt_file_returns_not_found

EARS-3  GET /ai/baseline/drift SHALL return the latest report or 404.
        test_get_drift_report_returns_latest
        test_get_drift_report_not_found
        test_get_drift_report_corrupt_file_returns_422
        test_get_drift_report_oversized_returns_422
        test_get_drift_report_missing_key_returns_422

Round-trip:
        test_persist_read_roundtrip

Security: no real IPs; RFC 5737 only.
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


def _make_client(
    baseline_path: Path | None = None,
    drift_report_path: Path | None = None,
) -> TestClient:
    """Build a test client with optional file paths injected."""
    app = create_app(
        registry={},
        config_store=_FakeConfigStore(),
        baseline_path=baseline_path,
        drift_report_path=drift_report_path,
    )
    return TestClient(app)


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


def _valid_drift_report() -> dict[str, Any]:
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


def _valid_baseline() -> dict[str, Any]:
    """Minimal baseline file: {category: verdict_dict}."""
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
# EARS-2: GET /ai/baseline
# ---------------------------------------------------------------------------


class TestGetBaselineStatus:
    def test_get_baseline_status_exists(self, tmp_path: Path) -> None:
        """GET /ai/baseline returns exists=True when a baseline file is present."""
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(
            json.dumps(_valid_baseline()), encoding="utf-8"
        )

        client = _make_client(baseline_path=baseline_path)
        resp = client.get("/ai/baseline")

        assert resp.status_code == 200
        data = resp.json()
        assert data["exists"] is True
        assert "scenario_count" in data
        assert data["scenario_count"] == 2

    def test_get_baseline_status_not_found(self, tmp_path: Path) -> None:
        """GET /ai/baseline returns exists=False when no baseline file exists."""
        missing = tmp_path / "no_such_file.json"
        client = _make_client(baseline_path=missing)

        resp = client.get("/ai/baseline")

        assert resp.status_code == 200
        data = resp.json()
        assert data["exists"] is False

    def test_get_baseline_status_corrupt_file_returns_not_found(
        self, tmp_path: Path
    ) -> None:
        """GET /ai/baseline returns exists=False gracefully for a corrupt file."""
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_bytes(b"not valid json {{{")

        client = _make_client(baseline_path=baseline_path)
        resp = client.get("/ai/baseline")

        assert resp.status_code == 200
        data = resp.json()
        # Graceful degradation: corrupt file -> exists=False (not a 500)
        assert data["exists"] is False

    def test_get_baseline_status_model_and_saved_at_null(
        self, tmp_path: Path
    ) -> None:
        """model and saved_at are null -- they are not stored in the baseline format."""
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(json.dumps(_valid_baseline()), encoding="utf-8")

        client = _make_client(baseline_path=baseline_path)
        resp = client.get("/ai/baseline")

        assert resp.status_code == 200
        data = resp.json()
        assert data["model"] is None
        assert data["saved_at"] is None


# ---------------------------------------------------------------------------
# EARS-3: GET /ai/baseline/drift
# ---------------------------------------------------------------------------


class TestGetDriftReport:
    def test_get_drift_report_returns_latest(self, tmp_path: Path) -> None:
        """GET /ai/baseline/drift returns the latest drift report when it exists."""
        drift_path = tmp_path / "drift_report.json"
        report = _valid_drift_report()
        drift_path.write_text(json.dumps(report), encoding="utf-8")

        client = _make_client(drift_report_path=drift_path)
        resp = client.get("/ai/baseline/drift")

        assert resp.status_code == 200
        data = resp.json()
        assert data["baseline_model"] == "llama3.2"
        assert data["candidate_model"] == "qwen3:14b"
        assert data["scenarios"] == 8
        assert data["diffs"] == []

    def test_get_drift_report_not_found(self, tmp_path: Path) -> None:
        """GET /ai/baseline/drift returns 404 when no comparison has been run."""
        missing = tmp_path / "no_drift_report.json"
        client = _make_client(drift_report_path=missing)

        resp = client.get("/ai/baseline/drift")

        assert resp.status_code == 404
        assert "no drift comparison" in resp.json()["detail"].lower() or (
            "no drift" in resp.json()["detail"].lower()
        )

    def test_get_drift_report_corrupt_file_returns_422(
        self, tmp_path: Path
    ) -> None:
        """GET /ai/baseline/drift returns 422 for a corrupt file."""
        drift_path = tmp_path / "drift_report.json"
        drift_path.write_bytes(b"totally not json")

        client = _make_client(drift_report_path=drift_path)
        resp = client.get("/ai/baseline/drift")

        assert resp.status_code == 422

    def test_get_drift_report_oversized_returns_422(self, tmp_path: Path) -> None:
        """GET /ai/baseline/drift returns 422 for an oversized file."""
        from firewatch_core.ai.baseline.drift_report import MAX_REPORT_BYTES

        drift_path = tmp_path / "drift_report.json"
        # Write more bytes than the cap allows
        drift_path.write_bytes(b"x" * (MAX_REPORT_BYTES + 1))

        client = _make_client(drift_report_path=drift_path)
        resp = client.get("/ai/baseline/drift")

        assert resp.status_code == 422

    def test_get_drift_report_missing_key_returns_422(self, tmp_path: Path) -> None:
        """GET /ai/baseline/drift returns 422 when the report is missing required keys."""
        drift_path = tmp_path / "drift_report.json"
        # Omit the 'diffs' key
        bad = {
            "baseline_model": "llama3.2",
            "candidate_model": "qwen3:14b",
        }
        drift_path.write_text(json.dumps(bad), encoding="utf-8")

        client = _make_client(drift_report_path=drift_path)
        resp = client.get("/ai/baseline/drift")

        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Round-trip: persist via CLI shape, read via API
# ---------------------------------------------------------------------------


class TestPersistReadRoundtrip:
    def test_persist_read_roundtrip(self, tmp_path: Path) -> None:
        """A report built by drift_report.build_drift_report is readable by the API."""
        from firewatch_core.ai.baseline.drift_report import build_drift_report
        from firewatch_core.ai.baseline.report import VerdictDrift

        drift = VerdictDrift(
            category="concise_waf_no_corr",
            field_drifts=[("threat_level", "HIGH", "MEDIUM")],
            saved={"threat_level": "HIGH", "recommended_action": "block",
                   "attack_stage": "exploitation", "confidence": 0.85},
            current={"threat_level": "MEDIUM", "recommended_action": "monitor",
                     "attack_stage": "reconnaissance", "confidence": 0.6},
        )
        baseline = {"concise_waf_no_corr": drift.saved}
        candidate = {"concise_waf_no_corr": drift.current}

        report = build_drift_report(
            drifts=[drift],
            baseline_verdicts=baseline,
            candidate_verdicts=candidate,
            baseline_model="llama3.2",
            candidate_model="qwen3:14b",
        )

        drift_path = tmp_path / "drift_report.json"
        drift_path.write_text(json.dumps(report), encoding="utf-8")

        client = _make_client(drift_report_path=drift_path)
        resp = client.get("/ai/baseline/drift")

        assert resp.status_code == 200
        data = resp.json()
        assert data["changed"] == 1
        assert len(data["diffs"]) == 1
        diff = data["diffs"][0]
        assert diff["scenario"] == "concise_waf_no_corr"
        assert diff["baseline_verdict"] == "HIGH"
        assert diff["candidate_verdict"] == "MEDIUM"
