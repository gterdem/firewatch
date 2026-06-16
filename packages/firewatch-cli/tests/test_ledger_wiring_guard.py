"""Guard test — MK-2 dead-wiring regression (issue #407).

This test asserts the REAL factory/startup wiring — NOT a hand-built ledger.

EARS criteria -> test mapping
===============================

G1  WHEN _build_pipeline() is called, the returned pipeline SHALL have a
    non-None ledger (the ledger is constructed in the factory).
    -> test_factory_pipeline_has_non_none_ledger

G2  WHEN an analysis flows through a factory-built pipeline (init + analyze_ip),
    a row SHALL be persisted in the ledger database AND
    GET /ai/analyses on an app wired the production way SHALL return it.
    -> test_factory_wired_analysis_persists_and_api_returns_it

Both tests MUST FAIL on the current (unwired) code and PASS after the fix.

Security: RFC 5737 documentation IPs only (192.0.2.0/24).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from firewatch_api.app import create_app
from firewatch_core.adapters.ledger.sqlite_ledger import SqliteAnalysisLedger
from firewatch_core.adapters.sqlite_store import SQLiteEventStore
from firewatch_core.pipeline import Pipeline
from firewatch_sdk import SecurityEvent

# RFC 5737 documentation IPs.
IP_A = "192.0.2.55"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_runtime(*, ai_enabled: bool = False) -> Any:
    """Build a minimal RuntimeConfig mock for _build_pipeline."""
    return MagicMock(
        ai_enabled=ai_enabled,
        ollama_base_url="http://127.0.0.1:11434",
        ollama_model="qwen3:8b",
        geo_provider="offline",
    )


class _FakeAIEngine:
    """Minimal fake engine that returns a validated (non-unavailable) AI result."""

    model = "test-model"
    base_url = "http://127.0.0.1:11434"

    async def is_available(self) -> bool:
        return True

    async def analyze_concise(self, **_kwargs: Any) -> dict[str, Any]:
        return {
            "ai_status": "ok",
            "threat_level": "LOW",
            "confidence": 0.5,
            "insights": [],
        }

    async def analyze_detailed(self, **_kwargs: Any) -> dict[str, Any]:
        return {
            "ai_status": "ok",
            "threat_level": "LOW",
            "confidence": 0.5,
        }


# ---------------------------------------------------------------------------
# G1 — _build_pipeline() returns a Pipeline with a non-None ledger
# ---------------------------------------------------------------------------


class TestFactoryPipelineHasLedger:
    """G1: The pipeline returned by _build_pipeline MUST have a non-None ledger.

    This test FAILS on the current code (no ledger= passed to Pipeline)
    and PASSES after the fix.
    """

    def test_factory_pipeline_has_non_none_ledger(self, tmp_path: Path) -> None:
        """_build_pipeline must wire a SqliteAnalysisLedger into Pipeline.ledger."""
        from firewatch_cli.commands._pipeline_factory import _build_pipeline

        with (
            patch(
                "firewatch_cli.commands._pipeline_factory.JsonFileConfigStore"
            ) as mock_cfg_store,
            patch(
                "firewatch_cli.commands._pipeline_factory.SQLiteEventStore"
            ) as mock_store,
        ):
            mock_cfg_store.return_value.get_runtime.return_value = _make_mock_runtime(
                ai_enabled=False
            )
            mock_store.return_value = MagicMock()

            raw = _build_pipeline(config_file=tmp_path / "fw.json")

        # _build_pipeline declares return type as object to decouple callers;
        # cast to Pipeline for attribute access in this test.
        pipeline = cast(Pipeline, raw)

        assert pipeline.ledger is not None, (
            "Pipeline.ledger must be a SqliteAnalysisLedger instance, not None. "
            "Fix: construct SqliteAnalysisLedger in _build_pipeline and pass it "
            "as ledger= to Pipeline(...)."
        )
        assert isinstance(pipeline.ledger, SqliteAnalysisLedger), (
            f"Expected SqliteAnalysisLedger, got {type(pipeline.ledger).__name__}. "
            "_build_pipeline must construct and wire a SqliteAnalysisLedger."
        )


# ---------------------------------------------------------------------------
# G2 — factory-built pipeline: analysis persists AND GET /ai/analyses returns it
# ---------------------------------------------------------------------------


class TestFactoryWiredAnalysisEndToEnd:
    """G2: Full wiring regression guard.

    Drives an analysis through a factory-built pipeline (with real SQLiteEventStore
    and SqliteAnalysisLedger on a tmp DB), then asserts a row is in the ledger and
    GET /ai/analyses returns it.

    This test FAILS on the current code (no ledger wired) and PASSES after the fix.
    """

    def test_factory_wired_analysis_persists_and_api_returns_it(
        self, tmp_path: Path
    ) -> None:
        """After analyze_ip on a factory-built pipeline, GET /ai/analyses returns a row."""
        from firewatch_cli.commands._pipeline_factory import _build_pipeline

        db_path = tmp_path / "firewatch_events.db"
        real_store = SQLiteEventStore(db_path=db_path)

        with (
            patch(
                "firewatch_cli.commands._pipeline_factory.SQLiteEventStore",
                return_value=real_store,
            ),
            patch(
                "firewatch_cli.commands._pipeline_factory.JsonFileConfigStore"
            ) as mock_cfg_store,
            patch(
                "firewatch_cli.commands._pipeline_factory.OpenAIEngine",
                return_value=_FakeAIEngine(),
            ),
        ):
            mock_cfg_store.return_value.get_runtime.return_value = _make_mock_runtime(
                ai_enabled=True
            )
            raw = _build_pipeline(config_file=tmp_path / "fw.json")

        pipeline = cast(Pipeline, raw)

        # G1 guard: ledger must be wired.
        assert pipeline.ledger is not None, (
            "Pipeline.ledger is None — factory wiring is still broken."
        )

        ledger = cast(SqliteAnalysisLedger, pipeline.ledger)
        store = cast(SQLiteEventStore, pipeline.store)

        async def _run() -> int:
            """Init store + ledger on the same loop, ingest an event, analyze."""
            await store.init()
            await ledger.init()

            event = SecurityEvent(
                source_ip=IP_A,
                source_id="test-instance",
                timestamp=datetime.now(timezone.utc),
                action="BLOCK",
                rule_id="rule-001",
                source_type="azure_waf",
            )
            await pipeline.ingest([event])
            await pipeline.analyze_ip(IP_A, use_ai=True)

            page = await ledger.list_page(limit=10)
            return len(page["items"])

        try:
            row_count = asyncio.run(_run())
        finally:
            asyncio.run(ledger.close())
            asyncio.run(store.close())

        assert row_count >= 1, (
            f"Expected at least 1 ledger row after analyze_ip, got {row_count}. "
            "Dead-wiring defect: even though the ledger adapter is built, it is not "
            "initialized and not injected into the pipeline, so writes are silently "
            "skipped. Fix: construct + init ledger in _build_pipeline and pass it to "
            "Pipeline(ledger=...)."
        )

        # Verify the API also sees it using the same wired ledger instance.
        app = create_app(registry={}, analysis_ledger=ledger)
        client = TestClient(app)
        resp = client.get("/ai/analyses")
        assert resp.status_code == 200, (
            f"GET /ai/analyses returned {resp.status_code}; expected 200. "
            "Ensure analysis_ledger is wired into create_app(...)."
        )
        items = resp.json()["items"]
        assert len(items) >= 1, (
            "GET /ai/analyses returned empty list even though a row was written. "
            "Ensure create_app(analysis_ledger=<same instance>) uses the wired ledger."
        )
        assert items[0]["ip"] == IP_A, (
            f"Expected ip={IP_A!r} in first ledger row, got {items[0].get('ip')!r}."
        )
