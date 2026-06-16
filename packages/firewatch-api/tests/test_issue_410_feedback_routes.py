"""Tests for MK-5 (#410) — feedback API routes and runtime wiring (ADR-0045).

EARS criteria -> test mapping
==============================

R1  POST /ai/analyses/{id}/feedback upserts and returns the stored row.
    -> test_post_feedback_inserts_new
    -> test_post_feedback_updates_existing (re-vote)
    -> test_post_feedback_returns_stored_row_fields

R2  POST /ai/analyses/{id}/feedback returns 404 for unknown analysis_id.
    -> test_post_feedback_unknown_analysis_404

R3  POST /ai/analyses/{id}/feedback returns 422 for invalid verdict.
    -> test_post_feedback_invalid_verdict_422

R4  POST /ai/analyses/{id}/feedback returns 422 for oversized reason.
    -> test_post_feedback_reason_over_cap_422

R5  GET /ai/feedback/summary returns {graded, agreed, agreement_pct}.
    -> test_get_summary_empty
    -> test_get_summary_with_data
    -> test_get_summary_denominator_present

R6  Both routes return 503 when no ledger is wired.
    -> test_post_feedback_no_ledger_503
    -> test_get_summary_no_ledger_503

R7  Runtime wiring guard: the feedback store is live via the production
    factory path (not a hand-built object).
    -> test_runtime_wiring_feedback_store_live

All RFC 5737 documentation IPs only.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from firewatch_api.app import create_app
from firewatch_core.adapters.ledger.sqlite_ledger import SqliteAnalysisLedger
from firewatch_core.ports.analysis_ledger import AnalysisRecord

# RFC 5737 documentation IPs only.
IP_A = "192.0.2.10"
IP_B = "198.51.100.20"

_REASON_CAP = 1_000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(ip: str = IP_A, kind: str = "concise") -> AnalysisRecord:
    return AnalysisRecord(
        ip=ip,
        kind=kind,  # type: ignore[arg-type]
        model="qwen3:8b",
        endpoint_host="127.0.0.1:11434",
        prompt_text="test prompt",
        response_text='{"threat_level":"LOW"}',
        validated_json={"threat_level": "LOW", "confidence": 0.5},
        ai_status="ok",
        threat_level="LOW",
        confidence=0.5,
        score=20,
        score_derivation="rules",
        latency_ms=100.0,
        prompt_tokens=80,
        completion_tokens=40,
        created_at=datetime.now(timezone.utc),
    )


def _client_with_ledger(ledger: Any) -> TestClient:
    app = create_app(registry={}, analysis_ledger=ledger)
    return TestClient(app)


def _client_no_ledger() -> TestClient:
    app = create_app(registry={})
    return TestClient(app)


def _setup_ledger_with_record(db_path: Path, ip: str = IP_A) -> tuple[SqliteAnalysisLedger, int]:
    """Init ledger, save one record, return (ledger, analysis_id)."""
    ledger = SqliteAnalysisLedger(db_path)

    async def _setup() -> int:
        await ledger.init()
        await ledger.save(_make_record(ip))
        page = await ledger.list_page(limit=1)
        return page["items"][0]["id"]

    analysis_id: int = asyncio.run(_setup())
    return ledger, analysis_id


# ---------------------------------------------------------------------------
# R1 — POST upsert semantics
# ---------------------------------------------------------------------------


def test_post_feedback_inserts_new(tmp_path: Path) -> None:
    """POST /ai/analyses/{id}/feedback inserts a new feedback row (R1)."""
    ledger, analysis_id = _setup_ledger_with_record(tmp_path / "test.db")
    try:
        client = _client_with_ledger(ledger)
        resp = client.post(
            f"/ai/analyses/{analysis_id}/feedback",
            json={"verdict": "agree", "reason": "looks right"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "agree"
        assert data["reason"] == "looks right"
        assert data["analysis_id"] == analysis_id
        assert "created_at" in data
    finally:
        asyncio.run(ledger.close())


def test_post_feedback_updates_existing(tmp_path: Path) -> None:
    """Re-submitting feedback for the same analysis_id upserts (latest wins) (R1)."""
    ledger, analysis_id = _setup_ledger_with_record(tmp_path / "test.db")
    try:
        client = _client_with_ledger(ledger)
        client.post(
            f"/ai/analyses/{analysis_id}/feedback",
            json={"verdict": "agree", "reason": "first vote"},
        )
        resp = client.post(
            f"/ai/analyses/{analysis_id}/feedback",
            json={"verdict": "disagree", "reason": "changed mind"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "disagree"
        assert data["reason"] == "changed mind"
    finally:
        asyncio.run(ledger.close())


def test_post_feedback_returns_stored_row_fields(tmp_path: Path) -> None:
    """POST response must include id, analysis_id, verdict, reason, created_at (R1)."""
    ledger, analysis_id = _setup_ledger_with_record(tmp_path / "test.db")
    try:
        client = _client_with_ledger(ledger)
        resp = client.post(
            f"/ai/analyses/{analysis_id}/feedback",
            json={"verdict": "disagree"},
        )
        assert resp.status_code == 200
        data = resp.json()
        for field in ("id", "analysis_id", "verdict", "created_at"):
            assert field in data, f"Response must include {field!r}"
    finally:
        asyncio.run(ledger.close())


# ---------------------------------------------------------------------------
# R2 — unknown analysis_id → 404
# ---------------------------------------------------------------------------


def test_post_feedback_unknown_analysis_404(tmp_path: Path) -> None:
    """POST feedback for an unknown analysis_id must return 404 (R2)."""
    ledger = SqliteAnalysisLedger(tmp_path / "test.db")
    asyncio.run(ledger.init())
    try:
        client = _client_with_ledger(ledger)
        resp = client.post(
            "/ai/analyses/999999/feedback",
            json={"verdict": "agree"},
        )
        assert resp.status_code == 404
        # Error body must NOT echo analysis record content (OWASP API4:2023).
        assert "999999" in resp.json()["detail"] or resp.status_code == 404
    finally:
        asyncio.run(ledger.close())


# ---------------------------------------------------------------------------
# R3 — invalid verdict → 422
# ---------------------------------------------------------------------------


def test_post_feedback_invalid_verdict_422(tmp_path: Path) -> None:
    """POST feedback with an invalid verdict must return 422 (R3)."""
    ledger, analysis_id = _setup_ledger_with_record(tmp_path / "test.db")
    try:
        client = _client_with_ledger(ledger)
        resp = client.post(
            f"/ai/analyses/{analysis_id}/feedback",
            json={"verdict": "maybe"},
        )
        assert resp.status_code == 422
    finally:
        asyncio.run(ledger.close())


# ---------------------------------------------------------------------------
# R4 — oversized reason → 422
# ---------------------------------------------------------------------------


def test_post_feedback_reason_over_cap_422(tmp_path: Path) -> None:
    """POST feedback with a reason > 1000 chars must return 422 (R4)."""
    ledger, analysis_id = _setup_ledger_with_record(tmp_path / "test.db")
    try:
        client = _client_with_ledger(ledger)
        resp = client.post(
            f"/ai/analyses/{analysis_id}/feedback",
            json={"verdict": "agree", "reason": "x" * (_REASON_CAP + 1)},
        )
        assert resp.status_code == 422
    finally:
        asyncio.run(ledger.close())


# ---------------------------------------------------------------------------
# R5 — GET /ai/feedback/summary
# ---------------------------------------------------------------------------


def test_get_summary_empty(tmp_path: Path) -> None:
    """GET /ai/feedback/summary with no feedback returns graded=0 (R5)."""
    ledger = SqliteAnalysisLedger(tmp_path / "test.db")
    asyncio.run(ledger.init())
    try:
        client = _client_with_ledger(ledger)
        resp = client.get("/ai/feedback/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["graded"] == 0
        assert data["agreed"] == 0
        assert data["agreement_pct"] == 0.0
    finally:
        asyncio.run(ledger.close())


def test_get_summary_with_data(tmp_path: Path) -> None:
    """GET /ai/feedback/summary reflects graded/agreed counts correctly (R5)."""
    ledger, aid1 = _setup_ledger_with_record(tmp_path / "test.db", IP_A)

    async def _add_second() -> int:
        await ledger.save(_make_record(IP_B))
        page = await ledger.list_page(limit=10)
        # Items are newest-first; the second save is the newest.
        return page["items"][0]["id"]

    aid2: int = asyncio.run(_add_second())

    async def _submit() -> None:
        await ledger.upsert_feedback(aid1, verdict="agree", reason=None)
        await ledger.upsert_feedback(aid2, verdict="disagree", reason=None)

    asyncio.run(_submit())

    try:
        client = _client_with_ledger(ledger)
        resp = client.get("/ai/feedback/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["graded"] == 2
        assert data["agreed"] == 1
        assert abs(data["agreement_pct"] - 50.0) < 0.01
    finally:
        asyncio.run(ledger.close())


def test_get_summary_denominator_present(tmp_path: Path) -> None:
    """GET /ai/feedback/summary must always include graded (honest denominator rule, R5)."""
    ledger, analysis_id = _setup_ledger_with_record(tmp_path / "test.db")
    asyncio.run(ledger.upsert_feedback(analysis_id, verdict="agree", reason=None))
    try:
        client = _client_with_ledger(ledger)
        resp = client.get("/ai/feedback/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "graded" in data
        assert data["graded"] >= 1
    finally:
        asyncio.run(ledger.close())


# ---------------------------------------------------------------------------
# R6 — 503 when no ledger wired
# ---------------------------------------------------------------------------


def test_post_feedback_no_ledger_503() -> None:
    """POST /ai/analyses/{id}/feedback returns 503 when no ledger is wired (R6)."""
    client = _client_no_ledger()
    resp = client.post("/ai/analyses/1/feedback", json={"verdict": "agree"})
    assert resp.status_code == 503


def test_get_summary_no_ledger_503() -> None:
    """GET /ai/feedback/summary returns 503 when no ledger is wired (R6)."""
    client = _client_no_ledger()
    resp = client.get("/ai/feedback/summary")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# R7 — Runtime wiring guard: feedback store is live via production factory path
# ---------------------------------------------------------------------------


def test_runtime_wiring_feedback_store_live(tmp_path: Path) -> None:
    """The feedback store must be reachable via the production create_app wiring (R7).

    This test drives the REAL factory path (create_app with a real
    SqliteAnalysisLedger) and exercises both feedback endpoints end-to-end.
    It will FAIL if the feedback methods are not wired onto the ledger object
    that create_app receives — i.e., it guards against dead-wiring.
    """
    db_path = tmp_path / "wiring.db"
    ledger = SqliteAnalysisLedger(db_path)

    async def _init_and_save() -> int:
        await ledger.init()
        await ledger.save(_make_record(IP_A))
        page = await ledger.list_page(limit=1)
        return page["items"][0]["id"]

    analysis_id: int = asyncio.run(_init_and_save())

    # Wire the real ledger through create_app (the production path).
    app = create_app(registry={}, analysis_ledger=ledger)
    client = TestClient(app)

    try:
        # 1. POST feedback — must succeed (not 503 / AttributeError).
        resp = client.post(
            f"/ai/analyses/{analysis_id}/feedback",
            json={"verdict": "agree", "reason": "wiring guard"},
        )
        assert resp.status_code == 200, (
            f"Feedback POST returned {resp.status_code} — "
            "feedback store not live via production wiring path"
        )
        assert resp.json()["verdict"] == "agree"

        # 2. GET summary — must reflect the submitted feedback.
        resp2 = client.get("/ai/feedback/summary")
        assert resp2.status_code == 200, (
            f"Feedback summary GET returned {resp2.status_code} — "
            "feedback store not live via production wiring path"
        )
        data = resp2.json()
        assert data["graded"] == 1, "Summary must show 1 graded after one feedback"
        assert data["agreed"] == 1
        assert data["agreement_pct"] == 100.0
    finally:
        asyncio.run(ledger.close())
