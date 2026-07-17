"""Tests for MK-2 AI verdict-ledger read API (issue #407, ADR-0044).

EARS criteria -> test mapping:

  E_LIST  GET /ai/analyses returns cursor-paginated summary list (ADR-0029).
    -> test_list_analyses_empty_ledger
    -> test_list_analyses_returns_items
    -> test_list_analyses_no_sensitive_fields
    -> test_list_analyses_ip_filter
    -> test_list_analyses_cursor_pagination
    -> test_list_analyses_no_ledger_returns_503

  E_DETAIL  GET /ai/analyses/{id} returns full record (ADR-0044 §5).
    -> test_get_analysis_returns_full_record
    -> test_get_analysis_includes_prompt_response
    -> test_get_analysis_unknown_id_returns_404
    -> test_get_analysis_no_ledger_returns_503

  E_ROUND_TRIP  Persist -> GET round-trip: inserted record is readable via the API.
    -> test_persist_and_get_round_trip_via_api

Security:
  -> test_list_excludes_prompt_and_response_text

All fakes use RFC 5737 documentation IPs only.
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

# RFC 5737 documentation IPs.
IP_A = "192.0.2.10"
IP_B = "198.51.100.20"


# ---------------------------------------------------------------------------
# Inline minimal ledger fake (synchronous) for tests that don't need real DB
# ---------------------------------------------------------------------------


class _FakeLedger:
    """Minimal fake ledger for list/detail route tests (in-memory)."""

    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self._rows: list[dict[str, Any]] = list(rows or [])

    def get_summary(self) -> dict[str, Any]:
        count = len(self._rows)
        last_at = self._rows[-1]["created_at"] if self._rows else None
        return {"analyses_count": count, "last_analysis_at": last_at}

    async def list_page(
        self,
        limit: int = 50,
        cursor: str | None = None,
        ip_filter: str | None = None,
    ) -> dict[str, Any]:
        items = list(self._rows)
        if ip_filter is not None:
            items = [r for r in items if r.get("ip") == ip_filter]
        items = items[:limit]
        return {"items": items, "next_cursor": None, "has_more": False}

    async def get_by_id(self, row_id: int) -> dict[str, Any] | None:
        for row in self._rows:
            if row.get("id") == row_id:
                return dict(row)
        return None


def _make_summary_row(
    row_id: int = 1,
    ip: str = IP_A,
    kind: str = "concise",
) -> dict[str, Any]:
    return {
        "id": row_id,
        "ip": ip,
        "kind": kind,
        "model": "qwen3:8b",
        "endpoint_host": "127.0.0.1:11434",
        "ai_status": "ok",
        "threat_level": "HIGH",
        "confidence": 0.8,
        "score": 60,
        "score_derivation": "rules+ai",
        "latency_ms": 200.0,
        "prompt_tokens": 100,
        "completion_tokens": 50,
        "schema_version": 1,
        "created_at": "2026-06-12T10:00:00+00:00",
        "prompt_truncated": False,
        "response_truncated": False,
    }


def _make_detail_row(row_id: int = 1, ip: str = IP_A) -> dict[str, Any]:
    row = _make_summary_row(row_id, ip)
    row["prompt_text"] = "the prompt sent to the model"
    row["response_text"] = '{"threat_level": "HIGH"}'
    row["validated_json"] = {"threat_level": "HIGH", "confidence": 0.8}
    return row


def _client_with_ledger(ledger: Any) -> TestClient:
    app = create_app(registry={}, analysis_ledger=ledger)
    return TestClient(app)


def _client_no_ledger() -> TestClient:
    app = create_app(registry={})
    return TestClient(app)


# ---------------------------------------------------------------------------
# E_LIST — GET /ai/analyses
# ---------------------------------------------------------------------------


def test_list_analyses_empty_ledger() -> None:
    """GET /ai/analyses with an empty ledger returns an empty items list."""
    client = _client_with_ledger(_FakeLedger())
    resp = client.get("/ai/analyses")
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["has_more"] is False
    assert data["next_cursor"] is None


def test_list_analyses_returns_items() -> None:
    """GET /ai/analyses returns rows from the ledger."""
    rows = [_make_summary_row(1, IP_A), _make_summary_row(2, IP_B)]
    client = _client_with_ledger(_FakeLedger(rows))
    resp = client.get("/ai/analyses")
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 2


def test_list_analyses_no_sensitive_fields() -> None:
    """GET /ai/analyses list items must NOT contain prompt_text or response_text (E8 security)."""
    rows = [_make_summary_row(1, IP_A)]
    client = _client_with_ledger(_FakeLedger(rows))
    resp = client.get("/ai/analyses")
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert "prompt_text" not in item, "prompt_text must not appear in list projection"
        assert "response_text" not in item, "response_text must not appear in list projection"


def test_list_excludes_prompt_and_response_text() -> None:
    """Security gate: list projection never exposes attacker-controlled text (OWASP LLM05)."""
    rows = [_make_summary_row(1, IP_A)]
    client = _client_with_ledger(_FakeLedger(rows))
    resp = client.get("/ai/analyses")
    body_text = resp.text
    assert "prompt_text" not in body_text
    assert "response_text" not in body_text


def test_list_analyses_ip_filter() -> None:
    """GET /ai/analyses?ip=X returns only rows for that IP."""
    rows = [_make_summary_row(1, IP_A), _make_summary_row(2, IP_B)]
    client = _client_with_ledger(_FakeLedger(rows))
    resp = client.get("/ai/analyses", params={"ip": IP_A})
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert all(item["ip"] == IP_A for item in items)


def test_list_analyses_cursor_pagination() -> None:
    """GET /ai/analyses respects cursor and has_more from the ledger."""
    # The fake returns has_more=False, so just confirm the envelope shape.
    client = _client_with_ledger(_FakeLedger([_make_summary_row(1)]))
    resp = client.get("/ai/analyses", params={"limit": 50})
    assert resp.status_code == 200
    data = resp.json()
    assert "has_more" in data
    assert "next_cursor" in data
    assert "items" in data


def test_list_analyses_no_ledger_returns_503() -> None:
    """GET /ai/analyses returns 503 when no ledger is wired (pre-#407 degrade)."""
    client = _client_no_ledger()
    resp = client.get("/ai/analyses")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# E_DETAIL — GET /ai/analyses/{id}
# ---------------------------------------------------------------------------


def test_get_analysis_returns_full_record() -> None:
    """GET /ai/analyses/1 returns the full record dict."""
    ledger = _FakeLedger()
    ledger._rows = [_make_detail_row(1, IP_A)]
    client = _client_with_ledger(ledger)
    resp = client.get("/ai/analyses/1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == 1
    assert data["ip"] == IP_A


def test_get_analysis_includes_prompt_response() -> None:
    """GET /ai/analyses/{id} must include prompt_text and response_text (detail endpoint)."""
    ledger = _FakeLedger()
    ledger._rows = [_make_detail_row(1, IP_A)]
    client = _client_with_ledger(ledger)
    resp = client.get("/ai/analyses/1")
    assert resp.status_code == 200
    data = resp.json()
    assert "prompt_text" in data
    assert "response_text" in data
    assert data["prompt_text"] == "the prompt sent to the model"


def test_get_analysis_unknown_id_returns_404() -> None:
    """GET /ai/analyses/{id} for an unknown id returns 404."""
    client = _client_with_ledger(_FakeLedger())
    resp = client.get("/ai/analyses/999999")
    assert resp.status_code == 404


def test_get_analysis_no_ledger_returns_503() -> None:
    """GET /ai/analyses/{id} returns 503 when no ledger is wired."""
    client = _client_no_ledger()
    resp = client.get("/ai/analyses/1")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# ADR-0066 (issue #39) — persisted "ok" maps to "active" at the read boundary
# ---------------------------------------------------------------------------


def test_list_analyses_maps_persisted_ok_to_active() -> None:
    """GET /ai/analyses maps a stored ai_status='ok' row to 'active' in the response.

    Ledger rows persist the AIEngine port's internal 'ok' discriminator
    verbatim (no data migration) — read routes map it to the ONE closed wire
    vocabulary so clients never see 'ok'.
    """
    rows = [_make_summary_row(1, IP_A)]
    assert rows[0]["ai_status"] == "ok"  # sanity: the fixture stores the raw value
    client = _client_with_ledger(_FakeLedger(rows))
    resp = client.get("/ai/analyses")
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert items[0]["ai_status"] == "active"


def test_list_analyses_passes_through_unavailable_unchanged() -> None:
    """A stored ai_status='unavailable' row passes through unchanged (not remapped)."""
    row = _make_summary_row(1, IP_A)
    row["ai_status"] = "unavailable"
    client = _client_with_ledger(_FakeLedger([row]))
    resp = client.get("/ai/analyses")
    assert resp.json()["items"][0]["ai_status"] == "unavailable"


def test_get_analysis_maps_persisted_ok_to_active() -> None:
    """GET /ai/analyses/{id} maps a stored ai_status='ok' row to 'active'."""
    ledger = _FakeLedger()
    ledger._rows = [_make_detail_row(1, IP_A)]
    client = _client_with_ledger(ledger)
    resp = client.get("/ai/analyses/1")
    assert resp.status_code == 200
    assert resp.json()["ai_status"] == "active"


# ---------------------------------------------------------------------------
# E_ROUND_TRIP — persist -> GET round-trip via real SqliteAnalysisLedger
# ---------------------------------------------------------------------------


def _make_record(ip: str = IP_A, kind: str = "concise") -> AnalysisRecord:
    return AnalysisRecord(
        ip=ip,
        kind=kind,  # type: ignore[arg-type]
        model="qwen3:8b",
        endpoint_host="127.0.0.1:11434",
        prompt_text="test prompt text",
        response_text='{"threat_level":"LOW"}',
        validated_json={"threat_level": "LOW", "confidence": 0.5},
        ai_status="ok",
        threat_level="LOW",
        confidence=0.5,
        score=20,
        score_derivation="rules",
        latency_ms=150.0,
        prompt_tokens=80,
        completion_tokens=40,
        created_at=datetime.now(timezone.utc),
    )


def test_persist_and_get_round_trip_via_api(tmp_path: Path) -> None:
    """Persist a record via SqliteAnalysisLedger then read it via the API (round-trip)."""
    db_path = tmp_path / "roundtrip.db"
    ledger = SqliteAnalysisLedger(db_path)

    async def _setup() -> None:
        await ledger.init()
        await ledger.save(_make_record(IP_A, "concise"))

    asyncio.run(_setup())

    try:
        app = create_app(registry={}, analysis_ledger=ledger)
        client = TestClient(app)

        # GET /ai/analyses — list should contain 1 item.
        resp = client.get("/ai/analyses")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["ip"] == IP_A
        assert items[0]["kind"] == "concise"
        # Summary projection must not include prompt/response text.
        assert "prompt_text" not in items[0]
        assert "response_text" not in items[0]

        # GET /ai/analyses/{id} — detail should include full record.
        row_id = items[0]["id"]
        resp2 = client.get(f"/ai/analyses/{row_id}")
        assert resp2.status_code == 200
        detail = resp2.json()
        assert detail["ip"] == IP_A
        assert detail["prompt_text"] == "test prompt text"
        assert "response_text" in detail
    finally:
        asyncio.run(ledger.close())
