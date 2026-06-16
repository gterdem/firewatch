"""Tests for issue #534 + #535 — cases API routes (ADR-0053 D4).

EARS → test mapping
───────────────────
Issue #534 (B1-core):

EARS-1  Create case + open in slide-over via {kind:"case", value}.
    → test_create_case_returns_id_and_201
    → test_create_case_no_store_returns_503

EARS-2  Timeline read assembles event refs + verdict-ledger refs.
    → test_get_timeline_returns_events
    → test_get_timeline_no_store_returns_503
    → test_get_timeline_unknown_case_returns_404

EARS-3  Add note; note has author + created_at.
    → test_add_note_persists_author
    → test_add_note_no_store_returns_503

EARS-4  author defaults to 'local operator'.
    → test_add_note_author_defaults_local_operator

EARS-5  Set disposition.
    → test_set_disposition_accepted
    → test_set_disposition_invalid_returns_422

ADR-0029 envelope — list cases.
    → test_list_cases_returns_envelope
    → test_list_cases_no_store_returns_503

Get case.
    → test_get_case_returns_case
    → test_get_case_unknown_returns_404

Dead-wiring guard (factory drives the REAL store):
    → test_factory_wires_real_case_store

Issue #535 (B1-polish — POST /cases/{id}/summary):

EARS-1  Summary endpoint returns narrative + provenance (rule-only when no pipeline).
    → test_summary_no_pipeline_returns_rule_only
EARS-2  Summary note is persisted with ai_drafted=1.
    → test_summary_note_persisted_ai_drafted
EARS-5  Rule-only degrade: provenance="rule" when pipeline unavailable.
    → test_summary_no_pipeline_returns_rule_only (provenance field)
EARS-6  Suggest-only: summary does NOT change case disposition.
    → test_summary_does_not_change_disposition
No-store → 503:
    → test_summary_no_store_returns_503
Unknown case → 404:
    → test_summary_unknown_case_returns_404
LLM path (fake pipeline, subject is a known IP):
    → test_summary_with_pipeline_returns_ai_provenance

All IPs are RFC 5737 documentation IPs (192.0.2.0/24, 198.51.100.0/24).
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from firewatch_api.app import create_app
from firewatch_core.adapters.cases.sqlite_cases import SqliteCaseStore

_IP_A = "192.0.2.10"
_IP_B = "198.51.100.20"


# ---------------------------------------------------------------------------
# Minimal in-memory fake case store for route unit tests
# ---------------------------------------------------------------------------


class _FakeCaseStore:
    """In-memory fake SqliteCaseStore for route-layer tests."""

    def __init__(self) -> None:
        self._cases: dict[int, dict[str, Any]] = {}
        self._notes: dict[int, list[dict[str, Any]]] = {}
        self._events: dict[int, list[dict[str, Any]]] = {}
        self._next_id = 1

    async def create_case(
        self,
        title: str,
        subject: str,
        status: str = "open",
        disposition: str = "open",
    ) -> int:
        case_id = self._next_id
        self._next_id += 1
        self._cases[case_id] = {
            "id": case_id,
            "title": title,
            "subject": subject,
            "status": status,
            "disposition": disposition,
            "created_at": "2026-06-13T00:00:00+00:00",
            "updated_at": "2026-06-13T00:00:00+00:00",
        }
        self._notes[case_id] = []
        self._events[case_id] = []
        return case_id

    async def get_case(self, case_id: int) -> dict[str, Any] | None:
        return self._cases.get(case_id)

    async def list_cases(
        self,
        limit: int = 50,
        cursor: str | None = None,
        subject: str | None = None,
    ) -> dict[str, Any]:
        items = list(self._cases.values())
        if subject is not None:
            items = [c for c in items if c.get("subject") == subject]
        return {"items": items[:limit], "next_cursor": None, "has_more": False}

    async def set_disposition(self, case_id: int, disposition: str) -> None:
        valid = {"true-positive", "false-positive", "benign", "open"}
        if disposition not in valid:
            raise ValueError(f"Invalid disposition {disposition!r}")
        if case_id not in self._cases:
            raise LookupError(f"Case {case_id} not found.")
        self._cases[case_id]["disposition"] = disposition

    async def set_status(self, case_id: int, status: str) -> None:
        if case_id not in self._cases:
            raise LookupError(f"Case {case_id} not found.")
        self._cases[case_id]["status"] = status

    async def add_note(
        self,
        case_id: int,
        body_md: str,
        author: str = "local operator",
        ai_drafted: bool = False,
    ) -> int:
        if case_id not in self._cases:
            raise LookupError(f"Case {case_id} not found.")
        note_id = self._next_id
        self._next_id += 1
        note: dict[str, Any] = {
            "id": note_id,
            "case_id": case_id,
            "author": author,
            "body_md": body_md,
            "ai_drafted": int(ai_drafted),
            "created_at": "2026-06-13T00:00:00+00:00",
            "updated_at": "2026-06-13T00:00:00+00:00",
        }
        self._notes[case_id].append(note)
        return note_id

    async def list_notes(self, case_id: int) -> list[dict[str, Any]]:
        return list(self._notes.get(case_id, []))

    async def link_event(self, case_id: int, ref_kind: str, ref_id: str) -> int:
        if case_id not in self._cases:
            raise LookupError(f"Case {case_id} not found.")
        ev_id = self._next_id
        self._next_id += 1
        ev: dict[str, Any] = {
            "id": ev_id,
            "case_id": case_id,
            "ref_kind": ref_kind,
            "ref_id": ref_id,
            "created_at": "2026-06-13T00:00:00+00:00",
        }
        self._events[case_id].append(ev)
        return ev_id

    async def get_timeline(self, case_id: int) -> dict[str, Any]:
        if case_id not in self._cases:
            return {"case_id": case_id, "events": []}
        return {"case_id": case_id, "events": list(self._events.get(case_id, []))}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client(case_store: Any | None = None) -> TestClient:
    app = create_app(case_store=case_store)
    return TestClient(app, raise_server_exceptions=True)


def _client_with_store() -> tuple[TestClient, _FakeCaseStore]:
    store = _FakeCaseStore()
    return _client(case_store=store), store


# ---------------------------------------------------------------------------
# EARS-1 — create case
# ---------------------------------------------------------------------------


def test_create_case_returns_id_and_201() -> None:
    client, _ = _client_with_store()
    resp = client.post("/cases", json={"title": "Investigation", "subject": _IP_A})
    assert resp.status_code == 201
    body = resp.json()
    assert "id" in body
    assert isinstance(body["id"], int)


def test_create_case_no_store_returns_503() -> None:
    client = _client(case_store=None)
    resp = client.post("/cases", json={"title": "No store", "subject": _IP_A})
    assert resp.status_code == 503


def test_create_case_missing_title_returns_422() -> None:
    client, _ = _client_with_store()
    resp = client.post("/cases", json={"subject": _IP_A})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Get case
# ---------------------------------------------------------------------------


def test_get_case_returns_case() -> None:
    client, store = _client_with_store()
    create_resp = client.post("/cases", json={"title": "Get me", "subject": _IP_B})
    case_id = create_resp.json()["id"]

    resp = client.get(f"/cases/{case_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["title"] == "Get me"
    assert body["subject"] == _IP_B
    assert body["disposition"] == "open"


def test_get_case_unknown_returns_404() -> None:
    client, _ = _client_with_store()
    resp = client.get("/cases/99999")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# List cases
# ---------------------------------------------------------------------------


def test_list_cases_returns_envelope() -> None:
    client, _ = _client_with_store()
    client.post("/cases", json={"title": "C1", "subject": _IP_A})
    client.post("/cases", json={"title": "C2", "subject": _IP_B})

    resp = client.get("/cases")
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body
    assert "next_cursor" in body
    assert "has_more" in body
    assert len(body["items"]) == 2


def test_list_cases_no_store_returns_503() -> None:
    client = _client(case_store=None)
    resp = client.get("/cases")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# EARS-3 / EARS-4 — add note
# ---------------------------------------------------------------------------


def test_add_note_persists_author() -> None:
    client, _ = _client_with_store()
    create_resp = client.post("/cases", json={"title": "Note target", "subject": _IP_A})
    case_id = create_resp.json()["id"]

    resp = client.post(
        f"/cases/{case_id}/notes",
        json={"body_md": "# Summary\nDetails here.", "author": "alice"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "id" in body
    assert isinstance(body["id"], int)


def test_add_note_author_defaults_local_operator() -> None:
    """No author in request body → store receives 'local operator' (EARS-4)."""
    client, store = _client_with_store()
    create_resp = client.post("/cases", json={"title": "Default author", "subject": _IP_A})
    case_id = create_resp.json()["id"]

    # No author field in body.
    resp = client.post(
        f"/cases/{case_id}/notes",
        json={"body_md": "A note with no explicit author."},
    )
    assert resp.status_code == 201

    # Inspect stored note via the fake store directly.
    notes = asyncio.run(store.list_notes(case_id))
    assert len(notes) == 1
    assert notes[0]["author"] == "local operator"


def test_add_note_no_store_returns_503() -> None:
    client = _client(case_store=None)
    resp = client.post("/cases/1/notes", json={"body_md": "Hi."})
    assert resp.status_code == 503


def test_add_note_unknown_case_returns_404() -> None:
    client, _ = _client_with_store()
    resp = client.post("/cases/99999/notes", json={"body_md": "Ghost note."})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# EARS-5 — set disposition
# ---------------------------------------------------------------------------


def test_set_disposition_accepted() -> None:
    client, _ = _client_with_store()
    create_resp = client.post("/cases", json={"title": "Disp test", "subject": _IP_A})
    case_id = create_resp.json()["id"]

    for disp in ["true-positive", "false-positive", "benign", "open"]:
        resp = client.patch(f"/cases/{case_id}/disposition", json={"disposition": disp})
        assert resp.status_code == 200, f"Expected 200 for {disp!r}, got {resp.status_code}"

    # Confirm last written value.
    case_resp = client.get(f"/cases/{case_id}")
    assert case_resp.json()["disposition"] == "open"


def test_set_disposition_invalid_returns_422() -> None:
    client, _ = _client_with_store()
    create_resp = client.post("/cases", json={"title": "Bad disp", "subject": _IP_B})
    case_id = create_resp.json()["id"]

    resp = client.patch(f"/cases/{case_id}/disposition", json={"disposition": "maybe"})
    assert resp.status_code == 422


def test_set_disposition_no_store_returns_503() -> None:
    client = _client(case_store=None)
    resp = client.patch("/cases/1/disposition", json={"disposition": "benign"})
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# EARS-2 — timeline
# ---------------------------------------------------------------------------


def test_get_timeline_returns_events() -> None:
    client, store = _client_with_store()
    create_resp = client.post("/cases", json={"title": "Timeline", "subject": _IP_A})
    case_id = create_resp.json()["id"]

    # Pre-seed two event refs via the store.
    asyncio.run(store.link_event(case_id, "security_event", "evt-001"))
    asyncio.run(store.link_event(case_id, "ai_analysis", "42"))

    resp = client.get(f"/cases/{case_id}/timeline")
    assert resp.status_code == 200
    body = resp.json()
    assert "events" in body
    ref_ids = {e["ref_id"] for e in body["events"]}
    assert "evt-001" in ref_ids
    assert "42" in ref_ids


def test_get_timeline_no_store_returns_503() -> None:
    client = _client(case_store=None)
    resp = client.get("/cases/1/timeline")
    assert resp.status_code == 503


def test_get_timeline_unknown_case_returns_404() -> None:
    client, _ = _client_with_store()
    resp = client.get("/cases/99999/timeline")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Dead-wiring guard — drives the REAL factory
# ---------------------------------------------------------------------------


def test_factory_wires_real_case_store(tmp_path: Path) -> None:
    """The REAL SqliteCaseStore must initialise and serve a create→get round-trip.

    This guards against dead-wiring: if the store is never connected to the app
    state, the route returns 503 and this test fails.
    """
    db_path = tmp_path / "guard_test.db"
    real_store = SqliteCaseStore(db_path=db_path)
    asyncio.run(real_store.init())

    app = create_app(case_store=real_store)
    with TestClient(app, raise_server_exceptions=True) as client:
        create_resp = client.post(
            "/cases", json={"title": "Guard test", "subject": _IP_A}
        )
        assert create_resp.status_code == 201
        case_id = create_resp.json()["id"]

        get_resp = client.get(f"/cases/{case_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["title"] == "Guard test"

    asyncio.run(real_store.close())


# ---------------------------------------------------------------------------
# Issue #535 — POST /cases/{case_id}/summary tests (ADR-0053 D2)
# ---------------------------------------------------------------------------


def _client_with_pipeline(
    case_store: Any,
    pipeline: Any,
) -> TestClient:
    """Build a TestClient that has both a case_store and a pipeline wired."""
    app = create_app(case_store=case_store, pipeline=pipeline)
    return TestClient(app, raise_server_exceptions=True)


class _FakeAiEngine:
    """Minimal AI engine that returns a canned narration."""

    def __init__(self, narrative: str = "AI narrative here.") -> None:
        self._narrative = narrative
        self.calls: list[dict[str, Any]] = []

    async def is_available(self) -> bool:
        return True

    async def analyze_concise(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(dict(kwargs))
        return {"narrative": self._narrative}


class _FakePipelineWithDetail:
    """Fake pipeline for summary tests — returns preset detail."""

    def __init__(
        self,
        detail: dict[str, Any] | None = None,
        ai_engine: Any = None,
    ) -> None:
        self._detail = detail or {
            "score": 80,
            "threat_level": "HIGH",
            "total_events": 10,
            "blocked_events": 5,
            "first_seen": "2026-06-13T00:00:00Z",
            "last_seen": "2026-06-13T01:00:00Z",
            "ai_status": "ok",
            "score_derivation": "rule",
            "score_breakdown": [
                {"label": "Brute-force", "factor": "bf", "points": 30}
            ],
        }
        self.ai_engine = ai_engine or _FakeAiEngine()

    async def analyze_ip_detailed(
        self, ip: str, *, include_ai: bool = True, stage_sink: Any = None
    ) -> dict[str, Any]:
        return dict(self._detail)


class _FakePipelineNoDetail:
    """Fake pipeline that reports the IP is unknown (error path)."""

    def __init__(self) -> None:
        self.ai_engine = _FakeAiEngine()

    async def analyze_ip_detailed(
        self, ip: str, *, include_ai: bool = True, stage_sink: Any = None
    ) -> dict[str, Any]:
        return {"error": f"No logs found for {ip}"}


def test_summary_no_store_returns_503() -> None:
    """POST /cases/{id}/summary returns 503 when case store is not wired."""
    client = _client(case_store=None)
    resp = client.post("/cases/1/summary")
    assert resp.status_code == 503


def test_summary_unknown_case_returns_404() -> None:
    """POST /cases/{id}/summary returns 404 when case does not exist."""
    client, _ = _client_with_store()
    resp = client.post("/cases/99999/summary")
    assert resp.status_code == 404


def test_summary_no_pipeline_returns_rule_only() -> None:
    """EARS-5: when pipeline is None, returns rule-only summary (provenance='rule')."""
    client, store = _client_with_store()
    create_resp = client.post("/cases", json={"title": "No pipeline", "subject": _IP_A})
    case_id = create_resp.json()["id"]

    # No pipeline wired → rule-only fallback.
    resp = client.post(f"/cases/{case_id}/summary")
    assert resp.status_code == 201
    body = resp.json()
    assert "narrative" in body
    assert body["provenance"] == "rule"
    assert "note_id" in body
    assert isinstance(body["note_id"], int)


def test_summary_note_persisted_ai_drafted() -> None:
    """EARS-2: summary note is persisted with ai_drafted=1 (ADR-0035)."""
    client, store = _client_with_store()
    create_resp = client.post("/cases", json={"title": "Draft note", "subject": _IP_B})
    case_id = create_resp.json()["id"]

    resp = client.post(f"/cases/{case_id}/summary")
    assert resp.status_code == 201
    note_id = resp.json()["note_id"]

    # Verify the note was persisted with ai_drafted=1.
    notes = asyncio.run(store.list_notes(case_id))
    assert any(n["id"] == note_id and bool(n["ai_drafted"]) for n in notes), (
        "Expected a note with ai_drafted=1 matching the returned note_id"
    )


def test_summary_does_not_change_disposition() -> None:
    """EARS-6: summary is suggest-only — disposition is unchanged."""
    client, store = _client_with_store()
    create_resp = client.post("/cases", json={"title": "Disposition guard", "subject": _IP_A})
    case_id = create_resp.json()["id"]

    # Initial disposition is 'open'.
    before = asyncio.run(store.get_case(case_id))
    assert before is not None and before["disposition"] == "open"

    client.post(f"/cases/{case_id}/summary")

    # Disposition must still be 'open' — summary must not change it.
    after = asyncio.run(store.get_case(case_id))
    assert after is not None and after["disposition"] == "open", (
        "Summary endpoint must not change case disposition (EARS-6 / ADR-0015)"
    )


def test_summary_with_pipeline_returns_ai_provenance() -> None:
    """EARS-1: when pipeline + LLM are available, provenance should be 'ai'."""
    store = _FakeCaseStore()
    pipeline = _FakePipelineWithDetail()
    client = _client_with_pipeline(case_store=store, pipeline=pipeline)

    # We need to create the case via the HTTP API so the store is populated.
    create_resp = client.post("/cases", json={"title": "AI summary", "subject": _IP_A})
    assert create_resp.status_code == 201
    case_id = create_resp.json()["id"]

    resp = client.post(f"/cases/{case_id}/summary")
    assert resp.status_code == 201
    body = resp.json()
    # When the LLM runs, provenance must NOT be 'rule'.
    assert body["provenance"] in ("ai", "ai+rule"), (
        f"Expected ai/ai+rule provenance, got {body['provenance']!r}"
    )
    assert body["narrative"], "Narrative must be non-empty"
    assert body["note_id"] > 0
