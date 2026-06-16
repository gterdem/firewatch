"""Tests for issue #757 — subject query filter on GET /cases (route layer).

EARS criterion map (backend half)
----------------------------------
EARS-1  The frontend calls GET /cases?subject=<ip> to find-or-create.
        Backend: when subject matches, return matching cases; when none match,
        return empty list so the caller knows to create a new case.

Test coverage:
  test_list_cases_subject_filter_returns_matching
      Create 2 cases with subject A + 1 with subject B.
      GET /cases?subject=A returns exactly 2 items, all with subject A.
  test_list_cases_subject_filter_returns_empty_when_none_match
      GET /cases?subject=<unmatched> returns empty items list (200, not 404).
  test_list_cases_subject_filter_newest_first
      The two A cases are ordered newest-first in the response.
  test_list_cases_no_subject_returns_all
      GET /cases (no subject param) returns all 3 cases — no regression.
  test_list_cases_subject_filter_envelope_shape
      Response conforms to ADR-0029 envelope (items / next_cursor / has_more).

All IPs are RFC 5737 documentation IPs (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) — never real/public/routable IPs.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from firewatch_api.app import create_app
from firewatch_core.adapters.cases.sqlite_cases import SqliteCaseStore

# RFC 5737 documentation IPs only.
_SUBJECT_A = "192.0.2.10"
_SUBJECT_B = "198.51.100.20"
_SUBJECT_C = "203.0.113.5"


# ---------------------------------------------------------------------------
# Fixture: real SqliteCaseStore backed by a tmp file, wired to a TestClient
# ---------------------------------------------------------------------------


@pytest.fixture()
def client_and_store(tmp_path: Path) -> tuple[TestClient, SqliteCaseStore]:
    """Return a TestClient wired to a real SqliteCaseStore (tmp db)."""
    db_path = tmp_path / "cases_route_757.db"
    store = SqliteCaseStore(db_path=db_path)
    asyncio.run(store.init())
    app = create_app(case_store=store)
    return TestClient(app, raise_server_exceptions=True), store


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _seed(client: TestClient) -> tuple[int, int, int]:
    """Create 2 A cases + 1 B case; return (id_a1, id_a2, id_b1)."""
    r1 = client.post("/cases", json={"title": "Case A1", "subject": _SUBJECT_A})
    r2 = client.post("/cases", json={"title": "Case A2", "subject": _SUBJECT_A})
    r3 = client.post("/cases", json={"title": "Case B1", "subject": _SUBJECT_B})
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r3.status_code == 201
    return r1.json()["id"], r2.json()["id"], r3.json()["id"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_list_cases_subject_filter_returns_matching(
    client_and_store: tuple[TestClient, SqliteCaseStore],
) -> None:
    """GET /cases?subject=A returns exactly the 2 cases with subject A."""
    client, _ = client_and_store
    _seed(client)

    resp = client.get("/cases", params={"subject": _SUBJECT_A})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["items"]) == 2
    for item in body["items"]:
        assert item["subject"] == _SUBJECT_A


def test_list_cases_subject_filter_returns_empty_when_none_match(
    client_and_store: tuple[TestClient, SqliteCaseStore],
) -> None:
    """GET /cases?subject=<unmatched> returns 200 with empty items list."""
    client, _ = client_and_store
    _seed(client)

    resp = client.get("/cases", params={"subject": _SUBJECT_C})
    assert resp.status_code == 200
    body = resp.json()
    assert body["items"] == []
    assert body["has_more"] is False
    assert body["next_cursor"] is None


def test_list_cases_subject_filter_newest_first(
    client_and_store: tuple[TestClient, SqliteCaseStore],
) -> None:
    """Filtered results are newest-first (id_a2 before id_a1)."""
    client, _ = client_and_store
    id_a1, id_a2, _ = _seed(client)

    resp = client.get("/cases", params={"subject": _SUBJECT_A})
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 2
    # id_a2 was inserted after id_a1, so it must appear first.
    assert items[0]["id"] == id_a2
    assert items[1]["id"] == id_a1


def test_list_cases_no_subject_returns_all(
    client_and_store: tuple[TestClient, SqliteCaseStore],
) -> None:
    """GET /cases with no subject param returns all 3 cases (no regression)."""
    client, _ = client_and_store
    _seed(client)

    resp = client.get("/cases")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["items"]) == 3


def test_list_cases_subject_filter_envelope_shape(
    client_and_store: tuple[TestClient, SqliteCaseStore],
) -> None:
    """Response envelope has items / next_cursor / has_more (ADR-0029)."""
    client, _ = client_and_store
    _seed(client)

    resp = client.get("/cases", params={"subject": _SUBJECT_A})
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body
    assert "next_cursor" in body
    assert "has_more" in body
