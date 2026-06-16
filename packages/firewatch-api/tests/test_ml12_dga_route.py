"""Tests for ML-12 — GET /logs/dga-suspects DGA detection API route.

Mapped 1:1 to EARS acceptance criteria from issue #440.

EARS-1  GET /logs/dga-suspects SHALL return DNS rows whose dns_query scored
        above the DGA FLAG_THRESHOLD via local heuristic analysis.
        Tests: 200 shape, dga_score field, source_ip field.

EARS-2  Rows where dns_query is NULL SHALL be excluded honestly.
        Covered by the core builder tests; here we confirm the route
        returns an empty list when no DGA rows exist.

EARS-3  (EARS-3 covers AI narration — not tested here; see prompts tests.)

Additional:
  - 503 when store unavailable.
  - 422 when top_n is out of the valid range (ge=1, le=1000).
  - empty store -> 200 with empty list.
  - top_n param accepted (default and custom).
  - injection safety: non-integer top_n -> 422 (never 500).

Strategy: route tests use a minimal fake store whose get_dga_suspects()
returns a canned response.  This proves the route wires up correctly and
returns the right envelope shape.  Correctness of DGA scoring logic is
covered by the core unit tests in packages/firewatch-core/tests/test_dga.py.

All IPs use RFC 5737 / RFC 1918 ranges — never real/routable IPs.
"""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from firewatch_api.app import create_app
from firewatch_api.deps import get_event_store


# ---------------------------------------------------------------------------
# Fake stores
# ---------------------------------------------------------------------------

class _EmptyStore:
    """Minimal store fake returning empty DGA suspects."""

    async def get_dga_suspects_fake(self, top_n: int = 50) -> list[dict[str, Any]]:
        return []


class _DgaStore:
    """Fake store that returns a fixed DGA suspect row."""

    # RFC 5737 documentation IP only
    _SUSPECTS: list[dict[str, Any]] = [
        {
            "dns_query": "xkzqvbmnwjrfptdl.example",
            "source_ip": "192.0.2.10",
            "timestamp": "2026-06-13T12:00:00+00:00",
            "dga_score": 0.7541,
            "entropy": 0.736,
            "consonant_ratio": 1.0,
            "digit_ratio": 0.0,
            "label_length": 16,
        }
    ]

    async def get_dga_suspects_fake(self, top_n: int = 50) -> list[dict[str, Any]]:
        return self._SUSPECTS[:top_n]


# ---------------------------------------------------------------------------
# Route-level fake store wiring
# ---------------------------------------------------------------------------

# We monkey-patch get_dga_suspects from the route by injecting a fake store
# that delegates the DGA call through the real route handler.
# The route calls: await get_dga_suspects(store, top_n=top_n)
# So we need a store that has a _read_conn() compatible with the real scorer.
# For simplicity, use a minimal SQLite-backed store in tmp_path for integration
# tests, and a fake _read_conn for unit tests.


class _EmptyCursor:
    """Cursor returning empty rows."""
    async def fetchall(self) -> list[Any]:
        return []


class _EmptyDb:
    """DB stub whose execute() returns empty cursor."""
    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> _EmptyCursor:  # noqa: ARG002
        return _EmptyCursor()


class _FakeStoreEmpty:
    """Store fake with empty _read_conn — no DNS rows to score."""

    async def _read_conn(self) -> _EmptyDb:
        return _EmptyDb()


class _RowCursor:
    """Cursor returning a fixed list of rows."""

    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    async def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows


class _RowDb:
    """DB stub returning fixed DNS rows."""

    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> _RowCursor:  # noqa: ARG002
        return _RowCursor(self._rows)


class _FakeStoreDga:
    """Store fake with a DGA-like dns_query row in _read_conn."""

    # (dns_query, source_ip, timestamp)
    _ROWS: list[tuple[str, str, str]] = [
        ("xkzqvbmnwjrfptdl.example", "192.0.2.10", "2026-06-13T12:00:00+00:00"),
    ]

    async def _read_conn(self) -> _RowDb:
        return _RowDb(self._ROWS)


class _FakeStoreBenign:
    """Store fake with a benign dns_query row — should return empty suspects."""

    _ROWS: list[tuple[str, str, str]] = [
        ("example.com", "192.0.2.20", "2026-06-13T12:00:00+00:00"),
    ]

    async def _read_conn(self) -> _RowDb:
        return _RowDb(self._ROWS)


# ---------------------------------------------------------------------------
# Client helpers
# ---------------------------------------------------------------------------


def _client_with_store(store: Any) -> TestClient:
    app = create_app(event_store=store)
    app.dependency_overrides[get_event_store] = lambda: store
    return TestClient(app)


def _client_no_store() -> TestClient:
    app = create_app(event_store=None)
    return TestClient(app)


# ---------------------------------------------------------------------------
# EARS-1 + shape: 200 with correct fields
# ---------------------------------------------------------------------------


class TestDgaSuspectsShape:
    """EARS-1 — route returns 200 with correct field shapes."""

    def test_empty_store_returns_200_empty_list(self) -> None:
        """Empty store returns 200 with an empty list."""
        client = _client_with_store(_FakeStoreEmpty())
        resp = client.get("/logs/dga-suspects")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert data == []

    def test_dga_row_returns_200_with_suspect(self) -> None:
        """Store with a DGA-like dns_query row returns 200 with at least one suspect."""
        client = _client_with_store(_FakeStoreDga())
        resp = client.get("/logs/dga-suspects")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_suspect_row_has_dns_query(self) -> None:
        """Each suspect row has a dns_query field."""
        client = _client_with_store(_FakeStoreDga())
        resp = client.get("/logs/dga-suspects")
        assert resp.status_code == 200
        row = resp.json()[0]
        assert "dns_query" in row
        assert row["dns_query"] == "xkzqvbmnwjrfptdl.example"

    def test_suspect_row_has_source_ip(self) -> None:
        """Each suspect row has a source_ip field."""
        client = _client_with_store(_FakeStoreDga())
        resp = client.get("/logs/dga-suspects")
        assert resp.status_code == 200
        row = resp.json()[0]
        assert "source_ip" in row

    def test_suspect_row_has_dga_score(self) -> None:
        """Each suspect row has a dga_score float field."""
        client = _client_with_store(_FakeStoreDga())
        resp = client.get("/logs/dga-suspects")
        assert resp.status_code == 200
        row = resp.json()[0]
        assert "dga_score" in row
        assert isinstance(row["dga_score"], float)

    def test_suspect_row_has_glass_box_fields(self) -> None:
        """Each suspect row has entropy/consonant_ratio/digit_ratio/label_length."""
        client = _client_with_store(_FakeStoreDga())
        resp = client.get("/logs/dga-suspects")
        assert resp.status_code == 200
        row = resp.json()[0]
        for field in ("entropy", "consonant_ratio", "digit_ratio", "label_length"):
            assert field in row, f"Missing glass-box field: {field}"

    def test_dga_score_above_threshold(self) -> None:
        """The returned dga_score is above the FLAG_THRESHOLD (0.60)."""
        from firewatch_core.analytics.dga import FLAG_THRESHOLD
        client = _client_with_store(_FakeStoreDga())
        resp = client.get("/logs/dga-suspects")
        assert resp.status_code == 200
        row = resp.json()[0]
        assert row["dga_score"] >= FLAG_THRESHOLD


# ---------------------------------------------------------------------------
# EARS-2: benign domain not returned
# ---------------------------------------------------------------------------


class TestDgaSuspectsBenignExclusion:
    """EARS-2 — benign dns_query rows are not returned."""

    def test_benign_domain_not_in_suspects(self) -> None:
        """Store with only benign dns_query rows returns empty suspects list."""
        client = _client_with_store(_FakeStoreBenign())
        resp = client.get("/logs/dga-suspects")
        assert resp.status_code == 200
        data = resp.json()
        assert data == []


# ---------------------------------------------------------------------------
# 503 when store unavailable
# ---------------------------------------------------------------------------


class TestDgaStoreMissing:
    """Route returns 503 when the event store is not available."""

    def test_503_when_no_store(self) -> None:
        """Returns 503 when event_store is None."""
        client = _client_no_store()
        resp = client.get("/logs/dga-suspects")
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# top_n parameter validation
# ---------------------------------------------------------------------------


class TestDgaTopNValidation:
    """top_n query param: 422 for out-of-range, 200 for valid."""

    def test_default_top_n_returns_200(self) -> None:
        """Request without top_n uses default and returns 200."""
        client = _client_with_store(_FakeStoreEmpty())
        resp = client.get("/logs/dga-suspects")
        assert resp.status_code == 200

    def test_top_n_1_returns_200(self) -> None:
        """top_n=1 is the minimum valid value — returns 200."""
        client = _client_with_store(_FakeStoreEmpty())
        resp = client.get("/logs/dga-suspects?top_n=1")
        assert resp.status_code == 200

    def test_top_n_1000_returns_200(self) -> None:
        """top_n=1000 is the maximum valid value — returns 200."""
        client = _client_with_store(_FakeStoreEmpty())
        resp = client.get("/logs/dga-suspects?top_n=1000")
        assert resp.status_code == 200

    def test_top_n_0_returns_422(self) -> None:
        """top_n=0 is below minimum — returns 422 (never 500)."""
        client = _client_with_store(_FakeStoreEmpty())
        resp = client.get("/logs/dga-suspects?top_n=0")
        assert resp.status_code == 422

    def test_top_n_1001_returns_422(self) -> None:
        """top_n=1001 is above maximum — returns 422 (never 500)."""
        client = _client_with_store(_FakeStoreEmpty())
        resp = client.get("/logs/dga-suspects?top_n=1001")
        assert resp.status_code == 422

    def test_top_n_non_integer_returns_422(self) -> None:
        """Non-integer top_n returns 422 (injection safety — never 500)."""
        client = _client_with_store(_FakeStoreEmpty())
        resp = client.get("/logs/dga-suspects?top_n=notanumber")
        assert resp.status_code == 422
