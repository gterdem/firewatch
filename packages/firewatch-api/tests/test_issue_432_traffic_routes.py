"""Tests for ML-4 — GET /logs/top-talkers + GET /logs/protocol-mix API routes.

Mapped 1:1 to EARS criteria from issue #432.

EARS-2  GET /logs/top-talkers and GET /logs/protocol-mix SHALL return GROUP-BY
        counts (mirroring get_categories pattern):
        - returns list[{source_ip, count, blocked}] / list[{protocol, count}]
        - ?top_n= parameter controls the limit
        - ?top_n= out of range returns 422
        - store unavailable → 503

Store-layer tests (get_top_talkers / get_protocol_mix) are in:
  packages/firewatch-core/tests/test_issue_432_traffic_shape.py

All IPs use RFC 5737 / RFC 1918 ranges — no real/routable IPs.
"""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from firewatch_sdk.models import FilterSpec

from firewatch_api.app import create_app


# ---------------------------------------------------------------------------
# Fake store
# ---------------------------------------------------------------------------

class _FakeStore:
    """Minimal store fake — exposes top-talkers and protocol-mix fixtures."""

    def __init__(self) -> None:
        self.last_filters: FilterSpec | None = None
        self._top_talkers: list[dict[str, Any]] = [
            {"source_ip": "192.0.2.10", "count": 500, "blocked": 200},
            {"source_ip": "192.0.2.20", "count": 300, "blocked": 100},
        ]
        self._protocol_mix: list[dict[str, Any]] = [
            {"protocol": "TCP", "count": 800},
            {"protocol": "(unknown)", "count": 150},
        ]

    async def get_paginated(
        self, limit: int = 100, filters: FilterSpec | None = None
    ) -> dict[str, Any]:
        self.last_filters = filters
        return {"logs": [], "next_cursor": None, "has_more": False, "total_matching": 0}

    async def get_top_pairs(
        self, top_n: int = 10, filters: FilterSpec | None = None,
        *, start: str | None = None, end: str | None = None,
    ) -> list[dict[str, Any]]:
        self.last_filters = filters
        return []

    async def get_top_talkers(
        self, top_n: int = 10, filters: FilterSpec | None = None,
        *, start: str | None = None, end: str | None = None,
    ) -> list[dict[str, Any]]:
        # Issue #662: record the scoping FilterSpec the route threads through.
        self.last_filters = filters
        return self._top_talkers[:top_n]

    async def get_protocol_mix(
        self, top_n: int = 10, filters: FilterSpec | None = None,
        *, start: str | None = None, end: str | None = None,
    ) -> list[dict[str, Any]]:
        # Issue #662: record the scoping FilterSpec the route threads through.
        self.last_filters = filters
        return self._protocol_mix[:top_n]

    async def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        return []

    async def get_all_ips(self) -> list[str]:
        return []

    async def get_by_ip_raw(self, ip: str) -> list[dict[str, Any]]:
        return []

    async def get_categories(self) -> list[dict[str, Any]]:
        return []

    async def get_category_summary(self) -> list[dict[str, Any]]:
        return []

    async def get_timeline(
        self, start: str | None = None, end: str | None = None
    ) -> list[dict[str, Any]]:
        return []

    async def get_rule_descriptions(self) -> dict[str, str]:
        return {}

    async def get_analytics_geo(self) -> list[dict[str, Any]]:
        return []

    async def get_analytics_summary(self) -> dict[str, Any]:
        return {
            "total_ips": 0, "total_events": 0, "total_blocked": 0,
            "block_rate": 0.0, "top_country": "Unknown",
            "unique_countries": 0, "top_rule": "",
        }

    async def get_categories_timeline(
        self, start: str | None = None, end: str | None = None
    ) -> list[dict[str, Any]]:
        return []

    async def get_attack_dispositions(self, top_n: int = 5) -> list[dict[str, Any]]:
        return []

    async def get_stats(self) -> dict[str, Any]:
        return {"total_logs": 0, "total_ips": 0, "blocked_percentage": 0.0,
                "top_attack_types": [], "last_updated": None}

    async def source_health(self) -> list[dict[str, Any]]:
        return []


def _make_client(store: _FakeStore | None = None) -> TestClient:
    s = store or _FakeStore()
    app = create_app()
    app.dependency_overrides = {}
    from firewatch_api.deps import get_event_store
    app.dependency_overrides[get_event_store] = lambda: s
    return TestClient(app)


# ---------------------------------------------------------------------------
# GET /logs/top-talkers
# ---------------------------------------------------------------------------

class TestTopTalkersRoute:
    """GET /logs/top-talkers responds 200 and returns the correct shape."""

    def test_returns_200_with_list(self) -> None:
        """GET /logs/top-talkers returns 200 with a list of talker rows."""
        client = _make_client()
        resp = client.get("/logs/top-talkers")
        assert resp.status_code == 200
        rows = resp.json()
        assert isinstance(rows, list)

    def test_response_has_required_fields(self) -> None:
        """Each row has source_ip, count, and blocked fields."""
        client = _make_client()
        resp = client.get("/logs/top-talkers")
        rows = resp.json()
        assert len(rows) > 0
        for row in rows:
            assert "source_ip" in row
            assert "count" in row
            assert "blocked" in row

    def test_top_n_parameter_limits_results(self) -> None:
        """?top_n=1 returns at most 1 row."""
        client = _make_client()
        resp = client.get("/logs/top-talkers?top_n=1")
        assert resp.status_code == 200
        rows = resp.json()
        assert len(rows) <= 1

    def test_top_n_zero_returns_422(self) -> None:
        """?top_n=0 returns 422 (below ge=1 bound)."""
        client = _make_client()
        resp = client.get("/logs/top-talkers?top_n=0")
        assert resp.status_code == 422

    def test_top_n_above_max_returns_422(self) -> None:
        """?top_n=1001 returns 422 (above le=1000 bound)."""
        client = _make_client()
        resp = client.get("/logs/top-talkers?top_n=1001")
        assert resp.status_code == 422

    def test_store_unavailable_returns_503(self) -> None:
        """When the store is None (unavailable), the route returns 503."""
        app = create_app()
        app.dependency_overrides = {}
        from firewatch_api.deps import get_event_store
        app.dependency_overrides[get_event_store] = lambda: None
        client = TestClient(app)
        resp = client.get("/logs/top-talkers")
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# GET /logs/protocol-mix
# ---------------------------------------------------------------------------

class TestProtocolMixRoute:
    """GET /logs/protocol-mix responds 200 and returns the correct shape."""

    def test_returns_200_with_list(self) -> None:
        """GET /logs/protocol-mix returns 200 with a list of protocol rows."""
        client = _make_client()
        resp = client.get("/logs/protocol-mix")
        assert resp.status_code == 200
        rows = resp.json()
        assert isinstance(rows, list)

    def test_response_has_required_fields(self) -> None:
        """Each row has protocol and count fields."""
        client = _make_client()
        resp = client.get("/logs/protocol-mix")
        rows = resp.json()
        assert len(rows) > 0
        for row in rows:
            assert "protocol" in row
            assert "count" in row

    def test_unknown_sentinel_present_when_null_rows(self) -> None:
        """'(unknown)' sentinel is present in response when store has NULL protocol rows."""
        client = _make_client()
        resp = client.get("/logs/protocol-mix")
        rows = resp.json()
        protocols = [r["protocol"] for r in rows]
        assert "(unknown)" in protocols

    def test_top_n_parameter_limits_results(self) -> None:
        """?top_n=1 returns at most 1 row."""
        client = _make_client()
        resp = client.get("/logs/protocol-mix?top_n=1")
        assert resp.status_code == 200
        rows = resp.json()
        assert len(rows) <= 1

    def test_top_n_zero_returns_422(self) -> None:
        """?top_n=0 returns 422 (below ge=1 bound)."""
        client = _make_client()
        resp = client.get("/logs/protocol-mix?top_n=0")
        assert resp.status_code == 422

    def test_top_n_above_max_returns_422(self) -> None:
        """?top_n=101 returns 422 (above le=100 bound)."""
        client = _make_client()
        resp = client.get("/logs/protocol-mix?top_n=101")
        assert resp.status_code == 422

    def test_store_unavailable_returns_503(self) -> None:
        """When the store is None (unavailable), the route returns 503."""
        app = create_app()
        app.dependency_overrides = {}
        from firewatch_api.deps import get_event_store
        app.dependency_overrides[get_event_store] = lambda: None
        client = TestClient(app)
        resp = client.get("/logs/protocol-mix")
        assert resp.status_code == 503
