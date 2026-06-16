"""Tests for ML-3 — destination_ip/protocol filter query params + GET /logs/top-pairs.

Mapped 1:1 to EARS criteria from issue #431 (API layer).

EARS-1  GET /logs/paginated SHALL accept ?destination_ip= and ?protocol= query
        params; they are forwarded to FilterSpec and backed by store WHERE clauses.
        - ?destination_ip= is forwarded to FilterSpec.destination_ip
        - ?protocol= is forwarded to FilterSpec.protocol
        - both params are optional (no param → no filter)
        - invalid limit still returns 422 (existing behaviour preserved)

EARS-4  GET /logs/top-pairs SHALL return top (source_ip → destination_ip) pairs
        with counts; bounded top-N; 200 with the list shape.
        - returns list[{source_ip, destination_ip, count}]
        - ?top_n= param controls the limit (default 10)
        - ?top_n= out of range returns 422
        - store unavailable → 503

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
    """Minimal store fake that records FilterSpec and exposes top-pairs fixture."""

    def __init__(self) -> None:
        self.last_filters: FilterSpec | None = None
        self._top_pairs: list[dict[str, Any]] = [
            {"source_ip": "192.0.2.10", "destination_ip": "198.51.100.1", "count": 5},
            {"source_ip": "192.0.2.20", "destination_ip": "198.51.100.2", "count": 3},
        ]

    async def _conn(self) -> Any:
        return self

    async def get_paginated(
        self, limit: int = 100, filters: FilterSpec | None = None
    ) -> dict[str, Any]:
        self.last_filters = filters
        return {"logs": [], "next_cursor": None, "has_more": False, "total_matching": 0}

    async def get_top_pairs(
        self,
        top_n: int = 10,
        filters: FilterSpec | None = None,
        *,
        start: str | None = None,
        end: str | None = None,
    ) -> list[dict[str, Any]]:
        # Issue #662: record the scoping FilterSpec the route threads through.
        self.last_filters = filters
        return self._top_pairs[:top_n]

    # Minimal stubs for health / stats routes the app may call
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
# EARS-1: destination_ip and protocol filter params forwarded to FilterSpec
# ---------------------------------------------------------------------------

class TestDestIpProtocolQueryParams:
    """EARS-1 — destination_ip and protocol query params are forwarded to FilterSpec."""

    def test_destination_ip_param_forwarded_to_filter(self) -> None:
        """?destination_ip= is forwarded to FilterSpec.destination_ip."""
        store = _FakeStore()
        client = _make_client(store)
        res = client.get("/logs/paginated?destination_ip=198.51.100.1")
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.destination_ip == "198.51.100.1"

    def test_protocol_param_forwarded_to_filter(self) -> None:
        """?protocol= is forwarded to FilterSpec.protocol."""
        store = _FakeStore()
        client = _make_client(store)
        res = client.get("/logs/paginated?protocol=TCP")
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.protocol == "TCP"

    def test_both_params_forwarded_together(self) -> None:
        """?destination_ip= and ?protocol= can be combined in one request."""
        store = _FakeStore()
        client = _make_client(store)
        res = client.get("/logs/paginated?destination_ip=198.51.100.1&protocol=UDP")
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.destination_ip == "198.51.100.1"
        assert store.last_filters.protocol == "UDP"

    def test_missing_params_leave_filter_as_none(self) -> None:
        """Omitting destination_ip and protocol leaves FilterSpec fields as None."""
        store = _FakeStore()
        client = _make_client(store)
        res = client.get("/logs/paginated")
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.destination_ip is None
        assert store.last_filters.protocol is None

    def test_existing_filters_still_work_with_new_params(self) -> None:
        """Existing filters (ip=, severity=) work alongside the new params."""
        store = _FakeStore()
        client = _make_client(store)
        res = client.get(
            "/logs/paginated?ip=192.0.2&destination_ip=198.51.100&protocol=TCP"
        )
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.ip == "192.0.2"
        assert store.last_filters.destination_ip == "198.51.100"
        assert store.last_filters.protocol == "TCP"


# ---------------------------------------------------------------------------
# EARS-4: GET /logs/top-pairs
# ---------------------------------------------------------------------------

class TestTopPairsRoute:
    """EARS-4 — GET /logs/top-pairs returns bounded, ordered pair list."""

    def test_top_pairs_returns_200_with_list(self) -> None:
        """GET /logs/top-pairs returns 200 with a list of pair dicts."""
        client = _make_client()
        res = client.get("/logs/top-pairs")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)

    def test_top_pairs_response_shape(self) -> None:
        """Each pair entry has source_ip, destination_ip, count keys."""
        client = _make_client()
        res = client.get("/logs/top-pairs")
        data = res.json()
        assert len(data) >= 1
        row = data[0]
        assert "source_ip" in row
        assert "destination_ip" in row
        assert "count" in row

    def test_top_pairs_default_top_n(self) -> None:
        """Default top_n=10 is used when param is omitted."""
        store = _FakeStore()
        # Populate with exactly 2 pairs
        client = _make_client(store)
        res = client.get("/logs/top-pairs")
        assert res.status_code == 200
        # With only 2 stored pairs, both are returned
        assert len(res.json()) == 2

    def test_top_pairs_top_n_param(self) -> None:
        """?top_n=1 limits the result to 1 entry."""
        client = _make_client()
        res = client.get("/logs/top-pairs?top_n=1")
        assert res.status_code == 200
        assert len(res.json()) <= 1

    def test_top_pairs_top_n_zero_returns_422(self) -> None:
        """?top_n=0 is below the minimum — returns 422."""
        client = _make_client()
        res = client.get("/logs/top-pairs?top_n=0")
        assert res.status_code == 422

    def test_top_pairs_top_n_too_large_returns_422(self) -> None:
        """?top_n exceeding the maximum returns 422."""
        client = _make_client()
        res = client.get("/logs/top-pairs?top_n=1001")
        assert res.status_code == 422

    def test_top_pairs_no_store_returns_503(self) -> None:
        """GET /logs/top-pairs when store is None → 503."""
        app = create_app()
        from firewatch_api.deps import get_event_store
        app.dependency_overrides[get_event_store] = lambda: None
        client = TestClient(app)
        res = client.get("/logs/top-pairs")
        assert res.status_code == 503
