"""Tests for ML-13 — JA4+ fingerprint facet API routes (issue #441).

Mapped 1:1 to EARS criteria from issue #441 (API layer).

EARS-1  GET /logs/paginated SHALL accept ?tls_ja4= query param; forwarded to
        FilterSpec and backed by store WHERE clause.
        - ?tls_ja4= is forwarded to FilterSpec.tls_ja4
        - param is optional (no param -> no filter)
        - existing filters still work alongside tls_ja4=

EARS-1  GET /logs/top-ja4 SHALL return top JA4 fingerprints with counts;
        bounded top-N; 200 with the list shape.
        - returns list[{tls_ja4, count}]
        - ?top_n= controls the limit (default 10)
        - ?top_n=0 returns 422 (below ge=1)
        - ?top_n=101 returns 422 (above le=100)
        - store unavailable -> 503
        - empty result (all NULL tls_ja4) returns [] gracefully

EARS-2  NULL tls_ja4 = chip absent (honest); degrade-to-empty semantics.
        - GET /logs/top-ja4 returns [] when store has no JA4 rows (graceful)

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
    """Minimal store fake that records FilterSpec and exposes top-ja4 fixture."""

    def __init__(self) -> None:
        self.last_filters: FilterSpec | None = None
        self._top_ja4: list[dict[str, Any]] = [
            {"tls_ja4": "t13d1516h2_8daaf6152771_02713d6af862", "count": 12},
            {"tls_ja4": "t13d201100h2_40348e13a07b_f11594a38c92", "count": 4},
        ]

    async def get_paginated(
        self, limit: int = 100, filters: FilterSpec | None = None
    ) -> dict[str, Any]:
        self.last_filters = filters
        return {"logs": [], "next_cursor": None, "has_more": False, "total_matching": 0}

    async def get_top_ja4(self, top_n: int = 10) -> list[dict[str, Any]]:
        return self._top_ja4[:top_n]

    async def get_top_pairs(self, top_n: int = 10) -> list[dict[str, Any]]:
        return []

    async def get_top_talkers(self, top_n: int = 10) -> list[dict[str, Any]]:
        return []

    async def get_protocol_mix(self, top_n: int = 10) -> list[dict[str, Any]]:
        return []

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
# EARS-1: tls_ja4 filter param forwarded to FilterSpec
# ---------------------------------------------------------------------------


class TestTlsJa4QueryParam:
    """EARS-1 — tls_ja4 query param is forwarded to FilterSpec."""

    def test_tls_ja4_param_forwarded_to_filter(self) -> None:
        """?tls_ja4= is forwarded to FilterSpec.tls_ja4."""
        store = _FakeStore()
        client = _make_client(store)
        fp = "t13d1516h2_8daaf6152771_02713d6af862"
        res = client.get(f"/logs/paginated?tls_ja4={fp}")
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.tls_ja4 == fp

    def test_missing_tls_ja4_leaves_filter_as_none(self) -> None:
        """Omitting tls_ja4 leaves FilterSpec.tls_ja4 as None."""
        store = _FakeStore()
        client = _make_client(store)
        res = client.get("/logs/paginated")
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.tls_ja4 is None

    def test_tls_ja4_combines_with_existing_filters(self) -> None:
        """tls_ja4 filter combines with existing filters (ip=, severity=)."""
        store = _FakeStore()
        client = _make_client(store)
        fp = "t13d1516h2_8daaf6152771_02713d6af862"
        res = client.get(
            f"/logs/paginated?ip=192.0.2&severity=high&tls_ja4={fp}"
        )
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.ip == "192.0.2"
        assert store.last_filters.severity == "high"
        assert store.last_filters.tls_ja4 == fp

    def test_tls_ja4_combines_with_destination_ip(self) -> None:
        """tls_ja4 combines with destination_ip (both ML-13 and ML-3 filters active)."""
        store = _FakeStore()
        client = _make_client(store)
        fp = "t13d1516h2_8daaf6152771_02713d6af862"
        res = client.get(
            f"/logs/paginated?destination_ip=198.51.100&tls_ja4={fp}"
        )
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.destination_ip == "198.51.100"
        assert store.last_filters.tls_ja4 == fp


# ---------------------------------------------------------------------------
# EARS-1: GET /logs/top-ja4 route
# ---------------------------------------------------------------------------


class TestTopJa4Route:
    """EARS-1 — GET /logs/top-ja4 returns bounded, ordered fingerprint list."""

    def test_top_ja4_returns_200_with_list(self) -> None:
        """GET /logs/top-ja4 returns 200 with a list of fingerprint dicts."""
        client = _make_client()
        res = client.get("/logs/top-ja4")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)

    def test_top_ja4_response_shape(self) -> None:
        """Each fingerprint entry has tls_ja4 and count keys."""
        client = _make_client()
        res = client.get("/logs/top-ja4")
        data = res.json()
        assert len(data) >= 1
        row = data[0]
        assert "tls_ja4" in row
        assert "count" in row

    def test_top_ja4_default_top_n(self) -> None:
        """Default top_n=10 is used when param is omitted."""
        store = _FakeStore()
        # Store has exactly 2 fingerprints
        client = _make_client(store)
        res = client.get("/logs/top-ja4")
        assert res.status_code == 200
        assert len(res.json()) == 2

    def test_top_ja4_top_n_param(self) -> None:
        """?top_n=1 limits the result to 1 entry."""
        client = _make_client()
        res = client.get("/logs/top-ja4?top_n=1")
        assert res.status_code == 200
        assert len(res.json()) <= 1

    def test_top_ja4_top_n_zero_returns_422(self) -> None:
        """?top_n=0 is below the minimum — returns 422."""
        client = _make_client()
        res = client.get("/logs/top-ja4?top_n=0")
        assert res.status_code == 422

    def test_top_ja4_top_n_too_large_returns_422(self) -> None:
        """?top_n=101 exceeds the maximum — returns 422."""
        client = _make_client()
        res = client.get("/logs/top-ja4?top_n=101")
        assert res.status_code == 422

    def test_top_ja4_no_store_returns_503(self) -> None:
        """GET /logs/top-ja4 when store is None -> 503."""
        app = create_app()
        from firewatch_api.deps import get_event_store
        app.dependency_overrides[get_event_store] = lambda: None
        client = TestClient(app)
        res = client.get("/logs/top-ja4")
        assert res.status_code == 503


# ---------------------------------------------------------------------------
# EARS-2: empty/all-null JA4 degrades gracefully
# ---------------------------------------------------------------------------


class TestTopJa4EmptyDegrades:
    """EARS-2 — when all tls_ja4 are NULL, top-ja4 returns [] honestly."""

    def test_top_ja4_empty_store_returns_empty_list(self) -> None:
        """GET /logs/top-ja4 returns [] when store has no JA4 fingerprints."""
        store = _FakeStore()
        store._top_ja4 = []  # simulate all-null sensor data
        client = _make_client(store)
        res = client.get("/logs/top-ja4")
        assert res.status_code == 200
        assert res.json() == []

    def test_top_ja4_empty_is_not_an_error(self) -> None:
        """An empty top-ja4 response is 200 OK — degrade-to-empty, not 4xx."""
        store = _FakeStore()
        store._top_ja4 = []
        client = _make_client(store)
        res = client.get("/logs/top-ja4")
        assert res.status_code == 200
