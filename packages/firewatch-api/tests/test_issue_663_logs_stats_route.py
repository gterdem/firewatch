"""Tests for issue #663 — GET /logs/stats route (filter-scoped totals).

Mapped 1:1 to EARS acceptance criteria from issue #663 (API layer).

EARS-1  GET /logs/stats with no facets SHALL return true whole-store counts.
EARS-2  GET /logs/stats with FilterSpec facets SHALL return filter-scoped counts.
EARS-3  Counts SHALL NOT be derived from any top-N list (validated at store layer;
        here we verify the route passes the FilterSpec through correctly).
EARS-4  Attacker-controlled facets SHALL be ?-bound (tested at store layer;
        here we verify the route does not reject or mangle them before forwarding).
EARS-5  IF the store is unavailable, the endpoint SHALL return 503.
EARS-6  start/end ISO params are forwarded; invalid ISO value returns 422.

All IPs use RFC 5737 / RFC 1918 documentation ranges — no real/routable IPs.
"""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from firewatch_sdk.models import FilterSpec

from firewatch_api.app import create_app
from firewatch_api.deps import get_event_store


# ---------------------------------------------------------------------------
# Fake store
# ---------------------------------------------------------------------------


class _FakeStore:
    """Minimal store fake that records calls to get_logs_stats."""

    def __init__(
        self,
        *,
        stats: dict[str, Any] | None = None,
    ) -> None:
        self.last_filters: FilterSpec | None = None
        self.last_start: str | None = None
        self.last_end: str | None = None
        self._stats: dict[str, Any] = stats or {
            "total_events": 42,
            "blocked_events": 7,
            "distinct_ips": 5,
            "present_source_types": ["azure_waf", "suricata"],
        }

    async def get_logs_stats(
        self,
        filters: FilterSpec | None = None,
        *,
        start: str | None = None,
        end: str | None = None,
    ) -> dict[str, Any]:
        self.last_filters = filters
        self.last_start = start
        self.last_end = end
        return self._stats

    # Minimal stubs for other routes the app wires up
    async def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        return []

    async def get_all_ips(self) -> list[str]:
        return []

    async def get_categories(self) -> list[dict[str, Any]]:
        return []

    async def get_category_summary(self) -> list[dict[str, Any]]:
        return []

    async def get_timeline(
        self, start: str | None = None, end: str | None = None
    ) -> list[dict[str, Any]]:
        return []

    async def get_stats(self) -> dict[str, Any]:
        return {
            "total_logs": 0,
            "total_ips": 0,
            "blocked_percentage": 0.0,
            "top_attack_types": [],
            "last_updated": None,
        }

    async def source_health(self) -> list[dict[str, Any]]:
        return []

    async def get_analytics_geo(self) -> list[dict[str, Any]]:
        return []

    async def get_analytics_summary(self) -> dict[str, Any]:
        return {
            "total_ips": 0,
            "total_events": 0,
            "total_blocked": 0,
            "block_rate": 0.0,
            "top_country": "Unknown",
            "unique_countries": 0,
            "top_rule": "",
        }

    async def get_categories_timeline(
        self, start: str | None = None, end: str | None = None
    ) -> list[dict[str, Any]]:
        return []

    async def get_attack_dispositions(self, top_n: int = 5) -> list[dict[str, Any]]:
        return []

    async def get_rule_descriptions(self) -> dict[str, str]:
        return {}


def _make_client(store: _FakeStore | None = None) -> tuple[TestClient, _FakeStore]:
    s = store or _FakeStore()
    app = create_app()
    app.dependency_overrides[get_event_store] = lambda: s
    return TestClient(app), s


# ---------------------------------------------------------------------------
# EARS-1: whole-store counts when no facets supplied
# ---------------------------------------------------------------------------


class TestLogsStatsRouteNoFilter:
    """EARS-1 — endpoint returns real whole-store counts."""

    def test_returns_200_with_correct_shape(self) -> None:
        """GET /logs/stats returns 200 with the four expected fields."""
        client, _ = _make_client()
        res = client.get("/logs/stats")
        assert res.status_code == 200
        data = res.json()
        assert "total_events" in data
        assert "blocked_events" in data
        assert "distinct_ips" in data
        assert "present_source_types" in data

    def test_returns_store_values_verbatim(self) -> None:
        """The route returns exactly the values the store method produces."""
        client, _ = _make_client()
        res = client.get("/logs/stats")
        data = res.json()
        assert data["total_events"] == 42
        assert data["blocked_events"] == 7
        assert data["distinct_ips"] == 5
        assert data["present_source_types"] == ["azure_waf", "suricata"]

    def test_no_filter_passes_empty_filterspec_to_store(self) -> None:
        """No query params -> store receives a FilterSpec with all-None fields."""
        client, store = _make_client()
        client.get("/logs/stats")
        assert store.last_filters is not None
        # All FilterSpec fields must be None (no filtering)
        f = store.last_filters
        assert f.ip is None
        assert f.action is None
        assert f.severity is None
        assert f.source_type is None
        assert f.category is None


# ---------------------------------------------------------------------------
# EARS-2: filter-scoped counts
# ---------------------------------------------------------------------------


class TestLogsStatsRouteWithFilters:
    """EARS-2 — facet params are forwarded to the store as FilterSpec."""

    def test_source_type_param_forwarded(self) -> None:
        """?source_type= is forwarded to FilterSpec.source_type."""
        client, store = _make_client()
        res = client.get("/logs/stats?source_type=suricata")
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.source_type == "suricata"

    def test_ip_param_forwarded(self) -> None:
        """?ip= is forwarded to FilterSpec.ip."""
        client, store = _make_client()
        res = client.get("/logs/stats?ip=192.0.2")
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.ip == "192.0.2"

    def test_action_param_forwarded(self) -> None:
        """?action=blocked is forwarded to FilterSpec.action."""
        client, store = _make_client()
        res = client.get("/logs/stats?action=blocked")
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.action == "blocked"

    def test_severity_param_forwarded(self) -> None:
        """?severity=critical is forwarded to FilterSpec.severity."""
        client, store = _make_client()
        res = client.get("/logs/stats?severity=critical")
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.severity == "critical"

    def test_category_param_forwarded(self) -> None:
        """?category= is forwarded to FilterSpec.category."""
        client, store = _make_client()
        res = client.get("/logs/stats?category=SQL+Injection")
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.category == "SQL Injection"

    def test_multiple_params_forwarded_together(self) -> None:
        """Multiple facet params can be combined in one request."""
        client, store = _make_client()
        res = client.get("/logs/stats?source_type=suricata&severity=high&action=BLOCK")
        assert res.status_code == 200
        f = store.last_filters
        assert f is not None
        assert f.source_type == "suricata"
        assert f.severity == "high"
        assert f.action == "BLOCK"

    def test_destination_ip_param_forwarded(self) -> None:
        """?destination_ip= is forwarded to FilterSpec.destination_ip."""
        client, store = _make_client()
        res = client.get("/logs/stats?destination_ip=198.51.100")
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.destination_ip == "198.51.100"

    def test_protocol_param_forwarded(self) -> None:
        """?protocol= is forwarded to FilterSpec.protocol."""
        client, store = _make_client()
        res = client.get("/logs/stats?protocol=TCP")
        assert res.status_code == 200
        assert store.last_filters is not None
        assert store.last_filters.protocol == "TCP"


# ---------------------------------------------------------------------------
# EARS-5: store unavailable → 503
# ---------------------------------------------------------------------------


class TestLogsStatsRouteNoStore:
    """EARS-5 — 503 when the event store is not available."""

    def test_no_store_returns_503(self) -> None:
        """GET /logs/stats returns 503 when the store dependency resolves to None."""
        app = create_app()
        app.dependency_overrides[get_event_store] = lambda: None
        client = TestClient(app)
        res = client.get("/logs/stats")
        assert res.status_code == 503


# ---------------------------------------------------------------------------
# EARS-6: start/end forwarding and ISO validation
# ---------------------------------------------------------------------------


class TestLogsStatsStartEnd:
    """EARS-6 — start/end params are forwarded; invalid ISO returns 422."""

    def test_valid_start_end_forwarded_to_store(self) -> None:
        """Valid start/end ISO strings are forwarded to the store."""
        client, store = _make_client()
        res = client.get(
            "/logs/stats"
            "?start=2026-06-13T00:00:00%2B00:00"
            "&end=2026-06-13T23:59:59%2B00:00"
        )
        assert res.status_code == 200
        assert store.last_start is not None
        assert store.last_end is not None

    def test_invalid_start_returns_422(self) -> None:
        """A non-ISO start value returns 422 (ADR-0029 D3)."""
        client, _ = _make_client()
        res = client.get("/logs/stats?start=not-a-date")
        assert res.status_code == 422

    def test_invalid_end_returns_422(self) -> None:
        """A non-ISO end value returns 422 (ADR-0029 D3)."""
        client, _ = _make_client()
        res = client.get("/logs/stats?end=yesterday")
        assert res.status_code == 422

    def test_omitting_start_end_leaves_store_params_none(self) -> None:
        """Omitting start/end means the store receives None for both."""
        client, store = _make_client()
        client.get("/logs/stats")
        assert store.last_start is None
        assert store.last_end is None
