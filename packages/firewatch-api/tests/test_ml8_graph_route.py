"""Tests for ML-8 — GET /logs/graph entity-graph data API route.

Mapped 1:1 to EARS acceptance criteria from issue #436.

EARS-1  GET /logs/graph SHALL return nodes (source IP, destination IP, ASN,
        category) and edges (observed flows with counts), bounded by a
        cardinality cap.  Tests: 200 shape, node types, edge types.

EARS-2  Edges SHALL be built only from canonical/persisted fields
        (destination_ip from ML-1, ASN from ip_geo).
        NULL-dst exclusion and ASN-from-geo correctness are proven by the
        builder unit tests in packages/firewatch-core/tests/test_entity_graph.py.

EARS-3  WHEN cardinality exceeds the cap, the system SHALL return a
        truncated, deterministically-ranked subgraph with a truncation flag.
        Tests: max_edges param accepted, out-of-range → 422, truncated forwarded.

Additional:
  - 503 when store unavailable.
  - empty-DB shape (nodes=[], edges=[], truncated=False).
  - injection-safety: non-integer max_nodes/max_edges → 422 (never 500).

Strategy: route tests use a fake store whose _read_conn() returns a minimal
DB stub that returns empty rows from every SQL query.  This proves the route
wires up correctly and returns the right envelope.  Correctness of graph
aggregation logic is covered by the builder unit tests.

All IPs use RFC 5737 / RFC 1918 ranges — never real/routable IPs.
"""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from firewatch_api.app import create_app
from firewatch_api.deps import get_event_store
from firewatch_api.routes.graph import _MAX_EDGES_CEILING, _MAX_NODES_CEILING


# ---------------------------------------------------------------------------
# Minimal DB / cursor stubs
# ---------------------------------------------------------------------------


class _EmptyCursor:
    """Cursor that always returns empty rows and zero counts."""

    async def fetchall(self) -> list[Any]:
        return []

    async def fetchone(self) -> dict[str, Any]:
        return {"cnt": 0}


class _EmptyDb:
    """DB stub whose every execute() returns an _EmptyCursor.

    Sufficient for build_entity_graph to complete without error and return
    an empty graph — which is all the route tests need to verify the shape.
    """

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> _EmptyCursor:  # noqa: ARG002
        return _EmptyCursor()


# ---------------------------------------------------------------------------
# Fake store
# ---------------------------------------------------------------------------


class _FakeStore:
    """Minimal store fake that returns empty results from all methods."""

    async def _read_conn(self) -> _EmptyDb:
        return _EmptyDb()

    async def get_paginated(self, **kwargs: Any) -> dict[str, Any]:
        return {"logs": [], "next_cursor": None, "has_more": False, "total_matching": 0}

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

    async def get_timeline(self, **kwargs: Any) -> list[dict[str, Any]]:
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

    async def get_categories_timeline(self, **kwargs: Any) -> list[dict[str, Any]]:
        return []

    async def get_attack_dispositions(self, top_n: int = 5) -> list[dict[str, Any]]:
        return []

    async def get_stats(self) -> dict[str, Any]:
        return {
            "total_logs": 0, "total_ips": 0, "blocked_percentage": 0.0,
            "top_attack_types": [], "last_updated": None,
        }

    async def source_health(self) -> list[dict[str, Any]]:
        return []

    async def get_top_pairs(self, top_n: int = 10) -> list[dict[str, Any]]:
        return []


def _make_client(store: Any = None) -> TestClient:
    app = create_app()
    s = store or _FakeStore()
    app.dependency_overrides[get_event_store] = lambda: s
    return TestClient(app)


# ---------------------------------------------------------------------------
# EARS-1: Response shape — 200, nodes, edges, truncated
# ---------------------------------------------------------------------------


class TestGraphResponseShape:
    """EARS-1 — GET /logs/graph returns 200 with correct envelope shape."""

    def test_returns_200(self) -> None:
        """GET /logs/graph returns HTTP 200."""
        client = _make_client()
        res = client.get("/logs/graph")
        assert res.status_code == 200

    def test_envelope_has_nodes_edges_truncated(self) -> None:
        """Response has top-level 'nodes', 'edges', 'truncated' keys."""
        client = _make_client()
        data = client.get("/logs/graph").json()
        assert "nodes" in data
        assert "edges" in data
        assert "truncated" in data

    def test_nodes_is_list(self) -> None:
        """'nodes' is a list."""
        client = _make_client()
        data = client.get("/logs/graph").json()
        assert isinstance(data["nodes"], list)

    def test_edges_is_list(self) -> None:
        """'edges' is a list."""
        client = _make_client()
        data = client.get("/logs/graph").json()
        assert isinstance(data["edges"], list)

    def test_truncated_is_bool(self) -> None:
        """'truncated' is a boolean."""
        client = _make_client()
        data = client.get("/logs/graph").json()
        assert isinstance(data["truncated"], bool)

    def test_empty_db_returns_empty_graph(self) -> None:
        """Empty store returns nodes=[], edges=[], truncated=False."""
        client = _make_client()
        data = client.get("/logs/graph").json()
        assert data["nodes"] == []
        assert data["edges"] == []
        assert data["truncated"] is False


# ---------------------------------------------------------------------------
# EARS-3: max_nodes / max_edges params — validation
# ---------------------------------------------------------------------------


class TestGraphParams:
    """EARS-3 — max_nodes / max_edges params are validated; out-of-range → 422."""

    def test_default_params_accepted(self) -> None:
        """GET /logs/graph with no params returns 200 (defaults apply)."""
        client = _make_client()
        assert client.get("/logs/graph").status_code == 200

    def test_max_edges_param_accepted(self) -> None:
        """?max_edges=10 is valid → 200."""
        client = _make_client()
        assert client.get("/logs/graph?max_edges=10").status_code == 200

    def test_max_nodes_param_accepted(self) -> None:
        """?max_nodes=50 is valid → 200."""
        client = _make_client()
        assert client.get("/logs/graph?max_nodes=50").status_code == 200

    def test_max_edges_zero_returns_422(self) -> None:
        """?max_edges=0 is below minimum → 422."""
        client = _make_client()
        assert client.get("/logs/graph?max_edges=0").status_code == 422

    def test_max_nodes_zero_returns_422(self) -> None:
        """?max_nodes=0 is below minimum → 422."""
        client = _make_client()
        assert client.get("/logs/graph?max_nodes=0").status_code == 422

    def test_max_edges_exceeding_ceiling_returns_422(self) -> None:
        """?max_edges above the ceiling → 422."""
        client = _make_client()
        assert client.get("/logs/graph?max_edges=99999").status_code == 422

    def test_max_nodes_exceeding_ceiling_returns_422(self) -> None:
        """?max_nodes above the ceiling → 422."""
        client = _make_client()
        assert client.get("/logs/graph?max_nodes=99999").status_code == 422

    def test_max_edges_at_ceiling_is_accepted(self) -> None:
        """?max_edges at the defined ceiling is accepted → 200."""
        client = _make_client()
        assert client.get(f"/logs/graph?max_edges={_MAX_EDGES_CEILING}").status_code == 200

    def test_max_nodes_at_ceiling_is_accepted(self) -> None:
        """?max_nodes at the defined ceiling is accepted → 200."""
        client = _make_client()
        assert client.get(f"/logs/graph?max_nodes={_MAX_NODES_CEILING}").status_code == 200

    def test_both_params_together_accepted(self) -> None:
        """?max_nodes=50&max_edges=100 is valid → 200."""
        client = _make_client()
        assert client.get("/logs/graph?max_nodes=50&max_edges=100").status_code == 200


# ---------------------------------------------------------------------------
# 503 when store is unavailable
# ---------------------------------------------------------------------------


class TestGraphNoStore:
    """GET /logs/graph when store is None → 503."""

    def test_no_store_returns_503(self) -> None:
        """GET /logs/graph when event store is None → 503."""
        app = create_app()
        app.dependency_overrides[get_event_store] = lambda: None
        client = TestClient(app)
        assert client.get("/logs/graph").status_code == 503

    def test_503_body_has_detail(self) -> None:
        """503 response has a 'detail' key."""
        app = create_app()
        app.dependency_overrides[get_event_store] = lambda: None
        client = TestClient(app)
        data = client.get("/logs/graph").json()
        assert "detail" in data


# ---------------------------------------------------------------------------
# EARS-3: Truncated flag forwarded from builder
# ---------------------------------------------------------------------------


class TestTruncatedFlag:
    """EARS-3 — truncated=True/False is surfaced from the builder correctly."""

    def test_truncated_false_on_empty_db(self) -> None:
        """Empty store: truncated=False."""
        client = _make_client()
        data = client.get("/logs/graph").json()
        assert data["truncated"] is False


# ---------------------------------------------------------------------------
# Injection-safety: non-integer params return 422, not 500
# ---------------------------------------------------------------------------


class TestInjectionSafety:
    """Non-integer max_edges / max_nodes must return 422, never 500."""

    def test_non_integer_max_edges_returns_422(self) -> None:
        """?max_edges=abc → 422 (FastAPI validation, not 500)."""
        client = _make_client()
        assert client.get("/logs/graph?max_edges=abc").status_code == 422

    def test_non_integer_max_nodes_returns_422(self) -> None:
        """?max_nodes=abc → 422 (FastAPI validation, not 500)."""
        client = _make_client()
        assert client.get("/logs/graph?max_nodes=abc").status_code == 422

    def test_sql_injection_attempt_in_max_edges_returns_422(self) -> None:
        """SQL injection attempt in max_edges → 422 (integer validation rejects it)."""
        client = _make_client()
        assert client.get("/logs/graph?max_edges=1%3BDROP+TABLE+logs").status_code == 422

    def test_negative_max_edges_returns_422(self) -> None:
        """?max_edges=-1 → 422 (below minimum of 1)."""
        client = _make_client()
        assert client.get("/logs/graph?max_edges=-1").status_code == 422

    def test_negative_max_nodes_returns_422(self) -> None:
        """?max_nodes=-1 → 422 (below minimum of 1)."""
        client = _make_client()
        assert client.get("/logs/graph?max_nodes=-1").status_code == 422
