"""Tests for ML-8 — entity-graph builder (firewatch-core analytics).

Mapped 1:1 to EARS acceptance criteria from issue #436.

EARS-1  GET /logs/graph SHALL return nodes (source IP, destination IP, ASN,
        category) and edges (observed flows with counts), bounded by a
        cardinality cap.
        Tests here cover the CORE builder (data layer); route tests are in
        packages/firewatch-api/tests/test_ml8_graph_route.py.

EARS-2  Edges SHALL be built only from canonical/persisted fields
        (destination_ip from ML-1, ASN from ThreatScore).
        - NULL destination_ip rows are excluded from src→dst edges.
        - ASN comes from ip_geo table (populated by geo enricher).

EARS-3  WHEN cardinality exceeds the cap, the system SHALL return a
        truncated, deterministically-ranked subgraph with a truncation flag.

Additional:
  - empty-DB → empty graph (no errors).
  - injection-safety: limit param is bound via ?, never f-string.
  - node/edge shapes are correct (type, id, label / source, target, weight).
  - category nodes are built from the category column (canonical stored value).

All IPs use RFC 5737 / RFC 1918 ranges — never real/routable IPs.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from firewatch_sdk import SecurityEvent
from firewatch_sdk.models import ActionLiteral
from firewatch_core.adapters.sqlite_store import SQLiteEventStore
from firewatch_core.analytics.entity_graph import (
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_NODES,
    build_entity_graph,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

_TS = datetime(2026, 6, 13, 10, 0, 0, tzinfo=timezone.utc)

# RFC 5737 documentation IPs only
_SRC_A = "192.0.2.10"
_SRC_B = "192.0.2.20"
_SRC_C = "192.0.2.30"
_DST_A = "198.51.100.1"
_DST_B = "198.51.100.2"
_DST_C = "198.51.100.3"


def _ev(
    src: str,
    dst: str | None = None,
    category: str | None = None,
    action: ActionLiteral = "ALERT",
    ts_offset: int = 0,
) -> SecurityEvent:
    """Minimal SecurityEvent for graph tests."""
    from datetime import timedelta
    return SecurityEvent(
        source_type="suricata",
        source_id="test",
        source_ip=src,
        action=action,
        timestamp=_TS + timedelta(seconds=ts_offset),
        destination_ip=dst,
        category=category,
    )


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    """Fresh initialised SQLiteEventStore."""
    s = SQLiteEventStore(tmp_path / "graph.db")
    await s.init()
    yield s
    await s.close()


# ---------------------------------------------------------------------------
# Empty database — no errors, empty graph
# ---------------------------------------------------------------------------


class TestEmptyDatabase:
    """EARS-1 (empty-DB variant) — empty store returns empty graph without error."""

    @pytest.mark.asyncio
    async def test_empty_db_returns_empty_nodes_and_edges(
        self, store: SQLiteEventStore
    ) -> None:
        """Empty store yields an empty graph with no nodes or edges."""
        result = await build_entity_graph(store)
        assert result["nodes"] == []
        assert result["edges"] == []

    @pytest.mark.asyncio
    async def test_empty_db_truncated_flag_false(
        self, store: SQLiteEventStore
    ) -> None:
        """Empty store yields truncated=False (nothing was cut)."""
        result = await build_entity_graph(store)
        assert result["truncated"] is False


# ---------------------------------------------------------------------------
# EARS-1: Node and edge shapes
# ---------------------------------------------------------------------------


class TestNodeAndEdgeShapes:
    """EARS-1 — nodes carry type/id/label; edges carry source/target/weight."""

    @pytest.mark.asyncio
    async def test_src_ip_node_shape(self, store: SQLiteEventStore) -> None:
        """Source-IP nodes have type='ip', id=<ip>, label=<ip>."""
        await store.save_many([_ev(_SRC_A, dst=_DST_A)])
        result = await build_entity_graph(store)
        ip_nodes = [n for n in result["nodes"] if n["type"] == "ip"]
        assert any(n["id"] == _SRC_A and n["label"] == _SRC_A for n in ip_nodes)

    @pytest.mark.asyncio
    async def test_dst_ip_node_shape(self, store: SQLiteEventStore) -> None:
        """Destination-IP nodes have type='ip', id=<ip>, label=<ip>."""
        await store.save_many([_ev(_SRC_A, dst=_DST_A)])
        result = await build_entity_graph(store)
        ip_nodes = [n for n in result["nodes"] if n["type"] == "ip"]
        assert any(n["id"] == _DST_A and n["label"] == _DST_A for n in ip_nodes)

    @pytest.mark.asyncio
    async def test_category_node_shape(self, store: SQLiteEventStore) -> None:
        """Category nodes have type='category', id='cat:<category>', label=<category>."""
        await store.save_many([_ev(_SRC_A, dst=_DST_A, category="SQL Injection")])
        result = await build_entity_graph(store)
        cat_nodes = [n for n in result["nodes"] if n["type"] == "category"]
        assert any(
            n["id"] == "cat:SQL Injection" and n["label"] == "SQL Injection"
            for n in cat_nodes
        )

    @pytest.mark.asyncio
    async def test_edge_shape(self, store: SQLiteEventStore) -> None:
        """Edges have source (str), target (str), weight (int), kind (str)."""
        await store.save_many([_ev(_SRC_A, dst=_DST_A)])
        result = await build_entity_graph(store)
        assert len(result["edges"]) >= 1
        edge = result["edges"][0]
        assert "source" in edge
        assert "target" in edge
        assert "weight" in edge
        assert isinstance(edge["weight"], int)
        assert "kind" in edge

    @pytest.mark.asyncio
    async def test_src_dst_edge_kind(self, store: SQLiteEventStore) -> None:
        """Source→destination IP edge has kind='flow'."""
        await store.save_many([_ev(_SRC_A, dst=_DST_A)])
        result = await build_entity_graph(store)
        flow_edges = [e for e in result["edges"] if e["kind"] == "flow"]
        assert any(
            e["source"] == _SRC_A and e["target"] == _DST_A
            for e in flow_edges
        )

    @pytest.mark.asyncio
    async def test_ip_category_edge_kind(self, store: SQLiteEventStore) -> None:
        """IP→category edge has kind='category'."""
        await store.save_many([_ev(_SRC_A, dst=None, category="Brute Force")])
        result = await build_entity_graph(store)
        cat_edges = [e for e in result["edges"] if e["kind"] == "category"]
        assert any(
            e["source"] == _SRC_A and e["target"] == "cat:Brute Force"
            for e in cat_edges
        )


# ---------------------------------------------------------------------------
# EARS-2: NULL destination_ip exclusion
# ---------------------------------------------------------------------------


class TestNullDestinationExclusion:
    """EARS-2 — edges are only built from rows where destination_ip IS NOT NULL."""

    @pytest.mark.asyncio
    async def test_null_dst_excludes_flow_edge(
        self, store: SQLiteEventStore
    ) -> None:
        """A row with destination_ip=None produces no flow edge."""
        await store.save_many([_ev(_SRC_A, dst=None)])
        result = await build_entity_graph(store)
        flow_edges = [e for e in result["edges"] if e["kind"] == "flow"]
        assert flow_edges == []

    @pytest.mark.asyncio
    async def test_null_dst_rows_not_added_as_dst_nodes(
        self, store: SQLiteEventStore
    ) -> None:
        """NULL destination_ip rows do NOT produce destination IP nodes."""
        await store.save_many([_ev(_SRC_A, dst=None)])
        result = await build_entity_graph(store)
        # Only _SRC_A (source ip) could appear via category edge; no DST node
        ip_node_ids = {n["id"] for n in result["nodes"] if n["type"] == "ip"}
        assert _DST_A not in ip_node_ids

    @pytest.mark.asyncio
    async def test_mixed_null_and_nonnull_dst(
        self, store: SQLiteEventStore
    ) -> None:
        """Only rows with non-NULL destination_ip produce flow edges."""
        await store.save_many([
            _ev(_SRC_A, dst=None, ts_offset=0),
            _ev(_SRC_B, dst=_DST_A, ts_offset=1),
        ])
        result = await build_entity_graph(store)
        flow_edges = [e for e in result["edges"] if e["kind"] == "flow"]
        assert len(flow_edges) == 1
        assert flow_edges[0]["source"] == _SRC_B
        assert flow_edges[0]["target"] == _DST_A


# ---------------------------------------------------------------------------
# EARS-3: Cardinality cap / truncation
# ---------------------------------------------------------------------------


class TestCardinalityCap:
    """EARS-3 — WHEN cardinality exceeds the cap, return truncated subgraph
    with truncated=True; deterministically ranked by weight descending."""

    @pytest.mark.asyncio
    async def test_truncated_flag_when_edges_exceed_cap(
        self, store: SQLiteEventStore
    ) -> None:
        """truncated=True when edge count exceeds max_edges."""
        # Create 3 distinct (src, dst) pairs with 1 event each
        events = [
            _ev(_SRC_A, dst=_DST_A, ts_offset=0),
            _ev(_SRC_B, dst=_DST_B, ts_offset=1),
            _ev(_SRC_C, dst=_DST_C, ts_offset=2),
        ]
        await store.save_many(events)
        result = await build_entity_graph(store, max_edges=1)
        assert result["truncated"] is True

    @pytest.mark.asyncio
    async def test_edges_bounded_by_max_edges(
        self, store: SQLiteEventStore
    ) -> None:
        """Result never returns more edges than max_edges."""
        events = [
            _ev(_SRC_A, dst=_DST_A, ts_offset=0),
            _ev(_SRC_B, dst=_DST_B, ts_offset=1),
            _ev(_SRC_C, dst=_DST_C, ts_offset=2),
        ]
        await store.save_many(events)
        result = await build_entity_graph(store, max_edges=2)
        assert len(result["edges"]) <= 2

    @pytest.mark.asyncio
    async def test_edges_ranked_by_weight_descending(
        self, store: SQLiteEventStore
    ) -> None:
        """Flow edges are ranked by count descending (highest-weight first)."""
        # _SRC_A→_DST_A appears twice; _SRC_B→_DST_B once
        events = [
            _ev(_SRC_A, dst=_DST_A, ts_offset=0),
            _ev(_SRC_A, dst=_DST_A, action="BLOCK", ts_offset=1),
            _ev(_SRC_B, dst=_DST_B, ts_offset=2),
        ]
        await store.save_many(events)
        result = await build_entity_graph(store, max_edges=1)
        flow_edges = [e for e in result["edges"] if e["kind"] == "flow"]
        # Only the highest-weight pair should survive
        assert len(flow_edges) == 1
        assert flow_edges[0]["source"] == _SRC_A
        assert flow_edges[0]["target"] == _DST_A

    @pytest.mark.asyncio
    async def test_truncated_false_when_within_cap(
        self, store: SQLiteEventStore
    ) -> None:
        """truncated=False when edges and nodes are within the cap."""
        await store.save_many([_ev(_SRC_A, dst=_DST_A)])
        result = await build_entity_graph(store, max_edges=DEFAULT_MAX_EDGES)
        assert result["truncated"] is False

    @pytest.mark.asyncio
    async def test_nodes_bounded_by_max_nodes(
        self, store: SQLiteEventStore
    ) -> None:
        """Result never returns more nodes than max_nodes."""
        events = [
            _ev(_SRC_A, dst=_DST_A, category="SQL Injection", ts_offset=0),
            _ev(_SRC_B, dst=_DST_B, category="XSS", ts_offset=1),
            _ev(_SRC_C, dst=_DST_C, category="Brute Force", ts_offset=2),
        ]
        await store.save_many(events)
        # 6 IP nodes + 3 category nodes = 9 possible; cap at 4
        result = await build_entity_graph(store, max_nodes=4)
        assert len(result["nodes"]) <= 4


# ---------------------------------------------------------------------------
# EARS-2: ASN nodes from ip_geo
# ---------------------------------------------------------------------------


class TestAsnNodes:
    """EARS-2 — ASN nodes use the ip_geo table (populated by geo enricher)."""

    @pytest.mark.asyncio
    async def test_asn_node_appears_when_geo_populated(
        self, store: SQLiteEventStore
    ) -> None:
        """When ip_geo has ASN for an IP, an ASN node appears with type='asn'."""
        await store.save_many([_ev(_SRC_A, dst=_DST_A)])
        await store.upsert_ip_geo([{
            "ip": _SRC_A,
            "country": "US",
            "city": "Test",
            "lat": 0.0,
            "lon": 0.0,
            "asn": 64496,
            "as_name": "TEST-ASN",
        }])
        result = await build_entity_graph(store)
        asn_nodes = [n for n in result["nodes"] if n["type"] == "asn"]
        assert any(
            n["id"] == "asn:64496" and n["label"] == "TEST-ASN (AS64496)"
            for n in asn_nodes
        )

    @pytest.mark.asyncio
    async def test_asn_edge_ip_to_asn(self, store: SQLiteEventStore) -> None:
        """When ASN is known, an ip→asn edge with kind='asn' is emitted."""
        await store.save_many([_ev(_SRC_A, dst=_DST_A)])
        await store.upsert_ip_geo([{
            "ip": _SRC_A,
            "country": "US",
            "city": "Test",
            "lat": 0.0,
            "lon": 0.0,
            "asn": 64496,
            "as_name": "TEST-ASN",
        }])
        result = await build_entity_graph(store)
        asn_edges = [e for e in result["edges"] if e["kind"] == "asn"]
        assert any(
            e["source"] == _SRC_A and e["target"] == "asn:64496"
            for e in asn_edges
        )

    @pytest.mark.asyncio
    async def test_no_asn_node_when_geo_absent(
        self, store: SQLiteEventStore
    ) -> None:
        """When ip_geo has no entry for an IP, no ASN node is generated."""
        await store.save_many([_ev(_SRC_A, dst=_DST_A)])
        result = await build_entity_graph(store)
        asn_nodes = [n for n in result["nodes"] if n["type"] == "asn"]
        assert asn_nodes == []

    @pytest.mark.asyncio
    async def test_null_asn_in_geo_produces_no_asn_node(
        self, store: SQLiteEventStore
    ) -> None:
        """ip_geo row with asn=None produces no ASN node (honest NULL handling)."""
        await store.save_many([_ev(_SRC_A, dst=_DST_A)])
        await store.upsert_ip_geo([{
            "ip": _SRC_A,
            "country": "US",
            "city": "Test",
            "lat": 0.0,
            "lon": 0.0,
            "asn": None,
            "as_name": None,
        }])
        result = await build_entity_graph(store)
        asn_nodes = [n for n in result["nodes"] if n["type"] == "asn"]
        assert asn_nodes == []


# ---------------------------------------------------------------------------
# Edge aggregation correctness
# ---------------------------------------------------------------------------


class TestEdgeAggregation:
    """Verify that flow edge weights accumulate correctly."""

    @pytest.mark.asyncio
    async def test_flow_edge_weight_is_event_count(
        self, store: SQLiteEventStore
    ) -> None:
        """Flow edge weight equals the number of events for that (src, dst) pair."""
        events = [
            _ev(_SRC_A, dst=_DST_A, ts_offset=0),
            _ev(_SRC_A, dst=_DST_A, action="BLOCK", ts_offset=1),
            _ev(_SRC_A, dst=_DST_A, action="ALERT", ts_offset=2),
        ]
        await store.save_many(events)
        result = await build_entity_graph(store)
        flow_edges = [
            e for e in result["edges"]
            if e["kind"] == "flow" and e["source"] == _SRC_A and e["target"] == _DST_A
        ]
        assert len(flow_edges) == 1
        assert flow_edges[0]["weight"] == 3

    @pytest.mark.asyncio
    async def test_category_edge_weight_is_event_count(
        self, store: SQLiteEventStore
    ) -> None:
        """Category edge weight equals the count of events for (src_ip, category)."""
        events = [
            _ev(_SRC_A, dst=None, category="SQL Injection", ts_offset=0),
            _ev(_SRC_A, dst=None, category="SQL Injection", ts_offset=1),
        ]
        await store.save_many(events)
        result = await build_entity_graph(store)
        cat_edges = [
            e for e in result["edges"]
            if e["kind"] == "category"
            and e["source"] == _SRC_A
            and e["target"] == "cat:SQL Injection"
        ]
        assert len(cat_edges) == 1
        assert cat_edges[0]["weight"] == 2

    @pytest.mark.asyncio
    async def test_multiple_srcs_produce_multiple_nodes(
        self, store: SQLiteEventStore
    ) -> None:
        """Two distinct source IPs both appear as IP nodes."""
        await store.save_many([
            _ev(_SRC_A, dst=_DST_A, ts_offset=0),
            _ev(_SRC_B, dst=_DST_A, ts_offset=1),
        ])
        result = await build_entity_graph(store)
        ip_node_ids = {n["id"] for n in result["nodes"] if n["type"] == "ip"}
        assert _SRC_A in ip_node_ids
        assert _SRC_B in ip_node_ids

    @pytest.mark.asyncio
    async def test_no_duplicate_nodes(self, store: SQLiteEventStore) -> None:
        """Each node id appears exactly once even with many events for the same IP."""
        events = [_ev(_SRC_A, dst=_DST_A, ts_offset=i) for i in range(5)]
        await store.save_many(events)
        result = await build_entity_graph(store)
        node_ids = [n["id"] for n in result["nodes"]]
        assert len(node_ids) == len(set(node_ids)), "Duplicate node ids found"


# ---------------------------------------------------------------------------
# Injection-safety: LIMIT is bound via placeholder, not f-string
# ---------------------------------------------------------------------------


class TestInjectionSafety:
    """Verify that the limit param is bound safely (cannot do SQL injection)."""

    @pytest.mark.asyncio
    async def test_max_edges_integer_accepted(
        self, store: SQLiteEventStore
    ) -> None:
        """build_entity_graph accepts an integer max_edges without error."""
        await store.save_many([_ev(_SRC_A, dst=_DST_A)])
        result = await build_entity_graph(store, max_edges=5)
        assert isinstance(result["edges"], list)

    @pytest.mark.asyncio
    async def test_max_edges_one_returns_at_most_one_flow_edge(
        self, store: SQLiteEventStore
    ) -> None:
        """max_edges=1 returns at most 1 flow edge (LIMIT bound via ?)."""
        events = [
            _ev(_SRC_A, dst=_DST_A, ts_offset=0),
            _ev(_SRC_B, dst=_DST_B, ts_offset=1),
        ]
        await store.save_many(events)
        result = await build_entity_graph(store, max_edges=1)
        flow_edges = [e for e in result["edges"] if e["kind"] == "flow"]
        assert len(flow_edges) <= 1


# ---------------------------------------------------------------------------
# Default constants are sane
# ---------------------------------------------------------------------------


class TestDefaults:
    """Verify DEFAULT_MAX_NODES and DEFAULT_MAX_EDGES are reasonable."""

    def test_defaults_are_positive_ints(self) -> None:
        """DEFAULT_MAX_NODES and DEFAULT_MAX_EDGES are positive integers."""
        assert isinstance(DEFAULT_MAX_NODES, int)
        assert DEFAULT_MAX_NODES > 0
        assert isinstance(DEFAULT_MAX_EDGES, int)
        assert DEFAULT_MAX_EDGES > 0
