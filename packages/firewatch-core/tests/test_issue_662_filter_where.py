"""Tests for issue #662 — _filter_where shared helper and filtered aggregation endpoints.

Mapped 1:1 to EARS acceptance criteria from issue #662.

EARS-1  get_top_talkers with FilterSpec facet SHALL reflect only matching rows.
EARS-2  get_protocol_mix, get_top_pairs, build_entity_graph with FilterSpec facets
        SHALL apply the identical shared WHERE predicate.
EARS-3  WHERE no facet is supplied (filters=None), each method returns byte-identical
        output to the pre-change behaviour (golden parity).
EARS-4  Values flow through ? placeholders (B1 invariant — no f-string interpolation).
EARS-5  start/end timestamp range filter applies to all four aggregation methods.

All IPs use RFC 5737 / RFC 1918 documentation ranges — no real/routable IPs.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import pytest

from firewatch_sdk import SecurityEvent
from firewatch_sdk.models import ActionLiteral, FilterSpec, SeverityLiteral
from firewatch_core.adapters.sqlite_store import SQLiteEventStore
from firewatch_core.adapters.sqlite._filter_where import build_filter_where
from firewatch_core.analytics.entity_graph import build_entity_graph


# ---------------------------------------------------------------------------
# Shared helpers / constants
# ---------------------------------------------------------------------------

# RFC 5737 documentation IPs only — never real/routable
_SRC_A = "192.0.2.10"
_SRC_B = "192.0.2.20"
_SRC_C = "192.0.2.30"
_DST_A = "198.51.100.1"
_DST_B = "198.51.100.2"

_TS_BASE = datetime(2026, 6, 13, 12, 0, 0, tzinfo=timezone.utc)


def _ev(
    *,
    source_ip: str = _SRC_A,
    destination_ip: str | None = None,
    protocol: str | None = None,
    action: ActionLiteral = "ALERT",
    severity: SeverityLiteral | None = None,
    category: str | None = None,
    source_type: str = "suricata",
    source_id: str = "sensor",
    ts_offset_sec: int = 0,
) -> SecurityEvent:
    ts = _TS_BASE + timedelta(seconds=ts_offset_sec)
    return SecurityEvent(
        source_type=source_type,
        source_id=source_id,
        source_ip=source_ip,
        action=action,
        timestamp=ts,
        destination_ip=destination_ip,
        protocol=protocol,
        severity=severity,
        category=category,
    )


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    """Fresh initialised SQLiteEventStore."""
    s = SQLiteEventStore(tmp_path / "662.db")
    await s.init()
    yield s
    await s.close()


# ---------------------------------------------------------------------------
# Unit tests for build_filter_where helper (EARS-4)
# ---------------------------------------------------------------------------


class TestBuildFilterWhere:
    """The shared _filter_where helper produces correct SQL and params."""

    def test_none_filters_returns_empty_clause(self) -> None:
        """None filters -> empty WHERE clause and empty params list."""
        clause, params = build_filter_where(None)
        assert clause == ""
        assert params == []

    def test_empty_filterspec_returns_empty_clause(self) -> None:
        """Empty FilterSpec -> empty WHERE clause (all fields None)."""
        clause, params = build_filter_where(FilterSpec())
        assert clause == ""
        assert params == []

    def test_ip_filter_produces_like_clause(self) -> None:
        """FilterSpec.ip -> 'source_ip LIKE ?' with %-wrapped value."""
        clause, params = build_filter_where(FilterSpec(ip="192.0.2"))
        assert "source_ip LIKE ?" in clause
        assert "WHERE" in clause
        assert any("192.0.2" in str(p) for p in params)

    def test_action_blocked_expands_to_sql_frag(self) -> None:
        """FilterSpec.action='blocked' expands to the BLOCKED_ACTIONS fragment."""
        clause, params = build_filter_where(FilterSpec(action="blocked"))
        # Should contain action IN (...) covering BLOCK and DROP
        assert "action IN" in clause

    def test_action_exact_uses_placeholder(self) -> None:
        """FilterSpec.action='ALERT' -> 'action = ?' with ALERT as param."""
        clause, params = build_filter_where(FilterSpec(action="ALERT"))
        assert "action = ?" in clause
        assert "ALERT" in params

    def test_protocol_filter(self) -> None:
        """FilterSpec.protocol -> 'protocol = ?' with the protocol value."""
        clause, params = build_filter_where(FilterSpec(protocol="TCP"))
        assert "protocol = ?" in clause
        assert "TCP" in params

    def test_severity_filter(self) -> None:
        """FilterSpec.severity -> 'severity = ?' with lower-cased value."""
        clause, params = build_filter_where(FilterSpec(severity="HIGH"))
        assert "severity = ?" in clause
        assert "high" in params

    def test_category_exact_match(self) -> None:
        """FilterSpec.category (canonical) -> 'category = ?' placeholder."""
        clause, params = build_filter_where(FilterSpec(category="SQL Injection"))
        assert "category = ?" in clause
        assert "SQL Injection" in params

    def test_source_type_filter(self) -> None:
        """FilterSpec.source_type -> 'source_type = ?' placeholder."""
        clause, params = build_filter_where(FilterSpec(source_type="suricata"))
        assert "source_type = ?" in clause
        assert "suricata" in params

    def test_source_id_filter(self) -> None:
        """FilterSpec.source_id -> 'source_id = ?' placeholder."""
        clause, params = build_filter_where(FilterSpec(source_id="sensor-1"))
        assert "source_id = ?" in clause
        assert "sensor-1" in params

    def test_destination_ip_filter(self) -> None:
        """FilterSpec.destination_ip -> 'destination_ip LIKE ?' placeholder."""
        clause, params = build_filter_where(FilterSpec(destination_ip="198.51.100"))
        assert "destination_ip LIKE ?" in clause
        assert any("198.51.100" in str(p) for p in params)

    def test_q_filter(self) -> None:
        """FilterSpec.q -> free-text LIKE clause with ? placeholder."""
        clause, params = build_filter_where(FilterSpec(q="brute"))
        assert "?" in clause
        assert any("brute" in str(p) for p in params)

    def test_start_end_params(self) -> None:
        """start/end strings -> 'timestamp >= ?' AND 'timestamp <= ?' clauses."""
        clause, params = build_filter_where(
            None,
            start="2026-06-13T00:00:00+00:00",
            end="2026-06-13T23:59:59+00:00",
        )
        assert "timestamp >=" in clause
        assert "timestamp <=" in clause
        assert "2026-06-13T00:00:00+00:00" in params
        assert "2026-06-13T23:59:59+00:00" in params

    def test_multiple_filters_combined_with_and(self) -> None:
        """Multiple filters are combined with AND."""
        clause, params = build_filter_where(
            FilterSpec(ip="192.0.2", protocol="TCP", severity="high")
        )
        assert clause.count("AND") >= 2

    def test_conditions_are_static_literals(self) -> None:
        """The WHERE clause contains only ? placeholders (no attacker-controlled literals)."""
        # Using an IP that would be 'dangerous' if interpolated directly
        clause, params = build_filter_where(FilterSpec(ip="'; DROP TABLE logs; --"))
        # The injection string must only appear in params, never in the clause itself
        assert "DROP TABLE" not in clause
        # It must appear in params (bound via ?)
        assert any("DROP TABLE" in str(p) for p in params)


# ---------------------------------------------------------------------------
# EARS-1: get_top_talkers respects FilterSpec facets
# ---------------------------------------------------------------------------


class TestTopTalkersWithFilters:
    """EARS-1 -- get_top_talkers reflects only rows matching FilterSpec."""

    @pytest.mark.asyncio
    async def test_ip_filter_scopes_top_talkers(
        self, store: SQLiteEventStore
    ) -> None:
        """FilterSpec.ip filters top-talkers to matching source IPs only."""
        await store.save_many([
            _ev(source_ip=_SRC_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_A, ts_offset_sec=1),
            _ev(source_ip=_SRC_B, ts_offset_sec=2),
        ])
        rows = await store.get_top_talkers(top_n=10, filters=FilterSpec(ip=_SRC_A))
        ips = [r["source_ip"] for r in rows]
        assert _SRC_A in ips
        assert _SRC_B not in ips

    @pytest.mark.asyncio
    async def test_action_filter_scopes_top_talkers(
        self, store: SQLiteEventStore
    ) -> None:
        """FilterSpec.action='BLOCK' filters to only BLOCK events."""
        await store.save_many([
            _ev(source_ip=_SRC_A, action="BLOCK", ts_offset_sec=0),
            _ev(source_ip=_SRC_A, action="ALERT", ts_offset_sec=1),
            _ev(source_ip=_SRC_B, action="ALERT", ts_offset_sec=2),
        ])
        rows = await store.get_top_talkers(top_n=10, filters=FilterSpec(action="BLOCK"))
        # Only SRC_A has BLOCK events; ALERT rows are excluded
        assert len(rows) == 1
        assert rows[0]["source_ip"] == _SRC_A
        assert rows[0]["count"] == 1

    @pytest.mark.asyncio
    async def test_severity_filter_scopes_top_talkers(
        self, store: SQLiteEventStore
    ) -> None:
        """FilterSpec.severity='critical' filters to only critical events."""
        await store.save_many([
            _ev(source_ip=_SRC_A, severity="critical", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, severity="low", ts_offset_sec=1),
        ])
        rows = await store.get_top_talkers(top_n=10, filters=FilterSpec(severity="critical"))
        assert len(rows) == 1
        assert rows[0]["source_ip"] == _SRC_A

    @pytest.mark.asyncio
    async def test_source_type_filter_scopes_top_talkers(
        self, store: SQLiteEventStore
    ) -> None:
        """FilterSpec.source_type scopes top-talkers to the given source type."""
        await store.save_many([
            _ev(source_ip=_SRC_A, source_type="suricata", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, source_type="azure_waf", ts_offset_sec=1),
        ])
        rows = await store.get_top_talkers(
            top_n=10, filters=FilterSpec(source_type="suricata")
        )
        ips = [r["source_ip"] for r in rows]
        assert _SRC_A in ips
        assert _SRC_B not in ips

    @pytest.mark.asyncio
    async def test_no_filter_returns_all_rows(
        self, store: SQLiteEventStore
    ) -> None:
        """EARS-3: filters=None returns unfiltered results (golden parity)."""
        await store.save_many([
            _ev(source_ip=_SRC_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, ts_offset_sec=1),
        ])
        rows_unfiltered = await store.get_top_talkers(top_n=10)
        rows_none_filter = await store.get_top_talkers(top_n=10, filters=None)
        rows_empty_filter = await store.get_top_talkers(top_n=10, filters=FilterSpec())
        # All three must return the same set of IPs
        ips_unfiltered = {r["source_ip"] for r in rows_unfiltered}
        ips_none = {r["source_ip"] for r in rows_none_filter}
        ips_empty = {r["source_ip"] for r in rows_empty_filter}
        assert ips_unfiltered == ips_none == ips_empty


# ---------------------------------------------------------------------------
# EARS-2: get_protocol_mix respects FilterSpec facets
# ---------------------------------------------------------------------------


class TestProtocolMixWithFilters:
    """EARS-2 -- get_protocol_mix applies the identical shared WHERE predicate."""

    @pytest.mark.asyncio
    async def test_source_type_filter_scopes_protocol_mix(
        self, store: SQLiteEventStore
    ) -> None:
        """FilterSpec.source_type scopes protocol-mix to events from that source type."""
        await store.save_many([
            _ev(source_ip=_SRC_A, protocol="TCP", source_type="suricata", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, protocol="UDP", source_type="azure_waf", ts_offset_sec=1),
        ])
        rows = await store.get_protocol_mix(
            top_n=10, filters=FilterSpec(source_type="suricata")
        )
        protocols = {r["protocol"] for r in rows}
        assert "TCP" in protocols
        assert "UDP" not in protocols

    @pytest.mark.asyncio
    async def test_ip_filter_scopes_protocol_mix(
        self, store: SQLiteEventStore
    ) -> None:
        """FilterSpec.ip scopes protocol-mix to events from matching source IPs."""
        await store.save_many([
            _ev(source_ip=_SRC_A, protocol="TCP", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, protocol="UDP", ts_offset_sec=1),
        ])
        rows = await store.get_protocol_mix(
            top_n=10, filters=FilterSpec(ip=_SRC_A)
        )
        protocols = {r["protocol"] for r in rows}
        assert "TCP" in protocols
        assert "UDP" not in protocols

    @pytest.mark.asyncio
    async def test_action_filter_scopes_protocol_mix(
        self, store: SQLiteEventStore
    ) -> None:
        """FilterSpec.action scopes protocol-mix to matching action events."""
        await store.save_many([
            _ev(source_ip=_SRC_A, protocol="TCP", action="BLOCK", ts_offset_sec=0),
            _ev(source_ip=_SRC_A, protocol="UDP", action="ALERT", ts_offset_sec=1),
        ])
        rows = await store.get_protocol_mix(top_n=10, filters=FilterSpec(action="BLOCK"))
        protocols = {r["protocol"] for r in rows}
        assert "TCP" in protocols
        # UDP row is ALERT -- should not appear under BLOCK filter
        assert "UDP" not in protocols

    @pytest.mark.asyncio
    async def test_no_filter_golden_parity(
        self, store: SQLiteEventStore
    ) -> None:
        """EARS-3: filters=None is byte-identical to unfiltered (golden parity)."""
        await store.save_many([
            _ev(source_ip=_SRC_A, protocol="TCP", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, protocol="UDP", ts_offset_sec=1),
        ])
        rows_base = await store.get_protocol_mix(top_n=10)
        rows_none = await store.get_protocol_mix(top_n=10, filters=None)
        assert rows_base == rows_none


# ---------------------------------------------------------------------------
# EARS-2: get_top_pairs respects FilterSpec facets
# ---------------------------------------------------------------------------


class TestTopPairsWithFilters:
    """EARS-2 -- get_top_pairs applies the identical shared WHERE predicate."""

    @pytest.mark.asyncio
    async def test_source_type_filter_scopes_top_pairs(
        self, store: SQLiteEventStore
    ) -> None:
        """FilterSpec.source_type scopes top-pairs to events from that source type."""
        await store.save_many([
            _ev(
                source_ip=_SRC_A, destination_ip=_DST_A,
                source_type="suricata", ts_offset_sec=0,
            ),
            _ev(
                source_ip=_SRC_B, destination_ip=_DST_B,
                source_type="azure_waf", ts_offset_sec=1,
            ),
        ])
        rows = await store.get_top_pairs(
            top_n=10, filters=FilterSpec(source_type="suricata")
        )
        src_ips = {r["source_ip"] for r in rows}
        assert _SRC_A in src_ips
        assert _SRC_B not in src_ips

    @pytest.mark.asyncio
    async def test_ip_filter_scopes_top_pairs(
        self, store: SQLiteEventStore
    ) -> None:
        """FilterSpec.ip scopes top-pairs to matching source IPs."""
        await store.save_many([
            _ev(source_ip=_SRC_A, destination_ip=_DST_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, destination_ip=_DST_B, ts_offset_sec=1),
        ])
        rows = await store.get_top_pairs(
            top_n=10, filters=FilterSpec(ip=_SRC_A)
        )
        src_ips = {r["source_ip"] for r in rows}
        assert _SRC_A in src_ips
        assert _SRC_B not in src_ips

    @pytest.mark.asyncio
    async def test_protocol_filter_scopes_top_pairs(
        self, store: SQLiteEventStore
    ) -> None:
        """FilterSpec.protocol scopes top-pairs to matching protocol rows."""
        await store.save_many([
            _ev(
                source_ip=_SRC_A, destination_ip=_DST_A,
                protocol="TCP", ts_offset_sec=0,
            ),
            _ev(
                source_ip=_SRC_B, destination_ip=_DST_B,
                protocol="UDP", ts_offset_sec=1,
            ),
        ])
        rows = await store.get_top_pairs(top_n=10, filters=FilterSpec(protocol="TCP"))
        src_ips = {r["source_ip"] for r in rows}
        assert _SRC_A in src_ips
        assert _SRC_B not in src_ips

    @pytest.mark.asyncio
    async def test_destination_ip_filter_scopes_top_pairs(
        self, store: SQLiteEventStore
    ) -> None:
        """FilterSpec.destination_ip (substring) scopes top-pairs."""
        await store.save_many([
            _ev(source_ip=_SRC_A, destination_ip=_DST_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, destination_ip=_DST_B, ts_offset_sec=1),
        ])
        # _DST_A = "198.51.100.1" -- filter by exact value (LIKE match)
        rows = await store.get_top_pairs(
            top_n=10, filters=FilterSpec(destination_ip=_DST_A)
        )
        dst_ips = {r["destination_ip"] for r in rows}
        assert _DST_A in dst_ips
        assert _DST_B not in dst_ips

    @pytest.mark.asyncio
    async def test_no_filter_golden_parity(
        self, store: SQLiteEventStore
    ) -> None:
        """EARS-3: filters=None is byte-identical to unfiltered (golden parity)."""
        await store.save_many([
            _ev(source_ip=_SRC_A, destination_ip=_DST_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, destination_ip=_DST_B, ts_offset_sec=1),
        ])
        rows_base = await store.get_top_pairs(top_n=10)
        rows_none = await store.get_top_pairs(top_n=10, filters=None)
        assert rows_base == rows_none


# ---------------------------------------------------------------------------
# EARS-2: build_entity_graph respects FilterSpec facets
# ---------------------------------------------------------------------------


class TestEntityGraphWithFilters:
    """EARS-2 -- build_entity_graph applies the identical shared WHERE predicate."""

    @pytest.mark.asyncio
    async def test_source_type_filter_scopes_graph(
        self, store: SQLiteEventStore
    ) -> None:
        """FilterSpec.source_type scopes the entity graph to events from that source type."""
        await store.save_many([
            _ev(
                source_ip=_SRC_A, destination_ip=_DST_A,
                source_type="suricata", ts_offset_sec=0,
            ),
            _ev(
                source_ip=_SRC_B, destination_ip=_DST_B,
                source_type="azure_waf", ts_offset_sec=1,
            ),
        ])
        result = await build_entity_graph(
            store, filters=FilterSpec(source_type="suricata")
        )
        ip_ids = {n["id"] for n in result["nodes"] if n["type"] == "ip"}
        # Only suricata events -- SRC_A/DST_A should appear; SRC_B/DST_B should not
        assert _SRC_A in ip_ids
        assert _SRC_B not in ip_ids

    @pytest.mark.asyncio
    async def test_category_filter_scopes_graph(
        self, store: SQLiteEventStore
    ) -> None:
        """FilterSpec.category scopes the entity graph to matching category events."""
        await store.save_many([
            _ev(
                source_ip=_SRC_A, destination_ip=_DST_A,
                category="SQL Injection", ts_offset_sec=0,
            ),
            _ev(
                source_ip=_SRC_B, destination_ip=_DST_B,
                category="XSS", ts_offset_sec=1,
            ),
        ])
        result = await build_entity_graph(
            store, filters=FilterSpec(category="SQL Injection")
        )
        ip_ids = {n["id"] for n in result["nodes"] if n["type"] == "ip"}
        assert _SRC_A in ip_ids
        assert _SRC_B not in ip_ids

    @pytest.mark.asyncio
    async def test_ip_filter_scopes_graph(
        self, store: SQLiteEventStore
    ) -> None:
        """FilterSpec.ip scopes the entity graph flow edges to matching source IPs."""
        await store.save_many([
            _ev(source_ip=_SRC_A, destination_ip=_DST_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, destination_ip=_DST_B, ts_offset_sec=1),
        ])
        result = await build_entity_graph(
            store, filters=FilterSpec(ip=_SRC_A)
        )
        flow_edges = [e for e in result["edges"] if e["kind"] == "flow"]
        srcs = {e["source"] for e in flow_edges}
        assert _SRC_A in srcs
        assert _SRC_B not in srcs

    @pytest.mark.asyncio
    async def test_no_filter_golden_parity(
        self, store: SQLiteEventStore
    ) -> None:
        """EARS-3: filters=None produces the same result as the pre-change path."""
        await store.save_many([
            _ev(source_ip=_SRC_A, destination_ip=_DST_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, destination_ip=_DST_B, ts_offset_sec=1),
        ])
        result_base = await build_entity_graph(store)
        result_none = await build_entity_graph(store, filters=None)
        # Both must produce the same nodes and edges sets
        assert {n["id"] for n in result_base["nodes"]} == {
            n["id"] for n in result_none["nodes"]
        }
        assert len(result_base["edges"]) == len(result_none["edges"])


# ---------------------------------------------------------------------------
# EARS-5: start/end timestamp range
# ---------------------------------------------------------------------------


class TestStartEndFilter:
    """EARS-5 -- start/end timestamp range scopes all four aggregation methods."""

    @pytest.mark.asyncio
    async def test_top_talkers_scoped_by_start_end(
        self, store: SQLiteEventStore
    ) -> None:
        """get_top_talkers with start/end returns only events in the time window."""
        # SRC_A at T=0, SRC_B at T+1 hour
        await store.save_many([
            _ev(source_ip=_SRC_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, ts_offset_sec=3600),
        ])
        # Window covers only T=0 (first 30 minutes)
        start = _TS_BASE.isoformat()
        end = (_TS_BASE + timedelta(minutes=30)).isoformat()
        rows = await store.get_top_talkers(top_n=10, start=start, end=end)
        ips = {r["source_ip"] for r in rows}
        assert _SRC_A in ips
        assert _SRC_B not in ips

    @pytest.mark.asyncio
    async def test_protocol_mix_scoped_by_start_end(
        self, store: SQLiteEventStore
    ) -> None:
        """get_protocol_mix with start/end returns only events in the time window."""
        await store.save_many([
            _ev(source_ip=_SRC_A, protocol="TCP", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, protocol="UDP", ts_offset_sec=3600),
        ])
        start = _TS_BASE.isoformat()
        end = (_TS_BASE + timedelta(minutes=30)).isoformat()
        rows = await store.get_protocol_mix(top_n=10, start=start, end=end)
        protocols = {r["protocol"] for r in rows}
        assert "TCP" in protocols
        assert "UDP" not in protocols

    @pytest.mark.asyncio
    async def test_top_pairs_scoped_by_start_end(
        self, store: SQLiteEventStore
    ) -> None:
        """get_top_pairs with start/end returns only events in the time window."""
        await store.save_many([
            _ev(source_ip=_SRC_A, destination_ip=_DST_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, destination_ip=_DST_B, ts_offset_sec=3600),
        ])
        start = _TS_BASE.isoformat()
        end = (_TS_BASE + timedelta(minutes=30)).isoformat()
        rows = await store.get_top_pairs(top_n=10, start=start, end=end)
        src_ips = {r["source_ip"] for r in rows}
        assert _SRC_A in src_ips
        assert _SRC_B not in src_ips

    @pytest.mark.asyncio
    async def test_entity_graph_scoped_by_start_end(
        self, store: SQLiteEventStore
    ) -> None:
        """build_entity_graph with start/end returns only events in the time window."""
        await store.save_many([
            _ev(source_ip=_SRC_A, destination_ip=_DST_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, destination_ip=_DST_B, ts_offset_sec=3600),
        ])
        start = _TS_BASE.isoformat()
        end = (_TS_BASE + timedelta(minutes=30)).isoformat()
        result = await build_entity_graph(store, start=start, end=end)
        ip_ids = {n["id"] for n in result["nodes"] if n["type"] == "ip"}
        assert _SRC_A in ip_ids
        assert _SRC_B not in ip_ids
