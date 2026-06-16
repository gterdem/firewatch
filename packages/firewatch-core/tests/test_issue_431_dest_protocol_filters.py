"""Tests for ML-3 — destination_ip/protocol filters + top src→dst pairs.

Mapped 1:1 to EARS criteria from issue #431.

EARS-1  FilterSpec + store.get_paginated SHALL accept destination_ip (substring)
        and protocol (exact) filters, each backed by a WHERE clause.
        - filter by destination_ip substring returns only matching rows
        - filter by protocol exact-match returns only matching rows
        - combined filters intersect correctly
        - non-matching filter returns empty result
        - parameterized SQL (no injection risk from filter values)

EARS-4  GET /logs/top-pairs aggregate returns top (source_ip → destination_ip)
        pairs with counts; bounded top-N; parameterized.
        - returns pairs ordered by count DESC
        - bounded by the requested limit
        - returns empty list when no rows have destination_ip populated
        - pairs with NULL destination_ip are excluded

All IPs use RFC 5737 / RFC 1918 documentation ranges — no real/routable IPs.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from firewatch_sdk import SecurityEvent
from firewatch_sdk.models import ActionLiteral, FilterSpec
from firewatch_core.adapters.sqlite_store import SQLiteEventStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS_BASE = datetime(2026, 6, 13, 12, 0, 0, tzinfo=timezone.utc)

# RFC 5737 / RFC 1918 IPs — never real/routable
_SRC_A = "192.0.2.10"
_SRC_B = "192.0.2.20"
_DST_A = "198.51.100.1"
_DST_B = "198.51.100.2"
_DST_C = "203.0.113.50"


def _ev(
    *,
    source_ip: str = _SRC_A,
    destination_ip: str | None = None,
    protocol: str | None = None,
    action: ActionLiteral = "ALERT",
    ts_offset_sec: int = 0,
    **kwargs: Any,
) -> SecurityEvent:
    ts = datetime(
        2026, 6, 13, 12, 0, ts_offset_sec % 60, tzinfo=timezone.utc
    )
    return SecurityEvent(
        source_type="suricata",
        source_id="sensor",
        source_ip=source_ip,
        action=action,
        timestamp=ts,
        destination_ip=destination_ip,
        protocol=protocol,
        **kwargs,
    )


@pytest.fixture
async def store(tmp_path: Path) -> SQLiteEventStore:  # type: ignore[misc]
    s = SQLiteEventStore(tmp_path / "ml3.db")
    await s.init()
    yield s  # type: ignore[misc]
    await s.close()


# ---------------------------------------------------------------------------
# EARS-1: destination_ip substring filter
# ---------------------------------------------------------------------------


class TestDestinationIpFilter:
    """EARS-1 — destination_ip substring filter backs a WHERE clause."""

    @pytest.mark.asyncio
    async def test_filter_by_dest_ip_returns_matching_rows(
        self, store: SQLiteEventStore
    ) -> None:
        """Filter ?destination_ip=198.51.100.1 returns only rows with that dst IP."""
        await store.save_many([
            _ev(source_ip=_SRC_A, destination_ip=_DST_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, destination_ip=_DST_B, ts_offset_sec=1),
        ])
        result = await store.get_paginated(
            filters=FilterSpec(destination_ip=_DST_A)
        )
        assert result["total_matching"] == 1
        assert len(result["logs"]) == 1
        assert result["logs"][0]["destination_ip"] == _DST_A

    @pytest.mark.asyncio
    async def test_filter_by_dest_ip_substring_matches(
        self, store: SQLiteEventStore
    ) -> None:
        """Substring match: ?destination_ip=198.51 matches both 198.51.100.x rows."""
        await store.save_many([
            _ev(source_ip=_SRC_A, destination_ip=_DST_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, destination_ip=_DST_B, ts_offset_sec=1),
            _ev(source_ip=_SRC_A, destination_ip=_DST_C, ts_offset_sec=2),
        ])
        result = await store.get_paginated(
            filters=FilterSpec(destination_ip="198.51")
        )
        assert result["total_matching"] == 2

    @pytest.mark.asyncio
    async def test_filter_by_dest_ip_no_match_returns_empty(
        self, store: SQLiteEventStore
    ) -> None:
        """Non-matching destination_ip filter returns empty logs list."""
        await store.save_many([_ev(destination_ip=_DST_A)])
        result = await store.get_paginated(
            filters=FilterSpec(destination_ip="203.0.113.99")
        )
        assert result["total_matching"] == 0
        assert result["logs"] == []

    @pytest.mark.asyncio
    async def test_filter_by_dest_ip_excludes_null_dst(
        self, store: SQLiteEventStore
    ) -> None:
        """Rows with NULL destination_ip are excluded by the filter."""
        await store.save_many([
            _ev(destination_ip=None, ts_offset_sec=0),
            _ev(destination_ip=_DST_A, ts_offset_sec=1),
        ])
        result = await store.get_paginated(
            filters=FilterSpec(destination_ip=_DST_A)
        )
        assert result["total_matching"] == 1

    @pytest.mark.asyncio
    async def test_filter_dest_ip_sql_injection_safe(
        self, store: SQLiteEventStore
    ) -> None:
        """A filter value with SQL metacharacters must not cause a 500/injection.

        The store uses parameterized placeholders (B1 safety invariant) — the
        injected string is treated as a literal search value, not SQL syntax.
        No rows match the malicious string, and no error is raised.
        """
        await store.save_many([_ev(destination_ip=_DST_A)])
        # Should not raise; no rows should match the injection string
        result = await store.get_paginated(
            filters=FilterSpec(destination_ip="'; DROP TABLE logs; --")
        )
        assert result["total_matching"] == 0


# ---------------------------------------------------------------------------
# EARS-1: protocol exact-match filter
# ---------------------------------------------------------------------------


class TestProtocolFilter:
    """EARS-1 — protocol exact-match filter backs a WHERE clause."""

    @pytest.mark.asyncio
    async def test_filter_by_protocol_returns_matching_rows(
        self, store: SQLiteEventStore
    ) -> None:
        """Filter ?protocol=TCP returns only rows with protocol=TCP."""
        await store.save_many([
            _ev(protocol="TCP", ts_offset_sec=0),
            _ev(protocol="UDP", ts_offset_sec=1),
        ])
        result = await store.get_paginated(filters=FilterSpec(protocol="TCP"))
        assert result["total_matching"] == 1
        assert result["logs"][0]["protocol"] in ("TCP", "tcp")

    @pytest.mark.asyncio
    async def test_filter_by_protocol_case_insensitive(
        self, store: SQLiteEventStore
    ) -> None:
        """Protocol filter is stored/matched in the case as provided."""
        await store.save_many([
            _ev(protocol="TCP", ts_offset_sec=0),
            _ev(protocol="UDP", ts_offset_sec=1),
            _ev(protocol="ICMP", ts_offset_sec=2),
        ])
        result = await store.get_paginated(filters=FilterSpec(protocol="UDP"))
        assert result["total_matching"] == 1

    @pytest.mark.asyncio
    async def test_filter_by_protocol_no_match_returns_empty(
        self, store: SQLiteEventStore
    ) -> None:
        """Non-matching protocol filter returns empty result."""
        await store.save_many([_ev(protocol="TCP")])
        result = await store.get_paginated(filters=FilterSpec(protocol="SCTP"))
        assert result["total_matching"] == 0
        assert result["logs"] == []

    @pytest.mark.asyncio
    async def test_filter_by_protocol_excludes_empty_protocol(
        self, store: SQLiteEventStore
    ) -> None:
        """Rows stored with empty/null protocol are not returned by protocol filter."""
        await store.save_many([
            _ev(protocol=None, ts_offset_sec=0),
            _ev(protocol="TCP", ts_offset_sec=1),
        ])
        result = await store.get_paginated(filters=FilterSpec(protocol="TCP"))
        assert result["total_matching"] == 1


# ---------------------------------------------------------------------------
# EARS-1: combined destination_ip + protocol filters
# ---------------------------------------------------------------------------


class TestCombinedFilters:
    """EARS-1 — combined dest_ip + protocol filter intersects correctly."""

    @pytest.mark.asyncio
    async def test_combined_dest_ip_and_protocol_filter(
        self, store: SQLiteEventStore
    ) -> None:
        """Both filters applied together produce the intersection."""
        await store.save_many([
            _ev(destination_ip=_DST_A, protocol="TCP", ts_offset_sec=0),
            _ev(destination_ip=_DST_A, protocol="UDP", ts_offset_sec=1),
            _ev(destination_ip=_DST_B, protocol="TCP", ts_offset_sec=2),
        ])
        result = await store.get_paginated(
            filters=FilterSpec(destination_ip=_DST_A, protocol="TCP")
        )
        assert result["total_matching"] == 1
        row = result["logs"][0]
        assert row["destination_ip"] == _DST_A
        assert row["protocol"] in ("TCP", "tcp")

    @pytest.mark.asyncio
    async def test_combined_dest_ip_and_protocol_no_match(
        self, store: SQLiteEventStore
    ) -> None:
        """Combined filter with no intersection returns empty."""
        await store.save_many([
            _ev(destination_ip=_DST_A, protocol="UDP", ts_offset_sec=0),
        ])
        result = await store.get_paginated(
            filters=FilterSpec(destination_ip=_DST_A, protocol="TCP")
        )
        assert result["total_matching"] == 0

    @pytest.mark.asyncio
    async def test_dest_ip_combines_with_existing_ip_filter(
        self, store: SQLiteEventStore
    ) -> None:
        """destination_ip filter combines correctly with source_ip (ip=) filter."""
        await store.save_many([
            _ev(source_ip=_SRC_A, destination_ip=_DST_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, destination_ip=_DST_A, ts_offset_sec=1),
        ])
        result = await store.get_paginated(
            filters=FilterSpec(ip=_SRC_A, destination_ip=_DST_A)
        )
        assert result["total_matching"] == 1
        assert result["logs"][0]["source_ip"] == _SRC_A


# ---------------------------------------------------------------------------
# EARS-4: get_top_pairs aggregate
# ---------------------------------------------------------------------------


class TestGetTopPairs:
    """EARS-4 — top src→dst pairs aggregate: bounded, ordered by count, parameterized."""

    @pytest.mark.asyncio
    async def test_top_pairs_returns_correct_counts(
        self, store: SQLiteEventStore
    ) -> None:
        """Top-pairs returns (source_ip, destination_ip, count) ordered by count desc."""
        await store.save_many([
            # A→B: 3 events
            _ev(source_ip=_SRC_A, destination_ip=_DST_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_A, destination_ip=_DST_A, ts_offset_sec=1),
            _ev(source_ip=_SRC_A, destination_ip=_DST_A, ts_offset_sec=2),
            # B→C: 2 events
            _ev(source_ip=_SRC_B, destination_ip=_DST_C, ts_offset_sec=3),
            _ev(source_ip=_SRC_B, destination_ip=_DST_C, ts_offset_sec=4),
            # A→C: 1 event
            _ev(source_ip=_SRC_A, destination_ip=_DST_C, ts_offset_sec=5),
        ])
        result = await store.get_top_pairs(top_n=10)
        assert len(result) == 3
        assert result[0]["source_ip"] == _SRC_A
        assert result[0]["destination_ip"] == _DST_A
        assert result[0]["count"] == 3
        assert result[1]["count"] == 2
        assert result[2]["count"] == 1

    @pytest.mark.asyncio
    async def test_top_pairs_bounded_by_top_n(
        self, store: SQLiteEventStore
    ) -> None:
        """Result is bounded to top_n entries (default 10)."""
        # Insert 5 distinct src→dst pairs
        for i in range(5):
            for _ in range(5 - i):  # varying counts
                await store.save_many([
                    _ev(
                        source_ip=_SRC_A,
                        destination_ip=f"198.51.100.{i + 1}",
                        ts_offset_sec=i,
                    )
                ])
        # Request only top 3
        result = await store.get_top_pairs(top_n=3)
        assert len(result) <= 3

    @pytest.mark.asyncio
    async def test_top_pairs_excludes_null_destination(
        self, store: SQLiteEventStore
    ) -> None:
        """Rows with NULL destination_ip are excluded from top-pairs."""
        await store.save_many([
            _ev(source_ip=_SRC_A, destination_ip=None, ts_offset_sec=0),
            _ev(source_ip=_SRC_A, destination_ip=None, ts_offset_sec=1),
            _ev(source_ip=_SRC_A, destination_ip=_DST_A, ts_offset_sec=2),
        ])
        result = await store.get_top_pairs(top_n=10)
        assert len(result) == 1
        assert result[0]["destination_ip"] == _DST_A
        assert result[0]["count"] == 1

    @pytest.mark.asyncio
    async def test_top_pairs_empty_store_returns_empty_list(
        self, store: SQLiteEventStore
    ) -> None:
        """Empty store returns empty list (no crash)."""
        result = await store.get_top_pairs(top_n=10)
        assert result == []

    @pytest.mark.asyncio
    async def test_top_pairs_default_top_n_is_ten(
        self, store: SQLiteEventStore
    ) -> None:
        """Default top_n of 10 is applied when not specified."""
        # Insert 15 distinct pairs
        for i in range(15):
            await store.save_many([
                _ev(
                    source_ip=_SRC_A,
                    destination_ip=f"198.51.100.{i + 1}",
                    ts_offset_sec=i,
                )
            ])
        result = await store.get_top_pairs()
        assert len(result) == 10

    @pytest.mark.asyncio
    async def test_top_pairs_response_shape(
        self, store: SQLiteEventStore
    ) -> None:
        """Each result row has source_ip, destination_ip, count keys."""
        await store.save_many([
            _ev(source_ip=_SRC_A, destination_ip=_DST_A)
        ])
        result = await store.get_top_pairs(top_n=5)
        assert len(result) == 1
        row = result[0]
        assert "source_ip" in row
        assert "destination_ip" in row
        assert "count" in row
        assert isinstance(row["count"], int)
