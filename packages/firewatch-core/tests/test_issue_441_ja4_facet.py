"""Tests for ML-13 — JA4+ fingerprint facet (consume-only, issue #441).

Mapped 1:1 to EARS criteria from issue #441 (store layer).

EARS-1  FilterSpec + store.get_paginated SHALL accept tls_ja4 (exact match)
        filter, backed by a WHERE clause.
        - filter by tls_ja4 returns only rows with that fingerprint
        - filter with no-match returns empty result
        - rows with NULL tls_ja4 are excluded by the filter
        - parameterized SQL (no injection from filter values)

EARS-2  WHERE the sensor does not emit JA4, tls_ja4 is NULL and the
        get_paginated row carries NULL tls_ja4 (honest, absent).
        - saving an event without tls_ja4 stores NULL
        - the paginated row has tls_ja4=None when source omitted it

EARS-1  get_top_ja4 aggregate SHALL return top JA4 fingerprints with counts;
        bounded top-N; NULL tls_ja4 rows excluded.
        - returns fingerprints ordered by count DESC
        - bounded by requested limit
        - NULL tls_ja4 rows are excluded from the aggregate
        - empty store returns empty list (no crash)
        - each row has tls_ja4 and count keys

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

# RFC 5737 / RFC 1918 IPs — never real/routable
_SRC_A = "192.0.2.10"
_SRC_B = "192.0.2.20"

# Synthetic JA4 fingerprints (opaque strings — not real sensor captures)
_JA4_C2 = "t13d1516h2_8daaf6152771_02713d6af862"
_JA4_MALWARE = "t13d201100h2_40348e13a07b_f11594a38c92"


def _ev(
    *,
    source_ip: str = _SRC_A,
    tls_ja4: str | None = None,
    tls_ja4s: str | None = None,
    tls_sni: str | None = None,
    tls_version: str | None = None,
    action: ActionLiteral = "ALERT",
    ts_offset_sec: int = 0,
    **kwargs: Any,
) -> SecurityEvent:
    ts = datetime(2026, 6, 13, 12, 0, ts_offset_sec % 60, tzinfo=timezone.utc)
    return SecurityEvent(
        source_type="suricata",
        source_id="sensor",
        source_ip=source_ip,
        action=action,
        timestamp=ts,
        tls_ja4=tls_ja4,
        tls_ja4s=tls_ja4s,
        tls_sni=tls_sni,
        tls_version=tls_version,
        **kwargs,
    )


@pytest.fixture
async def store(tmp_path: Path) -> SQLiteEventStore:  # type: ignore[misc]
    s = SQLiteEventStore(tmp_path / "ml13.db")
    await s.init()
    yield s  # type: ignore[misc]
    await s.close()


# ---------------------------------------------------------------------------
# EARS-2: NULL tls_ja4 is stored and returned as None (honest, absent)
# ---------------------------------------------------------------------------


class TestJa4NullIsHonest:
    """EARS-2 — NULL tls_ja4 is stored and returned honestly as None."""

    @pytest.mark.asyncio
    async def test_event_without_ja4_stores_null(
        self, store: SQLiteEventStore
    ) -> None:
        """Saving an event without tls_ja4 stores NULL in the DB column."""
        await store.save_many([_ev(tls_ja4=None, ts_offset_sec=0)])
        result = await store.get_paginated()
        assert result["total_matching"] == 1
        row = result["logs"][0]
        # NULL stored -> None returned (honest absence)
        assert row.get("tls_ja4") is None

    @pytest.mark.asyncio
    async def test_event_with_ja4_stores_value(
        self, store: SQLiteEventStore
    ) -> None:
        """Saving an event with tls_ja4 stores the fingerprint in the DB column."""
        await store.save_many([_ev(tls_ja4=_JA4_C2, ts_offset_sec=0)])
        result = await store.get_paginated()
        assert result["total_matching"] == 1
        row = result["logs"][0]
        assert row.get("tls_ja4") == _JA4_C2

    @pytest.mark.asyncio
    async def test_tls_sni_and_version_also_stored(
        self, store: SQLiteEventStore
    ) -> None:
        """tls_sni and tls_version are stored and returned in the row."""
        await store.save_many([
            _ev(
                tls_ja4=_JA4_C2,
                tls_sni="c2.example.internal",
                tls_version="TLSv1.3",
                ts_offset_sec=0,
            )
        ])
        result = await store.get_paginated()
        row = result["logs"][0]
        assert row.get("tls_sni") == "c2.example.internal"
        assert row.get("tls_version") == "TLSv1.3"


# ---------------------------------------------------------------------------
# EARS-1: tls_ja4 exact-match filter
# ---------------------------------------------------------------------------


class TestJa4Filter:
    """EARS-1 — tls_ja4 exact-match filter backs a WHERE clause."""

    @pytest.mark.asyncio
    async def test_filter_by_ja4_returns_matching_rows(
        self, store: SQLiteEventStore
    ) -> None:
        """Filter tls_ja4=<fingerprint> returns only rows with that value."""
        await store.save_many([
            _ev(tls_ja4=_JA4_C2, ts_offset_sec=0),
            _ev(tls_ja4=_JA4_MALWARE, ts_offset_sec=1),
            _ev(tls_ja4=None, ts_offset_sec=2),
        ])
        result = await store.get_paginated(filters=FilterSpec(tls_ja4=_JA4_C2))
        assert result["total_matching"] == 1
        assert result["logs"][0]["tls_ja4"] == _JA4_C2

    @pytest.mark.asyncio
    async def test_filter_by_ja4_no_match_returns_empty(
        self, store: SQLiteEventStore
    ) -> None:
        """A tls_ja4 filter with no matching rows returns empty."""
        await store.save_many([_ev(tls_ja4=_JA4_C2, ts_offset_sec=0)])
        result = await store.get_paginated(
            filters=FilterSpec(tls_ja4="t00d000000h0_000000000000_000000000000")
        )
        assert result["total_matching"] == 0
        assert result["logs"] == []

    @pytest.mark.asyncio
    async def test_filter_by_ja4_excludes_null_rows(
        self, store: SQLiteEventStore
    ) -> None:
        """Rows with NULL tls_ja4 are excluded when a filter is active."""
        await store.save_many([
            _ev(tls_ja4=None, ts_offset_sec=0),
            _ev(tls_ja4=_JA4_C2, ts_offset_sec=1),
        ])
        result = await store.get_paginated(filters=FilterSpec(tls_ja4=_JA4_C2))
        assert result["total_matching"] == 1

    @pytest.mark.asyncio
    async def test_filter_ja4_sql_injection_safe(
        self, store: SQLiteEventStore
    ) -> None:
        """A filter value with SQL metacharacters is treated as a literal — no injection.

        The store uses parameterized placeholders (B1 safety invariant).
        No rows match the injected string and no error is raised.
        """
        await store.save_many([_ev(tls_ja4=_JA4_C2, ts_offset_sec=0)])
        result = await store.get_paginated(
            filters=FilterSpec(tls_ja4="'; DROP TABLE logs; --")
        )
        assert result["total_matching"] == 0

    @pytest.mark.asyncio
    async def test_filter_ja4_combines_with_source_ip_filter(
        self, store: SQLiteEventStore
    ) -> None:
        """tls_ja4 filter combines additively with ip= filter."""
        await store.save_many([
            _ev(source_ip=_SRC_A, tls_ja4=_JA4_C2, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, tls_ja4=_JA4_C2, ts_offset_sec=1),
        ])
        result = await store.get_paginated(
            filters=FilterSpec(ip=_SRC_A, tls_ja4=_JA4_C2)
        )
        assert result["total_matching"] == 1
        assert result["logs"][0]["source_ip"] == _SRC_A


# ---------------------------------------------------------------------------
# EARS-1: get_top_ja4 aggregate
# ---------------------------------------------------------------------------


class TestGetTopJa4:
    """EARS-1 — get_top_ja4 aggregate: bounded, ordered, NULL excluded."""

    @pytest.mark.asyncio
    async def test_top_ja4_returns_correct_counts(
        self, store: SQLiteEventStore
    ) -> None:
        """Top-JA4 returns (tls_ja4, count) ordered by count descending."""
        await store.save_many([
            # C2 fingerprint: 3 events
            _ev(tls_ja4=_JA4_C2, ts_offset_sec=0),
            _ev(tls_ja4=_JA4_C2, ts_offset_sec=1),
            _ev(tls_ja4=_JA4_C2, ts_offset_sec=2),
            # Malware fingerprint: 2 events
            _ev(tls_ja4=_JA4_MALWARE, ts_offset_sec=3),
            _ev(tls_ja4=_JA4_MALWARE, ts_offset_sec=4),
            # NULL fingerprint: should be excluded
            _ev(tls_ja4=None, ts_offset_sec=5),
        ])
        result = await store.get_top_ja4(top_n=10)
        assert len(result) == 2
        assert result[0]["tls_ja4"] == _JA4_C2
        assert result[0]["count"] == 3
        assert result[1]["tls_ja4"] == _JA4_MALWARE
        assert result[1]["count"] == 2

    @pytest.mark.asyncio
    async def test_top_ja4_bounded_by_top_n(
        self, store: SQLiteEventStore
    ) -> None:
        """Result is bounded to top_n entries."""
        # Insert 5 distinct fingerprints with varying counts
        fingerprints = [f"t13d{i:04d}h2_aabbccddeeff_112233445566" for i in range(5)]
        for i, fp in enumerate(fingerprints):
            for _ in range(5 - i):
                await store.save_many([_ev(tls_ja4=fp, ts_offset_sec=i)])
        result = await store.get_top_ja4(top_n=3)
        assert len(result) <= 3

    @pytest.mark.asyncio
    async def test_top_ja4_excludes_null_fingerprints(
        self, store: SQLiteEventStore
    ) -> None:
        """NULL tls_ja4 rows are excluded from the top-JA4 aggregate."""
        await store.save_many([
            _ev(tls_ja4=None, ts_offset_sec=0),
            _ev(tls_ja4=None, ts_offset_sec=1),
            _ev(tls_ja4=_JA4_C2, ts_offset_sec=2),
        ])
        result = await store.get_top_ja4(top_n=10)
        assert len(result) == 1
        assert result[0]["tls_ja4"] == _JA4_C2

    @pytest.mark.asyncio
    async def test_top_ja4_empty_store_returns_empty_list(
        self, store: SQLiteEventStore
    ) -> None:
        """Empty store returns empty list (no crash)."""
        result = await store.get_top_ja4(top_n=10)
        assert result == []

    @pytest.mark.asyncio
    async def test_top_ja4_response_shape(
        self, store: SQLiteEventStore
    ) -> None:
        """Each result row has tls_ja4 and count keys."""
        await store.save_many([_ev(tls_ja4=_JA4_C2, ts_offset_sec=0)])
        result = await store.get_top_ja4(top_n=5)
        assert len(result) == 1
        row = result[0]
        assert "tls_ja4" in row
        assert "count" in row
        assert isinstance(row["count"], int)

    @pytest.mark.asyncio
    async def test_top_ja4_all_null_returns_empty(
        self, store: SQLiteEventStore
    ) -> None:
        """When all rows have NULL tls_ja4, returns empty list gracefully."""
        await store.save_many([
            _ev(tls_ja4=None, ts_offset_sec=0),
            _ev(tls_ja4=None, ts_offset_sec=1),
        ])
        result = await store.get_top_ja4(top_n=10)
        assert result == []
