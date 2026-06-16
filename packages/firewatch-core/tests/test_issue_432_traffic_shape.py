"""Tests for ML-4 — get_top_talkers + get_protocol_mix (store layer).

Mapped 1:1 to EARS criteria from issue #432.

EARS-2  GET /logs/top-talkers and GET /logs/protocol-mix SHALL return GROUP-BY
        counts (mirroring get_categories):
        - top-talkers returns IPs ordered by count DESC, bounded by top_n
        - top-talkers includes blocked count per IP
        - protocol-mix returns protocols ordered by count DESC, bounded by top_n
        - protocol-mix aggregates NULL protocol rows under '(unknown)'
        - both methods are bounded via ? placeholder (defense-in-depth)

API route tests live in packages/firewatch-api/tests/test_issue_432_traffic_routes.py.

All IPs use RFC 5737 / RFC 1918 documentation ranges — no real/routable IPs.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from firewatch_sdk import SecurityEvent
from firewatch_sdk.models import ActionLiteral
from firewatch_core.adapters.sqlite_store import SQLiteEventStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS_BASE = datetime(2026, 6, 13, 12, 0, 0, tzinfo=timezone.utc)

# RFC 5737 / RFC 1918 IPs — never real/routable
_SRC_A = "192.0.2.10"
_SRC_B = "192.0.2.20"
_SRC_C = "192.0.2.30"


def _ev(
    *,
    source_ip: str = _SRC_A,
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
        protocol=protocol,
        **kwargs,
    )


@pytest.fixture
async def store(tmp_path: Path) -> SQLiteEventStore:  # type: ignore[misc]
    s = SQLiteEventStore(tmp_path / "ml4.db")
    await s.init()
    yield s  # type: ignore[misc]
    await s.close()


# ---------------------------------------------------------------------------
# get_top_talkers
# ---------------------------------------------------------------------------


class TestGetTopTalkers:
    """EARS-2 — get_top_talkers returns IPs ordered by count DESC."""

    @pytest.mark.asyncio
    async def test_returns_ips_ordered_by_count_desc(
        self, store: SQLiteEventStore
    ) -> None:
        """Top talkers are ordered by event count descending."""
        # SRC_B gets 3 events, SRC_A gets 1 — so SRC_B should rank first.
        await store.save_many([
            _ev(source_ip=_SRC_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, ts_offset_sec=1),
            _ev(source_ip=_SRC_B, ts_offset_sec=2),
            _ev(source_ip=_SRC_B, ts_offset_sec=3),
        ])
        rows = await store.get_top_talkers(top_n=10)
        assert len(rows) == 2
        assert rows[0]["source_ip"] == _SRC_B
        assert rows[0]["count"] == 3
        assert rows[1]["source_ip"] == _SRC_A
        assert rows[1]["count"] == 1

    @pytest.mark.asyncio
    async def test_includes_blocked_count(
        self, store: SQLiteEventStore
    ) -> None:
        """Each row includes the count of BLOCK/DROP events."""
        await store.save_many([
            _ev(source_ip=_SRC_A, action="BLOCK", ts_offset_sec=0),
            _ev(source_ip=_SRC_A, action="DROP", ts_offset_sec=1),
            _ev(source_ip=_SRC_A, action="ALERT", ts_offset_sec=2),
        ])
        rows = await store.get_top_talkers(top_n=10)
        assert len(rows) == 1
        assert rows[0]["count"] == 3
        assert rows[0]["blocked"] == 2

    @pytest.mark.asyncio
    async def test_bounded_by_top_n(self, store: SQLiteEventStore) -> None:
        """Result is bounded to at most top_n rows."""
        # Insert 3 distinct IPs
        await store.save_many([
            _ev(source_ip=_SRC_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, ts_offset_sec=1),
            _ev(source_ip=_SRC_C, ts_offset_sec=2),
        ])
        rows = await store.get_top_talkers(top_n=2)
        assert len(rows) == 2

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_data(
        self, store: SQLiteEventStore
    ) -> None:
        """Empty store returns an empty list."""
        rows = await store.get_top_talkers(top_n=10)
        assert rows == []

    @pytest.mark.asyncio
    async def test_top_n_coerced_to_positive_int(
        self, store: SQLiteEventStore
    ) -> None:
        """top_n=0 is coerced to 1 (safe_limit = max(1, int(top_n)))."""
        await store.save_many([_ev(source_ip=_SRC_A)])
        # Should not raise — coerces 0 → 1 internally
        rows = await store.get_top_talkers(top_n=0)
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# get_protocol_mix
# ---------------------------------------------------------------------------


class TestGetProtocolMix:
    """EARS-2 — get_protocol_mix returns protocols ordered by count DESC."""

    @pytest.mark.asyncio
    async def test_returns_protocols_ordered_by_count_desc(
        self, store: SQLiteEventStore
    ) -> None:
        """Protocols ordered by event count descending."""
        await store.save_many([
            _ev(protocol="TCP", ts_offset_sec=0),
            _ev(protocol="TCP", ts_offset_sec=1),
            _ev(protocol="UDP", ts_offset_sec=2),
        ])
        rows = await store.get_protocol_mix(top_n=10)
        assert len(rows) == 2
        assert rows[0]["protocol"] == "TCP"
        assert rows[0]["count"] == 2
        assert rows[1]["protocol"] == "UDP"
        assert rows[1]["count"] == 1

    @pytest.mark.asyncio
    async def test_null_protocol_aggregated_as_unknown(
        self, store: SQLiteEventStore
    ) -> None:
        """NULL protocol rows appear under the '(unknown)' sentinel."""
        await store.save_many([
            _ev(protocol=None, ts_offset_sec=0),
            _ev(protocol=None, ts_offset_sec=1),
            _ev(protocol="TCP", ts_offset_sec=2),
        ])
        rows = await store.get_protocol_mix(top_n=10)
        protocols = {r["protocol"]: r["count"] for r in rows}
        assert "(unknown)" in protocols
        assert protocols["(unknown)"] == 2
        assert protocols["TCP"] == 1

    @pytest.mark.asyncio
    async def test_bounded_by_top_n(self, store: SQLiteEventStore) -> None:
        """Result is bounded to at most top_n rows."""
        await store.save_many([
            _ev(protocol="TCP", ts_offset_sec=0),
            _ev(protocol="UDP", ts_offset_sec=1),
            _ev(protocol="ICMP", ts_offset_sec=2),
        ])
        rows = await store.get_protocol_mix(top_n=2)
        assert len(rows) == 2

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_data(
        self, store: SQLiteEventStore
    ) -> None:
        """Empty store returns an empty list."""
        rows = await store.get_protocol_mix(top_n=10)
        assert rows == []
