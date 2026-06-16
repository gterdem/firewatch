"""Tests for issue #663 — get_logs_stats store method (filter-scoped totals).

Mapped 1:1 to EARS acceptance criteria from issue #663.

EARS-1  WHEN get_logs_stats() called with no facets, it SHALL return the true
        whole-store counts (total_events=COUNT(*), distinct_ips=COUNT(DISTINCT source_ip),
        blocked_events=action IN (BLOCK,DROP)).
EARS-2  WHEN called with FilterSpec facets, the three counts SHALL reflect only
        matching rows (shared predicate with /logs/paginated).
EARS-3  The three values SHALL NOT be derived from any top-N list.
EARS-4  WHEN attacker-controlled facets are passed, they SHALL be ?-bound (B1).
EARS-5  present_source_types reflects the DISTINCT source_type values in scope.

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


# ---------------------------------------------------------------------------
# Shared helpers / constants
# ---------------------------------------------------------------------------

# RFC 5737 documentation IPs only — never real/routable
_SRC_A = "192.0.2.10"
_SRC_B = "192.0.2.20"
_SRC_C = "192.0.2.30"
_DST_A = "198.51.100.1"

_TS_BASE = datetime(2026, 6, 13, 12, 0, 0, tzinfo=timezone.utc)


def _ev(
    *,
    source_ip: str = _SRC_A,
    destination_ip: str | None = None,
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
        severity=severity,
        category=category,
    )


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    """Fresh initialised SQLiteEventStore."""
    s = SQLiteEventStore(tmp_path / "663.db")
    await s.init()
    yield s
    await s.close()


# ---------------------------------------------------------------------------
# EARS-1: whole-store counts (no filter)
# ---------------------------------------------------------------------------


class TestLogsStatsNoFilter:
    """EARS-1 — whole-store counts when no facets supplied."""

    @pytest.mark.asyncio
    async def test_total_events_counts_all_rows(self, store: SQLiteEventStore) -> None:
        """total_events is COUNT(*) across all rows when no filter applied."""
        await store.save_many([
            _ev(source_ip=_SRC_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_B, ts_offset_sec=1),
            _ev(source_ip=_SRC_C, ts_offset_sec=2),
        ])
        result = await store.get_logs_stats()
        assert result["total_events"] == 3

    @pytest.mark.asyncio
    async def test_blocked_events_counts_block_and_drop(self, store: SQLiteEventStore) -> None:
        """blocked_events counts rows where action IN (BLOCK, DROP)."""
        await store.save_many([
            _ev(source_ip=_SRC_A, action="BLOCK", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, action="DROP", ts_offset_sec=1),
            _ev(source_ip=_SRC_C, action="ALERT", ts_offset_sec=2),
        ])
        result = await store.get_logs_stats()
        assert result["blocked_events"] == 2
        assert result["total_events"] == 3

    @pytest.mark.asyncio
    async def test_distinct_ips_counts_unique_source_ips(self, store: SQLiteEventStore) -> None:
        """distinct_ips is COUNT(DISTINCT source_ip) across all rows."""
        await store.save_many([
            _ev(source_ip=_SRC_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_A, ts_offset_sec=1),  # duplicate — same IP
            _ev(source_ip=_SRC_B, ts_offset_sec=2),
        ])
        result = await store.get_logs_stats()
        assert result["distinct_ips"] == 2

    @pytest.mark.asyncio
    async def test_empty_store_returns_zeros(self, store: SQLiteEventStore) -> None:
        """An empty store returns all-zero counts."""
        result = await store.get_logs_stats()
        assert result["total_events"] == 0
        assert result["blocked_events"] == 0
        assert result["distinct_ips"] == 0

    @pytest.mark.asyncio
    async def test_filters_none_equals_no_arg(self, store: SQLiteEventStore) -> None:
        """filters=None and omitting filters produce identical results."""
        await store.save_many([
            _ev(source_ip=_SRC_A, action="BLOCK", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, action="ALERT", ts_offset_sec=1),
        ])
        result_default = await store.get_logs_stats()
        result_none = await store.get_logs_stats(filters=None)
        result_empty = await store.get_logs_stats(filters=FilterSpec())
        assert result_default == result_none == result_empty

    @pytest.mark.asyncio
    async def test_present_source_types_all_when_no_filter(self, store: SQLiteEventStore) -> None:
        """present_source_types lists ALL distinct source_type values when no filter."""
        await store.save_many([
            _ev(source_ip=_SRC_A, source_type="suricata", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, source_type="azure_waf", ts_offset_sec=1),
        ])
        result = await store.get_logs_stats()
        assert set(result["present_source_types"]) == {"suricata", "azure_waf"}

    @pytest.mark.asyncio
    async def test_present_source_types_is_sorted(self, store: SQLiteEventStore) -> None:
        """present_source_types is sorted alphabetically."""
        await store.save_many([
            _ev(source_ip=_SRC_A, source_type="suricata", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, source_type="azure_waf", ts_offset_sec=1),
        ])
        result = await store.get_logs_stats()
        types = result["present_source_types"]
        assert types == sorted(types)


# ---------------------------------------------------------------------------
# EARS-2: filter-scoped counts
# ---------------------------------------------------------------------------


class TestLogsStatsWithFilters:
    """EARS-2 — the three counts reflect only matching rows when facets are applied."""

    @pytest.mark.asyncio
    async def test_ip_filter_scopes_total_events(self, store: SQLiteEventStore) -> None:
        """FilterSpec.ip scopes total_events to matching source IPs only."""
        await store.save_many([
            _ev(source_ip=_SRC_A, ts_offset_sec=0),
            _ev(source_ip=_SRC_A, ts_offset_sec=1),
            _ev(source_ip=_SRC_B, ts_offset_sec=2),
        ])
        result = await store.get_logs_stats(filters=FilterSpec(ip=_SRC_A))
        assert result["total_events"] == 2
        assert result["distinct_ips"] == 1

    @pytest.mark.asyncio
    async def test_action_filter_scopes_blocked_events(self, store: SQLiteEventStore) -> None:
        """Filtering to blocked rows: total_events and blocked_events both reflect the scope."""
        await store.save_many([
            _ev(source_ip=_SRC_A, action="BLOCK", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, action="ALERT", ts_offset_sec=1),
        ])
        result = await store.get_logs_stats(filters=FilterSpec(action="blocked"))
        # Only the BLOCK row matches the filter
        assert result["total_events"] == 1
        assert result["blocked_events"] == 1

    @pytest.mark.asyncio
    async def test_source_type_filter_scopes_all_counts(self, store: SQLiteEventStore) -> None:
        """FilterSpec.source_type scopes all three counts to that source type."""
        await store.save_many([
            _ev(source_ip=_SRC_A, action="BLOCK", source_type="suricata", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, action="ALERT", source_type="azure_waf", ts_offset_sec=1),
        ])
        result = await store.get_logs_stats(filters=FilterSpec(source_type="suricata"))
        assert result["total_events"] == 1
        assert result["blocked_events"] == 1
        assert result["distinct_ips"] == 1

    @pytest.mark.asyncio
    async def test_severity_filter_scopes_counts(self, store: SQLiteEventStore) -> None:
        """FilterSpec.severity scopes counts to matching severity rows."""
        await store.save_many([
            _ev(source_ip=_SRC_A, severity="critical", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, severity="low", ts_offset_sec=1),
        ])
        result = await store.get_logs_stats(filters=FilterSpec(severity="critical"))
        assert result["total_events"] == 1
        assert result["distinct_ips"] == 1

    @pytest.mark.asyncio
    async def test_filter_that_matches_nothing_returns_zeros(self, store: SQLiteEventStore) -> None:
        """A filter matching no rows returns zeros, not an error."""
        await store.save_many([
            _ev(source_ip=_SRC_A, source_type="suricata", ts_offset_sec=0),
        ])
        result = await store.get_logs_stats(filters=FilterSpec(source_type="azure_waf"))
        assert result["total_events"] == 0
        assert result["blocked_events"] == 0
        assert result["distinct_ips"] == 0

    @pytest.mark.asyncio
    async def test_present_source_types_scoped_by_filter(self, store: SQLiteEventStore) -> None:
        """EARS-5 — present_source_types reflects sources within the filtered scope."""
        await store.save_many([
            _ev(source_ip=_SRC_A, source_type="suricata", severity="critical", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, source_type="azure_waf", severity="low", ts_offset_sec=1),
        ])
        result = await store.get_logs_stats(filters=FilterSpec(severity="critical"))
        assert result["present_source_types"] == ["suricata"]

    @pytest.mark.asyncio
    async def test_start_end_scopes_counts(self, store: SQLiteEventStore) -> None:
        """start/end timestamp range scopes all counts."""
        await store.save_many([
            _ev(source_ip=_SRC_A, action="BLOCK", ts_offset_sec=0),
            _ev(source_ip=_SRC_B, action="ALERT", ts_offset_sec=3600),  # 1 hour later
        ])
        start = _TS_BASE.isoformat()
        end = (_TS_BASE + timedelta(minutes=30)).isoformat()
        result = await store.get_logs_stats(start=start, end=end)
        # Only the first event (T=0) falls within the window
        assert result["total_events"] == 1
        assert result["blocked_events"] == 1
        assert result["distinct_ips"] == 1


# ---------------------------------------------------------------------------
# EARS-3: counts not derived from top-N list
# ---------------------------------------------------------------------------


class TestLogsStatsNotTopN:
    """EARS-3 — totals reflect ALL matching rows, not a top-N subset."""

    @pytest.mark.asyncio
    async def test_total_events_exceeds_top_ten(self, store: SQLiteEventStore) -> None:
        """total_events counts all rows even when there are more than 10 source IPs."""
        # Insert 15 distinct IPs with 2 events each = 30 total events
        # A top-10-only approach would cap at 20 events
        events = []
        for i in range(15):
            ip = f"192.0.2.{i + 1}"
            events.append(_ev(source_ip=ip, ts_offset_sec=i * 2))
            events.append(_ev(source_ip=ip, ts_offset_sec=i * 2 + 1))
        await store.save_many(events)

        result = await store.get_logs_stats()
        assert result["total_events"] == 30
        assert result["distinct_ips"] == 15

    @pytest.mark.asyncio
    async def test_blocked_events_counts_all_not_top_n(self, store: SQLiteEventStore) -> None:
        """blocked_events counts ALL blocked rows even beyond 10 IPs."""
        events = []
        for i in range(12):
            ip = f"192.0.2.{i + 1}"
            events.append(_ev(source_ip=ip, action="BLOCK", ts_offset_sec=i))
        await store.save_many(events)

        result = await store.get_logs_stats()
        # 12 blocked events across 12 IPs — a top-10 list would only see 10
        assert result["blocked_events"] == 12
        assert result["distinct_ips"] == 12


# ---------------------------------------------------------------------------
# EARS-4: B1 — values are ?-bound (no SQL injection)
# ---------------------------------------------------------------------------


class TestLogsStatsSecurityB1:
    """EARS-4 — attacker-controlled facets flow through ? placeholders only."""

    @pytest.mark.asyncio
    async def test_injection_attempt_in_ip_filter_does_not_break(
        self, store: SQLiteEventStore
    ) -> None:
        """SQL-injection string in ip filter is ? -bound; query returns 0 safely."""
        await store.save_many([_ev(source_ip=_SRC_A, ts_offset_sec=0)])
        # Injection payload — would cause SQL error if not properly bound
        malicious_ip = "'; DROP TABLE logs; --"
        result = await store.get_logs_stats(filters=FilterSpec(ip=malicious_ip))
        # Must not raise; must return zeros (no match)
        assert result["total_events"] == 0

    @pytest.mark.asyncio
    async def test_injection_attempt_in_source_type_does_not_break(
        self, store: SQLiteEventStore
    ) -> None:
        """SQL-injection string in source_type filter is ?-bound safely."""
        await store.save_many([_ev(source_ip=_SRC_A, ts_offset_sec=0)])
        malicious_type = "' OR '1'='1"
        result = await store.get_logs_stats(filters=FilterSpec(source_type=malicious_type))
        assert result["total_events"] == 0
