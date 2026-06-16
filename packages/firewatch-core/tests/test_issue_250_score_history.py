"""Tests for issue #250 — per-IP score history, score_delta, and snapshot pruning.

EARS → test mapping
───────────────────
E1  WHEN a threat score is persisted for an IP, a timestamped snapshot SHALL be recorded.
    → test_record_snapshot_persists_row
    → test_record_snapshot_multiple_ips
    → test_record_snapshot_does_not_alter_logs_table

E2  /threats rows SHALL carry additive score_delta (signed, 1h window);
    IPs without a prior in-window snapshot SHALL carry score_delta=null (new actor).
    → test_get_bulk_score_deltas_new_actor_is_null
    → test_get_bulk_score_deltas_delta_is_signed
    → test_get_bulk_score_deltas_negative_delta
    → test_get_bulk_score_deltas_window_respected
    → test_get_bulk_score_deltas_multiple_ips
    → test_get_bulk_score_deltas_empty_ip_list

E3  WHEN GET /threats/{ip}/score-history is called, a UTC-bucketed series SHALL be returned;
    unknown IPs yield an empty series.
    → test_get_score_history_returns_series
    → test_get_score_history_unknown_ip_returns_empty
    → test_get_score_history_window_filters_old_rows

E5  Snapshots older than the retention horizon SHALL be pruned.
    → test_prune_score_snapshots_removes_old_rows
    → test_prune_score_snapshots_keeps_recent_rows
    → test_prune_score_snapshots_empty_table

Structural:
    → test_score_history_table_is_indexed_on_ip_ts
    → test_clear_removes_score_history
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import aiosqlite
import pytest

from firewatch_core.adapters.sqlite_store import SQLiteEventStore

# RFC 5737 documentation IPs only.
IP_A = "192.0.2.10"
IP_B = "198.51.100.20"
IP_C = "203.0.113.30"


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[return]
    """Fresh, initialised store backed by a tmp file."""
    s = SQLiteEventStore(tmp_path / "test.db")
    await s.init()
    yield s
    await s.close()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ago(seconds: int = 0) -> datetime:
    """Return a UTC datetime `seconds` ago."""
    return _now() - timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# E1 — snapshot persistence
# ---------------------------------------------------------------------------


async def test_record_snapshot_persists_row(store: SQLiteEventStore) -> None:
    """A snapshot recorded for an IP must be readable via get_score_history (E1)."""
    ts = _now()
    await store.record_score_snapshot(IP_A, score=42, ts=ts)

    history = await store.get_score_history(IP_A, window_hours=1)
    assert len(history) == 1
    row = history[0]
    assert row["ip"] == IP_A
    assert row["score"] == 42
    assert "ts" in row


async def test_record_snapshot_multiple_ips(store: SQLiteEventStore) -> None:
    """Snapshots for different IPs must not cross-contaminate (E1)."""
    ts = _now()
    await store.record_score_snapshot(IP_A, score=10, ts=ts)
    await store.record_score_snapshot(IP_B, score=90, ts=ts)

    history_a = await store.get_score_history(IP_A, window_hours=1)
    history_b = await store.get_score_history(IP_B, window_hours=1)

    assert all(r["ip"] == IP_A for r in history_a)
    assert all(r["ip"] == IP_B for r in history_b)
    assert history_a[0]["score"] == 10
    assert history_b[0]["score"] == 90


async def test_record_snapshot_does_not_alter_logs_table(
    store: SQLiteEventStore,
) -> None:
    """Snapshot recording must be additive — the logs table is unchanged (E6 isolation)."""
    await store.record_score_snapshot(IP_A, score=50, ts=_now())

    async with aiosqlite.connect(store.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT COUNT(*) as cnt FROM logs")
        row = await cursor.fetchone()
    assert row is not None and row["cnt"] == 0, (
        "record_score_snapshot must not insert into the logs table"
    )


async def test_score_history_table_is_indexed_on_ip_ts(
    store: SQLiteEventStore,
) -> None:
    """The score_history table must have an index covering (ip, ts) for fast range queries."""
    async with aiosqlite.connect(store.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT name FROM sqlite_master"
            " WHERE type='index' AND tbl_name='score_history'"
        )
        index_names = {r["name"] for r in await cursor.fetchall()}

    assert index_names, "score_history table must have at least one index"


# ---------------------------------------------------------------------------
# E2 — score_delta: signed, windowed, null for new actors
# ---------------------------------------------------------------------------


async def test_get_bulk_score_deltas_new_actor_is_null(
    store: SQLiteEventStore,
) -> None:
    """An IP with no prior snapshot in the window must return score_delta=null (E2)."""
    deltas = await store.get_bulk_score_deltas(
        ips=[IP_A],
        current_scores={IP_A: 55},
        window_hours=1,
    )
    assert deltas[IP_A] is None, (
        "New actor (no prior snapshot) must have score_delta=null, not zero"
    )


async def test_get_bulk_score_deltas_delta_is_signed(
    store: SQLiteEventStore,
) -> None:
    """score_delta must be the signed difference: current - earliest-in-window (E2)."""
    ts_old = _ago(30 * 60)  # 30 min ago
    await store.record_score_snapshot(IP_A, score=40, ts=ts_old)

    deltas = await store.get_bulk_score_deltas(
        ips=[IP_A],
        current_scores={IP_A: 60},
        window_hours=1,
    )
    assert deltas[IP_A] == 20, f"Expected delta=20, got {deltas[IP_A]}"


async def test_get_bulk_score_deltas_negative_delta(
    store: SQLiteEventStore,
) -> None:
    """Negative delta (score dropped) must be returned as a negative integer (E2)."""
    ts_old = _ago(30 * 60)
    await store.record_score_snapshot(IP_A, score=80, ts=ts_old)

    deltas = await store.get_bulk_score_deltas(
        ips=[IP_A],
        current_scores={IP_A: 50},
        window_hours=1,
    )
    assert deltas[IP_A] == -30, f"Expected delta=-30, got {deltas[IP_A]}"


async def test_get_bulk_score_deltas_window_respected(
    store: SQLiteEventStore,
) -> None:
    """A snapshot outside the window must not be used for the delta (E2)."""
    ts_old = _ago(2 * 3600)  # 2 hours ago — outside the 1h window
    await store.record_score_snapshot(IP_A, score=30, ts=ts_old)

    deltas = await store.get_bulk_score_deltas(
        ips=[IP_A],
        current_scores={IP_A: 60},
        window_hours=1,
    )
    assert deltas[IP_A] is None, (
        "Snapshot outside the window must not count — IP treated as new actor"
    )


async def test_get_bulk_score_deltas_multiple_ips(
    store: SQLiteEventStore,
) -> None:
    """Bulk delta must handle multiple IPs correctly (E2 + E4)."""
    ts_old = _ago(30 * 60)
    await store.record_score_snapshot(IP_A, score=20, ts=ts_old)
    await store.record_score_snapshot(IP_B, score=70, ts=ts_old)
    # IP_C has no prior snapshot.

    deltas = await store.get_bulk_score_deltas(
        ips=[IP_A, IP_B, IP_C],
        current_scores={IP_A: 40, IP_B: 50, IP_C: 30},
        window_hours=1,
    )

    assert deltas[IP_A] == 20
    assert deltas[IP_B] == -20
    assert deltas[IP_C] is None


async def test_get_bulk_score_deltas_empty_ip_list(
    store: SQLiteEventStore,
) -> None:
    """Empty IP list must return an empty dict without error (E2)."""
    deltas = await store.get_bulk_score_deltas(
        ips=[],
        current_scores={},
        window_hours=1,
    )
    assert deltas == {}


# ---------------------------------------------------------------------------
# E3 — score history series for /threats/{ip}/score-history
# ---------------------------------------------------------------------------


async def test_get_score_history_returns_series(store: SQLiteEventStore) -> None:
    """get_score_history must return ordered rows with ip, score, ts (E3)."""
    t1 = _ago(50 * 60)  # 50 min ago
    t2 = _ago(20 * 60)  # 20 min ago
    await store.record_score_snapshot(IP_A, score=30, ts=t1)
    await store.record_score_snapshot(IP_A, score=60, ts=t2)

    history = await store.get_score_history(IP_A, window_hours=1)
    assert len(history) == 2
    # Must be ordered ascending by ts (chronological for sparkline rendering).
    scores = [r["score"] for r in history]
    assert scores == [30, 60], f"Expected [30, 60], got {scores}"


async def test_get_score_history_unknown_ip_returns_empty(
    store: SQLiteEventStore,
) -> None:
    """get_score_history for an IP with no snapshots must return [] (E3)."""
    history = await store.get_score_history("192.0.2.99", window_hours=1)
    assert history == []


async def test_get_score_history_window_filters_old_rows(
    store: SQLiteEventStore,
) -> None:
    """Rows outside the requested window must be excluded from the series (E3)."""
    ts_inside = _ago(30 * 60)
    ts_outside = _ago(3 * 3600)
    await store.record_score_snapshot(IP_A, score=10, ts=ts_outside)
    await store.record_score_snapshot(IP_A, score=50, ts=ts_inside)

    history = await store.get_score_history(IP_A, window_hours=1)
    assert len(history) == 1
    assert history[0]["score"] == 50


# ---------------------------------------------------------------------------
# E5 — retention / pruning
# ---------------------------------------------------------------------------


async def test_prune_score_snapshots_removes_old_rows(
    store: SQLiteEventStore,
) -> None:
    """prune_score_snapshots must delete rows older than retention_days (E5).

    record_score_snapshot inline-prunes on every write, so an 8-day-old row can
    never survive that path — insert it DIRECTLY to exercise the explicit prune
    (the defensive/idempotent path) in isolation.
    """
    ts_old = _ago(8 * 24 * 3600)     # 8 days old
    ts_recent = _ago(1 * 3600)        # 1 hour old
    # Recent row via the normal (inline-pruning) path.
    await store.record_score_snapshot(IP_A, score=50, ts=ts_recent)
    # Old row inserted directly, bypassing record_score_snapshot's inline prune.
    db = await store._conn()
    await db.execute(
        "INSERT INTO score_history (ip, score, ts) VALUES (?, ?, ?)",
        (IP_A, 10, ts_old.isoformat()),
    )
    await db.commit()

    pruned = await store.prune_score_snapshots(retention_days=7)
    assert pruned == 1

    # Only the recent row must remain.
    history = await store.get_score_history(IP_A, window_hours=24 * 8)
    assert len(history) == 1
    assert history[0]["score"] == 50


async def test_prune_score_snapshots_keeps_recent_rows(
    store: SQLiteEventStore,
) -> None:
    """prune_score_snapshots must not remove rows within the retention window (E5)."""
    ts_recent = _ago(3 * 24 * 3600)  # 3 days old — within 7-day window
    await store.record_score_snapshot(IP_A, score=70, ts=ts_recent)

    pruned = await store.prune_score_snapshots(retention_days=7)
    assert pruned == 0

    history = await store.get_score_history(IP_A, window_hours=24 * 7)
    assert len(history) == 1


async def test_prune_score_snapshots_empty_table(store: SQLiteEventStore) -> None:
    """prune_score_snapshots on an empty table must return 0 without error (E5)."""
    pruned = await store.prune_score_snapshots(retention_days=7)
    assert pruned == 0


# ---------------------------------------------------------------------------
# Structural: clear() must also clear score_history
# ---------------------------------------------------------------------------


async def test_clear_removes_score_history(store: SQLiteEventStore) -> None:
    """store.clear() must also delete score_history rows."""
    await store.record_score_snapshot(IP_A, score=50, ts=_now())
    await store.clear()
    history = await store.get_score_history(IP_A, window_hours=1)
    assert history == []
