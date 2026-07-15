"""Pipeline-level integration test for BLOCKING-1: score_history wiring.

Tests that analyze_ip actually calls _record_score_snapshot and _get_score_delta,
so score_history rows are written and ThreatScore.score_delta is populated.

EARS → test mapping
───────────────────
BLOCKING-1A  WHEN analyze_ip is called, score_history SHALL receive a timestamped snapshot.
             → test_analyze_ip_writes_score_history_row

BLOCKING-1B  WHEN analyze_ip is called twice for the same IP with changing scores,
             the second ThreatScore.score_delta SHALL be the signed change (not None).
             → test_analyze_ip_second_call_has_score_delta

BLOCKING-1C  WHEN analyze_ip is called for the first time (no prior snapshot),
             ThreatScore.score_delta SHALL be None (new actor semantics).
             → test_analyze_ip_first_call_score_delta_is_none

Structural:
BLOCKING-1D  analyze_ip with no events for an IP must still return score_delta=None
             without error (no snapshot written for zero-event path).
             → test_analyze_ip_empty_ip_no_snapshot_written
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from firewatch_core.adapters.sqlite_store import SQLiteEventStore
from firewatch_core.pipeline import Pipeline
from _fakes import FakeAIEngine, make_event

# RFC 5737 documentation IPs only.
IP_A = "192.0.2.10"
IP_B = "198.51.100.20"

# Base timestamp used to build events with distinct timestamps (avoiding dedup).
_T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

# Issue #52 (ADR-0070 D4): analyze_ip now windows run_rules/decide() to a
# trailing W_STATE slice measured from "now". These tests seed events at
# _T0-relative offsets (up to +60min), so a fixed synthetic clock 2h after _T0
# keeps both event batches inside W_STATE without relying on the real wall
# clock (no wall-clock flakiness).
_CLOCK = lambda: _T0 + timedelta(hours=2)  # noqa: E731


def _blocked_events_at(ip: str, n: int, start_offset_minutes: int = 0) -> list:
    """Build n BLOCK events with distinct timestamps (offset by seconds) to avoid store dedup.

    The SQLiteEventStore deduplicates on (timestamp, source_ip, rule_id, action,
    payload_snippet, source_id); varying the timestamp guarantees each event is unique.
    """
    base = _T0 + timedelta(minutes=start_offset_minutes)
    return [
        make_event(
            source_ip=ip,
            action="BLOCK",
            rule_id="942100",
            payload_snippet=f"' OR '1'='1 -- {i}",  # vary payload to ensure dedup bypass
            timestamp=base + timedelta(seconds=i),
        )
        for i in range(n)
    ]


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[return]
    """Fresh, initialised SQLiteEventStore backed by a tmp file."""
    s = SQLiteEventStore(tmp_path / "test.db")
    await s.init()
    yield s
    await s.close()


# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING-1A — analyze_ip writes a score_history snapshot
# ─────────────────────────────────────────────────────────────────────────────


async def test_analyze_ip_writes_score_history_row(store: SQLiteEventStore) -> None:
    """BLOCKING-1A: analyze_ip must write a timestamped snapshot to score_history."""
    await store.save_many(_blocked_events_at(IP_A, n=3))

    ai = FakeAIEngine()
    pipeline = Pipeline(store, ai, clock=_CLOCK)

    # Before the call, no snapshots should exist.
    history_before = await store.get_score_history(IP_A, window_hours=1)
    assert history_before == [], "Expected no snapshots before analyze_ip"

    await pipeline.analyze_ip(IP_A)

    # After the call, exactly one snapshot must be present.
    history_after = await store.get_score_history(IP_A, window_hours=1)
    assert len(history_after) >= 1, (
        f"Expected at least one score_history row after analyze_ip, got {history_after}"
    )
    row = history_after[0]
    assert row["ip"] == IP_A
    assert isinstance(row["score"], int)
    assert row["score"] > 0


# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING-1B — second call has signed score_delta
# ─────────────────────────────────────────────────────────────────────────────


async def test_analyze_ip_second_call_has_score_delta(
    store: SQLiteEventStore,
) -> None:
    """BLOCKING-1B: second analyze_ip call must return signed score_delta, not None.

    Steps:
    1. Seed 3 BLOCK events for IP_A; call analyze_ip once (score S1, snapshot written).
    2. Add 10 more BLOCK events with distinct timestamps → brute_force rule triggers,
       raising the score to S2 > S1.
    3. Call analyze_ip again → second ThreatScore.score_delta == S2 - S1 (positive).

    Event uniqueness: each batch uses a different start_offset_minutes so that the
    (timestamp, …) dedup UNIQUE index does not collapse them.
    """
    # Round 1: 3 BLOCK SQLi events → score = 40 (sqli) + 3 (blocked) = 43.
    await store.save_many(_blocked_events_at(IP_A, n=3, start_offset_minutes=0))
    ai = FakeAIEngine()
    pipeline = Pipeline(store, ai, clock=_CLOCK)

    first = await pipeline.analyze_ip(IP_A)
    score_1 = first.score
    # First call: new actor — no prior snapshot → score_delta must be None.
    assert first.score_delta is None, (
        f"First call: score_delta must be None (new actor), got {first.score_delta}"
    )

    # Round 2: add 10 more BLOCK events (distinct timestamps via offset).
    # Total blocked becomes 13 → brute_force rule (+30) fires; score increases.
    await store.save_many(_blocked_events_at(IP_A, n=10, start_offset_minutes=60))

    second = await pipeline.analyze_ip(IP_A)
    score_2 = second.score
    assert score_2 > score_1, (
        f"score must increase after adding more blocked events: {score_1} → {score_2}"
    )
    expected_delta = score_2 - score_1
    assert second.score_delta == expected_delta, (
        f"score_delta must be {expected_delta} (score_2 - score_1), got {second.score_delta}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING-1C — first call: score_delta is None (new actor)
# ─────────────────────────────────────────────────────────────────────────────


async def test_analyze_ip_first_call_score_delta_is_none(
    store: SQLiteEventStore,
) -> None:
    """BLOCKING-1C: First analyze_ip for an IP (no prior snapshot) → score_delta=None."""
    await store.save_many(_blocked_events_at(IP_B, n=2))
    ai = FakeAIEngine()
    pipeline = Pipeline(store, ai, clock=_CLOCK)

    result = await pipeline.analyze_ip(IP_B)
    assert result.score_delta is None, (
        f"New actor: score_delta must be None on first call, got {result.score_delta}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING-1D — zero-event path: no snapshot written, no error
# ─────────────────────────────────────────────────────────────────────────────


async def test_analyze_ip_empty_ip_no_snapshot_written(
    store: SQLiteEventStore,
) -> None:
    """BLOCKING-1D: analyze_ip for an IP with no events must not write a snapshot."""
    ai = FakeAIEngine()
    pipeline = Pipeline(store, ai, clock=_CLOCK)

    result = await pipeline.analyze_ip(IP_A)
    assert result.total_events == 0
    assert result.score_delta is None

    history = await store.get_score_history(IP_A, window_hours=1)
    assert history == [], "No snapshot should be written for an IP with no events"
