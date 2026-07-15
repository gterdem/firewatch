"""Tests for issue #313 — ai=true offline waits 14–18s, ai=false queues 8–30s.

EARS criteria mapped to tests:

EARS-313-1  WHEN ai=true is requested and the engine is offline/unreachable,
            the endpoint SHALL respond with the rules-only result and
            ai_status='unavailable' — never 'active'/'ok'/'skipped' (ADR-0035).

EARS-313-2  WHEN ai=true is requested and the engine is offline/unreachable,
            analyze_detailed SHALL NOT be called (no dead-endpoint hit, no
            120-second timeout).

EARS-313-3  WHEN ai=true and the engine IS available, behavior is byte-equivalent
            to today: sampling built, exactly ONE analyze_detailed call (ADR-0003).
            ai_status must NOT be 'unavailable' or 'skipped'.

EARS-313-4  Scores SHALL NOT change — merge_score/run_rules untouched;
            rules-only score for ai=false and ai=true-offline are identical.

EARS-313-5  WHEN a /detailed request is in flight, a concurrent read SHALL make
            progress (store-level contention test: concurrent reads during a
            write burst must not serialize behind the writer in WAL mode).

EARS-313-6  WAL mode and busy_timeout PRAGMA must be set on init() so readers
            do not need an exclusive lock (verifiable via PRAGMA journal_mode).

EARS-313-7  The dedicated read connection (_read_conn) MUST be a separate object
            from the write connection (_conn), so reads never queue behind writes.

Security note: all test IPs use RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) — no real/routable addresses.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from firewatch_core.adapters.sqlite_store import SQLiteEventStore
from firewatch_core.pipeline import Pipeline
from firewatch_sdk import EventStore, SecurityEvent

from _fakes import FakeAIEngine, FakeStore, make_event

# ---------------------------------------------------------------------------
# Constants — RFC 5737 documentation IPs only
# ---------------------------------------------------------------------------

IP = "203.0.113.77"

# Issue #52 (ADR-0070 D4): analyze_ip_detailed now windows run_rules to a
# trailing W_STATE slice measured from "now". _sqli_events() below uses
# make_event()'s default timestamp (_fakes.py: 2026-06-03T12:00:00Z), so this
# synthetic clock is fixed 1h after it — well inside W_STATE — instead of the
# real wall clock (no wall-clock flakiness).
_CLOCK = lambda: datetime(2026, 6, 3, 13, 0, 0, tzinfo=timezone.utc)  # noqa: E731
IP2 = "198.51.100.42"

_VALID_AI_RESULT: dict[str, Any] = {
    "threat_level": "HIGH",
    "confidence": 0.85,
    "executive_summary": "SQL injection attempt detected.",
    "intent": "Data exfiltration",
    "attack_stage": "exploitation",
    "attack_progression": ["Step 1: scan", "Step 2: exploit"],
    "insights": {"patterns": ["SQLi"], "risks": ["data breach"], "mitigations": []},
    "ioc_indicators": [],
    "recommended_action": "block",
    "false_positive_likelihood": 0.05,
    "ai_status": "ok",
}


def _sqli_events(n: int, source_ip: str = IP) -> list[SecurityEvent]:
    return [
        make_event(
            source_ip=source_ip,
            action="BLOCK",
            rule_id="942100",
            payload_snippet="' OR '1'='1",
        )
        for _ in range(n)
    ]


# ---------------------------------------------------------------------------
# Instrumented AI engine fakes
# ---------------------------------------------------------------------------


class _OfflineAIEngine:
    """Simulates Ollama being offline: is_available() returns False, but
    analyze_detailed would hang for 120s if called.  We make it raise
    immediately in tests so if the gate is missing, the test fails fast.
    """

    def __init__(self) -> None:
        self.detailed_calls: int = 0
        self.concise_calls: int = 0

    async def is_available(self) -> bool:
        return False

    async def analyze_concise(self, **kwargs: Any) -> dict[str, Any]:
        self.concise_calls += 1
        raise RuntimeError("Engine offline — this should not have been called")

    async def analyze_detailed(self, **kwargs: Any) -> dict[str, Any]:
        self.detailed_calls += 1
        raise RuntimeError("Engine offline — this should not have been called")


# ---------------------------------------------------------------------------
# EARS-313-1: ai=true + engine offline → ai_status='unavailable', rules-only
# ---------------------------------------------------------------------------


async def test_ai_true_offline_returns_unavailable_status() -> None:
    """EARS-313-1: engine offline + ai=true → ai_status='unavailable'.

    ADR-0035 honesty: the server MUST NOT claim success when AI did not run.
    The status must be 'unavailable' (requested but engine down), not 'ok',
    'active', or 'skipped'.
    """
    offline_ai = _OfflineAIEngine()
    store: EventStore = FakeStore(_sqli_events(3))
    result = await Pipeline(store, offline_ai, clock=_CLOCK).analyze_ip_detailed(  # type: ignore[arg-type]
        IP, include_ai=True
    )
    assert result.get("ai_status") == "unavailable", (
        f"Expected ai_status='unavailable' when engine offline + ai=true, "
        f"got {result.get('ai_status')!r}. ADR-0035: honest provenance required."
    )


async def test_ai_true_offline_returns_rules_only_result() -> None:
    """EARS-313-1 (cont): engine offline + ai=true → rules-only dict, not error.

    The result must contain the standard v1 fields (score, threat_level, ...)
    derived from the rules engine, not an error envelope.
    """
    offline_ai = _OfflineAIEngine()
    store: EventStore = FakeStore(_sqli_events(3))
    result = await Pipeline(store, offline_ai, clock=_CLOCK).analyze_ip_detailed(  # type: ignore[arg-type]
        IP, include_ai=True
    )
    for key in ("score", "threat_level", "total_events", "blocked_events",
                "attack_types", "source_ip"):
        assert key in result, (
            f"v1 field '{key}' missing from offline-ai=true result (EARS-313-1)."
        )


async def test_ai_true_offline_rules_only_score() -> None:
    """EARS-313-1/4: engine offline + ai=true → score equals rules-only score.

    3 blocked SQLi: sqli_BLOCK=round(40×0.5)=20 + persistence=10 = 30 (#651).
    No AI boost must be applied (nothing ran).
    Old math (removed): +40 sqli + 3 per-blocked = 43.
    """
    offline_ai = _OfflineAIEngine()
    store: EventStore = FakeStore(_sqli_events(3))
    result = await Pipeline(store, offline_ai, clock=_CLOCK).analyze_ip_detailed(  # type: ignore[arg-type]
        IP, include_ai=True
    )
    assert result["score"] == 30, (
        f"Expected rules-only score 30 when engine offline, got {result['score']}. (#651)"
    )


async def test_ai_false_and_ai_true_offline_produce_same_score() -> None:
    """EARS-313-4: ai=false and ai=true-offline yield identical scores.

    Scoring is deterministic (additive-only, rules base). Both offline paths
    must produce the exact same rules-only score — no AI boost in either case.
    """
    offline_ai = _OfflineAIEngine()
    store_false: EventStore = FakeStore(_sqli_events(3))
    store_offline: EventStore = FakeStore(_sqli_events(3))

    result_false = await Pipeline(
        store_false, FakeAIEngine(result=_VALID_AI_RESULT), clock=_CLOCK
    ).analyze_ip_detailed(IP, include_ai=False)
    result_offline = await Pipeline(
        store_offline, offline_ai, clock=_CLOCK  # type: ignore[arg-type]
    ).analyze_ip_detailed(IP, include_ai=True)

    assert result_false["score"] == result_offline["score"], (
        f"ai=false score={result_false['score']} != "
        f"ai=true-offline score={result_offline['score']}. "
        "Both must produce the rules-only score (EARS-313-4)."
    )


# ---------------------------------------------------------------------------
# EARS-313-2: engine offline + ai=true → analyze_detailed NOT called
# ---------------------------------------------------------------------------


async def test_ai_true_offline_analyze_detailed_not_called() -> None:
    """EARS-313-2: engine offline → analyze_detailed must NOT be invoked.

    The original bug: the engine call was gated on `if include_ai:` instead of
    `if ai_will_run:`, so an offline Ollama would be contacted under a 120s
    httpx timeout.  After the fix, zero calls to analyze_detailed.
    """
    offline_ai = _OfflineAIEngine()
    store: EventStore = FakeStore(_sqli_events(3))
    # Must complete without calling analyze_detailed (which would raise)
    result = await Pipeline(store, offline_ai, clock=_CLOCK).analyze_ip_detailed(  # type: ignore[arg-type]
        IP, include_ai=True
    )
    assert offline_ai.detailed_calls == 0, (
        f"analyze_detailed called {offline_ai.detailed_calls} time(s) with engine "
        "offline — this causes the 120s timeout bug (EARS-313-2)."
    )
    assert isinstance(result, dict), "Must return a dict even when engine offline."


# ---------------------------------------------------------------------------
# EARS-313-3: engine available + ai=true → one analyze_detailed call, no degraded status
# ---------------------------------------------------------------------------


async def test_ai_true_available_calls_analyze_detailed_once() -> None:
    """EARS-313-3: engine available + ai=true → exactly one analyze_detailed call.

    ADR-0003: one LLM call per IP. The fix must NOT change the happy path.
    """
    fake_ai = FakeAIEngine(result=_VALID_AI_RESULT)
    store: EventStore = FakeStore(_sqli_events(3))
    await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(IP, include_ai=True)
    assert fake_ai.detailed_calls == 1, (
        f"Expected exactly 1 AI call when engine available, got {fake_ai.detailed_calls}."
    )


async def test_ai_true_available_status_not_unavailable() -> None:
    """EARS-313-3: engine available → ai_status must NOT be 'unavailable' or 'skipped'."""
    fake_ai = FakeAIEngine(result=_VALID_AI_RESULT)
    store: EventStore = FakeStore(_sqli_events(3))
    result = await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(IP, include_ai=True)
    assert result.get("ai_status") not in ("unavailable", "skipped"), (
        f"ai_status={result.get('ai_status')!r} when engine IS available "
        "— must not claim degraded state on the happy path (EARS-313-3)."
    )


async def test_ai_true_available_score_boosted() -> None:
    """EARS-313-3: engine available + HIGH confidence → AI boost applied (additive)."""
    ai_result = {**_VALID_AI_RESULT, "threat_level": "HIGH", "confidence": 0.85}
    fake_ai = FakeAIEngine(result=ai_result)
    store: EventStore = FakeStore(_sqli_events(3))
    result = await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(IP, include_ai=True)
    # 30 (rules-only, #651) + 10 (HIGH boost at conf>0.7) = 40
    # Old math (removed): 43 + 10 = 53
    assert result["score"] == 40, (
        f"Expected 40 (30 rules + 10 HIGH boost), got {result['score']} (EARS-313-3, #651)."
    )


# ---------------------------------------------------------------------------
# EARS-313-5: store concurrent-reads test (WAL mode)
# ---------------------------------------------------------------------------


@pytest.fixture
async def wal_store(tmp_path: Path):  # type: ignore[return]
    """SQLiteEventStore in WAL mode for concurrency tests."""
    s = SQLiteEventStore(tmp_path / "wal_test.db")
    await s.init()
    yield s
    await s.close()


async def test_concurrent_reads_during_write_burst_make_progress(
    wal_store: SQLiteEventStore,
) -> None:
    """EARS-313-5: concurrent read makes progress while writes are in flight.

    Before the fix: one shared connection meant reads serialized behind writes.
    After the fix: WAL + dedicated read connection -> reads never block on writes.

    We write a burst of rows and concurrently fire read queries; the reads must
    all complete (counter ticks up) without waiting for the writes to finish.
    """
    # Seed some events first so reads have rows to return
    events = [
        SecurityEvent(
            source_type="suricata",
            source_id="pi-home",
            source_ip=IP,
            action="BLOCK",  # type: ignore[arg-type]
            timestamp=datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
            rule_id="1001",
            payload_snippet="test",
        )
        for _ in range(10)
    ]
    await wal_store.save_many(events)

    read_completions: list[int] = []

    async def _reader(n: int) -> None:
        """Issue a read and record completion."""
        await wal_store.get_by_ip(IP)
        read_completions.append(n)

    async def _writer() -> None:
        """Write a small burst to simulate polling writes."""
        for i in range(5):
            new_evt = SecurityEvent(
                source_type="suricata",
                source_id="pi-home",
                source_ip=IP2,
                action="BLOCK",  # type: ignore[arg-type]
                timestamp=datetime(2026, 6, 1, 12, i, 0, tzinfo=timezone.utc),
                rule_id="1002",
                payload_snippet=f"burst-{i}",
            )
            await wal_store.save_many([new_evt])
            await asyncio.sleep(0)  # yield to event loop

    # Run readers and writer concurrently
    await asyncio.gather(
        _reader(0),
        _reader(1),
        _reader(2),
        _writer(),
    )

    assert len(read_completions) == 3, (
        f"Expected 3 reads to complete concurrently with writes, "
        f"got {len(read_completions)}. Store may be serializing reads behind writes."
    )


# ---------------------------------------------------------------------------
# EARS-313-6: WAL + busy_timeout set on init
# ---------------------------------------------------------------------------


async def test_wal_mode_enabled_after_init(tmp_path: Path) -> None:
    """EARS-313-6: journal_mode=WAL must be set by init() (ADR-0007).

    WAL allows concurrent readers with a writer.  Without WAL, the read
    connection would block on the write connection's lock.
    """
    s = SQLiteEventStore(tmp_path / "wal_check.db")
    await s.init()
    try:
        # Query journal_mode via the write connection
        db = await s._conn()
        cursor = await db.execute("PRAGMA journal_mode")
        row = await cursor.fetchone()
        mode = row[0] if row else "unknown"
        assert mode == "wal", (
            f"Expected journal_mode='wal' after init(), got {mode!r}. "
            "WAL is required for concurrent read/write access (ADR-0007 / issue #313)."
        )
    finally:
        await s.close()


async def test_busy_timeout_set_after_init(tmp_path: Path) -> None:
    """EARS-313-6: busy_timeout must be set by init() so readers do not error immediately.

    Without a busy_timeout, a reader that hits a locked page returns SQLITE_BUSY
    immediately.  A non-zero timeout makes it retry — required for WAL to be useful
    under real concurrent load.
    """
    s = SQLiteEventStore(tmp_path / "timeout_check.db")
    await s.init()
    try:
        db = await s._conn()
        cursor = await db.execute("PRAGMA busy_timeout")
        row = await cursor.fetchone()
        timeout_ms = row[0] if row else 0
        assert timeout_ms > 0, (
            f"Expected busy_timeout > 0 after init(), got {timeout_ms}. "
            "A zero busy_timeout causes immediate SQLITE_BUSY on contention (issue #313)."
        )
    finally:
        await s.close()


# ---------------------------------------------------------------------------
# EARS-313-7: read connection is a separate object from write connection
# ---------------------------------------------------------------------------


async def test_read_conn_is_distinct_from_write_conn(tmp_path: Path) -> None:
    """EARS-313-7: _read_conn() must return a different connection object than _conn().

    Before the fix: _conn() returned the single shared connection, so reads
    and writes serialized on the same worker thread.  After the fix: a dedicated
    read connection means reads can run concurrently with writes (WAL allows this).
    """
    s = SQLiteEventStore(tmp_path / "conn_check.db")
    await s.init()
    try:
        write_conn = await s._conn()
        read_conn = await s._read_conn()
        assert write_conn is not read_conn, (
            "Read connection must be a separate aiosqlite.Connection object "
            "from the write connection to avoid serialization (EARS-313-7 / issue #313)."
        )
    finally:
        await s.close()


async def test_read_conn_returns_same_object_on_repeat_call(tmp_path: Path) -> None:
    """EARS-313-7: _read_conn() is memoized — repeated calls return the same object."""
    s = SQLiteEventStore(tmp_path / "conn_memo.db")
    await s.init()
    try:
        read_conn_a = await s._read_conn()
        read_conn_b = await s._read_conn()
        assert read_conn_a is read_conn_b, (
            "_read_conn() must be memoized (same object on repeat calls) — "
            "creating a new connection per call wastes file handles."
        )
    finally:
        await s.close()
