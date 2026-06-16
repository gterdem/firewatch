"""Tests for SQLiteEventStore — mapped one-to-one to issue #3 EARS criteria.

EARS criteria covered:
  E1  The adapter shall implement the EventStore protocol using aiosqlite.
  E2  The logs schema shall include a source_id TEXT column defaulting to 'default'.
  E3  The dedup unique index shall include source_id.
  E4  get_watermark / set_watermark shall be scoped per (source_type, source_id).
  E5  When save_many receives duplicate events, each unique row inserts once
      and the inserted count is returned.

Additional structural tests:
  - init() is idempotent (safe to call twice)
  - close() + reopen works
  - save_many([]) returns 0
  - get_by_ip returns only matching IP events
  - get_recent respects the limit
  - get_paginated returns the standard envelope
  - get_all_ips / get_ip_summary / get_stats return consistent data
  - get_categories / get_timeline / get_categories_timeline smoke-pass
  - get_analytics_geo / get_analytics_summary smoke-pass
  - get_ips_without_geo + upsert_ip_geo round-trip
  - upsert_rule_descriptions + get_rule_descriptions round-trip
  - clear() removes all logs
  - delete_older_than() prunes old rows and returns count

Issue #133 — source_health() (ADR-0032 Decision D):
  SH1  source_health() on an empty store returns an empty list.
  SH2  source_health() returns one row per unique (source_type, source_id).
  SH3  event_count reflects total rows for each (source_type, source_id) pair.
  SH4  last_event_at is the ISO timestamp of the most recent event for each pair.
  SH5  Two source_ids for the same source_type produce two separate entries.
  SH6  No source name is hard-coded — method is generic over source_type.
  SH7  get_stats() includes last_updated (ISO of most recent event overall, or null).
"""
from __future__ import annotations

import pytest
from collections.abc import AsyncGenerator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from firewatch_sdk import EventStore, SecurityEvent

from firewatch_core.adapters.sqlite_store import SQLiteEventStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def store(tmp_path: Path) -> AsyncGenerator[SQLiteEventStore, None]:
    """Fresh, initialised SQLiteEventStore backed by a tmp file."""
    s = SQLiteEventStore(tmp_path / "test.db")
    await s.init()
    yield s
    await s.close()


def _evt(
    *,
    source_ip: str = "10.0.0.1",
    source_type: str = "suricata",
    source_id: str = "pi-home",
    action: str = "BLOCK",
    timestamp: datetime | None = None,
    rule_id: str | None = "1001",
    payload_snippet: str | None = "test",
    category: str | None = "IDS Alert",
    severity: str | None = "high",
) -> SecurityEvent:
    ts = timestamp or datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    return SecurityEvent(
        source_type=source_type,
        source_id=source_id,
        source_ip=source_ip,
        action=action,  # type: ignore[arg-type]
        timestamp=ts,
        rule_id=rule_id,
        payload_snippet=payload_snippet,
        category=category,
        severity=severity,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# E1 — EventStore protocol conformance
# ---------------------------------------------------------------------------


def test_sqlite_store_is_event_store_protocol(tmp_path: Path) -> None:
    """SQLiteEventStore shall be an instance of the EventStore Protocol (E1)."""
    s = SQLiteEventStore(tmp_path / "proto.db")
    assert isinstance(s, EventStore), (
        "SQLiteEventStore must satisfy the runtime_checkable EventStore Protocol"
    )


# ---------------------------------------------------------------------------
# E2 — source_id column exists and defaults to 'default'
# ---------------------------------------------------------------------------


async def test_source_id_column_exists(store: SQLiteEventStore) -> None:
    """logs table shall contain a source_id column (E2)."""
    import aiosqlite

    async with aiosqlite.connect(store.db_path) as db:
        cursor = await db.execute("PRAGMA table_info(logs)")
        cols = {row[1] for row in await cursor.fetchall()}
    assert "source_id" in cols, "source_id column must be present in logs"


async def test_source_id_default_is_default(store: SQLiteEventStore) -> None:
    """Rows inserted without an explicit source_id column value shall read back 'default' (E2).

    This is verified by inserting a raw SQL row omitting source_id, then reading it back.
    """
    import aiosqlite

    async with aiosqlite.connect(store.db_path) as db:
        await db.execute(
            """INSERT INTO logs
               (source_ip, destination_port, protocol, action,
                rule_id, payload_snippet, timestamp, source_type)
               VALUES ('192.0.2.4', 0, 'TCP', 'BLOCK', '99', 'x', '2026-01-01T00:00:00', 'suricata')"""
        )
        await db.commit()
        cursor = await db.execute(
            "SELECT source_id FROM logs WHERE source_ip = '192.0.2.4'"
        )
        row = await cursor.fetchone()
    assert row is not None
    assert row[0] == "default", f"Expected 'default', got {row[0]!r}"


# ---------------------------------------------------------------------------
# E3 — dedup UNIQUE index includes source_id
# ---------------------------------------------------------------------------


async def test_dedup_index_includes_source_id(store: SQLiteEventStore) -> None:
    """Same (timestamp, source_ip, rule_id, action, payload_snippet) but different
    source_id values shall NOT be deduped — they produce two separate rows (E3)."""
    e1 = _evt(source_id="pi-home")
    e2 = _evt(source_id="azure-lab")  # identical except source_id
    count = await store.save_many([e1, e2])
    assert count == 2, (
        "Different source_id on otherwise identical rows must each insert once"
    )


async def test_dedup_same_source_id_is_single_row(store: SQLiteEventStore) -> None:
    """Truly duplicate events (same source_id included) shall insert only once (E3 + E5)."""
    e = _evt()
    count = await store.save_many([e, e])
    assert count == 1, "Duplicate event with same source_id must insert only once"


# ---------------------------------------------------------------------------
# E4 — watermark scoped per (source_type, source_id)
# ---------------------------------------------------------------------------


async def test_watermark_independent_per_source_type_and_id(
    store: SQLiteEventStore,
) -> None:
    """set/get_watermark shall be independent for different (source_type, source_id) pairs (E4)."""
    await store.set_watermark("2026-01-01T00:00:00", "suricata", "pi-home")
    await store.set_watermark("2026-02-01T00:00:00", "suricata", "azure-lab")
    await store.set_watermark("2026-03-01T00:00:00", "azure_waf", "pi-home")

    assert await store.get_watermark("suricata", "pi-home") == "2026-01-01T00:00:00"
    assert await store.get_watermark("suricata", "azure-lab") == "2026-02-01T00:00:00"
    assert await store.get_watermark("azure_waf", "pi-home") == "2026-03-01T00:00:00"


async def test_watermark_missing_returns_none(store: SQLiteEventStore) -> None:
    """get_watermark for an unseen key shall return None (E4)."""
    result = await store.get_watermark("suricata", "never-seen")
    assert result is None


async def test_watermark_overwrite(store: SQLiteEventStore) -> None:
    """set_watermark shall overwrite an existing value for the same key (E4)."""
    await store.set_watermark("2026-01-01T00:00:00", "suricata", "pi-home")
    await store.set_watermark("2026-06-01T00:00:00", "suricata", "pi-home")
    assert await store.get_watermark("suricata", "pi-home") == "2026-06-01T00:00:00"


# ---------------------------------------------------------------------------
# E5 — save_many dedup + inserted count
# ---------------------------------------------------------------------------


async def test_save_many_empty_returns_zero(store: SQLiteEventStore) -> None:
    """save_many([]) shall return 0 (E5)."""
    count = await store.save_many([])
    assert count == 0


async def test_save_many_unique_events_all_inserted(store: SQLiteEventStore) -> None:
    """save_many with N distinct events shall return N (E5)."""
    events = [
        _evt(source_ip=f"10.0.0.{i}", timestamp=datetime(2026, 6, 1, 12, 0, i, tzinfo=timezone.utc))
        for i in range(1, 6)
    ]
    count = await store.save_many(events)
    assert count == 5


async def test_save_many_mixed_duplicates_correct_count(store: SQLiteEventStore) -> None:
    """save_many with 3 unique + 2 duplicates shall return 3 (E5)."""
    e1 = _evt(source_ip="10.0.0.1")
    e2 = _evt(source_ip="10.0.0.2")
    e3 = _evt(source_ip="10.0.0.3")
    count = await store.save_many([e1, e2, e3, e1, e2])
    assert count == 3


async def test_save_many_across_calls_dedup(store: SQLiteEventStore) -> None:
    """Events already stored shall not be re-inserted on a second save_many call (E5)."""
    e = _evt()
    first = await store.save_many([e])
    second = await store.save_many([e])
    assert first == 1
    assert second == 0


# ---------------------------------------------------------------------------
# Structural: init idempotency
# ---------------------------------------------------------------------------


async def test_init_is_idempotent(tmp_path: Path) -> None:
    """Calling init() twice shall not raise (schema CREATE IF NOT EXISTS)."""
    s = SQLiteEventStore(tmp_path / "idem.db")
    await s.init()
    await s.init()  # should not raise
    await s.close()


# ---------------------------------------------------------------------------
# Structural: read methods
# ---------------------------------------------------------------------------


async def test_get_by_ip_returns_matching_only(store: SQLiteEventStore) -> None:
    await store.save_many([_evt(source_ip="10.0.0.1"), _evt(source_ip="10.0.0.2")])
    results = await store.get_by_ip("10.0.0.1")
    assert all(e.source_ip == "10.0.0.1" for e in results)
    assert len(results) == 1


async def test_get_by_ip_raw_returns_dicts(store: SQLiteEventStore) -> None:
    await store.save_many([_evt(source_ip="192.168.1.1")])
    rows = await store.get_by_ip_raw("192.168.1.1")
    assert len(rows) == 1
    assert isinstance(rows[0], dict)
    assert rows[0]["source_ip"] == "192.168.1.1"


async def test_get_recent_respects_limit(store: SQLiteEventStore) -> None:
    events = [
        _evt(source_ip="10.0.0.1", timestamp=datetime(2026, 6, 1, 12, 0, i, tzinfo=timezone.utc))
        for i in range(10)
    ]
    await store.save_many(events)
    recent = await store.get_recent(5)
    assert len(recent) <= 5


async def test_get_paginated_envelope(store: SQLiteEventStore) -> None:
    await store.save_many([_evt()])
    result = await store.get_paginated(10)
    assert "logs" in result
    assert "next_cursor" in result
    assert "has_more" in result
    assert "total_matching" in result


async def test_get_all_ips(store: SQLiteEventStore) -> None:
    await store.save_many([_evt(source_ip="192.0.2.11"), _evt(source_ip="192.0.2.22")])
    ips = await store.get_all_ips()
    assert "192.0.2.11" in ips
    assert "192.0.2.22" in ips


async def test_get_ip_summary(store: SQLiteEventStore) -> None:
    await store.save_many([_evt(source_ip="192.0.2.55")])
    summary = await store.get_ip_summary()
    assert any(row["source_ip"] == "192.0.2.55" for row in summary)


async def test_get_stats(store: SQLiteEventStore) -> None:
    await store.save_many([_evt(action="BLOCK"), _evt(source_ip="192.0.2.99", action="ALLOW")])
    stats = await store.get_stats()
    assert stats["total_logs"] >= 2
    assert stats["total_ips"] >= 1
    assert "blocked_percentage" in stats


async def test_get_categories_smoke(store: SQLiteEventStore) -> None:
    await store.save_many([_evt(action="BLOCK", rule_id="942100")])
    cats = await store.get_categories()
    assert isinstance(cats, list)


# ---------------------------------------------------------------------------
# Issue #322/#325 — get_categories grouped by stored category column
# The read-path no longer re-derives labels from rule_id; it groups directly
# on the stored category column (canonical-schema discipline, issue #325).
# ---------------------------------------------------------------------------


async def test_get_categories_dedup_other_single_row(store: SQLiteEventStore) -> None:
    """Rows with NULL stored category are aggregated under 'Other' exactly once.

    Structural guarantee: GROUP BY COALESCE(category,'Other') merges all NULL-
    category blocked rows into one 'Other' bucket regardless of rule_id.
    This is the #322 structural fix: one-row-per-category is now a SQL guarantee,
    not a Python merge pass.
    """
    await store.save_many([
        _evt(action="BLOCK", rule_id=None,       category=None, source_ip="192.0.2.10"),
        _evt(action="BLOCK", rule_id=None,       category=None, source_ip="192.0.2.11"),
        _evt(action="DROP",  rule_id="CUSTOM-999", category=None, source_ip="192.0.2.12"),
    ])
    cats = await store.get_categories()

    other_rows = [r for r in cats if r["category"] == "Other"]
    assert len(other_rows) == 1, (
        f"Expected exactly one 'Other' row, got {len(other_rows)}: {other_rows}"
    )
    assert other_rows[0]["count"] == 3, (
        f"Expected merged count=3, got {other_rows[0]['count']}"
    )


async def test_get_categories_category_labels_unique(store: SQLiteEventStore) -> None:
    """Each stored category value must appear at most once in the response.

    GROUP BY on the stored column is the structural guarantee — no separate
    merge pass required.
    """
    await store.save_many([
        _evt(action="BLOCK", rule_id="942100", category="SQL Injection", source_ip="192.0.2.20"),
        _evt(action="BLOCK", rule_id="942200", category="SQL Injection", source_ip="192.0.2.21"),  # same label
        _evt(action="DROP",  rule_id="941001", category="XSS",           source_ip="192.0.2.22"),
        _evt(action="BLOCK", rule_id=None,     category=None,            source_ip="192.0.2.23"),  # Other
        _evt(action="DROP",  rule_id="ZZZ",    category=None,            source_ip="192.0.2.24"),  # Other (same)
    ])
    cats = await store.get_categories()

    labels = [r["category"] for r in cats]
    assert len(labels) == len(set(labels)), (
        f"Duplicate category labels in get_categories response: {labels}"
    )


async def test_get_categories_count_conservation(store: SQLiteEventStore) -> None:
    """Sum of all category counts must equal total blocked/dropped event count."""
    events = [
        _evt(action="BLOCK", rule_id="942100", category="SQL Injection", source_ip="192.0.2.30"),
        _evt(action="DROP",  rule_id="941001", category="XSS",           source_ip="192.0.2.31"),
        _evt(action="BLOCK", rule_id=None,     category=None,            source_ip="192.0.2.32"),
        _evt(action="DROP",  rule_id="CUSTOM", category=None,            source_ip="192.0.2.33"),
        # ALLOW action must NOT appear in categories (only BLOCK/DROP counted)
        _evt(action="ALLOW", rule_id="942300", category="SQL Injection", source_ip="192.0.2.34"),
    ]
    await store.save_many(events)
    cats = await store.get_categories()

    total = sum(r["count"] for r in cats)
    assert total == 4, f"Expected 4 blocked/dropped events, got {total}"


async def test_get_categories_empty_store(store: SQLiteEventStore) -> None:
    """Empty store returns an empty list (no crash, no 'Other' phantom row)."""
    cats = await store.get_categories()
    assert cats == []


async def test_get_categories_no_collision_happy_path(store: SQLiteEventStore) -> None:
    """When each stored category value is distinct, each appears once with correct count."""
    await store.save_many([
        _evt(action="BLOCK", rule_id="942100", category="SQL Injection", source_ip="192.0.2.40"),
        _evt(action="DROP",  rule_id="941001", category="XSS",           source_ip="192.0.2.41"),
        _evt(action="BLOCK", rule_id="GeoBlock-US", category="Geo-Blocked", source_ip="192.0.2.42"),
    ])
    cats = await store.get_categories()

    labels = {r["category"] for r in cats}
    assert labels == {"SQL Injection", "XSS", "Geo-Blocked"}
    assert len(cats) == 3


async def test_get_timeline_smoke(store: SQLiteEventStore) -> None:
    await store.save_many([_evt()])
    tl = await store.get_timeline(None, None)
    assert isinstance(tl, list)


async def test_get_categories_timeline_smoke(store: SQLiteEventStore) -> None:
    await store.save_many([_evt(action="BLOCK")])
    ctl = await store.get_categories_timeline(None, None)
    assert isinstance(ctl, list)


async def test_get_analytics_summary_smoke(store: SQLiteEventStore) -> None:
    await store.save_many([_evt()])
    s = await store.get_analytics_summary()
    assert isinstance(s, dict)
    assert "total_events" in s


async def test_get_analytics_geo_smoke(store: SQLiteEventStore) -> None:
    geo = await store.get_analytics_geo()
    assert isinstance(geo, list)


# ---------------------------------------------------------------------------
# Structural: geo round-trip
# ---------------------------------------------------------------------------


async def test_get_ips_without_geo(store: SQLiteEventStore) -> None:
    await store.save_many([_evt(source_ip="192.0.2.88")])
    missing = await store.get_ips_without_geo()
    assert "192.0.2.88" in missing


async def test_upsert_ip_geo_round_trip(store: SQLiteEventStore) -> None:
    await store.upsert_ip_geo(
        [{"ip": "192.0.2.88", "country": "US", "city": "Documentation City", "lat": 37.4, "lon": -122.1}]
    )
    # After upsert, IP should no longer appear in "without geo" if also in logs
    await store.save_many([_evt(source_ip="192.0.2.88")])
    missing = await store.get_ips_without_geo()
    assert "192.0.2.88" not in missing


# ---------------------------------------------------------------------------
# Structural: rule descriptions round-trip
# ---------------------------------------------------------------------------


async def test_rule_descriptions_round_trip(store: SQLiteEventStore) -> None:
    descs = {"942100": "SQL injection detected", "941100": "XSS detected"}
    await store.upsert_rule_descriptions(descs)
    result = await store.get_rule_descriptions()
    assert result["942100"] == "SQL injection detected"
    assert result["941100"] == "XSS detected"


# ---------------------------------------------------------------------------
# Structural: housekeeping
# ---------------------------------------------------------------------------


async def test_clear_removes_logs(store: SQLiteEventStore) -> None:
    await store.save_many([_evt()])
    await store.clear()
    ips = await store.get_all_ips()
    assert ips == []


async def test_delete_older_than_prunes_old_rows(store: SQLiteEventStore) -> None:
    old_ts = datetime.now(timezone.utc) - timedelta(days=10)
    new_ts = datetime.now(timezone.utc)
    old_evt = _evt(timestamp=old_ts, source_ip="198.51.100.1")
    new_evt = _evt(timestamp=new_ts, source_ip="198.51.100.2")
    await store.save_many([old_evt, new_evt])
    deleted = await store.delete_older_than(7)
    assert deleted == 1
    ips = await store.get_all_ips()
    assert "198.51.100.2" in ips
    assert "198.51.100.1" not in ips


# ---------------------------------------------------------------------------
# Structural: source_id propagates through save/read round-trip
# ---------------------------------------------------------------------------


async def test_source_id_stored_and_retrieved(store: SQLiteEventStore) -> None:
    """source_id written into the DB shall be readable from get_by_ip_raw."""
    e = _evt(source_ip="203.0.113.77", source_id="azure-lab")
    await store.save_many([e])
    rows = await store.get_by_ip_raw("203.0.113.77")
    assert rows[0]["source_id"] == "azure-lab"


async def test_source_type_stored_and_retrieved(store: SQLiteEventStore) -> None:
    """source_type written into the DB shall be readable from get_by_ip_raw."""
    e = _evt(source_ip="203.0.113.66", source_type="azure_waf")
    await store.save_many([e])
    rows = await store.get_by_ip_raw("203.0.113.66")
    assert rows[0]["source_type"] == "azure_waf"


# ---------------------------------------------------------------------------
# Structural: get_paginated filters
# ---------------------------------------------------------------------------


async def test_get_paginated_filter_by_source_id(store: SQLiteEventStore) -> None:
    """get_paginated FilterSpec.source_id shall narrow results to matching rows."""
    from firewatch_sdk import FilterSpec

    e1 = _evt(source_ip="10.1.1.1", source_id="pi-home")
    e2 = _evt(source_ip="10.1.1.2", source_id="azure-lab")
    await store.save_many([e1, e2])
    result = await store.get_paginated(10, FilterSpec(source_id="pi-home"))
    ips = [r["source_ip"] for r in result["logs"]]
    assert "10.1.1.1" in ips
    assert "10.1.1.2" not in ips


async def test_get_paginated_filter_by_source_type(store: SQLiteEventStore) -> None:
    """get_paginated FilterSpec.source_type shall narrow results to matching rows."""
    from firewatch_sdk import FilterSpec

    e1 = _evt(source_ip="10.2.2.1", source_type="suricata")
    e2 = _evt(source_ip="10.2.2.2", source_type="azure_waf")
    await store.save_many([e1, e2])
    result = await store.get_paginated(10, FilterSpec(source_type="suricata"))
    ips = [r["source_ip"] for r in result["logs"]]
    assert "10.2.2.1" in ips
    assert "10.2.2.2" not in ips


# ---------------------------------------------------------------------------
# Security fix B3 — cursor parsing: malformed cursor input is handled cleanly
# ---------------------------------------------------------------------------


async def test_get_paginated_malformed_cursor_non_integer_id(
    store: SQLiteEventStore,
) -> None:
    """A cursor with a non-integer id part must not raise (B3).

    Malformed cursors are treated as absent (no cursor), so all rows are returned.
    """
    from firewatch_sdk import FilterSpec

    await store.save_many([_evt(source_ip="10.3.0.1")])
    # id part is not an integer — must not propagate ValueError
    result = await store.get_paginated(10, FilterSpec(cursor="2026-06-01T12:00:00|not_an_int"))
    assert "logs" in result
    assert isinstance(result["logs"], list)


async def test_get_paginated_malformed_cursor_wrong_shape(
    store: SQLiteEventStore,
) -> None:
    """A cursor missing the pipe separator must not raise (B3).

    Malformed cursors are treated as absent; all rows are returned.
    """
    from firewatch_sdk import FilterSpec

    await store.save_many([_evt(source_ip="10.3.0.2")])
    result = await store.get_paginated(10, FilterSpec(cursor="garbage_no_pipe"))
    assert "logs" in result
    assert isinstance(result["logs"], list)


async def test_get_paginated_malformed_cursor_garbage_timestamp(
    store: SQLiteEventStore,
) -> None:
    """A cursor with a garbage timestamp and non-integer id must not raise (B3)."""
    from firewatch_sdk import FilterSpec

    await store.save_many([_evt(source_ip="10.3.0.3")])
    result = await store.get_paginated(10, FilterSpec(cursor="not_a_timestamp|garbage"))
    assert "logs" in result
    assert isinstance(result["logs"], list)


async def test_get_paginated_valid_cursor_still_paginates(store: SQLiteEventStore) -> None:
    """A well-formed cursor must still paginate correctly after the B3 fix."""
    from firewatch_sdk import FilterSpec

    events = [
        _evt(
            source_ip=f"10.4.0.{i}",
            timestamp=datetime(2026, 6, 1, 12, 0, i, tzinfo=timezone.utc),
        )
        for i in range(1, 6)
    ]
    await store.save_many(events)
    # Fetch with limit=2 to get a next_cursor
    first_page = await store.get_paginated(2)
    assert first_page["has_more"] is True
    cursor = first_page["next_cursor"]
    assert cursor is not None
    # Use that cursor for page 2 — must not raise
    second_page = await store.get_paginated(2, FilterSpec(cursor=cursor))
    assert "logs" in second_page
    assert isinstance(second_page["logs"], list)


# ---------------------------------------------------------------------------
# Security fix B2 — get_categories_timeline granularity (static SQL, no f-string)
# ---------------------------------------------------------------------------


async def test_get_categories_timeline_daily_granularity(store: SQLiteEventStore) -> None:
    """get_categories_timeline uses daily granularity for spans > 48 h (B2)."""
    await store.save_many([_evt(action="BLOCK", rule_id="942100")])
    rows = await store.get_categories_timeline("2026-05-01", "2026-06-03")
    assert isinstance(rows, list)
    if rows:
        assert rows[0].get("granularity") == "daily"


async def test_get_categories_timeline_hourly_granularity(store: SQLiteEventStore) -> None:
    """get_categories_timeline uses hourly granularity for spans <= 48 h (B2)."""
    await store.save_many([_evt(action="BLOCK", rule_id="941100")])
    # 24 h window => hourly
    rows = await store.get_categories_timeline("2026-06-02T00:00:00", "2026-06-03T00:00:00")
    assert isinstance(rows, list)
    if rows:
        assert rows[0].get("granularity") == "hourly"


# ---------------------------------------------------------------------------
# Security fix NB-1 — init() dedup-index: except narrowed to IntegrityError only
# ---------------------------------------------------------------------------


async def test_init_dedup_rebuild_for_genuine_duplicates(tmp_path: Path) -> None:
    """The dedup-rebuild path (DELETE + recreate) runs only for genuine duplicates (NB-1).

    We set up duplicate rows manually, drop the index, then call init() again.
    init() must clean the duplicates and leave exactly one of each.
    """
    import aiosqlite

    db_path = tmp_path / "dedup_test.db"
    s = SQLiteEventStore(db_path)
    await s.init()
    await s.close()

    # Bypass the unique index by dropping it, then insert two identical rows.
    async with aiosqlite.connect(db_path) as db:
        await db.execute("DROP INDEX IF EXISTS idx_logs_dedup")
        for _ in range(2):
            await db.execute(
                """INSERT INTO logs
                   (source_ip, destination_port, protocol, action,
                    rule_id, payload_snippet, timestamp, source_type, source_id)
                   VALUES ('192.0.2.250', 80, 'TCP', 'BLOCK',
                           'dup-rule', 'dup-snippet',
                           '2026-01-01T00:00:00', 'test', 'default')"""
            )
        await db.commit()
        count_before_row = await (await db.execute("SELECT COUNT(*) FROM logs")).fetchone()
        assert count_before_row is not None
        count_before: int = count_before_row[0]
    assert count_before == 2

    # Re-init must detect duplicates, deduplicate, and rebuild the index.
    s2 = SQLiteEventStore(db_path)
    await s2.init()  # must not raise
    await s2.close()

    async with aiosqlite.connect(db_path) as db:
        count_after_row = await (await db.execute("SELECT COUNT(*) FROM logs")).fetchone()
        assert count_after_row is not None
        count_after: int = count_after_row[0]
    assert count_after == 1, "Dedup rebuild must leave exactly one of each duplicate"


async def test_init_unrelated_db_error_does_not_trigger_mass_delete(
    tmp_path: Path,
) -> None:
    """An OperationalError during index creation must propagate, NOT trigger a mass DELETE (NB-1).

    The narrowed except clause (IntegrityError only) must not swallow unrelated DB errors.
    """
    import sqlite3

    db_path = tmp_path / "err_test.db"
    s = SQLiteEventStore(db_path)

    # We need to get the db connected first so _db is set.
    await s._conn()
    assert s._db is not None

    # Wrap the real execute to raise OperationalError only on the dedup index creation.
    real_execute = s._db.execute
    call_count = 0

    async def patched_execute(sql: str, *args: object, **kwargs: object) -> object:
        nonlocal call_count
        if "CREATE UNIQUE INDEX" in sql and "idx_logs_dedup" in sql:
            call_count += 1
            if call_count == 1:
                raise sqlite3.OperationalError("simulated disk-full error")
        return await real_execute(sql, *args, **kwargs)

    s._db.execute = patched_execute  # type: ignore[method-assign]

    with pytest.raises(sqlite3.OperationalError, match="simulated disk-full error"):
        await s.init()

    # Restore and close cleanly.
    s._db.execute = real_execute  # type: ignore[method-assign]
    await s.close()


# ---------------------------------------------------------------------------
# Issue #133 — source_health() and get_stats() last_updated (ADR-0032 D)
# ---------------------------------------------------------------------------


async def test_source_health_empty_store(store: SQLiteEventStore) -> None:
    """SH1: source_health() on an empty store returns an empty list."""
    result = await store.source_health()
    assert result == []


async def test_source_health_single_source(store: SQLiteEventStore) -> None:
    """SH2+SH3+SH4: One source_type/source_id produces one entry with correct count and timestamp."""
    ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    await store.save_many([
        _evt(source_ip="192.0.2.1", source_type="suricata", source_id="pi-home",
             timestamp=ts),
        _evt(source_ip="192.0.2.2", source_type="suricata", source_id="pi-home",
             timestamp=datetime(2026, 6, 1, 13, 0, 0, tzinfo=timezone.utc),
             rule_id="1002"),
    ])
    result = await store.source_health()
    assert len(result) == 1
    row = result[0]
    assert row["source_type"] == "suricata"
    assert row["source_id"] == "pi-home"
    assert row["event_count"] == 2
    # last_event_at should be the later of the two timestamps
    assert row["last_event_at"] is not None
    assert "13:00" in row["last_event_at"]


async def test_source_health_two_source_ids_same_type(store: SQLiteEventStore) -> None:
    """SH5: Two source_ids for the same source_type produce two separate entries."""
    await store.save_many([
        _evt(source_ip="192.0.2.10", source_type="suricata", source_id="pi-home"),
        _evt(source_ip="192.0.2.11", source_type="suricata", source_id="pi-office",
             rule_id="1002"),
    ])
    result = await store.source_health()
    assert len(result) == 2
    ids = {r["source_id"] for r in result}
    assert ids == {"pi-home", "pi-office"}
    for row in result:
        assert row["event_count"] == 1


async def test_source_health_multiple_source_types(store: SQLiteEventStore) -> None:
    """SH6: Method is generic — different source_types produce independent entries."""
    await store.save_many([
        _evt(source_ip="192.0.2.20", source_type="suricata", source_id="s1"),
        _evt(source_ip="192.0.2.21", source_type="azure_waf", source_id="waf1",
             rule_id="942001"),
    ])
    result = await store.source_health()
    assert len(result) == 2
    types = {r["source_type"] for r in result}
    assert types == {"suricata", "azure_waf"}


async def test_source_health_event_count_per_pair(store: SQLiteEventStore) -> None:
    """SH3: event_count is per-(source_type, source_id) pair, not global."""
    await store.save_many([
        _evt(source_ip="192.0.2.30", source_type="suricata", source_id="a"),
        _evt(source_ip="192.0.2.31", source_type="suricata", source_id="a",
             rule_id="1002"),
        _evt(source_ip="192.0.2.32", source_type="suricata", source_id="a",
             rule_id="1003"),
        _evt(source_ip="192.0.2.33", source_type="azure_waf", source_id="b"),
    ])
    result = await store.source_health()
    counts = {(r["source_type"], r["source_id"]): r["event_count"] for r in result}
    assert counts[("suricata", "a")] == 3
    assert counts[("azure_waf", "b")] == 1


async def test_get_stats_includes_last_updated(store: SQLiteEventStore) -> None:
    """SH7: get_stats() returns last_updated as ISO timestamp of most recent event."""
    ts = datetime(2026, 6, 5, 10, 0, 0, tzinfo=timezone.utc)
    await store.save_many([
        _evt(source_ip="192.0.2.40", timestamp=ts),
    ])
    stats = await store.get_stats()
    assert "last_updated" in stats
    assert stats["last_updated"] is not None
    # The value must be a string ISO timestamp containing the date
    assert "2026-06-05" in stats["last_updated"]


async def test_get_stats_last_updated_null_when_empty(store: SQLiteEventStore) -> None:
    """SH7: get_stats() returns last_updated=null when no events exist."""
    stats = await store.get_stats()
    assert "last_updated" in stats
    assert stats["last_updated"] is None


# ---------------------------------------------------------------------------
# Issue #118 — get_events_for_timeline() (cross-source event timeline)
# ---------------------------------------------------------------------------


async def test_timeline_empty_when_no_events(store: SQLiteEventStore) -> None:
    """TL1: get_events_for_timeline returns [] when the IP has no events."""
    rows = await store.get_events_for_timeline("192.0.2.50")
    assert rows == []


async def test_timeline_only_returns_events_for_requested_ip(
    store: SQLiteEventStore,
) -> None:
    """TL2: get_events_for_timeline returns only events for the requested IP."""
    target_ip = "192.0.2.51"
    other_ip = "192.0.2.52"
    ts1 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    ts2 = datetime(2026, 6, 1, 12, 1, 0, tzinfo=timezone.utc)
    await store.save_many([
        _evt(source_ip=target_ip, timestamp=ts1),
        _evt(source_ip=other_ip, timestamp=ts2, rule_id="9999"),
    ])
    rows = await store.get_events_for_timeline(target_ip)
    assert all(r["source_type"] is not None for r in rows)
    # No row should have leaked from other_ip — verify via rule_id
    rule_ids = {r.get("rule_id") for r in rows}
    assert "9999" not in rule_ids, "other IP's events must not appear in the timeline"


async def test_timeline_ordered_ascending(store: SQLiteEventStore) -> None:
    """TL3: get_events_for_timeline returns events ordered by timestamp ascending."""
    ip = "192.0.2.53"
    ts_early = datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
    ts_middle = datetime(2026, 6, 1, 11, 0, 0, tzinfo=timezone.utc)
    ts_late = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    # Insert in non-chronological order to confirm ordering is query-driven.
    await store.save_many([
        _evt(source_ip=ip, timestamp=ts_late, rule_id="L"),
        _evt(source_ip=ip, timestamp=ts_early, rule_id="E"),
        _evt(source_ip=ip, timestamp=ts_middle, rule_id="M"),
    ])
    rows = await store.get_events_for_timeline(ip)
    assert len(rows) == 3
    timestamps = [r["timestamp"] for r in rows]
    assert timestamps == sorted(timestamps), (
        f"Expected ascending timestamp order, got: {timestamps}"
    )


async def test_timeline_respects_limit(store: SQLiteEventStore) -> None:
    """TL4: get_events_for_timeline caps the result at the supplied limit."""
    ip = "192.0.2.54"
    base_ts = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    events = [
        _evt(
            source_ip=ip,
            timestamp=base_ts.replace(hour=i),
            rule_id=f"R{i}",
            payload_snippet=f"p{i}",
        )
        for i in range(10)
    ]
    await store.save_many(events)

    rows = await store.get_events_for_timeline(ip, limit=4)
    assert len(rows) == 4, f"Expected 4 rows (limit), got {len(rows)}"


async def test_timeline_row_carries_canonical_fields(store: SQLiteEventStore) -> None:
    """TL5: each row from get_events_for_timeline carries the expected canonical fields."""
    ip = "192.0.2.55"
    ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    await store.save_many([
        _evt(
            source_ip=ip,
            source_type="suricata",
            timestamp=ts,
            action="ALERT",
            rule_id="ET-1234",
            category="IDS Alert",
            severity="high",
            payload_snippet="test-payload",
        )
    ])
    rows = await store.get_events_for_timeline(ip)
    assert len(rows) == 1
    r = rows[0]
    assert r["source_type"] == "suricata"
    assert "timestamp" in r
    assert r["action"] == "ALERT"
    assert r["rule_id"] == "ET-1234"
    assert r["category"] == "IDS Alert"
    assert r["severity"] == "high"
    assert r["payload_snippet"] == "test-payload"


async def test_timeline_multi_source_all_returned(store: SQLiteEventStore) -> None:
    """TL6: events from multiple source_types are all returned (no source filter)."""
    ip = "192.0.2.56"
    ts1 = datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
    ts2 = datetime(2026, 6, 1, 11, 0, 0, tzinfo=timezone.utc)
    await store.save_many([
        _evt(source_ip=ip, source_type="suricata", timestamp=ts1, rule_id="S1"),
        _evt(source_ip=ip, source_type="azure_waf", timestamp=ts2, rule_id="W1"),
    ])
    rows = await store.get_events_for_timeline(ip)
    assert len(rows) == 2
    source_types = {r["source_type"] for r in rows}
    assert source_types == {"suricata", "azure_waf"}, (
        "All source types must appear in the timeline result"
    )


# ---------------------------------------------------------------------------
# Issue #176 — get_stats() top_attack_types must use category, not protocol
# ---------------------------------------------------------------------------


async def test_get_stats_top_attack_types_uses_category(store: SQLiteEventStore) -> None:
    """EARS #176: WHEN blocked events with populated categories exist,
    GET /stats SHALL return the top categories in top_attack_types, ordered
    by frequency descending.  The result must NOT contain protocol values
    (TCP/UDP) and must NOT contain empty strings.
    """
    base_ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        # 3x SQL Injection (most frequent)
        _evt(source_ip="192.0.2.60", action="BLOCK", category="SQL Injection",
             rule_id="942001", timestamp=base_ts),
        _evt(source_ip="192.0.2.61", action="BLOCK", category="SQL Injection",
             rule_id="942002", timestamp=base_ts.replace(minute=1)),
        _evt(source_ip="192.0.2.62", action="BLOCK", category="SQL Injection",
             rule_id="942003", timestamp=base_ts.replace(minute=2)),
        # 2x XSS
        _evt(source_ip="192.0.2.63", action="BLOCK", category="XSS",
             rule_id="941001", timestamp=base_ts.replace(minute=3)),
        _evt(source_ip="192.0.2.64", action="BLOCK", category="XSS",
             rule_id="941002", timestamp=base_ts.replace(minute=4)),
        # 1x Bot Activity
        _evt(source_ip="192.0.2.65", action="BLOCK", category="Bot Activity",
             rule_id="300001", timestamp=base_ts.replace(minute=5)),
        # 1x ALLOW event — must not appear in top_attack_types
        _evt(source_ip="192.0.2.66", action="ALLOW", category="Bot Activity",
             rule_id="300002", timestamp=base_ts.replace(minute=6)),
    ]
    await store.save_many(events)

    stats = await store.get_stats()
    top = stats["top_attack_types"]

    # Must be a non-empty list of strings
    assert isinstance(top, list)
    assert len(top) > 0, "top_attack_types must not be empty when blocked events exist"

    # Must not contain protocol values
    assert "TCP" not in top, f"Protocol value 'TCP' leaked into top_attack_types: {top}"
    assert "UDP" not in top, f"Protocol value 'UDP' leaked into top_attack_types: {top}"

    # Must not contain empty strings or None
    assert all(
        isinstance(v, str) and v != "" for v in top
    ), f"top_attack_types contains empty/null entry: {top}"

    # SQL Injection must be first (3 blocked events, highest frequency)
    assert top[0] == "SQL Injection", (
        f"Expected 'SQL Injection' as top category (3 blocked), got {top[0]!r}"
    )

    # XSS must appear before Bot Activity (2 vs 1)
    assert "XSS" in top
    assert "Bot Activity" in top
    xss_idx = top.index("XSS")
    bot_idx = top.index("Bot Activity")
    assert xss_idx < bot_idx, (
        f"XSS (2 events) should rank above Bot Activity (1 event), "
        f"but got order: {top}"
    )


async def test_get_stats_top_attack_types_excludes_null_category(
    store: SQLiteEventStore,
) -> None:
    """EARS #176: NULL/empty categories must not appear in top_attack_types."""
    base_ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        # One blocked event with a real category
        _evt(source_ip="198.51.100.10", action="BLOCK", category="XSS",
             rule_id="941001", timestamp=base_ts),
        # One blocked event with NULL category (category=None)
        _evt(source_ip="198.51.100.11", action="BLOCK", category=None,
             rule_id="unknown-rule", timestamp=base_ts.replace(minute=1)),
    ]
    await store.save_many(events)

    stats = await store.get_stats()
    top = stats["top_attack_types"]

    assert all(
        isinstance(v, str) and v != "" and v is not None for v in top
    ), f"top_attack_types must not contain null/empty entries: {top}"
    assert "XSS" in top, f"Real category 'XSS' must appear in top_attack_types: {top}"


async def test_get_stats_top_attack_types_empty_when_no_blocked_events(
    store: SQLiteEventStore,
) -> None:
    """EARS #176: top_attack_types must be an empty list when no blocked events exist."""
    # Insert ALLOW-only events with categories
    base_ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    await store.save_many([
        _evt(source_ip="203.0.113.10", action="ALLOW", category="XSS",
             rule_id="941001", timestamp=base_ts),
    ])

    stats = await store.get_stats()
    assert stats["top_attack_types"] == [], (
        "top_attack_types must be [] when no BLOCK/DROP events are present"
    )


# ---------------------------------------------------------------------------
# #252 — 'blocked' action shorthand in get_paginated
# EARS criteria:
#   BA1  WHEN action=blocked, every returned row has action ∈ {BLOCK, DROP}.
#   BA2  WHEN action=blocked, total_matching counts only those rows.
#   BA3  Case-insensitive: action=Blocked, BLOCKED, blocked all expand the same.
#   BA4  Exact BLOCK still maps to BLOCK+DROP (legacy compat unchanged).
#   BA5  Exact DROP returns only DROP rows.
#   BA6  Exact ALLOW returns only ALLOW rows.
#   BA7  BLOCKED_ACTIONS constant = frozenset({"BLOCK", "DROP"}).
# ---------------------------------------------------------------------------


async def _setup_mixed_actions(store: SQLiteEventStore) -> None:
    """Insert three events — BLOCK, DROP, ALLOW — for action-filter tests."""
    base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    await store.save_many([
        _evt(source_ip="192.0.2.11", action="BLOCK",
             timestamp=base, rule_id="b1", payload_snippet="block"),
        _evt(source_ip="192.0.2.12", action="DROP",
             timestamp=base + timedelta(seconds=1), rule_id="d1", payload_snippet="drop"),
        _evt(source_ip="192.0.2.13", action="ALLOW",
             timestamp=base + timedelta(seconds=2), rule_id="a1", payload_snippet="allow"),
    ])


async def test_blocked_shorthand_returns_only_block_and_drop(
    store: SQLiteEventStore,
) -> None:
    """BA1: action=blocked → every row has action ∈ {BLOCK, DROP}."""
    from firewatch_sdk.models import FilterSpec
    await _setup_mixed_actions(store)
    result = await store.get_paginated(filters=FilterSpec(action="blocked"))
    actions = {r["action"] for r in result["logs"]}
    assert "ALLOW" not in actions, "ALLOW must not appear when action=blocked"
    assert actions <= {"BLOCK", "DROP"}, (
        f"Unexpected actions in blocked filter result: {actions}"
    )
    assert len(result["logs"]) == 2


async def test_blocked_shorthand_total_matching_counts_only_blocked(
    store: SQLiteEventStore,
) -> None:
    """BA2: total_matching counts only BLOCK+DROP rows when action=blocked."""
    from firewatch_sdk.models import FilterSpec
    await _setup_mixed_actions(store)
    result = await store.get_paginated(filters=FilterSpec(action="blocked"))
    assert result["total_matching"] == 2, (
        f"Expected total_matching=2, got {result['total_matching']}"
    )


async def test_blocked_shorthand_case_insensitive(
    store: SQLiteEventStore,
) -> None:
    """BA3: 'Blocked', 'BLOCKED', 'blocked' all expand to BLOCK+DROP."""
    from firewatch_sdk.models import FilterSpec
    await _setup_mixed_actions(store)
    for variant in ("blocked", "Blocked", "BLOCKED"):
        result = await store.get_paginated(filters=FilterSpec(action=variant))
        assert result["total_matching"] == 2, (
            f"action={variant!r} must match 2 rows, got {result['total_matching']}"
        )
        actions = {r["action"] for r in result["logs"]}
        assert "ALLOW" not in actions, (
            f"action={variant!r} must not return ALLOW rows"
        )


async def test_exact_block_still_matches_block_and_drop(
    store: SQLiteEventStore,
) -> None:
    """BA4: exact 'BLOCK' keeps legacy compat — matches BLOCK+DROP."""
    from firewatch_sdk.models import FilterSpec
    await _setup_mixed_actions(store)
    result = await store.get_paginated(filters=FilterSpec(action="BLOCK"))
    assert result["total_matching"] == 2, (
        "action=BLOCK must still match both BLOCK and DROP (legacy compat)"
    )


async def test_exact_drop_returns_only_drop(
    store: SQLiteEventStore,
) -> None:
    """BA5: exact 'DROP' returns only DROP rows."""
    from firewatch_sdk.models import FilterSpec
    await _setup_mixed_actions(store)
    result = await store.get_paginated(filters=FilterSpec(action="DROP"))
    assert result["total_matching"] == 1
    assert result["logs"][0]["action"] == "DROP"


async def test_exact_allow_returns_only_allow(
    store: SQLiteEventStore,
) -> None:
    """BA6: exact 'ALLOW' returns only ALLOW rows."""
    from firewatch_sdk.models import FilterSpec
    await _setup_mixed_actions(store)
    result = await store.get_paginated(filters=FilterSpec(action="ALLOW"))
    assert result["total_matching"] == 1
    assert result["logs"][0]["action"] == "ALLOW"


def test_blocked_actions_constant() -> None:
    """BA7: BLOCKED_ACTIONS module constant = frozenset({"BLOCK", "DROP"})."""
    from firewatch_core.adapters.sqlite_store import BLOCKED_ACTIONS
    assert BLOCKED_ACTIONS == frozenset({"BLOCK", "DROP"}), (
        "BLOCKED_ACTIONS must be the canonical definition of the 'blocked' set"
    )


# ---------------------------------------------------------------------------
# Issue #247 — get_timeline additive fields (severity, top_category, top_source_ip)
# ---------------------------------------------------------------------------
# EARS: WHEN /logs/timeline is queried, each bucket SHALL include per-severity
#   counts, top_category, and top_source_ip as additive fields; existing fields
#   SHALL be byte-identical to pre-#247 (golden suite stays green).


async def test_get_timeline_additive_fields_present(
    store: SQLiteEventStore,
) -> None:
    """TLX1: Each bucket row includes the three additive fields from issue #247."""
    await store.save_many([_evt()])
    tl = await store.get_timeline(None, None)
    assert len(tl) >= 1
    row = tl[-1]  # most recent bucket
    # Additive fields must be present
    assert "severity" in row, "severity key must be present (issue #247)"
    assert "top_category" in row, "top_category key must be present (issue #247)"
    assert "top_source_ip" in row, "top_source_ip key must be present (issue #247)"


async def test_get_timeline_existing_fields_unchanged(
    store: SQLiteEventStore,
) -> None:
    """TLX2: Existing golden-pinned keys (hour, total, blocked, granularity) are unchanged."""
    await store.save_many([_evt(action="BLOCK")])
    tl = await store.get_timeline(None, None)
    assert len(tl) >= 1
    row = tl[-1]
    assert "hour" in row
    assert "total" in row
    assert "blocked" in row
    assert "granularity" in row
    # Values must be consistent
    assert isinstance(row["total"], int)
    assert isinstance(row["blocked"], int)
    assert row["granularity"] in ("hourly", "daily")


async def test_get_timeline_severity_counts_correct(
    store: SQLiteEventStore,
) -> None:
    """TLX3: severity sub-dict counts reflect actual severity distribution.

    Uses explicit start/end to avoid the default 12-hour look-back window
    truncating past-dated fixtures.  Events are differentiated by rule_id
    so the UNIQUE dedup index does not collapse them.
    """
    ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        _evt(severity="critical", timestamp=ts, rule_id="A1"),
        _evt(severity="critical", timestamp=ts, rule_id="A2"),
        _evt(severity="high",     timestamp=ts, rule_id="A3"),
        _evt(severity="medium",   timestamp=ts, rule_id="A4"),
        _evt(severity="low",      timestamp=ts, rule_id="A5"),
    ]
    await store.save_many(events)
    tl = await store.get_timeline("2026-06-01T00:00:00+00:00", "2026-06-01T23:59:59+00:00")
    nonempty = [r for r in tl if r["total"] > 0]
    assert len(nonempty) >= 1, "expected at least one non-empty bucket"
    row = nonempty[-1]
    sev = row["severity"]
    assert isinstance(sev, dict)
    assert sev["critical"] == 2, f"expected 2 critical, got {sev['critical']}"
    assert sev["high"] == 1, f"expected 1 high, got {sev['high']}"
    assert sev["medium"] == 1, f"expected 1 medium, got {sev['medium']}"
    assert sev["low"] == 1, f"expected 1 low, got {sev['low']}"


async def test_get_timeline_severity_normalises_case(
    store: SQLiteEventStore,
) -> None:
    """TLX4: LOWER() in the SQL normalises mixed-case severity values.

    SecurityEvent validates canonical lowercase, so pydantic-validated events
    always arrive in lowercase.  The SQL LOWER() guard is tested by inserting
    a mixed-case value directly via SQL (bypassing Pydantic) to simulate
    legacy plugin data that predates the canonical enum.

    Events differentiated by rule_id to survive the UNIQUE dedup index.
    """
    ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    ts_iso = ts.isoformat()
    # Insert one canonical-lowercase "high" via the normal path.
    await store.save_many([_evt(severity="high", timestamp=ts, rule_id="B1")])
    # Insert one mixed-case "HIGH" directly via SQL (legacy / non-SDK ingestor).
    db = await store._conn()
    await db.execute(
        "INSERT INTO logs (source_ip, destination_port, protocol, action, rule_id, "
        "payload_snippet, timestamp, source_type, source_id, severity, category) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("10.0.0.1", 0, "", "BLOCK", "B2", "test", ts_iso, "suricata", "pi-home", "HIGH", "IDS Alert"),
    )
    await db.commit()
    tl = await store.get_timeline("2026-06-01T00:00:00+00:00", "2026-06-01T23:59:59+00:00")
    nonempty = [r for r in tl if r["total"] > 0]
    assert len(nonempty) >= 1, "expected at least one non-empty bucket"
    row = nonempty[-1]
    assert row["severity"]["high"] == 2, (
        f"LOWER() should normalise 'HIGH' + 'high' to same bucket; got {row['severity']['high']}"
    )


async def test_get_timeline_top_category_is_mode(
    store: SQLiteEventStore,
) -> None:
    """TLX5: top_category is the most-frequent category in the bucket.

    Events differentiated by rule_id to survive the UNIQUE dedup index.
    """
    ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    await store.save_many([
        _evt(category="SQL Injection", timestamp=ts, rule_id="D1"),
        _evt(category="SQL Injection", timestamp=ts, rule_id="D2"),
        _evt(category="XSS",           timestamp=ts, rule_id="D3"),
    ])
    tl = await store.get_timeline("2026-06-01T00:00:00+00:00", "2026-06-01T23:59:59+00:00")
    nonempty = [r for r in tl if r["total"] > 0]
    assert len(nonempty) >= 1, "expected at least one non-empty bucket"
    row = nonempty[-1]
    assert row["top_category"] == "SQL Injection", (
        f"top_category should be 'SQL Injection' (mode), got {row['top_category']!r}"
    )


async def test_get_timeline_top_source_ip_is_mode(
    store: SQLiteEventStore,
) -> None:
    """TLX6: top_source_ip is the most-frequent source IP in the bucket.

    Events differentiated by rule_id to survive the UNIQUE dedup index.
    """
    ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    await store.save_many([
        _evt(source_ip="192.0.2.4", timestamp=ts, rule_id="C1"),
        _evt(source_ip="192.0.2.4", timestamp=ts, rule_id="C2"),
        _evt(source_ip="198.51.100.8", timestamp=ts, rule_id="C3"),
    ])
    tl = await store.get_timeline("2026-06-01T00:00:00+00:00", "2026-06-01T23:59:59+00:00")
    nonempty = [r for r in tl if r["total"] > 0]
    assert len(nonempty) >= 1, "expected at least one non-empty bucket"
    row = nonempty[-1]
    assert row["top_source_ip"] == "192.0.2.4", (
        f"top_source_ip should be '192.0.2.4' (mode), got {row['top_source_ip']!r}"
    )


async def test_get_timeline_empty_bucket_severity_zero(
    store: SQLiteEventStore,
) -> None:
    """TLX7: Zero-event buckets have severity {critical:0, high:0, medium:0, low:0}."""
    # Query a time range where no events exist
    tl = await store.get_timeline(
        "2020-01-01T00:00:00+00:00",
        "2020-01-01T12:00:00+00:00",
    )
    assert len(tl) >= 1
    for row in tl:
        sev = row["severity"]
        assert sev == {"critical": 0, "high": 0, "medium": 0, "low": 0}, (
            f"empty bucket severity must be all-zero, got {sev}"
        )
        assert row["top_category"] is None
        assert row["top_source_ip"] is None


# ---------------------------------------------------------------------------
# CF1–CF4 — get_ip_counterfactual (issue #215)
# ---------------------------------------------------------------------------


async def test_get_ip_counterfactual_mixed_actions(
    store: SQLiteEventStore,
) -> None:
    """CF1: unblocked_events == total_events - blocked_events for mixed actions.

    EARS ubiquitous: the number SHALL be reproducible from the evidence link's
    filtered event list (counts match).
    """
    ip = "192.0.2.71"
    await store.save_many([
        # 3 blocked (BLOCK/DROP)
        _evt(source_ip=ip, action="BLOCK", rule_id="R1"),
        _evt(source_ip=ip, action="BLOCK", rule_id="R2"),
        _evt(source_ip=ip, action="DROP", rule_id="R3"),
        # 2 unblocked (ALERT — IDS mode, ADR-0012; and ALLOW)
        _evt(source_ip=ip, action="ALERT", rule_id="R4"),
        _evt(source_ip=ip, action="ALLOW", rule_id="R5"),
    ])
    result = await store.get_ip_counterfactual(ip)
    assert result["total_events"] == 5
    assert result["blocked_events"] == 3
    assert result["unblocked_events"] == 2


async def test_get_ip_counterfactual_all_blocked(
    store: SQLiteEventStore,
) -> None:
    """CF2: When all events are BLOCK/DROP, unblocked_events is 0.

    EARS: WHEN all of the entity's events were already blocked, the card SHALL
    say so instead of showing '0' bare.  The store returns 0 honestly.
    """
    ip = "192.0.2.72"
    await store.save_many([
        _evt(source_ip=ip, action="BLOCK", rule_id="X1"),
        _evt(source_ip=ip, action="DROP", rule_id="X2"),
    ])
    result = await store.get_ip_counterfactual(ip)
    assert result["total_events"] == 2
    assert result["blocked_events"] == 2
    assert result["unblocked_events"] == 0


async def test_get_ip_counterfactual_unknown_ip_returns_zeros(
    store: SQLiteEventStore,
) -> None:
    """CF3: Unknown IP (no stored events) returns all-zero counts.

    Honest zero — never fabricated.
    """
    result = await store.get_ip_counterfactual("203.0.113.99")
    assert result == {"total_events": 0, "blocked_events": 0, "unblocked_events": 0}


async def test_get_ip_counterfactual_alert_events_count_as_unblocked(
    store: SQLiteEventStore,
) -> None:
    """CF4: Suricata ALERT events are unblocked (ADR-0012 semantics).

    IDS ALERT = detected but not stopped.  Blocking the IP would have stopped them.
    They must appear in unblocked_events, not blocked_events.
    """
    ip = "192.0.2.73"
    await store.save_many([
        _evt(source_ip=ip, action="ALERT", rule_id="A1"),
        _evt(source_ip=ip, action="ALERT", rule_id="A2"),
        _evt(source_ip=ip, action="BLOCK", rule_id="A3"),
    ])
    result = await store.get_ip_counterfactual(ip)
    # 1 BLOCK → blocked; 2 ALERT → unblocked
    assert result["blocked_events"] == 1
    assert result["unblocked_events"] == 2
    # Arithmetic invariant
    assert result["unblocked_events"] == result["total_events"] - result["blocked_events"]


# ---------------------------------------------------------------------------
# Issue #314 — get_attack_dispositions key-uniqueness
#
# EARS criteria:
#   AD1  The response SHALL contain at most one row per (attack_type, action) pair.
#   AD2  WHEN a stored category literally named "Other" is in the top-N AND tail
#        categories exist, their counts SHALL merge into a single row per action.
#   AD3  Count conservation: total event count across all response rows equals the
#        total event count in the store.
#   AD4  Empty store returns an empty list.
# ---------------------------------------------------------------------------


async def test_get_attack_dispositions_empty_store(
    store: SQLiteEventStore,
) -> None:
    """AD4: Empty store → empty list (no crash, no fabricated rows)."""
    result = await store.get_attack_dispositions(top_n=5)
    assert result == []


async def test_get_attack_dispositions_key_uniqueness(
    store: SQLiteEventStore,
) -> None:
    """AD1: Every (attack_type, action) pair appears at most once in the response.

    Reproduces the collision: a literal 'Other' category is stored AND tail
    categories exist, so step-2 top-N and step-3 tail both want to emit an
    'Other' row for the same action.

    Setup: top_n=1 forces only the most-frequent category ('Other', 2 events) into
    top-N. 'Rare' (1 event) falls into the tail bucket.  Step-3 emits Other×BLOCK
    for the tail, colliding with step-2's Other×BLOCK from the literal top-N row.
    """
    # Two events with category='Other' (literally stored) — lands in top-N (top_n=1).
    # Two events with category='Rare' (tail, outside top-1) — step-3 bucket.
    # Both map to action='BLOCK', so the old code would emit two Other×BLOCK rows.
    events = [
        _evt(source_ip="192.0.2.1", action="BLOCK", category="Other", rule_id="O1"),
        _evt(source_ip="192.0.2.2", action="BLOCK", category="Other", rule_id="O2"),
        _evt(source_ip="192.0.2.3", action="BLOCK", category="Rare", rule_id="R1"),
        _evt(source_ip="192.0.2.4", action="BLOCK", category="Rare", rule_id="R2"),
    ]
    await store.save_many(events)

    # top_n=1: only 'Other' (most frequent) fits in top-N; 'Rare' goes to tail.
    result = await store.get_attack_dispositions(top_n=1)

    # Build (attack_type, action) key set and check uniqueness.
    keys = [(r["attack_type"], r["action"]) for r in result]
    assert len(keys) == len(set(keys)), (
        f"Duplicate (attack_type, action) keys in response: {keys}"
    )


async def test_get_attack_dispositions_other_merge_sums_counts(
    store: SQLiteEventStore,
) -> None:
    """AD2+AD3: When literal 'Other' is in top-N AND tail exists, counts merge.

    The total count in the response must equal the total events inserted.

    Setup: top_n=1 forces only 'Other' (most frequent) into top-N; 'Tail' goes to
    the tail bucket.  Both share action='ALERT'.  Old code → two Other×ALERT rows
    with counts 2 and 1 (sum=3 but split across duplicates).  Fixed code → one
    Other×ALERT row with count 3.
    """
    # 3 events: category='Other' (top-N literal), category='Tail' (tail bucket).
    # All action='ALERT'.  Old code → two Other×ALERT rows with counts 2 and 1.
    # Fixed code → one Other×ALERT row with count 3.
    events = [
        _evt(source_ip="192.0.2.10", action="ALERT", category="Other", rule_id="O1"),
        _evt(source_ip="192.0.2.11", action="ALERT", category="Other", rule_id="O2"),
        _evt(source_ip="192.0.2.12", action="ALERT", category="Tail", rule_id="T1"),
    ]
    await store.save_many(events)

    # top_n=1: only 'Other' (2 events) is in top-N; 'Tail' (1 event) is tail.
    result = await store.get_attack_dispositions(top_n=1)

    # AD1: no duplicate keys.
    keys = [(r["attack_type"], r["action"]) for r in result]
    assert len(keys) == len(set(keys)), f"Duplicate keys: {keys}"

    # AD2: the single Other×ALERT row must carry the merged count.
    other_alert_rows = [
        r for r in result if r["attack_type"] == "Other" and r["action"] == "ALERT"
    ]
    assert len(other_alert_rows) == 1, (
        f"Expected exactly one Other×ALERT row, got {other_alert_rows}"
    )
    assert other_alert_rows[0]["count"] == 3, (
        f"Expected merged count 3, got {other_alert_rows[0]['count']}"
    )

    # AD3: count conservation — sum of all counts equals total events inserted.
    total_in_response = sum(r["count"] for r in result)
    assert total_in_response == len(events), (
        f"Count conservation violated: response sum={total_in_response}, inserted={len(events)}"
    )


async def test_get_attack_dispositions_multi_action_merge(
    store: SQLiteEventStore,
) -> None:
    """AD2: Merge works across multiple action types independently.

    'Other' (literal) in top-N with both BLOCK and ALERT actions.
    Tail categories also have BLOCK and ALERT.  top_n=1 forces only 'Other'
    (most-frequent) into top-N; TailA and TailB go to the tail bucket.
    Result: exactly one Other×BLOCK and one Other×ALERT row each, with merged counts.
    """
    events = [
        # Literal 'Other' — will be top-N (2 events → most frequent)
        _evt(source_ip="192.0.2.20", action="BLOCK", category="Other", rule_id="O1"),
        _evt(source_ip="192.0.2.21", action="ALERT", category="Other", rule_id="O2"),
        # Tail categories (1 event each — pushed out by top_n=1)
        _evt(source_ip="192.0.2.22", action="BLOCK", category="TailA", rule_id="TA1"),
        _evt(source_ip="192.0.2.23", action="ALERT", category="TailB", rule_id="TB1"),
    ]
    await store.save_many(events)

    # top_n=1: only 'Other' fits; TailA and TailB are tail.
    result = await store.get_attack_dispositions(top_n=1)

    keys = [(r["attack_type"], r["action"]) for r in result]
    assert len(keys) == len(set(keys)), f"Duplicate keys: {keys}"

    other_rows = [r for r in result if r["attack_type"] == "Other"]
    other_actions = {r["action"] for r in other_rows}
    # Both BLOCK and ALERT should be present, each as a single merged row.
    assert "BLOCK" in other_actions
    assert "ALERT" in other_actions
    assert len(other_rows) == len(other_actions), (
        "Each Other×action should appear exactly once"
    )


async def test_get_attack_dispositions_no_tail_no_collision(
    store: SQLiteEventStore,
) -> None:
    """AD1: When all categories are in top-N (no tail), no duplication occurs.

    This is the normal case: distinct categories, all fit in top-5.
    No 'Other' literal, no tail — just the happy path.
    """
    events = [
        _evt(source_ip="192.0.2.30", action="BLOCK", category="SQLi", rule_id="S1"),
        _evt(source_ip="192.0.2.31", action="ALERT", category="XSS", rule_id="X1"),
        _evt(source_ip="192.0.2.32", action="BLOCK", category="LFI", rule_id="L1"),
    ]
    await store.save_many(events)

    result = await store.get_attack_dispositions(top_n=5)

    keys = [(r["attack_type"], r["action"]) for r in result]
    assert len(keys) == len(set(keys)), f"Duplicate keys: {keys}"
    # Total count preserved (AD3)
    assert sum(r["count"] for r in result) == len(events)


# ---------------------------------------------------------------------------
# Issue #334 — get_paginated geo enrichment (inline city/country from ip_geo)
# ---------------------------------------------------------------------------
# EARS:
#   GE1  WHEN a log row IP has a cached geo entry, get_paginated SHALL include
#        geo_city and geo_country as non-null fields on that row.
#   GE2  WHEN a log row IP has NO cached geo entry, get_paginated SHALL include
#        geo_city=None and geo_country=None (null, not absent) so callers can
#        distinguish "cached unknown" from "field absent".
#   GE3  The geo join SHALL NOT affect existing fields or envelope keys (additive
#        only — golden-pinned fields are byte-identical).
#   GE4  Multiple rows with the SAME IP SHALL all carry the same geo_city /
#        geo_country (JOIN is correct, not a cross-product).
#   GE5  Rows with geo AND rows without geo in the SAME page SHALL not interfere
#        (mixed-geo page is consistent).


@pytest.mark.asyncio
async def test_get_paginated_geo_city_country_present_when_cached(
    store: SQLiteEventStore,
) -> None:
    """GE1: When geo is cached for an IP, rows carry geo_city and geo_country."""
    await store.save_many([_evt(source_ip="203.0.113.10")])
    await store.upsert_ip_geo([
        {"ip": "203.0.113.10", "country": "Germany", "city": "Frankfurt am Main",
         "lat": 50.11, "lon": 8.68},
    ])

    result = await store.get_paginated(10)
    row = next(r for r in result["logs"] if r["source_ip"] == "203.0.113.10")
    assert row.get("geo_city") == "Frankfurt am Main", (
        "geo_city must carry the cached city (GE1)"
    )
    assert row.get("geo_country") == "Germany", (
        "geo_country must carry the cached country (GE1)"
    )


@pytest.mark.asyncio
async def test_get_paginated_geo_null_when_not_cached(
    store: SQLiteEventStore,
) -> None:
    """GE2: When geo is NOT cached for an IP, geo_city and geo_country are None."""
    await store.save_many([_evt(source_ip="203.0.113.20")])
    # Deliberately do NOT upsert any geo for this IP

    result = await store.get_paginated(10)
    row = next(r for r in result["logs"] if r["source_ip"] == "203.0.113.20")
    assert row.get("geo_city") is None, "geo_city must be None when not cached (GE2)"
    assert row.get("geo_country") is None, "geo_country must be None when not cached (GE2)"


@pytest.mark.asyncio
async def test_get_paginated_geo_does_not_alter_envelope_keys(
    store: SQLiteEventStore,
) -> None:
    """GE3: Existing envelope keys (logs, next_cursor, has_more, total_matching) intact."""
    await store.save_many([_evt(source_ip="203.0.113.30")])

    result = await store.get_paginated(10)
    assert "logs" in result
    assert "next_cursor" in result
    assert "has_more" in result
    assert "total_matching" in result
    # Geo fields are additive — they must not replace any existing log-row field
    row = result["logs"][0]
    assert "source_ip" in row
    assert "action" in row
    assert "timestamp" in row


@pytest.mark.asyncio
async def test_get_paginated_geo_multiple_rows_same_ip(
    store: SQLiteEventStore,
) -> None:
    """GE4: Multiple rows for the same IP all carry the same geo_city / geo_country."""
    from datetime import timedelta
    ts_base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        _evt(source_ip="203.0.113.40", timestamp=ts_base, rule_id="R1"),
        _evt(source_ip="203.0.113.40", timestamp=ts_base + timedelta(seconds=1), rule_id="R2"),
    ]
    await store.save_many(events)
    await store.upsert_ip_geo([
        {"ip": "203.0.113.40", "country": "Bulgaria", "city": "Sopot",
         "lat": 42.66, "lon": 24.75},
    ])

    result = await store.get_paginated(10)
    rows = [r for r in result["logs"] if r["source_ip"] == "203.0.113.40"]
    assert len(rows) == 2, "Both events must be returned (GE4)"
    for row in rows:
        assert row.get("geo_city") == "Sopot", (
            "Every row for the same IP must carry the cached geo_city (GE4)"
        )
        assert row.get("geo_country") == "Bulgaria", (
            "Every row for the same IP must carry the cached geo_country (GE4)"
        )


@pytest.mark.asyncio
async def test_get_paginated_geo_mixed_page(
    store: SQLiteEventStore,
) -> None:
    """GE5: A page with some IPs cached and some not is consistent."""
    from datetime import timedelta
    ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    # One IP with cached geo, one without
    await store.save_many([
        _evt(source_ip="203.0.113.50", timestamp=ts, rule_id="R1"),
        _evt(source_ip="203.0.113.51", timestamp=ts + timedelta(seconds=1), rule_id="R2"),
    ])
    await store.upsert_ip_geo([
        {"ip": "203.0.113.50", "country": "Bulgaria", "city": "Sopot",
         "lat": 42.66, "lon": 24.75},
    ])
    # 203.0.113.51 has no cached geo

    result = await store.get_paginated(10)
    logs_by_ip = {r["source_ip"]: r for r in result["logs"]}

    with_geo = logs_by_ip["203.0.113.50"]
    assert with_geo.get("geo_city") == "Sopot"
    assert with_geo.get("geo_country") == "Bulgaria"

    without_geo = logs_by_ip["203.0.113.51"]
    assert without_geo.get("geo_city") is None
    assert without_geo.get("geo_country") is None
