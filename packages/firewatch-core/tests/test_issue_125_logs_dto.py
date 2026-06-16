"""Tests for issue #125 — surface rule_name / dest_port / payload_snippet in /logs DTO.

EARS acceptance criteria:

  E1  When save_many persists a SecurityEvent that has rule_name set, the value
      is written to the logs table's rule_name column.

  E2  get_paginated returns rule_name in each log row when the field is populated.

  E3  get_paginated returns rule_name as None/absent when the event had no rule_name
      (no regression — existing rows must not error).

  E4  destination_port is present in log rows returned by get_paginated.

  E5  payload_snippet is present in log rows returned by get_paginated.

  E6  get_by_ip_raw returns rule_name correctly (round-trip through DB).

  E7  Schema migration: init() on a DB that already has a logs table WITHOUT
      rule_name adds the column without losing existing rows (backward compat).

Test IP policy: RFC 5737 documentation IPs only (gitleaks public-ipv4 rule).
"""
from __future__ import annotations

import aiosqlite
import pytest
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from pathlib import Path

from firewatch_sdk.models import SecurityEvent

from firewatch_core.adapters.sqlite_store import SQLiteEventStore

# ---------------------------------------------------------------------------
# Test constants — RFC 5737 documentation IPs only
# ---------------------------------------------------------------------------
_IP_A = "192.0.2.10"   # RFC 5737 TEST-NET-1
_IP_B = "198.51.100.5"  # RFC 5737 TEST-NET-2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ts(hour: int = 12) -> datetime:
    return datetime(2026, 6, 1, hour, 0, 0, tzinfo=timezone.utc)


def _event(
    *,
    source_ip: str = _IP_A,
    rule_id: str | None = "942100",
    rule_name: str | None = None,
    destination_port: int | None = 443,
    payload_snippet: str | None = None,
    hour: int = 12,
) -> SecurityEvent:
    return SecurityEvent(
        source_type="test_plugin",
        source_id="sensor-01",
        source_ip=source_ip,
        action="BLOCK",
        timestamp=_ts(hour),
        rule_id=rule_id,
        rule_name=rule_name,
        destination_port=destination_port,
        payload_snippet=payload_snippet,
    )


@pytest.fixture
async def store(tmp_path: Path) -> AsyncGenerator[SQLiteEventStore, None]:
    """Fresh, initialised SQLiteEventStore backed by a tmp file."""
    s = SQLiteEventStore(tmp_path / "test.db")
    await s.init()
    yield s
    await s.close()


# ---------------------------------------------------------------------------
# E1 — rule_name is persisted by save_many
# ---------------------------------------------------------------------------


async def test_e1_save_many_persists_rule_name(store: SQLiteEventStore) -> None:
    """E1: save_many writes rule_name to the logs table when the field is set."""
    ev = _event(
        rule_name="ET WEB_SERVER SQL Injection Attempt",
        payload_snippet="' OR 1=1--",
    )
    inserted = await store.save_many([ev])
    assert inserted == 1

    rows = await store.get_by_ip_raw(_IP_A)
    assert len(rows) == 1
    assert rows[0].get("rule_name") == "ET WEB_SERVER SQL Injection Attempt", (
        f"Expected rule_name to be persisted; got {rows[0].get('rule_name')!r}"
    )


# ---------------------------------------------------------------------------
# E2 — get_paginated returns rule_name when populated
# ---------------------------------------------------------------------------


async def test_e2_get_paginated_surfaces_rule_name(store: SQLiteEventStore) -> None:
    """E2: get_paginated log rows contain rule_name when set."""
    ev = _event(rule_name="Microsoft_DefaultRuleSet-1.1-SQLI-942100")
    await store.save_many([ev])

    result = await store.get_paginated(limit=10)
    logs = result["logs"]
    assert len(logs) == 1
    assert "rule_name" in logs[0], (
        "get_paginated log rows must include rule_name key (issue #125)"
    )
    assert logs[0]["rule_name"] == "Microsoft_DefaultRuleSet-1.1-SQLI-942100"


# ---------------------------------------------------------------------------
# E3 — get_paginated returns None/null for rule_name when not set
# ---------------------------------------------------------------------------


async def test_e3_get_paginated_rule_name_null_when_absent(
    store: SQLiteEventStore,
) -> None:
    """E3: get_paginated returns None/null for rule_name when event has none."""
    ev = _event(rule_name=None)
    await store.save_many([ev])

    result = await store.get_paginated(limit=10)
    logs = result["logs"]
    assert len(logs) == 1
    # Key must be present; value must be None (not missing, not empty string)
    assert "rule_name" in logs[0], (
        "rule_name key must be present even when value is None"
    )
    assert logs[0]["rule_name"] is None, (
        f"Expected rule_name=None for events without rule_name; got {logs[0]['rule_name']!r}"
    )


# ---------------------------------------------------------------------------
# E4 — destination_port is surfaced in get_paginated
# ---------------------------------------------------------------------------


async def test_e4_get_paginated_surfaces_destination_port(
    store: SQLiteEventStore,
) -> None:
    """E4: get_paginated log rows contain destination_port."""
    ev = _event(destination_port=8443)
    await store.save_many([ev])

    result = await store.get_paginated(limit=10)
    logs = result["logs"]
    assert len(logs) == 1
    assert "destination_port" in logs[0], (
        "get_paginated log rows must include destination_port key"
    )
    assert logs[0]["destination_port"] == 8443


# ---------------------------------------------------------------------------
# E5 — payload_snippet is surfaced in get_paginated
# ---------------------------------------------------------------------------


async def test_e5_get_paginated_surfaces_payload_snippet(
    store: SQLiteEventStore,
) -> None:
    """E5: get_paginated log rows contain payload_snippet."""
    ev = _event(payload_snippet="GET /admin?id=1%27 HTTP/1.1")
    await store.save_many([ev])

    result = await store.get_paginated(limit=10)
    logs = result["logs"]
    assert len(logs) == 1
    assert "payload_snippet" in logs[0], (
        "get_paginated log rows must include payload_snippet key"
    )
    assert logs[0]["payload_snippet"] == "GET /admin?id=1%27 HTTP/1.1"


# ---------------------------------------------------------------------------
# E6 — get_by_ip_raw round-trip for rule_name
# ---------------------------------------------------------------------------


async def test_e6_get_by_ip_raw_rule_name_roundtrip(store: SQLiteEventStore) -> None:
    """E6: get_by_ip_raw returns rule_name correctly after save_many."""
    sig = "ET SCAN Nmap Scripting Engine User-Agent Detected"
    ev = _event(source_ip=_IP_B, rule_name=sig, rule_id="2009358")
    await store.save_many([ev])

    rows = await store.get_by_ip_raw(_IP_B)
    assert len(rows) == 1
    assert rows[0].get("rule_name") == sig, (
        f"get_by_ip_raw must return the persisted rule_name; got {rows[0].get('rule_name')!r}"
    )


# ---------------------------------------------------------------------------
# E7 — Schema migration: init() adds rule_name to an existing DB
# ---------------------------------------------------------------------------


async def test_e7_migration_adds_rule_name_column(tmp_path: Path) -> None:
    """E7: init() adds rule_name column to a logs table that lacks it.

    Simulates a pre-existing DB created before issue #125 by manually creating
    the logs table without rule_name, inserting a row, then calling init() and
    verifying (a) the column exists, (b) old rows still read correctly.
    """
    db_path = tmp_path / "legacy.db"

    # Build a pre-#125 DB: logs table without rule_name
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip        TEXT    NOT NULL,
                destination_port INTEGER NOT NULL DEFAULT 0,
                protocol         TEXT    NOT NULL DEFAULT '',
                action           TEXT    NOT NULL,
                rule_id          TEXT,
                payload_snippet  TEXT,
                timestamp        TEXT    NOT NULL,
                source_type      TEXT    NOT NULL DEFAULT 'unknown',
                source_id        TEXT    NOT NULL DEFAULT 'default',
                severity         TEXT,
                category         TEXT
            )
        """)
        await db.execute("""
            INSERT INTO logs
                (source_ip, destination_port, protocol, action,
                 rule_id, payload_snippet, timestamp, source_type, source_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (_IP_A, 80, "TCP", "BLOCK", "942100", None,
              "2026-06-01T12:00:00+00:00", "azure_waf", "prod"))
        await db.commit()

    # Now call init() — it must add rule_name column and not lose the row
    store = SQLiteEventStore(db_path)
    await store.init()

    rows = await store.get_by_ip_raw(_IP_A)
    assert len(rows) == 1, "Pre-existing row must survive migration"
    # rule_name may be None for legacy rows — that's expected and acceptable
    assert "rule_name" in rows[0], (
        "rule_name key must be present in rows after migration"
    )

    await store.close()


# ---------------------------------------------------------------------------
# Regression — multiple field interplay in a single query
# ---------------------------------------------------------------------------


async def test_all_three_fields_in_single_paginated_row(
    store: SQLiteEventStore,
) -> None:
    """Smoke: a single event with all three fields survives the paginated round-trip."""
    ev = _event(
        rule_name="ET WEB_SERVER XSS Attempt in User-Agent Header",
        destination_port=443,
        payload_snippet="<script>alert(1)</script>",
    )
    await store.save_many([ev])

    result = await store.get_paginated(limit=10)
    logs = result["logs"]
    assert len(logs) == 1
    row = logs[0]
    assert row.get("rule_name") == "ET WEB_SERVER XSS Attempt in User-Agent Header"
    assert row.get("destination_port") == 443
    assert row.get("payload_snippet") == "<script>alert(1)</script>"
