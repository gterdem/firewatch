"""Tests for ML-1 — OCSF network-depth fields on SecurityEvent + SQLite store.

Mapped 1:1 to the EARS criteria from issue #429 / ADR-0048.

EARS-1  Migration idempotency: opening an OLD-schema DB adds every new column
        (incl. destination_ip) without error and without data loss; running init
        twice is a no-op (EARS-6: duplicate-column guard).
EARS-2  SecurityEvent model: every new field defaults to None; accepts valid values.
EARS-3  WHEN save_many persists an event, destination_ip and every populated new
        field are written; None fields store as NULL.
EARS-4  WHEN a row is read back, _row_to_security_event surfaces the new columns
        (NULL → None, populated → value).
EARS-5  WHERE a source leaves fields None, the store does NOT fabricate a value.
EARS-6  IF a column already exists, re-init is a no-op (no OperationalError).

Additional:
  - Full round-trip: write event with all new fields → read back → all values survive.
  - destination_ip specifically: previously dropped at persistence; now survives.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite
import pytest

from firewatch_sdk import SecurityEvent
from firewatch_core.adapters.sqlite_store import SQLiteEventStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = datetime(2026, 6, 13, 12, 0, 0, tzinfo=timezone.utc)

# RFC 5737 / RFC 1918 IPs only — never real/public/routable
_SRC_IP = "192.0.2.10"
_DST_IP = "198.51.100.20"


def _base_event(**overrides: Any) -> SecurityEvent:
    """Minimal valid SecurityEvent using RFC 5737 / RFC 1918 IPs."""
    return SecurityEvent(
        source_type="suricata",
        source_id="test-sensor",
        source_ip=_SRC_IP,
        action="ALERT",
        timestamp=_TS,
        **overrides,
    )


def _network_event() -> SecurityEvent:
    """SecurityEvent with ALL ADR-0048 network-depth fields populated."""
    return _base_event(
        destination_ip=_DST_IP,
        destination_port=443,
        protocol="TCP",
        # Group A — flow volume & duration (OCSF Network Activity 4001)
        bytes_in=1024,
        bytes_out=512,
        packets_in=10,
        packets_out=8,
        flow_duration_ms=350,
        # Group B — DNS (OCSF DNS Activity 4003)
        dns_query="example.com",
        dns_rcode="NOERROR",
        # Group C — TLS / JA4 fingerprint (OCSF TLS object on 4001)
        tls_ja4="t13d1516h2_8daaf6152771_02713d6af862",
        tls_ja4s="t13d790900_c8dde07ea8f6_b41a1c8e0d45",
        tls_sni="example.com",
        tls_version="TLSv1.3",
        # Group D — HTTP (OCSF HTTP Activity 4002)
        http_method="GET",
        http_host="example.com",
        http_url="https://example.com/path?q=1",
        http_user_agent="Mozilla/5.0",
    )


# ---------------------------------------------------------------------------
# EARS-2: Model field defaults and type acceptance
# ---------------------------------------------------------------------------


class TestSecurityEventModel:
    """EARS-2 — every new field defaults to None; accepts valid typed values."""

    def test_group_a_flow_fields_default_none(self) -> None:
        """Group A: bytes_in/out, packets_in/out, flow_duration_ms all default None."""
        ev = _base_event()
        assert ev.bytes_in is None
        assert ev.bytes_out is None
        assert ev.packets_in is None
        assert ev.packets_out is None
        assert ev.flow_duration_ms is None

    def test_group_b_dns_fields_default_none(self) -> None:
        """Group B: dns_query, dns_rcode default None."""
        ev = _base_event()
        assert ev.dns_query is None
        assert ev.dns_rcode is None

    def test_group_c_tls_fields_default_none(self) -> None:
        """Group C: tls_ja4, tls_ja4s, tls_sni, tls_version default None."""
        ev = _base_event()
        assert ev.tls_ja4 is None
        assert ev.tls_ja4s is None
        assert ev.tls_sni is None
        assert ev.tls_version is None

    def test_group_d_http_fields_default_none(self) -> None:
        """Group D: http_method, http_host, http_url, http_user_agent default None."""
        ev = _base_event()
        assert ev.http_method is None
        assert ev.http_host is None
        assert ev.http_url is None
        assert ev.http_user_agent is None

    def test_destination_ip_defaults_none(self) -> None:
        """destination_ip (ADR-0048 fix: was dropped at persistence) defaults None."""
        ev = _base_event()
        assert ev.destination_ip is None

    def test_accepts_valid_int_values(self) -> None:
        """Group A integer fields accept valid non-negative integers."""
        ev = _base_event(bytes_in=2048, bytes_out=1024, packets_in=20, packets_out=15, flow_duration_ms=1000)
        assert ev.bytes_in == 2048
        assert ev.bytes_out == 1024
        assert ev.packets_in == 20
        assert ev.packets_out == 15
        assert ev.flow_duration_ms == 1000

    def test_accepts_valid_str_values(self) -> None:
        """Group B/C/D string fields accept valid strings."""
        ev = _base_event(
            dns_query="malicious.example.com",
            dns_rcode="NXDOMAIN",
            tls_ja4="t13d1516h2_8daaf6152771_02713d6af862",
            tls_sni="malicious.example.com",
            tls_version="TLSv1.2",
            http_method="POST",
            http_host="malicious.example.com",
            http_url="/cmd=exec&id=1",
            http_user_agent="python-requests/2.28",
        )
        assert ev.dns_query == "malicious.example.com"
        assert ev.dns_rcode == "NXDOMAIN"
        assert ev.tls_ja4 == "t13d1516h2_8daaf6152771_02713d6af862"
        assert ev.http_method == "POST"

    def test_all_new_fields_populated(self) -> None:
        """All 16 new fields can be set in one shot."""
        ev = _network_event()
        assert ev.destination_ip == _DST_IP
        assert ev.bytes_in == 1024
        assert ev.bytes_out == 512
        assert ev.packets_in == 10
        assert ev.packets_out == 8
        assert ev.flow_duration_ms == 350
        assert ev.dns_query == "example.com"
        assert ev.dns_rcode == "NOERROR"
        assert ev.tls_ja4 == "t13d1516h2_8daaf6152771_02713d6af862"
        assert ev.tls_ja4s == "t13d790900_c8dde07ea8f6_b41a1c8e0d45"
        assert ev.tls_sni == "example.com"
        assert ev.tls_version == "TLSv1.3"
        assert ev.http_method == "GET"
        assert ev.http_host == "example.com"
        assert ev.http_url == "https://example.com/path?q=1"
        assert ev.http_user_agent == "Mozilla/5.0"

    def test_existing_source_code_still_creates_event_without_new_fields(self) -> None:
        """Existing sources that don't populate new fields still produce valid events.

        This is the modularity non-negotiable: zero changes required from sources.
        """
        ev = SecurityEvent(
            source_type="azure_waf",
            source_id="my-waf",
            source_ip=_SRC_IP,
            action="BLOCK",
            timestamp=_TS,
            rule_id="DefaultRuleSet-942100",
            category="WAF Rule",
        )
        # All new fields default to None — source needed no changes
        assert ev.bytes_in is None
        assert ev.tls_ja4 is None
        assert ev.dns_query is None
        assert ev.http_method is None


# ---------------------------------------------------------------------------
# EARS-1 + EARS-6: Migration idempotency on old-schema DB
# ---------------------------------------------------------------------------


class TestMigrationIdempotency:
    """EARS-1 + EARS-6 — additive migration adds missing columns; re-init is no-op."""

    @pytest.mark.asyncio
    async def test_old_schema_db_gets_new_columns(self, tmp_path: Path) -> None:
        """An OLD-schema DB (without new columns) gains all new columns after init().

        Simulates a DB created before ML-1 by creating the bare original schema,
        then running init() and verifying the new columns appear.
        """
        db_path = tmp_path / "old_schema.db"

        # Create the old schema manually (no new columns, no destination_ip)
        async with aiosqlite.connect(str(db_path)) as db:
            await db.execute("""
                CREATE TABLE logs (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip        TEXT    NOT NULL,
                    destination_port INTEGER NOT NULL DEFAULT 0,
                    protocol         TEXT    NOT NULL DEFAULT '',
                    action           TEXT    NOT NULL,
                    rule_id          TEXT,
                    rule_name        TEXT,
                    payload_snippet  TEXT,
                    timestamp        TEXT    NOT NULL,
                    source_type      TEXT    NOT NULL DEFAULT 'unknown',
                    source_id        TEXT    NOT NULL DEFAULT 'default',
                    severity         TEXT,
                    category         TEXT
                )
            """)
            # Insert a pre-migration row to verify data is not lost
            await db.execute(
                "INSERT INTO logs (source_ip, action, timestamp) VALUES (?, ?, ?)",
                (_SRC_IP, "ALERT", _TS.isoformat()),
            )
            await db.commit()

        # Run init() — should migrate cleanly
        store = SQLiteEventStore(db_path)
        await store.init()

        # Verify all new columns exist
        async with aiosqlite.connect(str(db_path)) as db:
            cursor = await db.execute("PRAGMA table_info(logs)")
            cols = {row[1] for row in await cursor.fetchall()}

        _expected_new_cols = {
            "destination_ip",
            "bytes_in", "bytes_out", "packets_in", "packets_out", "flow_duration_ms",
            "dns_query", "dns_rcode",
            "tls_ja4", "tls_ja4s", "tls_sni", "tls_version",
            "http_method", "http_host", "http_url", "http_user_agent",
        }
        missing = _expected_new_cols - cols
        assert not missing, f"Migration did not add columns: {missing}"

        await store.close()

    @pytest.mark.asyncio
    async def test_existing_row_preserved_after_migration(self, tmp_path: Path) -> None:
        """Pre-migration rows survive with NULL in new columns — no data loss (EARS-1)."""
        db_path = tmp_path / "old_data.db"

        async with aiosqlite.connect(str(db_path)) as db:
            await db.execute("""
                CREATE TABLE logs (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip        TEXT    NOT NULL,
                    destination_port INTEGER NOT NULL DEFAULT 0,
                    protocol         TEXT    NOT NULL DEFAULT '',
                    action           TEXT    NOT NULL,
                    rule_id          TEXT,
                    rule_name        TEXT,
                    payload_snippet  TEXT,
                    timestamp        TEXT    NOT NULL,
                    source_type      TEXT    NOT NULL DEFAULT 'unknown',
                    source_id        TEXT    NOT NULL DEFAULT 'default',
                    severity         TEXT,
                    category         TEXT
                )
            """)
            await db.execute(
                """INSERT INTO logs
                   (source_ip, action, timestamp, source_type, source_id, rule_id)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (_SRC_IP, "BLOCK", _TS.isoformat(), "suricata", "sensor-a", "1001"),
            )
            await db.commit()

        store = SQLiteEventStore(db_path)
        await store.init()

        # Pre-migration row still there
        events = await store.get_by_ip(_SRC_IP)
        assert len(events) == 1
        assert events[0].source_ip == _SRC_IP
        assert events[0].action == "BLOCK"
        # New fields are NULL → None (not fabricated)
        assert events[0].bytes_in is None
        assert events[0].dns_query is None
        assert events[0].tls_ja4 is None

        await store.close()

    @pytest.mark.asyncio
    async def test_init_twice_is_noop(self, tmp_path: Path) -> None:
        """EARS-6: calling init() on a fully-migrated DB is a no-op — no error."""
        store = SQLiteEventStore(tmp_path / "fresh.db")
        await store.init()
        # Second init must not raise "duplicate column name"
        await store.init()
        await store.close()

    @pytest.mark.asyncio
    async def test_migration_does_not_raise_on_existing_columns(self, tmp_path: Path) -> None:
        """EARS-6: re-init with all columns already present silently no-ops each ALTER."""
        # First init creates all columns
        store = SQLiteEventStore(tmp_path / "full.db")
        await store.init()
        await store.close()

        # Second init must succeed without OperationalError about duplicate columns
        store2 = SQLiteEventStore(tmp_path / "full.db")
        await store2.init()
        await store2.close()


# ---------------------------------------------------------------------------
# EARS-3 + EARS-4: Persistence round-trip
# ---------------------------------------------------------------------------


class TestStoreRoundTrip:
    """EARS-3 + EARS-4 — write all new fields; read them back intact."""

    @pytest.fixture
    async def store(self, tmp_path: Path):
        s = SQLiteEventStore(tmp_path / "rt.db")
        await s.init()
        yield s
        await s.close()

    @pytest.mark.asyncio
    async def test_destination_ip_survives_round_trip(self, store: SQLiteEventStore) -> None:
        """destination_ip: previously dropped at store boundary; now persisted (ADR-0048)."""
        ev = _base_event(destination_ip=_DST_IP)
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert len(events) == 1
        assert events[0].destination_ip == _DST_IP

    @pytest.mark.asyncio
    async def test_group_a_flow_fields_survive_round_trip(self, store: SQLiteEventStore) -> None:
        """Group A: bytes_in/out, packets_in/out, flow_duration_ms persist and are read back."""
        ev = _base_event(
            bytes_in=8192,
            bytes_out=4096,
            packets_in=100,
            packets_out=90,
            flow_duration_ms=5000,
        )
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert len(events) == 1
        assert events[0].bytes_in == 8192
        assert events[0].bytes_out == 4096
        assert events[0].packets_in == 100
        assert events[0].packets_out == 90
        assert events[0].flow_duration_ms == 5000

    @pytest.mark.asyncio
    async def test_group_b_dns_fields_survive_round_trip(self, store: SQLiteEventStore) -> None:
        """Group B: dns_query, dns_rcode persist and are read back."""
        ev = _base_event(dns_query="suspicious.example.com", dns_rcode="NXDOMAIN")
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert events[0].dns_query == "suspicious.example.com"
        assert events[0].dns_rcode == "NXDOMAIN"

    @pytest.mark.asyncio
    async def test_group_c_tls_fields_survive_round_trip(self, store: SQLiteEventStore) -> None:
        """Group C: tls_ja4, tls_ja4s, tls_sni, tls_version persist and are read back."""
        ja4 = "t13d1516h2_8daaf6152771_02713d6af862"
        ja4s = "t13d790900_c8dde07ea8f6_b41a1c8e0d45"
        ev = _base_event(tls_ja4=ja4, tls_ja4s=ja4s, tls_sni="example.com", tls_version="TLSv1.3")
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert events[0].tls_ja4 == ja4
        assert events[0].tls_ja4s == ja4s
        assert events[0].tls_sni == "example.com"
        assert events[0].tls_version == "TLSv1.3"

    @pytest.mark.asyncio
    async def test_group_d_http_fields_survive_round_trip(self, store: SQLiteEventStore) -> None:
        """Group D: http_method, http_host, http_url, http_user_agent persist and are read back."""
        ev = _base_event(
            http_method="POST",
            http_host="example.com",
            http_url="/login",
            http_user_agent="curl/7.88",
        )
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert events[0].http_method == "POST"
        assert events[0].http_host == "example.com"
        assert events[0].http_url == "/login"
        assert events[0].http_user_agent == "curl/7.88"

    @pytest.mark.asyncio
    async def test_all_new_fields_full_round_trip(self, store: SQLiteEventStore) -> None:
        """All 16 new fields (incl. destination_ip) survive a single round-trip."""
        ev = _network_event()
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert len(events) == 1
        result = events[0]

        assert result.destination_ip == _DST_IP
        assert result.bytes_in == 1024
        assert result.bytes_out == 512
        assert result.packets_in == 10
        assert result.packets_out == 8
        assert result.flow_duration_ms == 350
        assert result.dns_query == "example.com"
        assert result.dns_rcode == "NOERROR"
        assert result.tls_ja4 == "t13d1516h2_8daaf6152771_02713d6af862"
        assert result.tls_ja4s == "t13d790900_c8dde07ea8f6_b41a1c8e0d45"
        assert result.tls_sni == "example.com"
        assert result.tls_version == "TLSv1.3"
        assert result.http_method == "GET"
        assert result.http_host == "example.com"
        assert result.http_url == "https://example.com/path?q=1"
        assert result.http_user_agent == "Mozilla/5.0"


# ---------------------------------------------------------------------------
# EARS-5: No fabrication — None fields stay None after round-trip
# ---------------------------------------------------------------------------


class TestNoFabrication:
    """EARS-5 — WHERE a source leaves fields None, the store must not fabricate values."""

    @pytest.fixture
    async def store(self, tmp_path: Path):
        s = SQLiteEventStore(tmp_path / "nofab.db")
        await s.init()
        yield s
        await s.close()

    @pytest.mark.asyncio
    async def test_none_fields_read_back_as_none(self, store: SQLiteEventStore) -> None:
        """A minimal event (only required fields) reads back with all new fields as None."""
        ev = _base_event()  # no new fields populated
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert len(events) == 1
        result = events[0]
        assert result.destination_ip is None
        assert result.bytes_in is None
        assert result.bytes_out is None
        assert result.packets_in is None
        assert result.packets_out is None
        assert result.flow_duration_ms is None
        assert result.dns_query is None
        assert result.dns_rcode is None
        assert result.tls_ja4 is None
        assert result.tls_ja4s is None
        assert result.tls_sni is None
        assert result.tls_version is None
        assert result.http_method is None
        assert result.http_host is None
        assert result.http_url is None
        assert result.http_user_agent is None

    @pytest.mark.asyncio
    async def test_partial_population_preserves_none_for_unpopulated(
        self, store: SQLiteEventStore
    ) -> None:
        """If only dns_query is set, all other new fields remain None after round-trip."""
        ev = _base_event(dns_query="dga-check.example.com")
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        result = events[0]
        assert result.dns_query == "dga-check.example.com"
        # Everything else None — store did NOT fabricate
        assert result.bytes_in is None
        assert result.tls_ja4 is None
        assert result.http_method is None
