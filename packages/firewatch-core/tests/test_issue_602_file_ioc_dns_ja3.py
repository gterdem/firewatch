"""Tests for issue #602 / ADR-0055 — file-IOC, DNS-answer, JA3 fields.

Mapped 1:1 to the EARS acceptance criteria.

EARS-1  WHEN a plugin emits a SecurityEvent with file-IOC/DNS-answer/JA3 fields
        set, the store SHALL persist and read them back unchanged.
        → TestStoreRoundTrip

EARS-2  WHEN a plugin leaves all new fields unset, the system SHALL behave
        exactly as before (no regression; existing goldens unchanged).
        → TestNoRegression

EARS-3  WHEN a FilterSpec carries file_sha256 or dns_answer,
        /logs/paginated SHALL filter on the matching column.
        → TestFilterSpec (get_paginated WHERE clause)

EARS-5  The migration SHALL be idempotent (re-running against an
        already-migrated DB is a no-op).
        → TestMigrationIdempotency

EARS-4 (OCSF export) is covered by test_issue_602_ocsf_file_fields.py
in the firewatch-api package (separate concern).

All IPs use RFC 5737 / RFC 1918 documentation ranges — no real/routable IPs.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite
import pytest

from firewatch_sdk import SecurityEvent
from firewatch_sdk.models import FilterSpec
from firewatch_core.adapters.sqlite_store import SQLiteEventStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = datetime(2026, 6, 14, 12, 0, 0, tzinfo=timezone.utc)

# RFC 5737 / RFC 1918 IPs only — never real/public/routable
_SRC_IP = "192.0.2.10"
_DST_IP = "198.51.100.20"

# Synthetic file hashes — not real captured values
_SHA256 = "a" * 64   # 64 hex chars = valid SHA-256 placeholder
_MD5 = "b" * 32      # 32 hex chars = valid MD5 placeholder
_SHA1 = "c" * 40     # 40 hex chars = valid SHA-1 placeholder
_FILENAME = "malware.exe"
_MIME = "application/x-dosexec"
_DNS_ANSWER = "192.0.2.100,192.0.2.101"   # comma-joined; RFC 5737 IPs
_JA3 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"   # synthetic 32-char JA3 fingerprint


def _base_event(**overrides: Any) -> SecurityEvent:
    """Minimal valid SecurityEvent using RFC 5737 IPs."""
    return SecurityEvent(
        source_type="suricata",
        source_id="test-sensor",
        source_ip=_SRC_IP,
        action="ALERT",
        timestamp=_TS,
        **overrides,
    )


def _full_ioc_event() -> SecurityEvent:
    """SecurityEvent with ALL ADR-0055 Group E/F/G fields populated."""
    return _base_event(
        destination_ip=_DST_IP,
        # Group E — file IOC (OCSF File object / ECS file.hash.*)
        file_sha256=_SHA256,
        file_md5=_MD5,
        file_sha1=_SHA1,
        file_name=_FILENAME,
        file_mime_type=_MIME,
        # Group F — DNS answer (OCSF DNS Activity answers[].rdata / ECS dns.answers)
        dns_answer=_DNS_ANSWER,
        # Group G — JA3 fingerprint (ECS tls.client.ja3)
        tls_ja3=_JA3,
    )


# ---------------------------------------------------------------------------
# EARS-2 (implicit): SecurityEvent model field defaults
# ---------------------------------------------------------------------------


class TestSecurityEventModelDefaults:
    """All new fields default to None; existing fields are unaffected."""

    def test_group_e_file_ioc_fields_default_none(self) -> None:
        """Group E: file_sha256, file_md5, file_sha1, file_name, file_mime_type default None."""
        ev = _base_event()
        assert ev.file_sha256 is None
        assert ev.file_md5 is None
        assert ev.file_sha1 is None
        assert ev.file_name is None
        assert ev.file_mime_type is None

    def test_group_f_dns_answer_field_defaults_none(self) -> None:
        """Group F: dns_answer defaults None."""
        ev = _base_event()
        assert ev.dns_answer is None

    def test_group_g_tls_ja3_field_defaults_none(self) -> None:
        """Group G: tls_ja3 defaults None."""
        ev = _base_event()
        assert ev.tls_ja3 is None

    def test_existing_fields_unchanged(self) -> None:
        """All pre-existing fields (dns_query, tls_ja4, http_method, etc.) still work."""
        ev = _base_event(
            dns_query="example.com",
            dns_rcode="NOERROR",
            tls_ja4="t13d1516h2_8daaf6152771_02713d6af862",
            http_method="GET",
        )
        assert ev.dns_query == "example.com"
        assert ev.tls_ja4 == "t13d1516h2_8daaf6152771_02713d6af862"
        assert ev.http_method == "GET"
        # new fields still None when not set
        assert ev.file_sha256 is None
        assert ev.dns_answer is None
        assert ev.tls_ja3 is None

    def test_accepts_valid_file_ioc_values(self) -> None:
        """Group E fields accept valid string values."""
        ev = _base_event(
            file_sha256=_SHA256,
            file_md5=_MD5,
            file_sha1=_SHA1,
            file_name=_FILENAME,
            file_mime_type=_MIME,
        )
        assert ev.file_sha256 == _SHA256
        assert ev.file_md5 == _MD5
        assert ev.file_sha1 == _SHA1
        assert ev.file_name == _FILENAME
        assert ev.file_mime_type == _MIME

    def test_accepts_valid_dns_answer(self) -> None:
        """Group F: dns_answer accepts a comma-joined answer string."""
        ev = _base_event(dns_answer=_DNS_ANSWER)
        assert ev.dns_answer == _DNS_ANSWER

    def test_accepts_valid_tls_ja3(self) -> None:
        """Group G: tls_ja3 accepts a JA3 fingerprint string."""
        ev = _base_event(tls_ja3=_JA3)
        assert ev.tls_ja3 == _JA3

    def test_all_new_fields_populated_at_once(self) -> None:
        """All 7 new fields can be set in one shot."""
        ev = _full_ioc_event()
        assert ev.file_sha256 == _SHA256
        assert ev.file_md5 == _MD5
        assert ev.file_sha1 == _SHA1
        assert ev.file_name == _FILENAME
        assert ev.file_mime_type == _MIME
        assert ev.dns_answer == _DNS_ANSWER
        assert ev.tls_ja3 == _JA3


# ---------------------------------------------------------------------------
# EARS-2: No regression — existing sources unaffected
# ---------------------------------------------------------------------------


class TestNoRegression:
    """EARS-2 — existing sources that don't set new fields still work unchanged."""

    def test_azure_waf_event_needs_no_changes(self) -> None:
        """Azure WAF plugin event (no new fields) still produces a valid SecurityEvent."""
        ev = SecurityEvent(
            source_type="azure_waf",
            source_id="gw-prod",
            source_ip=_SRC_IP,
            action="BLOCK",
            timestamp=_TS,
            rule_id="942100",
            category="WAF Rule",
            severity="high",
        )
        # All new fields must be None — zero fabrication
        assert ev.file_sha256 is None
        assert ev.file_md5 is None
        assert ev.file_sha1 is None
        assert ev.file_name is None
        assert ev.file_mime_type is None
        assert ev.dns_answer is None
        assert ev.tls_ja3 is None

    def test_suricata_event_needs_no_changes(self) -> None:
        """Suricata plugin event (no new fields) still produces a valid SecurityEvent."""
        ev = SecurityEvent(
            source_type="suricata",
            source_id="sensor-01",
            source_ip=_SRC_IP,
            destination_ip=_DST_IP,
            destination_port=443,
            protocol="TCP",
            action="ALERT",
            timestamp=_TS,
            rule_id="2012345",
            category="Web Attack (IDS)",
            severity="high",
        )
        assert ev.file_sha256 is None
        assert ev.dns_answer is None
        assert ev.tls_ja3 is None

    @pytest.mark.asyncio
    async def test_store_round_trip_existing_event_unchanged(self, tmp_path: Path) -> None:
        """Store round-trip: pre-existing event (no new fields) reads back identically."""
        store = SQLiteEventStore(tmp_path / "regress.db")
        await store.init()
        ev = _base_event(rule_id="1001", category="Web Attack")
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert len(events) == 1
        r = events[0]
        assert r.source_ip == _SRC_IP
        assert r.rule_id == "1001"
        # New fields absent — store must NOT fabricate
        assert r.file_sha256 is None
        assert r.file_md5 is None
        assert r.file_sha1 is None
        assert r.file_name is None
        assert r.file_mime_type is None
        assert r.dns_answer is None
        assert r.tls_ja3 is None
        await store.close()


# ---------------------------------------------------------------------------
# EARS-5: Migration idempotency
# ---------------------------------------------------------------------------


class TestMigrationIdempotency:
    """EARS-5 — additive migration adds missing columns; re-init is a no-op."""

    @pytest.mark.asyncio
    async def test_old_schema_db_gets_new_columns(self, tmp_path: Path) -> None:
        """An OLD-schema DB (no new columns) gains all ADR-0055 columns after init()."""
        db_path = tmp_path / "old_schema.db"

        # Simulate a DB created before ADR-0055 (has the ADR-0048 columns but not ADR-0055)
        async with aiosqlite.connect(str(db_path)) as db:
            await db.execute("""
                CREATE TABLE logs (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip        TEXT    NOT NULL,
                    destination_port INTEGER NOT NULL DEFAULT 0,
                    destination_ip   TEXT,
                    protocol         TEXT    NOT NULL DEFAULT '',
                    action           TEXT    NOT NULL,
                    rule_id          TEXT,
                    rule_name        TEXT,
                    payload_snippet  TEXT,
                    timestamp        TEXT    NOT NULL,
                    source_type      TEXT    NOT NULL DEFAULT 'unknown',
                    source_id        TEXT    NOT NULL DEFAULT 'default',
                    severity         TEXT,
                    category         TEXT,
                    bytes_in         INTEGER,
                    bytes_out        INTEGER,
                    packets_in       INTEGER,
                    packets_out      INTEGER,
                    flow_duration_ms INTEGER,
                    dns_query        TEXT,
                    dns_rcode        TEXT,
                    tls_ja4          TEXT,
                    tls_ja4s         TEXT,
                    tls_sni          TEXT,
                    tls_version      TEXT,
                    http_method      TEXT,
                    http_host        TEXT,
                    http_url         TEXT,
                    http_user_agent  TEXT
                )
            """)
            # Insert a pre-migration row to verify data is not lost
            await db.execute(
                "INSERT INTO logs (source_ip, action, timestamp) VALUES (?, ?, ?)",
                (_SRC_IP, "ALERT", _TS.isoformat()),
            )
            await db.commit()

        # Run init() — should add ADR-0055 columns cleanly
        store = SQLiteEventStore(db_path)
        await store.init()

        async with aiosqlite.connect(str(db_path)) as db:
            cursor = await db.execute("PRAGMA table_info(logs)")
            cols = {row[1] for row in await cursor.fetchall()}

        _expected_new_cols = {
            "file_sha256", "file_md5", "file_sha1",
            "file_name", "file_mime_type",
            "dns_answer",
            "tls_ja3",
        }
        missing = _expected_new_cols - cols
        assert not missing, f"Migration did not add columns: {missing}"

        await store.close()

    @pytest.mark.asyncio
    async def test_existing_row_preserved_after_migration(self, tmp_path: Path) -> None:
        """Pre-migration rows survive with NULL in new columns — no data loss."""
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

        events = await store.get_by_ip(_SRC_IP)
        assert len(events) == 1
        assert events[0].source_ip == _SRC_IP
        assert events[0].action == "BLOCK"
        # New ADR-0055 fields must be NULL → None (not fabricated)
        assert events[0].file_sha256 is None
        assert events[0].dns_answer is None
        assert events[0].tls_ja3 is None

        await store.close()

    @pytest.mark.asyncio
    async def test_init_twice_is_noop(self, tmp_path: Path) -> None:
        """EARS-5: calling init() on a fully-migrated DB is a no-op — no OperationalError."""
        store = SQLiteEventStore(tmp_path / "fresh.db")
        await store.init()
        # Second init must not raise "duplicate column name"
        await store.init()
        await store.close()

    @pytest.mark.asyncio
    async def test_migration_silent_on_existing_columns(self, tmp_path: Path) -> None:
        """Re-init with all columns already present silently no-ops each ALTER."""
        store = SQLiteEventStore(tmp_path / "full.db")
        await store.init()
        await store.close()

        store2 = SQLiteEventStore(tmp_path / "full.db")
        await store2.init()   # must not raise OperationalError for duplicate columns
        await store2.close()


# ---------------------------------------------------------------------------
# EARS-1: Store round-trip — persist and read back
# ---------------------------------------------------------------------------


class TestStoreRoundTrip:
    """EARS-1 — save events with new fields; read them back unchanged."""

    @pytest.fixture
    async def store(self, tmp_path: Path) -> SQLiteEventStore:  # type: ignore[misc]
        s = SQLiteEventStore(tmp_path / "rt.db")
        await s.init()
        yield s  # type: ignore[misc]
        await s.close()

    @pytest.mark.asyncio
    async def test_group_e_file_sha256_survives_round_trip(
        self, store: SQLiteEventStore
    ) -> None:
        """file_sha256 is persisted and read back as the same string."""
        ev = _base_event(file_sha256=_SHA256)
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert len(events) == 1
        assert events[0].file_sha256 == _SHA256

    @pytest.mark.asyncio
    async def test_group_e_file_md5_sha1_survive_round_trip(
        self, store: SQLiteEventStore
    ) -> None:
        """file_md5 and file_sha1 are persisted and read back correctly."""
        ev = _base_event(file_md5=_MD5, file_sha1=_SHA1)
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert events[0].file_md5 == _MD5
        assert events[0].file_sha1 == _SHA1

    @pytest.mark.asyncio
    async def test_group_e_file_name_mime_survive_round_trip(
        self, store: SQLiteEventStore
    ) -> None:
        """file_name and file_mime_type are persisted and read back correctly."""
        ev = _base_event(file_name=_FILENAME, file_mime_type=_MIME)
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert events[0].file_name == _FILENAME
        assert events[0].file_mime_type == _MIME

    @pytest.mark.asyncio
    async def test_group_f_dns_answer_survives_round_trip(
        self, store: SQLiteEventStore
    ) -> None:
        """dns_answer (comma-joined string) is persisted and read back correctly."""
        ev = _base_event(dns_answer=_DNS_ANSWER)
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert events[0].dns_answer == _DNS_ANSWER

    @pytest.mark.asyncio
    async def test_group_g_tls_ja3_survives_round_trip(
        self, store: SQLiteEventStore
    ) -> None:
        """tls_ja3 (JA3 client fingerprint) is persisted and read back correctly."""
        ev = _base_event(tls_ja3=_JA3)
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert events[0].tls_ja3 == _JA3

    @pytest.mark.asyncio
    async def test_all_new_fields_full_round_trip(
        self, store: SQLiteEventStore
    ) -> None:
        """All 7 new fields survive a single round-trip unchanged."""
        ev = _full_ioc_event()
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert len(events) == 1
        r = events[0]
        assert r.file_sha256 == _SHA256
        assert r.file_md5 == _MD5
        assert r.file_sha1 == _SHA1
        assert r.file_name == _FILENAME
        assert r.file_mime_type == _MIME
        assert r.dns_answer == _DNS_ANSWER
        assert r.tls_ja3 == _JA3

    @pytest.mark.asyncio
    async def test_none_fields_read_back_as_none(
        self, store: SQLiteEventStore
    ) -> None:
        """A minimal event (no new fields) reads back with all ADR-0055 fields as None."""
        ev = _base_event()
        await store.save_many([ev])
        events = await store.get_by_ip(_SRC_IP)
        assert len(events) == 1
        r = events[0]
        assert r.file_sha256 is None
        assert r.file_md5 is None
        assert r.file_sha1 is None
        assert r.file_name is None
        assert r.file_mime_type is None
        assert r.dns_answer is None
        assert r.tls_ja3 is None

    @pytest.mark.asyncio
    async def test_paginated_row_contains_new_fields(
        self, store: SQLiteEventStore
    ) -> None:
        """get_paginated returns rows that contain the new ADR-0055 fields."""
        ev = _full_ioc_event()
        await store.save_many([ev])
        result = await store.get_paginated()
        assert result["total_matching"] == 1
        row = result["logs"][0]
        assert row.get("file_sha256") == _SHA256
        assert row.get("file_md5") == _MD5
        assert row.get("file_sha1") == _SHA1
        assert row.get("file_name") == _FILENAME
        assert row.get("file_mime_type") == _MIME
        assert row.get("dns_answer") == _DNS_ANSWER
        assert row.get("tls_ja3") == _JA3


# ---------------------------------------------------------------------------
# EARS-3: FilterSpec — file_sha256 and dns_answer WHERE clause
# ---------------------------------------------------------------------------


class TestFilterSpec:
    """EARS-3 — file_sha256 and dns_answer filters back WHERE clauses in get_paginated."""

    @pytest.fixture
    async def store(self, tmp_path: Path) -> SQLiteEventStore:  # type: ignore[misc]
        s = SQLiteEventStore(tmp_path / "filter.db")
        await s.init()
        yield s  # type: ignore[misc]
        await s.close()

    def _ev(
        self,
        *,
        file_sha256: str | None = None,
        dns_answer: str | None = None,
        ts_offset_sec: int = 0,
    ) -> SecurityEvent:
        ts = datetime(2026, 6, 14, 12, 0, ts_offset_sec % 60, tzinfo=timezone.utc)
        return SecurityEvent(
            source_type="suricata",
            source_id="sensor",
            source_ip=_SRC_IP,
            action="ALERT",
            timestamp=ts,
            file_sha256=file_sha256,
            dns_answer=dns_answer,
        )

    # ---- file_sha256 filter ----

    @pytest.mark.asyncio
    async def test_filter_by_file_sha256_returns_matching_rows(
        self, store: SQLiteEventStore
    ) -> None:
        """file_sha256 filter returns only rows with that hash (exact match)."""
        sha_a = "a" * 64
        sha_b = "b" * 64
        await store.save_many([
            self._ev(file_sha256=sha_a, ts_offset_sec=0),
            self._ev(file_sha256=sha_b, ts_offset_sec=1),
            self._ev(file_sha256=None, ts_offset_sec=2),
        ])
        result = await store.get_paginated(filters=FilterSpec(file_sha256=sha_a))
        assert result["total_matching"] == 1
        assert result["logs"][0]["file_sha256"] == sha_a

    @pytest.mark.asyncio
    async def test_filter_by_file_sha256_no_match_returns_empty(
        self, store: SQLiteEventStore
    ) -> None:
        """A file_sha256 filter with no matching rows returns empty."""
        await store.save_many([self._ev(file_sha256=_SHA256, ts_offset_sec=0)])
        result = await store.get_paginated(
            filters=FilterSpec(file_sha256="0" * 64)
        )
        assert result["total_matching"] == 0
        assert result["logs"] == []

    @pytest.mark.asyncio
    async def test_filter_by_file_sha256_excludes_null_rows(
        self, store: SQLiteEventStore
    ) -> None:
        """Rows with NULL file_sha256 are excluded when a hash filter is active."""
        await store.save_many([
            self._ev(file_sha256=None, ts_offset_sec=0),
            self._ev(file_sha256=_SHA256, ts_offset_sec=1),
        ])
        result = await store.get_paginated(filters=FilterSpec(file_sha256=_SHA256))
        assert result["total_matching"] == 1

    @pytest.mark.asyncio
    async def test_filter_sha256_sql_injection_safe(
        self, store: SQLiteEventStore
    ) -> None:
        """A file_sha256 filter value with SQL metacharacters is treated as literal."""
        await store.save_many([self._ev(file_sha256=_SHA256, ts_offset_sec=0)])
        result = await store.get_paginated(
            filters=FilterSpec(file_sha256="'; DROP TABLE logs; --")
        )
        assert result["total_matching"] == 0

    # ---- dns_answer filter ----

    @pytest.mark.asyncio
    async def test_filter_by_dns_answer_returns_matching_rows(
        self, store: SQLiteEventStore
    ) -> None:
        """dns_answer filter returns only rows with that answer value (exact match)."""
        ans_a = "192.0.2.100,192.0.2.101"
        ans_b = "198.51.100.1"
        await store.save_many([
            self._ev(dns_answer=ans_a, ts_offset_sec=0),
            self._ev(dns_answer=ans_b, ts_offset_sec=1),
            self._ev(dns_answer=None, ts_offset_sec=2),
        ])
        result = await store.get_paginated(filters=FilterSpec(dns_answer=ans_a))
        assert result["total_matching"] == 1
        assert result["logs"][0]["dns_answer"] == ans_a

    @pytest.mark.asyncio
    async def test_filter_by_dns_answer_no_match_returns_empty(
        self, store: SQLiteEventStore
    ) -> None:
        """A dns_answer filter with no matching rows returns empty."""
        await store.save_many([self._ev(dns_answer=_DNS_ANSWER, ts_offset_sec=0)])
        result = await store.get_paginated(
            filters=FilterSpec(dns_answer="203.0.113.1")
        )
        assert result["total_matching"] == 0
        assert result["logs"] == []

    @pytest.mark.asyncio
    async def test_filter_dns_answer_excludes_null_rows(
        self, store: SQLiteEventStore
    ) -> None:
        """Rows with NULL dns_answer are excluded when a dns_answer filter is active."""
        await store.save_many([
            self._ev(dns_answer=None, ts_offset_sec=0),
            self._ev(dns_answer=_DNS_ANSWER, ts_offset_sec=1),
        ])
        result = await store.get_paginated(filters=FilterSpec(dns_answer=_DNS_ANSWER))
        assert result["total_matching"] == 1

    @pytest.mark.asyncio
    async def test_filter_dns_answer_sql_injection_safe(
        self, store: SQLiteEventStore
    ) -> None:
        """A dns_answer filter value with SQL metacharacters is treated as literal."""
        await store.save_many([self._ev(dns_answer=_DNS_ANSWER, ts_offset_sec=0)])
        result = await store.get_paginated(
            filters=FilterSpec(dns_answer="'; DROP TABLE logs; --")
        )
        assert result["total_matching"] == 0

    @pytest.mark.asyncio
    async def test_filters_combine_additively(
        self, store: SQLiteEventStore
    ) -> None:
        """file_sha256 filter combines additively with source_ip filter."""
        src_a = "192.0.2.10"
        src_b = "192.0.2.20"
        sha = "a" * 64
        await store.save_many([
            SecurityEvent(
                source_type="suricata", source_id="s", source_ip=src_a,
                action="ALERT", timestamp=_TS, file_sha256=sha,
            ),
            SecurityEvent(
                source_type="suricata", source_id="s", source_ip=src_b,
                action="ALERT",
                timestamp=datetime(2026, 6, 14, 12, 0, 1, tzinfo=timezone.utc),
                file_sha256=sha,
            ),
        ])
        result = await store.get_paginated(
            filters=FilterSpec(ip=src_a, file_sha256=sha)
        )
        assert result["total_matching"] == 1
        assert result["logs"][0]["source_ip"] == src_a

    # ---- FilterSpec model ----

    def test_filter_spec_has_file_sha256_field(self) -> None:
        """FilterSpec accepts file_sha256 kwarg (field exists in model)."""
        f = FilterSpec(file_sha256=_SHA256)
        assert f.file_sha256 == _SHA256

    def test_filter_spec_has_dns_answer_field(self) -> None:
        """FilterSpec accepts dns_answer kwarg (field exists in model)."""
        f = FilterSpec(dns_answer=_DNS_ANSWER)
        assert f.dns_answer == _DNS_ANSWER

    def test_filter_spec_new_fields_default_none(self) -> None:
        """FilterSpec new fields default to None (no filter when absent)."""
        f = FilterSpec()
        assert f.file_sha256 is None
        assert f.dns_answer is None
