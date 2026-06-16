"""_SchemaMixin — sole owner of the aiosqlite connection + schema/migrations.

ADR-0023 §F: ONE loop-bound write connection, ONE dedicated read connection,
ONE asyncio.Lock.  No other mixin ever opens a connection or creates a Lock.
"""
from __future__ import annotations

import asyncio
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from ._base import (
    _DEFAULT_DB,
    _KV_GLOBAL_SOURCE_TYPE,
    _KV_RULE_DESC_NAMESPACE,
    _SOURCE_KV_CAP_VALUE,
    logger,
)

# Re-export logger alias so submodules that need it don't have to re-import.
_log = logging.getLogger("firewatch.sqlite")


class _SchemaMixin:
    """Owns __init__, connections, write lock, watermark key, init(), and close().

    Every other mixin references ``self._conn()``, ``self._read_conn()``, and
    ``self._write_lock`` — all provided here.  No other class may define these.
    """

    # Class-level alias pointing at the module-level Final constant.
    # The enforcement in source_kv_put always reads the module-level Final
    # directly, so patching this class attribute has no effect on enforcement.
    SOURCE_KV_CAP: int = _SOURCE_KV_CAP_VALUE

    def __init__(self, db_path: Path = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None
        # Issue #313 Fix 2: dedicated read connection (ADR-0007 / WAL concurrency).
        # WAL mode allows readers to run concurrently with a single writer.  Without a
        # separate connection, every read query serializes behind the write connection's
        # worker thread — even when no write is in progress — because aiosqlite
        # serializes all statements on a single thread per connection.  With WAL and a
        # separate read connection, interactive reads (e.g. ai=false /detailed requests)
        # never queue behind the polling GET /threats write+commit stream.
        #
        # Ref: https://sqlite.org/wal.html §2 — "WAL allows readers and writers to run
        # concurrently without blocking each other."
        self._read_db: aiosqlite.Connection | None = None
        # Connection-wide write mutex (BLOCKING-3 fix, option b).
        #
        # aiosqlite uses a single connection object shared across coroutines.
        # When two coroutines interleave writes (e.g. save_many's executemany +
        # commit races with source_kv_put), aiosqlite's default isolation_level=''
        # keeps an implicit transaction open across await points.  If source_kv_put
        # then tries to issue BEGIN IMMEDIATE while that implicit transaction is
        # still open on the shared connection, SQLite raises:
        #   OperationalError: cannot start a transaction within a transaction
        #
        # Fix: a single asyncio.Lock that every write method acquires.  Because
        # SQLite is single-writer anyway, serialising writes within the process is
        # both correct and sufficient.  source_kv_put's cap check + INSERT are
        # atomic simply because no other writer can interleave — BEGIN IMMEDIATE
        # (and the nested-transaction crash it caused) is no longer needed.
        self._write_lock: asyncio.Lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _conn(self) -> aiosqlite.Connection:
        """Return the write connection (memoized).  All writes go through this."""
        if self._db is None:
            self._db = await aiosqlite.connect(self.db_path)
            self._db.row_factory = aiosqlite.Row
        return self._db

    async def _read_conn(self) -> aiosqlite.Connection:
        """Return the dedicated read connection (memoized).

        Issue #313 Fix 2: a separate connection from _conn() so read queries
        never serialize behind write operations.  WAL (enabled in init()) allows
        this connection to read a consistent snapshot while the write connection
        has an uncommitted transaction in flight.

        Row factory is set to aiosqlite.Row (same as the write connection) so
        callers can use dict(row) uniformly.
        """
        if self._read_db is None:
            self._read_db = await aiosqlite.connect(self.db_path)
            self._read_db.row_factory = aiosqlite.Row
        return self._read_db

    @staticmethod
    def _watermark_key(source_type: str, source_id: str) -> str:
        """Composite key for the sync_state table (ADR-0016)."""
        return f"watermark:{source_type}:{source_id}"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def init(self) -> None:
        """Create the v2 schema if it does not exist.  Idempotent."""
        db = await self._conn()

        # Issue #313 Fix 2: enable WAL journal mode and set busy_timeout on BOTH
        # connections before any DDL/DML.
        #
        # WAL (Write-Ahead Logging) allows readers and writers to run concurrently
        # without blocking each other — ref: https://sqlite.org/wal.html §2.
        # Without WAL the default journal mode requires an exclusive lock for writes,
        # forcing all reads to serialize behind every GET /threats polling write+commit.
        #
        # busy_timeout: when a reader encounters a locked page, SQLite retries for
        # up to busy_timeout milliseconds before returning SQLITE_BUSY.  5 000 ms is
        # generous (a typical write commit is <5 ms under WAL) and prevents transient
        # busy errors under real concurrent load without introducing meaningful latency.
        #
        # PRAGMA notes:
        #
        # journal_mode=WAL — DB-global once set.  Only needs to be issued on ONE
        #   connection; all subsequent connections to the same DB file automatically
        #   open in WAL mode because the WAL file exists at the filesystem level.
        #   The read connection (_read_conn) therefore inherits WAL automatically —
        #   it does NOT need a separate PRAGMA journal_mode=WAL call.
        #
        # busy_timeout — per-connection.  Must be set on every connection that will
        #   wait on a contended page.  We set it on both the write connection and the
        #   read connection so neither returns SQLITE_BUSY immediately under load.
        #
        # Both are safe to re-issue on subsequent init() calls (idempotent).
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout=5000")
        # Read connection: inherit WAL (DB-global, no separate journal_mode needed);
        # set busy_timeout per-connection so readers retry on contention.
        rdb = await self._read_conn()
        await rdb.execute("PRAGMA busy_timeout=5000")

        # Core logs table — includes source_type and source_id (ADR-0016).
        # rule_name is the human-readable signature string (issue #125).
        # ADR-0048 (ML-1): destination_ip + OCSF network-depth fields added as
        # nullable columns so existing rows/sources are unaffected.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS logs (
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
                http_user_agent  TEXT,
                file_sha256      TEXT,
                file_md5         TEXT,
                file_sha1        TEXT,
                file_name        TEXT,
                file_mime_type   TEXT,
                dns_answer       TEXT,
                tls_ja3          TEXT
            )
        """)

        # Indexes for common query patterns (ported from legacy).
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs (source_ip)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_logs_id_rule ON logs (id DESC, rule_id)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs (timestamp DESC, id DESC)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_logs_category ON logs (category)"
        )

        # Dedup index — includes source_id so two distinct named instances of
        # the same source_type can each store the same event independently
        # (ADR-0016).
        #
        # NB-1 safety invariant: only sqlite3.IntegrityError (duplicate rows
        # blocking the unique-index creation) triggers the dedup+rebuild path.
        # Unrelated errors (disk-full, lock-contention, etc.) propagate so the
        # caller can handle or surface them.  The mass DELETE must never run for
        # transient infrastructure faults.
        try:
            await db.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_logs_dedup
                ON logs (timestamp, source_ip, rule_id, action, payload_snippet, source_id)
            """)
        except sqlite3.IntegrityError:
            # Existing rows contain duplicates that block the unique index.
            # Deduplicate (keep the lowest id for each unique combination), then
            # recreate the index.
            logger.info("Deduplicating existing logs before rebuilding dedup index …")
            await db.execute("""
                DELETE FROM logs WHERE id NOT IN (
                    SELECT MIN(id) FROM logs
                    GROUP BY timestamp, source_ip, rule_id, action, payload_snippet, source_id
                )
            """)
            await db.commit()
            await db.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_logs_dedup
                ON logs (timestamp, source_ip, rule_id, action, payload_snippet, source_id)
            """)

        # NB-5 — additive migration: add rule_name column to existing logs tables.
        #
        # Databases created before issue #125 have no rule_name column.
        # SQLite does not support "ADD COLUMN IF NOT EXISTS", so we attempt the
        # ALTER and silently ignore the "duplicate column name" OperationalError
        # that fires when the column is already present (idempotent on re-init).
        try:
            await db.execute("ALTER TABLE logs ADD COLUMN rule_name TEXT")
            await db.commit()
            logger.info("NB-5: added rule_name column to logs table (issue #125)")
        except Exception as exc:  # noqa: BLE001
            # "duplicate column name: rule_name" — column already exists, no-op.
            dup = "duplicate column name"
            if dup not in str(exc).lower():
                raise

        # NB-7 — additive migration: add ADR-0048 network-depth columns to existing
        # logs tables (ML-1, issue #429).
        #
        # Databases created before ML-1 have none of these columns.
        # SQLite does not support "ADD COLUMN IF NOT EXISTS", so we attempt each ALTER
        # and silently ignore the "duplicate column name" OperationalError that fires
        # when the column is already present (idempotent on re-init, satisfies EARS-6).
        # Existing rows backfill to NULL automatically — no forced re-collection, no data
        # loss (EARS-1). destination_ip already existed on the model but was previously
        # dropped at the store boundary; this migration adds the missing DB column.
        _NB7_COLS = [
            "destination_ip   TEXT",
            "bytes_in         INTEGER",
            "bytes_out        INTEGER",
            "packets_in       INTEGER",
            "packets_out      INTEGER",
            "flow_duration_ms INTEGER",
            "dns_query        TEXT",
            "dns_rcode        TEXT",
            "tls_ja4          TEXT",
            "tls_ja4s         TEXT",
            "tls_sni          TEXT",
            "tls_version      TEXT",
            "http_method      TEXT",
            "http_host        TEXT",
            "http_url         TEXT",
            "http_user_agent  TEXT",
        ]
        for _nb7_col in _NB7_COLS:
            try:
                await db.execute(f"ALTER TABLE logs ADD COLUMN {_nb7_col}")
                await db.commit()
                logger.info(
                    "NB-7: added %r column to logs table (ADR-0048 / issue #429)",
                    _nb7_col.split()[0],
                )
            except Exception as _nb7_exc:  # noqa: BLE001
                if "duplicate column name" not in str(_nb7_exc).lower():
                    raise

        # Watermark / sync state.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS sync_state (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        # Geo enrichment cache.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS ip_geo (
                ip         TEXT PRIMARY KEY,
                country    TEXT,
                city       TEXT,
                lat        REAL,
                lon        REAL,
                updated_at TEXT
            )
        """)

        # NB-6 — additive migration: add asn/as_name columns to existing ip_geo tables.
        #
        # Databases created before issue #211 have no asn/as_name columns.
        # SQLite does not support "ADD COLUMN IF NOT EXISTS", so we attempt each ALTER
        # and silently ignore the "duplicate column name" OperationalError that fires
        # when the column is already present (idempotent on re-init).
        # Existing rows backfill to NULL automatically — no forced re-lookup.
        # Field naming follows ECS §as: asn ~ as.number, as_name ~ as.organization.name.
        # Ref: https://www.elastic.co/guide/en/ecs/current/ecs-as.html
        for _col_def in ("asn INTEGER", "as_name TEXT"):
            try:
                await db.execute(f"ALTER TABLE ip_geo ADD COLUMN {_col_def}")
                await db.commit()
                logger.info(
                    "NB-6: added %r column to ip_geo table (issue #211)", _col_def
                )
            except Exception as _exc:  # noqa: BLE001
                if "duplicate column name" not in str(_exc).lower():
                    raise

        # source_kv — generic, source-scoped auxiliary key/value store (ADR-0025 (b)).
        # Primary key is (source_type, namespace, key); value is a TEXT/JSON blob.
        # ``upsert_rule_descriptions`` / ``get_rule_descriptions`` are facades over
        # this table using source_type='_global', namespace='rule_descriptions'.
        # Security note: all DDL is core-owned; plugins never touch this table
        # directly and are scoped by source_type at the application layer.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS source_kv (
                source_type TEXT NOT NULL,
                namespace   TEXT NOT NULL,
                key         TEXT NOT NULL,
                value       TEXT NOT NULL,
                updated_at  TEXT NOT NULL,
                PRIMARY KEY (source_type, namespace, key)
            )
        """)

        # Index for efficient get_all and cap-count queries.
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_source_kv_scope"
            " ON source_kv (source_type, namespace)"
        )

        # score_history — per-IP score snapshots (issue #250).
        #
        # Records a timestamped score for each IP whenever a ThreatScore is
        # persisted by the pipeline.  The history powers two consumers:
        #   (a) ``score_delta`` on the /threats list (signed change over a
        #       configurable window; default 1h; null = "new actor").
        #   (b) ``GET /threats/{ip}/score-history`` trajectory sparkline.
        #
        # Schema design:
        #   ip   — source IP string (not a foreign-key to logs; snapshots survive
        #          log pruning so the trend is independent of raw retention).
        #   score — integer 0–100, matching ThreatScore.score.
        #   ts    — ISO-8601 UTC timestamp stored as TEXT (same convention as logs).
        #
        # Retention:
        #   SCORE_HISTORY_RETENTION_DAYS (7 days) bounds growth.  Pruning piggybacks
        #   on the score-write path via ``record_score_snapshot``, which calls
        #   ``prune_score_snapshots`` inline — no new scheduler is needed.
        #
        # Index:
        #   idx_score_history_ip_ts covers the common (ip, ts >= cutoff) range scan
        #   used by both ``get_score_history`` and ``get_bulk_score_deltas``.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS score_history (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                ip    TEXT    NOT NULL,
                score INTEGER NOT NULL,
                ts    TEXT    NOT NULL
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_score_history_ip_ts"
            " ON score_history (ip, ts DESC)"
        )

        # NB-8 — ML-10 (issue #438): flow_baseline and anomaly_verdicts tables.
        #
        # flow_baseline — rolling (src_ip, dst_ip, dst_port) first-seen / last-seen
        #   baseline keyed for the rare-flow (first-seen) detector.  Core-owned; no
        #   plugin DDL (EARS-3).  PRIMARY KEY is the triple (src_ip, dst_ip, dst_port)
        #   with dst_port stored as INTEGER (NULL when the sensor does not emit a port).
        #
        # anomaly_verdicts — stores active anomaly flags for each (src_ip, dst_ip,
        #   dst_port, anomaly_type) combination so that get_paginated can annotate rows
        #   with inline badges and support the anomaly_type FilterSpec facet (EARS-2).
        #   The anomaly_type column is an open string (not an enum) so future anomaly
        #   detectors (ML-11 volumetric exfil, etc.) extend the lane with zero schema
        #   changes by simply writing a new anomaly_type value.
        #   flag_reason carries the ADR-0035 provenance string for R3 narration (EARS-4).
        #
        # Both tables use CREATE TABLE IF NOT EXISTS (idempotent: safe on re-init).
        await db.execute("""
            CREATE TABLE IF NOT EXISTS flow_baseline (
                src_ip      TEXT    NOT NULL,
                dst_ip      TEXT    NOT NULL,
                dst_port    INTEGER,
                first_seen  TEXT    NOT NULL,
                last_seen   TEXT    NOT NULL,
                count       INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (src_ip, dst_ip, dst_port)
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_flow_baseline_src"
            " ON flow_baseline (src_ip)"
        )
        await db.execute("""
            CREATE TABLE IF NOT EXISTS anomaly_verdicts (
                src_ip       TEXT NOT NULL,
                dst_ip       TEXT NOT NULL,
                dst_port     INTEGER,
                anomaly_type TEXT NOT NULL,
                flag_reason  TEXT,
                updated_at   TEXT NOT NULL,
                PRIMARY KEY (src_ip, dst_ip, dst_port, anomaly_type)
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_anomaly_verdicts_type"
            " ON anomaly_verdicts (anomaly_type)"
        )

        await db.commit()

        # NB-9 — ML-11 (issue #439): additive Welford byte-stats columns on flow_baseline.
        #
        # Adds six nullable REAL/INTEGER columns to flow_baseline so the volumetric
        # outlier detector can persist per-flow running mean and M2 (sum of squared
        # deviations) for bytes_in and bytes_out independently.  Using separate mean/M2
        # pairs (not a combined total) allows the narration layer (R3) to report
        # directional exfil signals ("bytes_out spiked 10x") rather than just a combined
        # figure.
        #
        # Welford column layout per dimension (bytes_in / bytes_out):
        #   bytes_{dim}_mean  REAL — running mean of {dim} (Welford M_n)
        #   bytes_{dim}_m2    REAL — running sum of squared deviations (Welford M2)
        # Shared across both dimensions:
        #   bytes_count  INTEGER — number of observations accumulated so far
        #
        # Existing rows backfill to NULL automatically.  NULL means "no byte stats yet"
        # and the detector treats them as count=0 (baseline not yet warm).
        #
        # SQLite does not support "ADD COLUMN IF NOT EXISTS"; each ALTER is attempted
        # individually and the "duplicate column name" OperationalError is silently
        # suppressed (idempotent on re-init, consistent with NB-5/NB-6/NB-7/NB-8).
        _NB9_COLS = [
            "bytes_in_mean  REAL",
            "bytes_in_m2    REAL",
            "bytes_out_mean REAL",
            "bytes_out_m2   REAL",
            "bytes_count    INTEGER",
        ]
        for _nb9_col in _NB9_COLS:
            try:
                await db.execute(f"ALTER TABLE flow_baseline ADD COLUMN {_nb9_col}")
                await db.commit()
                logger.info(
                    "NB-9: added %r column to flow_baseline (ML-11 / issue #439)",
                    _nb9_col.split()[0],
                )
            except Exception as _nb9_exc:  # noqa: BLE001
                if "duplicate column name" not in str(_nb9_exc).lower():
                    raise

        # NB-10 — ADR-0055 (issue #602): additive file-IOC, DNS-answer, JA3 columns.
        #
        # Databases created before ADR-0055 have none of the file_*/dns_answer/tls_ja3
        # columns.  SQLite does not support "ADD COLUMN IF NOT EXISTS"; each ALTER is
        # attempted individually and the "duplicate column name" OperationalError is
        # silently suppressed (idempotent on re-init, satisfies EARS-5).
        # Existing rows backfill to NULL automatically — no data loss, no forced
        # re-collection.
        #
        # Field OCSF / ECS sources (ADR-0055 §Standard alignment):
        #   file_sha256  — OCSF File.hashes[].value (algorithm_id=3); ECS file.hash.sha256
        #   file_md5     — OCSF File.hashes[].value (algorithm_id=1); ECS file.hash.md5
        #   file_sha1    — OCSF File.hashes[].value (algorithm_id=2); ECS file.hash.sha1
        #   file_name    — OCSF File.name; ECS file.name
        #   file_mime_type — OCSF File.mime_type; ECS file.mime_type
        #   dns_answer   — OCSF DNS Activity answers[].rdata (comma-joined); ECS dns.answers
        #   tls_ja3      — ECS tls.client.ja3 (stock-Zeek default fingerprint)
        _NB10_COLS = [
            "file_sha256    TEXT",
            "file_md5       TEXT",
            "file_sha1      TEXT",
            "file_name      TEXT",
            "file_mime_type TEXT",
            "dns_answer     TEXT",
            "tls_ja3        TEXT",
        ]
        for _nb10_col in _NB10_COLS:
            try:
                await db.execute(f"ALTER TABLE logs ADD COLUMN {_nb10_col}")
                await db.commit()
                logger.info(
                    "NB-10: added %r column to logs table (ADR-0055 / issue #602)",
                    _nb10_col.split()[0],
                )
            except Exception as _nb10_exc:  # noqa: BLE001
                if "duplicate column name" not in str(_nb10_exc).lower():
                    raise

        # NB-4 — one-time migration of legacy rule_descriptions rows (ADR-0025).
        #
        # Deployed databases created before this change hold a populated
        # ``rule_descriptions`` table with (rule_id TEXT PRIMARY KEY, description TEXT).
        # If that table still exists, migrate its rows into ``source_kv`` under
        # (_global, rule_descriptions, rule_id, description) using INSERT-OR-IGNORE
        # (first-write-wins, idempotent on repeated init() calls).  The legacy table
        # is left in place so a rollback can still read it.
        legacy_check = await (
            await db.execute(
                "SELECT 1 FROM sqlite_master"
                " WHERE type='table' AND name='rule_descriptions'"
            )
        ).fetchone()
        if legacy_check is not None:
            now_mig = datetime.now(timezone.utc).isoformat()
            await db.execute(
                """
                INSERT OR IGNORE INTO source_kv (source_type, namespace, key, value, updated_at)
                SELECT ?, ?, rule_id, description, ?
                FROM rule_descriptions
                """,
                (_KV_GLOBAL_SOURCE_TYPE, _KV_RULE_DESC_NAMESPACE, now_mig),
            )
            await db.commit()
            logger.info(
                "NB-4: migrated legacy rule_descriptions table into source_kv"
                " (_global/rule_descriptions)"
            )

    async def close(self) -> None:
        """Release both the write and read aiosqlite connections."""
        if self._db is not None:
            await self._db.close()
            self._db = None
        # Issue #313 Fix 2: close the dedicated read connection as well.
        if self._read_db is not None:
            await self._read_db.close()
            self._read_db = None
