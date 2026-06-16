"""SqliteAnalysisLedger — concrete AnalysisLedger adapter (ADR-0044).

Uses its own aiosqlite connection to the same DB file as SQLiteEventStore.
ADR-0023 §F: single event loop deployment — one async connection per role
(write / read), serialised by a write lock.

Cursor pagination (ADR-0029): opaque token is ``<created_at_iso>|<id>``
(descending order — newest first on page 1).  The token is URL-safe and
monotonically unique for a given row because (created_at, id DESC) is
the same ordering as the idx_ai_analyses_created index.

Security: all user-supplied values flow through parameterised queries
(``?`` placeholders).  No string interpolation into SQL.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import aiosqlite

from firewatch_core.adapters.ledger.caps import (
    GLOBAL_CAP_DEFAULT,
    PER_IP_CAP_DEFAULT,
    apply_field_caps,
)
from firewatch_core.adapters.ledger.feedback import (
    VerdictLiteral,
    get_feedback_for_analysis as _get_feedback_for_analysis,
    get_feedback_summary as _get_feedback_summary,
    upsert_feedback as _upsert_feedback,
)
from firewatch_core.adapters.ledger.schema import apply_schema
from firewatch_core.ports.analysis_ledger import AnalysisRecord

logger = logging.getLogger("firewatch.ledger")

# Summary columns returned by list_page (excludes prompt_text / response_text).
_SUMMARY_COLS = (
    "id", "ip", "kind", "model", "endpoint_host", "ai_status",
    "threat_level", "confidence", "score", "score_derivation",
    "latency_ms", "prompt_tokens", "completion_tokens",
    "schema_version", "flags_json", "created_at",
)
# Qualified SELECT list — all ai_analyses columns prefixed with "a." to avoid
# ambiguity with ai_feedback (which also has "id" and "created_at") in the
# LEFT JOIN used by list_page.  The resulting column names remain bare
# (SQLite strips the "a." qualifier in the result row), so downstream
# dict-key access is unchanged.
_SUMMARY_SEL_QUALIFIED = ", ".join(f"a.{c}" for c in _SUMMARY_COLS)


def _row_to_summary(row: aiosqlite.Row) -> dict[str, Any]:
    """Convert an aiosqlite Row to a summary dict (no prompt/response text).

    Also extracts the LEFT-JOINed feedback columns (fb_verdict, fb_created_at)
    and attaches them as a nested ``feedback`` field — or None when no feedback
    has been submitted for this analysis (ADR-0045 D2 / MK-6 D1).

    Security note: ``f.reason`` (operator free-text) is intentionally kept off
    the list projection (OWASP LLM01 — attacker-influenced text must not leak
    into list endpoints).  Only the detail and POST paths expose reason.
    """
    d = dict(row)
    # Expand flags_json inline so callers see flat booleans rather than a blob.
    try:
        flags = json.loads(d.pop("flags_json", "{}") or "{}")
    except (json.JSONDecodeError, TypeError):
        flags = {}
    d["prompt_truncated"] = flags.get("prompt_truncated", False)
    d["response_truncated"] = flags.get("response_truncated", False)

    # Extract LEFT-JOIN feedback columns and build the nested feedback object.
    fb_verdict = d.pop("fb_verdict", None)
    fb_created_at = d.pop("fb_created_at", None)
    d["feedback"] = (
        {"verdict": fb_verdict, "created_at": fb_created_at}
        if fb_verdict is not None
        else None
    )
    return d


def _row_to_detail(row: aiosqlite.Row) -> dict[str, Any]:
    """Convert an aiosqlite Row to a full detail dict (includes prompt/response)."""
    d = dict(row)
    try:
        raw_json = d.get("validated_json") or "{}"
        d["validated_json"] = json.loads(raw_json)
    except (json.JSONDecodeError, TypeError):
        d["validated_json"] = {}
    try:
        flags = json.loads(d.pop("flags_json", "{}") or "{}")
    except (json.JSONDecodeError, TypeError):
        flags = {}
    d["prompt_truncated"] = flags.get("prompt_truncated", False)
    d["response_truncated"] = flags.get("response_truncated", False)
    return d


def _parse_cursor(cursor: str) -> tuple[str, int] | None:
    """Parse an opaque cursor string into ``(created_at_iso, id)``.

    Returns None for malformed cursors — the caller treats it as "start
    from the beginning" (same resilience as get_paginated in sqlite_store).
    """
    try:
        sep = cursor.rfind("|")
        if sep == -1:
            return None
        ts_part = cursor[:sep]
        id_part = int(cursor[sep + 1:])
        return ts_part, id_part
    except (ValueError, TypeError):
        return None


class SqliteAnalysisLedger:
    """Concrete AnalysisLedger backed by SQLite (ADR-0044).

    Parameters
    ----------
    db_path:
        Path to the SQLite database file (shared with SQLiteEventStore).
    per_ip_cap:
        Maximum number of rows to retain per source IP.  Oldest rows are
        pruned on every save() call that would push the count over this limit.
        Default: PER_IP_CAP_DEFAULT (50).
    global_cap:
        Maximum total rows to retain across all IPs.  Oldest rows are pruned
        on every save() call that would push the global count over this limit.
        Default: GLOBAL_CAP_DEFAULT (5 000).
    """

    def __init__(
        self,
        db_path: Path,
        per_ip_cap: int = PER_IP_CAP_DEFAULT,
        global_cap: int = GLOBAL_CAP_DEFAULT,
    ) -> None:
        self.db_path = db_path
        self._per_ip_cap = per_ip_cap
        self._global_cap = global_cap
        self._db: aiosqlite.Connection | None = None
        self._read_db: aiosqlite.Connection | None = None
        self._write_lock: asyncio.Lock = asyncio.Lock()
        # Summary cache for the sync get_summary() call (attestation strip).
        # Updated after each save(); approximate — stale by at most one write.
        self._summary_cache: dict[str, Any] = {
            "analyses_count": 0,
            "last_analysis_at": None,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _conn(self) -> aiosqlite.Connection:
        """Return the write connection (memoised)."""
        if self._db is None:
            self._db = await aiosqlite.connect(self.db_path)
            self._db.row_factory = aiosqlite.Row
        return self._db

    async def _read_conn(self) -> aiosqlite.Connection:
        """Return the dedicated read connection (memoised)."""
        if self._read_db is None:
            self._read_db = await aiosqlite.connect(self.db_path)
            self._read_db.row_factory = aiosqlite.Row
        return self._read_db

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def init(self) -> None:
        """Create the ai_analyses schema and prime the summary cache (idempotent)."""
        db = await self._conn()
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout=5000")
        # FK enforcement is per-connection and OFF by default in SQLite. Set it on
        # the write connection at init so the retention-prune DELETE on ai_analyses
        # cascades to ai_feedback (MK-5, ADR-0045) even before any feedback is
        # submitted in a process lifetime — otherwise prune orphans feedback rows.
        await db.execute("PRAGMA foreign_keys = ON")
        rdb = await self._read_conn()
        await rdb.execute("PRAGMA busy_timeout=5000")
        await apply_schema(db)
        await db.commit()
        # Prime the summary cache from the existing row count (restart-safe).
        await self._refresh_summary_cache()

    async def close(self) -> None:
        """Release both aiosqlite connections."""
        if self._db is not None:
            await self._db.close()
            self._db = None
        if self._read_db is not None:
            await self._read_db.close()
            self._read_db = None

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def save(self, record: AnalysisRecord) -> None:
        """Persist one AnalysisRecord (ADR-0044).

        Applies field caps (64 KiB) via apply_field_caps(), inserts the row,
        then prunes per-IP and global caps — all within a single write lock
        acquisition so no concurrent write can interleave.

        Raises on hard storage errors; callers must catch (pipeline wraps in
        a fail-safe try/except — see pipeline._record_analysis).
        """
        # Apply field caps before storage (ADR-0044 §Security).
        (capped_prompt, capped_response), flags = apply_field_caps(
            record.prompt_text, record.response_text
        )
        flags_json = json.dumps(flags) if flags else "{}"
        validated_json_str = json.dumps(record.validated_json)
        created_at_iso = record.created_at.isoformat()

        db = await self._conn()
        async with self._write_lock:
            await db.execute(
                """
                INSERT INTO ai_analyses (
                    ip, kind, model, endpoint_host,
                    prompt_text, response_text, validated_json,
                    ai_status, threat_level, confidence,
                    score, score_derivation,
                    latency_ms, prompt_tokens, completion_tokens,
                    schema_version, flags_json, created_at
                ) VALUES (
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?,
                    ?, ?, ?,
                    ?, ?, ?
                )
                """,
                (
                    record.ip, record.kind, record.model, record.endpoint_host,
                    capped_prompt, capped_response, validated_json_str,
                    record.ai_status, record.threat_level, float(record.confidence),
                    int(record.score), record.score_derivation,
                    float(record.latency_ms), record.prompt_tokens, record.completion_tokens,
                    int(record.schema_version), flags_json, created_at_iso,
                ),
            )
            # Prune per-IP cap: delete oldest rows beyond PER_IP_CAP.
            await db.execute(
                """
                DELETE FROM ai_analyses
                WHERE ip = ?
                  AND id NOT IN (
                      SELECT id FROM ai_analyses
                      WHERE ip = ?
                      ORDER BY created_at DESC, id DESC
                      LIMIT ?
                  )
                """,
                (record.ip, record.ip, self._per_ip_cap),
            )
            # Prune global cap: delete oldest rows beyond GLOBAL_CAP.
            await db.execute(
                """
                DELETE FROM ai_analyses
                WHERE id NOT IN (
                    SELECT id FROM ai_analyses
                    ORDER BY created_at DESC, id DESC
                    LIMIT ?
                )
                """,
                (self._global_cap,),
            )
            await db.commit()

        # Update summary cache after write (outside lock — best effort).
        await self._refresh_summary_cache()

    async def _refresh_summary_cache(self) -> None:
        """Refresh the in-memory summary cache from the current DB state.

        Called after init() and after each save() so the sync get_summary()
        reflects the latest persisted count without requiring an event loop
        in the assembler's sync call context.

        Fail-safe: any DB error is swallowed; the cache retains its last value.
        """
        try:
            db = await self._read_conn()
            cursor_obj = await db.execute(
                "SELECT COUNT(*) as cnt, MAX(created_at) as last_at FROM ai_analyses"
            )
            row = await cursor_obj.fetchone()
            if row is not None:
                self._summary_cache = {
                    "analyses_count": int(row["cnt"] or 0),
                    "last_analysis_at": row["last_at"],
                }
        except Exception:
            logger.debug("ledger._refresh_summary_cache: DB read failed — cache unchanged")

    # ------------------------------------------------------------------
    # Sync summary (for attestation DTO assembler, ADR-0047)
    # ------------------------------------------------------------------

    def get_summary(self) -> dict[str, Any]:
        """Return a cached summary dict for the attestation DTO (ADR-0047).

        Returns::

            {
                "analyses_count": int,
                "last_analysis_at": str | None,   # ISO 8601 UTC string or None
            }

        This is a **synchronous** method that reads from an in-memory cache
        refreshed after each ``save()`` and at ``init()`` time.  The cache
        is at most one-write stale, which is acceptable for the display-only
        counter in the attestation strip (ADR-0047).

        The sync signature is required because ``build_attestation_dto``
        (``routes/attestation.py``) is a pure-sync assembler.

        Security: counts only — no attacker-controlled data exposed.
        """
        return dict(self._summary_cache)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def list_page(
        self,
        limit: int = 50,
        cursor: str | None = None,
        ip_filter: str | None = None,
    ) -> dict[str, Any]:
        """Return a cursor-paginated summary page (ADR-0029 envelope).

        Newest records first (descending created_at, id).

        The summary projection intentionally excludes ``prompt_text`` and
        ``response_text`` (ADR-0044 §Security / OWASP LLM05).

        Each item includes an additive ``feedback`` field populated via a
        LEFT JOIN on ``ai_feedback`` (ADR-0045 D2 / MK-6 D1).  The join is
        strictly 1:1 because ``ai_feedback.analysis_id`` is UNIQUE.
        ``feedback`` is ``None`` when no feedback has been submitted, or
        ``{"verdict": str, "created_at": str}`` otherwise.  The ``reason``
        field is deliberately excluded from the list projection (OWASP LLM01
        — operator free-text must not appear on list endpoints).

        Malformed cursors silently fall back to the first page — same
        resilience as sqlite_store.get_paginated (ADR-0029).
        """
        db = await self._read_conn()
        params: list[Any] = []
        where_clauses: list[str] = []

        # Cursor decoding: token is "<created_at_iso>|<id>"
        cursor_parsed = _parse_cursor(cursor) if cursor else None
        if cursor_parsed is not None:
            ts_part, id_part = cursor_parsed
            # Qualify with "a." — both tables have created_at and id.
            where_clauses.append(
                "(a.created_at < ? OR (a.created_at = ? AND a.id < ?))"
            )
            params.extend([ts_part, ts_part, id_part])

        if ip_filter is not None:
            where_clauses.append("a.ip = ?")
            params.append(ip_filter)

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        # Fetch limit+1 to detect has_more.
        fetch_limit = limit + 1
        params.append(fetch_limit)

        # LEFT JOIN ai_feedback (1:1 via UNIQUE analysis_id) to pre-seed the
        # feedback state without N+1 queries.  f.reason is excluded — it is
        # operator free-text that must not appear on list endpoints (OWASP LLM01).
        query = (
            f"SELECT {_SUMMARY_SEL_QUALIFIED},"
            f" f.verdict AS fb_verdict, f.created_at AS fb_created_at"
            f" FROM ai_analyses a"
            f" LEFT JOIN ai_feedback f ON f.analysis_id = a.id"
            f" {where_sql}"
            f" ORDER BY a.created_at DESC, a.id DESC"
            f" LIMIT ?"
        )

        cursor_obj = await db.execute(query, params)
        rows: list[aiosqlite.Row] = list(await cursor_obj.fetchall())

        has_more = len(rows) > limit
        page_rows = rows[:limit]
        items = [_row_to_summary(r) for r in page_rows]

        next_cursor: str | None = None
        if has_more and page_rows:
            # next_cursor reads bare "created_at" and "id" keys — these are
            # present as bare names after the "a." alias is stripped by SQLite.
            last = dict(page_rows[-1])
            next_cursor = f"{last['created_at']}|{last['id']}"

        return {
            "items": items,
            "next_cursor": next_cursor,
            "has_more": has_more,
        }

    async def get_by_id(self, row_id: int) -> dict[str, Any] | None:
        """Return the full record for *row_id*, or None if not found.

        Includes ``prompt_text`` and ``response_text`` — detail endpoint only
        (ADR-0044 §5 / OWASP LLM05: restricted to the /ai/analyses/{id} route).
        """
        db = await self._read_conn()
        cursor_obj = await db.execute(
            "SELECT * FROM ai_analyses WHERE id = ?",
            (row_id,),
        )
        row = await cursor_obj.fetchone()
        if row is None:
            return None
        return _row_to_detail(row)

    # ------------------------------------------------------------------
    # Feedback (ADR-0045) — delegate to feedback.py helpers
    # ------------------------------------------------------------------

    async def upsert_feedback(
        self,
        analysis_id: int,
        verdict: VerdictLiteral,
        reason: str | None,
    ) -> dict[str, Any]:
        """Upsert analyst feedback for an analysis record (ADR-0045 D1).

        Parameters
        ----------
        analysis_id:
            FK into ``ai_analyses.id``.  Raises ``LookupError`` when absent.
        verdict:
            ``"agree"`` or ``"disagree"``.  Raises ``ValueError`` for invalid values.
        reason:
            Optional operator note (≤ 1 000 chars).  Raises ``ValueError`` when over cap.

        Returns
        -------
        The stored feedback row as a dict with keys:
            id, analysis_id, verdict, reason, created_at.

        Raises
        ------
        LookupError
            When ``analysis_id`` does not exist.
        ValueError
            When ``verdict`` is invalid or ``reason`` exceeds 1 000 chars.
        """
        db = await self._conn()
        read_db = await self._read_conn()
        return await _upsert_feedback(
            db=db,
            read_db=read_db,
            write_lock=self._write_lock,
            analysis_id=analysis_id,
            verdict=verdict,
            reason=reason,
        )

    async def get_feedback_for_analysis(
        self,
        analysis_id: int,
    ) -> dict[str, Any] | None:
        """Return the current feedback row for *analysis_id*, or None.

        Used to populate the ``feedback`` field on ``GET /ai/analyses`` list items
        (ADR-0045 D2 additive field).
        """
        read_db = await self._read_conn()
        return await _get_feedback_for_analysis(
            read_db=read_db,
            analysis_id=analysis_id,
        )

    async def get_feedback_summary(self) -> dict[str, Any]:
        """Return the agreement rollup computed at read time (ADR-0045 D2 / D4).

        Returns
        -------
        dict with keys:
            graded        -- total feedback rows (denominator)
            agreed        -- rows where verdict = 'agree'
            agreement_pct -- agreed / graded * 100, or 0.0 when graded == 0

        Honest denominator rule (ADR-0045 D4): ``graded`` is always present so
        callers can display "84% over 120 graded" rather than a bare percentage.
        """
        read_db = await self._read_conn()
        return await _get_feedback_summary(read_db=read_db)
