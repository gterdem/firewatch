"""SqliteCaseStore — concrete cases adapter (ADR-0053 D4).

Connection pattern mirrors SqliteAnalysisLedger (ADR-0023 §F):
- Single write connection, single read connection, both memoised.
- All writes serialised through _write_lock to prevent concurrent insert races.
- apply_schema called at init(); the caller never touches the connection lifecycle.

Cursor pagination (ADR-0029): opaque token is ``<created_at_iso>|<id>``
(descending — newest first on page 1), same format as the ledger.

Security:
- All user values flow through parameterised queries (``?``).
- body_md and author are capped / validated before any DB call.
- ON DELETE CASCADE on foreign keys means deleting a case_file purges notes
  and event-refs atomically (PRAGMA foreign_keys = ON set at init).

Auth-aware seam (ADR-0053 D3):
- add_note() accepts an explicit ``author`` kwarg; when omitted it defaults to
  the Python-level default ``'local operator'`` which mirrors the column DEFAULT.
  Post-ADR-0026 the API layer passes the authenticated principal here — zero
  schema change required.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

from firewatch_core.adapters.cases.caps import (
    MAX_EVENTS_PER_CASE,
    MAX_NOTE_BODY_CHARS,
    MAX_NOTES_PER_CASE,
    VALID_DISPOSITIONS,
    VALID_STATUSES,
)
from firewatch_core.adapters.cases.schema import apply_schema

logger = logging.getLogger("firewatch.cases")

_DEFAULT_AUTHOR = "local operator"
_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200


def _now_iso() -> str:
    """Return current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _parse_cursor(cursor: str) -> tuple[str, int] | None:
    """Parse ``<created_at_iso>|<id>`` cursor; return None on malformed input."""
    try:
        sep = cursor.rfind("|")
        if sep == -1:
            return None
        return cursor[:sep], int(cursor[sep + 1:])
    except (ValueError, TypeError):
        return None


def _row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
    return dict(row)


class SqliteCaseStore:
    """Concrete cases store backed by SQLite (ADR-0053 D4).

    Parameters
    ----------
    db_path:
        Path to the SQLite database file (shared with SQLiteEventStore /
        SqliteAnalysisLedger via separate connections — ADR-0023 §F WAL mode).
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None
        self._read_db: aiosqlite.Connection | None = None
        self._write_lock: asyncio.Lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Internal connection helpers
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
        """Create schema and configure the write connection (idempotent)."""
        db = await self._conn()
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout=5000")
        await db.execute("PRAGMA foreign_keys = ON")
        rdb = await self._read_conn()
        await rdb.execute("PRAGMA busy_timeout=5000")
        await apply_schema(db)
        await db.commit()

    async def close(self) -> None:
        """Release both aiosqlite connections."""
        if self._db is not None:
            await self._db.close()
            self._db = None
        if self._read_db is not None:
            await self._read_db.close()
            self._read_db = None

    # ------------------------------------------------------------------
    # Case CRUD
    # ------------------------------------------------------------------

    async def create_case(
        self,
        title: str,
        subject: str,
        status: str = "open",
        disposition: str = "open",
    ) -> int:
        """Insert a new case_file row and return its ID.

        Parameters
        ----------
        title:
            Short human-readable case title.
        subject:
            Entity under investigation (e.g. source IP, hostname).
        status:
            'open' or 'closed'.  Defaults to 'open'.
        disposition:
            'true-positive', 'false-positive', 'benign', or 'open'.
            Defaults to 'open'.

        Returns
        -------
        The ``id`` of the newly created case_file row.

        Raises
        ------
        ValueError
            If ``status`` or ``disposition`` is not a recognised value.
        """
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid status {status!r}. Must be one of {sorted(VALID_STATUSES)}")
        if disposition not in VALID_DISPOSITIONS:
            raise ValueError(
                f"Invalid disposition {disposition!r}. Must be one of {sorted(VALID_DISPOSITIONS)}"
            )
        now = _now_iso()
        db = await self._conn()
        async with self._write_lock:
            cursor = await db.execute(
                """
                INSERT INTO case_files (title, subject, status, disposition, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (title, subject, status, disposition, now, now),
            )
            await db.commit()
            row_id = cursor.lastrowid
        assert row_id is not None
        return int(row_id)

    async def get_case(self, case_id: int) -> dict[str, Any] | None:
        """Return the case_file row for *case_id*, or None if not found."""
        db = await self._read_conn()
        cursor = await db.execute(
            "SELECT * FROM case_files WHERE id = ?", (case_id,)
        )
        row = await cursor.fetchone()
        return _row_to_dict(row) if row is not None else None

    async def list_cases(
        self,
        limit: int = _DEFAULT_LIMIT,
        cursor: str | None = None,
        subject: str | None = None,
    ) -> dict[str, Any]:
        """Return a cursor-paginated list of cases (ADR-0029 envelope).

        Newest cases first (descending created_at, id).

        Parameters
        ----------
        limit:
            Maximum number of items to return (clamped to _MAX_LIMIT).
        cursor:
            Opaque pagination token from a previous response.
        subject:
            Optional equality filter on ``case_files.subject``.  When provided,
            only cases whose ``subject`` exactly matches this value are returned
            (parameterized ``WHERE subject = ?`` — no string interpolation).
            When omitted, all cases are returned (backward-compatible).

        Returns
        -------
        ``{"items": [...], "next_cursor": str | None, "has_more": bool}``
        """
        limit = min(limit, _MAX_LIMIT)
        db = await self._read_conn()
        params: list[Any] = []
        where_parts: list[str] = []

        # Subject equality filter (issue #757 — parameterized; no interpolation).
        if subject is not None:
            where_parts.append("subject = ?")
            params.append(subject)

        cursor_parsed = _parse_cursor(cursor) if cursor else None
        if cursor_parsed is not None:
            ts_part, id_part = cursor_parsed
            where_parts.append("(created_at < ? OR (created_at = ? AND id < ?))")
            params.extend([ts_part, ts_part, id_part])

        where_sql = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
        fetch_limit = limit + 1
        params.append(fetch_limit)

        rows_cursor = await db.execute(
            f"SELECT * FROM case_files {where_sql} ORDER BY created_at DESC, id DESC LIMIT ?",
            params,
        )
        rows: list[aiosqlite.Row] = list(await rows_cursor.fetchall())

        has_more = len(rows) > limit
        page_rows = rows[:limit]
        items = [_row_to_dict(r) for r in page_rows]

        next_cursor: str | None = None
        if has_more and page_rows:
            last = dict(page_rows[-1])
            next_cursor = f"{last['created_at']}|{last['id']}"

        return {"items": items, "next_cursor": next_cursor, "has_more": has_more}

    async def set_disposition(self, case_id: int, disposition: str) -> None:
        """Update the disposition of an existing case (EARS-5).

        Parameters
        ----------
        case_id:
            The case_files.id to update.
        disposition:
            One of 'true-positive', 'false-positive', 'benign', 'open'.

        Raises
        ------
        ValueError
            If ``disposition`` is not a recognised value.
        LookupError
            If ``case_id`` does not exist.
        """
        if disposition not in VALID_DISPOSITIONS:
            raise ValueError(
                f"Invalid disposition {disposition!r}. "
                f"Must be one of {sorted(VALID_DISPOSITIONS)}"
            )
        now = _now_iso()
        db = await self._conn()
        async with self._write_lock:
            cursor = await db.execute(
                "UPDATE case_files SET disposition = ?, updated_at = ? WHERE id = ?",
                (disposition, now, case_id),
            )
            await db.commit()
            if cursor.rowcount == 0:
                raise LookupError(f"Case {case_id} not found.")

    async def set_status(self, case_id: int, status: str) -> None:
        """Update the status of an existing case.

        Parameters
        ----------
        case_id:
            The case_files.id to update.
        status:
            One of 'open', 'closed'.

        Raises
        ------
        ValueError
            If ``status`` is not a recognised value.
        LookupError
            If ``case_id`` does not exist.
        """
        if status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status {status!r}. Must be one of {sorted(VALID_STATUSES)}"
            )
        now = _now_iso()
        db = await self._conn()
        async with self._write_lock:
            cursor = await db.execute(
                "UPDATE case_files SET status = ?, updated_at = ? WHERE id = ?",
                (status, now, case_id),
            )
            await db.commit()
            if cursor.rowcount == 0:
                raise LookupError(f"Case {case_id} not found.")

    # ------------------------------------------------------------------
    # Notes
    # ------------------------------------------------------------------

    async def add_note(
        self,
        case_id: int,
        body_md: str,
        author: str = _DEFAULT_AUTHOR,
        ai_drafted: bool = False,
    ) -> int:
        """Append a markdown note to a case (EARS-3 / EARS-4).

        Parameters
        ----------
        case_id:
            FK into case_files.id.
        body_md:
            Markdown body (capped at MAX_NOTE_BODY_CHARS).  Must be rendered as
            sanitized text/markdown by the UI — never raw HTML (ADR-0029 D3).
        author:
            Note author identity.  Defaults to 'local operator' (ADR-0053 D3
            auth-aware seam); post-ADR-0026 the API passes the authenticated
            principal here with zero schema change.
        ai_drafted:
            True when the body was generated by the local LLM (ADR-0035
            provenance tagging).

        Returns
        -------
        The ``id`` of the newly created case_notes row.

        Raises
        ------
        ValueError
            When ``body_md`` exceeds MAX_NOTE_BODY_CHARS or the per-case note
            count would exceed MAX_NOTES_PER_CASE.
        LookupError
            When ``case_id`` does not exist.
        """
        if len(body_md) > MAX_NOTE_BODY_CHARS:
            raise ValueError(
                f"body_md exceeds {MAX_NOTE_BODY_CHARS} chars "
                f"(got {len(body_md)})."
            )
        now = _now_iso()
        db = await self._conn()
        async with self._write_lock:
            # Guard: verify case exists.
            chk = await db.execute(
                "SELECT id FROM case_files WHERE id = ?", (case_id,)
            )
            if await chk.fetchone() is None:
                raise LookupError(f"Case {case_id} not found.")

            # Guard: enforce per-case note cap.
            cnt_cursor = await db.execute(
                "SELECT COUNT(*) FROM case_notes WHERE case_id = ?", (case_id,)
            )
            cnt_row = await cnt_cursor.fetchone()
            note_count = int(cnt_row[0]) if cnt_row else 0
            if note_count >= MAX_NOTES_PER_CASE:
                raise ValueError(
                    f"Exceeded {MAX_NOTES_PER_CASE} notes per case (case_id={case_id})."
                )

            cursor = await db.execute(
                """
                INSERT INTO case_notes (case_id, author, body_md, ai_drafted, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (case_id, author, body_md, int(ai_drafted), now, now),
            )
            await db.commit()
            row_id = cursor.lastrowid
        assert row_id is not None
        return int(row_id)

    async def list_notes(self, case_id: int) -> list[dict[str, Any]]:
        """Return all notes for a case in chronological order (oldest first).

        Security: body_md is operator text that may embed attacker-controlled
        content; callers must render it as sanitized markdown (ADR-0029 D3).
        """
        db = await self._read_conn()
        rows_cursor = await db.execute(
            "SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at ASC, id ASC",
            (case_id,),
        )
        return [_row_to_dict(r) for r in await rows_cursor.fetchall()]

    # ------------------------------------------------------------------
    # Event references (timeline links, ADR-0041 / ADR-0053 D2)
    # ------------------------------------------------------------------

    async def link_event(
        self,
        case_id: int,
        ref_kind: str,
        ref_id: str,
    ) -> int:
        """Link a security_event or ai_analysis reference to a case (EARS-2).

        Stores a reference only — no payload is copied (ADR-0041 discipline).

        Parameters
        ----------
        case_id:
            FK into case_files.id.
        ref_kind:
            Kind of reference: 'security_event' or 'ai_analysis' (extensible TEXT).
        ref_id:
            Stringified ID in the referenced table (e.g. str(event.id)).

        Returns
        -------
        The ``id`` of the newly created case_events row.

        Raises
        ------
        ValueError
            When the per-case event-reference cap would be exceeded.
        LookupError
            When ``case_id`` does not exist.
        """
        now = _now_iso()
        db = await self._conn()
        async with self._write_lock:
            # Guard: verify case exists.
            chk = await db.execute(
                "SELECT id FROM case_files WHERE id = ?", (case_id,)
            )
            if await chk.fetchone() is None:
                raise LookupError(f"Case {case_id} not found.")

            # Guard: enforce per-case event-ref cap.
            cnt_cursor = await db.execute(
                "SELECT COUNT(*) FROM case_events WHERE case_id = ?", (case_id,)
            )
            cnt_row = await cnt_cursor.fetchone()
            ev_count = int(cnt_row[0]) if cnt_row else 0
            if ev_count >= MAX_EVENTS_PER_CASE:
                raise ValueError(
                    f"Exceeded {MAX_EVENTS_PER_CASE} event refs per case (case_id={case_id})."
                )

            cursor = await db.execute(
                """
                INSERT INTO case_events (case_id, ref_kind, ref_id, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (case_id, ref_kind, ref_id, now),
            )
            await db.commit()
            row_id = cursor.lastrowid
        assert row_id is not None
        return int(row_id)

    async def get_timeline(self, case_id: int) -> dict[str, Any]:
        """Return the timeline for a case: all linked event/analysis references.

        References are assembled at read time (ADR-0041 / ADR-0053 D2) — no
        denormalized copies are stored.

        Returns
        -------
        ``{"case_id": int, "events": [{"id", "ref_kind", "ref_id", "created_at"}]}``
        """
        db = await self._read_conn()
        rows_cursor = await db.execute(
            "SELECT * FROM case_events WHERE case_id = ? ORDER BY created_at ASC, id ASC",
            (case_id,),
        )
        events = [_row_to_dict(r) for r in await rows_cursor.fetchall()]
        return {"case_id": case_id, "events": events}
