"""SqliteDecisionStore — concrete ``triage_decisions`` adapter (ADR-0072 D2).

Connection pattern mirrors ``SqliteCaseStore`` (ADR-0023 §F / ADR-0053 D4):
- Single write connection, single read connection, both memoised.
- All writes serialised through ``_write_lock`` to prevent concurrent insert races.
- ``apply_schema`` called at ``init()``; the caller never touches the connection
  lifecycle.

Cursor pagination (ADR-0029 D2): opaque token is ``<decided_at_iso>|<id>``
(descending — newest first on page 1), same format as the cases/ledger stores.

Append-only (ADR-0072 D2): rows are never deleted or otherwise UPDATEd except
``revoke_decision`` stamping ``revoked_at`` — the soft-revoke behind
``DELETE /decisions/{id}``. ``list_decisions`` returns the FULL history
(active + revoked) — that history feeds the case inbox (#16).
``get_active_for_actor`` returns ONLY active rows — the input the pure
suppression evaluator (``firewatch_core.triage.suppression.evaluate``) consumes.

Security:
- All user values flow through parameterised queries (``?``).
- ``verb``/``rule_name`` pairing and field-length caps are validated in Python
  BEFORE any INSERT — a violation raises ``ValueError`` (routes/decisions.py
  maps this to a clean 422), never an sqlite ``IntegrityError`` surfaced as a 500.

Auth-aware seam (ADR-0053 D3):
- ``create_decision`` accepts an explicit ``author`` kwarg; when omitted it
  defaults to ``'local operator'`` (mirrors the column DEFAULT). Post-#18 the
  API layer passes the authenticated principal here — zero schema change.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

from firewatch_core.adapters.decisions.caps import (
    DEFAULT_LIMIT,
    MAX_ACTOR_IP_CHARS,
    MAX_LIMIT,
    MAX_NOTE_CHARS,
    MAX_RULE_NAME_CHARS,
    VALID_VERBS,
)
from firewatch_core.adapters.decisions.schema import apply_schema

logger = logging.getLogger("firewatch.decisions")

_DEFAULT_AUTHOR = "local operator"


def _now_iso() -> str:
    """Return current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _parse_cursor(cursor: str) -> tuple[str, int] | None:
    """Parse ``<decided_at_iso>|<id>`` cursor; return None on malformed input."""
    try:
        sep = cursor.rfind("|")
        if sep == -1:
            return None
        return cursor[:sep], int(cursor[sep + 1:])
    except (ValueError, TypeError):
        return None


def _row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
    return dict(row)


def _validate_new_decision(
    actor_ip: str,
    verb: str,
    rule_name: str | None,
    note: str | None,
) -> None:
    """Validate a candidate row BEFORE it reaches SQLite (mirrors the DB CHECK).

    Raises ``ValueError`` on any violation — callers (routes/decisions.py) map
    this to a 422, never a 500 from a surfaced ``IntegrityError``.
    """
    if verb not in VALID_VERBS:
        raise ValueError(f"Invalid verb {verb!r}. Must be one of {sorted(VALID_VERBS)}")
    is_false_positive = verb == "false_positive"
    has_rule_name = rule_name is not None and rule_name != ""
    if is_false_positive != has_rule_name:
        raise ValueError(
            "rule_name is required when verb='false_positive' and forbidden otherwise "
            f"(verb={verb!r}, rule_name={rule_name!r})."
        )
    if not actor_ip or len(actor_ip) > MAX_ACTOR_IP_CHARS:
        raise ValueError(
            f"actor_ip must be 1-{MAX_ACTOR_IP_CHARS} chars (got {len(actor_ip)})."
        )
    if rule_name is not None and len(rule_name) > MAX_RULE_NAME_CHARS:
        raise ValueError(f"rule_name exceeds {MAX_RULE_NAME_CHARS} chars.")
    if note is not None and len(note) > MAX_NOTE_CHARS:
        raise ValueError(f"note exceeds {MAX_NOTE_CHARS} chars.")


class SqliteDecisionStore:
    """Concrete ``triage_decisions`` store backed by SQLite (ADR-0072 D2).

    Parameters
    ----------
    db_path:
        Path to the SQLite database file (shared with the event/case stores
        via separate connections — ADR-0023 §F WAL mode).
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
    # Writes
    # ------------------------------------------------------------------

    async def create_decision(
        self,
        *,
        actor_ip: str,
        verb: str,
        rule_name: str | None,
        decided_tier: int | None,
        decided_score: int,
        author: str = _DEFAULT_AUTHOR,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Insert a new ``triage_decisions`` row and return the full record.

        ``decided_tier``/``decided_score`` are the SERVER-computed snapshot
        (ADR-0072 D2 "snapshot authority is the server") — callers (the route)
        must have already run the actor through the pipeline; this method
        never recomputes them.

        Raises
        ------
        ValueError
            On an invalid verb, a verb/rule_name pairing mismatch, or an
            oversized field (mirrors the DB CHECK — mapped to 422 upstream).
        """
        _validate_new_decision(actor_ip, verb, rule_name, note)
        now = _now_iso()
        db = await self._conn()
        async with self._write_lock:
            cursor = await db.execute(
                """
                INSERT INTO triage_decisions
                    (actor_ip, verb, rule_name, decided_tier, decided_score,
                     decided_at, author, note)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (actor_ip, verb, rule_name, decided_tier, decided_score, now, author, note),
            )
            await db.commit()
            row_id = cursor.lastrowid
        assert row_id is not None
        return {
            "id": int(row_id),
            "actor_ip": actor_ip,
            "verb": verb,
            "rule_name": rule_name,
            "decided_tier": decided_tier,
            "decided_score": decided_score,
            "decided_at": now,
            "revoked_at": None,
            "author": author,
            "note": note,
        }

    async def revoke_decision(self, decision_id: int) -> None:
        """Soft-revoke a decision (``DELETE /decisions/{id}``) — the row survives.

        Idempotent: revoking an already-revoked row is a no-op success (the
        audit intent — "this decision is not active" — already holds).

        Raises
        ------
        LookupError
            If ``decision_id`` does not exist at all.
        """
        db = await self._conn()
        async with self._write_lock:
            chk = await db.execute(
                "SELECT revoked_at FROM triage_decisions WHERE id = ?", (decision_id,)
            )
            row = await chk.fetchone()
            if row is None:
                raise LookupError(f"Decision {decision_id} not found.")
            if row["revoked_at"] is not None:
                return  # Already revoked — idempotent no-op.
            now = _now_iso()
            await db.execute(
                "UPDATE triage_decisions SET revoked_at = ? WHERE id = ?",
                (now, decision_id),
            )
            await db.commit()

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def list_decisions(
        self,
        limit: int = DEFAULT_LIMIT,
        cursor: str | None = None,
        actor: str | None = None,
    ) -> dict[str, Any]:
        """Return a cursor-paginated list of decisions (ADR-0029 D2 envelope).

        Newest first (``decided_at DESC, id DESC``). Returns the FULL history
        (active + revoked) — ``actor`` filters to one actor's history when
        provided; omitted, all actors are returned.

        Returns
        -------
        ``{"items": [...], "next_cursor": str | None, "has_more": bool}``
        """
        limit = min(limit, MAX_LIMIT)
        db = await self._read_conn()
        params: list[Any] = []
        where_parts: list[str] = []

        if actor is not None:
            where_parts.append("actor_ip = ?")
            params.append(actor)

        cursor_parsed = _parse_cursor(cursor) if cursor else None
        if cursor_parsed is not None:
            ts_part, id_part = cursor_parsed
            where_parts.append("(decided_at < ? OR (decided_at = ? AND id < ?))")
            params.extend([ts_part, ts_part, id_part])

        where_sql = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
        fetch_limit = limit + 1
        params.append(fetch_limit)

        rows_cursor = await db.execute(
            f"SELECT * FROM triage_decisions {where_sql}"
            " ORDER BY decided_at DESC, id DESC LIMIT ?",
            params,
        )
        rows: list[aiosqlite.Row] = list(await rows_cursor.fetchall())

        has_more = len(rows) > limit
        page_rows = rows[:limit]
        items = [_row_to_dict(r) for r in page_rows]

        next_cursor: str | None = None
        if has_more and page_rows:
            last = dict(page_rows[-1])
            next_cursor = f"{last['decided_at']}|{last['id']}"

        return {"items": items, "next_cursor": next_cursor, "has_more": has_more}

    async def get_active_for_actor(self, actor_ip: str) -> list[dict[str, Any]]:
        """Return this actor's ACTIVE (non-revoked) decision rows.

        The input the pure suppression evaluator
        (``firewatch_core.triage.suppression.evaluate``) consumes — filtered
        at the SQL layer via the ``(actor_ip, revoked_at)`` index.
        """
        db = await self._read_conn()
        rows_cursor = await db.execute(
            "SELECT * FROM triage_decisions WHERE actor_ip = ? AND revoked_at IS NULL"
            " ORDER BY decided_at ASC, id ASC",
            (actor_ip,),
        )
        return [_row_to_dict(r) for r in await rows_cursor.fetchall()]
