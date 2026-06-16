"""Feedback operations for the ai_feedback table (ADR-0045 D1–D2).

Kept separate from sqlite_ledger.py so that concern boundaries are clear:
- sqlite_ledger.py owns the ai_analyses lifecycle (save, list, get_by_id, pruning).
- feedback.py owns the ai_feedback lifecycle (upsert, read, rollup).

SqliteAnalysisLedger delegates all feedback calls here, passing its write
connection and write lock so all mutations stay serialised.

Security
--------
- All SQL uses ``?`` parameterised placeholders — no interpolation.
- ``verdict`` is validated against the closed set {agree, disagree} before the
  INSERT so the DB-level CHECK constraint is a defence-in-depth second layer.
- ``reason`` is capped at REASON_CAP_CHARS (1 000) server-side before storage;
  the cap is enforced here, not at the DB column level (SQLite TEXT is always
  variable-length so a column constraint would add no enforcement value).
- ``analysis_id`` existence is verified before upsert; unknown IDs raise
  LookupError which the API layer maps to 404.  This prevents leaking internal
  DB error detail in the response body (OWASP API4:2023).
- The ``reason`` field is operator input (attacker-influenced text).  It is
  returned verbatim and must be rendered as a text node in the UI (MK-6) —
  never interpolated into HTML or prompts (ADR-0045 D3 / OWASP LLM01).

ADR-0045 D3 invariant: this module is display + eval only.
No function here is called by the pipeline, the AI engine, or the scorer.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Literal

import aiosqlite

logger = logging.getLogger("firewatch.ledger.feedback")

# Closed verdict set (ADR-0045 D1).
VALID_VERDICTS: frozenset[str] = frozenset({"agree", "disagree"})
VerdictLiteral = Literal["agree", "disagree"]

# Server-side cap for the reason field (ADR-0045 D1: ≤ 1 000 chars).
REASON_CAP_CHARS: int = 1_000


def _validate_verdict(verdict: str) -> None:
    """Raise ValueError when verdict is not in the closed set."""
    if verdict not in VALID_VERDICTS:
        raise ValueError(
            f"Invalid verdict {verdict!r}. Must be one of: "
            + ", ".join(sorted(VALID_VERDICTS))
        )


def _validate_reason(reason: str | None) -> None:
    """Raise ValueError when reason exceeds REASON_CAP_CHARS."""
    if reason is not None and len(reason) > REASON_CAP_CHARS:
        raise ValueError(
            f"reason exceeds {REASON_CAP_CHARS} character limit "
            f"(got {len(reason)} chars)"
        )


async def upsert_feedback(
    db: aiosqlite.Connection,
    read_db: aiosqlite.Connection,
    write_lock: asyncio.Lock,
    analysis_id: int,
    verdict: VerdictLiteral,
    reason: str | None,
) -> dict[str, Any]:
    """Upsert one feedback row; return the stored row dict.

    Parameters
    ----------
    db:
        Write connection (caller's ``_conn()``).
    read_db:
        Read connection for the existence check (``_read_conn()``).
    write_lock:
        The write lock serialising all mutations on the ledger.
    analysis_id:
        FK into ``ai_analyses.id``.  Raises ``LookupError`` when absent.
    verdict:
        ``"agree"`` or ``"disagree"``.  Raises ``ValueError`` for other values.
    reason:
        Optional operator note.  Raises ``ValueError`` when > 1 000 chars.

    Raises
    ------
    LookupError
        When ``analysis_id`` does not exist in ``ai_analyses``.
    ValueError
        When ``verdict`` is invalid or ``reason`` exceeds the cap.
    """
    _validate_verdict(verdict)
    _validate_reason(reason)

    # Verify the analysis exists before acquiring the write lock.
    # Uses the read connection so it does not block ongoing reads.
    cursor = await read_db.execute(
        "SELECT id FROM ai_analyses WHERE id = ?", (analysis_id,)
    )
    existing = await cursor.fetchone()
    if existing is None:
        raise LookupError(
            f"analysis {analysis_id} not found — cannot submit feedback for an "
            "unknown analysis record"
        )

    created_at_iso = datetime.now(timezone.utc).isoformat()

    async with write_lock:
        # Enable FK enforcement for this connection (per-connection in SQLite).
        await db.execute("PRAGMA foreign_keys = ON")
        # INSERT OR REPLACE upserts: if a row with the same analysis_id already
        # exists (UNIQUE constraint), SQLite deletes it and re-inserts with the
        # new values — effectively "latest wins" with an updated created_at.
        await db.execute(
            """
            INSERT OR REPLACE INTO ai_feedback
                (analysis_id, verdict, reason, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (analysis_id, verdict, reason, created_at_iso),
        )
        await db.commit()

    # Read back the stored row via the read connection (after commit).
    row_cursor = await read_db.execute(
        "SELECT id, analysis_id, verdict, reason, created_at"
        " FROM ai_feedback WHERE analysis_id = ?",
        (analysis_id,),
    )
    row = await row_cursor.fetchone()
    if row is None:  # Should never happen after a successful upsert.
        raise RuntimeError(
            f"ai_feedback row for analysis_id={analysis_id} not found after upsert"
        )
    return dict(row)


async def get_feedback_for_analysis(
    read_db: aiosqlite.Connection,
    analysis_id: int,
) -> dict[str, Any] | None:
    """Return the current feedback row for *analysis_id*, or None if absent.

    This is the single-row point-lookup used to populate the ``feedback``
    field on ``GET /ai/analyses`` list items (ADR-0045 D2 additive field).
    """
    cursor = await read_db.execute(
        "SELECT id, analysis_id, verdict, reason, created_at"
        " FROM ai_feedback WHERE analysis_id = ?",
        (analysis_id,),
    )
    row = await cursor.fetchone()
    return dict(row) if row is not None else None


async def get_feedback_summary(
    read_db: aiosqlite.Connection,
) -> dict[str, Any]:
    """Return the agreement rollup computed at read time (ADR-0045 D2 / D4).

    Returns
    -------
    dict with keys:
        graded        -- total feedback rows (= denominator)
        agreed        -- rows where verdict = 'agree'
        agreement_pct -- agreed / graded * 100, or 0.0 when graded == 0

    The honest denominator rule (ADR-0045 D4): agreement_pct is never returned
    without ``graded`` so callers can show "84% over 120 graded" not just "84%".
    """
    cursor = await read_db.execute(
        """
        SELECT
            COUNT(*)                                        AS graded,
            SUM(CASE WHEN verdict = 'agree' THEN 1 ELSE 0 END) AS agreed
        FROM ai_feedback
        """
    )
    row = await cursor.fetchone()
    # COUNT(*) always returns exactly one row; the None branch is unreachable
    # in practice but required to satisfy pyright's Optional narrowing.
    if row is None:
        return {"graded": 0, "agreed": 0, "agreement_pct": 0.0}
    graded: int = int(row[0] or 0)
    agreed: int = int(row[1] or 0)
    agreement_pct: float = (agreed / graded * 100.0) if graded > 0 else 0.0
    return {"graded": graded, "agreed": agreed, "agreement_pct": agreement_pct}
