"""DDL for the cases store tables (ADR-0053 D4).

Exposed as a single async function ``apply_schema(db)`` so the caller
(SqliteCaseStore.init) owns the connection lifecycle (ADR-0023 §F).

Schema design
-------------
case_files
    Primary case record: title, subject (e.g. source IP), status, disposition,
    and timestamps.  The subject column is the entity reference (IP / hostname /
    whatever the analyst is investigating) — generic, not per-source.

case_notes
    Analyst-written markdown notes linked to a case.
    author TEXT NOT NULL DEFAULT 'local operator'  — ADR-0053 D3 auth-aware seam:
        ships with 'local operator'; post-ADR-0026 the API populates a real identity
        with zero schema change.
    ai_drafted INTEGER NOT NULL DEFAULT 0  — ADR-0035 provenance: 1 = AI-drafted.
    body_md is capped at 32 KiB before INSERT (caps.py).

case_events
    References to related events / AI analyses — NOT denormalized copies (ADR-0041).
    ref_kind: 'security_event' | 'ai_analysis' (extensible TEXT).
    ref_id:   stringified ID in the referenced table.

Indexes
-------
    idx_case_files_created   — powers list_cases cursor pagination (newest first).
    idx_case_notes_case_id   — powers list_notes per-case lookup.
    idx_case_events_case_id  — powers get_timeline per-case lookup.

Security
--------
    - All user-supplied values flow through parameterised queries (``?``).
    - ON DELETE CASCADE: removing a case_file purges its notes and event-refs.
    - FOREIGN KEY enforcement must be set on the write connection (PRAGMA foreign_keys = ON).
"""
from __future__ import annotations

import aiosqlite

_CREATE_CASE_FILES = """
CREATE TABLE IF NOT EXISTS case_files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT    NOT NULL,
    subject     TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'closed')),
    disposition TEXT    NOT NULL DEFAULT 'open'
                    CHECK (disposition IN ('true-positive', 'false-positive', 'benign', 'open')),
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
)
"""

_CREATE_CASE_NOTES = """
CREATE TABLE IF NOT EXISTS case_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL
                    REFERENCES case_files(id) ON DELETE CASCADE,
    author      TEXT    NOT NULL DEFAULT 'local operator',
    body_md     TEXT    NOT NULL,
    ai_drafted  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
)
"""

_CREATE_CASE_EVENTS = """
CREATE TABLE IF NOT EXISTS case_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL
                    REFERENCES case_files(id) ON DELETE CASCADE,
    ref_kind    TEXT    NOT NULL,
    ref_id      TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
)
"""

_IDX_CASE_FILES_CREATED = (
    "CREATE INDEX IF NOT EXISTS idx_case_files_created"
    " ON case_files (created_at DESC)"
)

_IDX_CASE_NOTES_CASE_ID = (
    "CREATE INDEX IF NOT EXISTS idx_case_notes_case_id"
    " ON case_notes (case_id, created_at ASC)"
)

_IDX_CASE_EVENTS_CASE_ID = (
    "CREATE INDEX IF NOT EXISTS idx_case_events_case_id"
    " ON case_events (case_id, created_at ASC)"
)


async def apply_schema(db: aiosqlite.Connection) -> None:
    """Create case_files, case_notes, and case_events tables and indexes (idempotent).

    Must be called within a transaction context; the caller commits.
    """
    await db.execute(_CREATE_CASE_FILES)
    await db.execute(_CREATE_CASE_NOTES)
    await db.execute(_CREATE_CASE_EVENTS)
    await db.execute(_IDX_CASE_FILES_CREATED)
    await db.execute(_IDX_CASE_NOTES_CASE_ID)
    await db.execute(_IDX_CASE_EVENTS_CASE_ID)
