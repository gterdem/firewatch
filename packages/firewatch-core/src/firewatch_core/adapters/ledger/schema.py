"""DDL for the ai_analyses table (ADR-0044 §2).

Exposed as a single async function ``apply_schema(db)`` so the caller
(SqliteAnalysisLedger.init) owns the connection lifecycle.

Schema design
-------------
- All fields match ADR-0044 §2 column list.
- ``validated_json`` and ``flags_json`` are stored as TEXT (JSON blobs).
  Storing JSON in TEXT is standard SQLite practice for structured data that
  does not need to be indexed by individual keys.
- ``prompt_text`` / ``response_text`` are TEXT with no length constraint at
  the DB level — the 64 KiB cap is enforced at write time by caps.py before
  the INSERT (defence-in-depth: no unbounded LOBs in hot paths, but SQLite
  TEXT is always variable-length so a column constraint would add no value).
- Indexes:
    idx_ai_analyses_ip_created   — powers ip-filtered list + per-IP prune
    idx_ai_analyses_created      — powers global-cap prune + cursor pagination
"""
from __future__ import annotations

import aiosqlite

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS ai_analyses (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ip                 TEXT    NOT NULL,
    kind               TEXT    NOT NULL,
    model              TEXT    NOT NULL,
    endpoint_host      TEXT    NOT NULL,
    prompt_text        TEXT    NOT NULL,
    response_text      TEXT    NOT NULL,
    validated_json     TEXT    NOT NULL,
    ai_status          TEXT    NOT NULL,
    threat_level       TEXT    NOT NULL,
    confidence         REAL    NOT NULL,
    score              INTEGER NOT NULL,
    score_derivation   TEXT    NOT NULL,
    latency_ms         REAL    NOT NULL,
    prompt_tokens      INTEGER,
    completion_tokens  INTEGER,
    schema_version     INTEGER NOT NULL,
    flags_json         TEXT    NOT NULL DEFAULT '{}',
    created_at         TEXT    NOT NULL
)
"""

_CREATE_IDX_IP_CREATED = (
    "CREATE INDEX IF NOT EXISTS idx_ai_analyses_ip_created"
    " ON ai_analyses (ip, created_at DESC)"
)

_CREATE_IDX_CREATED = (
    "CREATE INDEX IF NOT EXISTS idx_ai_analyses_created"
    " ON ai_analyses (created_at DESC)"
)

# ---------------------------------------------------------------------------
# ai_feedback table (ADR-0045 D1)
# ---------------------------------------------------------------------------

# One current analyst judgment per verdict (UNIQUE on analysis_id).
# Re-submitting upserts (INSERT OR REPLACE) — latest wins; created_at is updated.
# CASCADE DELETE: pruning an ai_analyses row removes its feedback (consistency).
# reason: operator-authored text, capped at 1 000 chars server-side (feedback.py).
# verdict: CHECK constraint is defence-in-depth; server validates before DB call.
_CREATE_FEEDBACK_TABLE = """
CREATE TABLE IF NOT EXISTS ai_feedback (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL UNIQUE
                    REFERENCES ai_analyses(id) ON DELETE CASCADE,
    verdict     TEXT    NOT NULL CHECK (verdict IN ('agree', 'disagree')),
    reason      TEXT    NULL,
    created_at  TEXT    NOT NULL
)
"""

_CREATE_IDX_FEEDBACK_ANALYSIS = (
    "CREATE INDEX IF NOT EXISTS idx_ai_feedback_analysis_id"
    " ON ai_feedback (analysis_id)"
)


async def apply_schema(db: aiosqlite.Connection) -> None:
    """Create the ai_analyses + ai_feedback tables and indexes (idempotent).

    Must be called within a transaction context; the caller commits.
    """
    await db.execute(_CREATE_TABLE)
    await db.execute(_CREATE_IDX_IP_CREATED)
    await db.execute(_CREATE_IDX_CREATED)
    # ADR-0045 D1: feedback table (additive — runs after ai_analyses is guaranteed
    # to exist so the REFERENCES constraint resolves).
    await db.execute(_CREATE_FEEDBACK_TABLE)
    await db.execute(_CREATE_IDX_FEEDBACK_ANALYSIS)
