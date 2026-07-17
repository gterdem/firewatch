"""DDL for the ``triage_decisions`` table (ADR-0072 D2).

Exposed as a single async ``apply_schema(db)`` so the caller
(``SqliteDecisionStore.init``) owns the connection lifecycle (ADR-0023 §F) —
same pattern as ``adapters/cases/schema.py``.

Schema design
-------------
triage_decisions
    Append-only: rows are never deleted or UPDATEd except to set
    ``revoked_at`` (soft-revoke, ``DELETE /decisions/{id}``). "Latest active
    actor-scoped row wins" for evaluation (``firewatch_core.triage.suppression``);
    the full history (including revoked rows) feeds the case inbox (#16).

    actor_ip      — actor identity (IP in M1; entity-kind widening is #16's).
    verb          — 'expected' | 'dismissed' | 'false_positive'.
    rule_name     — the targeted detection; NOT NULL iff verb='false_positive'
                    (CHECK below) — enforces ADR-0072 D2's identity-scoping rule
                    at the DB layer, not just in the API/Pydantic layer.
    decided_tier  — verdict tier at decision time; NULL = observed stratum
                    (the #56 re-entry input).
    decided_score — score at decision time (#49 input; NOT a re-entry trigger
                    in M1 — ADR-0072 D4).
    decided_at    — UTC ISO-8601, server-stamped (never client-supplied).
    revoked_at    — NULL = active; undo/re-decide writes a NEW row, this row's
                    revoked_at is stamped, never deleted.
    author        — ADR-0053 D3 seam: ships with 'local operator'; the M3 auth
                    ADR (#18) populates a real identity with zero schema change.
    note          — optional operator prose (capped, see caps.py).

Indexes
-------
    idx_triage_decisions_actor_revoked — powers the suppression evaluator's
        per-actor active-row lookup (``actor_ip, revoked_at``).
    idx_triage_decisions_decided_at    — powers GET /decisions cursor
        pagination (ADR-0029 D2), newest-first.

Security
--------
    - All user-supplied values flow through parameterised queries (``?``).
    - The CHECK constraint below is the DB-layer enforcement of the
      verb/rule_name pairing rule; the API layer (routes/decisions.py)
      re-validates before INSERT so a violation surfaces as a clean 422,
      not an IntegrityError leaking to the client as a 500.
"""
from __future__ import annotations

import aiosqlite

_CREATE_TRIAGE_DECISIONS = """
CREATE TABLE IF NOT EXISTS triage_decisions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_ip      TEXT    NOT NULL,
    verb          TEXT    NOT NULL CHECK (verb IN ('expected','false_positive','dismissed')),
    rule_name     TEXT,
    decided_tier  INTEGER,
    decided_score INTEGER NOT NULL,
    decided_at    TEXT    NOT NULL,
    revoked_at    TEXT,
    author        TEXT    NOT NULL DEFAULT 'local operator',
    note          TEXT,
    CHECK ((verb = 'false_positive') = (rule_name IS NOT NULL))
)
"""

_IDX_ACTOR_REVOKED = (
    "CREATE INDEX IF NOT EXISTS idx_triage_decisions_actor_revoked"
    " ON triage_decisions (actor_ip, revoked_at)"
)

_IDX_DECIDED_AT = (
    "CREATE INDEX IF NOT EXISTS idx_triage_decisions_decided_at"
    " ON triage_decisions (decided_at DESC)"
)


async def apply_schema(db: aiosqlite.Connection) -> None:
    """Create ``triage_decisions`` and its indexes (idempotent).

    Must be called within a transaction context; the caller commits.
    """
    await db.execute(_CREATE_TRIAGE_DECISIONS)
    await db.execute(_IDX_ACTOR_REVOKED)
    await db.execute(_IDX_DECIDED_AT)
