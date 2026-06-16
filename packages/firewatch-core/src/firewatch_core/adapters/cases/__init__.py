"""firewatch_core.adapters.cases — AI Case File store subpackage (ADR-0053 D4).

Mirrors the proven adapters/ledger/ layout:

  schema.py        DDL + apply_schema(db) — caller owns the loop-bound connection
                   (ADR-0023 §F).
  caps.py          Per-case note/event caps and note-body length cap.
  sqlite_cases.py  SqliteCaseStore — CRUD for case_files / case_notes / case_events.

The store shares the single loop-bound aiosqlite connection via the same
connection-holder pattern the ledger uses (ADR-0023 §F — single-owner lifecycle).
Tables are core-owned canonical tables (ADR-0025); no plugin DDL.

Auth-aware seam (ADR-0053 D3): case_notes.author defaults to 'local operator' today;
a real identity is supplied post-ADR-0026 with zero schema change.
"""
