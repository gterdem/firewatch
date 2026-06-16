"""firewatch_core.adapters.ledger — AI verdict ledger adapter subpackage.

Modules
-------
schema.py       DDL + migration-on-init for the ai_analyses table.
caps.py         Field-size caps (64 KiB) and prune-count constants.
sqlite_ledger.py  SqliteAnalysisLedger — the concrete AnalysisLedger adapter.

The adapter uses its own aiosqlite connection to the same DB file as
SQLiteEventStore (ADR-0023 §F — single event loop; ADR-0025 — core-owned
canonical tables).  It is deliberately NOT folded into sqlite_store.py
(decompose-by-concern rule; ADR-0044 decision §1).
"""
