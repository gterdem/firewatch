# ADR-007: Storage — SQLite Now, PostgreSQL Later (M6)

**Date:** April 2026
**Status:** Accepted

**Decision:** SQLite for current version. PostgreSQL migration planned for M6. Elasticsearch considered for v3.0.

**Reasoning:** SQLite handles 50K+ events with zero config. The migration is clean — one class (`SQLiteEventStore`) to replace. PostgreSQL adds concurrent writes, JSONB for flexible fields, and `tsvector` for full-text search. Elasticsearch is only justified when sub-second search across millions of events is needed.
