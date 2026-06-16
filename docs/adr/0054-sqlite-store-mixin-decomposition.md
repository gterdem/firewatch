# ADR-0054: Internal Decomposition of the SQLite Store via Connection-Sharing Mixins — Single-Owner Connection Preserved (ADR-0023 §F)

**Date:** June 2026
**Status:** Accepted

**Relates to:** ADR-0023 §F (loop-bound single `aiosqlite` connection — the invariant this ADR
preserves through the split), ADR-0007 (SQLite-now / WAL-deferred-to-M6 — unchanged), ADR-0025
(source-scoped KV contract + caps — code moves verbatim), ADR-0016 (watermark keying — code moves
verbatim), ADR-0024 (`legacy/` is the behavior oracle; the golden suite is the regression proof).

**Implements (issue):** #482 — *split the ~2,700-line `sqlite_store.py` into a cohesive
`adapters/sqlite/` subpackage*. The binding module-layout artifact is the architecture-spec **comment
on #482**; this ADR records the one *architecturally significant* decision in that spec — **how the
split keeps the §F single-owner-connection invariant intact** — because that is the only part of the
refactor that touches a settled correctness contract rather than mere file organization.

---

## Context

`SQLiteEventStore` (`packages/firewatch-core/src/firewatch_core/adapters/sqlite_store.py`) has grown
to ~2,740 lines spanning seven on-disk tables (`logs`, `sync_state`, `ip_geo`, `source_kv`,
`score_history`, `flow_baseline`, `anomaly_verdicts`) and roughly seven distinct concerns (schema +
migrations, event writes/row-reads, aggregate analytics reads, geo cache + watermarks, source-KV +
rule-descriptions, score-history, ML anomaly state). It is the single worst agent-context-killer in
the codebase: every backend change pays the cost of loading a 2.7k-line file, and the dense ML
anomaly region near the end of the file killed two implementation agents outright (the
`record_anomaly_verdict` / `flow_baseline` cluster). Splitting it by concern is a straightforward
application of CLAUDE.md's "one class ≈ one concern, files ≤ ~500 lines" rule.

**The one non-trivial risk is correctness, not cohesion.** ADR-0023 §F is explicit and load-bearing:
`SQLiteEventStore` holds **one loop-bound `aiosqlite` write connection** (§F cites the very line being
moved — `sqlite_store.py:204`), plus the issue-#313 dedicated read connection. The entire
`firewatch run` single-event-loop design rests on that connection being **single-owner and
loop-bound**. §F's own words: *"One loop = one connection = the entire bug class ceases to exist."*
If the split fragments connection ownership — e.g. each concern object opening its own
`aiosqlite.connect`, or two modules memoizing two different connection handles — the loop-binding
invariant breaks and `firewatch run` regresses to the `got Future attached to a different loop` bug
class §F was written to kill. **No published cross-vendor standard governs *internal store
decomposition*** (OCSF/ECS apply to the on-disk *schema*, which is **frozen** by this refactor's
EARS-2 "no DDL/query change" constraint, not to module layout), so the layout is justified on
internal-cohesion + blast-radius grounds, and the *correctness* choice below is justified directly
against ADR-0023 §F.

## Decision

**1. Decompose `SQLiteEventStore` into behavior *mixins* over a SINGLE connection-owner — not into
separate objects that each own a connection.** The concrete store is assembled by inheritance; the
shared mutable connection state lives on exactly one instance, owned by exactly one module.

```
adapters/sqlite/
  __init__.py        # public surface: re-exports SQLiteEventStore + every constant/exception
  _base.py           # constants, SourceKVCapExceededError, _row_to_security_event,
  schema.py          # _SchemaMixin  — SINGLE owner: __init__, _conn, _read_conn,
                     #                 _watermark_key, close + ALL DDL/migrations (init)
  events.py          # _EventsMixin       — logs writes + row-level reads
  analytics.py       # _AnalyticsMixin    — read-only aggregate/summary/timeline queries
  geo.py             # _GeoMixin          — ip_geo cache + watermark (sync_state) accessors
  source_kv.py       # _SourceKVMixin     — source_kv + rule_descriptions facade (ADR-0025)
  score_history.py   # _ScoreHistoryMixin — score_history snapshots/deltas/prune
  anomaly.py         # _AnomalyMixin      — flow_baseline + anomaly_verdicts (ML-10/ML-11)
  store.py           # SQLiteEventStore(...) — empty-body class composing the mixins in MRO
                     #                         order + cross-table maintenance (clear,
                     #                         delete_older_than) + SOURCE_KV_CAP class attr
```

```python
# adapters/sqlite/store.py
class SQLiteEventStore(
    _SchemaMixin,        # owns __init__, _conn, _read_conn, _watermark_key, init, close
    _EventsMixin, _AnalyticsMixin, _GeoMixin,
    _SourceKVMixin, _ScoreHistoryMixin, _AnomalyMixin,
):
    ...
```

Each concern module is a mixin (`class _EventsMixin:`) containing **only `async def` methods** that
reference `self._conn()`, `self._read_conn()`, `self._write_lock`, `self._watermark_key(...)`. Mixins
**never** define `__init__`, **never** call `aiosqlite.connect`, **never** own lifecycle.

**2. `_SchemaMixin` is the sole connection + schema owner.** It alone defines `__init__`, `_conn`,
`_read_conn`, `_watermark_key`, `close`, and all DDL/migrations (`init`). The write connection
(`self._db`), the read connection (`self._read_db`, issue #313), and `self._write_lock`
(BLOCKING-3 write mutex) are created **once, in `__init__`** — never at class scope (a class-scope
`asyncio.Lock` is shared across instances and binds to the import-time loop, which would itself be a
latent §F violation). There is therefore exactly one place in the codebase where a connection is
ever opened, which makes the §F single-owner invariant **structurally guaranteed** by the layout
rather than maintained by convention.

**3. `adapters/sqlite_store.py` becomes a thin re-export facade** (it is NOT deleted), so every
existing import path keeps working byte-for-byte:

```python
# adapters/sqlite_store.py — the entire file after the refactor
"""Back-compat re-export. Real implementation lives in adapters/sqlite/."""
from firewatch_core.adapters.sqlite import (  # noqa: F401
    SQLiteEventStore, SourceKVCapExceededError, SOURCE_KV_CAP, RULE_DESC_KV_CAP,
    SCORE_HISTORY_DELTA_WINDOW_HOURS, SCORE_HISTORY_RETENTION_DAYS, BLOCKED_ACTIONS,
)
```

This is the zero-consumer-churn path: ~30 runtime/test/TYPE_CHECKING import sites across
`packages/**` are untouched, and **the tests passing unchanged IS the EARS-2/-3 proof**. Whether new
code should prefer the new package path over the shim is a follow-up nicety, out of scope here.

**4. Behavior is preserved verbatim.** No DDL, no SQL query text, no parameter order, no result shape
changes. Every method body is a pure move; the only permitted edits are the enclosing class name and
imports of `_base` constants. The `tests/golden` oracle passes with **zero updates** — same v1 logs →
same scores — which is the regression proof (ADR-0024). The public method surface and the read-only
`SQLiteEventStore.SOURCE_KV_CAP` class attribute are byte-identical to today.

## Alternatives considered

- **Separate concern *objects*, each holding its own `aiosqlite` connection (delegation to
  sub-stores).** Rejected — this is the direct §F violation: multiple connections (or one connection
  threaded through a holder and at risk of being re-memoized) reintroduces the `got Future attached
  to a different loop` bug class. It also multiplies the lifecycle (`init`/`close`) ownership that §F
  deliberately centralized into one place.
- **A holder/coordinator object that owns the one connection, injected into each concern object.**
  Behaviorally safe for §F (single connection) but rejected on simplicity + EARS-3: it forces a
  per-method forwarding/delegation layer on the facade to keep the public surface byte-identical
  (otherwise every `store.save_many(...)` call site changes to `store.events.save_many(...)`),
  adding boilerplate and a second place a connection handle could be mis-cached, for no behavioral
  gain over mixins. Mixins give one `self`, one MRO, one connection resolution.
- **Leave the monolith as-is.** Rejected — it is the recurring agent-context-killer this issue
  exists to remove, and it violates the CLAUDE.md cohesion rule. Doing nothing de-risks nothing.
- **Split the on-disk schema too (e.g. one DB file per concern).** Out of scope and undesirable —
  it would break §F's single-connection model, ADR-0007's single-SQLite-file storage, and the
  cross-table `clear`/joins. The schema is frozen here; only the *Python module layout* changes.

## Reasoning

- **ADR-0023 §F is the binding constraint, and mixins honor it structurally.** Because only
  `_SchemaMixin` ever opens a connection or creates the write lock, "one loop = one connection"
  remains true by construction after the split — there is literally one `aiosqlite.connect` site and
  one `asyncio.Lock()` site in the package. The composition pattern is chosen *because* it makes the
  §F invariant impossible to violate accidentally, not merely unlikely.
- **ADR-0007 is untouched.** No WAL, no `busy_timeout`, no durability machinery is pulled forward;
  the refactor is behavior-preserving, so the "WAL deferred to M6/Postgres" posture stands.
- **Cohesion + blast radius (CLAUDE.md).** Seven concern modules of ≤ ~500 lines each replace one
  2.7k-line file; future backend changes load only the relevant concern, and the anomaly region that
  killed two agents becomes an isolated ~290-line file. No external schema standard governs internal
  decomposition (OCSF/ECS bind the *schema*, which is frozen), so the internal-cohesion rule is the
  correct authority for the layout, and §F is the correct authority for the connection decision.
- **EARS-2/-3 via the golden oracle (ADR-0024).** "Same v1 logs → same scores" with zero test edits
  and zero consumer-import edits is the objective, mechanical proof that the move changed nothing an
  analyst or downstream caller can observe.

## Out of scope

- Any behavior, schema, DDL, query, performance, or API change; the Postgres migration (ADR-0007 /
  M6); WAL / `busy_timeout` tuning.
- Rewriting consumer imports to the new package path (the shim covers them indefinitely; a
  deprecation of the shim, if ever, is a separate issue).
- Splitting `get_paginated` internally (it stays one method in `events.py`).

## References

- **Internal:** ADR-0023 §F (loop-bound single connection; the invariant preserved here), ADR-0007
  (SQLite-now / WAL-deferred), ADR-0025 (source-KV contract + caps), ADR-0016 (watermark keying),
  ADR-0024 (golden oracle as the behavior proof).
- **CLAUDE.md** — "Decompose by concern" (files ≤ ~500 lines, one class ≈ one concern; architect
  specifies the layout for complex components).
- **SQLite WAL semantics** — https://sqlite.org/wal.html §2 (confirms no WAL is required for the
  single-connection / single-loop model; ADR-0007 posture preserved).
- **OCSF 1.x / ECS** — apply to the on-disk *schema* (frozen by this refactor), not to internal
  Python module layout; cited to record *why* no external standard governs this decomposition.
- **Issue #482** — the binding module-layout spec (architecture-spec comment) this ADR accompanies.
