# ADR-0041: Evidence Chain — Recompute Factor→Events at Read Time; Never Persist Event IDs

**Date:** June 2026 (accepted 2026-06-12)
**Status:** Accepted

**Decision:** The auditable-AI evidence chain ("score 87 = rules 62 + AI 20 + correlation 5, based
on THESE events") maps each score-breakdown factor to its contributing **`logs` row ids**, and that
mapping is **recomputed at read time** from stored rows — never persisted, never read from
`matched_event_ids`/`event_id`, never backfilled. Concretely:

- **A pure builder in core** — `build_evidence_chain(rows, breakdown, detections, ai_meta)` — takes
  an actor's stored events *with their `logs` row ids*, the `build_score_breakdown()` factors, and
  correlation detections, and returns factor → contributing row ids by re-applying each factor's
  own predicate read-only (blocked/dropped rows for `brute_force`/`blocked_events`; distinct-port
  rows for `port_scan`; `SQL_PATTERNS`/`XSS_PATTERNS` matches for the payload factors — imported,
  not duplicated; correlation predicates re-run read-only for `detection_boost`).
- **`ai_boost` evidence is a reference to the stored AI analysis artifact** (with its ADR-0035
  provenance) — never a re-run of sample building or any LLM call.
- **Consistency invariant (test-pinned):** the factors and points in the evidence response are
  identical to `build_score_breakdown()`'s output for the same rows.
- **Hard boundary:** zero changes to scoring values/thresholds, `merge_score`,
  `build_score_breakdown`, prompts, sample building, or engine selection
  (`ai-engine-invariants`). The chain *explains* the score; it never participates in producing it.
- A read endpoint exposes the chain for the slide-over; its shape aligns with OCSF Detection
  Finding's `evidences` vocabulary (ADR-0040) so UI payload and export speak the same language.

**Why recompute is forced, not preferred:** gap analysis (2026-06-12, verified in code) found
`SecurityEvent.event_id` and `Detection.matched_event_ids` are **empty in production** — event ids
are never assigned or persisted, the `logs` table has no event-id column, and the `logs` row `id`
is the only stable identifier. Any persisted-id design starts with a schema migration plus a
backfill that *cannot* reconstruct historical attribution honestly.

**Alternatives considered:**
- **Assign + persist event ids; populate `matched_event_ids` going forward** — rejected: a store
  migration and a write-path change to the scoring pipeline for data that is derivable on demand;
  historical rows would still need the recompute path, so persistence buys one code path and costs
  two. Also risks drift: a persisted chain can disagree with the live breakdown after a
  rules/threshold change, which is precisely the dishonesty the auditable-AI bet must avoid.
- **Backfill `matched_event_ids` from a one-time recompute** — rejected: freezes today's predicate
  results into the store; same drift problem, plus a misleading air of "recorded at detection time."
- **Compute the chain in the API layer (SQL-side or in the route)** — rejected: the factor
  predicates live in core (`scoring.py` patterns/constants); duplicating them in the API layer
  creates two sources of truth for what a factor means. The builder lives in core, pure, importing
  the existing patterns.

**Reasoning:** Recompute-on-read makes the evidence *definitionally* consistent with the score the
analyst is looking at — both derive from the same stored rows through the same factor logic, so the
consistency invariant is testable rather than aspirational. It needs no migration, no write-path
risk to the frozen scoring engine, and works for all historical data on day one. Cost: read-time
work per drill-down — acceptable because evidence is fetched for one actor at a time on an analyst
click, against rows already loaded for the detailed view. This honest-explainability posture is the
differentiator the 2026 AI-SOC field lacks (unauditable LLM verdicts are its #1 documented
complaint — `docs/differentiation-roadmap.md` §A1); provenance and presentation rules stay governed
by ADR-0035/ADR-0036.

**Consequences:**
- MI-6 (#387) implements: SDK `FactorEvidence` DTOs, core `evidence.py` (pure, no I/O), an additive
  events-with-row-ids store query, the read endpoint (route choice recorded in ADR-0029's
  catalogue). MI-7 (#388) renders it.
- `scoring.py` is untouched; golden score tests and the prompt-regression baseline stay
  byte-identical.
- If a future store migration introduces first-class event ids for *other* reasons, the chain may
  switch keys — but the recompute-don't-persist principle stands unless superseded.
