# ADR-0044: AI Verdict Ledger — Persist Every Validated AI Analysis (Prompt, Output, Model, Stats)

**Date:** 2026-06-12
**Status:** Accepted (architect-decided under delegated authority, 2026-06-12)

**Relates to:** ADR-0003 (sampling, additive-only), ADR-0007 (SQLite), ADR-0022 (local `/v1`
endpoint), ADR-0025 (DB contract — core-owned canonical tables), ADR-0029 (read API; D3
attacker-controlled text), ADR-0035 (provenance), ADR-0041 (evidence recompute), ADR-0043
(AI Engine page), ADR-0045 (feedback rides this ledger).
**Implements:** the persistence foundation for R2 (verdict ledger/cards) and R3
(prompt-transparency drawer) from `scratch/ai-analysis-suggestions.md`.

---

## Context

**Grounding correction (code-verified 2026-06-12):** FireWatch persists *no* AI analysis today.
`sqlite_store.py` has `logs`, `sync_state`, `ip_geo`, `source_kv`, `score_history` — no analyses
table. `Pipeline.analyze_ip` / `analyze_ip_detailed` compute and return; the only "stored
analysis" is a client-side session cache (`frontend/src/components/entity/analysisCache.ts`,
issue #268). The strategist's R3 question — "is the sentinel-delimited sample stored with the
analysis?" — resolves to **no, because nothing is stored**. The token `usage` block returned by
the OpenAI-compatible endpoint is also discarded (`ai_openai.py:_call_endpoint` reads only
`choices[0].message.content`).

The AI Engine page (ADR-0043) is a *retrospective accountability ledger*: every verdict, what the
model saw, who authored it, how the analyst graded it. None of that is possible without a
persistent record written at analysis time.

## Decision

1. **New core-owned port + adapter: the Analysis Ledger.** A `ai_analyses` table in the same
   SQLite database (ADR-0007/0025 — core-owned canonical table; plugins never touch it), behind a
   new **`AnalysisLedger` port** with a **`SqliteAnalysisLedger` adapter in its own module**
   (`adapters/ledger/`, NOT folded into the 2000+-line `sqlite_store.py` — the #268 context-kill
   lesson and the ≤500-line decomposition rule).
2. **Record shape (one row per validated analysis):**
   - `id` (PK), `ip`, `kind` (`concise` | `detailed`), `created_at` (UTC ISO),
   - `model` (engine model id), `endpoint_host` (host:port only, never credentials),
   - `prompt_text` — the **exact** prompt sent, including the sentinel-delimited sample
     (size-capped; see Security),
   - `response_text` — the raw model content string as returned (size-capped),
   - `validated_json` — the schema-validated, known-keys-projected result (the only field the
     scoring path ever consumed),
   - `ai_status`, `threat_level`, `confidence`,
   - `score`, `score_derivation` — the merged score state at analysis time (ADR-0035/0036),
   - `latency_ms`, `prompt_tokens`, `completion_tokens` (from the endpoint's `usage` block when
     present; NULL otherwise — never fabricated),
   - `schema_version` (integer; the closed-output-schema revision).
3. **Write points: after validation, off the hot path, fail-safe.** The pipeline records a row
   when `analyze_ip` (background/concise) or `analyze_ip_detailed` completes with a
   schema-validated result. The write happens **after** `merge_score` — it can never change a
   score, a prompt, or the golden/prompt baselines. Ledger write failures are logged and
   swallowed (same fail-safe stance as `record_score_snapshot`). Fallback envelopes
   (`ai_status == "unavailable"`) are **not** persisted in this milestone.
4. **The adapter exposes call metadata additively.** `ai_openai.py` gains a way to surface
   `(prompt_text, response_text, usage, latency)` alongside the validated dict (e.g. an optional
   metadata carrier on the result) **without** touching prompts, sampling, `stream: False`, the
   qwen3 quirk, or validation order (ai-engine-invariants skill; `test_ai_prompt --compare` must
   stay green).
5. **Read API (class C, ADR-0026/0029):**
   - `GET /ai/analyses` — cursor-paginated list, **summary projection only** (no `prompt_text` /
     `response_text` in list responses), filterable by `ip`.
   - `GET /ai/analyses/{id}` — full record, including prompt/response texts, for the
     prompt-transparency drawer.
6. **Retention:** prune-on-write like `score_history`: per-IP cap (default 50) + global cap
   (default 5,000), oldest-first. Caps configurable via the runtime config (ADR-0006).

## Security

- `prompt_text` and `response_text` are **the most attacker-influenced strings in the product**
  (sampled payloads are attacker-controlled). They are: size-capped at write (prompt ≤ 64 KiB,
  response ≤ 64 KiB, truncation flagged in the row), returned only by the detail endpoint, and
  rendered **as text nodes only** in the UI (ADR-0029 D3; OWASP LLM05/insecure output handling).
- No secrets are persisted: `endpoint_host` only — never API keys or full config.
- The ledger is local data on the operator's box (ADR-0022 posture); export is out of scope.

## Alternatives considered

- **Keep computing on demand (no persistence)** — rejected: re-running the model to "show" a past
  verdict fabricates history (a different generation is a different verdict — the exact dishonesty
  ADR-0035 exists to kill) and burns the single GPU slot for display purposes.
- **Persist only a hash of the prompt** — rejected: a hash proves integrity but shows nothing;
  the drawer's entire value is *displaying* what the model saw, which local-first makes safe.
  (A cloud vendor would have to hash; we don't.)
- **Fold the tables into `SQLiteEventStore`** — rejected: the class is already the codebase's
  largest editing hazard; the ledger is a separate concern with its own lifecycle (decompose-by-
  concern rule).
- **Store in `source_kv`** — rejected: ADR-0025 scopes that to *plugin* state; the ledger is core
  analytical record-keeping with relational queries (feedback join, rollups).

## Reasoning

- Record-keeping for AI system outputs is the regulatory direction of travel: EU AI Act Art. 12
  (automatic logging/record-keeping), NIST AI RMF 1.0 MEASURE/GOVERN functions (documentation and
  traceability of AI outputs). OCSF models findings with attached `analytic` + `evidences`; our
  ledger row is the local durable analogue of a Learning-analytic finding record.
- The ledger is what makes R2 (verdict cards, agreement stats), R3 (drawer), and the future
  R5 replay twist ("re-run *your disputed verdicts* against the candidate model") possible —
  every later accountability feature hangs off this table.

## Out of scope

- Analyst feedback (ADR-0045 — separate table, FK onto this one).
- Persisting failed/fallback generations (honest-failure rows) — post-launch candidate.
- Any change to prompts, sampling, scoring math, or baselines.
- Export of ledger rows (OCSF export stays events/findings — ADR-0040).

## References

- EU AI Act Art. 12 (record-keeping); NIST AI RMF 1.0 (GOVERN/MEASURE).
- OWASP Top 10 for LLM Applications — LLM05 insecure output handling (bounded storage,
  text-node rendering); OWASP API Top 10 2023 API4 (caps on stored/returned sizes).
- OCSF — finding `analytic` / `evidences` objects (ADR-0040/0041 alignment).
- Internal: ADR-0003/0007/0022/0025/0026/0029/0035/0036/0041; ai-engine-invariants skill;
  `scratch/ai-analysis-suggestions.md` R2/R3.
