# ADR-0045: Verdict Feedback Store — Analyst Agree/Disagree as a Local, Additive Table

**Date:** 2026-06-12
**Status:** Accepted (architect-decided under delegated authority, 2026-06-12)

**Relates to:** ADR-0044 (the ledger this rides on), ADR-0026 (write routes gated when exposed),
ADR-0029 (read API envelope), ADR-0035 (provenance), ADR-0043 (AI Engine page).
**Implements:** R2b from `scratch/ai-analysis-suggestions.md` (§3 R2, §5 item 5).

---

## Context

The verdict ledger (ADR-0044) shows what the model said; the trust loop closes only when the
analyst can *grade* it and the product shows the model's measured local track record ("Analyst
agreement: 84% over 120 graded verdicts"). The competitive research found **no product that
maintains an on-device, analyst-graded accuracy record of its own AI** — cloud vendors cannot
publish their own disagreement rate. Disagreement reasons are also future fuel: a curated local
eval set for drift replay (R5 twist) and, eventually, the gated tuned-AI path (#213).

## Decision

1. **Table `ai_feedback`** (same SQLite DB, owned by the `AnalysisLedger` port/adapter family):
   - `id` (PK), `analysis_id` (FK → `ai_analyses.id`, `UNIQUE` — one current judgment per
     verdict; re-submitting **upserts**, latest wins),
   - `verdict` — TEXT, CHECK in (`agree`, `disagree`),
   - `reason` — TEXT NULL, operator-authored, ≤ 1,000 chars (server-enforced),
   - `created_at` (UTC ISO; updated on upsert).
   Deleting a ledger row cascades its feedback (retention pruning keeps the pair consistent).
2. **API:**
   - `POST /ai/analyses/{id}/feedback` `{verdict, reason?}` → upsert; 404 on unknown analysis;
     422 on invalid verdict/oversized reason. This is a **mutating route**: under ADR-0026 it is
     loopback-open by default and key-gated the moment the API is exposed (no exception carved).
   - `GET /ai/feedback/summary` → `{graded, agreed, agreement_pct}` computed at read time
     (no denormalized counters to drift).
   - Feedback state joins onto `GET /ai/analyses` list rows (additive field).
3. **Feedback is an annotation, never an input.** It does not change scores, prompts, sampling,
   or model behavior, and is never interpolated into any prompt — automated use of feedback
   (eval sets, tuning) is the gated #213-path's business, post-launch, behind its own review.
4. **Honest denominator rule:** the agreement stat always shows `agreed / graded` with the graded
   count visible ("84% over 120 graded verdicts") — never a percentage without its base
   (small-n honesty; ADR-0036's word-confidence spirit).

## Alternatives considered

- **Append-only feedback history (no upsert)** — deferred: an audit trail of changed minds is
  post-launch polish; one-current-judgment is the simplest honest model and the UNIQUE constraint
  makes the rollup unambiguous. Superseding rows can be added later additively.
- **5-point ratings / per-field grading** — rejected: binary agree/disagree with an optional
  reason matches SOC disposition practice (true/false positive) and keeps the stat legible;
  granularity can be layered on if real use demands it.
- **Segmented agreement ("weakest on port-scan actors") at launch** — deferred: requires joining
  feedback to attack-type facets with enough graded volume to be meaningful; pre-launch data
  volume would render noise. Ship count + percentage only.

## Reasoning

- Closing the human-feedback loop is the NIST AI RMF MEASURE-function expectation (mechanisms for
  tracking AI system performance with human feedback) and matches the EU AI Act's post-market
  monitoring direction (Art. 72). SOC analysts already think in true/false-positive dispositions —
  the control vocabulary is native.
- Local-only grading is the differentiator: model, verdicts, and grading on one box. The launch
  claim ("the AI that shows you its own report card") must be re-verified against the field before
  copy asserts "first" (strategist flag — non-blocking Haiku pass; `docs/ai-claims-checklist.md`).

## Out of scope

- Using feedback in prompts, tuning, or eval automation (gated #213 path).
- Multi-analyst attribution (single-analyst product today — ADR-0026's IAM deferral applies).
- Feedback on rule-derived artifacts (this grades AI verdicts only).
- Segmented/per-attack-type agreement rollups.

## References

- NIST AI RMF 1.0 — MEASURE (human feedback / performance tracking); EU AI Act Art. 72
  (post-market monitoring, direction of travel).
- OWASP API Top 10 2023 — API2/API5 (the POST is a gated mutating route under ADR-0026).
- Internal: ADR-0026, ADR-0029, ADR-0036, ADR-0044; `scratch/ai-analysis-suggestions.md` R2/R5;
  `docs/ai-claims-checklist.md`.
