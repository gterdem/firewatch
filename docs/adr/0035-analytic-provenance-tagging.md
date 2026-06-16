# ADR-0035: Analytic Provenance Tagging — `RULE` / `AI` / `AI+RULE` on Every Analyst-Facing Artifact

**Date:** June 2026
**Status:** Accepted

**Context:** Maintainer's dashboard walkthrough (part 1) found the same defect in three different panes
(P2 "AI Signal", P4 "AI threat summary", P6 "Recommendations"): **rule-engine output wearing AI
clothing**. The card titled "🧠 AI threat summary" is a React template filling rule-engine fields;
"AI Signal" shows a rules-only score of 100 next to "0% confidence" because AI was disabled at
scoring time; the recommendations pane derives `block/investigate/monitor` from a block-rate
heuristic while sitting beside an "AI Recommendations" panel. Each pane was about to grow its own
ad-hoc fix. Honesty of provenance is FireWatch's main trust lever versus incumbents — it must be
ONE consistent primitive, not three local patches.

**Decision:** Every analyst-facing analytic artifact (a score, a threat level, a summary sentence,
a recommendation card, an attack-type label) carries a **derivation tag** with exactly three values:

| Wire value | Chip | Meaning |
|---|---|---|
| `rule` | `RULE` | Deterministic engine output (regex/heuristic/threshold), or UI text templated purely from deterministic fields |
| `ai` | `AI` | LLM-authored content (prose, insights, model-suggested actions) |
| `ai+rule` | `AI+RULE` | Merged result — e.g. the final score when the AI boost was actually applied on top of the rules base |

Contract points:

1. **Derivation is determined at the point of authorship, never inferred downstream.**
   - The **backend** computes and returns `score_derivation` (`"rule"` | `"ai+rule"`) on score
     payloads — a score is never pure `ai` because scoring is additive-only (rules base + optional
     AI boost; ADR-0003 / AI-engine invariants). `ai_status` alone is NOT sufficient: `ai_status ==
     "ok"` does not mean the boost fired (it requires CRITICAL/HIGH + confidence > 0.7), so the
     pipeline must report whether the boost was actually applied. Additive field; response envelope
     (ADR-0029) unchanged.
   - **UI-composed text** is tagged statically by the component that authors it: a sentence
     templated from deterministic fields is `rule`; rendering `executive_summary` / `intent` /
     `ai_insights` is `ai`. No component may guess another component's derivation.
2. **One shared `ProvenanceChip` component** in the frontend design system renders the tag.
   Panes never hand-roll provenance labels.
3. **Naming rule:** a pane/card may be titled "AI …" only if its content derivation includes `ai`.
   Otherwise it is retitled (e.g. "Threat summary") and carries a `RULE` chip.
4. **Engine status lives in ONE global spot** (app header chip: model name + status dot; click
   reveals model details). Panes do not repeat an always-on "AI active" chip; they surface state
   **only when degraded**, using the standard wording "Rules-only mode · AI engine offline".

**Alternatives considered:**
- **Per-pane ad-hoc labels** ("(rules)" suffixes, local badges) — rejected: P2/P4/P6 would each
  reinvent it; inconsistent wording is exactly the trust-killer this fixes.
- **A boolean `is_ai`** — rejected: loses the merged case. The additive score (rules base + AI
  boost) is the most common real state and must be representable honestly.
- **Infer derivation in the UI from `ai_status`** — rejected: `ai_status` is per-analysis, not
  per-artifact, and does not reveal whether the boost actually changed the score. Duplicate
  inference logic in every pane would drift.

**Reasoning:** This aligns with OCSF, which models exactly this distinction: the OCSF **`analytic`
object's `type_id`** separates `Rule` analytics from `Learning` (ML/AI) analytics on findings.
FireWatch deviates deliberately in one way: we add the merged **`ai+rule`** value because our
scoring is additive (deterministic base + bounded AI boost), which OCSF's single-analytic model
does not express — collapsing the merged case to either side would be dishonest in both directions.
Transparency about machine-generated content is also the regulatory direction of travel (NIST AI
RMF 1.0 "accountable and transparent" characteristic; EU AI Act Art. 50 transparency obligations
for AI-generated output). Incumbents (Elastic Attack Discovery, Microsoft Security Copilot) label
their AI-generated summaries but do not unify provenance across rule and AI output in one consistent
primitive — doing it cleanly is a genuine differentiator for a local-first tool that can also show
*which model, running where*.

**Out of scope (this ADR):**
- The presentation of scores/confidence themselves (bands, words, breakdown) — ADR-0036.
- The grounded-AI-summary rework (feeding LLM `executive_summary` into the dashboard, evidence
  chips, sampling enrichment) — separate gated issue; this ADR only makes today's content honest.
- Any change to score math, prompts, or the golden/prompt baselines.

**References / standards consulted:**
- OCSF (Open Cybersecurity Schema Framework) — `analytic` object, `type_id` enum distinguishing
  `Rule` vs `Learning` (ML/AI) analytics on findings.
- NIST AI RMF 1.0 — transparency/accountability characteristics for AI system outputs.
- EU AI Act, Art. 50 — transparency obligations for AI-generated content (direction of travel).
- ADR-0003 (sampling + additive-only AI), ADR-0029 (read API envelope), AI-engine-invariants skill.
- Industry: Elastic Attack Discovery and Microsoft Security Copilot label AI-generated summaries;
  neither unifies rule/AI provenance into one contract.
