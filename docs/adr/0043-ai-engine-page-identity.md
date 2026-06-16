# ADR-0043: The `/ai` Page Becomes "AI Engine" — the Local-AI Accountability Surface

**Date:** 2026-06-12
**Status:** Accepted (architect-decided under delegated authority, 2026-06-12; Maintainer pre-approved
the rename + full pre-launch scope)

**Relates to:** ADR-0018 (product positioning — integrated open-source AI SOC platform),
ADR-0035 (provenance tagging), ADR-0036 (score/confidence presentation), ADR-0037 (entity
slide-over), ADR-0044 (verdict ledger), ADR-0045 (feedback store), ADR-0046 (stage ticker),
ADR-0047 (attestation strip).
**Source:** product-strategist report `scratch/ai-analysis-suggestions.md` (G1–G6, §1, R1–R5, §6)
plus the cited research passes (`scratch/research/ai-analysis-competitive-research.md`,
`…-innovation-research.md`).

---

## Context

The current `/ai` page is *nominally* an AI page (strategist grounding G1–G6, code-verified):

- Its headline panel ("AI-generated threat summary", 🧠 icon) is a React template over
  deterministic `/threats` fields — an ADR-0035 rule-#3 breach on the page whose identity is AI
  (`frontend/src/components/ai/AiSummaryPanel.tsx`).
- The "Generate summary" button calls nothing — it flips a boolean that reveals the Score column,
  while the templated text claims "one Local AI prompt per actor" (false on the live instance).
- The rest is a duplicate of the Dashboard threat table (`AiThreatTable.tsx`), competing with the
  primary triage surface; `AiReviewPanel.tsx` is orphaned dead code.
- Meanwhile the raw material for a genuinely distinctive page exists and is unused here:
  `score_breakdown`/`score_derivation` (ADR-0036), the MI-6 evidence chain (ADR-0041),
  `/ai/models`, the MI-9 `firewatch ai-baseline` drift CLI, and the local-first inference
  guarantees (ADR-0022/0042).

The competitive research splits the field cleanly: incumbents embed AI inline because AI is a
*feature* of their SIEM; AI-first products ship a dedicated AI dashboard because AI *is* the
product. FireWatch's positioning (ADR-0018) is the second camp — a product whose differentiation
is *auditable local AI* with no place to audit the AI is incoherent. The emerging best practice is
**inline AI for triage + a dedicated page for evidence review, audit, and governance**; FireWatch
already has the inline half (provenance chips, score breakdown, evidence chips, slide-over).

## Decision

1. **The page is repurposed, not removed.** `/ai` stops being a second triage surface and becomes
   the **local-AI accountability surface** — verdict audit, model governance, drift, coverage,
   and the model's working materials. Triage stays on the Dashboard; the 5-tab nav is unchanged
   in structure.
2. **Nav rename: "AI Analysis" → "AI Engine"** (`frontend/src/app/AppNav.tsx`), paired with an
   in-page subtitle: *"Every verdict, what the model saw, and proof nothing left this box."*
3. **Page composition (top to bottom), each block a bounded pane (no inner scrollbars):**
   1. **Zero-egress attestation strip** (ADR-0047) — the engine header.
   2. **Coverage ledger** — AI-analysed / rules-only / below-threshold facets, top-N + view-all
      (absorbs the `?filter=below-threshold` deep-link as a facet).
   3. **Verdict cards** — per persisted analysis (ADR-0044): AI prose (`AI` chip), evidence chips
      (MI-7 components, reused), model identity, `ConfidenceLabel`, agree/disagree controls
      (ADR-0045), and the prompt-transparency drawer.
   4. **Model trust panel** — verdict drift across model swaps (surfaces the MI-9 CLI output).
4. **Everything on this page obeys ADR-0035** (a pane titled "AI …" must have `ai` derivation;
   rule-templated text carries `RULE` chips) and ADR-0036 (banded scores, word confidence).
   The page renders *retrospective, validated* artifacts; nothing pre-validation appears here
   (live generation visibility belongs to the stage ticker, ADR-0046, mounted on the slide-over).

## Alternatives considered

- **Fold the content inline and drop the tab** — rejected: governance/audit/drift material has no
  inline home under the bounded-height rules; it forfeits the glass-box surface right before the
  open-source launch; and the fixed tab slot would need filling anyway (strategist §1.4).
- **Keep the page as-is and only fix the honesty defects** — rejected: post-fix the page would be
  an honest duplicate of the Dashboard (G4), which the competitive research identifies as the
  failure mode of dedicated AI pages (triage fragmentation).
- **Rename to "AI Audit"** — considered; "AI Engine" chosen: it names the *thing being shown*
  (the engine and its record), not just one activity, and matches the attestation-strip framing.

## Reasoning

- Trust in AI verdicts is the field's documented gap (Gartner: ~10% trust without explainability —
  competitive research §3); regulators demand evidence trails and transparency for AI-generated
  output (NIST AI RMF 1.0 "accountable and transparent"; EU AI Act Art. 50 transparency,
  Art. 12 record-keeping as the direction of travel).
- No cloud competitor can render this page: showing "what the model saw" admits data egress;
  verdict-only products have nothing to audit. Local-first (ADR-0022) makes it free.
- The honest one-line identity is also the launch pitch (first-impression-paramount): the page is
  the 30-second demo of "auditable local AI".

## Out of scope

- Triage features (recommendation queue, block actions) — Dashboard/ADR-0033 territory.
- The Devil's-Advocate sweep (R8) and grounded-narrative span coloring (R9) — gated post-launch
  with #213 + mandatory security review.
- Raw token streaming on real data — declined on honesty grounds (see ADR-0046).

## References

- OCSF `analytic` object (Rule vs Learning analytics) — the provenance grounding (ADR-0035).
- NIST AI RMF 1.0 (transparency/accountability); EU AI Act Art. 50 / Art. 12.
- `scratch/ai-analysis-suggestions.md` §0–§3, §6; `scratch/research/ai-analysis-competitive-research.md`
  §1/§3/§6 (inline-for-triage + dedicated audit page; Gartner trust stat).
- Internal: ADR-0018, ADR-0022, ADR-0035, ADR-0036, ADR-0041, ADR-0042; `docs/ai-claims-checklist.md`.
