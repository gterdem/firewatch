# ADR-0036: Score & Confidence Presentation Contract — Banded Labels, Word Confidence, Exposed Contributions

**Date:** June 2026
**Status:** Accepted

**Context:** Walkthrough P2: the dashboard showed `192.0.2.23 100 conf 0%` — a naked score next
to a naked percentage. "100" is the 0–100 risk score; "0%" is AI confidence, genuinely zero because
AI was disabled at scoring time. To a glancing eye it reads "100% sure" when the truth is "rules say
100, AI had no say". Two further problems: the frontend has **drifted severity bands** (AiSidebar
colors at ≥70/≥40 while the engine's canonical bands are 76/51/26), and nothing in the product can
answer "*why* is this 100?" because the scoring layer never exposes its contributing factors.

**Decision:** Three presentation rules, one backend exposure:

1. **Never naked numbers — scores always carry their band label.** The canonical severity bands are
   the engine's (`merge_score`): CRITICAL ≥ 76, HIGH 51–75, MEDIUM 26–50, LOW < 26. The UI renders
   score + level together (e.g. `Risk 100 · CRITICAL` badge) via one shared `ScoreBadge` DS
   component and **must not re-derive its own bands** (the ≥70/≥40 drift in `AiSidebar.scoreColor`
   is a defect under this contract). The backend `threat_level` field is the single source of truth;
   color tokens map from the level, not from local thresholds.
2. **Confidence is a word, never a percent.** An uncalibrated local LLM's 0–1 confidence is fake
   precision as a percentage. Mapping: no AI ran → `n/a (AI off)`; otherwise High ≥ 0.7,
   Medium 0.4–0.69, Low < 0.4. The 0.7 cut is deliberately the same threshold `merge_score` uses to
   gate the AI boost — "High" in the UI means exactly "confident enough to move the score". One
   shared `ConfidenceLabel` DS component.
3. **"Why this score" must be answerable.** The score badge offers a breakdown (popover) listing the
   top contributing factors — e.g. `brute_force +30 · 150 blocked events +150→cap · AI boost +20`.
4. **Backend exposure — `score_breakdown` (additive).** The scoring layer exposes its contributions
   instead of the UI guessing: each factor as `{factor, label, points}` covering the rule heuristics
   (brute_force +30, port_scan +25, sql_injection +40, xss +35), the per-blocked-event component,
   the capped detection boost, the AI boost (with the 100 cap noted). **The score math does not
   change** — contributions are computed from the same constants in `scoring.py` (single source of
   the math; sketch: extract a pure `_ai_boost(ai_result) -> int` used by both `merge_score` and the
   derivation/breakdown path so the condition is never duplicated). Golden tests must stay green
   byte-identically; the breakdown is a new additive field on `/threats/{ip}` and `/detailed`
   responses (ADR-0029 envelope unchanged).

**Alternatives considered:**
- **Keep raw numbers, add a legend/tooltip** — rejected: the misread ("0% conf" next to "100")
  happens at glance speed; a legend is not read at glance speed. Banded labels are the universal
  SIEM pattern (Elastic severity bands, Datadog thresholds).
- **Show confidence as a calibrated percentage** — rejected: we have no calibration data for a
  swappable local model (ADR-0022 — any OpenAI-compatible runtime/model); words communicate the
  honest precision. OCSF itself normalizes confidence to a Low/Medium/High enum (`confidence_id`).
- **Compute the breakdown in the UI from event data** — rejected: duplicates the scoring constants
  in TypeScript; drifts on the first tuning change. The layer that owns the math owns the
  explanation.

**Reasoning:** OCSF normalizes both concepts this ADR pins: `confidence_id` is an enum
(Low/Medium/High), and risk is carried as `risk_level` alongside any raw `risk_score` — i.e. the
2026 cross-vendor schema already says "band it, word it". Score-composition transparency is the
anti-black-box move every leading platform exposes (Elastic entity risk scoring shows per-input
contributions; Microsoft exposes alert evidence). For FireWatch the breakdown is also the natural
consumer of ADR-0035 provenance: the `AI boost +20` line IS the `ai+rule` derivation made visible.

**Out of scope (this ADR):**
- Any change to scoring formulas, thresholds, prompts, or golden baselines.
- The provenance vocabulary itself (ADR-0035) and the slide-over host where the popover may render
  (ADR-0037).
- Recalibrating or re-banding the engine's 76/51/26 thresholds — settled engine behavior, golden-locked.

**References / standards consulted:**
- OCSF — base event `confidence_id` (Low/Medium/High enum) and `risk_level`/`risk_score` pairing.
- Elastic Security — severity bands and entity risk score composition (per-contribution exposure).
- ADR-0022 (swappable local model — no calibration assumption), ADR-0029 (additive read-API fields),
  AI-engine-invariants skill (0.7 boost gate; additive-only scoring).
- LLM-calibration literature consensus: verbalized percentage confidence from instruction-tuned
  models is poorly calibrated — present qualitative bands instead.
