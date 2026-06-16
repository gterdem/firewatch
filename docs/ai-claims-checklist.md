# AI Claims Checklist — every public claim, mapped to what enforces it

**Purpose (MI-8, issue #NNN):** launch/README copy about FireWatch's AI must
never outrun the implementation. Every public or marketing claim gets a row
here mapping it to the exact code, test, or accepted ADR that substantiates it.
This file lives next to the copy so future edits stay honest.

## Editing rules (binding)

1. **No new public AI claim ships without a row in this table** citing an
   enforcing test or an accepted ADR that is **on `main`**.
2. **Forbidden phrasing:** "tested verdicts" / "validated verdicts" as a vendor
   claim. Verdicts are model-dependent; the only honest form is
   "operator-recorded baseline via `firewatch ai-baseline`" (MI-9).
3. **Footprint numbers** (RAM / model size / hardware) may appear **only** with
   a citation to the MI-2 measured-results doc (issue #NNN). Until that doc
   exists, no footprint number appears anywhere in launch copy.
4. **"Air-gapped"** is always a link to the verified mode doc
   (`docs/air-gapped-mode.md`), never a bare adjective — and inherits that
   doc's honest boundary (cloud-API sources like Azure WAF are out of scope).
5. Rows whose status is not "On main" block copy freeze: the claim may stay in
   draft copy, but the copy must not be published before the row turns green.

## The claims

| # | Claim (as it appears in README/launch copy) | Substantiated by | Status |
|---|---|---|---|
| 1 | All inference is local-only; no cloud LLM; non-local endpoints are refused at construction | [ADR-0022](adr/0022-local-inference-openai-compatible-endpoint.md); `packages/firewatch-core/src/firewatch_core/adapters/ai_openai.py` — `_validate_local_first()` (loopback/RFC-1918 allowlist, numeric-IP pinning, fail-closed on unresolvable hosts); tests `packages/firewatch-core/tests/test_ai_openai_engine.py` (cloud hostname rejected, arbitrary public hostname rejected, fail-closed, *no request ever sent* to a rejected URL) | On main |
| 2 | FireWatch supports verified zero-egress (air-gapped) operation | MI-4 doc [`docs/air-gapped-mode.md`](air-gapped-mode.md) (egress inventory + verification recipe, issue #NNN); `packages/firewatch-core/tests/test_issue_385_zero_egress.py`; offline geo default per ADR-0039 (MI-1, #NNN) | On main — claim must carry the doc's honest boundary (cloud-API sources excluded) |
| 3 | The AI boost is additive-only and bounded: +20 (CRITICAL, conf > 0.7) / +10 (HIGH, conf > 0.7) / 0 otherwise; it can never lower the rule score; correlation capped +30; total capped 100 | `packages/firewatch-core/src/firewatch_core/scoring.py` — `_ai_boost()`, `merge_score()`; `ai-engine-invariants` skill; ADR-0003; tests `packages/firewatch-core/tests/test_scoring.py` (`test_merge_ai_critical_boost`, `test_merge_ai_high_boost`, `test_merge_ai_below_confidence_no_boost`, `test_merge_detection_boost_capped_at_30`, `test_merge_score_clamped_to_100`); golden score oracle `tests/golden/test_suricata_scores.py` + `tests/golden/fixtures/expected_scores.json` | On main |
| 4 | The model's output schema is closed: fixed key set, enum-validated threat level, confidence range-checked; unknown keys dropped; any invalid response falls back to rules-only | `ai_openai.py` — `_validate_concise_schema()` / `_validate_detailed_schema()` + NB-5 allowlist projection (extra LLM keys silently dropped); tests `test_ai_openai_engine.py` (schema-invalid JSON → fallback, invalid enum → fallback, confidence out of range → fallback, fallback never raises) | On main |
| 5 | Every number in a score comes from event data or a fixed constant — the model cannot inject score fields | Follows from rows 3 + 4: the only AI-derived contribution to any score is the bounded `_ai_boost()` integer; `build_score_breakdown()` factors are computed exclusively from events + constants in `scoring.py`; `packages/firewatch-core/tests/test_score_breakdown.py` (breakdown sums to `merge_score` output) | On main |
| 6 | Every analytic artifact is provenance-tagged (`RULE` / `AI` / `AI+RULE`); a score is tagged `ai+rule` only when the boost actually fired | [ADR-0035](adr/0035-analytic-provenance-tagging.md); `merge_score()` returns `score_derivation` at the point of authorship; tests `packages/firewatch-core/tests/test_score_derivation.py`; UI: shared `frontend/src/components/ds/analytics/ProvenanceChip.tsx` | On main |
| 7 | The prompt path is regression-pinned: prompt text is byte-stable against committed baselines in CI; any change is an explicit reviewed rebaseline | Prompt-baseline oracle `tests/golden/ai/` (`test_prompt_baseline.py`, fixtures from RFC 5737 ranges, `harness --save` rebaseline flow); EARS-2 byte-equality + EARS-3 change-detection tests | On main |
| 8 | Attacker payloads enter the prompt only inside `<untrusted_data>` sentinels; dropping the wrapping fails a test (NB-1 / ADR-0015) | `packages/firewatch-core/src/firewatch_core/ai/prompts.py` — `SENTINEL_OPEN`/`SENTINEL_CLOSE` + escaping of attacker-embedded sentinel strings; tests `tests/golden/ai/test_prompt_baseline.py::test_delimiter_present_in_all_baselines` and `::test_delimiter_in_generated_prompt_not_just_baseline` (EARS-4) | On main |
| 9 | Every score carries an evidence chain: each breakdown factor maps to the exact stored events that produced it, recomputed from data at read time (cannot drift from the score) | [ADR-0041](adr/0041-evidence-chain-recompute-at-read-time.md); MI-6 (issue #NNN, PR #NNN, merged): `GET /threats/{ip}/evidence` (`packages/firewatch-api/src/firewatch_api/routes/threats.py`, `EvidenceChainResponse`), read-time recompute `packages/firewatch-core/src/firewatch_core/evidence.py`; UI chips MI-7 (issue #NNN, merged): `frontend/src/components/evidence/` | On main — claim is firm (recompute-at-read-time enforced in `evidence.py`) |
| 10 | Operators can regression-test their own model's verdicts: `firewatch ai-baseline --save` / `--compare` (exit code = drift gate, CI-scriptable by the operator) | MI-9 (issue #NNN, PR #NNN, merged): `packages/firewatch-cli/src/firewatch_cli/commands/ai_baseline.py`, `packages/firewatch-core/src/firewatch_core/ai/baseline/` (fixtures · runner · report); tests `packages/firewatch-cli/tests/test_ai_baseline.py` (22 tests, all mocked) | On main |
| 11 | The verdict baseline is operator-recorded, not vendor-guaranteed (verdicts are model-dependent) | Stated in the MI-9 design itself: no vendor baseline file is committed; `--save` is a deliberate operator act; no CI live-model dependency (`ai_baseline.py` module docstring, PR #NNN) | On main — this row exists to keep the *negative* claim honest |
| 12 | If the AI engine is down/slow/invalid, FireWatch degrades to rules-only and labels it ("Rules-only mode · AI engine offline") | `ai_openai.py` fallback envelopes (timeout / connection error / malformed JSON / HTTP error → rules-only, `ai_status` set; `test_fallback_never_raises`); `packages/firewatch-core/tests/test_issue_306_ai_status_guard.py`; standard degraded wording per ADR-0035 §4 | On main |
| 13 | *(Reserved)* Footprint claim — "runs on X GB with model Y" | **Blocked on MI-2** (issue #NNN, measured-footprint benchmark, both inference profiles). No number may appear before that doc lands and is cited. | Blocked — claim slot reserved, currently absent from all copy |

## Claims we deliberately do NOT make (and why)

- **"The AI never hallucinates / is always correct."** Untestable and false for
  any LLM. The honest claim is *structural containment* (rows 3–5): a wrong
  verdict cannot lower a score, invent fields, or inject numbers, and its
  contribution is tagged (row 6) and bounded (row 3).
- **"Tested/validated verdicts" (vendor-guaranteed).** Verdicts vary by model,
  quantization, and runtime. What is vendor-tested is the structure (prompts,
  schema, merge math — rows 3, 4, 7, 8). Verdict testing is the operator's,
  via row 10.
- **"Fully air-gapped" without qualification.** Cloud-API sources (Azure WAF)
  are inherently online; the air-gapped doc draws that boundary explicitly
  (row 2).
- **Any performance/footprint number.** Until MI-2 publishes measured results
  (row 13).
