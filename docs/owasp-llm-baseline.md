# OWASP Top 10 for LLM Applications (2025) — FireWatch Baseline Sweep

**Date:** 2026-06-13
**Milestone:** follow-through on the LLM Top 10 deferral from the MP / OWASP-API
gate (issue #NNN deferred LLM01 to ADR-0022 / #NNN; ADR-0026 Decision 7).
**Scope:** the FireWatch local-LLM surface —
`packages/firewatch-core/src/firewatch_core/ai/` (prompt builders, narration,
baseline/drift), `packages/firewatch-core/.../adapters/ai_openai.py` (the engine
+ local-first guard + closed-schema validation), the NL→FilterSpec pipeline
(`packages/firewatch-core/.../nl_query/`), the verdict-ledger caps
(`adapters/ledger/caps.py`), the config-write local-first guard
(`packages/firewatch-sdk/.../config.py`), and the React render paths that display
AI output (`frontend/src/components/ai/ledger/`).
**Implements:** ADR-0022 (local-first inference) + ADR-0044 (verdict ledger) +
ADR-0049 (NL→FilterSpec) + ADR-0015 / ADR-0033 (action seam) reasoning.

This is the documented checklist pass that mirrors `docs/owasp-api-baseline.md`
for the LLM surface. It **assesses + documents**; it does **not** implement fixes
(real gaps become follow-up issues — see the LLM01 and LLM10 rows).

## Standard cited

- **OWASP Top 10 for LLM Applications — 2025 version** (the current edition; the
  list was renumbered/expanded from the 2023/2024 editions — e.g. LLM07 is now
  *System Prompt Leakage*, LLM08 *Vector and Embedding Weaknesses*, LLM10
  *Unbounded Consumption*). Category model + per-entry mitigations:
  <https://genai.owasp.org/llm-top-10/> ·
  <https://owasp.org/www-project-top-10-for-large-language-model-applications/>
- **OWASP LLM01:2025 Prompt Injection** — direct *and* indirect (data-plane)
  injection; "delimit/segregate untrusted content" + "constrain model output
  format" + "human-in-the-loop for privileged actions" are the named mitigations.
- Cross-referenced FireWatch decisions: **ADR-0022** (local-first inference, no
  cloud egress), **ADR-0044** (verdict ledger + field caps), **ADR-0049** (NL→
  FilterSpec strict-allowlist), **ADR-0015 / ADR-0033** (SIEM-now / SOAR-later
  action seam — the AI takes no action), **ADR-0035** (anti-fabrication / honesty),
  **ADR-0029 D3** (UI renders attacker-controlled strings as text nodes only).

> **Version note (verify-against-industry-standard):** FireWatch tracks the
> **2025** edition explicitly. The numbering below is the 2025 numbering. Earlier
> in-code comments (e.g. `# OWASP LLM01`, NB-1) were written against the
> 2023/2024 list; LLM01 (Prompt Injection) is unchanged across editions, so those
> references remain accurate.

## BLOCKER status: NONE

No LLM-surface finding blocks the loopback-only release posture. The headline
risk — **indirect prompt injection via attacker-controlled telemetry** — is
mitigated by a **defence-in-depth stack** (input delimiting + sentinel escaping +
truncation, *and* closed-schema output validation that constrains the verdict to
an enum) and is the strongest single control on this surface. Two real
hardening gaps are filed as follow-ups (LLM01 regression-oracle, LLM10 global
AI-call budget); neither is a release blocker under loopback-only.

---

## The baseline — one row per LLM01–LLM10 (2025)

| # | Category | Status | Evidence pointer |
|---|----------|--------|------------------|
| **LLM01** | Prompt Injection (direct + **indirect/data-plane**) | **covered (defence-in-depth) + hardening follow-up (#NNN)** | **This is the headline row.** Attacker-controlled telemetry *does* reach the model: `scoring.py::build_samples` takes `e.payload_snippet` (raw WAF/Suricata payload) into the `payload` field, and `build_detailed_samples` adds vendor rule `description`. Every such field is delimited, escaped, and truncated before prompt embedding: `ai/prompts.py::_wrap_payload` → truncate (100/300 chars) → `_escape_sentinels` (neutralises any embedded `</untrusted_data>`, close-before-open ordering) → wrap in `<untrusted_data>…</untrusted_data>`. Same treatment for DGA `dns_query`, JA4 fingerprints, and (in `ai/narration.py`) geo, AS name, attack-type labels, MITRE IDs, prior-AI `executive_summary`/`intent`. **Output side (the real teeth):** `ai_openai.py::_validate_concise_schema`/`_validate_detailed_schema` force the verdict into a **closed enum** (`threat_level`, `attack_stage`, `recommended_action`) + `NB-5` key-projection drops any extra keys — so an injected payload cannot make the model emit free-form instructions the product will consume; an out-of-contract response degrades to the fixed fallback envelope. **NL→FilterSpec path** is separately hardened: `nl_query/prompt.py` `<user_query>…</user_query>` sentinel + `<`/`>`→`&lt;`/`&gt;` escaping + explicit "treat as DATA" system rule, and `nl_query/validator.py` re-validates LLM output against a strict allowlist (OOV field/value/low-confidence → `q=` fallback). Tests: `test_concise_payload_is_delimited`, `test_concise_sentinel_close_in_payload_is_neutralized`, `test_sentinel_open_in_payload_is_neutralized` (`tests/test_ai_prompts.py`); `test_angle_brackets_escaped_in_query`, `test_double_quote_injection_cannot_escape_sentinel`, `test_system_prompt_has_injection_warning` (`tests/test_nl_prompt.py`). **Hardening gap:** there is no *end-to-end injection-canary regression oracle* (a fixture payload that tries to steer the verdict, asserting the verdict is unchanged) — delimiting is a probabilistic mitigation per OWASP, so a regression test that proves the schema-clamp holds against a crafted steering payload is worth having. Follow-up **#NNN**. |
| **LLM02** | Sensitive Information Disclosure | **covered** | **No third-party leak by construction:** all inference is local — `ai_openai.py::_validate_local_first` + the config-write guard `config.py::_validate_ollama_base_url_local_first` reject any non-loopback/non-RFC1918 `base_url` at construction *and* at config-write (ADR-0022, fail-closed). The model never sees operator secrets: the prompt is built only from telemetry + score factors (`format_concise`/`format_detailed`/`build_narration_prompt`) — no API keys, webhook URLs, or `SecretStr` values are ever interpolated (those are masked at the API edge by `routes/config.py::_mask_secrets`, per API3). Error envelopes never echo raw exception text into model-visible or UI fields (`NB-6`, `_concise_fallback`/`_detailed_fallback`). The prompt-transparency drawer shows the *prompt*, which contains telemetry the operator already owns — not secrets (see LLM07). |
| **LLM03** | Supply Chain | **deferred-with-ref** | The model is an operator-supplied local artifact (Ollama-pulled or a bundled/air-gapped GGUF). FireWatch ships **no** model weights and makes **no** outbound model-registry call in the lean profile (offline model-copy flow, MI-4 / #NNN). Model provenance/integrity (checksum-verify the GGUF, pin the Ollama tag) is an operator/deploy concern, tracked to the install-path checklist; there is no in-product attestation today. Python dependency supply chain is covered by the repo-wide gitleaks + the standard `uv` lock, out of scope for this LLM sweep. Deferred to the MI-4 air-gapped-model doc. |
| **LLM04** | Data and Model Poisoning | **covered (by design)** | FireWatch **never fine-tunes or retrains** on telemetry or analyst feedback — the model is read-only at runtime. ADR-0035 honesty rule: analyst agree/disagree feedback is recorded but **never** feeds back into the model or the score (no training loop to poison). The operator-saved **verdict baseline** (ADR-0051/ADR-0044) is a deliberate human-authored snapshot used only for *drift reporting* (`ai/baseline/runner.py` — "DOES NOT auto-rebaseline; saving is a deliberate human act"; `_VERDICT_FIELDS` compared, never written back to the model). The classifier provenance (`adapters/ip_classifier.py`) uses bundled curated ASN sets, zero-egress — no external feed to poison. |
| **LLM05** | Improper Output Handling | **covered** | AI verdicts/insights/narration are attacker-influenced strings (the model can be steered to echo a crafted payload). Every React render path treats them as **text nodes only** — repo-wide grep confirms **zero** real `dangerouslySetInnerHTML` usage; every match is a *negative-affirmation comment* (e.g. `PromptDrawer.tsx`, `VerdictCard.tsx`, `promptSections.ts`, `IpHeaderMeta.tsx`). `PromptDrawer.tsx` (the most attacker-controlled subtree) renders `prompt_text`/`response_text` in a `<pre>` as a React child (textContent path), with no markdown/HTML/ANSI interpretation — hostile strings like `<img src=x onerror=…>` render inert. React's default escaping is the control (ADR-0029 D3). Backend never builds SQL from LLM output (NL→FilterSpec values always flow through SQLite `?` placeholders — `nl_query/validator.py` docstring). Test: `ActiveRangeChip.test.tsx` asserts no `dangerouslySetInnerHTML`; `promptSections.test.ts`. |
| **LLM06** | Excessive Agency | **covered (by design)** | The AI has **no agency**: it produces advisory text + a structured verdict, and takes **no action**. SIEM-now / SOAR-later is the settled boundary — ADR-0033 routes all triage verbs through a single `onAction` seam that today only *records* the analyst's decision (Block is record-only); ADR-0015 tiered autonomy defers any execution behind human approval. Narration prompts explicitly forbid SOAR actions ("no execution, no SOAR actions" — `narration.py::_NARRATION_PREAMBLE` rule 3). The model has no tool access, no function-calling, no network/file capability beyond returning JSON to the validator. |
| **LLM07** | System Prompt Leakage | **covered (intentional transparency)** | The prompt-transparency "What the model saw" drawer (`frontend/.../ai/ledger/PromptDrawer.tsx`, MK-7/#NNN) **deliberately displays** the full prompt — this is an *intentional glass-box design choice*, not a leak. It is acceptable because the FireWatch system prompt contains **no secret**: it is a SOC-analyst instruction template + the operator's own telemetry (both already visible to the authenticated operator). There is no credential, key, or hidden privileged instruction whose disclosure would weaken a control — the security model does not rely on prompt secrecy (the controls are the local-first guard, the closed-schema validator, and the strict allowlist, none of which the prompt protects). The drawer itself is gated behind API auth when a key is set (the `/ai/analyses/{id}` read is class-C, API9 inventory). Glass-box transparency over secret-prompt obscurity is the deliberate, defensible posture. |
| **LLM08** | Vector and Embedding Weaknesses | **N/A (no RAG/embeddings)** | FireWatch performs **no** retrieval-augmented generation and stores **no** vector embeddings. The classifier prompt is built from structured telemetry per-IP (`build_samples`), not from a vector store. There is no embedding index, no similarity search, no document-ingest pipeline. This category does not apply to the current architecture. (Revisit if a future ADR introduces RAG over rule descriptions or historical cases.) |
| **LLM09** | Misinformation / Overreliance | **covered** | The honesty treatment (ADR-0035, MK work) directly mitigates overreliance: (1) **AI verdict vs score-move separation** — the AI assessment is shown *alongside* but does not silently override the deterministic rule score; derivation is labelled (`narration.py` emits `Derivation:` rule|ai). (2) **Anti-fabrication** — narration is gated on actually-collected fields; a `collected_fields` list + `PROVENANCE:` footer force the model to ground every claim, and DGA/rule signals are tagged `RULE provenance, not AI` so the model can't overstate confidence. (3) **agree/disagree never retrains** (LLM04) — feedback is advisory, preventing a false-consensus loop. (4) The fallback envelope says `"AI analysis unavailable"` rather than fabricating a verdict. (5) Confidence is surfaced separately from the gate decision. |
| **LLM10** | Unbounded Consumption | **covered (read+storage) + gap follow-up (#NNN)** | **Per-call input is bounded:** `scoring.py::MAX_SAMPLES = 15` caps samples per IP; `MAX_PAYLOAD_LEN`/`_CONCISE_MAX_PAYLOAD`(100)/`_DETAILED_MAX_PAYLOAD`(300) cap each payload; narration caps fields at 80–300 chars; the NL query is truncated to `MAX_QUERY_LEN = 500`. **Storage is bounded:** `adapters/ledger/caps.py` caps `prompt_text`/`response_text` at 64 KiB each and prunes the ledger (50/IP, 5 000 global). **Per-IP concurrency:** `routes/ai_stream.py` single-flights duplicate concurrent streams for the same IP (409). **GAP:** there is **no global AI-call rate/concurrency budget** — nothing caps how many *distinct* IPs can trigger analysis in parallel or per unit time, nor a per-analysis output-token ceiling at the engine. Under loopback-only single-operator posture this is acceptable (Ollama serialises on one GPU, providing incidental backpressure), but a non-loopback or multi-operator deployment could drive unbounded local-inference cost. Follow-up **#NNN** (global AI-call budget / per-analysis token cap; `deferred`). |

**Legend:** *covered* = enforced + tested today · *covered (by design)* =
structurally impossible, credited · *deferred-with-ref* = intentionally out of
scope with an ADR/issue reference · *N/A* = category does not apply to the
architecture · *gap + follow-up* = real gap, filed as an issue, not fixed here.

---

## The single most important finding

**Indirect (data-plane) prompt injection via attacker-controlled telemetry is
COVERED by defence-in-depth — not an open gap.** Attacker text *does* reach the
classifier and per-IP analysis prompts (`build_samples` → `payload`,
`build_detailed_samples` → `description`, plus DGA/JA4/geo/ASN fields), but two
independent controls stack:

1. **Input delimiting + escaping + truncation** (`ai/prompts.py::_wrap_payload`,
   `ai/narration.py::_wrap`) — every untrusted field is sentinel-wrapped, with
   embedded sentinels neutralised (close-before-open) so a crafted payload cannot
   break out of `<untrusted_data>`.
2. **Closed-schema output validation** (`ai_openai.py::_validate_*_schema` +
   `NB-5` key projection) — the verdict is clamped to enums; a steered/garbage
   response fails validation and degrades to a fixed fallback. This is the
   control that matters most: even if delimiting were bypassed, the product never
   consumes free-form model instructions.

The **residual** is that delimiting is a probabilistic mitigation and there is no
*regression oracle* proving the schema-clamp holds against a deliberate steering
payload. That is filed as a low-severity hardening follow-up (**#NNN**), not a
blocker.

---

## Deferred / N-A items

- **LLM03 Supply Chain** — model-artifact provenance/checksum is an operator/deploy
  concern (MI-4 air-gapped doc, #NNN); no in-product attestation today.
- **LLM08 Vector/Embedding** — N/A; FireWatch has no RAG or embedding store.

## Follow-up issues filed by this sweep

- **#NNN** — End-to-end indirect-prompt-injection regression oracle for the
  classifier/analysis path (a crafted steering payload fixture asserting the
  verdict schema-clamp holds). LLM01 hardening; `area:core` / `area:tests` /
  `security`.
- **#NNN** — Global AI-call budget (concurrency + frequency) and per-analysis
  output-token ceiling, before non-loopback / multi-operator exposure. LLM10 gap;
  `deferred` / `area:core` / `area:api` / `security`.

---

_Swept 2026-06-13 as the LLM-Top-10 follow-through to the MP / OWASP-API gate
(#NNN → ADR-0026 D7). Verification grounded in the cited `path/file.py:func`
references and the named tests (`test_ai_prompts.py`, `test_nl_prompt.py`,
`test_nl_engine.py`, `test_nl_validator.py`, `promptSections.test.ts`)._
