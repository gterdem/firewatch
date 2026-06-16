# FireWatch AI: Trust & Auditability

Most AI security tools ask you to trust a verdict you cannot inspect. FireWatch is built
the other way around: the AI is **structurally contained**, and every claim below is backed
by a test or an accepted design decision you can read in this repository.

**Pairs with:**
- [docs/ai-claims-checklist.md](ai-claims-checklist.md) — the full claim-by-claim mapping
  to the code, test, or ADR that enforces each statement on this page. The copy here is not
  allowed to outrun it.
- [docs/guide/ai-engine.md](guide/ai-engine.md) — the analyst-facing guide to the AI Engine
  page: reading verdicts, provenance chips, the evidence drawer, and model-drift checks.

---

<!-- Summary→checklist trace (rule 1 of docs/ai-claims-checklist.md):
     local-only/cloud-refused → rows 1, 2 · deterministic floor / bounded boost → rows 3, 5
     rules-only degradation, labeled → row 12 · provenance + factor/evidence linkage → rows 6, 9
     (row 9 evidence-chain shipped — #NNN merged; endpoint + evidence.py on main) · prompt pinning → rows 7, 8
     ai-baseline operator-recorded → rows 10, 11. "Pluggable sources" is an architecture claim
     (PLUGIN_CONTRACT.md), not an AI claim — no row needed. -->

**1. Inference is local-only. No cloud LLM — enforced, not promised.**
All inference targets a local OpenAI-compatible endpoint (Ollama by default; vLLM,
llama.cpp, LM Studio, and SGLang also work). The adapter refuses to construct against a
non-loopback / non-private host, so "local" can never quietly become a hosted API. Your
WAF/IDS logs stay on hardware you control.
([ADR-0022](adr/0022-local-inference-openai-compatible-endpoint.md); enforced in
`packages/firewatch-core/src/firewatch_core/adapters/ai_openai.py`.) For fully offline
operation, see [Air-gapped mode](air-gapped-mode.md) — a verified zero-egress
configuration, not an adjective.

**2. The AI can only *add* to a deterministic score — never replace it, never lower it.**
A rule engine produces the base score first: brute force, port scan, SQLi/XSS payload
patterns, blocked-event volume — plain, readable Python in
`packages/firewatch-core/src/firewatch_core/scoring.py`. The model may then add a *bounded*
boost (+20 for a high-confidence CRITICAL verdict, +10 for HIGH, nothing otherwise);
correlation detections add at most +30; the total is capped at 100. If the model is wrong,
offline, or hallucinating, the deterministic floor stands. This is simultaneously the
scoring design and a prompt-injection mitigation: an attacker who somehow swayed the model
still cannot suppress their own score.

**3. The model's output schema is closed. It cannot invent score fields.**
LLM responses are validated against a fixed schema (threat-level enum, confidence in 0..1,
a fixed key set). Unknown keys are dropped; an invalid value rejects the entire response and
FireWatch falls back to the rules-only score. Every number in a FireWatch score comes from
your event data or a fixed constant in `scoring.py` — never from model free text.

**4. The prompt path is regression-pinned in CI.**
The exact prompt text the model sees is byte-pinned by committed baselines
(`tests/golden/ai/`). Any change to the prompts fails CI unless it is an explicit, reviewed
rebaseline. Attacker-controlled payloads enter the prompt only inside `<untrusted_data>`
sentinels — and a dedicated test fails if that wrapping is ever dropped. The
prompt-injection posture is something you can diff, not a black box.

**5. Every score explains itself — provenance-tagged and evidence-linked.**
Each score carries a derivation tag (`RULE` vs `AI+RULE` — was the AI boost actually
applied, or is this pure rule output?) and an additive factor breakdown that sums exactly to
the number on screen. An **evidence chain** maps each factor to the specific stored events
that produced it, recomputed from your data at read time so the explanation can never
silently drift from the score it explains.
([ADR-0035](adr/0035-analytic-provenance-tagging.md) provenance tagging,
[ADR-0041](adr/0041-evidence-chain-recompute-at-read-time.md) evidence chain — both shipped;
the chain is served by `GET /threats/{ip}/evidence`, recomputed at read time in `evidence.py`.)

**6. You can regression-test your own model's verdicts.**
```
firewatch ai-baseline --save      # record what YOUR model concludes on a canonical scenario set
firewatch ai-baseline --compare   # re-run later; exits non-zero if any verdict drifted
```
Run it after a model swap, a quantization change, or a runtime upgrade. Verdicts are
model-dependent — so the baseline is **operator-recorded on your hardware**, not a vendor
promise. FireWatch pins the prompt path centrally and hands you the tool to pin verdicts on
your own setup.

### What we deliberately do NOT claim

- We do **not** claim the AI "never hallucinates" or is "always correct." We claim
  hallucination is *contained*: it cannot lower a score, invent score fields, or inject
  numbers — and any contribution it does make is tagged and bounded.
- We do **not** ship "tested verdicts." Verdicts depend on the model and runtime *you* run.
  What is vendor-tested is the structure around the model (prompt text, schema, merge math);
  what tests verdicts is `ai-baseline`, run by you.
- If the AI engine is unreachable, FireWatch keeps working in rules-only mode and labels it
  on screen — it does not fake AI output.
