---
name: ai-engine-invariants
description: The tuned, fragile rules of the FireWatch dual-engine AI scoring path. Load before touching the analyzer, ai_classifier, prompts, sample-building, or scoring. These are easy to break by "cleaning up".
---
# AI engine invariants — change with care, guard with the prompt baseline

## Sampling (ADR-0003) — never per-log
One LLM call per IP. Build samples: group blocked events by `rule_id`, take the LONGEST payload
per rule, sort by frequency, cap at 15 (concise) / uncapped (detailed). Payload truncation
100 chars (concise) / 300 (detailed).

## Prompts are tuned — do not reword casually
`IP_SUMMARY_PROMPT` (concise) and `IP_DETAILED_PROMPT` (detailed) output a CLOSED JSON schema
(`threat_level` enum, `confidence` 0..1, `intent`, `attack_stage` enum, `insights`, `recommended_action` enum).
Any prompt edit must keep `test_ai_prompt --compare` green or be an intentional, noted rebaseline.

## qwen3 format quirk — do NOT "fix" it
Ollama's `format:"json"` constraint makes qwen3 return empty `{}`. `_use_format_json()` detects
qwen3 and OMITS the format param; `_extract_json()` walks the text for the outermost `{…}`.
Removing this re-breaks qwen3.

## Scoring is additive-only
Rules score runs first (deterministic, instant). AI may BOOST (CRITICAL+conf>0.7 → +20,
HIGH+conf>0.7 → +10, cap 100) but must NEVER lower the rules score. This is both the scoring
design and the prompt-injection mitigation.

## Other invariants
- **Local-first**: inference targets a **local OpenAI-compatible endpoint** (Ollama default;
  vLLM/SGLang/llama.cpp/LM Studio supported) — never add a cloud-LLM call, and validate the
  endpoint resolves to loopback/LAN, not a public host (ADR-0004 → ADR-0022).
- **Concurrency is runtime-dependent**: Ollama serializes per GPU (→ 3); batching runtimes like
  vLLM sustain far more. Tune per the configured endpoint — don't hardcode 3.
- **Graceful degradation**: Ollama offline/timeout/invalid-JSON → rules-only score, `ai_status` set.
- **Injection**: sampled payloads are attacker-controlled — keep them delimited as untrusted DATA
  in the prompt; validate output against the closed schema. (ADR-0015)
  `rule_id`, `category`, `rule_name` (correlation) and `reason` (correlation) are also
  sentinel-wrapped (#642) — they are sensor-observed, not operator-fixed, so a crafted CEF
  SignatureID / CategoryName can embed injection text. Only `count`, `score_delta`,
  `first_triggered`, and `last_triggered` remain bare (trusted engine numerics/timestamps).
