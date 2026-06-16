# ADR-022: Local Inference Interface — OpenAI-Compatible Endpoint

**Date:** June 2026
**Status:** Accepted (supersedes ADR-0004)

**Decision:** Keep the **local-first invariant unchanged** — all inference stays on hardware the
operator controls; **no cloud LLM in the product**. Relax the *runtime* lock-in: the `ai_engine`
adapter targets a **local OpenAI-compatible `/v1` endpoint** (configurable `base_url`) rather than
Ollama's native API. **Ollama remains the default and recommended runtime** (it exposes an
OpenAI-compatible API out of the box); operators who need throughput can point `base_url` at
**vLLM** or **SGLang** with no code change. TGI is dropped from consideration (maintenance/EOL
since Dec 2025).

**Alternatives considered:**
- **Ollama-native only (ADR-0004 as written)** — rejected: soft lock-in to one runtime; Ollama
  processes requests sequentially and is ~6× slower than vLLM under concurrency, with no path to
  production-scale serving.
- **One adapter per runtime (Ollama, vLLM, llama.cpp native APIs)** — rejected: N adapters to
  maintain when a single de-facto interface already exists.
- **Allow cloud/OpenAI-hosted endpoints** — rejected: violates the local-first invariant (data
  sovereignty for WAF/IDS logs), which this ADR explicitly *retains*.

**Reasoning:** The OpenAI-compatible `/v1` API is the de-facto interface for local serving — Ollama,
vLLM, llama.cpp, LM Studio, and SGLang all expose it — so targeting it removes runtime lock-in at
zero interface cost. vLLM (PagedAttention) is the 2026 throughput standard for multi-user/on-prem
serving. The real principle worth protecting is "local-first," not "Ollama specifically." Sources:
[Ollama vs vLLM vs TGI 2026 benchmark](https://codersera.com/blog/vllm-vs-ollama-vs-lm-studio-production-2026/),
[2026 guide to running local LLMs in production](https://www.sitepoint.com/the-2026-definitive-guide-to-running-local-llms-in-production/).

**Reasoning (local-first enforcement):** The adapter should validate that the configured `base_url`
resolves to a loopback/LAN address (not a public/cloud host), so "OpenAI-compatible" never becomes
a backdoor to a hosted API. This preserves the ADR-0004 invariant mechanically.

**Consequences:**
- `ai_engine` adapter uses an OpenAI-compatible client with a configurable `base_url` (default =
  local Ollama); the `ai-engine-invariants` skill is updated (the "Ollama-only" invariant becomes
  "local OpenAI-compatible endpoint, Ollama default").
- ARCHITECTURE.md invariant #2 reworded from "all inference via Ollama" → "all inference via a
  local OpenAI-compatible endpoint; no cloud LLM."
- On acceptance, ADR-0004 is marked `Superseded by ADR-0022` (local-first rationale preserved).
- The model/format quirks noted in `ai-engine-invariants` (e.g. qwen3 format handling) must be
  re-validated against the chosen runtime.
