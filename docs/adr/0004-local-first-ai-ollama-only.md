# ADR-004: Local-First AI — Ollama Only

**Date:** February 2026
**Status:** Superseded by ADR-0022

> **Superseded by [ADR-0022](0022-local-inference-openai-compatible-endpoint.md).** The
> local-first invariant below is retained; only the "Ollama-only" runtime lock-in is relaxed —
> inference now targets a local OpenAI-compatible endpoint (Ollama default; vLLM/SGLang/llama.cpp/
> LM Studio supported).

**Decision:** All LLM inference via local Ollama. No OpenAI, Anthropic, or other cloud API options.

**Reasoning:** Target users are security engineers who can't send WAF logs to cloud providers. Privacy and data sovereignty are non-negotiable for security tooling. Local inference also eliminates rate limits and per-token costs.
