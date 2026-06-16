# ADR-003: AI Approach — Sampling, Not Per-Log

**Date:** February 2026
**Status:** Accepted

**Decision:** One LLM call per IP (sampling one payload per triggered rule), not one call per log event.

**Reasoning:** WAF/IDS rules already classify individual payloads. The AI's value is synthesizing intent across multiple rules. Sampling reduces Ollama calls from thousands to tens, making real-time AI analysis practical (~5-15s per IP instead of hours).
