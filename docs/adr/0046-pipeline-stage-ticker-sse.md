# ADR-0046: Pipeline Stage Ticker — Fetch-Streamed SSE of Validated Stage Facts (No Raw Tokens)

**Date:** 2026-06-12
**Status:** Accepted (architect-decided under delegated authority, 2026-06-12)

**Relates to:** ADR-0022 (local endpoint), ADR-0023 §F (single loop), ADR-0026 (auth posture —
the stream inherits class C), ADR-0035 (honesty — nothing pre-validation is rendered), ADR-0037
(slide-over host), ADR-0043 (AI Engine page inherits the component).
**Implements:** the strategist's §6 verdict in `scratch/ai-analysis-suggestions.md`: glass-box the
*validation gauntlet*, not the tokens.

---

## Context

The deep-analysis wait (`DeepAnalysisControl` / `AiSectionSkeleton`, issue #268) is a ~15s blind
skeleton — the only live AI moment in the product. The strategist evaluated raw "watch it think"
token streaming and **declined it on real data**: a raw stream bypasses every safety gate
(`_extract_json` → closed-schema validation → allowlist projection → `ai_status` guard), renders
attacker-influenced pre-validation output, shows JSON assembling char-by-char, and labels
known-unfaithful reasoning traces as "thinking" (the exact ADR-0035 miscalibration). 2–5% of
generations fail validation — the operator would watch a verdict assemble, then vanish.

The accepted reframe: a **pipeline stage ticker** — stream *facts about the gauntlet*, each one
true and already determined: `prompt built (12 samples) → sent to qwen3:8b @127.0.0.1 →
generating… (elapsed) → received (642 tok · 9.8s) → schema validated ✓ → projected to 7 fields ✓`,
and on failure: `validation FAILED → rules-only fallback`, shown proudly.

**Code grounding:** no SSE/WS exists anywhere in the API; `ai_openai.py` hardcodes
`"stream": False` (invariant); Ollama serializes per GPU — an in-flight generation holds the
single GPU slot.

## Decision

1. **Transport: Server-Sent Events** (`text/event-stream`, WHATWG HTML §9.2 "server-sent
   events") on a new endpoint:
   `GET /threats/{ip}/detailed/stream` — runs the *same* `analyze_ip_detailed` path and emits
   stage events, ending with a terminal `result` event carrying the same payload the
   non-streaming endpoint returns (no second fetch).
2. **Client consumes via `fetch` + `ReadableStream` SSE parsing — NOT `EventSource`.** Two hard
   reasons: (a) `EventSource` cannot send the `Authorization` header, so the stream could never
   honor ADR-0026's key-gated-when-exposed posture; (b) `AbortController` gives deterministic
   cancellation. SSE wire format is kept so the server side stays standard.
3. **Closed stage-fact vocabulary (enum, versioned).** Events are limited to:
   `stage: prompt_built {sample_count}`, `stage: request_sent {model, endpoint_host}`,
   `stage: generating {elapsed_ms}` (heartbeat), `stage: received {latency_ms, completion_tokens?}`,
   `stage: validated`, `stage: projected {field_count}`, `stage: failed {stage, reason_code}`,
   `result {…detailed payload}`. **No model-authored text ever appears in a stage event** —
   prose arrives only inside the terminal `result`, after the full gauntlet, exactly as on the
   non-streaming path. Unknown event types are dropped by the client (forward-compatible).
4. **No upstream token streaming in this milestone.** The adapter keeps `"stream": False`
   (ai-engine-invariants). The `generating` heartbeat carries **elapsed time only**; token counts
   appear in `received` from the endpoint's `usage` block when present. A future enhancement MAY
   stream upstream *solely to count tokens and cancel earlier* — token text must still never be
   forwarded; the assembled text must pass the identical validation gauntlet. Recorded here so it
   isn't reinvented dishonestly.
5. **Cancellation frees the GPU slot — mandatory.** When the client aborts (slide-over closed,
   component unmounted, navigation), the server MUST detect the disconnect and **cancel the
   in-flight analysis task, closing the upstream httpx request** so Ollama aborts generation and
   releases its single GPU slot. An orphaned 15–120s generation per closed panel is a self-DoS
   (OWASP API4). Implementation: the SSE generator's cancellation (client disconnect raises in
   the generator) propagates `asyncio.CancelledError` into the awaited engine call.
6. **Auth + abuse posture:** the route is class **C** (read/analyze — same class as
   `GET /threats/{ip}/detailed`, which already triggers inference): loopback-open by default,
   key-gated when exposed (ADR-0026). Per-IP single-flight guard (409 on a duplicate concurrent
   stream for the same ip) — reusing the product's existing single-flight pattern — bounds
   resource consumption.
7. **Mounting order:** the ticker component mounts first on the slide-over deep-analysis control
   (replacing the blind skeleton); the AI Engine page's verdict-card "Re-run" inherits the same
   component (zero dedicated work, ADR-0043). Failure of the stream itself degrades gracefully to
   the existing non-streaming request — the ticker is presentation, never a new failure mode for
   analysis.
8. **Accessibility:** the ticker is a WAI-ARIA `aria-live="polite"` status region announcing
   stage transitions (not every heartbeat); it respects `prefers-reduced-motion`; the pane is
   bounded-height (stages overwrite/append within a fixed block — no inner scrollbar).

## Alternatives considered

- **Raw token streaming on real data** — DECLINED (Maintainer + strategist concur): renders
  unvalidated attacker-influenced output, unfaithful "thinking" labels, vanishing-verdict UX,
  cloud-chatbot aesthetic anyone owns. A literal-stream venue remains legitimate later for
  **synthetic input only** (Settings "Test model" showroom — flagged post-launch, not here).
- **WebSockets** — rejected: bidirectional capability unneeded; SSE is simpler, proxies well,
  and the fetch-stream client sidesteps `EventSource`'s header limitation anyway.
- **Polling a progress endpoint** — rejected: server must then hold progress state per analysis;
  SSE keeps it request-scoped, and cancellation maps 1:1 to disconnect.
- **One global stream multiplexing all analyses** — rejected: lifecycle/auth scoping per entity
  is simpler and matches the slide-over's mount/unmount.

## Reasoning

- Honesty: every rendered fact is already true when emitted (the stage happened); nothing
  model-authored is shown pre-validation — ADR-0035 holds by construction.
- Differentiation: the gauntlet IS the product story ("closed schema, local endpoint, validated
  or proudly failed") — a cloud vendor's equivalent ticker would read "sent your data to us".
- Standards: WHATWG HTML Living Standard §9.2 (SSE; `text/event-stream`); RFC 9110 §11 +
  ADR-0026 for the credentialed fetch; OWASP API4 (resource consumption → single-flight +
  cancel-on-disconnect); WCAG 2.2 / WAI-ARIA live regions for the status updates.

## Out of scope

- Raw token streaming anywhere on real data; the synthetic-input "Test model" showroom (Settings)
  — separate post-launch item.
- Streaming for the background/concise scoring path (it has no watcher).
- The Devil's-Advocate sweep's actor-by-actor progress tail (R8, gated).
- Upstream `stream: True` token counting (permitted future enhancement, constraints recorded
  in Decision 4).

## References

- WHATWG HTML Living Standard §9.2 Server-sent events (incl. the `EventSource`-cannot-set-headers
  limitation motivating the fetch-stream client).
- OWASP API Security Top 10 2023 — API4 unrestricted resource consumption.
- WCAG 2.2 / WAI-ARIA — live regions, reduced motion.
- Internal: ADR-0022/0023/0026/0035/0037/0043; ai-engine-invariants skill;
  `scratch/ai-analysis-suggestions.md` §6 (incl. the corrections/flags paragraph: GPU-slot
  cancellation and ADR-0026 inheritance were strategist-flagged architect notes).
