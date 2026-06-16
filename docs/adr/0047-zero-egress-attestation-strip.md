# ADR-0047: Zero-Egress Attestation Strip — Derived From Enforced Configuration, Never Asserted

**Date:** 2026-06-12
**Status:** Accepted (architect-decided under delegated authority, 2026-06-12)

**Relates to:** ADR-0022 (local-first `/v1` endpoint + the constructor guard), ADR-0035 (rule #4:
engine status lives in ONE spot), ADR-0039 (offline geo — the other egress, closed), ADR-0042
(runtime profiles), ADR-0043 (AI Engine page header), ADR-0044 (ledger supplies the counters).
**Implements:** R4 from `scratch/ai-analysis-suggestions.md`; wording discipline per
`docs/ai-claims-checklist.md` (MI-8).

---

## Context

"All inference is local" is FireWatch's headline differentiator, and the one claim no cloud
competitor can render. It is also exactly the kind of claim that becomes marketing-washing if
asserted rather than proven (the #1 practitioner complaint in the competitive research). The
product already *enforces* locality mechanically: `OpenAIEngine` refuses, **at construction**, any
`base_url` that does not resolve to loopback or an RFC 1918/link-local address
(`ai_openai.py:_is_local_address`, ADR-0022's fail-closed guard) — so a cloud AI call is not
"avoided", it is *unconfigurable*.

## Decision

1. **A slim engine-header strip on the AI Engine page** (ADR-0043 block 1), rendering only facts
   with a named enforcement point:

   | Strip line | Derived from (the proof) |
   |---|---|
   | Model name (+ runtime profile, Ollama default / llama.cpp lean) | runtime config + `/ai/models` (ADR-0042) |
   | Endpoint `127.0.0.1:11434` — "validated local at startup" | the ADR-0022 constructor guard (boot fails otherwise) |
   | "N analyses since install · last HH:MM" | `ai_analyses` row count / max(created_at) (ADR-0044) |
   | "0 cloud AI calls — non-local endpoints are refused by design" | the same guard: every call that ever ran went to a validated local address |

2. **Derivation, not assertion — the wording rule.** Every line must be (a) computed from
   validated config or recorded data at render time, and (b) traceable to the mechanism that
   makes it true. No line may make a promise the code does not enforce. Specifically:
   - The claim is **scoped to AI inference**. It is NOT a blanket "FireWatch never egresses"
     claim — webhook alerting and (pre-MI-1 installs) geolocation are operator-visible egress
     with their own controls. Blanket zero-egress wording is reserved for the air-gapped mode doc
     (MI-4/ADR-0039), where it is configuration-verified.
   - The counter wording is existence-proof shaped ("non-local endpoints are refused by design"),
     not surveillance-shaped ("we monitored all traffic") — we do not monitor traffic, and must
     not imply we do.
3. **Backend: an attestation DTO** on the AI read surface (`GET /ai/engine`): model, runtime
   profile, endpoint host (host:port — never credentials), `endpoint_validated_local: true`,
   analyses count, last-analysis timestamp. Computed at read time; no new state.
4. **The strip is THE engine-status spot for this page** (ADR-0035 rule #4): no per-pane "AI
   active" chips elsewhere on the page; panes surface state only when degraded ("Rules-only mode
   · AI engine offline"). Click expands model details (the `/ai/models` list).

## Alternatives considered

- **A static marketing banner ("100% private AI")** — rejected: unprovable wording, the exact
  AI-washing failure mode; also violates the MI-8 claims checklist.
- **Network-monitoring-based attestation (count actual egress packets)** — rejected: out of
  product scope, platform-specific, and implies an observability the product doesn't have;
  config-enforcement attestation is honest and sufficient.
- **Putting the strip in the global app header** — rejected: the global header already carries
  the one engine status chip (ADR-0035 rule #4); the *attestation* (proof framing, counters,
  endpoint) is AI Engine page identity, not global chrome.

## Reasoning

- Claims discipline: substantiation-before-claim is both the internal rule
  (`docs/ai-claims-checklist.md`, MI-8) and the regulatory norm for advertising claims
  (FTC substantiation doctrine; EU AI Act Art. 50 transparency). Deriving each line from an
  enforcement point makes the strip audit-proof — an open-source reviewer can read
  `_is_local_address` and verify the sentence above it.
- Competitive: no major vendor markets pure local-first AI as a headline (competitive research
  §4); the strip is the launch screenshot that cannot be copied without changing their
  architecture.

## Out of scope

- Blanket whole-product zero-egress claims (air-gapped doc territory, ADR-0039/MI-4).
- Webhook/alert egress presentation (Settings concern).
- Cryptographic attestation (TPM/measured boot) — far beyond a single-box SOC's needs.

## References

- FTC advertising-substantiation doctrine (claims require a reasonable basis); EU AI Act Art. 50.
- OWASP API Top 10 2023 API8 (no credential leakage in the DTO — host:port only).
- Internal: ADR-0022 (guard), ADR-0035 (rule #4), ADR-0039, ADR-0042, ADR-0044;
  `docs/ai-claims-checklist.md`; `scratch/ai-analysis-suggestions.md` R4.
