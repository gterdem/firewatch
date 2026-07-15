# ADR-0066: Honest AI State Model — Administrative vs Operational State, One Closed `ai_status` Vocabulary

**Date:** July 2026
**Status:** Proposed (refines ADR-0022's enforcement point and ADR-0035 §4's wording; supersedes nothing)

**Context:** Maintainer report: the AI status surfaces collapse "deliberately off" into "broken."
Verified against the code, the problem is wider — the same concept is expressed in five
divergent dialects, and choice/fault conflation appears at four independent sites:

1. `Pipeline.analyze_ip` (concise) stamps `disabled`/`active`/`unavailable`; `analyze_ip_detailed`
   stamps `skipped`/`unavailable`/engine-`ok` — two paths, two dialects, one file.
2. The detailed path stamps `unavailable` (a fault) whenever `ai_will_run` is false — including
   when the operator deliberately disabled AI (`_DisabledAIEngine`, the rules-only profile).
   A user who chose rules-only is told their AI is broken (found live in PR #36-era testing of
   the `rules-only` profile; blocks issue #4's honesty criterion).
3. The concise path stamps `active` when sampling yields **no input** and the engine was never
   invoked — success claimed for a call that never happened (the opposite ADR-0035 violation).
4. `GET /health` probes the inference endpoint **unconditionally** (never consults `ai_enabled`)
   and reports only a boolean `ollama_connected` — so "off by choice" and "down" are
   indistinguishable there too, and a rules-only box dials an endpoint the user said doesn't exist.
5. The pipeline factory maps *engine construction failure while AI is enabled* to a
   `disabled`-reporting engine — a fault labeled as a choice (the inverse of defect 2). Relatedly,
   the ADR-0022 config validator DNS-resolves `ollama_base_url` at config-parse time and fails
   closed even when `ai_enabled=false`, crashing the rules-only profile at startup (worked around
   in docs by PR #37).

Plus dead vocabulary: `AIStatusLiteral` declares `degraded`, which nothing produces.

**Decision:** Model AI state on **two layers**, mirroring RFC 2863's interfaces-MIB split between
`ifAdminStatus` (what the operator chose) and `ifOperStatus` (what is operationally true) — the
long-settled industry pattern for exactly this distinction ("admin down" is a choice an operator
reads differently from a failure):

**Layer 1 — engine state** (component-level, on `GET /health`, additive field `ai`):

| value | meaning to the user |
|---|---|
| `active` | AI is on and the engine answered the probe |
| `disabled` | AI is off because you turned it off — nothing is wrong |
| `unreachable` | AI is on but the engine cannot be reached — go fix something |

When `ai_enabled=false`, `/health` MUST NOT dial the inference endpoint (an off subsystem is
inert) and reports `disabled`. `ollama_connected` (bool) is retained for compatibility,
`true` iff `ai == "active"`, documented as deprecated.

**Layer 2 — per-analysis outcome** (`ai_status` on every analysis payload — the analog of ECS
`event.outcome`, "success or a failure from the perspective of the entity that produced the
event", extended with *why-not-attempted*). ONE closed vocabulary, both pipeline paths, all
API surfaces:

| value | meaning to the user | kind |
|---|---|---|
| `active` | the AI engine analyzed this and produced a verdict | success |
| `disabled` | AI is turned off in your config; rules scored this | choice (operator) |
| `skipped` | this request asked for rules-only (`ai=false`) | choice (caller) |
| `no_input` | there was nothing to send to the AI; rules scored this | non-event |
| `unavailable` | AI was wanted but the engine failed or was unreachable | **fault — the only state that means "go fix something"** |

Stamping truth table (single authority — one pure function used by both paths, replacing the
two divergent stamping sites): caller opted out → `skipped`; else AI administratively off →
`disabled`; else engine unreachable/errored → `unavailable`; else no samples to analyze →
`no_input`; else engine ran → `active` (the engine envelope's internal `ok` discriminator maps
to `active` at this boundary and never reaches a client).

Supporting decisions:
- `degraded` is removed from `AIStatusLiteral` (dead, never produced).
- The `AIEngine` port's envelope `ai_status` (`"ok"`/`"unavailable"`) remains an **internal
  shape discriminator** for schema validation (ports.py contract, unchanged); persisted ledger
  rows keep their recorded values and read routes map `ok → active` — no data migration.
- Backend consumers stop enumerating not-run states (`ai_status not in ("unavailable",
  "skipped", "disabled")` — which would silently misread `no_input` as "AI ran") and branch
  positively on `active`.
- **Inertness principle** (the root cause of defects 4–5 and the PR #37 crash): when
  `ai_enabled=false`, no AI-subsystem code may run, dial, validate, or crash. Consequently the
  ADR-0022 `ollama_base_url` config validator becomes **pure/syntactic** (scheme + IP-literal
  locality checks; NO DNS resolution at config time) — the same rationale this codebase already
  applies to the webhook validator ("a validator must stay pure/fast, and resolution is itself
  a TOCTOU vector"). The *resolving* local-first egress check moves entirely to the dial
  boundary (`OpenAIEngine` construction/first use), which only exists when AI is enabled. This
  refines ADR-0022's "rejected at config-write time" line; the egress invariant itself is
  unchanged and still enforced before any byte leaves the box.
- Construction failure while `ai_enabled=true` is a **fault**: the factory fallback reports
  `unavailable` (admin-up, oper-down), never `disabled`.
- Presentation (refines ADR-0035 §4's single "Rules-only mode · AI engine offline" wording,
  which conflated the two): `disabled` renders neutral/non-alarming ("AI off · rules-only" —
  a choice is never an error); `unavailable` renders as attention-worthy but not critical
  ("AI unreachable · rules-only" — detection is unaffected, ADR-0015 floor); `active` renders
  live/green. `skipped`/`no_input` are per-analysis annotations only, never the global chip.

**Alternatives considered:**
- **One merged `off` state + a `reason` field** — rejected: every consumer switch becomes a
  two-field decode; the membership-check bug class (threats.py/cases.py) gets worse, not
  better; and `skipped` is already load-bearing in the fast-path API contract.
- **Boolean `ai_ran`** — rejected: loses choice-vs-fault, which is the entire complaint; same
  shape as the `ollama_connected` boolean that produced defect 4.
- **Drop `no_input` (stamp `skipped` or keep `active`)** — rejected: `active` is a success
  claim for a call that never happened (ADR-0035); `skipped` asserts a caller choice the
  caller didn't make. The state is real (sampling can legitimately produce nothing) and the
  frontend already default-branches unknown values to "did not run", so it degrades safely.
- **Fix only the detailed path (minimum for issue #4)** — rejected: leaves the concise/detailed
  dialect divergence and the `active`-on-no-input lie in place; three more local patches is the
  exact anti-pattern ADR-0035 was written against.
- **Keep the validator failing closed on DNS** — rejected: it crashes a legitimate profile at
  startup for a URL that will never be dialed, is inconsistent with the repo's own webhook
  validator TOCTOU stance, and adds a startup-order fragility even for AI-enabled compose
  stacks. The check that matters (no telemetry egress to non-local endpoints) lives at the dial
  boundary regardless.

**Reasoning:** The governing principle is ADR-0035 honesty applied consistently: never claim
success when nothing ran; never claim a fault when nothing is broken. The industry grounding
is verified, not assumed: RFC 2863 (IF-MIB) separates administrative from operational state
precisely because operators must distinguish "I turned it off" from "it broke" —
`ifOperStatus` even documents the interaction rule ("If ifAdminStatus is down(2) then
ifOperStatus should be down(2)"), and network tooling universally surfaces "admin down" as a
distinct, non-alarming condition. ECS `event.outcome` (success/failure/unknown) is the
per-event outcome analog; OCSF findings carry the equivalent `status`/`status_id`
success-failure enums (FireWatch's OCSF export surface is pinned by ADR-0040). **Deliberate
deviation:** neither ECS nor OCSF defines per-event vocabulary for *why an optional analytic
stage was not attempted* (deliberately off vs caller-skipped vs no input) — we add the three
not-attempted states because rules-only is a first-class product profile (D5 / issue #4 /
ADR-0042), not an error condition, and because "detection is identical everywhere; AI is
additive" (ADR-0015) is the product's core honesty claim. At the OCSF export boundary these
states simply mean no `Learning`-type analytic is attached (ADR-0035's mapping) — nothing to
translate, no export change.

**Consequences:**
- Three issues implement this: core/SDK/API vocabulary + stamping authority (blocks issue #4's
  second acceptance criterion); config/factory inertness (retires PR #37's loopback-URL
  workaround); frontend three-state presentation.
- `tests/golden` is untouched: `ai_status` feeds no scoring input (`run_rules`/`detect`/
  `merge_score` are status-blind); this is relabeling of report fields only. Any golden diff is
  a defect in the change, not a re-blessing event.
- Plugin authors: no impact. `AIEngine` is implemented by core only; `SecurityEvent`/`RawEvent`
  and the source-plugin contract carry no `ai_status`. No PLUGIN_CONTRACT version bump.
- Client contract: `no_input` is a new wire value and `disabled` newly appears on the detailed
  endpoint. The shipped TS client's `AiStatus` union is open (`| string`) and its consumers
  default unknown values to "did not run", so nothing breaks at compile or render time; the
  backend membership checks are corrected in the same change. Third-party consumers get the
  vocabulary documented on the response schemas.

**References (verified live for this ADR):**
- RFC 2863 (The Interfaces Group MIB) — `ifAdminStatus` / `ifOperStatus`,
  https://www.rfc-editor.org/rfc/rfc2863.txt
- Elastic Common Schema — `event.outcome`,
  https://www.elastic.co/docs/reference/ecs/ecs-event
- OCSF analytic/finding status alignment per ADR-0035 / ADR-0040 (export surface pinned 1.8.0).
- In-repo: `firewatch_core/pipeline.py` (both stamping sites), `firewatch_sdk/models.py`
  (`AIStatusLiteral`), `firewatch_sdk/config.py` (validator + webhook TOCTOU precedent),
  `firewatch_cli/commands/_pipeline_factory.py` (`_DisabledAIEngine`, fallback),
  `firewatch_api/routes/meta.py` (`/health` probe), ADR-0015/0022/0035/0042.
