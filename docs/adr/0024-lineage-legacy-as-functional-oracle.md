# ADR-0024: Codebase Lineage — `legacy/` is the FEATURE/UX Oracle ONLY (NOT a Behavioral/Classification Oracle), and Parity Means FEATURE Parity

**Date:** 2026-06-04
**Status:** Accepted

**Supersedes framing of:** the earlier draft of this ADR, which asserted that "v1-parity
doubles as the regression oracle (for behavior)." That framing is **withdrawn** — see Decision 2
and the Reasoning. The classification/regression oracle pins to the canonical standard, never to
legacy's classification outputs.

---

## Context

`packages/` is a clean-room realization of FireWatch v2's hexagonal vision as a modular plugin
architecture. `legacy/` (the previous version) is kept as a reference oracle. The open question
this ADR settles is **what kind of oracle `legacy/` actually is** — because the answer determines
what the golden/regression tests are allowed to pin to, and what "parity" means as a scope anchor.

New evidence gathered this session forces a sharper distinction than the earlier draft made:

- **`legacy/firewatch.db` inspection + `docs/research/azure-waf-log-standard.md`** show legacy's
  Azure WAF classification is **substandard, not a standard to reproduce**: empty `severity` on
  every Azure event, ~68% of events categorized `"Other"`, no MITRE/CAPEC, no OCSF. The legacy
  Azure normalization (`legacy/app/sync.py` `pull_azure_logs` + the Azure half of
  `legacy/core/normalizer.py`) is a confirmed **band-aid**: a lossy KQL projection that discards
  `ruleGroup`/`ruleSetVersion`/`transactionId`/`details.*`; an action map that collapses
  `Detected`/`Matched` into `BLOCK` (mislabelling non-terminating and detection-mode events as
  blocks, inflating block counts); fabricated `destination_port=80`/`protocol="TCP"` that Azure WAF
  logs do not even carry; and a broad `except Exception` that swallows auth/permission/schema errors
  as "no data."
- Even legacy **Suricata** category labels in the DB are **pre-canonical** — they predate ADR-0014
  (MITRE/CAPEC) and ADR-0020 (OCSF). The thing that is standards-correct is the **canonical
  `SecurityEvent`** produced by the *new* `normalize()` + core pipeline, proven by the 35 Suricata
  golden tests (#5), whose expected values were independently verified against
  `legacy/core/normalizer.py`'s category/severity/action maps — i.e. legacy informed the Suricata
  mapping *because that mapping happens to be standard-aligned*, not because legacy outputs are
  authoritative by default.

This means a single undifferentiated "v1-parity = the oracle" claim is wrong: it would license the
golden tests to pin to legacy's *classification* values, which for Azure are demonstrably broken and
for Suricata are pre-canonical.

---

## Decision

### 1. `legacy/` is the FEATURE / UX oracle ONLY — never a behavioral/classification oracle.

We mine `legacy/` exclusively for **what the product is and does** — which screens, endpoints,
request/response *shapes*, workflows, controls, KPIs, and views exist (catalogued in
`docs/v2-surface-inventory.md`). We do **NOT** mine it for **how to classify or normalize** —
i.e. never for severity/category/action/MITRE/OCSF *values*, and never for normalization logic.

Concretely:

- **Allowed to use legacy for:** the route inventory and response *envelope shapes* (e.g.
  `ThreatScore` / stats payload structure), the dashboard's 5-page structure, the source-card and
  faceted-filter UX, the auto-sync/test/sync controls — i.e. the feature surface.
- **NEVER use legacy for:** what `severity`/`category`/`action`/`ocsf_class`/`attack_technique` a
  given input should map to; the Azure normalization wiring; the band-aid behaviors enumerated in
  `docs/research/azure-waf-log-standard.md` §3. The Azure path in particular is **discarded
  wiring**, not a behavior to reproduce.

Its **architecture remains NON-AUTHORITATIVE** (already settled): the monolith wiring
(`app/main.py` as the app, `app/sync.py`, `app/config.py` process-global singletons, `app.state`
in-process task loops) is historical. `ARCHITECTURE.md`, `PLUGIN_CONTRACT.md`, and the accepted ADRs
always win, and `legacy/` is never imported into `packages/`.

### 2. "Parity" = FEATURE/UX parity on top of standards-correct classification — NOT classification parity.

The scope anchor stays **parity-first**, but parity is explicitly redefined:

- **Feature/UX parity (what we reproduce from legacy):** the v1 product's feature surface — every
  view, control, and endpoint a user relied on — re-expressed on the modular core. This is the
  risk-ordering principle for milestone sequencing (reproduce the proven surface before extending
  it).
- **Classification correctness (what we hold to the standard, NOT to legacy):** the
  golden/regression oracle pins normalized `SecurityEvent`s and `ThreatScore`s to the **canonical
  standard** — lightweight-OCSF (ADR-0020) + MITRE/CAPEC (ADR-0014) + action semantics (ADR-0012) —
  proven by the Suricata golden tests. **The oracle NEVER pins to legacy's classification outputs.**
  Where legacy and the standard agree (much of Suricata), the golden expectations are derived from
  the standard and *happen* to match legacy; where they disagree (all of Azure: empty severity,
  68% "Other", `Detected/Matched→BLOCK`), the standard wins and legacy is treated as a bug to
  *not* reproduce.

So: **same v1 *features* → same v1 *screens/endpoints*** (feature parity, legacy-anchored), but
**standards-correct logs → standards-correct scores** (classification correctness,
canonical-anchored). These are two different oracles and must not be conflated.

### 3. The aspirational cluster is built deliberately, not ported as monolith wiring.

The genuinely net-new subsystems behind the parity surface — a real config service (replacing
`FireWatchConfig` globals), supervisor-fronted sync controls (ADR-0023 / #22), the discovery +
schema-driven Settings UI, and the Azure WAF plugin **built to the new OCSF/MITRE standard** — are
designed deliberately as their own milestones (see `docs/roadmap-m3.md`), NOT ported as the
least-modular parts of the monolith.

---

## Alternatives considered

- **(Withdrawn) "v1-parity doubles as the regression oracle for behavior."** This was the earlier
  draft's framing. Rejected now because the evidence shows legacy's *classification* behavior is
  substandard (Azure band-aid: empty severity, 68% "Other", collapsed actions, fabricated fields)
  and pre-canonical (Suricata categories predate ADR-0014/0020). Pinning the regression oracle to
  "v1 behavior" would license reproducing those defects. The oracle must pin to the **canonical
  standard**; legacy's role is narrowed to *feature/UX* evidence.
- **(b) Full-v2 as a single deliverable.** Still rejected (unchanged from the prior draft): the v2
  surface splits into 13 WIRED / ~9 PARTIAL / 8 ASPIRATIONAL routes
  (`docs/v2-surface-inventory.md` §3); bundling the proven read paths with the config-service +
  supervisor-fronted-sync + Azure-plugin cluster is too large and tempts re-importing the
  global-singleton wiring.
- **(c) Treat legacy as fully non-authoritative (ignore it entirely).** Rejected: the *feature
  surface* legacy encodes is the proven product definition and the lowest-risk scope anchor. The
  fix is not to discard legacy, but to bound precisely what it is an oracle *for* (features/UX),
  versus what the published standards are the oracle for (classification).

---

## Reasoning

- **The two oracles have different sources of truth, so they must be separated.** Feature/UX is a
  product-definition question — legacy is the best available evidence for it. Classification is a
  correctness question against an external standard — OCSF/ECS/MITRE/OWASP are the evidence, and
  legacy's Azure path is a *counter-example* of how not to do it. Merging them under one "parity"
  banner is the category error this revision corrects.
- **The Suricata golden tests are not a counterexample to this split — they confirm it.** They pass
  because the new standard-aligned `normalize()` agrees with legacy's Suricata maps where those maps
  were already correct; their expected values were verified against the *standard*, and the v2
  extensions (`source_type`, MITRE, OCSF) were added as ADR-backed deltas, not copied from legacy.
- **The standards alignment for the surface we build (cited so the parity target is grounded):**
  - **OCSF / ECS** — normalized payloads (`SecurityEvent`, `ThreatScore`) align to the
    lightweight-OCSF model (ADR-0020); ECS frames source identity (`source_type`≈`event.module`,
    `source_id`≈`observer.name`). The classification oracle pins here, not to legacy.
    Refs: OCSF schema (`https://schema.ocsf.io/`); Elastic Common Schema
    (`https://www.elastic.co/elasticsearch/common-schema`).
  - **MITRE ATT&CK** — attack tagging targets ATT&CK techniques/tactics (ADR-0014); note ATT&CK v18
    (Oct 2025) renamed "Data Sources" → "Log Sources". Ref: `https://attack.mitre.org/`.
  - **OWASP API Security Top 10 (2023) + OWASP LLM Top 10** — the parity API introduces
    config-mutators and a webhook sink; designed against API1 (BOLA), API3, and SSRF guidance; the
    AI-analysis routes against the LLM Top 10 (prompt-injection delimiting already addressed by
    ADR-0022 / #16). **Legacy's "no auth" is a gap to decide, NOT a baseline to inherit.**
    Refs: `https://owasp.org/API-Security/editions/2023/en/0x11-t10/`;
    `https://owasp.org/www-project-top-10-for-large-language-model-applications/`.
  - **RFC 9110 (HTTP Semantics)** — REST tidy-up of the verb-y `/config/*` mutators and RPC-style
    `/sync*` routes is design input for the rebuild. Ref: `https://www.rfc-editor.org/rfc/rfc9110`.
  - **12-Factor** — config as an externalized service (Factor III) replaces `FireWatchConfig`
    globals; this is *why* the config service is a deliberate net-new milestone, not a port.
    Ref: `https://12factor.net/`.
  - **ADR-0019** governs the UI stack (React/Vite/TS/rjsf); this ADR only sets the scope order
    (feature-parity views) and the classification-correctness bar, not the stack.

---

## Consequences

- `docs/roadmap-m3.md` is sequenced as **goal-oriented vertical slices** (base infra → Suricata
  end-to-end → Azure-WAF-to-standard), with exit criteria stated as demoable outcomes, not
  horizontal layers (see that doc).
- The golden oracle's remit is **classification correctness against the canonical standard** plus
  **feature/UX-parity response shapes** — but it must NOT assert legacy's broken/pre-canonical
  classification values. New Azure golden fixtures are built to the OCSF/MITRE standard
  (`docs/research/azure-waf-log-standard.md` §4), never recorded from the legacy band-aid.
- **Follow-up code correction (flagged here, implemented later):** the SDK field comment at
  `packages/firewatch-sdk/src/firewatch_sdk/models.py:79` says `ocsf_class` "e.g. 6004 = Web
  Resources Activity". WAF must normalize to **OCSF HTTP Activity (`class_uid = 4002`,
  `category_uid = 4`)** per `docs/research/azure-waf-log-standard.md` §2a. The stale 6004 comment
  is the same outdated mapping the legacy normalizer baked in and must be corrected (small code
  issue, not done by the architect). See the new DB-contract ADR and `docs/module-author-guide.md`.
- "No auth in legacy" is treated as a gap to decide (its own ADR), not a baseline to inherit.

---

## References / standards consulted

- OCSF schema; Elastic Common Schema (ECS); MITRE ATT&CK (v18, "Log Sources").
- OWASP API Security Top 10 (2023); OWASP Top 10 for LLM Applications.
- RFC 9110 (HTTP Semantics); The Twelve-Factor App.
- Internal: `docs/v2-surface-inventory.md`, `docs/research/azure-waf-log-standard.md`,
  `docs/research/db-modularity-best-practices.md`, ADR-0012, ADR-0014, ADR-0016, ADR-0019,
  ADR-0020, ADR-0022, ADR-0023, and the Suricata golden tests (#5).
