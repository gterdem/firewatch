# ADR-0026: API Authentication / Authorization Posture — Loopback-Default, Optional API Key, Per-Route-Class Gating

**Date:** 2026-06-04
**Status:** Accepted

> **Amendment (2026-06-13) — enforce-when-set clarification:** Decisions 1–4 were keyed on
> *binding* and were silent on one corner: **a configured `api_key` while still on loopback.**
> That corner is now settled as **enforce-when-set** — a configured key is enforced on **all**
> requests regardless of bind address; the loopback no-auth exemption applies **only when no key
> is set**. See the full "[Amendment 1 (2026-06-13)](#amendment-1-2026-06-13--enforce-when-set-the-configured-key-corner)"
> section below for rationale and the 2×2 truth table.

**Relates to:** ADR-0006 (config precedence: env > file > default; `SecretStr`),
ADR-0019 (frontend stack — the React shell that talks to this API),
ADR-0022 (local-first invariant; `base_url` must resolve loopback/LAN, not cloud),
ADR-0023 (collector supervisor — resilience seams), PLUGIN_CONTRACT.md.
**Implements / gates:** MA.2 config service (#31), MA.3 discovery endpoint (#32),
MA.4 Settings UI (#33) — all of which ship **loopback-only** and defer auth to *this* ADR;
this ADR is the prerequisite for any **non-loopback** exposure introduced in the Suricata (MB) milestone.
**Standards consulted:** OWASP API Security Top 10 (2023), OWASP Top 10 for LLM Applications (2025),
RFC 9110 (HTTP semantics) + RFC 6750 (Bearer scheme), The Twelve-Factor App (config),
NIST SP 800-52r2 (TLS at the reverse-proxy edge).

---

## Context

MA introduces FireWatch's first real HTTP API surface: a config service write side
(`PUT /config/*`, per-source config validated against each plugin's `config_schema()`, #31), a
plugin **discovery** endpoint (`GET /sources/types`, #32), and the React Settings UI that consumes
them (#33). MB will add read/analyze surfaces (logs, scores, source instances) and the
webhook/alert sink. The MA issues each carry the same explicit deferral: *"API authn/authz —
ADR-0026 (pending); loopback-only for MA, no off-host exposure until settled."* This ADR settles
that posture and answers the roadmap's open question:

> **Does auth gate the read/analyze API, or only the config-mutating routes?**

FireWatch's product ethos is **local-first / single-host SOC** (ADR-0022): inference and data stay
on hardware the operator controls. The common deployment is one analyst on one box. We must not
bolt enterprise IAM onto that default, but we must have a credible, standards-grounded story the
moment the API is reachable beyond `127.0.0.1` (reverse proxy, LAN, MB's exposed ingestion).

### Route risk classes (OWASP API Security Top 10, 2023)

| Class | Routes (current + planned) | Primary risk | OWASP item(s) |
|---|---|---|---|
| **A. Config-mutating** | `PUT /config/*`, per-source config writes (#31) | tamper with thresholds, AI `base_url`, webhook URL → blunt detection / pivot | **API5** broken function-level authz, **API1** BOLA, **API3** broken object-property authz |
| **B. Action-triggering** | webhook/alert sink (operator-set destination URL); future test/sync buttons; ADR-0015 active-response | **SSRF** via attacker-influenced outbound URL; unauthorized side effects | **API7** SSRF, **API5**, **API6** unrestricted access to sensitive business flows |
| **C. Read / analyze** | `GET /sources/types` (#32), logs/scores/instances (MB), AI-analysis read paths | discloses threat data + topology (sensitive) but **read-only**, no state change | **API2** broken authentication, **API1** BOLA (object reads), **API4** resource consumption |

The asymmetry is the crux: classes **A** and **B** can *change FireWatch's behavior or make it act*
(including act outbound), so they are the higher-impact surface; class **C** *discloses* data but
cannot mutate or pivot. OWASP's two most-impactful 2023 categories are precisely the authorization
ones (API1 BOLA, API5 function-level authz) — both concentrated in A/B.

---

## Decision

**Posture is a function of *binding*, with per-route-class minimums when exposed.**

1. **Default (MA, single-host): loopback bind, no application auth.** The API binds `127.0.0.1`
   only. The trust boundary is the host OS / loopback interface, not an app credential. This is the
   MA Base-Infrastructure default and is what #31/#32/#33 ship against. No API key is required to
   run FireWatch locally — the local-first, zero-friction path is preserved (RFC 9110 §11: absence
   of `Authorization` is legitimate when the resource is not access-controlled; here access control
   is delegated to the network boundary).

2. **Optional built-in API key (the lightweight exposed-beyond-loopback option).** A single
   configurable shared secret (`api_key: SecretStr`, ADR-0006 / 12-Factor III), **constant-time
   compared** (`hmac.compare_digest`), supplied by the client as a bearer-style credential over the
   `Authorization` header (RFC 9110 §11.6.2). It is **off by default** and **must be set** before
   the bind address is anything other than loopback.

3. **Gate per route class when exposed (answering the open question):**
   - **A (config-mutating) and B (action-triggering): MUST be authenticated whenever the API is
     non-loopback. Non-negotiable minimum.** No unauthenticated write or action-trigger is ever
     served off-host.
   - **C (read/analyze): also gated when exposed.** Recommendation: **gate reads too — do not leave
     C open.** See "Gate reads too, or only mutations?" below.
   - **Therefore: when bound non-loopback, the API key gates *all* routes (A+B+C), with A and B the
     hard floor that may never be relaxed.** A "read-only, no key" exposed mode is **not** offered
     as a default; if a future operator wants it, it must be an explicit, documented opt-in that
     still keeps A and B authenticated (and is out of scope here).

4. **Fail-closed binding guard.** Startup MUST refuse to bind a non-loopback address while
   `api_key` is unset (analogous to ADR-0022's local-first `base_url` guard). Misconfiguration
   fails loudly at boot, not silently at first request.

5. **Reverse-proxy termination is the recommended production path for anything public.** TLS
   termination + authentication/SSO at an nginx / Caddy / oauth2-proxy layer is the recommended
   posture for public exposure; the built-in API key is the *lightweight LAN / behind-trusted-proxy*
   option, not a substitute for a hardened edge. FireWatch ships HTTP (plaintext) on loopback by
   design; TLS is the proxy's job (NIST SP 800-52r2 applies at the edge).

6. **SSRF control on the webhook sink (class B) is independent of auth and always on.** The
   operator-configured webhook/alert URL is validated/constrained regardless of whether a request is
   authenticated (OWASP API7): scheme allowlist, block link-local/loopback/metadata ranges
   (169.254.0.0/16, 127.0.0.0/8, ::1, cloud metadata 169.254.169.254) unless explicitly permitted,
   no unbounded redirect following. Auth limits *who* can set the URL; SSRF hardening limits *where*
   it can point. Both are required.

7. **AI-analysis routes (class C) inherit the C posture; prompt-injection is already handled.** The
   LLM threat (OWASP LLM01 indirect prompt injection) is mitigated at the analysis layer by
   ADR-0022 / #16 NB-1 (delimit + schema-validate + additive-only), **not** by this ADR. This ADR
   only governs *who may call* those routes (gated when exposed); it does not re-litigate prompt
   safety.

8. **Deferred — explicitly out of scope (future milestone):** multi-user accounts, SSO/OIDC, RBAC,
   per-object authorization (true API1 BOLA scoping across tenants), session management, audit-log
   of auth events, secret backends beyond `SecretStr`/env (Vault/KMS — MD+ per #31). This ADR
   deliberately stops at single-shared-secret because the product is single-host single-analyst
   today; richer IAM is a later ADR when multi-user lands.

---

## "Gate reads too, or only mutations?" — the recommendation

**Recommendation: when the API is exposed beyond loopback, gate reads as well — the API key
protects A, B, *and* C. The config-mutating (A) and action-triggering (B) classes are the
non-negotiable floor; the read/analyze class (C) is also gated by default.**

Why not "writes/actions only, reads open":

- **The read surface is genuinely sensitive.** Class C exposes scored threat events, source IPs,
  attack categorization, and network topology — this is exactly the data the local-first invariant
  (ADR-0022) exists to keep on the operator's hardware. Disclosing it to anyone who can reach the
  port contradicts that posture. OWASP API2 (broken **or missing** authentication) — together with
  API1 (object disclosure on reads) — makes an unauthenticated sensitive read endpoint a finding in
  its own right.
- **An open read surface is an enumeration / object-disclosure (API1 BOLA) and resource-exhaustion
  (API4) surface** even with writes locked. Threat-intel and topology leak through reads alone.
- **One credential, one mental model.** A "reads are open, writes need a key" split is a classic
  source of API5 (broken function-level authz) mistakes — a route mis-classified as read when it has
  a side effect (e.g. a "test connection" GET that actually dials out is really class B). Gating
  everything removes that footgun; route-class minimums then only ever *tighten*, never open a hole.
- **Cost is ~zero.** With loopback as the default, the local single-analyst path pays nothing
  (no key needed). The "gate everything" rule only bites once the operator has *chosen* to expose
  the API — at which point uniform auth is the safe default and matches what the reverse-proxy path
  would enforce anyway.

So: **A and B are the hard, never-relaxable minimum; C is gated too by default.** A read-only
exposed-without-key mode is not part of this decision (it would require an explicit future opt-in
that still keeps A+B authenticated).

---

## Amendment 1 (2026-06-13) — enforce-when-set: the configured-key corner

**Status: Accepted (clarification, not a reversal).** Decisions 1–4 are unchanged; this amendment
resolves a corner they left under-specified.

### The corner that was ambiguous

The original Decisions 1–4 frame the posture as "a function of *binding*" (loopback vs not). That
framing answers three of the four cells of the (key set?) × (loopback?) matrix but is silent on the
fourth — **a key is configured *and* the bind is still loopback.** Two readings were possible:

- **(a) bind-conditional / dormant-on-loopback:** loopback is always no-op, even with a key set; the
  key only "wakes up" when the bind leaves loopback.
- **(b) enforce-when-set:** a configured key is enforced everywhere, including loopback; the
  loopback no-auth exemption applies *only when no key is set*.

**Decision: (b) enforce-when-set.** A configured `api_key` is enforced on **all** requests
regardless of bind address. The loopback no-auth exemption (Decision 1) is conditioned on **no key
being set** — it is the *absence of a credential* that delegates control to the network boundary,
not the loopback bind by itself.

### Resolved truth table

| `api_key` | bind | behavior | source |
|---|---|---|---|
| unset | loopback | **open** — network boundary is the control | Decision 1 (unchanged) |
| unset | non-loopback | **refuse to start** — fail-closed guard | Decision 4 (unchanged) |
| **set** | **loopback** | **ENFORCED** | **this amendment (newly clarified)** |
| set | non-loopback | **enforced** | Decisions 2–3 (unchanged) |

Only the third row is new; the other three are restatements of the original decisions.

### Why enforce-when-set (cited)

- **No surveyed self-hosted tool silently ignores a *configured* credential based on bind
  address.** The "bind-conditional" tools (Redis protected-mode, Ollama, Docker TCP socket) skip
  auth on loopback only when **no** credential is set; the moment one is configured (e.g. Redis
  `requirepass`) it is enforced everywhere, loopback included. The always-enforce tools (Jupyter,
  Grafana, n8n, Home Assistant, Portainer, MongoDB, Elasticsearch) enforce a configured credential
  regardless of bind. "Configured credential + dormant on loopback" is a pattern **no surveyed tool
  exhibits**. (Competitive research: `docs/research/api-auth-loopback-conventions-2026-06-13.md`.)
- **OWASP secure-by-default + "do not silently ignore configured credentials" + Principle of Least
  Astonishment + NIST SP 800-63B** all point the same way: a credential the operator deliberately
  set must be validated and enforced consistently, not silently accommodated based on bind address.
  An operator who sets a key reasonably expects it to be active. (Standards already cited in this
  ADR's references; see also the OWASP Authentication Cheat Sheet and NIST SP 800-63B Rev. 4.)
- **Internal consistency with this ADR's own philosophy.** The "Gate reads too, or only mutations?"
  section rejects conditional auth modes precisely because a "this is gated, that isn't" split breeds
  **API5** (broken function-level authz) mis-classification footguns. "Key set but dormant on
  loopback" is exactly such a conditional special-case (auth state depends on a second axis, the
  bind). Enforce-when-set is the option that matches the ADR's stated preference for one credential,
  one mental model — auth state depends only on "is a key set?", never additionally on "where are we
  bound?".
- **Security-product footgun (option (a) is the false-confidence pattern).** Dormant-on-loopback is
  the "I set a key, so I'm covered" trap behind the Redis / MongoDB / Docker mass-exposure incidents
  (60k+ Redis, 87k+ MongoDB): a control that *looks* configured but is not actually exercised until
  the moment of exposure. Enforce-when-set means the key is proven working from request #1 — the
  operator exercises it the instant they set it, on loopback, before any exposure — rather than
  discovering at exposure time that their dashboard/clients were never actually sending it. For a
  security product whose first impression matters (pre-open-source), shipping the false-confidence
  pattern would be self-undermining.

### Why not (a) — and why this is a clarification, not a reversal

Option (a) was never *stated* by Decisions 1–4; it was one of two ways to read their silence. Picking
(b) does not contradict any accepted decision — Decision 1's exemption is now read as conditioned on
"no key set" (which is the only state in which it was ever exercised in MA, since MA shipped no key).
The original framing "a function of binding" is refined to "a function of *whether a credential is
configured*, with binding governing the fail-closed guard" — a sharpening, not an overturn.

A future explicit **opt-out** (PostgreSQL/MySQL-style OS-level peer auth as a deliberate,
documented alternative to the api_key for local-only deployments) remains available if ever wanted —
that is *explicit opt-out*, the opposite of *silent dormancy*, and is out of scope here.

### Implementation & UX impact (forward references)

- **#548 (MP.3) — middleware.** The auth dependency enforces: **key set ⇒ gate all routes
  regardless of bind**; loopback no-op applies **only** when no key is set. The `auth/posture.py`
  policy keys on `api_key is not None` first, bind second. (#548's "Open question" is hereby
  answered: option (b); its EARS criterion on the loopback-with-key case is updated to require
  enforcement.)
- **#550 (MP.5) — SPA bearer + honest UX.** The SPA auto-attaches the bearer from the same Settings
  config the operator already uses (no login screen; the human enters the key once and it is reused
  via `buildHeaders()`). Two honesty affordances:
  - **One-time notice on first key-set while on loopback:** "API key now active — required on every
    request including this dashboard; used automatically." (Makes the enforce-on-loopback behavior
    non-astonishing.)
  - **Honest empty state when no key is set:** "No key set — protected by the loopback boundary
    only; set a key before exposing." (Names the actual control so the operator isn't lulled.)

This amendment makes the enforce-when-set behavior the *single* source of truth; #548/#550 issue
text is reconciled to it.

---

## Alternatives considered

- **Mandatory auth always, even on loopback (enterprise-default).** Rejected for the MA default: it
  taxes the single-host local-first experience (ADR-0022) with credential management for a surface
  whose only reachable client is the same machine. The loopback boundary is a legitimate access
  control (RFC 9110 §11). Auth becomes mandatory the instant the bind leaves loopback (Decision 1–4).
- **Build SSO/OIDC + RBAC now.** Rejected (YAGNI / scope). The product is single-analyst,
  single-host today; multi-user authorization (real API1 object-scoping) has no consumer yet.
  Premature IAM is complexity with no tenant to serve. Deferred to a future ADR (Decision 8).
- **Gate only the config-mutating routes; leave reads open when exposed.** Rejected as the default —
  see the section above: the read surface is sensitive threat/topology data, an open read surface is
  an API1/API2/API4 finding, and the read/write split invites API5 mis-classification. A and B stay
  the hard floor, but C is gated too.
- **App-managed TLS instead of a reverse proxy.** Rejected as the *recommended* public path: TLS
  cert lifecycle, OCSP, cipher policy (NIST SP 800-52r2) are better handled by a dedicated edge
  (nginx/Caddy/oauth2-proxy), which also offers SSO when multi-user arrives. FireWatch serves HTTP
  on loopback and lets the proxy terminate TLS + (optionally) auth. The built-in key is the
  lightweight LAN option, not an edge replacement.
- **Per-route bespoke tokens / scopes now.** Rejected as over-engineering for a single shared
  secret; scopes belong with the deferred RBAC work, not the single-key built-in.
- **Bind-conditional / dormant-on-loopback key (option (a) — a configured key stays inert on
  loopback).** Rejected by Amendment 1 (2026-06-13): no surveyed tool silently ignores a configured
  credential by bind address, it violates OWASP secure-by-default / least-astonishment / NIST
  SP 800-63B, it contradicts this ADR's own anti-conditional-auth stance (API5 footgun), and it is
  the "I set a key so I'm covered" false-confidence pattern behind the Redis/MongoDB/Docker
  mass-exposure incidents. See Amendment 1 for the full reasoning. Enforce-when-set adopted instead.

---

## Reasoning

- **OWASP API Security Top 10 (2023) ranks the authorization failures highest** — API1 (BOLA) and
  API5 (broken function-level authorization) are #1 and #5, and both concentrate on routes that
  *act on objects or invoke privileged functions*, i.e. our classes A and B. Making A/B the
  non-negotiable authenticated floor targets the highest-impact categories directly. API7 (SSRF)
  motivates the always-on webhook URL hardening independent of auth. ([OWASP API Top 10 2023][owasp-api])
- **OWASP API2 (broken authentication) + the sensitivity of read data** justify gating C too rather
  than leaving an open read surface — disclosing scored threats / source IPs / topology to any
  reachable client is itself the finding. ([OWASP API2][owasp-api2])
- **OWASP Top 10 for LLM Applications (LLM01)** is already mitigated for the AI-analysis routes by
  ADR-0022 / #16 NB-1 (delimit + schema-validate + additive-only); this ADR cites it to scope it
  *out* (access control here, prompt safety there) rather than duplicate it. ([OWASP LLM Top 10][owasp-llm])
- **RFC 9110** gives the HTTP semantics we rely on: §11 authentication framework, §11.6.2
  `Authorization` request header for the bearer-style key, and the principle that a resource not
  under access control legitimately needs no credential — which is what makes the loopback default
  standards-clean rather than a shortcut. ([RFC 9110 §11][rfc9110])
- **The Twelve-Factor App (III. Config)** dictates the key lives in config/env as a secret, never in
  code — `SecretStr` per ADR-0006, constant-time compared, never logged. ([12-Factor III][twelve])
- **Local-first deviation, recorded:** FireWatch deliberately ships *no* application auth on the
  default loopback bind. The justification is the single-host SOC ethos (ADR-0022) and a legitimate
  network trust boundary (RFC 9110); the fail-closed binding guard (Decision 4) ensures the
  deviation cannot silently follow the API off-host.

---

## Consequences

- **MA (#31/#32/#33) is unblocked as-is:** they ship loopback-only with no auth (their stated
  assumption). The config service (#31) already models secret fields as `SecretStr`; `api_key` is
  one such field.
- **Config model gains** `api_key: SecretStr | None = None` and `bind_address` (default
  `127.0.0.1`), resolved env > file > default (ADR-0006). Startup adds the fail-closed guard:
  non-loopback bind with unset key ⇒ refuse to start.
- **`firewatch-api` (the package from #32)** gains a single auth dependency/middleware: no-op on
  loopback-without-key; constant-time bearer check on A+B always-when-exposed and on C-when-exposed.
  Route classification (A/B/C) is declared per route so a side-effecting "GET" cannot be mis-served
  as open read.
- **Webhook sink (class B, MB)** carries always-on SSRF hardening (scheme allowlist + private/
  metadata-range block + no unbounded redirects), independent of auth.
- **MB exposure gate:** any non-loopback ingestion/read exposure in the Suricata milestone is
  blocked on this ADR being Accepted and the key + guard implemented.
- **Settings UI (#33, ADR-0019):** no login UI in MA (loopback). A minimal "API key" field /
  attach-bearer behavior is needed only when exposed; full auth UI is deferred with the IAM work
  (Decision 8).
- **A future ADR** supersedes/extends this for multi-user SSO/OIDC + RBAC + per-object (BOLA)
  authorization + auth audit logging when multi-user lands.

---

## References / standards consulted

- OWASP API Security Top 10 (2023) — API1 BOLA, API2 broken authentication, API5 broken
  function-level authorization, API7 SSRF: [owasp-api][owasp-api], [API2][owasp-api2].
- OWASP Top 10 for LLM Applications (LLM01 prompt injection — mitigation owned by ADR-0022/#16):
  [owasp-llm][owasp-llm].
- RFC 9110 (HTTP Semantics) — §11 authentication, §11.6.2 `Authorization`: [rfc9110][rfc9110]. The
  literal `Bearer` scheme (if used) is defined by [RFC 6750][rfc6750], not RFC 9110.
- The Twelve-Factor App — III. Config (secrets in env): [twelve][twelve].
- NIST SP 800-52r2 (TLS configuration — applies at the reverse-proxy edge): [nist-tls][nist-tls].
- Internal: ADR-0006, ADR-0019, ADR-0022, ADR-0023; issues #31, #32, #33; PLUGIN_CONTRACT.md.

[owasp-api]: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
[owasp-api2]: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
[owasp-llm]: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
[rfc9110]: https://www.rfc-editor.org/rfc/rfc9110#section-11
[rfc6750]: https://www.rfc-editor.org/rfc/rfc6750
[twelve]: https://12factor.net/config
[nist-tls]: https://csrc.nist.gov/pubs/sp/800/52/r2/final
