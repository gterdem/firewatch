# OWASP API Security Top 10 (2023) — FireWatch Baseline Sweep

**Date:** 2026-06-13
**Milestone:** MP — API Auth + OWASP-API baseline (exit gate, issue #NNN)
**Scope:** the FireWatch HTTP API surface (`packages/firewatch-api`) plus the
outbound webhook sink (`packages/firewatch-core/.../webhook_notifier.py`) and the
anti-SSRF config validator (`packages/firewatch-sdk/.../config.py`).
**Implements:** ADR-0026 (API auth posture) reasoning.

This is the documented checklist pass that gates **non-loopback exposure** and the
open-source announcement. It assesses + documents; it does **not** implement fixes
(real gaps become follow-up issues — see the API4 row).

## Standards cited (reused from ADR-0026 references)

- **OWASP API Security Top 10 (2023)** — the category model itself.
  <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- **RFC 9110 (HTTP Semantics) §11** — authentication framework; §11.6.2
  `Authorization`; §15.5.14 `413 Payload Too Large`; the principle that a resource
  not under access control legitimately needs no credential (loopback default).
- **RFC 6750 (Bearer scheme)** — §2.1 token format; §3 `WWW-Authenticate` on 401.
- **The Twelve-Factor App — III. Config** — the key/secret lives in env/config as a
  secret (`SecretStr`), never in code.
- **NIST SP 800-52r2** — TLS configuration; applies at the reverse-proxy edge
  (FireWatch ships HTTP on loopback by design; TLS is the proxy's job, ADR-0026 D5).
- **NIST SP 800-63B §5.2.7** — verifiers shall not disclose timing information
  (motivates the constant-time `hmac.compare_digest`).

## BLOCKER status: NONE

The API9 route inventory below was built by walking `app.routes` and reading the
`_fw_route_class` attribute stamped by `wire_auth`. **No class-A (config-mutating)
or class-B (action-triggering) route is served unauthenticated when a key is set.**
The middleware (`auth/middleware.py::AuthMiddleware.dispatch`) gates **all** routes
uniformly the moment a key is configured (enforce-when-set, ADR-0026 Amendment 1) —
A and B are the never-relaxable hard floor (ADR-0026 D3). Inventory: 65 routes,
**0 unclassified**, 4×A, 11×B, 50×C. The coverage invariant is enforced by
`test_all_routes_have_route_class` (`tests/test_auth_548.py`).

---

## The baseline — one row per API1–API10

| # | Category | Status | Evidence pointer |
|---|----------|--------|------------------|
| **API1** | Broken Object Level Authorization (BOLA) | **deferred-with-ref** | Single-analyst / single-host today; no multi-tenant object boundary exists, so there is no per-object scope to enforce. Reads are gated **wholesale** when a key is set (no object-scoped authz). True per-object BOLA is **ADR-0026 Decision 8** (future IAM ADR). Wholesale read gating verified by `test_key_set_no_bearer_class_c_is_401` (`tests/test_auth_548.py`). |
| **API2** | Broken Authentication | **covered** | Constant-time `hmac.compare_digest` on **all** paths (Django UNUSABLE_PASSWORD pattern) — `auth/credential.py::verify_bearer_token`; bearer over `Authorization` (RFC 6750 §2.1) — `extract_bearer_token`; `401` + `WWW-Authenticate: Bearer` (RFC 6750 §3) — `auth/middleware.py`; key never logged/echoed. Tests: `test_verify_uses_hmac_compare_digest`, `test_no_direct_equality_in_verify`, `test_401_has_www_authenticate_bearer`, `test_key_not_in_401_response_body`, `test_key_not_in_401_response_headers` (`tests/test_auth_548.py`). Loopback-no-key no-op is intentional (RFC 9110 §11; ADR-0026 D1). |
| **API3** | Broken Object Property Level Authorization | **covered** | Config writes never echo secrets. `SecretStr` (`api_key`, `webhook_url`) is replaced with `None` before serialization by `routes/config.py::_mask_secrets` (applied in `_config_to_dict`) on every `GET /config/*`; `GET /config/runtime` exposes only non-secret booleans `webhook_url_set` / `api_key_set`, never the values (`get_runtime_config`). The discovery endpoint (`routes/discovery.py` → `GET /sources/types`) returns plugin schema metadata only — no stored config values. 422 bodies are sanitized (`_sanitize_validation_errors` strips `input`/`ctx`) so a submitted secret cannot reflect back. Tests: `test_get_source_config_does_not_echo_secret`, `test_get_runtime_config_webhook_url_never_returned`, `test_get_runtime_config_api_key_never_returned`, `test_put_422_does_not_echo_submitted_secret_in_input_key` (`tests/test_config_routes.py`). |
| **API4** | Unrestricted Resource Consumption | **gap + follow-up (#NNN)** | **Read side covered:** pagination/top-N caps are enforced via FastAPI `Query(..., le=...)` — `le=1000` on `/logs/paginated`, `/logs/recent`, `/logs/top-pairs`, `/logs/top-talkers`, `/logs/dga-suspects`; `le=100` on `/logs/protocol-mix`, `/logs/top-ja4` (`routes/logs.py`). **Batch count bounded:** `POST /logs/batch` rejects `len(events) > FIREWATCH_MAX_BATCH_SIZE` (default 100) with 422 before persistence — `routes/ingest.py::post_log_batch` + `_max_batch_size`. **GAP:** no server-enforced raw **request-body byte cap** on `POST /logs` / `/logs/batch` — explicit `# TODO(D7.3)` at `routes/ingest.py` lines ~31-35. Acceptable only under loopback-only posture (ADR-0029 D7.3); MUST close before non-loopback ingestion exposure. Follow-up: **#NNN** (413 body-size guard, EARS criteria, `deferred`/`area:api`/`area:core`/`security`). |
| **API5** | Broken Function Level Authorization | **covered** | Every route carries an explicit `RouteClass` (A/B/C) stamped by `auth/wiring.py::_classify_route` (PUT/PATCH→A, POST→B, else→C) + decorator/path-override extension points (`auth/classes.py`). A side-effecting GET cannot be silently served as an open read — coverage asserted by `test_all_routes_have_route_class`; the enum shape by `test_route_class_enum_has_a_b_c` (`tests/test_auth_548.py`). Inventory review (API9 table below) confirms **no side-effecting GET is mis-classified as C**: all 50 class-C routes are read/analyze; analyze-on-read paths (`/threats/{ip}/detailed`) are still C and still gated when a key is set. A+B are the hard floor (ADR-0026 D3). |
| **API6** | Unrestricted Access to Sensitive Business Flows | **covered** | Class-B action routes are gated uniformly when a key is set (same middleware as A/C). Inventory confirms the sensitive flows are class B: `POST /sources/{type}/test`, `POST /sync/{type}`, `POST /sources/{type}/actions/{id}` (ADR-0034 active-response), `POST /logs`, `POST /logs/batch` (ingest), `POST /logs/nl-query`, plus the `/cases` and `/ai/analyses/{id}/feedback` writes. Gating verified by `test_key_set_no_bearer_class_b_is_401`, `test_key_set_wrong_bearer_class_b_is_401` (`tests/test_auth_548.py`). |
| **API7** | Server-Side Request Forgery (SSRF) | **covered** | The operator-set webhook URL is anti-SSRF-validated **at config-write time**, independent of auth, by `firewatch_sdk/config.py::_assert_webhook_url_safe` (invoked from the `webhook_url` field validator). Defenses: **scheme allowlist** (`http`/`https` only — rejects `file://`, `gopher://`); **blocked ranges** loopback / link-local (incl. cloud-metadata `169.254.169.254`) / multicast / reserved / unspecified (`_is_blocked_webhook_address`); literal `localhost` blocked; **non-canonical-encoding defense** — decimal/octal/hex-dotted/trailing-dot IP forms `ipaddress` can't parse are resolved via `socket.getaddrinfo` and every resolved address re-checked. RFC 1918 LAN is intentionally allowed (self-hosted receiver, operator-trusted). At delivery, `webhook_notifier.py::_post` sets `follow_redirects=False` (ADR-0026 D6) so a 3xx can't bypass the allowlist; URL never logged. DNS-rebinding is a documented residual (network egress policy, #NNN). Tests: `test_canonical_blocked_urls_rejected` (loopback/metadata/localhost/0.0.0.0/file/gopher), `test_encoded_bypass_urls_rejected` (`2130706433`, octal, `0x7f.0.0.1`, trailing-dot, metadata-decimal), `test_rfc1918_lan_allowed` (`tests/test_webhook_notifier.py::TestWebhookUrlSsrfValidation`); `test_3xx_no_second_request_to_redirect_target` (same file). |
| **API8** | Security Misconfiguration | **covered** | Fail-closed bind guard: startup refuses a non-loopback bind while `api_key` is unset/empty/whitespace — `server.py::_check_bind_guard` + `_is_key_set` + `_is_loopback_host` (malformed host = non-loopback, fail-closed). HTTP-on-loopback by design; TLS terminates at the reverse-proxy edge (NIST SP 800-52r2, ADR-0026 D5). 401 body is a generic `{"detail":"Authentication required."}` — no debug/stack/info disclosure (`auth/middleware.py`). Tests: `test_nonloopback_rfc5737_no_key_raises`, `test_zero_dot_zero_no_key_raises`, `test_ipv6_any_address_no_key_raises`, `test_empty_secret_str_key_treated_as_no_key`, `test_whitespace_only_secret_str_key_treated_as_no_key`, `test_nonloopback_loopback_class_is_not_bypassed`, `test_loopback_127_no_key_starts` (`tests/test_bind_guard_547.py`). | 
| **API9** | Improper Inventory Management | **covered** | Full route inventory enumerated below (65 routes, 0 unclassified, all A/B/C-classified). Coverage invariant enforced by `test_all_routes_have_route_class` (`tests/test_auth_548.py`) — any new mounted route lacking `_fw_route_class` fails the build. OpenAPI/docs endpoints are themselves gated when a key is set (`test_openapi_json_returns_401_when_key_set`, `test_docs_returns_401_when_key_set`). Deferred surfaces (multi-user/SSO) noted under ADR-0026 D8. |
| **API10** | Unsafe Consumption of APIs | **covered** | Two outbound consumers. **Webhook sink** — covered by API7 above (scheme allowlist + blocked ranges + `follow_redirects=False` + 10 s timeout; failures never raise, status-only logging, URL never logged — `webhook_notifier.py::_post`). **Local AI endpoint** — `ollama_base_url` is constrained at config-write time to loopback/RFC 1918/link-local by `config.py::_validate_ollama_base_url_local_first` (ADR-0022 local-first guard; rejects cloud endpoints + `0.0.0.0`). Tests: `test_ollama_base_url_rejects_public_endpoint`, `test_ollama_base_url_accepts_loopback` (`tests/test_config_port.py`). LLM-prompt-injection (OWASP LLM01) for AI responses is **out of scope here** — owned by ADR-0022 / #NNN (ADR-0026 D7). |

**Legend:** *covered* = enforced + tested today · *deferred-with-ref* = intentionally
out of scope with an ADR/issue reference · *gap + follow-up* = real gap, filed as an
issue, not fixed in this gate.

---

## API9 — full route inventory (the A/B/C table)

Generated by walking `app.routes` and reading the `_fw_route_class` attribute
(constant `ROUTE_CLASS_STATE_KEY` in `auth/classes.py`) stamped by
`auth/wiring.py::wire_auth`. **65 routes · 0 unclassified · 4×A · 11×B · 50×C.**
When a key is set, **every** route below is gated; A and B are the hard floor.

### Class A — config-mutating (hard floor)

| Method | Path |
|--------|------|
| PATCH | `/cases/{case_id}/disposition` |
| PUT | `/config/runtime` |
| PUT | `/config/sources/{type_key}` |
| PUT | `/sources/{type_key}/auto-sync` |

### Class B — action-triggering / side-effecting (hard floor)

| Method | Path |
|--------|------|
| POST | `/ai/analyses/{analysis_id}/feedback` |
| POST | `/cases` |
| POST | `/cases/{case_id}/events` |
| POST | `/cases/{case_id}/notes` |
| POST | `/cases/{case_id}/summary` |
| POST | `/logs` |
| POST | `/logs/batch` |
| POST | `/logs/nl-query` |
| POST | `/sources/{type_key}/actions/{action_id}` |
| POST | `/sources/{type_key}/test` |
| POST | `/sync/{type_key}` |

### Class C — read / analyze (gated by default when a key is set)

| Method | Path |
|--------|------|
| GET | `/ai/analyses` |
| GET | `/ai/analyses/{analysis_id}` |
| GET | `/ai/baseline` |
| GET | `/ai/baseline/drift` |
| GET | `/ai/engine` |
| GET | `/ai/feedback/summary` |
| GET | `/ai/models` |
| GET | `/analytics/asn` |
| GET | `/analytics/asn/{asn}/narration` |
| GET | `/analytics/attack-dispositions` |
| GET | `/analytics/categories-timeline` |
| GET | `/analytics/geo` |
| GET | `/analytics/summary` |
| GET | `/cases` |
| GET | `/cases/{case_id}` |
| GET | `/cases/{case_id}/notes` |
| GET | `/cases/{case_id}/timeline` |
| GET | `/config/runtime` |
| GET | `/config/sources/{type_key}` |
| GET | `/export/ocsf/events` |
| GET | `/export/ocsf/findings` |
| GET | `/health` |
| GET | `/logs/categories` |
| GET | `/logs/category-summary` |
| GET | `/logs/dga-suspects` |
| GET | `/logs/graph` |
| GET | `/logs/ip/{ip}` |
| GET | `/logs/ips` |
| GET | `/logs/paginated` |
| GET | `/logs/protocol-mix` |
| GET | `/logs/recent` |
| GET | `/logs/timeline` |
| GET | `/logs/top-ja4` |
| GET | `/logs/top-pairs` |
| GET | `/logs/top-talkers` |
| GET | `/rules` |
| GET | `/sources` |
| GET | `/sources/types` |
| GET | `/sources/{type_key}/actions` |
| GET | `/sources/{type_key}/auto-sync` |
| GET | `/stats` |
| GET | `/threats` |
| GET | `/threats/{ip}` |
| GET | `/threats/{ip}/counterfactual` |
| GET | `/threats/{ip}/detailed` |
| GET | `/threats/{ip}/detailed/stream` |
| GET | `/threats/{ip}/events` |
| GET | `/threats/{ip}/evidence` |
| GET | `/threats/{ip}/narration` |
| GET | `/threats/{ip}/score-history` |

> **API5 cross-check:** every class-C route above is read/analyze. The
> analyze-on-read paths (`/threats/{ip}/detailed`, `.../stream`, `/narration`,
> `/counterfactual`) trigger local AI but mutate no external state and remain
> gated when a key is set — they are not mis-classified open writes. `GET
> /sources/{type_key}/actions` only *lists* available actions; the *invoking*
> route is the class-B `POST /sources/{type_key}/actions/{action_id}`.

---

## Deferred items (per ADR-0026 Decision 8 — future IAM ADR)

The following are intentionally out of scope and tracked to ADR-0026 D8 (the future
multi-user IAM ADR) — they are **deferred-with-ref rows, not work for this gate**:

- True per-object BOLA scoping across tenants (API1) — no multi-tenant boundary today.
- Multi-user accounts, SSO / OIDC, RBAC, per-route scopes, session management.
- Auth-event audit logging.
- Secret backends beyond `SecretStr` / env (Vault / KMS).
- Rate-limiting / per-client quotas beyond body-size + pagination caps (edge/proxy concern).
- OWASP LLM Top 10 (LLM01 prompt injection) — owned by ADR-0022 / #NNN (ADR-0026 D7).

## Follow-up issues filed by this sweep

- **#NNN** — Add server-enforced request-body-size guard on the ingest write door
  (`POST /logs`, `/logs/batch`) before non-loopback exposure (API4 gap; 413 cap,
  EARS criteria; labels `deferred` / `area:api` / `area:core` / `security`).

---

_Swept 2026-06-13 as the MP exit gate (#NNN). Verification: `uv run pytest
packages/firewatch-api/tests/test_auth_548.py
packages/firewatch-api/tests/test_bind_guard_547.py` → 88 passed; webhook SSRF +
config-secret tests green (`test_webhook_notifier.py`, `test_config_routes.py`,
`test_config_port.py`)._
