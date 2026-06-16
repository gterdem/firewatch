# ADR-0029: Read/Query API Contract — `firewatch-api` Read Surface, Cursor-Pagination Envelope, Response Shapes & SDK↔API Schema Split

**Date:** 2026-06-04
**Status:** Accepted

**Relates to:** ADR-0020 (lightweight OCSF alignment — payload field mapping; **not reopened**),
ADR-0024 (feature/UX parity; canonical values, not legacy classification; **not reopened**),
ADR-0028 (frontend layout — the UI consumes this surface over loopback HTTP; **not reopened**),
ADR-0026 (loopback-default posture — the fail-closed bind guard lands in MB.7; full auth deferred),
ADR-0007 (storage port — `get_paginated` envelope originates here), ADR-0016 (per-instance `source_id`,
cross-source `source_types` provenance), ADR-0006 (config precedence; `SecretStr` masking on read).
**Implements / gates:** MB.1 (#53 — read/query API). Consumed by MB.4 (#56), MB.5 (#57), MB.6 (#58).
**Standards consulted:**
- **RFC 9110 — HTTP Semantics** (STD 97, June 2022; obsoletes RFC 7231): method semantics (safe `GET`),
  status codes (200/404/422), representation metadata. <https://www.rfc-editor.org/rfc/rfc9110>
- **OCSF — Open Cybersecurity Schema Framework**, schema **v1.8.0** current (1.9.0-dev in flight),
  verified live at <https://schema.ocsf.io/> (2026-06-04). HTTP Activity `class_uid=4002`. Linux
  Foundation project. <https://ocsf.io/>
- **Cursor- (keyset-) pagination** as the standard for stable, large, append-mostly result sets
  (opaque continuation token, not page numbers) — common practice across GraphQL Cursor Connections,
  Stripe/Slack/GitHub REST list endpoints, and PostgreSQL keyset-pagination guidance.
- **OpenAPI 3.1** as the description format for the surface (JSON-Schema-aligned; FastAPI emits it).
- **OWASP API Security Top 10 (2023)** — API3 (Broken Object Property Level Authorization): read
  payloads must not echo secrets; reinforces the SecretStr-masking rule already in MA.

---

## Context

MB.1 (#53) stands up the `firewatch-api` read/query surface over the new core. Before an
implementer writes routes, the architect must **pin the contract** so that (a) the React views
(MB.4–MB.6) and the golden e2e (MB.8) build against a stable shape, and (b) the surface does not
drift from the standards or from the store's already-shipped pagination envelope.

The legacy `api/app.py` is the **UX oracle** for *which* read routes exist (ADR-0024): `/threats`,
`/threats/{ip}`, `/threats/{ip}/detailed`, `/stats`, `/logs/*`, `/rules`, `/analytics/*`, `/health`.
We preserve that route *surface* (feature parity) while pinning *values* to the canonical standard
(ADR-0024) and *payloads* to the OCSF field mapping (ADR-0020). This ADR does **not** re-litigate
those settled decisions; it formalizes the read contract that sits on top of them.

Three things are genuinely open and decided here:

1. The exact **read-route surface** MB.1 ships (and what is explicitly out of scope for MB).
2. The **pagination envelope** — already implemented by `SQLiteEventStore.get_paginated` and the
   `EventStore` port as `{logs, next_cursor, has_more, total_matching}`; the API must expose it
   **verbatim** rather than inventing a parallel page-number scheme.
3. The **SDK↔API schema split** — which response shapes are SDK domain models (`ThreatScore`,
   `SecurityEvent`) versus API-only wrappers (the pagination envelope, the error shape) that live in
   a `firewatch-api/schemas.py`.

---

## Decision

### D1 — Read-route surface (MB.1)

`firewatch-api` exposes these **safe `GET`** routes (RFC 9110 §9.2.1 — safe, side-effect-free),
thin controllers delegating to core/store:

| Route | Returns | Backing |
|---|---|---|
| `GET /health` | liveness + component status | core/store ping |
| `GET /threats` | `list[ThreatScore]` | pipeline/store |
| `GET /threats/{ip}` | `ThreatScore` (concise) | `pipeline.analyze_ip` |
| `GET /threats/{ip}/detailed` | detailed analysis | `pipeline.analyze_ip_detailed` (#19) |
| `GET /logs/paginated` | **pagination envelope** (D2) | `store.get_paginated` |
| `GET /logs/recent` | `list[raw row]` | `store.get_recent` |
| `GET /logs/ip/{ip}` | `list[raw row]` | `store.get_by_ip_raw` |
| `GET /logs/categories` | category counts | `store.get_categories` |
| `GET /logs/category-summary` | per-category summary | `store.get_category_summary` (MB.3) |
| `GET /logs/timeline` | timeline buckets | `store.get_timeline` |
| `GET /logs/ips` | distinct IPs | `store.get_all_ips` |
| `GET /rules` | rule descriptions | `store.get_rule_descriptions` |
| `GET /analytics/geo` | server-side geo points | `store.get_analytics_geo` (#20) |
| `GET /analytics/summary` | analytics aggregate | `store.get_analytics_summary` |
| `GET /analytics/categories-timeline` | category-over-time | `store.get_categories_timeline` |
| `GET /stats` | global stats + source_health | `store.get_stats` |

The control/mutating routes (`/sources`, `/sources/suricata/test`, `/sync/suricata`, auto-sync) are
defined by **MB.4** and the config routes by **MA.2/MA.3** (already shipped); they are referenced
here only so the full surface is legible. **Azure ingest** (`POST /logs`, `/logs/batch`) is **MC**.

### D2 — Pagination envelope (cursor/keyset, exposed verbatim)

`GET /logs/paginated` returns the store's envelope **unchanged**:

```json
{
  "logs": [ /* canonical log rows */ ],
  "next_cursor": "2026-06-01T12:00:00|4815",
  "has_more": true,
  "total_matching": 1287
}
```

- `next_cursor` is an **opaque continuation token** (timestamp + tiebreak id); clients echo it back
  via the request's `cursor` filter and **never** compute offsets client-side. A malformed cursor
  yields a well-formed first/empty page (the store already tolerates this — see
  `test_get_paginated_malformed_cursor_*`), never a 500.
- `has_more` signals another page exists; `total_matching` is the filter-scoped count for UI display.
- **Cursor (keyset) over offset/page-number** because the log table is large and append-mostly:
  offset pagination drifts and re-scans under concurrent inserts; keyset is stable and index-friendly.
- The envelope shape is **owned by the `EventStore` port** (ADR-0007) and surfaced verbatim by the
  API; the API does not re-wrap or rename keys (one source of truth).
- **Request side (filters):** `/logs/paginated` accepts `cursor` + `limit` plus the facet filters
  already supported by `store.get_paginated` (source_type / source_id / category / severity / ip /
  time-range / free-text search). MB.1 pins these **1:1 to the store signature** (no API-only filters
  invented); MB.6's faceted filter bar binds to exactly this set. Perf note: `total_matching` is a
  filter-scoped count — the one non-keyset scan in the envelope; watch its cost on very large tables.

### D3 — Response shapes (`ThreatScore` / log rows)

- `GET /threats*` return the SDK `ThreatScore` model **as-is** (`source_ip`, `threat_level`,
  `score`, `total_events`, `blocked_events`, `attack_types`, `first_seen`, `last_seen`,
  `source_types`, `detections`, `ai_insights`, `ai_confidence`, `ai_status`). This is the
  **feature-parity shape** (ADR-0024); `ai_*` fields are additive-only (ADR-0015) — a degraded AI
  yields `ai_status` `unavailable`/`disabled` and does not change the rule+detection score.
- Log rows in `/logs/*` carry the canonical `SecurityEvent` fields plus the OCSF-mapped fields
  (D4); source-specific native fields live in `raw_log`/`RawEvent.data`, not as new top-level
  columns (ADR-0010 unified table).
- **Untrusted data at the boundary:** `raw_log` and native source fields are **attacker-controlled**
  (they originate from ingested telemetry). The read API emits them as opaque data; **consumers (the
  UI) MUST treat them as untrusted and escape on render** — no `dangerouslySetInnerHTML`, no
  HTML/script interpolation — the same data-plane discipline as the AI-path NB-1 delimiting (ADR-0015).
  This is a hard requirement on MB.6's log table / IP drill-down.
- **404, not empty-200:** `GET /threats/{ip}` for an IP with no events returns `404` (RFC 9110
  §15.5.5), not a hollow `ThreatScore`. Validation failures on query params return `422`.

### D4 — OCSF field mapping in payloads (ADR-0020)

Every event-bearing payload preserves the OCSF-aligned mapping formalized in ADR-0020:
`action` → `disposition_id`/`activity_id`, `severity` → `severity_id`, `category` → OCSF class,
and the model's `ocsf_class`/`ocsf_category` as `class_uid`/`category_uid` (e.g. WAF HTTP Activity
`class_uid=4002`, OCSF v1.8.0). The API is the **OCSF view at the boundary** (ADR-0020's serializer
seam), not a second internal schema. This ADR does not extend the mapping — it pins that the read
surface emits it.

### D5 — SDK↔API schema split (`schemas.py`)

- **Domain models live in `firewatch-sdk`** (`ThreatScore`, `SecurityEvent`, …) and are imported by
  the API — never redefined. This keeps one canonical model shared by core, plugins, and API
  (dependency rule: both depend on the SDK).
- **API-only shapes live in `firewatch-api/src/firewatch_api/schemas.py`**: the pagination-envelope
  wrapper type, the error-detail shape, and any response composition that is an HTTP concern, not a
  domain concern. These do not belong in the SDK because plugins/core never produce them.
- Rationale: the SDK is the cross-package contract; bloating it with HTTP-shaped wrappers would leak
  a delivery concern into the shared kernel. The split keeps the SDK delivery-agnostic and lets the
  API evolve its envelopes without an SDK release.

### D6 — Description format & posture

The surface is described by **OpenAPI 3.1** (FastAPI-emitted; JSON-Schema-aligned, consistent with
the rjsf JSON-Schema discovery used by the UI). MB ships **loopback-only** (ADR-0026); read routes
are not auth-gated in MB. The fail-closed bind guard (ADR-0026 Decision 4) is the only auth artifact
in MB (MB.7); full per-route-class gating (including gating reads when exposed) is deferred to a
later milestone + a future auth ADR (not drafted now).

---

## Alternatives considered

- **Offset/limit (page-number) pagination** — rejected: drifts and re-scans on a large,
  concurrently-appended log table; the store already implements stable keyset pagination, and
  exposing a second scheme would fork the contract. (Keyset is the documented best practice for this
  shape.)
- **Re-wrapping the store envelope into a new API shape** (e.g. `{data, meta:{cursor,…}}`) — rejected:
  two pagination shapes for one dataset, more mapping code, more drift surface. Expose the port's
  envelope verbatim (one source of truth, ADR-0007).
- **Putting the pagination/error wrappers in the SDK** — rejected: they are HTTP-delivery concerns;
  plugins and core never emit them. The SDK stays delivery-agnostic (D5).
- **Empty-200 for an unknown IP** (legacy convenience) — rejected: violates RFC 9110 resource
  semantics and forces clients to disambiguate "no such IP" from "IP with zero score." Use 404.
- **Full OCSF object conformance at the API boundary** — out of scope; ADR-0020 already chose the
  lightweight serializer-at-the-boundary approach and is not reopened here.
- **Defining new value vocabularies at the API layer** — rejected: values are pinned to the canonical
  standard upstream (ADR-0024); the API is a view, it does not re-classify.

## Reasoning

The read API is a **thin, standards-anchored view** over already-settled decisions: the store owns
the pagination envelope (ADR-0007), the SDK owns the domain models, OCSF owns the field mapping
(ADR-0020), and the canonical standard owns the values (ADR-0024). Pinning the surface, the envelope,
the shapes, and the SDK↔API split now lets MB.4–MB.6 and MB.8 build in parallel against a fixed
contract without re-opening any accepted ADR. Cursor pagination and `GET`/404/422 semantics follow
the published standards (keyset best practice; RFC 9110) rather than legacy convenience.

---

## Consequences

- MB.1 implementers have a fixed route table, envelope, and schema-ownership rule; reviewers check
  against this ADR.
- The SDK gains no new wrapper types; `firewatch-api/schemas.py` is introduced for HTTP-only shapes.
- A future REST resource tidy-up (verb-y `/sync*` → resources) is deferred to when the surface is
  already changing (post-MB), keeping the feature-parity diff small early.
- If exposure beyond loopback is later wanted, a future auth ADR governs auth/gating of these reads; this ADR
  deliberately leaves that open.

---

## Addendum (2026-06-05) — D7: Write door for ingest (`POST /logs`, `/logs/batch`) — MC.3

**Status:** Accepted · **Relates to:** ADR-0024 (plugin owns its `normalize()`), ADR-0025
(canonical SecurityEvent is the one schema), ADR-0010 (unified table), ADR-0015 (untrusted
data-plane discipline), ADR-0026 (loopback posture). **Implements:** MC.3 (#88).

D1 reserved `POST /logs` + `/logs/batch` as the MC ingest door. MC.3 makes it concrete; this
addendum pins its contract so the read ADR stays the single source of truth for the `firewatch-api`
surface.

### D7.1 — The door accepts `RawEvent` + `source_type`, and normalizes server-side

`POST /logs` (one event) and `POST /logs/batch` (a bounded list) accept a **`RawEvent`** body plus a
**`source_type`** discriminator. The API routes the body to that source's registered `normalize()`
(the same plugin path used by the pull collectors) and persists the resulting canonical
`SecurityEvent`. The shipper sends *its* native shape; **FireWatch owns the mapping**.

- **Rejected: accepting a pre-normalized `SecurityEvent`.** That would move canonical-schema authority
  to the shipper and let an external sender write arbitrary classification/severity/OCSF values into
  the unified table — breaking ADR-0024 (values pinned to the canonical standard, never to the
  producer) and ADR-0025 (one schema, core-owned). The door takes raw telemetry and classifies it
  with the same `normalize()` the pull path uses; there is exactly one classifier per source.
- **Unknown `source_type` ⇒ `422`** (no registered plugin to normalize with); a malformed `RawEvent`
  body ⇒ `422`. These never 500.
- This makes ingest **transport-symmetric**: pull (collector) and push (`POST /logs`) converge on the
  same `normalize()` → same `SecurityEvent` → same store, so a pushed Azure event scores and
  correlates identically to a pulled one. (Anticipates ADR-0030's transport-agnostic framing.)

### D7.2 — Semantics, safety, and limits

- **Not safe/idempotent** (RFC 9110 §9.2): `POST` creates resources. Dedup remains the store's job
  (the existing unique index, ADR-0007/0016) — a replayed batch is absorbed, not double-counted;
  the response reports an inserted-vs-deduped count, mirroring `save_many`.
- **`/logs/batch` is bounded** — a max batch size (config-overridable, ADR-0006); an over-limit body
  ⇒ `422`/`413` rather than an unbounded write. Backpressure/throughput tuning is **out of scope**
  (MD+).
- **Untrusted at the boundary (ADR-0015):** a pushed `RawEvent.data` is attacker-controlled exactly
  like a collected one — it flows into `raw_log`, and the UI escapes on render (D3). The write door
  adds no new trust.
- **Background analyze/alert (event-driven):** on successful ingest the pipeline schedules
  `analyze_ip` + webhook check for the affected IP (composed from existing
  `Pipeline.analyze_ip` + `WebhookNotifier.check_and_alert`; no new core schema). This is what makes a
  pushed event light up the correlation view (`ThreatScore.source_types`, already populated at
  `pipeline.py:218`).

### D7.3 — Posture

Loopback-only in MC (ADR-0026), same as the read surface — **but a write door is a higher-value
target than reads**, so when exposure beyond loopback is later considered, the future auth ADR MUST
gate the write routes at least as strictly as reads (OWASP API Top 10 — unauthenticated mass-write is
API2/API8). MC does not expose it; this is a forward-constraint, not an MC deliverable.
