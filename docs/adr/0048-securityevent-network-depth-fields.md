# ADR-0048: Extend SecurityEvent with OCSF-aligned network-depth fields

**Date:** 2026-06-13
**Status:** Accepted

## Context
The Network page (milestone ML) must show "the whole network traffic" and support
behavioral detection (beaconing, volumetric exfil), entity-graph edges, and
encrypted-traffic/DNS fingerprinting (JA4+, DGA). The canonical `SecurityEvent`
(firewatch-sdk/models.py) is transport-and-disposition focused and L7-thin: it
carries src/dst IP+port and protocol but NOT flow volume (bytes/packets), flow
duration, or any L7 detail (DNS, TLS/JA4, HTTP). Additionally `destination_ip`
exists on the model but is dropped at the SQLite store boundary (sqlite_store.py
logs DDL ~line 323 has no destination_ip column), so it is not queryable today.

R7 (volumetric exfil) and R8 (JA4/DGA) are blocked on these fields; R4/R6/R7's
destination-keyed halves are blocked on persisting destination_ip. Maintainer has
decided the FULL extension ships before the open-source launch (first impression).

## Decision
Add the following fields to `SecurityEvent`, **all additive and nullable**
(`<type> | None = None`), grouped by their OCSF anchor. Add the matching
**nullable columns** to the `logs` table via idempotent additive `ALTER TABLE …
ADD COLUMN` migrations (the existing NB-5 rule_name / NB-6 asn pattern), extend
`save_many`'s INSERT and `_row_to_security_event`'s read mapping, and add the
queryable subset to `FilterSpec` + the store WHERE-builder + the `/logs/paginated`
route (ADR-0029 D2: filters stay 1:1 with the store).

### Group A — flow volume & duration  → OCSF Network Activity (class_uid 4001, category_uid 4), Network Traffic object
- `bytes_in:  int | None`   — bytes from responder→originator. OCSF Network Traffic `bytes_in`. (ECS `destination.bytes`.)
- `bytes_out: int | None`   — bytes originator→responder. OCSF Network Traffic `bytes_out`. (ECS `source.bytes`.)
- `packets_in:  int | None` — OCSF Network Traffic `packets_in`. (ECS `destination.packets`.)
- `packets_out: int | None` — OCSF Network Traffic `packets_out`. (ECS `source.packets`.)
- `flow_duration_ms: int | None` — connection duration. ECS `event.duration` (ns) → we store ms for readability; documented deviation. OCSF has no first-class duration scalar on Network Activity, hence the ECS anchor.

### Group B — DNS  → OCSF DNS Activity (class_uid 4003, category_uid 4), DNS Query object
- `dns_query: str | None` — queried FQDN. OCSF DNS Query `hostname`. (ECS `dns.question.name`.) Feeds R8 DGA.
- `dns_rcode: str | None` — response code (e.g. NXDOMAIN). OCSF `rcode`. (ECS `dns.response_code`.)

### Group C — TLS / fingerprint  → OCSF TLS object (on Network Activity 4001)
- `tls_ja4:  str | None` — JA4 client fingerprint. (ECS `tls.client.ja4` — added to ECS 8.x.) Feeds R8 JA4+.
- `tls_ja4s: str | None` — JA4S server fingerprint. (ECS `tls.server.ja4s`.)
- `tls_sni:  str | None` — TLS SNI server name. OCSF TLS `sni`. (ECS `tls.client.server_name`.)
- `tls_version: str | None` — negotiated TLS version. OCSF TLS `version`. (ECS `tls.version`.)

### Group D — HTTP  → OCSF HTTP Activity (class_uid 4002, category_uid 4), HTTP Request object
- `http_method: str | None` — OCSF HTTP Request `http_method`. (ECS `http.request.method`.)
- `http_host:   str | None` — OCSF/ECS `url.domain` / Host header. (ECS `url.domain`.)
- `http_url:    str | None` — OCSF HTTP Request `url`. (ECS `url.full`.)
- `http_user_agent: str | None` — OCSF HTTP Request `user_agent`. (ECS `user_agent.original`.)

(`destination_ip` already exists on the model; this ADR persists it — adds the
`destination_ip TEXT` column + INSERT + read mapping + filter — fixing the
store-boundary drop.)

## Modularity rule (non-negotiable)
Every field is **optional and defaults to None**. No source is forced to populate
any of them; the core never special-cases a source. Suricata populates them
opportunistically from the EVE `flow`/`dns`/`tls`/`http` objects it already retains
in `raw_log`; Azure WAF populates only the HTTP subset it actually has and leaves
flow/DNS/TLS null (it never fabricates transport fields — PLUGIN_CONTRACT.md). The
UI renders "—" for null. This keeps "add a source = zero core edits" intact: the
contract grows by *optional* fields only.

## Standard alignment & deviations
OCSF is the security-event standard (ADR-0020). Where OCSF Network Activity lacks a
clean scalar (flow duration), we anchor to ECS and cite it. JA4/JA4S are an emerging
fingerprint standard (FoxIO) recently added to ECS `tls.*`; we adopt the ECS field
names. We keep the FireWatch "lightweight alignment" stance (ADR-0020): flat
nullable scalars on the existing model, NOT nested OCSF objects — the OCSF object
mapping lives at the export serializer boundary, deferred as before.

### Open sub-decision — JA4 compute vs. consume (must resolve before R8)
Suricata EVE exposes `tls.ja3`/`ja3s` natively on all builds and `tls.ja4` only on
recent builds (JA4 support landed in Suricata 7.x with `ja4` enabled in suricata.yaml).
Options: (a) **consume** `tls.ja4` when the sensor emits it, null otherwise (zero
compute, sensor-version-dependent); (b) **compute** JA4 in normalize() from the TLS
handshake fields (more fields needed in EVE, more code, licensing/spec care — JA4 is
BSD-3 spec). RECOMMEND (a) for ML (consume; null when absent — honest), defer compute
to a post-launch issue if sensor coverage proves thin. This ADR adopts the field;
**R8's issue (ML-13) ratifies the population strategy — this sub-decision is
explicitly deferred to ML-13, not settled here.**

## Consequences
- `normalize()` for each source populates the subset it can; golden fixtures updated:
  existing `expected_*.json` gain the new keys as `null` (additive round-trip proof) +
  one NEW enriched EVE fixture (flow/dns/tls) proves extraction. Scoring oracle
  (`expected_scores.json`) unchanged — new fields don't feed scoring in ML.
- The plugin contract grows by optional fields; **plugin authors need no change**
  (a `contract-version` minor bump is noted in PLUGIN_CONTRACT.md changelog; existing
  plugins remain conformant because every new field is optional).
- Store migration is additive/idempotent (NB-5/NB-6 pattern); historical rows
  backfill to NULL, no data loss, no forced re-collection.
- An OCSF-object export view for the new fields is deferred (ADR-0020 boundary).

## Alternatives considered
- **destination_ip-only minimal add now, full schema deferred** (strategist §6 Q3) —
  rejected by Maintainer: the full NDR-grade depth is wanted as the launch first impression.
- **Nested OCSF objects on the internal model** — rejected: violates ADR-0020
  lightweight stance; heavy for a single-binary tool.
- **Per-source side tables for L7 data** — rejected: breaks the one-schema/one-table
  correlation model and the ADR-0007 single-store swap; the OCSF/ECS "extension
  attributes overlay one schema" model says optional columns, not parallel storage.
