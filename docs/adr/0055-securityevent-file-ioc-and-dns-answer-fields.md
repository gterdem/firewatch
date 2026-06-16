# ADR-0055: Extend SecurityEvent with file-IOC, DNS-answer, and JA3 fields (refines ADR-0048)

**Date:** 2026-06-14
**Status:** Accepted

**Implements / referenced by:** the contract-stress draft `docs/contract-stress-2026-06.md`
(Source 4 — Zeek; Finding 3). **Relates to:** ADR-0048 (network-depth fields — same
additive/nullable pattern this ADR follows), ADR-0020 (lightweight OCSF alignment),
ADR-0025 (§4 — a new storage shape is a core decision, ADR-gated), PLUGIN_CONTRACT.md §normalize
("never invent new top-level fields" — this ADR adds the home so plugins don't have to).

---

## Context

The plugin-contract stress test (`docs/contract-stress-2026-06.md`) drafted four candidate
sources against the contract. Three fit as-is; **Zeek** exposed a real schema gap: its richest,
highest-SOC-value telemetry has **no canonical home** on `SecurityEvent` and would be stranded,
unqueryable, in `RawEvent.data`:

- **File hashes / file metadata (`files.log`).** MD5/SHA1/SHA256, filename, MIME type. This is
  the single highest-value Zeek field for a SOC tool: the join key to threat intelligence
  (VirusTotal / MISP), the IOC analysts pivot on. There is no `file_*` field on the model today.
- **DNS answers (`dns.log answers`).** ADR-0048 added `dns_query` + `dns_rcode` but not the
  *answer set* (resolved A/AAAA/CNAME values), which powers passive-DNS pivoting and
  fast-flux/DGA correlation.
- **JA3 fingerprint (`ssl.log`).** The schema has `tls_ja4`/`tls_ja4s` (ML-13), but **stock Zeek
  emits JA3 by default** (JA4 requires the FoxIO Zeek plugin), so a default Zeek install
  populates *neither* JA4 field.

These are not Zeek-specific: file hashes appear in Suricata `fileinfo` events, EDR telemetry, and
any future malware-detection source; DNS answers appear in any passive-DNS feed. The gap is
generic; Zeek merely surfaced it first.

Per ADR-0025 §4, adding a **source** is zero core edits, but adding a **new storage shape** is a
deliberate core decision made by ADR — which is exactly this ADR.

## Decision

Add the following fields to `SecurityEvent` (`firewatch-sdk/models.py`), **all additive and
nullable** (`<type> | None = None`), grouped by OCSF/ECS anchor. Add matching **nullable columns**
to the `logs` table via idempotent additive `ALTER TABLE … ADD COLUMN` migrations (the ADR-0048 /
NB-5 / NB-6 pattern), extend `save_many`'s INSERT and `_row_to_security_event`'s read mapping, and
add the queryable subset (`file_sha256`, `dns_answer`) to `FilterSpec` + the store WHERE-builder +
the `/logs/paginated` route (ADR-0029 D2: filters stay 1:1 with the store).

### Group E — File IOC → OCSF `File` object + `Fingerprint` (on Detection Finding 2004 / File System Activity)
- `file_sha256: str | None` — SHA-256 file hash. OCSF `File.hashes[].value` (algorithm_id=3).
  (ECS `file.hash.sha256`.) The primary threat-intel join key. **Queryable** (FilterSpec).
- `file_md5: str | None` — MD5 file hash. OCSF `File.hashes[]` (algorithm_id=1). (ECS `file.hash.md5`.)
- `file_sha1: str | None` — SHA-1 file hash. OCSF `File.hashes[]` (algorithm_id=2). (ECS `file.hash.sha1`.)
- `file_name: str | None` — file name. OCSF `File.name`. (ECS `file.name`.)
- `file_mime_type: str | None` — MIME type. OCSF `File.mime_type`. (ECS `file.mime_type`.)

### Group F — DNS answers → OCSF DNS Activity (class_uid 4003), DNS Answer object
- `dns_answer: str | None` — resolved values (A/AAAA/CNAME), comma-joined for a flat scalar.
  OCSF DNS Activity `answers[].rdata`. (ECS `dns.answers[].data` / `dns.resolved_ip`.)
  **Queryable** (FilterSpec) for passive-DNS pivoting.

### Group G — JA3 fingerprint → OCSF TLS object (on Network Activity 4001)
- `tls_ja3: str | None` — JA3 client fingerprint. (ECS `tls.client.ja3`.) Stock-Zeek default
  fingerprint. **JA4 remains the primary/strategic fingerprint (ML-13, `tls_ja4`/`tls_ja4s`); JA3
  is kept ALONGSIDE it — not as a fallback to be retired — because a large installed base of sensors
  (stock Zeek, many Suricata builds, legacy proxies/CDNs) still emits only JA3.** Carrying the
  client-side `tls_ja3` lets those widely-deployed sources be expressible and correlatable today
  without forcing the FoxIO JA4+ plugin everywhere.
  **`tls_ja3s` (server fingerprint) is deliberately SKIPPED:** it is rarely used for threat hunting
  (analysts pivot on the *client* fingerprint), and JA4S already covers the server side strategically.

## Modularity rule (non-negotiable — unchanged from ADR-0048)

Every field is **optional and defaults to None**. No source is forced to populate any of them;
the core never special-cases a source. Zeek populates them opportunistically from `files.log` /
`dns.log` / `ssl.log`; Suricata may populate `file_*` from `fileinfo` events it already retains;
Azure WAF / AWS NFW / pfSense leave them null and never fabricate (PLUGIN_CONTRACT.md §normalize).
The UI renders "—" for null. **"Add a source = zero core edits" stays intact: the contract grows
by optional fields only.** Existing plugins (Suricata, Azure WAF, syslog) require **no changes**
and remain conformant.

## Standard alignment & deviations

OCSF is the security-event standard (ADR-0020). File hashes map to OCSF's first-class `File`
object with a `Fingerprint` array; we keep the FireWatch "lightweight alignment" stance (ADR-0020)
— **flat nullable scalars** (`file_sha256` etc.), NOT a nested OCSF `hashes[]` array — and the
ADR-0040 export serializer reassembles the nested OCSF shape at the boundary (same as it does for
the ADR-0048 flat fields). DNS answers are joined to a comma-separated scalar for the same
flat-model reason; the export serializer can split them back to the OCSF `answers[]` array. JA3
uses the ECS `tls.client.ja3` field name.

**Deviation recorded:** OCSF/ECS model file hashes as an array keyed by algorithm; we flatten to
one scalar per algorithm (`file_sha256`/`file_md5`/`file_sha1`). Justification: identical to
ADR-0048's flat-scalar stance — avoids nested JSON columns in SQLite, keeps `FilterSpec` exact-match
simple, and the lossless nested form is reconstructed only at the OCSF export boundary (ADR-0040).

## Alternatives considered

- **Leave file hashes / DNS answers in `RawEvent.data`** — *rejected.* `RawEvent.data` is opaque
  to core: it is not queryable, not filterable, not correlatable, and not surfaced in the entity
  panel or export. File hashes are *the* IOC pivot; stranding them defeats ingesting Zeek at all.
- **Add a nested OCSF `File`/`hashes[]` JSON column** — *rejected* (for now). Contradicts ADR-0020's
  flat-scalar lightweight-alignment stance and ADR-0048's precedent; adds JSON-column query
  complexity in SQLite for little near-term gain. The export serializer already bridges flat→nested.
- **Add `tls_ja3` AND `tls_ja3s`** — *rejected.* Add only the client-side `tls_ja3`: it is the
  fingerprint analysts pivot on for hunting, and the one stock Zeek emits. `tls_ja3s` (server) is
  rarely used for hunting and is covered strategically by JA4S; carrying it would be dead schema weight.
- **Drop JA3 entirely and require JA4 (FoxIO plugin) everywhere** — *rejected.* JA4 is the strategic
  fingerprint, but a large installed base still emits only JA3; refusing JA3 would strand those
  sources. JA3 and JA4 coexist — JA3 for compatibility, JA4 as the forward direction.
- **Defer entirely until a real malware-detection source ships** — *rejected.* Zeek IS that source
  (build order item 4), and sequencing it last means this ADR must land first to unblock it. The
  field set is small, additive, and zero-risk to existing plugins.

## Reasoning

File hashes are the highest-value field in Zeek for a SOC tool and the contract's own rule
("never invent new top-level fields") means a plugin *cannot* add the home itself — only a
core-owned, ADR-gated schema addition can, which is exactly ADR-0025 §4's designed growth path.
The change is purely additive/nullable (the proven ADR-0048 pattern), so it costs existing plugins
nothing and breaks nothing, while making Zeek (and future malware/passive-DNS sources) fully
expressible instead of stranding their richest telemetry.

## Consequences

- A follow-up implementation issue adds the fields to `SecurityEvent`, the nullable columns +
  INSERT/read mapping in `SQLiteEventStore`, the `file_sha256` + `dns_answer` filters to
  `FilterSpec` + WHERE-builder + `/logs/paginated`, and the ADR-0040 OCSF serializer mapping
  (flat → nested `File.hashes[]` / DNS `answers[]`).
- PLUGIN_CONTRACT.md gets a v1.2 changelog entry mirroring the ADR-0048 v1.1 entry
  ("plugin author impact: none; every field optional, defaults to None").
- Version bumps to the OCSF export remain deliberate (ADR-0040 `OCSF_VERSION` unchanged; these
  fields map within the existing pinned 1.8.0 `File`/DNS objects).
- **Implementation gate (FoxIO JA4+ Zeek plugin license).** This ADR adds `tls_ja3` (stock Zeek,
  no extra plugin) and leaves the JA4 fields (ADR-0048/ML-13) populated only when the FoxIO JA4+
  Zeek plugin is present. The Zeek build (#606) MUST verify the **FoxIO JA4+ Zeek plugin license is
  compatible with FireWatch's AGPL-3.0 / no-closed-commercial stance** (see the licensing ADR)
  before taking any build-time or runtime dependency on it. If the license is incompatible, JA4 stays
  optional/absent on Zeek and `tls_ja3` carries the fingerprint — the ADR is unaffected. This gate is
  recorded as an acceptance note on #606.

## References

- **OCSF `File` object + `Fingerprint`/`hashes`** — https://schema.ocsf.io/ (1.8.0; `File` object,
  `hashes` array with `algorithm_id`) — backs Group E.
- **OCSF DNS Activity `answers[]`** — https://schema.ocsf.io/ (class_uid 4003, DNS Answer object) —
  backs Group F.
- **ECS file fields** — https://www.elastic.co/guide/en/ecs/current/ecs-file.html
  (`file.hash.*`, `file.name`, `file.mime_type`) — backs Group E field names.
- **ECS DNS fields** — https://www.elastic.co/guide/en/ecs/current/ecs-dns.html
  (`dns.answers`, `dns.resolved_ip`) — backs Group F.
- **ECS TLS / JA3** — https://www.elastic.co/guide/en/ecs/current/ecs-tls.html (`tls.client.ja3`) —
  backs Group G.
- **Internal:** ADR-0048 (additive network-depth fields — the pattern), ADR-0020 (flat-scalar
  lightweight OCSF alignment), ADR-0040 (export serializer bridges flat→nested), ADR-0025 §4
  (new storage shape = ADR-gated core decision).
