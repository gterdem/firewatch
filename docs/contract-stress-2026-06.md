# Plugin-Contract Stress Test — Four Candidate Sources (2026-06)

**Author:** architect · **Date:** 2026-06-13 · **Status:** analysis (design-only, no code)

## Purpose

Validate the FireWatch plugin contract (`PLUGIN_CONTRACT.md` v1.1) *on paper* by drafting
four candidate source plugins chosen to stress different parts of it, **before** building or
spending on Terraform. The thesis under test:

> **A new source = a new package under `packages/sources/`, implementing `SourcePlugin` +
> a Pull/Push flavor, registered via entry points, with ZERO edits to `firewatch-core`.**

If any of the four cannot be expressed without a core change, the contract has a real gap and
must not graduate to 1.0.0. We stay v0.x until the contract is proven.

The four were picked to probe the four corners where gaps hide:

| # | Source | Flavor | Stresses |
|---|--------|--------|----------|
| 1 | AWS Network Firewall | PULL | The **control** — 2nd cloud, mirrors Azure-WAF KQL-pull |
| 2 | Generic Syslog/CEF receiver | **PUSH** | Push lifecycle + **vendor-agnostic** (one plugin, many vendors) |
| 3 | pfSense | **PUSH** | 2nd push case + concrete vendor mapping on the syslog/CEF substrate |
| 4 | Zeek | PULL | **Multi-stream** (conn/dns/ssl/files/http) + **schema field coverage** (DNS answers, file hashes) |

Grounded in the real contract and the two reference plugins:
- Pull reference: `packages/sources/azure-waf/` (KQL pull) and `packages/sources/suricata/` (SSH pull).
- Push reference: `packages/sources/syslog/` (UDP/TCP listener).
- Canonical schema: `packages/firewatch-sdk/src/firewatch_sdk/models.py::SecurityEvent`.
- Push lifecycle: ADR-0023 (supervisor), ADR-0030 (transport seam), ADR-0021 (push path).

---

## Source 1 — AWS Network Firewall (PULL, the control)

AWS Network Firewall writes alert/flow/TLS logs to **CloudWatch Logs**, **S3**, or **Kinesis
Data Firehose**. The natural pull is CloudWatch Logs (`FilterLogEvents` / Logs Insights) on a
time watermark, or an S3-object poll — structurally identical to Azure WAF's Log-Analytics KQL
pull on a watermark window.

**Flavor → contract.** PULL. Maps 1:1 onto `PullSource.collect(cfg, since, ctx)` with a
watermark keyed on `(source_type, source_id)`. Same shape as `firewatch_azure_waf.client.collect`.

**Config schema (sketch).**
```
AwsNetworkFirewallConfig:
  delivery: Literal["cloudwatch", "s3"]       # which sink to pull from
  region: str
  log_group: str | None                       # cloudwatch mode
  s3_bucket / s3_prefix: str | None            # s3 mode
  # AWS auth — instance-profile default; explicit keys optional
  access_key_id: str | None
  secret_access_key: SecretStr | None = None   # SecretStr MUST default to None (contract)
  role_arn: str | None                         # STS assume-role
  initial_window_hours: int = 24
```

**normalize() mapping → SecurityEvent.**
| AWS NFW field (alert log) | SecurityEvent |
|---|---|
| `event.src_ip` / `event.dest_ip` | `source_ip` / `destination_ip` |
| `event.src_port` / `event.dest_port` | `source_port` / `destination_port` |
| `event.proto` | `protocol` |
| `event.alert.action` (`blocked`/`alert`) | `action` → BLOCK / ALERT (ADR-0012) |
| `event.alert.signature` / `signature_id` | `rule_name` / `rule_id` |
| `event.alert.severity` | `severity` |
| `event.app_proto`, `event.flow_id`, netflow bytes | `bytes_in/out`, `packets_in/out` (ADR-0048) |
| `event.tls.*` | `tls_sni`, `tls_version` (ADR-0048) |
| MITRE — not in NFW logs natively | derive from Suricata-style category if present, else leave null |

**Key realization: AWS NFW alert logs ARE Suricata EVE JSON.** AWS Network Firewall's
stateful engine *is* Suricata; its alert log records are EVE-shaped. So normalize() is largely
the Suricata mapping with AWS envelope-stripping — the strongest possible evidence the contract
generalizes across clouds.

**Entry-point registration.**
```toml
[project.entry-points."firewatch.sources"]
aws_network_firewall = "firewatch_aws_nfw.plugin:AwsNetworkFirewallSource"
```

**CONTRACT VERDICT: ✅ fits as-is.** Zero core edits. The control passes — exactly as it must.
(One commodity sub-decision, not a contract gap: boto3 vs aioboto3 for an async pull. Suricata
already proves the `run_in_executor` boundary for a sync client inside an async `collect`.)

---

## Source 2 — Generic Syslog/CEF receiver (PUSH, the primary stress)

A long-running UDP/TCP listener that ingests **RFC 5424 / RFC 3164 syslog** AND **CEF**
(ArcSight Common Event Format) — and, ideally, **LEEF** (IBM QRadar) — from *many different
device vendors* through one plugin, mapping each to `SecurityEvent`.

This probes the **two least-proven parts of the contract at once**: (1) the push-receiver
lifecycle, and (2) whether one plugin can be vendor-*agnostic* (a CEF→OCSF mapping registry)
rather than the implicit one-source-one-schema assumption baked into today's reference plugins.

**Flavor → contract.** PUSH. `PushSource.start(cfg, emit, ctx)` / `stop()`. The existing
`firewatch_syslog` listener is the substrate — UDP datagram + TCP line framing, batch `emit`,
backpressure (UDP drop-with-counter / TCP block per ADR-0023), `max_connections`, `idle_timeout`,
`max_line_length`, loopback-default bind. **The transport lifecycle is fully covered** (see
Finding 1). What is *missing* is a parser/mapper layer above the line framing.

**Config schema (sketch).** Extends today's `SyslogConfig` with format + mapping selection:
```
SyslogReceiverConfig(SyslogConfig):           # inherits bind/port/protocol/limits
  formats: list[Literal["rfc5424","rfc3164","cef","leef"]] = ["rfc5424","rfc3164"]
  vendor_map: Literal["auto","linux_auth","cisco_asa","fortinet","paloalto","generic_cef"] = "auto"
  # "auto" = sniff CEF/LEEF header, else RFC; route by CEF DeviceVendor/DeviceProduct
```

**normalize() mapping → SecurityEvent.** This is where the design gets interesting. A CEF
record is `CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension`
where Extension is `key=value` pairs from a **standard CEF dictionary** (`src`, `dst`, `spt`,
`dpt`, `proto`, `act`, `msg`, `request`, `cs1`…). The mapping is therefore:
| CEF field | SecurityEvent |
|---|---|
| `src` / `dst` | `source_ip` / `destination_ip` |
| `spt` / `dpt` | `source_port` / `destination_port` |
| `proto` | `protocol` |
| `act` (deny/block/permit) | `action` (vendor-specific value table → BLOCK/ALLOW/DROP/ALERT) |
| `SignatureID` / `Name` | `rule_id` / `rule_name` |
| `Severity` (0–10) | `severity` (banded) |
| `request` / `requestMethod` | `http_url` / `http_method` (ADR-0048) |
| `DeviceVendor`+`DeviceProduct` | (selects the per-vendor `act`→action value table) |

The CEF *dictionary* keys map to canonical fields **once**; only the small **`act`→action**
value table and a handful of severity bands are vendor-specific. That is a **CEF→OCSF mapping
registry inside the plugin** — a `dict[(vendor,product) → ActionValueTable]`, defaulting to a
generic table. **The contract permits this**: normalize() OWNS its mapping (PLUGIN_CONTRACT.md
§normalize), and `source_type` stays the constant `"syslog_cef"` — the plugin is free to branch
on the *payload's* DeviceVendor; it just must never branch on `source_id` (Flag B). The registry
lives entirely in the plugin; core never learns vendor names.

**Entry-point registration.**
```toml
[project.entry-points."firewatch.sources"]
syslog_cef = "firewatch_syslog_cef.plugin:SyslogCefSource"
```
(Could also be a v2 evolution of the existing `syslog` plugin rather than a new package — see
Build order. Either way, zero core edits.)

**CONTRACT VERDICT: ✅ fits as-is** for the lifecycle and the vendor-agnostic mapping; **⚠️
gap is implementation maturity, not contract shape.** The contract supports everything needed.
The catch is that today's `firewatch_syslog` plugin is NOT actually vendor-agnostic — it
regex-matches Linux `sshd` lines against a hardcoded 4-entry category map, with **no CEF parser
and no vendor registry** (`firewatch_syslog/normalize.py`). So the *contract* holds, but the
*reference push plugin under-demonstrates it*. That is a build gap (issue), not a contract break.

---

## Source 3 — pfSense (PUSH, vendor mapping on the syslog substrate)

pfSense ships its firewall log (`filterlog`) over **syslog** as a CSV-in-syslog payload (the
`filterlog` CSV: rule#, iface, action `pass`/`block`, dir, ip-version, proto, src, dst, sport,
dport, …). It is a concrete *vendor mapping* sitting on the same push substrate as Source 2.

**Flavor → contract.** PUSH, identical lifecycle to Source 2 / the `firewatch_syslog` reference.

**Config schema (sketch).** Same listener fields (`bind/port/protocol/limits`); optionally a
`facility` filter. No vendor selection needed — it's a single-vendor plugin.

**normalize() mapping → SecurityEvent.** Parse the `filterlog` CSV out of the syslog MSG:
| pfSense filterlog field | SecurityEvent |
|---|---|
| action `pass`/`block` | `action` → ALLOW / BLOCK (ADR-0012) |
| `srcip` / `dstip` | `source_ip` / `destination_ip` |
| `srcport` / `dstport` | `source_port` / `destination_port` |
| `proto` (tcp/udp/icmp) | `protocol` |
| rule number / tracker id | `rule_id` |
| interface + direction | → `RawEvent.data` (no top-level home; leave there, don't fabricate) |
| (no signature name) | `rule_name` null; category = "Firewall Block"/"Firewall Pass" |
| (no MITRE in a packet-filter log) | `attack_*` null — correctly unset |

**Entry-point registration.**
```toml
[project.entry-points."firewatch.sources"]
pfsense = "firewatch_pfsense.plugin:PfSenseSource"
```

**CONTRACT VERDICT: ✅ fits as-is.** A second clean push case. The interface+direction fields
having no canonical home is *correct* contract behavior — they stay in `RawEvent.data` (the
OCSF/ECS extension-overlay model, PLUGIN_CONTRACT.md §normalize "never invent new top-level
fields"). No gap.

**Design note — overlap with Source 2.** pfSense is arguably *one vendor table* inside the
generic syslog/CEF receiver, not a separate package. Whether it's its own plugin or a vendor
profile under Source 2 is a packaging call, not a contract question — both are zero-core-edit.
Recommendation: ship it as its own small plugin first (cleaner golden tests, clearer Settings
card), fold into the generic receiver only if vendor sprawl demands it.

---

## Source 4 — Zeek (PULL, multi-stream + schema coverage — the deepest stress)

Zeek (formerly Bro) emits **multiple TSV/JSON log streams** — `conn.log`, `dns.log`, `ssl.log`,
`files.log`, `http.log`, `weird.log`, … — pulled the same way as Suricata (JSON log files over
SSH, or local). It carries the **richest telemetry** of the four: DNS queries *and answers*,
TLS/JA3(+SNI/cert), **file hashes (MD5/SHA1/SHA256)**, flow byte/packet counts, HTTP detail.

This stresses two distinct things: **(a) one plugin ingesting several log types** and **(b)
whether `SecurityEvent` has a home for the rich fields.**

**Flavor → contract.** PULL, identical to Suricata's SSH/local `collect`. No issue here.

### (a) Multi-stream — does the contract assume one stream per source?

**No — the contract is stream-agnostic by construction, and verdict is ✅.** The contract never
says "one log file per source." A `RawEvent` carries `source_type` + an opaque `data: dict`; a
plugin can read N files, tag each `RawEvent.data` with its `_zeek_stream` (`"conn"`/`"dns"`/…),
and `normalize()` switches on that tag to populate the right fields. Precedent already exists:
Suricata's `normalize()` already branches on EVE `event_type` (alert vs flow vs dns vs tls)
within one plugin (`firewatch_suricata/normalize.py`). Zeek is the same pattern across files
instead of across `event_type` values in one file.

One real design choice (plugin-internal, not a contract change): **fan-out vs join.** A single
Zeek connection produces a `conn.log` row AND possibly `dns.log`/`ssl.log`/`files.log` rows
sharing a `uid`. The plugin can either (i) emit one `SecurityEvent` per log row (simplest,
multiple events per connection, joined later by `uid` in `RawEvent.data`), or (ii) join on
`uid` into one enriched event. **Recommendation: (i) one-event-per-row for the first build**
— it matches the at-least-once / dedup model (ADR-0023) and keeps `normalize()` a pure
per-row mapping; a `uid` correlation key in `RawEvent.data` reserves (ii) for later. This is a
**module-layout** call the implementer must NOT default away: see the sketch below.

**Module layout (architect's sketch — Zeek is multi-concern, do not ship as one file):**
```
firewatch_zeek/
  plugin.py        # thin SourcePlugin/PullSource surface; delegates
  config.py        # ZeekConfig (ssh/local mode, log_dir, which streams to ingest)
  collector.py     # SSH/local tail of N log files; tags each RawEvent.data["_zeek_stream"]
  streams/
    __init__.py    # registry: stream name → per-stream normalizer
    conn.py        # conn.log   → flow fields (bytes/packets/duration), action
    dns.py         # dns.log    → dns_query/dns_rcode (+ dns_answer — SEE GAP)
    ssl.py         # ssl.log    → tls_sni/tls_version/tls_ja3 (+ JA4 if present)
    files.py       # files.log  → file hashes (SEE GAP — no canonical home today)
    http.py        # http.log   → http_method/host/url/user_agent
  normalize.py     # dispatch on _zeek_stream → streams.<x>.normalize
```

### (b) Schema field coverage — where SecurityEvent has gaps

Mapping Zeek's streams onto the canonical `SecurityEvent` (post ADR-0048):

| Zeek field (stream) | SecurityEvent | Home? |
|---|---|---|
| `id.orig_h`/`id.resp_h` (conn) | `source_ip`/`destination_ip` | ✅ |
| `id.orig_p`/`id.resp_p` (conn) | `source_port`/`destination_port` | ✅ |
| `proto` (conn) | `protocol` | ✅ |
| `orig_bytes`/`resp_bytes` (conn) | `bytes_out`/`bytes_in` | ✅ ADR-0048 |
| `orig_pkts`/`resp_pkts` (conn) | `packets_out`/`packets_in` | ✅ ADR-0048 |
| `duration` (conn) | `flow_duration_ms` | ✅ ADR-0048 |
| `query` (dns) | `dns_query` | ✅ ADR-0048 |
| `rcode_name` (dns) | `dns_rcode` | ✅ ADR-0048 |
| **`answers` / resolved IPs (dns)** | — | **❌ NO HOME** (only `dns_query`/`dns_rcode` exist) |
| `server_name` (ssl) | `tls_sni` | ✅ ADR-0048 |
| `version` (ssl) | `tls_version` | ✅ ADR-0048 |
| **`ja3` (ssl, Zeek default)** | only `tls_ja4`/`tls_ja4s` exist | **⚠️ JA3≠JA4** (see below) |
| `method`/`host`/`uri`/`user_agent` (http) | `http_method`/`http_host`/`http_url`/`http_user_agent` | ✅ ADR-0048 |
| **`md5`/`sha1`/`sha256` (files)** | — | **❌ NO HOME** (no file-hash field on the model) |
| **`filename`/`mime_type` (files)** | — | **❌ NO HOME** |

**Three concrete schema gaps, in priority order:**

1. **File hashes (`files.log`) have no canonical home — the most important gap.** There is no
   `file_sha256` / `file_md5` / `file_sha1` / `file_name` / `file_mime_type` on `SecurityEvent`.
   File hashes are the single highest-value Zeek field for a SOC tool: they are the join key to
   threat-intel (VirusTotal/MISP), the IOC analysts pivot on, and OCSF has a first-class
   representation (`File` object with a `Fingerprint`/`hashes` array; ECS `file.hash.sha256`).
   With no home, this telemetry would be **stranded in `RawEvent.data`**, unqueryable and
   un-correlatable — defeating the point of ingesting Zeek at all. **This is a real schema gap →
   propose ADR-0055 (file-IOC fields), same additive/nullable pattern as ADR-0048.**

2. **DNS answers (resolved IPs) have no home.** ADR-0048 added `dns_query`/`dns_rcode` but not
   the *answer set* (the resolved A/AAAA/CNAME values). DNS answers power passive-DNS pivoting
   and DGA/fast-flux detection. Lower urgency than file hashes (the query alone covers DGA),
   but a genuine gap for Zeek/passive-DNS use. Roll into ADR-0055 as an optional `dns_answer`
   (string, comma-joined, ECS `dns.answers`/`dns.resolved_ip`).

3. **JA3 vs JA4 (minor).** The schema has `tls_ja4`/`tls_ja4s` (ML-13), but **Zeek emits JA3 by
   default**; JA4 requires the FoxIO Zeek plugin. So a stock Zeek install populates *neither*
   JA4 field. Options: (a) document that JA4 needs the Zeek JA4 plugin (no schema change, JA3
   stays in `RawEvent.data`); (b) add `tls_ja3`/`tls_ja3s` to ADR-0055. JA3 is being deprecated
   in favor of JA4 industry-wide, so **(a) is defensible** — but adding `tls_ja3` is cheap and
   matches what stock Zeek actually emits. Architect leans (b)-lite: add `tls_ja3` only,
   skip `tls_ja3s`, note JA4 is the strategic fingerprint.

**Entry-point registration.**
```toml
[project.entry-points."firewatch.sources"]
zeek = "firewatch_zeek.plugin:ZeekSource"
```

**CONTRACT VERDICT: ⚠️ needs amendment (ADR-0055 — additive schema fields).** Multi-stream is
✅ (contract is stream-agnostic; one plugin, N normalizers — no core change). But the *richest*
Zeek telemetry (file hashes, DNS answers) has no canonical field and would be stranded in
`RawEvent.data`. The fix is **purely additive/nullable** (the ADR-0048 pattern: optional fields,
zero impact on existing plugins, store gains nullable columns) — so it is an **amendment, NOT a
contract break.** The contract's growth mechanism (optional fields added by core decision, per
ADR-0025 §4) is exactly designed for this.

---

## Verdict table

| # | Source | Flavor | Verdict | Why |
|---|--------|--------|---------|-----|
| 1 | AWS Network Firewall | PULL | **✅ fits as-is** | Mirrors Azure-WAF pull; NFW alert logs *are* Suricata EVE. Zero core edits. |
| 2 | Generic Syslog/CEF | PUSH | **✅ fits as-is** (contract) · ⚠️ ref plugin under-built | Push lifecycle fully covered (ADR-0023/0030); vendor-agnostic CEF registry is allowed (plugin owns normalize). Gap is the *current* `syslog` plugin has no CEF parser — a build gap, not a contract gap. |
| 3 | pfSense | PUSH | **✅ fits as-is** | Clean 2nd push case; unmappable fields correctly stay in `RawEvent.data`. |
| 4 | Zeek | PULL | **⚠️ needs amendment ADR-0055** | Multi-stream is ✅; but file hashes + DNS answers have no canonical home. Fix is additive/nullable fields (ADR-0048 pattern) — amendment, not break. |

---

## The four stress-dimension findings

### Finding 1 — Push-source lifecycle: FULLY SPECIFIED (the surprise — push is NOT under-proven)

Going in, the hypothesis was that push is the weak link because both shipped sources predating
syslog were pull. It is not. The push lifecycle is the **best-specified** part of the contract:

- **Bind / framing / batch.** `PushSource.start(cfg, emit, ctx)` + `stop()`; `emit` takes a
  *batch* (coalesces UDP/TCP bursts). Reference `firewatch_syslog/listener.py` implements UDP
  datagram + TCP line framing, `MAX_BATCH_SIZE`, loopback-default bind, IP-literal bind validation.
- **Backpressure.** ADR-0023 §Steals settles it *per transport*: **UDP = drop-newest + counter**
  (UDP is already lossy; blocking the loop is worse), **TCP/file = block** (flow-controlled).
  Implemented as a `BoundedSemaphore` inflight cap in the reference listener.
- **Supervision / parking.** ADR-0023 §A–D: one_for_one isolation (a crashing listener never
  takes down siblings), full-jitter capped backoff, restart-storm **park**+alert, dead-letter
  for poison records, `idle` state (ADR-0031). A long-running listener is a first-class citizen
  of the supervisor, not a bolt-on.
- **Graceful shutdown.** ADR-0023 §E: `stop()` on every listener within a bounded grace, hard
  deadline force-cancel.
- **Transport durability ladder.** ADR-0030: in-process default → disk-WAL → broker, all behind
  a seam, sources never see transport.

**Conclusion: the push *contract* holds for Source 2 and Source 3 with no amendment.** The only
push-related gap is that the *reference plugin* demonstrates a single implicit vendor (Linux
`sshd` regex), under-selling the vendor-agnostic capability the contract actually permits
(Finding 2). That is a build-quality gap, filed as an issue, not a contract change.

### Finding 2 — Vendor-agnostic mapping: the contract ALLOWS it; the reference plugin doesn't SHOW it

The canonical schema does **not** assume one-source-one-schema. `normalize()` explicitly OWNS
its mapping and may branch on the *payload* (it must only not branch on `source_id`). So a single
syslog/CEF plugin holding a **CEF→OCSF mapping registry** (`(DeviceVendor,DeviceProduct) →
action/severity value tables`, defaulting to a generic CEF-dictionary mapping) is fully
contract-legal — `source_type` stays the plugin's one constant; the registry is plugin-internal;
core learns nothing about vendors.

The gap is purely demonstrative: today's `firewatch_syslog` regex-matches four Linux auth
patterns and has no CEF parser. The vendor-agnostic claim is *unproven by example*. Action:
either evolve `syslog` into the CEF-capable receiver (Source 2 build) or ship `syslog_cef` as a
distinct plugin. Either is zero-core-edit. **No contract amendment.**

### Finding 3 — SecurityEvent coverage for Zeek's rich telemetry: TWO real gaps (file hash, DNS answer)

Post-ADR-0048 the schema covers flow volume/duration, DNS query+rcode, TLS SNI/version/JA4, and
HTTP detail — so most of Zeek's `conn`/`http`/`ssl` land cleanly. **JA4 already exists (ML-13).**
The genuine gaps:
- **File hashes / file metadata (`files.log`)** — no `file_sha256`/`md5`/`sha1`/`name`/`mime_type`.
  Highest-value Zeek field (threat-intel join key, IOC pivot). **Real gap → ADR-0055.**
- **DNS answers (`dns.log answers`)** — only the query side exists. **Real gap → ADR-0055 (optional).**
- **JA3** — Zeek emits JA3 by default, schema has only JA4. **Minor → ADR-0055 (`tls_ja3` only).**

All three fixes are **additive/nullable** (ADR-0048 pattern): existing plugins unaffected, no
source forced to populate, store gains nullable columns via idempotent `ALTER TABLE`. This is the
contract's *designed* growth path (ADR-0025 §4: new storage shape = a core decision, by ADR),
NOT a break.

### Finding 4 — Multi-stream sources: NO contract assumption of one-stream-per-source

The contract is stream-agnostic. `RawEvent.data` is opaque; a plugin reads N log files, tags each
raw event with its stream, and `normalize()` dispatches per-stream. Suricata already does the
in-file version of this (branches on EVE `event_type`). Zeek generalizes it across files. The only
real decision is plugin-internal (fan-out one-event-per-row vs join-on-`uid`) and the architect
has sketched the `streams/` module layout above so the implementer doesn't collapse it into a
monolithic `normalize()`. **No contract amendment.**

---

## CONCLUSION

**The contract HOLDS for all four sources** — with **one additive schema amendment** (ADR-0055)
required to make Source 4 (Zeek) *fully* expressible rather than stranding its richest fields.

- **3 of 4 fit as-is** (AWS NFW, Syslog/CEF, pfSense) with **zero core edits** — the
  "new source = zero core edits" thesis survives a second cloud (pull), the push-receiver
  lifecycle, a concrete vendor mapping, and vendor-agnostic multi-vendor mapping.
- **1 of 4 (Zeek) needs an additive amendment** — file-hash and DNS-answer fields. This is the
  contract's *designed* growth mechanism (optional/nullable fields, core-owned, ADR-gated per
  ADR-0025 §4), not a contract break. No source is broken by it; no existing plugin changes.

**Most important gap found:** the **file-hash / file-IOC schema gap** for Zeek's `files.log`
(Finding 3). It is the highest-value field in Zeek for a SOC tool and has nowhere to land today.
(Notably, the *expected* gap — the push lifecycle — turned out to be the best-specified part of
the contract, not a gap: Finding 1.)

No contract was silently changed. The one needed change is filed as **Proposed ADR-0055** and a
`contract-change` issue for Maintainer's approval.

---

## Recommended build order (when we implement)

Sequenced to retire the most contract-risk per unit of build, and to unblock each other:

1. **AWS Network Firewall** (pull, ✅). Lowest risk, highest confidence — it reuses the
   Suricata EVE normalizer almost verbatim and proves a second cloud. Good warm-up; validates the
   pull path generalizes before touching push or schema.
2. **Generic Syslog/CEF receiver** (push, ✅ contract). Highest *learning* value: builds the
   CEF parser + vendor-registry layer the reference plugin lacks, and is the substrate Source 3
   sits on. Either evolve `syslog`→`syslog_cef` or ship a new package.
3. **pfSense** (push, ✅). Cheap once Source 2's substrate exists; a single vendor table.
   Concrete, demoable, real home-lab value.
4. **Zeek** (pull, ⚠️). Build LAST, after **ADR-0055 lands** (file-hash/DNS-answer/JA3 fields),
   because it is the only one needing a schema amendment and the most complex (multi-stream
   module layout). Sequencing it last means its core dependency (ADR-0055) is approved and shipped
   before the plugin is written.

Even if not all four get built, the draft is the point: the contract is paper-proven for a
second cloud, the push lifecycle, vendor-agnostic mapping, and multi-stream — and the one real
schema gap is surfaced as an ADR rather than discovered mid-build.

---

## Filed artifacts

- **Proposed ADR-0055** — `docs/adr/0055-securityevent-file-ioc-and-dns-answer-fields.md`
  (additive file-hash + DNS-answer + JA3 fields; ADR-0048 pattern). Maintainer approves before merge.
- **GitHub issues** — one `contract-change` issue for ADR-0055, plus four build issues
  (one per source) with EARS criteria and area labels. See the issue ledger.
