# Research: Azure WAF Log Standard & Normalization for a Future FireWatch Azure Source Plugin

**Date:** 2026-06-04
**Status:** Research note (not an ADR). Informs a future `packages/sources/azure-waf` plugin.
**Author:** research agent

## Why this exists

FireWatch v1 (`legacy/`) ingested Azure WAF events badly: empty `severity`, ~68% of events
categorized as `"Other"`, and no MITRE/OCSF tagging. The owner suspects the legacy Azure path is a
band-aid and does NOT want it carried forward. This note establishes the *current,
industry-standard* shape of Azure WAF logs (both Azure products) and the recommended normalization
into FireWatch's canonical `SecurityEvent` (ADR-0020 lightweight-OCSF, ADR-0014 MITRE/CAPEC,
ADR-0012 action mapping). `legacy/` is REFERENCE-ONLY — nothing here proposes importing it.

---

## 1. Azure WAF diagnostic log schemas (current)

Azure has **two** WAF products, each with its own resource-log table. They share the OWASP-CRS
lineage but differ in field names and casing, so a plugin must handle both shapes.

### 1a. Application Gateway WAF — `ApplicationGatewayFirewallLog`

Resource log emitted by the WAF on Azure Application Gateway v2 (category
`ApplicationGatewayFirewallLog`, operation `ApplicationGatewayFirewall`). All Azure resource logs
share a common envelope (`time`/`timeStamp`, `resourceId`, `operationName`, `category`) plus a
service-specific `properties` object.

`properties` field set ([MS Learn — Monitor logs for Azure WAF](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/web-application-firewall-logs)):

| Field | Meaning |
| --- | --- |
| `instanceId` | Gateway instance that generated the row |
| `clientIp` | Originating client IP |
| `requestUri` | URL of the received request |
| `ruleSetType` | Rule set type, e.g. `OWASP` (or `Microsoft_DefaultRuleSet`) |
| `ruleSetVersion` | e.g. `3.0`, `3.2`, `2.2.9` |
| `ruleId` | CRS rule ID of the triggering event, e.g. `920350`, `942100` |
| `ruleGroup` | CRS group, e.g. `920-PROTOCOL-ENFORCEMENT`, `942-APPLICATION-ATTACK-SQLI` |
| `message` | User-friendly description of the triggering event |
| `action` | Disposition — see action vocabulary below |
| `site` | Always `Global` today |
| `details.message` | Full rule description |
| `details.data` | The specific request data that matched |
| `details.file` | CRS config file, e.g. `rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf` |
| `details.line` | Line in that config file |
| `hostname` | Hostname/IP of the gateway |
| `transactionId` | Groups multiple rule violations within ONE request |
| `policyId` | Resource ID of the firewall policy |
| `policyScope` | `Global` \| `Listener` \| `Location` |
| `policyScopeName` | Name of the object the policy is applied to |

Verbatim example record (from MS Learn, same source):

```json
{
  "resourceId": "/SUBSCRIPTIONS/{subscriptionId}/RESOURCEGROUPS/{rg}/PROVIDERS/MICROSOFT.NETWORK/APPLICATIONGATEWAYS/{name}",
  "operationName": "ApplicationGatewayFirewall",
  "time": "2017-03-20T15:52:09.1494499Z",
  "category": "ApplicationGatewayFirewallLog",
  "properties": {
    "instanceId": "ApplicationGatewayRole_IN_0",
    "clientIp": "203.0.113.147",
    "requestUri": "/",
    "ruleSetType": "OWASP",
    "ruleSetVersion": "3.0",
    "ruleId": "920350",
    "ruleGroup": "920-PROTOCOL-ENFORCEMENT",
    "message": "Host header is a numeric IP address",
    "action": "Matched",
    "site": "Global",
    "details": {
      "message": "Warning. Pattern match \"^[\\d.:]+$\" at REQUEST_HEADERS:Host ....",
      "data": "127.0.0.1",
      "file": "rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
      "line": "791"
    },
    "hostname": "127.0.0.1",
    "transactionId": "16861477007022634343",
    "policyId": ".../perListener",
    "policyScope": "Listener",
    "policyScopeName": "httpListener1"
  }
}
```

The companion **access** log (category `ApplicationGatewayAccessLog`) carries legitimate-traffic
fields: `clientIP`, `httpMethod`, `requestUri`, `httpStatus`, `httpVersion`, `receivedBytes`,
`sentBytes`, `timeTaken`, `serverRouted`, `serverStatus`, `host`, `userAgent`, etc.

### 1b. Front Door WAF — `FrontDoorWebApplicationFirewallLog` (Std/Premium) / `FrontdoorWebApplicationFirewallLog` (classic)

Note the casing difference (`...Door...` for Standard/Premium vs `...door...` for classic) — both
table names exist. `properties` field set ([MS Learn — Front Door WAF monitoring](https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-monitor)):

| Field | Meaning |
| --- | --- |
| `action` | Disposition — see action vocabulary below |
| `clientIP` | Client IP (taken from `X-Forwarded-For` if present) |
| `clientPort` | Client port |
| `socketIP` | Source IP from the TCP session (ignores request headers) |
| `requestUri` | Full request URI |
| `ruleName` | Matched rule, e.g. `Microsoft_DefaultRuleSet-1.1-SQLI-942100` |
| `policy` | WAF policy name |
| `policyMode` | `Prevention` \| `Detection` |
| `host` | `Host` header |
| `trackingReference` | Unique request ID, echoed to client in `X-Azure-Ref` |
| `details.matches[].matchVariableName` | Matched HTTP parameter (≤100 chars) |
| `details.matches[].matchVariableValue` | Value that triggered the match (≤100 chars) |

Verbatim example (from MS Learn, same source):

```json
{
  "time": "2020-06-09T22:32:17.8376810Z",
  "category": "FrontdoorWebApplicationFirewallLog",
  "operationName": "Microsoft.Cdn/Profiles/Write",
  "properties": {
    "clientIP": "203.0.113.10",
    "clientPort": "52097",
    "socketIP": "203.0.113.10",
    "requestUri": "https://wafdemofrontdoorwebapp.azurefd.net:443/?q=%27%20or%201=1",
    "ruleName": "Microsoft_DefaultRuleSet-1.1-SQLI-942100",
    "policy": "WafDemoCustomPolicy",
    "action": "Block",
    "host": "wafdemofrontdoorwebapp.azurefd.net",
    "trackingReference": "08Q3gXgAAAAA...",
    "policyMode": "prevention",
    "details": { "matches": [ { "matchVariableName": "QueryParamValue:q", "matchVariableValue": "' or 1=1" } ] }
  }
}
```

Key shape difference vs App Gateway: Front Door packs the CRS metadata into a single dotted
`ruleName` string (`{ruleset}-{version}-{group}-{ruleId}`) and puts matched data in
`details.matches[]`, whereas App Gateway exposes `ruleId` / `ruleGroup` / `details.{message,data,file,line}`
as discrete fields. **A plugin must parse `ruleName` for Front Door** to recover the rule ID.

### 1c. Action vocabulary (both products)

Sources: App Gateway and Front Door MS Learn pages above.

- **`Detected`** — detection-mode match; logged then passed (App Gateway).
- **`Allowed` / `allow`** — all rule conditions matched, request passed (prevention/custom rule).
- **`Blocked` / `Block` / `block`** — request blocked (rule block, or anomaly score threshold reached).
- **`Matched`** — App Gateway: a non-terminating CRS rule contributed to the anomaly score; final
  block/pass decided later. Front Door's equivalent is **`AnomalyScoring` / `logandscore`**.
- **`Log` / `log`** — non-terminating, informational.
- **JS Challenge family** — `JSChallengeIssued`, `JSChallengePass`, `JSChallengeValid`, `JSChallengeBlock`.

Casing is inconsistent across products and even within Front Door (`Block`/`block`,
`prevention`/`Prevention`), so the plugin must **normalize case** before mapping.

### 1d. How logs are retrieved — the standard path today

Azure offers three sinks via **Diagnostic Settings**, common to both products ([App Gateway WAF logs](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/web-application-firewall-logs), [Front Door WAF monitoring](https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-monitor)):

1. **Azure Monitor / Log Analytics workspace** — query with KQL. This is the standard path for
   real-time monitoring and is what Microsoft's own Sentinel detections assume. **This is the
   ingestion path FireWatch should target** (pull via `azure-monitor-query` KQL, same library
   family legacy used).
2. **Event Hub** — the SIEM-integration path (streaming/push). Worth a future *push* flavor but
   not the M-now target.
3. **Storage account** — JSON blobs, archival/batch.

Two table-shape regimes inside Log Analytics:
- **Resource-specific tables** (the modern default): `AGWFirewallLogs`, `AGWAccessLogs`, and the
  Front Door equivalents — typed columns, PascalCase, recommended by Microsoft.
- **Legacy `AzureDiagnostics`** (the old shared table): every property becomes a suffixed column
  (`clientIp_s`, `ruleId_s`, `action_s`, `httpStatus_d`, `details_message_s`, …). Still common on
  older workspaces.

A plugin should prefer resource-specific tables and **fall back** to `AzureDiagnostics` — but as a
clean, declared adapter, not as a try/except guess (see legacy critique).

---

## 2. Recommended OCSF / MITRE / severity normalization

### 2a. OCSF class — use HTTP Activity (4002), not "Web Resources Activity"

The legacy code maps Azure WAF to OCSF **6004 "Web Resources Activity"** (Application Activity
category). This is wrong on two counts:

- **The number is stale.** In current released OCSF, the Application-Activity web class is
  **6001 Web Resources Activity** (category_uid 6); its `activity_id` enum is CRUD-style
  (Create/Read/Update/Delete/Search/Import/Export/Share) — semantically a *content-management*
  class, not a security-control class. Verified at [schema.ocsf.io/classes/web_resources_activity](https://schema.ocsf.io/classes/web_resources_activity).
- **A dedicated WAF class exists but is not yet a stable released class.** OCSF discussion
  [#671](https://github.com/ocsf/ocsf-schema/discussions/671) proposes **Web Application Firewall
  Activity (6005)** with `activity_id` ∈ {Allow=1, Count=2, Challenge=3, Block=4}, but maintainers
  steered toward reusing **HTTP Activity (4002)** with a firewall/`disposition_id` overlay rather
  than minting a new class.

**Recommendation:** normalize Azure WAF to **OCSF HTTP Activity, `class_uid = 4002`,
`category_uid = 4` (Network Activity)** ([schema.ocsf.io/classes/http_activity](https://schema.ocsf.io/classes/http_activity)).
This is the idiomatic 2026 target: OCSF's own HTTP Activity guidance explicitly says to normalize
"Web Application Firewalls (WAF) … and anything else with HTTP traffic to this Event Class"
([OCSF schema browser](https://schema.ocsf.io/)). It is a *Network Activity* class, so the WAF
disposition rides on `disposition_id`, and `activity_id` carries the HTTP verb (Get/Post/…).

> **Action item for the SDK:** the `SecurityEvent.ocsf_class` field comment in
> `packages/firewatch-sdk/src/firewatch_sdk/models.py:79` still says "e.g. 6004 = Web Resources
> Activity", and `normalizer` examples reference 6004. That stale number should be corrected when
> the Azure plugin lands (HTTP Activity = 4002 for WAF). This is the same outdated mapping the
> legacy normalizer baked in — do not reproduce it.

### 2b. action → OCSF disposition_id (ADR-0020) and SecurityEvent.action (ADR-0012)

OCSF `disposition_id` enum (from the Network Activity / firewall profile dictionary,
[ocsf-schema dictionary](https://github.com/ocsf/ocsf-schema/blob/main/dictionary.json)):
`1 Allowed, 2 Blocked, 6 Dropped, 15 Detected, 17 Logged` (among others).

| Azure action (any case) | SecurityEvent.action | OCSF `disposition_id` | Notes |
| --- | --- | --- | --- |
| `Blocked` / `Block` | `BLOCK` | 2 Blocked | terminating block |
| `Allowed` / `Allow` | `ALLOW` | 1 Allowed | rule matched, passed |
| `Detected` | `ALERT` | 15 Detected | detection-mode; logged not blocked |
| `Matched` / `AnomalyScoring` / `logandscore` | `ALERT` | 15 Detected | non-terminating CRS contribution to anomaly score — **NOT a block** |
| `Log` | `LOG` | 17 Logged | informational |
| `JSChallengeBlock` | `BLOCK` | 2 Blocked | challenge failed |
| `JSChallengeIssued`/`Pass`/`Valid` | `LOG` | 17 Logged | challenge lifecycle |

This corrects a concrete legacy bug: v1 mapped **`Matched` and `Detected` both to `BLOCK`**
(`legacy/app/sync.py:90`), inflating block counts. Per the MS docs `Matched`/`AnomalyScoring` are
explicitly non-terminating, and `Detected` is detection-mode (passed to backend). They should be
`ALERT`, mirroring how the Suricata normalizer already distinguishes ALERT from BLOCK
(`legacy/core/normalizer.py` `suricata_raw_to_security_event`, preserved in the new SDK contract).

### 2c. category + MITRE/CAPEC from CRS rule IDs (ADR-0014)

Both products are OWASP CRS underneath, so the **CRS rule-ID range is the source of truth** for
category and attack tagging. For App Gateway use `ruleId`/`ruleGroup` directly; for Front Door
parse the trailing rule ID out of `ruleName` (`...-SQLI-942100` → `942100`). CRS rule-ID ranges
([CRS docs — Rule IDs](https://coreruleset.org/docs/3-about-rules/ruleid/),
[Azure CRS rule groups](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-crs-rulegroups-rules)):

| CRS range | Category | Suggested MITRE ATT&CK | CAPEC (from CRS rule tags) | Severity |
| --- | --- | --- | --- | --- |
| 913xxx | Scanner/recon detection | T1595 Active Scanning (TA0043 Recon) | CAPEC-118 / 169 | low |
| 920xxx | Protocol enforcement/violation | T1190 Exploit Public-Facing App | CAPEC-272 | low–medium |
| 921xxx | Protocol attack (HTTP smuggling) | T1190 | CAPEC-105 | medium |
| 930xxx | Local File Inclusion (LFI) | T1190 | CAPEC-126 Path Traversal | high |
| 931xxx | Remote File Inclusion (RFI) | T1190 | CAPEC-193 | high |
| 932xxx | Remote Code Execution (RCE/cmd inj) | T1190 | CAPEC-248 Command Injection | critical |
| 933xxx | PHP injection | T1190 | CAPEC-242 | high |
| 941xxx | XSS | T1059 / T1190 | CAPEC-63 XSS | high |
| 942xxx | SQL Injection | T1190 | CAPEC-66 SQLi | high |
| 943xxx | Session fixation | T1190 | CAPEC-61 | medium |
| 944xxx | Java attacks (e.g. Log4Shell) | T1190 | CAPEC-242 | critical |
| 949xxx / 959xxx / 980xxx | Anomaly-score blocking/eval | T1190 | — | derive from score |

Notes:
- The CRS source files carry real `capec/...` and `paranoia-level/...` tags in rule metadata
  ([CRS docs](https://coreruleset.org/docs/3-about-rules/ruleid/)). The plugin can ship a static
  `ruleId-range → (category, T-id, TA-id, CAPEC, severity)` table — **no runtime dependency on CRS
  needed** (ADR-0014: "extract at normalize-time, no new deps"). This static table replaces v1's
  7-entry `RULE_CATEGORIES` dict that produced the ~68% "Other" rate.
- `kill_chain_phase` derives from the tactic (mostly `Initial Access`/`Reconnaissance`).
- The legacy `categorize_rule()` covered only `942/941/930/932/920/949/300` and fell through to
  `"Other"` for everything else (913, 921, 931, 933, 943, 944, custom rules, RateLimit/GeoBlock
  unless string-matched). **That fall-through is the direct cause of the 68% "Other".** The future
  plugin's static table must cover the full CRS range plus Azure's custom-rule names.

### 2d. severity — never leave it empty

The legacy Azure path never set `severity` at all (the `LogEntry` shape had no severity field; see
`legacy/app/sync.py`), so every Azure event landed with `severity = None`. The new plugin must
always populate it. Two complementary signals:

1. **Primary: CRS category** (table in 2c) — SQLi/XSS/RCE = high/critical, protocol/scanner =
   low/medium.
2. **Refinement: anomaly score** — when `action`/`message` carries an anomaly total (e.g. Front
   Door `Inbound Anomaly Score Exceeded (Total Score: N)`), escalate. CRS default inbound
   threshold is 5; treat ≥ threshold as high+, large scores as critical.

Map to FireWatch `SeverityLiteral` {info, low, medium, high, critical}, which lines up with OCSF
`severity_id` (1 Informational … 5 Critical) per ADR-0020.

---

## 3. Critique of the legacy approach — verdict: band-aid, discard the wiring

The relevant code is `legacy/app/sync.py` (`pull_azure_logs`) and the Azure half of
`legacy/core/normalizer.py` (`log_entry_to_security_event` + `categorize_rule`). Assessment:

**Non-standard / band-aid characteristics (discard):**

1. **Lossy projection at the KQL layer.** `pull_azure_logs` does
   `| project TimeGenerated, clientIp_s, ruleId_s, action_s, requestUri_s, details_message_s`
   (`sync.py:84`). It throws away `ruleGroup`, `ruleSetType/Version`, `transactionId`, `policyId`,
   `hostname`, `details.data/file/line`, `httpMethod`, `host` — i.e. nearly everything needed for
   MITRE/CAPEC tagging, request grouping, and forensic drill-down. ADR-0024's "functional oracle"
   value is in the *scoring logic*, not this projection.
2. **Wrong action mapping.** `{"Blocked","Detected","Matched"} → "BLOCK"` (`sync.py:90`) collapses
   three distinct dispositions into one and mislabels non-terminating/detection events as blocks
   (see 2b). Standard practice keeps ALERT vs BLOCK separate (Suricata already does).
3. **Severity dropped entirely.** The `LogEntry` model has no severity; Azure events were stored
   with empty severity. Substandard — severity is derivable from the CRS category and anomaly score.
4. **~68% "Other" categories.** `categorize_rule()` knows 7 prefixes and falls through to "Other".
   No coverage of 913/921/931/933/943/944 or Azure custom rules. No MITRE/CAPEC at all (predates
   ADR-0014).
5. **Hardcoded fabricated fields.** `destination_port=80, protocol="TCP"` are invented (Azure WAF
   logs carry neither), and `source_ip` defaults to `"0.0.0.0"`. Fabricating transport fields is
   exactly the kind of guess the canonical-schema skill forbids; unknown fields should stay in
   `RawEvent.data`, not be filled with placeholders.
6. **"Try legacy AzureDiagnostics first" by trial-and-error.** The comment calls AzureDiagnostics
   "most common" and runs it speculatively, swallowing failures (`_query` returns `[]` on any
   Exception, `sync.py:43`). Silent broad `except Exception` masks auth/permission/schema errors as
   "no data" — operationally dangerous. Table selection should be explicit config, not a guess.
7. **Geo-lookup baked into sync** (`geo_lookup_ips`) and a plaintext `http://ip-api.com` call —
   cross-cutting concern that belongs in an enricher port, not the Azure source. (Also HTTP not
   HTTPS.)

**Worth keeping (logic, not wiring):**
- The **`azure-monitor-query` LogsQueryClient + `DefaultAzureCredential`** approach is the correct,
  standard SDK for the Log-Analytics pull path. Keep the *technique*; rewrite the queries to select
  the full field set against resource-specific tables with explicit `AzureDiagnostics` fallback.
- The **watermark + 5-minute overlap** pattern for incremental pulls (`sync.py:65-74`) is a sound
  idea for a pull-flavored plugin's checkpoint logic.
- The **rule-description capture** (`message` → human label) is useful as `rule_name`, but should
  come straight through normalization, not a side-channel `dict`.

**Verdict:** The legacy Azure ingestion+normalization is a **band-aid**. The pull *mechanism*
(SDK choice, watermarking) is salvageable as a pattern; the *normalization* (lossy projection,
collapsed actions, no severity, 68% Other, fabricated transport fields, no MITRE/OCSF) must be
**discarded entirely** and rebuilt against the field sets and mappings in sections 1–2. Per the
working agreement, port logic — never the wiring — and never import `legacy/`.

---

## 4. Sample data for golden-test fixtures

We have no real Azure samples. Usable public, documented sources (replace any IPs with RFC 5737
doc ranges — 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — before committing, per the testing
lessons):

1. **MS Learn schema examples (authoritative, ready to copy):**
   - App Gateway firewall-log JSON (the 920350 record): [web-application-firewall-logs](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/web-application-firewall-logs).
     Already uses doc IP `203.0.113.147`.
   - Front Door WAF SQLi block record (942100): [waf-front-door-monitor](https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-monitor).
     Uses `xxx.xxx.xxx.xxx` placeholders — substitute RFC 5737 IPs.
   - Both docs live in the open-source [MicrosoftDocs/azure-docs](https://github.com/MicrosoftDocs/azure-docs)
     repo (search the `web-application-firewall` article tree) — convenient for pulling raw markdown
     with the JSON blocks.
2. **Microsoft Sentinel detection content (real KQL against these tables + column names):**
   [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) — e.g. the
   `Solutions/Azure Web Application Firewall (WAF)/Analytic Rules/App-GW-WAF-Scanner-detection.yaml`
   rule shows the exact resource-specific column names and realistic attack patterns to model
   fixtures on. Sentinel SQLi/XSS detection templates ([waf-new-threat-detection](https://learn.microsoft.com/en-us/azure/web-application-firewall/waf-new-threat-detection)).
3. **CRS rule corpus for category/CAPEC fixtures:** [coreruleset/coreruleset](https://coreruleset.org/docs/3-about-rules/ruleid/)
   `rules/REQUEST-9xx-*.conf` files carry rule IDs, messages, `capec/` and `paranoia-level/` tags —
   ideal for building and verifying the `ruleId → (category, MITRE, CAPEC, severity)` table.

**Fixture recommendation:** build at least two golden inputs — one `ApplicationGatewayFirewallLog`
row (discrete `ruleId`/`ruleGroup`) and one `FrontDoorWebApplicationFirewallLog` row (dotted
`ruleName` + `details.matches[]`) — covering each action (Block/Detected/Matched/Allowed/Log) and
2-3 CRS families (SQLi 942, XSS 941, RCE 932, scanner 913), asserting the full normalized
`SecurityEvent` including `severity`, `category`, `attack_technique`, `capec_id`, `ocsf_class=4002`.

---

## Summary of recommendations for the future Azure plugin

1. **Ingestion:** Log Analytics KQL pull via `azure-monitor-query` + `DefaultAzureCredential`;
   prefer resource-specific tables (`AGWFirewallLogs`, Front Door equivalents) with explicit
   `AzureDiagnostics` fallback (config-selected, not try/except). Keep the watermark+overlap
   checkpoint pattern. Consider an Event Hub *push* flavor later.
2. **Two shapes:** handle App Gateway (`ruleId`/`ruleGroup`) and Front Door (parse `ruleName`)
   separately; normalize action casing.
3. **Action (ADR-0012):** Block/JSChallengeBlock→BLOCK, Allow→ALLOW, Detected/Matched/AnomalyScoring→ALERT, Log→LOG.
4. **OCSF (ADR-0020):** `ocsf_class = 4002` (HTTP Activity), `ocsf_category = 4`; `disposition_id`
   from action; `severity_id` from severity. **Fix the stale 6004 reference in the SDK.**
5. **Category + MITRE/CAPEC (ADR-0014):** static `ruleId-range → (category, Tid, TAid, CAPEC, severity)`
   table covering the full CRS range — kills the "Other" problem; no runtime CRS dependency.
6. **Severity:** always set, from CRS category + anomaly score. Never `None`.
7. **No fabricated fields:** don't invent `destination_port`/`protocol`; keep unmapped Azure fields
   in `RawEvent.data`.
8. **Legacy verdict:** band-aid — discard the normalization wiring; keep only the pull *technique*.
