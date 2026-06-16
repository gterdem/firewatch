# Air-Gapped Operation

FireWatch can operate with **zero outbound network egress** from the core pipeline. This document is produced from a sweep of the actual source code (see Egress Inventory below) and describes the honest boundary, the zero-egress configuration recipe, the geo DB copy-in workflow, and a verification recipe.

> **Honest boundary:** "zero-egress" applies to the core pipeline, offline MMDB geo enrichment, local AI inference, and push/SSH sources (e.g. Suricata). Cloud-API sources (Azure WAF) are inherently online and are explicitly out of scope for air-gapped operation — see the Sources section below.

---

## Egress Inventory

Every outbound network path in a default deployment, and its air-gapped alternative:

### 1. Geo enrichment (online) — `geo_provider=online`

| Property | Detail |
|---|---|
| Code | `packages/firewatch-core/src/firewatch_core/adapters/geo_enricher.py` lines 51-53 |
| Protocol | **Plaintext HTTP** (ip-api.com free tier is HTTP-only; documented as NB-3 in the source) |
| Trigger | Every enrich cycle when `geo_provider=online` |
| Data sent | The source IPs from collected events (attacker-facing data to a third party) |
| Config switch | `geo_provider` field in `RuntimeConfig` (`FIREWATCH_GEO_PROVIDER` env var); default is **`offline`** since ADR-0039 |
| Air-gapped | **Off by default.** Set `geo_provider=offline` (or omit — it is already the default). |

### 2. Geo DB first-run download — `geo_provider=offline`, DBs absent

| Property | Detail |
|---|---|
| Code | `packages/firewatch-core/src/firewatch_core/adapters/geo_mmdb_fetch.py` — `ensure_dbs()` line 269 |
| Protocol | **HTTPS** to `download.db-ip.com` |
| Trigger | First call to `MmdbGeoEnricher.enrich()` when either DB-IP Lite MMDB file is absent |
| Data sent | **None.** Only a public artifact is fetched; no operator data, no IPs, no telemetry leaves the host (ADR-0039). |
| What is downloaded | DB-IP IP-to-City Lite + DB-IP IP-to-ASN Lite (CC-BY 4.0, no account required) |
| Integrity | SHA1 of the compressed download is verified against DB-IP's published checksum before atomic install |
| After first run | Zero egress — all lookups are local MMDB reads |
| Air-gapped | **Avoided by the copy-in workflow** (see below). Pre-place both files; no fetch happens. |

### 3. Local AI inference endpoint — `ollama_base_url`

| Property | Detail |
|---|---|
| Code | `packages/firewatch-core/src/firewatch_core/adapters/ai_openai.py` — `OpenAIEngine` |
| Protocol | HTTP to the configured `ollama_base_url` (default: `http://127.0.0.1:11434`) |
| Destination | **Loopback or RFC 1918 LAN only** — `LocalFirstViolation` is raised at construction for any host outside those ranges (ADR-0022 hard rule enforced at line 450) |
| Data sent | Normalized event summaries to the local inference endpoint; never leaves the host/LAN |
| Air-gapped | **Compatible as-is.** The validator ensures this can never be a public/cloud endpoint. |

### 4. Webhook notifier — `webhook_url`

| Property | Detail |
|---|---|
| Code | `packages/firewatch-core/src/firewatch_core/adapters/webhook_notifier.py` — `WebhookNotifier._post()` line 160 |
| Protocol | HTTPS (operator-configured URL) |
| Trigger | On threat score crossing `alert_threshold`, or after a sync cycle if `alert_on_sync=true` |
| Destination | Operator-supplied URL (Discord, Slack, or any HTTPS endpoint) |
| Data sent | Threat score fields: `source_ip`, threat level, score, AI insights |
| Air-gapped | **Operator's choice.** Leave `webhook_url` unset (the default `None`) for zero-egress operation. An operator-internal webhook (e.g. a LAN-side service) is also acceptable. |

### 5. Suricata collector — SSH or local file

| Property | Detail |
|---|---|
| Code | `packages/sources/suricata/src/firewatch_suricata/collector.py` — `_collect_remote()` |
| Protocol | **SSH** (asyncssh) in remote mode; local filesystem read in local mode |
| Destination | Operator's own Suricata sensor (not a third-party service) |
| Data direction | **Inbound only** — FireWatch pulls EVE JSON from the sensor; nothing is sent to the sensor |
| Air-gapped | **Compatible.** SSH to an operator-owned sensor on the same private network is not external egress. Use `mode=local` for fully isolated operation. |

### 6. Suricata fetch_ruleset action — SSH

| Property | Detail |
|---|---|
| Code | `packages/sources/suricata/src/firewatch_suricata/ruleset.py` — `stream_remote_rules()` line 62 |
| Protocol | **SSH** (asyncssh) |
| Destination | Operator's own Suricata sensor |
| Data direction | **Inbound only** — downloads the sensor's local `.rules` file for SID/message mapping |
| Air-gapped | **Compatible.** Same boundary as the collector. |

### 7. Azure WAF collector — Azure Log Analytics KQL

| Property | Detail |
|---|---|
| Code | `packages/sources/azure-waf/src/firewatch_azure_waf/client.py` — `collect()` line 277 |
| Protocol | HTTPS (Azure SDK: `azure-monitor-query` + `azure-identity`) |
| Destination | Azure Log Analytics workspace (Microsoft Azure endpoints) |
| Air-gapped | **Inherently online.** Azure WAF is a cloud service; this source cannot function without outbound connectivity to Azure. It is **out of scope for air-gapped operation.** |

---

## Zero-Egress Configuration Recipe

Apply all of the following to achieve zero outbound egress from the core pipeline:

```bash
# 1. Offline geo (default since ADR-0039 — no env var needed, but explicit is fine)
FIREWATCH_GEO_PROVIDER=offline

# 2. Local AI — loopback only (this is the default; Ollama running on the same host)
FIREWATCH_OLLAMA_BASE_URL=http://127.0.0.1:11434

# 3. No webhook (omit FIREWATCH_WEBHOOK_URL, or set an operator-internal LAN URL)
# unset = webhook_url defaults to None = no outbound alerts

# 4. Use push/SSH sources only; do NOT configure Azure WAF source instances
#    (any Azure WAF source instance requires outbound access to Azure)
```

Then place the DB-IP Lite files before first run (see the Geo DB Copy-In Workflow section below).

### What works in air-gapped mode

- Log ingestion, normalization, and scoring
- Rule-based detection and scoring
- AI threat classification (local LLM via Ollama or any OpenAI-compatible local runtime)
- Offline geo enrichment: country, city, lat/lon, ASN, AS name
- Dashboard and API (backed by local SQLite; no external dependencies)
- Suricata log collection (SSH to operator-owned sensor, or local file mode)

### What is unavailable in air-gapped mode

| Feature | Status | Notes |
|---|---|---|
| Azure WAF log collection | Unavailable | Inherently cloud-dependent |
| ip-api.com geo lookup | Unavailable | Requires internet; `geo_provider=online` is an explicit opt-in |
| Outbound webhook alerts | Operator's choice | Leave `webhook_url` unset; an operator-internal webhook URL is fine |
| DB-IP Lite first-run download | Unavailable on air-gapped host | Pre-place DBs via the copy-in workflow |

---

## Geo DB Copy-In Workflow

For air-gapped deployments, download the two DB-IP Lite MMDB files on a connected machine and copy them to the FireWatch host before first run. When the files are already present, no download is attempted.

### Step 1 — Download on a connected machine

```bash
# DB-IP Lite is published monthly.
# City Lite page: https://db-ip.com/db/download/ip-to-city-lite
# ASN Lite page:  https://db-ip.com/db/download/ip-to-asn-lite
# Download the .mmdb.gz files and decompress them.

YEAR=2026; MONTH=06
curl -L "https://download.db-ip.com/free/dbip-city-lite-${YEAR}-${MONTH}.mmdb.gz" \
     -o dbip-city-lite-${YEAR}-${MONTH}.mmdb.gz
curl -L "https://download.db-ip.com/free/dbip-asn-lite-${YEAR}-${MONTH}.mmdb.gz" \
     -o dbip-asn-lite-${YEAR}-${MONTH}.mmdb.gz

# Decompress
gzip -dk dbip-city-lite-${YEAR}-${MONTH}.mmdb.gz  # produces .mmdb
gzip -dk dbip-asn-lite-${YEAR}-${MONTH}.mmdb.gz
```

### Step 2 — Verify integrity (recommended)

DB-IP publishes SHA1 checksums at the same URL with a `.sha1` suffix. FireWatch verifies these automatically during a first-run download; for manual copy-in verify with:

```bash
# Fetch the expected SHA1
curl -sL "https://download.db-ip.com/free/dbip-city-lite-${YEAR}-${MONTH}.mmdb.gz.sha1"
# Compare against:
sha1sum dbip-city-lite-${YEAR}-${MONTH}.mmdb.gz

curl -sL "https://download.db-ip.com/free/dbip-asn-lite-${YEAR}-${MONTH}.mmdb.gz.sha1"
sha1sum dbip-asn-lite-${YEAR}-${MONTH}.mmdb.gz
```

### Step 3 — Copy to the air-gapped deployment

The geo DB files are resolved by `geo_mmdb_fetch._build_urls()` using the current year and month at startup time. The default install path is:

```
<firewatch_data_dir>/geo_data/dbip-city-lite-<YYYY>-<MM>.mmdb
<firewatch_data_dir>/geo_data/dbip-asn-lite-<YYYY>-<MM>.mmdb
```

Copy the decompressed `.mmdb` files to the `geo_data` subdirectory of the FireWatch data directory before starting FireWatch:

```bash
GEO_DATA_DIR="<firewatch_data_dir>/geo_data"
mkdir -p "$GEO_DATA_DIR"
cp dbip-city-lite-${YEAR}-${MONTH}.mmdb "$GEO_DATA_DIR/"
cp dbip-asn-lite-${YEAR}-${MONTH}.mmdb  "$GEO_DATA_DIR/"
```

### What happens when files are present

When FireWatch starts with the geo DB files already in place:

1. `MmdbGeoEnricher._open_readers()` detects both files present — `_try_first_run_fetch()` is not called.
2. `maxminddb.open_database()` opens the local files.
3. All subsequent IP lookups are local MMDB reads — zero network egress.

### Fail-safe: missing DB

If a DB file is missing or corrupt (e.g. partial copy), FireWatch:

1. Attempts a first-run download (which will fail with no outbound access).
2. Logs a `WARNING` that includes copy-in instructions pointing to this document.
3. Returns all events unchanged — enrichment is skipped, not fatal.

The `WARNING` message text (`_COPY_IN_HINT` in `geo_mmdb.py`) tells the operator exactly which files to place and where.

### Bring-your-own MMDB

Any MMDB file with DB-IP City/ASN-compatible field names can be used in place of the DB-IP Lite files. The reader is the standard `maxminddb` Python library. See `geo_mmdb._extract_city_record()` and `geo_mmdb._extract_asn_record()` for the exact field paths expected.

### Attribution

"IP Geolocation by DB-IP" — [db-ip.com](https://db-ip.com) — CC-BY 4.0.
This attribution is required wherever bundled DB-IP geo data is presented (dashboard, docs).

---

## Verification Recipe

To confirm FireWatch makes no unexpected outbound connections in the documented air-gapped configuration, run with outbound traffic blocked and verify full functionality.

### Option A — iptables egress-deny

```bash
# Block all outbound traffic from the FireWatch process user
sudo iptables -A OUTPUT -m owner --uid-owner $(id -u) -j DROP
# Allow loopback (required for local Ollama)
sudo iptables -I OUTPUT -o lo -j ACCEPT

# Start FireWatch with the zero-egress config
FIREWATCH_GEO_PROVIDER=offline \
FIREWATCH_OLLAMA_BASE_URL=http://127.0.0.1:11434 \
uv run firewatch run

# Remove the rule afterwards
sudo iptables -D OUTPUT -m owner --uid-owner $(id -u) -j DROP
```

### Option B — Docker `--network=none` (or Compose `internal: true`)

```yaml
# docker-compose.yml
services:
  firewatch:
    image: firewatch:latest
    network_mode: "none"
    environment:
      FIREWATCH_GEO_PROVIDER: "offline"
      FIREWATCH_OLLAMA_BASE_URL: "http://host-gateway:11434"
    volumes:
      - ./geo_data:/app/data/geo_data   # pre-placed MMDB files
  ollama:
    image: ollama/ollama
    # ollama stays on the internal network only
```

### Expected result

| Component | Expected behaviour |
|---|---|
| Geo enrichment | Resolves IPs from local MMDB; log shows `geo_mmdb: resolved N/M IPs (offline MMDB)` |
| AI analysis | Reaches local Ollama; no external connections |
| Webhook | Silent (no `webhook_url` set) |
| Azure WAF source | Do not configure; would fail |
| Dashboard API | Serves from local SQLite |

### What to check in logs

- No `WARNING: geo_enricher: batch lookup failed` lines (those come from the online enricher).
- Log line: `geo_mmdb: resolved N/M IPs (offline MMDB)` — confirms offline path.
- No `httpx.ConnectError` to external hosts.
- If any connection error to an unexpected external host appears, check for misconfigured `webhook_url` or an Azure WAF source instance.

---

## Security Notes

- FireWatch never sends operator telemetry to any third party by design. The only outbound calls it makes on its own initiative are: the one-time MMDB download (public artifact, no operator data), and local AI inference (loopback/LAN only, validated in code).
- The local-first AI invariant is enforced at engine construction — `LocalFirstViolation` is raised if `ollama_base_url` does not resolve to loopback or RFC 1918 (ADR-0022). Misconfiguration is caught immediately, not silently.
- For deeper hardening (NIST SP 800-233 covert-channel analysis, per-process egress-deny rules, attestation of the DB-IP file chain-of-custody), consult your organisation's air-gapped deployment standard.
