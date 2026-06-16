# Settings — Page Guide

**Audience:** Junior Security Operations Center (SOC) analyst and the operator configuring
FireWatch — you know security basics and are new to this tool.

**Series note:** This is the second guide in the per-page series. Every page guide follows
the same five-section template used here and in `docs/guide/dashboard.md`.

---

<!-- SCREENSHOT PLACEHOLDER: replace this comment with a full-width screenshot of the
     Settings page once the public repo is set up and screenshots can be committed. -->

---

## 1. What this page is for

The Settings page is where you connect data sources and tune how FireWatch alerts and
escalates threats. Think of it as the control room for what FireWatch watches and how
loudly it tells you about problems.

There are two broad things you do here:

- **Connect sources** — each installed source plugin (for example a Suricata IDS
  installation or an Azure WAF feed) appears as its own configuration card. Fill in the
  credentials or paths, turn the source on, and FireWatch starts collecting from it.
- **Tune alerting behavior** — set how severe a threat has to be before FireWatch sends
  you a notification, configure the webhook it posts to, and decide how the escalation
  policy should behave.

The page has one important design property: **source cards are generated automatically
from each plugin's configuration schema**. There is no hand-written page per source. When
you install a new source plugin the card appears here; when you uninstall it the card
disappears. You configure it, turn it on, and FireWatch does the rest. This is the modular
principle at work — zero core edits needed when you add a new data source.

---

## 2. What you are looking at

Cards and sections appear on the page in this order, top to bottom:

| # | Card / section | One-line purpose |
|---|----------------|-----------------|
| — | **Supervisor offline banner** | Appears only when the FireWatch backend supervisor process is unreachable; all collection controls are disabled until it recovers. |
| — | **Page header** | Title ("Settings") and a one-sentence summary explaining the install-to-card model. |
| — | **Ingest sources label** | A small section heading that marks where source cards begin. |
| 1 | **Source cards** (one per installed plugin) | Schema-driven configuration card for each installed source plugin. Active sources appear at the top, expanded; inactive sources appear below, collapsed. |
| 2 | **Local AI card** | Configure the local AI (Artificial Intelligence) inference endpoint, choose the model, enable or disable AI-assisted scoring, and set geo-enrichment and theme preferences. |
| 3 | **Escalation Policy card** | Set the triage threshold, see the two-axis alert-worthiness rule, review the registered detection rules table, and read the enforcement tier staircase. |
| 4 | **Notifications card** | Set the notification threshold, configure the webhook URL for Slack or Discord, and tune escalation-aware notification options. |
| 5 | **API access card** | Set or clear the shared API (Application Programming Interface) key that protects every request to FireWatch, including from this dashboard. |

---

## 3. How to read it

### Source cards — schema-driven configuration

When you install a source plugin (for example `pip install firewatch-source-suricata`),
FireWatch discovers it on the next page load and renders a card for it here. The card's
fields come directly from the plugin's own configuration schema — FireWatch generates the
form; you do not need to write any frontend code or edit any config file by hand.

Each card header shows:

- The source's display name and an icon (for example a satellite dish icon for Suricata,
  a cloud icon for Azure WAF).
- A small badge indicating the source type.
- The source identifier (the `source_id`, which defaults to the type key in single-instance
  mode — for example `suricata`).
- The plugin version.
- A colored health dot.
- A status label.

For pull-type sources (sources that FireWatch reaches out to fetch data from), the card
header also shows an **Active / Off toggle**. Green means the source is running and
collecting; grey means it is turned off.

**Health dot color meanings:**

| Dot color | Meaning |
|-----------|---------|
| Green | Active — data is flowing normally. |
| Amber | Stale — the source is registered but no recent events have arrived. |
| Red | Error — the source collector has failed or gone dark. Click the dot to jump to the diagnostics section inside the card. |
| Grey | Not configured or no data yet. |

**Status label meanings for pull sources:**

| Label | What it means |
|-------|---------------|
| Active (with time ago) | Collecting normally; the time shows how long since the last successful pull. |
| Stale (with time ago) | Registered and running but no fresh events; may need investigation. |
| Error | Collector failure — check the diagnostics panel inside the card. |
| Parked / Backoff | The collector paused itself after repeated failures. Press "Sync now to resume" in the amber recovery banner at the top of the card body. |
| Off | Source is not turned on. Flip the Active toggle to start it. |
| Not configured | Config fields are empty — fill in the required values and save. |

**What the card body contains:**

When a card is expanded you see:

1. A recovery banner (amber, with a "Sync now to resume" button) — appears only when
   the source is in a paused or error state.
2. The config form — fields generated from the plugin's schema. Fill these in and press
   the Save button at the bottom.

Below the config form, for pull-type sources:

- **Sync now** — triggers an immediate data pull.
- **Test** — runs a connectivity check and returns a staged pass/fail checklist (see
  below). Only available when the source is Active.
- **Sync every N s** — the scheduled pull interval; edit the number and tab away to
  save it. Minimum 30 seconds, maximum 86,400 seconds (24 hours).
- **Last sync** information — the timestamp, how many events were ingested, and the
  status of the most recent pull.

For push-type sources (where the external system sends data to FireWatch, such as syslog
over UDP), the card shows a listener status line instead of Sync/Test controls.

### The Test / connectivity checklist

When you press **Test** on an active pull source, FireWatch runs a staged connectivity
check and returns the result as an ordered checklist. Each step in the checklist shows one
of three glyphs:

| Glyph | Meaning |
|-------|---------|
| ✓ | Step passed — that leg of the connectivity check succeeded. |
| ✗ | Step failed — this is where the problem is. Read the message below the step for details. |
| ⊘ | Step was skipped — usually because an earlier step failed and the later steps could not run. |

Read the checklist top to bottom. The first ✗ is where to focus your investigation. Steps
below the first failure are typically marked ⊘ because they depend on what failed above
them.

### Local AI card — sections

The card is divided into two labeled groups:

**AI engine group:**

| Control | What it does |
|---------|-------------|
| Enable AI engine (checkbox) | Turns AI-assisted scoring on or off. When off, every risk score is produced by the rule engine alone (shown as "rules only" in the scoring provenance line). |
| Local AI endpoint URL | The HTTP address of your local inference server — Ollama, vLLM, llama.cpp, or LM Studio; any OpenAI-compatible endpoint. Enter the URL and press Save. |
| Test button (next to the URL) | Probes the endpoint without saving anything; lists the models available at that address. |
| Model selector | The model that FireWatch will use for AI-assisted scoring and narration. The dropdown is populated from the endpoint you configured above. |
| Connection status | Shows "Connected" (green) with the active model name when the endpoint is reachable, "Disconnected" (grey) when it is not, or "Checking…" on first load. |

A scoring provenance line just below the card title summarizes the current mode in plain
language — for example "Scoring: local model llama3 · rules + AI" or "Scoring: rules only
· AI engine offline".

**Appearance group:**

| Control | What it does |
|---------|-------------|
| Geo enrichment | "Offline" uses the bundled MMDB (MaxMind database) file to resolve IP addresses to countries and ASNs — no outbound calls. "Online" uses ip-api.com. |
| Theme | Switches between Dark (default) and Light (presentation) color schemes for this session. |

### Escalation Policy card — sections

**Triage threshold field:** A dropdown (LOW / MEDIUM / HIGH / CRITICAL, default HIGH) that
controls the minimum severity band at which a threat actor is included in the Triage
Banner on the Dashboard. Raise it to reduce noise; lower it to see more actors.

**Alert-worthiness explainer:** A read-only box explaining that an actor reaches the
triage banner when *either* of two axes fires — the score-band axis (risk score meets or
exceeds the triage threshold) OR the escalation-tier axis (the detection rule has its
auto-escalate flag set, which forces the actor to surface regardless of score). This is
why a low-score actor can still appear in the banner.

**Registered detections table:** A read-only table listing every detection rule that is
registered in the escalation policy. Columns are:

| Column | What it shows |
|--------|--------------|
| Detection rule | The rule name. |
| Severity | The declared severity badge (CRITICAL / HIGH / MEDIUM / LOW), or "—" when not declared. |
| Auto-escalate | "Auto-escalate" badge when the rule forces escalation regardless of score; "—" otherwise. |
| 24h hits | How many times this rule fired in the last 24 hours (rolling count). |

The table paginates at 10 rows per page. Installing a source plugin adds that plugin's
rules to this table automatically.

**Enforcement tiers:** A read-only staircase showing the three tiers of automated
enforcement and which are active:

| Tier | Status | What it means |
|------|--------|---------------|
| WARN | Active | Every alert-worthy detection is logged and surfaced in the triage banner. |
| Require approval | Active | Escalated detections require an explicit Block action from you — no automated blocking without your confirmation. |
| Auto-block | Coming with SOAR | Displayed but greyed out — planned for the SOAR (Security Orchestration, Automation, and Response) integration. Not yet active. |

### Notifications card — sections

**Alerts group:**

| Control | What it does |
|---------|-------------|
| Notification threshold | The minimum severity band (LOW / MEDIUM / HIGH / CRITICAL, default CRITICAL) at which FireWatch posts an alert to your webhook. |
| Webhook URL | The outbound URL for alerts — for example a Slack or Discord incoming webhook. The secret value is never shown after saving; when set, the placeholder shows "•••• set — type to replace". |
| Notify me when a scheduled pull is blocked | When checked, FireWatch also sends an alert via the webhook when an automatic data-pull is throttled or rejected by the source. |

**Escalation group:**

| Control | What it does |
|---------|-------------|
| Also notify on auto-escalating detections | Default off. When on, a low-score threat that has the auto-escalate flag set (escalation tier 1 or 2) also triggers a webhook notification, even if its score is below the Notification threshold band. |

### API access card

The API key field protects FireWatch when it is accessible beyond the local machine. Once
a key is set, every request — including from this dashboard — must include it. The key is
held in memory for the current browser session; it is never stored in the URL or logged.

The card shows an honest status:

- **"No key set"** — the only protection is the loopback boundary (traffic is restricted
  to 127.0.0.1). Set a key before exposing FireWatch on a network.
- **"•••• set — type to replace"** — a key is configured; leave the field blank and save
  to keep the existing key, or type a new value to replace it.
- **"API key is configured — re-enter it to manage or replace it."** — a key exists on
  the server but the dashboard does not have it in memory (for example after a page
  reload). Re-enter the key to authenticate.

To clear the key entirely, leave the field blank and press Save.

---

## 4. What you would do here

### Scenario A — "Add a new source and start collecting"

1. Install the source plugin on your server:
   ```
   pip install firewatch-source-<name>
   ```
2. Reload the Settings page. A new source card appears in the **Ingest sources** section
   automatically — no page edits are needed.
3. Click the card header to expand it (or it may already be expanded if it is Active).
4. Fill in the required fields in the config form (for example the log file path for
   Suricata, or the subscription ID and resource group for Azure WAF).
5. Press **Save** at the bottom of the form. A "Settings saved." toast confirms success.
6. Flip the **Active** toggle in the card header to "Active" (green). The source begins
   collecting on the configured schedule.
7. Press **Test** to run the staged connectivity checklist. Read the result top to bottom.
   If any step shows ✗, the message below it tells you what is wrong.

### Scenario B — "A source has gone red — what happened?"

1. Find the source card with the red health dot. The status label will say "Error",
   "Parked", or "Backoff".
2. If a recovery banner appears at the top of the card body (amber, with a "Sync now to
   resume" button), the source paused itself after repeated failures. Press **Sync now to
   resume** to attempt recovery.
3. Press **Test** to run the connectivity checklist and see exactly which step is failing.
4. Alternatively, click the red health dot in the card header — this scrolls the
   diagnostics panel inside the card into view, which shows the last error message from
   the source.
5. Fix the underlying issue (for example a changed file path or expired credential), save
   the updated config, and press **Test** again to confirm the fix.

### Scenario C — "Set up alerting to Slack"

1. Scroll to the **Notifications** card.
2. Set the **Notification threshold** to the lowest severity band you want to be paged
   about (for example HIGH means you get a message for HIGH and CRITICAL threats only).
3. Paste your Slack incoming webhook URL into the **Webhook URL** field and press **Save**.
   The URL is stored as a secret on the server — it will not be echoed back to the page.
4. Optionally check **Also notify on auto-escalating detections** if you want a Slack
   message whenever a low-score threat is auto-escalated (for example an allowed-through
   actor whose detection rule has the auto-escalate flag set), even if it is below the
   threshold band.
5. Return to the Dashboard and wait for real traffic (or trigger a test event) to confirm
   the webhook fires.

---

## 5. Terms used here

<!-- GLOSSARY CANDIDATES: all terms below are candidates for the shared Glossary page -->

- **SOC (Security Operations Center)** — a team responsible for monitoring, detecting, and
  responding to security events.

- **Source plugin** — a software package that tells FireWatch where and how to collect
  telemetry. Examples: `firewatch-source-suricata` (for Suricata IDS logs),
  `firewatch-source-azure-waf` (for Azure WAF events). Install one and its card appears
  here; uninstall it and the card disappears.

- **IDS (Intrusion Detection System)** — a system that monitors network traffic for
  suspicious activity and generates alerts. Suricata is an IDS. Unlike a WAF, an IDS in
  detection mode alerts but does not block by itself.

- **WAF (Web Application Firewall)** — a security control that inspects HTTP traffic and
  blocks requests matching known attack patterns. Azure Application Gateway WAF is an
  example.

- **API (Application Programming Interface)** — a set of rules that allow software
  components to communicate. The FireWatch backend exposes an API; the API key protects
  access to it.

- **Pull source** — a source where FireWatch reaches out on a schedule to fetch logs (for
  example reading a Suricata log file every 300 seconds). The Active toggle and Sync
  controls are visible on pull-type source cards.

- **Push source** — a source where the external system sends data to FireWatch (for
  example syslog over UDP). No Sync controls appear; instead the card shows a listener
  status.

- **Schema-driven** — the source card fields are generated from the plugin's own
  configuration schema. FireWatch does not contain hand-written forms per source. Install
  a plugin and the correct fields appear automatically.

- **AI engine** — FireWatch's optional local inference layer. When enabled and connected
  to a local model server (Ollama, vLLM, llama.cpp, or LM Studio), it adds AI-assisted
  confidence signals to rule-engine scores. When disabled or disconnected, scoring falls
  back to rules only.

- **Geo enrichment** — the process of resolving an IP (Internet Protocol) address to a
  geographic location (country) and ASN (Autonomous System Number). Offline mode uses a
  bundled MMDB file; online mode queries ip-api.com.

- **MMDB** — MaxMind Database, a binary file format used to store IP-to-geography
  mappings. The bundled MMDB file lets FireWatch enrich IP addresses without any
  outbound network calls (zero-egress mode).

- **ASN (Autonomous System Number)** — a block of IP addresses operated by a single
  network provider (for example an ISP or cloud operator). Used in geo enrichment and
  for grouping distributed attack traffic.

- **Notification threshold** — the minimum severity band at which FireWatch posts an
  alert to your webhook. Set to CRITICAL by default. Distinct from the triage threshold.

- **Triage threshold** — the minimum severity band at which a threat actor is included in
  the Dashboard's Triage Banner "needs a decision" queue. Set to HIGH by default.
  Configurable in the Escalation Policy card.

- **Webhook** — an HTTP POST sent to a URL you specify, used here to deliver alerts to
  tools like Slack or Discord. FireWatch stores the webhook URL as a secret; the value is
  never echoed back to the UI.

- **Auto-escalate** — a flag on an individual detection rule that forces a threat to
  surface in the triage banner regardless of its numeric score. Visible in the Registered
  detections table in the Escalation Policy card.

- **SOAR (Security Orchestration, Automation, and Response)** — a category of tools that
  automate security workflows, including blocking decisions. FireWatch's auto-block tier is
  planned for the SOAR integration and is shown greyed out in the enforcement staircase.

- **Loopback boundary** — the restriction that FireWatch only accepts connections from
  127.0.0.1 (the local machine) when no API key is set. The API access card's empty state
  reminds you to set a key before exposing FireWatch beyond this boundary.

- **Source ID** — the identifier used internally for a source instance, defaulting to the
  source type key (for example `suricata`). Shown in the card header next to the display
  name.

- **Health dot** — the colored status indicator in each source card header, and also in
  the app navigation bar. Color is determined by the server-computed health field: green
  (ok), amber (stale), red (error/dark), or grey (not configured).
