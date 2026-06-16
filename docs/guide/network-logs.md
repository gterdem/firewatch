# Network Logs — Page Guide

**Audience:** Junior Security Operations Center (SOC) analyst — you know security basics and
are new to FireWatch.

**Series note:** This is the second guide in the per-page series. It follows the same
five-section template as `docs/guide/dashboard.md`.

---

<!-- SCREENSHOT PLACEHOLDER: replace this comment with a full-width screenshot of the
     Network Logs page once the public repo is set up and screenshots can be committed. -->

---

## 1. What this page is for

The Network Logs page is where you investigate the raw event feed. Use it when the
Dashboard flags a suspicious IP (Internet Protocol address), attack category, or action
and you need to read the actual log events — one row per network event — before deciding
what to do.

---

## 2. What you are looking at

Panels appear on the page in this order, top to bottom:

| # | Panel name | One-line purpose |
|---|------------|-----------------|
| 1 | **Page header** | "Network Logs" title next to a persistent "Local-only · 0 bytes egressed" trust badge confirming that all AI inference runs on this machine and no data leaves it. |
| 2 | **Strip Tiles** | Five compact tiles in a row — Events, Blocked, Distinct IPs, Top Talker, and Top Protocol — each showing a count or the leading value for that dimension; the two pivot tiles open a popover when clicked. |
| 3 | **Filter Bar** | An "Ask the network" natural-language query input above a row of dropdown and text filters (Source, Category, Action, Severity, Search, Dest IP, Protocol, JA4), plus Export and Clear-all controls; active filters appear as removable chips below the row. |
| 4 | **Top Source → Destination Pairs** | A small table of the top IP-to-IP traffic pairs, ranked by event count; clicking any row cross-filters the whole page to that source/destination combination. |
| 5 | **Entity Relationship Graph (ERG)** | An interactive force-directed graph showing IP nodes connected to ASN (Autonomous System Number) and attack-category nodes by weighted edges; clicking an IP node cross-filters the page. |
| 6 | **Network Logs Table** | The main raw-event grid — a sticky-header table with seven spine columns and an expandable detail panel per row, paginated with cursor-based next/previous controls above and below the table. |

---

## 3. How to read it

### Strip Tiles

The strip is a quick one-glance summary that re-queries every time you change a filter,
so the numbers always reflect what is currently in scope.

| Tile | What it shows |
|------|--------------|
| **Events** | Total log events matching the current filter. |
| **Blocked** | Events where the WAF (Web Application Firewall) or IDS (Intrusion Detection System) issued a block or drop action. |
| **Distinct IPs** | Count of unique source IP addresses in the filtered set. |
| **Top Talker** | The source IP with the most events; shows event count and — when available — the percentage of those events that were blocked. Click to open a popover listing the top five talkers; click any row in the popover to filter the page to that IP. |
| **Top Protocol** | The network protocol (TCP, UDP, etc.) with the most events and its share of total traffic. Click to open a popover listing the top five protocols; click any row to filter. Entries without a protocol field appear as "Other" and are not clickable. |

### Filter Bar

The filter bar controls everything on this page: changing any filter re-fetches the table,
re-draws the graph, and re-queries the pairs panel.

**"Ask the network" bar** — type a plain-English question such as
`"show blocked high severity TCP traffic"` and press Enter or click **Ask**. FireWatch sends
the query to the local AI model (zero-egress — it never leaves this machine), which tries to
convert it into one or more filter chips. A small **AI** badge confirms the parse succeeded
and the filters were applied. If the parse fails, a badge reading **AI: degraded** appears
and no filter is changed — you can rephrase and try again.

**Dropdown filters** — each opens a searchable list:

| Filter | Narrows to |
|--------|-----------|
| Source | Log source type (e.g. Azure WAF, Suricata). |
| Category | Attack category (e.g. SQL Injection, Port Scan). |
| Action | What the sensor did: Blocked (BLOCK + DROP), Block, Drop, Allow, or Alert (IDS). |
| Severity | Critical, High, Medium, Low, or Informational. |

**Text filters** — type directly in the box:

| Filter | Narrows to |
|--------|-----------|
| Search | Free text matched against rule name, signature, or HTTP (HyperText Transfer Protocol) payload. |
| Dest IP | Destination IP address of the traffic flow. |
| Protocol | Protocol string (e.g. `TCP`, `UDP`). |
| JA4 | JA4 TLS fingerprint — a hash of the TLS (Transport Layer Security) client handshake, available only for Suricata events that carry this field. |

**Filter chips** appear below the row, one per active filter. Click the **x** on any chip to
remove that filter. Click **Clear all** to remove every filter at once.

**URL deep-links** — the page keeps the active IP, Action, and Search filters in the browser
URL (as `?ip=`, `?action=`, and `?q=`). You can copy the URL from the address bar and share
it; the recipient lands directly on the filtered view. When you open a deep-link that contains
a filter, the page scrolls automatically to the log table.

### Top Source → Destination Pairs

This panel shows the source IP / destination IP pairs that generated the most events.
It is a quick way to spot which machines are talking the most and to whom. The top five
pairs are always visible; if there are more, a **View all** link reveals the rest inline.
Click any row to scope the entire page to that source–destination pair.

### Entity Relationship Graph (ERG)

The ERG is a force-directed network diagram. Think of it as a map of who is connected to
whom, built from the same events as the log table.

**Node types and colours:**

| Node shape/colour | What it represents |
|-------------------|--------------------|
| IP node — tinted by risk band (red/orange/yellow/neutral) | A source IP address seen in the current filter scope. Tint is derived from the local AI verdict (CRITICAL = red, HIGH = orange, MEDIUM = yellow, no verdict = neutral). |
| ASN node — blue tint | A network block (Autonomous System Number) that groups IP addresses under a single internet service provider or organisation. |
| Category node — purple tint | An attack category (e.g. "Port Scan") that one or more IPs attempted. |

**Edges (lines between nodes):**

| Edge colour | Relationship |
|-------------|-------------|
| Grey (flow) | Direct traffic flow between two IP addresses. Thicker lines = more events. |
| Blue tint | IP belongs to the ASN node it is connected to. |
| Orange tint | IP was seen using the attack category it is connected to. |

**Controls:**

- **Click the graph** first to activate scroll-to-zoom. Before you click, scrolling the
  mouse wheel scrolls the page; after you click, the wheel zooms the graph.
- **[+] / [−] buttons** (bottom-right corner) — zoom in or out.
- **[⤢] button** — reset zoom and pan back to the default fit-to-view.
- **Keyboard:** use `+` / `−` / `0` keys and arrow keys once the graph is focused.
- **Hover over a node** to see a tooltip with the node label, type, connection count, and
  AI verdict (if available). Hovered nodes and their direct neighbours stay fully visible;
  everything else dims.
- **Legend toggles** — click the ASN or Category legend toggle in the panel header to
  hide that node kind from the diagram.
- **Newly exposed banner** — when you change a filter and the graph picks up IP addresses
  or connections that were not visible before, a brief notice reads "N entities newly
  exposed by this filter". This is a factual count of what the filter change revealed; it
  does not infer anything about attacker behaviour.
- **Truncation chip** — if the event cardinality is very high, the graph shows only the
  top N nodes and displays a chip reading "showing top N — filter to narrow". Narrow the
  filter to see a more complete graph.

### Network Logs Table

The table is a scrollable grid with a sticky header. Each row is one network event.

**Spine columns (always visible):**

| Column | What it shows |
|--------|--------------|
| (chevron) | Click to expand a detail panel beneath the row. |
| **Time** | Event timestamp in compact format. |
| **Source** | A badge identifying the data source (e.g. WAF, Suricata). |
| **Source IP** | The attacker's IP address, shown as a clickable link. City and country are appended when geo data is available (e.g. `203.0.113.5 · Berlin, DE`). Click to open the entity slide-over for a full history of that IP without leaving this page. |
| **Action** | What the sensor did with this event: Block, Drop, Allow, or Alert. Colour-coded: red for Block/Drop, orange for Alert, muted for Allow. |
| **Severity** | The rule's severity rating: Critical, High, Medium, Low, or Informational. |
| **Signature** | The rule name, signature string, or rule ID that fired. Click the signature text to open a detail popover with the full rule context; click the link inside that popover to re-filter the table to all events matching the same signature. |

**AI Verdict column** (may narrow at very small screen widths):

| Sub-element | Meaning |
|-------------|---------|
| **RULE / AI** provenance chip | Whether the verdict was produced by the deterministic rule engine (RULE) or boosted by the local AI model (AI). |
| Verdict badge | **block**, **investigate**, or **monitor** — derived from the numeric risk score (block ≥ 70, investigate ≥ 40, monitor < 40). |
| Score (and confidence%) | The numeric risk score 0–100; when the AI engine is active, the AI model's confidence percentage is appended. |

When the AI engine is not running or has no score for a given IP, the AI Verdict cell is
blank — the row is always shown; only the verdict chip is absent.

**Row detail panel** — click anywhere on a row body (except the IP link or Signature cell)
to expand a detail panel beneath it. Multiple rows can be expanded simultaneously. The panel
groups additional fields into sections:

| Section | Fields shown |
|---------|-------------|
| Identity | Event ID, Timestamp, Source, Source ID, Category |
| Network | Source IP, Destination IP, Destination Port, Protocol |
| TLS / JA4 | JA4 fingerprint, JA4S, SNI (Server Name Indication), TLS Version |
| DNS | DNS Query, DGA Score (a local entropy heuristic for algorithmically generated domains) |
| HTTP | Payload snippet |
| Detection | Rule Name, Rule ID, Severity, Action |
| Geo | City, Country, ASN, AS Name |
| Provenance / Raw | Full raw_log value (collapsed by default; labelled as attacker-controlled) |

Sections that have no data for a given event are hidden entirely — you will never see a
wall of empty "—" rows.

**Pagination** — the table loads 25 rows at a time. The cursor-pager above and below the
table shows how many events match the current filter and provides **Next page** and
**First page** controls. There is no offset-based page numbering; the server sends a cursor
token that advances to the next batch.

### Disposition labels and severity bands

These apply to both the strip tiles and the table:

| Term | Values and meaning |
|------|--------------------|
| **Action / Disposition** | **Block / Drop** — request rejected before reaching the application. **Alert** — IDS flagged it but did not reject it (detection mode). **Allow** — request passed through. |
| **Severity** | **Critical, High, Medium, Low, Informational** — set by the detection rule; does not change based on what the sensor did with the event. |

---

## 4. What you would do here

### Scenario A — "The Dashboard flagged an IP; I want to read its events"

1. On the Dashboard, click the IP address in the Threat Actors table or a Triage Banner
   chip. FireWatch opens the entity slide-over. Inside the slide-over, click
   **View logs for this IP** — this navigates to the Network Logs page with `?ip=` set to
   that address and scrolls the viewport to the table automatically.
2. The filter bar shows an **IP** chip. The Strip Tiles, Top Pairs, and ERG all refresh to
   show only traffic from that source.
3. Read the **Action** and **Severity** columns to understand what the sensor did and how
   the rule scored each event. Expand a row by clicking its body to see the full Signature,
   Destination IP, Protocol, and Payload detail.
4. If you see Alert (IDS detection-mode) events alongside Block events, note the
   destination IPs — the alerted traffic was not stopped and may have reached its target.

### Scenario B — "I want to investigate high-volume talkers and who they are targeting"

1. Look at the **Top Talker** tile. Click it to open the popover listing the top five
   source IPs by event count. Click the IP with the highest count — the tile cross-filters
   the table and graph to that address.
2. Check the **Top Source → Destination Pairs** panel. The pairs now reflect only traffic
   from your chosen IP. Note which destination IPs appear; these are the hosts being
   targeted.
3. Click a pair row to narrow further to a specific source→destination flow.
4. In the ERG, find the IP node (it will be prominent because it has the most connections).
   Hover over it to see its verdict band. If it is tinted red (CRITICAL), the local AI
   model has already scored it as high risk.
5. Click the IP node in the graph to re-scope the table to that address; then read the
   Signature column to understand which attack rules fired.

### Scenario C — "I need to find events matching a specific rule or signature"

1. In the **Search** box in the filter bar, type the rule name, rule ID, or a payload
   keyword (up to 200 characters).
2. The table re-fetches immediately. The result count next to the filter row shows how
   many events match.
3. Click any row's **Signature** cell to open the rule detail popover — it shows the full
   rule name, rule ID, and category. Inside the popover, click the link to re-filter the
   table to all events that share the same signature across every source IP.
4. To share this filtered view with a colleague, copy the URL — it contains `?q=` with
   your search text and will reproduce the same filter when opened.

---

## 5. Terms used here

<!-- GLOSSARY CANDIDATES: all terms below are candidates for the shared Glossary page -->

- **SOC (Security Operations Center)** — a team responsible for monitoring, detecting, and
  responding to security events.

- **IP (Internet Protocol address)** — a numerical label assigned to a device on a network,
  used here to identify the source or destination of incoming traffic.

- **WAF (Web Application Firewall)** — a security control that inspects HTTP traffic and
  blocks requests matching known attack patterns (e.g. Azure Application Gateway WAF).

- **IDS (Intrusion Detection System)** — a system that monitors network traffic for
  suspicious activity and generates alerts (e.g. Suricata). In detection mode an IDS alerts
  but does not block.

- **ERG (Entity Relationship Graph)** — the interactive network diagram on this page that
  maps IP addresses, ASNs, and attack categories as nodes connected by weighted edges. Used
  to visualise which sources are related and how traffic flows.

- **ASN (Autonomous System Number)** — a block of IP addresses operated by a single
  organisation or internet service provider. ASN nodes in the ERG group multiple IP
  addresses that share the same network owner.

- **Action / Disposition** — what the WAF or IDS did with a specific request: Block (or
  Drop) means the request was rejected; Alert means the sensor flagged it but let it
  through; Allow means the request passed without a block.

- **Severity** — the rule-assigned importance of a detection event: Critical, High, Medium,
  Low, or Informational. Set by the detection rule; independent of what the sensor did with
  the traffic.

- **AI Verdict** — a per-IP recommendation (block, investigate, or monitor) derived from
  the local AI model's risk score. Shown only when the AI engine is running and has a score
  for the IP; the table always renders even when the verdict is absent.

- **Provenance chip (RULE / AI)** — a small badge that marks whether a score or verdict
  was produced by the deterministic rule engine alone (RULE) or with an AI confidence boost
  (AI). Defined in ADR-0035.

- **JA4** — a compact fingerprint of a TLS client handshake (analogous to a browser
  fingerprint for network traffic). Available only for sources such as Suricata that emit
  this field; absent for L7-only sources such as Azure WAF.

- **DGA Score** — a local heuristic score (0–1) estimating how likely a DNS query domain
  name was algorithmically generated (Domain Generation Algorithm). Computed on-device
  from entropy, consonant ratios, and digit ratios — no external DNS lookup is performed.

- **SNI (Server Name Indication)** — the hostname that a TLS client sends at the start of
  a handshake to indicate which certificate it expects. Visible in Suricata TLS events.

- **Top Talker** — the source IP that generated the most events in the current filter scope.

- **Cursor pagination** — a technique where the server returns a cursor token (an opaque
  pointer to the next batch of results) instead of a page number. FireWatch uses this so
  that large log sets can be paged efficiently without re-running full-table offset queries.

- **Zero-egress** — a guarantee that no log data, AI query, or inference payload is sent
  to any external service. The "Local-only · 0 bytes egressed" badge on this page signals
  that this guarantee is in effect.
