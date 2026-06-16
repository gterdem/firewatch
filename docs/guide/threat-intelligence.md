# Threat Intelligence — Page Guide

**Audience:** Junior Security Operations Center (SOC) analyst — you know security basics and
are new to FireWatch.

**Series note:** This is the second guide in the per-page series. Every page guide follows the
same five-section template used in `docs/guide/dashboard.md`.

---

<!-- SCREENSHOT PLACEHOLDER: replace this comment with a full-width screenshot of the
     Threat Intelligence page once the public repo is set up and screenshots can be committed. -->

---

## 1. What this page is for

The Threat Intelligence page answers one question: **"Who is attacking us, and where are they
coming from?"** It shifts your focus from individual events (handled on the Dashboard and Network
Logs pages) to the *networks and geographies* behind the traffic — the networks that host the
attacking IP (Internet Protocol) addresses, and the countries associated with those addresses.

Two lenses are available in the same panel. The **Country** lens plots each source IP on a world
map so you can see geographic clusters at a glance. The **ASN** (Autonomous System Number) lens
ranks the operator-level networks — internet service providers, cloud providers, hosting companies
— that are sending the most traffic, so you can spot infrastructure patterns that a country view
alone would miss.

All geo-enrichment happens on the FireWatch server using a local database. Nothing is sent to an
external service.

---

## 2. What you are looking at

Panels appear on the page in this order, top to bottom:

| # | Panel name | One-line purpose |
|---|------------|-----------------|
| 1 | **Geographic Distribution** | Plots each source IP as a circle on a world map (Country mode) or ranks the top autonomous systems by event volume (ASN mode); a Country / ASN toggle switches between the two views. |
| 2 | **Event Analytics** | Shows six summary stat tiles (Total Events, Blocked, Unique IPs, Block Rate, Top Country, Countries) plus the most-triggered blocked rule, and a Categories Over Time table breaking down attack types across the most recent time periods. |

---

## 3. How to read it

### The Country / ASN toggle

The toggle in the top-right corner of the Geographic Distribution panel controls which lens you
are looking at. Only one view is active at a time.

| Toggle position | What you see |
|-----------------|-------------|
| **Country** | A world map with a circle marker for each source IP. Circle size scales with event count — a larger circle means more events from that location. |
| **ASN** | A ranked list of the top autonomous systems, sorted by total events. Each row shows the AS number, the operator name, event count, distinct IP count, and the percentage of traffic that was blocked. |

### Reading the geo map (Country mode)

Each circle marker on the map is color-coded by what FireWatch knows about the source IP:

| Marker style | IP class | What it means |
|---|---|---|
| Solid amber circle | Residential | Best available origin signal — likely the actor's real location. |
| Hollow amber ring | Datacenter or VPN-likely | The IP is a cloud or VPN exit node; the country shown is where the server is hosted, not necessarily where the actor is. |
| Muted / faint circle | Unresolved | Geo-enrichment is pending or incomplete — treat the location with caution. |

Click any circle to open a small popup. The popup shows the IP address, the city and country,
the total event count, and a provenance line naming the autonomous system and its IP class
(for example: *"AS16509 Amazon — cloud egress; geographic origin unreliable."*). This line is
there to stop you anchoring on a country when the traffic is likely routing through a cloud or
VPN network.

#### The Unresolved / private chip

Below the map you may see a small chip labeled **Unresolved / private: N IPs not mapped**. This
chip counts source IPs that could not be placed on the map — either because they are RFC-1918
private addresses (like 192.168.x.x or 10.x.x.x) or because geo-enrichment has not yet run for
them. The chip makes this count visible rather than silently dropping those IPs. If you have a
large unresolved count and your traffic is from a private lab network or a monitored internal
segment, this is expected.

When there are no geo-resolvable IPs at all, the panel shows an honest empty state explaining
why rather than displaying a blank map frame.

### Reading the ASN list (ASN mode)

Each row in the ASN panel shows:

- **Rank and AS label** (for example `AS15169`) — click the label to open the Network Logs page
  pre-filtered to that ASN, so you can read the individual events without leaving the threat
  context.
- **Operator name** — the registered name of the network (for example "Google LLC" or "Amazon
  Technologies Inc.").
- **Event count** — total events seen from any IP in this autonomous system during the current
  data window.
- **Distinct IP count** — how many different source IPs within this ASN sent events.
- **Blocked %** — the fraction of those events that were blocked. Values at or above 50% turn
  red to flag high-traffic, high-block autonomous systems.

By default the list shows the top five ASNs. If more are available, a **View all N ASNs** link
expands the list in place. Click **Show less** to collapse it again.

#### The Narrate button

Each ASN row has a **Narrate** button on the right. Clicking it generates a short plain-language
summary (up to approximately 120 words) that describes the autonomous system's activity pattern
based on the data FireWatch has already collected — event volume, IP spread, block rate, and
similar fields.

After the narration appears, you will see:

- A **provenance chip** — either **RULE** (the summary was built entirely from the rule engine's
  data) or **AI+RULE** (the local AI engine contributed an additional interpretation). If the
  AI engine is offline, a small notice reads *"Rules-only · AI offline"*.
- A **Grounded in** line listing the exact data fields used to produce the narration, so you can
  verify the summary refers to real data and is not fabricated.
- A **Re-explain** button to regenerate the narration if you want a second pass.

The narration is produced locally. No data leaves FireWatch to reach an external AI service.

### Reading the Event Analytics panel

**Stat tiles** (top of the panel):

| Tile | What it counts |
|------|---------------|
| Total Events | All log events in the current data window. |
| Blocked | Events where the WAF (Web Application Firewall) or IDS (Intrusion Detection System) issued a block or drop action. |
| Unique IPs | Distinct source IP addresses seen in the window. |
| Block Rate | Blocked events as a percentage of total events. |
| Top Country | The country associated with the most blocked events, or "Unknown" when no geo data is available. |
| Countries | The number of distinct countries seen in the window. |

**Top Blocked Rule** (shown only when data is available): the rule identifier that fired most
often in the current window. This tile is hidden when there is no rule data.

**Categories Over Time** (table at the bottom of the panel): the most recent time periods
(up to ten), with columns for each attack category and a total. Each category column is colored
to help you scan for spikes:

| Column label | Attack category | Color |
|---|---|---|
| SQLi | SQL Injection (WAF rules 942*) | Orange |
| XSS | Cross-Site Scripting (WAF rules 941*) | Amber |
| Bot | Bot activity (WAF rules 300*) | Blue |
| Rate Limit | Rate-limited requests | Red |
| Geo Block | Geo-blocked traffic | Cyan |
| LFI | Local File Inclusion (WAF rules 930*) | Pink |
| IDS Alert | Suricata IDS alerts | Orange |

A zero in a cell is shown in a muted color. A non-zero count is shown in the category's color,
making hot periods easy to spot by scanning the row.

---

## 4. What you would do here

### Scenario A — "I want to know which networks are behind the most attacks"

1. Open the **Geographic Distribution** panel and click **ASN** in the toggle.
2. Read the ranked list. Look at the **distinct IP count**: a high number of distinct IPs from
   one autonomous system suggests a coordinated or distributed attack originating from that
   provider's infrastructure, not just a single machine.
3. If one ASN stands out, click **Narrate** to get a plain-language summary of its activity.
   Check the **Grounded in** line to confirm the summary is based on real fields.
4. Click the **AS number label** to jump to Network Logs filtered to that ASN. Scan the raw
   events to see what rules fired and whether any traffic was allowed through.

### Scenario B — "I see a cluster on the map and want to investigate"

1. In **Country** mode, click a circle on the map to open the popup. Read the provenance line
   at the bottom of the popup. If the IP class is *datacenter* or *VPN-likely*, the geographic
   location shown is the hosting country, not the actor's true location — treat it as
   infrastructure context only, not a reliable actor origin.
2. Note the event count in the popup. A large circle with a high count means that IP has been
   consistently active.
3. Switch to **ASN** mode. Find the autonomous system that corresponds to the IP's AS label
   from the popup. Use **Narrate** for a summary, then click the AS label to pivot to Network
   Logs.

### Scenario C — "I want to spot a spike in a specific attack type over time"

1. In the **Event Analytics** panel, look at the **Categories Over Time** table.
2. Scan down the colored columns. A period where the **SQLi** column turns bright orange (a
   non-zero value) when it has been muted for several periods is a signal that SQL Injection
   attempts increased in that window.
3. Note the period label (ISO date or date-hour) and take that time reference to the Network
   Logs page to search for the corresponding events.

---

## 5. Terms used here

<!-- GLOSSARY CANDIDATES -->

- **SOC (Security Operations Center)** — a team responsible for monitoring, detecting, and
  responding to security events.

- **IP (Internet Protocol address)** — a numerical label assigned to a device on a network,
  used here to identify the source of incoming requests.

- **WAF (Web Application Firewall)** — a security control that inspects HTTP traffic and blocks
  requests matching known attack patterns (for example, Azure Application Gateway WAF).

- **IDS (Intrusion Detection System)** — a system that monitors network traffic for suspicious
  activity and generates alerts (for example, Suricata). Unlike a WAF, an IDS in detection mode
  alerts but does not block.

- **ASN (Autonomous System Number)** — a unique identifier assigned to a block of IP addresses
  that are managed under a single routing policy by one organization (an internet service
  provider, cloud provider, or hosting company). Looking at ASNs lets you see which networks —
  not just which countries — are the source of attack traffic.

- **GeoIP** — the process of mapping a public IP address to a geographic location (country,
  city, latitude/longitude) using a local database. FireWatch does this entirely on-box using
  the DB-IP Lite database (ADR-0047); no external service is called.

- **IP class** — FireWatch's classification of what kind of network a source IP belongs to.
  Classes: *residential* (likely the actor's real location), *datacenter* (a cloud or hosting
  provider exit), *vpn-likely* (a VPN or anonymiser exit), *private* (an RFC-1918 non-routable
  address, not plotted on the map), and *unresolved* (enrichment pending or absent).

- **RFC-1918** — the internet standard that reserves specific IP ranges (10.x.x.x, 172.16–31.x.x,
  192.168.x.x) for private networks. These addresses are never routable on the public internet
  and cannot be geo-located — FireWatch counts them in the Unresolved / private chip rather than
  showing them on the map.

- **Provenance chip** — a small label on a narration that tells you what produced it:
  **RULE** means the summary was built entirely from deterministic rule data; **AI+RULE** means
  the local AI engine also contributed an interpretation. The chip is there so you know how to
  weight the summary.

- **Narration** — a short (up to ~120 words) plain-language summary of an ASN's behavior,
  generated on-box from the data FireWatch already holds. The **Grounded in** line lists the
  exact data fields used, so you can verify the narration is not fabricated.

- **SQLi (SQL Injection)** — an attack that embeds malicious SQL commands inside a request,
  hoping to manipulate a database. Tracked here by WAF rule prefix 942*.

- **XSS (Cross-Site Scripting)** — an attack that injects client-side scripts into a web page
  to run in other users' browsers. Tracked here by WAF rule prefix 941*.

- **LFI (Local File Inclusion)** — an attack that manipulates file-path parameters to read
  files from the server's local filesystem. Tracked here by WAF rule prefix 930*.
