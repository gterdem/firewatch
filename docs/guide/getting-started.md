# Your First 10 Minutes with FireWatch

**Audience:** You have just opened FireWatch for the first time. You are a Security
Operations Center (SOC) analyst — or an operator who wants to understand the analyst
experience before handing it off to one.

---

## What FireWatch is for you

FireWatch is a threat-monitoring dashboard that pulls together raw security logs — from a
Web Application Firewall (WAF) or an Intrusion Detection System (IDS) — and tells you,
right at shift start, which IP addresses need a block decision and which ones can wait.
It combines deterministic detection rules with an optional local AI model for a second
opinion, and it never sends your log data to an external service. Your first job is simple:
open the Dashboard, act on what is urgent, and dig into the evidence when you need to.

---

## The guided path through FireWatch

Follow these five steps in order the first time you sit down with the tool. Each step
links to the full page guide when you want more depth.

### Step 1 — Start on the Dashboard

The [Dashboard](dashboard.md) is your shift-start screen. It is designed to answer one
question immediately: "Is anything happening right now that needs a decision?" Open it
first, every shift, before you look at anything else.

Scan the four KPI (Key Performance Indicator) tiles at the top — Total events, Blocked,
Unique IPs, and Block rate — to get a sense of the scale of activity since you last
checked.

### Step 2 — Check the Triage Banner

The Triage Banner sits at the very top of the Dashboard. If it shows a count (for example
"3 actors need a BLOCK decision"), those are the actors FireWatch has already prioritised
for you based on their risk score and what happened to their traffic. Start there.

Each chip in the banner shows the source IP, an escalation tier badge (T1 through T4), and
a disposition label. **T1 chips are the most urgent** — they mean the traffic was allowed
through and may have reached your application.

Click the disposition label on a chip to see the rule evidence. Click the IP address to
open the entity slide-over for the actor's full history. Then press Block, Investigate, or
Done. If the banner reads "All clear", the queue is empty and you can move to a broader
review.

For a full explanation of escalation tiers, disposition labels, and risk score bands, see
the [Dashboard guide](dashboard.md) and the [Glossary](glossary.md).

### Step 3 — When something is flagged, open the IP

Any time you see an IP address in FireWatch — in the Triage Banner, the Threat Actors
table, or the Risk Movers sidebar — you can click it to open the entity slide-over. The
slide-over shows that actor's full event history, their risk score, the AI verdict (if the
AI engine is running), and quick action buttons, all without leaving the page you are on.

Use the slide-over to gather enough evidence to make a decision. If you need more, the
slide-over contains a "View logs for this IP" link that takes you directly to step 4.

### Step 4 — Use Network Logs to dig in

The [Network Logs page](network-logs.md) is where you read the raw event feed — one row
per network event. Use it when the Dashboard flags a suspicious IP or attack category and
you need to read the actual log entries before deciding what to do.

Type an IP into the Source IP filter, or use the "Ask the network" bar to write a
plain-English query (for example `"show blocked high severity TCP traffic"`). The table,
the Entity Relationship Graph, and the top source-destination pairs all update together to
reflect your filter.

Expand any row by clicking its body to see the full detail: destination IP, protocol, JA4
fingerprint, DGA score, payload snippet, and more. If you see Alert events alongside Block
events for the same IP, note the destination IPs — alerted traffic was not stopped and
may have reached its target.

### Step 5 — Settings to connect a source

If FireWatch is not yet collecting data, or if you want to add a new source, go to the
[Settings page](settings.md). Installing a source plugin (for example
`pip install firewatch-source-suricata`) causes a configuration card to appear here
automatically. Fill in the required fields, flip the Active toggle, and press Test to
confirm connectivity.

The Settings page is also where you tune the triage threshold (how severe a threat must
be before it appears in the Triage Banner) and configure a webhook to send alerts to Slack
or Discord.

---

## Quick reference

| If you want to… | Go to… |
|-----------------|--------|
| See what needs a decision right now | [Dashboard](dashboard.md) → Triage Banner |
| Understand geographic attack patterns | [Threat Intelligence](threat-intelligence.md) |
| Audit what the AI concluded and why | [AI Engine](ai-engine.md) |
| Read raw log events and filter them | [Network Logs](network-logs.md) |
| Connect a data source or tune alerts | [Settings](settings.md) |
| Look up a term | [Glossary](glossary.md) |

---

## Where to go next

Once you are comfortable with the basic flow, each page guide goes deeper into the panels,
controls, and worked scenarios for that page. The [Glossary](glossary.md) is the single
reference for every acronym and term used across the guides — if a word is unfamiliar,
look there first.
