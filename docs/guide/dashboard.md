# Dashboard — Page Guide

**Audience:** Junior Security Operations Center (SOC) analyst — you know security basics and
are new to FireWatch.

**Series note:** This is the first guide in the per-page series. Every page guide follows the
same five-section template used here.

---

<!-- SCREENSHOT PLACEHOLDER: replace this comment with a full-width screenshot of the
     Dashboard page once the public repo is set up and screenshots can be committed. -->

---

## 1. What this page is for

The Dashboard is your shift-start screen. It answers one question immediately: **"Is anything
happening right now that needs a decision?"** Everything else on the page helps you understand
what is happening and gather enough evidence to take action without leaving FireWatch.

---

## 2. What you are looking at

Panels appear on the page in this order, top to bottom:

| # | Panel name | One-line purpose |
|---|------------|-----------------|
| 1 | **Triage Banner** | Leads the page; tells you how many threat actors need a block decision right now (or shows "All clear" when the queue is empty, with a legend explaining the escalation model). Actors in the **Observed** stratum (no escalation claim) never appear as chips here — they roll up into one aggregate line, "N detections on the record from M sources → Network Logs," shown below the chips (or below "All clear" when the queue is empty), so nothing is silently dropped. |
| 2 | **KPI Strip** | A thin row of four numbers — Total events, Blocked, Unique IPs (Internet Protocol addresses), and Block rate — each with a sparkline trend; the AI (Artificial Intelligence) engine status chip is pinned to the right. |
| 3 | **Threat Summary** | A single prose block spotlighting the top-scored actor: their IP, attack types, block rate, risk score, confidence, and (when the AI engine is active) bullet-point AI insights. |
| 4 | **Attack Categories** | A short bar chart of the attack types your adversaries attempted, ranked by how many distinct sources tried each type. |
| 5 | **Dispositions** | A short bar chart of what your WAF (Web Application Firewall) or IDS (Intrusion Detection System) *did* — blocked, alerted, allowed — grouped by rule category. |
| 6 | **Threat Actors** | A table of the top six scored source IPs, with columns for Last Active, Events, Blocked count, and Risk Score. When more than 50 distinct sources appear, rows are automatically rolled up by network block (/24 subnet or ASN) to signal a distributed attack. |
| 7 | **Detection vs Enforcement** | A compact strip of proportional bars (one per top attack type) showing the Blocked / Detected / Allowed split at a glance. Only visible when cross-tab data is available. |
| 8 | **Activity Timeline** | A stacked bar chart of event volume over the last 12 or 24 hours (your choice), with a severity-vs-disposition toggle and statistical spike markers. |
| 9 | **Risk Movers (sidebar)** | The right-side column opens with the IPs whose risk scores changed the most in the last hour — the "who is escalating right now?" view. |
| 10 | **Recommended Actions (sidebar)** | Directly below Risk Movers: up to three advisory cards suggesting Block, Investigate, or Monitor for the highest-priority actors. |
| 11 | **Recently Blocked Network Logs** | Full-width table at the bottom — the raw blocked-event feed (up to 8 rows per category tab), searchable by IP, with columns for Time, Source IP, Severity, Action, and Signature. |

---

## 3. How to read it

### Risk score bands

Every actor gets a numeric risk score from 0 to 100. The score is calculated by the rule
engine and, when the AI engine is running, boosted by the AI model's confidence verdict.

| Score range | Band label | What it means |
|-------------|-----------|---------------|
| 76 – 100 | CRITICAL | Highly confident, high-severity threat. Immediate attention required. |
| 51 – 75 | HIGH | Strong indicators; likely malicious. Should be reviewed this shift. |
| 26 – 50 | MEDIUM | Notable activity; could be reconnaissance or low-volume probing. |
| 0 – 25 | LOW | Minimal signal; informational only. |

Scores are shown as colored badges throughout the page (for example in the Threat Actors
table and the Threat Summary block). The color tracks the band: red for CRITICAL, orange for
HIGH, and so on.

### Escalation tiers (T1 – T4)

FireWatch also classifies each actor by what the WAF or IDS *did with* the traffic — not
just how high the score is. This is the escalation axis.

| Tier badge | Disposition | Urgency |
|------------|-------------|---------|
| **T1** | Got through — possible breach | Highest. The detection fired but the request got past your defenses. The attack may have reached your application. |
| **T2** | Flagged — needs review | High. A correlation rule or a source-declared high/critical severity flagged this actor as hostile. This label makes no claim about whether the traffic was actually blocked. |
| **T3** | Blocked — kept trying | Moderate. Your defenses held, but the source is determined and high-volume; consider an IP-level block. |
| **T4** | Blocked — didn't keep trying | Informational. Your defenses stopped every attempt, and this one didn't keep coming back. |
| **Observed** | On the record — no escalation claim | Calm default. Nothing asserted this actor is hostile; still scored and visible in Network Logs, never dropped. |

A T1 or T2 actor can surface in the Triage Banner even if their numeric score is LOW —
because a confirmed breach (T1) or a qualifying hostile assertion (T2) matters more than the score
alone.

Observed actors are the opposite case: they never surface as a banner chip on their own (unless
the numeric score independently crosses your Triage threshold — the severity-band axis still
scores them). Instead, the Triage Banner shows one summary line — "N detections on the record
from M sources → Network Logs" — whenever one or more observed actors exist, whether the banner
is showing chips or the all-clear state. This is why a watch-only install (Suricata, syslog,
ClamAV — no source that can block anything) can now reach the calm "All clear" screen on a normal
day: the background noise these sources generate is on the record, not in your queue.

### Disposition labels

You will see three outcome words used in the Dispositions panel and the log table:

- **Block / Drop** — the WAF or IDS rejected the request before it reached your application.
- **Alert / Detect** — the engine flagged the request but did not reject it (detection mode).
- **Allow** — the request passed through, with or without a rule match.

### Provenance chips

Small chips on panels tell you *what produced* a number or a recommendation:

- **RULE** — derived entirely from deterministic rule logic.
- **AI+RULE** — the rule engine scored the actor and the AI model provided an additional
  insight or confidence boost. The AI engine must be running and connected for this chip to
  appear.

The title "Threat summary" (not "AI threat summary") is intentional — FireWatch never claims
AI authorship for content that the rule engine produced on its own.

### KPI Strip details

| Tile | What it counts |
|------|---------------|
| Total events | All log events ingested in the current data window. |
| Blocked | Events where the WAF or IDS issued a block or drop action. |
| Unique IPs | Distinct source IP addresses seen in the window. |
| Block rate | Blocked events as a percentage of total events. |

Each tile has a small sparkline (a tiny trend line) so you can see whether the number is
rising or falling — without needing to look at the timeline.

### Activity Timeline controls

Two controls appear in the panel header:

- **12h / 24h toggle** — switches the chart to show the trailing 12- or 24-hour window from
  now. Click either button to activate it.
- **From / To pickers** — enter a custom date and time range (up to 24 hours). Editing the
  pickers takes over from the toggle; clicking 12h or 24h switches back to trailing-window
  mode.

The chart has two view modes — **Severity** (bars stacked into Critical / High / Medium / Low
segments) and **Disposition** (bars split into Blocked vs Allowed). A toggle in the panel
switches between them.

A small statistical spike marker appears on any hour-bucket where volume was unusually high
compared to the surrounding window.

---

## 4. What you would do here

### Scenario A — "Is there anything critical this shift?"

1. Look at the **Triage Banner** at the top. If it shows a count ("3 actors need a BLOCK
   decision"), read each actor chip. Each chip shows the source IP, the escalation tier badge
   (T1 – T4), and the disposition label. T1 chips (red, "Allowed through") are the most
   urgent.
2. Click the disposition label on a chip to open a popover with the full rule justification
   and block status — this gives you the evidence FireWatch used to surface the actor.
3. Click the IP address on any chip to open the entity slide-over panel. The slide-over shows
   the actor's full event history without taking you away from the Dashboard.
4. After reviewing, press **Block**, **Investigate**, or **Done** (dismiss) on the chip.
   Dismissed actors disappear from the banner and the recommendation queue immediately.

### Scenario B — "I want to understand what attack types are hitting us"

1. Read the **Attack Categories** panel (left column, top). The bars show how many distinct
   source IPs used each attack type. Click any bar to jump to the Network Logs page filtered
   to that attack type.
2. Compare it with the **Dispositions** panel directly below — if "SQL Injection" has many
   attempted sources but the Dispositions panel shows most SQL Injection events were blocked,
   your WAF rules are holding. If the Dispositions panel shows "Allowed" volume for the same
   category, investigate further.
3. Check the **Detection vs Enforcement** strip to see the blocked / detected / allowed
   proportions per attack type side by side.

### Scenario C — "An IP is flagged; I want to drill in"

1. In the **Threat Actors** table, find the IP. You can sort the table by **Top score** (risk
   magnitude) or **Top movers** (recent fastest-rising scores).
2. Click the IP address to open the entity slide-over. This shows the actor's full evidence
   chain without leaving the Dashboard.
3. If the IP also appears in the **Recently Blocked Network Logs** at the bottom, use the
   **Search by IP** field in the panel header to filter the log table to that address.
4. From the **Recommended Actions** sidebar card for that actor, click **Block** to log the
   decision, or **Investigate** to record that you are reviewing it.

---

## 5. Terms used here

<!-- GLOSSARY CANDIDATES: all terms below are candidates for the shared Glossary page -->

- **SOC (Security Operations Center)** — a team responsible for monitoring, detecting, and
  responding to security events.

- **IP (Internet Protocol address)** — a numerical label assigned to a device on a network,
  used here to identify the source of incoming requests or attacks.

- **WAF (Web Application Firewall)** — a security control that inspects HTTP traffic and
  blocks requests matching known attack patterns (e.g. Azure Application Gateway WAF).

- **IDS (Intrusion Detection System)** — a system that monitors network traffic for suspicious
  activity and generates alerts (e.g. Suricata). Unlike a WAF, an IDS in detection mode alerts
  but does not block.

- **Risk score** — a number from 0 to 100 computed by FireWatch's rule engine (and optionally
  boosted by the AI engine) that expresses how likely and how dangerous a source IP's activity
  is. Bands: LOW (0 – 25), MEDIUM (26 – 50), HIGH (51 – 75), CRITICAL (76 – 100).

- **Escalation tier (T1 – T4)** — a second axis that classifies actors by what the
  WAF/IDS *did* with the traffic, independent of the numeric score. T1 (allowed through) is
  the most urgent; T4 (blocked one-off) is informational.

- **Disposition** — what the WAF or IDS did with a specific request: Block/Drop, Alert/Detect,
  or Allow.

- **Provenance** — who or what produced a data point. FireWatch marks every panel and
  recommendation with either a RULE chip (rule engine only) or an AI+RULE chip (rule engine
  plus AI model).

- **Triage** — the process of reviewing flagged actors and deciding whether to block, continue
  investigating, or dismiss the alert.

- **Triage threshold** — the minimum score band (default: HIGH) at which an actor is included
  in the Triage Banner's "needs a decision" count. Configurable via the runtime config API.

- **Score derivation** — the record of whether the final score was produced by the rule engine
  alone (`RULE`) or was boosted by an AI confidence signal (`AI+RULE`). Used to populate the
  provenance chip.

- **Risk Movers** — actors whose score changed the most (up or down) in the last one-hour
  window. A rising delta (shown in red) means the threat is intensifying; a falling delta
  (shown in green) means it is subsiding.

- **ASN (Autonomous System Number)** — a block of IP addresses operated by a single network
  provider. When more than 50 scored source IPs appear, FireWatch rolls them up by ASN or /24
  subnet to signal a distributed (coordinated) attack pattern rather than showing 50+ rows.
