# Glossary

**Audience:** Junior Security Operations Center (SOC) analyst — new to FireWatch or to
security operations tooling.

This is the shared reference for every term used across the five page guides
([Dashboard](dashboard.md), [Network Logs](network-logs.md), [AI Engine](ai-engine.md),
[Threat Intelligence](threat-intelligence.md), and [Settings](settings.md)). Each guide's
"Terms used here" section points here; you do not need to re-read the same definition in
every guide.

Terms are listed alphabetically. Acronyms are spelled out on first use.

---

## A

**Additive-only (AI)** — The structural rule that governs how the AI (Artificial
Intelligence) engine interacts with risk scores: the AI can only raise a score, never lower
or replace it. The rule engine score is always the floor. If the AI model disagrees with the
rule engine's score and calls an actor lower risk, the score does not drop. See the
[AI Engine guide](ai-engine.md) for how this plays out in practice.

**Agreement rate** — The percentage of AI verdicts that analysts have reviewed and marked
Agree. Computed from analyst-recorded grades only — never derived from the AI model itself.
Displayed in the Agreement stat headline at the top of the AI verdicts panel on the
[AI Engine page](ai-engine.md). When fewer than 10 verdicts have been graded, the display
shows raw counts ("3 of 4") instead of a percentage, because a small sample does not
support a meaningful rate.

**AI (Artificial Intelligence)** — In FireWatch, refers specifically to a local language
model that reads threat-actor evidence and produces a verdict. The model runs on your own
hardware using a locally installed model server (Ollama, vLLM, llama.cpp, or LM Studio).
No data is sent to a cloud service. AI-contributed results are always marked with a
provenance chip so you can tell them apart from rule-engine results.

**AI baseline** — See *Baseline (AI baseline)*.

**API (Application Programming Interface)** — A set of rules that allow software components
to communicate. The FireWatch backend exposes an API; the API key in the Settings page
protects access to every request against that API, including requests from the FireWatch
dashboard itself.

**ASN (Autonomous System Number)** — A unique identifier assigned to a block of IP
(Internet Protocol) addresses that are managed under a single routing policy by one
organisation — for example an internet service provider, cloud provider, or hosting company.
FireWatch uses ASNs to group distributed attack traffic: when more than 50 scored source
IPs appear, the Dashboard rolls them up by ASN or /24 subnet to signal a coordinated attack
pattern. The [Threat Intelligence page](threat-intelligence.md) has a dedicated ASN lens to
rank operator-level networks by attack volume.

**Auto-escalate** — A flag on an individual detection rule that forces the associated
threat actor to surface in the Triage Banner on the Dashboard regardless of its numeric
risk score. Visible in the Registered Detections table in the Escalation Policy card on the
[Settings page](settings.md). A T1 or T2 actor with a LOW score can still appear in the
triage queue when the rule has this flag set.

---

## B

**Baseline (AI baseline)** — A saved snapshot of how the currently installed local model
judged a fixed set of 25 synthetic attack scenarios. Created by running
`firewatch ai-baseline --save` from the command line. Used as the reference point when you
later run `--compare` to detect whether a model upgrade changed the model's behavior. See
*Model drift* and *Model Consistency Score*.

---

## C

**Confidence** — How certain the local model was about its verdict, expressed as a decimal
between 0 and 1 (for example, 0.82). FireWatch displays this as a word band: High, Medium,
or Low. Only HIGH or CRITICAL verdicts with a confidence value at or above the configured
boost threshold can raise the engine score. See the [AI Engine guide](ai-engine.md).

**Cursor pagination** — A technique where the server returns an opaque cursor token
pointing to the next batch of results, rather than a traditional page number. FireWatch uses
cursor pagination in the Network Logs table so that large log sets can be paged efficiently
without re-running full-table offset queries. Controls show "Next page" and "First page"
rather than numbered pages.

---

## D

**DGA Score** — A local heuristic score from 0 to 1 estimating how likely a DNS (Domain
Name System) query domain name was algorithmically generated, which is a technique often
used by malware to contact command-and-control servers. Computed on-device from entropy,
consonant ratios, and digit ratios — no external DNS lookup is performed. Visible in the
row detail panel of the [Network Logs table](network-logs.md).

**Disposition** — What a WAF (Web Application Firewall) or IDS (Intrusion Detection System)
did with a specific request. Three outcomes: **Block / Drop** — the request was rejected
before reaching your application; **Alert / Detect** — the sensor flagged it but let it
through (detection mode); **Allow** — the request passed through without a block. Shown in
the Dispositions panel on the Dashboard and in the Action column on the Network Logs page.

---

## E

**ERG (Entity Relationship Graph)** — The interactive force-directed network diagram on the
[Network Logs page](network-logs.md) that maps IP addresses, ASNs, and attack categories
as nodes connected by weighted edges. Used to visualise which sources are related and how
traffic flows. IP nodes are tinted by risk band; ASN nodes appear in blue; attack-category
nodes appear in purple. Clicking a node cross-filters the log table.

**Escalation tier (T1 – T4)** — A second classification axis for threat actors that records
what the WAF or IDS *did* with the traffic, independent of the numeric risk score.

| Tier | Disposition | Urgency |
|------|-------------|---------|
| T1 | Got through — possible breach | Highest |
| T2 | Flagged — block status unknown | High |
| T3 | Blocked — kept trying | Moderate |
| T4 | Blocked — didn't keep trying | Informational |
| — | Observed — on the record, no escalation claim | Calm default (not a tier) |

A T1 actor can surface in the Triage Banner even when their numeric score is LOW because
the outcome (traffic reached the application) matters more than the score alone. A T2 actor
surfaces because a qualifying signal flagged it as hostile, even though block status is
unconfirmed. An **observed** actor makes no escalation claim and stays out of the banner unless
its accumulated score crosses the severity-band threshold on its own merit.

---

## G

**Geo enrichment** — The process of resolving a public IP address to a geographic location
(country, city) and ASN. FireWatch performs this entirely on-box using a bundled MMDB
(MaxMind Database) file in Offline mode, so no IP addresses are sent to an external service.
Online mode queries ip-api.com. Configured in the Local AI card on the
[Settings page](settings.md).

**GeoIP** — A shorthand for the IP-to-geography mapping process. FireWatch uses the DB-IP
Lite database (see ADR-0047) to perform GeoIP lookups locally.

---

## H

**Health dot** — The colored status indicator shown in each source card header on the
[Settings page](settings.md) and in the application navigation bar. Colors: green (active,
data flowing), amber (stale, no recent events), red (error or collector failure), grey (not
configured or no data yet). Click the red dot to jump directly to the diagnostics panel
inside the card.

---

## I

**IDS (Intrusion Detection System)** — A system that monitors network traffic for
suspicious activity and generates alerts. Suricata is an example IDS. Unlike a WAF, an IDS
in detection mode alerts but does not block traffic. An IDS that is configured in
inline/blocking mode can drop traffic, which FireWatch records as a Block or Drop
disposition.

**IP (Internet Protocol address)** — A numerical label assigned to a device on a network,
used throughout FireWatch to identify the source or destination of incoming traffic or
attack attempts.

**IP class** — FireWatch's classification of what kind of network a source IP belongs to.
Classes: *residential* (likely the actor's real location), *datacenter* (a cloud or hosting
provider exit), *vpn-likely* (a VPN or anonymiser exit), *private* (an RFC-1918
non-routable address, not plotted on the map), and *unresolved* (enrichment pending or
absent). Shown in the geo map popup on the [Threat Intelligence page](threat-intelligence.md).

---

## J

**JA4 / JA4S** — A compact fingerprint of a TLS (Transport Layer Security) client or server
handshake, analogous to a browser fingerprint for network traffic. JA4 identifies the client
handshake; JA4S identifies the server response. Available only for sources such as Suricata
that emit these fields — absent for layer-7-only sources such as Azure WAF. Visible in the
row detail panel on the [Network Logs page](network-logs.md).

---

## L

**LFI (Local File Inclusion)** — An attack that manipulates file-path parameters to read
files from a server's local filesystem. Tracked on the Threat Intelligence page by WAF rule
prefix 930*.

**LLM (Large Language Model)** — The type of AI model FireWatch uses to analyse threat
actors. A large neural network trained to read and generate text. FireWatch uses any
OpenAI-compatible local model (for example one served by Ollama or vLLM). Results are
always labelled with a provenance chip so you know when the LLM contributed.

**Loopback boundary** — The restriction that FireWatch only accepts connections from
127.0.0.1 (the local machine) when no API key is set. This protects the API from
network-adjacent access during development and single-operator deployments. The API access
card on the [Settings page](settings.md) shows a reminder to set a key before exposing
FireWatch on a broader network.

---

## M

**MMDB (MaxMind Database)** — A binary file format used to store IP-to-geography mappings.
The bundled MMDB file lets FireWatch resolve IP addresses to countries and ASNs without
making any outbound network calls, satisfying the zero-egress posture. See also
*Geo enrichment*.

**Model Consistency Score** — The percentage of synthetic baseline scenarios where the
currently installed model gave the same verdict as the saved baseline. 100% means no drift;
anything below 100% means at least one scenario changed verdict after a model switch or
update. Shown in the Model trust panel on the [AI Engine page](ai-engine.md).

**Model drift** — The change in a model's verdicts between two points in time, typically
before and after a model upgrade or swap. FireWatch measures drift by re-running a fixed set
of synthetic baseline scenarios and comparing results to the saved baseline. A drift report
lists changed scenarios with before-and-after verdicts side by side.

---

## N

**Narration** — A short plain-language summary (up to approximately 120 words) of an
autonomous system's activity pattern, generated on-box from data FireWatch already holds.
Each narration includes a **Grounded in** line listing the exact data fields used, so you
can verify the summary is not fabricated. Appears on the [Threat Intelligence page](threat-intelligence.md)
when you click the Narrate button on an ASN row.

**Notification threshold** — The minimum severity band at which FireWatch posts an alert to
your configured webhook. Set to CRITICAL by default. Distinct from the triage threshold.
Configurable in the Notifications card on the [Settings page](settings.md).

---

## P

**Pipeline stage ticker** — The inline progress display that appears when you click
"Re-run analysis" on a verdict card on the [AI Engine page](ai-engine.md). Steps through
each stage of the analysis pipeline in real time: fetch, build prompt, call model, validate
output.

**Prompt drawer** — The "What the model saw" expandable section inside each verdict card on
the [AI Engine page](ai-engine.md). Shows the exact text sent to the model and the model's
raw response, split into sections: Instructions, Attack samples, Output schema, Raw model
response, and Validated JSON. Used to verify that the model saw what you expected and that
its output was well-formed before FireWatch consumed it.

**Provenance** — Who or what produced a data point. FireWatch marks every panel, number,
and recommendation with a chip:

| Chip | Meaning |
|------|---------|
| RULE | Produced entirely by FireWatch's deterministic detection rules. No AI involved. |
| AI | Produced by the local AI model. |
| AI+RULE | Both the rule engine and the AI model contributed. |

Every page guide refers to these chips. The Threat Summary panel is always marked RULE even
when it appears on the AI Engine page, because its text is generated from rule-derived
counts, not written by the model.

**Pull source** — A source where FireWatch reaches out on a schedule to fetch logs (for
example reading a Suricata log file every 300 seconds). Pull-type source cards on the
[Settings page](settings.md) show an Active toggle, Sync Now button, and Test button.

**Push source** — A source where the external system sends data to FireWatch (for example
syslog over UDP). Push-type source cards show a listener status line instead of Sync and
Test controls.

---

## R

**RFC-1918** — The internet standard that reserves specific IP ranges (10.x.x.x,
172.16–31.x.x, 192.168.x.x) for private networks. These addresses are not routable on the
public internet and cannot be geo-located. FireWatch counts them in the "Unresolved /
private" chip on the [Threat Intelligence page](threat-intelligence.md) rather than showing
them on the map.

**Risk Movers** — Threat actors whose risk scores changed the most (up or down) in the last
one-hour window. A rising delta (shown in red) means the threat is intensifying; a falling
delta (shown in green) means it is subsiding. Displayed in the sidebar of the
[Dashboard](dashboard.md).

**Risk score** — A number from 0 to 100 computed by FireWatch's rule engine, and optionally
boosted by the AI engine's confidence verdict, that expresses how likely and how dangerous a
source IP's activity is.

| Score range | Band label | Meaning |
|-------------|-----------|---------|
| 76 – 100 | CRITICAL | Highly confident, high-severity threat. Immediate attention required. |
| 51 – 75 | HIGH | Strong indicators; likely malicious. Review this shift. |
| 26 – 50 | MEDIUM | Notable activity; could be reconnaissance or low-volume probing. |
| 0 – 25 | LOW | Minimal signal; informational only. |

---

## S

**Schema-driven** — The property of source configuration cards on the [Settings page](settings.md)
whereby the form fields are generated automatically from each plugin's own configuration
schema. FireWatch contains no hand-written form per source. Install a plugin and the correct
fields appear; uninstall it and the card disappears.

**Score derivation** — Whether the final risk score was produced by the rule engine alone
(RULE) or boosted by the AI engine's confidence signal (AI+RULE). Tagged on every analysis
record and visible as a provenance chip.

**SNI (Server Name Indication)** — The hostname that a TLS client sends at the start of a
handshake to indicate which certificate it expects. Visible in Suricata TLS events in the
row detail panel on the [Network Logs page](network-logs.md).

**SOAR (Security Orchestration, Automation, and Response)** — A category of tools that
automate security workflows, including blocking decisions. FireWatch's auto-block enforcement
tier is planned for a future SOAR integration; it is shown greyed out in the Enforcement
staircase on the [Settings page](settings.md) and listed in the roadmap as a later
milestone.

**SOC (Security Operations Center)** — A team responsible for monitoring, detecting, and
responding to security events. All five page guides are written for the junior SOC analyst
as the primary audience.

**Source ID** — The identifier used internally for a source instance, defaulting to the
source type key (for example `suricata`). Shown in the source card header on the
[Settings page](settings.md) next to the display name.

**Source plugin** — A software package that tells FireWatch where and how to collect
telemetry. Examples: `firewatch-source-suricata` for Suricata IDS logs,
`firewatch-source-azure-waf` for Azure WAF events. Install one and its configuration card
appears on the Settings page; uninstall it and the card disappears. Adding a new source
requires zero edits to FireWatch's core.

**SQLi (SQL Injection)** — An attack that embeds malicious SQL commands inside a request,
hoping to manipulate a backend database. Tracked on the Threat Intelligence page by WAF
rule prefix 942*.

**Synthetic baseline scenarios** — The fixed set of 25 attack descriptions used by
`firewatch ai-baseline` to measure model drift. These are not production events; they are
representative examples used to test whether the model's judgment is consistent over time.

---

## T

**Top Talker** — The source IP that generated the most events in the current filter scope.
Shown as a clickable tile on the [Network Logs page](network-logs.md); clicking it opens a
popover listing the top five source IPs by event count.

**Triage** — The process of reviewing flagged threat actors and deciding whether to block
them, continue investigating, or dismiss the alert. The Triage Banner on the Dashboard is
the primary interface for this workflow.

**Triage threshold** — The minimum risk score band at which a threat actor is included in
the Dashboard's Triage Banner "needs a decision" queue. Set to HIGH by default.
Configurable in the Escalation Policy card on the [Settings page](settings.md). Distinct
from the notification threshold (which controls webhook alerts).

---

## V

**Verdict** — The AI model's assessment of a threat actor: a threat level (CRITICAL, HIGH,
MEDIUM, or LOW), a confidence value, and optionally prose explaining the assessment. A
verdict is stored in the ledger when you request a deep analysis for an actor from the
[AI Engine page](ai-engine.md).

---

## W

**WAF (Web Application Firewall)** — A security control that inspects HTTP (HyperText
Transfer Protocol) traffic and blocks requests matching known attack patterns. Azure
Application Gateway WAF is an example. A WAF operates at layer 7 (the application layer)
and can block traffic before it reaches your application.

**Webhook** — An HTTP POST sent to a URL you specify, used here to deliver alerts to tools
like Slack or Discord when a threat reaches the notification threshold. FireWatch stores the
webhook URL as a secret on the server; the value is never echoed back to the UI after
saving.

---

## X

**XSS (Cross-Site Scripting)** — An attack that injects client-side scripts into a web page
to run in other users' browsers. Tracked on the Threat Intelligence page by WAF rule
prefix 941*.

---

## Z

**Zero-egress** — A deployment posture in which no log data, AI query, or inference payload
leaves the local machine. All AI inference runs on-device using a locally installed model.
FireWatch enforces this by refusing to connect to non-local AI endpoints at startup. The
"Local-only · 0 bytes egressed" badge on the Network Logs page confirms this guarantee is
in effect.
