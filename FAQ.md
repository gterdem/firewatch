# Frequently Asked Questions

Short answers to the questions new users ask most. For depth, follow the links into the
[README](README.md) and the per-page [guides](docs/guide/). New to the terms? Start with the
[Glossary](docs/guide/glossary.md).

## What does FireWatch do and why should I use it?

FireWatch is a modular, local-first threat-monitoring console. It pulls security telemetry from
several sources into one canonical event shape, scores and triages attacker IP addresses with a
deterministic rule engine, and adds local-AI explanation on top. Everything runs on hardware you
control — no telemetry leaves your machine. See the [README](README.md) and the
[getting-started guide](docs/guide/getting-started.md).

## What sources can I use in FireWatch?

Sources are **plugins** against a single contract — adding one needs zero edits to the core, so
anyone can write a new one (see [PLUGIN_CONTRACT.md](PLUGIN_CONTRACT.md) and the
[module-author guide](docs/module-author-guide.md)). Shipped today:

| Source | What it is | Ingest |
|--------|-----------|--------|
| Azure WAF | Azure Web Application Firewall logs | Pull |
| Suricata IDS/IPS | Intrusion Detection / Prevention System | Pull |
| AWS Network Firewall | AWS managed network firewall | Pull |
| Syslog (UDP/TCP) | Generic syslog listener | Push |
| Syslog/CEF | Vendor-agnostic Common Event Format receiver | Push |

## How are logs ingested?

Two flavors, both normalized into one canonical `SecurityEvent` before scoring:

```
Pull sources  ──poll on a watermark (only events newer than last time)──┐
                                                                        ├──► normalize ──► SecurityEvent
Push sources  ──listen on a socket (sources send to FireWatch)──────────┘
```

- **Pull** (Azure WAF, Suricata, AWS NFW): FireWatch polls and tracks a watermark per source so it
  never re-reads old events.
- **Push** (Syslog, Syslog/CEF): FireWatch runs a listener; the source sends events to it.

## What is the `T2 — Flagged — needs review` I see on the dashboard?

It is the **escalation tier** for an actor whose traffic carries a *qualifying signal* — a
FireWatch correlation rule, or a source-declared high/critical severity — flagging it as hostile
and requiring an operator decision. This label makes no claim about whether the traffic was
actually blocked (that depends on enforcement posture — a later phase, issues #44/#45 — not settled
today). Bare detection-mode telemetry with no qualifying signal does **not**
reach Tier 2; it is recorded honestly as **observed** instead (see
[docs/escalation-and-triage-model.md §2.1](docs/escalation-and-triage-model.md#21-the-assertion-gate-and-the-observed-stratum)).
The full action-aware model ([ADR-0058](docs/adr/0058-action-aware-deterministic-escalation-axis.md),
[ADR-0067](docs/adr/0067-assertion-gated-triage-entry-observed-stratum.md); dashboard wording:
[docs/escalation-and-triage-model.md](docs/escalation-and-triage-model.md)):

| Tier | What happened | Block status |
|------|---------------|--------------|
| **T1** | Allowed through despite a high-fidelity detection | allowed |
| **T2** | Alert / log, flagged by a qualifying signal — disposition not asserted | **unconfirmed** |
| **T3** | Blocked/dropped, and the adversary kept trying (persistent) | blocked |
| **T4** | Blocked/dropped, and the adversary didn't keep trying | blocked |
| **Observed** | Alert / log with no qualifying signal, or allow-only with no detection | reflects the truthful state |

## Why does my Triage Banner show "All clear" when I know FireWatch is seeing traffic?

That is the intended calm state — not a bug. Only actors carrying an escalation claim (Tier 1 or
Tier 2, or a score that crosses your Triage threshold on its own) render as banner chips. Every
**observed**-stratum actor — background noise with no qualifying signal — rolls up into one
honest line instead: **"N detections on the record from M sources → Network Logs."** That line
appears whenever observed events exist, whether the banner is showing chips or "All clear," so
nothing is ever silently dropped; click through to Network Logs for the per-event detail. Both
numbers are plain engine counts, never attacker-influenced text ([ADR-0035](docs/adr/0035-analytic-provenance-tagging.md)).
This is exactly what makes "All clear" the reachable default on a watch-only install (Suricata,
syslog, ClamAV — nothing that can block): the sensors' routine background noise is on the record,
not in your queue. See [ADR-0067](docs/adr/0067-assertion-gated-triage-entry-observed-stratum.md)
D5 and [docs/escalation-and-triage-model.md §4](docs/escalation-and-triage-model.md#4-the-triage-banner).

## What does "412 hostile attempts from 87 actors — 0 succeeded · 2 need review" mean?

That is the **attempts headline** — it appears below the Triage Banner's chips (or below "All
clear") whenever one or more qualifying attempts exist in the trailing 24-hour window, and it
supersedes the older "N detections on the record" line in that same slot. Every number is an
engine integer, computed by the same escalation pipeline that scores your actors — the banner
never counts anything differently than the engine ([ADR-0070](docs/adr/0070-hostile-attempt-pressure-and-campaign-detection.md) D1/D3):

- **hostile attempts / actors** — the count of qualifying attempt events (failed logins,
  rejected/alerted connections, matched attack signatures) and the distinct actors that made them.
- **succeeded** — actors with a Tier-1 verdict **OR** a critical-severity qualifying detection,
  never Tier 1 alone. This is the important correction: a host-based source (syslog,
  `linux_auth`) never emits an "allowed" event, so a real SSH brute-force compromise on such a
  source is Tier 2, not Tier 1 — a Tier-1-only definition would read "0 succeeded" while that
  compromise is actively firing. The critical-severity arm closes that gap.
- **need review** — the Triage queue size (K), the same count of Tier-1/Tier-2 actors eligible
  to appear as banner chips.

Below the sentence, a bounded **pressure strip** (at most 5 rows) names the highest-pressure
actors — IP, attempt count, and time span — with no block/investigate/dismiss action attached;
it is a reference list, not a worklist. A "+N more actors → Network Logs" link covers the rest.
See [docs/guide/dashboard.md §3](docs/guide/dashboard.md#attempts-headline-and-pressure-strip)
for the full field-by-field breakdown.

## What is score and how is it calculated?

Score is a deterministic, rule-based risk number from 0–100 (`scoring.py`). Each matching signal
adds points; the total is capped at 100. The AI does **not** drive it — see Q6.

| Signal | Points |
|--------|--------|
| Brute force (≥10 blocked events) | +30 |
| Port scan (≥5 distinct destination ports) | +25 |
| SQL-injection payload | +40 × disposition weight |
| Cross-site-scripting (XSS) payload | +35 × disposition weight |
| Persistence (≥3 blocked events) | +10 |
| Correlation detection boost | up to +30 |

The *disposition weight* (allowed-through ×1.0 / alert ×0.75 / blocked ×0.5) means an exploit that
got through scores higher than one the firewall stopped. Bands: 0–25 LOW · 26–50 MEDIUM ·
51–75 HIGH · 76–100 CRITICAL.

## What is the AI Engine and what is it mainly used for?

A **local** large language model (default: [Ollama](https://ollama.com)) that explains
already-decided escalations in plain language — what an actor was doing and why it matters. It is
**not** a per-log detector and **not** the score driver. It can only *add* a bounded boost on top
of the rule score (+20 for a confident CRITICAL verdict, +10 for HIGH, nothing otherwise) and can
never lower or replace it. If it is offline, FireWatch runs rules-only and says so on screen. See
the [AI Engine guide](docs/guide/ai-engine.md) and
[docs/ai-claims-checklist.md](docs/ai-claims-checklist.md).

## What is the use case of Model Trust?

Model Trust is the drift-check panel on the [AI Engine page](docs/guide/ai-engine.md). You save a
**baseline** of how your local model judges a fixed set of synthetic scenarios
(`firewatch ai-baseline --save`), then re-run it later (`--compare`). It reports a Model Consistency
Score — the percent of scenarios where the model still gives the same verdict — so after a model
swap, quantization change, or runtime upgrade you can answer: *"did my model's judgment change?"*
It tests consistency, not correctness.

## What is the Entity Relationship Graph and what is it used for?

An interactive force-directed graph on the [Network Logs page](docs/guide/network-logs.md). It maps
IP addresses, network blocks (ASNs), and attack categories as nodes connected by weighted edges —
so you can see at a glance how one actor connects across the data (which networks it belongs to,
what it targeted, who it talked to). Clicking a node cross-filters the whole page to it.
