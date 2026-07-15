# ADR-0069: Canonical Severity Semantics — Sigma-Anchored Behavioral Definitions for `SecurityEvent.severity` and the Per-Source Mapping Discipline

**Date:** 2026-07-15
**Status:** Proposed (coupled with ADR-0070 — see ADR-0070 D8 for the landing order)

**Relates to / honours:** ADR-0067 (assertion-gated triage entry — D1(b) made severity a routing
input, which is what forces this definition to exist), ADR-0068 (the volume oracle — its fact 4
is the live proof of cost; #50 is the mechanical adjudicator for every mapping in this ADR),
ADR-0058 D1 (the Sigma anchor for *rule-declared* severity — this ADR extends the same anchor to
*source-declared* severity), ADR-0040 (OCSF export surface pinned to 1.8.0 — `severity_id`
mapping unchanged), ADR-0020 (lightweight OCSF alignment — the `info` level's origin),
ADR-0012 (action semantics — orthogonal axis, untouched).
**Skill gate:** none new; `canonical-schema` and `firewatch-plugin-author` are *updated by* this
ADR's docs issue.

---

## Context

### The defect class: a contract field with no contract

`SecurityEvent.severity` (`SeverityLiteral = "info" | "low" | "medium" | "high" | "critical"`,
`firewatch-sdk/models.py:21`) has existed since v1.0 of the plugin contract — and **nothing
anywhere states what the levels mean.** PLUGIN_CONTRACT.md lists `severity` among the fields
`normalize()` "MUST set" and says nothing else. Every in-tree normalizer therefore invented its
own vendor→FireWatch mapping in isolation:

- Suricata's map is literally commented *"Ported from legacy/core/normalizer.py"* — inherited,
  never derived (`firewatch_suricata/normalize.py:41`).
- AWS Network Firewall copied Suricata's map verbatim (`firewatch_aws_nfw/normalize.py:90`).
- Azure WAF derived per-CRS-category severities with anomaly-score refinement
  (`firewatch_azure_waf/severity.py`) — the most principled of the five, but calibrated against
  no shared definition.
- syslog hard-codes a single `Failed password` line → `high` (`firewatch_syslog/normalize.py:79`).
- syslog_cef bands the CEF 0–10 scale per the ArcSight spec (correct pattern), then duplicates
  syslog's `high` in its fallback path (`firewatch_syslog_cef/normalize.py:250`).

While severity was presentation-only, the inconsistency was invisible. **ADR-0067 D1(b) changed
that:** an `ALERT` with source-declared `severity ∈ {high, critical}` now qualifies an actor for
Tier 2 — severity became the triage queue's admission ticket. A mapping error is now a routing
error. ADR-0068's simulation quantified it: with severity distribution taken from Suricata's
shipped `classification.config`, **100 of 128 ambient actors qualify for Tier 2 through the
legacy map** — a second flood channel that survives #42.

The wider point (Maintainer's reframe, recorded as the motivation): this is not a Suricata bug.
pfSense (#22), Zeek (#23), Windows Event Log (#24), and every future source will re-commit the
same error unless the definition exists somewhere a plugin author cannot miss.

### Why the industry gives no free answer (verified live, quoted verbatim)

**ECS explicitly refuses to define cross-source severity semantics.** `event.severity`
(https://github.com/elastic/ecs, `schemas/event.yml`, fetched this session):

> "The numeric severity of the event according to your event source. What the different severity
> values mean can be different between sources and use cases. It's up to the implementer to make
> sure severities are consistent across events from the same source."

That stance — consistent *within* a source, undefined *across* sources — is exactly the
condition FireWatch is in today, and it is unusable once a cross-source gate consumes the field.
ECS is the cautionary tale here, not the anchor.

**Sigma defines its `level` vocabulary behaviorally** (SigmaHQ/sigma-specification,
`specification/sigma-rules-specification.md`, fetched this session):

> "The level field contains one of five string values. It describes the criticality of a
> triggered rule. While `low` and `medium` level events have an informative character, events
> with `high` and `critical` level should lead to immediate reviews by security analysts.
>
> - `informational`: Rule is intended for enrichment of events, e.g. by tagging them. No case or
>   alerting should be triggered by such rules because it is expected that a huge amount of
>   events will match these rules.
> - `low`: Notable event but rarely an incident. Low rated events can be relevant in high numbers
>   or combination with others. Immediate reaction shouldn't be necessary, but a regular review
>   is recommended.
> - `medium`: Relevant event that should be reviewed manually on a more frequent basis.
> - `high`: Relevant event that should trigger an internal alert and requires a prompt review.
> - `critical`: Highly relevant event that indicates an incident. Critical events should be
>   reviewed immediately. It is used only for cases in which probability borders certainty."

**OCSF 1.8.0 defines `severity_id` in effort/action terms**
(https://schema.ocsf.io/api/1.8.0/classes/detection_finding, fetched this session):

> "The normalized severity is a measurement the effort and expense required to manage and resolve
> an event or incident."
> `1 Informational`: "Informational message. No action required." ·
> `2 Low`: "The user decides if action is needed." ·
> `3 Medium`: "Action is required but the situation is not serious at this time." ·
> `4 High`: "Action is required immediately." ·
> `5 Critical`: "Action is required immediately and the scope is broad."

Sigma and OCSF **agree in ordering and agree behaviorally at the levels the gate acts on**
(Sigma `high` "requires a prompt review" ↔ OCSF 4 "Action is required immediately"; Sigma
`critical` "reviewed immediately… probability borders certainty" ↔ OCSF 5 "immediately and the
scope is broad"). They **diverge in prose at `medium`**: OCSF 3 says "Action is required,"
Sigma `medium` says "reviewed manually on a more frequent basis" (informative character, per its
preamble). For ambient sensor telemetry — the mass FireWatch actually processes — Sigma's
`medium` describes the honest handling and OCSF's prose does not. They cannot be silently
blended; one must be normative.

### Current per-source mappings vs. what a real deployment produces

Audit of all five in-tree normalizers (this session), with the ambient-mass vs.
genuine-assertion distribution each produces. "Ambient mass" = what a healthy, internet-exposed
deployment generates continuously; "assertion" = the events an operator should see one at a time.

| Source | Current mapping | Ambient mass → current severity | Genuine assertions → current severity | Verdict under D1(b) |
|---|---|---|---|---|
| **suricata** | `{1: critical, 2: high, 3: medium, 4: low}`, fallback `medium` | ET SCAN (`attempted-recon`, prio 2) + ET DROP/CINS (`misc-attack`, prio 2) → **high**; ET INFO (`misc-activity`, prio 3) → medium | `trojan-activity` / `web-application-attack` / `successful-admin` (prio 1) → critical | **Offender.** 100/128 ambient actors qualify (ADR-0068 fact 4, simulated on shipped `classification.config`) |
| **aws_network_firewall** | Same map, copied verbatim (same engine — NFW's stateful engine IS Suricata) | Same: AWS managed rule groups include the same reputation/scan classes at prio 2 → **high** | Same as Suricata | **Offender** (identical defect, second file) |
| **syslog** | Category table: single `Failed password` line → ALERT/**high**; sudo failure → ALERT/medium; login → LOG/info; generic → LOG/info | Internet-exposed sshd: hundreds of distinct scanner IPs per night, each emitting `Failed password` lines → **every one an ALERT-high actor** | Brute-force *sequences* — but those are the detector's correlations (`brute_force_then_login` critical/auto-escalate, `ids_then_brute_force` high), not the single line | **Offender.** A second flood channel of the same magnitude as Suricata's — one failed login = one Tier-2 actor |
| **syslog_cef** (CEF path) | CEF 0–10 banded per ArcSight spec: 0–3 low, 4–6 medium, 7–8 high, 9–10 critical; absent → "5" → medium | Device-dependent; pass-through of the device's own declared scale, translated per that vendor's published spec | Same — the device asserts, FireWatch translates | **Conformant** — this is the correct pattern (D3 below). Security caveat: spoofable transport, see D6 |
| **syslog_cef** (fallback path) | Duplicate of syslog's table: `Failed password` → **high** | Same as syslog | Same as syslog | **Offender** (same defect, third file) |
| **azure_waf** | Per-CRS-category table (`severity.py`): scanner/protocol/bot/rate/geo → low; IP-reputation/protocol-attack/session-fixation/anomaly-threshold → medium; LFI/RFI/PHP/XSS/SQLi → **high**; RCE/Log4j → **critical**; anomaly-score refinement: ≥5 → high, ≥30 → critical | Scanner/crawler/protocol probes → low (**safe**); commodity attack-payload probes (bot-sprayed SQLi/XSS/Log4j strings — ambient on any public site) → per-rule `Matched`/`Detected` ALERTs at **high/critical**, in *both* Detection and Prevention mode (`_ACTION_MAP`: `matched`→ALERT) | The CRS **anomaly-threshold** event (`Inbound Anomaly Score Exceeded`) — CRS's own aggregate verdict | **Partial offender.** The recon floor is right; per-rule attack-class matches at high/critical hand every commodity probe actor a queue ticket. No in-tree ambient capture exists — distribution derived from CRS structure; live juiceshop run calibrates (D4c) |

The detector's correlation rules match on `category` and `source_type`, never on event severity
(`detector.py` — verified this session), and `scoring.py` does not read event severity at all —
so recalibrating severity **cannot change scores or detections**; it changes only D1(b) routing,
presentation, and the OCSF export's `severity_id`. `tests/golden/fixtures/expected_scores.json`
is untouched by everything in this ADR.

## Decision

### D1 — Sigma `level` is the normative semantics of `SecurityEvent.severity`

FireWatch adopts the five Sigma definitions quoted verbatim above as the meaning of
`info`/`low`/`medium`/`high`/`critical` (FireWatch's `info` = Sigma's `informational`; the SDK
literal keeps its existing short spelling — rename churn refused). This extends ADR-0058 D1's
existing Sigma anchor from rule-declared severity to source-declared severity: **one vocabulary,
both axes of D1's gate.**

The definition is behavioral, and FireWatch adds one operational clause that makes it
mechanically checkable:

> **`severity ∈ {high, critical}` on an ALERT is an assertion that this event, on its own,
> belongs in the triage queue (ADR-0067 D1(b)).** A mapping is therefore correct only if the
> events it labels `high`+ are ones an operator should promptly review one at a time.
> **Corollary (the distribution rule): any event class that is ambient at volume on a healthy
> deployment maps to at most `medium` — by definition, not by tuning.** Escalation of ambient
> classes is the job of the correlation rules (D1(a)) and the band axis (ADR-0067 D5), which
> exist precisely to turn volume and combination into a claim.

### D2 — OCSF `severity_id` stays the export encoding; its prose is not normative

The ADR-0040 export mapping (`firewatch-api/ocsf/mapping.py`: info=1, low=2, medium=3, high=4,
critical=5, None=0) is **unchanged and remains lossless-ordinal**. Where OCSF's level prose
diverges from Sigma's (the `medium` case above), Sigma governs FireWatch's internal meaning and
OCSF governs only the wire numbers. Recorded as a deliberate deviation: FireWatch maps to OCSF's
*identifiers*, not to OCSF's *descriptions* — because OCSF 3 Medium's "Action is required" is
false for the ambient sensor mass that Sigma `medium` honestly describes, and because ADR-0067
D1(b)'s gate semantics were specified in Sigma terms from the start.

### D3 — The mapping discipline (what every plugin author must do)

Normative, lands in PLUGIN_CONTRACT.md (D5):

1. **Translate the vendor's own published scale where one exists; cite it.** If the source
   declares severity (Suricata priority, CEF 0–10, Windows Event level, Zeek notice…), the
   normalizer *translates* that scale per the vendor's published semantics into the Sigma-defined
   levels — it never re-scores individual events. (syslog_cef's CEF banding is the reference
   implementation of this pattern.)
2. **Justify every band against the D1 definitions** — in the mapping-table comment, with the
   vendor doc URL.
3. **State the distribution.** The plugin's PR must say what the source's *ambient mass* maps to
   and what its *genuine assertions* map to, and show the ambient mass lands ≤ `medium`
   (the D1 corollary). "What does a healthy night look like?" is an acceptance question, not an
   afterthought.
4. **Fail quiet.** Missing/unparseable vendor severity maps to `low` (telemetry-grade), never to
   a gate-qualifying level, and never fabricated upward. (Consistent with ADR-0067 D3:
   undeclared severity never queues.)
5. **Contested calls are adjudicated by the volume oracle** (ADR-0068 / `tests/volume/`): if a
   mapping floods the queue under a realistic manifest, the mapping is wrong — mechanically.

### D4 — Recalibration of the in-tree offenders

**(a) Suricata and AWS Network Firewall** (one defect, two files — the maps must stay identical):

| Suricata priority (shipped `classification.config`, quoted in ADR-0068) | New level | Justification against D1 (Sigma verbatim) | What would falsify it |
|---|---|---|---|
| 1 (`trojan-activity` "A Network Trojan was detected", `web-application-attack`, `successful-admin`) | **high** (was critical) | "should trigger an internal alert and requires a prompt review" — yes for a trojan/web-attack signature match. NOT `critical`: Sigma reserves it for "probability borders certainty," and a single ET signature match is well-documented as FP-prone; one match does not border certainty | A real night where priority-1 alerts are ambient at volume (> the #50 tripwire from healthy background) falsifies `high`; a confirmed intrusion whose priority-1 alerts needed `critical` to be noticed falsifies the downshift (it cannot — `high` already queues via D1(b)) |
| 2 (`attempted-recon`, `misc-attack` — the ET SCAN / ET DROP-reputation ambient mass) | **medium** (was high) | "Relevant event that should be reviewed manually on a more frequent basis" — the record + band-axis handling, exactly. The D1 corollary applies: this class is ambient at volume on every exposed sensor (ADR-0068 fact 1), so > medium is definitionally wrong | A confirmed intrusion whose *only* signal was priority-2 alerts and which the band axis + correlations failed to queue. (#50's breach-among-noise variant is the standing check) |
| 3 (`misc-activity` — ET INFO) | **low** (was medium) | "Notable event but rarely an incident… relevant in high numbers or combination with others" — ET INFO verbatim | ET INFO classes shown to carry per-event actionable meaning on a real deployment |
| 4 (unused by the shipped `classification.config`, which assigns only 1–3; reachable via custom classifications) | **info** (was low) | "expected that a huge amount of events will match" — the below-low ordinal floor | A vendor/custom classification at priority 4 that demonstrably warrants review |
| missing / unparseable (today `or 3` → medium) | **low** | D3 rule 4 (fail quiet) | — |

**(b) syslog and the syslog_cef fallback path** (one defect, two files):

- Single `Failed password`/`publickey` line ("SSH Brute Force" category): **high → low.**
  Sigma `low` verbatim: "Notable event but rarely an incident. Low rated events can be relevant
  in high numbers or combination with others" — a lone failed login is this, letter for letter.
  The "high numbers or combination" path is owned by D1(a): `brute_force_then_login`
  (critical, auto_escalate), `ids_then_brute_force` (high), plus ADR-0070's
  `attempt_pressure`/`campaign` rules (the volume-of-unsuccessful-attempts owner; nothing in
  `run_rules` accumulates with unblocked count — ADR-0070 D7 corrects the earlier "band
  accumulation" premise). Distribution:
  an internet-exposed sshd sees hundreds of distinct ambient scanner IPs per night; at `high`,
  each is a Tier-2 actor — the same flood Suricata's map produces, out of a different pipe.
  What is lost: on the *success* paths, nothing reachable — a single failure followed by a
  success is a normal typo; an attacker succeeding with <3 prior failures was never detectable
  from failure-count severity in the first place. **The ongoing-unsuccessful case IS lost by
  this downshift taken alone** — a sustained brute force that never succeeds becomes
  ALERT/`low` (never qualifies) and, before ADR-0070, scores 0 (no volume rule counts unblocked
  attempts). This recalibration is therefore coupled to ADR-0070 and MUST NOT land before its
  R1/R2 rules (ADR-0070 D8 fixes the landing order). Falsifiers: a real compromise sequence
  with ≥3 failures + success failing to queue (it cannot — the correlation is `critical` +
  `auto_escalate`); and a sustained unsuccessful brute force that produces neither an ADR-0070
  pressure episode nor a campaign — adjudicated by #50's brute-force personas.
  The category *name* "SSH Brute Force" for a single line is a misnomer, but the detector
  correlates on that exact string — renaming is out of scope here (noted for a follow-up).
- Sudo Failure stays **medium** ("reviewed manually on a more frequent basis"); it is local-only
  and near-zero ambient on a healthy box.
- SSH Login / generic syslog stay **info** on LOG (unchanged; LOG never self-qualifies anyway).

**(c) Azure WAF — per-rule matches are contributors; threshold events are the assertion.**
CRS's own architecture (coreruleset.org, fetched this session, verbatim): "Anomaly scoring mode
combines the concepts of collaborative detection and delayed blocking. The key idea to
understand is that the inspection/detection rule logic is decoupled from the blocking
functionality. Individual rules designed to detect specific types of attacks and malicious
behavior are executed. If a rule matches, no immediate disruptive action is taken… Instead, the
matched rule contributes to a transactional anomaly score."

Applying that: individual rule-match events (`Matched`/`Detected`/`AnomalyScoring` → ALERT) are
*contributors* and cap at **medium** (attack-class categories LFI/RFI/PHP/XSS/SQLi/RCE/Log4j:
high|critical → medium; the low tiers stay low); the **anomaly-threshold refinement is
unchanged** (score ≥ 5 → high, ≥ 30 → critical) and becomes the sole carrier of the queue
assertion — which is CRS's own verdict event. Nothing real is lost: a single CRITICAL CRS rule
contributes 5 points = the default inbound threshold, so any genuine attack that matches even
one attack rule also produces the threshold event, which queues. Distribution caveat, stated
honestly: there is no in-tree ambient WAF capture; this table is derived from CRS structure and
the known composition of commodity web scanning. **The live juiceshop (Terraform) run calibrates
it before the announcement gate** — if observation contradicts the derivation, the mapping issue
reopens with data.

**(d) syslog_cef CEF path — no change.** The ArcSight banding is the D3 pattern done right.

**(e) M1 flagships (specs amended, cheapest moment):**
- **ClamAV (#2):** `FOUND` → **high** stands (ADR-0067 D4, maintainer-ruled) and is D1-conformant:
  malware present on disk "requires a prompt review"; not `critical` because a signature match
  alone does not "border certainty." Distribution: a healthy machine produces ~zero `FOUND`
  events — not ambient; the gate ticket is honest.
- **linux_auth (#3):** single auth failure → **low**; accepted login → **info** (LOG); sudo/su
  failure → **medium**; escalation rides the declared correlations (D1(a)), exactly as #3's
  criteria already state. The issue gains an explicit severity table so the implementer maps to
  a definition, not to instinct.

### D5 — Where the rule lives (so a future author cannot miss it)

- **PLUGIN_CONTRACT.md** (v1.4 changelog + a new "Severity semantics" subsection under
  `normalize()` responsibilities): the five Sigma definitions verbatim, the D1 operational
  clause + corollary, and the D3 discipline. Severity is contract surface — the core's gate
  consumes it (ADR-0067 D1(b)) — so its semantics belong in the contract, which is the one
  document a plugin author must read.
- **`canonical-schema` skill:** currently wrong twice (vocabulary listed as
  `{critical, high, medium, low}` — missing `info`; documents the legacy Suricata map as the
  worked example). Fixed to the five levels + the new map + the distribution rule.
- **`firewatch-plugin-author` skill:** gains the D3 checklist (translate-cite-justify-distribute,
  fail-quiet) and a PR checklist line: "ambient-mass vs assertion distribution stated."
- The ADR carries the *why*; the contract carries the *rule*; the skills carry the *how*.
  A rule only in an ADR is a rule nobody reads at 2am.

### D6 — Security posture (recorded, routed to #18 — not solved here)

Severity is device-asserted, and D1(b) makes it a routing input: a spoofable transport (UDP
syslog/CEF) can assert `Severity=10` → `critical` → forced queue entry — alert-fatigue
injection. This ADR *narrows* one such channel (a spoofed `Failed password` line no longer
qualifies at `high`; an attacker must now clear the correlation thresholds instead) and leaves
the CEF numeric channel open by design (D4d — translating the vendor scale is correct; the
transport is what is untrusted). Bounded, as ADR-0067 D3 recorded, by the same
source-authentication posture as ingestion generally; the auth ADR (#18, M3) owns transport
trust and SHOULD consider whether unauthenticated push transports get a severity trust ceiling
at the gate. Noted against #18.

### D7 — The golden re-bless (one, deliberate, documented — ADR-0058 D5b discipline)

`expected_scores.json` is untouched (scoring reads no severity — verified). The Suricata
normalize oracles move, on purpose, and each new value is justified in D4(a) on its own terms
(vendor's shipped classification × the verbatim Sigma definitions — not "the old one was a
bug"):

| Pinned artifact | Old → New |
|---|---|
| `expected_01_web_attack_alert.json` (EVE sev 2) | high → **medium** |
| `expected_02_port_scan_block.json` (EVE sev 1) | critical → **high** |
| `expected_03_trojan_alert.json` (EVE sev 2) | high → **medium** |
| `expected_04_privesc_mitre.json` (EVE sev 1) | critical → **high** |
| `expected_05_recon_alert.json` (EVE sev 3) | medium → **low** — *this file moves too; earlier scoping listed only 01/02/03/04/06* |
| `expected_06_tls_dns_flow_enriched.json` (EVE sev 2) | high → **medium** |
| `tests/golden/test_suricata_normalize.py` in-file oracles + `test_severity_critical_for_severity_1` | per the D4(a) table |
| `tests/golden/test_suricata_e2e_demo.py` severity assertions | per the D4(a) table |
| Package tests: `sources/suricata/tests/test_plugin.py`, `sources/aws-nfw/tests/test_aws_nfw.py`, `sources/syslog/tests/test_plugin.py`, `sources/syslog_cef/tests/test_cef_plugin.py` (fallback-path pins only) | per D4(a)/D4(b) |
| `tests/golden/test_syslog_cef_golden.py` (CEF-path pins) | **unchanged** (D4d) — acts as the regression net proving the recalibration did not leak into the CEF path |

Azure WAF's pins move under its own issue with the same justification form (D4c), after live
calibration input if the Maintainer wants the data first. What would falsify the re-bless as a
whole: the #50 volume oracle failing its breach-among-noise invariant under the new maps —
i.e., a planted genuine breach that no longer queues. The oracle is the standing falsifier.

## Alternatives considered

- **OCSF `severity_id` prose as the normative semantics** — rejected. Its `medium` ("Action is
  required") mislabels the ambient sensor mass, and D1(b)'s gate was specified in Sigma terms
  (ADR-0058 D1). OCSF remains the pinned export encoding (ADR-0040); identifiers, not prose.
- **ECS's stance (severity is source-relative; define nothing)** — rejected; quoted above. It is
  precisely the current defect: unusable the moment a cross-source gate consumes the field.
- **Suricata-only patch** — rejected (Maintainer's reframe). Leaves the identical trap armed in
  aws_nfw (same map, copied), syslog/syslog_cef (worse: `high` for one failed login), azure_waf
  (attack-class per-rule matches), and every future plugin.
- **Gate on something other than severity (e.g. a dedicated `queue_worthy` flag)** — rejected. It
  would re-invent severity under a new name, orphan the existing field, and desynchronize from
  the Sigma/OCSF vocabulary the rest of the pipeline and export surface already speak.
- **Numeric 0–100 risk score instead of five levels** (Elastic `risk_score` style) — rejected for
  the contract surface: false precision for sources that publish 3–5 ordinal levels; the ordinal
  literal is what Sigma, OCSF ids, and the existing SDK already agree on.
- **Category renames alongside (e.g. "SSH Brute Force" → "Failed SSH Auth")** — deferred. The
  detector correlates on the exact category string; renaming is a separate, riskier change with
  its own blast radius, and severity alone closes the flood channel.

## Reasoning

ADR-0067 moved severity from decoration to routing; a field that routes needs defined semantics,
and the definition must be behavioral because "high" as an adjective is exactly how five
normalizers diverged unnoticed. Sigma's vocabulary is the only published standard of the three
candidates that defines levels by *what a human should do*, it is already the anchor for the
rule-declared half of the same gate (ADR-0058 D1), and its `medium`/`low` describe honestly what
a sensor's ambient mass deserves. The distribution corollary ("ambient at volume ⇒ ≤ medium")
turns the definition into a mechanical test a plugin PR can be held to, and the volume oracle
(ADR-0068) is the CI instrument that holds it. The recalibrations then follow from the
definition rather than from taste — each is a translation of the vendor's own published scale,
which is why the same rule works for pfSense, Zeek, and Windows Event Log before their plugins
exist.

## Consequences

- Implementing issues (filed with this ADR, pending Maintainer approval):
  **docs/contract** (PLUGIN_CONTRACT v1.4 + both skills; M1),
  **suricata + aws_nfw recalibration** (D4a + D7 re-bless; M1 — with #42 and #50, closes the
  flood), **syslog + syslog_cef fallback recalibration** (D4b; M1),
  **azure_waf contributor/assertion recalibration** (D4c; M3, calibrated by the live run).
- Issues **#2 / #3** gain explicit severity tables (D4e) before their implementations pin
  anything — the cheapest moment.
- Issue **#50**'s manifest declares persona severities under the D4(a) map; the oracle is the
  adjudicator of record for all future mapping disputes (D3 rule 5).
- Issue **#18** gains the D6 note (severity trust ceiling for unauthenticated transports —
  decide there, not here).
- `ARCHITECTURE.md` gains one sentence pointing at the contract's severity section.
- The D7 re-bless is the only authorized golden move for D4(a)/D4(b); `expected_scores.json`
  and the CEF-path pins stay frozen and act as the regression net.

## References

- **Sigma specification, `level`** — https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md
  — all five definitions quoted verbatim in Context (fetched this session).
- **OCSF 1.8.0 `severity_id`** — https://schema.ocsf.io/api/1.8.0/classes/detection_finding —
  enum descriptions quoted verbatim in Context (fetched this session).
- **ECS `event.severity`** — https://github.com/elastic/ecs/blob/main/schemas/event.yml —
  quoted verbatim in Context (fetched this session).
- **Suricata `classification.config`** — https://raw.githubusercontent.com/OISF/suricata/master/etc/classification.config
  — priorities quoted in ADR-0068 (fetched in that session; distribution facts re-used here).
- **OWASP CRS anomaly scoring** — https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/
  — "collaborative detection and delayed blocking" passage quoted verbatim in D4(c) (fetched
  this session).
- **ArcSight CEF Implementation Standard** — the 0–10 Severity banding syslog_cef already cites.
- **Internal:** ADR-0067, ADR-0068, ADR-0058 D1, ADR-0040, ADR-0020, ADR-0012;
  `firewatch_suricata/normalize.py`, `firewatch_aws_nfw/normalize.py`,
  `firewatch_syslog/normalize.py`, `firewatch_syslog_cef/normalize.py`,
  `firewatch_azure_waf/severity.py`, `firewatch-api/ocsf/mapping.py`, `detector.py`,
  `tests/golden/`.
