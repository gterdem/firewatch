# ADR-0058: Action-Aware Deterministic Escalation Axis — Rules Escalate Instantly, AI Narrates the Post-Alert Story

**Date:** 2026-06-14
**Status:** Accepted — **partially superseded by [ADR-0067](0067-assertion-gated-triage-entry-observed-stratum.md)** (D2's Tier-2 entry semantics and the ALERT/LOG "block status unknown" label; the four tiers, Tier 1's unconditional bypass, D1, D3, D5, D6 and Amendment 1 all stand). Two premises did not survive verification: D2's "no explicit OCSF disposition" for ALERT/LOG (OCSF 1.8.0 defines `disposition_id` 19 Alert / 15 Detected / 17 Logged and `action_id` 3 Observed), and D1's registry — designed as the queue-jumping gate "consumed by D2" — was wired only to a justification adjective until #42.

**Implements / referenced by:** the design handoff `scratch/action-aware-escalation-handoff.md`
(§1 problem · §3 code-grounded gap analysis · §4/§4a/§4b the approved C+B+A recommendation).
**Relates to / honours:** ADR-0003 (AI sampling, not per-log — **stays Accepted**, referenced here, not reopened),
ADR-0012 (IDS `ALERT` badge — the honest disposition this ADR leans on), ADR-0015 (tiered autonomy — the
auto-block ceiling), ADR-0020 (lightweight OCSF alignment — disposition semantics),
ADR-0033 (the `onAction` SIEM-now/SOAR-later seam — where auto-block enforcement lands),
ADR-0035 (RULE / AI / AI+RULE provenance — the escalation justification carries a `RULE` tag),
ADR-0036 (score & confidence presentation — the escalation axis is presented *alongside* the band, not folded into it).
**Skill gate:** anyone touching `scoring.py` / `detector.py` / the AI path loads the `ai-engine-invariants` skill first.

---

## Context

Maintainer, testing FireWatch against synthetic attack data, hit two related failures. Both are
**code-confirmed** (file:line below), not anecdotal.

### Failure 1 — the signal/noise inversion (the blind spot)

`run_rules()` (`packages/firewatch-core/src/firewatch_core/scoring.py:57`) is **blocked-only** for
its high-fidelity factors:

```python
blocked = [e for e in events if e.action in ("BLOCK", "DROP")]   # scoring.py:59
...                                                               # brute_force: len(blocked) >= 10
for e in blocked:                                                 # scoring.py:74 — SQLi/XSS scanned ONLY in blocked
    ...  score += 40  # sql_injection
    ...  score += 35  # xss
score += len(blocked)                                             # scoring.py:92 — +1 per blocked event
```

Only `port_scan` is action-agnostic (`dest_ports` is taken from *all* events, `scoring.py:67`).
The consequence:

- A firewall-**BLOCKED** flood (defence held, the noisy majority of Maintainer's live data) accumulates
  `+1` per event and dominates the board.
- An **ALLOWED-through** SQLi (the request that may have *succeeded*) and an **alert-only** Suricata
  IDS hit (the "might have gotten through" signal) contribute **~0** — they are not in `blocked`,
  so SQLi/XSS pattern-scanning never even looks at them.
- `build_samples` / `build_detailed_samples` (the AI feed, `scoring.py:96` / `:122`) are *also*
  blocked-only (`:104` / `:141`) — so the AI never sees allowed-through or alert-only traffic either.

The loudest events are the ones the defence already stopped; the quietest are the ones that matter most.

### Failure 2 — escalation latency (a single unmistakable attack waits for volume or the AI)

`merge_score` (`scoring.py:189`) bands the score: `>=76` CRITICAL, `>=51` HIGH, `>=26` MEDIUM, else LOW
(`scoring.py:215-222`). The dashboard triage banner is driven by `deriveTriageActors`
(`frontend/src/routes/DashboardRoute.tsx:124`), which surfaces only `threat_level ∈ {CRITICAL, HIGH}`.
So **banner-worthiness == score ≥ 51**. A textbook single SQLi is `+40` → MEDIUM (26-50) → never
banners on its own. To cross 51 it must wait for *volume* or for the AI to clear
`CONFIDENCE_BOOST_THRESHOLD = 0.7` (`scoring.py:47`) and add `+20`/`+10` (`_ai_boost`, `:163`). A single,
obvious, high-fidelity attack therefore sits silent until something else accumulates.

### The frozen blind spot in the oracle

`tests/golden/fixtures/expected_scores.json` **Scenario A** is *a single Suricata `ALERT` → score 0,
LOW* — the blind spot frozen as "correct." Scenario D (5 ALERTs across 5 ports → 25) only scores
because `port_scan` is the one action-agnostic factor. Any rebalance that scores alert-only / allowed
attacks above zero **moves Scenario A and the SQLi/XSS oracles** — which is the *intent*, not a regression.

### What is NOT broken (so we do not "fix" it with an LLM)

The signal already exists. `run_rules` detects SQLi/XSS/port-scan instantly with **zero LLM**. The
`action` axis is already honest and needs **no schema change**: `ActionLiteral` is
`Literal["ALLOW","BLOCK","DROP","ALERT","LOG"]` (`packages/firewatch-sdk/src/firewatch_sdk/models.py:19`),
and normalizers populate it truthfully — Suricata IDS → `ALERT`
(`packages/sources/suricata/src/firewatch_suricata/normalize.py:153`); Azure WAF Detection → `ALERT`,
Block → `BLOCK`, Allowed → `ALLOW` (`firewatch_azure_waf/normalize.py:55-78`); AWS NFW alert → `ALERT` /
pass → `ALLOW` / blocked → `BLOCK`. `ALERT` honestly means "a detection fired; a terminating
disposition is NOT asserted" — the OCSF `Other / Unknown` disposition (≈ `disposition_id` not in the
explicit Blocked/Allowed set). The gap is **escalation latency + packaging**, not detection.

## Decision

Adopt the approved **C-foundation + B-at-launch (frozen golden) + A-as-blessed-follow-up** model
(handoff §4). Deliver "instant + AI-driven" **deterministically**: rules escalate instantly, the AI
*narrates the already-decided escalation* after the fact — never as the per-log trigger.

### D1 — (C) Per-detection declared severity + escalation policy (foundation)

Each correlation/detection rule in `detector.py` carries **declared metadata**: a `severity` level and
an `auto_escalate` policy flag. Anchored to **Sigma `level`** (informational/low/medium/high/critical)
and **Elastic `risk_score`** (0-100 ordinal). Default is **non-escalating** — adding metadata changes
no behaviour until a rule opts in. This is the registry of "which detections are loud enough to jump
the queue," consumed by D2. **Foundation only — no score math, no AI in this piece.**

### D2 — (B, launch) A deterministic, action-aware `escalation` axis on `ThreatScore`

A pure function (no LLM, free at ingest) maps `(events, detections)` → an **escalation verdict** and
writes it to a new additive `ThreatScore.escalation` sub-object. It is computed in
`pipeline.analyze_ip` (`pipeline.py:534`) and read by the banner **in addition to** `threat_level`.
**Scores are frozen at launch → the golden oracle is untouched → safe to ship.** The banner becomes
worthy on the escalation verdict OR `threat_level ∈ {CRITICAL,HIGH}` — so a single high-fidelity
allowed-through / alert-only attack banners *now*, without moving any score.

**The 4-tier action model (handoff §4a) — deterministic, free at ingest, no LLM:**

| `action` | Honest meaning | Tier when a high-fidelity detection is present |
|---|---|---|
| `ALLOW` | Matched a rule, **passed through** — may have **succeeded** | **Tier 1 — loudest.** "Allowed through — possible success." |
| `ALERT` / `LOG` | Detection fired; disposition **NOT asserted** (IDS / WAF Detection) | **Tier 2 — high.** Labelled "block status unknown." |
| `BLOCK` / `DROP`, persistent / high-volume | Defence held but adversary is determined | **Tier 3.** Escalate on persistence → "consider edge/IP block." |
| `BLOCK` / `DROP`, one-off | The WAF did its job | **Tier 4 — informational.** Do not cry wolf. |

"Block status unknown" is the honest analyst-facing label for `ALERT`/`LOG`: FireWatch claims neither
that the traffic was stopped nor that it got through. The same `action` axis is the deterministic
handoff into the post-launch AI narrative (D5 / Issue 6).

### D3 — Additive SDK fields (no contract break)

All fields additive and nullable/defaulted — existing plugins and the read API are unaffected
(the ADR-0048/0055 additive-growth pattern; PLUGIN_CONTRACT.md grows by optional fields only):

- **On `Detection`** (`models.py:193`): `severity: SeverityLiteral | None = None` and
  `auto_escalate: bool = False` — the C metadata.
- **New `ThreatScore.escalation` sub-object** (additive field on `ThreatScore`, `models.py:336`):
  - `tier: int` — 1-4 per the table above (lower = louder).
  - `disposition: str` — the honest action label (`"allowed_through"` / `"block_status_unknown"` /
    `"blocked_persistent"` / `"blocked_one_off"`).
  - `justification: str` — a human-readable, `RULE`-tagged (ADR-0035) sentence safe to render as a
    text node (e.g. "SQLi signature matched on an ALLOWED request — possible success").
  - `block_status: str` — `"blocked"` / `"allowed"` / `"unknown"` (the explicit, non-fabricated state).

Per ADR-0058 this is a **single ThreatScore sub-object**, deliberately *not* split into its own ADR.

### D4 — Deterministic, NOT LLM-per-log (ADR-0003 stays Accepted)

We deliver "instant + AI-driven" **deterministically**. Rules escalate; the AI narrates *after* the
escalation is already decided, per already-fired alert, gated. We explicitly **do NOT** reopen ADR-0003
and **do NOT** make the LLM the per-log detector. Rationale (recorded so this is a decision, not a
silent override): LLM-per-log is slow and costly at log volume, is a prompt-injection surface
(#590/#642), and directly contradicts ADR-0003's accepted "sampling, not per-log" posture. No credible
2026 vendor runs an LLM over every raw log; they LLM-triage *already-fired alerts*. Anthropic's own
framing places the AI threat **post-compromise**, not at initial probes — which is exactly where D5
points the model. ADR-0003 remains **Accepted**; this ADR references it and reinforces it.

### D5 — (A, blessed follow-up, in two parts)

**D5a — score floor on high-fidelity detections + the `run_rules` rebalance (handoff §4b).** Scan
SQLi/XSS across **all** events (not just `blocked`, fixing the `scoring.py:74` blind spot); weight by
disposition (ALLOWED-through highest > ALERT/LOG high > one-off BLOCK informational); make BLOCK
escalate on **persistence**, not a flat `+1` per event (`scoring.py:92`). The AI stays
**additive-only** (ADR-0003 / ARCHITECTURE invariant 3 unchanged). Weights anchored to Sigma `level` /
Elastic `risk_score`. **This MOVES the golden oracle.**

**D5b — the deliberate, blessed golden re-bless (Maintainer's Decision #2, PRE-LAUNCH).** Scenario A
(single Suricata `ALERT`) moves **0 → non-zero on purpose**, along with the SQLi/XSS oracles. This is
recorded here as an **intentional re-bless, not a regression**: the old expected values encoded the
blind spot; the new values encode the principled, action-aware fix that belongs in the open-source
first impression (`first-impression-paramount`). The re-bless PR (Issue 5) MUST land documented new
expected values for Scenario A and the SQLi/XSS scenarios, and carries an explicit **architect
sign-off** in the PR. Maintainer has signed off that Scenario A moving above zero is the *point*.

### D6 — Post-launch AI narrative + future auto-block (seams, not built here)

- The **post-alert AI narrative** (Issue 6, milestone #21) fires *after* an actor escalates, one
  per-alert narrative explaining the already-decided escalation, via `background_analyze_and_alert`
  (`pipeline.py:677`). The LLM is **never the trigger**; additive-only; attacker fields stay inside the
  `<untrusted_data>` sentinel (#590/#642). **Hard-gated on #591** (AI budget/rate control).
- **Auto-block enforcement** (Issue 7, milestone #22, deferred) activates the greyed Settings tier
  through the existing ADR-0033 `onAction` seam, under ADR-0015 guardrails. Not built here.

## Module shape (sketch — for the implementers)

A new **`escalation/` concern** under `packages/firewatch-core/src/firewatch_core/`, decomposed by
concern (target ≤ ~500 lines/file, one concern per module — do not hand it to a single class):

- `escalation/model.py` — the verdict dataclass/types (tier, disposition, justification, block_status)
  and the `SeverityLiteral`-anchored severity ordering (C metadata shape).
- `escalation/policy.py` — the per-detection severity + `auto_escalate` registry that decorates
  `detector.py` rules; defaults non-escalating.
- `escalation/decider.py` — **the pure function** `decide(events, detections) -> EscalationVerdict`.
  No I/O, no LLM. The single home of the 4-tier mapping (§4a). Unit-testable in isolation.
- Wiring point: `pipeline.analyze_ip` calls `decide(...)` and attaches the verdict to `ThreatScore`.

Frontend: extend `deriveTriageActors` (`DashboardRoute.tsx:124`) to admit escalated actors and
present the justification line + disposition label in the (presentational) `TriageBanner.tsx`.

## Standard alignment & deviations

- **Severity / `auto_escalate` (C).** Anchored to **Sigma `level`**
  (informational/low/medium/high/critical — the de-facto detection-rule severity vocabulary) and
  **Elastic Detection Rules `risk_score`** (0-100 ordinal severity). `SeverityLiteral` already mirrors
  Sigma's five levels (`models.py:21`), so C reuses the existing vocabulary — no new enum.
- **Disposition semantics (the 4-tier model).** Anchored to **OCSF `disposition_id`**: `ALLOW` ≈
  *Allowed*, `BLOCK`/`DROP` ≈ *Blocked*, and `ALERT`/`LOG` ≈ a non-terminating disposition we surface
  honestly as "block status unknown" (we assert neither Allowed nor Blocked). This is consistent with
  ADR-0012 (IDS `ALERT` badge) and ADR-0020 (lightweight OCSF alignment).
- **Deviation recorded.** OCSF models disposition as a single integer on a Finding; FireWatch keeps the
  flat `ActionLiteral` it already stores (no schema change) and *derives* tier/disposition from it at
  read time. Justification: the `action` axis is already populated honestly by every normalizer, the
  derivation is pure and free, and folding an OCSF integer column in would be schema churn for zero
  added fidelity. The OCSF export boundary (ADR-0040) can map `action → disposition_id` there if needed.
- **Provenance.** The escalation `justification` is a `RULE`-tagged artifact (ADR-0035): it is a
  deterministic rule output, never an AI inference. The post-launch narrative (D6) is separately tagged.

## Blast radius

- **SDK** — additive only: two fields on `Detection`, one `escalation` sub-object on `ThreatScore`.
  No existing field changes value. **No PLUGIN_CONTRACT break** (PLUGIN_CONTRACT.md gets an additive
  changelog entry, the ADR-0048/0055 pattern).
- **Core** — new `escalation/` package; `detector.py` gains declared metadata; `pipeline.analyze_ip`
  gains one `decide(...)` call. D5 (follow-up) edits `run_rules` / `build_samples` scoping.
- **Frontend** — `deriveTriageActors` + `TriageBanner` read the new axis; a global, schema-driven
  Settings card (Issue 4). No per-source UI (modular-UI rule).
- **API** — the `escalation` sub-object surfaces on the existing read-shape (ADR-0029), additive.
- **Golden oracle** — **untouched at launch (B)**; **deliberately re-blessed exactly once** by D5/Issue 5.

## Alternatives considered

- **LLM-per-log detection ("make it AI-driven" literally)** — *rejected.* Slow, costly,
  prompt-injection surface (#590/#642), and contradicts ADR-0003 (Accepted). The signal is already
  detected deterministically; the AI's value is post-alert synthesis, not detection.
- **Just lower the HIGH band / bump SQLi from +40** — *rejected.* A blunt tuning that floods the banner
  with blocked one-offs (the noise) and still can't express "allowed-through is louder than blocked."
  The action axis is the missing dimension; a single threshold can't carry it.
- **Fold escalation into `threat_level` (one number)** — *rejected.* ADR-0036 keeps band and reasoning
  separable; collapsing disposition into the score loses the honest "blocked vs allowed vs unknown"
  distinction that is the whole point. Escalation is a *second axis* presented alongside the band.
- **Split the `ThreatScore.escalation` sub-object into its own ADR** — *rejected* (Maintainer Decision #3).
  One ADR keeps the C/B/A story and its SDK shape coherent; the sub-object is meaningless without the
  decider that produces it.
- **Re-bless the golden oracle silently / treat Scenario A move as a regression** — *rejected.* The
  blind spot was frozen as "correct"; moving it is the deliberate fix and must be recorded as such with
  documented new values and architect sign-off (D5b).
- **Ship the rebalance (A) post-launch** — *considered, rejected by Maintainer (Decision #2).* The
  principled fix is part of the open-source first impression; it ships **pre-launch** under milestone #19.

## Reasoning

The product Maintainer wants — obvious attacks warn *immediately, with a justification*, and the platform
feels *AI-driven and SOAR-ready* — is achievable **without** putting the LLM in the per-log hot path.
The `action` field already carries the disposition truth honestly across every source, for free, at
ingest. A pure deterministic decider turns that into an escalation axis that makes a single
allowed-through SQLi or an alert-only IDS hit banner-worthy *now* (B, frozen scores, safe). The
principled scoring rebalance (A) then closes the blind spot at the source, deliberately and once, with
the oracle re-blessed on purpose. The LLM is pointed where it actually differentiates — post-alert
"did it succeed / what next" narrative on already-fired alerts — preserving ADR-0003 and matching how
credible 2026 vendors actually use AI in the SOC.

## Consequences

- Follow-up issues (handoff §5): **Issues 1-5 pre-launch** under milestone #19 (severity registry;
  deterministic escalation axis; banner + legend explanation layer; global Detection & Escalation
  Policy settings card; the phased `run_rules` rebalance + blessed re-bless). **Issue 6** (post-alert
  AI narrative) → milestone #21, **hard-gated on #591**. **Issue 7** (auto-block via `onAction`) →
  milestone #22, deferred.
- **Issue 5 is the one and only deliberate golden re-bless** (D5b) and carries architect sign-off.
- PLUGIN_CONTRACT.md gains an additive changelog entry for the two new `Detection` fields.
- The `ai-engine-invariants` skill governs every PR touching `scoring.py` / `detector.py` / the AI path.
- ADR-0003 remains Accepted and is reinforced, not superseded.

## References

- **Sigma `level`** (rule severity vocabulary) — https://sigmahq.io/docs/basics/rules.html — backs D1
  severity levels.
- **Elastic Detection Rules `risk_score`** (0-100 ordinal severity) —
  https://www.elastic.co/guide/en/security/current/rules-ui-create.html — backs D1 escalation weighting.
- **OCSF `disposition_id` / Finding dispositions** — https://schema.ocsf.io/ (1.8.0) — backs the
  4-tier action→disposition mapping; ALERT/LOG = non-terminating ("block status unknown").
- **OWASP Testing Guide v4.2 §4.7.5/§4.7.6** — the SQLi pattern basis already in `scoring.py:36`.
- **NIST SP 800-61r2** — IR lifecycle; escalation = Detection & Analysis, enforcement = Containment
  (the SIEM-now / SOAR-later boundary this ADR honours via ADR-0033/0015).
- **Internal:** ADR-0003 (sampling, not per-log — reinforced), ADR-0012 (IDS ALERT badge),
  ADR-0015 (tiered autonomy ceiling), ADR-0020 (OCSF alignment), ADR-0033 (`onAction` seam),
  ADR-0035 (RULE/AI provenance), ADR-0036 (score/confidence presentation), ADR-0048/0055 (additive
  SDK-growth pattern). Design handoff: `scratch/action-aware-escalation-handoff.md`.

---

## Amendment 1 (2026-06-14) — Partial / mixed-disposition actors: `block_status` must tell the truth

**Status: Accepted (correctness + honesty fix, not a reversal).** D1–D6 are unchanged. Tier and
priority semantics are unchanged. This amendment adds a fifth `block_status` value and a structured
count breakdown so the *block-status truth* survives the common case where one actor produces both
alert-only and terminally-blocked events. The strategist owns this design; this records it.

### The corner D2/D3 left under-specified (code-confirmed bug)

D3 closed `EscalationVerdict.block_status` to **`blocked` / `allowed` / `unknown`** — there is **no
vocabulary for the mixed case**, where an actor's events span more than one terminal disposition.
The decider (`escalation/decider.py` `decide()`) partitions events into allow / alert_log /
block_drop (lines 72–74) but **returns on the first non-empty partition in priority order**: the
ALERT/LOG branches (lines 89–104) fire *before* the BLOCK/DROP partition is ever inspected, and emit
`block_status="unknown"`. For the live actor `198.51.100.64` (307 ALERT + 9 BLOCK), the **9 real
BLOCK events are silently discarded** and the verdict falsely reads `block_status_unknown` — FireWatch
asserts "block status unknown" while holding 9 confirmed blocks in hand. That falsifies the **honest
provenance** claim this very ADR is built on.

This is about to become the *common* actor shape, not a corner: with the IPS-flip Maintainer is performing
(IDS detect → IPS inline-block), a determined actor routinely produces a large ALERT/LOG body **and**
a smaller set of confirmed BLOCK/DROP events. The closed three-value `block_status` falsifies the
honesty guarantee at exactly the worst time.

### Decision

**A1 — Add `"partial"` to `EscalationBlockStatusLiteral` (additive SDK change).** When an actor's
events span **more than one terminal disposition class** (e.g. both ALERT/LOG and BLOCK/DROP present),
`block_status="partial"`. The three existing values keep their exact meaning for single-class actors;
nothing changes for actors whose events all share one disposition. This is the ADR-0048/0055 additive
pattern D3 already invokes — no PLUGIN_CONTRACT break, existing plugins and the read API unaffected.

**A2 — Add a structured count breakdown `disposition_counts` to `EscalationVerdict` (additive).** A
small integer-valued object — `{blocked: int, alert_unknown: int, allowed: int}` — counting the
events in each terminal-disposition class. **Structured integers, NOT a baked English string.** The
frontend formats the human label ("9 blocked · 298 alert-only"); the backend ships glass-box,
testable, i18n-safe counts. (Rationale: a pre-formatted string is untestable beyond string-equality,
not localizable, and tempts attacker-field interpolation. Counts are pure engine numerics — the same
"trusted bare numerics" class as `count` / `score_delta` in the #642 sentinel discipline.)

**A3 — The decider stops short-circuiting; it tallies all partitions.** `decide()` is rewritten to
count every partition before returning, instead of returning on the first non-empty one. Then:

- **Tier still derives from the loudest present action** — priority order is **unchanged**. ALERT/LOG
  still outranks BLOCK/DROP for the headline; the actor still lands in the triage queue (most of its
  traffic was *not* terminally blocked, so it remains "needs a decision"). The IPS flip does not
  down-rank these actors.
- **`block_status = "partial"`** whenever events span >1 terminal class; otherwise the existing
  single-class value (`blocked` / `allowed` / `unknown`).
- **`disposition_counts`** is attached on every verdict (the mix is carried by counts, present even
  for single-class actors where two of the three are zero).

**A4 — `disposition` stays the single loudest label; we do NOT add a 5th `disposition` value or a 5th
tier.** Keeping `disposition` to its four `EscalationDispositionLiteral` values avoids re-coupling
disposition→tier and avoids growing every color/legend/routing map that switches on it. The mixed
reality is carried entirely by `block_status="partial"` + `disposition_counts`. (Strategist R2.)

**A5 — The mixed justification is a RULE-tagged ledger sentence built from the counts** — e.g.
`"[RULE] 307 ALERT/LOG (block unknown) + 9 BLOCK/DROP — most traffic not terminally blocked; 9
confirmed blocked."` Built from engine integers only; **no attacker-controlled event fields embedded**
(keeps the #648 / #642 discipline — rule-derived text + bare numerics only, exactly as the existing
justification builders).

### Resolved block-status truth table

| events span | `block_status` | `disposition` (loudest) | `disposition_counts` | source |
|---|---|---|---|---|
| ALLOW only | `allowed` | `allowed_through` | `{allowed:n}` | D3 (unchanged) |
| ALERT/LOG only | `unknown` | `block_status_unknown` | `{alert_unknown:n}` | D3 (unchanged) |
| BLOCK/DROP only | `blocked` | `blocked_persistent`/`blocked_one_off` | `{blocked:n}` | D3 (unchanged) |
| **>1 terminal class** (e.g. ALERT + BLOCK) | **`partial`** | loudest present (priority unchanged) | **`{blocked, alert_unknown, allowed}`** | **this amendment** |

Only the last row is new; the first three are restatements of D3.

### Standard alignment & deviation (cited — verified, not assumed)

Entity-level mixed/partial disposition is **not a field-recognized term**, so FireWatch's per-actor
partial-with-counts is a **deliberate FireWatch-native representation**, explicitly *not* "matching
vendor X":

- **OCSF `disposition_id` is per-finding, not per-actor.** OCSF 1.x defines `disposition_id` as an
  enum on a single Detection Finding (Blocked, Allowed, … — ~27 values); it specifies **no actor-level
  aggregation**. An actor in FireWatch *aggregates* findings and is therefore **inherently
  multi-disposition** — so a per-actor "partial + structured counts" rollup is the honest projection of
  OCSF's per-finding model onto an entity, a glass-box differentiator rather than a deviation from a
  defined OCSF actor-rollup (there is none). Ref: OCSF `detection_finding` `disposition_id`,
  https://schema.ocsf.io/ (1.x).
- **Splunk ES `disposition`** is an *analyst-judgment* field (True/False Positive, Benign, …), **not an
  action rollup** — orthogonal to FireWatch's action-derived axis. **Microsoft Sentinel** and
  **Elastic Security** have **no entity-level disposition rollup** at all. So there is no field
  standard to mimic here; FireWatch defines the honest representation.

The deviation already recorded in the parent ADR (FireWatch derives disposition from the flat
`ActionLiteral` at read time rather than storing an OCSF integer) is unchanged and now simply spans
multiple classes per actor via `disposition_counts`.

### Blast radius (amendment)

- **SDK** — additive only: `"partial"` added to `EscalationBlockStatusLiteral`; new
  `disposition_counts` object field on `EscalationVerdict` (defaulted, so older serialized verdicts and
  existing plugins are unaffected). **No PLUGIN_CONTRACT break** (additive changelog entry, ADR-0048/0055).
- **Core** — `escalation/decider.py` rewritten to full-tally (no short-circuit) + a mixed-justification
  builder; the model gains the `disposition_counts` type. Tier/priority logic **unchanged**.
- **Frontend** — `TriageBanner.tsx` `blockStatusLabel()` gains a `partial` case that renders
  "9 blocked · 298 alert-only" from the counts (small signature change to pass counts in); the popover
  shows the breakdown; `TIER_LEGEND` stays **4 rows + one explanatory line** ("an actor can be partial:
  some events blocked, some alert-only; it's queued by its loudest events"). Bounded-height / no inner
  scrollbar preserved.
- **Golden oracle** — a **new mixed-actor fixture is ADDITIVE coverage**: it adds a scenario asserting
  `block_status="partial"` + the `disposition_counts` for a span-two-classes actor. It **does NOT
  touch any existing `expected_scores.json` value** and is **NOT** a second re-bless — the one and only
  authorized golden move remains D5b (Scenario A, already landed under issue #651). Scores stay frozen
  for this amendment; only the new fixture's *escalation* assertions are added.

### Alternatives considered (amendment)

- **Leave `block_status="unknown"` for the mixed case** — *rejected.* It is the bug: it discards
  confirmed blocks and asserts "unknown" while holding evidence to the contrary. Falsifies the ADR's
  own honesty claim, worst at IPS-flip time.
- **Add a 5th `disposition` value and/or a 5th tier for "mixed"** — *rejected (R2/A4).* Re-couples
  disposition→tier, forces a new color/legend/routing branch everywhere `disposition` is switched on,
  and still wouldn't carry the actual counts. `block_status="partial"` + `disposition_counts` carries
  the mix without growing the tier model.
- **Ship a pre-baked English breakdown string from the backend** — *rejected (R1).* Untestable beyond
  string-equality, not i18n-able, and an attacker-field interpolation temptation. Structured integers
  are glass-box and let the frontend own presentation.
- **Down-rank partial actors (they're "mostly blocked")** — *rejected.* Most of a partial actor's
  traffic was *not* terminally blocked (the ALERT/LOG body); it belongs in the queue at its loudest
  tier. An optional within-tier "got-through ratio" tiebreak is noted as a **post-release nicety**, not
  part of this amendment.

### References (amendment)

- **OCSF `detection_finding` `disposition_id`** (per-finding enum; no actor-level rollup defined) —
  https://schema.ocsf.io/ — frames the FireWatch-native per-actor partial-with-counts representation.
- **Splunk ES `disposition`** (analyst-judgment, not action) / **Microsoft Sentinel** &
  **Elastic Security** (no entity-level disposition rollup) — confirm there is no field standard to
  mimic; FireWatch defines the honest representation.
- **Internal:** D3 (the closed three-value `block_status` this extends), #642/#648 (sentinel /
  rule-derived-text-only justification discipline this amendment honours), ADR-0035 (RULE provenance),
  ADR-0048/0055 (additive SDK growth). Bug actor: `198.51.100.64` (307 ALERT + 9 BLOCK).
