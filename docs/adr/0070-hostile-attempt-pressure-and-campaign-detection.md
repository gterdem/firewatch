# ADR-0070: Hostile-Attempt Pressure and Campaign Detection — Windowed, Disposition-Agnostic Persistence Scoring

**Date:** 2026-07-15
**Status:** Proposed (coupled with ADR-0069; corrects ADR-0067 D5(1) — see D7)

**Corrects:** ADR-0067 **D5(1)** (the band-axis safety-net claim — mechanically false as written;
§D7 below). On acceptance, ADR-0067's status line gains "D5(1)'s band-accumulation claim
corrected by ADR-0070" (status-line update only; the text is never edited).
**Couples with:** ADR-0069 (canonical severity semantics — its D4(b) severity downshift removes
the *accidental* per-event queue path for auth failures; this ADR adds the *deliberate*
aggregate one. Either alone leaves a hole; §D8 fixes the landing order).
**Relates to / honours:** ADR-0058 (+A1 — D1 severity registry, D5a disposition weighting, the
capped `detection_boost` seam all reused, not changed), ADR-0067 (assertion gate — R2 enters the
queue through D1(a), machinery already built), ADR-0059 (Triage threshold stays the one tunable
visibility knob), ADR-0068 (the volume oracle is the adjudicator of every constant here),
ADR-0041 (recompute-at-read-time — the precedent for deriving campaign state instead of
persisting it), ADR-0036 (band ⊥ escalation), ADR-0035 (RULE provenance), ADR-0033 ("Harden"
stays advice via the action seam; enforcement verbs arrive with SOAR, M4), ADR-0021/0065
(agentless, local-first — FireWatch observes and triages; it does not interdict).
**Skill gate:** anyone touching `detector.py`, `scoring.py`, or `escalation/` loads
`ai-engine-invariants` first.

---

## Context

### The defect, verified (file:line, this session)

**Nothing in FireWatch scores the persistence of unblocked hostile attempts.** The scoring and
correlation model was built against Azure WAF, where "the control fired" (BLOCK) was a reliable
proxy for "a hostile attempt happened." The M1 Solo bundle (Suricata IDS, syslog/linux_auth,
detect-only ClamAV) is entirely passive — nothing blocks, so nothing counts:

- **Presence rules fire once.** `run_rules` (`scoring.py:96`) adds `_SQLI_BASE=40` ×
  disposition weight when `sqli_events` is non-empty — one probe scores the same as 10,000.
  Same for XSS (35).
- **Every volume rule filters on BLOCK/DROP first.** `brute_force` (≥10 blocked, +30,
  `scoring.py:102`), the persistence floor (≥3 blocked, +10, `scoring.py:128`), and
  `_sustained_attack` (≥10 blocked spanning ≥30 min, `detector.py:197`) all count only what a
  control denied.
- **`_brute_force_then_login` fires only on compromise** (≥3 brute-force events *plus* a
  successful login, `detector.py:136`).
- **`port_scan` is action-agnostic but breadth-only** (≥5 distinct ports, +25) — and 25 alone
  is LOW band; it never reaches any threshold by itself.

Consequence, mechanically: **a pure SSH brute force — hundreds of ALERT-action `Failed
password` events, no success — produces `rule_score = 0` and zero detections, at any volume.**
The Maintainer escalated exactly this as first-order.

**Defect 2 — no time denominator.** `pipeline.analyze_ip` (`pipeline.py:569`) and
`analyze_ip_detailed` (`pipeline.py:846`) call `store.get_by_ip(ip)` — `SELECT * FROM logs
WHERE source_ip = ?`, **all events ever** (`adapters/sqlite/events.py:107`). So `len(blocked)
>= 10` counts *lifetime* blocks: an IP blocked ten times over six months is permanently
`brute_force +30`; three lifetime blocks is permanently Tier-3 `blocked_persistent`
(`escalation/decider.py`, `_PERSISTENCE_THRESHOLD = 3`). A windowed variant —
`get_by_ip_since(ip, cutoff)` — already exists one function below (`events.py:117`, used by the
escalation-policy route for its 24h hit-counts, issue #650). **Any fix that generalizes
counting to unblocked attempts MUST carry a window, or every recurring ambient scanner crosses
every threshold eventually — the ADR-0067 flood on a delay timer.**

**Defect 3 — distributed attacks are architecturally invisible.** `detect()` and the whole
analysis path are per-IP (`detect(events: list[SecurityEvent])` receives one actor's list).
Single-source volumetrics are fixable in this shape; distributed (many-actor) campaigns are
not. Recorded as a scope boundary (§D9), not solved here.

### Why this is first-order and not another presentation fix

ADR-0067 closed the *false-urgency* half of the passive-source problem (bare ALERT/LOG no
longer floods the queue). This ADR closes the *false-calm* half: after #42, and especially
after ADR-0069's severity recalibration lands, a watch-only box shows a reachable calm state —
while a determined, unsuccessful, ongoing attack accumulates **nothing anywhere**. The
Maintainer's three cases — SSH brute force, sustained SQLi probing, a single-IP flood — are one
defect: `BLOCK/DROP` was never the semantics the volume rules wanted. It was a WAF-era proxy
for **"a hostile attempt that did not succeed."** Name the real predicate and the three cases
collapse into one rule.

### Standards and prior art (verified this session unless noted)

**fail2ban 1.1.0 — the incumbent for exactly this problem** (shipped `config/jail.conf`,
fetched this session from
https://raw.githubusercontent.com/fail2ban/fail2ban/1.1.0/config/jail.conf):

- Defaults, verbatim: `bantime  = 10m` · `findtime  = 10m` · `maxretry = 5`, with the comment
  *"A host is banned if it has generated \"maxretry\" during the last \"findtime\" seconds."*
  The `[sshd]` jail adds no overrides — it inherits these.
- The `recidive` jail, verbatim: `logpath  = /var/log/fail2ban.log` · `bantime  = 1w` ·
  `findtime = 1d` — **a detector whose input is the output of other detectors** (it greps
  fail2ban's own Ban lines): five bans in a day escalates to a week-long all-ports ban. This is
  structurally identical to R2 (`campaign`) consuming R1 (`attempt_pressure`) episodes — the
  shape is proven prior art, not invention.
- fail2ban's own answer to "don't lock me out" is an **identity allowlist, not a threshold**,
  verbatim: *"\"ignoreip\" can be a list of IP addresses, CIDR masks or DNS hosts. Fail2ban
  will not ban a host which matches an address in this list."* and *"\"ignoreself\" specifies
  whether the local resp. own IP addresses should be ignored (default is true)."* — the
  false-positive case is answered with "this identity is me," not "raise the number." (§D6
  builds on this.)
- fail2ban has **no severity concept** (every filter match is equal weight; sensitivity is
  chosen via filter *modes* — `[sshd]` comment, verbatim: *"normal (default), ddos, extra or
  aggressive"*) and no report-only mode.

**ECS `event.kind`** — the ALERT/LOG line the attempt predicate rides on was verified live and
quoted verbatim in ADR-0067 RC4 (`alert` = "an alert or notable event, triggered by a detection
rule executing externally"; `event` = general telemetry;
https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-kind — fetched in that
session, reused here with attribution).

**Sigma `level`, `informational`** — quoted verbatim in ADR-0069 (fetched live in that
session): *"No case or alerting should be triggered by such rules because it is expected that a
huge amount of events will match these rules."* — the basis for excluding `info`-severity
ALERTs from the attempt count (§D1).

**MITRE ATT&CK T1110 (Brute Force), TA0006** — the technique class R1/R2's flagship case
normalizes to (already the syslog category's mapping, `firewatch_syslog/normalize.py:80`).

## Decision

### D1 — The attempt predicate (no new SDK field, no per-source logic)

> An event is a **hostile attempt** iff
> `action ∈ {BLOCK, DROP, ALERT}` **and not** (`action == ALERT` and `severity == "info"`).

- **BLOCK/DROP** — a control denied a hostile try (the try still happened).
- **ALERT** — a detection engine asserted a hostile try (ECS `kind:alert`, the exact line
  ADR-0067 RC4 drew). Covers passive Suricata, WAF Detection mode, detect-only ClamAV, and the
  syslog `Failed password` line (verified: `firewatch_syslog/normalize.py:79-80` maps it to
  `ALERT`, and it stays `ALERT` after ADR-0069 D4(b) — only its severity drops to `low`).
- **LOG and ALLOW stay out.** LOG is telemetry (ECS `kind:event` — nothing asserted anything);
  ALLOW-with-detection is Tier-1 territory (possible *success*, not a failed attempt) and
  already has the loudest path in the product.
- **`info`-severity ALERTs stay out** — counting events that Sigma defines as "expected that a
  huge amount … will match" into a pressure metric would rebuild the flood inside the band
  axis. `severity=None` **does count** (fail-quiet maps unknown to `low`, ADR-0069 D3.4; an
  asserting event with no declared level is still an assertion).

The predicate is core-owned, computed at analyze time from fields every event already carries.
No SDK change, no normalizer change, nothing for a plugin author to opt into.

### D2 — R1 `attempt_pressure`: a new correlation rule, windowed by construction

A new rule in the detector (template: `_sustained_attack`), **not** a `run_rules` rewrite —
`detect()` already receives the full per-IP list, computes spans, declares severity and
`auto_escalate` into the ADR-0058 D1 registry, and its `score_delta` flows to the band via the
capped `detection_boost` (`merge_score`, cap +30). Two arms, either fires it:

- **Density (the flood/brute-force arm):** ≥ `N_p` attempts within any trailing `W_p` window
  (provisional `N_p = 10`, `W_p = 30 min`).
- **Endurance (the slow-drip arm):** ≥ `N_p` attempts spanning ≥ `W_p` within the state window
  (§D4) — the `_sustained_attack` predicate generalized from blocked-only to attempts.

Declaration: `severity="medium"`, `auto_escalate=False`, `score_delta=15`. **Pressure alone
does not queue** — on an internet-exposed box, single-window pressure is ambient (fail2ban's
entire existence proves actors trip 5-in-10-min continuously). It contributes band score, and
it is the input to R2. The reason string carries engine integers only (count, span — ADR-0035
discipline).

**R1 subsumes and retires `_sustained_attack`.** Blocked events are a strict subset of
attempts, so every event set that fired `_sustained_attack` (≥10 BLOCK/DROP spanning ≥30 min)
fires R1's endurance arm; the score_delta is identical (15), so no score changes for
previously-firing sets. Keeping both would double-count the same mass inside the capped boost
and muddy the breakdown. `tests/golden/` pins no `sustained_attack` values (verified —
`expected_scores.json` has `detection_rule_names: []` throughout; the name appears only in
core/api unit tests, which update as ordinary test changes, not a re-bless).

### D3 — R2 `campaign`: the queue-entry bar, derived — not persisted

An actor is a **campaign** when its attempts within the campaign horizon (§D4) show
**recidivism or breadth growth**:

- **Recidivism:** ≥ 2 distinct *pressure episodes*. An episode is a maximal run of attempts in
  which consecutive attempts are separated by less than the quiet gap `G` (provisional
  `G = 60 min`) and which satisfies R1's predicate. Two episodes = the actor stopped and came
  back — fail2ban's `recidive` shape (a detector over detector output), with our episodes in
  place of its Ban lines.
- **Breadth growth:** ≥ 1 pressure episode **and** the actor's attempts span ≥ 2 attack
  categories or ≥ 5 distinct destination ports across the horizon — pressure that is also
  *exploring* is not commodity spray.

Declaration: `severity="high"`, `auto_escalate=True`, `score_delta=25` (> R1's 15, so the
decider's `_top_rule_name` headline names the campaign). Via ADR-0067 D1(a) — the qualify gate
already merged in #42/PR #51 — a campaign detection puts the actor at **Tier 2** with a
RULE-tagged justification. No new escalation machinery.

**Campaign state is derived, not persisted.** `detect()` stays pure (its module contract: "Pure
functions, no I/O"); episodes are recomputed from the event list on every analysis — the
ADR-0041 pattern (recompute factor→events at read time; never persist derived state). The event
store *is* the state; the campaign horizon (§D4) bounds the recompute. This deliberately
rejects the "small persistence surface" a first design pass suggested: a materialized episode
ledger is a future *optimization* (if horizon queries ever measure slow), never a second source
of truth. R6's decision memory (§D6) is different — operator decisions are primary facts, not
derived ones, and they persist (issue #47).

### D4 — Windowing is a first-class decision (fixes defect 2 everywhere, not just for R1)

Two named windows, both core constants, both provisional (§D5):

| Window | Provisional value | Feeds | Meaning |
|---|---|---|---|
| **State window `W_state`** | 24 h | `run_rules`, `build_score_breakdown`, `decide()` | "What is this actor's *current* threat state?" — score, band, tier reflect the trailing day, not the actor's lifetime |
| **Campaign horizon `W_campaign`** | 7 d | `detect()` | "Is this actor *waging a campaign*?" — recidivism needs memory longer than state |

- The pipeline fetches once per actor and slices in-process; `first_seen`, `last_seen`,
  `total_events`, and `blocked_events` on `ThreatScore` **keep their lifetime meaning**
  (presentation facts, unchanged), while every *counting rule* sees only its window. The
  24 h precedent already exists in-tree: the escalation-policy route derives its hit-counts via
  `get_by_ip_since(ip, now − 24 h)` (issue #650).
- This closes defect 2's concrete absurdities: ten blocks across six months is no longer
  permanent `brute_force +30`; three lifetime blocks is no longer permanent Tier-3.
- A Tier-2 campaign verdict therefore **auto-expires**: once the actor's attempts age past
  `W_campaign` with no recurrence, the campaign no longer derives and the actor returns to
  observed/record. `W_campaign = 7 d` deliberately matches fail2ban's `recidive`
  `bantime = 1w` — the incumbent's chosen memory for "this actor keeps coming back."
- **Golden oracle: untouched.** `tests/golden/test_suricata_scores.py` calls
  `run_rules(events)` / `merge_score` directly on in-memory lists (verified this session) —
  the window is applied by the *pipeline* before those functions, so `expected_scores.json`
  values do not move. No re-bless is required by this ADR. (This is the strategist's
  fixtures-are-small claim, verified and made precise: it holds because windowing lands at the
  fetch/slice seam, not inside `run_rules`.)

### D5 — The constants are provisional, and say so (nothing laundered)

`N_p = 10`, `W_p = 30 min`, `G = 60 min`, episodes ≥ 2, breadth = 2 categories / 5 ports,
`W_state = 24 h`, `W_campaign = 7 d`, deltas 15/25 are **engineering estimates, not calibrated
values**. They are:

- **Declared in one place** — a named-constants block consumed by the rules, mirrored into the
  volume-oracle manifest (#50) as the adjudicating fixture (ADR-0068 D2's manifest discipline:
  changes need a stated distribution justification, no bless ceremony).
- **Calibrated by the standing procedure** — the ADR-0068 D3 live-calibration pass (Pi
  Suricata night + internet-exposed sshd capture; the pending live-systems test): compare the
  observed per-actor attempt distribution against the manifest personas and adjust
  deliberately, with the diff justified in the PR.
- **Falsifiable, in both directions:**
  - *Too loose:* a real ambient night in which > the flood tripwire (10, ADR-0068 D2-2) of
    actors reach `campaign` — the queue floods on a recidivism timer → raise `N_p` /
    tighten R2.
  - *Too tight:* a planted (or real) determined brute force / single-IP flood that fails to
    produce a pressure episode → lower `N_p` / widen `W_p`.
  - The breach-among-noise invariant (ADR-0068 D2-3) remains the anti-suppression backstop.

Until the calibration pass runs, the values ship as defaults **with the oracle asserting them
against the manifest** — the manifest, not this ADR, is the ledger of record for the numbers.

### D6 — Configurability: decisions, not thresholds

The Maintainer asked: "shouldn't all of them be configurable?" Resolution, per knob class:

- **Detection floor (R1/R2 constants): NOT operator-tunable.** Code-declared, Sigma-anchored
  severity semantics (ADR-0069), volume-oracle-adjudicated (#50). This preserves the settled
  property that FireWatch *cannot be misconfigured into missing a breach* (ADR-0067's
  zero-tuning gate, extended). fail2ban is not a counter-example: it must expose `maxretry`
  because its output is a *ban* whose false positive locks a human out — and even so, its own
  answer to that FP is the identity allowlist, not the number (`ignoreip` / `ignoreself = true`
  by default, quoted verbatim above). FireWatch's output at this layer is *attention*, and the
  FP remedy is the same shape: identity, not threshold.
- **Visibility: tunable — and it already exists.** The ADR-0059 Triage threshold (default
  HIGH) is the one operator knob over band-axis queue entry. R1's score contribution flows
  under it; no new knob.
- **Suppression: per-object with memory and re-entry, never a global number.** Two verbs with
  different lifecycles, server-side (extends issue #47):
  - **"Expected — this is me"** marks the **actor identity** (the `ignoreip` precedent): my
    backup job, my scanner, my own laptop. Suppresses the actor's queue entries; re-enters on
    material change (the #49 novelty bar — minimal slice pulled forward, §Consequences).
  - **"False positive"** marks the **detection-on-actor** (the signal misfired): this campaign
    call was wrong. Suppresses that detection's re-assertion for that actor; a *different*
    qualifying signal still queues.
  Conflating these was retracted from an earlier design pass; they age differently (an
  identity stays yours; a misfire is per-signal) and feed different improvement loops (the FP
  verb is future rule-calibration data).

### D7 — Correction to ADR-0067 D5(1): the band net did not exist

ADR-0067 D5(1) claims, verbatim: *"A persistent low-severity scanner accumulates score, crosses
the band threshold, and enters triage **on merit via the band axis**. This is the can't-miss
net that makes D3's fail-quiet safe."* **This is mechanically false as written** (author: this
ADR's author; the correction is owed). `run_rules` has no term that grows with unblocked event
count — the maximum a persistent unblocked scanner without signature payloads can reach is
`port_scan +25` + `multi_source +10` = 35, LOW/MEDIUM band, below the default HIGH Triage
threshold at any volume; a single-port SSH brute force reaches exactly 0. The band axis was not
a weak net for passive sources — it was *no net*, and D3's fail-quiet rested on it.

Disposition: **correction, not reversal.** D3's fail-quiet ruling stands — but as of this ADR
it rests on R1/R2 (which are what D5(1) described wishfully): pressure accumulates band score,
campaigns queue via D1(a). Form: a status-line addendum on ADR-0067 pointing here (house rule —
supersede/annotate, never edit). The lesson feeds the standing conformance check: D5(1) was an
architecture claim about existing code that nothing verified at writing time; distribution
claims in ADRs now get the same file:line verification as root-cause claims.

### D8 — Coupling with ADR-0069: one M1 slice, two halves, fixed landing order

Today (post-#42, pre-0069), a real SSH brute force *does* queue — **by accident**: every
`Failed password` line is ALERT/`high` (`firewatch_syslog/normalize.py:80`), so one ambient
failed login = one Tier-2 actor via D1(b) — the flood channel ADR-0069 D4(b) closes by
downshifting the single line to `low`. But that downshift alone would make a determined,
unsuccessful brute force invisible to the queue (ALERT/`low` never qualifies; score 0 — this
ADR's defect 1). And R1/R2 alone would leave the per-event flood channel open. **Neither ADR is
safe to ship without the other.**

Landing order inside M1: **R1/R2 land before or with the ADR-0069 severity recalibration of
syslog/suricata** — the interim state then errs toward the existing flood (known, bounded by
#42's gate) rather than toward silent invisibility of an active attack. The volume oracle (#50)
asserts the end state of both together; its manifest gains the brute-force personas (§D5).

ADR-0069's D4(b) "what is lost: nothing reachable" falsifier is amended (draft-edit, it is
uncommitted) to acknowledge the case it did not cover: the **ongoing-unsuccessful** attacker,
which after the downshift is reachable only through this ADR's R1/R2. Its falsifier gains the
corresponding clause (a sustained unsuccessful brute force that neither pressures nor
campaigns).

### D9 — Scope boundaries (recorded, deliberate)

- **Distributed / many-actor campaigns are out of scope** (defect 3). The per-actor pipeline
  shape cannot see them; a cross-actor aggregation stage is a future ADR with its own
  distribution analysis. The R5 headline's *aggregate* counts (all actors) are presentation
  over per-actor results, not cross-actor detection.
- **Detection stays fully deterministic.** The LLM narrates post-alert (ADR-0058); rules-only
  is a supported install (issue #4) — the AI is never the safety net.
- **No interdiction.** R2's output is a queue entry and advice ("Harden" via the ADR-0033
  seam — e.g., *recommending* fail2ban on the attacked host is in-scope advice); enforcement
  verbs arrive with SOAR (M4, ADR-0015/issues #20-21). Tier 1's unconditional bypass and the
  four-tier vocabulary stand.
- **Rules are core-owned and source-agnostic.** The attempt predicate reads only contract
  fields; no per-source detection logic anywhere in this ADR.

### Position vs fail2ban's defaults (explicit, for migrating users)

FireWatch's pressure bar (10-in-30-min, provisional) is **looser than fail2ban's 5-in-10-min**,
and deliberately so: fail2ban decides *when to punish* with a cheap, reversible, invisible
10-minute ban; FireWatch decides *when to demand human attention* — expensive and
non-reversible. A user migrating from fail2ban will find FireWatch less trigger-happy than
what they ran, and that is correct for a triage product; the two are complementary (fail2ban
interdicts on the host, FireWatch sees, scores, and narrates the campaign — including, later,
fail2ban's own log as a source). Where we mirror fail2ban exactly is the *shape*: episode
counting over a findtime-like window, recidivism as a second-order detector, identity
allowlisting as the FP remedy, and a one-week recidivism memory.

## The distribution this design produces (M1 Solo, mechanical)

Derived from the ADR-0068 ambient-night manifest (128 actors / 369 events; largest ambient
persona 1-4 alerts/night) plus the ADR-0069 audit of normalizer output:

| Population | R1 | R2 | Queue effect |
|---|---|---|---|
| ~128 ambient Suricata/reputation actors, 1-4 alerts each | 0 fire (max 4 attempts ≪ 10) | 0 | none — observed/record, as before |
| Ambient sshd scanners (hundreds of IPs/night, low per-IP counts) | fires only for IPs with ≥10 attempts in-window | first night: queue **once** per genuinely recidivist/breadth-growing IP; then the D6 decision loop holds it out | bounded by #50's tripwire (≤10); the honest unknown is how many ambient IPs cross R2 on a real night — that is precisely what the Pi/sshd calibration measures, and the D5 falsifier catches |
| Determined single-burst brute force (e.g. 120 attempts / 40 min, never returns) | fires (both arms) | no (one episode, no breadth) | **record + pressure strip + band contribution, not queue** — deliberate: no success (else `brute_force_then_login`, critical), no recurrence, no exploration; commodity spray. If calibration shows real attacks presenting as single episodes, R2's bar is the falsified constant |
| Recidivist brute force (returns after a quiet gap, or scans ports/categories while pressing) | fires | fires → Tier 2 | 1 queue entry with a RULE-tagged campaign justification |
| Headline aggregate (R5) | — | — | "N hostile attempts from M actors — 0 succeeded · K need review" from engine integers (attempts = D1 predicate; succeeded = Tier-1 actors; K = queue size) |

## Module shape (sketch — for the implementers)

- `firewatch_core/attempts.py` — **new, pure.** The D1 predicate (`is_attempt(event)`),
  episode segmentation (`episodes(events, gap) -> list[Episode]`), and attempt tallies. Shared
  by R1, R2, and the R5 feed aggregation (one home for the predicate — the banner may never
  count differently than the detector).
- `firewatch_core/detector.py` — R1 + R2 registered alongside the existing rules
  (`ESCALATION_POLICY.register(...)` before `finalize()`); `_sustained_attack` retired (D2).
  Rules import from `attempts.py`; file stays ≤ ~500 lines or splits into `detector/` then.
- `firewatch_core/pipeline.py` — the window slice (D4): one fetch, `W_state` view for
  `run_rules`/`decide`/breakdown, `W_campaign` view for `detect`; lifetime facts from the full
  list. Named constants live beside the fetch, mirrored in #50's manifest.
- `escalation/` — **unchanged.** R2 rides D1(a) through `qualify.py` as built.
- API: additive aggregate fields on the banner feed (attempts/actors/succeeded/need-review +
  top-N pressure records); frontend: `TriageBanner.tsx` headline + bounded pressure strip
  (no inner scrollbar), `escalationCopy.ts` for the new vocabulary.

## Alternatives considered

- **A volume term inside `run_rules`** — rejected. Moves `expected_scores.json` (a real
  re-bless with new-value proofs), duplicates windowing logic outside the detector, and
  conflates the band axis's "how bad" with the queue's "is a question pending" — the exact
  two-jobs error ADR-0067 unwound.
- **Pressure auto-escalates (R1 `auto_escalate=True`)** — rejected. Single-window pressure is
  ambient on exposed boxes; queueing it re-creates the flood with better justification text.
  The queue bar is recidivism/breadth (R2), where the actor has demonstrated intent over time.
- **A persisted episode/campaign ledger** — deferred (D3). ADR-0041's recompute-at-read-time
  precedent holds; the event store is the state; a ledger is an optimization to adopt only on
  measured fetch cost, never a second source of truth.
- **A new SDK `attempt`/`hostile` field set by normalizers** — rejected. Re-invents the action
  + severity axes per-source, violates "no per-source detection," and every existing event
  already carries the inputs.
- **Leaky-bucket accumulator (CrowdSec-style capacity + drain rate) as R1's internals** —
  **open, not adopted.** It would unify D2's two arms (density + endurance) in two constants
  and is the strongest candidate refinement — but it has not been researched in-session, and
  this ADR does not cite from memory. The observable contract (D2's two arms) is
  accumulator-agnostic; if the calibration pass shows the two-arm shape mis-discriminating
  bursty vs slow-drip actors, a CrowdSec research pass precedes the refinement ADR/issue.
  Nothing in M1 blocks on it.
- **A global sensitivity knob ("paranoia level")** — rejected for M1 (D6). It reopens
  "misconfigured into missing a breach"; CRS-style paranoia levels are a rule-*set* selection
  concept, not a queue-entry tuner. Demand-gated per-rule overrides already exist as #31 (M5).
- **Fixing only `run_rules`' lifetime-count bug without the attempt generalization** —
  insufficient alone (it was the *asked* question; the real problem is wider): windowing
  blocked-only counters still scores a passive box at 0.

## Reasoning

The organizing insight is that the volume rules' `action in ("BLOCK", "DROP")` filter was a
proxy that silently narrowed "hostile attempt" to "hostile attempt our WAF denied." On passive
sources the proxy evaluates to the empty set, and every volume defense evaporates — while the
presence rules (fire-once) and the compromise rule (fires-on-success) were never designed to
carry persistence. Naming the attempt predicate restores the rules' original intent on every
source, agentlessly, with fields the contract already guarantees. The pressure/campaign split
then maps cleanly onto machinery this codebase already has: R1 is `_sustained_attack`
generalized (same registry, same capped boost seam), R2 is fail2ban's `recidive` shape expressed
as a pure rule over the same per-IP list, and queue entry flows through the assertion gate
built in #42 rather than any new door. The windows make the whole thing honest in time — the
one dimension the original model ignored — and the volume oracle makes every number in this
design a testable claim instead of a hope.

## Consequences

- **Implementing issues** (drafted with this ADR, filed on acceptance; all M1 unless noted):
  1. Core: trailing analysis windows (`W_state`/`W_campaign`) — the defect-2 fix; prerequisite.
  2. Core: `attempts.py` + R1 `attempt_pressure` (retires `_sustained_attack`).
  3. Core: R2 `campaign` (episodes, recidivism/breadth, Tier-2 via D1(a)).
  4. API+Frontend: attempts headline + pressure strip (extends #43's aggregate line).
  5. Amend #47 (server-side decisions): two-verb model (Expected = actor / False positive =
     detection-on-actor) and pull from M3 → M1.
  6. New (M1): minimal re-entry slice — a decided actor re-enters when a tier appears
     (carved from #49; full novelty model stays M5).
- **#50 (volume oracle)** gains the brute-force/recidivist personas and the R1/R2 membership
  invariants; its manifest is the constants' ledger of record (D5).
- **ADR-0067** status line gains the D5(1) correction pointer (D7) on acceptance.
- **ADR-0069 (draft)** D4(b) falsifier text amended per D8 (edit in the same review batch).
- **ADR-0058's** rule registry and `detection_boost` cap are consumed, not modified;
  `_sustained_attack`'s registry entry is replaced by `attempt_pressure` + `campaign`
  (escalation-policy route output changes accordingly — unit tests, not golden).
- `tests/golden/` untouched (D4); any golden drift in implementing PRs is a regression by
  definition.
- Docs: `docs/escalation-and-triage-model.md`, dashboard guide, FAQ gain the
  pressure/campaign vocabulary with issue 4; PLUGIN_CONTRACT.md is **unchanged** (no contract
  surface moved).

## References

- **fail2ban 1.1.0 `config/jail.conf`** —
  https://raw.githubusercontent.com/fail2ban/fail2ban/1.1.0/config/jail.conf — fetched this
  session; `bantime`/`findtime`/`maxretry` defaults, `[sshd]` inheritance, `[recidive]`
  parameters, `ignoreip`/`ignoreself` comments quoted verbatim in Context.
- **ECS `event.kind`** — https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-kind
  — verbatim quotes recorded in ADR-0067 RC4 (fetched live in that session; reused with
  attribution).
- **Sigma specification, `level`** —
  https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md
  — `informational` definition quoted verbatim in ADR-0069 (fetched live in that session).
- **MITRE ATT&CK T1110 Brute Force / TA0006 Credential Access** — https://attack.mitre.org/techniques/T1110/
  — the technique class of the flagship case (mapping already in-tree).
- **NIST SP 800-61r2** — Detection & Analysis: triage as the analysis-phase discipline; the
  attention-vs-interdiction split in D6/the fail2ban position.
- **Internal:** ADR-0067 (+ the D5(1) text corrected here), ADR-0069 (draft, coupled),
  ADR-0058 (+A1), ADR-0059, ADR-0068, ADR-0041, ADR-0036, ADR-0035, ADR-0033, ADR-0021/0065;
  `scoring.py`, `detector.py`, `pipeline.py:569/846`, `adapters/sqlite/events.py:107/117`,
  `escalation/qualify.py` (PR #51), `tests/golden/fixtures/expected_scores.json`.
