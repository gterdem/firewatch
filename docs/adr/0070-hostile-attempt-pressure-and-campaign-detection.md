# ADR-0070: Hostile-Attempt Intensity — Pressure, Attack-in-Progress, and Campaign Detection

**Date:** 2026-07-15 (Revision 1: 2026-07-16)
**Status:** Accepted (2026-07-16) — Revision 1 read and approved by the Maintainer (verbatim:
"I read the ADR changes and I approve them"), superseding the first draft wholesale. Coupled
with ADR-0069 (still Proposed): D8's fixed landing order stands — neither half ships alone.
Amendable on evidence; the D5 falsifiers and the ADR-0068 D3 live calibration pass are the
named mechanisms, and a live-testing finding is an amendment, not a reopening.

**Revision 1** replaces the first draft's queue-entry machinery — D2's two-arm
volume-in-window rule and D3's quiet-gap episode segmentation — with an **intensity (rate)
model**, on the Maintainer's direction. Everything else stands: D1 (the attempt predicate),
D5's constants discipline, D6, D7, D8, D9 — and D4's windows, reinterpreted. The withdrawn
Amendment 1's findings are preserved in Context (they are part of why the first draft fell).
The first draft's text is superseded wholesale by this revision; this ADR was never accepted,
so the supersede-never-edit house rule does not bind (it protects accepted decisions).

**Corrects:** ADR-0067 **D5(1)** (the band-axis safety-net claim — mechanically false as
written; §D7 below). On acceptance, ADR-0067's status line gains "D5(1)'s band-accumulation
claim corrected by ADR-0070" (status-line update only; the text is never edited).
**Couples with:** ADR-0069 (canonical severity semantics — its D4(b) severity downshift removes
the *accidental* per-event queue path for auth failures; this ADR adds the *deliberate*
aggregate one. Either alone leaves a hole; §D8 fixes the landing order).
**Couples with:** ADR-0059 Amendment 1 (notification defaults for the states this ADR creates —
Maintainer decision, same date; implementing issue #74 — with the A1.1 stock-vs-flow correction,
2026-07-16 ruling, same batch).
**Couples with:** ADR-0071 (draft, same batch — the auth-outcome contract vocabulary; owns
generalizing the two category-coupled rules behind the CRITICAL path named in D3/D9 and retiring
PR #73's interim selector union).
**Relates to / honours:** ADR-0058 (+A1 — D1 severity registry, D5a disposition weighting, the
capped `detection_boost` seam all reused, not changed), ADR-0067 (assertion gate — queue entry
flows through D1(a), machinery already built), ADR-0059 (Triage threshold stays the one tunable
band-visibility knob), ADR-0068 (the volume oracle is the adjudicator of every constant here),
ADR-0041 (recompute-at-read-time — the precedent for deriving intensity instead of persisting
it), ADR-0036 (band ⊥ escalation), ADR-0035 (RULE provenance — reasons carry engine integers,
never raw statistics), ADR-0033 ("Harden" stays advice via the action seam; enforcement verbs
arrive with SOAR, M4), ADR-0021/0065 (agentless, local-first — FireWatch observes and triages;
it does not interdict).
**Skill gate:** anyone touching `detector.py`, `scoring.py`, or `escalation/` loads
`ai-engine-invariants` first.

---

## Context

### The defect, verified (file:line, original session)

**Nothing in FireWatch scores the persistence of unblocked hostile attempts.** The scoring and
correlation model was built against Azure WAF, where "the control fired" (BLOCK) was a reliable
proxy for "a hostile attempt happened." The M1 Solo bundle (Suricata IDS, syslog/linux_auth,
detect-only ClamAV) is entirely passive — nothing blocks, so nothing counts:

- **Presence rules fire once.** `run_rules` (`scoring.py:96`) adds `_SQLI_BASE=40` ×
  disposition weight when `sqli_events` is non-empty — one probe scores the same as 10,000.
  Same for XSS (35).
- **Every volume rule filters on BLOCK/DROP first.** `brute_force` (≥10 blocked, +30,
  `scoring.py:102`), the persistence floor (≥3 blocked, +10, `scoring.py:128`), and
  `_sustained_attack` (≥10 blocked spanning ≥30 min, `detector.py:245`) all count only what a
  control denied.
- **`_brute_force_then_login` fires only on compromise** (≥3 brute-force events *plus* a
  successful login, `detector.py:193`).
- **`port_scan` is action-agnostic but breadth-only** (≥5 distinct ports, +25) — and 25 alone
  is LOW band; it never reaches any threshold by itself.

Consequence, mechanically: **a pure SSH brute force — hundreds of ALERT-action `Failed
password` events, no success — produces `rule_score = 0` and zero detections, at any volume.**
The Maintainer escalated exactly this as first-order.

**Defect 2 — no time denominator.** Fixed by issue #52 (merged): `analyze_ip` /
`analyze_ip_detailed` now slice each actor's events to trailing windows (`W_STATE` = 24 h for
score/tier, `W_CAMPAIGN` = 7 d for `detect()`) at the fetch/slice seam (`pipeline.py:152-153`,
verified post-merge). Lifetime facts (`first_seen`, `last_seen`, `total_events`) keep their
presentation meaning. The windows' *interpretation* is revised in §D4 below; the code stands.

**Defect 3 — distributed attacks are architecturally invisible.** `detect()` and the whole
analysis path are per-IP. Single-source volumetrics are fixable in this shape; distributed
(many-actor) campaigns are not. Recorded as a scope boundary (§D9), not solved here.

### Why Revision 1 replaced the first draft (the record — do not re-derive these)

The first draft answered defect 1 with **volume-in-window counting** (two arms: ≥10 attempts
dense-in-30-min, or ≥10 spanning ≥30 min) and a **quiet-gap episode model** for queue entry
(≥2 episodes separated by ≥60 min of silence, or episode + breadth). Four findings killed it:

1. **The Maintainer's override (the decisive one).** The first draft's D3 ruled that a
   single-burst brute force that never returns does not queue ("commodity spray"). The
   Maintainer, from user experience: an IP attempting SSH brute force **50 times per minute**
   must be raised **immediately** — "why would anyone wait to get hacked willingly while they
   can see it's happening." The first draft's own D5 falsifier ("if real attacks present as
   single episodes, R2's bar is the falsified constant") fired — supplied by the Maintainer
   before the calibration pass could. The reversal is deliberate and recorded: **a
   high-intensity attack queues while it is happening**, not after it demonstrates recidivism.
2. **Intensity non-monotonicity in the episode model** (the withdrawn Amendment 1's A1.1
   finding, preserved here). An episode was a maximal run with internal gaps < 60 min — so a
   *continuous* attack stream was **one episode at any volume and duration**: a 7-day,
   100,000-attempt hammer never satisfied "≥2 episodes" and never queued. An actor strictly
   *more* aggressive than a recidivist was strictly *less* likely to queue. A1.1 patched this
   with an episode span cap (`E_max = 24 h`); Revision 1 retires the patch with the proxy —
   under a rate measure, more events per unit time always means higher measured intensity.
3. **The two arms were one predicate wearing two names** (observed by the coordinating
   session; verified in this revision by case analysis). At a shared threshold `N_p`, any set
   of ≥10 attempts either has span < 30 min (density arm) or span ≥ 30 min (endurance arm) —
   the arms were exhaustive, so D2 reduced to "≥10 attempts in `W_STATE`", i.e. a **10-per-day
   average-rate threshold**. Volume-in-window was a crude rate proxy all along; its edge
   pathologies (finding 2, and pacing evasion) were artifacts of the proxy, not of the
   problem. (The arms *would* differ with distinct thresholds per arm; none were ever
   specified. Named here so the structure is not re-derived.)
4. **The plateau theorem** (derived by the product-strategist; verified by derivation in the
   revising session). Any score that adds δ per event and decays exponentially has, at pacing
   interval Δ, the finite steady state S\* = δ/(1 − e^(−βΔ)) — so for every threshold there is
   a pacing rate that never crosses it. **No-permanent-branding and rate-independence are
   incompatible in a single decaying number.** The Maintainer's model chooses rate-dependence,
   which makes the sub-threshold paced actor a *designed* INFORM outcome (§D9), not a
   discovered hole.

### Standards and prior art

**fail2ban 1.1.0** (fetched in the original session from
https://raw.githubusercontent.com/fail2ban/fail2ban/1.1.0/config/jail.conf): defaults verbatim
`bantime = 10m` · `findtime = 10m` · `maxretry = 5` — *"A host is banned if it has generated
\"maxretry\" during the last \"findtime\" seconds."* The `recidive` jail (`bantime = 1w`,
`findtime = 1d`) is a detector over detector output. fail2ban's false-positive remedy is an
**identity allowlist, not a threshold** (`ignoreip` / `ignoreself`, quoted in D6). These
inform θ_press (≈ the mass of a `maxretry` burst), the 7-day campaign memory, and D6's
suppression design. fail2ban's *ban cycle* is also why its recidive jail never had finding 2:
banning forcibly segments a continuous offense; our gap segmentation had no analogue.

**ECS `event.kind`** — the ALERT/LOG line the attempt predicate rides on, verified live and
quoted verbatim in ADR-0067 RC4 (`alert` = "an alert or notable event, triggered by a detection
rule executing externally"; https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-kind).

**Sigma `level`, `informational`** — quoted verbatim in ADR-0069: *"No case or alerting should
be triggered by such rules because it is expected that a huge amount of events will match
these rules."* — the basis for excluding `info`-severity ALERTs from the attempt count (§D1).

**MITRE ATT&CK T1110 (Brute Force), TA0006** — the technique class of the flagship case
(already the syslog category's mapping, `firewatch_syslog/normalize.py:80`).

**Exponential-kernel intensity (the estimator's provenance, with honest attribution).** The
kernel shape is the deterministic evaluation half of a Hawkes self-exciting process (Hawkes
1971, Biometrika 58(1):83-90); the O(1)-per-event evaluation is the Ogata (1981) recursion
w(q) = e^(−βΔt)(1 + w(q−1)). Both papers were fetched and verified in the coordinating
research session (2026-07-15); the two identities used here (the sum's fold form and the
plateau closed form) were **re-verified by direct derivation in the revising session** — they
are elementary algebra and do not rest on the citations. This ADR deliberately does **not**
adopt the Hawkes *process model* (no background rate μ, no branching ratio, no parameter
fitting) — see D2 and Alternatives. The exponential kernel's decisive property over
linear-drain accumulators (CUSUM-style): its half-life is fixed at ln(2)/β **regardless of
burst size**, where a constant-rate drain takes time proportional to the peak to quiesce
(measured at over six days in Beaumont-Gay 2007 — research-session finding, attributed).

## Decision

### D1 — The attempt predicate (unchanged in Revision 1)

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

### D2 — The intensity estimator, and R1 `attempt_pressure` (revised)

**The measure.** For an actor with attempt timestamps t₁ ≤ … ≤ tₙ (D1 predicate), the
**attempt intensity** at time t is the exponentially-decayed attempt count

> λ̂(t) = Σᵢ e^(−β(t−tᵢ))  for tᵢ ≤ t,  with half-life H = ln(2)/β  (provisional H = 30 min).

Read it as "how many attempts' worth of pressure is on this actor *right now*": one attempt
contributes 1 immediately, ½ after 30 min, ¼ after an hour. Properties, each load-bearing:

- **Monotone in aggression by construction.** Adding events never lowers λ̂ anywhere. More
  attempts per unit time ⇒ higher intensity, always — finding 2 cannot recur inside a clause.
- **Graded fade for free.** When the actor stops, λ̂ halves every H — the Maintainer's
  "fade/decrease slowly" is the kernel, not bolted-on bookkeeping. Fade acts on the **state
  axis** (which detections derive), never on the 0-100 band score (§D4).
- **Pure, deterministic, cheap.** One fold over the fetched event list
  (w(q) = e^(−βΔt)(1 + w(q−1)), O(1) per event), recomputed at read time from the event store —
  the ADR-0041 pattern. Nothing persisted; the event store is the state. Down-crossings of any
  threshold between events are closed-form (t = tᵢ + ln(λᵢ/θ)/β), so episode segmentation
  (D3) is exact, not sampled.
- **Explainable.** λ̂ is an internal quantity. Every reason string carries **engine integers
  only** (ADR-0035): "312 hostile attempts in the last 30 min", "2 pressure episodes within
  7 days" — never a raw λ value.
- **Evaluated at the pipeline's anchored `now`** (the #52 seam). Freshness is bounded by
  collection cadence — see the latency note in §D5.

This is **not a fitted Hawkes process**: no background rate μ, no excitation parameters, no
estimation. We use the kernel as a deterministic rate estimator with declared constants,
because FireWatch's detection layer must be explainable and calibratable by the volume oracle,
not statistically inferred (D9: detection stays fully deterministic).

**R1 `attempt_pressure` — the INFORM weight.** A detector rule (registered in the ADR-0058 D1
registry, template `_sustained_attack`): fires iff the actor's **peak λ̂ within the trailing
`W_STATE` reaches θ_press** (provisional **θ_press = 5** — the decayed mass of a fail2ban
`maxretry` burst). Declaration: `severity="medium"`, `auto_escalate=False`, `score_delta=15`.
**Pressure alone does not queue** — fail2ban's existence proves single IPs trip 5-in-10-min
continuously on exposed boxes; pressure contributes band score and the pressure-strip
visibility, and its episodes feed D3.

**R1 retires `_sustained_attack` — near-subsumption, honestly stated.** Every *dense* set that
fired `_sustained_attack` (≥10 BLOCK/DROP spanning ≥30 min, concentrated enough to hold
decayed mass ≥5) fires R1 with the same +15. The population that does **not** carry over:
≥10 blocked events spread so thin that λ̂ never reaches 5 (roughly, sustained under ~7
attempts/hour) — it loses a +15 band contribution that never queued anything and is
per-IP-indistinguishable from ambient slow retry loops. Stated, deliberate; the D5 falsifiers
adjudicate. `tests/golden/` pins no `sustained_attack` values (verified in the original
session — `expected_scores.json` has `detection_rule_names: []` throughout; re-verified in the
revising session, sha `fe4787…3f31f`).

### D3 — Queue entry: R2 `attack_in_progress` and R3 `campaign` (revised)

The operator vocabulary (Maintainer's model) and its mechanical mapping:

| State | Meaning | Mechanism |
|---|---|---|
| **CRITICAL** | Success observed — probable compromise | **`brute_force_then_login`** (registered `severity="critical"` + `auto_escalate=True` — the registry's only critical rule, `detector.py:63-67`) → **Tier 2** through the same untouched D1(a) gate; an actor whose window *also* contains an ALLOW event reaches Tier 1 independently (the gate is per-actor, not per-rule). See the tier-attribution correction below this table. **Reachability caveat (2026-07-16 ruling; citations corrected to merged main `a935f33`, ADR-0071 Rev 1 batch):** the rule selects through a hand-maintained union of the known plugins' category spellings (`_SSH_BRUTE_FORCE_CATEGORIES` / `_SSH_LOGIN_SUCCESS_CATEGORIES`, `detector.py:140-141`, applied at :189,:193 — PR #73's merged interim patch), so a contract-conformant source whose auth events carry spellings outside that in-core frozenset never reaches it without a core edit — linux_auth (categories `"SSH Login Failure"` / `"SSH Login Success"`) proved this mechanically before its spellings were unioned in. Interim: the merged union (in-code INTERIM marker, `detector.py:129-139`); owner of the real fix: **ADR-0071** |
| **HIGH ALERT** | Attack in progress, or demonstrated intent over time | **Tier 2** via R2 or R3 below, through the untouched ADR-0067 D1(a) gate |
| **INFORM** | Hostile activity below the queue bar | Observed stratum + pressure strip + R1's band weight — visible on look; never notified **via the tier axis**, and via the band axis only at the operator's `alert_threshold` (default CRITICAL — for observed actors reachable only by payload-bearing populations; the non-payload ceiling is band 35 today, ~55 post-#53). ADR-0059 A1.2 as corrected 2026-07-16 — an earlier draft of this row said "never notified by default," the claim that correction retires |

**Tier attribution, corrected (2026-07-16 — verified against `decide()`; census corrected
same day, see the provenance note at the end of this block).** An earlier draft of this table
bound CRITICAL to "Tier 1". That conflated the rule's *severity label* with the *escalation
tier*. The actual mechanics, stated precisely because two readers misstated them in opposite
directions on the same day:

- **The tier is decided per-actor over the whole window partition, never per-rule.** Tier 1 is
  "any ALLOW event where any detection fired" (`decider.py:147,188`) — evaluated against the
  actor's full event list, not against the events a rule matched.
- **`brute_force_then_login` itself never produces Tier 1.** Its inputs are ALERT + LOG
  events; on a pure host-auth actor the verdict is **Tier 2** via the D1(a) gate — and always
  was, including for syslog before linux_auth existed. Its loudness is its *registration*
  (`severity="critical"`, `auto_escalate=True`), not a tier number.
- **ALLOW census (three emitters, not two — corrected):** azure_waf
  (`_ACTION_MAP:66-67`), aws_nfw (`"pass" → ALLOW`, `normalize.py:103`), and **syslog_cef's
  generic CEF path** (`registry.py:55-62` maps `allow/allowed/permit/permitted/pass/passed/`
  `accept/accepted` → ALLOW via `resolve_action` — firewall-style CEF is exactly what a CEF
  receiver ingests). syslog_cef's **SSH categories still never carry ALLOW** — that path
  hard-codes `ALERT`/`LOG` (`normalize.py:249,260`) and never consults the registry. syslog
  and linux_auth emit no ALLOW anywhere (hosts authenticate; they do not pass traffic).
- **Consequence of the per-actor gate:** a mixed-telemetry actor can reach Tier 1 through an
  *unrelated* ALLOW — e.g. one CEF receiver seeing both a firewall (`act=permitted` → ALLOW)
  and an SSH box (brute-force categories) from the same IP: the partition holds `allow_events`
  and a detection ⇒ **Tier 1** (`block_status="partial"`). Arguably correct behavior — it got
  through the firewall and then authenticated — but it means the same rule yields Tier 1 or
  Tier 2 depending on *what else the actor did*, not on the rule or the plugin.

Worked partition examples (each traced through `decide()` this session), because prose alone
has now failed twice:

| Actor's window partition | Detections | Verdict | Operator state |
|---|---|---|---|
| 3× ALERT (auth failures) + 1× LOG (auth success) — pure SSH box | `brute_force_then_login` (critical, auto-esc) | **Tier 2**, `block_status_unknown` | **CRITICAL** (via the severity arm) |
| Same + 1× ALLOW (unrelated CEF firewall `act=permitted`, same IP) | same | **Tier 1**, `allowed_through`, `block_status="partial"` | **CRITICAL** (via the tier arm) |
| ALLOW + any detection (traffic source) | e.g. `multi_source_attack` (medium) | **Tier 1**, `allowed_through` | **CRITICAL** — decide()'s existing "got through" semantics |
| ALERT mass, λ̂ ≥ θ_high | R2 `attack_in_progress` (high, auto-esc) | **Tier 2** | **HIGH ALERT** |
| 5× ALERT `low`, nothing qualifying | none | `tier=None`, `observed` | **INFORM** |

Binding consequences:

- **The operator vocabulary binds to (tier, qualifying-detection severity) — never to the tier
  number alone — because tier alone is unreliable in *both* directions.** It *under-reports*:
  the CRITICAL rule is Tier 2 on a pure SSH box, so `CRITICAL := tier == 1` makes CRITICAL
  structurally unreachable for the endpoint class. It *over-attributes*: the same rule rides a
  Tier-1 verdict when the actor happens to carry an unrelated ALLOW, so tier does not identify
  *which* claim fired. The binding
  **CRITICAL := `tier == 1` OR (`tier == 2` AND top qualifying detection severity ==
  `critical`)** handles both; HIGH ALERT := every other Tier-2 entry (R2/R3 declare `high`).
  If #55 binds CRITICAL to the tier number, the same word silently means different things on a
  WAF and on an SSH box — the exact failure this table exists to prevent. The severity is
  derivable from the persisted `ThreatScore.detections` (the ADR-0059 D6 read path); plumbing
  is #55's.
- **Nobody "fixes" host sources by fabricating ALLOW.** A host auth success is `LOG` by
  ADR-0012 Flag A and stays so; the never-fabricate rule (PLUGIN_CONTRACT) applies to actions
  as much as to transport fields.
- The Tier-2 justification string for this rule is the generic qualified-Tier-2 sentence; the
  CRITICAL state copy rides the banner state vocabulary (#55), not the justification.
- Audit result, for the record: the other rows of this table were re-verified (HIGH ALERT =
  Tier 2 via D1(a) — correct as written; INFORM = observed stratum — correct), and a repo-wide
  scan found the Tier-1 conflation only in this ADR's two corrected lines — no other ADR, doc,
  or frontend copy asserts it.
- Provenance, kept deliberately: the tier error entered via a relayed premise and was caught
  by PR #73's implementer refusing to pin an asserted tier (ran `decide()` on real linux_auth
  shapes); the first correction then overstated the ALLOW census from a filtered grep whose
  file list silently excluded `registry.py` (the filter required the string `SecurityEvent`;
  a control grep refuted it same day). Two misreadings of one mechanism in one day is a
  legibility fact about the mechanism — hence the worked examples above.

Presentation guidance (binding on copy, exact words are the frontend issue's): the HIGH ALERT
copy says **"active attack in progress"** — not "you are being hacked", which implies the
attacker is *succeeding*; by D1 these are attempts. The CRITICAL copy says **"probable
compromise"** — a success-shaped login after brute force is strong evidence, not a confirmed
breach. Honest-state discipline (ADR-0066 precedent).

**R2 `attack_in_progress` — the Maintainer's 50/min case.** Fires iff **λ̂(now) ≥ θ_high**
(provisional **θ_high = 40**). Declaration: `severity="high"`, `auto_escalate=True`,
`score_delta=25`. Mechanics of the flagship cases:

- 50 attempts/min: λ̂ ≈ 49 after the first minute (decay over 60 s is negligible) — **queued
  in under a minute**, while the attack is happening.
- Sustained r attempts/min: steady state λ̂\* = r·H/ln 2 ≈ 43.3·r (at H = 30 min) — θ_high = 40
  is reachable only by sustained ≥ ~55 attempts/hour, or a burst of ≥ ~40 attempts inside a
  few minutes. An ambient 20-attempt burst peaks ≈ 20 and never queues.
- **Fade:** attack stops → λ̂ halves every 30 min → R2 stops deriving within ~H·log₂(peak/40)
  of cessation → the actor leaves the queue on the state axis. No manual expiry, no cliff.

**R3 `campaign` — intent demonstrated over time.** Define a **pressure episode** as a maximal
interval during which λ̂(t) ≥ θ_press (an intensity excursion; boundaries are the closed-form
crossings). Within the `W_CAMPAIGN` horizon, R3 fires iff any of:

- **Recidivism:** ≥ 2 pressure episodes — the actor's intensity rose, collapsed to quiet, and
  rose again. fail2ban's `recidive` insight, expressed on the rate measure.
- **Endurance:** any single episode with span ≥ `D_endure` (provisional **24 h**) — the
  moderate-rate grinder that never spikes to θ_high but never stops (the population finding 2
  was about, caught without a segmentation patch).
- **Breadth:** ≥ 1 episode **and** horizon attempts span ≥ 2 attack categories or ≥ 5 distinct
  destination ports — pressure that is also exploring is not commodity spray.

Declaration: `severity="high"`, `auto_escalate=True`, `score_delta=20` (below R2's 25, so when
both fire the decider's `_top_rule_name` headline names the *current* attack — the more urgent
claim — over the historical pattern).

**The clause-seam boundary, stated (search for what refutes you).** Adding events can merge
two episodes into one (fill the quiet dip), converting a recidivism-qualifying actor into a
single-episode actor. This is the inherent boundary of any {return-pattern OR duration}
disjunction — the withdrawn A1.1 model had the same seam — and it is **bounded, not a
calm-path**: to exploit it an actor must hold λ̂ ≥ θ_press continuously (it may never let the
dip form), which (a) fires endurance at `D_endure`, (b) accrues R1 pressure + band score the
whole time, (c) queues immediately if it ever reaches θ_high. The limit property, which is the
real charter requirement: **any actor sustaining pressure-level intensity queues within
`D_endure`; any actor reaching θ_high queues immediately; no addition of events can move an
actor to calm.** A single decayed number cannot replace the clauses — a one-off 25-attempt
burst outscores a nightly-10 recidivist's asymptote on *any* single slow-decay sum (derived in
the revising session), so "came back" is not expressible as a threshold on one number. Anyone
proposing to collapse the three clauses re-derives finding 2 or this paragraph first.

**Queue entry and derivation.** R2/R3 enter Tier 2 through `escalation/qualify.py` D1(a) as
built (merged in #42/PR #51) — no new escalation machinery. Both are derived at analyze time
from the event list (ADR-0041); nothing persisted. A campaign auto-expires when its episodes
age past `W_CAMPAIGN`; an attack-in-progress expires by decay. Notification: R2/R3 actors
notify by default when a webhook is configured — ADR-0059 Amendment 1 / issue #74.

### D4 — Windows reinterpreted; the band scale does not decay

The #52 windows stand as merged (`pipeline.py:152-153`):

| Window | Value | Feeds | Revision-1 meaning |
|---|---|---|---|
| `W_STATE` | 24 h | `run_rules`, `build_score_breakdown`, `decide()` | Unchanged — the band axis reflects the trailing day. **Golden-load-bearing; untouched.** |
| `W_CAMPAIGN` | 7 d | `detect()` | The **episode-counting memory and fetch horizon**. λ̂ itself needs no horizon (an event 7 days old contributes e^(−β·7d) ≈ 0 at H = 30 min); the horizon exists so recidivism has bounded, declared memory — deliberately fail2ban's `recidive` week. |

**The 0-100 band score does not decay.** Fade lives on the state axis (R2/R3 stop deriving as
λ̂ falls), never on the number: a decay factor applied to a bounded score silently changes what
the maximum *means* (a forgetting factor caps the achievable maximum — Jøsang & Ismail 2002,
research-session finding, attributed), which would corrupt the band vocabulary
(LOW < 26 ≤ MEDIUM ≤ 50 < HIGH ≤ 75 < CRITICAL) and force a golden re-bless for a cosmetic
effect. The band already "forgets" via `W_STATE`. If a gliding displayed number is ever wanted,
it is a presentation-layer derivation, a separate decision.

**Golden oracle: untouched by this ADR.** All scoring changes land at the detector seam
(detections → capped `detection_boost` → tier axis); `run_rules`/`merge_score` are not
modified. Verified in the revising session: `expected_scores.json` sha
`fe4787643955c920e934e3789c79f741cd8c8cde6b2adbc6540b66ff3743f31f`, all records pin
`detection_rule_names: []`. Any golden drift in an implementing PR is a regression by
definition.

### D5 — The constants are provisional, and say so (nothing laundered)

| Constant | Provisional value | Anchor |
|---|---|---|
| `H` (half-life; β = ln 2/H) | 30 min | Maintainer's fade intuition ("stops after 60 minutes … fade slowly"): pressure halves twice within the hour after cessation |
| `θ_press` | 5 | ≈ decayed mass of a fail2ban `maxretry`-scale burst — the INFORM/pressure floor |
| `θ_high` | 40 | Crossed in <1 min at 50/min (the Maintainer's case); unreachable below ~55 attempts/h sustained; above observed ambient burst mass |
| `D_endure` | 24 h | The maximum queue deferral the clause seam allows (D3); matches `W_STATE` intuition |
| Episodes (recidivism) | ≥ 2 | fail2ban `recidive` shape |
| Breadth | ≥ 2 categories or ≥ 5 ports | Carried from first draft; matches `port_scan`'s breadth bar |
| `W_STATE` / `W_CAMPAIGN` | 24 h / 7 d | #52 as merged; `recidive` week |
| Deltas | R1 15 · R2 25 · R3 20 | Headline ordering (D3); all under the +30 `detection_boost` cap |

They are **engineering estimates, not calibrated values** — declared in one named-constants
block, mirrored into the volume-oracle manifest (#50) as the adjudicating fixture (ADR-0068 D2
manifest discipline), and calibrated by the standing ADR-0068 D3 live pass (Pi Suricata night +
internet-exposed sshd capture). Falsifiable in both directions:

- *Too loose:* a real ambient night in which more than the flood tripwire (10, ADR-0068 D2-2)
  of actors reach R2 or R3 → raise θ_high / θ_press. (Post-#74, the *eligible-to-notify set*
  equals the queue population, and #74's transition semantics bound firing to state changes —
  so the tripwire adjudicates both. Stated set-wise on purpose: see the A1.1 stock-vs-flow
  correction in ADR-0059.)
- *Too tight:* a planted or real attack at the Maintainer's rates that fails to queue within
  its first minutes → lower θ_high or lengthen H.
- The breach-among-noise invariant (ADR-0068 D2-3) remains the anti-suppression backstop.

**Latency, named as a requirement.** "Raised immediately" is an end-to-end property: at high
rates the *statistic* needs seconds (evidence accrues at the attack's own rate), so the binding
term is **collection cadence + analysis trigger**, per collection mode. The implementing issues
carry the budget "θ_high crossing is visible within one collection cycle of the crossing";
local tail readers are near-real-time, remote pulls are their poll interval. Push notification
of the crossing is #74's path.

### D6 — Configurability: decisions, not thresholds (unchanged in Revision 1)

- **Detection floor (H, θ_press, θ_high, D_endure, breadth): NOT operator-tunable.**
  Code-declared, volume-oracle-adjudicated (#50). Preserves the settled property that FireWatch
  *cannot be misconfigured into missing a breach* (ADR-0067's zero-tuning gate, extended).
  fail2ban must expose `maxretry` because its output is a *ban* that can lock a human out — and
  even fail2ban's FP remedy is the identity allowlist, not the number (verbatim: *"\"ignoreip\"
  can be a list of IP addresses, CIDR masks or DNS hosts. Fail2ban will not ban a host which
  matches an address in this list."*; *"\"ignoreself\" specifies whether the local resp. own IP
  addresses should be ignored (default is true)."*). FireWatch's output at this layer is
  *attention*, and the FP remedy is the same shape: identity, not threshold.
- **Visibility: tunable — and it already exists.** The ADR-0059 Triage threshold (default HIGH)
  is the one operator knob over band-axis queue entry. R1's score flows under it; no new knob.
  Notification defaults are ADR-0059 Amendment 1 (#74).
- **Suppression: per-object with memory and re-entry, never a global number** (extends #47):
  **"Expected — this is me"** marks the actor identity (the `ignoreip` precedent; re-enters on
  material change — the #49 novelty bar, minimal slice pulled forward); **"False positive"**
  marks the detection-on-actor (suppresses that detection's re-assertion; a different
  qualifying signal still queues). They age differently and feed different improvement loops.

### D7 — Correction to ADR-0067 D5(1): the band net did not exist (unchanged in Revision 1)

ADR-0067 D5(1) claims, verbatim: *"A persistent low-severity scanner accumulates score, crosses
the band threshold, and enters triage **on merit via the band axis**. This is the can't-miss
net that makes D3's fail-quiet safe."* **This is mechanically false as written** (author: this
ADR's author; the correction is owed). `run_rules` has no term that grows with unblocked event
count — the maximum a persistent unblocked scanner without signature payloads can reach is
`port_scan +25` + `multi_source +10` = 35, below the default HIGH Triage threshold at any
volume; a single-port SSH brute force reaches exactly 0. The band axis was not a weak net for
passive sources — it was *no net*, and D3's fail-quiet rested on it.

Disposition: **correction, not reversal.** ADR-0067 D3's fail-quiet ruling stands — but as of
this ADR it rests on R1/R2/R3: pressure accumulates band score, attacks-in-progress and
campaigns queue via D1(a). Form: a status-line addendum on ADR-0067 pointing here (house rule —
supersede/annotate, never edit). Distribution claims in ADRs now get the same file:line
verification as root-cause claims.

### D8 — Coupling with ADR-0069: one M1 slice, two halves, fixed landing order (rule names updated)

Today (post-#42, pre-0069), a real SSH brute force *does* queue — **by accident**: every
`Failed password` line is ALERT/`high` (`firewatch_syslog/normalize.py:80`), so one ambient
failed login = one Tier-2 actor via D1(b) — the flood channel ADR-0069 D4(b) closes by
downshifting the single line to `low`. But that downshift alone would make a determined,
unsuccessful brute force invisible to the queue (ALERT/`low` never qualifies; score 0 — this
ADR's defect 1). And the intensity rules alone would leave the per-event flood channel open.
**Neither ADR is safe to ship without the other.**

Landing order inside M1: **the intensity rules (#53/#54) land before or with the ADR-0069
severity recalibration of syslog/suricata** — the interim state then errs toward the existing
flood (known, bounded by #42's gate) rather than toward silent invisibility of an active
attack. The volume oracle (#50) asserts the end state of both together.

### D9 — Scope boundaries and designed exclusions (extended in Revision 1)

- **The sub-threshold paced actor is INFORM, by design** (the withdrawn A1.2, promoted from
  stipulation to consequence). An actor whose intensity never reaches θ_press — e.g. 2 probes
  per week for a year, or any pacing at the plateau S\* < θ_press — fires nothing at any
  lifetime volume: observed stratum, lifetime facts preserved, no tier, no queue, no
  tier-axis notification (the band axis at the operator's `alert_threshold` remains an
  observed actor's only notification path — ADR-0059 A1.2; for the non-payload profile
  described here it is unreachable at any volume). Per-IP this profile is
  indistinguishable from the dominant ambient population
  (the recurring low-rate probes reputation lists exist to catalog); queueing it re-creates the
  flood by construction, and it is **not fixable by constants** (lowering θ_press toward
  sparse rates admits the ambient mass wholesale — the plateau theorem guarantees some pacing
  always remains below any threshold). **Falsifier:** a real incident whose only per-IP signal
  was sub-θ_press attempts → the fix is a new discriminator (identity/intel enrichment, or the
  cross-actor stage below) — a design ADR, never a threshold move.
- **The slow continuous grinder is INFORM below the θ_press boundary** — a Revision-1
  population change: the withdrawn A1.1's `E_max` segmentation would eventually have queued
  any ≥10/day continuous actor; the intensity model does not. Two claims here, deliberately
  separated: **the boundary's *existence* is theorem-forced** (the plateau theorem — any
  decaying score admits a sub-threshold pacing, so *some* grinder rate is always INFORM), but
  **its *placement* — ~7 attempts/hour at the provisional H = 30 min / θ_press = 5 — is an
  engineering estimate, not a measured fact.** "That rate is inside ambient retry-loop
  territory" is the D5 hypothesis the ADR-0068 D3 calibration pass exists to test, not
  something this ADR knows. **Falsifier (deliberately distinct from the paced-actor bullet's
  above):** a real attack grinding just below the boundary while calibration shows ambient
  sitting well under it means the boundary is *misplaced* — the remedy is a constants move
  (θ_press / H, per D5), which is legitimate here; ambient measured *above* ~7/h means the
  boundary is too low — same remedy, other direction. Only the paced-at-plateau exclusion
  above is constants-immune and requires a new-discriminator ADR; do not conflate the two
  falsifiers.
- **Distributed / many-actor campaigns are out of scope** (defect 3). The per-actor pipeline
  cannot see them; a cross-actor aggregation stage is a future ADR with its own distribution
  analysis.
- **Detection stays fully deterministic.** The LLM narrates post-alert (ADR-0058); rules-only
  is a supported install (issue #4) — the AI is never the safety net. No fitted statistical
  models in the detection path (D2).
- **No interdiction.** R2/R3's output is a queue entry, a notification (#74), and advice
  ("Harden" via the ADR-0033 seam); enforcement verbs arrive with SOAR (M4, ADR-0015 /
  issues #20-21). Tier 1's unconditional bypass and the four-tier vocabulary stand.
- **Rules are core-owned and source-agnostic — with one honest caveat** *(citations corrected
  to merged main `a935f33`, ADR-0071 Rev 1 batch)*. The attempt predicate
  and R1/R2/R3 read only contract fields (`action`, `severity`, timestamps); no per-source
  detection logic anywhere in this ADR. But the two pre-existing coupled rules this ADR *leans
  on* are **not** source-agnostic today: `_brute_force_then_login` (the CRITICAL backstop)
  selects through a hand-maintained union of the known plugins' category spellings
  (`detector.py:140-141`, applied at :189,:193), and `_ids_then_brute_force` additionally
  hard-codes `source_type == "suricata"` on its corroboration leg (`detector.py:156`); its
  former auth-leg `source_type == "syslog"` filter was removed by PR #73's merged union. A
  plugin can satisfy the contract literally and still be invisible to the CRITICAL path until
  someone grows core's frozensets on its behalf. **ADR-0071** owns the generalization; the
  merged interim union carries reachability until it lands.

### Position vs fail2ban's defaults (updated numbers, same posture)

FireWatch's queue bar (θ_high = 40, or the campaign clauses) is **looser than fail2ban's
5-in-10-min**, deliberately: fail2ban decides *when to punish* with a cheap, reversible,
invisible 10-minute ban; FireWatch decides *when to demand human attention* — expensive and
non-reversible. fail2ban's 5-in-10 burst lands at FireWatch's θ_press (pressure: visible,
scored, not queued). Where we mirror fail2ban exactly is the shape: a findtime-like short
memory (H), recidivism as a second-order signal, identity allowlisting as the FP remedy, and a
one-week recidivism memory. The two are complementary (fail2ban interdicts on the host;
FireWatch sees, scores, and narrates — including, later, fail2ban's own log as a source).

## The distribution this design produces (M1 Solo, mechanical)

Derived from the ADR-0068 ambient-night manifest (128 actors / 369 events; largest ambient
persona 1-4 alerts/night), the ADR-0069 normalizer audit, and steady-state arithmetic
(λ̂\* ≈ 43.3·r at H = 30 min):

| Population | λ̂ behaviour | R1 | R2 | R3 | Outcome |
|---|---|---|---|---|---|
| ~128 ambient actors, 1-4 alerts/night | peak ≤ 4 < θ_press | — | — | — | observed/record, as before |
| Ambient sshd burst (5-in-10-min, leaves) | peak ≈ 5 | borderline — calibration adjudicates θ_press | — | — | at most band +15 + strip; **no queue** |
| Maintainer's INFORM case (2 attempts / 30 min, isolated) | peak ≈ 2 | — | — | — | record + strip (INFORM) |
| **Maintainer's 50/min brute force** | ≥ 40 in < 1 min | fires | **fires in < 1 min** | after pattern | **Tier 2 while in progress + default notification (#74); fades ~30-60 min after cessation** — REVERSED from first draft, by Maintainer decision |
| Single burst 120 / 40 min, never returns | peak ≈ 60-80 | fires | fires ~15 min in | — | queued **during** the attack; leaves queue by decay; record + strip persist |
| Nightly recidivist (10-attempt bursts) | 2 episodes by night 2 | fires | — | fires night 2 | Tier 2 with a campaign justification |
| Moderate grinder (12/h continuous) | λ̂\* ≈ 8.7; one episode > 24 h | fires | — | endurance at 24 h | Tier 2 within a day |
| Slow grinder (≤ ~7/h) or paced-at-plateau | below θ_press | — | — | — | INFORM forever — **designed exclusion, D9** |
| Success after brute force | **fades — the inversion:** attempts *stop* on success, so λ̂ decays | — | — | — | `brute_force_then_login` → the CRITICAL state (**Tier 2** on host-auth sources via its `critical`/auto-escalate registration — D3's tier-attribution correction; Tier 1 only where ALLOW exists) — **load-bearing, not a leftover.** On success the actor stops attempting, λ̂ decays, R2/R3 stop deriving: the intensity axis reads **calmer at the exact moment the situation got worse** (the fade-on-success inversion). The success rule is the only thing standing between "compromise" and "fades to calm" — which is why its reachability caveat (D3) and ADR-0071's generalization are part of this design, not an adjacent cleanup |

The honest unknown remains how many real ambient IPs cross θ_press/θ_high on a live night —
exactly what the ADR-0068 D3 calibration pass measures; the D5 falsifiers catch it in both
directions.

## Module shape (sketch — for the implementers)

- `firewatch_core/attempts.py` — **new, pure.** The D1 predicate (`is_attempt(event)`); the
  intensity fold (`intensity_at(events, t, half_life)`, `peak_intensity(events, window, now)`);
  episode segmentation over the closed-form θ_press crossings
  (`episodes(events, threshold, half_life) -> list[Episode]`). One home for predicate and
  math — the banner may never count differently than the detector.
- `firewatch_core/detector.py` — R1/R2/R3 registered alongside the existing rules
  (`ESCALATION_POLICY.register(...)` before `finalize()`); `_sustained_attack` retired (D2).
  `detect()` gains an explicit `now` parameter (pure; supplied from the pipeline's #52 anchor).
  File stays ≤ ~500 lines or splits into `detector/`.
- `firewatch_core/pipeline.py` — the #52 seam unchanged; passes `now` into `detect()`. Named
  constants live beside `W_STATE`/`W_CAMPAIGN`, mirrored into #50's manifest.
- `escalation/` — **unchanged.** R2/R3 ride D1(a) through `qualify.py` as built.
- API/frontend — additive aggregate fields on the banner feed; `TriageBanner.tsx` headline +
  bounded pressure strip (no inner scrollbar); `escalationCopy.ts` gains the
  INFORM / HIGH ALERT / CRITICAL vocabulary with D3's honest-copy guidance.

## Alternatives considered

- **Windowed two-arm counting + quiet-gap episodes (this ADR's first draft).** Replaced by
  Revision 1: the arms were exhaustive at a shared threshold (one predicate wearing two
  names), the episode model was non-monotone in intensity (a continuous hammer never queued),
  and the `E_max` amendment was a patch on the proxy rather than the problem. Preserved above
  as findings 1-4.
- **A fitted Hawkes process (μ, α, β estimated).** Rejected — unexplainable reasons (ADR-0035
  requires engine integers), unvalidatable parameters, and D9's determinism boundary. We take
  the kernel, not the model. (Omitting μ in a *fitted* model makes ambient clustering
  masquerade as self-excitation — research-session finding — a second reason not to fit one
  casually.)
- **A single slow-decay score as the whole queue bar (two-kernel collapse).** Rejected with a
  derivation: any single decayed sum ranks a one-off 25-attempt burst above a nightly-10
  recidivist's asymptote — "came back after quiet" is a pattern over the trajectory, not a
  level, so recidivism must remain a clause (D3).
- **CUSUM-style accumulator with constant-rate drain.** Rejected — drain is not proportional to
  level, so time-to-quiescence scales with peak (measured at 6+ days; research-session
  finding); violates the Maintainer's graded-fade requirement.
- **TRW/SPRT sequential test.** Rejected — verdicts are terminal/permanent (a permanent benign
  verdict is a farmable free pass; a permanent hostile one violates no-permanent-branding),
  and its own authors note window-based variants are evaded by increasing the scanning
  interval (research-session finding).
- **Leaky bucket (CrowdSec-style), the first draft's open refinement.** **Resolved by
  adoption-in-substance:** an exponential-decay counter *is* the leaky bucket with
  proportional (not constant) drain; the open alternative closes here rather than surviving as
  a research item.
- **A volume term inside `run_rules`.** Rejected (unchanged from first draft) — moves
  `expected_scores.json` (a real re-bless), duplicates windowing outside the detector, and
  conflates the band's "how bad" with the queue's "is a question pending".
- **A persisted intensity/episode ledger.** Rejected (ADR-0041): recompute at read; the event
  store is the state; a ledger is an optimization to adopt only on measured fetch cost.
- **A new SDK `attempt`/`hostile` field set by normalizers.** Rejected — re-invents the
  action+severity axes per-source; every event already carries the inputs.
- **A global sensitivity knob.** Rejected for M1 (D6) — reopens "misconfigured into missing a
  breach"; demand-gated per-rule overrides already exist as #31 (M5).

## Reasoning

The first draft correctly named the real predicate — BLOCK/DROP was a WAF-era proxy for "a
hostile attempt that did not succeed" — but then measured it with a second proxy:
events-counted-in-windows, whose edges produced every defect the amendment process found
(one-episode-forever, arms that collapse into each other, pacing plateaus discovered rather
than declared). The Maintainer's override names the quantity the design was circling:
**intensity**. Rate is what distinguishes "you should look at this eventually" from "this is
happening to you right now" — and an exponentially-decayed count is the smallest honest
implementation of it: monotone in aggression, graded in forgetting, O(1) to evaluate, derived
from the event store on demand exactly like every other FireWatch verdict. The three queue
clauses (now / endured / returned) are the three ways a human would say "this one is not
ambient," and each is a threshold on the same one measure, calibrated by the same oracle,
entering the queue through the same gate the codebase already trusts.

## Consequences

- **Implementing issues (all exist by number):**
  - **#53** (redrafted with this revision) — `attempts.py` + intensity estimator + R1
    `attempt_pressure`; retires `_sustained_attack`.
  - **#54** (rewritten with this revision; comes off HOLD on its rewrite) — R2
    `attack_in_progress` + R3 `campaign`; Tier-2 entry via D1(a).
  - **#74** (new) — ADR-0059 Amendment 1's notification default flip, **with transition
    semantics** (notify on tier-state *transitions*, never per re-evaluation — see the A1.1
    stock-vs-flow correction in ADR-0059).
  - **#50** — the volume-oracle manifest gains the intensity constants and the personas of the
    distribution table (ledger of record for all numbers, D5) — including the boundary-probing
    pair: the patient grinder (4/h × 14 d → INFORM expected) and the 25/h sprayer in both its
    continuous (R3 endurance) and stop-and-return (R3 recidivism) variants.
  - **ADR-0071 (draft, same batch)** — the auth-outcome contract vocabulary; owns generalizing
    the two category-coupled rules (D3/D9 caveats) and retiring PR #73's interim selector union.
  - Presentation — **#55** (the attempts headline + pressure strip; extends #43's aggregate
    line).
- **ADR-0067** status line gains the D5(1) correction pointer (D7) on acceptance.
- **ADR-0069 (draft)** D4(b) falsifier gains the ongoing-unsuccessful-attacker clause (D8);
  landing order binds as stated.
- **ADR-0059** gains Amendment 1 (notification defaults — same review batch as this revision).
- `tests/golden/` untouched (D4); any golden drift in implementing PRs is a regression.
- **PR #73 (off hold per the 2026-07-16 ruling; merged as `a935f33` with both obligations
  landed)** — two interim obligations, both with named retirements:
  - **(a) `_ssh_login_failure_intense` threshold moves ≥30 → ≥45 failures in 10 min.**
    Derivation: at H = 30 min, N failures spread uniformly over T = 10 min carry decayed mass
    N · (1 − e^(−βT))/(βT) = N × 0.893 (βT = ln 2/3). The PR's ≥30 gives λ̂ ≈ 26.8 < θ_high = 40
    — a Tier-2 ticket the end state would not grant; **45 × 0.893 ≈ 40.2** is the smallest
    count whose uniform-spread mass clears θ_high, so the interim and the end state agree at
    the boundary. Retired by #53/#54 (R1/R2 subsume it).
  - **(b) the reachability patch** — selector union in `_brute_force_then_login` and
    `_ids_then_brute_force` (linux_auth's `"SSH Login Failure"`/`"SSH Login Success"` categories
    join the union frozensets, `detector.py:140-141`; as merged, the auth leg's former
    `source_type == "syslog"` filter was **removed rather than extended** — the SSH leg keys on
    category alone), with positive **and must-NOT** tests — so a linux_auth success after brute
    force can reach the CRITICAL rule (D3's reachability caveat; the fade-on-success inversion
    makes this load-bearing). Retired by **ADR-0071**'s generalization.
- Docs: `docs/escalation-and-triage-model.md` §7 (which still describes `sustained_attack` and
  the first draft's recidivism framing) is updated in the #53/#54 landing batch — **stated
  interim:** until then it describes the code as it exists, which is accurate today.

## Revision 1 retire list (grep-derived in the revising session: `grep -rln "episode|attempt_pressure|sustained_attack" docs/ packages/`; `grep -rn "N_p|W_p|E_max|recidiv" packages/ --include="*.py"`)

| Artifact | Disposition |
|---|---|
| First-draft D2/D3 text + Amendment 1 (uncommitted working-tree diff) | **Replaced by this revision in place** (ADR never accepted; A1.1's finding preserved as Context finding 2; A1.2 promoted into D9; A1.3 moot — no gap/window episode semantics survive) |
| Issue #53 body (two-arm rule) | **Replaced** — redrafted against this revision (same batch) |
| Issue #54 body ("single-burst … must NOT queue — by design") | **Replaced** — rewritten against this revision (same batch); the quoted criterion is deliberately reversed for the high-intensity case |
| Issue #3 criterion (burst → Tier 2 via a 5-in-10 correlation) | Conflicts with this ADR at ambient rates; **edited in the PR #73 batch** (merged `a935f33`; issue #3 closed) |
| PR #73 interim detector additions — `_ssh_login_failure_burst` (`medium`, 5-in-10), `_ssh_login_failure_intense` (`high`/auto-escalate, ≥45-in-10 per the 2026-07-16 ruling), and the selector-union reachability patch in the two coupled rules | **Stand as marked interims** (each carries an in-code INTERIM note naming its retirer): the count rules **until #53/#54** (R1/R2 subsume them — the ≥45 alignment in Consequences makes the handover value-preserving); the selector union **until ADR-0071**'s outcome-keyed generalization |
| `_sustained_attack` (`detector.py:245`) + tests (`test_detector.py`, `test_issue_647_severity_policy.py`, `test_issue_52_trailing_windows.py`, `test_pipeline.py`, api `test_issue_650_escalation_policy_route.py`) | **Stand until #53**, which retires them (D2) |
| `pipeline.py` `W_STATE`/`W_CAMPAIGN` + comments (`pipeline.py:137-153`, incl. the line-145 "recidivism" comment) | **Stand**; comments updated to Revision-1 meaning in the #53 PR |
| `docs/escalation-and-triage-model.md` §7 (`sustained_attack` rows, §D2/§D3 pointer) | **Stands until #53/#54** (describes current code accurately); updated in their docs batch |
| ADR-0069 D8 coupling / landing order | **Stands** (rule names updated here; obligation unchanged) |

## References

- **fail2ban 1.1.0 `config/jail.conf`** —
  https://raw.githubusercontent.com/fail2ban/fail2ban/1.1.0/config/jail.conf — fetched in the
  original session; defaults, `[recidive]`, `ignoreip`/`ignoreself` quoted verbatim above.
- **ECS `event.kind`** — https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-kind
  — verbatim quotes recorded in ADR-0067 RC4 (fetched live in that session).
- **Sigma specification, `level`** —
  https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md
  — `informational` definition quoted verbatim in ADR-0069.
- **MITRE ATT&CK T1110 / TA0006** — https://attack.mitre.org/techniques/T1110/
- **Hawkes (1971)**, Biometrika 58(1):83-90 — the exponential kernel; **Ogata (1981)** — the
  O(1) recursion. Fetched/verified in the coordinating research session (2026-07-15); the two
  identities used are re-verified by derivation in this revision.
- **Jung, Paxson, Berger, Balakrishnan (2004)**, IEEE S&P — TRW/SPRT (rejected alternative;
  research-session extraction).
- **Axelsson (1999/2000)** — the base-rate fallacy; false-alarm suppression as the limiting
  factor (research-session extraction) — binds the D5 calibration.
- **Beaumont-Gay (2007)** — CUSUM quiescence measurements (rejected alternative;
  research-session finding).
- **Jøsang & Ismail (2002)** — forgetting factors cap achievable maxima (why the band does not
  decay, D4; research-session finding).
- **NIST SP 800-61r2** — Detection & Analysis: triage as the analysis-phase discipline; the
  attention-vs-interdiction split in D6.
- **Internal:** ADR-0067 (+ the D5(1) text corrected here), ADR-0069 (draft, coupled),
  ADR-0059 (+ Amendment 1), ADR-0058 (+A1), ADR-0068, ADR-0041, ADR-0036, ADR-0035, ADR-0033,
  ADR-0021/0065; `scoring.py`, `detector.py`, `pipeline.py:137-153`,
  `escalation/qualify.py` (PR #51), `tests/golden/fixtures/expected_scores.json`; issues
  #52 (merged), #53, #54, #74, #50.
