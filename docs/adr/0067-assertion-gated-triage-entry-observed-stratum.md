# ADR-0067: Assertion-Gated Triage Entry, the Observed Stratum, and Enforcement Posture — a Tier Is a Disposition, Not a Ticket

**Date:** 2026-07-14
**Status:** Accepted (implemented by #42 / PR #51). **D5(1) is corrected by [ADR-0070](0070-hostile-attempt-pressure-and-campaign-detection.md) D7** — the band axis is not the safety net D3's fail-quiet assumed; ADR-0070's pressure axis supplies it. Partially supersedes ADR-0058 D2's entry semantics and the ALERT/LOG "block status unknown" label.

**Supersedes (partially):** ADR-0058 **D2's Tier-2 entry semantics** (the bare ALERT/LOG →
Tier 2 branch) and the **"ALERT/LOG ≈ block status unknown" disposition premise**. Everything
else in ADR-0058 — the four-tier disposition vocabulary, Tier 1's unconditional bypass, the
deterministic no-LLM decider, D1's severity/`auto_escalate` registry, D3's additive SDK shape,
D4, D5a/D5b (landed), D6's seams, and Amendment 1 in full — **remains Accepted**. On acceptance,
ADR-0058's status line gains "D2 entry semantics and the ALERT/LOG disposition label superseded
by ADR-0067" (status-line update only; the text is never edited).
**Relates to / honours:** ADR-0059 (three named thresholds + shared worthiness predicate —
predicate *mechanics* unchanged; the tier half's *meaning* changes, D7 below), ADR-0036 (band ⊥
escalation, never collapsed), ADR-0035 (RULE provenance), ADR-0033 (triage-action seam — the
posture-aware verbs land there), ADR-0060 (the additive `SourceMetadata` capability-declaration
pattern D6 reuses), ADR-0012 / ADR-0020 (honest action axis / lightweight OCSF alignment).
**Skill gate:** anyone touching `escalation/` or `scoring.py` loads `ai-engine-invariants` first.

---

## Context

### The flood

On the M1 Solo bundle (Suricata IDS, syslog, linux_auth, ClamAV — all watch-only), the triage
banner floods: hundreds of actors, all marked "needs a BLOCK decision," on a deployment that has
nothing that can block. Every root cause below is code-confirmed (file:line), not anecdotal.

**RC1 — Tier 2 has no fidelity gate; ADR-0058 D1's registry was never wired into routing.**
ADR-0058's D2 table is explicitly headed *"Tier when a high-fidelity detection is present,"* and
D1 built the escalation-policy registry (`escalation/policy.py`) whose stated purpose is "the
registry of which detections are loud enough to jump the queue, consumed by D2," default
non-escalating. The shipped decider grants Tier 2 on `if alert_log_events:` alone
(`escalation/decider.py:160-171`) — no detection, no severity, no `auto_escalate` check.
`auto_escalate` is consumed only by `_auto_escalate_wording` (`decider.py:221-225`) — a string
suffix. The flood-control valve was designed, built, registered, finalized — and left unwired.
Note the asymmetry: a BLOCK needs **≥ 3 events** to reach even Tier 3, but a **single** ALERT or
LOG event reaches Tier 2 — one failed SSH login outranks a thousand confirmed blocks.

**RC2 — the unconditional `OR tier <= 2` bypass is the amplifier, not the disease.**
`worthiness.py:100` + `frontend/src/lib/triageBand.ts:29` make every Tier-2 actor banner-worthy
regardless of the operator's Triage threshold — the knob is dead when ~100% of actors are Tier 2.
But the bypass is *correct design conditional on Tier 2 being rare and high-fidelity*; it is what
delivers "cannot be misconfigured into missing a breach." Fix RC1 and RC2 becomes correct again.

**RC3 — the OCSF premise behind "block status unknown" is factually false.** ADR-0058 justified
merging ALERT/LOG into one "block status unknown" label on: *"ALERT/LOG ≈ non-terminating (no
explicit OCSF disposition — 'block status unknown')."* Verified live against
`schema.ocsf.io/api/1.8.0/classes/detection_finding`, OCSF 1.8.0 says otherwise, verbatim:

- `disposition_id = 19` **Alert**: "The request or activity was detected as a threat and
  resulted in a notification **but request was not blocked**." — asserts NOT-blocked, not unknown.
- `disposition_id = 15` **Detected**: "Suspicious activity or a policy violation was detected
  without further action." — detect-only ClamAV, exactly.
- `disposition_id = 17` **Logged**: "The operation or action was logged without further action."
- `disposition_id = 0` **Unknown** exists separately — for the genuinely unknown case.
- `action_id = 3` **Observed**: "observed, but neither explicitly allowed nor denied. **This is
  common with IDS and EDR controls** that report additional information on observed behavior…"
  — the passive-sensor posture is a first-class OCSF concept, not an absence of one.

The honest per-sensor statements are: passive Suricata ALERT → "not blocked *by this control*"
(OCSF Alert/Observed); detect-only ClamAV → "detected, no action taken, file present" (OCSF
Detected); a failed-login LOG line → the outcome is known and attested — the login **failed**
(ECS `event.outcome: failure`). "Block status unknown" is honest only for the inline-silent
case — the rarest class. Mislabeling known outcomes as "unknown" is what manufactures urgency.

**RC4 — merging ALERT and LOG conflates two standard axes.** ECS `event.kind` (verified live,
elastic.co/docs/reference/ecs/ecs-allowed-values-event-kind) draws exactly this line: `alert` =
"an alert or notable event, triggered by a detection rule executing externally" (IDS, WAF,
EDR); `event` = general telemetry — something happened, nothing detected anything. FireWatch's
`ALERT` is ECS `kind:alert`; `LOG` is ECS `kind:event`. Merging them at `decider.py:123` means
**raw telemetry auto-escalates**: a successful benign SSH login (`syslog/normalize.py` → `LOG`)
lands in Tier 2 and reads "needs a BLOCK decision" — for the operator's own laptop logging into
their own machine.

**RC5 — the sources are NOT guilty.** Every normalizer was checked: Suricata signature → ALERT,
WAF Detection → ALERT, ClamAV FOUND → ALERT, auth lines → LOG are all correct per ECS
`event.kind` and ADR-0012. Remapping sources would falsify the standard; the escalation layer is
what converts honest actions into uniform urgency.

### Presentation already tried, already failed

A top-N(10) + view-all + tier-grouping pass on `TriageBanner.tsx` shipped pre-launch and failed
live — the maintainer still hit the wall. Two mechanism reasons presentation cannot fix this:
(i) worthiness is computed **server-side** (`is_alert_worthy` also drives the opt-in
notification path) — no UI grouping stops it; (ii) the headline is a **false statement** ("N
actors need a BLOCK decision" on a watch-only box, block status "unknown" while the outcome is
attested) — no layout repairs a false label. The count *is* the content.

### The accepted product target (recorded here; reconciled below)

The triage surface is a **worklist**: every item carries a pending human decision, and deciding
consumes it. Facts go on the record (Network Logs, Analytics); questions go in the queue. The
structural error in ADR-0058's shipped form: the tier axis was given **two jobs** — "how loud"
(disposition) and "is a question pending" (queue entry) — and the flood is the second job
failing. The separation adopted: **assertion gates entry; tier ranks urgency within the queue;
novelty controls re-entry** (novelty is follow-up work, not this ADR).

## Decision

### D1 — Tier 2 requires a qualifying assertion (restores ADR-0058 §4a's own condition)

An actor's ALERT/LOG population reaches **Tier 2** only when a qualifying signal is present:

- **(a) a FireWatch correlation detection** in the window with `auto_escalate=True` **or**
  declared `severity ∈ {high, critical}` — the ADR-0058 D1 registry, finally consumed for
  routing, exactly as its own docstring promised; **or**
- **(b) an upstream assertion**: any `ALERT` event carrying source-declared
  `SecurityEvent.severity ∈ {high, critical}` (Sigma-anchored; the field already exists at
  `models.py:61` and every in-tree normalizer populates it — Suricata signature severity, WAF
  CRS-category severity, ClamAV FOUND → high, CEF banded severity).

**`LOG` events never self-qualify** — ECS `kind:event` is telemetry, not an assertion; they
escalate only via (a). This is the ALERT/LOG split RC4 demands, expressed as gate asymmetry
rather than a remap. **Tier 1 (ALLOW + detection) is untouched and stays unconditional** — it is
the breach signal and it never flooded. Tiers 3/4 (BLOCK/DROP) are unchanged.

The gate is **declaration-driven, zero operator tuning**: rule severities are code-declared,
signature severities are source-declared. Nothing to misconfigure; the can't-miss property moves
intact onto the qualifying signals plus the nets in D5.

### D2 — The observed stratum: `tier=None` + disposition `"observed"` — deliberately NOT tier 5

Unqualified ALERT/LOG populations (and ALLOW-only actors with no detection, today's tier-4
fallback at `decider.py:198-206`) receive a verdict with **`tier=None`** and a new additive
disposition **`"observed"`**. `block_status` keeps its truthful value (`unknown` for
ALERT-only, `allowed` for ALLOW-only); `disposition_counts` is attached as always.

**Why not tier 5 (load-bearing, maintainer-settled):** a fifth tier would force a **false
ranking against tier 4**. Tier 4 is "blocked, one-off" — the perimeter handled it. Observed is
"passed through, nothing flagged it." Neither is defensibly more urgent than the other, so any
number asserts an ordering we cannot justify. `tier=None` says the true thing: **this verdict
makes no escalation claim at all.** Tiers are a *disposition* vocabulary (action-aware,
ADR-0058), not threat magnitude (that is the band axis, ADR-0036) — and observation is a
non-claim, so it sits off the ladder. The name anchors to OCSF `action_id = 3 Observed`.
This also matches a semantic the predicate already half-owns: `worthiness.py` is deliberately
defensive on `escalation=None` (tier axis → False; band axis alone decides). `tier=None` extends
that same "no claim → no tier vote" behavior to a present verdict.

**Two consumer guards are REQUIRED, not optional** (found in review; neither currently exists):

- `worthiness.py:100` does `escalation.tier <= 2` — on `tier=None` this **raises `TypeError`**.
  The predicate gains an explicit `tier is not None` guard.
- `triageBand.ts:29` does `t.escalation.tier <= 2` — in JavaScript **`null <= 2` is `true`**
  (null coerces to 0), which would silently re-admit every observed actor and reproduce the
  flood. The TS type widens to `tier: number | null` and the comparison null-guards. The
  sort at `triageBand.ts:58` (`?? 99`) already handles null. Because a backend emitting
  `tier: null` against an unguarded frontend re-creates the flood by coercion, **the TS guard
  ships in the same change as the backend emission** (one cross-stack PR, recorded here as a
  deliberate exception to the usual per-package PR slicing).

SDK: `EscalationVerdict.tier` widens from `int = Field(ge=1, le=4)` to
`int | None = Field(default=None, ge=1, le=4)`; `EscalationDispositionLiteral` gains
`"observed"`. Both additive under the ADR-0048/0055 pattern (existing serialized verdicts remain
valid; plugins never construct verdicts).

### D3 — Fail-quiet on undeclared severity (maintainer ruling 1)

An `ALERT` with `severity=None` and no qualifying detection → **observed**, not escalated.
Rationale: Tier 1 and the correlation rules still catch anything that actually *does* something,
and the band axis (D5) catches accumulation. This is recorded as the one place the "zero-tuning
can't-miss" virtue is deliberately traded — the miss window is a source that neither declares
severity nor trips any correlation nor accumulates score, which no in-tree source can produce
(all five populate severity; verified this session). Fail-open was rejected: it re-admits the
flood for exactly the sloppy sources most likely to produce chaff.

**Security note (recorded, not solved here):** qualification input (b) is device-asserted.
A spoofable transport (UDP syslog/CEF) can therefore assert high severity and force escalation —
an alert-fatigue injection vector. This is not a new exposure class (spoofed events already
influence scoring and the band axis) and is bounded by the same source-authentication posture as
event ingestion generally; the auth ADR (M3) owns transport trust.

### D4 — Detect-only ClamAV escalates on severity; no separate stratum (maintainer ruling 2)

A ClamAV `FOUND` detection is `kind:alert` + high severity + a known-bad outcome — the malware
is on disk. It qualifies via D1(b) and belongs in the queue at Tier 2 with an honest
`detected_no_action` label (D6). A dedicated "host-attested" stratum was considered and
rejected: the severity gate already admits it, and a new stratum would grow the vocabulary for
zero routing difference.

### D5 — Where observed events live (the safety net; the argument D3 rests on)

> **⚠ CORRECTED — D5(1) below is FALSE as written. See [ADR-0070](0070-hostile-attempt-pressure-and-campaign-detection.md) D7.**
> The original text is preserved unedited (supersede, never edit) as the record of what was
> believed. The error: `run_rules` has **no term that grows with unblocked event count**. An
> unblocked, non-payload actor tops out at 35 (`port_scan` 25 + `multi_source` 10) against a
> HIGH band floor of 51 — it cannot cross the default Triage threshold **at any volume**. The
> band axis was not a weak net for passive sources; it was **no net**, and D3's fail-quiet was
> unsafe until ADR-0070's pressure axis supplied the real one. The verification that was
> skipped: the claim cites `scoring.py` for the *independence* of the axes (true) and infers
> *accumulation* from it (false) — reading the fetch path and the rule terms would have caught it.

Observed is **not a drop**. Three surfaces, all mandatory:

1. **The band axis still scores observed events.** `run_rules(events)` and
   `merge_score(rule_score, ai_result, detection_boost)` take no tier — the axes are computed
   independently (verified against `scoring.py`). A persistent low-severity scanner accumulates
   score, crosses the band threshold, and enters triage **on merit via the band axis**. This is
   the can't-miss net that makes D3's fail-quiet safe, and it revives the Triage threshold knob
   that the Tier-2 flood had made dead (ADR-0059's design intent restored).
2. **An aggregate line on the banner** — "N detections on the record → Network Logs" — the
   below-gate mass is visible as one honest sentence, never silently dropped.
3. **Network Logs** carries the per-event detail, as today.

### D6 — Enforcement posture: plugin-declared default, core-owned per-instance override

The honest replacement labels for RC3 require knowing what the producing control *could have
done*. Posture is **per-instance, not per-plugin** — proven in-tree by the Suricata IDS→IPS flip
and Azure WAF's per-policy Detection/Prevention modes. Shape:

- **SDK (additive, ADR-0060 pattern):** `SourceMetadata.enforcement:
  Literal["observe", "enforce", "detect_only"] | None = None`. `None` = undeclared →
  conservative labels, zero forced churn; declaring is the honest path. Anchors: OCSF
  `action_id` 3 Observed / 2 Denied; `detect_only` for host controls that detect without
  removal (OCSF Detected).
- **Core-owned per-instance override:** a well-known key on the `_instances` entry
  (`instance_loader.py`), rendered **generically** on every instance's Settings card — posture
  is core's interpretation knob, not plugin config. Plugins need zero edits; no per-source UI
  (modular-UI rule holds on both counts).
- **Purity constraint honoured:** `normalize()` stays pure (PLUGIN_CONTRACT.md — no cfg, no
  ctx), so posture cannot ride on `SecurityEvent`. It joins **core-side at analyze time**:
  `decide(...)` gains an additive posture-map parameter supplied by the pipeline from
  (instance override ∨ plugin metadata default). Core-internal signature change, not a
  contract change.
- **Honest labels** (additive `EscalationDispositionLiteral` values, replacing the uniform
  "unknown" for qualified Tier-2 verdicts): posture `observe` → `not_blocked_passive` ("not
  blocked by this control — watch-only sensor"); `detect_only` → `detected_no_action`
  ("detected — no action taken; file present"); `enforce` or undeclared →
  `block_status_unknown`, which becomes **rare and genuinely meaningful** (an inline control
  that alerted without a terminal verdict). Per-sensor truth only: a passive sensor cannot see a
  *downstream* block — cross-source block evidence stays with Amendment 1's `partial` +
  `disposition_counts` machinery, unchanged.
- `block_status`'s literal set is **unchanged** in this ADR (a `not_blocked` value was
  considered and deferred — disposition + justification carry the honesty; growing two
  vocabularies at once is churn without routing value).

Posture also feeds the **posture-aware decision vocabulary**: the banner headline verb derives
from deployment posture ("N need review", never "N need a BLOCK decision" on a watch-only box),
and the per-item verbs in watch-only mode are Investigate / Expected (suppress-with-memory) /
Harden (advice via the ADR-0033 seam; enforcement verbs arrive with SOAR, M4).

### D7 — ADR-0059 predicate: mechanics unchanged, meaning corrected

`is_alert_worthy` keeps its exact OR shape — `band_meets(...) OR (escalation present AND tier is
not None AND tier <= 2)`. No threshold names, defaults, or the D3 notification toggle change.
What changes is what "tier ≤ 2" *means*: queue-eligible by assertion, not "any non-terminal
event exists." ADR-0059 is not reopened.

### D8 — The golden re-bless (one, deliberate, documented — the D5b discipline)

`tests/golden/fixtures/expected_scores.json` is **untouched** (verified: it pins scores only —
no tier/escalation keys; D5 confirms scoring takes no tier input). The escalation-semantics
oracle `tests/golden/test_mixed_actor_escalation.py` **moves, on purpose**:

| Pin (current) | New expected value | Why |
|---|---|---|
| Pure-ALERT actor (5 ALERT, no detections) → `tier == 2`, `disposition == "block_status_unknown"` (:138-143) | `tier is None`, `disposition == "observed"`, `block_status == "unknown"` (unchanged) | The pinned value **encodes the flood**: it asserts that a bare, severity-less ALERT population jumps the queue — the exact behavior ADR-0058's own §4a header excluded. |
| Mixed actor (9 ALERT + 3 BLOCK, no detections) → `tier == 2`, `disposition == "block_status_unknown"` (:100-109) | `tier == 3`, `disposition == "blocked_persistent"`, `block_status == "partial"` (unchanged), `disposition_counts` (unchanged) | The unqualified ALERT mass makes no claim; the 3 confirmed BLOCKs do (≥ persistence threshold). Discarding them from the tier was Amendment 1's bug in mirror image; the loudest **qualifying** class now decides. |

All other pins in that file — `partial`, the counts, `[RULE]` tagging, integer-only
justifications, the Tier-1/3/4 single-class cases — **hold unchanged** and act as the regression
net for this change. Justification for moving pinned values, stated in ADR-0058 D5b's own words:
*the old expected values encoded the blind spot* — here, the flood. This is the same one-time,
architect-signed re-bless discipline: the implementing PR documents the new values, cites this
table, and carries explicit architect sign-off. No other golden value moves; any additional
drift in that PR is a regression, not part of the bless.

## Module shape (sketch — for the implementers)

`packages/firewatch-core/src/firewatch_core/escalation/` (existing package; one concern per
module, ≤ ~500 lines):

- `qualify.py` — **new.** The assertion gate: `qualify(events, detections) -> QualifyResult`
  (did anything qualify; which signal; the evidence for the justification). Pure; the single
  home of D1's rules. Unit-testable alone.
- `decider.py` — consumes `qualify`; assembles Tier-1..4 verdicts and the observed verdict
  (D2); loudest-qualifying-class selection for mixed actors.
- `posture.py` — **new (posture issue).** Resolve (metadata default ∨ instance override) into a
  per-instance posture map; the disposition-label table (D6). Joined in by the pipeline.
- `policy.py` / `model.py` — unchanged shapes; `policy` finally consumed for routing.
- `worthiness.py` — the `tier is not None` guard (D7); nothing else.

Frontend: `triageBand.ts` (type + null guard), `TriageBanner.tsx` (aggregate record line,
observed legend row, posture-derived headline), `escalationCopy.ts` (the single copy file the
tier-copy PR established — new vocabulary lands there).

## Alternatives considered

- **Tier 5 for the observed stratum** — rejected (maintainer ruling 3). Forces a false ranking
  against tier 4; a number asserts an ordering between "blocked one-off" and "passed, unflagged"
  that cannot be justified. Observation is a non-claim; it sits off the ladder (D2).
- **Fail-open on `severity=None`** — rejected (ruling 1). Re-admits the flood for undeclared
  sources; the D5 nets (Tier 1, correlations, band accumulation) already cover the miss window.
- **A separate stratum for host-attested detections (ClamAV)** — rejected (ruling 2). The
  severity gate admits it; a new stratum adds vocabulary without routing difference.
- **Gate at the worthiness layer instead of tier assignment (condition the `OR tier<=2`
  bypass)** — rejected. Relocates RC1 into the wrong module and leaves the *stored verdict*
  dishonest; Tier 1's unconditional bypass is the can't-miss guarantee and stays.
- **Remap source actions (e.g. Suricata → LOG)** — rejected. RC5: the sources are honest per ECS
  `event.kind`; remapping falsifies the standard to hide a core defect.
- **Presentation-only mitigation** — rejected on evidence: top-N + grouping already shipped and
  failed live; worthiness is server-side; the headline is false and no layout repairs a false
  label.
- **Amendment 2 on ADR-0058 instead of a new ADR** — rejected. Amendment 1 was explicitly "not a
  reversal"; this *is* a partial reversal of shipped, golden-pinned D2 semantics plus withdrawal
  of a premise 0058's standards section asserts — under the house rule that is a supersede, not
  an edit. It also carries net-new architecture (the posture axis, the observed stratum) that
  deserves first-class numbering. A second amendment would leave a 450-line document arguing
  with itself.
- **Split ALERT/LOG only (no gate)** — rejected as primary. Fixes linux_auth; Suricata/WAF/
  ClamAV are 100% ALERT and still flood. Subsumed as D1's LOG asymmetry.

## Reasoning

ADR-0058's core insight — disposition is a second axis, deterministic, free at ingest — survives
intact. Its failure was narrower: the tier's entry condition ("when a high-fidelity detection is
present") never made it into code, its designed gate (D1's registry) was left decorative, and
the merged "unknown" label rested on an OCSF claim that is verbatim-false. Restoring the gate is
*finishing* 0058; correcting the labels is following the standard 0058 itself cites. The
observed stratum then says the honest thing about everything below the gate — no claim — while
the band axis, the aggregate record line, and Network Logs guarantee nothing is dropped. The
result on an M1 watch-only box: the queue holds only items with a nameable question, the
headline verb matches what the deployment can actually do, and the calm state — the product's
best screen — becomes reachable.

## Consequences

- Implementing issues (filed with this ADR): **#42** (assertion gate + observed stratum + the
  D8 re-bless; M1), **#43** (observed-stratum presentation + aggregate record line; M1),
  **#44** (enforcement posture axis; M3), **#45** (posture-aware decision vocabulary + headline;
  M3), **#46** (coverage line + minimal negative-evidence header; M3), **#47** (server-side
  triage decisions; M3), **#48/#49** (negative-evidence ledger panel; novelty/re-entry memory;
  M5).
- Issue **#3** (linux_auth) context/criteria corrected: its "the escalation axis already treats
  [LOG] honestly" claim is falsified by RC3/RC4 — auth LOG events land observed; the brute-force
  story escalates via a declared correlation (D1(a)). Issue **#2** (ClamAV) escalates via the
  D1(b) severity gate (ruling 2). PR **#38**'s tier-2 copy ("Unconfirmed — may have gotten in")
  is invalidated for both M1 flagships; the copy file it established is the landing zone for the
  new vocabulary.
- `PLUGIN_CONTRACT.md` gains an additive changelog entry (`SourceMetadata.enforcement`).
- `docs/escalation-and-triage-model.md`, the tier legend, FAQ, and dashboard guide update with
  #42/#43.
- The D8 re-bless is the **only** authorized golden move; `expected_scores.json` stays frozen.

## References

- **OCSF 1.8.0 `detection_finding`** — `disposition_id` 19 Alert ("…resulted in a notification
  but request was not blocked"), 15 Detected, 17 Logged, 0 Unknown; `action_id` 3 Observed
  ("…common with IDS and EDR controls…") — https://schema.ocsf.io/api/1.8.0/classes/detection_finding
  (verified live; verbatim quotes above). The falsified-premise basis for the partial supersede.
- **ECS `event.kind`** (`alert` vs `event`) —
  https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-kind (verified live) — D1's
  LOG asymmetry. **ECS `event.outcome`** — the attested-outcome framing for auth failures.
- **Sigma `level`** (informational…critical) — https://sigmahq.io/docs/basics/rules.html — the
  severity vocabulary D1 consumes (already the ADR-0058 D1 anchor).
- **OWASP CRS anomaly scoring** — https://coreruleset.org/docs/2-how-crs-works/2-1-paranoia-levels/
  — the in-tree Azure-WAF severity derivation that D1(b) rides on.
- **NIST SP 800-61r2** — Detection & Analysis vs Containment; the queue-vs-record split is the
  analysis-phase triage discipline.
- **Internal:** ADR-0058 (+ Amendment 1), ADR-0059, ADR-0036, ADR-0035, ADR-0033, ADR-0060,
  ADR-0012, ADR-0020; `escalation/decider.py`, `escalation/policy.py`,
  `escalation/worthiness.py`, `frontend/src/lib/triageBand.ts`,
  `tests/golden/test_mixed_actor_escalation.py`.
