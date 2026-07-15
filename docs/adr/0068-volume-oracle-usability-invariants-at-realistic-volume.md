# ADR-0068: The Volume Oracle — Usability Invariants at Realistic Event Volume as a Deterministic CI Gate

**Date:** 2026-07-15
**Status:** Proposed

**Relates to / honours:** ADR-0067 (assertion-gated triage entry — supplies the invariant this
oracle asserts), ADR-0058 (+ Amendment 1 — the escalation axis under test), ADR-0059 (the shared
worthiness predicate — the exact function the oracle exercises), ADR-0036 (band ⊥ escalation),
ADR-0024 (legacy as functional oracle — the precedent that oracles are first-class architecture).
**Skill gate:** none new; `tests/golden/` discipline is unchanged by this ADR.

---

## Context

### The class of bug nothing catches

The M1 triage flood shipped past every automated gate: ruff, pyright, ~3,800 tests, the 222-test
golden oracle, and two clean security reviews — and was found only when the Maintainer *used the
app* against a night of real telemetry. Three holes let it through; two are now closed by standing
architect checks (ADR-conformance at pickup; distribution analysis before acceptance criteria).
The third is structural: **no automated gate exercises the product at realistic volume.**

`tests/golden/` answers *"does the same input produce the same score?"* — exact values, per-event
and per-small-scenario. Nothing answers *"does realistic input produce a usable result?"* The
flood was a property-at-scale failure: every individual verdict was "correct" per its unit tests;
the *population* of verdicts was unusable. The design worked at 3 events and drowned at 400.

The previously planned mitigation — "pull the live-data test forward" (Terraform Azure WAF + a
Suricata Pi) — is not a gate: it depends on infrastructure that is not always up, which is
exactly why it stayed pending for months while features shipped past it. You do not need live
Azure to know 400 IDS alerts flood a banner; you need a deterministic fixture that replays 400
events. **Live data is calibration for the fixtures — proof they are realistic — never a per-PR
gate.**

### Verified distribution facts this ADR is built on (fetched live, quoted verbatim)

1. **Suricata's shipped `classification.config`**
   (https://raw.githubusercontent.com/OISF/suricata/master/etc/classification.config):
   `attempted-recon,Attempted Information Leak,2` · `misc-attack,Misc Attack,2` ·
   `misc-activity,Misc activity,3` · `trojan-activity,A Network Trojan was detected, 1` ·
   `web-application-attack,Web Application Attack,1`. EVE `alert.severity` is this priority.
   The ambient mass on an exposed sensor — ET SCAN (attempted-recon) and ET DROP/CINS reputation
   rules (misc-attack) — is therefore **severity 2**; ET INFO (misc-activity) is severity 3.
2. **Sigma `level` semantics** (the vocabulary ADR-0058 D1 / ADR-0067 D1(b) anchor severity to;
   https://github.com/SigmaHQ/sigma-specification, `sigma-rules-specification.md`): "`medium`:
   Relevant event that should be reviewed manually on a more frequent basis." · "`high`: Relevant
   event that should trigger an internal alert and requires a prompt review." · "While `low` and
   `medium` level events have an informative character, events with `high` and `critical` level
   should lead to immediate reviews by security analysts."
3. **Simulation on today's code** (128 ambient actors / 369 events, seeded, run this session
   through `decide()` + `is_alert_worthy()`): triage queue = **128 of 128 actors** — the flood,
   reproduced deterministically in under a second, no hardware.
4. The same simulation projected onto ADR-0067 D1(b) as specced: **100 of 128 actors still
   qualify for Tier 2**, because the legacy Suricata map (`firewatch_suricata/normalize.py`
   `_SEVERITY_MAP = {1: critical, 2: high, 3: medium, 4: low}`) upshifts priority-2 ambient noise
   into Sigma-`high`. Per the verbatim Sigma definitions above, priority-2 recon/reputation noise
   is Sigma-`medium` behavior ("reviewed manually on a more frequent basis"), not `high`
   ("requires a prompt review"). This calibration defect is filed separately; the oracle exists
   precisely to adjudicate such questions mechanically. (Fact 4 is itself the proof of value: the
   oracle found a second flood channel before a line of it was written.)

## Decision

### D1 — A second oracle class: `tests/volume/`, pinning properties, not values

Adopt a **volume oracle** as a sibling of the golden oracle, living in `tests/volume/`,
running in the default `uv run pytest` suite (no marker, no opt-in — a gate that must be enabled
is not a gate).

The two oracle classes are deliberately distinct and neither inherits the other's discipline:

| | `tests/golden/` | `tests/volume/` |
|---|---|---|
| Question | Same input → same exact output? | Realistic input → usable result? |
| Pins | Exact scores/fields | Invariants (set membership, bounds, ordering, conservation) |
| Input scale | 1–12 events | One "ambient night" (~350–500 events, ~120 actors) |
| Change discipline | One-time architect-signed re-bless (ADR-0058 D5b / ADR-0067 D8) | Manifest edits require a stated distribution justification in the PR (what real deployment produces these numbers); no bless ceremony |

Overloading golden's re-bless ritual onto manifest tuning would either ossify the manifest or
dilute the ritual; keeping them apart protects both.

### D2 — The invariants (what a scenario asserts)

Every volume scenario carries a **manifest** declaring, per actor persona, the expected
classification (`queue` / `observed` / `band`). The tests assert:

1. **Exact queue membership** — the set of queue-eligible actors (per the real
   `is_alert_worthy` predicate at the default `HIGH` threshold) equals the manifest's declared
   set. Set equality, not a bare ceiling: a ceiling alone cannot localize a failure and can be
   satisfied by suppressing everything.
2. **Flood tripwire** — additionally, `len(queue) <= 10` (one screenful; the number is a named
   manifest constant). Absolute, never a ratio: the queue is consumed by one human, and 5% of
   10,000 is still a flood. This survives manifest growth as a backstop even if (1) is edited.
3. **Breach-among-noise (anti-suppression)** — the scenario variant that plants a genuine breach
   (Tier-1: ALLOW + qualifying detection) and a band-`HIGH` accumulator inside the same ambient
   noise MUST show both in the queue, with the Tier-1 actor sorted first. A gate that only
   rewards silence is passed by suppressing everything; this invariant makes silence a failure.
4. **Conservation (observed is not a drop, ADR-0067 D5)** — every actor with ≥1 event is
   accounted for in exactly one of {queue, observed record}; the observed/record count equals the
   manifest's count. Nothing silently disappears.
5. **Calm reachability** — the ambient-only variant (no planted breach) yields the manifest's
   expected queue (empty once calibrated): the calm state is a machine-checked precondition, not
   a hope.
6. **Determinism** — generation is a pure function of (manifest, seed); the suite regenerates
   in-process and compares against the committed derived artifact (D4), so environment
   nondeterminism or silent generator drift fails loudly.

### D3 — Generation: manifest × recorded templates × seeded generator

Neither hand-written 400-event JSON (unreviewable) nor free property-based generation
(unrealistic distribution, flaky-adjacent, equally unreviewable) — a hybrid:

- **Templates** are the recorded real logs already in-tree (`tests/golden/fixtures/eve_*.json`,
  syslog lines) — realism anchors to captured traffic, not invented shapes.
- **The manifest** is the reviewable artifact: ~40 lines of personas ("60 reputation-listed
  scanners, 1–4 alerts each, severity 2 (`misc-attack`)…"), each field justified against a
  published distribution (fact 1 above) or a recorded capture. A human can sanity-check the
  manifest in one screen — the fixture hazard ("a fixture nobody can sanity-check") lands here
  and is answered here.
- **A seeded generator** (`random.Random(seed)`) expands manifest × templates into `RawEvent`s
  fed through the **real normalizers** — the volume path exercises the same code a deployment
  does from ingestion shape onward.
- **Live data = calibration.** The documented procedure (in `tests/volume/README.md`): after a
  real collection night (Pi Suricata / Terraform WAF), compare the observed persona distribution
  against the manifest and adjust the manifest deliberately, with the diff justified. Live
  infrastructure never blocks CI.

### D4 — Assertion layer: the core decision slice + the frontend derivation function

The oracle asserts at the **cheapest layer that contains the defect class**, twice, because the
worthiness predicate is deliberately implemented on both sides of the stack (ADR-0059):

- **Python (`tests/volume/`):** RawEvents → real normalizers → per-actor
  `run_rules`/`detect`/`merge_score`/`decide` → `ThreatScore` → `is_alert_worthy`. No DB, no API
  server, no AI (the decision path is pure — verified this session; the whole night runs in
  well under a second). The API routes are pass-through for this shape and add cost without
  marginal coverage.
- **Frontend (vitest):** the Python harness emits a committed derived artifact
  (`derived_threats.json`, drift-checked per D2-6); `deriveTriageActors` (`triageBand.ts`) over
  that artifact must produce the same membership and ordering. This closes the JS-side channel
  independently — in JavaScript `null <= 2` is `true`, so an unguarded frontend against a
  `tier: null` backend re-creates the flood by coercion even when every Python test is green
  (ADR-0067 D2).
- **The rendered UI stays empirical, not gating:** ui-tester's mandate (seed at realistic volume,
  judge usability in a real browser) is the judgment layer above this deterministic layer. The
  oracle proves the *count*; ui-tester judges the *screen*. Division of labor, not overlap.

### D5 — A pattern, instanced once — not a framework

"Design works at 3, drowns at 400" is a class, not a triage-only bug: Network Logs at 50k
events, Analytics aggregation, Settings at 12 instances, the entity graph at 500 nodes all carry
it. This ADR establishes the pattern (manifest + generator + invariants under `tests/volume/`)
and builds **one scenario: the triage surface** — the surface with a live, maintainer-hit
failure. Additional surfaces get volume scenarios **on demand** — when an ADR asserts a rarity
assumption or a walkthrough finds a scale defect — each as its own small issue reusing the
harness. No speculative scenarios now (gold-plating); the README records how to add one.

## Module shape (sketch — for the implementers)

```
tests/volume/
  README.md                      — the oracle-class contract: properties not pins; manifest
                                   change discipline (D1); live-calibration procedure (D3);
                                   how to add a surface (D5)
  conftest.py
  manifests/ambient_night.json   — personas + per-persona expected classification (D2)
                                   (breach variant = overlay flag or second manifest)
  generator.py                   — pure: (manifest, seed) → list[RawEvent] from recorded
                                   templates; one concern: expansion, no scoring imports
  harness.py                     — one concern: RawEvents → real normalizers → per-actor
                                   ThreatScore + EscalationVerdict (no DB / API / AI)
  test_triage_volume.py          — invariants D2-1..6 for the two scenario variants
  fixtures/derived_threats.json  — committed serialized ThreatScores for the frontend sibling
scripts/regen_volume_fixtures.py — the single regeneration entrypoint
frontend/src/lib/__tests__/triageBand.volume.test.ts — D4's frontend assertions
```

## Alternatives considered

- **Live-data test as the gate (the original plan)** — rejected. Depends on hardware/cloud being
  up; that is why it stayed pending for months. Retained as *calibration* (D3).
- **Property-based testing (Hypothesis) as the gate** — rejected as the primary. Random case
  search neither encodes "a realistic night" nor produces a reviewable fixture, and shrinking
  nondeterminism is flaky-adjacent in CI. Complementary for the pure decider later; not this gate.
- **A lint/static rule on the decider** — rejected. The defect is a property of a *population* of
  verdicts under a distribution; no static rule sees distributions.
- **Fold into `tests/golden/`** — rejected (D1). Different question, different change discipline;
  overloading the re-bless ritual damages both oracles.
- **Assert through the API server** — rejected (D4). The routes are pass-through for this shape;
  server startup adds seconds per run for zero marginal defect coverage — and a slow gate gets
  disabled (then it isn't a gate).
- **A bare ceiling ("queue ≤ N") as the only assertion** — rejected (D2). Cannot localize
  failures and is satisfiable by total suppression; set-equality + the breach-among-noise
  invariant close both holes. Ratio thresholds rejected: usability of a human queue is absolute.
- **Committed 400-event fixture, no generator** — rejected (D3). Unreviewable; every calibration
  becomes a 400-line diff nobody reads.

## Reasoning

The golden oracle protects *computation*; nothing protected *usability under load* — and the
product's core promise (ADR-0067: "the queue holds only items with a nameable question; the calm
state is reachable") is a usability-under-load property. Making that promise a deterministic,
sub-second, per-PR assertion converts the class of bug from "found by the Maintainer at night"
to "found by CI before merge." The first concrete payoff arrived before implementation: building
the fixture's severity distribution from Suricata's shipped `classification.config` exposed that
ADR-0067 D1(b) + the legacy Suricata severity map leave a second flood channel (100/128 ambient
actors still qualifying) — exactly the kind of finding this oracle exists to force into the open.

## Consequences

- Implementing issue: **#50** (M1 — the triage-surface volume oracle; the regression net for #42
  and the machine-check of #43's calm state).
- **Known-red at birth, by design:** the ambient scenario fails on today's code (the flood,
  fact 3) and — as ADR-0067/#42 are currently specced — is expected to remain red after #42 for
  the severity-map channel (fact 4). The Suricata severity-map recalibration is a separate,
  small conformance-to-Sigma decision (Maintainer), filed against M1; it moves golden-pinned
  normalize severities (`expected_01/02/03/04/06`) and therefore carries its own justified
  re-bless if approved.
- `ARCHITECTURE.md` §testing and CLAUDE.md's non-negotiable #3 gain the second oracle sentence
  ("golden: same input → same scores; volume: realistic input → usable result") **after** this
  ADR is accepted.
- CI budget: the scenario adds ~1–2 s to `uv run pytest` (measured: the full decision slice on
  369 events completes in <1 s; golden's 222 tests run in 0.57 s). Compatible with #17.
- ui-tester keeps the empirical rendered-layer mandate; this ADR takes nothing from it.

## References

- **Suricata `classification.config`** (shipped defaults; priority → EVE `alert.severity`) —
  https://raw.githubusercontent.com/OISF/suricata/master/etc/classification.config — verbatim
  lines quoted in Context (fetched this session).
- **Sigma specification, `level`** —
  https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md
  — verbatim `medium`/`high` definitions quoted in Context (fetched this session).
- **NIST SP 800-61r2** — Detection & Analysis: alert triage as the analysis-phase discipline the
  queue-size invariant operationalizes.
- **Internal:** ADR-0067 (the invariant source), ADR-0058 (+A1), ADR-0059 (the predicate under
  test), ADR-0036, ADR-0024 (oracle-as-architecture precedent);
  `escalation/decider.py`, `escalation/worthiness.py`, `frontend/src/lib/triageBand.ts`,
  `tests/golden/` (the sibling), issues #42/#43/#17.
