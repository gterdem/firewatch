# `tests/volume/` — the volume oracle

**Question this oracle answers:** *does realistic input produce a usable
result?* (Sibling of `tests/golden/`, which answers *"does the same input
produce the same exact score?"* — deliberately separate disciplines, ADR-0068
D1. Neither inherits the other's change ritual.)

## What lives here

```
manifests/ambient_night.json   — the reviewable manifest: personas + expected
                                  classification, justified against Suricata's
                                  shipped classification.config / ADR-0069's
                                  syslog recalibration (ADR-0068 D2/D3)
generator.py                   — pure: (manifest, seed) -> list[RawEvent],
                                  expanding recorded templates
                                  (tests/golden/fixtures/eve_*.json, the
                                  "Failed password" line shape from
                                  packages/sources/syslog/tests) — no scoring
                                  imports, no hand-built SecurityEvents
harness.py                     — RawEvents -> the REAL normalizers
                                  (firewatch_suricata/firewatch_syslog/
                                  firewatch_syslog_cef) -> per-actor
                                  ThreatScore + EscalationVerdict, by mirroring
                                  (not reimplementing) Pipeline.analyze_ip's
                                  decision slice. No DB, no API server, no AI.
test_triage_volume.py           — the invariants (ADR-0068 D2) + the ADR-0070
                                  distribution-table personas as named,
                                  individually-failing assertions
fixtures/derived_threats.json  — committed, regenerated via
                                  scripts/regen_volume_fixtures.py; consumed
                                  by the frontend sibling test
```

The frontend sibling lives at `frontend/src/test/triageBand.volume.test.ts` —
it feeds the committed `derived_threats.json` through `deriveTriageActors`
(`frontend/src/lib/triageBand.ts`) and asserts the SAME membership/ordering
the Python harness computed, closing the JS-side `tier: null` <= 2 coercion
channel independently (ADR-0068 D4).

## The two scenario variants (ADR-0068 D2)

- **Ambient-only** (`generator.build_ambient_scenario(manifest, seed, breach=False)`)
  — pure noise: ~127 actors built from Suricata priority-2 scanners, syslog
  "Failed password" ambient scanners, a leaving 5-in-10-min sshd burst, and
  the Maintainer's isolated 2-attempts/30-min INFORM case. Expected queue:
  **empty** — the calm state is a machine-checked precondition, not a hope.
- **Breach variant** (`breach=True`) — the SAME ambient noise plus two
  overlay actors: a Tier-1 actor (ALLOW + a corroborating detection) and a
  band-HIGH accumulator (a pure BLOCK/port-scan actor crossing the HIGH band
  via `run_rules` alone, independent of the tier axis). Expected queue:
  **exactly those two actors**, Tier-1 sorted first — a gate that only
  rewards silence fails this test.

## The ADR-0070 (+ Amendment 1) persona ledger

`test_triage_volume.py`'s `TestPersonaFiftyPerMinuteAttacker` through
`TestPersonaAmbientSuricataPriority2NoTicket` are the ledger of record for
`H` / `theta_press` / `theta_high` / `theta_quiet` / `D_endure`
(`firewatch_core.attempts`, `firewatch_core.detector`). Each persona is run
through the REAL syslog normalizer (never a hand-built `SecurityEvent`),
mirroring — not duplicating — the unit-level pins in
`packages/firewatch-core/tests/test_issue_54_attack_in_progress_campaign.py`.
A constants change that breaks a persona fails a NAMED test here with the
persona's own name in the traceback, not a silent drift.

## Manifest-change discipline (ADR-0068 D1)

Unlike `tests/golden/`'s one-time architect-signed re-bless, a manifest edit
here (adding/resizing a persona, changing a severity) requires:

1. **A stated distribution justification in the PR** — "what a real
   deployment produces these numbers" (a citation to Suricata's shipped
   `classification.config`, a Sigma `level` definition, an ADR, or a live
   capture — see the calibration procedure below). No bless ceremony.
2. **Regenerate the derived fixture**: `uv run python
   scripts/regen_volume_fixtures.py`. `test_triage_volume.py`'s
   `TestDeterminism::test_committed_derived_threats_fixture_matches_current_generation`
   fails loudly if you forget — the fixture is drift-checked, not
   hand-maintained.
3. **Never touch `tests/golden/`** from this discipline — the two oracles
   stay independent (ADR-0068 D1).

## Live-data calibration procedure (ADR-0068 D3)

Live infrastructure (a Pi running Suricata, an internet-exposed `sshd`
capture, a Terraform Azure WAF deployment) is **calibration for this
manifest, never a per-PR gate** — it must never block CI. After a real
collection night:

1. Export the actor-level persona distribution (event counts per IP, time
   spans, severities) from the real capture.
2. Compare against `manifests/ambient_night.json`'s declared personas.
3. If the live distribution disagrees with a persona's declared shape (e.g.
   more than the flood tripwire's worth of real ambient actors reach
   `theta_press`/`theta_high`), adjust the manifest's counts/severities OR
   file a `contract-change`-style finding against the relevant ADR's D5
   falsifier (`ADR-0070` D5/D9) if a CONSTANT (not just the manifest) looks
   miscalibrated.
4. Regenerate (`scripts/regen_volume_fixtures.py`) and state the live-data
   justification in the PR.

## Adding a new volume surface (ADR-0068 D5)

This ADR builds ONE scenario (the triage surface — the one with a live,
maintainer-hit failure). Future surfaces (Network Logs at 50k events,
Analytics aggregation, Settings at N instances, the entity graph at 500
nodes) arrive **on demand** — when an ADR asserts a rarity assumption or a
walkthrough finds a scale defect — each as its own small issue, reusing
`generator.py`'s schedule helpers and `harness.py`'s normalize-dispatch
pattern rather than a new framework. Do not add a speculative scenario
without a concrete trigger (gold-plating).

## Running

No opt-in marker — this scenario runs in the default `uv run pytest`
invocation, alongside `tests/golden/`. Both variants together score in well
under a second (`TestCiBudget`, ADR-0068's <=5s budget).
