# ADR-0072: Server-Side Triage Decisions — Schema, Suppression-at-Read, and the Two-Verb Lifecycles

**Date:** July 2026
**Status:** Accepted 2026-07-17 (maintainer-approved; implements ADR-0070 D6's suppression
design; implementing issues #47 → #45 → #56)

**Decision (one line):** Triage decisions (`expected` / `dismissed` / `false_positive`) move
out of browser `localStorage` into an append-only server-side store; queue suppression and
re-entry are **computed at read time** by one pure function and served to every client as an
additive annotation — decided actors are **annotated, never removed** from the read surface.

**Implements / honours:** ADR-0070 D6 (per-object suppression with memory and re-entry, never
a global number — the two verbs and their lifecycles are D6's text; this ADR is their storage
and evaluation contract), ADR-0067 (deciding consumes the item ⇒ decisions must be durable;
the observed stratum ⇒ lifetime facts are never hidden), ADR-0029 (all API additions are
additive; loopback posture unchanged — the M3 auth ADR (#18) owns beyond-loopback),
ADR-0041 (recompute-at-read precedent — suppression/re-entry are derived, never persisted),
ADR-0035 (re-entry payloads carry engine integers, RULE-tagged), ADR-0036 (band ⊥ escalation —
a decision never alters a verdict), ADR-0033 (the action seam survives; "Harden" stays
advice), ADR-0053 D3 (the `author` auth-aware seam precedent), ADR-0054 (store adapter
decomposition pattern).
**Supersedes (behavioral):** the localStorage triage persistence and its lifecycle promises in
`frontend/src/lib/triageActions.ts` (issues #727/#755 lineage) — see D7's retire list. In
particular the "dismiss never re-surfaces" promise and the client-side
`hasMaterialChange` (score ≥ +5) rule are **overridden as an explicit decision** (D5).

---

## Context

Triage decisions today live per-browser (`frontend/src/lib/triageActions.ts`, localStorage):
a dismissed actor is back on every second device, and the queue's "done" state cannot carry a
product promise. ADR-0067 made deciding *consume* the item; ADR-0070 D6 fixed the
false-positive remedy as **identity, not threshold** — fail2ban's precedent, quoted verbatim
in ADR-0070 D6: *"'ignoreip' can be a list of IP addresses, CIDR masks or DNS hosts. Fail2ban
will not ban a host which matches an address in this list."* Suppression-with-memory is only
safe if it cannot become a blind spot, which is why re-entry (#56) is pulled into M1 alongside
the store (#47) and the vocabulary (#45).

Three constraints shape the contract:

1. **Lifetime facts are never hidden** (ADR-0067 D2 observed stratum, ADR-0070 D9). `GET
   /threats` feeds the observed record, the entity panel, and summaries — so "excluded
   server-side" must mean *the server computes the exclusion*, not *the row disappears*.
   Removing rows would also silently change an existing ADR-0029 D3 response population,
   which is not additive.
2. **One evaluator, every surface.** The banner headline count (`/banner/summary`
   `queue_size`, issue #55) and the queue list must exclude the same actors or the headline
   contradicts the list it sits above.
3. **False-positive scoping needs structured rule identity.** `EscalationVerdict` carries the
   qualifying signal only as justification prose; `QualifyResult.qualifying_detections`
   (`escalation/qualify.py`) has the structure but never leaves the decider. Suppressing
   "only that rule's re-assertion" (ADR-0070 D6) requires it on the verdict.

## Decision

### D1 — Prerequisite: additive `qualifying_rules` on `EscalationVerdict`

`EscalationVerdict` gains `qualifying_rules: list[str] = []` — the `rule_name` identities
whose assertion produced queue entry (from `QualifyResult.qualifying_detections[].rule_name`
plus the qualifying ALERT event's `SecurityEvent.rule_name` when present). Additive and
defaulted per the ADR-0048/0055 pattern; populated by `qualify.py`/`decider.py`; **changes no
scores** — the golden oracle stays byte-identical (must-NOT criterion on the implementing PR).

### D2 — The store: append-only `triage_decisions`, cases-adapter pattern

```sql
CREATE TABLE IF NOT EXISTS triage_decisions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_ip      TEXT    NOT NULL,          -- actor identity (IP in M1; entity-kind widening is #16's)
    verb          TEXT    NOT NULL CHECK (verb IN ('expected','false_positive','dismissed')),
    rule_name     TEXT,                      -- the targeted detection; CHECK: NOT NULL iff verb='false_positive'
    decided_tier  INTEGER,                   -- verdict tier at decision time; NULL = observed (the #56 re-entry input)
    decided_score INTEGER NOT NULL,          -- score at decision time (#49 input; NOT a re-entry trigger in M1)
    decided_at    TEXT    NOT NULL,          -- UTC ISO-8601
    revoked_at    TEXT,                      -- NULL = active; undo/re-decide writes a new row — rows are never deleted
    author        TEXT    NOT NULL DEFAULT 'local operator',  -- ADR-0053 D3 seam; #18 populates a real identity later
    note          TEXT
);
-- CHECK ((verb = 'false_positive') = (rule_name IS NOT NULL))
-- idx (actor_ip, revoked_at); idx (decided_at) for cursor pagination (ADR-0029 D2)
```

- **Snapshot authority is the server.** On `POST`, the server runs the actor through the
  pipeline and records `decided_tier`/`decided_score` itself — the client never self-reports
  them (a stale tab must not write a stale baseline; the browser is not a trust boundary for
  engine facts).
- Append-only: "latest active actor-scoped row wins" for evaluation; the full history feeds
  the case inbox (#16).
- Adapter layout per ADR-0054: `firewatch_core/adapters/decisions/` (`schema.py`,
  `sqlite_decisions.py`), a port protocol in `firewatch_core/ports`, wired in the API
  lifespan. Parameterised queries throughout.

### D3 — The additive API surface (ADR-0029; loopback posture unchanged)

| Endpoint | Semantics |
|---|---|
| `POST /decisions` | body `{actor_ip, verb, rule_name?, note?}` → 201 with the full record incl. server-computed snapshot. 422 when `verb='false_positive'` XOR `rule_name` present. |
| `GET /decisions?actor=&cursor=` | list; ADR-0029 D2 cursor envelope; newest-first. |
| `DELETE /decisions/{id}` | soft-revoke (`revoked_at`) — undo; the audit row survives. |
| `GET /threats`, `GET /threats/{ip}` | each ThreatScore gains additive `triage_decision: null \| {verb, decided_at, decided_tier, decided_score, suppressed: bool, reentry: null \| {…}}` — added in the **API schema layer** (`schemas.py`, ADR-0029 D5 split), not the SDK model. |
| `GET /banner/summary` | `queue_size` (and #55's "K need review" count) exclude suppressed actors via the same evaluator. |

**Client contract:** queue membership is `escalated && !(triage_decision?.suppressed)`. No
lifecycle logic runs client-side; the client renders what the server computed. Migration:
one-shot best-effort push of localStorage `dismissed` entries as `verb='dismissed'` on first
load; **`acknowledged` entries are NOT migrated** (D6). After migration, localStorage is
never authoritative for queue membership (must-NOT criterion).

### D4 — The three verbs and the pure evaluator

| verb | scope | suppresses | re-enters when |
|---|---|---|---|
| `expected` | actor identity (fail2ban `ignoreip` precedent, ADR-0070 D6) | all queue entries for the actor | **#56**: current tier appears (`decided_tier IS NULL` → any tier) or is numerically lower than `decided_tier` |
| `dismissed` | actor identity | same as `expected` in M1 | same #56 rule (D5 records the override) |
| `false_positive` | (actor, `rule_name`) | only that rule's contribution to queue entry | **inherently, at every read**: any qualifying rule NOT covered by an active FP row re-queues the actor — coverage recomputation (ADR-0041), no snapshot, no #56 logic |

One pure function (`firewatch_core/triage/suppression.py`), per actor:

```
F = {rule_name of active false_positive rows}
A = latest active row with verb ∈ {expected, dismissed}   (may be None)

suppressed_by_actor = A exists AND NOT reentry(A, verdict)
    where reentry = (A.decided_tier IS None AND verdict.tier IS NOT None)
                 OR (both non-None AND verdict.tier < A.decided_tier)   # ← #56; until #56 lands: reentry ≡ False
suppressed_by_fp   = verdict.tier IS NOT None
                 AND verdict.qualifying_rules ≠ ∅
                 AND set(verdict.qualifying_rules) ⊆ F

suppressed = suppressed_by_actor OR suppressed_by_fp
```

Two **fail-toward-visibility boundaries**, deliberate:

1. An actor whose only qualifying signal is an **anonymous** source ALERT
   (`rule_name = None`) has empty `qualifying_rules` and can never be FP-suppressed — it
   stays queued. Suppression that cannot name what it suppresses is a blind spot.
2. Volume/score deltas never enter `reentry` in M1: `decided_score` is recorded as input for
   the full novelty memory (#49), not consumed. "Volume alone SHALL NOT re-enter" is a
   tested negative in #56.

Re-entry payload (`reentry`): `{decided_tier, decided_score, current_tier, current_score,
decided_at}` — engine integers, RULE-tagged (ADR-0035). A re-entered actor's decision row
still renders in its history (nothing is hidden); re-deciding writes a NEW row whose fresh
snapshot becomes the next re-entry baseline.

**Why `expected` and `dismissed` stay distinct rows despite identical M1 lifecycles:**
ADR-0070 D6 — "they age differently and feed different improvement loops." #49 (M5) diverges
their aging; #16's inbox displays them differently. Collapsing them now would be
un-collapsible later; the schema cost of keeping them apart is one CHECK value.

**Interim between #47 and #56 (stated per the deferred-correction rule):** a decided actor
does not re-enter on tier appearance until #56 merges. This is honest only because #56 is
the next PR in the same milestone; if #56 slips past M1, #47's suppression must gain a
stopgap re-entry rule — that slippage reopens this section, it does not extend the interim.

### D5 — Lifecycle override: dismissed re-enters (supersedes the localStorage promises)

`frontend/src/lib/triageActions.ts` documents, verbatim: *"dismiss → resolve/close the actor —
stronger suppression than acknowledge; does NOT re-surface on material change"* and defines
material change as *score +5 / block_status flip / tier decrease* (`hasMaterialChange`,
`MATERIAL_SCORE_DELTA`). **Both are superseded:**

- `dismissed` re-enters on the #56 tier rule, same as `expected`. ADR-0070 D6's one-way-door
  guard is the reason: per-object suppression is only a safe FP remedy if suppression cannot
  become a blind spot, and "an actor you closed as noise later starts a campaign" is exactly
  the one-way door #56 exists to guard. A verb that opts out of re-entry re-creates the
  blind spot by menu choice.
- The score-≥+5 clause of the old material-change rule is deliberately **dropped**, not
  ported: score growth without a tier is volume, and volume alone re-entering is the flood
  ADR-0070's distribution table exists to prevent. The tier-decrease clause survives as the
  #56 rule; the block_status-flip clause is deferred to #49 (band/kind semantics).

### D6 — Vocabulary and placement (maintainer rulings, 2026-07-17)

- **Queue card actions:** Investigate / **Expected — this is me** / Harden (advice-only,
  ADR-0033 seam). **Dismiss** lives in an overflow menu on the card.
- **False positive** is offered on the **detection row** (expanded item / entity panel
  detection list), because it targets a rule, not the actor — placing it on the card would
  invite actor-level misuse. The API ships FP regardless of UI placement.
- **The `acknowledge` verb is retired.** Its "suppress now, re-surface on material change"
  semantics are subsumed by `expected`/`dismissed` + server-side re-entry. Existing
  localStorage `acknowledged` entries are **not migrated** (ephemeral "working on it" state:
  the actor re-appears and gets an honest verb); `dismissed` entries migrate best-effort.
- Posture-aware headline (#45) derives from queued verdicts' **merged Phase-A disposition
  keys** (issue #75: `not_blocked_passive` / `detected_no_action` / `not_blocked_enforcing`,
  with `block_status_unknown` as the undeclared/mixed fallback) — review verb unless a queued
  verdict carries an enforcing/blocked disposition. No new posture endpoint; no dependency on
  Phase B (#44).

### D7 — Retire list (grep-derived 2026-07-16; verified mechanically at review)

Re-run at review:
`grep -rn "isDismissed\|reconcileAcknowledged\|hasMaterialChange\|ACKNOWLEDGED_ACTORS_KEY\|DISMISSED_ACTORS_KEY\|MATERIAL_SCORE_DELTA\|acknowledge" frontend/src --include="*.ts*" | grep -v test`
— only the survivals listed here may remain.

| Artifact | Disposition |
|---|---|
| `triageActions.ts`: `isDismissed`, `reconcileAcknowledged`, `hasMaterialChange`, `MATERIAL_SCORE_DELTA`, `snapshotOf`, `AcknowledgedSnapshot`, `addDismissed`/`addAcknowledged`, `ensure*Loaded`, `flush*Store`, `clearDismissed` | replace-with-server-store in #47's PR |
| `DISMISSED_ACTORS_KEY` / `ACKNOWLEDGED_ACTORS_KEY` | survive ONLY inside the one-shot migration reader (`lib/triageDecisions.ts`); no other reader |
| `acknowledge` verb branch + its lifecycle docs | retired in #47's PR (D6 ruling) |
| `DashboardRoute.tsx` `dismissVersion` state + `reconcileAcknowledged` call; `triageBand.ts` / `RecommendationCards.tsx` `isDismissed` imports | replace-with-`triage_decision` predicate in #47's PR |
| `TriageBanner.tsx:237` hard-coded "need a BLOCK decision" headline + stale comments (`TriageBanner.tsx:2`, `DashboardRoute.tsx:472`) | stands until #45's PR, because #45 owns the vocabulary; replaced there |
| `makeOnAction` seam, `OnAction`/`OnActionCallbacks`, `isValidIpFormat`, the `block`-branch SOAR wire-in comment | stands permanently — boundary: ADR-0033 |

### D8 — Module layout (implementer sketch, not a straitjacket)

- `firewatch_core/triage/` — new package (post-verdict concern, deliberately not inside
  `escalation/`): `models.py` (`TriageDecision`, `DecisionEvaluation` — frozen, pure data) ·
  `suppression.py` (the D4 evaluator; no I/O).
- `firewatch_core/adapters/decisions/` — `schema.py` + `sqlite_decisions.py` (D2).
- `firewatch_api/routes/decisions.py` — the D3 route;
  `firewatch_api/decision_annotator.py` — pure annotation/exclusion helper
  (`banner_assembler.py` style: aggregates already-computed facts, never re-derives).
- Frontend: `api/decisions.ts` (client) · `lib/triageDecisions.ts` (migration +
  queue-membership predicate) · `lib/triageActions.ts` shrinks to the ADR-0033 seam.

**Boundary test (dead-wire guard):** #47 ships an API-level integration test over the real
app + real sqlite crossing route → annotator → suppression → store in one request:
`POST /decisions` → `/threats` shows `suppressed: true` → `/banner/summary` `queue_size`
decremented → (with #56) tier appears → `reentry` served.

## Alternatives considered

- **Remove decided actors from `GET /threats`** (#47's AC read literally) — rejected: hides
  lifetime facts (ADR-0067 D2 / ADR-0070 D9), breaks the observed record / entity panel, and
  silently changes an existing ADR-0029 D3 response population, which is not additive.
- **Client-reported decision snapshots** (`decided_tier`/`score` in the POST body) — rejected:
  a stale tab writes a stale re-entry baseline, and the browser is not a trust boundary for
  engine facts. The server recomputes from the pipeline at decision time.
- **Persist suppression/re-entry state** (a `suppressed` column, expiry sweeps) — rejected:
  ADR-0041's recompute-at-read precedent; derived state persisted is state that drifts. The
  evaluator is pure and deterministic against the stored snapshot.
- **Collapse `dismissed` into `expected`** — rejected: ADR-0070 D6, they age differently and
  feed different improvement loops (#49, #16); the divergence would be un-recoverable.
- **Keep `acknowledge` as a fourth verb** — rejected (maintainer ruling, D6): subsumed by
  actor-scoped decisions + server-side re-entry; keeping it preserves a score-threshold
  re-surface rule D5 deliberately drops.
- **A global suppression threshold instead of per-object decisions** — rejected upstream by
  ADR-0070 D6 (identity, not threshold — the fail2ban `ignoreip` precedent quoted there).

## Reasoning

The store is boring on purpose: an append-only table of operator utterances plus the engine
facts current at utterance time. Everything interpretive — is this actor suppressed *now*, has
it escalated *since* — is a pure function of (rows, current verdict), evaluated at read time.
That keeps the two lifecycles honest (they are code, not data), makes re-entry deterministic
and unit-testable against fixed snapshots (#56's acceptance), keeps every client identical
(the server computes; clients render a boolean), and leaves nothing to drift between a
persisted flag and the verdict it summarizes. The fail-toward-visibility boundaries encode
the one asymmetry that matters in a triage tool: a wrongly-visible actor costs a glance; a
wrongly-suppressed one costs the incident.

## Consequences

- #47 implements D1–D4 + D6's migration + D7's retire list; #45 implements D6's vocabulary
  on top; #56 implements D4's `reentry` clause + payload. Frontend sequencing: #47 → #45 ∥
  #56-backend → #56-chip (the only #45/#56 file overlap, `TriageBanner.tsx`, lands last).
- `tests/golden/fixtures/expected_scores.json` stays byte-identical
  (`fe4787643955c920e934e3789c79f741cd8c8cde6b2adbc6540b66ff3743f31f`) across all three PRs —
  a changed hash is a defect, never a re-bless.
- The `author` column and loopback posture leave a zero-schema-change seam for the M3 auth
  ADR (#18); multi-user attribution stays out of scope until then.
- #16 (case inbox) consumes this store's history; #49 (novelty memory) extends the evaluator
  and owns decision aging/expiry and the deferred block_status-flip clause (D5).
