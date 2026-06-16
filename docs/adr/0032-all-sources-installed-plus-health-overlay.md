# ADR-0032: "All Sources" = Installed Modules + Honest Colored Health Overlay

**Date:** June 2026
**Status:** Accepted (2026-06-10)

**Implements / closes:** the dashboard header's "All Sources" filter + health row is always empty —
the frontend reads `source_health[]` off `GET /stats`, but the backend `get_stats()`
(`adapters/sqlite_store.py`) never returns that field, and the `/sources` route's `event_count`
is wired through a `count_by_source` store method **that does not exist** (the `hasattr` guard
always misses, so counts are silently 0).

**Relates to:** ADR-0029 (read/query API contract — `GET /stats` is *already specified* to return
"global stats + source_health"; this ADR fixes an **unimplemented obligation**, it does not invent a
new endpoint), ADR-0010 (unified source cards — one card per installed type), ADR-0016
(multi-source-per-type; `source_id` identity), ADR-0023 (supervisor `InstanceStatus` — the
running/error half of health), ADR-0031 (auto-sync `idle`/`running` states feed the dot),
PLUGIN_CONTRACT.md (discovery via entry points; `flavor`).

**Supersedes binding:** the front-end **OD-2** binding (approved 2026-06-05, recorded in
`frontend/src/lib/sourceHealth.ts`) for *dot semantics and list membership* — see Decision C.

**Standards consulted:** Google SRE "four golden signals" / black-box vs white-box monitoring
(an honest health signal distinguishes *not-configured* from *configured-but-silent* from
*was-working-now-failing*); OCSF/ECS source identity (`source_type` vs `source_id`, already in
PLUGIN_CONTRACT.md). These ground the **4-state, installed-driven** model over a data-only recency
dot.

---

## Context

Maintainer's decision: the "All Sources" list is driven by **installed plugins** (discovery already
enumerates them: `GET /sources/types`), **not by data** and **not by an enable flag**. Each entry
shows a colored health dot:

| Color | Meaning |
|---|---|
| **grey** | installed, **not configured** (discoverability — Maintainer confirmed these DO show) |
| **amber** | configured, **no data yet** |
| **green** | **healthy** — recent events |
| **red** | **dark / error** — was collecting, now failing (entry point to future Settings diagnostics) |

The honest signal requires **both halves**:
- **events from the store** (per source: count + last-event timestamp) → distinguishes amber (none)
  from green (recent), and detects "went dark" (was recent, now stale);
- **running/error state from the supervisor** (`InstanceStatus.state`, `last_error`) → distinguishes
  red-because-erroring from amber-because-idle, and is the only source of the **red/error** signal.

The frontend list/health-overlay code largely exists (`AppHeader.tsx`, `SourceHealth`,
`lib/sourceHealth.ts`, the `SourceHealth`/`StatsResponse` types). The **missing half is the
backend `source_health[]`** — and the list-membership + dot-color semantics need to evolve from the
data-only OD-2 binding to the installed-driven 4-state model.

---

## Decision

### A. List membership = installed plugins (discovery), not data, not enablement

`source_health[]` carries **one entry per installed source plugin** — the same set
`GET /sources/types` enumerates — regardless of whether it is configured or has data. An installed-
but-unconfigured source appears **grey**. This makes the header a discoverability surface
("these source types exist; here's their health"), and it means *adding a plugin package makes a
greyed entry appear with zero core/frontend edits* (the modularity non-negotiable).

The backend builds the list by iterating the **plugin registry** (already injected into the API),
then left-joining the store (events) and the supervisor (status). A source with neither config nor
data still emits an entry (`status: not_configured`, `last_event_at: null`, `event_count: 0`).

### B. `source_health[]` entry shape

```jsonc
{
  "source_type": "azure_waf",       // type_key (discovery identity)
  "source_id":   "azure_waf",       // instance name; == type_key in the single-instance era (ADR-0031 §B)
  "display_name":"Azure WAF",       // from metadata() — for the chip label
  "flavor":      "pull",            // pull|push — drives pull (Sync) vs push (listener) framing
  "health":      "ok",              // SERVER-COMPUTED state — see Decision C
  "supervisor_state": "running",    // running|backoff|parked|stopped|idle (ADR-0023+0031), or null if no record
  "last_event_at": "2026-06-09T…",  // ISO8601, or null if no data
  "event_count": 12345,             // total events for this (source_type, source_id)
  "last_error": null                // supervisor last_error string when state is error/parked, else null
}
```

`health` is computed **server-side** (Decision C) so the dot color is one honest, testable value and
the front-end does not re-derive policy. The raw inputs (`supervisor_state`, `last_event_at`,
`last_error`) are included for the tooltip/expanded view and for future Settings diagnostics.

### C. The dot is a 4-state server-computed `health` — this evolves OD-2

OD-2 made the dot a **recency-only** signal (`ok<5m / warn<15m / down≥15m / idle=null`) and put
supervisor status in the *tooltip only*. Maintainer's 4-color model needs the supervisor's **error**
state to drive the dot (red), and needs **installed-but-unconfigured** to be a first-class dot
(grey) — neither of which a recency-only dot can express. This ADR therefore **supersedes OD-2's
dot-semantics + list-membership** with:

The four states are evaluated **in this order** — the first match wins, so **red (error) outranks
recency** (a source that errored one minute after a good pull shows red, not green):

```
health = red    if supervisor_state in {parked, backoff-with-error} OR last_error set   // 1. was working, now failing
       = grey   if no config section for this source                                     // 2. installed, not configured
       = amber  if configured AND (no events yet OR last_event_at older than freshness)  // 3. configured, silent/stale
       = green  if configured AND last_event_at within the freshness window              // 4. healthy
```

- **Precedence: red beats green.** Error/parked is tested first, so a supervisor error always colors
  the dot red regardless of how recent the last event was. Recency cannot mask an error.
- **green/amber** keep OD-2's recency idea but gate it on *configured*. **Freshness window = 5 min**
  (config-overridable, ADR-0006): within 5 min ⇒ green; older (or no events yet) ⇒ amber.
- **Stale-but-no-error is amber, not red.** A configured source whose events stopped while the
  supervisor still reports `running`/no error stays **amber** — "not yet confirmed dark." **red is
  reserved for an actual supervisor error/park**, never for recency alone. (There is no separate
  staleness-to-red threshold; the amber/green boundary is the single freshness window above.)
- **red** is the new supervisor-driven signal OD-2 deliberately excluded from the dot; Maintainer's model
  requires it, so the exclusion is lifted **for the error case only** (a healthy `running` instance
  with recent events is still green).
- **grey** is new: it requires the installed-but-unconfigured entry from Decision A.

The freshness window is a server constant (config-overridable, ADR-0006) so the color is computed in
one place and golden-testable. `frontend/src/lib/sourceHealth.ts` remains the single front-end seam;
it is simplified to *render the server `health`* rather than re-derive it (the recency math moves
server-side).

### D. New core read method — `source_health()` on the store (no per-source frontend code)

The store gains **one** generic read method, keyed on `(source_type, source_id)`:

```python
async def source_health(self) -> list[SourceHealthRow]:  # (source_type, source_id, event_count, last_event_at)
```

backed by a single `GROUP BY source_type, source_id` over `logs` (the `get_ip_summary` query already
shows the `MAX(timestamp)`/`COUNT(*)` shape). This **also** supplies the per-source `event_count`
that the `/sources` route currently tries to read through the **non-existent** `count_by_source`
method (its `hasattr` guard always fails → counts silently 0). This ADR fixes both with the one
method. It is fully source-agnostic — no source name is ever hard-coded (non-negotiable #1).

### E. `/stats` gains the supervisor + registry dependencies

`get_stats` route today injects only `store`. To assemble `source_health[]` it must also read the
**registry** (installed set, for grey entries) and the **supervisor** (`status()`, for
running/error). Both are already provided to the app and injected elsewhere (`/sources`); `/stats`
adds the same `Depends`. The supervisor is **optional** (serve-only deployments have none): when
absent, `supervisor_state` is `null` and `health` falls back to the store-only signal
(grey/amber/green; red is unavailable without supervisor data) — exactly the 503-safe degradation
the front-end already handles for `/sources`.

`/stats` also gains `last_updated` (ISO of the most recent event overall), which the
`StatsResponse` type already declares but the backend omits.

---

## Consequences

**Positive**
- Closes an *already-specified* ADR-0029 obligation (`source_health` on `/stats`) and the silent
  `event_count: 0` bug in one read method.
- The header becomes an honest, discoverable health surface: installed-but-unconfigured (grey) vs
  configured-silent (amber) vs healthy (green) vs went-dark (red) — the Google-SRE black-box vs
  white-box distinction, served as one server-computed value.
- Zero per-source frontend code; adding a plugin makes a greyed chip appear automatically.
- `red` is the entry point into the deferred Settings-diagnostics view (ADR-0031 §F / the deferred
  issue) — the dot and the diagnostics share `last_error`/`supervisor_state`.

**Negative / accepted**
- Supersedes OD-2's "supervisor status never colors the dot" rule. Accepted: Maintainer's 4-color model
  explicitly needs the error state on the dot; the trade is recorded here and the front-end seam is
  simplified, not duplicated.
- `/stats` becomes supervisor-aware (was store-only). Accepted and bounded: the dependency is
  optional and degrades 503-safe, identical to `/sources`.

---

## Alternatives considered

- **Keep OD-2 (recency-only dot, data-driven list)** — *rejected:* cannot express grey
  (unconfigured) or red (erroring), both of which Maintainer's model requires; and a data-driven list
  hides installed-but-unconfigured sources, killing discoverability.
- **List driven by an enable flag** — *rejected:* there is no enable flag (ADR-0031: auto-sync, not
  enable/disable); and it would hide installed sources, same discoverability loss.
- **Compute `health` on the front-end** — *rejected:* duplicates policy across two languages and
  defeats one golden-testable color; the server owns the freshness/staleness constants (ADR-0006).
- **A separate `/sources/health` endpoint** — *rejected:* ADR-0029 already specifies `source_health`
  *on `/stats`*; the front-end already reads it there; a new endpoint would fork the contract.

---

## Resolved decisions (approved 2026-06-10)

1. **Freshness window = 5 min; stale-but-no-error = amber** (§C, config-overridable per ADR-0006).
   Green when `last_event_at` is within 5 min of *now*; amber when configured with no events yet or
   events older than 5 min. A configured source whose events stopped while the supervisor reports no
   error stays **amber** ("not yet confirmed dark"); **red is reserved for an actual supervisor
   error/park**, never for recency alone — there is no separate staleness-to-red threshold.
2. **`red` precedence — error/parked outranks recency** (§C). The state ladder tests red first, so a
   source that errored one minute after a good pull shows red, not green.

---

## Erratum (2026-06-11) — canonical wire vocabulary for `health`

This ADR shipped internally inconsistent: the Context table and the §C ladder use **color words**
(`green`/`grey`) while §B's entry-shape example (normative) says `"ok"` and §A says
`not_configured`. The drift reached production: the assembler emits `"green"`, the frontend adapter
handles `"ok"` → healthy sources render as a gray/idle dot with the raw enum leaking into the
tooltip (walkthrough part-3 P14.1; fixed by #279).

**Resolution (architect, approved framing 2026-06-11):**

- The **§B JSON example is normative for the wire**: `health ∈ {ok, amber, red, not_configured}`.
- The color words in the Context table and the §C ladder describe the **dot presentation only**
  (green dot ⇔ `ok`, grey dot ⇔ `not_configured`, amber dot ⇔ `amber`, red dot ⇔ `red`); they are
  not wire values. Read §C's `health = green/grey/…` pseudocode as the dot color the state maps to.
- Rationale: (a) three of the four values already shipped in the semantic form on **both** halves
  (`not_configured`, `amber`, `red` — only `green` vs `ok` diverged), so this is the
  minimal-blast-radius resolution; (b) industry direction is semantic status words, not colors —
  IETF health-check JSON draft (draft-inadarei-api-health-check) uses `pass|warn|fail`.
  **Accepted deviation:** `amber`/`red` remain color-named wire values; renaming them to fully
  semantic words would buy purity at contract-churn cost across assembler, types, adapter and
  fixtures. Recorded here so the trade is deliberate.
- Enforcement: #279 adds a vocabulary contract test (assembler emit-set ↔ frontend adapter
  handled-set) so future drift fails CI.

This erratum resolves a defect in the document's internal consistency; it does **not** change any
decision in §A–§E.

---

## Amendment 1 (2026-06-12) — operational dot vocabulary, sync evidence, missed-poll heartbeat
**(part-4 walkthrough P7 follow-up; issues #377 #378 #379 #380)**

### Defect that triggered this amendment

Issue #335 added a self-teaching hover legend to the health dot — but the legend hardcodes a
CrowdStrike-style RECENCY ladder (`green ≤2m / amber 2–60m / red >60m`,
`frontend/src/lib/freshnessLadder.ts`) that the server-computed `health` never follows. It
contradicts this ADR twice: (a) Decision C / Resolved decision 1 say stale-but-no-error is amber,
never red — there IS no staleness-to-red threshold, yet the legend advertises one at 60 min; and
(b) the server's green boundary is `FRESHNESS_MINUTES = 5`, not the legend's 2 min. The legend
advertises behavior the dot cannot exhibit — a correctness bug, the same class of legend/server
drift the 2026-06-11 erratum fixed for the wire vocabulary.

### R1 — RATIFIED: the dot vocabulary is OPERATIONAL, not recency (issue #377)

The dot answers "is this collector working?", not "how old is the newest event?":

| Dot | Operational meaning |
|---|---|
| green | ingesting — event within the freshness window |
| amber | configured, no recent events (stale or quiet) |
| red | collector failure — parked / backoff / last_error |
| grey | not configured |

The self-teaching legend MUST describe THIS vocabulary; the 2m/60m recency ladder is deleted.
To eliminate the root cause (a second hardcoded copy of a server constant), `GET /stats` gains a
top-level `freshness_minutes` field carrying the live `FRESHNESS_MINUTES` value; the legend
renders that, never a client constant. **R1 reaffirms Decision C; it changes no color rule.**

### R2 — RATIFIED: surface sync evidence — honest provenance applied to liveness (issue #378)

The supervisor already records the answer to the operator's real question ("is my sensor broken,
or is the network quiet?"): `last_sync_at` / `last_sync_ingested` / `last_sync_status`
(`ok|no_data|error`) per ADR-0031 §F — and `GET /sources` already serves them. The health
assembler currently discards them. The §B entry shape gains three additive fields:

```jsonc
  "last_sync_at":       "2026-06-12T…",  // ISO8601 (converted from the DTO epoch float), or null
  "last_sync_status":   "no_data",       // ok | no_data | error, or null (push sources / pre-first-cycle)
  "last_sync_ingested": 0
```

so the tooltip / health card can split the single amber into three honest states:
**verified quiet** (poll completed ok, no new events) · **never connected** (no completed sync
since configuration) · **stale** (last good poll N min ago). This is ADR-0035's
honest-provenance principle applied to liveness: the dot can now say "the sensor checked in and
confirmed nothing happened." **Dot COLOR is unchanged — Decision C is not reopened.**
Recorded divergence: `GET /sources` serves `last_sync_at` as a raw epoch float (pre-existing);
`source_health[]` uses ISO8601 for internal consistency with `last_event_at`.

### R3 — FORWARD-SCOPED (deferred, post-release; amends Decision C's letter): missed-poll → red (issue #379)

For PULL sources the sync cycle is a control-plane heartbeat. If
`now − last_sync_at > N × pull_interval` (default **N = 3**, config-overridable per ADR-0006)
while `state == running`, the collector provably should have polled and didn't — that is
**confirmed dark**, and it flows to red through the existing error channel. This honors Decision
C's *spirit* (red = confirmed failure, never mere recency) while amending its letter ("never for
recency alone" — an overdue heartbeat is not event-recency). Guardrails:
- The trigger is missed POLLS, never event-silence: a `no_data` poll RESETS the clock, so a
  quiet network never escalates.
- Push/event-driven sources have no heartbeat and stay amber on silence.
- `pull_interval` is private to the supervisor (`InstanceRecord._pull_interval`); detection
  belongs supervisor-side (e.g. an `overdue` field computed at `status()` time), per ADR-0029.

**Status: deferred, post-release.** Not active until its issue is picked up and ratified
explicitly.

### R4 — OPEN QUESTION (recorded, NOT decided; issue #380)

Should a verified-quiet pull source (recent `ok`/`no_data` poll) be GREEN rather than amber?
That redefines green from "data flowing" to "collector alive" (the CrowdStrike/Wazuh
sensor-health convention) and touches every consumer of the settled color vocabulary. It must be
a deliberate ADR debate — never a quiet tweak. Revisit after R3 and post-release operator
feedback.

### Standards grounding — sensor LIVENESS is separated from alert VOLUME industry-wide

- **Wazuh** derives agent health (`active` / `disconnected` / `pending` / `never connected`) from
  the keepalive heartbeat (60s acknowledgment window), independent of alert volume —
  https://documentation.wazuh.com/current/user-manual/agent/agent-management/agent-connection.html
- **Grafana Alerting** treats **No Data** as a distinct, separately-configurable evaluation state
  (No Data / Alerting / Normal / Keep Last State) — explicitly NOT an automatic alarm —
  https://grafana.com/docs/grafana/latest/alerting/fundamentals/alert-rule-evaluation/nodata-and-error-states/
- **Datadog** monitors expose "notify on missing data" (`notify_no_data`) as a separate, opt-in
  setting distinct from the alert condition —
  https://docs.datadoghq.com/monitors/guide/adjusting-no-data-alerts-for-metric-monitors/
- **CrowdStrike Falcon** determines sensor liveness from `SensorHeartbeat` events (every ~2 min)
  and classifies host status (DOWN / VERIFY / RECOVERY_LIKELY / OK) via last-heartbeat time, not
  event count —
  https://www.crowdstrike.com/wp-content/uploads/2024/07/Granular-status-dashboards-to-identify-Windows-hosts-impacted-by-content-issue-v8.6-updated.pdf
- **Google SRE** — "every page should be actionable"; alert on observable symptoms, not transient
  component states — non-actionable alarms cause fatigue and get ignored —
  https://sre.google/sre-book/practical-alerting/
- IETF health-check draft (`draft-inadarei-api-health-check`, cited in the erratum): health
  statuses are operational states (`pass|warn|fail`), not data-recency buckets.

FireWatch's mapping: liveness lives in the sync heartbeat (R2 evidence, R3 escalation); event
recency only ever distinguishes green from amber — never red (R1 / Decision C).

### Status ledger

| Part | Status |
|---|---|
| R1 legend honesty + `freshness_minutes` | **Accepted with this amendment** — pre-open-source (#377, MH) |
| R2 sync evidence on the wire + tooltip | **Accepted with this amendment** — pre-open-source (#378, MH) |
| R3 missed-poll → red | **Deferred / forward-scoped** — post-release; ratify at pickup (#379) |
| R4 verified-quiet = green? | **Open question** — not decided, not scheduled (#380) |

---

## References

- Google SRE — Monitoring Distributed Systems (four golden signals; black-box vs white-box) —
  https://sre.google/sre-book/monitoring-distributed-systems/ — backs Decision C (an honest health
  signal distinguishes not-configured / configured-silent / failing).
- ADR-0029 (this repo) — `GET /stats` already specifies "global stats + source_health"; this ADR
  implements that obligation rather than adding a new contract.
- PLUGIN_CONTRACT.md (this repo) — `source_type` vs `source_id` identity; discovery via entry
  points; `flavor` — backs Decisions A/B (installed-driven list, identity, pull/push framing).
