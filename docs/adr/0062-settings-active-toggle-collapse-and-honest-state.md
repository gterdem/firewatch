# ADR-0062: Settings Source Cards — "Active" as the Single Honest On-Switch, Collapse-by-Default Layout, and Honest Inactive State

**Date:** June 2026
**Status:** Proposed

**Implements / refines:** the Settings → Sources UX. Refines the *presentation* of
ADR-0031 (Collect Trigger — Manual Sync + Persisted Auto-Sync as the Instance-Registration
Seam). It does **not** change ADR-0031's backend state model — it relabels and re-lays-out the
existing surface.

**Relates to:** ADR-0010 (unified, schema-driven source cards — one card per installed type,
zero per-source frontend branching), ADR-0028 (frontend layout/toolchain), ADR-0031 (the
`_instances` entry IS the on-state; `source_id` defaults to `type_key`; interval bounded
[30, 86400]), ADR-0032 (honest colored health overlay — dot color from server health, not
recency), ADR-0034 (source maintenance actions seam; the staged connectivity-check from
#689/#690/#691 is an ADR-0034 action), ADR-0035 (honest labeling), ADR-0016 / #500
(multi-instance-per-type, deferred).

**Standards consulted:**
- **NN/g — Progressive Disclosure** (collapse the rarely-needed detail; show the primary
  control in the always-visible header). https://www.nngroup.com/articles/progressive-disclosure/
- **NN/g — Error-Message Guidelines** (never surface a raw status code; state the problem in
  plain language and give the user a way forward).
  https://www.nngroup.com/articles/error-message-guidelines/
- **WAI-ARIA Authoring Practices — Disclosure (Show/Hide) pattern** (the collapsed/expanded
  card header is a `button` with `aria-expanded`).
  https://www.w3.org/WAI/ARIA/apg/patterns/disclosure/
- **WAI-ARIA — Switch pattern** (the in-header Active toggle is `role="switch"` with
  `aria-checked`). https://www.w3.org/WAI/ARIA/apg/patterns/switch/
- **Splunk modular inputs / Elastic Beats** (the per-input *enable* flag is the unit of
  collection control — a single on-switch, not a register-then-enable two-step) — already cited
  by ADR-0031 §A/§B; reaffirmed here as the basis for one switch labeled "Active".

---

## Context — the bug found in the Phase-2 live walkthrough

On Settings → Sources, Maintainer configured a fresh Suricata source, pressed **Save**, then **Test**,
and got a bare **"Test failed (422)."** Root cause, confirmed in code:

1. `POST /sources/{type_key}/test` (`routes/sources.py`) takes a **required** `source_id` query
   param and 404/422-guards it against a *registered* instance (`_resolve_instance` →
   `supervisor.get_instance`).
2. A source only becomes a registered instance when an `_instances` entry exists in
   `firewatch_config.json` — and **today the only thing that writes that entry is enabling
   auto-sync** (ADR-0031 §A: "the `_instances` entry IS the auto-sync state"). Saving the config
   section alone (`PUT /config/sources/{type}`) does **not** register an instance.
3. So: configure + Save → config persisted, **no instance** → GET /sources returns no row for the
   type → the card's `instance` is `null` → `testSource(typeKey, instance?.source_id)` fires with
   `source_id === undefined` → FastAPI 422 → the UI prints the raw `(422)`.

Two cosmetic faults compounded it:
- An unregistered, never-run card can render **"Stale — NNNNm ago"** (`toStatusText` in
  `SourceCard.tsx`, the `amber` branch) — "stale" wrongly implies the source *ran and lapsed*.
- The instance label reads **"Suricata IDS/IPS · default"**, where `default` is a placeholder
  string (`SettingsList.instanceLabel`) standing in for the real `source_id`.

The deeper UX problem the walkthrough exposed: **"Auto-sync" is the de-facto on-switch but is not
named or placed like one.** Every installed source package renders a fully-expanded card whether or
not it is used; Maintainer has every package installed and actively uses ~one. The page is a wall of
expanded forms, and the one control that actually turns a source on is buried at the bottom of each
form under a label ("Auto-sync") that reads like an optional convenience rather than the master
switch.

This ADR settles the *approved, pragmatic* redesign. It deliberately takes the **cheap path**:
relabel + relayout the existing wiring; do **not** split ADR-0031's conflated state model.

---

## Decision

### A. Collapse-by-default, active-first layout (progressive disclosure)

Each source card collapses to **just its header** by default. The card header is a disclosure
control (`button` + `aria-expanded`); the config form body and the secondary controls live in the
expanded region. This is generic and schema-driven — it wraps the existing `SourceConfigForm` body
unchanged; there is **zero per-source branching** (ADR-0010 ubiquitous criterion preserved).

Sort and default-expansion are driven by Active state:

- **Active** sources sort to the **top** and render **expanded** by default.
- **Inactive** sources sort to the **bottom** and render **collapsed**.

Expanding is for *editing config*; it is not required to turn a source on/off (see §B). The user
can expand any collapsed card manually (and collapse an active one) — sort + default-expansion are
the initial state, not a lock.

> **Module/structure sketch (frontend).** Keep the layout concern out of the card body:
> - `SettingsList.tsx` — owns sort: partition `sources` into active/inactive (active determined per
>   §B), render active first. One Active-state lookup feeds both sort and default-expansion.
> - `ds/sources/SourceCard.tsx` (DS shell) — gains a `collapsible`/`defaultExpanded` seam: header is
>   the disclosure `button`; body + actions move into the collapsible region. Generic shell change,
>   no source knowledge.
> - `SourceCard.tsx` (page-level) — passes `defaultExpanded={isActive}`; the in-header Active toggle
>   (§B) is rendered into a header slot, not the body.
> The Active-state source of truth (per §B) is fetched once and threaded down — do not fan out one
> `getAutoSync` per card on top of the existing `GET /sources` (the instance list already tells us
> which types are active; see §B).

### B. Rename "Auto-sync" → "Active": one honest on-switch, moved into the collapsed header

"Active" replaces "Auto-sync" as the master on/off control for a source.

- **Active = ON** means exactly what auto-sync ON means today (ADR-0031 §A): an `_instances` entry
  exists → the instance is registered and the supervised pull loop runs on the interval. **No new
  backend concept is introduced.** The control reuses the existing `PUT /sources/{type_key}/auto-sync`
  enable/disable path verbatim (the #632 `enable_pull` wiring).
- The Active toggle lives **in the collapsed card header** (`role="switch"`, `aria-checked`), so a
  source can be turned on/off **without expanding the card**. You expand only to edit config.
- The header shows a **state pill**: **● Active** (filled/green) when on, **○ Off** (hollow/muted)
  when off.
- The **sync schedule** is demoted to a **secondary sub-line shown only when Active**:
  *"Sync every [N] s · Sync now"* (the interval input + the manual Sync action). When the source is
  Off, no schedule UI is shown (matching today's "Enable auto-sync to set a schedule" hint, now
  implicit).

**Active-state source of truth (no new fan-out).** A type is Active **iff it has an instance in
`GET /sources`** — because an `_instances` entry is the *only* thing that puts it there (ADR-0031
§A). `GET /sources` is already fetched. The per-type `GET /sources/{type}/auto-sync` (`enabled`)
remains the authoritative read for the expanded controls and stays as-is; §A's sort/default-expand
should use the already-loaded instance list to avoid N extra requests.

This is a **relabel + relocation**, not a state-model change. Push sources are unchanged: they have
no Active toggle (configuring a push source starts its listener — ADR-0031 §D); their header shows
listener status. The flavor discriminant already lives in one place (`CollectControls`
`renderSourceControls`); the header Active control renders only for `flavor === "pull"`.

### C. `source_id` shown as the real id, defaulting to the type key

Replace the `"default"` placeholder (`SettingsList.instanceLabel`) with the **real `source_id`**,
which per ADR-0031 §B defaults to the **`type_key`** — `suricata`, `azure_waf`, `aws_nfw`. This is
already the live convention (the running `azure_waf` instance has `source_id == "azure_waf"`). The
header reads "Suricata IDS/IPS · `suricata`" instead of "· default".

Forward-compatible with #500 (multi-instance): when a type runs N user-named instances, each carries
its own `source_id`; the type key is simply the default id of the first/only instance today. No
schema change — `_instances` is already keyed on `(source_type, source_id)` (ADR-0016).

### D. Humanize the Test / action error — never surface a raw status code

No user-facing string may be a bare `"(NNN)"`. Specifically:

- **Inactive source (the 422 case):** the Test (and Sync) action is **not available** on an
  inactive source because there is no registered instance to probe. The UI MUST either
  (a) **disable** Test/Sync on an inactive source with a tooltip *"Turn this source on to test
  it,"* or (b) short-circuit the click and show that same sentence — **never** call the endpoint
  with a missing `source_id` and never print `422`. (This is the honest consequence of the
  out-of-scope decision in §"Out of scope": we keep "test only after Active".)
- **Other failures (SSH / connection / path / auth):** map to plain-language remediation text. The
  staged connectivity-check checklist already built in #689/#690/#691
  (`StagedDetailChecklist.tsx`, surfaced generically via `SourceActions`) is the reuse target — it
  already renders per-stage human outcomes; route Test failures through it rather than printing
  `extractErrorMessage`'s `"(status)"` suffix for the inactive case.

`extractErrorMessage` (in `CollectControls.tsx`) currently appends `(${err.status})` to messages.
That is acceptable as a *developer* fallback for genuinely unexpected errors, but the inactive-source
and known-remediation paths must be intercepted *before* it, so a normal operator never sees a code.

### E. Honest collapsed-header state text — "Off", not "Stale"

An inactive / never-run source MUST read a neutral **"Off"** (or "Not active") in its collapsed
header — **never "Stale — NNNNm ago."** "Stale" (the `amber` branch of `toStatusText`) must be
reserved for a source that **is Active and actually ran** but whose newest event has aged past the
server freshness boundary (ADR-0032 Decision C). For an inactive source (`instance === null`,
i.e. not in `GET /sources`), the header state is "Off". This is a copy/branching fix in
`toStatusText`, gated on Active state, not a health-model change (ADR-0032 stands).

---

## Consequences

**Positive**
- The "configure → Save → Test → 422" trap is closed at the UX level: the on-switch is named
  honestly ("Active"), placed where the user looks (the header), and Test is simply unavailable
  until the source is on — with a sentence that says so.
- Progressive disclosure makes a multi-package install legible: the one or two sources you use sit
  expanded at the top; the rest collapse out of the way but remain one click from configuration.
- Minimal blast radius: no backend state-model change, no new endpoint, no migration. The change is
  a relabel + a header-slot relocation + a disclosure wrapper + two copy fixes.
- Modularity preserved: still one card per installed type, still schema-driven, still zero
  per-source branching (ADR-0010); the flavor discriminant stays in its single existing site.

**Negative / accepted**
- "Active" continues to conflate *registered* and *auto-syncing* (ADR-0031 §A). We accept this — see
  Out of scope. The cost is that "turn it on to collect even once" and "schedule it" are the same
  switch; for the single-instance era that is the simpler, more honest mental model, and it is what
  the operator already learned from v1.
- **Test/Sync are unavailable before a source is Active** (you cannot dry-run connectivity on an
  unsaved/unregistered config). Accepted as the honest trade of keeping the conflation — calling
  Test requires a registered instance, and the only honest way to get one today is to turn the
  source on. (A future "test before enabling" would require the §"Out of scope" state split.)
- The DS `SourceCard` shell grows a collapsible seam. Accepted: it is generic chrome, reused by
  every card.

---

## Out of scope (deliberately deferred — do NOT design or build under this ADR)

1. **A separate Register / Unregister concept and a registered-but-idle state in the UI.** The
   "heavy" option (configure → register → separately enable scheduling) is explicitly *not* adopted.
   We keep one switch labeled "Active."
2. **Amending ADR-0031 to split "registered" from "auto-syncing" into two backend states.** ADR-0031
   §A's conflation is kept intentionally. *Rationale for the future option:* if/when multi-instance
   (#500, ADR-0016) introduces "configured-but-parked, manually-syncable" as a first-class operator
   need (e.g. a costly Azure source you register once and sync on demand without a schedule), that is
   the moment to revisit splitting the state — at which point §C's real-`source_id` and the existing
   `idle` supervisor disposition (ADR-0031 §C) are already the seam. Until then, no split.
3. **"Test before enabling"** on an unsaved/unregistered config. Accepted trade of the §D / §B
   design — Test requires a registered instance.

These are recorded so a future session does not re-derive them as gaps; they are choices, not
omissions.

---

## Alternatives considered

- **Keep cards fully expanded, just rename Auto-sync → Active in place.** Rejected: does not solve
  the wall-of-forms legibility problem for a many-packages install; the on-switch stays buried at the
  bottom of a long form rather than in the header where the user decides "do I use this source?".
- **Split register/enable into two controls + two backend states (the heavy path).** Rejected by the
  schedule-pressed constraint and by ADR-0031's deliberate conflation; deferred to #500 (see Out of
  scope #2).
- **Make Test work on an unregistered config by giving the endpoint a config-only probe path.**
  Rejected for this milestone: it widens the Test endpoint's contract and re-opens the "what does
  Test mean without an instance" question; the honest, cheap answer is "turn it on first."
- **Surface the raw 422 with a friendlier prefix only.** Rejected — NN/g error guidance: state the
  problem and the next step ("Turn this source on to test it"), do not show codes.

---

## References

- NN/g — Progressive Disclosure — https://www.nngroup.com/articles/progressive-disclosure/
- NN/g — Error-Message Guidelines — https://www.nngroup.com/articles/error-message-guidelines/
- WAI-ARIA APG — Disclosure (Show/Hide) — https://www.w3.org/WAI/ARIA/apg/patterns/disclosure/
- WAI-ARIA APG — Switch — https://www.w3.org/WAI/ARIA/apg/patterns/switch/
- Splunk modular inputs (per-input enable + interval) & Elastic Beats (`enabled` + `scan_frequency`)
  — per-input enablement as the collection-control unit — already cited in ADR-0031 §A/§B.

---

## Amendment 1 (2026-06-15) — "Active" = auto-sync `enabled`; one signal, no flicker

**Status:** Accepted (amends §A/§B/§E of this ADR; does not reopen ADR-0031's state model).

**Trigger.** The Phase-2 live walkthrough surfaced three Settings bugs (maintainer
report 2a/2b/2c) that all trace to the *Active-state source of truth* this ADR pinned in
§B: *"a type is Active iff it has an instance in `GET /sources`."* That rule is **wrong in
the presence of ADR-0031 §C idle registration**, and the original ADR did not account for it.

### The three-signal disagreement (root cause, confirmed in live code + a fresh DB reset)

`GET /sources` is built from `Supervisor.status()` (`routes/sources.py::list_instances`),
which returns **every registered `InstanceRecord`** — including IDLE ones. The CLI boot path
`run.py::_register_idle_configured_pulls` registers an **IDLE** supervisor record for *any
pull source that has a config section but no `_instances` entry* (ADR-0031 §C, so manual Sync
works without auto-sync). Result: three "is this source on?" signals that legitimately
disagree:

| Signal | Source of truth | True for a config-only (auto-sync OFF) source? |
|---|---|---|
| **instance-present** in `GET /sources` | `Supervisor.status()` (incl. IDLE) | **YES** (IDLE record) |
| **`_instances` membership** | `firewatch_config.json` → `load_instances` | NO |
| **auto-sync `enabled`** | `GET /sources/{t}/auto-sync` (derived from `_instances`) | NO |

Live proof (fresh reset, `_instances == []`): `GET /sources` returned `azure_waf` and
`suricata` both with `state="idle"`, while `GET /sources/suricata/auto-sync` returned
`enabled=false`. Under §B's literal rule, **both render Active=ON** while nothing auto-syncs.

- **2a (flicker to Off).** `SourceCard` initialises `useState(isActive=false)` → first paint
  shows "Off" for every card; `loadInstance()` then resolves `GET /sources` and sets
  `isActive = (instance !== null)` → flips to "Active". The flicker is the async resolve, and
  the *resolved value is also wrong* (keys off instance-present, the YES column above).
- **2b (Activate never enables auto-sync).** Because instance-present is already true for an
  idle source, the toggle paints **Active=ON without the user ever toggling**, so the
  `PUT …/auto-sync {enabled:true}` path (`enable_pull` + `_instances` write + 60 s loop) never
  fires. `state=idle`/`running` disagrees with `enabled=false` and `_instances=[]`; the loop
  never starts; `last_sync_at` stays frozen.
- **2c (Sync hangs).** `PullControls.handleSync` already wires `syncResult`/`syncError` (the
  backend `POST /sync/{t}` returns `{ok, events_ingested}` / 502 envelope). The hang the
  walkthrough saw is the **downstream** symptom of 2b: Sync is gated on `isActive`, and the
  inconsistent signals + the missing completion affordances make a slow SSH pull look frozen.
  The remaining gap is purely UX — a definite success/failure/last-result state and a bounded,
  cancellable feel.

### Decision — collapse to ONE signal: auto-sync `enabled`

1. **"Active" means auto-sync `enabled` (the `_instances` entry exists).** This is the single,
   restart-stable, honest on-switch — exactly what ADR-0031 §A calls the ON state. It is **not**
   keyed off instance-present (which now includes idle). §B is amended accordingly: *"A type is
   Active iff auto-sync is `enabled` for it,"* read from the per-type auto-sync state, not from
   the presence of a row in `GET /sources`. This is the honest-reporting principle behind OCSF
   `status`/`status_detail` and ECS `event.outcome`: report the operationally-true state, never a
   proxy that can disagree with it. (OCSF 1.x Base Event `status_id`; ECS `event.outcome` —
   report the real outcome, not an inferred one.)

2. **The backend stops presenting an idle, never-enabled source as "on".** `GET /sources`
   keeps returning idle records (manual-Sync still needs the instance — ADR-0031 §C), but it
   becomes **self-describing** so the UI never has to guess. Add a derived boolean
   **`auto_sync_enabled`** to each `GET /sources` entry, computed from the `_instances` file the
   same way `GET …/auto-sync` computes `enabled`. The UI reads *that field* — never instance-
   presence — for the Active pill, the sort, and the default-expansion. (One fetch, no per-card
   `getAutoSync` fan-out — the §A "no new fan-out" constraint is preserved by moving the truth
   *into the list payload*, not by adding requests.) `state` ("idle"/"running"/…) remains a
   *diagnostic* field, never the Active discriminant.

3. **Toggling Active is atomic and already correct on the backend.** `PUT …/auto-sync
   {enabled:true}` already does upsert `_instances` → `register_idle` → `enable_pull` (launch the
   60 s loop) in one handler, and `{enabled:false}` does `disable` → `remove_instance`. No
   backend behaviour change is needed for atomicity — the bug was that the **UI never invoked
   the ON path** because it mis-read Active. With Active driven by `auto_sync_enabled`, an idle
   source paints **Off**, the user toggles, and the existing atomic path runs. The eliminated
   disagreement is structural: after this amendment, `auto_sync_enabled` (list payload) ==
   `enabled` (GET auto-sync) == `_instances` membership, by construction (all three read the same
   file). `state` is free to be idle/running/backoff without ever contradicting "Active".

4. **No-flicker contract (loading is not "Off").** The Active pill MUST distinguish three
   states: **unknown/loading**, **Off**, **Active**. Until the first `GET /sources` resolves,
   the header renders a neutral *loading* affordance (skeleton/disabled switch with no committed
   `aria-checked`), **never a committed Active=false**. The `isActive` state therefore becomes
   tri-valued (`null | false | true`); §E's `toStatusText` returns `""`/"Loading…" for the
   `null` case, "Off" only for a *resolved* inactive source, and "Active"/"Stale" only for a
   resolved active one. This follows the WAI-ARIA Switch + "don't show a definitive empty/false
   state before data settles" guidance (NN/g — skeleton/loading over premature zero-state).

5. **Sync completion contract (2c).** `POST /sync/{type_key}` already returns
   `{ok, source_type, source_id, events_ingested}` on success and a 502
   `{error:{code:"SYNC_FAILED", message}}` on failure (ADR-0031 §F / issue #569). The UI MUST
   render a **terminal** result after every Sync click — success ("Synced — N events" + the
   refreshed `last_sync_at`), failure (the sanitized message, never a bare code — §D), and must
   clear the spinner in `finally` (it already does; the perceived hang is the long pull with no
   intermediate affordance). Add an explicit *"Syncing… (this can take up to ~Xs for SSH
   sources)"* in-progress line and surface `last_sync_status`/`last_sync_at` as the persisted
   "last result" so a slow-but-working sync is legible. No new endpoint.

### What this does NOT change (still out of scope)

- ADR-0031 §A's deliberate conflation of *registered* and *auto-syncing* stays. We are not
  adding a "registered-but-parked, manually-syncable" first-class UI state (that remains Out of
  scope #1/#2 of this ADR, deferred to #500). The idle record is an **internal seam for manual
  Sync**, not a user-facing "on" state — Amendment 1 just makes the UI ignore it for Active.
- No new backend concept, no migration. `auto_sync_enabled` is a *derived* field on an existing
  response, computed from the existing `_instances` file.
- Modularity is preserved: `auto_sync_enabled` is computed generically in
  `routes/sources.py::list_instances` for every pull instance; zero per-source branching, zero
  core→plugin imports. Push sources omit the field (they have no auto-sync — §B unchanged).

### Standards consulted (this amendment)

- **OCSF** Base Event `status_id` / `status_detail` — report the operational status as a
  first-class field, not via a proxy. https://schema.ocsf.io/
- **ECS** `event.outcome` — record the true outcome of an operation, not an inferred one.
  https://www.elastic.co/guide/en/ecs/current/ecs-event.html
- **WAI-ARIA APG — Switch** — a switch's `aria-checked` must reflect committed state; do not
  commit a false value before it is known. https://www.w3.org/WAI/ARIA/apg/patterns/switch/
- **NN/g — skeleton/loading states** — show a loading affordance, not an empty/false zero-state,
  before data resolves. https://www.nngroup.com/articles/skeleton-screens/
