# ADR-0064: App-Wide Live Refresh — One Shared Heartbeat, a `dataVersion` Signal, and Auto-Refresh-vs-Deferred-Pill by Page Type

**Date:** 2026-06-15
**Status:** Accepted

**Relates to:** ADR-0019 (frontend stack — React + Vite + TS), ADR-0028 (frontend layout/toolchain),
ADR-0032 + Amendment 1 (`GET /stats` is the single source of source health / freshness), ADR-0029
(read/query API contract), ADR-0037 (entity slide-over host — the precedent for an app-root provider),
ADR-0015 (AI is additive-only; degrade, never crash). Implements the maintainer's Phase-2 walkthrough
requirement: "when new telemetry is ingested, ALL data pages should reflect it — not just the Dashboard."

---

## Context

The console **looks** live but only the header is. Two decoupled systems exist today:

1. **The header heartbeat.** `src/hooks/useHeaderRefresh.ts` polls `GET /stats` every
   `HEALTH_POLL_MS = 30_000`. It already computes everything an app-wide signal needs:
   - the **net new-event delta** between the two most recent polls (`lastSyncDeltaCount`),
   - a **monotonic event id** that only ever increases (`syncEventId`),
   - the **set of `source_type`s whose `event_count` grew** this cycle (surfaced via `pulsingSources`),
   - `lastPollAt`, `isLive`, `freshnessMinutes`.
   It drives the top-right LIVE badge, the source dots, and the "N new events from <source>" banner
   (`src/app/AppHeader.tsx`).

2. **The data pages.** Every data page fetches once on mount with `[]`-dep `useEffect`s and never
   re-runs. Confirmed in `DashboardRoute.tsx` (the main `Promise.all` fetch + the `/health` and
   `/config/runtime` fetches all have `deps=[]`), `LogsRoute.tsx` + `useLogsSurround.ts`, `AIRoute.tsx`,
   and `AnalyticsRoute.tsx`. Result: the banner announces "19 new events" while the page below stays
   frozen at page-load data.

There are **two existing per-page intervals** that this work must consolidate, not multiply:
`AIRoute.tsx` runs its own 15 s `GET /health` poll, and `useHeaderRefresh` runs the 30 s `GET /stats`
poll. Adding a third interval per page would multiply loopback API load and produce uncoordinated
refresh storms.

## Decision

### D1 — One shared heartbeat, lifted to an app-root `RefreshProvider`

There is exactly **one** polling interval for the freshness signal: the existing 30 s `GET /stats`
poll. Its delta/grew-set computation is lifted into a `RefreshProvider` mounted once at the app root
(the same architectural seam as `EntityPanelProvider`, ADR-0037), so both `AppHeader` and every routed
page consume it via a hook with no prop-drilling and no second interval.

`useHeaderRefresh` is **refactored into two layers**, not duplicated:
- a **core poll hook** (`useStatsHeartbeat`) that owns the single `setInterval`, the delta math, and the
  grew-set — the existing body of `useHeaderRefresh` moved verbatim;
- the **`RefreshProvider`** calls `useStatsHeartbeat` once and exposes the result via context;
- `useHeaderRefresh()` becomes a **thin context reader** (same return shape) so `AppHeader` needs no
  changes beyond import path. Backward-compatible by construction.

### D2 — The signal model: `dataVersion` + `grewSources`

The provider exposes a **`RefreshSignal`**:

| field | type | meaning |
|---|---|---|
| `dataVersion` | `number` | increments by 1 **only when `lastSyncDeltaCount > 0`** (a real ingest delta). Pages add this to their fetch-effect deps to soft-refetch. Never resets. |
| `grewSources` | `ReadonlySet<string>` | the `source_type`s whose `event_count` grew this cycle (the existing grew-set). Lets a page refetch **selectively**, and powers per-source pill attribution. |
| `lastDeltaCount` | `number` | the net new-event count for the latest positive delta (drives the pill copy). |
| `lastPollAt`, `isLive`, `freshnessMinutes` | (unchanged) | already exposed; carried through. |

`dataVersion` is decoupled from `syncEventId`'s banner role: a page must depend on a counter that
**only changes on a real delta** so empty poll cycles (delta = 0) cause **zero** refetches. This is the
"no doubled API load / no refetch storm" guarantee.

### D3 — The per-page subscription contract (uniform, low-boilerplate)

Every page opts in the **same** way — no bespoke per-page polling:

```ts
const { dataVersion } = useRefreshSignal()
useEffect(() => { /* existing fetch */ }, [/* existing deps */, dataVersion])
```

For pages whose fetch effect is keyed on a serialized object (Logs, `useLogsSurround`), append
`dataVersion` to the existing key array. For stream pages that use the **deferred pill** (D4), the page
does **not** add `dataVersion` to the live fetch effect; instead it reads `dataVersion`/`lastDeltaCount`
into a small "pending" state and refetches **on the user's click**. That is the only variation, and it
is dictated entirely by D4.

A page MAY use `grewSources` to skip a refetch when none of its relevant sources grew (optional
optimization; default is "refetch on any `dataVersion` bump").

### D4 — Auto-refresh vs. deferred "new data" pill — the rule, by page **type**

**The rule (named `REFRESH-MODE`):**

- **`auto` — position-stable aggregate/summary surfaces refresh silently in place.**
  Dashboard, AI Engine, Threat Intelligence. These render charts, KPI strips, ranked tables, maps, and
  verdict cards. There is no scroll-anchored reading position in a row stream to disturb; re-rendering
  updated aggregates is the expected behavior of a monitoring dashboard. They bump on `dataVersion`.

- **`deferred` — position-sensitive row streams show a non-intrusive pill.**
  Network Logs (`LogsRoute`). Auto-injecting rows at the top of a paginated, scrolled, filtered,
  expandable table mid-investigation is a rug-pull: it shifts the rows under the analyst's cursor,
  can collapse the row they were reading, and silently changes what page 1 means. Instead, on a
  positive `dataVersion` bump the page shows a **"N new events — click to load"** pill
  (the Gmail/Twitter/X pattern); clicking it refetches page 1 and dismisses the pill. While the analyst
  is on a deeper cursor page (`filter.cursor` set), the pill still accumulates the count but loading it
  returns to page 1 (honest: "newest" lives on page 1).

  **One pill, two consumers — the whole page under a single control.** The Network Logs page hosts
  BOTH the logs **table** AND the **Entity Relationship Graph (ERG)** (the force-directed graph with
  zoom/pan/fit/focus, ADR-0061 / ADR-0050). They MUST NOT each get their own "load new data" affordance
  — two refresh buttons on one page is exhausting and confusing (maintainer decision, 2026-06-15). The
  page shows **exactly one** page-level `deferred` pill, driven by the single `dataVersion` /
  `lastDeltaCount` heartbeat. On a single click, the pill's handler **fans out to both surfaces** even
  though their update *methodologies* differ:
  - **Table:** reset to page 1 / refetch the paginated logs (the existing `deferred` behavior above).
  - **ERG:** **incrementally merge** the new nodes/edges into the existing graph while **preserving the
    viewport (zoom/pan) and any focused/selected node** — NOT a from-scratch rebuild. See D5 for the
    binding rule and its justification.

  The surround data (top-pairs + ERG, fetched by `useLogsSurround`) refreshes on the same pill click,
  not on a `dataVersion` dep. There is still only one user-facing control; the fan-out is internal.

**Industry grounding:**
- **Nielsen Norman Group** — auto-forwarding / auto-updating content that shifts the reading position
  is disorienting and removes user control; user-initiated loading of new stream items is the
  recommended pattern for feeds.
- **WCAG 2.2 SC 2.2.2 (Pause, Stop, Hide)** — auto-updating content must be controllable; a deferred,
  user-triggered load satisfies this for the high-churn stream surface.
- **Established stream UIs** (Gmail "N new messages", X/Twitter "N new posts") use the deferred-pill
  pattern precisely because injecting items mid-scroll is hostile.
- **Aggregate dashboards** (Grafana, Datadog, Kibana) silently auto-refresh on an interval — there is
  no per-row position to protect — which is why the aggregate surfaces take `auto`.

This is a **recommendation the maintainer drives** (per the working agreement, UX is Maintainer's call). It
is written as a single named rule so it can be accepted as-is or flipped per page by changing one page's
mode; flipping a page is a one-line change (add `dataVersion` to the fetch deps vs. route it through the
pending-pill state).

### D5 — Soft refresh only; preserve interaction state (hard requirement)

A `dataVersion`-triggered refetch is a **state update + re-render**. It MUST NOT call
`location.reload()`, remount the route, or flash the page. A soft refetch MUST preserve **all** local
interaction state. The provider holds **no** page state, so the only requirement on each page is: the
refetch effect updates *only* the server-data slice and touches none of the interaction slices below.

Per affected page, what MUST survive a refresh:

- **Dashboard** (`DashboardRoute`): timeline window mode (`activeTimelineMode`), preset
  (`windowHours`), custom range (`customStart`/`customEnd`/`windowedTimeline`), the logs search box
  (`logsSearch`), and scroll position. The Acknowledge/Dismiss set is already `localStorage` (#727) —
  safe. **Note:** the timeline panel uses its own windowed fetch; the `dataVersion` refetch must feed
  the *base* `data` slice and must not stomp `windowedTimeline` when a custom/preset window is active.
- **Network Logs** (`LogsRoute`, `deferred`): on pill click, preserve active filters/search
  (`filter`), URL params (`?ip/?action/?q`), expanded detail rows (ADR-0063 spine), and the
  Combobox/facet UI. The pill click resets to page 1 by design (loading newest), which is the one
  intentional pagination change; deeper-page scroll is otherwise untouched until the analyst clicks.

  - **ERG incremental-merge + preserve-viewport (hard requirement).** The single pill click ALSO
    refreshes the Entity Relationship Graph, but the ERG MUST **incrementally merge** the new
    nodes/edges into the existing graph rather than rebuild it. Specifically, on a pill-driven graph
    refresh the implementation MUST:
    1. **Reuse existing node positions.** Nodes already present keep their current `(x, y)`. New nodes
       are seeded near a connected neighbour (or the layout center) and the force simulation is run
       only enough to settle the additions — existing nodes are pinned / warm-started, NOT re-laid-out
       from a fresh circle. Removed nodes (gone from the new set) drop out. This means
       `useEntityGraph` MUST gain a merge path that carries forward prior positions instead of
       re-running the full 300-tick cold layout on every data change.
    2. **Preserve the viewport.** The d3-zoom transform (zoom scale + pan) MUST be retained across the
       merge. The auto-fit-to-content in `useGraphZoom` (today keyed on `nodeKey` = node positions)
       MUST NOT re-fire on a pill-driven merge — re-fitting recenters/rescales the canvas and is itself
       a viewport rug-pull. Auto-fit stays the correct behavior for a **filter re-scope** (an explicit
       analyst action that intends a new view) and for first load; it MUST be suppressed for an
       **incremental data merge**. The `[⤢]` fit button and the `0` key remain available for a
       deliberate user-initiated re-fit.
    3. **Preserve focus/selection.** Any focused/hovered/selected node state (the ADR-0061 D5
       focus+context set; the cross-filter selection) survives the merge if that node still exists;
       it clears only if the node is no longer present.
    4. **Preserve legend toggles** (`hiddenKinds`) and the newly-exposed accent treatment continues to
       work — the existing `useNewlyExposed` set-diff already identifies the merged-in nodes/edges, so
       the new entities get the ADR-0061 D6 accent pulse, which is the intended "here's what just
       arrived" glass-box cue (now also firing on live merge, not only on filter re-scope).

    **Justification — the ERG-reflow rug-pull.** Today a graph data change re-runs the full force
    layout from a fresh circular seed (`useEntityGraph` memoised on the node-id / edge set) and
    `useGraphZoom`'s auto-fit re-frames the viewport on the resulting new `nodeKey`. If that fired on a
    live refresh, every ingest would scramble all node positions and snap the analyst's zoom/pan back
    to fit — destroying the mental map they built and the region they were inspecting. That is the same
    class of harm D4 protects the table from (NN/g: don't shift content under the user; WCAG 2.2
    SC 2.2.2: auto-updating content must not disrupt). The deferred pill makes the refresh
    user-initiated; incremental-merge + preserve-viewport makes the *result* of that click
    non-disruptive — the analyst's view persists and only the genuinely-new entities animate in.
- **AI Engine** (`AIRoute`): the `?filter=below-threshold` facet, the ProvenanceChip legend dismiss
  (sessionStorage), `feedbackVersion`/`ledgerVersion` (analyst-submission reactivity), expanded verdict
  cards, and scroll. AI's existing 15 s `/health` poll is **folded into the shared heartbeat**
  (see D6) so the page drops its own interval.
- **Threat Intelligence** (`AnalyticsRoute`): the Country|ASN lens (`lens`), the lazily-fetched ASN
  cache (`asnStatus` — must NOT be refetched/reset by `dataVersion`; only the geo/summary/timeline base
  slice refreshes), the Leaflet map pan/zoom state, and scroll.

### D6 — Fold the AI `/health` poll into the heartbeat (remove the second interval)

`AIRoute`'s standalone 15 s `GET /health` interval is removed. Engine state already belongs to the
shared cadence; the AI page reads health from the shared signal (the heartbeat assembler adds a
`health` field, or the page refetches `/health` keyed on `dataVersion` plus a slow floor). Net effect:
**one interval app-wide**, not three. (The Dashboard `/health` fetch likewise moves to the shared
signal or `dataVersion` dep — no new interval.)

## Alternatives considered

- **Per-page `setInterval` (status quo extended).** Rejected: multiplies loopback API load, produces
  uncoordinated refresh storms, and duplicates delta logic the header already computes. Directly the
  "no second interval" constraint.
- **React Query / SWR migration (fetch on `focus`/`interval`, dedupe, cache).** This is the
  *proper* long-term answer (window-focus refetch, request dedupe, stale-while-revalidate, built-in
  pause/resume). Rejected **for now** because the app is uniformly manual `useState`+`fetch`; a
  query-library migration is a large cross-cutting change that would block a Phase-2 walkthrough fix.
  **Deferred** as a tracked follow-up; ADR-0064's `useRefreshSignal` contract is intentionally
  compatible with later swapping the per-page effect bodies for query hooks without touching the signal.
- **WebSocket / SSE push instead of polling.** Rejected for this scope: there is already an SSE seam
  for the pipeline ticker (ADR-0046), but a general data-push channel is a backend contract change.
  30 s polling against an already-existing loopback `/stats` is sufficient and needs **zero** backend
  work. SSE-driven `dataVersion` is a clean future upgrade behind the same signal.
- **Auto-refresh everything (including Logs).** Rejected on NN/g + WCAG 2.2.2 grounds (D4): injecting
  rows into a scrolled, filtered, expanded investigation table is a rug-pull.
- **Pill everywhere (including aggregates).** Rejected: a "click to update the chart" pill on a
  monitoring dashboard is friction with no position to protect; aggregates have no rug-pull risk.

## Reasoning

- **Reuse beats rebuild.** The header already computes the delta and the grew-set; the work is to
  *lift and share* that one signal, not invent a new one. One interval, one source of truth (`/stats`,
  per ADR-0032), zero backend change.
- **Standards-grounded UX split.** The auto-vs-pill rule is not a taste call — it follows NN/g feed
  guidance and WCAG 2.2 SC 2.2.2, and matches the dominant stream-vs-dashboard conventions.
- **Modularity / consistency.** One contract (`useRefreshSignal` + `dataVersion` in deps) adopted
  identically by every page; no per-source or per-page bespoke polling, consistent with the project's
  modularity non-negotiable.
- **Forward-compatible.** The signal abstracts *how* freshness is detected; polling today, SSE or
  React Query later, with no page-level rewrite.

## Out of scope

- Migrating any page off manual `useState`+`fetch` to React Query/SWR (deferred follow-up; this ADR
  only requires the page effects gain a `dataVersion` dep / pending-pill state).
- Changing the polling **interval** or any `GET /stats` response shape (no backend/API change; `/stats`
  already returns `source_health[]` + `freshness_minutes`).
- An SSE/WebSocket push transport for data refresh (future upgrade behind the same signal).
- The Settings page (`SettingsRoute`) — configuration, not telemetry; it does not subscribe.
- The pipeline-ticker SSE stream (ADR-0046) — a separate live surface, unchanged.
- The visual design of the pill and the banner copy beyond the "N new events — click to load" spec
  (DS detail; settled in the per-page issue).

## References

- Nielsen Norman Group — *Infinite Scrolling* and guidance on auto-updating / auto-forwarding content
  (user control over content that shifts reading position).
- WCAG 2.2 — Success Criterion 2.2.2 *Pause, Stop, Hide* (auto-updating content must be controllable).
- Stream-UI convention: Gmail "N new messages", X/Twitter "N new posts" deferred-load pill.
- Aggregate-dashboard convention: Grafana / Datadog / Kibana interval auto-refresh.
- Internal: ADR-0032 + Amendment 1 (`/stats` is the freshness source of truth), ADR-0037 (app-root
  provider precedent), ADR-0046 (pipeline SSE seam), ADR-0015 (additive/degrade posture),
  ADR-0063 (Logs detail-panel spine — expanded-row state to preserve),
  ADR-0061 / ADR-0050 (Entity Relationship Graph — d3-force layout + d3-zoom viewport, focus+context,
  newly-exposed accent — the viewport/focus state the ERG merge must preserve);
  `src/hooks/useHeaderRefresh.ts`, `src/app/AppHeader.tsx`, `src/app/App.tsx`,
  `src/routes/{DashboardRoute,LogsRoute,AIRoute,AnalyticsRoute}.tsx`,
  `src/components/logs/useLogsSurround.ts`,
  `src/components/logs/EntityGraph.tsx`, `src/components/logs/useEntityGraph.ts` (force-layout — needs a
  merge/warm-start path), `src/components/logs/useGraphZoom.ts` (auto-fit must be suppressed on merge),
  `src/components/logs/useNewlyExposed.ts` (already set-diffs merged-in entities).
