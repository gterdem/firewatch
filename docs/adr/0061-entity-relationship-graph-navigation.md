# ADR-0061: Entity Relationship Graph Navigation — Lift ADR-0050's Static-MVP Constraint; Add a d3-zoom Transform Layer, Label Level-of-Detail, and Focus/Context (amends ADR-0050)

**Date:** June 2026
**Status:** Accepted

**Amends:** ADR-0050 (Entity-graph render — `d3-force` for layout only → hand-rolled SVG). This ADR **supersedes ONLY ADR-0050's deferred-zoom MVP clause** ("The MVP defers that polish — a settled static layout", ADR-0050 lines 52-53, and the `useEntityGraph.ts` "no d3-zoom / no pan / no zoom" constraint). **Everything else in ADR-0050 STANDS:** d3-force for layout math only, hand-rolled SVG with real DOM nodes, **no graph framework** (react-flow / cytoscape / sigma), **no canvas/WebGL**, verdict-band node tint, text-node-only labels.
**Implements / backs:** Issue #668 (ERG redesign, WS4b). **Honours:** ADR-0029 D3 (attacker-controlled labels render as text nodes only).
**Relates to:** #667 (filter-scoped graph re-query — the new world this navigates), #662 (aggregation filter-passthrough), #664 (present-sources, optional). Those are *plumbing*; this ADR is the **navigation / level-of-detail / representation** decision.

---

## Context

ADR-0050 chose d3-force-to-SVG and deliberately deferred drag/zoom/pan as "MVP polish," shipping a settled static layout. In live testing that static graph is **unreadable at density**: labels overlap into mush and there is no way to navigate into a region of interest. The ERG also now sits **directly above the `/logs` table** and is becoming **filter-scoped** (#667/#662 re-query it with the same `LogsFilter` facets), so it is a focused, ego-centred subgraph that the analyst needs to *move around in*.

Two facts shape the fix:
1. **`forceCollide` is already wired** (`useEntityGraph.ts:183-186`) — so node *overlap* is not the readability problem. The problem is **labels** (all rendered, always — `EntityGraph.tsx:470-479`) plus a **cramped canvas**.
2. Because the ERG is **directly above the table**, a naive wheel-zoom would **trap the page scroll** — the analyst couldn't scroll past the graph to reach the table.

Lifting the zoom deferral changes a settled ADR, so per the README's supersede rule this amendment is required before build (Issue #668 explicitly gates on it).

## Decision

Add navigation, label level-of-detail, and focus/context to the ERG, **within ADR-0050's render contract** — d3-zoom contributes **math + event-handling only** (a `transform`), exactly as d3-force contributes layout math only. No rendering paradigm changes.

### D1 — d3-zoom transform layer (not an overflow scroll region)

Apply `d3-zoom` as a CSS/SVG `transform` on a `<g>` layer wrapping the existing nodes/edges. Mouse-wheel/trackpad **zoom** + drag **pan**. The hand-rolled SVG and real DOM nodes are unchanged. **Because zoom/pan is a transform, the no-inner-scrollbar constraint holds** — there is no `overflow` scroll region nested in the page (consistent with the "avoid nested scrollbars" lean).

### D2 — Click-to-activate wheel zoom (scroll-trap prevention)

Wheel-zoom is **inactive until the user clicks into the graph**: until then the **wheel scrolls the page**, and a faint **"click to interact"** hint shows while inactive. This resolves the scroll-trap created by the ERG sitting directly above the table — the analyst scrolls past the graph normally and opts into zoom deliberately.

### D3 — Explicit controls + keyboard (real buttons, a11y)

A bottom-right control cluster **`[+] [−] [⤢ fit/reset]`** as **real `<button>`s with aria-labels**, plus keyboard **`+` / `−` / `0` (reset) / arrow-pan**. Every navigation affordance is reachable without the wheel and without a mouse.

### D4 — Label level-of-detail (the real readability fix — labels, not collision)

Stop rendering all labels always. Label only **top-K nodes by degree ∪ CRITICAL/HIGH-verdict IPs ∪ the hovered/focused node**, and **reveal more labels as zoom scale rises** (descending degree — the Sentinel/Maltego LOD pattern). Hover/focus **always** shows a node's label. The readability budget is spent on **label LOD + a larger DECOUPLED world size** (layout coordinates larger than the viewport, which d3-zoom navigates) — **not** on re-adding node collision, which is already wired.

### D5 — Focus/context, legend toggles, honest density cap

- **Focus + context on hover:** highlight the hovered node's neighbors, **dim the rest** — **no network fetch** (pure client-side, on already-fetched graph state).
- **Legend chips become layer toggles:** clicking "Category"/"ASN" hides that node/edge **kind** (client-side `hiddenKinds` set; IP nodes are always shown).
- **Tighter default cap:** lower the unfiltered default to **~40 nodes** (today 200), with the existing `truncated` flag surfaced honestly as "showing top N of M by traffic — filter to narrow." Generous **invisible padded hit-areas** keep small nodes clickable.

### D6 — Filter-scoped subgraph; client-side "newly-exposed paths"

The graph is now **filter-scoped** — clicking an IP node **re-scopes the graph AND table together** (one filter change, via the #667 re-query), not an in-graph expansion. When a filter re-scopes, **set-diff the new vs previous node/edge id sets** (both already in React state) and briefly **pulse** the newly-surfaced entities with an "N entities newly exposed by this filter" caption; under `prefers-reduced-motion`, a static accent ring replaces the pulse. This diff is **pure client-side — no backend**. (The re-query plumbing itself is #667/#662; this ADR governs only the *representation* of the diff.)

## Module shape (sketch — for the implementer; split `EntityGraph`'s growing concerns)

```
frontend/src/components/logs/
  EntityGraph.tsx          orchestrator — composes the pieces below; ≤ ~500 lines
  useEntityGraph.ts        layout math — extend: larger DECOUPLED world size; keep forceCollide
  useGraphZoom.ts          NEW — d3-zoom transform state; click-to-activate; +/−/0/arrow keys
  graphLabels.ts           NEW — label LOD: top-K-by-degree ∪ CRIT/HIGH ∪ focused, scale-gated
  GraphControls.tsx        NEW — [+][−][⤢] cluster; real buttons + aria-labels
  GraphLegendToggles.tsx   NEW — legend chips as hiddenKinds layer toggles
  useNewlyExposed.ts       NEW — prev-vs-next id set-diff → pulse set + caption; reduced-motion aware
  NodeTooltipPortal        keep; reuse the existing Popover/portal where it fits
```
This is a sketch, not a straitjacket — but do **not** hand the growing zoom/LOD/diff concerns to a single `EntityGraph` class.

## Standard alignment & deviations

- **Label level-of-detail by node importance** is the established graph-viz readability pattern (Microsoft Sentinel investigation graph, Maltego, Gephi all prioritise labels by degree/centrality and reveal on zoom) rather than rendering every label. FireWatch's importance signal adds **verdict band** (CRITICAL/HIGH always labelled) on top of degree — surfacing the on-box AI's read, consistent with ADR-0050's verdict-tint property.
- **Click-to-activate wheel zoom** is the standard web pattern for an embedded zoomable surface inside a scrolling page (interactive maps, embedded force graphs) — it prevents scroll-trapping. We add a visible "click to interact" hint so the affordance is discoverable rather than surprising.
- **Deviation from "frameworks give this for free":** ADR-0050 noted a heavy graph library would hand us zoom/pan/label-de-collision for free. We **still decline the framework** and hand-roll these via d3-zoom + LOD, because (per ADR-0050) the bundle/a11y/DS-fit cost of a 100–400KB framework outweighs the polish, and our bounded node counts (now *tighter*, ~40 default) sit well within hand-rolled SVG's range. The deviation cost is the code in the module sketch above; the benefit is keeping the no-heavy-framework, real-DOM-a11y culture intact.

## Blast radius

- **Frontend only** — new `useGraphZoom`/`graphLabels`/`GraphControls`/`GraphLegendToggles`/`useNewlyExposed` modules; `EntityGraph.tsx`/`useEntityGraph.ts` extended. No new dependency beyond `d3-zoom` (a small, tree-shakeable d3 module, consistent with ADR-0050's d3-force-only import posture).
- **API / SDK / core** — none (the re-query plumbing is #667/#662, separate issues).
- **Golden oracle** — untouched (pure presentation).
- **ADR-0050** — its zoom-deferral clause is superseded; every other decision in it stands and is reaffirmed here.

## Alternatives considered

- **Re-add / strengthen node collision to fix readability** — *rejected.* `forceCollide` is already wired; overlap is not the problem. The unreadability is labels + a cramped canvas; the fix is label LOD + a larger decoupled world, not more collision.
- **Always-on wheel zoom (no click-to-activate)** — *rejected.* The ERG sits directly above the table; always-on wheel zoom traps the page scroll and the analyst can't reach the table. Click-to-activate + a hint is the standard embedded-surface fix.
- **Adopt a graph framework (react-flow / cytoscape / sigma) to get zoom/pan/LOD "for free"** — *rejected (ADR-0050 reaffirmed).* 100–400KB, theming/a11y is their model not ours, and our node counts (~40 default) don't need it. We lift only the zoom deferral, not the framework ban.
- **Switch to canvas/WebGL for zoom performance** — *rejected (ADR-0050 reaffirmed).* Loses real-DOM a11y; unnecessary at our bounded, now-tighter node counts.
- **Render all labels always, just smaller / de-collided** — *rejected.* Still mush at density and fights `forceCollide`; importance-ranked LOD is the proven pattern.
- **Server-side "newly-exposed paths" computation** — *rejected.* Both id sets are already in client React state; a client-side set-diff is free and needs no backend (keeps the change frontend-only).

## Reasoning

The ERG's readability problem is precisely diagnosable from the code — labels, not collision — and its navigation problem (it sits above the table) has a standard, scroll-safe answer (click-to-activate zoom). Both fixes live entirely inside ADR-0050's render contract: d3-zoom contributes a transform the same way d3-force contributes layout, the SVG/real-DOM/no-framework/no-canvas decisions all stand, and labels remain text-node-only (ADR-0029 D3). Lifting only the deferred-zoom clause — and recording it as a supersede of that one clause, not a rewrite of ADR-0050 — gives the analyst a navigable, importance-labelled, focus/context graph with no inner scrollbar, no new framework, and no backend change.

## Consequences

- ADR-0050's zoom-deferral clause is **superseded**; ADR-0050 is otherwise reaffirmed (its render contract is the binding constraint on this work).
- Backs Issue #668 (WS4b). The graph becomes filter-scoped via #667/#662; "newly-exposed paths" is the client-side representation of that re-scope.
- Adds one small d3 module (`d3-zoom`) consistent with ADR-0050's import posture; no per-source UI (modular-UI rule).
- The no-inner-scrollbar constraint holds (zoom/pan is a transform, not an overflow region).

## References

- **ADR-0050** — Entity-graph render (d3-force → SVG); this ADR amends only its deferred-zoom clause.
- **ADR-0029 D3** — attacker-controlled labels as text nodes only (reaffirmed for all node ids/labels).
- **Graph-viz label LOD prior art** — Microsoft Sentinel investigation graph; Maltego; Gephi — importance-ranked labels revealed on zoom; backs D4.
- **`d3-zoom`** — https://github.com/d3/d3-zoom — transform-only zoom/pan, consistent with ADR-0050's d3-force-only posture.
- Backs Issue #668; relates to #667 / #662 (re-query plumbing) and #664 (present-sources).
