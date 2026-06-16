# ADR-0050: Entity-graph render — `d3-force` for layout only, drawn to hand-rolled SVG (no graph framework, no canvas)

**Date:** 2026-06-13
**Status:** Accepted (deferred-zoom MVP clause superseded by [ADR-0061](0061-entity-relationship-graph-navigation.md); all other decisions stand)

## Context
ML-9 (issue #437) renders the entity graph on the Network page over the bounded
`GET /logs/graph` contract (issue #436, merged): `{ nodes, edges, truncated }`,
default 200 nodes / 500 edges, hard ceiling 1000 / 2000, flow edges weight-ranked
so the heaviest talkers survive truncation. The ML milestone deliberately left the
graph-viz library as an Open Decision (CLAUDE.md "Open decision: UI graph-widget
approach"; ML "Out of scope": *a graph-viz library choice … library ADR is a
separate gate*). This ADR is that gate.

The existing chart culture is **pure hand-rolled SVG/CSS with no charting library**:
`Sparkline.tsx` is an SVG polyline; `TimelineChart`, `AttackDispositionFlow`,
`HorizontalBarList` are CSS/flex; Leaflet is present but geo-only. The render
choice must not fight that culture, the design-system tokens, or the shipped
a11y/tooltip patterns.

## Decision
Render the entity graph with **`d3-force` for the layout math only**, mapped onto
**hand-rolled SVG with real DOM nodes** — **no dedicated graph framework
(react-flow / cytoscape / sigma), and no canvas/WebGL.**

- Import only the small force modules (`forceSimulation`, `forceLink`,
  `forceManyBody`, `forceCenter`), run a fixed number of ticks (or a short settle),
  then map each `node.x` / `node.y` onto `<circle>` / `<line>` — exactly the way
  `Sparkline.tsx` maps data points onto a polyline today.
- Nodes stay **real DOM elements**, so native click-to-filter, keyboard focus, ARIA
  labels, design-system-token fills, and the shipped `CellTooltip` hover all reuse
  existing patterns with no new rendering paradigm.
- **Standout product property:** IP nodes are **tinted by the local-AI verdict band**
  (the same `scoreToSeverityBand` tokens used on the verdict cards, from the already
  fetched verdict map). The analyst sees the fan-out actor AND the on-box model's
  read of it on one canvas, with **zero egress** — a node-link graph whose node
  colors come from a 100%-local LLM. No cloud-graph product can claim this.
- Attacker-controlled labels (IP / category) render as **text nodes only**
  (ADR-0029 D3).

## Rationale
- **Bundle / DS fit.** `d3-force` alone is tens of KB and tree-shakeable; dedicated
  graph libs are 100–400KB+ and bring an opinionated styling/theming model that
  fights Tailwind and the design-system tokens.
- **Bounded node counts make canvas needless.** SVG comfortably handles low-thousands
  of DOM elements; canvas only wins past ~2–5k. The API caps (200/500 default,
  1000/2000 ceiling) sit squarely in SVG's range, and canvas is strictly worse for
  a11y (manual hit-testing, hand-built focus/ARIA).
- **We own the render**, consistent with the existing no-charting-library culture.

## Consequences
- We own layout polish that a heavy lib gives for free (drag-to-reposition, zoom/pan,
  label de-collision). The MVP defers that polish — a settled static layout +
  click-to-cross-filter (`FacetFilters`) + an always-visible honest "showing top N"
  truncation chip is the shippable, honest first impression. LLM subgraph narration
  stays out of scope (seam only).
- Resolves the CLAUDE.md **"Open decision: UI graph-widget approach"** for this surface.

## Reopen condition
**Reopenable only if node counts ever break the bounded `GET /logs/graph` contract**
(e.g. a future need for 5k+ nodes or rich graph-editing). Because the API is bounded
by design, we likely never do.

## Alternatives considered
- **Dedicated graph library (react-flow / cytoscape / sigma)** — rejected: 100–400KB+,
  theming/a11y is their model not ours, ADR friction against the no-heavy-framework
  instinct; overkill at the bounded node counts.
- **Canvas / WebGL force-graph** — rejected: loses real DOM (manual hit-testing,
  worse a11y), unnecessary at this scale.
