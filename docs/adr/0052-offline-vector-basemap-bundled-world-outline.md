# ADR-0052: Offline Vector Basemap — Bundled Natural Earth World-Outline GeoJSON (Closes the CartoDB Tile Egress)

**Date:** 2026-06-13
**Status:** Accepted (architect-decided under delegated authority; Maintainer pre-approved the
Analytics Phase-0 set and the zero-egress mandate for the showcase map)

**Relates to:** ADR-0022 (local-first invariant — assets stay on operator-controlled hardware),
ADR-0039 (offline geolocation default — the precedent: closed the ip-api egress by bundling an
offline asset), ADR-0047 (zero-egress attestation strip — we render a "nothing left this box"
claim), ADR-0050 (entity-graph render — precedent for "draw to SVG, no heavyweight framework"),
ADR-0028 (frontend stack — dark default theme).
**Implements:** issue #528 (CartoDB tile egress), the basemap foundation for A1 (honest geo
provenance) and A2 (ASN lens) in milestone MO.

---

## Context

`frontend/src/components/analytics/GeoMap.tsx` renders the Analytics map with Leaflet and pulls
its basemap from **CartoDB dark-matter tiles over an external CDN** (`*.basemaps.cartocdn.com`).
Every render of the Analytics page issues outbound tile requests off-box. This is a **live
external network egress on the one page FireWatch showcases as zero-egress** — it directly
contradicts ADR-0022 (local-first) and ADR-0047 (the attestation strip literally asserts nothing
leaves the box). A reviewer or security-conscious adopter watching the Network tab on first run
would catch it immediately, undermining the headline differentiator. The in-code comments already
flag this as an unsolved air-gap wart deferred from MF-5.

ADR-0039 set the exact precedent for this class of fix: it closed the ip-api geo egress by moving
to a **bundled offline asset** (DB-IP Lite MMDB) rather than accepting the network call. The map
basemap is the same problem one layer up.

The use case is narrow and well-scoped: **plot event markers as dots on a world map with
zoom/pan and click-to-drill**. It is not interactive cartography. A street-level tile pyramid is
far more than the surface needs.

## Decision

**Render the basemap as a bundled vector world-outline (GeoJSON/TopoJSON) drawn by Leaflet's
native `L.geoJSON` layer, replacing the `L.tileLayer` CartoDB call. Zero runtime network
requests for any map asset.**

1. **Asset:** ship a **Natural Earth 1:110m Admin-0 countries** outline (public-domain), bundled
   into the frontend build as a static import. At 1:110m the file is ~100–250 KB (TopoJSON
   smaller); adequate fidelity for a world dot-map. No tiles, styles, glyphs, or sprites are
   fetched at runtime.
2. **Renderer:** keep **Leaflet** (already a dependency). Replace the `L.tileLayer(...)` call
   with an `L.geoJSON(worldOutline, …)` base layer styled from `--fw-*` dark-theme tokens
   (land/stroke fill), preserving the dark SOC console look (ADR-0028) without the CDN.
   `L.circleMarker` event markers, zoom/pan, the bounded 380px panel, the empty-state, and the
   A1/A2 layers to come are all preserved unchanged — they sit on top of the vector base exactly
   as they sit on tiles today.
3. **Attribution:** Natural Earth is public-domain (no attribution required); the CartoDB/OSM
   attribution control is removed with the tile layer.
4. **No new heavyweight dependency.** This mirrors ADR-0050's "draw to SVG, no graph framework"
   discipline: use the renderer we already have plus a static data file, not a new map engine.

## Alternatives considered

- **MapLibre GL + self-hosted/bundled vector tiles + local style** — modern, and the natural
  substrate for the deck.gl/H3 path that a *future* A3 (temporal campaign playback at high marker
  volume) may want. **Rejected for now:** it adds a new map engine and bundled vector-tile data
  (basemap weight, build complexity) to serve a use case a 110 KB outline covers. Premature; A3
  is explicitly post-launch and out of scope for MO. A 1:110m outline does **not** paint us into
  a corner — A3, if built, would be a deliberate, separately-scoped re-platform decision, and
  nothing here forecloses it.
- **Bundled raster tile set** — a full offline raster pyramid is hundreds of MB for global
  coverage; violates the lean-footprint mandate (#528 EARS-3). Rejected.
- **Accept the CDN egress with a disclosure** — rejected outright: contradicts the zero-egress
  claim on the showcase page; the whole point of #528 is to stop asserting and start enforcing
  (ADR-0047's "derived from enforced configuration, never asserted").

## Reasoning

The lightest approach that fully satisfies the requirement wins (ADR-0022 lean-footprint,
#528 EARS-3). A vector country outline is the right primitive for "honest dots on a world map":
it is public-domain, tiny, renders with the renderer we already ship, keeps the dark aesthetic,
and turns the attestation strip's zero-egress claim into a verifiable fact on the Analytics page.
It follows the in-repo precedent (ADR-0039 bundled-asset fix; ADR-0050 minimal-renderer
discipline) rather than introducing a new subsystem. The deck.gl/H3 evaluation remains a separate
future spike tied to A3 — out of scope here.

**Verification:** WHEN the Analytics page renders the map, the browser Network tab SHALL show
zero external requests for basemap tiles/styles/glyphs/sprites (the #528 EARS-1 gate).
