# ADR-019: Frontend Stack — React + react-jsonschema-form

**Date:** June 2026
**Status:** Accepted (supersedes ADR-0009)

**Decision:** Build the frontend rewrite on **React 18/19 + Vite + TypeScript +
`react-jsonschema-form` (rjsf) + Tailwind/shadcn**. Migration is a **clean rewrite
behind the existing API**, shipped **view-by-view with Settings/source-cards first**.
This resolves all three open questions left by ADR-0009 (framework, migration
strategy, component library).

**Alternatives considered:**
- **Angular 20 + ngx-formly / JSONForms-Angular** — strong schema-form story and
  enterprise-robust; rejected as the heaviest, most opinionated stack with the
  least idiomatic Chart.js/Leaflet integration — overkill for a solo-maintained
  SOC dashboard. The considered #2.
- **Vue 3 + JSONForms-Vue (Vuetify) / FormKit** — lightest *mature* option, gentle
  curve; rejected because its JSON-Schema→form layer is less battle-tested on
  complex conditional schemas than rjsf, and `vue-leaflet` trails `react-leaflet`.
- **Svelte 5 + `@sjsf/form`** — best DX and smallest bundle; rejected because the
  load-bearing schema-form layer rests on a single-maintainer, unofficial rjsf
  port with no JSONForms fallback — the wrong place to carry ecosystem risk.

**Reasoning:** The architectural bet of the UI (ARCHITECTURE.md, ADR-0010) is that
*the unified source card is rendered declaratively from each plugin's
`config_schema`*. That makes **Pydantic `model_json_schema()` → form** the
load-bearing requirement, with two hard cases already present in the contract:
the Suricata **local/remote toggle** (JSON Schema `if/then/else` / `dependencies`)
and **secrets** (`SecretStr` → password widget). `react-jsonschema-form` is the
de-facto reference implementation for exactly this pattern — native `if/then/else`,
custom widgets, ajv validation — and `@sjsf/form` (Svelte) is literally a port of
it. React also has the most mature `react-chartjs-2` / `react-leaflet` wrappers
(Chart.js + Leaflet are already the legacy dashboard's dependencies) and the
largest ecosystem and AI-assist coverage. A clean rewrite is preferred over an
incremental wrapper because the API surface is already complete and stable
(40+ endpoints) and the legacy dashboard is a monolithic vanilla-JS SPA being
replaced wholesale — so the incremental-mount advantage buys little.

**Component library:** Tailwind + shadcn/ui (headless Radix) to preserve the
existing bespoke dark SOC theme — the legacy CSS variables are already
Tailwind-shaped (`--bg`, amber `--accent`, severity colors). rjsf renders against
a Tailwind theme.

**Migration order:** Settings/source-cards (validates the schema-driven thesis) →
Network Logs → Analytics → Dashboard → AI Analysis.

**Consequences:**
- Introduces a Node/Vite build step and `frontend/` toolchain (none today).
- Plugins' `config_schema` JSON Schema output must stay rjsf-consumable; the
  Suricata reference plugin (ADR-0005) must emit `if/then/else` for its mode toggle.
- UI implementation is a later milestone; the backend M1 slice ships no UI.
