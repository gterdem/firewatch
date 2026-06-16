# ADR-0060: Plugin-Declared Field-Production Capability — `SourceMetadata.produces` (the structural axis for `/logs` empty-column hiding)

**Date:** June 2026
**Status:** Accepted

**Implements / backs:** Issue #664 (Option-B structural empty-column hiding, WS3).
**Contract change:** PLUGIN_CONTRACT.md — an **additive** `SourceMetadata` field (architect-owned; additive-growth pattern of ADR-0048/0055).
**Relates to / honours:** ADR-0016 (`type_key` ≈ source identity), ADR-0020 (lightweight-OCSF canonical schema — `SecurityEvent` is the carrier), ADR-0025 (no plugin DDL — `produces` is metadata, not schema), ADR-0029 D1 (the read/query surface that serves it), ADR-0034 (additive-`SourceMetadata` precedent set by `actions`), ADR-0048/0055 (the additive flat-field deviation rationale this reuses). **Composes with — does not replace —** the viewport `useColumnPriority` axis.

---

## Context

On the `/logs` page, a column for a field a source never emits (e.g. `destination_ip` / `protocol` / `destination_port` for an L7-only Azure WAF source) shows up perpetually empty, adding noise. Maintainer approved auto-hiding such columns, and explicitly chose the **structural** mechanism (Option B) over the **value-based** one (Option A):

- **Option A (value-based — rejected by Maintainer).** Hide a column when every visible *row* is falsy for it. This mistakes **Azure WAF's real `destination_port = 0`** for "empty", and causes **flicker** as you paginate/filter (per-page emptiness is unstable).
- **Option B (structural — chosen).** Hide a column when **no source present in the current scope can produce that field *by design***. Capability is a fixed property of the *source*, so the hidden set is stable across pages and never inspects a value.

For Option B the system needs a declared, per-plugin answer to "which canonical fields can this source emit?" — which does not exist today. `SourceMetadata` (`firewatch_sdk/metadata.py`) carries `type_key`, `display_name`, `version`, `flavor`, and the ADR-0034 `actions` tuple, but nothing about field production.

### Industry-standard grounding

- **OCSF** models field presence as **profiles + requirement levels** (Required / Recommended / Optional) *per class* — absence is a schema property of the class/profile, **not** a per-record null (https://schema.ocsf.io/, 1.8.0). Our `SecurityEvent` is the lightweight-OCSF carrier (ADR-0020); declaring which canonical fields a source *produces* is FireWatch's analogue of an OCSF profile's optional-attribute set.
- **ECS** is "populate the subset you have; absence is meaningful — **never fabricate**" (https://www.elastic.co/guide/en/ecs/current/) — which already underwrites PLUGIN_CONTRACT's "never fabricate transport fields you do not have."

Both standards say the same thing: **presence/absence is a declared schema/profile property of the source, not an inferred property of a row.** That is exactly Option B, and it is why Option A is the wrong abstraction.

## Decision

Add an **additive, defaulted** field to `SourceMetadata`:

```python
produces: frozenset[str] = frozenset()   # canonical SecurityEvent field names this source can emit
```

### D1 — Members are canonical `SecurityEvent` field names, validated fail-closed

Each member is a `SecurityEvent` field name (e.g. `"destination_ip"`, `"protocol"`, `"destination_port"`, `"tls_ja4"`, `"dns_query"`). Members are validated against `SecurityEvent.model_fields` **at metadata-build time**; an unknown member (typo) **fails construction**. This keeps a silent typo from quietly hiding the wrong column.

### D2 — Empty `produces` means "produces everything" (the backward-compatible default)

The default empty set means **"does not declare / unknown"**, which is treated as **produces-all** → hides **nothing**. Every existing plugin is therefore **byte-compatible** and behaves identically to today. A source **opts in** to column-hiding by declaring its set. **Declaring is the honest, better-UX path; silence is deliberately permissive** (hide nothing rather than risk hiding a column a source actually fills). New plugins *should* declare `produces` for best UX but are **not required** to.

In this issue's PRs (plugin metadata only — zero core edits, area:source):
- **Azure WAF** declares its L7 set **minus** `destination_ip` / `protocol` / `destination_port`.
- **Suricata** declares the broad L3–L7 set.

### D3 — Two read-surface carriers (additive, ADR-0029 D1)

The frontend needs (a) each plugin's produced-field set and (b) which source types are actually present in the current filtered scope:

- **`GET /sources/types`** gains a `"produces": sorted(meta.produces)` key per plugin entry (additive; resilient-discovery posture unchanged).
- **`GET /logs/stats`** gains `present_source_types: list[str]` — **DISTINCT `source_type` over the *filtered* scope** the table binds (one query, already filter-scoped). Page-derived presence is the documented fallback only, since it would reintroduce per-page instability.

### D4 — Frontend consumption: a structural axis orthogonal to viewport priority

The UI **unions** the produced-field sets of the sources actually present and hides any column **no present source can emit** — a structural, **value-blind**, flicker-free computation. It **composes** with the existing `useColumnPriority` (viewport/space) axis: `visible(col) = priority.has(col) AND NOT structurallyAbsent(col)`. The two axes stay orthogonal — *priority = space, absence = structural capability* — and neither replaces the other. A "+N fields not produced by this source" chip surfaces the hidden columns honestly, each with its existing `FIELD_NOTES` note (discoverability without fabrication).

## Standard alignment & deviations

- **Alignment.** `produces` is FireWatch's flat analogue of an OCSF profile's optional-attribute set / an ECS "subset you populate" — presence declared as a property of the *source*, exactly as both standards prescribe.
- **Deviation recorded.** We declare `produces` as a **flat `frozenset` of canonical field names on the plugin**, not full OCSF profiles or ECS field-reference documents. Justification: identical to the ADR-0048/0055 flat-scalar deviation — `SecurityEvent` is already a flat, lightweight-OCSF carrier; a flat field set matches that shape, is trivially validated against `model_fields`, and avoids importing OCSF's profile machinery for zero added fidelity at our scale. The full OCSF mapping, if ever needed, lives at the export boundary (ADR-0040), not in plugin metadata.

## Blast radius

- **SDK** — one additive, defaulted field on `SourceMetadata`; no existing field changes. **No PLUGIN_CONTRACT break** (additive changelog entry, ADR-0048/0055 pattern).
- **Plugins** — Suricata + Azure WAF declare `produces` (metadata only, zero core edits); all other plugins keep the empty default (produces-all → no hiding) and opt in later.
- **API** — additive `produces` key on `/sources/types`; additive `present_source_types` on `/logs/stats`.
- **Frontend** — a new structural-absence hook composing with `useColumnPriority`; a hidden-fields chip. No per-source UI (modular-UI rule).
- **Golden oracle** — untouched (no scoring/normalization change; metadata + read-shape only).

## Alternatives considered

- **Option A — value-based per-page hiding** — *rejected by Maintainer.* Mistakes real falsy values (Azure WAF `destination_port = 0`) for "empty" and flickers as you paginate/filter. Inspecting values is the wrong abstraction; presence is a property of the source, not the row (OCSF/ECS).
- **Derive presence from the current page's rows instead of `/logs/stats`** — *rejected as the primary path* (documented fallback only). Page-derived presence reintroduces the per-page instability Option B exists to avoid.
- **Make `produces` required (no produces-all default)** — *rejected.* Would break every existing plugin and force churn on plugins that have no column-hiding need. The permissive default keeps modularity's "zero core edits, zero forced churn" promise; declaring is opt-in, honest, and better-UX.
- **Full OCSF profiles / ECS field-reference docs in metadata** — *rejected.* Over-engineered for a flat lightweight-OCSF schema; the flat field set is the right-sized analogue (same deviation rationale as ADR-0048/0055).

## Reasoning

The honest, stable way to hide a perpetually-empty column is to know what a source *can* produce — a declared schema property, exactly as OCSF and ECS model presence — not to guess from row values. A defaulted `frozenset` field makes that capability explicit, validates it fail-closed against the real schema, and stays fully backward-compatible (empty = produces-all). Surfaced through two additive read keys, it gives the UI a structural, value-blind, flicker-free hiding axis that composes cleanly with the existing viewport-priority axis — closing #664 without touching scoring, normalization, or the golden oracle.

## Consequences

- Enables Option-B structural empty-column hiding (#664) end-to-end.
- PLUGIN_CONTRACT.md gains an additive changelog entry for `SourceMetadata.produces` (the ADR-0034/0048/0055 pattern).
- New plugins are *encouraged* (not required) to declare `produces`; absence remains permissive (produces-all).
- Composes with — never replaces — `useColumnPriority`; the two axes remain orthogonal.

## References

- **OCSF profiles & requirement levels** — https://schema.ocsf.io/ (1.8.0) — presence as a class/profile property, not a per-record null; backs the structural model.
- **Elastic Common Schema (ECS)** — https://www.elastic.co/guide/en/ecs/current/ — "populate the subset you have; never fabricate"; backs "declared, never inferred."
- **Internal:** ADR-0016 (source identity), ADR-0020 (lightweight-OCSF carrier), ADR-0025 (no plugin DDL), ADR-0029 D1 (read surface), ADR-0034 (additive-`SourceMetadata` precedent), ADR-0048/0055 (additive flat-field deviation rationale), ADR-0040 (OCSF export boundary). Backs Issue #664.
