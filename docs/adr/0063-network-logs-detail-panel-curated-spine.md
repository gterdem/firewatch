# ADR-0063: Network Logs Table — Curated "Spine" Columns + Per-Row Detail Panel (SIEM log-explorer pattern)

**Date:** June 2026
**Status:** Accepted

**Implements / backs:** Walkthrough Phase-2 finding — the `/logs` Network Logs table is *squished and messy at full data*, not only when columns are empty.
**Supersedes (in part):** ADR-0060 — see "ADR-0060 disposition" below. ADR-0060's structural empty-column hiding becomes **moot for the long-tail optional columns** that move into the detail panel.
**Relates to / honours:** ADR-0011 (faceted filters over tabs), ADR-0012 (ALERT badge), ADR-0015 (AI is additive-only / graceful degradation), ADR-0029 D2/D3 (read-row shape; attacker-controlled fields = text nodes only), ADR-0035 (RULE/AI provenance), ADR-0037 (entity slide-over panel), ADR-0048/0055 (network-depth + file-IOC/DNS SecurityEvent fields), ADR-0057 (Radix overlay primitives). **Composes with — does not replace —** `useColumnPriority` (viewport axis) and the cell popovers (CellDetailPopover).

---

## Context

`LogsTable.tsx` renders up to **12 columns inline** (Time · Source · Source IP · Dest Port · Severity · Action · Destination · Protocol · JA4 · Signature · HTTP Payload · DNS/DGA), with a per-row AI-verdict fold inside the Action cell. Under `tableLayout:fixed` the columns fight for a fixed width budget: JA4 alone wants 180px, Signature and Payload want ~192px each, and the AI verdict + provenance chips stack two lines inside Action. The result is **legibility loss even when every field is populated** — wide fingerprint/payload values truncate to noise and the eye cannot find the spine of the event (who · when · what · verdict).

Maintainer walked this during the Phase-2 live test and **rejected "hide empty columns" (ADR-0060) as the remedy**: the data *might* exist later, so the table must be designed for the **full-data** case, not the sparse one. The approved direction is the **SIEM log-explorer pattern** used by Splunk *Events* and Elastic *Discover*: a small curated set of always-inline columns, and a **per-row expand → detail view** that carries the complete field set for that one event.

### Industry-standard grounding

- **Splunk Events view** — a fixed `_time` + `_raw` spine with selectable "interesting/selected fields"; the full field set for an event lives in the **expanded event row**, not in columns. (https://docs.splunk.com/Documentation/Splunk/latest/Search/Eventsviewer)
- **Elastic Discover / Security** — a compact document table with user-chosen columns and a **per-row "expand document" flyout** that lists every field grouped/searchable; the *Security* app reuses the same right-side **entity/event flyout** for context preservation. (https://www.elastic.co/guide/en/kibana/current/discover.html)
- **Microsoft Sentinel / Defender** — results grid + a per-row **details pane**; entity inspection is a side pane, exactly the primitive FireWatch already adopted in ADR-0037.
- **OCSF / ECS** — model an event as a **wide, mostly-optional attribute set**; only a few attributes are *Required/Recommended*, the rest are *Optional* per class/profile (https://schema.ocsf.io/ 1.8.0; https://www.elastic.co/guide/en/ecs/current/). The "few required + long optional tail" shape is precisely a *small spine + everything-else-in-a-detail-view* presentation. This ADR is the UI realisation of the same shape ADR-0060 cited.

Every reference converges: **a few spine columns inline, the full record in a per-row detail surface.** That is the decision.

## Decision

Redesign the Network Logs table around a **curated spine + per-row detail panel**.

### D1 — Curated "spine" column set (always inline; never hidden)

Seven columns form the spine. They answer *when · what source · who · what happened · how bad · what verdict · what rule* — the SOC triage scan-line — and they never participate in either hiding axis (`never: true` for viewport priority; out of scope for structural hiding):

| # | Column | Field(s) | Rationale |
|---|--------|----------|-----------|
| 1 | **Time** | `timestamp` | Anchor of every log scan; compact `MM-DD HH:mm:ss`. |
| 2 | **Source** | `source_type` (SourceBadge) | Which plugin/sensor — disambiguates multi-source rows (ADR-0016). Narrow badge. |
| 3 | **Source IP** | `source_ip` (+ inline geo, ClickableIp) | The primary entity; click opens the ADR-0037 panel. The single most-pivoted cell. |
| 4 | **Action** | `action` (Badge) | ALLOW/BLOCK/DROP/ALERT — the disposition (ADR-0012). |
| 5 | **Severity** | `severity` (Badge) | Triage ordering. |
| 6 | **Signature** | `rule_name → signature → rule_id` | The "what fired" — the most information-dense readable cell; keeps its CellDetailPopover. |
| 7 | **AI verdict** | derived from `threatMap` | The triage recommendation chip + RULE/AI provenance — **promoted out of the Action cell into its own narrow column** so Action stops being two-line (see D5). Empty when no score (ADR-0015). |

A trailing **expand affordance** (chevron) column is added at the row's leading or trailing edge (D2).

**Everything else is long-tail** and moves to the detail panel (D3): `destination_ip`, `destination_port`, `protocol`, `tls_ja4`/`tls_ja4s`/`tls_sni`/`tls_version`, `dns_query`/`dga_score`, HTTP `payload_snippet`, `category`, `geo_*`, `source_id`, `raw_log`, and any native fields.

> Judgment call recorded: **HTTP Payload** and **DNS/DGA** were inline today. They are demoted to the panel because (a) payload is a wide, wrapping, attacker-controlled blob that dominates table width, and (b) DGA is a derived signal better shown with its glass-box sub-scores in the panel. The Signature cell remains the inline "what happened" anchor; payload/DNS are one expand away. If field-walkthrough shows DNS is needed inline for a DNS-heavy deployment, a **column chooser (D7, phase-2)** can pin it back — without re-widening the default.

### D2 — Interaction: inline row-expand (not a drawer)

Clicking the row's chevron (or the row body, excluding the IP button and Signature trigger) **expands an inline detail region directly beneath the row** (an accordion `<tr>` spanning all columns), and the chevron rotates. This is chosen over a side drawer:

- **Rationale for inline-expand over side drawer.** The **right-side slide-over is already owned by ADR-0037 for *entity* inspection** (IP → score/AI/timeline/recent-logs, with a pivot breadcrumb). Using a second right drawer for *event* detail would collide visually and semantically with the entity panel and force a focus-trap contest. Inline expand keeps **event** detail in the table flow (Splunk Events / Elastic Discover expanded-row idiom), preserves the analyst's scroll position and surrounding rows, and lets **multiple rows** be expanded for side-by-side comparison. The entity panel stays the place you go to inspect the *IP*; the row-expand is where you read the *event*.
- Keyboard: Enter/Space on the focused chevron toggles; Esc collapses the expanded row. One row's expansion is independent of others (no single-open invariant — comparison is a feature).
- The expanded region is `role="region"` with an `aria-label` referencing the row's time + source IP.

### D3 — Detail-panel layout: grouped, text-only, zero-egress

The expanded region renders the **full field set for that event**, grouped into labelled sections (a section is omitted entirely when it has no populated fields — honest absence, never a fabricated "—" wall):

- **Identity** — `id`, `timestamp` (full ISO + local), `source_type`, `source_id`, `category`.
- **Network** — `source_ip` (+ geo_city/geo_country, ClickableIp), `destination_ip`, `destination_port`, `protocol`.
- **TLS / JA4** — `tls_ja4`, `tls_ja4s`, `tls_sni`, `tls_version`.
- **DNS** — `dns_query`, `dga_score` (with the glass-box note that DGA is a local RULE heuristic, ADR-0035).
- **HTTP** — `payload_snippet` / `http_payload` / `payload` (full, wrapping, copy-able).
- **Detection** — `rule_name`, `rule_id`/`sid`, `signature`, `severity`, `action`.
- **Geo** — `geo_city`, `geo_country`, and (when present on the row) `asn`/`as_name`.
- **Provenance / Raw** — `raw_log` (collapsed by default; expand to view; **Copy**). Labelled "attacker-controlled — shown verbatim."

Field rows use a label/value grid; every value is a **React text node** (ADR-0029 D3 — `raw_log` and native fields are attacker-controlled; **no `dangerouslySetInnerHTML` anywhere**). Each long value (payload, raw_log, fingerprints) gets a **Copy** affordance — reusing the `CopyButton` pattern already in `CellDetailPopover.tsx`. No field triggers any network call; geo/asn are server-joined values already on the row (zero-egress, consistent with ADR-0047/0039). A **"View in Network Logs →"**-style deep-link is *not* added here (we are already in Network Logs); instead, value chips that have a facet (action, protocol, signature, JA4, dns) MAY offer "Filter to this" applying the existing `LogsFilter` facet — phase-2, see D7/Out-of-scope.

### D4 — Coexistence with existing surfaces

- **CellDetailPopover (Signature / Payload cell popovers).** The **Signature cell keeps its `RuleCellTooltip` → `CellDetailPopover`** (peek-then-pin, Copy, deep-link) — it is inline and remains the fast path. **Payload's inline cell + `PayloadCellTooltip` is removed** (payload leaves the table), so its popover is no longer mounted from the table; the full payload now lives in the detail panel's HTTP section. `CellDetailPopover` itself is unchanged and still used by the Signature cell and by IpPanel "Recent logs" (#613) — no shared-component change required.
- **Source-IP → entity panel (ADR-0037).** Unchanged and orthogonal. The Source IP cell (spine) and the detail-panel Network section both render `ClickableIp`, which opens the **entity slide-over**. Row-expand (event detail, inline) and entity panel (IP detail, side flyout) are deliberately different planes: one is about *this event*, the other about *this actor*. Clicking the IP never toggles the row; toggling the row never opens the entity panel.
- **AI-verdict chip (ADR-0015 / ADR-0035).** The per-row verdict + provenance chip **moves from a fold inside Action to its own spine column (D1 #7)**. Behaviour is identical: derived from `threatMap`, absent when no score, RULE vs AI provenance via `ProvenanceChip`, score/confidence mono text. The detail panel does **not** duplicate the verdict (the entity panel owns the deep AI assessment); the spine chip is the only per-row AI surface. Graceful degradation unchanged (ADR-0015): no `threatMap` → empty column cell, never an error.

### D5 — Action cell de-folds

Today the Action `<td>` stacks the action badge (line 1) and the AI verdict + provenance chip (line 2), forcing `verticalAlign:top` and vertical sprawl. With the verdict promoted to its own column (D1 #7), **Action becomes a single-line badge cell**, and AI-verdict becomes a single-line chip cell. This directly removes the multi-line row height that contributes to the "squished/messy" feel.

### D6 — ADR-0060 disposition (partial supersession)

ADR-0060 (`SourceMetadata.produces` + structural empty-column hiding) was built to stop *long-tail optional columns* (Destination, Protocol, Dest Port, JA4, DNS/DGA) from showing perpetually empty. **All five of those columns now move into the detail panel (D3)** and are no longer inline — so **structural hiding of them is moot**: there is nothing inline to hide.

Decision:
- **The frontend structural-hiding mechanism is retired for the logs table.** `useStructuralColumns` is no longer consumed by `LogsRoute`/`LogsTable`; the `structurallyAbsent` prop, `HiddenFieldsChip` toolbar, and the `+N fields not produced` chip are removed from the table. None of the spine columns are optional, so no inline column needs structural hiding.
- **ADR-0060's *backend* contribution is retained and NOT superseded.** `SourceMetadata.produces`, its `model_fields` validation (D1/D2), `GET /sources/types.produces`, and `GET /logs/stats.present_source_types` (D3) remain valid, honest capability metadata with independent value (export/OCSF mapping, future column chooser availability hints, source-capability docs). Only ADR-0060 **D4 (the frontend orthogonal-axis consumption)** is **superseded by this ADR** for the logs table.
- ADR-0060's README status becomes **"Accepted (D4 superseded by ADR-0063)"** — the metadata/backend decision stands; the UI hiding axis is replaced by the detail panel. We do **not** require any value-based-hiding work (explicitly out of scope — the panel removes the need).

`FIELD_NOTES` / `COLUMN_CANONICAL_FIELDS` copy in `fieldAvailability.ts` is repurposed: the detail panel reuses the honest "why might this be empty for this source" notes as section/field hints, so the discoverability ADR-0060 added is preserved without the inline chip.

### D7 — Column chooser is phase-2, not core

A **user-pinned column chooser** (let an analyst promote a long-tail field — e.g. JA4 or DNS — back into the inline table, Splunk "selected fields" / Discover "add column") is a **follow-up**, not part of this redesign. The default ships with the 7-column spine. When built, `SourceMetadata.produces` (retained per D6) feeds the chooser's "which fields can appear for the present sources" availability list — that is the lasting value of the retained backend metadata.

## Standard alignment & deviations

- **Alignment.** Spine-columns + per-row expanded detail is the Splunk Events / Elastic Discover idiom, and the OCSF/ECS "few required + long optional tail" shape rendered honestly.
- **Deviation recorded.** We choose **inline row-expand** for *event* detail rather than a side flyout, deviating from Elastic's *document* flyout. Justification: the right-side flyout slot is already FireWatch's **entity** surface (ADR-0037); a second right drawer would collide, and inline-expand uniquely enables multi-row comparison and scroll-position preservation. The side flyout remains the right primitive for *entity* (IP/ASN) inspection — we deviate only for *event* detail, deliberately.

## Blast radius

- **Frontend only.** No backend field is required that is not already on the `/logs/paginated` row (ADR-0029 D2): every detail-panel field (`destination_ip`, `protocol`, TLS quad, `dns_query`/`dga_score`, payload aliases, geo, `source_id`, `raw_log`, native rule fields) is already present or accessible via native-field fallback. **No API/SDK/contract change. No golden-oracle change** (no scoring/normalization touched).
- **Removed from the table surface:** inline Payload/DNS/Destination/Protocol/DestPort/JA4 columns; `structurallyAbsent` prop; `HiddenFieldsChip` mount; `FieldAvailabilityLegend` header "?" (its copy migrates into the panel). `PayloadCellTooltip` is no longer mounted by the table.
- **Added:** an expand affordance + an expanded-row detail component (new module, D-layout below); an AI-verdict spine column.
- **Retained:** `CellDetailPopover` (Signature cell + IpPanel), `ClickableIp` + entity panel (ADR-0037), `useColumnPriority` (now trivial — 7 never-hide columns, but kept for the chooser/phase-2 and responsive narrowing of the chip column).

## Module layout (sketch — implementer refines, does not monolith)

The expanded-row detail is architecturally a multi-section renderer; do **not** fold it into `LogsTable.tsx`:

- `frontend/src/components/logs/detail/LogDetailPanel.tsx` — the expanded-row container: takes one `LogEntry`, renders the section list, owns nothing but layout.
- `frontend/src/components/logs/detail/sections.ts` — the **declarative section model**: an ordered list of `{ id, title, fields: Array<{ label, accessor, mono?, copyable?, hint? }> }`; the single source of truth for grouping (Identity · Network · TLS/JA4 · DNS · HTTP · Detection · Geo · Provenance/Raw). Keeps grouping out of JSX so it is testable and reorderable.
- `frontend/src/components/logs/detail/DetailField.tsx` — one label/value row; text-node rendering, optional Copy (reuse `CopyButton` pattern), `—`/omitted handling.
- `frontend/src/components/logs/detail/RawLogField.tsx` — the collapsed-by-default `raw_log` viewer + Copy.
- `frontend/src/components/logs/useRowExpansion.ts` — `Set<rowId>` toggle state + keyboard handlers; allows multiple expanded rows.
- `LogsTable.tsx` shrinks to the 7 spine columns + a chevron cell + the conditional expanded `<tr>`; it imports `LogDetailPanel`.

## Alternatives considered

- **Keep all columns; just hide empty ones (ADR-0060 as-is)** — *rejected by Maintainer.* Band-aid: fails at full data; the data "might exist." This ADR is the approved replacement for the inline long tail.
- **Value-based per-page hiding (ADR-0060 Option A)** — *rejected* (already rejected in ADR-0060; the panel removes any need for it — explicitly not in scope).
- **Side-drawer for event detail (Elastic document flyout)** — *rejected* for *event* detail: collides with the ADR-0037 entity flyout slot; loses multi-row comparison and scroll position. Adopted only for *entity* inspection, where ADR-0037 already owns it.
- **Horizontal scroll the 12 columns** — *rejected.* The table already does this as a fallback and it is exactly the "squished/messy" experience under report.
- **Fewer spine columns (e.g. drop Source or Severity)** — *rejected.* Source disambiguates multi-source rows (ADR-0016); Severity is the triage sort key; both are scan-line essentials. Seven is the floor that keeps the SOC scan-line intact.

## Reasoning

Designing for full data means accepting that an event is a **wide record with a narrow triage spine**. The legible answer — used by every major SIEM and matching the OCSF/ECS required-vs-optional shape — is to render the spine inline and put the full record one expand away. This removes the width contest at its root (it does not paper over empty cells), de-folds the Action cell, keeps the entity slide-over (ADR-0037) and Signature popover (ADR-0029/#329) exactly where analysts already expect them, and is **frontend-only** with **no contract or golden-oracle change**. ADR-0060's honest capability metadata survives where it has lasting value (export, a future column chooser); only its now-redundant inline-hiding UI axis is superseded.

## Consequences

- The Network Logs table ships with a 7-column spine + per-row inline detail panel; legible at full data, never squished.
- ADR-0060 D4 (frontend structural hiding) is superseded for the logs table; `useStructuralColumns`/`HiddenFieldsChip`/`structurallyAbsent` are removed from the table surface. ADR-0060's SDK/API metadata is retained.
- A column chooser (D7) and "Filter to this value" chips (D3) are explicit phase-2 follow-ups.
- No backend, SDK, contract, or golden-oracle change.

## References

- **Splunk Events viewer** — https://docs.splunk.com/Documentation/Splunk/latest/Search/Eventsviewer — spine + expanded-event field list.
- **Elastic Discover** — https://www.elastic.co/guide/en/kibana/current/discover.html — compact doc table + per-row expand-document flyout; selectable columns.
- **OCSF schema** — https://schema.ocsf.io/ (1.8.0) — required/recommended/optional attribute model (few-required, long-optional-tail).
- **Elastic Common Schema** — https://www.elastic.co/guide/en/ecs/current/ — populate the subset you have; absence is meaningful.
- **WAI-ARIA Authoring Practices — Disclosure / accordion** — expand affordance keyboard + `aria-expanded` semantics.
- **Internal:** ADR-0011, ADR-0012, ADR-0015, ADR-0016, ADR-0029 (D2/D3), ADR-0035, ADR-0037, ADR-0039/0047 (zero-egress), ADR-0048/0055 (field set), ADR-0057, ADR-0060 (D4 superseded; SDK/API retained).
