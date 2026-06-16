# ADR-0038: Global Source-Scope Seam — `SourceScopeContext` + `sources=` Read-API Parameter

**Date:** June 2026
**Status:** Proposed (design settled now; **build deferred post-release** — phases tracked as
#286/#287/#288, all outside milestone MH per the release roadmap)

**Origin:** walkthrough part-3 Problem 14.3 — the header "All Sources" dropdown is a dead control.
Maintainer's intent (approved via the product-strategist recommendation): an **app-wide multi-select
source scope** — select Azure WAF only and *every* tab shows only Azure WAF data; select all (the
default) and everything shows. Interim honesty fix: the dead dropdown is removed now (#282).

**Relates to:** ADR-0029 (read/query API contract — the param rides every read endpoint),
ADR-0016 (multi-source-per-type; `source_type`/`source_id` identity), ADR-0032 (header health
display; out-of-scope dimming), ADR-0035 (provenance — extended to scope), ADR-0026 (no user
model; scope persistence is local/URL).

---

**Decision:**

1. **One frontend seam.** A single `SourceScopeContext` (React context, `lib/sourceScope/`),
   **URL-param-backed** (`?sources=azure_waf,suricata:vm-target`) so any scoped view is shareable
   and bookmarkable. Default (param absent) = all sources. Every data hook consumes the context;
   no page invents its own picker.
2. **One backend parameter.** An optional `sources=` filter on **every** ADR-0029 read endpoint
   (`/stats`, `/threats*`, `/logs/paginated`, analytics). Values are `source_type` keys (= all
   instances of that type) or `source_type:source_id` instance refs (ADR-0016 identity). Omitted ⇒
   unscoped, byte-identical to today (golden-safe). Filtering is **server-side** because cursor
   pagination and aggregates are server-computed (ADR-0029) — client-side filtering would lie
   about totals. Unknown refs contribute an empty scope (honest empty state), not an error.
3. **Scope honesty riders.** Analytic artifacts (AI summary, triage, recommendations) computed on
   a scoped set are stamped **"scoped to N of M sources"** — ADR-0035 provenance applied to scope,
   so a partial view can never masquerade as the full picture. Header health dots **dim** for
   out-of-scope sources (the header shows your blind spot) while keeping true health on hover
   (ADR-0032 display).
4. **Phased build (post-release):** **A** — ratify this ADR + `SourceScopeContext` + `sources=`
   on the read API (#286); **B** — header multi-select picker + Dashboard/Logs wired (#287);
   **C** — full page coverage + saved scopes + scope provenance + dot dimming (#288).

**Alternatives considered:**
- **Per-page data-view pickers (Elastic model)** — rejected: scope diverges between tabs; Maintainer's
  requirement is explicitly whole-app ("all tabs").
- **Query-side scoping (Splunk SPL model)** — rejected: no persistent, shareable scope UX; pushes
  filter syntax onto the analyst on every page.
- **Client-side filtering of fetched data** — rejected: pagination, counts and aggregates are
  server-computed (ADR-0029); client filtering misrepresents totals and breaks cursors.
- **Wire the existing dropdown single-select to the Logs page only (strategist's interim B)** —
  rejected as interim: a single-page single-select contradicts the approved app-wide multi-select
  model and would train users on throwaway behavior; removal (#282) is the honest stopgap.

**Reasoning:** The closest incumbent precedent is Datadog's **multi-value template variables**
(whole-surface scoping with saved views — https://docs.datadoghq.com/dashboards/template_variables/);
Elastic offers only per-page data-views, Splunk pushes scoping into the query — so a persistent
app-wide multi-select is both feasible (one context + one param) and a genuine differentiator.
It is architect-owned because it is cross-cutting: every read endpoint and every page touches the
seam; an uncoordinated version would fragment into per-page filters. It is **deferred** because it
is L-sized and must not gate the walkthrough → open-source sequence (release roadmap); the design
is fixed now so the interim removal (#282) and the health display (#281) point at a settled target.
