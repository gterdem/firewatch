# ADR-0037: Entity Slide-Over Panel — Right-Side Flyout Replaces the Centered IP Drill-Down Modal

**Date:** June 2026
**Status:** Accepted

**Context:** Walkthrough P1: the triage banner's "Drill down" button navigates to
`/logs?ip=…`, which silently does nothing (the route ignores the param) — and even fixed, full
navigation throws away the dashboard context mid-triage. Meanwhile P1, P3, P4 and P5 all converge
on the same interaction: *click an entity (IP today) anywhere → inspect it in place*. The existing
`IpDrilldownModal` (centered, 760px, progressive 3-fetch loading) already contains the right
content; its *presentation* (centered modal, single-page-only wiring) is the wrong primitive.
Maintainer chose the right-side slide-over over a centered modal explicitly.

**Decision:** One app-wide **entity slide-over panel**, anchored right, dashboard/page content
remaining visible behind it. It **evolves `IpDrilldownModal` — replace, not duplicate**: the modal's
proven internals (progressive loading: fast `/threats/{ip}` → slow `/detailed` + `/rules` →
`/threats/{ip}/events`; section order; RulePopup; security posture "text nodes only", ADR-0029 D3)
are extracted into section components and re-hosted in a generic slide-over shell. `LogsRoute`
migrates to the same component in the same change; the centered modal is deleted (no second IP view
left to drift).

Contract points:
1. **Every entity value is a click target.** A shared `ClickableIp` token component (mono-blue,
   keyboard-focusable) opens the panel. The triage banner, threat-actors rows, summary evidence
   chips, recommendation evidence links, and logs-table IPs all use it. (Hover micro-menu —
   Analyze · Filter · Copy — is a later additive on the same token.)
2. **Pivot breadcrumb.** The panel keeps an internal navigation stack (banner → IP → related
   event → …) with a visible trail; stepping back never loses the starting context. Opening an
   entity from inside the panel pushes; the trail header pops.
3. **Overlay semantics retained.** The page stays *visible* but inert: `role="dialog"`,
   `aria-modal="true"`, focus moved in and restored on close, Esc closes top-of-stack first
   (popup → panel), overlay click closes — i.e. the WAI-ARIA dialog pattern the modal already
   implements, in a right-anchored, full-height shell (~600–760px wide). A non-modal always-mounted
   panel is explicitly rejected for now (focus/screen-reader complexity, no demonstrated need).
4. **Entity-typed, IP-first.** The panel API takes an entity ref (`{kind: "ip", value}`); `kind`
   exists from day one so the P3 DDoS rollup can open `asn`/`cidr` group views later without
   reshaping the host.

**Module layout (sketch — implementer refines, does not monolith):**
- `frontend/src/components/entity/SlideOver.tsx` — generic right-panel shell: overlay, focus trap,
  Esc handling, width, breadcrumb header slot. No data fetching.
- `frontend/src/components/entity/EntityPanelProvider.tsx` + `useEntityPanel()` — app-level host:
  `openEntity(ref)`, the breadcrumb stack state, one mount point in the app layout.
- `frontend/src/components/entity/ClickableIp.tsx` — the entity token.
- `frontend/src/components/entity/ip/…` — sections extracted from `IpDrilldownModal`
  (score header + m-stats, AI assessment box, event timeline, recent logs); fetch logic in a
  `useIpDetails(ip)` hook so sections stay presentational.
- `IpDrilldownModal.tsx` is removed once `LogsRoute` is migrated.

**Alternatives considered:**
- **Keep the centered modal and reuse it from the dashboard** — rejected: blocks the dashboard
  during triage; Maintainer explicitly picked the slide-over; the industry pattern for entity inspection
  is the side flyout (Elastic Security flyout, Microsoft Sentinel entity panel, Defender side pane)
  precisely for context preservation.
- **Build a new slide-over alongside the modal** — rejected: two diverging IP views; the modal's
  internals are tested and security-reviewed — evolve them, don't fork them.
- **Full-page navigation per entity** (`/logs?ip=`) — rejected as the *primary* pattern: that is
  the broken P1 affordance; navigation loses triage context. (The shareable `?ip=` filter URL is
  still fixed separately — it's a legitimate deep-link, just not the click-an-entity behavior.)

**Reasoning:** This is the highest-leverage primitive in the walkthrough report: P1 (banner IP),
P3 (actor rows + future ASN groups), P4 (evidence chips), P5 (category bar → filtered events) are
all consumers. Building it once as the *first* frontend foundation issue means every subsequent
pane fix is mostly deletion of bespoke wiring. The breadcrumb pivot is cheap in a single-page React
app and is a real differentiator — the big SIEMs lose the trail across page navigations.

**Out of scope (this ADR):**
- The contents of new section types (ASN/CIDR group view — wave-2 issue; score-breakdown popover —
  ADR-0036).
- The hover micro-menu actions and any SOAR-side verbs (ADR-0033 seam unchanged; `investigate`'s
  *implementation* in the dashboard container switches from navigation to `openEntity`, which is
  exactly the container-owned change ADR-0033 reserves to the container).
- Mobile behavior (ADR-0017: desktop-first).

**References / standards consulted:**
- WAI-ARIA Authoring Practices — dialog (modal) pattern: focus management, Esc, `aria-modal`.
- Industry entity-inspection pattern: Elastic Security flyout, Microsoft Sentinel entity side
  panel, Microsoft Defender side pane — side flyout over center modal for context preservation.
- ADR-0033 (action seam; container owns verb implementations), ADR-0029 D3 (attacker-controlled
  fields rendered as text nodes only), ADR-0017 (desktop-first).
