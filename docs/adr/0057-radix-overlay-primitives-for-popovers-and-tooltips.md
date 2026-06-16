# ADR-0057: Design-System Overlay Primitives — Adopt Radix Popover/Tooltip, Retire the Hand-Rolled Positioner

**Date:** 2026-06-14
**Status:** Proposed

**Relates to:** ADR-0019 (frontend stack — React + RJSF/shadcn), ADR-0028 (frontend layout/toolchain),
MD (SOC Design System v2). Implements the product-strategist's CR1/CR2 verdicts in
`scratch/phase-2-tests/test-dashboard-opus.md` (the Phase-2 Dashboard walkthrough), and provides the
design-system home for the existing **#289 cell-popover sweep**.

---

## Context

Three places in the Dashboard render anchored overlays — the Recent-logs `payload-cell-detail-popover`,
the Score-Evidence Payload cell (today a raw native `title=`), and the cells enumerated in the deferred
**#289** sweep. They are served by a **hand-rolled positioner**, `useTooltipPosition`
(`frontend/src/components/ds/core/useTooltipPosition.ts`): it portals to `document.body`, estimates
content height with a constant (`TOOLTIP_ESTIMATED_HEIGHT = 80`), and manually computes flip-above /
flip-below and a right-edge clamp. It works, but it re-implements collision-aware positioning that the
ecosystem already solves, and the height *estimate* is a standing source of the very overlap bugs it
has been patched for (see the issue-#369 note in the file header).

The Phase-2 walkthrough surfaced two overlay defects (CR1: Score-Evidence Payload needs a real,
keyboard-reachable, WCAG-1.4.13-dismissible tooltip instead of native `title`; CR2: the recent-logs
popover opens *below* and reads as "in place"). The strategist endorsed adopting Radix as the durable
fix for both.

**Grounding correction (verified against `frontend/package.json`):** the strategist note assumed Radix
Popover/Tooltip are "already in the stack via shadcn." They are **not**. Only `@radix-ui/react-label`
and `@radix-ui/react-slot` are installed; there is no `components/ui/` shadcn directory and no
Floating-UI / Popper dependency. Radix Popover/Tooltip and their Floating-UI-based positioning are a
**genuine new dependency**, not a free pickup. This raises the cost of doing the migration *inside* the
two walkthrough CRs and is the central reason for the staging decision below.

## Decision

1. **Direction: standardize anchored overlays on Radix UI primitives**
   (`@radix-ui/react-popover` for click-pinned reference content like payload cells;
   `@radix-ui/react-tooltip` for hover/focus hints), styled per the SOC Design System (MD). Radix's
   positioning is Floating-UI-backed and gives `side`/`align` + collision-aware `flip`/`shift`/`size`
   middleware out of the box — the exact behavior `useTooltipPosition` hand-codes. Radix also supplies
   the WAI-ARIA wiring (focus management, `Escape`/outside-click dismiss, hoverable content) that a
   native `title` and the current div-portal cannot.

2. **Stage the adoption — do NOT block the two walkthrough CRs on the migration.**
   - **Tactical now (in CR1 / CR2):** ship correct behavior with the tools already in tree.
     - CR1: replace the Score-Evidence Payload native `title=` with the *existing* portal-popover
       pattern (the same one Recent-logs uses), making it keyboard-reachable — i.e. reach parity with
       the rest of the Dashboard now, not a regression to native tooltips.
     - CR2: the recent-logs popover flips to **above** by passing the positioner's already-present
       `preferAbove` option (`useTooltipPosition` exposes it; default is below). Right-edge clamp is
       already implemented. No new dependency.
   - **Migration later (folded into #289):** the full swap of the hand-rolled positioner for Radix
     Popover/Tooltip across all overlay cells is scoped onto the existing **#289 cell-popover sweep**,
     which already owns "remaining cells per the DS rule." #289 is re-scoped from "sweep the remaining
     cells with the current pattern" to "introduce the Radix overlay primitive and migrate ALL overlay
     cells (payload, evidence payload, source-badge health, health-card sparkline) to it, then delete
     `useTooltipPosition`." That is a ~Design-System-wide refactor and is correctly post-release.

3. **`useTooltipPosition` is retained until #289 lands, then deleted.** No new call sites should be
   added to it beyond the CR1/CR2 tactical fixes; new overlays after this ADR is accepted should wait
   for the Radix primitive (or, if urgent, reuse the existing pattern and add a `// TODO(#289)` marker).

4. **Honesty / a11y invariants carry over unchanged.** Overlays still render attacker-derived payload
   text as inert text nodes only (ADR-0029 D3 — no raw hex, no HTML injection path); the Radix content
   must keep `Escape`-dismiss + outside-click close and be hoverable (WCAG 2.2 SC 1.4.13).

## Alternatives considered

- **Do the Radix migration inside CR1/CR2 (strategist's first framing).** Rejected as the *default*
  path: it makes two small walkthrough polish fixes depend on adding a dependency and refactoring
  ~3–20 overlay sites — exactly the "blocked on a ~20-component refactor" risk the coordinator
  flagged. The tactical fixes are cheap (`preferAbove` flag; reuse existing popover) and unblock the
  first-impression Dashboard pass; the migration earns its own tracked sweep.
- **Floating-UI directly (no Radix), keep our own components.** Rejected: we'd still hand-build the
  ARIA/focus/dismiss layer that Radix gives for free, and ADR-0019 already commits us to the
  Radix/shadcn family — staying in it is lower long-term cost than a second overlay paradigm.
- **Keep `useTooltipPosition` indefinitely (just fix bugs as they appear).** Rejected: the
  content-height *estimate* is a structural defect (it cannot know rendered height), and we keep
  paying for collision math the platform solves. Tech-debt with a recurring bug tail.
- **Native `title` everywhere (cheapest).** Rejected on WCAG 1.4.13: native `title` is not
  dismissible, not hoverable, has uncontrolled delay, and no keyboard path — the precise reason CR1
  was filed.

## Reasoning

- **Standards:** WAI-ARIA Authoring Practices Guide — Tooltip & Dialog/Popover patterns (focus,
  `Escape`, outside-click); WCAG 2.2 SC 1.4.13 *Content on Hover or Focus* (dismissible, hoverable,
  persistent) — the explicit gap in the native-`title` Payload cell. Radix UI implements these
  patterns and is Floating-UI-backed (the maintained successor to Popper.js) for collision-aware
  placement. Staying within the Radix/shadcn family is consistent with ADR-0019.
- **Sequencing:** the split keeps the Phase-2 first-impression Dashboard fixes shippable now while
  giving the cross-cutting overlay refactor a real, post-release home (#289) rather than smuggling a
  dependency add into a polish PR.

## Out of scope

- The behavior/spec of CR1 and CR2 themselves (tracked as their own milestone-MR issues); this ADR
  only settles *which overlay technology* they use now vs. later.
- Non-anchored overlays (modals, slide-overs — ADR-0037, toasts). This ADR is about
  cell-anchored tooltips/popovers only.
- The actual #289 implementation work (it remains its own issue; this ADR re-scopes its mandate).

## References

- WAI-ARIA Authoring Practices Guide (APG) — Tooltip pattern; Dialog (Modal) / Popover patterns.
- WCAG 2.2 Success Criterion 1.4.13 — Content on Hover or Focus.
- Radix UI Primitives — Popover, Tooltip (Floating-UI positioning: `side`/`align`/`collisionPadding`).
- Internal: ADR-0019 (React + RJSF/shadcn), ADR-0028 (frontend toolchain), ADR-0029 D3 (no raw
  attacker data), ADR-0037 (slide-over host); issue #289 (cell-popover sweep);
  `scratch/phase-2-tests/test-dashboard-opus.md` CR1/CR2;
  `frontend/src/components/ds/core/useTooltipPosition.ts` (the positioner being retired).
