/**
 * useTooltipPosition — computes fixed-position coordinates for a tooltip
 * anchored to a trigger element, with viewport-aware flipping.
 *
 * Strategy (default — preferAbove=false):
 *   - Place the tooltip below the trigger, aligned to its left edge.
 *   - Flip above if the bottom would extend past the viewport bottom minus a
 *     small safety margin (8px).
 *   - Clamp left edge so the tooltip doesn't overflow the right side of the
 *     viewport.
 *
 * preferAbove=true (ScoreBreakdownPopover — issue #266, #366, #369):
 *   - Place the tooltip above the trigger by default.
 *     "Above" means the tooltip's BOTTOM edge is at (rect.top - GAP), so the
 *     tooltip sits fully above the trigger with a clean gap — no overlap with
 *     the trigger element (issue #366).
 *   - The ACTUAL rendered content height is used when contentRef is supplied
 *     (issue #369 fix). This eliminates the ~64px overlap caused by using the
 *     TOOLTIP_ESTIMATED_HEIGHT constant when the content is taller than the
 *     estimate (e.g. the ScoreBreakdownPopover is ~150px vs an 80px estimate).
 *   - Flip below when there is insufficient room above (trigger near the top of
 *     the viewport — "flip-below-when-near-top" rule from the issue spec).
 *
 * Issue #366 fix — useLayoutEffect instead of useEffect:
 *   Measuring the trigger element and calling setPos MUST happen in a
 *   useLayoutEffect (runs synchronously after DOM mutation, before paint).
 *   Using useEffect would schedule measurement after paint, causing:
 *     1. A "setState-during-render" warning on the very first open (React
 *        flushes the effect synchronously on first render in some paths).
 *     2. A visible mis-position on first open (tooltip renders at (0,0)
 *        for one frame then jumps to the correct position).
 *   useLayoutEffect eliminates both by measuring after layout but before paint.
 *
 * Issue #369 fix — measure actual content height via contentRef:
 *   TOOLTIP_ESTIMATED_HEIGHT is a conservative constant that was too small for
 *   the ScoreBreakdownPopover (~150px actual vs 80px estimate). This caused the
 *   popover's top to be computed too low, overlapping the badge by ~64px.
 *
 *   When contentRef is supplied, we read contentRef.current.offsetHeight inside
 *   the same useLayoutEffect that measures the trigger. Because both the trigger
 *   and the portal content are in the DOM after React's commit phase (and
 *   useLayoutEffect runs after commit, before paint), the actual height is
 *   available on the first open — no visible jump, no first-frame overlap.
 *
 *   TOOLTIP_ESTIMATED_HEIGHT is kept as the fallback for callers that do not
 *   supply contentRef (CellDetailPopover, AiEnginePill — they use the
 *   default-below path and are not affected by the height bug).
 *
 * Returns { top, left } as pixel values ready for use in a `position:fixed`
 * element. Returns zeros when the trigger ref has no DOMRect (e.g. in tests
 * where getBoundingClientRect returns all-zeros).
 */

import { useState, useLayoutEffect, type RefObject } from 'react'

const TOOLTIP_ESTIMATED_HEIGHT = 80   // px — conservative estimate for flip calc
const TOOLTIP_MAX_WIDTH = 320         // px — must match maxWidth in CellTooltip render (#567)
const GAP = 6                         // px gap between trigger and tooltip
const VIEWPORT_MARGIN = 8             // px margin from viewport edge

export interface TooltipPosition {
  top: number
  left: number
}

export interface UseTooltipPositionOptions {
  /**
   * When true, prefer placing the tooltip ABOVE the trigger and flip BELOW
   * only when there is insufficient room above (trigger near the top).
   * Default: false (prefer below, flip above when near the bottom).
   */
  preferAbove?: boolean
  /**
   * Optional ref to the popover/content element.
   *
   * When supplied and preferAbove=true, the hook reads contentRef.current.offsetHeight
   * inside useLayoutEffect (after React's commit, before paint) to obtain the ACTUAL
   * rendered content height. This ensures the popover bottom edge sits exactly at
   * (triggerRect.top − GAP) — fully above the trigger with no overlap (issue #369).
   *
   * If the ref's element has no height yet (zero or null), falls back to
   * TOOLTIP_ESTIMATED_HEIGHT. This keeps callers that do not supply contentRef working
   * identically to before.
   */
  contentRef?: RefObject<HTMLElement | null>
}

export function useTooltipPosition(
  triggerRef: RefObject<HTMLElement | null>,
  open: boolean,
  options: UseTooltipPositionOptions = {},
): TooltipPosition {
  const { preferAbove = false, contentRef } = options
  const [pos, setPos] = useState<TooltipPosition>({ top: 0, left: 0 })

  // useLayoutEffect: measure the trigger AFTER layout but BEFORE paint.
  // This prevents both the "setState-during-render" React warning and the
  // one-frame mis-position at (0,0) that useEffect would cause (issue #366).
  //
  // When contentRef is supplied, contentRef.current.offsetHeight is also read
  // here. React's commit phase has already inserted all portal content into the
  // DOM at this point, so offsetHeight reflects the actual rendered height —
  // no second paint needed (issue #369).
  useLayoutEffect(() => {
    if (!open || !triggerRef.current) return

    const rect = triggerRef.current.getBoundingClientRect()
    const vh = window.innerHeight
    const vw = window.innerWidth

    let top: number

    if (preferAbove) {
      // Resolve content height: use actual offsetHeight when available,
      // fall back to the estimate for callers that don't supply contentRef.
      const contentEl = contentRef?.current
      const actualHeight =
        contentEl != null && contentEl.offsetHeight > 0
          ? contentEl.offsetHeight
          : TOOLTIP_ESTIMATED_HEIGHT

      // Prefer above: position the tooltip so its BOTTOM edge sits at
      // (rect.top - GAP). This places the popover fully above the trigger
      // with a clean gap — no overlap with the trigger element (issue #366).
      // Using actualHeight instead of TOOLTIP_ESTIMATED_HEIGHT eliminates the
      // ~64px overlap when content is taller than the estimate (issue #369).
      const aboveTop = rect.top - actualHeight - GAP

      if (aboveTop < VIEWPORT_MARGIN) {
        // Not enough room above — flip below.
        top = rect.bottom + GAP
      } else {
        top = aboveTop
      }
    } else {
      // Default: below the trigger.
      top = rect.bottom + GAP

      // Flip above if the tooltip would overflow the bottom viewport edge.
      if (top + TOOLTIP_ESTIMATED_HEIGHT > vh - VIEWPORT_MARGIN) {
        top = rect.top - TOOLTIP_ESTIMATED_HEIGHT - GAP
      }
    }

    // Align left edge to the trigger; clamp so the right edge of the tooltip
    // (left + TOOLTIP_MAX_WIDTH) stays within the viewport (#567 viewport collision).
    // maxLeft is the largest left value that keeps the tooltip on-screen.
    let left = rect.left
    const maxLeft = vw - TOOLTIP_MAX_WIDTH - VIEWPORT_MARGIN
    if (left > maxLeft) {
      left = Math.max(VIEWPORT_MARGIN, maxLeft)
    }

    setPos({ top, left })
  }, [open, triggerRef, preferAbove, contentRef])

  return pos
}
