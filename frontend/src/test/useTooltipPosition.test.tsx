/**
 * Unit tests for useTooltipPosition hook (issues #366, #369).
 *
 * EARS acceptance criteria mapped to tests:
 *
 *   EARS-366-1 — WHEN a popover opens with preferAbove=true, the position SHALL be
 *                computed BEFORE the first paint (no setState-during-render warning,
 *                no one-frame mis-position at (0,0)).
 *                → "returns non-zero position on first open (preferAbove=true, real rect)"
 *                → "does NOT return zero position when trigger has a real rect"
 *
 *   EARS-366-2 — WHEN preferAbove=true and there is room above, the popover SHALL be
 *                placed fully ABOVE the trigger (top < rect.top, no overlap).
 *                → "preferAbove: top is less than trigger top (no overlap)"
 *                → "preferAbove: places popover at rect.top - ESTIMATED_HEIGHT - GAP"
 *
 *   EARS-366-3 — WHEN preferAbove=true and the trigger is near the top of the viewport
 *                (insufficient room above), the popover SHALL flip below the trigger.
 *                → "preferAbove: flips below when trigger near top of viewport"
 *                → "preferAbove: flip-below top equals rect.bottom + GAP"
 *
 *   EARS-366-4 — WHEN preferAbove=false (default), the popover SHALL appear below the
 *                trigger (existing behavior — regression guard).
 *                → "default (preferAbove=false): places popover below trigger"
 *                → "default: top equals rect.bottom + GAP"
 *
 *   EARS-366-5 — WHEN open=false, the hook SHALL return the last known position
 *                (not reset to zero on close — prevents flash on re-open).
 *                → "returns zeros when never opened (initial state)"
 *                → "does not reset position when open transitions to false"
 *
 *   EARS-369-1 — WHEN contentRef is supplied with a measurable height, the computed
 *                top SHALL equal triggerRect.top − actualHeight − GAP so the popover
 *                bottom sits fully above the trigger (no overlap).
 *                → "uses actual content height when contentRef has measurable height"
 *                → "popover bottom is at or above triggerRect.top - GAP (no overlap)"
 *
 *   EARS-369-2 — WHEN contentRef height is 0 or contentRef is absent, the hook SHALL
 *                fall back to TOOLTIP_ESTIMATED_HEIGHT (backward compatible).
 *                → "falls back to TOOLTIP_ESTIMATED_HEIGHT when contentRef height is 0"
 *                → "falls back to estimate when contentRef is not supplied"
 *
 *   EARS-369-3 — WHEN the actual height leaves no room above, the hook SHALL flip
 *                below — same flip-below semantics, just measured accurately.
 *                → "flips below when actual height leaves insufficient room above"
 */

import { describe, it, expect, vi, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useTooltipPosition } from '../components/ds'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Mock getBoundingClientRect on an element to return specific values.
 */
function mockRect(el: HTMLElement, rect: Partial<DOMRect>) {
  vi.spyOn(el, 'getBoundingClientRect').mockReturnValue({
    top: 0,
    bottom: 0,
    left: 0,
    right: 0,
    width: 0,
    height: 0,
    x: 0,
    y: 0,
    toJSON: () => ({}),
    ...rect,
  } as DOMRect)
}

/**
 * Wrapper that creates a real DOM element to use as triggerRef.
 * useTooltipPosition takes a RefObject<HTMLElement | null>, so we attach
 * a real div element that we can spy on.
 */
function createTriggerEl(rectOverride: Partial<DOMRect> = {}): HTMLElement {
  const el = document.createElement('div')
  document.body.appendChild(el)
  mockRect(el, rectOverride)
  return el
}

afterEach(() => {
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// EARS-366-1: No zero-position on first open
// ---------------------------------------------------------------------------

describe('useTooltipPosition — preferAbove: no zero-position on first open (EARS-366-1)', () => {
  it('returns non-zero top when trigger has a real rect (preferAbove=true)', () => {
    const el = createTriggerEl({ top: 300, bottom: 320, left: 50 })
    const triggerRef = { current: el }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true, { preferAbove: true }),
    )

    // With real rect: top = 300 - 80 - 6 = 214 (above path)
    expect(result.current.top).not.toBe(0)
    el.remove()
  })

  it('returns non-zero left when trigger has a real rect', () => {
    const el = createTriggerEl({ top: 300, bottom: 320, left: 100 })
    const triggerRef = { current: el }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true, { preferAbove: true }),
    )

    expect(result.current.left).toBe(100)
    el.remove()
  })
})

// ---------------------------------------------------------------------------
// EARS-366-2: preferAbove places popover above trigger (no overlap)
// ---------------------------------------------------------------------------

describe('useTooltipPosition — preferAbove: fully above trigger (EARS-366-2)', () => {
  it('top is strictly less than trigger rect.top (no overlap)', () => {
    const triggerTop = 300
    const el = createTriggerEl({ top: triggerTop, bottom: 320, left: 50 })
    const triggerRef = { current: el }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true, { preferAbove: true }),
    )

    // Popover's top MUST be less than trigger's top — fully above, no overlap.
    expect(result.current.top).toBeLessThan(triggerTop)
    el.remove()
  })

  it('top equals rect.top - TOOLTIP_ESTIMATED_HEIGHT - GAP (214 = 300 - 80 - 6)', () => {
    const el = createTriggerEl({ top: 300, bottom: 320, left: 50 })
    const triggerRef = { current: el }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true, { preferAbove: true }),
    )

    // Constants: TOOLTIP_ESTIMATED_HEIGHT=80, GAP=6
    expect(result.current.top).toBe(300 - 80 - 6)  // 214
    el.remove()
  })
})

// ---------------------------------------------------------------------------
// EARS-366-3: preferAbove flips below near top of viewport
// ---------------------------------------------------------------------------

describe('useTooltipPosition — preferAbove: flips below near top of viewport (EARS-366-3)', () => {
  it('flips below when trigger top is at 0 (jsdom default)', () => {
    // getBoundingClientRect returns all-zeros in jsdom by default.
    // aboveTop = 0 - 80 - 6 = -86 < VIEWPORT_MARGIN (8) → flip below.
    const el = createTriggerEl({ top: 0, bottom: 0, left: 0 })
    const triggerRef = { current: el }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true, { preferAbove: true }),
    )

    // Flipped below: top = rect.bottom + GAP = 0 + 6 = 6
    expect(result.current.top).toBe(6)
    el.remove()
  })

  it('flips below when aboveTop < VIEWPORT_MARGIN (8px)', () => {
    // Trigger at top=80: aboveTop = 80 - 80 - 6 = -6 < 8 → flip below.
    const el = createTriggerEl({ top: 80, bottom: 95, left: 50 })
    const triggerRef = { current: el }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true, { preferAbove: true }),
    )

    // Flipped below: top = rect.bottom + GAP = 95 + 6 = 101
    expect(result.current.top).toBe(101)
    el.remove()
  })

  it('stays above when aboveTop >= VIEWPORT_MARGIN', () => {
    // Trigger at top=200: aboveTop = 200 - 80 - 6 = 114 >= 8 → stays above.
    const el = createTriggerEl({ top: 200, bottom: 220, left: 50 })
    const triggerRef = { current: el }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true, { preferAbove: true }),
    )

    // Stays above: top = 200 - 80 - 6 = 114
    expect(result.current.top).toBe(114)
    el.remove()
  })
})

// ---------------------------------------------------------------------------
// EARS-366-4: default (preferAbove=false) places popover below trigger
// ---------------------------------------------------------------------------

describe('useTooltipPosition — default (preferAbove=false): below trigger (EARS-366-4)', () => {
  it('places popover below the trigger (default behavior)', () => {
    const el = createTriggerEl({ top: 200, bottom: 220, left: 50 })
    const triggerRef = { current: el }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true),
    )

    // Default below: top = rect.bottom + GAP = 220 + 6 = 226
    expect(result.current.top).toBe(226)
    el.remove()
  })

  it('top equals rect.bottom + GAP (220 + 6 = 226)', () => {
    const el = createTriggerEl({ top: 200, bottom: 220, left: 50 })
    const triggerRef = { current: el }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true, { preferAbove: false }),
    )

    expect(result.current.top).toBe(226)
    el.remove()
  })
})

// ---------------------------------------------------------------------------
// EARS-366-5: open=false returns zeros initially, stable on close
// ---------------------------------------------------------------------------

describe('useTooltipPosition — open=false behavior (EARS-366-5)', () => {
  it('returns zeros before opening (initial state)', () => {
    const el = createTriggerEl({ top: 300, bottom: 320, left: 50 })
    const triggerRef = { current: el }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, false, { preferAbove: true }),
    )

    expect(result.current.top).toBe(0)
    expect(result.current.left).toBe(0)
    el.remove()
  })

  it('does not reset position when open transitions false → false after being open', () => {
    const el = createTriggerEl({ top: 300, bottom: 320, left: 50 })
    const triggerRef = { current: el }

    // Start open
    const { result, rerender } = renderHook(
      ({ open }: { open: boolean }) =>
        useTooltipPosition(triggerRef, open, { preferAbove: true }),
      { initialProps: { open: true } },
    )

    const posAfterOpen = result.current.top
    expect(posAfterOpen).not.toBe(0)

    // Close: position should be preserved (not reset to 0)
    act(() => {
      rerender({ open: false })
    })

    // Hook retains last position — prevents flash on re-open
    expect(result.current.top).toBe(posAfterOpen)
    el.remove()
  })

  it('recomputes position when re-opened', () => {
    const el = createTriggerEl({ top: 300, bottom: 320, left: 50 })
    const triggerRef = { current: el }

    const { result, rerender } = renderHook(
      ({ open }: { open: boolean }) =>
        useTooltipPosition(triggerRef, open, { preferAbove: true }),
      { initialProps: { open: false } },
    )

    expect(result.current.top).toBe(0)

    act(() => {
      rerender({ open: true })
    })

    expect(result.current.top).toBe(300 - 80 - 6)  // 214
    el.remove()
  })
})

// ---------------------------------------------------------------------------
// Left-edge clamping — viewport collision fix (#567)
// ---------------------------------------------------------------------------

describe('useTooltipPosition — left-edge clamping', () => {
  it('aligns left to trigger rect.left when not near right edge', () => {
    const el = createTriggerEl({ top: 200, bottom: 220, left: 100 })
    const triggerRef = { current: el }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true),
    )

    expect(result.current.left).toBe(100)
    el.remove()
  })

  it('clamps left so tooltip right edge stays within viewport (#567: 1440px case)', () => {
    // jsdom window.innerWidth defaults to 1024. Override to simulate 1440px wide viewport.
    const origInnerWidth = window.innerWidth
    Object.defineProperty(window, 'innerWidth', { writable: true, configurable: true, value: 1440 })

    // Trigger near the right edge — left=1200 would put a 320px tooltip at 1520, off-screen.
    // Expected clamped left = 1440 - 320 - 8 = 1112
    const el = createTriggerEl({ top: 30, bottom: 50, left: 1200 })
    const triggerRef = { current: el }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true),
    )

    // Tooltip must start at most at (vw - TOOLTIP_MAX_WIDTH - VIEWPORT_MARGIN) = 1112
    expect(result.current.left).toBeLessThanOrEqual(1440 - 320 - 8)
    // The right edge (left + 320) must be within the viewport
    expect(result.current.left + 320).toBeLessThanOrEqual(1440 - 8)

    el.remove()
    Object.defineProperty(window, 'innerWidth', { writable: true, configurable: true, value: origInnerWidth })
  })

  it('does not clamp when trigger is well within viewport width', () => {
    const origInnerWidth = window.innerWidth
    Object.defineProperty(window, 'innerWidth', { writable: true, configurable: true, value: 1440 })

    // Trigger at left=100 — tooltip fits fine; no clamping needed.
    const el = createTriggerEl({ top: 200, bottom: 220, left: 100 })
    const triggerRef = { current: el }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true),
    )

    expect(result.current.left).toBe(100)

    el.remove()
    Object.defineProperty(window, 'innerWidth', { writable: true, configurable: true, value: origInnerWidth })
  })
})

// ---------------------------------------------------------------------------
// EARS-369: measure actual content height via contentRef
// ---------------------------------------------------------------------------

/**
 * Create a DOM element that reports a specific offsetHeight via a spy.
 * We spy on the offsetHeight getter because jsdom doesn't do layout, so
 * offsetHeight is always 0 by default.
 */
function createContentEl(offsetHeight: number): HTMLElement {
  const el = document.createElement('div')
  document.body.appendChild(el)
  vi.spyOn(el, 'offsetHeight', 'get').mockReturnValue(offsetHeight)
  return el
}

describe('useTooltipPosition — actual content height via contentRef (EARS-369)', () => {
  it('uses actual content height when contentRef has measurable height', () => {
    // Trigger at top=400, well below viewport margin.
    // Actual content height = 150px (taller than the 80px estimate).
    // Expected: top = 400 - 150 - 6 = 244
    const triggerEl = createTriggerEl({ top: 400, bottom: 420, left: 50 })
    const contentEl = createContentEl(150)
    const triggerRef = { current: triggerEl }
    const contentRef = { current: contentEl }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true, { preferAbove: true, contentRef }),
    )

    expect(result.current.top).toBe(400 - 150 - 6)  // 244
    triggerEl.remove()
    contentEl.remove()
  })

  it('popover bottom is at or above triggerRect.top - GAP (no overlap)', () => {
    // This is the canonical "no overlap" invariant: top + actualHeight <= triggerTop - GAP
    // i.e. the popover bottom edge clears the trigger top with a gap.
    const triggerTop = 400
    const actualHeight = 150
    const gap = 6
    const triggerEl = createTriggerEl({ top: triggerTop, bottom: 420, left: 50 })
    const contentEl = createContentEl(actualHeight)
    const triggerRef = { current: triggerEl }
    const contentRef = { current: contentEl }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true, { preferAbove: true, contentRef }),
    )

    const computedTop = result.current.top
    const popoverBottom = computedTop + actualHeight
    // Popover bottom must be at most (triggerTop - GAP): no pixel overlap with trigger.
    expect(popoverBottom).toBeLessThanOrEqual(triggerTop - gap)
    triggerEl.remove()
    contentEl.remove()
  })

  it('falls back to TOOLTIP_ESTIMATED_HEIGHT when contentRef height is 0', () => {
    // contentRef exists but offsetHeight is 0 (element not yet laid out or empty).
    // Should fall back to the 80px estimate: top = 300 - 80 - 6 = 214.
    const triggerEl = createTriggerEl({ top: 300, bottom: 320, left: 50 })
    const contentEl = createContentEl(0)  // zero height — unmeasured
    const triggerRef = { current: triggerEl }
    const contentRef = { current: contentEl }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true, { preferAbove: true, contentRef }),
    )

    expect(result.current.top).toBe(300 - 80 - 6)  // 214 — same as no-contentRef path
    triggerEl.remove()
    contentEl.remove()
  })

  it('falls back to estimate when contentRef is not supplied (backward compat)', () => {
    // No contentRef supplied — same behavior as before issue #369.
    const el = createTriggerEl({ top: 300, bottom: 320, left: 50 })
    const triggerRef = { current: el }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true, { preferAbove: true }),
    )

    expect(result.current.top).toBe(300 - 80 - 6)  // 214 — estimate path
    el.remove()
  })

  it('flips below when actual height leaves insufficient room above (no overlap on flip)', () => {
    // Trigger at top=100. Actual content height = 150.
    // aboveTop = 100 - 150 - 6 = -56 < VIEWPORT_MARGIN (8) → flips below.
    // Expected: top = rect.bottom + GAP = 115 + 6 = 121
    const triggerEl = createTriggerEl({ top: 100, bottom: 115, left: 50 })
    const contentEl = createContentEl(150)
    const triggerRef = { current: triggerEl }
    const contentRef = { current: contentEl }

    const { result } = renderHook(() =>
      useTooltipPosition(triggerRef, true, { preferAbove: true, contentRef }),
    )

    // Flipped below: top = 115 + 6 = 121
    expect(result.current.top).toBe(121)
    triggerEl.remove()
    contentEl.remove()
  })

  it('recomputes with actual height when re-opened after close', () => {
    const triggerEl = createTriggerEl({ top: 400, bottom: 420, left: 50 })
    const contentEl = createContentEl(150)
    const triggerRef = { current: triggerEl }
    const contentRef = { current: contentEl }

    const { result, rerender } = renderHook(
      ({ open }: { open: boolean }) =>
        useTooltipPosition(triggerRef, open, { preferAbove: true, contentRef }),
      { initialProps: { open: false } },
    )

    expect(result.current.top).toBe(0)

    act(() => {
      rerender({ open: true })
    })

    // Must use actual height: 400 - 150 - 6 = 244
    expect(result.current.top).toBe(244)
    triggerEl.remove()
    contentEl.remove()
  })
})
