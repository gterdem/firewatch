/**
 * Tests for D1 fix (#226): SlideOver z-index must exceed AppHeader z-index (100)
 * so the panel header row (breadcrumb + close button) is not occluded by the
 * sticky AppHeader and remains pointer-clickable.
 *
 * EARS criterion:
 *   WHEN the slide-over is open,
 *   THEN its close button SHALL be pointer-reachable (panel z-index > AppHeader z-index).
 *
 * Why programmatic-click tests are insufficient:
 *   @testing-library/user-event's click() ignores CSS stacking context, so a test
 *   that just clicks the close button passes even when the button is visually occluded.
 *   These tests assert the z-index relationship directly — the structural guarantee
 *   that the panel/overlay sit above any sticky z-index-100 header.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import SlideOver from '../components/entity/SlideOver'

// AppHeader declares z-index 100 (sticky, top:0).
// D1 fix requires: overlay >= 101 and panel > overlay > 100.
// The chosen values: overlay=109, panel=110.
const APP_HEADER_Z_INDEX = 100

describe('SlideOver z-index (D1 fix #226)', () => {
  it('panel z-index exceeds AppHeader z-index (not occluded by sticky header)', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test">
        content
      </SlideOver>,
    )

    const panel = screen.getByTestId('slide-over-panel')
    const panelZIndex = parseInt(String(panel.style.zIndex), 10)

    expect(panelZIndex).toBeGreaterThan(APP_HEADER_Z_INDEX)
  })

  it('overlay z-index exceeds AppHeader z-index (overlay covers sticky header)', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test">
        content
      </SlideOver>,
    )

    const overlay = screen.getByTestId('slide-over-overlay')
    const overlayZIndex = parseInt(String(overlay.style.zIndex), 10)

    expect(overlayZIndex).toBeGreaterThan(APP_HEADER_Z_INDEX)
  })

  it('panel z-index exceeds overlay z-index (panel renders above its own backdrop)', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test">
        content
      </SlideOver>,
    )

    const panel = screen.getByTestId('slide-over-panel')
    const overlay = screen.getByTestId('slide-over-overlay')
    const panelZIndex = parseInt(String(panel.style.zIndex), 10)
    const overlayZIndex = parseInt(String(overlay.style.zIndex), 10)

    // Panel must paint above the overlay so its content is reachable.
    expect(panelZIndex).toBeGreaterThan(overlayZIndex)
  })

  it('close button is present and not hidden behind the panel header (structural check)', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test">
        content
      </SlideOver>,
    )

    const closeBtn = screen.getByTestId('slide-over-close')

    // The button must be in the DOM and not have pointer-events:none / visibility:hidden.
    expect(closeBtn).toBeInTheDocument()
    expect(closeBtn.style.pointerEvents).not.toBe('none')
    expect(closeBtn.style.visibility).not.toBe('hidden')
  })

  it('panel z-index is exactly 110 and overlay is exactly 109 (stable contract values)', () => {
    // These are the concrete values chosen to sit above AppHeader (100) with headroom
    // for future layering (e.g. toasts at 120, command palette at 130).
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test">
        content
      </SlideOver>,
    )

    const panel = screen.getByTestId('slide-over-panel')
    const overlay = screen.getByTestId('slide-over-overlay')

    expect(parseInt(String(panel.style.zIndex), 10)).toBe(110)
    expect(parseInt(String(overlay.style.zIndex), 10)).toBe(109)
  })
})
