/**
 * Tests for CellTooltip DS primitive (WCAG 2.2 SC 1.4.13) — issue #246.
 *
 * EARS criteria verified:
 *   1. Hover path: pointer hover → tooltip content appears; underlying trigger
 *      content remains visible.
 *   2. Keyboard path: keyboard focus → tooltip content appears (parity with hover).
 *   3. Hoverable (WCAG 1.4.13): pointer moving onto tooltip content keeps it open.
 *   4. Esc dismisses the tooltip only; an outer slide-over Esc handler is NOT called
 *      on the same keypress (layered-Esc, #226 pattern).
 *   5. Blur / mouseleave closes the tooltip.
 *   6. Tooltip renders in a portal (child of document.body, not inside the trigger).
 *   7. role="tooltip" + aria-describedby wiring.
 *   8. Trigger is keyboard-focusable (tabIndex=0).
 *   9. Consumer test: keyboard-only path reaches and verifies tooltip content.
 *  10. Consumer test: pointer-only path reaches and verifies tooltip content.
 *  11. CellTooltip is exported from the DS barrel.
 *
 * Test design:
 *   - @testing-library/user-event fires real keyboard events (Esc stopPropagation
 *     IS respected, unlike programmatic .click()).
 *   - fireEvent.mouseEnter / mouseLeave are used where user-event lacks mouse-move
 *     support in jsdom.
 *   - Portal assertions check document.body for the tooltip node.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CellTooltip } from '../components/ds'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderTooltip(content = <span>Tooltip detail</span>) {
  return render(
    <CellTooltip content={content}>
      <span>Cell value</span>
    </CellTooltip>,
  )
}

// ---------------------------------------------------------------------------
// beforeEach / afterEach — always restore real timers to prevent timer-state
// leakage between tests when a fake-timer test fails mid-flight.
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  vi.useRealTimers()
})

// ---------------------------------------------------------------------------
// 1. Hover path — tooltip opens on mouseenter
// ---------------------------------------------------------------------------

describe('CellTooltip — hover path', () => {
  it('tooltip content appears on mouseenter', async () => {
    renderTooltip()
    const trigger = screen.getByTestId('cell-tooltip-trigger')

    expect(screen.queryByTestId('cell-tooltip-content')).not.toBeInTheDocument()

    fireEvent.mouseEnter(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })
  })

  it('underlying trigger content stays visible when tooltip is open', async () => {
    renderTooltip()
    const trigger = screen.getByTestId('cell-tooltip-trigger')

    fireEvent.mouseEnter(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })

    // Trigger text still in the DOM
    expect(screen.getByText('Cell value')).toBeInTheDocument()
  })

  it('tooltip closes on mouseleave after delay', async () => {
    renderTooltip()
    const trigger = screen.getByTestId('cell-tooltip-trigger')

    // Open the tooltip with real timers so waitFor works
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })

    // Switch to fake timers now that the tooltip is open
    vi.useFakeTimers()

    fireEvent.mouseLeave(trigger)
    // Advance past the leave delay (80ms)
    act(() => { vi.advanceTimersByTime(200) })

    expect(screen.queryByTestId('cell-tooltip-content')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 2. Keyboard path — tooltip opens on focus
// ---------------------------------------------------------------------------

describe('CellTooltip — keyboard path', () => {
  it('tooltip content appears on focus', async () => {
    renderTooltip()
    const trigger = screen.getByTestId('cell-tooltip-trigger')

    expect(screen.queryByTestId('cell-tooltip-content')).not.toBeInTheDocument()

    fireEvent.focus(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })
  })

  it('tooltip closes on blur', async () => {
    renderTooltip()
    const trigger = screen.getByTestId('cell-tooltip-trigger')

    // Open with real timers so waitFor works
    fireEvent.focus(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })

    // Switch to fake timers now that the tooltip is open
    vi.useFakeTimers()

    fireEvent.blur(trigger)
    act(() => { vi.advanceTimersByTime(200) })

    expect(screen.queryByTestId('cell-tooltip-content')).not.toBeInTheDocument()
  })

  it('trigger has tabIndex=0 (keyboard-focusable)', () => {
    renderTooltip()
    const trigger = screen.getByTestId('cell-tooltip-trigger')
    expect(trigger.getAttribute('tabindex')).toBe('0')
  })
})

// ---------------------------------------------------------------------------
// 3. Hoverable — pointer on tooltip keeps it open (WCAG 1.4.13)
// ---------------------------------------------------------------------------

describe('CellTooltip — hoverable (WCAG 1.4.13)', () => {
  it('moving pointer from trigger onto tooltip content keeps tooltip open', async () => {
    renderTooltip()
    const trigger = screen.getByTestId('cell-tooltip-trigger')

    // Open via trigger with real timers
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })

    // Switch to fake timers now that tooltip is visible
    vi.useFakeTimers()

    // Pointer leaves trigger — leave timer starts
    fireEvent.mouseLeave(trigger)

    // Before the delay expires, pointer enters the tooltip content
    const tooltip = screen.getByTestId('cell-tooltip-content')
    fireEvent.mouseEnter(tooltip)

    // Advance past what would have been the leave delay
    act(() => { vi.advanceTimersByTime(200) })

    // Tooltip MUST still be open (leave timer was cleared by tooltip mouseEnter)
    expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
  })

  it('tooltip closes when pointer also leaves the tooltip content', async () => {
    renderTooltip()
    const trigger = screen.getByTestId('cell-tooltip-trigger')

    // Open with real timers
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })

    // Switch to fake timers
    vi.useFakeTimers()

    // Move pointer to tooltip
    const tooltip = screen.getByTestId('cell-tooltip-content')
    fireEvent.mouseLeave(trigger)
    fireEvent.mouseEnter(tooltip)

    // Now leave the tooltip too
    fireEvent.mouseLeave(tooltip)
    act(() => { vi.advanceTimersByTime(200) })

    expect(screen.queryByTestId('cell-tooltip-content')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 4. Esc dismissal — layered-Esc contract (#226)
// ---------------------------------------------------------------------------

describe('CellTooltip — Esc dismissal (layered-Esc #226)', () => {
  it('Esc closes the tooltip', async () => {
    const user = userEvent.setup()
    renderTooltip()
    const trigger = screen.getByTestId('cell-tooltip-trigger')

    fireEvent.focus(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })

    await user.keyboard('{Escape}')
    expect(screen.queryByTestId('cell-tooltip-content')).not.toBeInTheDocument()
  })

  it('Esc with tooltip open does NOT propagate to outer document handler (layered-Esc)', async () => {
    const user = userEvent.setup()
    // Simulate a slide-over Esc handler on the document (bubble phase)
    const outerHandler = vi.fn()
    document.addEventListener('keydown', outerHandler)

    try {
      renderTooltip()
      const trigger = screen.getByTestId('cell-tooltip-trigger')

      fireEvent.focus(trigger)
      await waitFor(() => {
        expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
      })

      // Esc is captured by CellTooltip before reaching the outer handler
      await user.keyboard('{Escape}')

      expect(screen.queryByTestId('cell-tooltip-content')).not.toBeInTheDocument()
      // Outer handler must NOT have been called on the same Esc keypress
      expect(outerHandler).not.toHaveBeenCalled()
    } finally {
      document.removeEventListener('keydown', outerHandler)
    }
  })

  it('after tooltip closes via Esc, subsequent Esc reaches outer handler', async () => {
    const user = userEvent.setup()
    const outerHandler = vi.fn()
    document.addEventListener('keydown', outerHandler)

    try {
      renderTooltip()
      const trigger = screen.getByTestId('cell-tooltip-trigger')

      fireEvent.focus(trigger)
      await waitFor(() => {
        expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
      })

      // First Esc: closes tooltip (intercepts event)
      await user.keyboard('{Escape}')
      expect(screen.queryByTestId('cell-tooltip-content')).not.toBeInTheDocument()
      expect(outerHandler).not.toHaveBeenCalled()

      // Second Esc: tooltip gone — outer handler receives it
      await user.keyboard('{Escape}')
      expect(outerHandler).toHaveBeenCalledTimes(1)
    } finally {
      document.removeEventListener('keydown', outerHandler)
    }
  })
})

// ---------------------------------------------------------------------------
// 5. Portal — tooltip renders in document.body, not inside trigger
// ---------------------------------------------------------------------------

describe('CellTooltip — portal rendering', () => {
  it('tooltip is a direct child of document.body (portal)', async () => {
    renderTooltip()
    const trigger = screen.getByTestId('cell-tooltip-trigger')

    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })

    const tooltip = screen.getByTestId('cell-tooltip-content')
    // Portal: tooltip's parent must be document.body
    expect(tooltip.parentElement).toBe(document.body)
  })
})

// ---------------------------------------------------------------------------
// 6. Accessibility — role="tooltip" + aria-describedby
// ---------------------------------------------------------------------------

describe('CellTooltip — accessibility wiring', () => {
  it('tooltip container has role="tooltip"', async () => {
    renderTooltip()
    const trigger = screen.getByTestId('cell-tooltip-trigger')

    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByRole('tooltip')).toBeInTheDocument()
    })
  })

  it('trigger has aria-describedby pointing to the tooltip when open', async () => {
    renderTooltip()
    const trigger = screen.getByTestId('cell-tooltip-trigger')

    expect(trigger.getAttribute('aria-describedby')).toBeNull()

    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })

    const tooltipId = screen.getByTestId('cell-tooltip-content').id
    expect(trigger.getAttribute('aria-describedby')).toBe(tooltipId)
  })

  it('trigger aria-describedby is removed when tooltip closes', async () => {
    renderTooltip()
    const trigger = screen.getByTestId('cell-tooltip-trigger')

    // Open with real timers
    fireEvent.focus(trigger)
    await waitFor(() => {
      expect(trigger.getAttribute('aria-describedby')).toBeTruthy()
    })

    // Switch to fake timers for close
    vi.useFakeTimers()

    fireEvent.blur(trigger)
    act(() => { vi.advanceTimersByTime(200) })

    expect(trigger.getAttribute('aria-describedby')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// 7. Consumer end-to-end: keyboard-only path
// ---------------------------------------------------------------------------

describe('CellTooltip — consumer test: keyboard-only path', () => {
  it('keyboard-only user can reach and verify tooltip content via Tab + focus', async () => {
    const user = userEvent.setup()

    render(
      <div>
        <button data-testid="before">Before</button>
        <CellTooltip content={<span data-testid="tooltip-detail">Score: 92/100</span>}>
          <span>Risk Score</span>
        </CellTooltip>
        <button data-testid="after">After</button>
      </div>,
    )

    // Tab to the trigger
    await user.tab()
    // First tab goes to "Before" button; second reaches the tooltip trigger
    await user.tab()

    // Tooltip should now be open from focus
    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })

    // Content is accessible (same as hover)
    expect(screen.getByTestId('tooltip-detail')).toBeInTheDocument()
    expect(screen.getByTestId('tooltip-detail').textContent).toBe('Score: 92/100')

    // Esc closes it
    await user.keyboard('{Escape}')
    expect(screen.queryByTestId('cell-tooltip-content')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 8. Consumer end-to-end: pointer-only path
// ---------------------------------------------------------------------------

describe('CellTooltip — consumer test: pointer-only path', () => {
  it('pointer-only user can trigger and dismiss tooltip', async () => {
    renderTooltip(<span data-testid="hover-detail">Blocked: 47 events</span>)
    const trigger = screen.getByTestId('cell-tooltip-trigger')

    // Hover opens
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })

    // Content is reachable in the DOM
    expect(screen.getByTestId('hover-detail').textContent).toBe('Blocked: 47 events')

    // Mouseleave closes after delay — switch to fake timers now that tooltip is open
    vi.useFakeTimers()
    fireEvent.mouseLeave(trigger)
    act(() => { vi.advanceTimersByTime(200) })
    expect(screen.queryByTestId('cell-tooltip-content')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 9. DS barrel export
// ---------------------------------------------------------------------------

describe('CellTooltip — DS barrel export', () => {
  it('CellTooltip is exported from ds/index.ts', () => {
    expect(CellTooltip).toBeDefined()
    expect(typeof CellTooltip).toBe('function')
  })
})
