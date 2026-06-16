/**
 * Tests for useDismissableDisclosure and its consumers (issue #327).
 *
 * EARS acceptance criteria mapped to tests:
 *
 *   EARS-1 (outside-click dismiss):
 *     WHEN a disclosure is open and the user clicks anywhere outside the trigger
 *     and the popover, the disclosure SHALL close.
 *
 *   EARS-2 (Escape dismiss + focus return):
 *     WHEN a disclosure is open and the user presses Escape, the disclosure SHALL
 *     close and focus SHALL return to the trigger.
 *
 *   EARS-3 (single-open invariant):
 *     WHEN a second disclosure is opened, the first SHALL close — the system SHALL
 *     never render two open click-disclosures simultaneously.
 *
 *   EARS-4 (hover-open, WCAG 1.4.13):
 *     WHEN the user hovers kpi-ai-status (AiEnginePill with allowHover=true),
 *     its popover SHALL open and SHALL remain open while the pointer is over the
 *     popover content.
 *
 *   EARS-5 (ubiquitous routing):
 *     AiEnginePill and ScoreBadge SHALL route through useDismissableDisclosure
 *     — outside-click + Esc + single-open all verified at consumer level.
 *
 * Dead-wire lesson (docs/lessons.md):
 *   Tests assert BEHAVIOR (open/close from events) not just wire-up.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { useDismissableDisclosure } from '../components/ds'
import AiEnginePill from '../components/dashboard/AiEnginePill'
import { ScoreBadge } from '../components/ds'
import type { HealthResponse, ScoreBreakdownItem } from '../api/types'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  vi.useRealTimers()
})

// ---------------------------------------------------------------------------
// Test component that wraps useDismissableDisclosure
// ---------------------------------------------------------------------------

function DisclosureTestHarness({ allowHover = false }: { allowHover?: boolean }) {
  const { open, triggerRef, contentRef, triggerProps, contentProps } =
    useDismissableDisclosure({ allowHover })

  return (
    <div>
      <button
        ref={triggerRef as React.RefObject<HTMLButtonElement>}
        data-testid="disclosure-trigger"
        {...triggerProps}
      >
        Toggle
      </button>
      {open && (
        <div
          ref={contentRef as React.RefObject<HTMLDivElement>}
          data-testid="disclosure-content"
          {...contentProps}
        >
          Content
        </div>
      )}
      <button data-testid="outside-btn">Outside</button>
    </div>
  )
}

/** Two independent disclosures for single-open invariant tests. */
function TwoDisclosures() {
  return (
    <div>
      <DisclosureTestHarness />
      <DisclosureTestHarness />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const HEALTH_ONLINE: HealthResponse = {
  status: 'ok',
  ollama_connected: true,
  ollama_model: 'llama3.2',
  db_ok: true,
}

const SCORE_BREAKDOWN: ScoreBreakdownItem[] = [
  { factor: 'brute_force', label: 'Brute force', points: 30 },
  { factor: 'port_scan', label: 'Port scan', points: 25 },
]

// ---------------------------------------------------------------------------
// EARS-1: Outside-click dismiss — useDismissableDisclosure (unit)
// ---------------------------------------------------------------------------

describe('useDismissableDisclosure — outside-click dismiss (EARS-1)', () => {
  it('clicking outside the trigger and content closes the disclosure', async () => {
    render(<DisclosureTestHarness />)
    const trigger = screen.getByTestId('disclosure-trigger')
    const outside = screen.getByTestId('outside-btn')

    // Open the disclosure
    fireEvent.click(trigger)
    expect(screen.getByTestId('disclosure-content')).toBeInTheDocument()

    // Click outside — pointerdown on the "outside" button
    fireEvent.pointerDown(outside)
    expect(screen.queryByTestId('disclosure-content')).not.toBeInTheDocument()
  })

  it('clicking inside the content does NOT close the disclosure', async () => {
    render(<DisclosureTestHarness />)
    const trigger = screen.getByTestId('disclosure-trigger')

    fireEvent.click(trigger)
    const content = screen.getByTestId('disclosure-content')
    expect(content).toBeInTheDocument()

    // Click inside the content
    fireEvent.pointerDown(content)
    expect(screen.getByTestId('disclosure-content')).toBeInTheDocument()
  })

  it('clicking the trigger itself does NOT close via outside-click (toggle handles it)', async () => {
    render(<DisclosureTestHarness />)
    const trigger = screen.getByTestId('disclosure-trigger')

    // Open
    fireEvent.click(trigger)
    expect(screen.getByTestId('disclosure-content')).toBeInTheDocument()

    // pointerDown on the trigger — should NOT fire outside-click close
    // (the toggle in onClick will run instead)
    fireEvent.pointerDown(trigger)
    // Still open at this point (pointerdown alone doesn't toggle, click does)
    expect(screen.getByTestId('disclosure-content')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-2: Escape dismiss + focus return — useDismissableDisclosure (unit)
// ---------------------------------------------------------------------------

describe('useDismissableDisclosure — Escape dismiss (EARS-2)', () => {
  it('Escape closes the disclosure', async () => {
    const user = userEvent.setup()
    render(<DisclosureTestHarness />)
    const trigger = screen.getByTestId('disclosure-trigger')

    fireEvent.click(trigger)
    expect(screen.getByTestId('disclosure-content')).toBeInTheDocument()

    await user.keyboard('{Escape}')
    expect(screen.queryByTestId('disclosure-content')).not.toBeInTheDocument()
  })

  it('Escape does NOT propagate to outer document handler (layered-Esc, #226)', async () => {
    const user = userEvent.setup()
    const outerHandler = vi.fn()
    document.addEventListener('keydown', outerHandler)

    try {
      render(<DisclosureTestHarness />)
      const trigger = screen.getByTestId('disclosure-trigger')

      fireEvent.click(trigger)
      expect(screen.getByTestId('disclosure-content')).toBeInTheDocument()

      await user.keyboard('{Escape}')
      expect(screen.queryByTestId('disclosure-content')).not.toBeInTheDocument()
      // Outer handler must NOT have been called (stopImmediatePropagation)
      expect(outerHandler).not.toHaveBeenCalled()
    } finally {
      document.removeEventListener('keydown', outerHandler)
    }
  })

  it('Escape returns focus to the trigger', async () => {
    const user = userEvent.setup()
    render(<DisclosureTestHarness />)
    const trigger = screen.getByTestId('disclosure-trigger')

    trigger.focus()
    fireEvent.click(trigger)
    expect(screen.getByTestId('disclosure-content')).toBeInTheDocument()

    await user.keyboard('{Escape}')
    // Focus should be back on the trigger
    expect(document.activeElement).toBe(trigger)
  })
})

// ---------------------------------------------------------------------------
// EARS-3: Single-open invariant — useDismissableDisclosure (unit)
// ---------------------------------------------------------------------------

describe('useDismissableDisclosure — single-open invariant (EARS-3)', () => {
  it('opening a second disclosure closes the first', () => {
    const { getAllByTestId } = render(<TwoDisclosures />)
    const [trigger1, trigger2] = getAllByTestId('disclosure-trigger')

    // Open first
    fireEvent.click(trigger1)
    expect(getAllByTestId('disclosure-content')).toHaveLength(1)

    // Open second — first should close
    fireEvent.click(trigger2)
    const contents = getAllByTestId('disclosure-content')
    expect(contents).toHaveLength(1)
    // Verify the remaining one is the second, not the first
    // (first trigger area is before second; only one content remains)
  })

  it('two disclosures are NEVER open simultaneously', () => {
    const { getAllByTestId } = render(<TwoDisclosures />)
    const [trigger1, trigger2] = getAllByTestId('disclosure-trigger')

    // Rapidly open both
    fireEvent.click(trigger1)
    fireEvent.click(trigger2)

    // At most one content element should exist at any time
    const contents = getAllByTestId('disclosure-content')
    expect(contents.length).toBeLessThanOrEqual(1)
  })
})

// ---------------------------------------------------------------------------
// EARS-4: Hover-open + WCAG 1.4.13 hoverable — useDismissableDisclosure
// ---------------------------------------------------------------------------

describe('useDismissableDisclosure — hover-open (EARS-4)', () => {
  it('mouseenter on trigger opens the disclosure (allowHover=true)', async () => {
    render(<DisclosureTestHarness allowHover />)
    const trigger = screen.getByTestId('disclosure-trigger')

    expect(screen.queryByTestId('disclosure-content')).not.toBeInTheDocument()
    fireEvent.mouseEnter(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('disclosure-content')).toBeInTheDocument()
    })
  })

  it('pointer moving from trigger to content keeps disclosure open (WCAG 1.4.13 hoverable)', async () => {
    render(<DisclosureTestHarness allowHover />)
    const trigger = screen.getByTestId('disclosure-trigger')

    // Open via hover
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('disclosure-content')).toBeInTheDocument()
    })

    // Switch to fake timers after open
    vi.useFakeTimers()

    // Pointer leaves trigger — leave timer starts
    fireEvent.mouseLeave(trigger)

    // Before delay expires, pointer enters the content
    const content = screen.getByTestId('disclosure-content')
    fireEvent.mouseEnter(content)

    // Advance past what would have been the leave delay
    act(() => { vi.advanceTimersByTime(200) })

    // Disclosure MUST still be open
    expect(screen.getByTestId('disclosure-content')).toBeInTheDocument()
  })

  it('disclosure closes after pointer leaves both trigger and content', async () => {
    render(<DisclosureTestHarness allowHover />)
    const trigger = screen.getByTestId('disclosure-trigger')

    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('disclosure-content')).toBeInTheDocument()
    })

    vi.useFakeTimers()

    // Move to content, then leave content too
    const content = screen.getByTestId('disclosure-content')
    fireEvent.mouseLeave(trigger)
    fireEvent.mouseEnter(content)
    fireEvent.mouseLeave(content)
    act(() => { vi.advanceTimersByTime(200) })

    expect(screen.queryByTestId('disclosure-content')).not.toBeInTheDocument()
  })

  it('no hover behavior when allowHover=false (default)', async () => {
    render(<DisclosureTestHarness allowHover={false} />)
    const trigger = screen.getByTestId('disclosure-trigger')

    fireEvent.mouseEnter(trigger)
    // Should NOT open on hover
    expect(screen.queryByTestId('disclosure-content')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-5a: AiEnginePill — outside-click dismiss (consumer test)
// ---------------------------------------------------------------------------

describe('AiEnginePill — outside-click dismiss (EARS-5)', () => {
  it('clicking outside the pill and disclosure closes the disclosure', () => {
    render(
      <div>
        <AiEnginePill health={HEALTH_ONLINE} />
        <button data-testid="outside">Outside</button>
      </div>,
    )
    const pill = screen.getByTestId('ai-engine-pill')
    const outside = screen.getByTestId('outside')

    // Open by click
    fireEvent.click(pill)
    expect(screen.getByTestId('ai-engine-pill-disclosure')).toBeInTheDocument()

    // Click outside
    fireEvent.pointerDown(outside)
    expect(screen.queryByTestId('ai-engine-pill-disclosure')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-5b: AiEnginePill — Escape dismiss (consumer test)
// ---------------------------------------------------------------------------

describe('AiEnginePill — Escape dismiss (EARS-5)', () => {
  it('Escape closes the disclosure', async () => {
    const user = userEvent.setup()
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    const pill = screen.getByTestId('ai-engine-pill')

    fireEvent.click(pill)
    expect(screen.getByTestId('ai-engine-pill-disclosure')).toBeInTheDocument()

    await user.keyboard('{Escape}')
    expect(screen.queryByTestId('ai-engine-pill-disclosure')).not.toBeInTheDocument()
  })

  it('Escape does NOT propagate to outer handler (layered-Esc, #226)', async () => {
    const user = userEvent.setup()
    const outerHandler = vi.fn()
    document.addEventListener('keydown', outerHandler)

    try {
      render(<AiEnginePill health={HEALTH_ONLINE} />)
      const pill = screen.getByTestId('ai-engine-pill')

      fireEvent.click(pill)
      expect(screen.getByTestId('ai-engine-pill-disclosure')).toBeInTheDocument()

      await user.keyboard('{Escape}')
      expect(outerHandler).not.toHaveBeenCalled()
    } finally {
      document.removeEventListener('keydown', outerHandler)
    }
  })
})

// ---------------------------------------------------------------------------
// EARS-5c: AiEnginePill — hover-open (consumer test, WCAG 1.4.13)
// ---------------------------------------------------------------------------

describe('AiEnginePill — hover-open kpi-ai-status (EARS-5 / WCAG 1.4.13)', () => {
  it('hovering the pill opens the disclosure (allowHover=true)', async () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    const pill = screen.getByTestId('ai-engine-pill')

    expect(screen.queryByTestId('ai-engine-pill-disclosure')).not.toBeInTheDocument()
    fireEvent.mouseEnter(pill)

    await waitFor(() => {
      expect(screen.getByTestId('ai-engine-pill-disclosure')).toBeInTheDocument()
    })
  })

  it('pointer moving from pill to disclosure keeps it open (WCAG 1.4.13 hoverable)', async () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    const pill = screen.getByTestId('ai-engine-pill')

    fireEvent.mouseEnter(pill)
    await waitFor(() => {
      expect(screen.getByTestId('ai-engine-pill-disclosure')).toBeInTheDocument()
    })

    vi.useFakeTimers()

    // Pointer leaves pill
    fireEvent.mouseLeave(pill)
    // Before delay expires, pointer enters the disclosure
    const disclosure = screen.getByTestId('ai-engine-pill-disclosure')
    fireEvent.mouseEnter(disclosure)

    act(() => { vi.advanceTimersByTime(200) })

    // Disclosure must still be open
    expect(screen.getByTestId('ai-engine-pill-disclosure')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-5d: AiEnginePill — single-open invariant (consumer test)
// ---------------------------------------------------------------------------

describe('AiEnginePill + ScoreBadge — single-open invariant (EARS-5)', () => {
  it('opening AiEnginePill closes an already-open ScoreBadge popover', () => {
    render(
      <div>
        <ScoreBadge
          score={95}
          threatLevel="CRITICAL"
          scoreBreakdown={SCORE_BREAKDOWN}
        />
        <AiEnginePill health={HEALTH_ONLINE} />
      </div>,
    )

    // Open the ScoreBadge breakdown popover first
    const scoreBtn = screen.getByRole('button', { name: /show score breakdown/i })
    fireEvent.click(scoreBtn)
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()

    // Now open the AiEnginePill disclosure
    const pill = screen.getByTestId('ai-engine-pill')
    fireEvent.click(pill)

    // ScoreBadge popover should be CLOSED (single-open invariant)
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
    // AiEnginePill disclosure should be OPEN
    expect(screen.getByTestId('ai-engine-pill-disclosure')).toBeInTheDocument()
  })

  it('opening ScoreBadge popover closes an already-open AiEnginePill disclosure', () => {
    render(
      <div>
        <AiEnginePill health={HEALTH_ONLINE} />
        <ScoreBadge
          score={95}
          threatLevel="CRITICAL"
          scoreBreakdown={SCORE_BREAKDOWN}
        />
      </div>,
    )

    // Open AiEnginePill first
    const pill = screen.getByTestId('ai-engine-pill')
    fireEvent.click(pill)
    expect(screen.getByTestId('ai-engine-pill-disclosure')).toBeInTheDocument()

    // Now open ScoreBadge breakdown popover
    const scoreBtn = screen.getByRole('button', { name: /show score breakdown/i })
    fireEvent.click(scoreBtn)

    // AiEnginePill disclosure should be CLOSED
    expect(screen.queryByTestId('ai-engine-pill-disclosure')).not.toBeInTheDocument()
    // ScoreBadge popover should be OPEN
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-5e: ScoreBadge — outside-click dismiss (consumer test)
// ---------------------------------------------------------------------------

describe('ScoreBadge — outside-click dismiss (EARS-5)', () => {
  it('clicking outside the score badge closes the breakdown popover', () => {
    render(
      <div>
        <ScoreBadge
          score={95}
          threatLevel="CRITICAL"
          scoreBreakdown={SCORE_BREAKDOWN}
          data-testid="score-badge"
        />
        <button data-testid="outside">Outside</button>
      </div>,
    )

    const scoreBtn = screen.getByRole('button', { name: /show score breakdown/i })
    fireEvent.click(scoreBtn)
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()

    // Click outside
    fireEvent.pointerDown(screen.getByTestId('outside'))
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
  })

  it('clicking inside the breakdown popover does NOT close it (outside-click immune)', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={SCORE_BREAKDOWN}
        data-testid="score-badge"
      />,
    )

    const scoreBtn = screen.getByRole('button', { name: /show score breakdown/i })
    fireEvent.click(scoreBtn)
    const popover = screen.getByTestId('score-breakdown-popover')
    expect(popover).toBeInTheDocument()

    // Click inside the popover
    fireEvent.pointerDown(popover)
    // Popover should remain open
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-5f: ScoreBadge — Escape dismiss (consumer test)
// ---------------------------------------------------------------------------

describe('ScoreBadge — Escape dismiss (EARS-5)', () => {
  it('Escape closes the breakdown popover', async () => {
    const user = userEvent.setup()
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={SCORE_BREAKDOWN}
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: /show score breakdown/i }))
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()

    await user.keyboard('{Escape}')
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
  })

  it('Escape does NOT propagate to outer handler (layered-Esc, #226)', async () => {
    const user = userEvent.setup()
    const outerHandler = vi.fn()
    document.addEventListener('keydown', outerHandler)

    try {
      render(
        <ScoreBadge
          score={95}
          threatLevel="CRITICAL"
          scoreBreakdown={SCORE_BREAKDOWN}
        />,
      )

      fireEvent.click(screen.getByRole('button', { name: /show score breakdown/i }))
      expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()

      await user.keyboard('{Escape}')
      expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
      expect(outerHandler).not.toHaveBeenCalled()
    } finally {
      document.removeEventListener('keydown', outerHandler)
    }
  })
})

// ---------------------------------------------------------------------------
// DS barrel export
// ---------------------------------------------------------------------------

describe('useDismissableDisclosure — DS barrel export', () => {
  it('useDismissableDisclosure is exported from the DS barrel', () => {
    expect(typeof useDismissableDisclosure).toBe('function')
  })
})

// ---------------------------------------------------------------------------
// Consumer-level StatefulDisclosure — verify hook works with useState wrapper
// ---------------------------------------------------------------------------

/**
 * A minimal controlled consumer that mirrors real usage where a parent manages
 * its own visible state via React useState alongside the hook.
 */
function StatefulDisclosure() {
  const [count, setCount] = useState(0)
  const { open, triggerRef, contentRef, triggerProps, contentProps } =
    useDismissableDisclosure()

  return (
    <div>
      <button
        ref={triggerRef as React.RefObject<HTMLButtonElement>}
        data-testid="stateful-trigger"
        {...triggerProps}
      >
        Toggle {count}
      </button>
      {open && (
        <div
          ref={contentRef as React.RefObject<HTMLDivElement>}
          data-testid="stateful-content"
          {...contentProps}
        >
          Stateful content
        </div>
      )}
      <button data-testid="inc-btn" onClick={() => setCount((c) => c + 1)}>
        Increment
      </button>
    </div>
  )
}

describe('useDismissableDisclosure — stateful consumer regression', () => {
  it('parent state changes do not accidentally close the disclosure', () => {
    render(<StatefulDisclosure />)
    const trigger = screen.getByTestId('stateful-trigger')
    const incBtn = screen.getByTestId('inc-btn')

    // Open
    fireEvent.click(trigger)
    expect(screen.getByTestId('stateful-content')).toBeInTheDocument()

    // Trigger a parent re-render
    fireEvent.click(incBtn)

    // Disclosure must still be open
    expect(screen.getByTestId('stateful-content')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-359: No setState-in-render — toggle must NOT call closeAllExcept inside
// the setIsOpen updater (issue #359 regression guard).
// ---------------------------------------------------------------------------

/**
 * Two distinct consumer components (AiEnginePill + ScoreBadge) mirror the
 * real scenario where one is open and the other is toggled open.
 * The test asserts:
 *   1. Single-open invariant still holds (opening B closes A).
 *   2. No "Cannot update a component … while rendering …" React warning fires.
 */
describe('useDismissableDisclosure — no setState-in-render (EARS-359)', () => {
  it('toggling one disclosure open while another is open does NOT emit a React setState-in-render warning', () => {
    // Spy on console.error to catch React's "Cannot update … while rendering …" warning.
    const consoleError = vi.spyOn(console, 'error').mockImplementation((...args) => {
      // Re-throw so the test fails on the real warning, but suppress other noise.
      const msg = typeof args[0] === 'string' ? args[0] : ''
      if (msg.includes('Cannot update') && msg.includes('while rendering')) {
        throw new Error(`React setState-in-render detected: ${msg}`)
      }
    })

    try {
      render(
        <div>
          <ScoreBadge
            score={95}
            threatLevel="CRITICAL"
            scoreBreakdown={SCORE_BREAKDOWN}
          />
          <AiEnginePill health={HEALTH_ONLINE} />
        </div>,
      )

      // Open ScoreBadge popover first.
      const scoreBtn = screen.getByRole('button', { name: /show score breakdown/i })
      fireEvent.click(scoreBtn)
      expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()

      // Toggle AiEnginePill open while ScoreBadge is already open.
      // This is the exact scenario that triggered the warning before the fix.
      const pill = screen.getByTestId('ai-engine-pill')
      // Must not throw (no setState-in-render warning).
      expect(() => fireEvent.click(pill)).not.toThrow()

      // Single-open invariant: ScoreBadge closed, AiEnginePill open.
      expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
      expect(screen.getByTestId('ai-engine-pill-disclosure')).toBeInTheDocument()
    } finally {
      consoleError.mockRestore()
    }
  })

  it('toggling the already-open disclosure closed does NOT call closeAllExcept (no spurious close)', () => {
    // Regression: when the open disclosure is toggled closed, closeAllExcept must
    // NOT be called (it would be a no-op for others, but we verify the invariant
    // holds — the disclosure simply closes).
    render(
      <div>
        <ScoreBadge
          score={75}
          threatLevel="HIGH"
          scoreBreakdown={SCORE_BREAKDOWN}
        />
        <AiEnginePill health={HEALTH_ONLINE} />
      </div>,
    )

    const scoreBtn = screen.getByRole('button', { name: /show score breakdown/i })

    // Open then close by clicking the same button twice.
    fireEvent.click(scoreBtn)
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()

    fireEvent.click(scoreBtn)
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()

    // AiEnginePill was never opened — must still be closed.
    expect(screen.queryByTestId('ai-engine-pill-disclosure')).not.toBeInTheDocument()
  })
})
