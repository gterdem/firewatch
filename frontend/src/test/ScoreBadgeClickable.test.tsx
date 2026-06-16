/**
 * Tests for ScoreBadge whole-badge clickable trigger (issue #330, part-4 P1).
 * Updated for issue #356 (regression fixes):
 *   - aria-label is now value-first: "Risk score N, severity BAND — show score breakdown"
 *   - mouseleave does NOT close the popover (instant-close bug fix)
 *   - second click closes (triggerRef wired correctly)
 *   - Esc returns focus to the trigger
 *
 * EARS acceptance criteria mapped 1:1:
 *
 * EARS-330-1 — WHEN the user clicks anywhere on a ScoreBadge (with scoreBreakdown),
 *              the score-breakdown disclosure SHALL open (same content/behavior as
 *              the previous '?' click).
 *   → "clicking the badge button opens the breakdown popover"
 *   → "clicking a second time toggles the popover closed"
 *   → "clicking on the score text (not just ?) opens the popover"
 *   → "popover shows breakdown contributor labels"
 *
 * EARS-330-2 — WHEN the badge is hovered or keyboard-focused, the system SHALL
 *              show a pointer cursor, a visible hover/focus affordance (amber glow),
 *              and the "Click for score breakdown" hint (title tooltip).
 *   → "badge button has cursor: pointer"
 *   → "badge button has title='Click for score breakdown'"
 *   → "badge shows amber box-shadow on hover (--fw-accent)"
 *   → "badge shows amber box-shadow on focus"
 *   → "glow is absent when badge is not hovered or focused"
 *
 * EARS-330-3 — Ubiquitous: the badge SHALL remain a single accessible button
 *              (one tab stop; accessible name contains score + band); the compact
 *              variant (#263) SHALL get the same whole-badge behavior.
 *   → "badge with scoreBreakdown is a <button> element (single tab stop)"
 *   → "accessible name leads with score + band (WCAG 2.5.3 Label-in-Name)"
 *   → "badge without scoreBreakdown remains presentational span (no button)"
 *   → "compact variant: whole badge is a button when scoreBreakdown provided"
 *   → "compact variant: badge button opens popover on click"
 *   → "compact variant: accessible name contains score + band"
 *   → "? glyph is aria-hidden inside the button (no duplicate screen-reader text)"
 *
 * EARS-330-4 — Ubiquitous: dismiss behavior follows #327 primitive.
 *   → "Esc closes the breakdown popover"
 *   → "Esc returns focus to the trigger button (WCAG focus management)"
 *   → "outside-click closes the breakdown popover"
 *   → "clicking inside the popover does NOT close it"
 *   → "mouse-leave does NOT close the popover (issue #356 fix)"
 *   → "single-open: opening a second ScoreBadge closes the first"
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import { ScoreBadge } from '../components/ds'
import type { ScoreBreakdownItem } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BREAKDOWN: ScoreBreakdownItem[] = [
  { factor: 'brute_force', label: 'Brute force', points: 40 },
  { factor: 'sql_injection', label: 'SQL injection', points: 35 },
]

// Accessible-name helper — matches the new value-first label format.
// e.g. "Risk score 95, severity CRITICAL — show score breakdown"
const BADGE_LABEL_RE = /show score breakdown/i

// ---------------------------------------------------------------------------
// EARS-330-1: Clicking the whole badge opens the breakdown
// ---------------------------------------------------------------------------

describe('ScoreBadge — whole badge opens breakdown on click (EARS-330-1)', () => {
  it('clicking the badge button opens the breakdown popover', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: BADGE_LABEL_RE }))
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
  })

  it('clicking a second time toggles the popover closed', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    const btn = screen.getByRole('button', { name: BADGE_LABEL_RE })
    fireEvent.click(btn)
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
    fireEvent.click(btn)
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
  })

  it('popover shows breakdown contributor labels after click', () => {
    render(
      <ScoreBadge
        score={75}
        threatLevel="HIGH"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: BADGE_LABEL_RE }))
    expect(screen.getByText('Brute force')).toBeInTheDocument()
    expect(screen.getByText('SQL injection')).toBeInTheDocument()
  })

  it('aria-expanded is false before click and true after click', () => {
    render(
      <ScoreBadge
        score={90}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    const btn = screen.getByRole('button', { name: BADGE_LABEL_RE })
    expect(btn.getAttribute('aria-expanded')).toBe('false')
    fireEvent.click(btn)
    expect(btn.getAttribute('aria-expanded')).toBe('true')
  })

  it('legacy onBreakdownClick fires when whole badge is clicked', () => {
    const handler = vi.fn()
    render(
      <ScoreBadge
        score={80}
        threatLevel="HIGH"
        scoreBreakdown={BREAKDOWN}
        onBreakdownClick={handler}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: BADGE_LABEL_RE }))
    expect(handler).toHaveBeenCalledOnce()
  })
})

// ---------------------------------------------------------------------------
// EARS-330-2: Hover / focus affordance
// ---------------------------------------------------------------------------

describe('ScoreBadge — hover/focus affordance (EARS-330-2)', () => {
  it('badge button has cursor: pointer in its style', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    const btn = screen.getByRole('button', { name: BADGE_LABEL_RE })
    expect(btn.style.cursor).toBe('pointer')
  })

  it("badge button has title='Click for score breakdown'", () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    const btn = screen.getByRole('button', { name: BADGE_LABEL_RE })
    expect(btn.getAttribute('title')).toBe('Click for score breakdown')
  })

  it('badge shows amber box-shadow on mouseenter (--fw-accent)', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    const btn = screen.getByRole('button', { name: BADGE_LABEL_RE })
    // No glow before hover
    expect(btn.style.boxShadow).toBe('')
    act(() => { fireEvent.mouseEnter(btn) })
    expect(btn.style.boxShadow).toContain('var(--fw-accent)')
  })

  it('badge removes amber box-shadow on mouseleave (hover state only — popover stays open)', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    const btn = screen.getByRole('button', { name: BADGE_LABEL_RE })
    // Open popover first, then leave — glow should go but popover must stay
    fireEvent.click(btn)
    act(() => { fireEvent.mouseEnter(btn) })
    expect(btn.style.boxShadow).toContain('var(--fw-accent)')
    act(() => { fireEvent.mouseLeave(btn) })
    expect(btn.style.boxShadow).toBe('')
    // Popover still open — mouseleave only clears hover glow, not the popover
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
  })

  it('badge shows amber box-shadow on focus', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    const btn = screen.getByRole('button', { name: BADGE_LABEL_RE })
    expect(btn.style.boxShadow).toBe('')
    act(() => { fireEvent.focus(btn) })
    expect(btn.style.boxShadow).toContain('var(--fw-accent)')
  })

  it('badge removes amber box-shadow on blur', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    const btn = screen.getByRole('button', { name: BADGE_LABEL_RE })
    act(() => { fireEvent.focus(btn) })
    expect(btn.style.boxShadow).toContain('var(--fw-accent)')
    act(() => { fireEvent.blur(btn) })
    expect(btn.style.boxShadow).toBe('')
  })

  it('glow is absent when badge has no scoreBreakdown (non-interactive span)', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        data-testid="badge"
      />,
    )
    const badge = screen.getByTestId('badge')
    // Non-interactive span — no glow, no pointer cursor
    expect(badge.style.boxShadow).toBe('')
  })
})

// ---------------------------------------------------------------------------
// EARS-330-3: Single accessible button; compact variant parity; a11y
// ---------------------------------------------------------------------------

describe('ScoreBadge — single accessible button, compact parity (EARS-330-3)', () => {
  it('badge with scoreBreakdown renders as a <button> element', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
        data-testid="badge"
      />,
    )
    const badge = screen.getByTestId('badge')
    expect(badge.tagName).toBe('BUTTON')
  })

  it('accessible name leads with score + band (WCAG 2.5.3 Label-in-Name) — issue #356', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
        data-testid="badge"
      />,
    )
    const badge = screen.getByTestId('badge')
    const label = badge.getAttribute('aria-label') ?? ''
    // Must contain score and band BEFORE the action phrase
    expect(label).toContain('95')
    expect(label).toContain('CRITICAL')
    expect(label).toMatch(/show score breakdown/i)
    // Value-first: score appears before the action phrase
    expect(label.indexOf('95')).toBeLessThan(label.indexOf('show score breakdown'))
  })

  it('exactly ONE button is rendered (single tab stop) when scoreBreakdown provided', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    expect(screen.getAllByRole('button')).toHaveLength(1)
  })

  it('badge WITHOUT scoreBreakdown remains a <span> (presentational, no tab stop)', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        data-testid="badge"
      />,
    )
    const badge = screen.getByTestId('badge')
    expect(badge.tagName).toBe('SPAN')
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('? glyph is aria-hidden inside the button (no duplicate screen-reader announcement)', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    const btn = screen.getByRole('button', { name: BADGE_LABEL_RE })
    // The ? span inside the button must have aria-hidden="true".
    // There can be multiple aria-hidden spans (e.g. "·" separator in default variant).
    // Find the one whose text content is exactly "?".
    const allHiddenSpans = Array.from(btn.querySelectorAll('span[aria-hidden="true"]'))
    const questionSpan = allHiddenSpans.find((s) => s.textContent === '?')
    expect(questionSpan).toBeDefined()
  })

  it('compact variant: whole badge is a button when scoreBreakdown provided', () => {
    render(
      <ScoreBadge
        score={80}
        threatLevel="HIGH"
        variant="compact"
        scoreBreakdown={BREAKDOWN}
        data-testid="badge"
      />,
    )
    const badge = screen.getByTestId('badge')
    expect(badge.tagName).toBe('BUTTON')
  })

  it('compact variant: badge button opens popover on click', () => {
    render(
      <ScoreBadge
        score={80}
        threatLevel="HIGH"
        variant="compact"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: BADGE_LABEL_RE }))
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
  })

  it('compact variant: accessible name contains score + band', () => {
    render(
      <ScoreBadge
        score={80}
        threatLevel="HIGH"
        variant="compact"
        scoreBreakdown={BREAKDOWN}
        data-testid="badge"
      />,
    )
    const label = screen.getByTestId('badge').getAttribute('aria-label') ?? ''
    expect(label).toContain('80')
    expect(label).toContain('HIGH')
    expect(label).toMatch(/show score breakdown/i)
  })

  it('compact variant: data-band, data-score, data-variant on the button', () => {
    render(
      <ScoreBadge
        score={80}
        threatLevel="HIGH"
        variant="compact"
        scoreBreakdown={BREAKDOWN}
        data-testid="badge"
      />,
    )
    const badge = screen.getByTestId('badge')
    expect(badge.getAttribute('data-band')).toBe('HIGH')
    expect(badge.getAttribute('data-score')).toBe('80')
    expect(badge.getAttribute('data-variant')).toBe('compact')
  })

  it('fw-score-badge class is on the button element', () => {
    const { container } = render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    const el = container.querySelector('.fw-score-badge')
    expect(el).not.toBeNull()
    expect(el?.tagName).toBe('BUTTON')
  })
})

// ---------------------------------------------------------------------------
// EARS-330-4: Dismiss behavior (#327 primitive) — updated for issue #356
// ---------------------------------------------------------------------------

describe('ScoreBadge — dismiss behavior follows #327 (EARS-330-4)', () => {
  it('Esc closes the breakdown popover', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: BADGE_LABEL_RE }))
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
  })

  it('Esc returns focus to the trigger button (WCAG focus management) — issue #356', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    const btn = screen.getByRole('button', { name: BADGE_LABEL_RE })
    fireEvent.click(btn)
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
    // Focus trigger so we can verify it gets it back
    btn.focus()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
    // useDismissableDisclosure restores focus to returnFocusRef (the trigger button)
    expect(document.activeElement).toBe(btn)
  })

  it('outside-click (pointerdown) closes the breakdown popover', () => {
    render(
      <div>
        <ScoreBadge
          score={95}
          threatLevel="CRITICAL"
          scoreBreakdown={BREAKDOWN}
        />
        <button data-testid="outside">Outside</button>
      </div>,
    )
    fireEvent.click(screen.getByRole('button', { name: BADGE_LABEL_RE }))
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
    fireEvent.pointerDown(screen.getByTestId('outside'))
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
  })

  it('clicking inside the popover does NOT close it (outside-click immune)', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
        data-testid="badge"
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: BADGE_LABEL_RE }))
    const popover = screen.getByTestId('score-breakdown-popover')
    expect(popover).toBeInTheDocument()
    fireEvent.pointerDown(popover)
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
  })

  it('mouse-leave from the badge does NOT close the popover (issue #356 instant-close fix)', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={BREAKDOWN}
        data-testid="badge"
      />,
    )
    // Open popover
    fireEvent.click(screen.getByRole('button', { name: BADGE_LABEL_RE }))
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
    // Move pointer off the badge (as happens when travelling to the portaled popover)
    act(() => { fireEvent.mouseLeave(screen.getByTestId('badge')) })
    // Popover MUST remain open — this was the instant-close regression
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
  })

  it('single-open: opening a second ScoreBadge closes the first', () => {
    render(
      <div>
        <ScoreBadge
          score={95}
          threatLevel="CRITICAL"
          scoreBreakdown={BREAKDOWN}
          data-testid="badge-1"
        />
        <ScoreBadge
          score={60}
          threatLevel="HIGH"
          scoreBreakdown={[{ factor: 'port_scan', label: 'Port scan', points: 20 }]}
          data-testid="badge-2"
        />
      </div>,
    )

    // Open the first badge's popover (use regex that matches both badge labels)
    const [btn1, btn2] = screen.getAllByRole('button', { name: BADGE_LABEL_RE })
    fireEvent.click(btn1)
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
    expect(screen.getByText('Brute force')).toBeInTheDocument()

    // Open the second badge — should close the first
    fireEvent.click(btn2)
    // Second popover now visible, not the first's content
    expect(screen.getByText('Port scan')).toBeInTheDocument()
    expect(screen.queryByText('Brute force')).not.toBeInTheDocument()
  })
})
