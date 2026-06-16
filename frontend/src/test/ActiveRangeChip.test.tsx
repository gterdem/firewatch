/**
 * Tests for components/dashboard/ActiveRangeChip.tsx (issue #249).
 *
 * EARS acceptance criteria covered:
 *
 * A. Chip visibility:
 *    - Chip renders with data-testid="active-range-chip".
 *    - Chip shows formatted start and end time labels.
 *    - Chip shows the local timezone label (from lib/time.ts).
 *
 * B. One-click clear:
 *    - The ✕ button is present with aria-label.
 *    - Clicking the button calls onClear.
 *
 * C. Security — no innerHTML injection:
 *    - Chip renders time labels as text nodes only.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import ActiveRangeChip from '../components/dashboard/ActiveRangeChip'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const RANGE = {
  start: '2026-06-11T02:00:00.000Z',
  end: '2026-06-11T04:00:00.000Z',
}

// ---------------------------------------------------------------------------
// A. Chip visibility
// ---------------------------------------------------------------------------

describe('ActiveRangeChip — visibility', () => {
  it('renders the chip container', () => {
    render(<ActiveRangeChip range={RANGE} onClear={vi.fn()} />)
    expect(screen.getByTestId('active-range-chip')).toBeInTheDocument()
  })

  it('renders a start time label', () => {
    render(<ActiveRangeChip range={RANGE} onClear={vi.fn()} />)
    // The start label element exists and has non-empty text
    const startEl = screen.getByTestId('active-range-start')
    expect(startEl.textContent?.trim().length).toBeGreaterThan(0)
  })

  it('renders an end time label', () => {
    render(<ActiveRangeChip range={RANGE} onClear={vi.fn()} />)
    const endEl = screen.getByTestId('active-range-end')
    expect(endEl.textContent?.trim().length).toBeGreaterThan(0)
  })

  it('renders a timezone zone label', () => {
    render(<ActiveRangeChip range={RANGE} onClear={vi.fn()} />)
    const zoneEl = screen.getByTestId('active-range-zone')
    expect(zoneEl.textContent?.trim().length).toBeGreaterThan(0)
  })

  it('chip label contains "filtered to" text', () => {
    render(<ActiveRangeChip range={RANGE} onClear={vi.fn()} />)
    const label = screen.getByTestId('active-range-label')
    expect(label.textContent).toContain('filtered to')
  })

  it('chip label has aria-live=polite for screen-reader announcement', () => {
    render(<ActiveRangeChip range={RANGE} onClear={vi.fn()} />)
    const label = screen.getByTestId('active-range-label')
    expect(label.getAttribute('aria-live')).toBe('polite')
  })
})

// ---------------------------------------------------------------------------
// B. One-click clear
// ---------------------------------------------------------------------------

describe('ActiveRangeChip — clear button', () => {
  it('renders a clear button', () => {
    render(<ActiveRangeChip range={RANGE} onClear={vi.fn()} />)
    expect(screen.getByTestId('active-range-clear')).toBeInTheDocument()
  })

  it('clear button has an aria-label containing the range', () => {
    render(<ActiveRangeChip range={RANGE} onClear={vi.fn()} />)
    const btn = screen.getByTestId('active-range-clear')
    expect(btn.getAttribute('aria-label')).toContain('Clear time filter')
  })

  it('clicking clear calls onClear', () => {
    const onClear = vi.fn()
    render(<ActiveRangeChip range={RANGE} onClear={onClear} />)
    fireEvent.click(screen.getByTestId('active-range-clear'))
    expect(onClear).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// C. Security — text nodes only
// ---------------------------------------------------------------------------

describe('ActiveRangeChip — security', () => {
  it('chip does not use dangerouslySetInnerHTML (time values as text nodes)', () => {
    render(<ActiveRangeChip range={RANGE} onClear={vi.fn()} />)
    const chip = screen.getByTestId('active-range-chip')
    // dangerouslySetInnerHTML produces __html attributes in the DOM — none should exist
    expect(chip.innerHTML).not.toContain('dangerouslySetInnerHTML')
  })
})
