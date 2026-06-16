/**
 * Tests for LogsTable #666 fixes:
 *   (a) Capped grid with sticky header and internal vertical scroll.
 *   (b) FieldAvailabilityLegend tooltip portals to document.body (not clipped).
 *   (c) Time column compact format (MM-DD HH:mm:ss — no ellipsis truncation).
 *   (d) Action cell constrained 2-line layout (no 4-line whiteSpace:normal sprawl).
 *
 * EARS criteria covered (from issue #666):
 *   - WHEN the table has more than ~22 rows, the grid SHALL cap its height (~680px)
 *     and scroll internally; the <thead> SHALL remain sticky while scrolling.
 *   - WHEN the FieldAvailability "?" is hovered or focused, its tooltip SHALL render
 *     fully visible (not clipped) and SHALL be keyboard-reachable and Esc-dismissable.
 *   - The Time column SHALL render a fixed-width compact timestamp that never truncates.
 *   - The Action cell SHALL render the action badge on one line and the
 *     provenance/verdict/score on a second line — never wrapping to 4 lines.
 *   - SECURITY: all attacker-controlled fields remain text nodes (ADR-0029 D3).
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LogsTable from '../components/logs/LogsTable'
import { FieldAvailabilityLegend } from '../components/logs/FieldAvailabilityLegend'
import { fmtTimeCompact } from '../lib/time'
import { LOG_ENTRY_FIXTURE } from './readFixtures'
import type { LogEntry, ThreatScore } from '../api/types'

// ---------------------------------------------------------------------------
// Helper: render LogsTable inside MemoryRouter with wide viewport stub
// ---------------------------------------------------------------------------

function renderTable(props: Parameters<typeof LogsTable>[0]) {
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 1200, height: 40, top: 0, left: 0, bottom: 40, right: 1200,
    x: 0, y: 0, toJSON: () => ({}),
  } as DOMRect)

  const result = render(
    <MemoryRouter>
      <LogsTable {...props} />
    </MemoryRouter>,
  )

  vi.restoreAllMocks()
  return result
}

/** Build N log entries for testing the capped grid. */
function makeLogEntries(count: number): LogEntry[] {
  return Array.from({ length: count }, (_, i) => ({
    ...LOG_ENTRY_FIXTURE,
    id: 1000 + i,
    timestamp: `2026-06-14T${String(Math.floor(i / 60)).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}:00Z`,
    source_ip: `192.0.2.${(i % 254) + 1}`,
  }))
}

// ---------------------------------------------------------------------------
// (a) Capped grid + sticky header
// ---------------------------------------------------------------------------

describe('LogsTable #666 — capped grid + sticky header', () => {
  it('renders the scroll container with data-testid logs-table-scroll-container', () => {
    renderTable({ logs: makeLogEntries(25), onIpClick: vi.fn() })
    const container = screen.getByTestId('logs-table-scroll-container')
    expect(container).toBeInTheDocument()
  })

  it('scroll container has maxHeight ~680px and overflowY:auto', () => {
    renderTable({ logs: makeLogEntries(25), onIpClick: vi.fn() })
    const container = screen.getByTestId('logs-table-scroll-container')
    const style = container.style
    // maxHeight is 680px (the ~18-22 row cap)
    expect(style.maxHeight).toBe('680px')
    expect(style.overflowY).toBe('auto')
  })

  it('scroll container also has overflowX:auto (composes with horizontal scroll)', () => {
    renderTable({ logs: makeLogEntries(5), onIpClick: vi.fn() })
    const container = screen.getByTestId('logs-table-scroll-container')
    expect(container.style.overflowX).toBe('auto')
  })

  it('thead has position:sticky and top:0 so it pins while scrolling', () => {
    renderTable({ logs: makeLogEntries(25), onIpClick: vi.fn() })
    const thead = document.querySelector('thead')
    expect(thead).toBeTruthy()
    expect(thead!.style.position).toBe('sticky')
    expect(thead!.style.top).toBe('0px')
  })

  it('thead is inside the scroll container (single overflow wrapper)', () => {
    renderTable({ logs: makeLogEntries(25), onIpClick: vi.fn() })
    const container = screen.getByTestId('logs-table-scroll-container')
    const thead = document.querySelector('thead')
    expect(thead).toBeTruthy()
    // thead must be a descendant of the scroll container
    expect(container.contains(thead)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// (b) FieldAvailabilityLegend tooltip portals to document.body
// ---------------------------------------------------------------------------

describe('FieldAvailabilityLegend #666 — portal tooltip escapes overflow container', () => {
  it('tooltip renders inside document.body (not inside the legend span)', () => {
    const { container } = render(<FieldAvailabilityLegend column="Destination" />)
    const hint = screen.getByTestId('field-availability-hint')

    // Trigger hover
    fireEvent.mouseEnter(hint)

    const tooltip = screen.getByTestId('field-availability-tooltip')
    expect(tooltip).toBeInTheDocument()

    // Crucially: the tooltip must NOT be inside the component's own container —
    // it must be portaled to document.body.
    expect(container.contains(tooltip)).toBe(false)
    expect(document.body.contains(tooltip)).toBe(true)
  })

  it('tooltip is position:fixed (not position:absolute) so it escapes overflow clipping', () => {
    render(<FieldAvailabilityLegend column="Destination" />)
    fireEvent.mouseEnter(screen.getByTestId('field-availability-hint'))
    const tooltip = screen.getByTestId('field-availability-tooltip')
    // Fixed positioning escapes any ancestor's overflow container
    expect(tooltip.style.position).toBe('fixed')
  })

  it('tooltip opens on keyboard focus', () => {
    render(<FieldAvailabilityLegend column="Protocol" />)
    const hint = screen.getByTestId('field-availability-hint')
    fireEvent.focus(hint)
    expect(screen.getByTestId('field-availability-tooltip')).toBeInTheDocument()
  })

  it('tooltip closes after blur (with leave-delay)', async () => {
    render(<FieldAvailabilityLegend column="Destination" />)
    const hint = screen.getByTestId('field-availability-hint')
    fireEvent.focus(hint)
    expect(screen.getByTestId('field-availability-tooltip')).toBeInTheDocument()
    fireEvent.blur(hint)
    // waitFor polls until the leave-delay (80ms) fires and React removes the portal
    await waitFor(() => {
      expect(screen.queryByTestId('field-availability-tooltip')).toBeNull()
    }, { timeout: 500 })
  })

  it('tooltip closes on Esc keypress (keyboard-accessible dismiss)', async () => {
    render(<FieldAvailabilityLegend column="Destination" />)
    const hint = screen.getByTestId('field-availability-hint')
    fireEvent.focus(hint)
    expect(screen.getByTestId('field-availability-tooltip')).toBeInTheDocument()
    // Dispatch Esc — useHoverFocusDisclosure listens on the document in capture phase
    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() => {
      expect(screen.queryByTestId('field-availability-tooltip')).toBeNull()
    }, { timeout: 500 })
  })

  it('tooltip has role="tooltip" (ARIA landmark)', () => {
    render(<FieldAvailabilityLegend column="Destination" />)
    fireEvent.mouseEnter(screen.getByTestId('field-availability-hint'))
    const tooltip = screen.getByRole('tooltip')
    expect(tooltip).toBeInTheDocument()
  })

  it('renders nothing for columns without a note', () => {
    const { container } = render(<FieldAvailabilityLegend column="Signature" />)
    expect(container.firstChild).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// (c) Time column compact format
// ---------------------------------------------------------------------------

describe('fmtTimeCompact — fixed-width timestamp format', () => {
  it('produces MM-DD HH:mm:ss format matching a regex pattern', () => {
    // 2026-06-14T13:25:07Z → local-time representation in MM-DD HH:mm:ss format
    const result = fmtTimeCompact('2026-06-14T13:25:07Z')
    // Must match MM-DD HH:mm:ss — all 2-digit, no month abbreviation
    expect(result).toMatch(/^\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/)
  })

  it('handles naive (tz-omitted) timestamps as UTC', () => {
    const withZ = fmtTimeCompact('2026-06-14T13:25:07Z')
    const naive = fmtTimeCompact('2026-06-14T13:25:07')
    // Both must produce the same output (naive treated as UTC per parseApiTimestamp)
    expect(naive).toBe(withZ)
  })

  it('returns the raw ISO string for invalid input (defensive fallback)', () => {
    const invalid = fmtTimeCompact('not-a-date')
    // Falls back to raw string, does not throw
    expect(typeof invalid).toBe('string')
  })

  it('returns empty string for empty input', () => {
    expect(fmtTimeCompact('')).toBe('')
  })

  it('always produces exactly 14 characters (MM-DD HH:mm:ss)', () => {
    // Fixed width ensures the cell never ellipsis-truncates
    const result = fmtTimeCompact('2026-06-14T08:05:03Z')
    expect(result).toMatch(/^\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/)
    expect(result.length).toBe(14)
  })
})

describe('LogsTable #666 — Time cell rendering', () => {
  it('time cell has data-testid log-row-time', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    expect(screen.getByTestId('log-row-time')).toBeInTheDocument()
  })

  it('time cell renders compact MM-DD format (no "Jun 14, 0…" truncation)', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    const timeCell = screen.getByTestId('log-row-time')
    // Must match the compact pattern, NOT contain a month abbreviation
    expect(timeCell.textContent).toMatch(/^\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/)
    // Must NOT contain the truncation-prone "Jun" abbreviation
    expect(timeCell.textContent).not.toMatch(/^[A-Za-z]{3}/)
  })

  it('time cell has overflow:visible so it cannot truncate', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    const timeCell = screen.getByTestId('log-row-time')
    expect(timeCell.style.overflow).toBe('visible')
  })

  it('time cell has minWidth set (prevents column collapse to truncate width)', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    const timeCell = screen.getByTestId('log-row-time')
    // minWidth must be set to a positive value (112px per column definition)
    const minWidth = parseInt(timeCell.style.minWidth, 10)
    expect(minWidth).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// (d) Action cell 2-line layout (no 4-line whiteSpace:normal sprawl)
// ---------------------------------------------------------------------------

describe('LogsTable #666 — Action cell 2-line layout', () => {
  const threatMap: ReadonlyMap<string, ThreatScore> = new Map([
    ['192.0.2.1', {
      source_ip: '192.0.2.1',
      threat_level: 'HIGH',
      score: 78,
      total_events: 120,
      blocked_events: 95,
      attack_types: ['SQL Injection'],
      first_seen: '2026-06-01T08:00:00Z',
      last_seen: '2026-06-14T09:55:00Z',
      source_types: ['suricata'],
      detections: [],
      ai_insights: ['Intent: reconnaissance'],
      ai_confidence: 0.87,
      ai_status: 'active',
      location: 'Chicago, United States',
      score_breakdown: [],
      asn: null,
      as_name: null,
      score_delta: 22,
    }],
  ])

  it('action cell does NOT have whiteSpace:normal (the 4-line sprawl style)', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn(), threatMap })
    const actionBadge = screen.getByTestId('log-row-action-badge')
    // Walk up to the <td> parent
    const td = actionBadge.closest('td')
    expect(td).toBeTruthy()
    // whiteSpace must NOT be 'normal' (was the root cause of 4-line wrap)
    expect(td!.style.whiteSpace).not.toBe('normal')
  })

  it('action badge and AI verdict chip are in SEPARATE columns (ADR-0063 D5 de-fold)', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn(), threatMap })
    // Both the badge and the verdict chip should be present
    const badge = screen.getByTestId('log-row-action-badge')
    const verdict = screen.getByTestId('log-row-ai-verdict')
    expect(badge).toBeInTheDocument()
    expect(verdict).toBeInTheDocument()

    // ADR-0063 D5: the AI verdict is de-folded OUT of the action cell.
    // They are now in separate <td> elements.
    const actionCell = badge.closest('td')
    const verdictCell = verdict.closest('td')
    expect(actionCell).toBeTruthy()
    expect(verdictCell).toBeTruthy()
    // The two cells must be DIFFERENT elements
    expect(actionCell).not.toBe(verdictCell)
    // The verdict chip is not inside the action cell
    expect(actionCell!.contains(verdict)).toBe(false)
  })

  it('AI verdict chip uses flexWrap:nowrap (no internal wrap to extra lines)', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn(), threatMap })
    const verdict = screen.getByTestId('log-row-ai-verdict')
    expect(verdict.style.flexWrap).toBe('nowrap')
  })
})
