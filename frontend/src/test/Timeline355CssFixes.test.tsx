/**
 * Tests for issue #355 — CSS/layout fixes in the Activity Timeline.
 *
 * These tests cover what unit tests CAN verify about the bugs that were fixed.
 * Visual/geometry verification (actual rendered widths) must be confirmed in a
 * real browser; this file guards the structural invariants.
 *
 * P3a — bars invisible (0px width, CellTooltip flex collapse):
 *   CellTooltip now accepts a triggerStyle prop.  TimelineChart passes
 *   triggerStyle={{ flex: 1, minWidth: 0 }} to make the trigger span grow as
 *   a flex child instead of collapsing to 0px inline width.
 *   Unit test: the trigger span receives the flex-grow style; segment divs exist.
 *
 * P3c — pill inflates panel header:
 *   lineHeight: 16 (unitless = 160px) → lineHeight: '16px' (string with unit).
 *   Unit test: the pill's inline lineHeight style is a string ending in 'px'.
 *
 * NOTE: P3b tests (TimelineBrush overlay structure) have been removed because
 * TimelineBrush was deleted in part-4 P3 — the brush overlay was blocking
 * CellTooltip bar hover via pointer-events:auto. The 12h/24h window toggle
 * is the replacement (see TimelineWindowToggle.test.tsx).
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import TimelineFilteredPill from '../components/dashboard/TimelineFilteredPill'
import TimelineChart from '../components/dashboard/TimelineChart'
import type { TimelineBucket } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures — RFC-5737 IPs only
// ---------------------------------------------------------------------------

const BUCKET_A: TimelineBucket = {
  hour: '2026-06-11T20:00',
  total: 2,
  blocked: 2,
  granularity: 'hourly',
  severity: { critical: 0, high: 0, medium: 2, low: 0 },
  top_source_ip: '203.0.113.1',
  top_category: 'XSS',
}
const BUCKET_B: TimelineBucket = {
  hour: '2026-06-11T21:00',
  total: 8,
  blocked: 5,
  granularity: 'hourly',
  severity: { critical: 0, high: 0, medium: 5, low: 3 },
  top_source_ip: '203.0.113.2',
  top_category: 'SQL Injection',
}
const BUCKET_C: TimelineBucket = {
  hour: '2026-06-11T22:00',
  total: 4,
  blocked: 4,
  granularity: 'hourly',
  severity: { critical: 0, high: 0, medium: 3, low: 1 },
  top_source_ip: '203.0.113.3',
  top_category: 'Path Traversal',
}
const BUCKETS = [BUCKET_A, BUCKET_B, BUCKET_C]

// ---------------------------------------------------------------------------
// P3c — pill lineHeight fix
// ---------------------------------------------------------------------------

describe('P3c — TimelineFilteredPill lineHeight is a string with unit (issue #355)', () => {
  it('renders the pill with a lineHeight style that is a string (not a bare number)', () => {
    render(<TimelineFilteredPill active={true} />)
    const pill = screen.getByTestId('timeline-filtered-pill')
    // React serialises CSSProperties numbers as unitless — a unitless lineHeight
    // of 16 becomes CSS line-height:16 (= 160px at 10px font-size), inflating the
    // panel header.  The fix uses '16px' (string with unit).
    // jsdom sets .style.lineHeight; check it is not the bare number '16'.
    const lineHeight = pill.style.lineHeight
    expect(typeof lineHeight).toBe('string')
    // Must not be the bare integer that caused the inflation
    expect(lineHeight).not.toBe('16')
    // Must resolve to a reasonable line-height — either a string like '16px',
    // or a small unitless ratio like '1.2' (the actual fix used; CSS best practice
    // for line-height inheritance).  Anything > 4 as a unitless value would be
    // huge (e.g. the original 16 = 160px at 10px font-size).
    const isPxValue = lineHeight.endsWith('px')
    const isSmallUnitlessRatio = !lineHeight.endsWith('px') && parseFloat(lineHeight) < 4
    expect(isPxValue || isSmallUnitlessRatio).toBe(true)
  })

  it('pill does not render when active is false (regression guard)', () => {
    render(<TimelineFilteredPill active={false} />)
    expect(screen.queryByTestId('timeline-filtered-pill')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// P3a — CellTooltip triggerStyle prop propagates to the trigger span
// ---------------------------------------------------------------------------

describe('P3a — CellTooltip triggerStyle applied to trigger span (issue #355)', () => {
  it('TimelineChart bar trigger spans are present in the DOM for each bucket', () => {
    render(<TimelineChart buckets={BUCKETS} />)
    // Each bucket gets a timeline-bar-trigger-{idx} testid via CellTooltip
    expect(screen.getByTestId('timeline-bar-trigger-0')).toBeInTheDocument()
    expect(screen.getByTestId('timeline-bar-trigger-1')).toBeInTheDocument()
    expect(screen.getByTestId('timeline-bar-trigger-2')).toBeInTheDocument()
  })

  it('bar trigger span carries flex:1 style (P3a: grows to fill row instead of collapsing)', () => {
    render(<TimelineChart buckets={BUCKETS} />)
    const trigger = screen.getByTestId('timeline-bar-trigger-0')
    // jsdom serialises flex:1 as the shorthand; check it is set at all.
    // The exact serialisation varies (may be '1 1 0%' or '1'); test that
    // flexGrow is not 0 / not absent.
    const flexValue = trigger.style.flex
    const flexGrow = trigger.style.flexGrow
    // At least one of the two should indicate growth
    const hasGrow =
      (flexValue !== '' && flexValue !== '0') ||
      (flexGrow !== '' && flexGrow !== '0')
    expect(hasGrow).toBe(true)
  })

  it('segment divs are present in the DOM for non-zero buckets', () => {
    render(<TimelineChart buckets={BUCKETS} />)
    // All three buckets have non-zero totals, so at least one severity segment
    // must be present per row (medium or low are non-zero in all three).
    const mediumSegments = screen.getAllByTestId('timeline-segment-medium')
    expect(mediumSegments.length).toBeGreaterThan(0)
  })
})
