/**
 * Tests for the Activity Timeline legend (issue #98, updated issue #247).
 *
 * EARS acceptance criteria (#98):
 *   - The Activity Timeline SHALL display an inline legend when data is present.
 *   - The legend SHALL NOT render when the bucket list is empty (no data = no legend).
 *
 * Issue #247 update:
 *   The default mode is now "severity".  Blocked/Allowed swatches live in the
 *   legend only when in disposition mode (after toggle).  Tests that previously
 *   asserted these swatches in the default render are updated to toggle first,
 *   preserving the correctness of the token-class contract.
 */

import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import TimelineChart from '../components/dashboard/TimelineChart'
import type { TimelineBucket } from '../api/types'

const SINGLE_BUCKET: TimelineBucket[] = [
  {
    hour: '2026-06-04T06:00:00Z',
    total: 100,
    blocked: 60,
    granularity: 'hourly',
    severity: { critical: 10, high: 30, medium: 40, low: 20 },
  },
]

describe('TimelineChart — inline legend (issue #98)', () => {
  it('renders the legend when buckets are present', () => {
    render(<TimelineChart buckets={SINGLE_BUCKET} />)
    expect(screen.getByTestId('timeline-legend')).toBeInTheDocument()
  })

  it('does NOT render the legend when bucket list is empty', () => {
    render(<TimelineChart buckets={[]} />)
    expect(screen.queryByTestId('timeline-legend')).not.toBeInTheDocument()
  })

  it('renders the chart AND the legend together when data is present', () => {
    render(<TimelineChart buckets={SINGLE_BUCKET} />)
    expect(screen.getByTestId('timeline-chart')).toBeInTheDocument()
    expect(screen.getByTestId('timeline-legend')).toBeInTheDocument()
  })

  // Disposition mode (after toggle) — backward-compat for blocked/allowed swatch tests

  it('legend contains "Blocked" label in disposition mode', () => {
    render(<TimelineChart buckets={SINGLE_BUCKET} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    const legend = screen.getByTestId('timeline-legend')
    expect(legend).toHaveTextContent('Blocked')
  })

  it('legend contains "Allowed" label in disposition mode', () => {
    render(<TimelineChart buckets={SINGLE_BUCKET} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    const legend = screen.getByTestId('timeline-legend')
    expect(legend).toHaveTextContent('Allowed')
  })

  it('blocked swatch carries soc-enforced-fg token class (disposition mode, #96)', () => {
    render(<TimelineChart buckets={SINGLE_BUCKET} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    const swatch = screen.getByTestId('timeline-legend-blocked-swatch')
    expect(swatch.className).toContain('soc-enforced-fg')
    // Must not use a hardcoded color — token only
    expect(swatch.className).not.toMatch(/#[0-9a-fA-F]{3,6}/)
  })

  it('allowed swatch carries soc-ok-fg token class (disposition mode, #96)', () => {
    render(<TimelineChart buckets={SINGLE_BUCKET} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    const swatch = screen.getByTestId('timeline-legend-allowed-swatch')
    expect(swatch.className).toContain('soc-ok-fg')
    expect(swatch.className).not.toMatch(/#[0-9a-fA-F]{3,6}/)
  })

  it('blocked swatch and allowed swatch have different token classes (disposition mode)', () => {
    render(<TimelineChart buckets={SINGLE_BUCKET} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    const blockedSwatch = screen.getByTestId('timeline-legend-blocked-swatch')
    const allowedSwatch = screen.getByTestId('timeline-legend-allowed-swatch')
    expect(blockedSwatch.className).not.toEqual(allowedSwatch.className)
  })
})
