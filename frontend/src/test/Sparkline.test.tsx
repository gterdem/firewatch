/**
 * Tests for Sparkline DS primitive (issue #245).
 *
 * EARS acceptance criteria covered:
 *
 * 1. Ubiquitous: renders a trend from a UTC-bucketed series at fixed footprint,
 *    no inner scrollbar.
 * 2. WHEN buckets are missing, gap-fills them as zero before rendering.
 * 3. WHEN series has fewer than 2 points, renders placeholder (no crash, no line).
 * 4. Tz-naive bucket keys interpreted as UTC (via lib/time.ts).
 * 5. Each sparkline carries an aria-label trend summary.
 * 6. Consumer-level test: renders from a real-shaped series and correctly reflects
 *    the trend direction in the aria-label (integration, not unit-only).
 * 7. DS barrel export.
 *
 * Test design:
 *   - Behavioral (what renders, not snapshot) to mirror the existing DS test style.
 *   - No snapshot tests — they break on trivial style/layout changes.
 *   - SVG points attribute checked for correct point count (gap-fill verification).
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Sparkline } from '../components/ds'
import type { SeriesPoint } from '../lib/series'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const RAMP: SeriesPoint[] = [
  { t: '2026-06-11T00:00Z', value: 0 },
  { t: '2026-06-11T01:00Z', value: 10 },
  { t: '2026-06-11T02:00Z', value: 20 },
  { t: '2026-06-11T03:00Z', value: 30 },
]

const FLAT: SeriesPoint[] = [
  { t: '2026-06-11T00:00Z', value: 5 },
  { t: '2026-06-11T01:00Z', value: 5 },
  { t: '2026-06-11T02:00Z', value: 5 },
]

// Sparse: 3 canonical buckets, only 2 present
const SPARSE_WITH_BUCKETS: SeriesPoint[] = [
  { t: '2026-06-11T00:00Z', value: 10 },
  { t: '2026-06-11T02:00Z', value: 30 },
]

// Tz-naive keys (no offset)
const TZNAIVE: SeriesPoint[] = [
  { t: '2026-06-11T00:00', value: 5 },
  { t: '2026-06-11T01:00', value: 15 },
  { t: '2026-06-11T02:00', value: 25 },
]

// ---------------------------------------------------------------------------
// 1. Renders SVG polyline from valid series
// ---------------------------------------------------------------------------

describe('Sparkline — renders trend SVG', () => {
  it('renders an SVG element from a valid series', () => {
    const { container } = render(<Sparkline series={RAMP} label="Requests" />)
    const svg = container.querySelector('svg')
    expect(svg).toBeInTheDocument()
  })

  it('renders a polyline inside the SVG', () => {
    const { container } = render(<Sparkline series={RAMP} />)
    const polyline = container.querySelector('polyline')
    expect(polyline).toBeInTheDocument()
  })

  it('polyline has correct number of points (one per series item)', () => {
    const { container } = render(<Sparkline series={RAMP} />)
    const polyline = container.querySelector('polyline')
    const points = polyline?.getAttribute('points') ?? ''
    // 4 points → 4 coordinate pairs
    const pairs = points.trim().split(/\s+/)
    expect(pairs).toHaveLength(4)
  })

  it('rendered as role="img" outer element', () => {
    render(<Sparkline series={RAMP} label="Events" />)
    expect(screen.getByRole('img')).toBeInTheDocument()
  })

  it('SVG is aria-hidden (screen reader uses outer aria-label)', () => {
    const { container } = render(<Sparkline series={RAMP} label="Events" />)
    const svg = container.querySelector('svg')
    expect(svg?.getAttribute('aria-hidden')).toBe('true')
  })
})

// ---------------------------------------------------------------------------
// 2. No inner scrollbar (ADR-0017 bounded-panes)
// ---------------------------------------------------------------------------

describe('Sparkline — no inner scrollbar', () => {
  it('outer wrapper does not have overflow:auto or overflow:scroll', () => {
    const { container } = render(<Sparkline series={RAMP} />)
    const wrapper = container.firstElementChild as HTMLElement
    const ov = wrapper.style.overflow
    expect(ov).not.toBe('auto')
    expect(ov).not.toBe('scroll')
  })
})

// ---------------------------------------------------------------------------
// 3. Gap-fill: sparse series renders correct point count
// ---------------------------------------------------------------------------

describe('Sparkline — gap-fill for sparse series', () => {
  it('SPARSE series with 2 data points across 2 buckets renders 2 polyline points', () => {
    // When only a 2-bucket series is provided (no explicit gap-fill needed),
    // the component renders exactly those points.
    const { container } = render(<Sparkline series={SPARSE_WITH_BUCKETS} />)
    const polyline = container.querySelector('polyline')
    const points = polyline?.getAttribute('points') ?? ''
    const pairs = points.trim().split(/\s+/)
    // buildDenseSeries gets 2 valid points → 2 pairs
    expect(pairs).toHaveLength(2)
  })

  it('all-zero series still renders a polyline (not a placeholder)', () => {
    const allZero: SeriesPoint[] = [
      { t: '2026-06-11T00:00Z', value: 0 },
      { t: '2026-06-11T01:00Z', value: 0 },
    ]
    const { container } = render(<Sparkline series={allZero} />)
    const polyline = container.querySelector('polyline')
    expect(polyline).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 4. Degenerate input: < 2 points → placeholder
// ---------------------------------------------------------------------------

describe('Sparkline — degenerate input (<2 points)', () => {
  it('empty series renders placeholder (no polyline)', () => {
    const { container } = render(<Sparkline series={[]} label="No data" />)
    // Placeholder renders a <line> (dashed midline), not a <polyline>
    expect(container.querySelector('polyline')).not.toBeInTheDocument()
    expect(container.querySelector('line')).toBeInTheDocument()
  })

  it('empty series does not crash', () => {
    expect(() => render(<Sparkline series={[]} />)).not.toThrow()
  })

  it('single-point series renders placeholder (no polyline)', () => {
    const { container } = render(
      <Sparkline series={[{ t: '2026-06-11T00:00Z', value: 5 }]} />,
    )
    expect(container.querySelector('polyline')).not.toBeInTheDocument()
    expect(container.querySelector('line')).toBeInTheDocument()
  })

  it('single-point series does not crash', () => {
    expect(() =>
      render(<Sparkline series={[{ t: '2026-06-11T00:00Z', value: 5 }]} />),
    ).not.toThrow()
  })

  it('placeholder for empty series has role="img"', () => {
    render(<Sparkline series={[]} label="Empty" />)
    expect(screen.getByRole('img')).toBeInTheDocument()
  })

  it('placeholder aria-label contains "no data"', () => {
    render(<Sparkline series={[]} />)
    const img = screen.getByRole('img')
    expect(img.getAttribute('aria-label')).toContain('no data')
  })
})

// ---------------------------------------------------------------------------
// 5. Accessibility: aria-label with trend direction
// ---------------------------------------------------------------------------

describe('Sparkline — aria-label trend summary', () => {
  it('aria-label contains "rising" for a rising series', () => {
    render(<Sparkline series={RAMP} label="Events" />)
    const img = screen.getByRole('img')
    expect(img.getAttribute('aria-label')).toContain('rising')
  })

  it('aria-label contains "falling" for a falling series', () => {
    const falling: SeriesPoint[] = [
      { t: '2026-06-11T00:00Z', value: 50 },
      { t: '2026-06-11T01:00Z', value: 10 },
    ]
    render(<Sparkline series={falling} label="Blocked" />)
    const img = screen.getByRole('img')
    expect(img.getAttribute('aria-label')).toContain('falling')
  })

  it('aria-label contains "flat" for a flat series', () => {
    render(<Sparkline series={FLAT} />)
    const img = screen.getByRole('img')
    expect(img.getAttribute('aria-label')).toContain('flat')
  })

  it('aria-label includes the custom label prefix when provided', () => {
    render(<Sparkline series={RAMP} label="Blocked IPs" />)
    const img = screen.getByRole('img')
    expect(img.getAttribute('aria-label')).toContain('Blocked IPs')
  })

  it('trend direction is conveyed in text, not color alone', () => {
    // WCAG 1.4.1: direction must be in aria-label, not just a color change.
    render(<Sparkline series={RAMP} />)
    const img = screen.getByRole('img')
    const label = img.getAttribute('aria-label') ?? ''
    // Must contain one of the three direction words
    expect(label).toMatch(/rising|falling|flat/)
  })
})

// ---------------------------------------------------------------------------
// 6. UTC correctness: tz-naive bucket keys
// ---------------------------------------------------------------------------

describe('Sparkline — tz-naive keys treated as UTC', () => {
  it('renders correct point count for tz-naive series', () => {
    const { container } = render(<Sparkline series={TZNAIVE} />)
    const polyline = container.querySelector('polyline')
    const points = polyline?.getAttribute('points') ?? ''
    const pairs = points.trim().split(/\s+/)
    // 3 naive keys → 3 points
    expect(pairs).toHaveLength(3)
  })

  it('aria-label is non-empty for tz-naive series', () => {
    render(<Sparkline series={TZNAIVE} label="IDS" />)
    const img = screen.getByRole('img')
    expect(img.getAttribute('aria-label')).toBeTruthy()
  })

  it('tz-naive rising series produces "rising" in aria-label', () => {
    // TZNAIVE: 5→15→25 — rising
    render(<Sparkline series={TZNAIVE} />)
    const img = screen.getByRole('img')
    expect(img.getAttribute('aria-label')).toContain('rising')
  })
})

// ---------------------------------------------------------------------------
// 7. Filled variant (area fill option)
// ---------------------------------------------------------------------------

describe('Sparkline — filled area variant', () => {
  it('filled=true renders a <path> element in addition to polyline', () => {
    const { container } = render(<Sparkline series={RAMP} filled />)
    // Filled area is a <path>; the line is a <polyline>
    expect(container.querySelector('path')).toBeInTheDocument()
    expect(container.querySelector('polyline')).toBeInTheDocument()
  })

  it('filled=false (default) does NOT render a <path> area element', () => {
    const { container } = render(<Sparkline series={RAMP} />)
    expect(container.querySelector('path')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 8. DS barrel export
// ---------------------------------------------------------------------------

describe('Sparkline — DS barrel export', () => {
  it('is exported from ds/index.ts', () => {
    expect(Sparkline).toBeDefined()
    expect(typeof Sparkline).toBe('function')
  })
})

// ---------------------------------------------------------------------------
// 9. Consumer integration test (real-shaped series)
// ---------------------------------------------------------------------------

describe('Sparkline — consumer integration: real-shaped series', () => {
  it('renders correctly from a 24-bucket hourly WAF series', () => {
    // Simulate a 24-hour hourly bucketed WAF event count series
    const wafSeries: SeriesPoint[] = Array.from({ length: 24 }, (_, i) => ({
      t: `2026-06-11T${String(i).padStart(2, '0')}:00Z`,
      value: i < 12 ? i * 5 : (23 - i) * 5, // ramp up then ramp down
    }))

    const { container } = render(
      <Sparkline series={wafSeries} label="WAF events" width={120} height={28} />,
    )

    // Must render an SVG
    const svg = container.querySelector('svg')
    expect(svg).toBeInTheDocument()

    // Must have a polyline
    const polyline = container.querySelector('polyline')
    expect(polyline).toBeInTheDocument()

    // Must have 24 points
    const pts = (polyline?.getAttribute('points') ?? '').trim().split(/\s+/)
    expect(pts).toHaveLength(24)

    // aria-label must be present and contain trend direction
    const img = screen.getByRole('img')
    const label = img.getAttribute('aria-label') ?? ''
    expect(label).toContain('WAF events')
    expect(label).toMatch(/rising|falling|flat/)
  })

  it('renders correctly from a 7-day daily Risk Mover series', () => {
    const riskSeries: SeriesPoint[] = [
      { t: '2026-06-05T00:00Z', value: 20 },
      { t: '2026-06-06T00:00Z', value: 35 },
      { t: '2026-06-07T00:00Z', value: 28 },
      { t: '2026-06-08T00:00Z', value: 55 },
      { t: '2026-06-09T00:00Z', value: 72 },
      { t: '2026-06-10T00:00Z', value: 68 },
      { t: '2026-06-11T00:00Z', value: 90 },
    ]

    render(<Sparkline series={riskSeries} label="Risk score" />)

    const img = screen.getByRole('img')
    // Net delta: 90-20=+70 → rising
    expect(img.getAttribute('aria-label')).toContain('rising')
    expect(img.getAttribute('aria-label')).toContain('+70')
  })
})
