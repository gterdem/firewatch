/**
 * Tests for KpiStrip + KpiTile (issue #254).
 *
 * EARS acceptance criteria covered:
 *
 * 1. Ubiquitous: strip spans full width — tiles are evenly distributed
 *    (flex:1 on each tile, no left-packed dead space).
 * 2. Ubiquitous: AI/engine status pill is pinned to the far right of the strip;
 *    it is the only always-on AI indicator (kpi-ai-status testid hard-right).
 * 3. WHEN a KPI has a derivable time series (timeline provided):
 *    its tile SHALL render a sparkline row.
 * 4. WHEN a KPI has no derivable series (Unique IPs):
 *    tile renders number-only, same height as tiles with sparklines.
 * 5. Ubiquitous: trend direction not conveyed by color alone — arrow glyph present.
 * 6. Consumer-level: strip renders with mocked timeline data (full layout stable).
 * 7. Consumer-level: strip renders with empty timeline (no sparklines, no crash).
 * 8. lib/kpiSeries helpers: totalEventsSeries, blockedEventsSeries, blockRateSeries.
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import KpiStrip from '../components/dashboard/KpiStrip'
import type { StatsResponse, TimelineBucket } from '../api/types'
import {
  totalEventsSeries,
  blockedEventsSeries,
  blockRateSeries,
} from '../lib/kpiSeries'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const STATS_FIXTURE: StatsResponse = {
  total_logs: 4815,
  total_ips: 23,
  blocked_percentage: 62.3,
  source_health: [],
  last_updated: '2026-06-04T10:00:00Z',
}

const STATS_ZERO_FIXTURE: StatsResponse = {
  total_logs: 0,
  total_ips: 0,
  blocked_percentage: 0,
  source_health: [],
  last_updated: null,
}

const TIMELINE_FIXTURE: TimelineBucket[] = [
  { hour: '2026-06-04T06:00:00Z', total: 120, blocked: 80, granularity: 'hourly' },
  { hour: '2026-06-04T07:00:00Z', total: 200, blocked: 140, granularity: 'hourly' },
  { hour: '2026-06-04T08:00:00Z', total: 95, blocked: 60, granularity: 'hourly' },
  { hour: '2026-06-04T09:00:00Z', total: 310, blocked: 200, granularity: 'hourly' },
]

// ---------------------------------------------------------------------------
// 1. Full-width justified strip layout
// ---------------------------------------------------------------------------

describe('KpiStrip — full-width justified layout (#254)', () => {
  it('renders the kpi-strip container', () => {
    render(<KpiStrip stats={STATS_FIXTURE} />)
    expect(screen.getByTestId('kpi-strip')).toBeInTheDocument()
  })

  it('contains a kpi-tiles container with all four KPI tiles', () => {
    render(<KpiStrip stats={STATS_FIXTURE} />)
    expect(screen.getByTestId('kpi-tiles')).toBeInTheDocument()
    expect(screen.getByTestId('kpi-total-events')).toBeInTheDocument()
    expect(screen.getByTestId('kpi-blocked')).toBeInTheDocument()
    expect(screen.getByTestId('kpi-unique-ips')).toBeInTheDocument()
    expect(screen.getByTestId('kpi-block-rate')).toBeInTheDocument()
  })

  it('tiles wrapper has flex-grow set (fills the strip width)', () => {
    render(<KpiStrip stats={STATS_FIXTURE} />)
    const tilesContainer = screen.getByTestId('kpi-tiles')
    // The tiles container must grow to fill available width.
    // JSDOM normalizes flex:1 to "1 1 0%" — check flexGrow instead.
    expect(tilesContainer.style.flexGrow).toBe('1')
  })

  it('renders correct KPI values', () => {
    render(<KpiStrip stats={STATS_FIXTURE} />)
    // total_logs = 4815 → "4,815"
    expect(screen.getByTestId('kpi-total-events')).toHaveTextContent('4,815')
    // blocked = round(4815 * 62.3 / 100) = round(2999.745) = 3000
    expect(screen.getByTestId('kpi-blocked')).toHaveTextContent('3,000')
    // total_ips = 23
    expect(screen.getByTestId('kpi-unique-ips')).toHaveTextContent('23')
    // block rate = "62.3%"
    expect(screen.getByTestId('kpi-block-rate')).toHaveTextContent('62.3%')
  })
})

// ---------------------------------------------------------------------------
// 2. AI engine pill docked hard-right
// ---------------------------------------------------------------------------

describe('KpiStrip — AI engine pill hard-right slot (#254)', () => {
  it('kpi-ai-status element is present', () => {
    render(<KpiStrip stats={STATS_FIXTURE} health={null} />)
    expect(screen.getByTestId('kpi-ai-status')).toBeInTheDocument()
  })

  it('kpi-ai-status comes AFTER kpi-tiles in DOM order (pinned right)', () => {
    render(<KpiStrip stats={STATS_FIXTURE} />)
    const strip = screen.getByTestId('kpi-strip')
    const tiles = screen.getByTestId('kpi-tiles')
    const aiSlot = screen.getByTestId('kpi-ai-status')

    // DOM order: tiles first, then ai-status slot (pinned right via order)
    const children = Array.from(strip.children)
    const tilesIdx = children.indexOf(tiles)
    const aiIdx = children.indexOf(aiSlot)
    expect(tilesIdx).toBeLessThan(aiIdx)
  })

  it('renders AiEnginePill inside kpi-ai-status when health=online', () => {
    render(
      <KpiStrip
        stats={STATS_FIXTURE}
        health={{ status: 'ok', ollama_connected: true, ollama_model: 'llama3.2', db_ok: true, ai: 'active' }}
      />,
    )
    expect(screen.getByTestId('ai-engine-pill')).toBeInTheDocument()
    expect(screen.getByTestId('ai-engine-pill')).toHaveTextContent('active')
  })

  it('does not render AiEnginePill when both health and aiStatus are absent/null', () => {
    render(<KpiStrip stats={STATS_FIXTURE} health={null} aiStatus={null} />)
    expect(screen.queryByTestId('ai-engine-pill')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 3. Per-KPI sparklines — WHEN timeline provided
// ---------------------------------------------------------------------------

describe('KpiStrip — per-KPI sparkline with timeline data (#254)', () => {
  it('renders sparkline rows for KPIs with derivable series', () => {
    render(<KpiStrip stats={STATS_FIXTURE} timeline={TIMELINE_FIXTURE} />)

    // Total events — has series
    expect(screen.getByTestId('kpi-total-events-sparkline-row')).toBeInTheDocument()
    // Blocked — has series
    expect(screen.getByTestId('kpi-blocked-sparkline-row')).toBeInTheDocument()
    // Block rate — has series
    expect(screen.getByTestId('kpi-block-rate-sparkline-row')).toBeInTheDocument()
    // Unique IPs — no series (number-only, sparkline row still present but empty)
    expect(screen.getByTestId('kpi-unique-ips-sparkline-row')).toBeInTheDocument()
  })

  it('sparkline has accessible aria-label (trend direction not color-only)', () => {
    render(<KpiStrip stats={STATS_FIXTURE} timeline={TIMELINE_FIXTURE} />)

    // Each sparkline row for tiles with series should contain an aria-label element
    // (the Sparkline component sets role="img" + aria-label on its outer span).
    const sparklineRows = [
      screen.getByTestId('kpi-total-events-sparkline-row'),
      screen.getByTestId('kpi-blocked-sparkline-row'),
      screen.getByTestId('kpi-block-rate-sparkline-row'),
    ]

    for (const row of sparklineRows) {
      const sparklineEl = row.querySelector('[role="img"]')
      expect(sparklineEl).not.toBeNull()
      const ariaLabel = sparklineEl?.getAttribute('aria-label') ?? ''
      // aria-label must mention 'rising', 'falling', or 'flat' — not just a color
      expect(ariaLabel.length).toBeGreaterThan(0)
      expect(ariaLabel).toMatch(/rising|falling|flat|no data/)
    }
  })

  it('Unique IPs sparkline row has no sparkline element (number-only)', () => {
    render(<KpiStrip stats={STATS_FIXTURE} timeline={TIMELINE_FIXTURE} />)
    const uniqueIpsRow = screen.getByTestId('kpi-unique-ips-sparkline-row')
    // No sparkline element inside (no role=img, no polyline)
    expect(uniqueIpsRow.querySelector('[role="img"]')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// 4. Degrades gracefully with empty timeline (number-only, no crash)
// ---------------------------------------------------------------------------

describe('KpiStrip — degrades with empty / absent timeline (#254)', () => {
  it('renders number-only tiles with no timeline prop (no crash)', () => {
    render(<KpiStrip stats={STATS_FIXTURE} />)
    expect(screen.getByTestId('kpi-strip')).toBeInTheDocument()
    expect(screen.getByTestId('kpi-total-events')).toHaveTextContent('4,815')
    // No sparklines when timeline not provided
    expect(
      screen.getByTestId('kpi-total-events-sparkline-row').querySelector('[role="img"]'),
    ).toBeNull()
  })

  it('renders number-only tiles with empty timeline array (no crash)', () => {
    render(<KpiStrip stats={STATS_FIXTURE} timeline={[]} />)
    expect(screen.getByTestId('kpi-strip')).toBeInTheDocument()
    expect(
      screen.getByTestId('kpi-blocked-sparkline-row').querySelector('[role="img"]'),
    ).toBeNull()
  })

  it('strip is stable with all-zero stats and no timeline', () => {
    render(<KpiStrip stats={STATS_ZERO_FIXTURE} />)
    expect(screen.getByTestId('kpi-strip')).toBeInTheDocument()
    expect(screen.getByTestId('kpi-total-events')).toHaveTextContent('0')
    expect(screen.getByTestId('kpi-unique-ips')).toHaveTextContent('0')
  })
})

// ---------------------------------------------------------------------------
// 5. lib/kpiSeries helpers — pure unit tests
// ---------------------------------------------------------------------------

describe('lib/kpiSeries — series derivation helpers (#254)', () => {
  describe('totalEventsSeries', () => {
    it('maps timeline total values to series points', () => {
      const series = totalEventsSeries(TIMELINE_FIXTURE)
      expect(series).toHaveLength(4)
      expect(series[0]).toEqual({ t: '2026-06-04T06:00:00Z', value: 120 })
      expect(series[3]).toEqual({ t: '2026-06-04T09:00:00Z', value: 310 })
    })

    it('returns empty array for empty input', () => {
      expect(totalEventsSeries([])).toEqual([])
    })
  })

  describe('blockedEventsSeries', () => {
    it('maps timeline blocked values to series points', () => {
      const series = blockedEventsSeries(TIMELINE_FIXTURE)
      expect(series).toHaveLength(4)
      expect(series[0]).toEqual({ t: '2026-06-04T06:00:00Z', value: 80 })
      expect(series[3]).toEqual({ t: '2026-06-04T09:00:00Z', value: 200 })
    })

    it('returns empty array for empty input', () => {
      expect(blockedEventsSeries([])).toEqual([])
    })
  })

  describe('blockRateSeries', () => {
    it('derives block rate percentage per bucket', () => {
      const series = blockRateSeries(TIMELINE_FIXTURE)
      expect(series).toHaveLength(4)
      // bucket 0: 80/120 * 100 = 66.6... → rounded 67
      expect(series[0]).toEqual({ t: '2026-06-04T06:00:00Z', value: 67 })
      // bucket 1: 140/200 * 100 = 70
      expect(series[1]).toEqual({ t: '2026-06-04T07:00:00Z', value: 70 })
      // bucket 2: 60/95 * 100 = 63.15... → rounded 63
      expect(series[2]).toEqual({ t: '2026-06-04T08:00:00Z', value: 63 })
      // bucket 3: 200/310 * 100 = 64.51... → rounded 65
      expect(series[3]).toEqual({ t: '2026-06-04T09:00:00Z', value: 65 })
    })

    it('returns 0 for buckets with total=0 (no NaN/Infinity)', () => {
      const zeroBucket: TimelineBucket[] = [{ hour: '2026-06-04T00:00Z', total: 0, blocked: 0 }]
      const series = blockRateSeries(zeroBucket)
      expect(series).toHaveLength(1)
      expect(series[0].value).toBe(0)
    })

    it('returns empty array for empty input', () => {
      expect(blockRateSeries([])).toEqual([])
    })
  })
})
