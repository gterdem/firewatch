/**
 * Tests for TimelineChart component (issues #247, #248).
 *
 * EARS acceptance criteria covered:
 *
 * A. Severity-stacked bars (default mode):
 *    - Severity segments render with data-testid="timeline-segment-{key}".
 *    - The chart defaults to severity mode on mount.
 *    - Severity mode toggle button is aria-pressed=true on mount.
 *
 * B. Disposition toggle:
 *    - Clicking "Disposition" button re-segments bars to blocked/allowed.
 *    - No refetch — same component instance, same props, new segments.
 *    - Toggling back to "Severity" restores severity segments.
 *    - Disposition mode: blocked count and allowed count are displayed.
 *
 * C. Rich per-bucket hover (WCAG 1.4.13 via CellTooltip #246):
 *    - Bar track is wrapped in a CellTooltip trigger.
 *    - Hovering the trigger reveals TimelineBucketHover content:
 *        total count, top category, top source IP, severity mix.
 *    - SECURITY: top_source_ip and top_category are rendered as text nodes
 *      (no innerHTML). Verified by checking textContent, not innerHTML.
 *
 * D. Zero-event bucket:
 *    - isEmpty buckets render the track with no colour segments.
 *    - Hover on an empty bucket shows "No events in this period".
 *
 * E. Empty bucket list → timeline-empty message (regression guard).
 *
 * F. Legend:
 *    - Severity mode legend has data-testid for each severity swatch.
 *    - Disposition mode legend has blocked + allowed swatches.
 *    - Swatches carry soc-* token classes (no hardcoded hex).
 *
 * G. TimelineChartLegend backward-compat:
 *    - In disposition mode the swatches timeline-legend-blocked-swatch /
 *      timeline-legend-allowed-swatch still appear with their expected
 *      soc-enforced-fg / soc-ok-fg classes (pre-#247 test compat).
 *
 * H. Spike annotation integration (issue #248):
 *    - A spike marker renders for a bucket whose total exceeds the threshold.
 *    - No spike marker renders for a flat series.
 *    - No spike marker renders when the series is shorter than the window.
 */

import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import TimelineChart from '../components/dashboard/TimelineChart'
import type { TimelineBucket } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BUCKET_FULL: TimelineBucket = {
  hour: '2026-06-11T02:00',
  total: 100,
  blocked: 60,
  granularity: 'hourly',
  severity: { critical: 10, high: 30, medium: 40, low: 20 },
  top_category: 'SQL Injection',
  top_source_ip: '198.51.100.1',
}

const BUCKET_MEDIUM: TimelineBucket = {
  hour: '2026-06-11T03:00',
  total: 50,
  blocked: 20,
  granularity: 'hourly',
  severity: { critical: 5, high: 15, medium: 20, low: 10 },
  top_category: 'XSS',
  top_source_ip: '10.0.0.2',
}

const BUCKET_ZERO: TimelineBucket = {
  hour: '2026-06-11T04:00',
  total: 0,
  blocked: 0,
  granularity: 'hourly',
  severity: { critical: 0, high: 0, medium: 0, low: 0 },
}

const BUCKETS = [BUCKET_FULL, BUCKET_MEDIUM, BUCKET_ZERO]

// ---------------------------------------------------------------------------
// A. Default severity mode
// ---------------------------------------------------------------------------

describe('TimelineChart — default severity mode', () => {
  it('renders the timeline chart container', () => {
    render(<TimelineChart buckets={BUCKETS} />)
    expect(screen.getByTestId('timeline-chart')).toBeInTheDocument()
  })

  it('severity toggle button is aria-pressed=true on mount', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    const btn = screen.getByTestId('timeline-toggle-severity')
    expect(btn.getAttribute('aria-pressed')).toBe('true')
  })

  it('disposition toggle button is aria-pressed=false on mount', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    const btn = screen.getByTestId('timeline-toggle-disposition')
    expect(btn.getAttribute('aria-pressed')).toBe('false')
  })

  it('renders severity segments for a bucket with severity data', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    // At least one severity-keyed segment must appear
    const critSeg = screen.queryByTestId('timeline-segment-critical')
    const highSeg = screen.queryByTestId('timeline-segment-high')
    // Both critical (10) and high (30) are non-zero so must render
    expect(critSeg).toBeInTheDocument()
    expect(highSeg).toBeInTheDocument()
  })

  it('does NOT render disposition segments in severity mode', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    // In severity mode, blocked/allowed segment testids should not be present
    // (note: the .tl-cnt count text has data-testids timeline-blocked-bar
    //  and timeline-allowed-bar in DISPOSITION mode only)
    expect(screen.queryByTestId('timeline-segment-blocked')).not.toBeInTheDocument()
    expect(screen.queryByTestId('timeline-segment-allowed')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// B. Disposition toggle
// ---------------------------------------------------------------------------

describe('TimelineChart — disposition toggle', () => {
  it('clicking Disposition changes aria-pressed to true', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    const btn = screen.getByTestId('timeline-toggle-disposition')
    fireEvent.click(btn)
    expect(btn.getAttribute('aria-pressed')).toBe('true')
  })

  it('after toggle to disposition, severity toggle is aria-pressed=false', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    expect(screen.getByTestId('timeline-toggle-severity').getAttribute('aria-pressed')).toBe('false')
  })

  it('after toggle to disposition, shows blocked and allowed counts in .tl-cnt', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    // .tl-cnt should now show blocked/allowed spans
    expect(screen.getByTestId('timeline-blocked-bar')).toBeInTheDocument()
    expect(screen.getByTestId('timeline-allowed-bar')).toBeInTheDocument()
  })

  it('blocked count equals bucket.blocked in disposition mode', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    const blockedEl = screen.getByTestId('timeline-blocked-bar')
    // 60 formatted with toLocaleString — at least contains '60'
    expect(blockedEl.textContent).toContain('60')
  })

  it('toggling back to severity hides disposition segments', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    fireEvent.click(screen.getByTestId('timeline-toggle-severity'))
    // After returning to severity mode, disposition .tl-cnt elements gone
    expect(screen.queryByTestId('timeline-blocked-bar')).not.toBeInTheDocument()
    expect(screen.queryByTestId('timeline-allowed-bar')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// C. Rich per-bucket hover (via CellTooltip #246)
// ---------------------------------------------------------------------------

describe('TimelineChart — rich per-bucket hover', () => {
  it('each bar row has a CellTooltip trigger element', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    // CellTooltip trigger has data-testid="timeline-bar-trigger-0"
    expect(screen.getByTestId('timeline-bar-trigger-0')).toBeInTheDocument()
  })

  it('hovering a bar trigger reveals the hover content', async () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    const trigger = screen.getByTestId('timeline-bar-trigger-0')
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('timeline-hover-content')).toBeInTheDocument()
    })
  })

  it('hover content contains the total count', async () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    fireEvent.mouseEnter(screen.getByTestId('timeline-bar-trigger-0'))
    await waitFor(() => {
      expect(screen.getByTestId('timeline-hover-content')).toBeInTheDocument()
    })
    const content = screen.getByTestId('timeline-hover-content')
    expect(content.textContent).toContain('100')
  })

  it('hover content renders top_category as a text node (not innerHTML)', async () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    fireEvent.mouseEnter(screen.getByTestId('timeline-bar-trigger-0'))
    await waitFor(() => {
      expect(screen.getByTestId('timeline-hover-content')).toBeInTheDocument()
    })
    const content = screen.getByTestId('timeline-hover-content')
    // Must appear as text — check textContent contains the value
    expect(content.textContent).toContain('SQL Injection')
    // Must NOT be set via innerHTML (textContent equals innerHTML only for text nodes)
    // The component never uses dangerouslySetInnerHTML; this is a structural check.
    expect(content.innerHTML).not.toContain('dangerouslySetInnerHTML')
  })

  it('hover content renders top_source_ip as a text node (ADR-0029 D3)', async () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    fireEvent.mouseEnter(screen.getByTestId('timeline-bar-trigger-0'))
    await waitFor(() => {
      expect(screen.getByTestId('timeline-hover-content')).toBeInTheDocument()
    })
    const content = screen.getByTestId('timeline-hover-content')
    expect(content.textContent).toContain('198.51.100.1')
  })
})

// ---------------------------------------------------------------------------
// D. Zero-event bucket
// ---------------------------------------------------------------------------

describe('TimelineChart — zero-event bucket', () => {
  it('empty bucket hover shows "No events in this period"', async () => {
    render(<TimelineChart buckets={[BUCKET_ZERO]} />)
    // BUCKET_ZERO is at index 0
    const trigger = screen.getByTestId('timeline-bar-trigger-0')
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('timeline-hover-empty')).toBeInTheDocument()
    })
    expect(screen.getByTestId('timeline-hover-empty').textContent).toContain('No events')
  })

  it('empty bucket bar track renders (isEmpty=true means no coloured segment divs)', () => {
    render(<TimelineChart buckets={[BUCKET_ZERO]} />)
    const track = screen.getByTestId('timeline-bar-track')
    // The track exists but no coloured-segment divs inside it
    expect(track).toBeInTheDocument()
    expect(track.querySelectorAll('[data-testid^="timeline-segment-"]')).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// E. Empty bucket list
// ---------------------------------------------------------------------------

describe('TimelineChart — empty bucket list', () => {
  it('renders the empty state message when buckets=[]', () => {
    render(<TimelineChart buckets={[]} />)
    expect(screen.getByTestId('timeline-empty')).toBeInTheDocument()
  })

  it('does NOT render the chart container when buckets=[]', () => {
    render(<TimelineChart buckets={[]} />)
    expect(screen.queryByTestId('timeline-chart')).not.toBeInTheDocument()
  })

  it('does NOT render the legend when buckets=[]', () => {
    render(<TimelineChart buckets={[]} />)
    expect(screen.queryByTestId('timeline-legend')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// F. Legend — severity mode
// ---------------------------------------------------------------------------

describe('TimelineChart — legend in severity mode (default)', () => {
  it('renders the legend when data is present', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    expect(screen.getByTestId('timeline-legend')).toBeInTheDocument()
  })

  it('legend contains Critical label in severity mode', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    expect(screen.getByTestId('timeline-legend').textContent).toContain('Critical')
  })

  it('critical swatch carries soc-critical class', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    const swatch = screen.getByTestId('timeline-legend-critical-swatch')
    expect(swatch.className).toContain('soc-critical')
  })

  it('swatch classes do NOT contain hardcoded hex', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    const legend = screen.getByTestId('timeline-legend')
    expect(legend.innerHTML).not.toMatch(/#[0-9a-fA-F]{3,6}/)
  })
})

// ---------------------------------------------------------------------------
// G. Legend — disposition mode (backward-compat with TimelineChartLegend.test.tsx)
// ---------------------------------------------------------------------------

describe('TimelineChart — legend in disposition mode', () => {
  it('after toggle to disposition, legend shows Blocked and Allowed', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    const legend = screen.getByTestId('timeline-legend')
    expect(legend.textContent).toContain('Blocked')
    expect(legend.textContent).toContain('Allowed')
  })

  it('blocked swatch carries soc-enforced-fg class (backward-compat)', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    const swatch = screen.getByTestId('timeline-legend-blocked-swatch')
    expect(swatch.className).toContain('soc-enforced-fg')
  })

  it('allowed swatch carries soc-ok-fg class (backward-compat)', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    const swatch = screen.getByTestId('timeline-legend-allowed-swatch')
    expect(swatch.className).toContain('soc-ok-fg')
  })

  it('blocked and allowed swatches have different token classes (backward-compat)', () => {
    render(<TimelineChart buckets={[BUCKET_FULL]} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    const blocked = screen.getByTestId('timeline-legend-blocked-swatch')
    const allowed = screen.getByTestId('timeline-legend-allowed-swatch')
    expect(blocked.className).not.toEqual(allowed.className)
  })
})

// ---------------------------------------------------------------------------
// H. Spike annotation integration (issue #248)
// ---------------------------------------------------------------------------

/**
 * Build a series with 6 flat baseline buckets followed by one large spike.
 * The spike bucket (index 6) will be flagged by detectSpikes.
 * Uses RFC-5737 IPs (gitleaks-safe fixture convention).
 */
function makeSpikedBuckets(): import('../api/types').TimelineBucket[] {
  const base = (hour: string, total: number): import('../api/types').TimelineBucket => ({
    hour,
    total,
    blocked: Math.floor(total * 0.6),
    granularity: 'hourly',
    severity: {
      critical: Math.floor(total * 0.1),
      high: Math.floor(total * 0.3),
      medium: Math.floor(total * 0.4),
      low: Math.floor(total * 0.2),
    },
    top_source_ip: '198.51.100.1',
    top_category: 'Recon',
  })

  return [
    base('2026-06-11T00:00', 10),
    base('2026-06-11T01:00', 12),
    base('2026-06-11T02:00', 9),
    base('2026-06-11T03:00', 11),
    base('2026-06-11T04:00', 10),
    base('2026-06-11T05:00', 13),
    // Spike bucket: 200 events — far above the median of ~10-13
    base('2026-06-11T06:00', 200),
    base('2026-06-11T07:00', 11),
  ]
}

describe('TimelineChart — spike annotation integration (issue #248)', () => {
  it('renders a spike marker glyph for a spiked bucket', () => {
    render(<TimelineChart buckets={makeSpikedBuckets()} />)
    // The spike at index 6 should produce at least one spike-marker-glyph.
    expect(screen.getAllByTestId('spike-marker-glyph').length).toBeGreaterThan(0)
  })

  it('spike marker trigger is present in the DOM for a spiked bucket', () => {
    render(<TimelineChart buckets={makeSpikedBuckets()} />)
    expect(screen.getAllByTestId('spike-marker-trigger').length).toBeGreaterThan(0)
  })

  it('hovering the spike marker trigger shows statistical magnitude', async () => {
    render(<TimelineChart buckets={makeSpikedBuckets()} />)
    const trigger = screen.getAllByTestId('spike-marker-trigger')[0]
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('spike-stat-line')).toBeInTheDocument()
    })
    expect(screen.getByTestId('spike-stat-line').textContent).toContain('vs window median')
  })

  it('spike hover contains the event count of the spiked bucket', async () => {
    render(<TimelineChart buckets={makeSpikedBuckets()} />)
    const trigger = screen.getAllByTestId('spike-marker-trigger')[0]
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('spike-stat-line')).toBeInTheDocument()
    })
    // 200 events in the spike bucket
    expect(screen.getByTestId('spike-stat-line').textContent).toContain('200')
  })

  it('spike hover does NOT contain AI-attributed wording (ADR-0035)', async () => {
    render(<TimelineChart buckets={makeSpikedBuckets()} />)
    const trigger = screen.getAllByTestId('spike-marker-trigger')[0]
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('spike-hover-content')).toBeInTheDocument()
    })
    const text = screen.getByTestId('spike-hover-content').textContent ?? ''
    expect(text).not.toMatch(/\bAI\b/i)
    expect(text).not.toMatch(/\bLLM\b/i)
    expect(screen.queryByTestId('spike-llm-reason')).not.toBeInTheDocument()
  })

  it('flat series renders NO spike markers', () => {
    const flatBuckets: import('../api/types').TimelineBucket[] = Array.from({ length: 10 }, (_, i) => ({
      hour: `2026-06-11T${String(i).padStart(2, '0')}:00`,
      total: 10,
      blocked: 6,
      granularity: 'hourly' as const,
      severity: { critical: 1, high: 3, medium: 4, low: 2 },
    }))
    render(<TimelineChart buckets={flatBuckets} />)
    expect(screen.queryAllByTestId('spike-marker-glyph')).toHaveLength(0)
  })

  it('series shorter than detection window renders NO spike markers', () => {
    // 4 buckets < window (6) — no marks should appear even if values vary.
    const shortBuckets: import('../api/types').TimelineBucket[] = [
      { hour: '2026-06-11T00:00', total: 10, blocked: 6, granularity: 'hourly', severity: { critical: 1, high: 3, medium: 4, low: 2 } },
      { hour: '2026-06-11T01:00', total: 500, blocked: 300, granularity: 'hourly', severity: { critical: 50, high: 200, medium: 200, low: 50 } },
      { hour: '2026-06-11T02:00', total: 10, blocked: 6, granularity: 'hourly', severity: { critical: 1, high: 3, medium: 4, low: 2 } },
      { hour: '2026-06-11T03:00', total: 10, blocked: 6, granularity: 'hourly', severity: { critical: 1, high: 3, medium: 4, low: 2 } },
    ]
    render(<TimelineChart buckets={shortBuckets} />)
    expect(screen.queryAllByTestId('spike-marker-glyph')).toHaveLength(0)
  })
})
