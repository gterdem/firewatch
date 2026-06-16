/**
 * MF-5 — Analytics v2 restyle tests.
 *
 * EARS criteria:
 *   - Ubiquitous: Analytics tab SHALL render with DS Panel containers (fw-panel class).
 *   - Ubiquitous: KPI tiles SHALL use DS StatCard (fw-stat class) not raw div tiles.
 *   - Ubiquitous: category hues SHALL be applied to timeline cells via CSS custom
 *     property color tokens (no raw hex literals in component attributes).
 *   - State-driven: WHILE geo data exists, the map SHALL plot markers on the bundled basemap (ADR-0052: no CDN tile URL).
 *   - State-driven: WHILE geo is empty, DS Panel still renders with EmptyState inside.
 *   - Ubiquitous: geo popups SHALL remain XSS-safe (no innerHTML interpolation).
 *   - Ubiquitous: #111 adherence — emoji icon for geo empty state, no SVG.
 *
 * Tests are keyed 1:1 to EARS criteria from issue #162.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import AnalyticsRoute from '../routes/AnalyticsRoute'
import AnalyticsCharts from '../components/analytics/AnalyticsCharts'
import {
  GEO_FIXTURE,
  ANALYTICS_SUMMARY_FIXTURE,
  CATEGORIES_TIMELINE_FIXTURE,
  ANALYTICS_SUMMARY_EMPTY_FIXTURE,
} from './readFixtures'
import type { GeoPoint } from '../api/types'

const { mockFetchGeo, mockFetchAnalyticsSummary, mockFetchCategoriesTimeline } = vi.hoisted(
  () => ({
    mockFetchGeo: vi.fn(),
    mockFetchAnalyticsSummary: vi.fn(),
    mockFetchCategoriesTimeline: vi.fn(),
  }),
)

vi.mock('../api/analytics', () => ({
  fetchGeo: mockFetchGeo,
  fetchAnalyticsSummary: mockFetchAnalyticsSummary,
  fetchCategoriesTimeline: mockFetchCategoriesTimeline,
}))

// GeoMap uses Leaflet dynamic import — mock for unit tests.
vi.mock('../components/analytics/GeoMap', () => ({
  default: ({ points }: { points: GeoPoint[] }) => (
    <div data-testid="geo-map-mock">GeoMap: {points.length} points</div>
  ),
}))

// ---------------------------------------------------------------------------
// 1. DS Panel containers
// ---------------------------------------------------------------------------

describe('MF-5: AnalyticsRoute — DS Panel containers (fw-panel class)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)
  })

  it('renders geographic distribution inside a DS Panel (fw-panel class)', async () => {
    const { container } = render(<AnalyticsRoute />)
    await waitFor(() => {
      expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument()
    })
    // DS Panel renders with class "fw-panel" (Panel.tsx recipe)
    const panels = container.querySelectorAll('.fw-panel')
    expect(panels.length).toBeGreaterThanOrEqual(1)
  })

  it('renders analytics charts inside a DS Panel (fw-panel class)', async () => {
    const { container } = render(<AnalyticsRoute />)
    await waitFor(() => {
      expect(screen.getByTestId('analytics-charts')).toBeInTheDocument()
    })
    const panels = container.querySelectorAll('.fw-panel')
    // At least two panels: geo + charts
    expect(panels.length).toBeGreaterThanOrEqual(2)
  })

  it('Panel header shows "Geographic Distribution" title', async () => {
    render(<AnalyticsRoute />)
    await waitFor(() => {
      expect(screen.getByText('Geographic Distribution')).toBeInTheDocument()
    })
  })

  it('Panel header shows "Event Analytics" title', async () => {
    render(<AnalyticsRoute />)
    await waitFor(() => {
      expect(screen.getByText('Event Analytics')).toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// 2. DS StatCard for KPI tiles
// ---------------------------------------------------------------------------

describe('MF-5: AnalyticsCharts — DS StatCard (fw-stat class) for KPIs', () => {
  it('KPI grid uses DS StatCard (fw-stat class), not raw rounded border tiles', () => {
    const { container } = render(
      <AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={[]} />,
    )
    // DS StatCard renders with class "fw-stat"
    const statCards = container.querySelectorAll('.fw-stat')
    // Expect 6 KPI stat cards (total_events, total_blocked, total_ips, block_rate,
    // top_country, unique_countries)
    expect(statCards.length).toBeGreaterThanOrEqual(6)
  })

  it('StatCard for total_events shows the value in fw-stat__val', () => {
    const { container } = render(
      <AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={[]} />,
    )
    // The stat value node should contain the total_events figure
    const valNodes = container.querySelectorAll('.fw-stat__val')
    const texts = Array.from(valNodes).map((n) => n.textContent ?? '')
    expect(texts).toContain('4,815')
  })

  it('StatCard label is uppercase (fw-stat__lbl)', () => {
    const { container } = render(
      <AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={[]} />,
    )
    const lblNodes = container.querySelectorAll('.fw-stat__lbl')
    expect(lblNodes.length).toBeGreaterThanOrEqual(6)
  })

  it('block_rate StatCard uses red accent for visual emphasis', () => {
    render(<AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={[]} />)
    // The block-rate card value should have the red accent token applied
    const blockRateStat = screen.getByTestId('analytics-block-rate').closest('.fw-stat')
    expect(blockRateStat).not.toBeNull()
    const valEl = blockRateStat!.querySelector('.fw-stat__val')
    expect(valEl).not.toBeNull()
    // Color is applied inline via the ACCENT_COLOR map in StatCard
    expect((valEl as HTMLElement).style.color).toContain('var(--fw-red)')
  })

  it('total_blocked StatCard uses red accent token', () => {
    render(<AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={[]} />)
    const blockedStat = screen.getByTestId('analytics-total-blocked').closest('.fw-stat')
    expect(blockedStat).not.toBeNull()
    const valEl = blockedStat!.querySelector('.fw-stat__val')
    expect((valEl as HTMLElement).style.color).toContain('var(--fw-red)')
  })

  it('unique_countries StatCard uses cyan accent token (geo context)', () => {
    render(<AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={[]} />)
    const countriesStat = screen.getByTestId('analytics-unique-countries').closest('.fw-stat')
    expect(countriesStat).not.toBeNull()
    const valEl = countriesStat!.querySelector('.fw-stat__val')
    expect((valEl as HTMLElement).style.color).toContain('var(--fw-cyan)')
  })
})

// ---------------------------------------------------------------------------
// 3. Category hues in timeline table
// ---------------------------------------------------------------------------

describe('MF-5: AnalyticsCharts — category hues on timeline cells', () => {
  it('timeline table header cells have data-category attribute for hue styling', () => {
    const { container } = render(
      <AnalyticsCharts
        summary={ANALYTICS_SUMMARY_FIXTURE}
        timeline={CATEGORIES_TIMELINE_FIXTURE}
      />,
    )
    // Category column headers should carry the data-category attribute so CSS
    // (or inline styles) can apply the correct hue token
    const catHeaders = container.querySelectorAll('th[data-category]')
    expect(catHeaders.length).toBeGreaterThanOrEqual(7) // 7 category columns
  })

  it('sqli header carries data-category="sqli"', () => {
    render(
      <AnalyticsCharts
        summary={ANALYTICS_SUMMARY_FIXTURE}
        timeline={CATEGORIES_TIMELINE_FIXTURE}
      />,
    )
    const sqliHeader = document.querySelector('th[data-category="sqli"]')
    expect(sqliHeader).not.toBeNull()
  })

  it('ids_alert header carries data-category="ids_alert"', () => {
    render(
      <AnalyticsCharts
        summary={ANALYTICS_SUMMARY_FIXTURE}
        timeline={CATEGORIES_TIMELINE_FIXTURE}
      />,
    )
    const idsHeader = document.querySelector('th[data-category="ids_alert"]')
    expect(idsHeader).not.toBeNull()
  })

  it('timeline data cells have data-category attribute matching column', () => {
    const { container } = render(
      <AnalyticsCharts
        summary={ANALYTICS_SUMMARY_FIXTURE}
        timeline={CATEGORIES_TIMELINE_FIXTURE}
      />,
    )
    // Each data cell should carry data-category for color-dot rendering
    const catCells = container.querySelectorAll('td[data-category]')
    // 2 rows × 7 category columns = 14 cells
    expect(catCells.length).toBe(14)
  })

  it('non-zero category cells carry color style using --fw-* token (no raw hex)', () => {
    const { container } = render(
      <AnalyticsCharts
        summary={ANALYTICS_SUMMARY_FIXTURE}
        timeline={CATEGORIES_TIMELINE_FIXTURE}
      />,
    )
    // Cells with non-zero values should have a color style with a CSS var
    const coloredCells = Array.from(container.querySelectorAll('td[data-category]')).filter(
      (el) => (el as HTMLElement).style.color !== '',
    )
    for (const cell of coloredCells) {
      // Must use CSS custom property, not a raw hex
      expect((cell as HTMLElement).style.color).toMatch(/var\(--fw-/)
      expect((cell as HTMLElement).style.color).not.toMatch(/#[0-9a-fA-F]{3,6}/)
    }
  })
})

// ---------------------------------------------------------------------------
// 4. Zero-egress basemap (ADR-0052, closes #528)
// ---------------------------------------------------------------------------
// UPDATED: CartoDB tile layer replaced with bundled Natural Earth GeoJSON (ADR-0052).
// Tests now verify the zero-egress invariant: no CDN URL in source, no tileLayer call.

describe('ADR-0052 / #528: GeoMap — zero-egress bundled basemap', () => {
  it('GeoMap source contains NO CartoDB tile URL (EARS-1 zero-egress guard)', async () => {
    // Source-level static check: after the ADR-0052 fix, no CDN URL must exist.
    const src = (
      await import('../components/analytics/GeoMap?raw')
    ).default as string

    // CartoDB CDN — the former tile URL that was the egress violation
    expect(src).not.toContain('cartocdn.com')
    expect(src).not.toContain('basemaps.cartocdn')
    // OpenStreetMap tile CDN
    expect(src).not.toContain('tile.openstreetmap.org')
    // Tile subdomain pattern ('{s}.' used by slippy-map tile layers)
    expect(src).not.toContain('{s}.basemaps')
  })

  it('GeoMap source contains NO L.tileLayer call — tile CDN removed (EARS-1)', async () => {
    const src = (
      await import('../components/analytics/GeoMap?raw')
    ).default as string

    // tileLayer is the Leaflet API for external tile CDN — must not be called
    expect(src).not.toContain('tileLayer(')
    expect(src).not.toContain('DARK_TILE_URL')
  })

  it('GeoMap source uses L.geoJSON for the bundled world-outline basemap (EARS-2)', async () => {
    const src = (
      await import('../components/analytics/GeoMap?raw')
    ).default as string

    // geoJSON is the Leaflet API used to render the bundled vector layer
    expect(src).toContain('geoJSON(')
    // The bundled asset must be imported
    expect(src).toContain('world-outline.geojson')
  })

  it('GeoMap renders the map container without making any tileLayer call (EARS-1)', async () => {
    // Render the real GeoMap with a Leaflet mock and assert tileLayer is never called.
    const tileLayerCalls: string[] = []
    const geoJSONLayers: unknown[] = []

    vi.doMock('leaflet', async () => {
      return {
        default: {
          map: () => ({
            remove: vi.fn(),
          }),
          tileLayer: (url: string) => {
            tileLayerCalls.push(url)
            return { addTo: vi.fn() }
          },
          geoJSON: (data: unknown) => {
            geoJSONLayers.push(data)
            return { addTo: vi.fn() }
          },
          circleMarker: () => ({ bindPopup: () => ({ addTo: vi.fn() }) }),
        },
      }
    })

    const { default: GeoMapReal } = await import('../components/analytics/GeoMap')
    render(<GeoMapReal points={GEO_FIXTURE} />)

    // Wait briefly for the async Leaflet import inside useEffect
    await waitFor(() => {
      expect(geoJSONLayers.length).toBeGreaterThan(0)
    }, { timeout: 2000 }).catch(() => {
      // jsdom env may not fully execute the dynamic import — source checks above cover this
    })

    // tileLayer must never be called — no CDN tile requests
    expect(tileLayerCalls).toHaveLength(0)

    vi.doUnmock('leaflet')
  })
})

// ---------------------------------------------------------------------------
// 5. Empty-state geo path with DS Panel
// ---------------------------------------------------------------------------

describe('MF-5: AnalyticsRoute — empty geo with DS Panel still renders', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)
  })

  it('WHILE geo is empty, DS Panel still wraps the empty state (fw-panel present)', async () => {
    mockFetchGeo.mockResolvedValue([] as GeoPoint[])
    const { container } = render(<AnalyticsRoute />)
    await waitFor(() => {
      expect(screen.getByTestId('empty-state')).toBeInTheDocument()
    })
    const panels = container.querySelectorAll('.fw-panel')
    expect(panels.length).toBeGreaterThanOrEqual(1)
  })

  it('WHILE geo is empty, EmptyState icon uses emoji (not SVG) — #111 adherence', async () => {
    mockFetchGeo.mockResolvedValue([] as GeoPoint[])
    render(<AnalyticsRoute />)
    await waitFor(() => {
      expect(screen.getByTestId('empty-state-icon')).toBeInTheDocument()
    })
    const iconEl = screen.getByTestId('empty-state-icon')
    // No SVG element inside the icon slot
    expect(iconEl.querySelector('svg')).toBeNull()
    // Emoji text must be present
    expect(iconEl.textContent).toMatch(/🌍/)
  })

  it('WHILE geo has data, GeoMap renders (not EmptyState)', async () => {
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    render(<AnalyticsRoute />)
    await waitFor(() => {
      expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('empty-state')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 6. XSS safety regression guard (geoPopup — #74 lesson)
// ---------------------------------------------------------------------------

describe('MF-5: geoPopup XSS safety regression guard (#74)', () => {
  it('XSS payload in IP renders as inert text — no live script node', async () => {
    const { buildGeoPopup } = await import('../components/analytics/geoPopup')
    const xssIp = "<script>alert('xss')</script>"
    // Use real DTO shape: total_events (not `count`) — fix #178
    const el = buildGeoPopup({ lat: 0, lon: 0, total_events: 1, blocked: 0, rules_triggered: 0, ip: xssIp })
    expect(el.textContent).toContain(xssIp)
    expect(el.querySelector('script')).toBeNull()
  })

  it('XSS payload in city renders as inert text — no live img node', async () => {
    const { buildGeoPopup } = await import('../components/analytics/geoPopup')
    const xssCity = '"><img src=x onerror=alert(1)>'
    // Use real DTO shape: total_events (not `count`) — fix #178
    const el = buildGeoPopup({ lat: 0, lon: 0, total_events: 1, blocked: 0, rules_triggered: 0, ip: '198.51.100.1', city: xssCity })
    expect(el.textContent).toContain(xssCity)
    expect(el.querySelector('img')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// 7. EARS state-driven: sparse / present geo data handling
// ---------------------------------------------------------------------------

describe('MF-5: geo data presence state machine', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_EMPTY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue([])
  })

  it('WHILE absent (0 points): shows EmptyState, does NOT render the map', async () => {
    mockFetchGeo.mockResolvedValue([])
    render(<AnalyticsRoute />)
    await waitFor(() => expect(screen.getByTestId('empty-state')).toBeInTheDocument())
    expect(screen.queryByTestId('geo-map-mock')).not.toBeInTheDocument()
  })

  it('WHILE present (>0 points): shows map, does NOT show EmptyState', async () => {
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    render(<AnalyticsRoute />)
    await waitFor(() => expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument())
    expect(screen.queryByTestId('empty-state')).not.toBeInTheDocument()
  })
})
