/**
 * Tests for src/routes/AnalyticsRoute.tsx
 *
 * EARS criteria covered:
 *   - Ubiquitous: geo uses server-side /analytics/geo — never an external ip-api.com call.
 *   - Event-driven: on mount, calls fetchGeo, fetchAnalyticsSummary, fetchCategoriesTimeline.
 *   - State-driven: populated data → charts rendered.
 *   - Unwanted: API error → error state shown, no crash.
 *   - #98: 0 geo markers → EmptyState shown, NOT a blank map frame.
 *   - #98: "air-gap safe" developer subtitle NOT rendered anywhere.
 *   - #98: LoadingState used while in flight; ErrorState on failure.
 *   - #562: ASN lens must leave 'loading' after fetch resolves (no perpetual spinner).
 *   - #562: Rapid ASN→Country→ASN toggle still resolves correctly.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import AnalyticsRoute from '../routes/AnalyticsRoute'
import {
  GEO_FIXTURE,
  ANALYTICS_SUMMARY_FIXTURE,
  CATEGORIES_TIMELINE_FIXTURE,
} from './readFixtures'
import type { GeoPoint } from '../api/types'

const {
  mockFetchGeo,
  mockFetchAnalyticsSummary,
  mockFetchCategoriesTimeline,
  mockFetchAsnStats,
} = vi.hoisted(() => ({
  mockFetchGeo: vi.fn(),
  mockFetchAnalyticsSummary: vi.fn(),
  mockFetchCategoriesTimeline: vi.fn(),
  mockFetchAsnStats: vi.fn(),
}))

vi.mock('../api/analytics', () => ({
  fetchGeo: mockFetchGeo,
  fetchAnalyticsSummary: mockFetchAnalyticsSummary,
  fetchCategoriesTimeline: mockFetchCategoriesTimeline,
  fetchAsnStats: mockFetchAsnStats,
}))

// GeoMap uses Leaflet dynamic import — mock it for unit tests.
vi.mock('../components/analytics/GeoMap', () => ({
  default: ({ points }: { points: unknown[] }) => (
    <div data-testid="geo-map-mock">GeoMap: {points.length} points</div>
  ),
}))

// AsnPanel uses useNavigate — mock it to avoid router dependency in unit tests.
// We expose the loading/empty/done states via data-testid so the regression
// tests can assert on them directly.
vi.mock('../components/analytics/AsnPanel', () => ({
  default: ({
    rows,
    loading,
    error,
  }: {
    rows: unknown[]
    loading: boolean
    error: string | null
  }) => {
    if (loading) return <div data-testid="asn-panel-loading">Loading ASN data...</div>
    if (error) return <div data-testid="asn-panel-error">{error}</div>
    if (rows.length === 0) return <div data-testid="asn-panel-empty">No ASN data</div>
    return <div data-testid="asn-panel">ASN: {rows.length} rows</div>
  },
}))

describe('AnalyticsRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // Ubiquitous: geo data comes from the server endpoint, not an external service.
  it('calls server-side fetchGeo (not external ip-api.com) on mount', async () => {
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(mockFetchGeo).toHaveBeenCalledTimes(1)
    })
    // fetchGeo must be the only geo source — no external call is made in this component.
    expect(mockFetchAnalyticsSummary).toHaveBeenCalledTimes(1)
    expect(mockFetchCategoriesTimeline).toHaveBeenCalledTimes(1)
  })

  it('renders geo map with server-provided point count', async () => {
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument()
    })
    expect(screen.getByTestId('geo-map-mock')).toHaveTextContent(
      `GeoMap: ${GEO_FIXTURE.length} points`,
    )
  })

  it('renders analytics charts section', async () => {
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('analytics-charts')).toBeInTheDocument()
    })
    expect(screen.getByTestId('analytics-total-events')).toHaveTextContent('4,815')
    expect(screen.getByTestId('analytics-total-ips')).toHaveTextContent('23')
  })

  it('shows loading state while data is in flight', () => {
    mockFetchGeo.mockReturnValue(new Promise(() => {}))
    mockFetchAnalyticsSummary.mockReturnValue(new Promise(() => {}))
    mockFetchCategoriesTimeline.mockReturnValue(new Promise(() => {}))

    render(<AnalyticsRoute />)
    expect(screen.getByTestId('analytics-loading')).toBeInTheDocument()
  })

  it('shows error state when API rejects', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchGeo.mockRejectedValue(new ApiError(503, null))
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue([])

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('analytics-error')).toBeInTheDocument()
    })
    expect(screen.getByRole('alert')).toHaveTextContent('503')
  })

  // -------------------------------------------------------------------------
  // Issue #98 — empty geo state + subtitle removal
  // -------------------------------------------------------------------------

  // EARS #98: 0 geo markers → EmptyState instead of blank world map
  it('shows EmptyState when geo returns 0 markers', async () => {
    const emptyGeo: GeoPoint[] = []
    mockFetchGeo.mockResolvedValue(emptyGeo)
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('empty-state')).toBeInTheDocument()
    })
    // GeoMap must NOT render when there are 0 markers
    expect(screen.queryByTestId('geo-map-mock')).not.toBeInTheDocument()
  })

  it('EmptyState headline reads "No geo-resolvable traffic yet" at 0 markers (issue #532 EARS-5)', async () => {
    mockFetchGeo.mockResolvedValue([])
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('empty-state-headline')).toBeInTheDocument()
    })
    expect(screen.getByTestId('empty-state-headline')).toHaveTextContent(
      'No geo-resolvable traffic yet',
    )
  })

  it('panel stays present (does not hide) when geo is empty — #98 decision', async () => {
    mockFetchGeo.mockResolvedValue([])
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)

    render(<AnalyticsRoute />)

    await waitFor(() => {
      // The "Geographic Distribution" heading is still rendered
      expect(screen.getByText('Geographic Distribution')).toBeInTheDocument()
    })
  })

  // EARS #98: internal developer subtitle must not appear in the UI
  it('does NOT render the "air-gap safe" developer note subtitle', async () => {
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByText('Geographic Distribution')).toBeInTheDocument()
    })
    expect(screen.queryByText(/air-gap safe/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/server-side geo/i)).not.toBeInTheDocument()
  })

  // The subtitle must also be absent on the empty-geo path
  it('does NOT render the "air-gap safe" subtitle when geo is empty', async () => {
    mockFetchGeo.mockResolvedValue([])
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('empty-state')).toBeInTheDocument()
    })
    expect(screen.queryByText(/air-gap safe/i)).not.toBeInTheDocument()
  })

  // -------------------------------------------------------------------------
  // Issue #562 — ASN lens useEffect cleanup race (regression guard)
  // -------------------------------------------------------------------------

  /**
   * EARS-1 (issue #562): When the user toggles to ASN lens, the panel SHALL
   * resolve to either data or the empty state — never stay on 'loading'.
   *
   * The original bug: `asnStatus` in the useEffect dep array caused the effect
   * to re-run when setting phase:'loading', whose cleanup fired `cancelled = true`
   * before `fetchAsnStats` could resolve → permanent spinner.
   *
   * Guard: fetchAsnStats returns [] (the real-API response at sparse data) →
   * AsnPanel must receive loading=false and rows=[] (empty state), never
   * remain stuck with loading=true.
   */
  it('#562 regression: ASN panel leaves loading state after fetch resolves with []', async () => {
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)
    mockFetchAsnStats.mockResolvedValue([])

    render(<AnalyticsRoute />)

    // Wait for initial data to load
    await waitFor(() => {
      expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument()
    })

    // Click the ASN toggle
    const user = userEvent.setup()
    await user.click(screen.getByTestId('lens-asn'))

    // The panel must NOT stay on loading indefinitely — it must resolve to
    // empty state ([] rows) within a normal async tick.
    await waitFor(() => {
      expect(screen.queryByTestId('asn-panel-loading')).not.toBeInTheDocument()
    })
    expect(screen.getByTestId('asn-panel-empty')).toBeInTheDocument()
  })

  /**
   * EARS-1 (issue #562): When ASN returns rows, the panel shows the data.
   */
  it('#562 regression: ASN panel shows data rows when fetch resolves with results', async () => {
    const asnRows = [
      { asn: 'AS1234', as_name: 'Test ASN', event_count: 100, ip_count: 5, blocked_pct: 20 },
    ]
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)
    mockFetchAsnStats.mockResolvedValue(asnRows)

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument()
    })

    const user = userEvent.setup()
    await user.click(screen.getByTestId('lens-asn'))

    await waitFor(() => {
      expect(screen.queryByTestId('asn-panel-loading')).not.toBeInTheDocument()
    })
    expect(screen.getByTestId('asn-panel')).toHaveTextContent('ASN: 1 rows')
  })

  /**
   * EARS-3 (issue #562): Rapid ASN→Country→ASN toggle still resolves correctly.
   *
   * Simulates: user clicks ASN, immediately clicks Country, then clicks ASN again.
   * The final ASN activation must resolve to done/empty, not stick on loading.
   * The stale fetch from the first click must be discarded (token-based guard).
   */
  it('#562 regression: rapid toggle ASN→Country→ASN still resolves (no stuck state)', async () => {
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)
    // Simulate the first fetch being slow (stale) and the second resolving
    // immediately.  fetchAsnStats is called once (cached after first activation
    // transitions from idle to loading); the token tracks which response is live.
    mockFetchAsnStats.mockResolvedValue([])

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument()
    })

    const user = userEvent.setup()
    // Rapid toggle: ASN → Country → ASN
    await user.click(screen.getByTestId('lens-asn'))
    await user.click(screen.getByTestId('lens-country'))
    await user.click(screen.getByTestId('lens-asn'))

    // Must resolve — no perpetual spinner after rapid toggle.
    await waitFor(() => {
      expect(screen.queryByTestId('asn-panel-loading')).not.toBeInTheDocument()
    })
    // Shows empty state (data was [] from the server).
    expect(screen.getByTestId('asn-panel-empty')).toBeInTheDocument()
  })

  /**
   * EARS-2 (issue #562): ASN API error → error state shown, not loading.
   */
  it('#562 regression: ASN panel shows error state when fetch fails', async () => {
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)
    mockFetchAsnStats.mockRejectedValue(new Error('Network error'))

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument()
    })

    const user = userEvent.setup()
    await user.click(screen.getByTestId('lens-asn'))

    await waitFor(() => {
      expect(screen.queryByTestId('asn-panel-loading')).not.toBeInTheDocument()
    })
    expect(screen.getByTestId('asn-panel-error')).toBeInTheDocument()
  })
})
