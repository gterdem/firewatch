/**
 * AutoLiveRefresh.test.tsx — ADR-0064 D4 / D5 wiring tests.
 *
 * Issues: #747 (Dashboard), #749 (AI Engine), #750 (Threat Intelligence).
 *
 * For each route:
 *   [R1] When dataVersion increments, the page refetches its server-data slices.
 *   [D5] Interaction state survives a dataVersion refetch.
 * AI Engine (#749 only):
 *   [D6] Health fetch follows dataVersion — no standalone setInterval.
 *
 * Strategy: We use the real RefreshContext module (not the setup.ts stub) and
 * render routes inside a TestRefreshProvider that exposes a `bumpVersion()`
 * function.  Calling bumpVersion() advances the context value, causing
 * useRefreshSignal() to return a new dataVersion, which triggers useEffect
 * re-runs in the route.
 *
 * NOTE: This file uses `vi.unmock` to bypass the setup.ts global stub and
 * then provides a lightweight TestRefreshProvider that controls dataVersion.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { createContext, useContext, useState, useCallback, useEffect } from 'react'
import type { ReactNode } from 'react'
import type { RefreshSignal } from '../app/refresh/types'
import DashboardRoute from '../routes/DashboardRoute'
import AIRoute from '../routes/AIRoute'
import AnalyticsRoute from '../routes/AnalyticsRoute'
import {
  STATS_FIXTURE,
  TIMELINE_FIXTURE,
  CATEGORIES_FIXTURE,
  THREATS_FIXTURE as THREATS_FIXTURE_RAW,
  HEALTH_AI_ONLINE,
} from './readFixtures'

// ---------------------------------------------------------------------------
// Unmock the RefreshContext so we can provide our own controlled context.
// The setup.ts `vi.mock` is hoisted and runs before this file is imported.
// We un-do it here for this specific test file.
// ---------------------------------------------------------------------------
vi.unmock('../app/refresh/RefreshContext')

// ---------------------------------------------------------------------------
// TestRefreshContext — a minimal controllable substitute for RefreshProvider.
//
// We create a brand-new React context that matches the RefreshSignal shape.
// The route components read from this context via useRefreshSignal() which
// reads from the REAL RefreshContext.  But since we unmocked RefreshContext,
// useRefreshSignal reads from the actual context object — and we provide our
// test context value by mocking the implementation.
//
// Simpler: just re-mock RefreshContext HERE (after unmock) with a context-
// based implementation that React actually tracks for re-renders.
// ---------------------------------------------------------------------------

// Mutable signal managed by TestRefreshProvider
const TestSignalContext = createContext<{
  signal: RefreshSignal
  bump: () => void
} | null>(null)

function makeInitialSignal(dataVersion: number): RefreshSignal {
  return {
    dataVersion,
    grewSources: new Set<string>(),
    lastDeltaCount: 0,
    healthItems: [],
    isLive: false,
    lastPollAt: null,
    lastSyncDeltaCount: 0,
    syncEventId: 0,
    pulsingSources: new Set<string>(),
    clearSyncDelta: () => {},
    freshnessMinutes: 5,
  }
}

/**
 * TestRefreshProvider — wraps routes in tests.
 * Returns a `bumpVersion` ref that tests call to advance dataVersion by 1.
 */
function TestRefreshProvider({
  children,
  bumpRef,
}: {
  children: ReactNode
  bumpRef: React.MutableRefObject<(() => void) | null>
}) {
  const [signal, setSignal] = useState<RefreshSignal>(() => makeInitialSignal(0))

  const bump = useCallback(() => {
    setSignal((s) => makeInitialSignal(s.dataVersion + 1))
  }, [])

  // Expose bump via ref so test code can call it without triggering re-renders.
  // Assigned in useEffect (not during render) to satisfy react-hooks/refs.
  useEffect(() => {
    bumpRef.current = bump
  })

  return (
    <TestSignalContext.Provider value={{ signal, bump }}>
      {children}
    </TestSignalContext.Provider>
  )
}

// Re-mock RefreshContext to read from TestSignalContext so useRefreshSignal()
// inside routes picks up the controlled value.
vi.mock('../app/refresh/RefreshContext', () => ({
  useRefreshSignal: () => {
    const ctx = useContext(TestSignalContext)
    // Fallback to dataVersion=0 when called outside TestRefreshProvider
    // (safety net for tests that don't use TestRefreshProvider).
    return ctx?.signal ?? makeInitialSignal(0)
  },
  RefreshProvider: ({ children }: { children: ReactNode }) => children,
}))

// ---------------------------------------------------------------------------
// API mocks
// ---------------------------------------------------------------------------

const {
  mockFetchStats,
  mockFetchTimeline,
  mockFetchCategories,
  mockFetchThreats,
  mockFetchHealth,
} = vi.hoisted(() => ({
  mockFetchStats: vi.fn(),
  mockFetchTimeline: vi.fn(),
  mockFetchCategories: vi.fn(),
  mockFetchThreats: vi.fn(),
  mockFetchHealth: vi.fn(),
}))

vi.mock('../api/client', () => {
  class ApiError extends Error {
    status: number
    detail: unknown
    constructor(status: number, detail: unknown, message?: string) {
      super(message ?? `API error ${status}`)
      this.status = status
      this.detail = detail
    }
  }
  return {
    fetchStats: mockFetchStats,
    fetchTimeline: mockFetchTimeline,
    fetchCategories: mockFetchCategories,
    fetchThreats: mockFetchThreats,
    fetchHealth: mockFetchHealth,
    getRuntimeConfig: vi.fn().mockRejectedValue(new Error('not mocked')),
    // GET /banner/summary (issue #55) — non-blocking; rejecting keeps this file's
    // pre-#55 TriageBanner rendering assumptions unchanged.
    fetchBannerSummary: vi.fn().mockRejectedValue(new Error('not mocked')),
    fetchAnalyses: vi.fn().mockResolvedValue({ items: [], next_cursor: null, has_more: false }),
    fetchFeedbackSummary: vi.fn().mockResolvedValue(null),
    fetchScoreHistory: vi.fn().mockResolvedValue([]),
    fetchSourceTypes: vi.fn().mockResolvedValue([]),
    fetchBaselineStatus: vi.fn().mockResolvedValue({ exists: false }),
    fetchDriftReport: vi.fn().mockResolvedValue(null),
    ApiError,
    resolveBaseUrl: () => '',
    assertLoopbackBase: () => {},
  }
})

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
  fetchAttackDispositions: vi.fn().mockResolvedValue([]),
}))

vi.mock('../api/logs', () => ({
  fetchPaginatedLogs: vi.fn().mockResolvedValue({
    logs: [], next_cursor: null, has_more: false, total_matching: 0,
  }),
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
}))

vi.mock('../components/analytics/GeoMap', () => ({
  default: ({ points }: { points: unknown[] }) => (
    <div data-testid="geo-map-mock">{points.length}</div>
  ),
}))

vi.mock('../components/analytics/AsnPanel', () => ({
  default: ({ loading }: { loading: boolean }) =>
    loading ? <div data-testid="asn-panel-loading" /> : <div data-testid="asn-panel" />,
}))

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const THREATS_FIXTURE = THREATS_FIXTURE_RAW

const ANALYTICS_SUMMARY = {
  total_ips: 23,
  total_events: 4815,
  total_blocked: 3000,
  block_rate: 62.3,
  top_country: 'US',
  unique_countries: 12,
  top_rule: '2001219',
}

// ---------------------------------------------------------------------------
// Render helpers — each wraps the route in TestRefreshProvider
// ---------------------------------------------------------------------------

function renderDashboard() {
  const bumpRef: React.MutableRefObject<(() => void) | null> = { current: null }
  render(
    <TestRefreshProvider bumpRef={bumpRef}>
      <MemoryRouter>
        <DashboardRoute />
      </MemoryRouter>
    </TestRefreshProvider>,
  )
  return { bump: () => bumpRef.current?.() }
}

function renderAI(path = '/ai') {
  const bumpRef: React.MutableRefObject<(() => void) | null> = { current: null }
  render(
    <TestRefreshProvider bumpRef={bumpRef}>
      <MemoryRouter initialEntries={[path]}>
        <AIRoute />
      </MemoryRouter>
    </TestRefreshProvider>,
  )
  return { bump: () => bumpRef.current?.() }
}

function renderAnalytics() {
  const bumpRef: React.MutableRefObject<(() => void) | null> = { current: null }
  render(
    <TestRefreshProvider bumpRef={bumpRef}>
      <AnalyticsRoute />
    </TestRefreshProvider>,
  )
  return { bump: () => bumpRef.current?.() }
}

// ---------------------------------------------------------------------------
// #747 — DashboardRoute auto-live-refresh (ADR-0064 D4/D5)
// ---------------------------------------------------------------------------

describe('#747 — DashboardRoute auto-live-refresh', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
  })

  // [R1] main Promise.all refetches on dataVersion bump
  it('[R1] refetches stats/timeline/categories/threats when dataVersion increments', async () => {
    const { bump } = renderDashboard()

    await waitFor(() => expect(screen.getByTestId('kpi-strip')).toBeInTheDocument())

    const statsBefore = mockFetchStats.mock.calls.length
    const timelineBefore = mockFetchTimeline.mock.calls.length
    const threatsBefore = mockFetchThreats.mock.calls.length

    await act(async () => { bump() })

    await waitFor(() => {
      expect(mockFetchStats.mock.calls.length).toBeGreaterThan(statsBefore)
    })
    expect(mockFetchTimeline.mock.calls.length).toBeGreaterThan(timelineBefore)
    expect(mockFetchThreats.mock.calls.length).toBeGreaterThan(threatsBefore)
  })

  // [R1] health effect refetches on dataVersion bump
  it('[R1] health effect refetches when dataVersion increments', async () => {
    const { bump } = renderDashboard()

    await waitFor(() => expect(screen.getByTestId('kpi-strip')).toBeInTheDocument())

    const healthBefore = mockFetchHealth.mock.calls.length

    await act(async () => { bump() })

    await waitFor(() => {
      expect(mockFetchHealth.mock.calls.length).toBeGreaterThan(healthBefore)
    })
  })

  // [D5] logs search box unchanged after a dataVersion refetch
  it('[D5] logs search box is unchanged after a dataVersion refetch', async () => {
    const { bump } = renderDashboard()

    await waitFor(() => expect(screen.getByTestId('logs-search')).toBeInTheDocument())

    const valueBefore = (screen.getByTestId('logs-search') as HTMLInputElement).value

    await act(async () => { bump() })
    await waitFor(() => expect(mockFetchStats.mock.calls.length).toBeGreaterThan(1))

    expect(screen.getByTestId('logs-search')).toHaveValue(valueBefore)
  })

  // [D5] timeline window controls unchanged after a dataVersion refetch
  it('[D5] timeline window controls are unchanged after a dataVersion refetch', async () => {
    const { bump } = renderDashboard()

    await waitFor(() => expect(screen.getByTestId('timeline-window-toggle')).toBeInTheDocument())

    expect(screen.getByTestId('timeline-window-12h')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByTestId('timeline-window-24h')).toHaveAttribute('aria-pressed', 'false')

    await act(async () => { bump() })
    await waitFor(() => expect(mockFetchStats.mock.calls.length).toBeGreaterThan(1))

    expect(screen.getByTestId('timeline-window-12h')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByTestId('timeline-window-24h')).toHaveAttribute('aria-pressed', 'false')
  })

  // [D5] no new polling interval introduced by Dashboard
  it('[D5] Dashboard does NOT introduce a new polling interval', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })

    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)

    render(<MemoryRouter><DashboardRoute /></MemoryRouter>)
    await waitFor(() => expect(screen.getByTestId('kpi-strip')).toBeInTheDocument())

    const statsAtMount = mockFetchStats.mock.calls.length

    await act(async () => { vi.advanceTimersByTime(60_000) })
    expect(mockFetchStats.mock.calls.length).toBe(statsAtMount)

    vi.useRealTimers()
  })
})

// ---------------------------------------------------------------------------
// #749 — AIRoute auto-live-refresh (ADR-0064 D4/D5/D6)
// ---------------------------------------------------------------------------

describe('#749 — AIRoute auto-live-refresh', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
  })

  // [R1] fetchThreats refetches on dataVersion bump
  it('[R1] refetches threats when dataVersion increments', async () => {
    const { bump } = renderAI()

    await waitFor(() => expect(screen.getByTestId('ai-page')).toBeInTheDocument())

    const threatsBefore = mockFetchThreats.mock.calls.length

    await act(async () => { bump() })

    await waitFor(() => {
      expect(mockFetchThreats.mock.calls.length).toBeGreaterThan(threatsBefore)
    })
  })

  // [R1][D6] health effect refetches on dataVersion bump
  it('[R1][D6] health effect refetches when dataVersion increments', async () => {
    const { bump } = renderAI()

    await waitFor(() => expect(screen.getByTestId('ai-page')).toBeInTheDocument())

    const healthBefore = mockFetchHealth.mock.calls.length

    await act(async () => { bump() })

    await waitFor(() => {
      expect(mockFetchHealth.mock.calls.length).toBeGreaterThan(healthBefore)
    })
  })

  // [D6] no recurring timer triggers fetchHealth in AIRoute
  it('[D6] fetchHealth is NOT triggered by a 15 s recurring timer (own interval removed)', async () => {
    // D6 verification: if a 15 s setInterval still existed, advancing 60 s would
    // trigger at least 4 additional health fetches (60 / 15 = 4).
    // With D6 applied, the increase must be < 4 (at most 1 from async timing noise).
    vi.useFakeTimers({ shouldAdvanceTime: true })

    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)

    render(<MemoryRouter initialEntries={['/ai']}><AIRoute /></MemoryRouter>)

    await waitFor(() => expect(screen.getByTestId('ai-page')).toBeInTheDocument())

    const healthAtMount = mockFetchHealth.mock.calls.length
    expect(healthAtMount).toBeGreaterThan(0)

    // Advance 60 s — a 15 s interval would fire 4 more times.
    await act(async () => { vi.advanceTimersByTime(60_000) })

    // Must NOT be called 4+ extra times (the hallmark of a recurring 15 s interval).
    const increase = mockFetchHealth.mock.calls.length - healthAtMount
    expect(increase).toBeLessThan(4)

    vi.useRealTimers()
  })

  // [D5] ?filter param preserved after a dataVersion refetch
  it('[D5] ?filter=below-threshold is preserved after a dataVersion refetch', async () => {
    const { bump } = renderAI('/ai?filter=below-threshold')

    await waitFor(() => expect(screen.getByTestId('ai-below-threshold-banner')).toBeInTheDocument())

    const threatsBefore = mockFetchThreats.mock.calls.length

    await act(async () => { bump() })

    await waitFor(() => {
      expect(mockFetchThreats.mock.calls.length).toBeGreaterThan(threatsBefore)
    })

    expect(screen.getByTestId('ai-below-threshold-banner')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// #750 — AnalyticsRoute auto-live-refresh (ADR-0064 D4/D5)
// ---------------------------------------------------------------------------

describe('#750 — AnalyticsRoute auto-live-refresh', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchGeo.mockResolvedValue([])
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY)
    mockFetchCategoriesTimeline.mockResolvedValue([])
    mockFetchAsnStats.mockResolvedValue([])
  })

  // [R1] base geo/summary/timeline refetches on dataVersion bump
  it('[R1] refetches geo/summary/timeline when dataVersion increments', async () => {
    const { bump } = renderAnalytics()

    await waitFor(() => expect(screen.getByTestId('analytics-page-title')).toBeInTheDocument())

    const geoBefore = mockFetchGeo.mock.calls.length
    const summaryBefore = mockFetchAnalyticsSummary.mock.calls.length
    const timelineBefore = mockFetchCategoriesTimeline.mock.calls.length

    await act(async () => { bump() })

    await waitFor(() => {
      expect(mockFetchGeo.mock.calls.length).toBeGreaterThan(geoBefore)
    })
    expect(mockFetchAnalyticsSummary.mock.calls.length).toBeGreaterThan(summaryBefore)
    expect(mockFetchCategoriesTimeline.mock.calls.length).toBeGreaterThan(timelineBefore)
  })

  // [D5] ASN lazy-load is NOT triggered by a dataVersion refetch
  it('[D5] ASN lazy-load is NOT re-triggered by a dataVersion refetch', async () => {
    const { bump } = renderAnalytics()

    await waitFor(() => expect(screen.getByTestId('analytics-page-title')).toBeInTheDocument())

    const asnBefore = mockFetchAsnStats.mock.calls.length

    await act(async () => { bump() })

    await waitFor(() => {
      expect(mockFetchGeo.mock.calls.length).toBeGreaterThan(1)
    })

    // ASN call count must be unchanged (user never activated ASN mode)
    expect(mockFetchAsnStats.mock.calls.length).toBe(asnBefore)
  })

  // [D5] no new polling interval introduced
  it('[D5] Analytics page does NOT introduce a new polling interval', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })

    mockFetchGeo.mockResolvedValue([])
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY)
    mockFetchCategoriesTimeline.mockResolvedValue([])

    render(<AnalyticsRoute />)

    await waitFor(() => expect(screen.getByTestId('analytics-page-title')).toBeInTheDocument())

    const geoAtMount = mockFetchGeo.mock.calls.length

    await act(async () => { vi.advanceTimersByTime(60_000) })
    expect(mockFetchGeo.mock.calls.length).toBe(geoAtMount)

    vi.useRealTimers()
  })
})
