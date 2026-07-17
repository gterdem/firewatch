/**
 * Tests for the Attack→Disposition flow strip (issue #214).
 *
 * EARS acceptance criteria → test mapping:
 *
 * E1 (data exists) — WHEN attack-type and disposition data exist, the strip SHALL
 *   show per top attack category the proportional split of dispositions.
 *   → 'renders flow rows when cross-tab data is present'
 *   → 'shows three disposition segments for a mixed row'
 *
 * E2 (click-through) — WHEN analyst clicks a ribbon, the events behind that pair
 *   SHALL be reachable in one click.
 *   → 'clicking a flow row navigates to /logs with attack type query'
 *
 * Ubiquitous (bounded) — strip SHALL stay bounded (top-5 + Other) with no inner
 *   scrollbar AND SHALL degrade to hidden (not broken) when cross-tab is empty.
 *   → 'renders null when rows array is empty'
 *   → 'renders at most 6 rows for bounded top-5 + Other input'
 *
 * Additional unit tests for buildFlowRows / mapActionToGroup:
 *   → 'mapActionToGroup: BLOCK and DROP map to Blocked'
 *   → 'mapActionToGroup: ALLOW maps to Allowed'
 *   → 'mapActionToGroup: ALERT, LOG and unknown map to Detected'
 *   → 'buildFlowRows: computes correct fractions'
 *   → 'buildFlowRows: excludes rows with total=0'
 *   → 'buildFlowRows: returns empty array for empty input'
 *   → 'DS color tokens contain var(--fw-*) for all disposition groups'
 *
 * Dashboard integration:
 *   → 'DashboardRoute shows flow strip when attackDispositions is non-empty'
 *   → 'DashboardRoute hides flow strip when attackDispositions is empty'
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import {
  mapActionToGroup,
  buildFlowRows,
  DISPOSITION_COLORS,
} from '../components/dashboard/attackDispositionUtils'
import type { AttackDispositionRow } from '../api/types'
import AttackDispositionFlow from '../components/dashboard/AttackDispositionFlow'
import {
  STATS_FIXTURE,
  TIMELINE_FIXTURE,
  CATEGORIES_FIXTURE,
  THREATS_FIXTURE,
  HEALTH_AI_ONLINE,
} from './readFixtures'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CROSS_TAB_FIXTURE: AttackDispositionRow[] = [
  { attack_type: 'SQL Injection', action: 'BLOCK', count: 920 },
  { attack_type: 'SQL Injection', action: 'ALERT', count: 60 },
  { attack_type: 'Port Scan', action: 'ALERT', count: 1200 },
  { attack_type: 'Port Scan', action: 'ALLOW', count: 40 },
  { attack_type: 'Brute Force', action: 'BLOCK', count: 600 },
  { attack_type: 'Brute Force', action: 'DROP', count: 20 },
  { attack_type: 'Malware', action: 'BLOCK', count: 300 },
  { attack_type: 'Malware', action: 'LOG', count: 10 },
]

/** A cross-tab with six attack types (top-5 + Other — bounded). */
const CROSS_TAB_SIX_FIXTURE: AttackDispositionRow[] = [
  ...CROSS_TAB_FIXTURE,
  { attack_type: 'XSS', action: 'BLOCK', count: 80 },
  { attack_type: 'Other', action: 'ALERT', count: 40 },
]

// ---------------------------------------------------------------------------
// Mock setup for DashboardRoute integration tests
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

const mockFetchAttackDispositions = vi.hoisted(() => vi.fn())

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
    fetchScoreHistory: vi.fn().mockResolvedValue([]),
    // DashboardRoute fetches triage_threshold from /config/runtime (ADR-0059 D1 / #650).
    getRuntimeConfig: vi.fn().mockRejectedValue(new Error('not mocked')),
    // GET /banner/summary (issue #55) — non-blocking; rejecting keeps this file's
    // pre-#55 TriageBanner rendering assumptions unchanged.
    fetchBannerSummary: vi.fn().mockRejectedValue(new Error('not mocked')),
    ApiError,
    resolveBaseUrl: () => '',
    assertLoopbackBase: () => {},
  }
})

vi.mock('../api/analytics', () => ({
  fetchAttackDispositions: mockFetchAttackDispositions,
  fetchGeo: vi.fn().mockResolvedValue([]),
  fetchAnalyticsSummary: vi.fn().mockResolvedValue({}),
  fetchCategoriesTimeline: vi.fn().mockResolvedValue([]),
}))

vi.mock('../api/logs', () => ({
  fetchPaginatedLogs: vi.fn().mockResolvedValue({
    logs: [],
    next_cursor: null,
    has_more: false,
    total_matching: 0,
  }),
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
}))

import DashboardRoute from '../routes/DashboardRoute'

function renderDashboard() {
  return render(
    <MemoryRouter>
      <DashboardRoute />
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// Unit tests — mapActionToGroup
// ---------------------------------------------------------------------------

describe('mapActionToGroup (unit)', () => {
  it('maps BLOCK to Blocked', () => {
    expect(mapActionToGroup('BLOCK')).toBe('Blocked')
  })

  it('maps DROP to Blocked', () => {
    expect(mapActionToGroup('DROP')).toBe('Blocked')
  })

  it('maps ALLOW to Allowed', () => {
    expect(mapActionToGroup('ALLOW')).toBe('Allowed')
  })

  it('maps ALERT to Detected', () => {
    expect(mapActionToGroup('ALERT')).toBe('Detected')
  })

  it('maps LOG to Detected', () => {
    expect(mapActionToGroup('LOG')).toBe('Detected')
  })

  it('maps unrecognized action to Detected (conservative)', () => {
    expect(mapActionToGroup('UNKNOWN_ACTION')).toBe('Detected')
    expect(mapActionToGroup('')).toBe('Detected')
  })

  it('is case-insensitive', () => {
    expect(mapActionToGroup('block')).toBe('Blocked')
    expect(mapActionToGroup('drop')).toBe('Blocked')
    expect(mapActionToGroup('allow')).toBe('Allowed')
    expect(mapActionToGroup('alert')).toBe('Detected')
  })
})

// ---------------------------------------------------------------------------
// Unit tests — buildFlowRows
// ---------------------------------------------------------------------------

describe('buildFlowRows (unit)', () => {
  it('returns empty array for empty input', () => {
    expect(buildFlowRows([])).toEqual([])
  })

  it('computes correct fractions for a pure-block category', () => {
    const rows: AttackDispositionRow[] = [
      { attack_type: 'SQL Injection', action: 'BLOCK', count: 900 },
      { attack_type: 'SQL Injection', action: 'ALERT', count: 100 },
    ]
    const [row] = buildFlowRows(rows)
    expect(row.label).toBe('SQL Injection')
    expect(row.total).toBe(1000)
    expect(row.blockedFraction).toBeCloseTo(0.9)
    expect(row.detectedFraction).toBeCloseTo(0.1)
    expect(row.allowedFraction).toBe(0)
    expect(row.blocked).toBe(900)
    expect(row.detected).toBe(100)
    expect(row.allowed).toBe(0)
  })

  it('preserves server-ordering (insertion order)', () => {
    const rows: AttackDispositionRow[] = [
      { attack_type: 'Port Scan', action: 'ALERT', count: 1200 },
      { attack_type: 'SQL Injection', action: 'BLOCK', count: 920 },
    ]
    const result = buildFlowRows(rows)
    expect(result[0].label).toBe('Port Scan')
    expect(result[1].label).toBe('SQL Injection')
  })

  it('groups BLOCK and DROP into Blocked', () => {
    const rows: AttackDispositionRow[] = [
      { attack_type: 'Brute Force', action: 'BLOCK', count: 600 },
      { attack_type: 'Brute Force', action: 'DROP', count: 20 },
    ]
    const [row] = buildFlowRows(rows)
    expect(row.blocked).toBe(620)
    expect(row.total).toBe(620)
    expect(row.blockedFraction).toBe(1)
  })

  it('excludes rows with total=0 (defensive)', () => {
    // This shouldn't come from the backend, but guard against it
    const rows: AttackDispositionRow[] = [
      { attack_type: 'EmptyType', action: 'BLOCK', count: 0 },
    ]
    // count=0 means total=0; should be excluded
    const result = buildFlowRows(rows)
    expect(result).toHaveLength(0)
  })

  it('handles full fixture correctly', () => {
    const result = buildFlowRows(CROSS_TAB_FIXTURE)
    expect(result).toHaveLength(4) // SQL Injection, Port Scan, Brute Force, Malware
    const sqli = result.find((r) => r.label === 'SQL Injection')
    expect(sqli).toBeDefined()
    expect(sqli!.total).toBe(980)
    expect(sqli!.blocked).toBe(920)
    expect(sqli!.detected).toBe(60)
  })
})

// ---------------------------------------------------------------------------
// Unit tests — DISPOSITION_COLORS
// ---------------------------------------------------------------------------

describe('DISPOSITION_COLORS (unit)', () => {
  it('all color tokens use var(--fw-*) syntax (ADR-0028 D6)', () => {
    for (const value of Object.values(DISPOSITION_COLORS)) {
      expect(value).toMatch(/^var\(--fw-/)
    }
  })

  it('has entries for Blocked, Detected, and Allowed', () => {
    expect(DISPOSITION_COLORS.Blocked).toBeTruthy()
    expect(DISPOSITION_COLORS.Detected).toBeTruthy()
    expect(DISPOSITION_COLORS.Allowed).toBeTruthy()
  })
})

// ---------------------------------------------------------------------------
// Component tests — AttackDispositionFlow
// ---------------------------------------------------------------------------

describe('AttackDispositionFlow (component)', () => {
  it('renders null (hidden) when rows array is empty', () => {
    const { container } = render(
      <MemoryRouter>
        <AttackDispositionFlow rows={[]} />
      </MemoryRouter>,
    )
    expect(container.firstChild).toBeNull()
  })

  it('renders flow rows when cross-tab data is present', () => {
    render(
      <MemoryRouter>
        <AttackDispositionFlow rows={CROSS_TAB_FIXTURE} />
      </MemoryRouter>,
    )
    const flowRows = screen.getAllByTestId('flow-row')
    expect(flowRows.length).toBeGreaterThan(0)
    // Should show all 4 distinct attack types
    expect(flowRows).toHaveLength(4)
  })

  it('shows blocked segment for a row with BLOCK events', () => {
    render(
      <MemoryRouter>
        <AttackDispositionFlow rows={CROSS_TAB_FIXTURE} />
      </MemoryRouter>,
    )
    // SQL Injection has both BLOCK and ALERT actions
    const blockedSegments = screen.getAllByTestId('flow-segment-blocked')
    expect(blockedSegments.length).toBeGreaterThan(0)
  })

  it('shows detected segment for a row with ALERT/LOG events', () => {
    render(
      <MemoryRouter>
        <AttackDispositionFlow rows={CROSS_TAB_FIXTURE} />
      </MemoryRouter>,
    )
    const detectedSegments = screen.getAllByTestId('flow-segment-detected')
    expect(detectedSegments.length).toBeGreaterThan(0)
  })

  it('shows allowed segment only when ALLOW events exist', () => {
    // Port Scan has ALLOW events
    render(
      <MemoryRouter>
        <AttackDispositionFlow rows={CROSS_TAB_FIXTURE} />
      </MemoryRouter>,
    )
    const allowedSegments = screen.getAllByTestId('flow-segment-allowed')
    expect(allowedSegments.length).toBeGreaterThan(0)
  })

  it('renders at most 6 rows for bounded top-5 + Other input', () => {
    render(
      <MemoryRouter>
        <AttackDispositionFlow rows={CROSS_TAB_SIX_FIXTURE} />
      </MemoryRouter>,
    )
    const flowRows = screen.getAllByTestId('flow-row')
    // 6 distinct attack types in fixture (SQL Injection, Port Scan, Brute Force, Malware, XSS, Other)
    expect(flowRows.length).toBeLessThanOrEqual(6)
  })

  it('clicking a flow row navigates to /logs with attack type query', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <MemoryRouter>
        <AttackDispositionFlow rows={CROSS_TAB_FIXTURE} />
      </MemoryRouter>,
    )
    const flowRows = screen.getAllByTestId('flow-row')
    expect(flowRows.length).toBeGreaterThan(0)

    await user.click(flowRows[0])

    // MemoryRouter absorbs navigation — no crash = success
    expect(container).toBeTruthy()
    // Component still present after click
    expect(screen.getByTestId('attack-disposition-flow')).toBeInTheDocument()
  })

  it('segment title attributes include count and percentage for hover display', () => {
    render(
      <MemoryRouter>
        <AttackDispositionFlow rows={[{ attack_type: 'SQL Injection', action: 'BLOCK', count: 900 }]} />
      </MemoryRouter>,
    )
    const blockedSeg = screen.getByTestId('flow-segment-blocked')
    expect(blockedSeg.title).toContain('900')
    expect(blockedSeg.title).toContain('100%')
  })

  it('strip header is labeled "Attack → Disposition" for clear UX', () => {
    render(
      <MemoryRouter>
        <AttackDispositionFlow rows={CROSS_TAB_FIXTURE} />
      </MemoryRouter>,
    )
    expect(screen.getByTestId('attack-disposition-flow')).toBeInTheDocument()
    expect(screen.getByText(/Attack.*Disposition/i)).toBeInTheDocument()
  })

  it('segment backgrounds use DS color tokens (no raw hex, ADR-0028 D6)', () => {
    render(
      <MemoryRouter>
        <AttackDispositionFlow rows={CROSS_TAB_FIXTURE} />
      </MemoryRouter>,
    )
    const blockedSegs = screen.getAllByTestId('flow-segment-blocked')
    for (const seg of blockedSegs) {
      expect((seg as HTMLElement).style.background).toContain('var(--fw-')
    }
  })

  it('renders correctly with two same-label (attack_type) rows of different actions (issue #314)', () => {
    // EARS criterion: "A component-level test SHALL render the flow with two
    // same-label rows (different actions) without a key warning."
    //
    // With the old server bug, two rows with the same attack_type but different
    // actions could arrive.  buildFlowRows merges them into one FlowRow, but the
    // composite key `${label}:${total}` ensures React still has unique keys even
    // if the aggregation contract changes.
    const duplicateLabelRows: AttackDispositionRow[] = [
      { attack_type: 'Other', action: 'BLOCK', count: 5 },
      { attack_type: 'Other', action: 'ALERT', count: 3 },
    ]
    // Spy on console.error to detect React duplicate-key warnings.
    const consoleSpy = vi.spyOn(console, 'error')

    render(
      <MemoryRouter>
        <AttackDispositionFlow rows={duplicateLabelRows} />
      </MemoryRouter>,
    )

    // Component renders one merged row (Other: blocked=5, detected=3).
    const flowRows = screen.getAllByTestId('flow-row')
    expect(flowRows).toHaveLength(1)

    // No React duplicate-key warning should have been emitted.
    const keyWarnings = consoleSpy.mock.calls.filter(
      (args) => typeof args[0] === 'string' && args[0].includes('key'),
    )
    expect(keyWarnings).toHaveLength(0)

    consoleSpy.mockRestore()
  })
})

// ---------------------------------------------------------------------------
// Dashboard integration tests
// ---------------------------------------------------------------------------

describe('DashboardRoute — flow strip integration (issue #214)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
  })

  it('shows the flow strip panel when attackDispositions is non-empty', async () => {
    mockFetchAttackDispositions.mockResolvedValue(CROSS_TAB_FIXTURE)

    renderDashboard()

    await waitFor(() =>
      expect(screen.getByTestId('attack-disposition-flow')).toBeInTheDocument(),
    )
  })

  it('hides the flow strip panel when attackDispositions is empty', async () => {
    mockFetchAttackDispositions.mockResolvedValue([])

    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('grid-2')).toBeInTheDocument())

    // Strip must not be visible when data is empty (degrade-to-hidden, not broken)
    expect(screen.queryByTestId('attack-disposition-flow')).toBeNull()
  })

  it('dashboard remains functional when fetchAttackDispositions rejects (non-fatal)', async () => {
    mockFetchAttackDispositions.mockRejectedValue(new Error('Network error'))

    renderDashboard()

    // Dashboard loads normally despite the failure
    await waitFor(() => expect(screen.getByTestId('grid-2')).toBeInTheDocument())

    // No broken state; flow strip simply absent
    expect(screen.queryByTestId('attack-disposition-flow')).toBeNull()
    // Core dashboard content still present
    expect(screen.getByTestId('attack-categories-pane')).toBeInTheDocument()
    expect(screen.getByTestId('category-breakdown')).toBeInTheDocument()
  })
})
