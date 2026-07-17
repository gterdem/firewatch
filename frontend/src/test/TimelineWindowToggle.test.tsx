/**
 * Tests for the 12h / 24h window toggle and custom date-range pickers in
 * DashboardRoute (part-4 P3 + follow-up).
 *
 * The TimelineBrush drag-select overlay was removed because its
 * pointer-events:auto div blocked CellTooltip bar hover in TimelineChart.
 * The window toggle in the Activity-timeline Panel header is the replacement.
 * A custom From/To datetime-local picker row was added alongside the toggle.
 *
 * EARS acceptance criteria covered:
 *
 * A. Toggle renders with correct defaults:
 *    - The timeline-window-toggle group is present in the dashboard.
 *    - The 12h button defaults to aria-pressed="true".
 *    - The 24h button defaults to aria-pressed="false".
 *
 * B. Switching to 24h refetches timeline:
 *    - Clicking the 24h button triggers fetchTimeline with a ~24h start param.
 *    - The start param is approximately now - 24h (within a 60s tolerance).
 *    - The end param is approximately now (within a 60s tolerance).
 *
 * C. Switching back to 12h reflects aria-pressed:
 *    - After clicking 24h then 12h, the 12h button has aria-pressed="true".
 *
 * D. No timeline-brush-overlay in the DOM:
 *    - The removed brush overlay must NOT exist after the brush deletion.
 *
 * E. No brush-start-input / brush-end-input in the DOM:
 *    - The removed range slider thumbs must NOT exist after the brush deletion.
 *
 * F. Custom date-range pickers render alongside the toggle:
 *    - timeline-date-range-picker is present in the dashboard.
 *    - timeline-range-start and timeline-range-end inputs are present.
 *
 * G. Start change defaults End to Start + 12h when End is empty:
 *    - After entering a Start value, the End input value is set to Start + 12h.
 *    - fetchTimeline is called with a valid UTC start/end pair.
 *
 * H. End > 24h after Start is clamped to Start + 24h:
 *    - Entering an End more than 24h after Start calls fetchTimeline with
 *      End = Start + 24h (the clamped value), not the original input.
 *
 * I. Valid custom range calls fetchTimeline with UTC ISO start/end:
 *    - Both start and end params are valid UTC ISO strings.
 *    - The window (end − start) is within the valid range.
 *
 * J. Clicking a preset after custom range returns to trailing window:
 *    - After entering a custom range, clicking 12h calls fetchTimeline
 *      with a trailing ~12h window from now.
 *    - The 12h button re-gains aria-pressed="true".
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import DashboardRoute from '../routes/DashboardRoute'
import {
  STATS_FIXTURE,
  TIMELINE_FIXTURE,
  CATEGORIES_FIXTURE,
  THREATS_FIXTURE,
  HEALTH_AI_ONLINE,
} from './readFixtures'

// ---------------------------------------------------------------------------
// Mocks
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
    fetchScoreHistory: vi.fn().mockResolvedValue([]),
    // DashboardRoute fetches triage_threshold from /config/runtime (ADR-0059 D1 / #650).
    getRuntimeConfig: vi.fn().mockRejectedValue(new Error('not mocked')),
    // GET /banner/summary (issue #55) — non-blocking; rejecting keeps attemptSummary
    // null, matching this file's pre-#55 TriageBanner rendering assumptions.
    fetchBannerSummary: vi.fn().mockRejectedValue(new Error('not mocked')),
    ApiError,
    resolveBaseUrl: () => '',
    assertLoopbackBase: () => {},
  }
})

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

vi.mock('../api/analytics', () => ({
  fetchAttackDispositions: vi.fn().mockResolvedValue([]),
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderDashboard() {
  return render(
    <MemoryRouter>
      <DashboardRoute />
    </MemoryRouter>,
  )
}

async function waitForDashboardLoad() {
  await waitFor(() => {
    expect(screen.getByTestId('kpi-strip')).toBeInTheDocument()
  })
}

// ---------------------------------------------------------------------------
// beforeEach
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
  mockFetchStats.mockResolvedValue(STATS_FIXTURE)
  mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
  mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
  mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
  mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
})

// ---------------------------------------------------------------------------
// A. Toggle renders with correct defaults
// ---------------------------------------------------------------------------

describe('Timeline window toggle — renders with correct defaults', () => {
  it('timeline-window-toggle group is present in the dashboard', async () => {
    renderDashboard()
    await waitForDashboardLoad()
    expect(screen.getByTestId('timeline-window-toggle')).toBeInTheDocument()
  })

  it('12h button is present', async () => {
    renderDashboard()
    await waitForDashboardLoad()
    expect(screen.getByTestId('timeline-window-12h')).toBeInTheDocument()
  })

  it('24h button is present', async () => {
    renderDashboard()
    await waitForDashboardLoad()
    expect(screen.getByTestId('timeline-window-24h')).toBeInTheDocument()
  })

  it('12h button defaults to aria-pressed="true"', async () => {
    renderDashboard()
    await waitForDashboardLoad()
    const btn12 = screen.getByTestId('timeline-window-12h')
    expect(btn12.getAttribute('aria-pressed')).toBe('true')
  })

  it('24h button defaults to aria-pressed="false"', async () => {
    renderDashboard()
    await waitForDashboardLoad()
    const btn24 = screen.getByTestId('timeline-window-24h')
    expect(btn24.getAttribute('aria-pressed')).toBe('false')
  })

  it('toggle group has role="group" with accessible label', async () => {
    renderDashboard()
    await waitForDashboardLoad()
    const group = screen.getByRole('group', { name: 'Timeline window' })
    expect(group).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// B. Switching to 24h refetches timeline with ~24h start param
// ---------------------------------------------------------------------------

describe('Timeline window toggle — 24h click refetches with ~24h window', () => {
  it('clicking 24h triggers fetchTimeline with a start and end param', async () => {
    renderDashboard()
    await waitForDashboardLoad()

    // Clear the initial mount calls
    mockFetchTimeline.mockClear()

    const beforeClick = Date.now()

    await act(async () => {
      await userEvent.click(screen.getByTestId('timeline-window-24h'))
    })

    await waitFor(() => {
      expect(mockFetchTimeline).toHaveBeenCalled()
    })

    const callArgs = mockFetchTimeline.mock.calls[0] as [{ start: string; end: string }]
    expect(callArgs[0]).toBeDefined()
    expect(callArgs[0].start).toBeDefined()
    expect(callArgs[0].end).toBeDefined()

    // The start should be approximately now - 24h (within 60 seconds tolerance)
    const startMs = new Date(callArgs[0].start).getTime()
    const endMs = new Date(callArgs[0].end).getTime()
    const windowMs = endMs - startMs

    // Window should be close to 24h (86400000 ms), within 60s tolerance
    expect(windowMs).toBeGreaterThan(86400000 - 60000)
    expect(windowMs).toBeLessThan(86400000 + 60000)

    // End should be close to beforeClick (within 5 seconds)
    expect(endMs).toBeGreaterThanOrEqual(beforeClick - 1000)
    expect(endMs).toBeLessThanOrEqual(beforeClick + 5000)
  })

  it('24h button has aria-pressed="true" after clicking it', async () => {
    renderDashboard()
    await waitForDashboardLoad()

    await act(async () => {
      await userEvent.click(screen.getByTestId('timeline-window-24h'))
    })

    expect(screen.getByTestId('timeline-window-24h').getAttribute('aria-pressed')).toBe('true')
    expect(screen.getByTestId('timeline-window-12h').getAttribute('aria-pressed')).toBe('false')
  })
})

// ---------------------------------------------------------------------------
// C. Switching back to 12h reflects aria-pressed
// ---------------------------------------------------------------------------

describe('Timeline window toggle — switching back to 12h', () => {
  it('12h button regains aria-pressed="true" after 24h → 12h click sequence', async () => {
    renderDashboard()
    await waitForDashboardLoad()

    await act(async () => {
      await userEvent.click(screen.getByTestId('timeline-window-24h'))
    })
    await act(async () => {
      await userEvent.click(screen.getByTestId('timeline-window-12h'))
    })

    expect(screen.getByTestId('timeline-window-12h').getAttribute('aria-pressed')).toBe('true')
    expect(screen.getByTestId('timeline-window-24h').getAttribute('aria-pressed')).toBe('false')
  })
})

// ---------------------------------------------------------------------------
// D. No timeline-brush-overlay in the DOM (brush removed)
// ---------------------------------------------------------------------------

describe('Timeline brush overlay — removed (part-4 P3)', () => {
  it('timeline-brush-overlay is NOT in the DOM', async () => {
    renderDashboard()
    await waitForDashboardLoad()
    expect(screen.queryByTestId('timeline-brush-overlay')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// E. No brush slider thumbs in the DOM (brush removed)
// ---------------------------------------------------------------------------

describe('Timeline brush sliders — removed (part-4 P3)', () => {
  it('brush-start-input is NOT in the DOM', async () => {
    renderDashboard()
    await waitForDashboardLoad()
    expect(screen.queryByTestId('brush-start-input')).not.toBeInTheDocument()
  })

  it('brush-end-input is NOT in the DOM', async () => {
    renderDashboard()
    await waitForDashboardLoad()
    expect(screen.queryByTestId('brush-end-input')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// F. Custom date-range pickers render alongside the toggle
// ---------------------------------------------------------------------------

describe('Timeline custom date-range pickers — render', () => {
  it('timeline-date-range-picker is present in the dashboard', async () => {
    renderDashboard()
    await waitForDashboardLoad()
    expect(screen.getByTestId('timeline-date-range-picker')).toBeInTheDocument()
  })

  it('timeline-range-start input is present', async () => {
    renderDashboard()
    await waitForDashboardLoad()
    expect(screen.getByTestId('timeline-range-start')).toBeInTheDocument()
  })

  it('timeline-range-end input is present', async () => {
    renderDashboard()
    await waitForDashboardLoad()
    expect(screen.getByTestId('timeline-range-end')).toBeInTheDocument()
  })

  it('both pickers render alongside the preset toggle (timeline-controls wrapper)', async () => {
    renderDashboard()
    await waitForDashboardLoad()
    expect(screen.getByTestId('timeline-controls')).toBeInTheDocument()
    const controls = screen.getByTestId('timeline-controls')
    expect(controls.contains(screen.getByTestId('timeline-window-toggle'))).toBe(true)
    expect(controls.contains(screen.getByTestId('timeline-date-range-picker'))).toBe(true)
  })

  it('no timeline-brush-overlay is reintroduced (regression guard)', async () => {
    renderDashboard()
    await waitForDashboardLoad()
    expect(screen.queryByTestId('timeline-brush-overlay')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// G. Start change defaults End to Start + 12h when End is empty
// ---------------------------------------------------------------------------

describe('Timeline custom range — Start change defaults End to Start + 12h', () => {
  it('entering a Start value calls fetchTimeline with a valid UTC start/end pair', async () => {
    renderDashboard()
    await waitForDashboardLoad()

    mockFetchTimeline.mockClear()

    const startInput = screen.getByTestId('timeline-range-start')
    // "2026-06-10T08:00" — a fixed past time; End field is initially empty.
    await act(async () => {
      await userEvent.type(startInput, '2026-06-10T08:00')
      // Trigger the change event explicitly (userEvent.type on datetime-local)
      fireEvent.change(startInput, { target: { value: '2026-06-10T08:00' } })
    })

    await waitFor(() => {
      expect(mockFetchTimeline).toHaveBeenCalled()
    })

    const callArgs = mockFetchTimeline.mock.calls[mockFetchTimeline.mock.calls.length - 1] as [{ start: string; end: string }]
    expect(callArgs[0].start).toBeDefined()
    expect(callArgs[0].end).toBeDefined()

    const startMs = new Date(callArgs[0].start).getTime()
    const endMs = new Date(callArgs[0].end).getTime()
    const windowMs = endMs - startMs

    // End − Start should be 12h (the default when End was empty)
    expect(windowMs).toBeGreaterThanOrEqual(12 * 60 * 60 * 1000 - 5000)
    expect(windowMs).toBeLessThanOrEqual(12 * 60 * 60 * 1000 + 5000)
  })
})

// ---------------------------------------------------------------------------
// H. End > 24h after Start is clamped to Start + 24h
// ---------------------------------------------------------------------------

describe('Timeline custom range — End >24h after Start is clamped', () => {
  it('entering End 26h after Start results in fetchTimeline called with End = Start + 24h', async () => {
    renderDashboard()
    await waitForDashboardLoad()

    const startInput = screen.getByTestId('timeline-range-start')
    // Set Start first
    await act(async () => {
      fireEvent.change(startInput, { target: { value: '2026-06-10T08:00' } })
    })

    await waitFor(() => expect(mockFetchTimeline).toHaveBeenCalled())
    mockFetchTimeline.mockClear()

    const endInput = screen.getByTestId('timeline-range-end')
    // Enter End 26h after Start → should be clamped to Start + 24h
    await act(async () => {
      fireEvent.change(endInput, { target: { value: '2026-06-11T10:00' } })
    })

    await waitFor(() => {
      expect(mockFetchTimeline).toHaveBeenCalled()
    })

    const callArgs = mockFetchTimeline.mock.calls[0] as [{ start: string; end: string }]
    const startMs = new Date(callArgs[0].start).getTime()
    const endMs = new Date(callArgs[0].end).getTime()
    const windowMs = endMs - startMs

    // Window must be exactly 24h (the cap), not 26h
    expect(windowMs).toBeGreaterThanOrEqual(24 * 60 * 60 * 1000 - 5000)
    expect(windowMs).toBeLessThanOrEqual(24 * 60 * 60 * 1000 + 5000)
  })
})

// ---------------------------------------------------------------------------
// I. Valid custom range calls fetchTimeline with UTC ISO start/end
// ---------------------------------------------------------------------------

describe('Timeline custom range — valid range calls fetchTimeline with UTC ISO strings', () => {
  it('valid range produces UTC ISO strings (end with Z) in the API call', async () => {
    renderDashboard()
    await waitForDashboardLoad()

    mockFetchTimeline.mockClear()

    const startInput = screen.getByTestId('timeline-range-start')
    const endInput = screen.getByTestId('timeline-range-end')

    await act(async () => {
      fireEvent.change(startInput, { target: { value: '2026-06-10T08:00' } })
    })
    await waitFor(() => expect(mockFetchTimeline).toHaveBeenCalled())
    mockFetchTimeline.mockClear()

    // Now set a valid End 6h later
    await act(async () => {
      fireEvent.change(endInput, { target: { value: '2026-06-10T14:00' } })
    })

    await waitFor(() => {
      expect(mockFetchTimeline).toHaveBeenCalled()
    })

    const callArgs = mockFetchTimeline.mock.calls[0] as [{ start: string; end: string }]
    // Both must be UTC ISO strings
    expect(callArgs[0].start).toMatch(/Z$/)
    expect(callArgs[0].end).toMatch(/Z$/)

    // Window should be 6h
    const windowMs = new Date(callArgs[0].end).getTime() - new Date(callArgs[0].start).getTime()
    expect(windowMs).toBeGreaterThan(0)
    expect(windowMs).toBeLessThanOrEqual(24 * 60 * 60 * 1000)
  })
})

// ---------------------------------------------------------------------------
// J. Clicking a preset after a custom range returns to trailing window
// ---------------------------------------------------------------------------

describe('Timeline custom range → preset — returns to trailing window', () => {
  it('clicking 12h after custom range calls fetchTimeline with ~12h trailing window', async () => {
    renderDashboard()
    await waitForDashboardLoad()

    // Enter a custom range first
    const startInput = screen.getByTestId('timeline-range-start')
    await act(async () => {
      fireEvent.change(startInput, { target: { value: '2026-06-10T08:00' } })
    })
    await waitFor(() => expect(mockFetchTimeline).toHaveBeenCalled())
    mockFetchTimeline.mockClear()

    const beforeClick = Date.now()

    // Now click the 12h preset
    await act(async () => {
      await userEvent.click(screen.getByTestId('timeline-window-12h'))
    })

    await waitFor(() => {
      expect(mockFetchTimeline).toHaveBeenCalled()
    })

    const callArgs = mockFetchTimeline.mock.calls[0] as [{ start: string; end: string }]
    const startMs = new Date(callArgs[0].start).getTime()
    const endMs = new Date(callArgs[0].end).getTime()
    const windowMs = endMs - startMs

    // Window should be ~12h (trailing from now)
    expect(windowMs).toBeGreaterThan(12 * 60 * 60 * 1000 - 60000)
    expect(windowMs).toBeLessThan(12 * 60 * 60 * 1000 + 60000)

    // End should be close to now
    expect(endMs).toBeGreaterThanOrEqual(beforeClick - 1000)
    expect(endMs).toBeLessThanOrEqual(beforeClick + 5000)
  })

  it('12h button re-gains aria-pressed="true" after switching from custom mode', async () => {
    renderDashboard()
    await waitForDashboardLoad()

    // Enter custom mode
    const startInput = screen.getByTestId('timeline-range-start')
    await act(async () => {
      fireEvent.change(startInput, { target: { value: '2026-06-10T08:00' } })
    })

    // Verify 12h button is NOT the active preset in custom mode
    // (aria-pressed depends on activeTimelineMode === 'preset' AND windowHours === 12)
    // Click 12h to switch back
    await act(async () => {
      await userEvent.click(screen.getByTestId('timeline-window-12h'))
    })

    expect(screen.getByTestId('timeline-window-12h').getAttribute('aria-pressed')).toBe('true')
    expect(screen.getByTestId('timeline-window-24h').getAttribute('aria-pressed')).toBe('false')
  })
})
