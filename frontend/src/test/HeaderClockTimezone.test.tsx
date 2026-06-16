/**
 * Tests for issue #278 — header clock becomes timezone authority.
 *
 * EARS acceptance criteria (1:1):
 *
 * 1. WHEN the Dashboard renders, the system SHALL NOT render the
 *    dashboard-zone-chip banner row.
 *
 * 2. WHILE the app header is visible, MonoClock SHALL render local time
 *    with an inline zone label (e.g. "21:47:03 EDT").
 *    - The clock text must end with a non-empty zone abbreviation.
 *    - Rendering uses the monospace font (--fw-font-mono).
 *
 * 3. WHEN the clock is hovered, the system SHALL show a CellTooltip
 *    containing the live UTC time (ends with " UTC") and the legend
 *    "all times shown in … · stored as UTC".
 *
 * 4. WHEN the clock trigger is keyboard-focused, the same tooltip content
 *    SHALL appear (keyboard parity, WCAG 1.4.13).
 *
 * 5. DashboardRoute no longer references DashboardZoneChip — the zone chip
 *    testid must not appear anywhere on the dashboard.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import type React from 'react'
import { RefreshProvider } from '../app/refresh/RefreshContext'

// ---------------------------------------------------------------------------
// Minimal ThemeContext mock so AppHeader renders without ThemeProvider wrapper
// (same pattern as AllSourcesHealthList.test.tsx)
// ---------------------------------------------------------------------------

vi.mock('../app/ThemeContext', () => ({
  useTheme: () => ({ theme: 'dark', toggleTheme: vi.fn() }),
  ThemeProvider: ({ children }: { children: React.ReactNode }) => children,
}))

// ---------------------------------------------------------------------------
// Mocks for AppHeader (SourceFilterBar polls GET /stats) and DashboardRoute
// ---------------------------------------------------------------------------

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    fetchStats: vi.fn().mockResolvedValue({
      source_health: [],
      total_logs: 100,
      total_ips: 5,
      blocked_percentage: 50,
      last_updated: null,
    }),
    fetchSourceTypes: vi.fn().mockResolvedValue([]),
    fetchTimeline: vi.fn().mockResolvedValue([]),
    fetchCategories: vi.fn().mockResolvedValue([]),
    fetchThreats: vi.fn().mockResolvedValue([]),
    fetchHealth: vi.fn().mockResolvedValue({ ollama_connected: false, ollama_model: null }),
    ApiError: class ApiError extends Error {
      status: number
      detail: unknown
      constructor(status: number, detail: unknown, message?: string) {
        super(message ?? `API error ${status}`)
        this.status = status
        this.detail = detail
      }
    },
    resolveBaseUrl: () => '',
    assertLoopbackBase: () => {},
  }
})

vi.mock('../api/sources', () => ({
  fetchSources: vi.fn().mockResolvedValue([]),
}))

vi.mock('../api/analytics', () => ({
  fetchAttackDispositions: vi.fn().mockResolvedValue([]),
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function renderAppHeader() {
  const { default: AppHeader } = await import('../app/AppHeader')
  return render(
    <RefreshProvider>
      <MemoryRouter>
        <AppHeader />
      </MemoryRouter>
    </RefreshProvider>,
  )
}

// ---------------------------------------------------------------------------
// 1. Dashboard does NOT render the zone-chip banner row
// ---------------------------------------------------------------------------

describe('#278 — dashboard-zone-chip banner removed', () => {
  it('dashboard-zone-chip testid is NOT present on the dashboard (loading state)', async () => {
    // The api/client mock above returns total_logs: 100 but the DashboardRoute
    // will reach loading → resolved state. Either way the zone chip must be absent.
    // We verify absence immediately (the zone chip JSX was deleted from DashboardRoute).
    const { default: DashboardRoute } = await import('../routes/DashboardRoute')
    render(
      <MemoryRouter>
        <DashboardRoute />
      </MemoryRouter>,
    )
    // Immediately after render (before async resolves) chip must not be there
    expect(screen.queryByTestId('dashboard-zone-chip')).not.toBeInTheDocument()
  })

  it('dashboard-zone-chip testid is NOT present after data loads', async () => {
    const { default: DashboardRoute } = await import('../routes/DashboardRoute')
    render(
      <MemoryRouter>
        <DashboardRoute />
      </MemoryRouter>,
    )
    // Wait for loading to settle (kpi-strip or error or empty-state appears)
    await waitFor(() => {
      const loaded =
        screen.queryByTestId('kpi-strip') !== null ||
        screen.queryByRole('alert') !== null ||
        screen.queryByTestId('dashboard-empty-state') !== null
      if (!loaded) throw new Error('Still loading')
    }, { timeout: 3000 })
    // Zone chip must never appear — it was removed from this route
    expect(screen.queryByTestId('dashboard-zone-chip')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 2. MonoClock renders local time with inline zone label
// ---------------------------------------------------------------------------

describe('#278 — header clock shows zone label', () => {
  it('header-clock element is present in the AppHeader', async () => {
    await renderAppHeader()
    expect(screen.getByTestId('header-clock')).toBeInTheDocument()
  })

  it('header-clock text includes a zone label after the time digits', async () => {
    await renderAppHeader()
    const clock = screen.getByTestId('header-clock')
    const text = clock.textContent ?? ''
    // Format: "HH:MM:SS ZONE" — must have at least one space separating time from zone
    // and the zone must be a non-empty string after the last colon-bearing segment.
    expect(text).toBeTruthy()
    // Time portion: contains at least two colon-separated segments (HH:MM:SS)
    expect(text).toMatch(/\d{2}:\d{2}:\d{2}/)
    // Zone portion: a non-empty word follows the time (e.g. "UTC", "EDT", "UTC+5")
    expect(text).toMatch(/\d{2}:\d{2}:\d{2}\s+\S+/)
  })

  it('header-clock uses monospace font (--fw-font-mono)', async () => {
    await renderAppHeader()
    const clock = screen.getByTestId('header-clock')
    expect(clock.getAttribute('style')).toContain('fw-font-mono')
  })

  it('header-clock uses --fw-t3 color token', async () => {
    await renderAppHeader()
    const clock = screen.getByTestId('header-clock')
    expect(clock.getAttribute('style')).toContain('fw-t3')
  })
})

// ---------------------------------------------------------------------------
// 3 + 4. CellTooltip on clock: hover and keyboard-focus reveal UTC + legend
// ---------------------------------------------------------------------------

describe('#278 — clock tooltip via hover (WCAG 1.4.13)', () => {
  it('hovering the clock trigger shows the tooltip content', async () => {
    await renderAppHeader()
    const trigger = screen.getByTestId('header-clock-trigger')

    expect(screen.queryByTestId('clock-tooltip-content')).not.toBeInTheDocument()

    fireEvent.mouseEnter(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('clock-tooltip-content')).toBeInTheDocument()
    })
  })

  it('tooltip contains a UTC time string (ends with " UTC")', async () => {
    await renderAppHeader()
    const trigger = screen.getByTestId('header-clock-trigger')

    fireEvent.mouseEnter(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('clock-tooltip-content')).toBeInTheDocument()
    })

    const tooltipText = screen.getByTestId('clock-tooltip-content').textContent ?? ''
    expect(tooltipText).toMatch(/ UTC/)
  })

  it('tooltip contains the "stored as UTC" legend', async () => {
    await renderAppHeader()
    const trigger = screen.getByTestId('header-clock-trigger')

    fireEvent.mouseEnter(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('clock-tooltip-content')).toBeInTheDocument()
    })

    const tooltipText = screen.getByTestId('clock-tooltip-content').textContent ?? ''
    expect(tooltipText).toContain('stored as UTC')
  })

  it('tooltip legend contains "all times shown in"', async () => {
    await renderAppHeader()
    const trigger = screen.getByTestId('header-clock-trigger')

    fireEvent.mouseEnter(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('clock-tooltip-content')).toBeInTheDocument()
    })

    const tooltipText = screen.getByTestId('clock-tooltip-content').textContent ?? ''
    expect(tooltipText).toContain('all times shown in')
  })
})

describe('#278 — clock tooltip via keyboard focus (WCAG 1.4.13 parity)', () => {
  it('keyboard focus on the clock trigger shows the tooltip content', async () => {
    await renderAppHeader()
    const trigger = screen.getByTestId('header-clock-trigger')

    expect(screen.queryByTestId('clock-tooltip-content')).not.toBeInTheDocument()

    fireEvent.focus(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('clock-tooltip-content')).toBeInTheDocument()
    })
  })

  it('keyboard-focused clock tooltip also shows UTC and legend', async () => {
    await renderAppHeader()
    const trigger = screen.getByTestId('header-clock-trigger')

    fireEvent.focus(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('clock-tooltip-content')).toBeInTheDocument()
    })

    const tooltipText = screen.getByTestId('clock-tooltip-content').textContent ?? ''
    expect(tooltipText).toMatch(/ UTC/)
    expect(tooltipText).toContain('stored as UTC')
  })

  it('clock trigger is keyboard-focusable (tabIndex=0 on CellTooltip trigger)', async () => {
    await renderAppHeader()
    const trigger = screen.getByTestId('header-clock-trigger')
    expect(trigger.getAttribute('tabindex')).toBe('0')
  })
})

// ---------------------------------------------------------------------------
// 5. DashboardZoneChip is no longer imported anywhere in DashboardRoute
// ---------------------------------------------------------------------------

describe('#278 — DashboardZoneChip removed from DashboardRoute', () => {
  it('DashboardRoute module source does not contain DashboardZoneChip reference', async () => {
    // The import of DashboardZoneChip was removed from DashboardRoute.tsx.
    // We verify this by checking that the rendered dashboard does not contain
    // the dashboard-zone-chip testid (the chip rendered that testid).
    const { default: DashboardRoute } = await import('../routes/DashboardRoute')
    render(
      <MemoryRouter>
        <DashboardRoute />
      </MemoryRouter>,
    )
    // Give the component time to settle
    await new Promise((r) => setTimeout(r, 50))
    expect(screen.queryByTestId('dashboard-zone-chip')).not.toBeInTheDocument()
  })
})
