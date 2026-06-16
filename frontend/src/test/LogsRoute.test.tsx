/**
 * Tests for src/routes/LogsRoute.tsx (#112, migrated to slide-over ADR-0037,
 * #203 ?ip= deep-link, #252 ?action= deep-link + server-side action filter,
 * #565 ?q= / ?signature= / ?payload= deep-link params)
 *
 * EARS criteria covered:
 *   - On mount: calls fetchPaginatedLogs with limit=25 and no cursor.
 *   - On Next: echoes next_cursor from envelope.
 *   - On filter change: resets cursor; re-fetches.
 *   - Action filter (server-side, issue #252): selecting an action triggers a new
 *     fetch with ?action= — NOT a client-side page filter.
 *   - State-driven: populated logs → table rendered.
 *   - State-driven: empty result → empty state.
 *   - Unwanted: API error → error state (not a blank crash).
 *   - Loading state: Spinner shown while in-flight.
 *   - IP click → entity slide-over panel opens (ADR-0037, replaces modal).
 *
 * #203 — ?ip= deep-link EARS criteria:
 *   - WHEN mounted at /logs?ip=<valid>, table filters to that IP (ip chip shown).
 *   - WHEN the IP chip is removed, ?ip= is removed from the URL.
 *   - IF ?ip= is not a plausible IP, it is ignored gracefully (no crash).
 *
 * #252 — ?action= deep-link EARS criteria:
 *   - WHEN mounted at /logs?action=blocked, action is passed to fetchPaginatedLogs.
 *   - WHEN mounted at /logs?action=blocked, the action chip shows.
 *   - WHEN the action chip is removed, ?action= is cleared and re-fetch fires.
 *   - IF ?action= is an unknown/invalid value, it is ignored gracefully.
 *
 * #565 — ?q= / ?signature= / ?payload= deep-link EARS criteria:
 *   - WHEN mounted with ?q=<text>, seed filter.q and pass it to fetchPaginatedLogs.
 *   - WHEN mounted with ?signature=<val>, seed filter.q from it.
 *   - WHEN mounted with ?payload=<val>, seed filter.q from it.
 *   - WHEN multiple recognised params present, all are applied together.
 *   - WHEN an unrecognised param is present, it is ignored without error.
 *
 * NOTE: LogsRoute uses useSearchParams() (react-router-dom) — all renders must be
 * wrapped in a router context. renderLogsRoute() uses MemoryRouter (no URL params);
 * helpers with URL params pass initialEntries to MemoryRouter.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LogsRoute from '../routes/LogsRoute'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
// #748: LogsRoute now requires RefreshProvider (useRefreshSignal)
import { RefreshProvider } from '../app/refresh/RefreshContext'
import {
  PAGINATED_LOGS_PAGE1,
  PAGINATED_LOGS_LAST_PAGE,
  PAGINATED_LOGS_EMPTY,
} from './readFixtures'

const { mockFetchPaginatedLogs } = vi.hoisted(() => ({
  mockFetchPaginatedLogs: vi.fn(),
}))

vi.mock('../api/logs', () => ({
  fetchPaginatedLogs: mockFetchPaginatedLogs,
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
  // ML-3 (#431): fetchTopPairs added to route; default to empty list (non-fatal).
  fetchTopPairs: vi.fn().mockResolvedValue([]),
  // #665: StripTiles (replaced TrafficShapeHeader) uses these — default to empty/zeros (non-fatal).
  fetchLogsStats: vi.fn().mockResolvedValue({ total_events: 0, blocked_events: 0, distinct_ips: 0, present_source_types: [] }),
  fetchTopTalkers: vi.fn().mockResolvedValue([]),
  fetchProtocolMix: vi.fn().mockResolvedValue([]),
  // ML-9 (#437): entity graph — default to null (non-fatal; shows empty state).
  fetchEntityGraph: vi.fn().mockResolvedValue(null),
}))

vi.mock('../api/client', () => ({
  fetchThreats: vi.fn().mockResolvedValue([]),
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  // Issue #268: useDeepAnalysis calls fetchHealth; default to AI offline so it resolves instantly.
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'ok', ollama_connected: false, ollama_model: null, db_ok: true,
  }),
  // ML-4 (#432): TrafficShapeHeader fetches timeline — non-fatal empty default.
  fetchTimeline: vi.fn().mockResolvedValue([]),
  // #748: RefreshProvider (now required by LogsRoute) calls fetchStats once on mount.
  // Default to a minimal valid stats response so the provider initialises without error.
  fetchStats: vi.fn().mockResolvedValue({
    total_logs: 100,
    total_ips: 5,
    blocked_percentage: 10,
    last_updated: new Date().toISOString(),
    freshness_minutes: 5,
    source_health: [],
  }),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: unknown) {
      super(String(message ?? status))
      this.status = status
    }
  },
}))

/**
 * Render LogsRoute at a given URL path (defaults to /logs with no params).
 * Always wrapped in MemoryRouter + RefreshProvider (#748) + EntityPanelProvider.
 */
function renderLogsRoute(initialUrl = '/logs') {
  return render(
    <MemoryRouter initialEntries={[initialUrl]}>
      <RefreshProvider>
        <EntityPanelProvider>
          <LogsRoute />
        </EntityPanelProvider>
      </RefreshProvider>
    </MemoryRouter>,
  )
}

/**
 * Render LogsRoute at /logs?ip=<addr> — tests the #203 deep-link path.
 */
function renderLogsRouteWithIp(ip: string) {
  return renderLogsRoute(`/logs?ip=${encodeURIComponent(ip)}`)
}

/**
 * Render LogsRoute at /logs?action=<val> — tests the #252 deep-link path.
 */
function renderLogsRouteWithAction(action: string) {
  return renderLogsRoute(`/logs?action=${encodeURIComponent(action)}`)
}

describe('LogsRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('calls fetchPaginatedLogs on mount with limit=25 and no cursor', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute()
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.limit).toBe(25)
    expect(call.cursor).toBeUndefined()
  })

  it('renders log rows when logs are returned', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute()
    await waitFor(() => expect(screen.getByTestId('logs-table')).toBeInTheDocument())
    expect(screen.getAllByTestId('log-row')).toHaveLength(PAGINATED_LOGS_PAGE1.logs.length)
  })

  it('shows empty state when no logs returned', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_EMPTY)
    renderLogsRoute()
    await waitFor(() => expect(screen.getByTestId('logs-empty')).toBeInTheDocument())
  })

  it('shows error state when API rejects', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchPaginatedLogs.mockRejectedValue(new ApiError(503, null))
    renderLogsRoute()
    await waitFor(() => expect(screen.getByTestId('logs-error')).toBeInTheDocument())
    expect(screen.getByRole('alert')).toHaveTextContent('503')
  })

  it('sends next_cursor from envelope when Next page is clicked', async () => {
    mockFetchPaginatedLogs.mockResolvedValueOnce(PAGINATED_LOGS_PAGE1)
    mockFetchPaginatedLogs.mockResolvedValueOnce(PAGINATED_LOGS_LAST_PAGE)
    renderLogsRoute()
    await waitFor(() =>
      expect(screen.getAllByTestId('pager-next').length).toBeGreaterThan(0),
    )
    fireEvent.click(screen.getAllByTestId('pager-next')[0])
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(2))
    const secondCall = mockFetchPaginatedLogs.mock.calls[1][0] as Record<string, unknown>
    expect(secondCall.cursor).toBe(PAGINATED_LOGS_PAGE1.next_cursor)
  })

  it('resets cursor when a server filter changes', async () => {
    mockFetchPaginatedLogs.mockResolvedValueOnce(PAGINATED_LOGS_PAGE1)
    mockFetchPaginatedLogs.mockResolvedValueOnce(PAGINATED_LOGS_LAST_PAGE)
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_EMPTY)
    renderLogsRoute()
    await waitFor(() =>
      expect(screen.getAllByTestId('pager-next').length).toBeGreaterThan(0),
    )
    fireEvent.click(screen.getAllByTestId('pager-next')[0])
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(2))

    // Change search (server-side filter) — should reset cursor and use ?q= param
    fireEvent.change(screen.getByTestId('filter-search'), { target: { value: 'injection' } })
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(3))
    const filterCall = mockFetchPaginatedLogs.mock.calls[2][0] as Record<string, unknown>
    expect(filterCall.cursor).toBeUndefined()
    expect(filterCall.q).toBe('injection')
  })

  it('shows loading state while data is in flight', () => {
    mockFetchPaginatedLogs.mockReturnValue(new Promise(() => {}))
    renderLogsRoute()
    expect(screen.getByTestId('logs-loading')).toBeInTheDocument()
  })

  it('opens entity slide-over panel when an IP is clicked (ADR-0037)', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute()
    await waitFor(() =>
      expect(screen.getAllByTestId('log-row-ip')[0]).toBeInTheDocument(),
    )
    fireEvent.click(screen.getAllByTestId('log-row-ip')[0])
    // Panel opens — data-testid is now "slide-over-panel" (SlideOver component, ADR-0037)
    expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Action filter — server-side (issue #252)
//
// Action is now a SERVER-SIDE filter: selecting an action value triggers a
// new fetch with ?action= rather than filtering the current page in the browser.
// ---------------------------------------------------------------------------

describe('LogsRoute — Action server-side filter (issue #252)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('DOES call fetchPaginatedLogs when Action combobox changes', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute()
    await waitFor(() => expect(screen.getByTestId('logs-table')).toBeInTheDocument())
    const initialCallCount = mockFetchPaginatedLogs.mock.calls.length

    // Open Action combobox and pick ALERT
    const actionInput = screen.getByTestId('filter-action-combo').querySelector('input')!
    fireEvent.focus(actionInput)
    const alertOption = screen.getByTestId('combobox-option-ALERT')
    fireEvent.mouseDown(alertOption)

    // fetchPaginatedLogs MUST be called again (server-side filter)
    await waitFor(() =>
      expect(mockFetchPaginatedLogs.mock.calls.length).toBeGreaterThan(initialCallCount),
    )
    const lastCall =
      mockFetchPaginatedLogs.mock.calls[mockFetchPaginatedLogs.mock.calls.length - 1][0] as Record<
        string,
        unknown
      >
    expect(lastCall.action).toBe('ALERT')
  })

  it('sends action=blocked to fetchPaginatedLogs when "blocked" option is selected', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute()
    await waitFor(() => expect(screen.getByTestId('logs-table')).toBeInTheDocument())

    const actionInput = screen.getByTestId('filter-action-combo').querySelector('input')!
    fireEvent.focus(actionInput)
    fireEvent.mouseDown(screen.getByTestId('combobox-option-blocked'))

    await waitFor(() => expect(mockFetchPaginatedLogs.mock.calls.length).toBeGreaterThan(1))
    const lastCall =
      mockFetchPaginatedLogs.mock.calls[mockFetchPaginatedLogs.mock.calls.length - 1][0] as Record<
        string,
        unknown
      >
    expect(lastCall.action).toBe('blocked')
  })

  it('shows action chip and clears it — triggers a new server fetch without action', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute()
    await waitFor(() => expect(screen.getByTestId('logs-table')).toBeInTheDocument())

    // Pick ALERT action filter (server-side)
    const actionInput = screen.getByTestId('filter-action-combo').querySelector('input')!
    fireEvent.focus(actionInput)
    fireEvent.mouseDown(screen.getByTestId('combobox-option-ALERT'))

    // Action chip should appear
    await waitFor(() => expect(screen.getByTestId('chip-action')).toBeInTheDocument())

    const callsBeforeRemove = mockFetchPaginatedLogs.mock.calls.length
    // Remove the Action chip
    const chip = screen.getByTestId('chip-action')
    fireEvent.click(chip.querySelector('[role="button"]')!)

    // A new fetch must fire without the action param
    await waitFor(() =>
      expect(mockFetchPaginatedLogs.mock.calls.length).toBeGreaterThan(callsBeforeRemove),
    )
    const lastCall =
      mockFetchPaginatedLogs.mock.calls[mockFetchPaginatedLogs.mock.calls.length - 1][0] as Record<
        string,
        unknown
      >
    expect(lastCall.action).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// #203 — ?ip= deep-link: param-on-mount + URL sync
// ---------------------------------------------------------------------------

describe('LogsRoute — ?ip= deep-link (issue #203)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('reads ?ip= on mount and passes it to fetchPaginatedLogs', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRouteWithIp('192.0.2.1')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.ip).toBe('192.0.2.1')
  })

  it('shows the IP filter chip when ?ip= is set on mount', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRouteWithIp('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('chip-ip')).toBeInTheDocument())
    expect(screen.getByTestId('chip-ip')).toHaveTextContent('192.0.2.1')
  })

  it('removes ?ip= from filter (and calls fetchPaginatedLogs without ip) when IP chip is cleared', async () => {
    mockFetchPaginatedLogs.mockResolvedValueOnce(PAGINATED_LOGS_PAGE1)
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_EMPTY)
    renderLogsRouteWithIp('192.0.2.1')
    // Wait for the initial filtered fetch
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    // IP chip is present — click the remove button
    const chip = screen.getByTestId('chip-ip')
    fireEvent.click(chip.querySelector('[role="button"]')!)
    // A second fetch must fire without the ip param
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(2))
    const secondCall = mockFetchPaginatedLogs.mock.calls[1][0] as Record<string, unknown>
    expect(secondCall.ip).toBeUndefined()
    // IP chip must be gone
    expect(screen.queryByTestId('chip-ip')).not.toBeInTheDocument()
  })

  it('ignores ?ip= gracefully when the value is not a plausible IP (no crash, no filter)', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    // "<script>alert(1)</script>" is clearly not an IP
    renderLogsRoute('/logs?ip=%3Cscript%3Ealert(1)%3C%2Fscript%3E')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    // ip must be absent from the filter — guard rejected the value
    expect(call.ip).toBeUndefined()
    // No IP chip must be shown
    expect(screen.queryByTestId('chip-ip')).not.toBeInTheDocument()
  })

  it('ignores ?ip= gracefully when the value is plain freeform text (not IP notation)', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute('/logs?ip=not-an-ip-at-all')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.ip).toBeUndefined()
  })

  it('accepts an IPv6 address in ?ip=', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRouteWithIp('2001:db8::1')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.ip).toBe('2001:db8::1')
  })
})

// ---------------------------------------------------------------------------
// #252 — ?action= deep-link: param-on-mount + URL sync
// ---------------------------------------------------------------------------

describe('LogsRoute — ?action= deep-link (issue #252)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('reads ?action=blocked on mount and passes it to fetchPaginatedLogs', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRouteWithAction('blocked')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.action).toBe('blocked')
  })

  it('shows the action filter chip when ?action=blocked is set on mount', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRouteWithAction('blocked')
    await waitFor(() => expect(screen.getByTestId('chip-action')).toBeInTheDocument())
    expect(screen.getByTestId('chip-action')).toHaveTextContent('Blocked (BLOCK + DROP)')
  })

  it('reads ?action=ALLOW on mount and passes it to fetchPaginatedLogs', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRouteWithAction('ALLOW')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.action).toBe('ALLOW')
  })

  it('clears action filter (fires new fetch without action) when action chip is removed', async () => {
    mockFetchPaginatedLogs.mockResolvedValueOnce(PAGINATED_LOGS_PAGE1)
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_EMPTY)
    renderLogsRouteWithAction('blocked')
    // Wait for the initial filtered fetch
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    // Action chip is present — click the remove button
    const chip = screen.getByTestId('chip-action')
    fireEvent.click(chip.querySelector('[role="button"]')!)
    // A second fetch must fire without the action param
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(2))
    const secondCall = mockFetchPaginatedLogs.mock.calls[1][0] as Record<string, unknown>
    expect(secondCall.action).toBeUndefined()
    // Action chip must be gone
    expect(screen.queryByTestId('chip-action')).not.toBeInTheDocument()
  })

  it('ignores ?action= when the value is unknown (no crash, no filter)', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    // "unknown_action" is not in the known vocabulary
    renderLogsRoute('/logs?action=unknown_action')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.action).toBeUndefined()
    expect(screen.queryByTestId('chip-action')).not.toBeInTheDocument()
  })

  it('ignores ?action= when the value is an XSS attempt (no crash, no filter)', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute('/logs?action=%3Cscript%3Ealert(1)%3C%2Fscript%3E')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.action).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// #565 — ?q= / ?signature= / ?payload= deep-link: param-on-mount
// ---------------------------------------------------------------------------

describe('LogsRoute — ?q= / ?signature= / ?payload= deep-link (issue #565)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // --- ?q= ---

  it('reads ?q= on mount and passes it to fetchPaginatedLogs as filter.q', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute('/logs?q=injection')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.q).toBe('injection')
  })

  it('shows the search chip when ?q= is set on mount', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute('/logs?q=SQLi')
    await waitFor(() => expect(screen.getByTestId('chip-search')).toBeInTheDocument())
    expect(screen.getByTestId('chip-search')).toHaveTextContent('SQLi')
  })

  it('seeds the search input value from ?q= on mount', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute('/logs?q=xss-probe')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const searchInput = screen.getByTestId('filter-search') as HTMLInputElement
    expect(searchInput.value).toBe('xss-probe')
  })

  // --- ?signature= ---

  it('reads ?signature= on mount and maps it to filter.q', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute('/logs?signature=ET%20MALWARE%20Metasploit')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.q).toBe('ET MALWARE Metasploit')
  })

  it('shows the search chip when ?signature= is set on mount', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute('/logs?signature=ET%20SCAN')
    await waitFor(() => expect(screen.getByTestId('chip-search')).toBeInTheDocument())
    expect(screen.getByTestId('chip-search')).toHaveTextContent('ET SCAN')
  })

  // --- ?payload= ---

  it('reads ?payload= on mount and maps it to filter.q', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute('/logs?payload=SELECT%20%2A%20FROM')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.q).toBe('SELECT * FROM')
  })

  it('shows the search chip when ?payload= is set on mount', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute('/logs?payload=cmd%3Dcat')
    await waitFor(() => expect(screen.getByTestId('chip-search')).toBeInTheDocument())
    expect(screen.getByTestId('chip-search')).toHaveTextContent('cmd=cat')
  })

  // --- multiple params ---

  it('applies ?q= and ?ip= together when both are present on mount', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute('/logs?q=SQLi&ip=192.0.2.1')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.q).toBe('SQLi')
    expect(call.ip).toBe('192.0.2.1')
  })

  it('applies ?signature= and ?action= together when both are present on mount', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute('/logs?signature=ET%20SCAN&action=ALERT')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.q).toBe('ET SCAN')
    expect(call.action).toBe('ALERT')
  })

  // --- guard: unrecognised params ignored ---

  it('ignores unrecognised URL params without error or crash', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute('/logs?totally_unknown=whatever&another=ignored')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.q).toBeUndefined()
    expect(call.ip).toBeUndefined()
    expect(call.action).toBeUndefined()
  })

  // --- guard: length limit on ?q= / ?signature= / ?payload= ---

  it('ignores ?q= values that exceed the maximum allowed length', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    const tooLong = 'a'.repeat(500)
    renderLogsRoute(`/logs?q=${encodeURIComponent(tooLong)}`)
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.q).toBeUndefined()
  })

  // --- ?q= priority: ?signature= / ?payload= are only used when ?q= is absent ---

  it('prefers explicit ?q= over ?signature= when both are present', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    renderLogsRoute('/logs?q=explicit&signature=from-sig')
    await waitFor(() => expect(mockFetchPaginatedLogs).toHaveBeenCalledTimes(1))
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.q).toBe('explicit')
  })
})
