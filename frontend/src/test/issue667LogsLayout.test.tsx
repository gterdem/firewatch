/**
 * Tests for issue #667 — /logs layout reorder + filter scopes the surround +
 * Top-Pairs view-all + deep-link anchor-scroll.
 *
 * EARS acceptance criteria covered:
 *
 * EARS-1: The /logs page SHALL render sections top→bottom:
 *   strip-tiles → filter → top-pairs → ERG → table.
 *   → test_page_order_strip_then_filter_then_pairs_then_erg_then_table
 *
 * EARS-2: WHEN the active filter changes, top-pairs AND ERG SHALL re-query
 *   with the SAME LogsFilter facets the table uses.
 *   → test_surround_requeries_on_filter_change_pairs
 *   → test_surround_requeries_on_filter_change_graph
 *   → test_surround_initial_fetch_includes_filter_facets
 *
 * EARS-3: WHEN opened via a deep-link param (?ip= / ?action= / ?signature= / ?q=),
 *   the viewport SHALL anchor-scroll to the table section.
 *   → test_deeplink_ip_triggers_scroll
 *   → test_deeplink_action_triggers_scroll
 *   → test_deeplink_q_triggers_scroll
 *   → test_clean_entry_does_not_scroll
 *
 * EARS-4: Top-Pairs SHALL show top 5 by default with "View all" that reveals
 *   the rest WITHOUT a nested scrollbar.
 *   → test_top_pairs_shows_top_5_by_default
 *   → test_top_pairs_view_all_reveals_rest
 *   → test_top_pairs_view_all_hides_again
 *   → test_top_pairs_no_view_all_when_5_or_fewer
 *
 * EARS-5: WHEN any surround fetch fails, that panel SHALL degrade to its empty
 *   state; the table SHALL still load.
 *   → test_pairs_fetch_failure_degrades_gracefully
 *   → test_graph_fetch_failure_degrades_gracefully
 *   → test_table_loads_even_when_surround_fails
 *
 * EARS-6: Existing deep-link guards (#203/#252/#565) SHALL remain intact.
 *   → test_deeplink_guards_still_filter_correctly
 *
 * NOTE: LogsRoute uses useSearchParams() — all renders wrapped in MemoryRouter.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import TopPairsPanel from '../components/logs/TopPairsPanel'
import LogsRoute from '../routes/LogsRoute'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
// #748: LogsRoute now requires RefreshProvider (useRefreshSignal)
import { RefreshProvider } from '../app/refresh/RefreshContext'
import { PAGINATED_LOGS_EMPTY } from './readFixtures'
import type { TopPairsRow } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures (RFC 5737 doc IPs only — never real/routable)
// ---------------------------------------------------------------------------

/** 8 pairs: top-5 + 3 extra (used to test "View all") */
const PAIRS_8: TopPairsRow[] = [
  { source_ip: '192.0.2.1', destination_ip: '198.51.100.1', count: 800 },
  { source_ip: '192.0.2.2', destination_ip: '198.51.100.2', count: 700 },
  { source_ip: '192.0.2.3', destination_ip: '198.51.100.3', count: 600 },
  { source_ip: '192.0.2.4', destination_ip: '198.51.100.4', count: 500 },
  { source_ip: '192.0.2.5', destination_ip: '198.51.100.5', count: 400 },
  { source_ip: '192.0.2.6', destination_ip: '198.51.100.6', count: 300 },
  { source_ip: '192.0.2.7', destination_ip: '198.51.100.7', count: 200 },
  { source_ip: '192.0.2.8', destination_ip: '198.51.100.8', count: 100 },
]

const PAIRS_3: TopPairsRow[] = [
  { source_ip: '192.0.2.1', destination_ip: '198.51.100.1', count: 300 },
  { source_ip: '192.0.2.2', destination_ip: '198.51.100.2', count: 200 },
  { source_ip: '192.0.2.3', destination_ip: '198.51.100.3', count: 100 },
]

// ---------------------------------------------------------------------------
// Mock setup
// ---------------------------------------------------------------------------

const {
  mockFetchTopPairs,
  mockFetchEntityGraph,
  mockFetchPaginatedLogs,
  mockFetchLogsStats,
} = vi.hoisted(() => ({
  mockFetchTopPairs: vi.fn(),
  mockFetchEntityGraph: vi.fn(),
  mockFetchPaginatedLogs: vi.fn(),
  mockFetchLogsStats: vi.fn(),
}))

vi.mock('../api/logs', () => ({
  fetchPaginatedLogs: mockFetchPaginatedLogs,
  fetchTopPairs: mockFetchTopPairs,
  fetchEntityGraph: mockFetchEntityGraph,
  fetchLogsStats: mockFetchLogsStats,
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
  fetchTopTalkers: vi.fn().mockResolvedValue([]),
  fetchProtocolMix: vi.fn().mockResolvedValue([]),
}))

vi.mock('../api/client', () => ({
  fetchThreats: vi.fn().mockResolvedValue([]),
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'ok',
    ollama_connected: false,
    ollama_model: null,
    db_ok: true,
  }),
  fetchTimeline: vi.fn().mockResolvedValue([]),
  // #748: RefreshProvider (now required by LogsRoute) calls fetchStats.
  fetchStats: vi.fn().mockResolvedValue({
    total_logs: 0,
    total_ips: 0,
    blocked_percentage: 0,
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
  resolveBaseUrl: vi.fn(() => ''),
  assertLoopbackBase: vi.fn(),
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderLogsRoute(url = '/logs') {
  return render(
    <MemoryRouter initialEntries={[url]}>
      <RefreshProvider>
        <EntityPanelProvider>
          <LogsRoute />
        </EntityPanelProvider>
      </RefreshProvider>
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// Default mock values per test
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
  mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_EMPTY)
  mockFetchLogsStats.mockResolvedValue({
    total_events: 0,
    blocked_events: 0,
    distinct_ips: 0,
    present_source_types: [],
  })
  mockFetchTopPairs.mockResolvedValue([])
  mockFetchEntityGraph.mockResolvedValue(null)
})

afterEach(() => {
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// EARS-1: Page order
// ---------------------------------------------------------------------------

describe('#667 EARS-1 — page order: strip → filter → pairs → ERG → table', () => {
  it('renders strip-tiles, facet-filters, top-pairs-panel, entity-graph, and table section in document order', async () => {
    renderLogsRoute()
    await waitFor(() => {
      expect(screen.getByTestId('strip-tiles')).toBeInTheDocument()
    })

    const stripTiles = screen.getByTestId('strip-tiles')
    const filterBar = document.querySelector('[data-testid="facet-filters"]') ??
      document.querySelector('input[data-testid="filter-search"]')?.closest('form') ??
      // FacetFilters renders a filter-search input; use it as a proxy
      screen.getByTestId('filter-search').closest('div')
    const topPairsPanel = screen.getByTestId('top-pairs-panel')
    // ERG is either the panel or the empty state
    const ergEl =
      document.querySelector('[data-testid="entity-graph-panel"]') ??
      document.querySelector('[data-testid="entity-graph-empty"]')
    const tableSection = screen.getByTestId('logs-table-section')

    // All must be present
    expect(stripTiles).toBeInTheDocument()
    expect(filterBar).not.toBeNull()
    expect(topPairsPanel).toBeInTheDocument()
    expect(ergEl).not.toBeNull()
    expect(tableSection).toBeInTheDocument()

    // Document order (compareDocumentPosition bit 4 = preceding)
    if (filterBar) {
      expect(stripTiles.compareDocumentPosition(filterBar as Node) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    }
    expect(topPairsPanel.compareDocumentPosition(tableSection) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    if (ergEl) {
      expect(topPairsPanel.compareDocumentPosition(ergEl as Node) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
      expect((ergEl as Node).compareDocumentPosition(tableSection) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    }
  })
})

// ---------------------------------------------------------------------------
// EARS-2: useLogsSurround re-queries on filter change
// ---------------------------------------------------------------------------

describe('#667 EARS-2 — surround re-queries on filter change', () => {
  it('fetchTopPairs is called with the initial filter on mount', async () => {
    renderLogsRoute('/logs?ip=192.0.2.1')
    await waitFor(() => {
      expect(mockFetchTopPairs).toHaveBeenCalled()
    })
    const firstCall = mockFetchTopPairs.mock.calls[0]
    // Second arg is the filter
    const passedFilter = firstCall[1] as Record<string, unknown>
    expect(passedFilter.ip).toBe('192.0.2.1')
  })

  it('fetchEntityGraph is called with the initial filter on mount', async () => {
    renderLogsRoute('/logs?ip=192.0.2.1')
    await waitFor(() => {
      expect(mockFetchEntityGraph).toHaveBeenCalled()
    })
    // fetchEntityGraph(maxNodes, maxEdges, filter)
    const firstCall = mockFetchEntityGraph.mock.calls[0]
    const passedFilter = firstCall[2] as Record<string, unknown>
    expect(passedFilter.ip).toBe('192.0.2.1')
  })

  it('fetchTopPairs re-queries when filter changes (action applied)', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_EMPTY)
    renderLogsRoute()

    await waitFor(() => {
      expect(screen.getByTestId('filter-action-combo')).toBeInTheDocument()
    })

    const initialPairsCalls = mockFetchTopPairs.mock.calls.length

    // Apply action filter
    const actionInput = screen.getByTestId('filter-action-combo').querySelector('input')!
    fireEvent.focus(actionInput)
    fireEvent.mouseDown(screen.getByTestId('combobox-option-ALERT'))

    await waitFor(() => {
      expect(mockFetchTopPairs.mock.calls.length).toBeGreaterThan(initialPairsCalls)
    })

    const lastCall = mockFetchTopPairs.mock.calls[mockFetchTopPairs.mock.calls.length - 1]
    const passedFilter = lastCall[1] as Record<string, unknown>
    expect(passedFilter.action).toBe('ALERT')
  })

  it('fetchEntityGraph re-queries when filter changes (action applied)', async () => {
    renderLogsRoute()

    await waitFor(() => {
      expect(screen.getByTestId('filter-action-combo')).toBeInTheDocument()
    })

    const initialGraphCalls = mockFetchEntityGraph.mock.calls.length

    const actionInput = screen.getByTestId('filter-action-combo').querySelector('input')!
    fireEvent.focus(actionInput)
    fireEvent.mouseDown(screen.getByTestId('combobox-option-BLOCK'))

    await waitFor(() => {
      expect(mockFetchEntityGraph.mock.calls.length).toBeGreaterThan(initialGraphCalls)
    })

    const lastCall = mockFetchEntityGraph.mock.calls[mockFetchEntityGraph.mock.calls.length - 1]
    const passedFilter = lastCall[2] as Record<string, unknown>
    expect(passedFilter.action).toBe('BLOCK')
  })
})

// ---------------------------------------------------------------------------
// EARS-3: Deep-link anchor-scroll
// ---------------------------------------------------------------------------

describe('#667 EARS-3 — deep-link anchor-scroll', () => {
  it('calls scrollIntoView on the table section when ?ip= is set', async () => {
    const scrollMock = vi.fn()
    // scrollIntoView is not implemented in jsdom; spy on it
    window.HTMLElement.prototype.scrollIntoView = scrollMock

    renderLogsRoute('/logs?ip=192.0.2.1')

    // Wait for load to complete
    await waitFor(() => {
      expect(mockFetchPaginatedLogs).toHaveBeenCalled()
    })
    // loading transitions to false after fetch settles
    await waitFor(() => {
      expect(screen.queryByTestId('logs-loading')).not.toBeInTheDocument()
    })

    await waitFor(() => {
      expect(scrollMock).toHaveBeenCalled()
    })
  })

  it('calls scrollIntoView when ?action= is set', async () => {
    const scrollMock = vi.fn()
    window.HTMLElement.prototype.scrollIntoView = scrollMock

    renderLogsRoute('/logs?action=blocked')

    await waitFor(() => {
      expect(screen.queryByTestId('logs-loading')).not.toBeInTheDocument()
    })

    await waitFor(() => {
      expect(scrollMock).toHaveBeenCalled()
    })
  })

  it('calls scrollIntoView when ?q= is set', async () => {
    const scrollMock = vi.fn()
    window.HTMLElement.prototype.scrollIntoView = scrollMock

    renderLogsRoute('/logs?q=injection')

    await waitFor(() => {
      expect(screen.queryByTestId('logs-loading')).not.toBeInTheDocument()
    })

    await waitFor(() => {
      expect(scrollMock).toHaveBeenCalled()
    })
  })

  it('does NOT call scrollIntoView on clean entry (no params)', async () => {
    const scrollMock = vi.fn()
    window.HTMLElement.prototype.scrollIntoView = scrollMock

    renderLogsRoute('/logs')

    await waitFor(() => {
      expect(screen.queryByTestId('logs-loading')).not.toBeInTheDocument()
    })

    // Give any pending microtasks a chance to settle
    await new Promise((r) => setTimeout(r, 50))

    expect(scrollMock).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// EARS-4: Top-Pairs view-all affordance (unit-level TopPairsPanel tests)
// ---------------------------------------------------------------------------

describe('#667 EARS-4 — TopPairsPanel top-5 + view-all', () => {
  it('shows exactly 5 rows by default when more than 5 pairs are provided', () => {
    render(<TopPairsPanel pairs={PAIRS_8} onSelectPair={vi.fn()} />)
    // Without expanding, only 5 top-pairs-row elements visible
    const rows = screen.getAllByTestId('top-pairs-row')
    expect(rows).toHaveLength(5)
  })

  it('shows "View all" button when more than 5 pairs exist', () => {
    render(<TopPairsPanel pairs={PAIRS_8} onSelectPair={vi.fn()} />)
    expect(screen.getByTestId('top-pairs-view-all-btn')).toBeInTheDocument()
    expect(screen.getByTestId('top-pairs-view-all-btn').textContent).toContain('View all 8')
  })

  it('clicking "View all" reveals the remaining pairs', () => {
    render(<TopPairsPanel pairs={PAIRS_8} onSelectPair={vi.fn()} />)

    // Before expand: 5 rows
    expect(screen.getAllByTestId('top-pairs-row')).toHaveLength(5)

    fireEvent.click(screen.getByTestId('top-pairs-view-all-btn'))

    // After expand: all 8 rows
    expect(screen.getAllByTestId('top-pairs-row')).toHaveLength(8)
    expect(screen.getByTestId('top-pairs-expanded')).toBeInTheDocument()
  })

  it('clicking "Show less" after expand collapses back to 5', () => {
    render(<TopPairsPanel pairs={PAIRS_8} onSelectPair={vi.fn()} />)

    fireEvent.click(screen.getByTestId('top-pairs-view-all-btn'))
    expect(screen.getAllByTestId('top-pairs-row')).toHaveLength(8)

    // Button text changes to "Show less"
    expect(screen.getByTestId('top-pairs-view-all-btn').textContent).toContain('Show less')

    fireEvent.click(screen.getByTestId('top-pairs-view-all-btn'))
    expect(screen.getAllByTestId('top-pairs-row')).toHaveLength(5)
    expect(screen.queryByTestId('top-pairs-expanded')).not.toBeInTheDocument()
  })

  it('does NOT show "View all" when there are 5 or fewer pairs', () => {
    render(<TopPairsPanel pairs={PAIRS_3} onSelectPair={vi.fn()} />)
    expect(screen.queryByTestId('top-pairs-view-all-btn')).not.toBeInTheDocument()
    // All 3 pairs visible
    expect(screen.getAllByTestId('top-pairs-row')).toHaveLength(3)
  })

  it('does NOT show "View all" when there are exactly 5 pairs', () => {
    const exactly5 = PAIRS_8.slice(0, 5)
    render(<TopPairsPanel pairs={exactly5} onSelectPair={vi.fn()} />)
    expect(screen.queryByTestId('top-pairs-view-all-btn')).not.toBeInTheDocument()
    expect(screen.getAllByTestId('top-pairs-row')).toHaveLength(5)
  })

  it('clicking a row in the expanded section calls onSelectPair', () => {
    const onSelect = vi.fn()
    render(<TopPairsPanel pairs={PAIRS_8} onSelectPair={onSelect} />)
    fireEvent.click(screen.getByTestId('top-pairs-view-all-btn'))

    // The expanded section contains rows 6-8 (indices 5-7 of PAIRS_8)
    const expanded = screen.getByTestId('top-pairs-expanded')
    const expandedRows = within(expanded).getAllByTestId('top-pairs-row')
    // First expanded row is PAIRS_8[5]: 192.0.2.6 → 198.51.100.6
    fireEvent.click(expandedRows[0])
    expect(onSelect).toHaveBeenCalledWith('192.0.2.6', '198.51.100.6')
  })
})

// ---------------------------------------------------------------------------
// EARS-5: Surround fetch failure degrades gracefully
// ---------------------------------------------------------------------------

describe('#667 EARS-5 — surround fetch failure degrades gracefully', () => {
  it('shows empty pairs state when fetchTopPairs rejects', async () => {
    mockFetchTopPairs.mockRejectedValue(new Error('network'))
    renderLogsRoute()
    await waitFor(() => {
      expect(screen.getByTestId('top-pairs-empty')).toBeInTheDocument()
    })
  })

  it('shows ERG empty state when fetchEntityGraph rejects', async () => {
    mockFetchEntityGraph.mockRejectedValue(new Error('network'))
    renderLogsRoute()
    await waitFor(() => {
      expect(screen.getByTestId('entity-graph-empty')).toBeInTheDocument()
    })
  })

  it('table still loads even when surround fetches fail', async () => {
    mockFetchTopPairs.mockRejectedValue(new Error('pairs fail'))
    mockFetchEntityGraph.mockRejectedValue(new Error('graph fail'))
    renderLogsRoute()
    // Table section still appears (even if empty state)
    await waitFor(() => {
      expect(screen.getByTestId('logs-table-section')).toBeInTheDocument()
    })
    // No logs-error banner (table fetch succeeded)
    await waitFor(() => {
      expect(screen.queryByTestId('logs-error')).not.toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// EARS-6: Existing deep-link guards remain intact (#203/#252/#565)
// ---------------------------------------------------------------------------

describe('#667 EARS-6 — existing deep-link guards intact', () => {
  it('?ip= filter is applied to fetchPaginatedLogs (guard still works)', async () => {
    renderLogsRoute('/logs?ip=192.0.2.99')
    await waitFor(() => {
      expect(mockFetchPaginatedLogs).toHaveBeenCalled()
    })
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.ip).toBe('192.0.2.99')
  })

  it('invalid ?ip= is still ignored (guard not regressed)', async () => {
    renderLogsRoute('/logs?ip=%3Cscript%3Ealert(1)%3C%2Fscript%3E')
    await waitFor(() => {
      expect(mockFetchPaginatedLogs).toHaveBeenCalled()
    })
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.ip).toBeUndefined()
  })

  it('?action=ALLOW is still passed to fetchPaginatedLogs', async () => {
    renderLogsRoute('/logs?action=ALLOW')
    await waitFor(() => {
      expect(mockFetchPaginatedLogs).toHaveBeenCalled()
    })
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.action).toBe('ALLOW')
  })

  it('?q= is still passed to fetchPaginatedLogs as filter.q', async () => {
    renderLogsRoute('/logs?q=SQLi')
    await waitFor(() => {
      expect(mockFetchPaginatedLogs).toHaveBeenCalled()
    })
    const call = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(call.q).toBe('SQLi')
  })
})
