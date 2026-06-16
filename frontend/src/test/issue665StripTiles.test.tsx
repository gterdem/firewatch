/**
 * Tests for issue #665 — Network Logs header strip (StripTiles + Popover primitive).
 *
 * EARS criteria covered:
 *
 * EARS-1: WHEN /logs renders, the strip SHALL show 5 tiles in one horizontal row:
 *   Events, Blocked, Distinct IPs, Top Talker, Top Protocol.
 *   → test_strip_shows_5_tiles
 *
 * EARS-2: Events / Blocked / Distinct values SHALL come from GET /logs/stats (real totals).
 *   → test_stats_tiles_read_from_logs_stats
 *   → test_stats_tiles_NOT_a_top_n_sum (real vs summed totals differ)
 *
 * EARS-3: Top Talker ▾ popover SHALL list top 5; activating a row SHALL cross-filter by ip.
 *   → test_top_talker_popover_opens_on_trigger_click
 *   → test_top_talker_popover_lists_5_talkers
 *   → test_top_talker_row_click_cross_filters_by_ip
 *
 * EARS-4: Top Protocol ▾ popover SHALL list top 5; clickable rows cross-filter by protocol.
 *   → test_top_protocol_popover_opens_on_trigger_click
 *   → test_top_protocol_popover_lists_protocols
 *   → test_top_protocol_row_click_cross_filters_by_protocol
 *   → test_top_protocol_unknown_row_is_not_clickable (UT-10 / #508)
 *
 * EARS-5: Timeline SHALL NOT appear on /logs.
 *   → test_timeline_is_absent
 *
 * EARS-6: WHEN filter changes, tiles SHALL re-query with the same filter.
 *   → test_fetch_is_called_with_filter (WS4 plumbing verified at call level)
 *
 * Popover primitive:
 *   → test_popover_opens_closes_on_click
 *   → test_popover_closes_on_esc
 *   → test_popover_trigger_has_aria_expanded
 *
 * LogsRoute integration:
 *   → test_logs_route_renders_strip_tiles (TrafficShapeHeader gone)
 *   → test_logs_route_talker_click_cross_filters (ip= applied)
 *   → test_logs_route_protocol_click_cross_filters (protocol= applied)
 *   → test_logs_route_no_timeline_panel
 *
 * SECURITY (ADR-0029 D3):
 *   → test_xss_ip_rendered_as_text_node
 *   → test_xss_protocol_rendered_as_text_node
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import StripTiles from '../components/logs/StripTiles'
import LogsRoute from '../routes/LogsRoute'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import { RefreshProvider } from '../app/refresh/RefreshContext'
import { PAGINATED_LOGS_EMPTY } from './readFixtures'
import type { LogsStats, TopTalkerRow, ProtocolMixRow, LogsFilter } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures (RFC 5737 IPs only)
// ---------------------------------------------------------------------------

const STATS_FIXTURE: LogsStats = {
  total_events: 9_999,
  blocked_events: 1_234,
  distinct_ips: 42,
  present_source_types: ['azure_waf', 'suricata'],
}

const TALKER_FIXTURE: TopTalkerRow[] = [
  { source_ip: '192.0.2.10', count: 5000, blocked: 2000 },
  { source_ip: '192.0.2.20', count: 3000, blocked: 100 },
  { source_ip: '192.0.2.30', count: 1500, blocked: 500 },
  { source_ip: '192.0.2.40', count: 800, blocked: 0 },
  { source_ip: '192.0.2.50', count: 400, blocked: 10 },
]

const PROTOCOL_FIXTURE: ProtocolMixRow[] = [
  { protocol: 'TCP', count: 7000 },
  { protocol: 'UDP', count: 2000 },
  { protocol: '(unknown)', count: 999 },
  { protocol: 'ICMP', count: 100 },
  { protocol: 'TLS', count: 50 },
]

const XSS_TALKER: TopTalkerRow[] = [
  { source_ip: '<script>alert("xss")</script>', count: 99, blocked: 10 },
]

const XSS_PROTOCOL: ProtocolMixRow[] = [
  { protocol: '<img src=x onerror=alert(1)>', count: 5 },
]

// ---------------------------------------------------------------------------
// Mock setup
// ---------------------------------------------------------------------------

const {
  mockFetchLogsStats,
  mockFetchTopTalkers,
  mockFetchProtocolMix,
  mockFetchPaginatedLogs,
  mockFetchTopPairs,
} = vi.hoisted(() => ({
  mockFetchLogsStats: vi.fn(),
  mockFetchTopTalkers: vi.fn(),
  mockFetchProtocolMix: vi.fn(),
  mockFetchPaginatedLogs: vi.fn(),
  mockFetchTopPairs: vi.fn(),
}))

vi.mock('../api/client', () => ({
  fetchTimeline: vi.fn().mockResolvedValue([]),
  fetchThreats: vi.fn().mockResolvedValue([]),
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'ok', ollama_connected: false, ollama_model: null, db_ok: true,
  }),
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

vi.mock('../api/logs', () => ({
  fetchLogsStats: mockFetchLogsStats,
  fetchTopTalkers: mockFetchTopTalkers,
  fetchProtocolMix: mockFetchProtocolMix,
  fetchPaginatedLogs: mockFetchPaginatedLogs,
  fetchTopPairs: mockFetchTopPairs,
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
  fetchEntityGraph: vi.fn().mockResolvedValue(null),
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderStrip(onFilterChange = vi.fn(), filter: Partial<LogsFilter> = {}) {
  return render(<StripTiles filter={filter} onFilterChange={onFilterChange} />)
}

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
// Default mock setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  mockFetchLogsStats.mockResolvedValue(STATS_FIXTURE)
  mockFetchTopTalkers.mockResolvedValue(TALKER_FIXTURE)
  mockFetchProtocolMix.mockResolvedValue(PROTOCOL_FIXTURE)
  mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_EMPTY)
  mockFetchTopPairs.mockResolvedValue([])
})

// ---------------------------------------------------------------------------
// EARS-1: 5 tiles in one horizontal row
// ---------------------------------------------------------------------------

describe('StripTiles — EARS-1: 5 tiles present', () => {
  it('renders all 5 tile containers', async () => {
    renderStrip()
    await waitFor(() => {
      expect(screen.getByTestId('strip-tiles')).toBeInTheDocument()
    })
    expect(screen.getByTestId('strip-tile-events')).toBeInTheDocument()
    expect(screen.getByTestId('strip-tile-blocked')).toBeInTheDocument()
    expect(screen.getByTestId('strip-tile-distinct-ips')).toBeInTheDocument()
    expect(screen.getByTestId('strip-tile-top-talker')).toBeInTheDocument()
    expect(screen.getByTestId('strip-tile-top-protocol')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-2: Stats tiles from GET /logs/stats
// ---------------------------------------------------------------------------

describe('StripTiles — EARS-2: real totals from /logs/stats', () => {
  it('events tile shows total_events from /logs/stats', async () => {
    renderStrip()
    await waitFor(() => {
      const tile = screen.getByTestId('strip-tile-events')
      expect(tile.textContent).toContain('9,999')
    })
  })

  it('blocked tile shows blocked_events from /logs/stats', async () => {
    renderStrip()
    await waitFor(() => {
      const tile = screen.getByTestId('strip-tile-blocked')
      expect(tile.textContent).toContain('1,234')
    })
  })

  it('distinct IPs tile shows distinct_ips from /logs/stats', async () => {
    renderStrip()
    await waitFor(() => {
      const tile = screen.getByTestId('strip-tile-distinct-ips')
      expect(tile.textContent).toContain('42')
    })
  })

  it('shows loading dash before stats resolve', () => {
    // Never resolve
    mockFetchLogsStats.mockReturnValue(new Promise(() => {}))
    renderStrip()
    const tile = screen.getByTestId('strip-tile-events')
    expect(tile.textContent).toContain('—')
  })

  it('does NOT show top-talker sum as events total (real vs summed differ)', async () => {
    // top-talker sum = 5000+3000+1500+800+400 = 10700, real total = 9999
    renderStrip()
    await waitFor(() => {
      const tile = screen.getByTestId('strip-tile-events')
      expect(tile.textContent).toContain('9,999')
      expect(tile.textContent).not.toContain('10,700')
    })
  })
})

// ---------------------------------------------------------------------------
// EARS-3: Top Talker popover
// ---------------------------------------------------------------------------

describe('StripTiles — EARS-3: Top Talker popover', () => {
  it('opens popover when ▾ trigger is clicked', async () => {
    renderStrip()
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-talker-trigger')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('strip-top-talker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-talker-popover')).toBeInTheDocument()
    })
  })

  it('popover lists up to 5 talkers', async () => {
    renderStrip()
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-talker-trigger')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('strip-top-talker-trigger'))
    await waitFor(() => {
      const popover = screen.getByTestId('strip-top-talker-popover')
      expect(popover.textContent).toContain('192.0.2.10')
      expect(popover.textContent).toContain('192.0.2.20')
      expect(popover.textContent).toContain('192.0.2.30')
      expect(popover.textContent).toContain('192.0.2.40')
      expect(popover.textContent).toContain('192.0.2.50')
    })
  })

  it('clicking a talker row calls onFilterChange with ip patch', async () => {
    const onFilter = vi.fn()
    renderStrip(onFilter)
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-talker-trigger')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('strip-top-talker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('pivot-row-192.0.2.10')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('pivot-row-192.0.2.10'))
    expect(onFilter).toHaveBeenCalledWith({ ip: '192.0.2.10' })
  })

  it('keyboard Enter on a talker row calls onFilterChange', async () => {
    const onFilter = vi.fn()
    renderStrip(onFilter)
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-talker-trigger')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('strip-top-talker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('pivot-row-192.0.2.10')).toBeInTheDocument()
    })
    fireEvent.keyDown(screen.getByTestId('pivot-row-192.0.2.10'), { key: 'Enter' })
    expect(onFilter).toHaveBeenCalledWith({ ip: '192.0.2.10' })
  })
})

// ---------------------------------------------------------------------------
// EARS-4: Top Protocol popover
// ---------------------------------------------------------------------------

describe('StripTiles — EARS-4: Top Protocol popover', () => {
  it('opens popover when ▾ trigger is clicked', async () => {
    renderStrip()
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-protocol-trigger')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('strip-top-protocol-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-protocol-popover')).toBeInTheDocument()
    })
  })

  it('popover lists protocols', async () => {
    renderStrip()
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-protocol-trigger')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('strip-top-protocol-trigger'))
    await waitFor(() => {
      const popover = screen.getByTestId('strip-top-protocol-popover')
      expect(popover.textContent).toContain('TCP')
      expect(popover.textContent).toContain('UDP')
    })
  })

  it('clicking a protocol row calls onFilterChange with protocol patch', async () => {
    const onFilter = vi.fn()
    renderStrip(onFilter)
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-protocol-trigger')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('strip-top-protocol-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('pivot-row-TCP')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('pivot-row-TCP'))
    expect(onFilter).toHaveBeenCalledWith({ protocol: 'TCP' })
  })

  it('"Other" (unknown) protocol row is not clickable (UT-10 / #508)', async () => {
    renderStrip()
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-protocol-trigger')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('strip-top-protocol-trigger'))
    await waitFor(() => {
      const popover = screen.getByTestId('strip-top-protocol-popover')
      // "(unknown)" should appear as "Other"
      expect(popover.textContent).toContain('Other')
    })
    // The "(unknown)" row should NOT have a pivot-row testid (non-clickable)
    expect(screen.queryByTestId('pivot-row-(unknown)')).not.toBeInTheDocument()
    // No "Filter by Other" button either
    expect(screen.queryByRole('button', { name: 'Filter by Other' })).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-5: Timeline is absent
// ---------------------------------------------------------------------------

describe('StripTiles — EARS-5: timeline absent', () => {
  it('does not render a timeline panel or chart', async () => {
    renderStrip()
    await waitFor(() => {
      expect(screen.getByTestId('strip-tiles')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('traffic-timeline-panel')).not.toBeInTheDocument()
    expect(screen.queryByTestId('timeline-chart')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-6: fetchLogsStats is called with the active filter
// ---------------------------------------------------------------------------

describe('StripTiles — EARS-6: re-queries with filter', () => {
  it('calls fetchLogsStats with the provided filter', async () => {
    const filter: Partial<LogsFilter> = { ip: '192.0.2.10', action: 'block' }
    renderStrip(vi.fn(), filter)
    await waitFor(() => {
      expect(mockFetchLogsStats).toHaveBeenCalledWith(expect.objectContaining({ ip: '192.0.2.10', action: 'block' }))
    })
  })
})

// ---------------------------------------------------------------------------
// Degradation
// ---------------------------------------------------------------------------

describe('StripTiles — degradation', () => {
  it('shows dashes when /logs/stats fetch fails', async () => {
    mockFetchLogsStats.mockRejectedValue(new Error('network'))
    renderStrip()
    // Loading state shows dashes until resolved; after rejection they stay as dashes
    await waitFor(() => {
      expect(screen.getByTestId('strip-tile-events').textContent).toContain('—')
    })
  })

  it('does not crash when all fetches fail', () => {
    mockFetchLogsStats.mockRejectedValue(new Error('network'))
    mockFetchTopTalkers.mockRejectedValue(new Error('network'))
    mockFetchProtocolMix.mockRejectedValue(new Error('network'))
    expect(() => renderStrip()).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// SECURITY (ADR-0029 D3): XSS prevention
// ---------------------------------------------------------------------------

describe('StripTiles — SECURITY: XSS prevention', () => {
  it('renders XSS IP as inert text node in Top Talker tile', async () => {
    mockFetchTopTalkers.mockResolvedValue(XSS_TALKER)
    renderStrip()
    // Open the talker popover to see the IP
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-talker-trigger')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('strip-top-talker-trigger'))
    await waitFor(() => {
      const popover = screen.getByTestId('strip-top-talker-popover')
      expect(popover.textContent).toContain('<script>alert("xss")</script>')
    })
    expect(document.querySelectorAll('script[data-xss]').length).toBe(0)
  })

  it('renders XSS protocol as inert text node in Top Protocol popover', async () => {
    mockFetchProtocolMix.mockResolvedValue(XSS_PROTOCOL)
    renderStrip()
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-protocol-trigger')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('strip-top-protocol-trigger'))
    await waitFor(() => {
      const popover = screen.getByTestId('strip-top-protocol-popover')
      expect(popover.textContent).toContain('<img src=x onerror=alert(1)>')
    })
    expect(document.querySelectorAll('img[onerror]').length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Popover primitive — keyboard and ARIA
// ---------------------------------------------------------------------------

describe('Popover — keyboard accessibility', () => {
  it('trigger button has aria-expanded=false when closed', async () => {
    renderStrip()
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-talker-trigger')).toBeInTheDocument()
    })
    const trigger = screen.getByTestId('strip-top-talker-trigger')
    expect(trigger.getAttribute('aria-expanded')).toBe('false')
  })

  it('trigger button has aria-expanded=true after click', async () => {
    renderStrip()
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-talker-trigger')).toBeInTheDocument()
    })
    const trigger = screen.getByTestId('strip-top-talker-trigger')
    fireEvent.click(trigger)
    await waitFor(() => {
      expect(trigger.getAttribute('aria-expanded')).toBe('true')
    })
  })

  it('popover closes on Escape key', async () => {
    renderStrip()
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-talker-trigger')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('strip-top-talker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-talker-popover')).toBeInTheDocument()
    })
    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() => {
      expect(screen.queryByTestId('strip-top-talker-popover')).not.toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// LogsRoute integration
// ---------------------------------------------------------------------------

describe('LogsRoute — #665 StripTiles integration', () => {
  it('renders strip-tiles in LogsRoute (not TrafficShapeHeader)', async () => {
    renderLogsRoute()
    await waitFor(() => {
      expect(screen.getByTestId('strip-tiles')).toBeInTheDocument()
    })
    // Old TrafficShapeHeader testid must not appear
    expect(screen.queryByTestId('traffic-shape-header')).not.toBeInTheDocument()
  })

  it('no timeline panel in LogsRoute (EARS-5)', async () => {
    renderLogsRoute()
    await waitFor(() => {
      expect(screen.getByTestId('strip-tiles')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('traffic-timeline-panel')).not.toBeInTheDocument()
  })

  it('talker row click in LogsRoute cross-filters the page (ip= applied)', async () => {
    renderLogsRoute()
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-talker-trigger')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('strip-top-talker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('pivot-row-192.0.2.10')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('pivot-row-192.0.2.10'))
    await waitFor(() => {
      const calls = mockFetchPaginatedLogs.mock.calls
      const lastFilter = calls[calls.length - 1][0] as LogsFilter
      expect(lastFilter.ip).toBe('192.0.2.10')
    })
  })

  it('protocol row click in LogsRoute cross-filters the page (protocol= applied)', async () => {
    renderLogsRoute()
    await waitFor(() => {
      expect(screen.getByTestId('strip-top-protocol-trigger')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('strip-top-protocol-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('pivot-row-TCP')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByTestId('pivot-row-TCP'))
    await waitFor(() => {
      const calls = mockFetchPaginatedLogs.mock.calls
      const lastFilter = calls[calls.length - 1][0] as LogsFilter
      expect(lastFilter.protocol).toBe('TCP')
    })
  })
})
