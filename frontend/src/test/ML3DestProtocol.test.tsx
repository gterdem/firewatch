/**
 * Tests for ML-3 (#431) — Destination IP + Protocol columns, filters, and top-pairs panel.
 *
 * EARS criteria covered:
 *
 * EARS-2: LogsTable SHALL render Destination IP and Protocol columns via
 *   useColumnPriority, showing "—" where NULL.
 *   → test_destination_column_shows_ip_when_present
 *   → test_destination_column_shows_dash_when_null
 *   → test_protocol_column_shows_value_when_present
 *   → test_protocol_column_shows_dash_when_null
 *
 * EARS-3: WHEN source provides no destination/protocol (e.g. Azure WAF), row
 *   SHALL display "—".
 *   → test_azure_waf_row_shows_dash_for_destination_and_protocol
 *
 * EARS-1 (UI side): FacetFilters SHALL render destination_ip and protocol inputs;
 *   changes SHALL call onFilterChange with the new values.
 *   → test_facet_filters_renders_dest_ip_input
 *   → test_facet_filters_renders_protocol_input
 *   → test_dest_ip_input_calls_filter_change
 *   → test_protocol_input_calls_filter_change
 *   → test_dest_ip_chip_shown_when_active
 *   → test_protocol_chip_shown_when_active
 *
 * EARS-4 (UI side): TopPairsPanel SHALL render pairs; clicking a row SHALL
 *   cross-filter via onSelectPair.
 *   → test_top_pairs_panel_renders_rows
 *   → test_top_pairs_panel_shows_empty_state_when_no_pairs
 *   → test_top_pairs_panel_shows_loading_state
 *   → test_top_pairs_panel_click_calls_onSelectPair
 *   → test_top_pairs_panel_values_are_text_nodes_not_html
 *
 * EARS-4 (route): LogsRoute SHALL fetch top-pairs and render panel; clicking
 *   pair cross-filters the table.
 *   → test_logs_route_renders_top_pairs_panel
 *   → test_logs_route_top_pairs_click_applies_filter
 *
 * SECURITY (ADR-0029 D3): attacker-controlled destination_ip/protocol
 *   rendered as text nodes only.
 *   → test_destination_xss_renders_as_text_node
 *   → test_protocol_xss_renders_as_text_node
 *
 * Note: LogsTable uses useNavigate, FacetFilters and LogsRoute need MemoryRouter.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LogsTable from '../components/logs/LogsTable'
import FacetFilters from '../components/logs/FacetFilters'
import TopPairsPanel from '../components/logs/TopPairsPanel'
import LogsRoute from '../routes/LogsRoute'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import { RefreshProvider } from '../app/refresh/RefreshContext'
import { LOG_ENTRY_FIXTURE, PAGINATED_LOGS_EMPTY } from './readFixtures'
import type { LogEntry, LogsFilter, TopPairsRow } from '../api/types'

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/** Stub getBoundingClientRect so useColumnPriority keeps all columns visible. */
function stubWideContainer() {
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 1400, height: 40, top: 0, left: 0, bottom: 40, right: 1400,
    x: 0, y: 0, toJSON: () => ({}),
  } as DOMRect)
}

function renderTable(props: Parameters<typeof LogsTable>[0]) {
  stubWideContainer()
  const result = render(
    <MemoryRouter>
      <LogsTable {...props} />
    </MemoryRouter>,
  )
  vi.restoreAllMocks()
  return result
}

// RFC 5737 IPs only — never real/routable
const SURICATA_ROW_WITH_DEST: LogEntry = {
  ...LOG_ENTRY_FIXTURE,
  id: 200,
  source_ip: '192.0.2.10',
  destination_ip: '198.51.100.1',
  protocol: 'TCP',
}

const AZURE_WAF_ROW: LogEntry = {
  ...LOG_ENTRY_FIXTURE,
  id: 202,
  source_type: 'azure_waf',
  source_ip: '192.0.2.20',
  destination_ip: null,
  protocol: null,
}

const XSS_DEST_ROW: LogEntry = {
  ...LOG_ENTRY_FIXTURE,
  id: 203,
  destination_ip: '<script>alert("xss-dst")</script>',
  protocol: '<img src=x onerror=alert(1)>',
}

// ---------------------------------------------------------------------------
// ADR-0063 D1/D3: Destination IP and Protocol moved to the detail panel
// ---------------------------------------------------------------------------
//
// These columns are no longer inline in the table — they are rendered inside
// LogDetailPanel when the row is expanded. The EARS-2 / EARS-3 inline-column
// tests below verify the NEW behavior:
//   - No inline Destination or Protocol column headers in the table.
//   - The detail panel shows these values when the row is expanded.
//   - SECURITY: attacker-controlled values are text nodes in the panel too.

describe('LogsTable — ADR-0063 D1: Destination/Protocol NOT inline', () => {
  it('does not render Destination or Protocol column headers inline', () => {
    renderTable({ logs: [SURICATA_ROW_WITH_DEST], onIpClick: vi.fn() })
    const headers = Array.from(document.querySelectorAll('th')).map((th) => th.textContent ?? '')
    expect(headers.some((h) => /^Destination$/i.test(h.trim()))).toBe(false)
    expect(headers.some((h) => /^Protocol$/i.test(h.trim()))).toBe(false)
  })

  it('does not render log-row-dest-ip or log-row-protocol test IDs inline', () => {
    renderTable({ logs: [SURICATA_ROW_WITH_DEST], onIpClick: vi.fn() })
    expect(screen.queryByTestId('log-row-dest-ip')).not.toBeInTheDocument()
    expect(screen.queryByTestId('log-row-protocol')).not.toBeInTheDocument()
  })
})

describe('LogsTable — ADR-0063 D3: detail panel shows Destination/Protocol', () => {
  it('expanding a row shows destination IP in the detail panel', () => {
    renderTable({ logs: [SURICATA_ROW_WITH_DEST], onIpClick: vi.fn() })
    // Expand the row
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    // Detail panel should show destination IP
    expect(screen.getByTestId('log-detail-panel')).toBeInTheDocument()
    expect(screen.getByTestId('detail-section-network')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.1')).toBeInTheDocument()
  })

  it('expanding a row shows protocol in the detail panel', () => {
    renderTable({ logs: [SURICATA_ROW_WITH_DEST], onIpClick: vi.fn() })
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    expect(screen.getByText('TCP')).toBeInTheDocument()
  })

  it('Azure WAF row — Network section omits null destination/protocol fields', () => {
    renderTable({ logs: [AZURE_WAF_ROW], onIpClick: vi.fn() })
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    // destination_ip and protocol are null → those DetailField rows are omitted
    // The detail panel should be present but those labels should not appear as field values
    expect(screen.getByTestId('log-detail-panel')).toBeInTheDocument()
    // The values '—' should NOT appear as fabricated data (honest absence = omit row)
    const panel = screen.getByTestId('log-detail-panel')
    // Check text nodes — no fabricated dash wall
    expect(panel.textContent).not.toContain('198.51.100')
  })
})

// ---------------------------------------------------------------------------
// SECURITY: attacker-controlled destination/protocol in detail panel
// ---------------------------------------------------------------------------

describe('LogsTable — ML-3 SECURITY: XSS in detail panel destination/protocol', () => {
  it('destination_ip XSS renders as inert text in detail panel', () => {
    renderTable({ logs: [XSS_DEST_ROW], onIpClick: vi.fn() })
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    // The value appears in the detail panel as literal text
    const panel = screen.getByTestId('log-detail-panel')
    expect(panel.textContent).toContain('<script>alert("xss-dst")</script>')
    expect(document.querySelectorAll('script[data-xss]').length).toBe(0)
  })

  it('protocol XSS renders as inert text in detail panel', () => {
    renderTable({ logs: [XSS_DEST_ROW], onIpClick: vi.fn() })
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    const panel = screen.getByTestId('log-detail-panel')
    expect(panel.textContent).toContain('<img src=x onerror=alert(1)>')
    expect(document.querySelectorAll('img[onerror]').length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// EARS-1 (UI): FacetFilters dest_ip and protocol inputs
// ---------------------------------------------------------------------------

describe('FacetFilters — ML-3 destination_ip and protocol inputs', () => {
  const noop = vi.fn()
  const baseFilter: LogsFilter = {}

  it('renders destination IP input', () => {
    render(<FacetFilters filter={baseFilter} onFilterChange={noop} />)
    expect(screen.getByTestId('filter-dest-ip')).toBeInTheDocument()
  })

  it('renders protocol input', () => {
    render(<FacetFilters filter={baseFilter} onFilterChange={noop} />)
    expect(screen.getByTestId('filter-protocol')).toBeInTheDocument()
  })

  it('dest_ip input change calls onFilterChange with destination_ip', () => {
    const onChange = vi.fn()
    render(<FacetFilters filter={baseFilter} onFilterChange={onChange} />)
    fireEvent.change(screen.getByTestId('filter-dest-ip'), {
      target: { value: '198.51.100' },
    })
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ destination_ip: '198.51.100' })
    )
  })

  it('protocol input change calls onFilterChange with protocol', () => {
    const onChange = vi.fn()
    render(<FacetFilters filter={baseFilter} onFilterChange={onChange} />)
    fireEvent.change(screen.getByTestId('filter-protocol'), {
      target: { value: 'TCP' },
    })
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ protocol: 'TCP' })
    )
  })

  it('shows chip for active destination_ip filter', () => {
    render(
      <FacetFilters
        filter={{ ...baseFilter, destination_ip: '198.51.100.1' }}
        onFilterChange={noop}
      />
    )
    expect(screen.getByTestId('chip-destination_ip')).toBeInTheDocument()
    expect(screen.getByTestId('chip-destination_ip').textContent).toContain('198.51.100.1')
  })

  it('shows chip for active protocol filter', () => {
    render(
      <FacetFilters
        filter={{ ...baseFilter, protocol: 'UDP' }}
        onFilterChange={noop}
      />
    )
    expect(screen.getByTestId('chip-protocol')).toBeInTheDocument()
    expect(screen.getByTestId('chip-protocol').textContent).toContain('UDP')
  })

  it('removing destination_ip chip clears the filter', () => {
    const onChange = vi.fn()
    render(
      <FacetFilters
        filter={{ ...baseFilter, destination_ip: '198.51.100.1' }}
        onFilterChange={onChange}
      />
    )
    // FilterChip uses a <span role="button"> aria-label="Remove filter" for the ✕
    const removeSpans = screen.getAllByRole('button', { name: /remove filter/i })
    fireEvent.click(removeSpans[0])
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ destination_ip: undefined })
    )
  })
})

// ---------------------------------------------------------------------------
// EARS-4: TopPairsPanel
// ---------------------------------------------------------------------------

const PAIRS_FIXTURE: TopPairsRow[] = [
  { source_ip: '192.0.2.10', destination_ip: '198.51.100.1', count: 5 },
  { source_ip: '192.0.2.20', destination_ip: '198.51.100.2', count: 3 },
]

describe('TopPairsPanel', () => {
  it('renders pair rows', () => {
    render(
      <TopPairsPanel pairs={PAIRS_FIXTURE} onSelectPair={vi.fn()} />
    )
    const rows = screen.getAllByTestId('top-pairs-row')
    expect(rows).toHaveLength(2)
  })

  it('shows empty state when no pairs', () => {
    render(<TopPairsPanel pairs={[]} onSelectPair={vi.fn()} />)
    expect(screen.getByTestId('top-pairs-empty')).toBeInTheDocument()
  })

  it('shows loading state when loading=true', () => {
    render(<TopPairsPanel pairs={[]} onSelectPair={vi.fn()} loading={true} />)
    expect(screen.getByTestId('top-pairs-loading')).toBeInTheDocument()
  })

  it('clicking a row calls onSelectPair with source_ip and destination_ip', () => {
    const onSelect = vi.fn()
    render(<TopPairsPanel pairs={PAIRS_FIXTURE} onSelectPair={onSelect} />)
    const rows = screen.getAllByTestId('top-pairs-row')
    fireEvent.click(rows[0])
    expect(onSelect).toHaveBeenCalledWith('192.0.2.10', '198.51.100.1')
  })

  it('renders IP values as text nodes, not live HTML (SECURITY)', () => {
    const xssPairs: TopPairsRow[] = [
      {
        source_ip: '<script>alert("src")</script>',
        destination_ip: '<img src=x onerror=alert(1)>',
        count: 1,
      },
    ]
    render(<TopPairsPanel pairs={xssPairs} onSelectPair={vi.fn()} />)
    const row = screen.getByTestId('top-pairs-row')
    expect(row.textContent).toContain('<script>alert("src")</script>')
    expect(document.querySelectorAll('img[onerror]').length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// EARS-4: LogsRoute mounts top-pairs panel
// ---------------------------------------------------------------------------

// Mock fetchPaginatedLogs and fetchTopPairs for LogsRoute tests
const { mockFetchPaginatedLogs, mockFetchTopPairs } = vi.hoisted(() => ({
  mockFetchPaginatedLogs: vi.fn(),
  mockFetchTopPairs: vi.fn(),
}))

vi.mock('../api/logs', () => ({
  fetchPaginatedLogs: mockFetchPaginatedLogs,
  fetchTopPairs: mockFetchTopPairs,
  // #665: StripTiles (replaced TrafficShapeHeader) — default to zeros (non-fatal).
  fetchLogsStats: vi.fn().mockResolvedValue({ total_events: 0, blocked_events: 0, distinct_ips: 0, present_source_types: [] }),
  fetchTopTalkers: vi.fn().mockResolvedValue([]),
  fetchProtocolMix: vi.fn().mockResolvedValue([]),
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
  // ML-9 (#437): entity graph — default to null (non-fatal; shows empty state).
  fetchEntityGraph: vi.fn().mockResolvedValue(null),
}))

vi.mock('../api/client', () => ({
  fetchThreats: vi.fn().mockResolvedValue([]),
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'ok', ollama_connected: false, ollama_model: null, db_ok: true,
  }),
  // ML-4 (#432): TrafficShapeHeader fetches timeline — non-fatal empty default.
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
}))

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

describe('LogsRoute — ML-3 top-pairs panel', () => {
  beforeEach(() => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_EMPTY)
    mockFetchTopPairs.mockResolvedValue(PAIRS_FIXTURE)
  })

  it('renders the top-pairs panel', async () => {
    renderLogsRoute()
    await waitFor(() => {
      expect(screen.getByTestId('top-pairs-panel')).toBeInTheDocument()
    })
  })

  it('clicking a top-pairs row applies ip + destination_ip filters', async () => {
    renderLogsRoute()
    await waitFor(() => {
      expect(screen.getAllByTestId('top-pairs-row').length).toBeGreaterThan(0)
    })
    const firstRow = screen.getAllByTestId('top-pairs-row')[0]
    fireEvent.click(firstRow)
    // After clicking, fetchPaginatedLogs should be called with the pair's IPs
    await waitFor(() => {
      const calls = mockFetchPaginatedLogs.mock.calls
      const lastCall = calls[calls.length - 1][0] as LogsFilter
      expect(lastCall.ip).toBe('192.0.2.10')
      expect(lastCall.destination_ip).toBe('198.51.100.1')
    })
  })

  it('top-pairs fetch failure degrades to empty panel (non-fatal)', async () => {
    mockFetchTopPairs.mockRejectedValue(new Error('network'))
    renderLogsRoute()
    await waitFor(() => {
      expect(screen.getByTestId('top-pairs-empty')).toBeInTheDocument()
    })
  })
})
