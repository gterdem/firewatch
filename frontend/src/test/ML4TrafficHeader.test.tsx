/**
 * Tests for ML-4 (#432) — TrafficShapeHeader component.
 *
 * EARS criteria covered:
 *
 * EARS-1: The page SHALL render an events-over-time chart from GET /logs/timeline.
 *   → test_renders_timeline_panel_when_data_present
 *   → test_no_timeline_panel_when_timeline_empty
 *
 * EARS-2: GET /logs/top-talkers and GET /logs/protocol-mix SHALL return GROUP-BY counts.
 *   → test_renders_top_talkers_panel_when_data_present
 *   → test_renders_protocol_mix_panel_when_data_present
 *   → test_top_talkers_shows_ip_and_count
 *   → test_protocol_mix_shows_protocol_and_count
 *
 * EARS-3: WHEN the user clicks a header element, the system SHALL cross-filter the table.
 *   → test_clicking_talker_ip_calls_onFilterChange_with_ip
 *   → test_clicking_protocol_row_calls_onFilterChange_with_protocol
 *   → test_unknown_protocol_row_is_not_clickable
 *
 * EARS-4: A totals strip SHALL show events / blocked / distinct IPs.
 *   → test_totals_strip_shows_event_count
 *   → test_totals_strip_shows_blocked_count
 *   → test_totals_strip_shows_distinct_ips
 *
 * Degradation: empty data → header hides; fetch failures → no crash.
 *   → test_all_empty_renders_null
 *   → test_fetch_failure_renders_empty_state
 *
 * SECURITY (ADR-0029 D3):
 *   → test_ip_value_rendered_as_text_node
 *   → test_protocol_value_rendered_as_text_node
 *
 * LogsRoute integration: TrafficShapeHeader is mounted; click cross-filters table.
 *   → test_logs_route_renders_traffic_header
 *   → test_logs_route_traffic_talker_click_applies_ip_filter
 *   → test_logs_route_traffic_protocol_click_applies_protocol_filter
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import TrafficShapeHeader from '../components/logs/TrafficShapeHeader'
import { TIMELINE_FIXTURE } from './readFixtures'
import type { TopTalkerRow, ProtocolMixRow } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures (RFC 5737 IPs only)
// ---------------------------------------------------------------------------

const TALKER_FIXTURE: TopTalkerRow[] = [
  { source_ip: '192.0.2.10', count: 500, blocked: 200 },
  { source_ip: '192.0.2.20', count: 300, blocked: 100 },
  { source_ip: '192.0.2.30', count: 150, blocked: 50 },
]

const PROTOCOL_FIXTURE: ProtocolMixRow[] = [
  { protocol: 'TCP', count: 800 },
  { protocol: 'UDP', count: 200 },
  { protocol: '(unknown)', count: 150 },
]

const XSS_TALKER: TopTalkerRow = {
  source_ip: '<script>alert("xss")</script>',
  count: 99,
  blocked: 10,
}

const XSS_PROTOCOL: ProtocolMixRow = {
  protocol: '<img src=x onerror=alert(1)>',
  count: 5,
}

// ---------------------------------------------------------------------------
// Mock setup
// ---------------------------------------------------------------------------

const { mockFetchTimeline, mockFetchTopTalkers, mockFetchProtocolMix } = vi.hoisted(() => ({
  mockFetchTimeline: vi.fn(),
  mockFetchTopTalkers: vi.fn(),
  mockFetchProtocolMix: vi.fn(),
}))

vi.mock('../api/client', () => ({
  fetchTimeline: mockFetchTimeline,
  fetchThreats: vi.fn().mockResolvedValue([]),
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'ok', ollama_connected: false, ollama_model: null, db_ok: true,
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
  fetchTopTalkers: mockFetchTopTalkers,
  fetchProtocolMix: mockFetchProtocolMix,
  // Other exports needed by modules transitively imported (non-fatal stubs).
  fetchPaginatedLogs: vi.fn().mockResolvedValue({ logs: [], next_cursor: null, has_more: false, total_matching: 0 }),
  fetchTopPairs: vi.fn().mockResolvedValue([]),
  fetchLogsStats: vi.fn().mockResolvedValue({ total_events: 0, blocked_events: 0, distinct_ips: 0, present_source_types: [] }),
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
  fetchEntityGraph: vi.fn().mockResolvedValue(null),
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderHeader(onFilterChange = vi.fn()) {
  return render(<TrafficShapeHeader onFilterChange={onFilterChange} />)
}

// ---------------------------------------------------------------------------
// EARS-1: Volume timeline
// ---------------------------------------------------------------------------

describe('TrafficShapeHeader — EARS-1: timeline', () => {
  beforeEach(() => {
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchTopTalkers.mockResolvedValue(TALKER_FIXTURE)
    mockFetchProtocolMix.mockResolvedValue(PROTOCOL_FIXTURE)
  })

  it('renders the timeline panel when timeline data is present', async () => {
    renderHeader()
    await waitFor(() => {
      expect(screen.getByTestId('traffic-timeline-panel')).toBeInTheDocument()
    })
  })

  it('renders TimelineChart inside the timeline panel', async () => {
    renderHeader()
    await waitFor(() => {
      expect(screen.getByTestId('timeline-chart')).toBeInTheDocument()
    })
  })

  it('does not render timeline panel when timeline is empty', async () => {
    mockFetchTimeline.mockResolvedValue([])
    renderHeader()
    await waitFor(() => {
      expect(screen.queryByTestId('traffic-timeline-panel')).not.toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// EARS-2: Top talkers and protocol mix panels
// ---------------------------------------------------------------------------

describe('TrafficShapeHeader — EARS-2: top-talkers and protocol-mix', () => {
  beforeEach(() => {
    mockFetchTimeline.mockResolvedValue([])
    mockFetchTopTalkers.mockResolvedValue(TALKER_FIXTURE)
    mockFetchProtocolMix.mockResolvedValue(PROTOCOL_FIXTURE)
  })

  it('renders top-talkers panel when data is present', async () => {
    renderHeader()
    await waitFor(() => {
      expect(screen.getByTestId('traffic-top-talkers-panel')).toBeInTheDocument()
    })
  })

  it('renders protocol-mix panel when data is present', async () => {
    renderHeader()
    await waitFor(() => {
      expect(screen.getByTestId('traffic-protocol-mix-panel')).toBeInTheDocument()
    })
  })

  it('shows IP addresses as text in top-talkers', async () => {
    renderHeader()
    await waitFor(() => {
      expect(screen.getByTestId('traffic-top-talkers-panel')).toBeInTheDocument()
    })
    expect(screen.getByTestId('traffic-top-talkers-panel').textContent).toContain('192.0.2.10')
    expect(screen.getByTestId('traffic-top-talkers-panel').textContent).toContain('192.0.2.20')
  })

  it('shows protocol names in protocol-mix', async () => {
    renderHeader()
    await waitFor(() => {
      expect(screen.getByTestId('traffic-protocol-mix-panel')).toBeInTheDocument()
    })
    expect(screen.getByTestId('traffic-protocol-mix-panel').textContent).toContain('TCP')
    expect(screen.getByTestId('traffic-protocol-mix-panel').textContent).toContain('UDP')
  })
})

// ---------------------------------------------------------------------------
// EARS-3: Cross-filter on click
// ---------------------------------------------------------------------------

describe('TrafficShapeHeader — EARS-3: cross-filter on click', () => {
  beforeEach(() => {
    mockFetchTimeline.mockResolvedValue([])
    mockFetchTopTalkers.mockResolvedValue(TALKER_FIXTURE)
    mockFetchProtocolMix.mockResolvedValue(PROTOCOL_FIXTURE)
  })

  it('clicking a top-talker IP calls onFilterChange with ip field', async () => {
    const onFilter = vi.fn()
    renderHeader(onFilter)
    await waitFor(() => {
      expect(screen.getByTestId('traffic-top-talkers-panel')).toBeInTheDocument()
    })
    // Find the button for the first IP
    const btn = screen.getByRole('button', { name: 'Filter by 192.0.2.10' })
    fireEvent.click(btn)
    expect(onFilter).toHaveBeenCalledWith(expect.objectContaining({ ip: '192.0.2.10' }))
  })

  it('clicking a protocol row calls onFilterChange with protocol field', async () => {
    const onFilter = vi.fn()
    renderHeader(onFilter)
    await waitFor(() => {
      expect(screen.getByTestId('traffic-protocol-mix-panel')).toBeInTheDocument()
    })
    const btn = screen.getByRole('button', { name: 'Filter by TCP' })
    fireEvent.click(btn)
    expect(onFilter).toHaveBeenCalledWith(expect.objectContaining({ protocol: 'TCP' }))
  })

  it('"Other" (relabelled unknown) protocol row has no clickable role (UT-10 / #508)', async () => {
    renderHeader()
    await waitFor(() => {
      expect(screen.getByTestId('traffic-protocol-mix-panel')).toBeInTheDocument()
    })
    // After UT-10 fix: the sentinel "(unknown)" is displayed as "Other".
    // Neither the old label nor the new one should have a button role.
    expect(screen.queryByRole('button', { name: 'Filter by (unknown)' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Filter by Other' })).not.toBeInTheDocument()
    // But the "Other" text should be visible in the panel
    expect(screen.getByTestId('traffic-protocol-mix-panel').textContent).toContain('Other')
  })
})

// ---------------------------------------------------------------------------
// EARS-4: Totals strip
// ---------------------------------------------------------------------------

describe('TrafficShapeHeader — EARS-4: totals strip', () => {
  beforeEach(() => {
    mockFetchTimeline.mockResolvedValue([])
    mockFetchTopTalkers.mockResolvedValue(TALKER_FIXTURE)
    mockFetchProtocolMix.mockResolvedValue([])
  })

  it('renders totals strip', async () => {
    renderHeader()
    await waitFor(() => {
      expect(screen.getByTestId('traffic-totals-strip')).toBeInTheDocument()
    })
  })

  it('shows total event count from top-talkers', async () => {
    renderHeader()
    await waitFor(() => {
      expect(screen.getByTestId('traffic-total-events')).toBeInTheDocument()
    })
    // TALKER_FIXTURE totals: 500 + 300 + 150 = 950
    expect(screen.getByTestId('traffic-total-events').textContent).toContain('950')
  })

  it('shows blocked event count', async () => {
    renderHeader()
    await waitFor(() => {
      expect(screen.getByTestId('traffic-blocked-events')).toBeInTheDocument()
    })
    // TALKER_FIXTURE blocked: 200 + 100 + 50 = 350
    expect(screen.getByTestId('traffic-blocked-events').textContent).toContain('350')
  })

  it('shows distinct IP count', async () => {
    renderHeader()
    await waitFor(() => {
      expect(screen.getByTestId('traffic-distinct-ips')).toBeInTheDocument()
    })
    // TALKER_FIXTURE has 3 IPs
    expect(screen.getByTestId('traffic-distinct-ips').textContent).toContain('3')
  })
})

// ---------------------------------------------------------------------------
// Degradation tests
// ---------------------------------------------------------------------------

describe('TrafficShapeHeader — degradation', () => {
  it('renders nothing (returns null) when all data is empty', async () => {
    mockFetchTimeline.mockResolvedValue([])
    mockFetchTopTalkers.mockResolvedValue([])
    mockFetchProtocolMix.mockResolvedValue([])
    const { container } = renderHeader()
    await waitFor(() => {
      expect(screen.queryByTestId('traffic-shape-header')).not.toBeInTheDocument()
    })
    // Loading indicator should also be gone
    expect(screen.queryByTestId('traffic-header-loading')).not.toBeInTheDocument()
    expect(container.firstChild).toBeNull()
  })

  it('does not crash when fetches fail', async () => {
    mockFetchTimeline.mockRejectedValue(new Error('network'))
    mockFetchTopTalkers.mockRejectedValue(new Error('network'))
    mockFetchProtocolMix.mockRejectedValue(new Error('network'))
    // Should not throw — Promise.allSettled absorbs failures
    renderHeader()
    await waitFor(() => {
      expect(screen.queryByTestId('traffic-header-loading')).not.toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// SECURITY: attacker-controlled fields as text nodes
// ---------------------------------------------------------------------------

describe('TrafficShapeHeader — SECURITY: XSS prevention', () => {
  it('renders XSS IP as inert text, not live script', async () => {
    mockFetchTimeline.mockResolvedValue([])
    mockFetchTopTalkers.mockResolvedValue([XSS_TALKER])
    mockFetchProtocolMix.mockResolvedValue([])
    renderHeader()
    await waitFor(() => {
      expect(screen.getByTestId('traffic-top-talkers-panel')).toBeInTheDocument()
    })
    const panel = screen.getByTestId('traffic-top-talkers-panel')
    expect(panel.textContent).toContain('<script>alert("xss")</script>')
    expect(document.querySelectorAll('script[data-xss]').length).toBe(0)
  })

  it('renders XSS protocol as inert text, not live HTML', async () => {
    mockFetchTimeline.mockResolvedValue([])
    mockFetchTopTalkers.mockResolvedValue([])
    mockFetchProtocolMix.mockResolvedValue([XSS_PROTOCOL])
    renderHeader()
    await waitFor(() => {
      expect(screen.getByTestId('traffic-protocol-mix-panel')).toBeInTheDocument()
    })
    const panel = screen.getByTestId('traffic-protocol-mix-panel')
    expect(panel.textContent).toContain('<img src=x onerror=alert(1)>')
    expect(document.querySelectorAll('img[onerror]').length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// LogsRoute integration note:
// #665 replaced TrafficShapeHeader with StripTiles in LogsRoute.
// LogsRoute integration tests are in issue665StripTiles.test.tsx.
// The TrafficShapeHeader unit tests above remain valid (the component
// exists as a standalone module; it is no longer mounted in LogsRoute).
// ---------------------------------------------------------------------------
