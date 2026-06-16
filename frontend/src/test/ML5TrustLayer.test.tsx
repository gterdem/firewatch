/**
 * Tests for ML-5 (#433) — Provenance chips, zero-egress badge, field-availability honesty.
 *
 * EARS criteria covered:
 *
 * EARS-1: ProvenanceChip in AI verdict fold.
 *   → test_ai_verdict_chip_shows_ai_provenance_when_ai_active
 *   → test_ai_verdict_chip_shows_rule_provenance_when_ai_offline
 *   → test_ai_verdict_chip_degrades_gracefully_when_no_threat_map
 *
 * EARS-2: Zero-egress trust indicator persistent on the page.
 *   → test_logs_route_shows_zero_egress_badge
 *   → test_zero_egress_badge_renders_with_correct_text
 *   → test_zero_egress_badge_compact_form
 *   → test_zero_egress_badge_has_aria_label
 *
 * EARS-3: Field-availability honesty for L7-only sources.
 *   → test_destination_column_header_has_availability_hint
 *   → test_protocol_column_header_has_availability_hint
 *   → test_field_availability_tooltip_shows_on_hover
 *   → test_field_availability_legend_not_shown_for_unaffected_columns
 *   → test_azure_waf_row_dash_has_availability_hints_in_header
 *
 * SECURITY (ADR-0029 D3):
 *   → test_field_notes_are_static_not_attacker_controlled
 *   → test_zero_egress_badge_renders_no_dynamic_content
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LogsTable from '../components/logs/LogsTable'
import LogsRoute from '../routes/LogsRoute'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import { RefreshProvider } from '../app/refresh/RefreshContext'
import { ZeroEgressBadge } from '../components/logs/ZeroEgressBadge'
import { FieldAvailabilityLegend } from '../components/logs/FieldAvailabilityLegend'
import { FIELD_NOTES, COLUMNS_WITH_NOTES } from '../lib/fieldAvailability'
import { LOG_ENTRY_FIXTURE, PAGINATED_LOGS_EMPTY } from './readFixtures'
import type { LogEntry, ThreatScore } from '../api/types'

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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SURICATA_ROW: LogEntry = {
  ...LOG_ENTRY_FIXTURE,
  id: 300,
  source_type: 'suricata',
  source_ip: '192.0.2.30',
  destination_ip: '198.51.100.5',
  protocol: 'TCP',
}

const AZURE_WAF_ROW: LogEntry = {
  ...LOG_ENTRY_FIXTURE,
  id: 301,
  source_type: 'azure_waf',
  source_ip: '192.0.2.31',
  destination_ip: null,
  protocol: null,
}

/** ThreatScore with AI active — should produce derivation="ai" ProvenanceChip. */
const THREAT_AI_ACTIVE: ThreatScore = {
  source_ip: '192.0.2.30',
  threat_level: 'HIGH',
  score: 78,
  total_events: 10,
  blocked_events: 8,
  attack_types: ['SQL Injection'],
  first_seen: '2026-06-04T08:00:00Z',
  last_seen: '2026-06-04T10:00:00Z',
  source_types: ['suricata'],
  detections: [],
  ai_insights: ['Intent: scanning'],
  ai_confidence: 0.87,
  ai_status: 'active',
  location: null,
  score_breakdown: [],
  asn: null,
  as_name: null,
  score_delta: null,
}

/** ThreatScore with AI unavailable — should produce derivation="rule" ProvenanceChip. */
const THREAT_AI_OFFLINE: ThreatScore = {
  ...THREAT_AI_ACTIVE,
  ai_status: 'unavailable',
  ai_confidence: null,
  ai_insights: null,
}

// ---------------------------------------------------------------------------
// EARS-1: ProvenanceChip in AI verdict fold
// ---------------------------------------------------------------------------

describe('LogsTable — ML-5 EARS-1: ProvenanceChip in AI verdict fold', () => {
  it('shows AI ProvenanceChip when ai_status is active', () => {
    const threatMap = new Map([[SURICATA_ROW.source_ip, THREAT_AI_ACTIVE]])
    renderTable({ logs: [SURICATA_ROW], onIpClick: vi.fn(), threatMap })

    const chips = screen.getAllByTestId('log-row-provenance-chip')
    expect(chips.length).toBeGreaterThan(0)
    // ProvenanceChip with derivation="ai" renders "AI" label
    expect(chips[0].textContent).toMatch(/^AI$/i)
    expect(chips[0].getAttribute('data-derivation')).toBe('ai')
  })

  it('shows RULE ProvenanceChip when ai_status is not active (degraded)', () => {
    const threatMap = new Map([[SURICATA_ROW.source_ip, THREAT_AI_OFFLINE]])
    renderTable({ logs: [SURICATA_ROW], onIpClick: vi.fn(), threatMap })

    const chips = screen.getAllByTestId('log-row-provenance-chip')
    expect(chips.length).toBeGreaterThan(0)
    expect(chips[0].textContent).toMatch(/^RULE$/i)
    expect(chips[0].getAttribute('data-derivation')).toBe('rule')
  })

  it('does not show AI verdict chip when threatMap is absent', () => {
    renderTable({ logs: [SURICATA_ROW], onIpClick: vi.fn() })
    // No verdict fold when no threat data
    expect(screen.queryByTestId('log-row-ai-verdict')).toBeNull()
    expect(screen.queryByTestId('log-row-provenance-chip')).toBeNull()
  })

  it('does not show AI verdict chip when IP is not in threatMap', () => {
    const threatMap = new Map([['192.0.2.99', THREAT_AI_ACTIVE]])
    renderTable({ logs: [SURICATA_ROW], onIpClick: vi.fn(), threatMap })
    // SURICATA_ROW IP (192.0.2.30) is not in the map
    expect(screen.queryByTestId('log-row-ai-verdict')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// EARS-2: ZeroEgressBadge component unit tests
// ---------------------------------------------------------------------------

describe('ZeroEgressBadge', () => {
  it('renders with the full zero-egress text', () => {
    render(<ZeroEgressBadge />)
    const badge = screen.getByTestId('zero-egress-badge')
    expect(badge.textContent).toContain('Local-only')
    expect(badge.textContent).toContain('0 bytes egressed')
  })

  it('renders compact form with just "Local-only"', () => {
    render(<ZeroEgressBadge compact />)
    const badge = screen.getByTestId('zero-egress-badge')
    expect(badge.textContent).toContain('Local-only')
    expect(badge.textContent).not.toContain('bytes')
  })

  it('has accessible aria-label describing zero-egress guarantee', () => {
    render(<ZeroEgressBadge />)
    const badge = screen.getByTestId('zero-egress-badge')
    expect(badge.getAttribute('aria-label')).toMatch(/zero.egress|locally|no data leaves/i)
  })

  it('has role="status" for non-interactive presentation', () => {
    render(<ZeroEgressBadge />)
    const badge = screen.getByRole('status')
    expect(badge).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-2: ZeroEgressBadge in LogsRoute
// ---------------------------------------------------------------------------

const { mockFetchPaginatedLogs: mockLogsRouteLogsApi } = vi.hoisted(() => ({
  mockFetchPaginatedLogs: vi.fn(),
}))

vi.mock('../api/logs', () => ({
  fetchPaginatedLogs: mockLogsRouteLogsApi,
  fetchTopPairs: vi.fn().mockResolvedValue([]),
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

describe('LogsRoute — ML-5 EARS-2: zero-egress badge', () => {
  beforeEach(() => {
    mockLogsRouteLogsApi.mockResolvedValue(PAGINATED_LOGS_EMPTY)
  })

  it('renders the zero-egress badge on the logs page', async () => {
    renderLogsRoute()
    await waitFor(() => {
      expect(screen.getByTestId('zero-egress-badge')).toBeInTheDocument()
    })
  })

  it('zero-egress badge text contains "Local-only" and "0 bytes egressed"', async () => {
    renderLogsRoute()
    await waitFor(() => {
      const badge = screen.getByTestId('zero-egress-badge')
      expect(badge.textContent).toContain('Local-only')
      expect(badge.textContent).toContain('0 bytes egressed')
    })
  })

  it('page header contains "Network Logs" title alongside the badge', async () => {
    renderLogsRoute()
    await waitFor(() => {
      const header = screen.getByTestId('logs-page-header')
      expect(header.textContent).toContain('Network Logs')
    })
  })
})

// ---------------------------------------------------------------------------
// EARS-3: FieldAvailabilityLegend unit tests
// ---------------------------------------------------------------------------

describe('FieldAvailabilityLegend', () => {
  it('renders a "?" hint button for the Destination column', () => {
    render(<FieldAvailabilityLegend column="Destination" />)
    expect(screen.getByTestId('field-availability-hint')).toBeInTheDocument()
  })

  it('renders a "?" hint button for the Protocol column', () => {
    render(<FieldAvailabilityLegend column="Protocol" />)
    expect(screen.getByTestId('field-availability-hint')).toBeInTheDocument()
  })

  it('renders nothing for columns without a note (e.g. Signature)', () => {
    const { container } = render(<FieldAvailabilityLegend column="Signature" />)
    expect(container.firstChild).toBeNull()
  })

  it('shows tooltip text when the "?" button is focused', () => {
    render(<FieldAvailabilityLegend column="Destination" />)
    const hint = screen.getByTestId('field-availability-hint')
    fireEvent.focus(hint)
    const tooltip = screen.getByTestId('field-availability-tooltip')
    expect(tooltip).toBeInTheDocument()
    // Should mention L7-only sources
    expect(tooltip.textContent).toMatch(/L7.only/i)
  })

  it('shows tooltip text when the "?" button is hovered', () => {
    render(<FieldAvailabilityLegend column="Protocol" />)
    const hint = screen.getByTestId('field-availability-hint')
    fireEvent.mouseEnter(hint)
    const tooltip = screen.getByTestId('field-availability-tooltip')
    expect(tooltip).toBeInTheDocument()
    expect(tooltip.textContent).toMatch(/protocol/i)
  })

  it('hides tooltip after blur', async () => {
    // #666: FieldAvailabilityTooltip now uses useHoverFocusDisclosure which has an
    // 80ms leave-delay (WCAG 1.4.13 hoverable — lets pointer travel to tooltip without
    // it vanishing). waitFor polls until React re-renders with the closed state.
    render(<FieldAvailabilityLegend column="Destination" />)
    const hint = screen.getByTestId('field-availability-hint')
    fireEvent.focus(hint)
    expect(screen.getByTestId('field-availability-tooltip')).toBeInTheDocument()
    fireEvent.blur(hint)
    // waitFor polls until the tooltip disappears (after the 80ms leave-delay fires).
    await waitFor(() => {
      expect(screen.queryByTestId('field-availability-tooltip')).toBeNull()
    }, { timeout: 500 })
  })

  it('tooltip text is static — not derived from attacker-controlled input', () => {
    // FIELD_NOTES is a static compile-time constant — verify it only has expected keys
    expect(Object.keys(FIELD_NOTES)).toEqual(expect.arrayContaining(['Destination', 'Protocol']))
    // Verify COLUMNS_WITH_NOTES agrees
    expect(COLUMNS_WITH_NOTES.has('Destination')).toBe(true)
    expect(COLUMNS_WITH_NOTES.has('Protocol')).toBe(true)
    // Verify no unknown/injected keys in FIELD_NOTES
    for (const key of Object.keys(FIELD_NOTES)) {
      expect(typeof FIELD_NOTES[key]).toBe('string')
      // Should not contain script tags (static only)
      expect(FIELD_NOTES[key]).not.toContain('<script>')
    }
  })
})

// ---------------------------------------------------------------------------
// EARS-3: Field-availability hints in LogsTable — retired for logs spine (ADR-0063 D6)
//
// Under ADR-0063 D6, the frontend structural-hiding axis (FieldAvailabilityLegend
// in column headers, log-row-protocol / log-row-dest-ip inline cells) is retired
// for the logs table. Destination and Protocol move into the detail panel.
// The FieldAvailabilityLegend component itself still exists (used elsewhere),
// but it is NOT mounted by LogsTable's column headers anymore.
// ---------------------------------------------------------------------------

describe('LogsTable — ML-5 EARS-3: field-availability hints retired (ADR-0063 D6)', () => {
  it('LogsTable does NOT render field-availability-hint buttons in column headers', () => {
    stubWideContainer()
    render(
      <MemoryRouter>
        <LogsTable logs={[AZURE_WAF_ROW]} onIpClick={vi.fn()} />
      </MemoryRouter>,
    )
    vi.restoreAllMocks()

    // Under ADR-0063 D6, no FieldAvailabilityLegend "?" hint buttons in the spine headers
    expect(screen.queryByTestId('field-availability-hint')).not.toBeInTheDocument()
  })

  it('LogsTable does NOT render log-row-protocol inline cells', () => {
    stubWideContainer()
    render(
      <MemoryRouter>
        <LogsTable logs={[AZURE_WAF_ROW]} onIpClick={vi.fn()} />
      </MemoryRouter>,
    )
    vi.restoreAllMocks()

    // Protocol moved to detail panel (not an inline cell)
    expect(screen.queryByTestId('log-row-protocol')).not.toBeInTheDocument()
  })

  it('Destination and Protocol are visible in the detail panel when row is expanded', () => {
    stubWideContainer()
    render(
      <MemoryRouter>
        <LogsTable logs={[SURICATA_ROW]} onIpClick={vi.fn()} />
      </MemoryRouter>,
    )
    vi.restoreAllMocks()

    fireEvent.click(screen.getByTestId('log-row-chevron'))
    const panel = screen.getByTestId('log-detail-panel')
    // SURICATA_ROW has destination_ip and protocol — visible in Network section
    expect(screen.getByTestId('detail-section-network')).toBeInTheDocument()
    expect(panel.textContent).toContain('198.51.100.5')  // destination_ip
    expect(panel.textContent).toContain('TCP')            // protocol
  })

  it('Azure WAF row omits Destination/Protocol fields (null) from detail panel', () => {
    stubWideContainer()
    render(
      <MemoryRouter>
        <LogsTable logs={[AZURE_WAF_ROW]} onIpClick={vi.fn()} />
      </MemoryRouter>,
    )
    vi.restoreAllMocks()

    fireEvent.click(screen.getByTestId('log-row-chevron'))
    const panel = screen.getByTestId('log-detail-panel')
    // destination_ip and protocol are null → not rendered as explicit "—"
    // The network section still shows (source_ip is always present)
    expect(screen.getByTestId('detail-section-network')).toBeInTheDocument()
    // No "—" for null fields — honest absence (ADR-0063 D3)
    expect(panel.textContent).not.toContain('198.51.100.5')  // no dest ip
    expect(panel.textContent).not.toContain('TCP')             // no protocol
  })
})
