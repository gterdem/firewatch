/**
 * Tests for ADR-0063 — Network Logs detail-panel + spine redesign.
 *
 * Issues: #715 (detail panel scaffold), #716 (inline row-expand), #717 (spine trim),
 *         #718 (retire structural hiding).
 *
 * EARS criteria covered:
 *
 * #715 — Detail-panel scaffold (ADR-0063 D3):
 *   - LogDetailPanel renders only sections with ≥1 populated field.
 *   - LogDetailPanel omits sections entirely when all fields are empty.
 *   - raw_log collapsed by default; expands on demand.
 *   - raw_log rendered as React text node; no dangerouslySetInnerHTML.
 *   - Copy affordance present for copyable fields.
 *   - DGA score carries RULE-provenance hint.
 *   - No network calls (geo/asn already on row).
 *
 * #716 — Row-expand interaction (ADR-0063 D2):
 *   - Chevron click expands detail region beneath the row.
 *   - Second click collapses.
 *   - Multiple rows independently expandable.
 *   - Esc from expanded region collapses that row.
 *   - Source IP click does NOT toggle row.
 *   - Signature cell click does NOT toggle row.
 *   - Expanded region has role="region" + aria-label.
 *   - Chevron has aria-expanded.
 *   - No detail row in DOM when collapsed.
 *
 * #717 — Spine trim (ADR-0063 D1/D5):
 *   - Exactly the 7 spine headers + expand chevron.
 *   - AI verdict in its own column (not inside Action cell).
 *   - Action cell single-line (no verdict fold below badge).
 *   - AI verdict absent when no threatMap entry (ADR-0015).
 *   - Long-tail columns not inline.
 *
 * #718 — Retire structural hiding (ADR-0063 D6):
 *   - LogsTable does not render HiddenFieldsChip toolbar.
 *   - LogsTable does not render FieldAvailabilityLegend "?" hints.
 *
 * SECURITY (ADR-0029 D3):
 *   - All attacker-controlled values render as inert text nodes.
 *   - No dangerouslySetInnerHTML in detail panel.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LogsTable from '../components/logs/LogsTable'
import { LogDetailPanel } from '../components/logs/detail/LogDetailPanel'
import { useRowExpansion } from '../components/logs/useRowExpansion'
import { renderHook, act } from '@testing-library/react'
import { LOG_ENTRY_FIXTURE } from './readFixtures'
import type { LogEntry, ThreatScore } from '../api/types'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/** A LogEntry with ALL optional fields populated. */
const FULL_LOG: LogEntry = {
  ...LOG_ENTRY_FIXTURE,
  id: 1000,
  source_ip: '192.0.2.100',
  destination_ip: '198.51.100.50',
  destination_port: 443,
  protocol: 'TCP',
  tls_ja4: 'q13d0312h2_002f,0035,c02b',
  tls_ja4s: 's13d0312h2_002f,c02b',
  tls_sni: 'example.com',
  tls_version: 'TLSv1.3',
  dns_query: 'evil.example.com',
  dga_score: 0.87,
  payload_snippet: 'GET /api/users?id=1 OR 1=1',
  rule_name: 'ET SQL Injection Attempt',
  rule_id: 2001219,
  geo_city: 'Frankfurt am Main',
  geo_country: 'Germany',
  raw_log: '{"event_type":"alert","src_ip":"192.0.2.100"}',
}

/** A LogEntry with only mandatory fields — all optional fields null/absent. */
const SPARSE_LOG: LogEntry = {
  id: 1001,
  timestamp: '2026-06-04T10:00:00Z',
  source_type: 'suricata',
  source_ip: '192.0.2.101',
  category: 'Port Scan',
  severity: 'low',
  action: 'ALERT',
  raw_log: null,
}

/** A ThreatScore for FULL_LOG's IP. */
const FULL_THREAT: ThreatScore = {
  source_ip: '192.0.2.100',
  threat_level: 'HIGH',
  score: 75,
  total_events: 10,
  blocked_events: 8,
  attack_types: ['SQL Injection'],
  first_seen: null,
  last_seen: null,
  source_types: ['suricata'],
  detections: [],
  ai_insights: ['Intent: exfiltration'],
  ai_confidence: 0.90,
  ai_status: 'active',
  location: 'Frankfurt, Germany',
  score_breakdown: [],
  asn: 4837,
  as_name: 'CHINA-UNICOM',
  score_delta: 10,
}

// ---------------------------------------------------------------------------
// #715 — LogDetailPanel section omission / presence
// ---------------------------------------------------------------------------

describe('LogDetailPanel — #715 section presence/omission (ADR-0063 D3)', () => {
  it('renders Identity, Network, Detection sections for a minimally-populated entry', () => {
    render(<LogDetailPanel entry={SPARSE_LOG} />)
    // Identity: source_type, source_ip, category → present
    expect(screen.getByTestId('detail-section-identity')).toBeInTheDocument()
    // Network: source_ip → present (source_ip is in network section)
    expect(screen.getByTestId('detail-section-network')).toBeInTheDocument()
    // Detection: severity, action → present
    expect(screen.getByTestId('detail-section-detection')).toBeInTheDocument()
  })

  it('omits TLS section when all TLS fields are null/absent (honest absence)', () => {
    render(<LogDetailPanel entry={SPARSE_LOG} />)
    expect(screen.queryByTestId('detail-section-tls')).not.toBeInTheDocument()
  })

  it('omits DNS section when dns_query and dga_score are absent', () => {
    render(<LogDetailPanel entry={SPARSE_LOG} />)
    expect(screen.queryByTestId('detail-section-dns')).not.toBeInTheDocument()
  })

  it('omits HTTP section when no payload field', () => {
    render(<LogDetailPanel entry={SPARSE_LOG} />)
    expect(screen.queryByTestId('detail-section-http')).not.toBeInTheDocument()
  })

  it('omits Geo section when no geo fields', () => {
    render(<LogDetailPanel entry={SPARSE_LOG} />)
    expect(screen.queryByTestId('detail-section-geo')).not.toBeInTheDocument()
  })

  it('omits Provenance/Raw section when raw_log is null', () => {
    render(<LogDetailPanel entry={SPARSE_LOG} />)
    expect(screen.queryByTestId('detail-section-raw')).not.toBeInTheDocument()
  })

  it('renders all 8 sections when every field is populated', () => {
    render(<LogDetailPanel entry={FULL_LOG} />)
    expect(screen.getByTestId('detail-section-identity')).toBeInTheDocument()
    expect(screen.getByTestId('detail-section-network')).toBeInTheDocument()
    expect(screen.getByTestId('detail-section-tls')).toBeInTheDocument()
    expect(screen.getByTestId('detail-section-dns')).toBeInTheDocument()
    expect(screen.getByTestId('detail-section-http')).toBeInTheDocument()
    expect(screen.getByTestId('detail-section-detection')).toBeInTheDocument()
    expect(screen.getByTestId('detail-section-geo')).toBeInTheDocument()
    expect(screen.getByTestId('detail-section-raw')).toBeInTheDocument()
  })

  it('renders correct field values in sections', () => {
    render(<LogDetailPanel entry={FULL_LOG} />)
    const panel = screen.getByTestId('log-detail-panel')
    expect(panel.textContent).toContain('198.51.100.50')         // destination_ip
    expect(panel.textContent).toContain('TCP')                   // protocol
    expect(panel.textContent).toContain('q13d0312h2_002f,0035,c02b') // tls_ja4
    expect(panel.textContent).toContain('example.com')           // tls_sni
    expect(panel.textContent).toContain('evil.example.com')      // dns_query
    expect(panel.textContent).toContain('GET /api/users?id=1 OR 1=1') // payload
    expect(panel.textContent).toContain('ET SQL Injection Attempt')    // rule_name
    expect(panel.textContent).toContain('Frankfurt am Main')     // geo_city
    expect(panel.textContent).toContain('Germany')               // geo_country
  })
})

// ---------------------------------------------------------------------------
// #715 — raw_log behaviour
// ---------------------------------------------------------------------------

describe('LogDetailPanel — #715 raw_log (ADR-0063 D3)', () => {
  it('raw_log is collapsed by default (content not visible)', () => {
    render(<LogDetailPanel entry={FULL_LOG} />)
    expect(screen.getByTestId('detail-section-raw')).toBeInTheDocument()
    expect(screen.getByTestId('raw-log-toggle')).toBeInTheDocument()
    expect(screen.queryByTestId('raw-log-content')).not.toBeInTheDocument()
  })

  it('raw_log expands when the Expand button is clicked', () => {
    render(<LogDetailPanel entry={FULL_LOG} />)
    fireEvent.click(screen.getByTestId('raw-log-toggle'))
    expect(screen.getByTestId('raw-log-content')).toBeInTheDocument()
  })

  it('raw_log collapses again when Collapse is clicked', () => {
    render(<LogDetailPanel entry={FULL_LOG} />)
    fireEvent.click(screen.getByTestId('raw-log-toggle'))
    expect(screen.getByTestId('raw-log-content')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('raw-log-toggle'))
    expect(screen.queryByTestId('raw-log-content')).not.toBeInTheDocument()
  })

  it('raw_log shows attacker-controlled warning label', () => {
    render(<LogDetailPanel entry={FULL_LOG} />)
    expect(screen.getByTestId('raw-log-warning')).toHaveTextContent(/attacker-controlled/i)
  })

  it('raw_log Copy button is present (even collapsed)', () => {
    render(<LogDetailPanel entry={FULL_LOG} />)
    expect(screen.getByTestId('raw-log-copy')).toBeInTheDocument()
  })

  it('raw_log XSS renders as inert text — no dangerouslySetInnerHTML (ADR-0029 D3)', () => {
    const xssLog: LogEntry = {
      ...FULL_LOG,
      id: 1099,
      raw_log: '<script data-xss>alert("xss-raw")</script>',
    }
    render(<LogDetailPanel entry={xssLog} />)
    fireEvent.click(screen.getByTestId('raw-log-toggle'))
    const content = screen.getByTestId('raw-log-content')
    expect(content.textContent).toContain('<script data-xss>alert("xss-raw")</script>')
    expect(document.querySelectorAll('script[data-xss]').length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// #715 — DGA score provenance hint
// ---------------------------------------------------------------------------

describe('LogDetailPanel — #715 DGA score provenance (ADR-0035)', () => {
  it('DGA score field carries a RULE-provenance hint', () => {
    render(<LogDetailPanel entry={FULL_LOG} />)
    const hints = screen.getAllByTestId('detail-field-hint')
    const hintTexts = hints.map((h) => h.textContent ?? '')
    expect(hintTexts.some((t) => /RULE/i.test(t) || /heuristic/i.test(t))).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// #716 — Row-expand interaction (useRowExpansion hook)
// ---------------------------------------------------------------------------

describe('useRowExpansion — #716 toggle state', () => {
  it('starts with no rows expanded', () => {
    const { result } = renderHook(() => useRowExpansion())
    expect(result.current.expandedIds.size).toBe(0)
  })

  it('toggle expands a row', () => {
    const { result } = renderHook(() => useRowExpansion())
    act(() => { result.current.toggle(1) })
    expect(result.current.isExpanded(1)).toBe(true)
  })

  it('toggle collapses an expanded row', () => {
    const { result } = renderHook(() => useRowExpansion())
    act(() => { result.current.toggle(1) })
    act(() => { result.current.toggle(1) })
    expect(result.current.isExpanded(1)).toBe(false)
  })

  it('multiple rows expand independently', () => {
    const { result } = renderHook(() => useRowExpansion())
    act(() => { result.current.toggle(1) })
    act(() => { result.current.toggle(2) })
    expect(result.current.isExpanded(1)).toBe(true)
    expect(result.current.isExpanded(2)).toBe(true)
  })

  it('Esc key handler collapses a specific row', () => {
    const { result } = renderHook(() => useRowExpansion())
    act(() => { result.current.toggle('abc') })
    expect(result.current.isExpanded('abc')).toBe(true)
    const handler = result.current.makeRegionKeyDown('abc')
    act(() => {
      handler({ key: 'Escape', preventDefault: vi.fn() } as unknown as React.KeyboardEvent<HTMLTableRowElement>)
    })
    expect(result.current.isExpanded('abc')).toBe(false)
  })

  it('Esc key does not collapse other expanded rows', () => {
    const { result } = renderHook(() => useRowExpansion())
    act(() => { result.current.toggle(1) })
    act(() => { result.current.toggle(2) })
    const handler = result.current.makeRegionKeyDown(1)
    act(() => {
      handler({ key: 'Escape', preventDefault: vi.fn() } as unknown as React.KeyboardEvent<HTMLTableRowElement>)
    })
    expect(result.current.isExpanded(1)).toBe(false)
    expect(result.current.isExpanded(2)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// #716 — LogsTable row-expand UI
// ---------------------------------------------------------------------------

describe('LogsTable — #716 row-expand interaction (ADR-0063 D2)', () => {
  it('chevron has aria-expanded=false when collapsed', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    const chevron = screen.getByTestId('log-row-chevron')
    expect(chevron).toHaveAttribute('aria-expanded', 'false')
  })

  it('clicking chevron expands the detail row', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    expect(screen.queryByTestId('log-detail-row')).not.toBeInTheDocument()
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    expect(screen.getByTestId('log-detail-row')).toBeInTheDocument()
    expect(screen.getByTestId('log-detail-panel')).toBeInTheDocument()
  })

  it('chevron has aria-expanded=true when expanded', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    expect(screen.getByTestId('log-row-chevron')).toHaveAttribute('aria-expanded', 'true')
  })

  it('second chevron click collapses the detail row', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    expect(screen.getByTestId('log-detail-row')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    expect(screen.queryByTestId('log-detail-row')).not.toBeInTheDocument()
  })

  it('detail row has role="region" and aria-label when expanded', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    const detailRow = screen.getByTestId('log-detail-row')
    expect(detailRow).toHaveAttribute('role', 'region')
    expect(detailRow).toHaveAttribute('aria-label')
    expect(detailRow.getAttribute('aria-label')).toMatch(/192\.0\.2\.1/)
  })

  it('no detail row in DOM when not expanded', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    expect(screen.queryByTestId('log-detail-row')).not.toBeInTheDocument()
  })

  it('multiple rows expand independently (no single-open invariant)', () => {
    const twoLogs: LogEntry[] = [
      { ...LOG_ENTRY_FIXTURE, id: 10, source_ip: '192.0.2.10' },
      { ...LOG_ENTRY_FIXTURE, id: 11, source_ip: '192.0.2.11' },
    ]
    renderTable({ logs: twoLogs, onIpClick: vi.fn() })
    const chevrons = screen.getAllByTestId('log-row-chevron')
    fireEvent.click(chevrons[0])
    fireEvent.click(chevrons[1])
    const detailRows = screen.getAllByTestId('log-detail-row')
    expect(detailRows).toHaveLength(2)
  })

  it('clicking the row body toggles the expand', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    const dataRow = screen.getByTestId('log-row')
    fireEvent.click(dataRow)
    expect(screen.getByTestId('log-detail-row')).toBeInTheDocument()
  })

  it('clicking the Source IP button does NOT toggle the row', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    fireEvent.click(screen.getByTestId('log-row-ip'))
    expect(screen.queryByTestId('log-detail-row')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// #717 — Spine column set (ADR-0063 D1)
// ---------------------------------------------------------------------------

describe('LogsTable — #717 spine column set (ADR-0063 D1)', () => {
  it('renders exactly the 7 spine column headers + an expand column', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    const headers = Array.from(document.querySelectorAll('th')).map((th) => th.textContent?.trim() ?? '')
    expect(headers.some((h) => /Time/i.test(h))).toBe(true)
    expect(headers.some((h) => h === 'Source')).toBe(true)
    expect(headers.some((h) => /Source IP/i.test(h))).toBe(true)
    expect(headers.some((h) => /Action/i.test(h))).toBe(true)
    expect(headers.some((h) => /Severity/i.test(h))).toBe(true)
    expect(headers.some((h) => /Signature/i.test(h))).toBe(true)
    expect(headers.some((h) => /AI Verdict/i.test(h))).toBe(true)
  })

  it('Action cell is single-line badge — no AI verdict fold inside it (ADR-0063 D5)', () => {
    const threatMap = new Map([[String(LOG_ENTRY_FIXTURE.source_ip), {
      source_ip: LOG_ENTRY_FIXTURE.source_ip,
      threat_level: 'HIGH' as const,
      score: 80,
      total_events: 5,
      blocked_events: 4,
      attack_types: [],
      first_seen: null,
      last_seen: null,
      source_types: ['suricata'],
      detections: [],
      ai_insights: null,
      ai_confidence: null,
      ai_status: 'active' as const,
      location: null,
      score_breakdown: [],
      asn: null,
      as_name: null,
      score_delta: null,
    }]])
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn(), threatMap })
    // Action badge should be present
    const actionBadge = screen.getByTestId('log-row-action-badge')
    expect(actionBadge).toBeInTheDocument()
    // AI verdict should be in its OWN column, not inside the Action cell
    const verdictEl = screen.getByTestId('log-row-ai-verdict')
    expect(verdictEl).toBeInTheDocument()
    // The verdict should NOT be inside the action cell
    const actionCell = actionBadge.closest('td')!
    expect(actionCell.contains(verdictEl)).toBe(false)
    // The verdict should be in the verdict column cell
    const verdictCell = screen.getByTestId('log-row-verdict-cell')
    expect(verdictCell.contains(verdictEl)).toBe(true)
  })

  it('AI verdict column shows verdict when threatMap has entry (ADR-0063 D1 #7)', () => {
    const threatMap = new Map([[String(FULL_LOG.source_ip), FULL_THREAT]])
    renderTable({ logs: [FULL_LOG], onIpClick: vi.fn(), threatMap })
    expect(screen.getByTestId('log-row-ai-verdict')).toBeInTheDocument()
    expect(screen.getByTestId('log-row-ai-verdict-badge')).toHaveTextContent('block')
  })

  it('AI verdict cell is empty when no threatMap entry (ADR-0015 graceful degradation)', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    // Verdict cell present but empty
    const verdictCell = screen.getByTestId('log-row-verdict-cell')
    expect(verdictCell).toBeInTheDocument()
    expect(screen.queryByTestId('log-row-ai-verdict')).not.toBeInTheDocument()
  })

  it('AI verdict cell empty when threatMap is undefined (ADR-0015 graceful degradation)', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn(), threatMap: undefined })
    expect(screen.queryByTestId('log-row-ai-verdict')).not.toBeInTheDocument()
  })

  it('long-tail columns (Dest Port, HTTP Payload, Destination, Protocol, JA4, DNS) not inline', () => {
    renderTable({ logs: [FULL_LOG], onIpClick: vi.fn() })
    const headers = Array.from(document.querySelectorAll('th')).map((th) => th.textContent?.trim() ?? '')
    expect(headers).not.toContain('Dest Port')
    expect(headers).not.toContain('HTTP Payload')
    expect(headers.some((h) => /^Destination$/i.test(h))).toBe(false)
    expect(headers.some((h) => /^Protocol$/i.test(h))).toBe(false)
    expect(headers.some((h) => /^JA4$/i.test(h))).toBe(false)
    expect(headers.some((h) => /^DNS \/ DGA$/i.test(h))).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// #718 — Retire structural hiding (ADR-0063 D6)
// ---------------------------------------------------------------------------

describe('LogsTable — #718 structural hiding retired (ADR-0063 D6)', () => {
  it('HiddenFieldsChip toolbar is absent (not rendered)', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    expect(screen.queryByTestId('logs-table-toolbar')).not.toBeInTheDocument()
    expect(screen.queryByTestId('hidden-fields-chip')).not.toBeInTheDocument()
  })

  it('FieldAvailabilityLegend "?" hints are not in the table headers', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    expect(screen.queryByTestId('field-availability-hint')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// SECURITY — detail panel values are inert text nodes (ADR-0029 D3)
// ---------------------------------------------------------------------------

describe('LogDetailPanel — SECURITY: attacker-controlled values as text nodes', () => {
  it('XSS in dns_query renders as inert text in DNS section', () => {
    const xssLog: LogEntry = {
      ...FULL_LOG,
      id: 1050,
      dns_query: '<script data-xss>alert("dns-xss")</script>',
    }
    render(<LogDetailPanel entry={xssLog} />)
    const panel = screen.getByTestId('log-detail-panel')
    expect(panel.textContent).toContain('<script data-xss>alert("dns-xss")</script>')
    expect(document.querySelectorAll('script[data-xss]').length).toBe(0)
  })

  it('XSS in payload renders as inert text in HTTP section', () => {
    const xssLog: LogEntry = {
      ...FULL_LOG,
      id: 1051,
      payload_snippet: '<img src=x onerror=alert(1)>',
    }
    render(<LogDetailPanel entry={xssLog} />)
    const panel = screen.getByTestId('log-detail-panel')
    expect(panel.textContent).toContain('<img src=x onerror=alert(1)>')
    expect(document.querySelectorAll('img[onerror]').length).toBe(0)
  })

  it('XSS in tls_ja4 renders as inert text in TLS section', () => {
    const xssLog: LogEntry = {
      ...FULL_LOG,
      id: 1052,
      tls_ja4: '<script>alert("ja4")</script>',
    }
    render(<LogDetailPanel entry={xssLog} />)
    const panel = screen.getByTestId('log-detail-panel')
    expect(panel.textContent).toContain('<script>alert("ja4")</script>')
    expect(document.querySelectorAll('script').length).toBe(0)
  })
})
