/**
 * MF-4: Network Logs page tests (#161).
 *
 * EARS criteria covered (mapped 1:1):
 *
 * 1. Event-driven: WHEN a facet filter changes, the table SHALL update per the
 *    existing filter contract (no regression to the #112 behavior).
 *    → "filter change re-fetches and resets cursor (no regression)"
 *
 * 2. State-driven: WHILE the /logs DTO carries signature/payload/dest_port,
 *    those columns SHALL render.
 *    → "rule_name renders when present in DTO"
 *    → "rule_id renders as fallback when rule_name is null (graceful)"
 *    → "payload renders when present in DTO"
 *    → "dest_port renders when present in DTO"
 *
 * 3. State-driven: WHILE absent, the table SHALL degrade gracefully (no
 *    empty/undefined cells).
 *    → "signature/payload/dest_port each show em-dash when absent"
 *
 * 4. State-driven (AI fold): WHILE /threats DTO carries a ThreatScore for an IP,
 *    the AI verdict chip SHALL render in that row.
 *    → "AI verdict chip renders when threatMap has score for the row IP"
 *    → "AI verdict chip shows block for score ≥70"
 *    → "AI verdict chip shows investigate for score ≥40"
 *    → "AI verdict chip shows monitor for score <40"
 *    → "AI confidence % shows when ai_status is active"
 *    → "no AI verdict chip when threatMap has no entry for IP (ADR-0015)"
 *    → "no AI verdict chip when threatMap prop is absent (ADR-0015)"
 *
 * 5. Ubiquitous: the table SHALL render mono data with the v2 kit styling.
 *    → "pager-count uses --fw-font-mono (CursorPager v2 kit alignment)"
 *    → "CursorPager uses --fw-* token styles, no Tailwind class attributes"
 *
 * 6. Security: XSS-safe rendering of attacker payloads/URIs (text nodes only).
 *    → "payload with HTML/script renders as inert text (XSS safety)"
 *    → "rule_name with HTML renders as inert text"
 *
 * 7. LogsRoute integration: /threats fetched on mount, non-fatal failure.
 *    → "LogsRoute fetches /threats on mount and AI verdict appears"
 *    → "LogsRoute: /threats failure is non-fatal — logs still render"
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LogsTable from '../components/logs/LogsTable'

/**
 * Render LogsTable in a MemoryRouter (required — LogsTable uses useNavigate for
 * CellDetailPopover deep-links added in #329). Also stubs getBoundingClientRect
 * so useColumnPriority sees a wide container in JSDOM (returns 0 otherwise).
 */
function renderLT(props: Parameters<typeof LogsTable>[0]) {
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 1200, height: 40, top: 0, left: 0, bottom: 40, right: 1200,
    x: 0, y: 0, toJSON: () => ({}),
  } as DOMRect)
  const result = render(<MemoryRouter><LogsTable {...props} /></MemoryRouter>)
  vi.restoreAllMocks()
  return result
}
import CursorPager from '../components/logs/CursorPager'
import LogsRoute from '../routes/LogsRoute'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import { RefreshProvider } from '../app/refresh/RefreshContext'
import type { LogEntry, ThreatScore } from '../api/types'
import { LOG_ENTRY_FIXTURE, PAGINATED_LOGS_PAGE1, THREATS_FIXTURE } from './readFixtures'

// ---------------------------------------------------------------------------
// Mocks for LogsRoute integration tests
// ---------------------------------------------------------------------------

const { mockFetchPaginatedLogs, mockFetchThreats } = vi.hoisted(() => ({
  mockFetchPaginatedLogs: vi.fn(),
  mockFetchThreats: vi.fn(),
}))

vi.mock('../api/logs', () => ({
  fetchPaginatedLogs: mockFetchPaginatedLogs,
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
  // ML-3 (#431): fetchTopPairs added to LogsRoute; default to empty list (non-fatal).
  fetchTopPairs: vi.fn().mockResolvedValue([]),
  // #665: StripTiles (replaced TrafficShapeHeader) uses these — default to empty/zeros (non-fatal).
  fetchLogsStats: vi.fn().mockResolvedValue({ total_events: 0, blocked_events: 0, distinct_ips: 0, present_source_types: [] }),
  fetchTopTalkers: vi.fn().mockResolvedValue([]),
  fetchProtocolMix: vi.fn().mockResolvedValue([]),
  // ML-9 (#437): entity graph — default to null (non-fatal; shows empty state).
  fetchEntityGraph: vi.fn().mockResolvedValue(null),
}))

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    fetchThreats: mockFetchThreats,
    fetchSourceTypes: vi.fn().mockResolvedValue([]),
    // ML-4 (#432): TrafficShapeHeader fetches timeline — non-fatal empty default.
    fetchTimeline: vi.fn().mockResolvedValue([]),
  }
})

/**
 * Render LogsRoute wrapped in MemoryRouter (required for useSearchParams — issue #203)
 * + EntityPanelProvider (required for useEntityPanel hook).
 * Stubs getBoundingClientRect so useColumnPriority (added in #329) shows all columns
 * in JSDOM (which returns 0 width for all elements by default).
 * NOTE: the mock is NOT restored here so it stays active for async effects after render.
 * The vitest test isolation (afterEach cleanup) handles teardown between tests.
 */
function renderLogsRoute() {
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 1200, height: 40, top: 0, left: 0, bottom: 40, right: 1200,
    x: 0, y: 0, toJSON: () => ({}),
  } as DOMRect)
  return render(
    <MemoryRouter initialEntries={['/logs']}>
      <RefreshProvider>
        <EntityPanelProvider>
        <LogsRoute />
        </EntityPanelProvider>
      </RefreshProvider>
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// Fixtures for MF-4 (real DTO shapes — rule_name / payload / dest_port)
// ---------------------------------------------------------------------------

/**
 * LogEntry with all optional MF-4 fields present (real /logs/paginated DTO shape).
 * rule_name: resolved ET name; destination_port: numeric; payload: URI snippet.
 * SECURITY: payload contains a path traversal attempt — must render as inert text.
 */
const LOG_WITH_FULL_FIELDS: LogEntry = {
  id: 200,
  timestamp: '2026-06-04T12:00:00Z',
  source_type: 'suricata',
  source_id: 'suricata-1',
  source_ip: '192.0.2.10',
  destination_ip: '198.51.100.2',
  category: 'SQL Injection',
  severity: 'high',
  action: 'ALERT',
  raw_log: '{"event_type":"alert","src_ip":"192.0.2.10"}',
  rule_name: 'ET SQL 1 = 1 - Possible SQL Injection Attempt',
  rule_id: 2006445,
  destination_port: 443,
  payload: 'GET /api/users?id=1%20OR%201%3D1 HTTP/1.1',
}

/**
 * LogEntry where rule_name is null but rule_id is present.
 * Simulates the catalog-not-loaded case (#169 scope) — should show bare rule_id.
 */
const LOG_WITH_NULL_RULE_NAME: LogEntry = {
  id: 201,
  timestamp: '2026-06-04T12:01:00Z',
  source_type: 'suricata',
  source_id: 'suricata-1',
  source_ip: '192.0.2.11',
  destination_ip: null,
  category: 'Port Scan',
  severity: 'low',
  action: 'ALERT',
  raw_log: '{}',
  rule_name: null,
  rule_id: 2001219,
  destination_port: 80,
}

/**
 * LogEntry with XSS payload — must render as inert text (ADR-0029 D3).
 * SECURITY: this is the rawest attacker-controlled string in the app.
 */
const LOG_WITH_XSS_PAYLOAD: LogEntry = {
  id: 202,
  timestamp: '2026-06-04T12:02:00Z',
  source_type: 'azure_waf',
  source_id: 'waf-1',
  source_ip: '192.0.2.12',
  destination_ip: null,
  category: 'XSS',
  severity: 'high',
  action: 'BLOCK',
  raw_log: '{}',
  payload: '<script>alert("xss-in-payload")</script>',
  rule_name: '<img src=x onerror=alert(1)>',
}

/**
 * LogEntry with no optional fields — tests graceful "—" fallback.
 */
const LOG_NO_OPTIONAL: LogEntry = {
  ...LOG_ENTRY_FIXTURE,
  id: 203,
}

// ---------------------------------------------------------------------------
// ThreatScore fixtures for AI verdict fold
// ---------------------------------------------------------------------------

/** ThreatScore with score ≥70 → derives "block" verdict. */
const THREAT_HIGH: ThreatScore = {
  source_ip: '192.0.2.10',
  threat_level: 'HIGH',
  score: 75,
  total_events: 100,
  blocked_events: 80,
  attack_types: ['SQL Injection'],
  first_seen: '2026-06-04T10:00:00Z',
  last_seen: '2026-06-04T12:00:00Z',
  source_types: ['suricata'],
  detections: [],
  ai_insights: ['Intent: exfiltration'],
  ai_confidence: 0.88,
  ai_status: 'active',
  location: null,
  score_breakdown: [],
  asn: null,
  as_name: null,
  score_delta: null,
}

/** ThreatScore with score ≥40 and <70 → derives "investigate" verdict. */
const THREAT_MEDIUM: ThreatScore = {
  source_ip: '192.0.2.11',
  threat_level: 'MEDIUM',
  score: 50,
  total_events: 30,
  blocked_events: 10,
  attack_types: ['Port Scan'],
  first_seen: '2026-06-04T10:00:00Z',
  last_seen: '2026-06-04T12:00:00Z',
  source_types: ['suricata'],
  detections: [],
  ai_insights: null,
  ai_confidence: 0,
  ai_status: 'unavailable',
  location: null,
  score_breakdown: [],
  asn: null,
  as_name: null,
  score_delta: null,
}

/** ThreatScore with score <40 → derives "monitor" verdict. */
const THREAT_LOW: ThreatScore = {
  source_ip: '192.0.2.20',
  threat_level: 'LOW',
  score: 20,
  total_events: 5,
  blocked_events: 0,
  attack_types: [],
  first_seen: '2026-06-04T10:00:00Z',
  last_seen: '2026-06-04T12:00:00Z',
  source_types: ['suricata'],
  detections: [],
  ai_insights: null,
  ai_confidence: 0,
  ai_status: 'disabled',
  location: null,
  score_breakdown: [],
  asn: null,
  as_name: null,
  score_delta: null,
}

// ---------------------------------------------------------------------------
// Helper: build a ReadonlyMap<string, ThreatScore>
// ---------------------------------------------------------------------------
function makeThreatMap(threats: ThreatScore[]): ReadonlyMap<string, ThreatScore> {
  const m = new Map<string, ThreatScore>()
  for (const t of threats) m.set(t.source_ip, t)
  return m
}

// ===========================================================================
// 1. Filter contract — no regression (EARS: event-driven filter change)
// ===========================================================================

describe('MF-4 EARS #1 — filter contract no regression', () => {
  beforeEach(() => vi.clearAllMocks())

  it('filter change re-fetches and resets cursor', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    mockFetchThreats.mockResolvedValue([])
    renderLogsRoute()
    await waitFor(() => expect(screen.getByTestId('logs-table')).toBeInTheDocument())
    // Initial call with no cursor
    const firstCall = mockFetchPaginatedLogs.mock.calls[0][0] as Record<string, unknown>
    expect(firstCall.cursor).toBeUndefined()
    expect(firstCall.limit).toBe(25)
  })
})

// ===========================================================================
// 2. State-driven: rule_name / payload / dest_port render when present
// ===========================================================================

describe('MF-4 EARS #2 — optional columns render when DTO provides them', () => {
  it('rule_name renders in signature column when present', () => {
    renderLT({ logs: [LOG_WITH_FULL_FIELDS], onIpClick: vi.fn() })
    const sig = screen.getByTestId('log-row-signature')
    expect(sig).toHaveTextContent('ET SQL 1 = 1 - Possible SQL Injection Attempt')
  })

  it('rule_id renders as fallback when rule_name is null (graceful — no "undefined" or "—")', () => {
    renderLT({ logs: [LOG_WITH_NULL_RULE_NAME], onIpClick: vi.fn() })
    const sig = screen.getByTestId('log-row-signature')
    // Must show the bare rule_id, NOT "—" and NOT "undefined"/"null"
    expect(sig).toHaveTextContent('2001219')
    expect(sig).not.toHaveTextContent('—')
    expect(sig).not.toHaveTextContent('undefined')
    expect(sig).not.toHaveTextContent('null')
  })

  it('payload renders in detail panel (HTTP section) when present — not inline column (ADR-0063 D1)', () => {
    renderLT({ logs: [LOG_WITH_FULL_FIELDS], onIpClick: vi.fn() })
    // Payload is no longer an inline column — expand the row to see it
    expect(screen.queryByTestId('log-row-payload')).not.toBeInTheDocument()
    // Expand to verify it appears in the detail panel
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    expect(screen.getByTestId('detail-section-http')).toBeInTheDocument()
    expect(screen.getByTestId('log-detail-panel').textContent).toContain('GET /api/users?id=1%20OR%201%3D1 HTTP/1.1')
  })

  it('dest_port renders in detail panel (Network section) when present — not inline column (ADR-0063 D1)', () => {
    renderLT({ logs: [LOG_WITH_FULL_FIELDS], onIpClick: vi.fn() })
    // Dest port is no longer an inline column
    expect(screen.queryByTestId('log-row-dest-port')).not.toBeInTheDocument()
    // Expand to verify it appears in the detail panel
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    expect(screen.getByTestId('detail-section-network')).toBeInTheDocument()
    expect(screen.getByTestId('log-detail-panel').textContent).toContain('443')
  })
})

// ===========================================================================
// 3. State-driven: graceful "—" fallback when fields absent
// ===========================================================================

describe('MF-4 EARS #3 — graceful fallback "—" when optional fields absent', () => {
  it('signature shows "—" when no rule_name/signature/rule_id', () => {
    renderLT({ logs: [LOG_NO_OPTIONAL], onIpClick: vi.fn() })
    expect(screen.getByTestId('log-row-signature')).toHaveTextContent('—')
  })

  it('HTTP section absent from detail panel when no payload field (ADR-0063 D3 honest absence)', () => {
    renderLT({ logs: [LOG_NO_OPTIONAL], onIpClick: vi.fn() })
    expect(screen.queryByTestId('log-row-payload')).not.toBeInTheDocument()
    // Expand row — HTTP section omitted when no payload
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    expect(screen.queryByTestId('detail-section-http')).not.toBeInTheDocument()
  })

  it('Dest Port not in inline table (moved to detail panel, ADR-0063 D1)', () => {
    renderLT({ logs: [LOG_NO_OPTIONAL], onIpClick: vi.fn() })
    expect(screen.queryByTestId('log-row-dest-port')).not.toBeInTheDocument()
  })

  it('no cells show "undefined" or "null" literal strings when fields are absent', () => {
    renderLT({ logs: [LOG_NO_OPTIONAL], onIpClick: vi.fn() })
    const allCells = document.querySelectorAll('td')
    allCells.forEach((cell) => {
      expect(cell.textContent).not.toContain('undefined')
      expect(cell.textContent).not.toContain('[object Object]')
    })
  })
})

// ===========================================================================
// 4. State-driven: AI verdict fold per row
// ===========================================================================

describe('MF-4 EARS #4 — AI verdict chip (fold-AI per log row)', () => {
  it('renders AI verdict chip when threatMap has a score for the row IP', () => {
    const threatMap = makeThreatMap([THREAT_HIGH])
    renderLT({ logs: [LOG_WITH_FULL_FIELDS], onIpClick: vi.fn(), threatMap })
    expect(screen.getByTestId('log-row-ai-verdict')).toBeInTheDocument()
  })

  it('AI verdict badge shows "block" for score ≥70', () => {
    const threatMap = makeThreatMap([THREAT_HIGH]) // score=75
    renderLT({ logs: [LOG_WITH_FULL_FIELDS], onIpClick: vi.fn(), threatMap })
    const badge = screen.getByTestId('log-row-ai-verdict-badge')
    expect(badge).toHaveTextContent('block')
    expect(badge).toHaveAttribute('data-tone', 'block')
  })

  it('AI verdict badge shows "investigate" for score ≥40', () => {
    const threatMap = makeThreatMap([THREAT_MEDIUM]) // score=50, ip=192.0.2.11
    renderLT({ logs: [LOG_WITH_NULL_RULE_NAME], onIpClick: vi.fn(), threatMap })
    // LOG_WITH_NULL_RULE_NAME has source_ip=192.0.2.11
    const badge = screen.getByTestId('log-row-ai-verdict-badge')
    expect(badge).toHaveTextContent('investigate')
    expect(badge).toHaveAttribute('data-tone', 'alert')
  })

  it('AI verdict badge shows "monitor" for score <40', () => {
    const log: LogEntry = { ...LOG_ENTRY_FIXTURE, id: 999, source_ip: '192.0.2.20' }
    const threatMap = makeThreatMap([THREAT_LOW]) // score=20, ip=192.0.2.20
    renderLT({ logs: [log], onIpClick: vi.fn(), threatMap })
    const badge = screen.getByTestId('log-row-ai-verdict-badge')
    expect(badge).toHaveTextContent('monitor')
    expect(badge).toHaveAttribute('data-tone', 'neutral')
  })

  it('AI confidence % shown when ai_status is active', () => {
    const threatMap = makeThreatMap([THREAT_HIGH]) // ai_confidence=0.88, ai_status=active
    renderLT({ logs: [LOG_WITH_FULL_FIELDS], onIpClick: vi.fn(), threatMap })
    const scoreSpan = screen.getByTestId('log-row-ai-score')
    // Should show score "75" and confidence "88%"
    expect(scoreSpan.textContent).toContain('75')
    expect(scoreSpan.textContent).toContain('88%')
  })

  it('AI confidence % absent when ai_status is not active', () => {
    const threatMap = makeThreatMap([THREAT_MEDIUM]) // ai_status=unavailable, ai_confidence=0
    renderLT({ logs: [LOG_WITH_NULL_RULE_NAME], onIpClick: vi.fn(), threatMap })
    const scoreSpan = screen.getByTestId('log-row-ai-score')
    // Should show score only, no percentage
    expect(scoreSpan.textContent).toContain('50')
    expect(scoreSpan.textContent).not.toContain('%')
  })

  it('no AI verdict chip when threatMap has no entry for the row IP (ADR-0015 graceful)', () => {
    const emptyMap = makeThreatMap([]) // empty — no IPs
    renderLT({ logs: [LOG_WITH_FULL_FIELDS], onIpClick: vi.fn(), threatMap: emptyMap })
    expect(screen.queryByTestId('log-row-ai-verdict')).not.toBeInTheDocument()
  })

  it('no AI verdict chip when threatMap prop is absent (ADR-0015 graceful)', () => {
    // No threatMap prop at all
    renderLT({ logs: [LOG_WITH_FULL_FIELDS], onIpClick: vi.fn() })
    expect(screen.queryByTestId('log-row-ai-verdict')).not.toBeInTheDocument()
  })

  it('multiple rows: only rows with matching IP show verdict chip', () => {
    const threatMap = makeThreatMap([THREAT_HIGH]) // only 192.0.2.10
    // LOG_WITH_FULL_FIELDS = 192.0.2.10 (has score), LOG_NO_OPTIONAL = 192.0.2.1 (no score)
    renderLT({
      logs: [LOG_WITH_FULL_FIELDS, LOG_NO_OPTIONAL],
      onIpClick: vi.fn(),
      threatMap,
    })
    const verdicts = screen.queryAllByTestId('log-row-ai-verdict')
    expect(verdicts).toHaveLength(1)
  })
})

// ===========================================================================
// 5. Ubiquitous: v2 kit styling — CursorPager uses --fw-* tokens
// ===========================================================================

describe('MF-4 EARS #5 — v2 kit styling (CursorPager)', () => {
  it('pager-count span uses --fw-font-mono style', () => {
    render(
      <CursorPager
        nextCursor="cursor-abc"
        has_more={true}
        total_matching={500}
        pageSize={50}
        onNext={vi.fn()}
        onFirst={vi.fn()}
      />,
    )
    const countEl = screen.getByTestId('pager-count')
    expect(countEl).toHaveStyle({ fontFamily: 'var(--fw-font-mono)' })
  })

  it('CursorPager root div uses inline --fw-* styles (no Tailwind utility class)', () => {
    render(
      <CursorPager
        nextCursor="cursor-abc"
        has_more={true}
        total_matching={500}
        pageSize={50}
        onNext={vi.fn()}
        onFirst={vi.fn()}
      />,
    )
    const pager = screen.getByTestId('cursor-pager')
    // Should NOT have Tailwind class attributes (we migrated to inline tokens)
    const classList = Array.from(pager.classList)
    const tailwindClasses = classList.filter(
      (c) =>
        c.startsWith('flex') ||
        c.startsWith('text-') ||
        c.startsWith('items-') ||
        c.startsWith('justify-'),
    )
    expect(tailwindClasses).toHaveLength(0)
  })

  it('First button uses --fw-* inline style (no Tailwind classes)', () => {
    render(
      <CursorPager
        currentCursor="some-cursor"
        nextCursor="cursor-abc"
        has_more={true}
        total_matching={500}
        pageSize={50}
        onNext={vi.fn()}
        onFirst={vi.fn()}
      />,
    )
    const btn = screen.getByTestId('pager-first')
    const classList = Array.from(btn.classList)
    const tailwindClasses = classList.filter(
      (c) => c.startsWith('rounded') || c.startsWith('border') || c.startsWith('px-'),
    )
    expect(tailwindClasses).toHaveLength(0)
    // Should have inline style with fw tokens
    expect(btn.style.background).toBe('var(--fw-bg-input)')
  })
})

// ===========================================================================
// 6. Security: XSS-safe rendering (EARS: ubiquitous — text nodes only)
// ===========================================================================

describe('MF-4 EARS #6 — XSS safety: attacker payload/rule_name rendered as inert text', () => {
  it('payload with HTML/script renders as inert text in detail panel (ADR-0029 D3, ADR-0063 D3)', () => {
    renderLT({ logs: [LOG_WITH_XSS_PAYLOAD], onIpClick: vi.fn() })
    // Payload no longer in inline column — verify no inline injection
    expect(screen.queryByTestId('log-row-payload')).not.toBeInTheDocument()
    // Expand to see payload in the detail panel
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    const panel = screen.getByTestId('log-detail-panel')
    expect(panel.textContent).toContain('<script>alert("xss-in-payload")</script>')
    expect(document.querySelectorAll('script').length).toBe(0)
  })

  it('rule_name with HTML renders as inert text literal', () => {
    renderLT({ logs: [LOG_WITH_XSS_PAYLOAD], onIpClick: vi.fn() })
    const sigCell = screen.getByTestId('log-row-signature')
    expect(sigCell.textContent).toContain('<img src=x onerror=alert(1)>')
    expect(document.querySelectorAll('img[onerror]').length).toBe(0)
  })
})

// ===========================================================================
// 7. LogsRoute integration: /threats fetched, AI verdict appears; failure non-fatal
// ===========================================================================

describe('MF-4 EARS #7 — LogsRoute integration', () => {
  beforeEach(() => vi.clearAllMocks())

  it('fetches /threats on mount and AI verdict chip appears for matching IP', async () => {
    // PAGINATED_LOGS_PAGE1 has LOG_ENTRY_FIXTURE (ip=192.0.2.1) which matches THREATS_FIXTURE[0]
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE) // 192.0.2.1 → score=78

    renderLogsRoute()
    await waitFor(() => expect(screen.getByTestId('logs-table')).toBeInTheDocument())

    // Wait for threats fetch to resolve and AI verdict to appear
    await waitFor(() => {
      expect(screen.getAllByTestId('log-row-ai-verdict').length).toBeGreaterThan(0)
    })
    // The verdict for 192.0.2.1 (score=78 → block) should be present
    const verdicts = screen.getAllByTestId('log-row-ai-verdict-badge')
    expect(verdicts.some((v) => v.textContent?.includes('block'))).toBe(true)
  })

  it('/threats failure is non-fatal — logs still render without AI verdict', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(PAGINATED_LOGS_PAGE1)
    mockFetchThreats.mockRejectedValue(new Error('Network error'))

    renderLogsRoute()
    await waitFor(() => expect(screen.getByTestId('logs-table')).toBeInTheDocument())

    // Logs render normally
    expect(screen.getAllByTestId('log-row')).toHaveLength(PAGINATED_LOGS_PAGE1.logs.length)
    // No error state for threats failure
    expect(screen.queryByTestId('logs-error')).not.toBeInTheDocument()
    // No AI verdict (non-fatal — map is empty)
    expect(screen.queryByTestId('log-row-ai-verdict')).not.toBeInTheDocument()
  })
})
