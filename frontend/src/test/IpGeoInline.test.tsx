/**
 * Tests for inline geo rendering in LogsTable and BlockedLogsPanel (issue #334).
 *
 * EARS criteria:
 *   GR1  WHEN a public IP with cached geo renders in a Source IP cell of LogsTable,
 *        the cell SHALL show flag + city/country inline as a text node.
 *   GR2  WHEN geo is unknown (null fields), LogsTable SHALL show the bare IP only.
 *   GR3  WHEN a public IP with cached geo renders in BlockedLogsPanel,
 *        the geo suffix span (data-testid="blocked-log-ip-geo") SHALL be present.
 *   GR4  WHEN geo is unknown, BlockedLogsPanel SHALL show NO geo suffix span.
 *   GR5  The flag SHALL NOT appear without its text pair (text node guard).
 *   GR6  SECURITY: geo fields are attacker-controlled GeoIP values — no HTML injection.
 *
 * RFC 5737 IPs only (203.0.113.0/24, 192.0.2.0/24).
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LogsTable from '../components/logs/LogsTable'
import BlockedLogsPanel from '../components/dashboard/BlockedLogsPanel'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import type { LogEntry, PaginatedLogs, CategoryCount } from '../api/types'

// ---------------------------------------------------------------------------
// Mocks for BlockedLogsPanel dependencies
// ---------------------------------------------------------------------------

const mockFetchPaginatedLogs = vi.fn()
const mockFetchCategories = vi.fn()
const mockNavigate = vi.fn()

vi.mock('../api/logs', () => ({
  fetchPaginatedLogs: (...args: unknown[]) => mockFetchPaginatedLogs(...args),
}))

vi.mock('../api/client', () => ({
  fetchCategories: (...args: unknown[]) => mockFetchCategories(...args),
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  resolveBaseUrl: () => '',
  assertLoopbackBase: () => {},
  ApiError: class ApiError extends Error {
    status: number
    detail: unknown
    constructor(status: number, detail: unknown, message?: string) {
      super(message ?? `API error ${status}`)
      this.status = status
      this.detail = detail
    }
  },
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return { ...actual, useNavigate: () => mockNavigate }
})

// ---------------------------------------------------------------------------
// Fixtures — RFC 5737 IPs only
// ---------------------------------------------------------------------------

/** Log entry with geo cached (Germany / Frankfurt am Main). */
const LOG_WITH_GEO: LogEntry = {
  id: 1,
  timestamp: '2026-06-04T10:00:00Z',
  source_type: 'suricata',
  source_id: 'suricata-1',
  source_ip: '203.0.113.10',
  category: 'SQL Injection',
  severity: 'high',
  action: 'BLOCK',
  raw_log: '{}',
  geo_city: 'Frankfurt am Main',
  geo_country: 'DE',
}

/** Log entry with NO geo cached. */
const LOG_WITHOUT_GEO: LogEntry = {
  id: 2,
  timestamp: '2026-06-04T10:01:00Z',
  source_type: 'suricata',
  source_id: 'suricata-1',
  source_ip: '203.0.113.20',
  category: 'XSS',
  severity: 'medium',
  action: 'BLOCK',
  raw_log: '{}',
  geo_city: null,
  geo_country: null,
}

/** Log entry with XSS-payload geo (security test). */
const LOG_WITH_XSS_GEO: LogEntry = {
  id: 3,
  timestamp: '2026-06-04T10:02:00Z',
  source_type: 'suricata',
  source_id: 'suricata-1',
  source_ip: '192.0.2.1',
  category: 'XSS',
  severity: 'critical',
  action: 'BLOCK',
  raw_log: '{}',
  geo_city: '<script>alert(1)</script>',
  geo_country: '<img src=x onerror=alert(1)>',
}

// ---------------------------------------------------------------------------
// LogsTable — geo rendering
// ---------------------------------------------------------------------------

describe('LogsTable — GR1: Source IP cell shows inline geo when cached', () => {
  it('renders flag + city + country for a cached-geo IP', () => {
    render(<LogsTable logs={[LOG_WITH_GEO]} onIpClick={vi.fn()} />)
    const ipBtn = screen.getByTestId('log-row-ip')
    // Should contain the IP plus geo text
    expect(ipBtn).toHaveTextContent('203.0.113.10')
    expect(ipBtn.textContent).toContain('Frankfurt am Main')
    expect(ipBtn.textContent).toContain('DE')
    // Flag emoji for DE should be present
    expect(ipBtn.textContent).toContain('\u{1F1E9}\u{1F1EA}')
  })

  it('renders ip + flag + geo in the correct format', () => {
    render(<LogsTable logs={[LOG_WITH_GEO]} onIpClick={vi.fn()} />)
    const ipBtn = screen.getByTestId('log-row-ip')
    expect(ipBtn.textContent).toBe('203.0.113.10 \u{1F1E9}\u{1F1EA} (Frankfurt am Main, DE)')
  })
})

describe('LogsTable — GR2: Source IP cell shows bare IP when geo is unknown', () => {
  it('renders only the bare IP when geo_city and geo_country are null', () => {
    render(<LogsTable logs={[LOG_WITHOUT_GEO]} onIpClick={vi.fn()} />)
    const ipBtn = screen.getByTestId('log-row-ip')
    expect(ipBtn.textContent).toBe('203.0.113.20')
  })
})

describe('LogsTable — GR5: flag always paired with text', () => {
  it('when geo is shown, flag is accompanied by (City, Country) text', () => {
    render(<LogsTable logs={[LOG_WITH_GEO]} onIpClick={vi.fn()} />)
    const ipBtn = screen.getByTestId('log-row-ip')
    const text = ipBtn.textContent ?? ''
    const flagIdx = text.indexOf('\u{1F1E9}\u{1F1EA}')
    expect(flagIdx).toBeGreaterThan(-1)
    // Text must follow the flag within the same string
    expect(text.slice(flagIdx)).toContain('(')
  })
})

describe('LogsTable — GR6: SECURITY — geo fields rendered as inert text', () => {
  it('XSS in geo_city renders as literal text, not live HTML', () => {
    render(<LogsTable logs={[LOG_WITH_XSS_GEO]} onIpClick={vi.fn()} />)
    const ipBtn = screen.getByTestId('log-row-ip')
    expect(ipBtn.textContent).toContain('<script>')
    // No live <script> elements injected
    expect(document.querySelectorAll('script[src]').length).toBe(0)
  })

  it('XSS in geo_country renders as literal text, not live HTML', () => {
    render(<LogsTable logs={[LOG_WITH_XSS_GEO]} onIpClick={vi.fn()} />)
    // No img with onerror attribute injected
    expect(document.querySelectorAll('img[onerror]').length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// BlockedLogsPanel — geo rendering
// ---------------------------------------------------------------------------

/** Wrap BlockedLogsPanel with required providers. */
function renderPanel() {
  const categories: CategoryCount[] = [
    { category: 'all', count: 0 },
  ]
  const paginatedLogs: PaginatedLogs = {
    logs: [LOG_WITH_GEO, LOG_WITHOUT_GEO],
    next_cursor: null,
    has_more: false,
    total_matching: 2,
  }
  mockFetchCategories.mockResolvedValue(categories)
  mockFetchPaginatedLogs.mockResolvedValue(paginatedLogs)

  return render(
    <MemoryRouter>
      <EntityPanelProvider>
        <BlockedLogsPanel ipSearch="" />
      </EntityPanelProvider>
    </MemoryRouter>
  )
}

describe('BlockedLogsPanel — GR3: geo suffix shown for cached-geo IP', () => {
  it('renders geo suffix span when geo_city/geo_country are present', async () => {
    renderPanel()
    // Wait for async data load
    const geoSpan = await screen.findAllByTestId('blocked-log-ip-geo')
    expect(geoSpan.length).toBeGreaterThan(0)
    const firstGeo = geoSpan[0]
    expect(firstGeo.textContent).toContain('Frankfurt am Main')
    expect(firstGeo.textContent).toContain('DE')
    expect(firstGeo.textContent).toContain('\u{1F1E9}\u{1F1EA}')
  })
})

describe('BlockedLogsPanel — GR4: no geo suffix for unknown-geo IP', () => {
  it('the second row (no geo) must not have a geo suffix span', async () => {
    renderPanel()
    // Load rows
    await screen.findAllByTestId('blocked-log-row')
    // There should be exactly 1 geo suffix span (only the first row has geo)
    const geoSpans = screen.queryAllByTestId('blocked-log-ip-geo')
    expect(geoSpans).toHaveLength(1)
  })
})
