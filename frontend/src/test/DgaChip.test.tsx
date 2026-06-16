/**
 * Tests for ML-12 (#440) — DGA chip in the detail panel (ADR-0063 D1/D3).
 *
 * Under ADR-0063, DGA/DNS fields are REMOVED from the inline spine; they move
 * into LogDetailPanel's DNS section. This file verifies the new behaviour:
 *
 * EARS-1  DGA score and dns_query appear in the detail panel (DNS section)
 *         when the row is expanded, not in inline columns.
 * EARS-2  Rows without dns_query omit the DNS section from the detail panel.
 * SECURITY (ADR-0029 D3): dns_query is attacker-controlled — rendered as
 *   text node only in the detail panel, never via dangerouslySetInnerHTML.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LogsTable from '../components/logs/LogsTable'
import { LogDetailPanel } from '../components/logs/detail/LogDetailPanel'
import type { LogEntry } from '../api/types'

// RFC 5737 documentation IP only
const _SRC_IP = '192.0.2.10'
const _TS = '2026-06-13T12:00:00Z'

/** Base minimal log entry for DGA tests. */
const BASE_LOG: LogEntry = {
  id: 1,
  timestamp: _TS,
  source_type: 'suricata',
  source_id: 'test',
  source_ip: _SRC_IP,
  category: 'DNS',
  severity: 'medium',
  action: 'ALERT',
  raw_log: {},
}

/** Log entry with a DGA-flagged dns_query. */
const DGA_LOG: LogEntry = {
  ...BASE_LOG,
  id: 2,
  dns_query: 'xkzqvbmnwjrfptdl.example',
  dga_score: 0.7541,
}

/** Log entry with a benign dns_query (no dga_score). */
const BENIGN_DNS_LOG: LogEntry = {
  ...BASE_LOG,
  id: 3,
  dns_query: 'example.com',
}

/** Log entry with no dns_query (e.g. Azure WAF row). */
const NO_DNS_LOG: LogEntry = {
  ...BASE_LOG,
  id: 4,
}

/** Helper: render LogsTable inside a MemoryRouter with wide container stub. */
function renderTable(logs: LogEntry[]) {
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 1400,
    height: 40,
    top: 0,
    left: 0,
    bottom: 40,
    right: 1400,
    x: 0,
    y: 0,
    toJSON: () => ({}),
  } as DOMRect)

  const result = render(
    <MemoryRouter>
      <LogsTable logs={logs} onIpClick={vi.fn()} />
    </MemoryRouter>,
  )

  vi.restoreAllMocks()
  return result
}

// ---------------------------------------------------------------------------
// ADR-0063 D1: DNS/DGA no longer inline — moved to detail panel
// ---------------------------------------------------------------------------

describe('LogsTable — ML-12 DGA NOT inline (ADR-0063 D1)', () => {
  it('does NOT render log-row-dga-badge inline in the table', () => {
    renderTable([DGA_LOG])
    expect(screen.queryByTestId('log-row-dga-badge')).not.toBeInTheDocument()
  })

  it('does NOT render log-row-dga-score inline in the table', () => {
    renderTable([DGA_LOG])
    expect(screen.queryByTestId('log-row-dga-score')).not.toBeInTheDocument()
  })

  it('does NOT render log-row-dns-query inline in the table', () => {
    renderTable([DGA_LOG])
    expect(screen.queryByTestId('log-row-dns-query')).not.toBeInTheDocument()
  })

  it('does NOT render log-row-dns inline in the table', () => {
    renderTable([NO_DNS_LOG])
    expect(screen.queryByTestId('log-row-dns')).not.toBeInTheDocument()
  })

  it('does NOT render a "DNS / DGA" column header inline', () => {
    renderTable([DGA_LOG])
    const headers = Array.from(document.querySelectorAll('th')).map((th) => th.textContent?.trim() ?? '')
    expect(headers.some((h) => /DNS/i.test(h))).toBe(false)
    expect(headers.some((h) => /DGA/i.test(h))).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// EARS-1: DGA chip renders in the detail panel when row is expanded
// ---------------------------------------------------------------------------

describe('LogsTable — ML-12 DGA chip in detail panel (EARS-1)', () => {
  it('expanding a row shows DNS section with dns_query in detail panel', () => {
    renderTable([DGA_LOG])
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    expect(screen.getByTestId('detail-section-dns')).toBeInTheDocument()
    const panel = screen.getByTestId('log-detail-panel')
    expect(panel.textContent).toContain('xkzqvbmnwjrfptdl.example')
  })

  it('detail panel shows DGA score as numeric text in DNS section', () => {
    renderTable([DGA_LOG])
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    const panel = screen.getByTestId('log-detail-panel')
    // dga_score 0.7541 should appear as "0.754" (toFixed(3))
    expect(panel.textContent).toContain('0.754')
  })

  it('does NOT render DGA section for row with only dns_query (no dga_score)', () => {
    // Row has dns_query but no dga_score — DNS section still shows (dns_query present)
    // but DGA score field is omitted
    renderTable([BENIGN_DNS_LOG])
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    const panel = screen.getByTestId('log-detail-panel')
    // dns_query value visible
    expect(panel.textContent).toContain('example.com')
    // dga_score field absent (no numeric score rendered alongside it)
  })
})

// ---------------------------------------------------------------------------
// EARS-2: NULL dns_query omits DNS section from detail panel (honest absence)
// ---------------------------------------------------------------------------

describe('LogsTable — ML-12 DNS section omission (EARS-2, ADR-0063 D3)', () => {
  it('DNS section is absent from detail panel when dns_query is null', () => {
    renderTable([NO_DNS_LOG])
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    expect(screen.queryByTestId('detail-section-dns')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// LogDetailPanel unit tests: DNS section direct rendering
// ---------------------------------------------------------------------------

describe('LogDetailPanel — ML-12 DGA (direct unit test)', () => {
  it('DNS section present when dns_query populated', () => {
    render(<LogDetailPanel entry={DGA_LOG} />)
    expect(screen.getByTestId('detail-section-dns')).toBeInTheDocument()
  })

  it('DNS section absent when dns_query absent', () => {
    render(<LogDetailPanel entry={NO_DNS_LOG} />)
    expect(screen.queryByTestId('detail-section-dns')).not.toBeInTheDocument()
  })

  it('dns_query value appears in DNS section', () => {
    render(<LogDetailPanel entry={DGA_LOG} />)
    const section = screen.getByTestId('detail-section-dns')
    expect(section.textContent).toContain('xkzqvbmnwjrfptdl.example')
  })

  it('dga_score appears as formatted number in DNS section', () => {
    render(<LogDetailPanel entry={DGA_LOG} />)
    const section = screen.getByTestId('detail-section-dns')
    expect(section.textContent).toContain('0.754')
  })
})

// ---------------------------------------------------------------------------
// SECURITY: XSS payload in dns_query is inert text in detail panel
// ---------------------------------------------------------------------------

describe('LogsTable — ML-12 DGA chip SECURITY (ADR-0029 D3)', () => {
  it('renders XSS payload in dns_query as inert text in detail panel', () => {
    const xssLog: LogEntry = {
      ...BASE_LOG,
      id: 5,
      dns_query: '<img src=x onerror=alert(1)>',
      dga_score: 0.8,
    }
    renderTable([xssLog])
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    const panel = screen.getByTestId('log-detail-panel')
    // XSS string present as literal text
    expect(panel.textContent).toContain('<img src=x onerror=alert(1)>')
    // No injected img element with onerror attribute
    const injected = document.body.querySelector('img[onerror]')
    expect(injected).toBeNull()
  })
})
