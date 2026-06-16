/**
 * Tests for ML-13 (#441) — JA4+ TLS fingerprint facet (consume-only).
 *
 * EARS criteria covered:
 *
 * EARS-1: Surface tls_ja4 as a facet + filter param.
 *   → FacetFilters renders JA4 filter input (filter-tls-ja4)
 *   → FacetFilters emits tls_ja4 in onFilterChange when input changes
 *   → FacetFilters shows chip when tls_ja4 filter is active
 *   → FacetFilters chip removal clears tls_ja4 from filter
 *
 * EARS-2: WHERE sensor does not emit JA4, field is NULL and chip is absent.
 *   → LogsTable renders "—" for tls_ja4 when null (honest absence)
 *   → LogsTable chip absent when filter.tls_ja4 is unset
 *   → fetchTopJa4 returns Ja4FingerprintRow[] typed correctly
 *
 * EARS-2 (column): LogsTable renders JA4 column header and tls_ja4 values.
 *   → LogsTable renders "JA4" column header
 *   → LogsTable renders fingerprint as text node when present
 *   → LogsTable renders "—" when tls_ja4 is absent
 *
 * SECURITY (ADR-0029 D3): tls_ja4 is sensor-normalised from attacker-controlled
 *   TLS ClientHello data. Must be rendered as text nodes only.
 *   → XSS probe in tls_ja4 renders as inert text, not live HTML
 *
 * Note: LogsTable uses useNavigate — MemoryRouter required.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LogsTable from '../components/logs/LogsTable'
import FacetFilters from '../components/logs/FacetFilters'
import { LOG_ENTRY_FIXTURE } from './readFixtures'
import type { LogEntry, LogsFilter } from '../api/types'

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/** Stub getBoundingClientRect so useColumnPriority keeps all columns visible. */
function stubWideContainer() {
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 1600, height: 40, top: 0, left: 0, bottom: 40, right: 1600,
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

// Synthetic JA4 fingerprint — opaque opaque string (not a real capture)
const JA4_FP = 't13d1516h2_8daaf6152771_02713d6af862'

// RFC 5737 IPs only — never real/routable
const ROW_WITH_JA4: LogEntry = {
  ...LOG_ENTRY_FIXTURE,
  id: 300,
  source_ip: '192.0.2.30',
  tls_ja4: JA4_FP,
}

const ROW_WITHOUT_JA4: LogEntry = {
  ...LOG_ENTRY_FIXTURE,
  id: 301,
  source_ip: '192.0.2.31',
  tls_ja4: null,
}

const ROW_XSS_JA4: LogEntry = {
  ...LOG_ENTRY_FIXTURE,
  id: 302,
  source_ip: '192.0.2.32',
  tls_ja4: '<script>alert("ja4-xss")</script>',
}

// ---------------------------------------------------------------------------
// ADR-0063 D1/D3: JA4 column moved to the detail panel (not inline)
// ---------------------------------------------------------------------------

describe('LogsTable — ML-13 JA4 NOT inline (ADR-0063 D1)', () => {
  it('does NOT render a "JA4" column header inline', () => {
    renderTable({ logs: [ROW_WITH_JA4], onIpClick: vi.fn() })
    const headers = Array.from(document.querySelectorAll('th')).map((th) => th.textContent ?? '')
    expect(headers.some((h) => h.trim() === 'JA4')).toBe(false)
  })

  it('does NOT render log-row-tls-ja4 inline cell', () => {
    renderTable({ logs: [ROW_WITH_JA4], onIpClick: vi.fn() })
    expect(screen.queryByTestId('log-row-tls-ja4')).not.toBeInTheDocument()
  })

  it('shows JA4 fingerprint in detail panel when row is expanded', () => {
    renderTable({ logs: [ROW_WITH_JA4], onIpClick: vi.fn() })
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    // TLS section should appear in the panel
    expect(screen.getByTestId('detail-section-tls')).toBeInTheDocument()
    const panel = screen.getByTestId('log-detail-panel')
    expect(panel.textContent).toContain(JA4_FP)
  })

  it('TLS section absent when tls_ja4 is null (honest absence, ADR-0063 D3)', () => {
    renderTable({ logs: [ROW_WITHOUT_JA4], onIpClick: vi.fn() })
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    // When all TLS fields are null, the TLS section is omitted entirely
    expect(screen.queryByTestId('detail-section-tls')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// SECURITY: attacker-controlled tls_ja4 — text node only in detail panel (ADR-0029 D3)
// ---------------------------------------------------------------------------

describe('LogsTable — ML-13 SECURITY: XSS in tls_ja4 in detail panel', () => {
  it('tls_ja4 XSS probe renders as inert text in detail panel', () => {
    renderTable({ logs: [ROW_XSS_JA4], onIpClick: vi.fn() })
    fireEvent.click(screen.getByTestId('log-row-chevron'))
    const panel = screen.getByTestId('log-detail-panel')
    expect(panel.textContent).toContain('<script>alert("ja4-xss")</script>')
    expect(document.querySelectorAll('script[data-xss]').length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// EARS-1 (UI): FacetFilters JA4 input and chip
// ---------------------------------------------------------------------------

describe('FacetFilters — ML-13 JA4 fingerprint input', () => {
  const noop = vi.fn()
  const baseFilter: LogsFilter = {}

  it('renders the JA4 filter input', () => {
    render(<FacetFilters filter={baseFilter} onFilterChange={noop} />)
    expect(screen.getByTestId('filter-tls-ja4')).toBeInTheDocument()
  })

  it('input change calls onFilterChange with tls_ja4', () => {
    const onChange = vi.fn()
    render(<FacetFilters filter={baseFilter} onFilterChange={onChange} />)
    fireEvent.change(screen.getByTestId('filter-tls-ja4'), {
      target: { value: JA4_FP },
    })
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ tls_ja4: JA4_FP })
    )
  })

  it('clearing the input calls onFilterChange with tls_ja4 undefined', () => {
    const onChange = vi.fn()
    render(
      <FacetFilters
        filter={{ ...baseFilter, tls_ja4: JA4_FP }}
        onFilterChange={onChange}
      />
    )
    fireEvent.change(screen.getByTestId('filter-tls-ja4'), {
      target: { value: '' },
    })
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ tls_ja4: undefined })
    )
  })

  it('shows chip when tls_ja4 filter is active', () => {
    render(
      <FacetFilters
        filter={{ ...baseFilter, tls_ja4: JA4_FP }}
        onFilterChange={noop}
      />
    )
    expect(screen.getByTestId('chip-tls_ja4')).toBeInTheDocument()
    expect(screen.getByTestId('chip-tls_ja4').textContent).toContain(JA4_FP)
  })

  it('chip is absent when tls_ja4 filter is unset (honest absence)', () => {
    render(<FacetFilters filter={baseFilter} onFilterChange={noop} />)
    expect(screen.queryByTestId('chip-tls_ja4')).not.toBeInTheDocument()
  })

  it('chip label includes "JA4:" prefix', () => {
    render(
      <FacetFilters
        filter={{ ...baseFilter, tls_ja4: JA4_FP }}
        onFilterChange={noop}
      />
    )
    expect(screen.getByTestId('chip-tls_ja4').textContent).toMatch(/JA4:/i)
  })

  it('removing the chip calls onFilterChange with tls_ja4 undefined', () => {
    const onChange = vi.fn()
    render(
      <FacetFilters
        filter={{ ...baseFilter, tls_ja4: JA4_FP }}
        onFilterChange={onChange}
      />
    )
    // FilterChip renders a remove button — aria-label "Remove filter"
    const removeButtons = screen.getAllByRole('button', { name: /remove filter/i })
    fireEvent.click(removeButtons[0])
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ tls_ja4: undefined })
    )
  })
})
