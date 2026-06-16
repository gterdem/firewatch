/**
 * Tests for src/components/logs/LogsTable.tsx (#112, #329, ADR-0063)
 *
 * EARS criteria covered:
 *   - SECURITY (ADR-0029 D3): HTML/script payloads render as inert text, never live DOM.
 *   - ADR-0063 D1: Spine columns present: Time · Source · Source IP · Action · Severity ·
 *     Signature · AI Verdict + expand chevron.
 *   - ADR-0063 D1: Long-tail columns NOT inline (Dest Port, HTTP Payload, Destination,
 *     Protocol, JA4, DNS — all moved to the detail panel).
 *   - Action=ALERT renders with tone="alert" (solid orange, ADR-0012).
 *   - Action=BLOCK renders with tone="block" (red-tint).
 *   - Action=ALLOW renders with tone="allow" (green-tint).
 *   - IP click calls onIpClick with correct IP.
 *   - Empty logs → empty state message.
 *   - Mono font used for time, IP data cells.
 *
 * Note: LogsTable uses useNavigate (deep-link for CellDetailPopover) so all renders
 * must be wrapped in MemoryRouter.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LogsTable from '../components/logs/LogsTable'
import { LOG_ENTRY_FIXTURE, LOG_ENTRY_XSS_FIXTURE, PAGINATED_LOGS_PAGE1 } from './readFixtures'
import type { LogEntry } from '../api/types'

/** Helper: render LogsTable inside a MemoryRouter (required for useNavigate).
 * Also stubs getBoundingClientRect to return a large width so useColumnPriority
 * keeps all columns visible in JSDOM (which returns 0 for all layout dimensions).
 */
function renderTable(props: Parameters<typeof LogsTable>[0]) {
  // Stub getBoundingClientRect so the ResizeObserver-based useColumnPriority hook
  // sees a wide container and keeps all columns visible in JSDOM.
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 1200, height: 40, top: 0, left: 0, bottom: 40, right: 1200,
    x: 0, y: 0, toJSON: () => ({}),
  } as DOMRect)

  const result = render(
    <MemoryRouter>
      <LogsTable {...props} />
    </MemoryRouter>,
  )

  vi.restoreAllMocks()
  return result
}

// ---------------------------------------------------------------------------
// SECURITY tests
// ---------------------------------------------------------------------------

describe('LogsTable — SECURITY: attacker-controlled fields rendered as inert text', () => {
  /**
   * ADR-0063 D1 spine columns: Time · Source · Source IP · Action · Severity · Signature · AI Verdict.
   * LOG_ENTRY_XSS_FIXTURE has severity='<img src=x onerror=alert(1)>' — shown via Badge as text.
   * Category/raw_log are in the detail panel, not inline columns.
   */
  it('renders HTML/script payload in severity as inert literal text — never live HTML', () => {
    renderTable({ logs: [LOG_ENTRY_XSS_FIXTURE], onIpClick: vi.fn() })
    // The malicious severity string must appear as visible literal text
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    // No <img> element with onerror should exist from our payload
    expect(document.querySelectorAll('img[onerror]').length).toBe(0)
  })

  it('does not inject raw_log into the DOM as live HTML', () => {
    renderTable({ logs: [LOG_ENTRY_XSS_FIXTURE], onIpClick: vi.fn() })
    // raw_log is not shown in the table — verify it is NOT injected as live HTML
    expect(document.querySelector('script[data-xss]')).toBeNull()
    document.querySelectorAll('script').forEach((el) => {
      expect(el.textContent).not.toContain('xss-in-raw-log')
    })
  })

  it('source IP with malicious content renders as inert text button', () => {
    const xssIp: LogEntry = {
      ...LOG_ENTRY_XSS_FIXTURE,
      id: 99,
      source_ip: '<script>alert(1)</script>',
    }
    renderTable({ logs: [xssIp], onIpClick: vi.fn() })
    const ipBtn = screen.getByTestId('log-row-ip')
    // The script tag must appear as literal text, not executed
    expect(ipBtn.textContent).toBe('<script>alert(1)</script>')
    expect(document.querySelectorAll('script').length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Kit columns
// ---------------------------------------------------------------------------

describe('LogsTable — spine column headers (ADR-0063 D1)', () => {
  it('renders 7 spine column headers + expand affordance; no long-tail columns inline', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    const headers = document.querySelectorAll('th')
    const headerTexts = Array.from(headers).map((th) => th.textContent ?? '')
    // Spine columns
    expect(headerTexts.some((t) => /Time/i.test(t))).toBe(true)
    expect(headerTexts.some((t) => t.trim() === 'Source')).toBe(true)
    expect(headerTexts.some((t) => /Source IP/i.test(t))).toBe(true)
    expect(headerTexts.some((t) => /Action/i.test(t))).toBe(true)
    expect(headerTexts.some((t) => /Severity/i.test(t))).toBe(true)
    expect(headerTexts.some((t) => /Signature/i.test(t))).toBe(true)
    expect(headerTexts.some((t) => /AI Verdict/i.test(t))).toBe(true)
    // Long-tail columns must NOT be inline (they live in the detail panel)
    expect(headerTexts).not.toContain('Dest Port')
    expect(headerTexts).not.toContain('HTTP Payload')
    expect(headerTexts.some((t) => /^Destination$/i.test(t.trim()))).toBe(false)
    expect(headerTexts.some((t) => /^Protocol$/i.test(t.trim()))).toBe(false)
    expect(headerTexts.some((t) => /^JA4$/i.test(t.trim()))).toBe(false)
    expect(headerTexts.some((t) => /^DNS \/ DGA$/i.test(t.trim()))).toBe(false)
  })
})

describe('LogsTable — canonical column rendering', () => {
  it('renders source via SourceBadge (data-source + data-tone attributes)', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    const badge = screen.getByTestId('log-row-source-badge')
    expect(badge).toHaveAttribute('data-source', 'suricata')
    // suricata → IDS tone
    expect(badge).toHaveAttribute('data-tone', 'ids')
    expect(badge).toHaveTextContent('IDS')
  })

  it('renders source IP as clickable button', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    expect(screen.getByTestId('log-row-ip')).toHaveTextContent('192.0.2.1')
  })

  it('renders severity via DS Badge with correct tone attribute', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    const badge = screen.getByTestId('log-row-severity-badge')
    expect(badge).toHaveAttribute('data-tone', 'high')
  })

  it('renders action via DS Badge with correct text', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    const badge = screen.getByTestId('log-row-action-badge')
    expect(badge).toHaveTextContent('blocked')
    expect(badge).toHaveAttribute('data-tone', 'block')
  })

  it('renders one row per log entry', () => {
    renderTable({ logs: PAGINATED_LOGS_PAGE1.logs, onIpClick: vi.fn() })
    expect(screen.getAllByTestId('log-row')).toHaveLength(PAGINATED_LOGS_PAGE1.logs.length)
  })
})

// ---------------------------------------------------------------------------
// Action badge tones (ADR-0012)
// ---------------------------------------------------------------------------

describe('LogsTable — Action badge tones', () => {
  function logWithAction(action: string | null): LogEntry {
    return { ...LOG_ENTRY_FIXTURE, id: 99, action }
  }

  it('ALERT action renders with tone="alert" (solid orange per ADR-0012)', () => {
    renderTable({ logs: [logWithAction('ALERT')], onIpClick: vi.fn() })
    expect(screen.getByTestId('log-row-action-badge')).toHaveAttribute('data-tone', 'alert')
  })

  it('alert (lowercase) renders with tone="alert"', () => {
    renderTable({ logs: [logWithAction('alert')], onIpClick: vi.fn() })
    expect(screen.getByTestId('log-row-action-badge')).toHaveAttribute('data-tone', 'alert')
  })

  it('BLOCK action renders with tone="block"', () => {
    renderTable({ logs: [logWithAction('BLOCK')], onIpClick: vi.fn() })
    expect(screen.getByTestId('log-row-action-badge')).toHaveAttribute('data-tone', 'block')
  })

  it('ALLOW action renders with tone="allow"', () => {
    renderTable({ logs: [logWithAction('ALLOW')], onIpClick: vi.fn() })
    expect(screen.getByTestId('log-row-action-badge')).toHaveAttribute('data-tone', 'allow')
  })

  it('DROP action renders with tone="drop"', () => {
    renderTable({ logs: [logWithAction('DROP')], onIpClick: vi.fn() })
    expect(screen.getByTestId('log-row-action-badge')).toHaveAttribute('data-tone', 'drop')
  })

  it('null action renders em-dash placeholder', () => {
    renderTable({ logs: [logWithAction(null)], onIpClick: vi.fn() })
    expect(screen.getByTestId('log-row-action-badge')).toHaveTextContent('—')
  })
})

// ---------------------------------------------------------------------------
// Fallback columns (dest port / signature / payload)
// ---------------------------------------------------------------------------

describe('LogsTable — spine column rendering (ADR-0063 D1)', () => {
  it('signature shows "—" when no rule_id / rule_name / signature field', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    const cell = screen.getByTestId('log-row-signature')
    expect(cell).toHaveTextContent('—')
  })

  it('renders rule_id as signature when present', () => {
    const logWithRule: LogEntry = { ...LOG_ENTRY_FIXTURE, id: 56, rule_id: 2001219 }
    renderTable({ logs: [logWithRule], onIpClick: vi.fn() })
    expect(screen.getByTestId('log-row-signature')).toHaveTextContent('2001219')
  })

  it('long-tail cells (dest-port, payload, dest-ip, protocol, JA4, DNS) are NOT in the table DOM', () => {
    const logWithAll: LogEntry = {
      ...LOG_ENTRY_FIXTURE,
      id: 57,
      destination_port: 443,
      payload_snippet: 'GET /api',
      protocol: 'TCP',
      tls_ja4: 'q13d0312h2_002f...',
      dns_query: 'example.com',
    }
    renderTable({ logs: [logWithAll], onIpClick: vi.fn() })
    // These test-ids should not exist in the inline table (moved to detail panel)
    expect(screen.queryByTestId('log-row-dest-port')).not.toBeInTheDocument()
    expect(screen.queryByTestId('log-row-payload')).not.toBeInTheDocument()
    expect(screen.queryByTestId('log-row-dest-ip')).not.toBeInTheDocument()
    expect(screen.queryByTestId('log-row-protocol')).not.toBeInTheDocument()
    expect(screen.queryByTestId('log-row-tls-ja4')).not.toBeInTheDocument()
    expect(screen.queryByTestId('log-row-dns')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

describe('LogsTable — empty state', () => {
  it('shows empty message when logs array is empty', () => {
    renderTable({ logs: [], onIpClick: vi.fn() })
    expect(screen.getByTestId('logs-empty')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// IP click interaction
// ---------------------------------------------------------------------------

describe('LogsTable — IP click', () => {
  it('calls onIpClick with correct IP string', () => {
    const onIpClick = vi.fn()
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick })
    fireEvent.click(screen.getByTestId('log-row-ip'))
    expect(onIpClick).toHaveBeenCalledTimes(1)
    expect(onIpClick).toHaveBeenCalledWith('192.0.2.1')
  })
})

// ---------------------------------------------------------------------------
// Mono font data cells
// ---------------------------------------------------------------------------

describe('LogsTable — mono data cells', () => {
  it('Source IP button uses --fw-font-mono', () => {
    renderTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    const ip = screen.getByTestId('log-row-ip')
    expect(ip).toHaveStyle({ fontFamily: 'var(--fw-font-mono)' })
  })
})

// ---------------------------------------------------------------------------
// Source IP tooltip content (walkthrough fix — tooltip must show IP + location)
// ---------------------------------------------------------------------------

describe('LogsTable — Source IP cell tooltip', () => {
  it('shows IP + geo city and country in title when geo is present', () => {
    const logWithGeo: LogEntry = {
      ...LOG_ENTRY_FIXTURE,
      id: 70,
      source_ip: '192.0.2.42',
      geo_city: 'Frankfurt am Main',
      geo_country: 'Germany',
    }
    renderTable({ logs: [logWithGeo], onIpClick: vi.fn() })
    // The <td> wrapping the IP button carries the title tooltip
    const ipBtn = screen.getByTestId('log-row-ip')
    const td = ipBtn.closest('td')!
    expect(td.title).toContain('192.0.2.42')
    expect(td.title).toContain('Frankfurt am Main')
    expect(td.title).toContain('Germany')
    // Should mention that no external lookup was performed
    expect(td.title).toContain('geo cached locally')
    // Primary info (IP + location) must NOT be buried — must appear before the suffix note
    expect(td.title.indexOf('192.0.2.42')).toBeLessThan(td.title.indexOf('geo cached locally'))
  })

  it('shows bare IP as title when no geo data is present', () => {
    const logNoGeo: LogEntry = { ...LOG_ENTRY_FIXTURE, id: 71, source_ip: '198.51.100.5' }
    renderTable({ logs: [logNoGeo], onIpClick: vi.fn() })
    const ipBtn = screen.getByTestId('log-row-ip')
    const td = ipBtn.closest('td')!
    expect(td.title).toBe('198.51.100.5')
    // No spurious "geo cached locally" text when there is no geo
    expect(td.title).not.toContain('geo cached locally')
  })
})
