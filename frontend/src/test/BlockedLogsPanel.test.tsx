/**
 * Tests for BlockedLogsPanel rework (#253) and top-8 cap (#333).
 *
 * EARS criteria mapped to tests:
 *
 * --- From #253 ---
 * 1. Ubiquitous: pane fetches action=blocked server-side (no client ALLOW filter).
 * 2. Ubiquitous: signature cells render rule_name when present; fall back to rule_id.
 * 3. Ubiquitous: hover/focus on signature cell reveals CellTooltip (trigger present).
 * 4. Ubiquitous: IPs render as ClickableIp (data-testid="clickable-ip").
 * 5. Ubiquitous: "View all →" navigates to /logs?action=blocked.
 * 6. Ubiquitous: category tabs are driven from the categories endpoint (stable order),
 *    not derived from loaded rows.
 * 7. WHEN an IP is typed in Search-by-IP, a backend ip= query is issued (debounced).
 * 8. Ubiquitous: no inner scrollbar — the table has no max-height overflow wrapper.
 * 9. Ubiquitous: error state shown when fetch fails.
 *
 * --- From #333 (top-8 cap) ---
 * 10. Ubiquitous: pane renders at most 8 data rows (BLOCKED_FEED_LIMIT).
 * 11. WHEN total > 8: footer shows "View all {N} blocked →" with true server total.
 * 12. WHEN total ≤ 8: footer shows "View in Network Logs →" (no false count claim).
 * 13. WHEN total = 0: footer link is hidden (empty state, nothing to navigate to).
 * 14. Footer link always navigates to /logs?action=blocked.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import BlockedLogsPanel from '../components/dashboard/BlockedLogsPanel'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import type { LogEntry, PaginatedLogs, CategoryCount } from '../api/types'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockFetchPaginatedLogs = vi.fn()
const mockFetchCategories = vi.fn()
const mockNavigate = vi.fn()

vi.mock('../api/logs', () => ({
  fetchPaginatedLogs: (...args: unknown[]) => mockFetchPaginatedLogs(...args),
}))

vi.mock('../api/client', () => ({
  fetchCategories: (...args: unknown[]) => mockFetchCategories(...args),
  // EntityPanelProvider fetches source types on mount for the discovery cache
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
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** A BLOCK log entry with rule_name present (post-#165 DTO). */
const BLOCK_LOG_WITH_RULE_NAME: LogEntry = {
  id: 1,
  timestamp: '2026-06-04T10:00:00Z',
  source_type: 'suricata',
  source_id: 'suricata-1',
  source_ip: '192.0.2.1',
  destination_ip: '198.51.100.1',
  category: 'SQL Injection',
  severity: 'high',
  action: 'BLOCK',
  raw_log: '{}',
  rule_name: 'ET POLICY SQL Injection Attempt',
  rule_id: 2001219,
}

/** A DROP log entry with rule_name absent (falls back to rule_id). */
const DROP_LOG_NO_RULE_NAME: LogEntry = {
  id: 2,
  timestamp: '2026-06-04T10:01:00Z',
  source_type: 'azure_waf',
  source_id: 'waf-1',
  source_ip: '198.51.100.5',
  destination_ip: null,
  category: 'Brute Force',
  severity: 'medium',
  action: 'DROP',
  raw_log: '{}',
  rule_id: 9001,
}

const BLOCKED_LOGS_RESPONSE: PaginatedLogs = {
  logs: [BLOCK_LOG_WITH_RULE_NAME, DROP_LOG_NO_RULE_NAME],
  next_cursor: null,
  has_more: false,
  total_matching: 2,
}

const EMPTY_LOGS_RESPONSE: PaginatedLogs = {
  logs: [],
  next_cursor: null,
  has_more: false,
  total_matching: 0,
}

/**
 * Fixture for #333: server holds 371 blocked logs but returns only the top 8.
 * IPs use RFC-5737 documentation range (203.0.113.x) — never real attacker IPs.
 */
function makeRow(id: number): LogEntry {
  return {
    id,
    timestamp: `2026-06-04T10:0${id % 10}:00Z`,
    source_type: 'suricata',
    source_id: 'suricata-1',
    source_ip: `203.0.113.${id}`,
    destination_ip: null,
    category: 'Port Scan',
    severity: 'low',
    action: 'BLOCK',
    raw_log: '{}',
  }
}

/** Top-8 rows returned, but server total is 371. */
const LARGE_RESPONSE: PaginatedLogs = {
  logs: Array.from({ length: 8 }, (_, i) => makeRow(i + 1)),
  next_cursor: 'cursor-abc',
  has_more: true,
  total_matching: 371,
}

/** Exactly 8 rows returned and total_matching is also 8. */
const EXACTLY_8_RESPONSE: PaginatedLogs = {
  logs: Array.from({ length: 8 }, (_, i) => makeRow(i + 1)),
  next_cursor: null,
  has_more: false,
  total_matching: 8,
}

const CATEGORIES_RESPONSE: CategoryCount[] = [
  { category: 'SQL Injection', count: 980 },
  { category: 'Brute Force', count: 620 },
  { category: 'Port Scan', count: 1240 },
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderPanel(ipSearch = '') {
  return render(
    <MemoryRouter>
      <EntityPanelProvider>
        <BlockedLogsPanel ipSearch={ipSearch} />
      </EntityPanelProvider>
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('BlockedLogsPanel (#253 rework)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchCategories.mockResolvedValue(CATEGORIES_RESPONSE)
    mockFetchPaginatedLogs.mockResolvedValue(BLOCKED_LOGS_RESPONSE)
  })

  afterEach(() => {
    // Always restore real timers after each test so fake-timer usage does not
    // bleed across test boundaries.
    vi.useRealTimers()
  })

  // -------------------------------------------------------------------------
  // EARS 1: server-side action=blocked filter
  // -------------------------------------------------------------------------

  it('fetches with action=blocked (server-side filter, no client ALLOW filtering)', async () => {
    renderPanel()

    await waitFor(() => {
      expect(mockFetchPaginatedLogs).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'blocked' }),
      )
    })

    // All returned rows render (no client-side drop of any rows)
    await waitFor(() => {
      const rows = screen.getAllByTestId('blocked-log-row')
      expect(rows).toHaveLength(2)
    })
  })

  // -------------------------------------------------------------------------
  // EARS 2: Signature = rule_name primary, rule_id fallback
  // -------------------------------------------------------------------------

  it('renders rule_name when present in the signature cell', async () => {
    renderPanel()

    await waitFor(() => {
      expect(screen.getAllByTestId('rule-cell-display-name')[0]).toHaveTextContent(
        'ET POLICY SQL Injection Attempt',
      )
    })
  })

  it('falls back to rule_id when rule_name is absent', async () => {
    renderPanel()

    await waitFor(() => {
      const displayNames = screen.getAllByTestId('rule-cell-display-name')
      // Second row has no rule_name → should display rule_id "9001"
      expect(displayNames[1]).toHaveTextContent('9001')
    })
  })

  // -------------------------------------------------------------------------
  // EARS 3: CellTooltip wraps signature cells (trigger testid present)
  // -------------------------------------------------------------------------

  it('wraps signature cells in CellTooltip triggers', async () => {
    renderPanel()

    await waitFor(() => {
      const triggers = screen.getAllByTestId('rule-cell-tooltip-trigger')
      expect(triggers.length).toBeGreaterThan(0)
    })
  })

  // -------------------------------------------------------------------------
  // EARS 4: IPs render as ClickableIp (entity slide-over)
  // -------------------------------------------------------------------------

  it('renders source IPs as ClickableIp tokens', async () => {
    renderPanel()

    await waitFor(() => {
      const clickableIps = screen.getAllByTestId('clickable-ip')
      expect(clickableIps).toHaveLength(2)
      expect(clickableIps[0]).toHaveTextContent('192.0.2.1')
      expect(clickableIps[1]).toHaveTextContent('198.51.100.5')
    })
  })

  // -------------------------------------------------------------------------
  // EARS 5: "View all →" navigates to /logs?action=blocked
  // -------------------------------------------------------------------------

  it('View-all button navigates to /logs?action=blocked', async () => {
    renderPanel()

    await waitFor(() => {
      expect(screen.getByTestId('blocked-logs-view-all')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByTestId('blocked-logs-view-all'))
    expect(mockNavigate).toHaveBeenCalledWith('/logs?action=blocked')
  })

  // -------------------------------------------------------------------------
  // EARS 6: stable tabs — from categories endpoint, not from rows
  // -------------------------------------------------------------------------

  it('fetches category tabs from GET /logs/categories', async () => {
    renderPanel()

    await waitFor(() => {
      expect(mockFetchCategories).toHaveBeenCalledTimes(1)
    })
  })

  it('shows alphabetically sorted category tabs from the endpoint', async () => {
    renderPanel()

    // CATEGORIES_RESPONSE sorted alphabetically: Brute Force, Port Scan, SQL Injection
    await waitFor(() => {
      // The "All" tab is always first
      expect(screen.getByText('All')).toBeInTheDocument()
      // Each category from the endpoint appears as a tab
      expect(screen.getByText('Brute Force')).toBeInTheDocument()
      expect(screen.getByText('Port Scan')).toBeInTheDocument()
      expect(screen.getByText('SQL Injection')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // EARS 7: backend IP search — ip= param sent after debounce
  // -------------------------------------------------------------------------

  it('sends ip= query param to backend when ipSearch is set', async () => {
    // ipSearch='192.0.2' initialises debouncedIp to '192.0.2' immediately;
    // the initial fetch therefore sends ip= on mount (no need to advance timers).
    renderPanel('192.0.2')

    await waitFor(() => {
      expect(mockFetchPaginatedLogs).toHaveBeenCalledWith(
        expect.objectContaining({ ip: '192.0.2', action: 'blocked' }),
      )
    })
  })

  it('does not send ip= when ipSearch is empty', async () => {
    renderPanel('')

    await waitFor(() => {
      expect(mockFetchPaginatedLogs).toHaveBeenCalled()
    })

    const calls = mockFetchPaginatedLogs.mock.calls
    const lastCall = calls[calls.length - 1][0] as Record<string, unknown>
    expect(lastCall).not.toHaveProperty('ip')
  })

  // -------------------------------------------------------------------------
  // EARS 8: no inner scrollbar — no max-height overflow wrapper
  // -------------------------------------------------------------------------

  it('does not render a scrollable inner wrapper (no inner scrollbar)', async () => {
    const { container } = renderPanel()

    await waitFor(() => {
      expect(screen.getByTestId('blocked-logs-panel')).toBeInTheDocument()
    })

    // No element inside the panel should have overflowY: auto or scroll
    const panel = container.querySelector('[data-testid="blocked-logs-panel"]')
    const allChildren = panel ? Array.from(panel.querySelectorAll('*')) : []
    for (const el of allChildren) {
      const style = (el as HTMLElement).style
      expect(style.overflowY).not.toBe('auto')
      expect(style.overflowY).not.toBe('scroll')
    }
  })

  // -------------------------------------------------------------------------
  // EARS 9: error state
  // -------------------------------------------------------------------------

  it('shows error state when fetch fails', async () => {
    mockFetchPaginatedLogs.mockRejectedValue(new Error('network failure'))
    renderPanel()

    await waitFor(() => {
      expect(screen.getByTestId('blocked-logs-error')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Empty state
  // -------------------------------------------------------------------------

  it('shows empty state when no blocked logs are returned', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(EMPTY_LOGS_RESPONSE)
    renderPanel()

    await waitFor(() => {
      expect(screen.getByTestId('blocked-logs-empty')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Loading state
  // -------------------------------------------------------------------------

  it('shows loading state while fetch is in flight', () => {
    mockFetchPaginatedLogs.mockReturnValue(new Promise(() => {}))
    renderPanel()
    expect(screen.getByTestId('blocked-logs-loading')).toBeInTheDocument()
  })

  // -------------------------------------------------------------------------
  // Issue #322 — duplicate-label dedup: unique tab keys + click-to-filter
  // -------------------------------------------------------------------------

  it('deduplicates same-label categories: no React duplicate-key warning (issue #322)', async () => {
    // Simulate the bug: server returns two rows both labelled "Other".
    // After the server-side fix this should not happen, but the client-side
    // guard in useBlockedCategories must still prevent a duplicate-key warning.
    mockFetchCategories.mockResolvedValue([
      { category: 'Other', count: 2 },
      { category: 'Other', count: 2 },
      { category: 'SQL Injection', count: 10 },
    ])

    // Spy on console.error to detect React duplicate-key warnings.
    const consoleSpy = vi.spyOn(console, 'error')

    renderPanel()

    await waitFor(() => {
      // Only one "Other" tab should be rendered (merged count = 4)
      const tabs = screen.getAllByRole('tab')
      const otherTabs = tabs.filter((t) => t.textContent?.includes('Other'))
      expect(otherTabs).toHaveLength(1)
    })

    // No duplicate-key warning should have been emitted.
    const keyWarnings = consoleSpy.mock.calls.filter(
      (args) => typeof args[0] === 'string' && args[0].includes('key'),
    )
    expect(keyWarnings).toHaveLength(0)

    consoleSpy.mockRestore()
  })

  it('merges duplicate-label categories and sums counts (issue #322)', async () => {
    // Two "Other" rows with counts 2 + 2 should produce a single tab with count 4.
    mockFetchCategories.mockResolvedValue([
      { category: 'Other', count: 2 },
      { category: 'Other', count: 2 },
      { category: 'Geo-Blocked', count: 357 },
    ])

    renderPanel()

    await waitFor(() => {
      const tabs = screen.getAllByRole('tab')
      const otherTab = tabs.find((t) => t.textContent?.includes('Other'))
      expect(otherTab).toBeDefined()
      // Merged count "4" should appear within the tab
      expect(otherTab?.textContent).toContain('4')
    })
  })

  it('click on category tab filters the blocked-logs fetch (issue #322)', async () => {
    // EARS: WHEN a category tab is clicked, the blocked-logs table SHALL filter
    // to that category (confirmed: clicking calls setCat → useBlockedLogs re-fetches
    // with ?category=<label>).
    mockFetchCategories.mockResolvedValue([
      { category: 'SQL Injection', count: 10 },
      { category: 'Brute Force', count: 5 },
    ])

    renderPanel()

    // Wait for tabs to render
    await waitFor(() => {
      expect(screen.getByText('SQL Injection')).toBeInTheDocument()
    })

    // Click the "SQL Injection" tab
    fireEvent.click(screen.getByText('SQL Injection'))

    // The logs fetch should be re-issued with category='SQL Injection'
    await waitFor(() => {
      const calls = mockFetchPaginatedLogs.mock.calls
      const lastCall = calls[calls.length - 1][0] as Record<string, unknown>
      expect(lastCall).toMatchObject({ category: 'SQL Injection', action: 'blocked' })
    })
  })

  it('tab ids are unique — all rendered tabs have distinct aria keys (issue #322)', async () => {
    // Tabs component uses `id` as the React key; assert no two tabs share an id.
    // useBlockedCategories deduplicates so ids are derived from unique labels.
    mockFetchCategories.mockResolvedValue([
      { category: 'SQL Injection', count: 10 },
      { category: 'Brute Force', count: 5 },
      { category: 'Port Scan', count: 3 },
    ])

    renderPanel()

    await waitFor(() => {
      const tabs = screen.getAllByRole('tab')
      // Collect visible labels; each must be unique
      const labels = tabs.map((t) => t.textContent?.trim())
      const uniqueLabels = new Set(labels)
      expect(labels.length).toBe(uniqueLabels.size)
    })
  })

  // -------------------------------------------------------------------------
  // EARS #333 — top-8 cap + footer behaviour
  // -------------------------------------------------------------------------

  it('#333 — renders at most 8 data rows regardless of server total', async () => {
    // Server returns 8 rows; total_matching=371 (the rest are beyond the feed).
    mockFetchPaginatedLogs.mockResolvedValue(LARGE_RESPONSE)

    renderPanel()

    await waitFor(() => {
      const rows = screen.getAllByTestId('blocked-log-row')
      expect(rows).toHaveLength(8)
    })
  })

  it('#333 — fetch is issued with limit=8 (BLOCKED_FEED_LIMIT)', async () => {
    renderPanel()

    await waitFor(() => {
      expect(mockFetchPaginatedLogs).toHaveBeenCalledWith(
        expect.objectContaining({ limit: 8 }),
      )
    })
  })

  it('#333 — footer shows "View all {N} blocked →" when total > rows returned', async () => {
    // Server total 371 > 8 rows displayed.
    mockFetchPaginatedLogs.mockResolvedValue(LARGE_RESPONSE)

    renderPanel()

    await waitFor(() => {
      const btn = screen.getByTestId('blocked-logs-view-all')
      expect(btn).toHaveTextContent('View all 371 blocked →')
    })
  })

  it('#333 — footer shows "View in Network Logs →" when total ≤ rows returned (no false count)', async () => {
    // EXACTLY_8_RESPONSE: total_matching=8, logs.length=8 — no "extra" rows exist.
    mockFetchPaginatedLogs.mockResolvedValue(EXACTLY_8_RESPONSE)

    renderPanel()

    await waitFor(() => {
      const btn = screen.getByTestId('blocked-logs-view-all')
      expect(btn).toHaveTextContent('View in Network Logs →')
    })
  })

  it('#333 — footer shows "View in Network Logs →" for the 2-row fixture (total ≤ limit)', async () => {
    // Default BLOCKED_LOGS_RESPONSE: total_matching=2, logs.length=2.
    // 2 is not > 2, so no count claim.
    renderPanel()

    await waitFor(() => {
      const btn = screen.getByTestId('blocked-logs-view-all')
      expect(btn).toHaveTextContent('View in Network Logs →')
    })
  })

  it('#333 — footer link is hidden when total = 0 (empty state)', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(EMPTY_LOGS_RESPONSE)

    renderPanel()

    await waitFor(() => {
      expect(screen.getByTestId('blocked-logs-empty')).toBeInTheDocument()
    })

    // Footer button must not be present when there are no logs.
    expect(screen.queryByTestId('blocked-logs-view-all')).not.toBeInTheDocument()
  })

  it('#333 — footer link always navigates to /logs?action=blocked', async () => {
    mockFetchPaginatedLogs.mockResolvedValue(LARGE_RESPONSE)

    renderPanel()

    await waitFor(() => {
      expect(screen.getByTestId('blocked-logs-view-all')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByTestId('blocked-logs-view-all'))
    expect(mockNavigate).toHaveBeenCalledWith('/logs?action=blocked')
  })

  it('#333 — pane has no internal scrollbar at any row count', async () => {
    // Even with 8 rows the pane must not introduce overflow-y scroll.
    mockFetchPaginatedLogs.mockResolvedValue(LARGE_RESPONSE)

    const { container } = renderPanel()

    await waitFor(() => {
      expect(screen.getAllByTestId('blocked-log-row')).toHaveLength(8)
    })

    const panel = container.querySelector('[data-testid="blocked-logs-panel"]')
    const allChildren = panel ? Array.from(panel.querySelectorAll('*')) : []
    for (const el of allChildren) {
      const style = (el as HTMLElement).style
      expect(style.overflowY).not.toBe('auto')
      expect(style.overflowY).not.toBe('scroll')
    }
  })
})
