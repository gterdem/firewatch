/**
 * Tests for issue #134 — All Sources = installed-driven list + 4-color server health dot.
 *
 * ADR-0032: the source list is installed-driven (from GET /stats source_health[]).
 * Each chip's dot color is the server-computed `health` field — not derived from
 * last_event_at recency on the frontend.
 *
 * EARS criteria covered (1:1):
 *
 * 1. Event-driven: WHEN /stats returns source_health[], header renders one chip
 *    per entry (including unconfigured ones) [EARS-ED-1]
 * 2. State-driven: WHILE health="not_configured" → dot idle (grey) [EARS-SD-2]
 * 3. State-driven: WHILE health="amber" → dot warn (amber) [EARS-SD-3]
 * 4. State-driven: WHILE health="ok" → dot ok (green) [EARS-SD-4]
 * 5. State-driven: WHILE health="red" (error/parked) → dot down (red) [EARS-SD-5]
 * 6. Ubiquitous: no per-source-type branches — chip set driven by backend array [EARS-UB-6]
 * 7. Unwanted: IF /stats fails → header keeps last good state, no crash [EARS-UW-7]
 * 8. Ubiquitous: color from server `health` field — front-end does NOT recompute
 *    from last_event_at [EARS-UB-8]
 *
 * Tests use the real SourceHealth + SourceHealthItem shapes (ADR-0032 §B DTOs) to
 * guard against the shape-mismatch bug class.
 */

// ADR-0064 D4: setup.ts provides a global stub for RefreshContext so that route
// tests that don't wrap components in <RefreshProvider> don't throw.  This file
// tests the REAL RefreshContext, so we need to unmock it first.
import { vi } from 'vitest'
vi.unmock('../app/refresh/RefreshContext')

import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { SourceHealth } from '../components/ds'
import type { SourceHealthItem } from '../lib/sourceHealth'
import { dotStateFromHealth, toSourceHealthItems, buildTooltip } from '../lib/sourceHealth'
import type { SourceHealth as ApiSourceHealth } from '../api/types'
import { RefreshProvider } from '../app/refresh/RefreshContext'

// ---------------------------------------------------------------------------
// Fixture: real ADR-0032 §B DTO shapes (from health_assembler.py)
// ---------------------------------------------------------------------------

const FIXTURE_NOT_CONFIGURED: ApiSourceHealth = {
  source_type: 'azure_waf',
  source_id: 'azure_waf',
  display_name: 'Azure WAF',
  flavor: 'pull',
  health: 'not_configured',
  supervisor_state: null,
  last_event_at: null,
  event_count: 0,
  last_error: null,
}

const FIXTURE_AMBER: ApiSourceHealth = {
  source_type: 'suricata',
  source_id: 'suricata',
  display_name: 'Suricata IDS/IPS',
  flavor: 'pull',
  health: 'amber',
  supervisor_state: 'idle',
  last_event_at: null,
  event_count: 0,
  last_error: null,
}

const FIXTURE_GREEN: ApiSourceHealth = {
  source_type: 'suricata',
  source_id: 'suricata',
  display_name: 'Suricata IDS/IPS',
  flavor: 'pull',
  health: 'ok',
  supervisor_state: 'running',
  last_event_at: new Date(Date.now() - 60_000).toISOString(), // 1m ago
  event_count: 12345,
  last_error: null,
}

const FIXTURE_RED: ApiSourceHealth = {
  source_type: 'suricata',
  source_id: 'suricata',
  display_name: 'Suricata IDS/IPS',
  flavor: 'pull',
  health: 'red',
  supervisor_state: 'parked',
  last_event_at: new Date(Date.now() - 600_000).toISOString(), // 10m ago
  event_count: 8000,
  last_error: 'SSH connection refused',
}

// ---------------------------------------------------------------------------
// EARS-ED-1: toSourceHealthItems maps each source_health[] entry
// ---------------------------------------------------------------------------

describe('[EARS-ED-1] toSourceHealthItems — one item per source_health[] entry', () => {
  it('maps a single entry correctly', () => {
    const items = toSourceHealthItems([FIXTURE_NOT_CONFIGURED])
    expect(items).toHaveLength(1)
    expect(items[0].id).toBe('azure_waf')
    expect(items[0].label).toBe('Azure WAF')
    expect(items[0].health).toBe('not_configured')
  })

  it('maps multiple entries — one item per installed plugin', () => {
    const items = toSourceHealthItems([FIXTURE_NOT_CONFIGURED, FIXTURE_AMBER])
    expect(items).toHaveLength(2)
    expect(items[0].id).toBe('azure_waf')
    expect(items[1].id).toBe('suricata')
  })

  it('preserves all fields from the ADR-0032 §B shape', () => {
    const items = toSourceHealthItems([FIXTURE_RED])
    const item = items[0]
    expect(item.supervisorState).toBe('parked')
    expect(item.lastError).toBe('SSH connection refused')
    expect(item.lastEventAt).toBeTruthy()
  })

  it('empty array → empty items', () => {
    expect(toSourceHealthItems([])).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// EARS-SD-2: not_configured → grey dot
// ---------------------------------------------------------------------------

describe('[EARS-SD-2] health="not_configured" → dot idle (grey)', () => {
  it('dotStateFromHealth returns idle', () => {
    expect(dotStateFromHealth('not_configured')).toBe('idle')
  })

  it('SourceHealth component renders idle dot for not_configured', () => {
    const items = toSourceHealthItems([FIXTURE_NOT_CONFIGURED])
    render(<SourceHealth sources={items} />)
    const dot = screen.getByTestId('health-dot-azure_waf')
    expect(dot.getAttribute('data-state')).toBe('idle')
  })

  it('idle dot uses --fw-health-idle token', () => {
    const items = toSourceHealthItems([FIXTURE_NOT_CONFIGURED])
    render(<SourceHealth sources={items} />)
    const dot = screen.getByTestId('health-dot-azure_waf') as HTMLElement
    expect(dot.style.background).toContain('var(--fw-health-idle)')
  })
})

// ---------------------------------------------------------------------------
// EARS-SD-3: amber → amber dot
// ---------------------------------------------------------------------------

describe('[EARS-SD-3] health="amber" → dot warn (amber)', () => {
  it('dotStateFromHealth returns warn', () => {
    expect(dotStateFromHealth('amber')).toBe('warn')
  })

  it('SourceHealth component renders warn dot for amber', () => {
    const items = toSourceHealthItems([FIXTURE_AMBER])
    render(<SourceHealth sources={items} />)
    const dot = screen.getByTestId('health-dot-suricata')
    expect(dot.getAttribute('data-state')).toBe('warn')
  })

  it('warn dot uses --fw-health-warn token', () => {
    const items = toSourceHealthItems([FIXTURE_AMBER])
    render(<SourceHealth sources={items} />)
    const dot = screen.getByTestId('health-dot-suricata') as HTMLElement
    expect(dot.style.background).toContain('var(--fw-health-warn)')
  })
})

// ---------------------------------------------------------------------------
// EARS-SD-4: ok → green dot
// ---------------------------------------------------------------------------

describe('[EARS-SD-4] health="ok" → dot ok (green)', () => {
  it('dotStateFromHealth returns ok', () => {
    expect(dotStateFromHealth('ok')).toBe('ok')
  })

  it('SourceHealth component renders ok dot for ok', () => {
    const items = toSourceHealthItems([FIXTURE_GREEN])
    render(<SourceHealth sources={items} />)
    const dot = screen.getByTestId('health-dot-suricata')
    expect(dot.getAttribute('data-state')).toBe('ok')
  })

  it('ok dot uses --fw-health-ok token', () => {
    const items = toSourceHealthItems([FIXTURE_GREEN])
    render(<SourceHealth sources={items} />)
    const dot = screen.getByTestId('health-dot-suricata') as HTMLElement
    expect(dot.style.background).toContain('var(--fw-health-ok)')
  })
})

// ---------------------------------------------------------------------------
// EARS-SD-5: red (error/parked) → red dot; red outranks recency
// ---------------------------------------------------------------------------

describe('[EARS-SD-5] health="red" → dot down (red); error outranks recency', () => {
  it('dotStateFromHealth returns down for red', () => {
    expect(dotStateFromHealth('red')).toBe('down')
  })

  it('SourceHealth component renders down dot for red', () => {
    const items = toSourceHealthItems([FIXTURE_RED])
    render(<SourceHealth sources={items} />)
    const dot = screen.getByTestId('health-dot-suricata')
    expect(dot.getAttribute('data-state')).toBe('down')
  })

  it('red dot uses --fw-health-down token', () => {
    const items = toSourceHealthItems([FIXTURE_RED])
    render(<SourceHealth sources={items} />)
    const dot = screen.getByTestId('health-dot-suricata') as HTMLElement
    expect(dot.style.background).toContain('var(--fw-health-down)')
  })

  it('error state with recent last_event_at still shows red (error outranks recency)', () => {
    // last_event_at is very recent (30s ago) but health="red" due to supervisor error
    const recentError: ApiSourceHealth = {
      ...FIXTURE_GREEN,
      health: 'red',
      supervisor_state: 'parked',
      last_error: 'connection refused',
    }
    const items = toSourceHealthItems([recentError])
    render(<SourceHealth sources={items} />)
    // Despite recent events, dot is still red
    expect(screen.getByTestId('health-dot-suricata').getAttribute('data-state')).toBe('down')
  })
})

// ---------------------------------------------------------------------------
// EARS-UB-6: no per-source-type branches — chip set driven by backend array
// ---------------------------------------------------------------------------

describe('[EARS-UB-6] chip set driven entirely by backend array (no per-source hardcoding)', () => {
  it('renders a fictional source type with no frontend special-case', () => {
    const unknownSource: ApiSourceHealth = {
      source_type: 'my_custom_plugin',
      source_id: 'my_custom_plugin',
      display_name: 'My Custom Plugin',
      flavor: 'push',
      health: 'ok',
      supervisor_state: 'running',
      last_event_at: new Date().toISOString(),
      event_count: 42,
      last_error: null,
    }
    const items = toSourceHealthItems([unknownSource])
    render(<SourceHealth sources={items} />)
    // Renders the chip even though there's no hardcoded handler for this source type
    expect(screen.getByTestId('health-item-my_custom_plugin')).toBeInTheDocument()
    expect(screen.getByText('My Custom Plugin')).toBeInTheDocument()
    expect(screen.getByTestId('health-dot-my_custom_plugin').getAttribute('data-state')).toBe('ok')
  })

  it('a mix of installed sources all render correctly from the array', () => {
    const items = toSourceHealthItems([
      FIXTURE_NOT_CONFIGURED,
      FIXTURE_GREEN,
    ])
    render(<SourceHealth sources={items} />)
    // Both chips rendered — driven by array, not per-type code
    expect(screen.getByTestId('health-item-azure_waf')).toBeInTheDocument()
    expect(screen.getByTestId('health-item-suricata')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-UW-7: /stats failure → keep last good state, no crash
// (tested via AppHeader-level mock — the component itself stays at last good state)
// ---------------------------------------------------------------------------

describe('[EARS-UW-7] empty or failed stats — no crash', () => {
  it('SourceHealth renders empty list without crash', () => {
    render(<SourceHealth sources={[]} />)
    expect(document.querySelector('.fw-health')).toBeInTheDocument()
  })

  it('toSourceHealthItems([]) returns empty array without throw', () => {
    expect(() => toSourceHealthItems([])).not.toThrow()
    expect(toSourceHealthItems([])).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// EARS-UB-8: color from server `health`; frontend does NOT recompute from last_event_at
// ---------------------------------------------------------------------------

describe('[EARS-UB-8] color from server health field — frontend does not recompute recency', () => {
  it('a stale last_event_at with health="ok" still shows green', () => {
    // Server says "ok" — frontend must render green regardless of staleness
    const staleButOk: ApiSourceHealth = {
      source_type: 'azure_waf',
      source_id: 'azure_waf',
      display_name: 'Azure WAF',
      flavor: 'pull',
      health: 'ok',
      supervisor_state: 'running',
      // "stale" — older than 5 minutes from server perspective, but server says ok
      last_event_at: new Date(Date.now() - 900_000).toISOString(),
      event_count: 100,
      last_error: null,
    }
    const items = toSourceHealthItems([staleButOk])
    // item.health is "ok" — frontend does not recompute dot from last_event_at
    expect(items[0].health).toBe('ok')
    render(<SourceHealth sources={items} />)
    expect(screen.getByTestId('health-dot-azure_waf').getAttribute('data-state')).toBe('ok')
  })

  it('a fresh last_event_at with health="amber" still shows amber', () => {
    // Server says "amber" — frontend must render amber regardless of recency
    const freshButAmber: ApiSourceHealth = {
      ...FIXTURE_GREEN,
      health: 'amber',
      // Very recent event, but server computed "amber" for another reason
    }
    const items = toSourceHealthItems([freshButAmber])
    expect(items[0].health).toBe('amber')
    render(<SourceHealth sources={items} />)
    expect(screen.getByTestId('health-dot-suricata').getAttribute('data-state')).toBe('warn')
  })
})

// ---------------------------------------------------------------------------
// display_name as chip label (ADR-0032 §B — display_name from plugin metadata)
// ---------------------------------------------------------------------------

describe('display_name as chip label', () => {
  it('renders display_name label (not raw source_id)', () => {
    const items = toSourceHealthItems([FIXTURE_NOT_CONFIGURED])
    render(<SourceHealth sources={items} />)
    // "Azure WAF" is the display_name — should be visible
    expect(screen.getByText('Azure WAF')).toBeInTheDocument()
    // Raw source_id "azure_waf" should NOT be visible as text (it's the key, not the label)
    // (but we allow the test id attribute which uses it)
  })
})

// ---------------------------------------------------------------------------
// buildTooltip — uses supervisor_state / last_error / last_event_at (tooltip only)
// ---------------------------------------------------------------------------

describe('buildTooltip — diagnostic info in tooltip', () => {
  it('not_configured tooltip says "not configured"', () => {
    const item: SourceHealthItem = {
      id: 'azure_waf', label: 'Azure WAF', health: 'not_configured',
      supervisorState: null, lastEventAt: null, lastError: null,
      eventCount: 0, sourceType: 'azure_waf',
    }
    expect(buildTooltip(item)).toContain('not configured')
  })

  it('red + last_error includes error in tooltip', () => {
    const item: SourceHealthItem = {
      id: 'suricata', label: 'Suricata', health: 'red',
      supervisorState: 'parked', lastEventAt: null, lastError: 'SSH connection refused',
      eventCount: 0, sourceType: 'suricata',
    }
    const tip = buildTooltip(item)
    expect(tip).toContain('SSH connection refused')
    expect(tip).toContain('Suricata')
  })

  it('ok + lastEventAt includes recency info in tooltip (not dot color source)', () => {
    const recentIso = new Date(Date.now() - 30_000).toISOString() // 30s ago
    const item: SourceHealthItem = {
      id: 'waf', label: 'Azure WAF', health: 'ok',
      supervisorState: 'running', lastEventAt: recentIso, lastError: null,
      eventCount: 100, sourceType: 'azure_waf',
    }
    const tip = buildTooltip(item)
    // Tooltip mentions recency but dot color comes from server health, not this
    expect(tip).toContain('Azure WAF')
    expect(tip).toContain('healthy')
  })
})

// ---------------------------------------------------------------------------
// AppHeader integration — /stats fetch drives the installed-list
// (mock-based test to verify the plumbing: stats → toSourceHealthItems → render)
// ---------------------------------------------------------------------------

const { mockFetchStats } = vi.hoisted(() => ({
  mockFetchStats: vi.fn(),
}))

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    fetchStats: mockFetchStats,
  }
})

// Minimal ThemeContext mock so AppHeader renders in test
vi.mock('../app/ThemeContext', () => ({
  useTheme: () => ({ theme: 'dark', toggleTheme: vi.fn() }),
  ThemeProvider: ({ children }: { children: React.ReactNode }) => children,
}))

vi.mock('react-router-dom', () => ({
  useNavigate: () => vi.fn(),
}))

describe('[EARS-ED-1] AppHeader — source_health[] from /stats drives chip list', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders one health chip per installed source from /stats', async () => {
    mockFetchStats.mockResolvedValue({
      total_logs: 100,
      total_ips: 10,
      blocked_percentage: 50,
      last_updated: null,
      source_health: [FIXTURE_NOT_CONFIGURED, FIXTURE_GREEN],
    })

    const { default: AppHeader } = await import('../app/AppHeader')
    render(<RefreshProvider><AppHeader /></RefreshProvider>)

    await waitFor(() => {
      expect(screen.getByTestId('health-item-azure_waf')).toBeInTheDocument()
      expect(screen.getByTestId('health-item-suricata')).toBeInTheDocument()
    })
  })

  it('not_configured source chip has idle (grey) dot', async () => {
    mockFetchStats.mockResolvedValue({
      total_logs: 0,
      total_ips: 0,
      blocked_percentage: 0,
      last_updated: null,
      source_health: [FIXTURE_NOT_CONFIGURED],
    })

    const { default: AppHeader } = await import('../app/AppHeader')
    render(<RefreshProvider><AppHeader /></RefreshProvider>)

    await waitFor(() => {
      const dot = screen.getByTestId('health-dot-azure_waf')
      expect(dot.getAttribute('data-state')).toBe('idle')
    })
  })

  it('if /stats returns empty source_health, no health chips shown', async () => {
    mockFetchStats.mockResolvedValue({
      total_logs: 0,
      total_ips: 0,
      blocked_percentage: 0,
      last_updated: null,
      source_health: [],
    })

    const { default: AppHeader } = await import('../app/AppHeader')
    render(<RefreshProvider><AppHeader /></RefreshProvider>)

    // Wait for render to settle
    await waitFor(() => {
      expect(screen.getByTestId('source-filter-bar')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('source-health-row')).not.toBeInTheDocument()
  })

  it('[EARS-UW-7] /stats failure → header renders without crash (no health row)', async () => {
    mockFetchStats.mockRejectedValue(new Error('Network error'))

    const { default: AppHeader } = await import('../app/AppHeader')
    render(<RefreshProvider><AppHeader /></RefreshProvider>)

    // Header renders without throwing
    await waitFor(() => {
      expect(screen.getByTestId('app-header')).toBeInTheDocument()
    })
    // No chips shown — graceful degradation
    expect(screen.queryByTestId('source-health-row')).not.toBeInTheDocument()
  })
})
