/**
 * Tests for F3 #109 — source + filter DS components and the sourceHealth adapter.
 *
 * EARS criteria covered (1:1 mapping):
 *
 * SourceBadge:
 *   - Ubiquitous: renders WAF/IDS/SYS/FILE in source hue; known source → correct label.
 *   - Ubiquitous: unknown source id → raw upper-cased id in neutral style (no crash).
 *
 * SourceHealth (ADR-0032 / issue #134 — dot now driven by server `health` field):
 *   - State-driven: health="ok" → dot state ok (green).
 *   - State-driven: health="amber" → dot state warn (amber).
 *   - State-driven: health="red" → dot state down (red).
 *   - State-driven: health="not_configured" → dot state idle (grey).
 *   - Ubiquitous: dot color from server health field, NOT recency.
 *
 * FilterChip:
 *   - Event-driven: WHEN ✕ clicked, onRemove fires.
 *   - Renders chip label.
 *
 * Combobox:
 *   - Event-driven: WHEN text is typed, options filter live.
 *   - Event-driven: WHEN option is picked, onChange fires and dropdown closes.
 *   - Event-driven: WHEN ✕ is clicked, value clears (onChange("", "")).
 *
 * EventTimeline:
 *   - Renders events from detections/source_types.
 *   - State-driven: correlated entry gets orange left-stripe + "correlated" label.
 *
 * sourceHealth adapter (lib/sourceHealth.ts — ADR-0032):
 *   - dotStateFromHealth: correct state for each server health value.
 *   - toSourceHealthItems: maps SourceHealth[] → SourceHealthItem[] correctly.
 *   - buildTooltip: includes supervisor_state/last_error when present.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import {
  SourceBadge,
  SourceHealth,
  SourceCard,
  EventTimeline,
  Combobox,
  FilterChip,
} from '../components/ds'

import {
  dotStateFromHealth,
  toSourceHealthItems,
  buildTooltip,
} from '../lib/sourceHealth'

// ---------------------------------------------------------------------------
// SourceBadge
// ---------------------------------------------------------------------------

describe('SourceBadge — hue mapping', () => {
  it.each([
    ['azure_waf', 'WAF', 'waf'],
    ['waf', 'WAF', 'waf'],
    ['suricata', 'IDS', 'ids'],
    ['ids', 'IDS', 'ids'],
    ['syslog', 'SYS', 'syslog'],
    ['file', 'FILE', 'file'],
  ] as const)('source "%s" renders label "%s" with tone "%s"', (source, label, tone) => {
    render(<SourceBadge source={source} />)
    const el = screen.getByText(label)
    expect(el).toBeInTheDocument()
    expect(el.getAttribute('data-tone')).toBe(tone)
  })

  it('unknown source id renders raw upper-cased id in neutral style', () => {
    render(<SourceBadge source="my_custom_plugin" />)
    const el = screen.getByText('MY_CUSTOM_PLUGIN')
    expect(el).toBeInTheDocument()
    expect(el.getAttribute('data-tone')).toBe('neutral')
  })

  it('does not crash on empty source', () => {
    render(<SourceBadge source="" />)
    expect(screen.getByText('?')).toBeInTheDocument()
  })

  it('blue tint for WAF', () => {
    render(<SourceBadge source="waf" />)
    const el = screen.getByText('WAF')
    expect(el.style.color).toContain('var(--fw-blue)')
  })

  it('orange tint for IDS', () => {
    render(<SourceBadge source="suricata" />)
    const el = screen.getByText('IDS')
    expect(el.style.color).toContain('var(--fw-orange)')
  })

  it('green tint for syslog', () => {
    render(<SourceBadge source="syslog" />)
    const el = screen.getByText('SYS')
    expect(el.style.color).toContain('var(--fw-green)')
  })

  it('purple tint for file', () => {
    render(<SourceBadge source="file" />)
    const el = screen.getByText('FILE')
    expect(el.style.color).toContain('var(--fw-purple)')
  })
})

// ---------------------------------------------------------------------------
// SourceHealth
// ---------------------------------------------------------------------------

describe('SourceHealth — dot states (ADR-0032: server health field)', () => {
  it('renders a dot item per source', () => {
    render(
      <SourceHealth
        sources={[
          { id: 'waf', label: 'Azure WAF', health: 'ok', supervisorState: null, lastEventAt: null, lastError: null, eventCount: 0, sourceType: 'waf' },
          { id: 'ids', label: 'Suricata IDS', health: 'not_configured', supervisorState: null, lastEventAt: null, lastError: null, eventCount: 0, sourceType: 'ids' },
        ]}
      />,
    )
    expect(screen.getByTestId('health-item-waf')).toBeInTheDocument()
    expect(screen.getByTestId('health-item-ids')).toBeInTheDocument()
  })

  it('health="ok" → dot state ok (green)', () => {
    render(<SourceHealth sources={[{ id: 'waf', label: 'WAF', health: 'ok', supervisorState: null, lastEventAt: null, lastError: null, eventCount: 0, sourceType: 'waf' }]} />)
    expect(screen.getByTestId('health-dot-waf').getAttribute('data-state')).toBe('ok')
  })

  it('health="amber" → dot state warn (amber)', () => {
    render(<SourceHealth sources={[{ id: 'ids', label: 'IDS', health: 'amber', supervisorState: null, lastEventAt: null, lastError: null, eventCount: 0, sourceType: 'ids' }]} />)
    expect(screen.getByTestId('health-dot-ids').getAttribute('data-state')).toBe('warn')
  })

  it('health="red" → dot state down (red)', () => {
    render(<SourceHealth sources={[{ id: 'sys', label: 'SYS', health: 'red', supervisorState: 'parked', lastEventAt: null, lastError: 'connection refused', eventCount: 0, sourceType: 'sys' }]} />)
    expect(screen.getByTestId('health-dot-sys').getAttribute('data-state')).toBe('down')
  })

  it('health="not_configured" → dot state idle (grey)', () => {
    render(<SourceHealth sources={[{ id: 'syslog', label: 'Syslog', health: 'not_configured', supervisorState: null, lastEventAt: null, lastError: null, eventCount: 0, sourceType: 'syslog' }]} />)
    expect(screen.getByTestId('health-dot-syslog').getAttribute('data-state')).toBe('idle')
  })

  it('ok dot uses --fw-health-ok color token', () => {
    render(<SourceHealth sources={[{ id: 'waf', label: 'WAF', health: 'ok', supervisorState: null, lastEventAt: null, lastError: null, eventCount: 0, sourceType: 'waf' }]} />)
    const dot = screen.getByTestId('health-dot-waf') as HTMLElement
    expect(dot.style.background).toContain('var(--fw-health-ok)')
  })

  it('ADR-0032: supervisor error state drives red dot regardless of recency', () => {
    // A source with recent events BUT supervisor error → still red
    const recentIso = new Date(Date.now() - 30_000).toISOString() // 30s ago
    render(
      <SourceHealth
        sources={[{ id: 'waf', label: 'WAF', health: 'red', supervisorState: 'parked', lastEventAt: recentIso, lastError: 'SSH timeout', eventCount: 100, sourceType: 'waf' }]}
      />,
    )
    // Dot is down/red, NOT ok/green despite recent lastEventAt
    expect(screen.getByTestId('health-dot-waf').getAttribute('data-state')).toBe('down')
  })

  it('supervisorState visible in health card (CellTooltip replaces title= — issue #281 WCAG fix)', () => {
    // title= tooltip removed in #281 — diagnostic info now lives in HealthCard popover.
    // Verify the chip renders without error; CellTooltip state is tested in HealthCardPopover.test.tsx.
    render(
      <SourceHealth
        sources={[{ id: 'waf', label: 'WAF', health: 'red', supervisorState: 'backoff', lastEventAt: null, lastError: null, eventCount: 0, sourceType: 'waf' }]}
      />,
    )
    expect(screen.getByTestId('health-item-waf')).toBeInTheDocument()
    // No title= attribute — WCAG 1.4.13 fix; popover is used instead.
    expect(screen.getByTestId('health-item-waf').getAttribute('title')).toBeNull()
  })

  it('renders display_name label next to the dot', () => {
    render(<SourceHealth sources={[{ id: 'azure_waf', label: 'Azure WAF', health: 'ok', supervisorState: null, lastEventAt: null, lastError: null, eventCount: 0, sourceType: 'azure_waf' }]} />)
    expect(screen.getByText('Azure WAF')).toBeInTheDocument()
  })

  it('renders empty without crash', () => {
    render(<SourceHealth sources={[]} />)
    expect(document.querySelector('.fw-health')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// SourceCard (DS shell)
// ---------------------------------------------------------------------------

describe('SourceCard (DS shell) — card chrome', () => {
  it('renders source name in header', () => {
    render(<SourceCard name="Azure WAF" status="active" />)
    expect(screen.getByText('Azure WAF')).toBeInTheDocument()
  })

  it('renders icon when provided', () => {
    render(<SourceCard name="WAF" icon="☁️" />)
    expect(screen.getByText('☁️')).toBeInTheDocument()
  })

  it('active status renders green colour token', () => {
    // Bug 1 fix: when statusText is provided, DSSourceCard renders it directly
    // without prepending a literal `●` (that was the double-dot bug).
    // The colour token is on the [data-status] span; assert via that element.
    const { container } = render(<SourceCard name="WAF" status="active" statusText="Active" />)
    const statusEl = container.querySelector('[data-status="active"]') as HTMLElement
    expect(statusEl).toBeTruthy()
    expect(statusEl.textContent).toBe('Active')
    expect(statusEl.style.color).toContain('var(--fw-green)')
  })

  it('error status renders red colour token', () => {
    render(<SourceCard name="IDS" status="error" />)
    const statusEl = screen.getByText('● error')
    expect(statusEl.style.color).toContain('var(--fw-red)')
  })

  it('renders error block with role=alert', () => {
    render(<SourceCard name="IDS" error="SSH connection refused" />)
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('SSH connection refused')
  })

  it('renders success row with role=status', () => {
    render(<SourceCard name="WAF" success="Config saved" />)
    expect(screen.getByRole('status')).toHaveTextContent('Config saved')
  })

  it('renders children in config grid', () => {
    render(
      <SourceCard name="WAF">
        <span data-testid="field">Workspace ID</span>
      </SourceCard>,
    )
    expect(screen.getByTestId('field')).toBeInTheDocument()
  })

  it('renders action buttons row', () => {
    render(<SourceCard name="WAF" actions={<button>Sync</button>} />)
    expect(screen.getByRole('button', { name: 'Sync' })).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// FilterChip
// ---------------------------------------------------------------------------

describe('FilterChip — removable chip', () => {
  it('renders chip label', () => {
    render(<FilterChip>Source: IDS</FilterChip>)
    expect(screen.getByText('Source: IDS')).toBeInTheDocument()
  })

  it('calls onRemove when ✕ is clicked', () => {
    const handler = vi.fn()
    render(<FilterChip onRemove={handler}>Source: WAF</FilterChip>)
    fireEvent.click(screen.getByRole('button', { name: 'Remove filter' }))
    expect(handler).toHaveBeenCalledOnce()
  })

  it('no remove button when onRemove is not provided', () => {
    render(<FilterChip>Category: Bot</FilterChip>)
    expect(screen.queryByRole('button', { name: 'Remove filter' })).not.toBeInTheDocument()
  })

  it('passes extra HTML attributes through', () => {
    render(<FilterChip data-testid="chip-1">test</FilterChip>)
    expect(screen.getByTestId('chip-1')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Combobox
// ---------------------------------------------------------------------------

describe('Combobox — type-to-filter dropdown', () => {
  const options = [
    { value: 'waf', label: 'Azure WAF' },
    { value: 'ids', label: 'Suricata IDS' },
    { value: 'syslog', label: 'Syslog' },
  ]

  it('renders placeholder when no value selected', () => {
    render(<Combobox options={options} value="" placeholder="All sources" onChange={vi.fn()} />)
    expect(screen.getByPlaceholderText('All sources')).toBeInTheDocument()
  })

  it('shows dropdown options on focus', async () => {
    const user = userEvent.setup()
    render(<Combobox options={options} value="" onChange={vi.fn()} />)
    await user.click(screen.getByRole('textbox'))
    expect(screen.getByTestId('combobox-dropdown')).toBeInTheDocument()
  })

  it('filters options live as text is typed', async () => {
    const user = userEvent.setup()
    render(<Combobox options={options} value="" onChange={vi.fn()} />)
    const input = screen.getByRole('textbox')
    await user.click(input)
    await user.type(input, 'suri')
    expect(screen.getByTestId('combobox-option-ids')).toBeInTheDocument()
    expect(screen.queryByTestId('combobox-option-waf')).not.toBeInTheDocument()
  })

  it('calls onChange with value and label when option is picked', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    render(<Combobox options={options} value="" onChange={onChange} />)
    await user.click(screen.getByRole('textbox'))
    fireEvent.mouseDown(screen.getByTestId('combobox-option-ids'))
    expect(onChange).toHaveBeenCalledWith('ids', 'Suricata IDS')
  })

  it('shows clear button when a value is selected', () => {
    render(<Combobox options={options} value="waf" onChange={vi.fn()} />)
    expect(screen.getByRole('button', { name: 'Clear filter' })).toBeInTheDocument()
  })

  it('calls onChange("", "") when clear button is clicked', () => {
    const onChange = vi.fn()
    render(<Combobox options={options} value="waf" onChange={onChange} />)
    fireEvent.click(screen.getByRole('button', { name: 'Clear filter' }))
    expect(onChange).toHaveBeenCalledWith('', '')
  })

  it('renders label when provided', () => {
    render(<Combobox label="Source" options={options} value="" onChange={vi.fn()} />)
    expect(screen.getByText('Source')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EventTimeline
// ---------------------------------------------------------------------------

describe('EventTimeline — multi-source vertical timeline', () => {
  const events = [
    { source: 'suricata', time: '14:22:07', label: 'ET SCAN Nmap', payload: 'GET /admin', correlated: true },
    { source: 'azure_waf', time: '14:22:09', label: '942100 SQLi', payload: "/search?q=test' OR '1'='1" },
    { source: 'syslog', time: '14:22:31', label: 'sshd auth fail', payload: 'Failed password for root' },
  ]

  it('renders all events', () => {
    render(<EventTimeline events={events} />)
    expect(screen.getByTestId('timeline-event-0')).toBeInTheDocument()
    expect(screen.getByTestId('timeline-event-1')).toBeInTheDocument()
    expect(screen.getByTestId('timeline-event-2')).toBeInTheDocument()
  })

  it('renders timestamps', () => {
    render(<EventTimeline events={events} />)
    expect(screen.getByText('14:22:07')).toBeInTheDocument()
  })

  it('renders event labels', () => {
    render(<EventTimeline events={events} />)
    expect(screen.getByText('· ET SCAN Nmap')).toBeInTheDocument()
  })

  it('renders payload text', () => {
    render(<EventTimeline events={events} />)
    expect(screen.getByText('GET /admin')).toBeInTheDocument()
  })

  it('correlated entry has orange left-stripe', () => {
    render(<EventTimeline events={events} />)
    const item = screen.getByTestId('timeline-event-0')
    expect(item.getAttribute('data-correlated')).toBe('true')
    expect(item.style.borderLeft).toContain('var(--fw-orange)')
  })

  it('correlated entry renders "correlated" label', () => {
    render(<EventTimeline events={events} />)
    expect(screen.getByText('· correlated')).toBeInTheDocument()
  })

  it('non-correlated entry does NOT have orange stripe', () => {
    render(<EventTimeline events={events} />)
    const item = screen.getByTestId('timeline-event-1')
    expect(item.getAttribute('data-correlated')).toBe('false')
    expect(item.style.borderLeft).not.toContain('var(--fw-orange)')
  })

  it('renders empty timeline without crash', () => {
    render(<EventTimeline events={[]} />)
    expect(document.querySelector('.fw-evtl')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// sourceHealth adapter (lib/sourceHealth.ts)
// ---------------------------------------------------------------------------

describe('dotStateFromHealth (ADR-0032 — server health field)', () => {
  it('"ok" → ok (green)', () => expect(dotStateFromHealth('ok')).toBe('ok'))
  it('"amber" → warn (amber)', () => expect(dotStateFromHealth('amber')).toBe('warn'))
  it('"red" → down (red)', () => expect(dotStateFromHealth('red')).toBe('down'))
  it('"not_configured" → idle (grey)', () => expect(dotStateFromHealth('not_configured')).toBe('idle'))
  it('unknown value → idle (safe fallback)', () => expect(dotStateFromHealth('unknown_future_state')).toBe('idle'))

  /**
   * C1 — vocabulary contract (issue #279 / ADR-0032 §B erratum).
   *
   * The canonical wire vocabulary is {ok, amber, red, not_configured}.
   * Every member MUST map to a non-fallthrough DotState (i.e. not the default
   * 'idle' path that "green" was hitting before the fix).  If the backend ever
   * re-introduces a color word, the backend contract test catches it first;
   * this test is the frontend mirror that locks the adapter side.
   */
  it('[C1] every canonical health value is explicitly handled — no fallthrough to idle', () => {
    const canonical = ['ok', 'amber', 'red', 'not_configured'] as const
    const fallthroughResults: string[] = []
    for (const v of canonical) {
      const dot = dotStateFromHealth(v)
      // not_configured legitimately maps to idle — that is correct behaviour,
      // not a fallthrough.  We only flag unexpected idle results.
      if (v !== 'not_configured' && dot === 'idle') {
        fallthroughResults.push(`"${v}" → idle (unexpected fallthrough)`)
      }
    }
    expect(fallthroughResults).toEqual([])
  })

  it('[C1] "green" is NOT in the canonical vocabulary — maps to fallback idle, not ok', () => {
    // Regression guard: if backend re-emits "green" the dot silently turns grey.
    // This test documents and pins that behaviour so the breakage is visible.
    expect(dotStateFromHealth('green')).toBe('idle')
  })
})

describe('toSourceHealthItems (ADR-0032 — maps server SourceHealth[] to SourceHealthItem[])', () => {
  it('maps health field correctly', () => {
    const items = toSourceHealthItems([
      { source_id: 'waf', source_type: 'azure_waf', display_name: 'Azure WAF', flavor: 'pull',
        health: 'ok', supervisor_state: null, last_event_at: null, event_count: 10, last_error: null },
    ])
    expect(items[0].health).toBe('ok')
    expect(items[0].id).toBe('waf')
    expect(items[0].label).toBe('Azure WAF')
  })

  it('maps display_name as label', () => {
    const items = toSourceHealthItems([
      { source_id: 'suricata', source_type: 'suricata', display_name: 'Suricata IDS/IPS', flavor: 'pull',
        health: 'amber', supervisor_state: null, last_event_at: null, event_count: 0, last_error: null },
    ])
    expect(items[0].label).toBe('Suricata IDS/IPS')
  })

  it('maps supervisor_state and last_error for tooltip', () => {
    const items = toSourceHealthItems([
      { source_id: 'ids', source_type: 'suricata', display_name: 'Suricata', flavor: 'pull',
        health: 'red', supervisor_state: 'parked', last_event_at: null, event_count: 0, last_error: 'SSH timeout' },
    ])
    expect(items[0].supervisorState).toBe('parked')
    expect(items[0].lastError).toBe('SSH timeout')
  })

  it('handles empty stats health array', () => {
    expect(toSourceHealthItems([])).toEqual([])
  })

  it('not_configured entry has health="not_configured"', () => {
    const items = toSourceHealthItems([
      { source_id: 'azure_waf', source_type: 'azure_waf', display_name: 'Azure WAF', flavor: 'pull',
        health: 'not_configured', supervisor_state: null, last_event_at: null, event_count: 0, last_error: null },
    ])
    expect(items[0].health).toBe('not_configured')
  })
})

describe('buildTooltip (ADR-0032)', () => {
  const base = { supervisorState: null, lastEventAt: null, lastError: null, eventCount: 0, sourceType: 'test' }

  it('shows label and health status for not_configured', () => {
    const tip = buildTooltip({ id: 'waf', label: 'Azure WAF', health: 'not_configured', ...base })
    expect(tip).toContain('Azure WAF')
    expect(tip).toContain('not configured')
  })

  it('shows "healthy" for health="ok"', () => {
    const tip = buildTooltip({ id: 'waf', label: 'WAF', health: 'ok', ...base })
    expect(tip).toContain('healthy')
  })

  it('shows "no recent events" for health="amber"', () => {
    const tip = buildTooltip({ id: 'ids', label: 'IDS', health: 'amber', ...base })
    expect(tip).toContain('no recent events')
  })

  it('shows "error" for health="red"', () => {
    const tip = buildTooltip({ id: 'ids', label: 'IDS', health: 'red', ...base })
    expect(tip).toContain('error')
  })

  it('includes supervisorState when non-running/non-idle', () => {
    const tip = buildTooltip({ id: 'waf', label: 'WAF', health: 'red', supervisorState: 'backoff', lastEventAt: null, lastError: null, eventCount: 0, sourceType: 'waf' })
    expect(tip).toContain('backoff')
  })

  it('includes lastError when set', () => {
    const tip = buildTooltip({ id: 'waf', label: 'WAF', health: 'red', supervisorState: 'parked', lastEventAt: null, lastError: 'SSH timeout', eventCount: 0, sourceType: 'waf' })
    expect(tip).toContain('SSH timeout')
  })

  it('omits supervisor clause when supervisorState is null', () => {
    const tip = buildTooltip({ id: 'waf', label: 'WAF', health: 'ok', supervisorState: null, lastEventAt: null, lastError: null, eventCount: 0, sourceType: 'waf' })
    expect(tip).not.toContain('supervisor')
  })
})
