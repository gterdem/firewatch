/**
 * Tests for issue #281 — header source-health mini health-card popovers +
 * one aggregated per-type dot (worst-of-instances).
 *
 * EARS criteria covered (1:1):
 *
 * 1. Event-driven: WHEN a source chip is hovered/focused, the system SHALL show
 *    a CellTooltip mini health card with display name, status word, last event
 *    time (local + UTC), event count, supervisor state, last_error [EARS-ED-1]
 *
 * 2. State-driven: WHERE health="not_configured", the card SHALL include a
 *    "Configure →" deep-link to the Settings card [EARS-SD-2]
 *
 * 3. State-driven: WHEN source_type has >1 instance, header renders ONE dot
 *    per type, colored worst-of-instances [EARS-SD-3]
 *
 * 4. Ubiquitous: per-instance breakdown rows shown in multi-instance card
 *    (source_id · health · event count · last event) [EARS-UB-4]
 *
 * 5. Ubiquitous: aggregation is display-only — server values not re-derived
 *    [EARS-UB-5]
 *
 * 6. State-driven: worst-of ordering — red > amber > not_configured > ok
 *    [EARS-SD-6]
 *
 * ADR-0032 Erratum: health vocab is ok|amber|red|not_configured (no color words).
 * ADR-0029 D3: all rendered as text nodes.
 * RFC-5737: test IPs use 192.0.2.x (TEST-NET-1).
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import type { SourceTypeGroup } from '../lib/sourceHealth'
import {
  worstOfHealth,
  groupBySourceType,
  toSourceHealthItems,
} from '../lib/sourceHealth'
import { HealthCard, HealthDot, SourceHealth } from '../components/ds'
import type { SourceHealth as ApiSourceHealth } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures — ADR-0032 §B wire shape; IPs use RFC-5737 TEST-NET-1 (192.0.2.x)
// ---------------------------------------------------------------------------

const FIXTURE_OK: ApiSourceHealth = {
  source_type: 'suricata',
  source_id: 'suricata',
  display_name: 'Suricata IDS/IPS',
  flavor: 'pull',
  health: 'ok',
  supervisor_state: 'running',
  last_event_at: new Date(Date.now() - 60_000).toISOString(),
  event_count: 12345,
  last_error: null,
}

const FIXTURE_AMBER: ApiSourceHealth = {
  source_type: 'suricata',
  source_id: 'sensor-2',
  display_name: 'Suricata IDS/IPS',
  flavor: 'pull',
  health: 'amber',
  supervisor_state: 'idle',
  last_event_at: null,
  event_count: 0,
  last_error: null,
}

const FIXTURE_RED: ApiSourceHealth = {
  source_type: 'suricata',
  source_id: 'vm-target',
  display_name: 'Suricata IDS/IPS',
  flavor: 'pull',
  health: 'red',
  supervisor_state: 'parked',
  last_event_at: null,
  event_count: 8000,
  last_error: 'SSH connection refused',
}

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

// ---------------------------------------------------------------------------
// worstOfHealth — unit tests for aggregation logic
// ---------------------------------------------------------------------------

describe('[EARS-SD-6] worstOfHealth — severity ordering', () => {
  it('red beats all other states', () => {
    expect(worstOfHealth(['ok', 'amber', 'red', 'not_configured'])).toBe('red')
    expect(worstOfHealth(['red'])).toBe('red')
    expect(worstOfHealth(['ok', 'red'])).toBe('red')
  })

  it('amber beats not_configured and ok', () => {
    expect(worstOfHealth(['ok', 'amber'])).toBe('amber')
    expect(worstOfHealth(['not_configured', 'amber'])).toBe('amber')
    expect(worstOfHealth(['ok', 'amber', 'not_configured'])).toBe('amber')
  })

  it('not_configured beats ok', () => {
    expect(worstOfHealth(['ok', 'not_configured'])).toBe('not_configured')
    expect(worstOfHealth(['not_configured', 'ok', 'ok'])).toBe('not_configured')
  })

  it('ok is least severe', () => {
    expect(worstOfHealth(['ok', 'ok'])).toBe('ok')
    expect(worstOfHealth(['ok'])).toBe('ok')
  })

  it('empty array returns not_configured (safe fallback)', () => {
    expect(worstOfHealth([])).toBe('not_configured')
  })

  it('unknown health values treated as ok rank', () => {
    // Unknown falls back to rank 0 (same as ok) so amber still wins
    expect(worstOfHealth(['unknown_value', 'amber'])).toBe('amber')
  })
})

// ---------------------------------------------------------------------------
// groupBySourceType — grouping logic
// ---------------------------------------------------------------------------

describe('groupBySourceType — groups instances by source_type', () => {
  it('single instance → one group with one member', () => {
    const items = toSourceHealthItems([FIXTURE_NOT_CONFIGURED])
    const groups = groupBySourceType(items)
    expect(groups).toHaveLength(1)
    expect(groups[0].sourceType).toBe('azure_waf')
    expect(groups[0].instances).toHaveLength(1)
    expect(groups[0].worstHealth).toBe('not_configured')
  })

  it('two different types → two groups', () => {
    const items = toSourceHealthItems([FIXTURE_NOT_CONFIGURED, FIXTURE_OK])
    const groups = groupBySourceType(items)
    expect(groups).toHaveLength(2)
    expect(groups.map((g) => g.sourceType)).toEqual(['azure_waf', 'suricata'])
  })

  it('N instances of same type → one group, worst-of health', () => {
    // ok + amber + red → red is the worst
    const items = toSourceHealthItems([FIXTURE_OK, FIXTURE_AMBER, FIXTURE_RED])
    const groups = groupBySourceType(items)
    expect(groups).toHaveLength(1)
    expect(groups[0].sourceType).toBe('suricata')
    expect(groups[0].instances).toHaveLength(3)
    expect(groups[0].worstHealth).toBe('red')
  })

  it('mixed types preserve insertion order', () => {
    const items = toSourceHealthItems([FIXTURE_NOT_CONFIGURED, FIXTURE_OK])
    const groups = groupBySourceType(items)
    expect(groups[0].sourceType).toBe('azure_waf')
    expect(groups[1].sourceType).toBe('suricata')
  })

  it('typeLabel uses first instance display_name', () => {
    const items = toSourceHealthItems([FIXTURE_OK, FIXTURE_AMBER])
    const groups = groupBySourceType(items)
    expect(groups[0].typeLabel).toBe('Suricata IDS/IPS')
  })

  it('empty input → empty groups', () => {
    expect(groupBySourceType([])).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// [EARS-SD-3] One dot per source TYPE with worst-of color
// ---------------------------------------------------------------------------

describe('[EARS-SD-3] SourceHealth — one dot per source type (not per instance)', () => {
  it('three instances of same type → ONE dot, colored worst-of', () => {
    const items = toSourceHealthItems([FIXTURE_OK, FIXTURE_AMBER, FIXTURE_RED])
    render(<SourceHealth sources={items} />)

    // Only ONE dot for suricata — not three
    const dot = screen.getByTestId('health-dot-suricata')
    expect(dot).toBeInTheDocument()
    // Worst is red → state "down"
    expect(dot.getAttribute('data-state')).toBe('down')
  })

  it('different source types render separate dots', () => {
    const items = toSourceHealthItems([FIXTURE_NOT_CONFIGURED, FIXTURE_OK])
    render(<SourceHealth sources={items} />)

    expect(screen.getByTestId('health-dot-azure_waf')).toBeInTheDocument()
    expect(screen.getByTestId('health-dot-suricata')).toBeInTheDocument()
  })

  it('ok-only instances → ok (green) dot', () => {
    const items = toSourceHealthItems([FIXTURE_OK])
    render(<SourceHealth sources={items} />)
    const dot = screen.getByTestId('health-dot-suricata')
    expect(dot.getAttribute('data-state')).toBe('ok')
  })

  it('[EARS-UB-5] aggregation is display-only — server values not re-derived', () => {
    // The frontend only folds server-computed health values.
    // Verify: three instances pass through toSourceHealthItems, each retaining
    // their original server health value.
    const items = toSourceHealthItems([FIXTURE_OK, FIXTURE_AMBER, FIXTURE_RED])
    expect(items[0].health).toBe('ok')
    expect(items[1].health).toBe('amber')
    expect(items[2].health).toBe('red')
  })
})

// ---------------------------------------------------------------------------
// [EARS-ED-1] HealthCard — single instance fields
// ---------------------------------------------------------------------------

describe('[EARS-ED-1] HealthCard — single-instance card fields', () => {
  let singleGroup: SourceTypeGroup

  beforeEach(() => {
    const items = toSourceHealthItems([FIXTURE_OK])
    const groups = groupBySourceType(items)
    singleGroup = groups[0]
  })

  it('renders single-instance card', () => {
    render(<HealthCard group={singleGroup} />)
    expect(screen.getByTestId('health-card-single')).toBeInTheDocument()
  })

  it('shows display name', () => {
    render(<HealthCard group={singleGroup} />)
    expect(screen.getByTestId('health-card-label')).toHaveTextContent('Suricata IDS/IPS')
  })

  it('shows status word matching health value', () => {
    render(<HealthCard group={singleGroup} />)
    expect(screen.getByTestId('health-card-status-word')).toHaveTextContent('Healthy')
  })

  it('shows event count', () => {
    render(<HealthCard group={singleGroup} />)
    // 12345 formatted with locale (may be "12,345" or "12 345" depending on locale)
    const countEl = screen.getByTestId('health-card-event-count')
    expect(countEl.textContent).not.toBe('—')
  })

  it('shows supervisor state', () => {
    render(<HealthCard group={singleGroup} />)
    expect(screen.getByTestId('health-card-supervisor')).toHaveTextContent('running')
  })

  it('shows last event time field', () => {
    render(<HealthCard group={singleGroup} />)
    // lastEventAt is present — should not show "—"
    const timeEl = screen.getByTestId('health-card-last-event')
    expect(timeEl.textContent).not.toBe('—')
  })

  it('shows "—" for last event when null', () => {
    const noEventItems = toSourceHealthItems([FIXTURE_AMBER])
    const groups = groupBySourceType(noEventItems)
    // FIXTURE_AMBER has source_id='sensor-2', source_type='suricata'
    render(<HealthCard group={groups[0]} />)
    const timeEl = screen.getByTestId('health-card-last-event')
    expect(timeEl.textContent).toBe('—')
  })

  it('shows last_error when present', () => {
    const redItems = toSourceHealthItems([FIXTURE_RED])
    const groups = groupBySourceType(redItems)
    render(<HealthCard group={groups[0]} />)
    expect(screen.getByTestId('health-card-last-error')).toHaveTextContent('SSH connection refused')
  })

  it('does not render error row when last_error is null', () => {
    render(<HealthCard group={singleGroup} />)
    expect(screen.queryByTestId('health-card-last-error')).not.toBeInTheDocument()
  })

  it('SECURITY: last_error rendered as text node, not HTML', () => {
    // Simulate a last_error that contains HTML — must be text-escaped by React
    const xssAttempt: ApiSourceHealth = {
      ...FIXTURE_RED,
      last_error: '<script>alert(1)</script>',
    }
    const items = toSourceHealthItems([xssAttempt])
    const groups = groupBySourceType(items)
    render(<HealthCard group={groups[0]} />)
    const errorEl = screen.getByTestId('health-card-last-error')
    // Must be visible as text, not executed as HTML
    expect(errorEl.textContent).toContain('<script>')
    // Verify no script element was injected into the DOM
    expect(document.querySelectorAll('script').length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// [EARS-SD-2] HealthCard — "Configure →" link for not_configured
// ---------------------------------------------------------------------------

describe('[EARS-SD-2] HealthCard — Configure link for not_configured', () => {
  it('shows "Configure →" link when health=not_configured', () => {
    const items = toSourceHealthItems([FIXTURE_NOT_CONFIGURED])
    const groups = groupBySourceType(items)
    render(<HealthCard group={groups[0]} />)
    expect(screen.getByTestId('health-card-configure-link')).toBeInTheDocument()
    expect(screen.getByTestId('health-card-configure-link')).toHaveTextContent('Configure →')
  })

  it('Configure link uses custom buildSettingsHref when provided', () => {
    const items = toSourceHealthItems([FIXTURE_NOT_CONFIGURED])
    const groups = groupBySourceType(items)
    render(
      <HealthCard
        group={groups[0]}
        buildSettingsHref={(t) => `/settings/sources/${t}`}
      />,
    )
    const link = screen.getByTestId('health-card-configure-link')
    expect(link.getAttribute('href')).toBe('/settings/sources/azure_waf')
  })

  it('Configure link uses default href when no buildSettingsHref', () => {
    const items = toSourceHealthItems([FIXTURE_NOT_CONFIGURED])
    const groups = groupBySourceType(items)
    render(<HealthCard group={groups[0]} />)
    const link = screen.getByTestId('health-card-configure-link')
    expect(link.getAttribute('href')).toBe('#/settings?source=azure_waf')
  })

  it('does NOT show Configure link when health=ok', () => {
    const items = toSourceHealthItems([FIXTURE_OK])
    const groups = groupBySourceType(items)
    render(<HealthCard group={groups[0]} />)
    expect(screen.queryByTestId('health-card-configure-link')).not.toBeInTheDocument()
  })

  it('does NOT show Configure link when health=red', () => {
    const items = toSourceHealthItems([FIXTURE_RED])
    const groups = groupBySourceType(items)
    render(<HealthCard group={groups[0]} />)
    expect(screen.queryByTestId('health-card-configure-link')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// [EARS-UB-4] HealthCard — multi-instance breakdown rows
// ---------------------------------------------------------------------------

describe('[EARS-UB-4] HealthCard — multi-instance breakdown', () => {
  let multiGroup: SourceTypeGroup

  beforeEach(() => {
    // ok + amber → two instances of suricata
    const items = toSourceHealthItems([FIXTURE_OK, FIXTURE_AMBER])
    const groups = groupBySourceType(items)
    multiGroup = groups[0]
  })

  it('renders multi-instance card', () => {
    render(<HealthCard group={multiGroup} />)
    expect(screen.getByTestId('health-card-multi')).toBeInTheDocument()
  })

  it('shows type label + instance count in header', () => {
    render(<HealthCard group={multiGroup} />)
    expect(screen.getByTestId('health-card-type-label')).toHaveTextContent('Suricata IDS/IPS')
    expect(screen.getByTestId('health-card-instance-count')).toHaveTextContent('2 instances')
  })

  it('renders a row per instance with source_id', () => {
    render(<HealthCard group={multiGroup} />)
    // FIXTURE_OK has id='suricata', FIXTURE_AMBER has id='sensor-2'
    expect(screen.getByTestId('health-card-instance-suricata')).toBeInTheDocument()
    expect(screen.getByTestId('health-card-instance-sensor-2')).toBeInTheDocument()
  })

  it('per-instance row shows health status word', () => {
    render(<HealthCard group={multiGroup} />)
    expect(screen.getByTestId('health-card-instance-status-suricata')).toHaveTextContent('Healthy')
    expect(screen.getByTestId('health-card-instance-status-sensor-2')).toHaveTextContent('No recent events')
  })

  it('per-instance row shows event count', () => {
    render(<HealthCard group={multiGroup} />)
    // FIXTURE_OK has event_count=12345, FIXTURE_AMBER has event_count=0
    const okCount = screen.getByTestId('health-card-instance-count-suricata')
    expect(okCount.textContent).not.toBe('—')
    const amberCount = screen.getByTestId('health-card-instance-count-sensor-2')
    expect(amberCount.textContent).toBe('—')
  })

  it('per-instance row shows last-event time or "—"', () => {
    render(<HealthCard group={multiGroup} />)
    // FIXTURE_OK has lastEventAt set; FIXTURE_AMBER does not
    const okTime = screen.getByTestId('health-card-instance-last-event-suricata')
    expect(okTime.textContent).not.toBe('—')
    const amberTime = screen.getByTestId('health-card-instance-last-event-sensor-2')
    expect(amberTime.textContent).toBe('—')
  })

  it('shows Configure link for not_configured instance in multi card', () => {
    // Build group with one ok instance and one not_configured instance
    const mixedItems = toSourceHealthItems([
      FIXTURE_OK,
      { ...FIXTURE_NOT_CONFIGURED, source_type: 'suricata', source_id: 'unconfigured-instance', display_name: 'Suricata IDS/IPS' },
    ])
    const groups = groupBySourceType(mixedItems)
    render(<HealthCard group={groups[0]} />)
    // The not_configured instance row should have a configure link
    expect(screen.getByTestId('health-card-configure-link')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// [EARS-ED-1] HealthDot — CellTooltip wiring (keyboard + hover path)
// ---------------------------------------------------------------------------

describe('[EARS-ED-1] HealthDot — CellTooltip trigger opens HealthCard', () => {
  it('renders trigger with correct testid', () => {
    const items = toSourceHealthItems([FIXTURE_OK])
    const groups = groupBySourceType(items)
    render(<HealthDot group={groups[0]} />)
    expect(screen.getByTestId('health-dot-trigger-suricata')).toBeInTheDocument()
  })

  it('dot is not shown before hover', () => {
    const items = toSourceHealthItems([FIXTURE_OK])
    const groups = groupBySourceType(items)
    render(<HealthDot group={groups[0]} />)
    // Health card content is NOT in DOM before hover
    expect(screen.queryByTestId('health-card-single')).not.toBeInTheDocument()
  })

  it('health card appears after focus (keyboard path — WCAG 1.4.13)', () => {
    const items = toSourceHealthItems([FIXTURE_OK])
    const groups = groupBySourceType(items)
    render(<HealthDot group={groups[0]} />)

    const trigger = screen.getByTestId('health-dot-trigger-suricata')
    act(() => { fireEvent.focus(trigger) })

    // HealthCard should now be visible via CellTooltip portal
    expect(screen.getByTestId('health-card-single')).toBeInTheDocument()
  })

  it('dot has correct data-state for worst-of health', () => {
    const items = toSourceHealthItems([FIXTURE_OK])
    const groups = groupBySourceType(items)
    render(<HealthDot group={groups[0]} />)
    const dot = screen.getByTestId('health-dot-suricata')
    expect(dot.getAttribute('data-state')).toBe('ok')
  })

  it('aria-label on dot describes source and health', () => {
    const items = toSourceHealthItems([FIXTURE_OK])
    const groups = groupBySourceType(items)
    render(<HealthDot group={groups[0]} />)
    const dot = screen.getByTestId('health-dot-suricata')
    expect(dot.getAttribute('aria-label')).toContain('Suricata IDS/IPS')
    expect(dot.getAttribute('aria-label')).toContain('ok')
  })
})

// ---------------------------------------------------------------------------
// WCAG 1.4.13 + no title= attribute checks
// ---------------------------------------------------------------------------

describe('WCAG 1.4.13 — no title= tooltips; CellTooltip used instead', () => {
  it('HealthDot chip has no title= attribute (not a native tooltip)', () => {
    const items = toSourceHealthItems([FIXTURE_OK])
    const groups = groupBySourceType(items)
    render(<HealthDot group={groups[0]} />)
    // The health item div and dot should have no title= attribute
    const item = screen.getByTestId('health-item-suricata')
    expect(item.getAttribute('title')).toBeNull()
    const dot = screen.getByTestId('health-dot-suricata')
    expect(dot.getAttribute('title')).toBeNull()
  })
})
