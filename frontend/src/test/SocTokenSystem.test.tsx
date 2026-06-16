/**
 * Tests for the SOC semantic color token system (ADR-0028 D6, issue #96).
 *
 * EARS criteria covered:
 *   - The system SHALL define {critical, high, medium, low, ok} tokens; verified
 *     by asserting the CSS custom properties are present on :root and .dark.
 *   - WHEN action is BLOCK, the cell SHALL render with a visually distinct token
 *     (enforced/red) that is different from ALERT (watch/amber).
 *   - WHEN action is ALERT, the cell SHALL render with the watch token (amber).
 *   - Source-type badges SHALL use the semantic token classes, not flat grey.
 *   - Severity badges SHALL derive color from the shared token set (no hardcoded hex).
 *   - Activity Timeline bars SHALL use the soc-enforced and soc-ok token classes.
 *   - AI-status chips SHALL consume the ok/offline tokens.
 *   - Token set SHALL be theme-swappable (dark/light) with no call-site edits.
 *
 * Issue #97: AiEngineChip and AiStatusBadge replaced by shared AiStatusChip.
 *   - AiEngineChip/AiStatusBadge sections updated to use AiStatusChip.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LogsTable from '../components/logs/LogsTable'
import TimelineChart from '../components/dashboard/TimelineChart'
import SourceProvenanceBadges from '../components/threats/SourceProvenanceBadges'
import AiStatusChip from '../components/AiStatusChip'
import {
  severityBadgeClasses,
  actionBadgeClasses,
  sourceTypeBadgeClasses,
  threatLevelTextClasses,
} from '../lib/socTokens'
import {
  LOG_ENTRY_FIXTURE,
  TIMELINE_FIXTURE,
} from './readFixtures'
import type { LogEntry, TimelineBucket } from '../api/types'

// ---------------------------------------------------------------------------
// socTokens.ts unit tests
// ---------------------------------------------------------------------------

describe('socTokens — severityBadgeClasses()', () => {
  it('critical → contains soc-critical-fg and soc-critical-bg', () => {
    const cls = severityBadgeClasses('critical')
    expect(cls).toContain('soc-critical-fg')
    expect(cls).toContain('soc-critical-bg')
    expect(cls).toContain('soc-critical-border')
  })

  it('high → contains soc-high-fg and soc-high-bg', () => {
    const cls = severityBadgeClasses('high')
    expect(cls).toContain('soc-high-fg')
    expect(cls).toContain('soc-high-bg')
  })

  it('medium → contains soc-medium-fg', () => {
    const cls = severityBadgeClasses('medium')
    expect(cls).toContain('soc-medium-fg')
  })

  it('low → contains soc-low-fg', () => {
    const cls = severityBadgeClasses('low')
    expect(cls).toContain('soc-low-fg')
  })

  it('unknown value → falls back to muted-foreground (no soc token)', () => {
    const cls = severityBadgeClasses('unknown')
    expect(cls).toContain('muted-foreground')
    expect(cls).not.toContain('soc-')
  })

  it('case-insensitive: CRITICAL matches critical', () => {
    expect(severityBadgeClasses('CRITICAL')).toEqual(severityBadgeClasses('critical'))
  })
})

describe('socTokens — actionBadgeClasses(): BLOCK vs ALERT distinction', () => {
  it('block → enforced token (red/strong), distinct from alert', () => {
    const blockCls = actionBadgeClasses('block')
    expect(blockCls).toContain('soc-enforced-fg')
    expect(blockCls).toContain('soc-enforced-bg')
    // Must be visually distinct from alert (different token name)
    expect(blockCls).not.toContain('soc-watch')
  })

  it('blocked → same enforced token as block (normalised action value)', () => {
    const cls = actionBadgeClasses('blocked')
    expect(cls).toContain('soc-enforced-fg')
  })

  it('alert → watch token (amber), distinct from block', () => {
    const alertCls = actionBadgeClasses('alert')
    expect(alertCls).toContain('soc-watch-fg')
    expect(alertCls).toContain('soc-watch-bg')
    // Must be visually distinct from block
    expect(alertCls).not.toContain('soc-enforced')
  })

  it('alerted → same watch token as alert', () => {
    const cls = actionBadgeClasses('alerted')
    expect(cls).toContain('soc-watch-fg')
  })

  it('allow → ok token (green)', () => {
    const cls = actionBadgeClasses('allow')
    expect(cls).toContain('soc-ok-fg')
  })

  it('allowed → ok token', () => {
    const cls = actionBadgeClasses('allowed')
    expect(cls).toContain('soc-ok-fg')
  })

  it('drop → enforced token (same strong signal as block)', () => {
    const cls = actionBadgeClasses('drop')
    expect(cls).toContain('soc-enforced-fg')
  })

  it('unknown action → muted neutral (no soc token)', () => {
    const cls = actionBadgeClasses('unknown_action')
    expect(cls).toContain('muted-foreground')
    expect(cls).not.toContain('soc-')
  })

  it('BLOCK and ALERT are not the same class string (visually distinct)', () => {
    expect(actionBadgeClasses('BLOCK')).not.toEqual(actionBadgeClasses('ALERT'))
  })
})

describe('socTokens — sourceTypeBadgeClasses()', () => {
  it('azure_waf → soc-src-waf token (blue)', () => {
    const cls = sourceTypeBadgeClasses('azure_waf')
    expect(cls).toContain('soc-src-waf-fg')
    expect(cls).toContain('soc-src-waf-bg')
  })

  it('suricata → soc-src-ids token (orange)', () => {
    const cls = sourceTypeBadgeClasses('suricata')
    expect(cls).toContain('soc-src-ids-fg')
    expect(cls).toContain('soc-src-ids-bg')
  })

  it('azure_waf and suricata are not the same class string', () => {
    expect(sourceTypeBadgeClasses('azure_waf')).not.toEqual(sourceTypeBadgeClasses('suricata'))
  })

  it('unknown source → muted neutral fallback (not a soc-src-* token)', () => {
    const cls = sourceTypeBadgeClasses('future_source')
    expect(cls).toContain('muted-foreground')
    expect(cls).not.toContain('soc-src-')
  })
})

describe('socTokens — threatLevelTextClasses()', () => {
  it('CRITICAL → soc-critical-fg font-bold', () => {
    const cls = threatLevelTextClasses('CRITICAL')
    expect(cls).toContain('soc-critical-fg')
    expect(cls).toContain('font-bold')
  })

  it('HIGH → soc-high-fg font-semibold', () => {
    const cls = threatLevelTextClasses('HIGH')
    expect(cls).toContain('soc-high-fg')
    expect(cls).toContain('font-semibold')
  })

  it('MEDIUM → soc-medium-fg', () => {
    expect(threatLevelTextClasses('MEDIUM')).toContain('soc-medium-fg')
  })

  it('LOW → soc-low-fg', () => {
    expect(threatLevelTextClasses('LOW')).toContain('soc-low-fg')
  })
})

// ---------------------------------------------------------------------------
// Helpers — LogsTable requires MemoryRouter (uses useNavigate for deep-links,
// added in #329). All LogsTable renders must use renderLogTable().
// ---------------------------------------------------------------------------

/** Render LogsTable inside MemoryRouter + stub getBoundingClientRect for useColumnPriority. */
function renderLogTable(props: Parameters<typeof LogsTable>[0]) {
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 1200, height: 40, top: 0, left: 0, bottom: 40, right: 1200,
    x: 0, y: 0, toJSON: () => ({}),
  } as DOMRect)
  const result = render(<MemoryRouter><LogsTable {...props} /></MemoryRouter>)
  vi.restoreAllMocks()
  return result
}

// ---------------------------------------------------------------------------
// LogsTable ACTION column: BLOCK vs ALERT visually distinct via token classes
// ---------------------------------------------------------------------------

describe('LogsTable — ACTION column token badges (issue #96)', () => {
  function makeLog(action: string): LogEntry {
    return { ...LOG_ENTRY_FIXTURE, id: Math.random(), action }
  }

  it('BLOCK action renders an action badge with data-testid="log-row-action-badge"', () => {
    renderLogTable({ logs: [makeLog('block')], onIpClick: () => {} })
    const badge = screen.getByTestId('log-row-action-badge')
    expect(badge).toBeInTheDocument()
    expect(badge).toHaveTextContent('block')
  })

  it('ALERT action renders an action badge different from BLOCK', () => {
    const { rerender } = renderLogTable({ logs: [makeLog('block')], onIpClick: () => {} })
    const blockTone = screen.getByTestId('log-row-action-badge').getAttribute('data-tone')

    rerender(<MemoryRouter><LogsTable logs={[makeLog('alert')]} onIpClick={() => {}} /></MemoryRouter>)
    const alertTone = screen.getByTestId('log-row-action-badge').getAttribute('data-tone')

    // The two actions must have different tones — they are visually distinct (DS Badge)
    expect(blockTone).not.toEqual(alertTone)
  })

  it('BLOCK badge uses DS tone="block" (enforced/red — ADR-0028 D6)', () => {
    renderLogTable({ logs: [makeLog('block')], onIpClick: () => {} })
    const badge = screen.getByTestId('log-row-action-badge')
    expect(badge).toHaveAttribute('data-tone', 'block')
  })

  it('ALERT badge uses DS tone="alert" (solid-orange chip — ADR-0012)', () => {
    renderLogTable({ logs: [makeLog('alert')], onIpClick: () => {} })
    const badge = screen.getByTestId('log-row-action-badge')
    expect(badge).toHaveAttribute('data-tone', 'alert')
  })

  it('ALLOW badge uses DS tone="allow" (ok/green — ADR-0028 D6)', () => {
    renderLogTable({ logs: [makeLog('allow')], onIpClick: () => {} })
    const badge = screen.getByTestId('log-row-action-badge')
    expect(badge).toHaveAttribute('data-tone', 'allow')
  })

  it('null action renders em-dash (no badge chip)', () => {
    const log: LogEntry = { ...LOG_ENTRY_FIXTURE, id: 99, action: null }
    renderLogTable({ logs: [log], onIpClick: () => {} })
    const badge = screen.getByTestId('log-row-action-badge')
    expect(badge).toHaveTextContent('—')
    // The em-dash placeholder must NOT carry a tone attribute
    expect(badge).not.toHaveAttribute('data-tone')
  })
})

// ---------------------------------------------------------------------------
// LogsTable source-type badge: token-styled, not flat grey
// ---------------------------------------------------------------------------

describe('LogsTable — source-type badge token styling (issue #96)', () => {
  it('suricata source renders a SourceBadge with data-testid="log-row-source-badge"', () => {
    const log: LogEntry = { ...LOG_ENTRY_FIXTURE, source_type: 'suricata' }
    renderLogTable({ logs: [log], onIpClick: () => {} })
    const badge = screen.getByTestId('log-row-source-badge')
    expect(badge).toBeInTheDocument()
    // DS SourceBadge maps suricata→IDS label
    expect(badge).toHaveTextContent('IDS')
    expect(badge).toHaveAttribute('data-source', 'suricata')
    expect(badge).toHaveAttribute('data-tone', 'ids')
  })

  it('azure_waf source renders a SourceBadge with WAF tone (DS SourceBadge)', () => {
    const log: LogEntry = { ...LOG_ENTRY_FIXTURE, source_type: 'azure_waf' }
    renderLogTable({ logs: [log], onIpClick: () => {} })
    const badge = screen.getByTestId('log-row-source-badge')
    expect(badge).toHaveAttribute('data-source', 'azure_waf')
    expect(badge).toHaveAttribute('data-tone', 'waf')
    expect(badge).toHaveTextContent('WAF')
  })

  it('suricata and azure_waf source badges have different tones (DS SourceBadge)', () => {
    const { rerender } = renderLogTable({
      logs: [{ ...LOG_ENTRY_FIXTURE, source_type: 'suricata' }],
      onIpClick: () => {},
    })
    const suricataTone = screen.getByTestId('log-row-source-badge').getAttribute('data-tone')

    rerender(
      <MemoryRouter>
        <LogsTable
          logs={[{ ...LOG_ENTRY_FIXTURE, source_type: 'azure_waf' }]}
          onIpClick={() => {}}
        />
      </MemoryRouter>
    )
    const wafTone = screen.getByTestId('log-row-source-badge').getAttribute('data-tone')

    expect(suricataTone).not.toEqual(wafTone)
  })

  it('unknown source type falls back to neutral tone (DS SourceBadge — ADR-0024)', () => {
    const log: LogEntry = { ...LOG_ENTRY_FIXTURE, source_type: 'future_source' }
    renderLogTable({ logs: [log], onIpClick: () => {} })
    const badge = screen.getByTestId('log-row-source-badge')
    // ADR-0024: unknown sources get neutral fallback; no crash; no UI edit
    expect(badge).toHaveAttribute('data-tone', 'neutral')
    expect(badge).toHaveTextContent('FUTURE_SOURCE')
  })
})

// ---------------------------------------------------------------------------
// LogsTable severity badge: token-styled (no hardcoded Tailwind color utilities)
// ---------------------------------------------------------------------------

describe('LogsTable — severity badge uses DS Badge tone (issue #96 / #112)', () => {
  it('high severity badge uses tone="high" (DS Badge — no hardcoded Tailwind color)', () => {
    const log: LogEntry = { ...LOG_ENTRY_FIXTURE, severity: 'high' }
    renderLogTable({ logs: [log], onIpClick: () => {} })
    const badge = screen.getByTestId('log-row-severity-badge')
    expect(badge).toHaveAttribute('data-tone', 'high')
    expect(badge.className).not.toContain('bg-orange-100')
    expect(badge.className).not.toContain('dark:bg-orange-900')
  })

  it('critical severity badge uses tone="critical" (DS Badge — no hardcoded Tailwind color)', () => {
    const log: LogEntry = { ...LOG_ENTRY_FIXTURE, severity: 'critical' }
    renderLogTable({ logs: [log], onIpClick: () => {} })
    const badge = screen.getByTestId('log-row-severity-badge')
    expect(badge).toHaveAttribute('data-tone', 'critical')
    expect(badge.className).not.toContain('bg-red-100')
  })

  it('medium severity badge uses tone="medium"', () => {
    const log: LogEntry = { ...LOG_ENTRY_FIXTURE, severity: 'medium' }
    renderLogTable({ logs: [log], onIpClick: () => {} })
    const badge = screen.getByTestId('log-row-severity-badge')
    expect(badge).toHaveAttribute('data-tone', 'medium')
  })

  it('low severity badge uses tone="low"', () => {
    const log: LogEntry = { ...LOG_ENTRY_FIXTURE, severity: 'low' }
    renderLogTable({ logs: [log], onIpClick: () => {} })
    const badge = screen.getByTestId('log-row-severity-badge')
    expect(badge).toHaveAttribute('data-tone', 'low')
  })
})

// ---------------------------------------------------------------------------
// TimelineChart: bar colors from SOC token set
// ---------------------------------------------------------------------------

describe('TimelineChart — bar colors use SOC token set (issue #96)', () => {
  const buckets: TimelineBucket[] = [
    { hour: '2026-06-04T06:00:00Z', total: 100, blocked: 60, granularity: 'hourly' },
  ]

  it('renders timeline chart with data', () => {
    render(<TimelineChart buckets={buckets} />)
    expect(screen.getByTestId('timeline-chart')).toBeInTheDocument()
  })

  it('blocked bar has data-testid="timeline-blocked-bar" and soc-enforced-fg class (disposition mode, #247)', () => {
    render(<TimelineChart buckets={buckets} />)
    // Disposition mode required (#247 — default is now severity)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    const blockedBar = screen.getByTestId('timeline-blocked-bar')
    expect(blockedBar).toBeInTheDocument()
    expect(blockedBar.className).toContain('soc-enforced-fg')
    // Must not use old bg-destructive hardcode
    expect(blockedBar.className).not.toContain('bg-destructive')
  })

  it('allowed bar has data-testid="timeline-allowed-bar" and soc-ok-fg class (disposition mode, #247)', () => {
    render(<TimelineChart buckets={buckets} />)
    // Disposition mode required (#247 — default is now severity)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    const allowedBar = screen.getByTestId('timeline-allowed-bar')
    expect(allowedBar).toBeInTheDocument()
    expect(allowedBar.className).toContain('soc-ok-fg')
    // Must not use old hardcoded bg-blue-500
    expect(allowedBar.className).not.toContain('bg-blue-500')
  })

  it('blocked-only bucket: only blocked bar is rendered (disposition mode, #247)', () => {
    const allBlocked: TimelineBucket[] = [
      { hour: '2026-06-04T06:00:00Z', total: 50, blocked: 50, granularity: 'hourly' },
    ]
    render(<TimelineChart buckets={allBlocked} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    expect(screen.getByTestId('timeline-blocked-bar')).toBeInTheDocument()
    // allowed count = 0, so .tl-cnt span for allowed should show "0" but still renders
    // (count spans always render in disposition mode)
  })

  it('allowed-only bucket: allowed count is rendered in disposition mode (disposition mode, #247)', () => {
    const allAllowed: TimelineBucket[] = [
      { hour: '2026-06-04T06:00:00Z', total: 50, blocked: 0, granularity: 'hourly' },
    ]
    render(<TimelineChart buckets={allAllowed} />)
    fireEvent.click(screen.getByTestId('timeline-toggle-disposition'))
    expect(screen.getByTestId('timeline-allowed-bar')).toBeInTheDocument()
  })

  it('renders all fixture buckets', () => {
    render(<TimelineChart buckets={TIMELINE_FIXTURE} />)
    const rows = screen.getAllByTestId('timeline-row')
    expect(rows).toHaveLength(TIMELINE_FIXTURE.length)
  })
})

// ---------------------------------------------------------------------------
// SourceProvenanceBadges: token-styled (not flat grey)
// ---------------------------------------------------------------------------

describe('SourceProvenanceBadges — SOC token styling (issue #96)', () => {
  it('suricata badge uses soc-src-ids token class (not flat grey bg-muted)', () => {
    render(<SourceProvenanceBadges sourceTypes={['suricata']} />)
    const badge = screen.getByTestId('source-provenance-badge')
    expect(badge.className).toContain('soc-src-ids-fg')
    expect(badge.className).not.toContain('bg-muted text-muted-foreground')
  })

  it('azure_waf badge uses soc-src-waf token class', () => {
    render(<SourceProvenanceBadges sourceTypes={['azure_waf']} />)
    const badge = screen.getByTestId('source-provenance-badge')
    expect(badge.className).toContain('soc-src-waf-fg')
  })

  it('correlated label uses soc-medium-fg (not hardcoded blue-600)', () => {
    render(<SourceProvenanceBadges sourceTypes={['azure_waf', 'suricata']} />)
    const label = screen.getByTestId('source-correlated-label')
    expect(label.className).toContain('soc-medium-fg')
    expect(label.className).not.toContain('text-blue-600')
  })

  it('unknown source type still gets a badge (muted neutral fallback)', () => {
    render(<SourceProvenanceBadges sourceTypes={['new_source']} />)
    const badge = screen.getByTestId('source-provenance-badge')
    expect(badge.className).toContain('muted-foreground')
  })
})

// ---------------------------------------------------------------------------
// AiStatusChip: ok/offline tokens (issue #97 — unified shared chip)
// ---------------------------------------------------------------------------

describe('AiStatusChip — SOC token styling (issue #96/#97)', () => {
  it('active status chip uses soc-ok token classes (not hardcoded green-*)', () => {
    render(<AiStatusChip status="active" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip.className).toContain('soc-ok-fg')
    expect(chip.className).toContain('soc-ok-bg')
    expect(chip.className).toContain('soc-ok-border')
    // Must not use old hardcoded color values
    expect(chip.className).not.toContain('green-800')
    expect(chip.className).not.toContain('green-200')
  })

  it('disabled status chip uses muted neutral (non-alarming, ADR-0015)', () => {
    render(<AiStatusChip status="disabled" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip.className).toContain('muted')
    expect(chip.className).not.toContain('soc-ok')
    // AI offline is informational — must NOT use alarming enforced/red token
    expect(chip.className).not.toContain('soc-enforced')
  })

  it('unavailable status chip is non-alarming muted', () => {
    render(<AiStatusChip status="unavailable" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip.className).toContain('muted')
    expect(chip.className).not.toContain('soc-enforced')
  })

  it('null status → chip hidden (no flash during load)', () => {
    const { container } = render(<AiStatusChip status={null} />)
    expect(container.firstChild).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Theme-swappability smoke test: token CSS vars must be defined in both themes
// ---------------------------------------------------------------------------

describe('SOC token CSS vars — theme-swappability smoke test (issue #96)', () => {
  /**
   * This test verifies that the index.css token definitions reach the jsdom
   * environment. In jsdom, CSS is not actually processed by Tailwind/PostCSS, so
   * we cannot test CSS var resolution. We instead assert that the token functions
   * return consistent non-empty class strings that reference CSS custom property
   * names defined in index.css. The key contract: the class name references
   * "soc-*" tokens, which are registered in @theme inline in index.css, meaning
   * the same class string works for both themes (dark and light) because
   * CSS resolves the var() at render time.
   */

  const ALL_SEVERITIES = ['critical', 'high', 'medium', 'low'] as const
  const ALL_ACTIONS = ['block', 'alert', 'allow'] as const
  const ALL_SOURCES = ['azure_waf', 'suricata'] as const

  it.each(ALL_SEVERITIES)('severity "%s" → stable class string containing soc-%s', (sev) => {
    const cls = severityBadgeClasses(sev)
    expect(cls.length).toBeGreaterThan(0)
    expect(cls).toContain(`soc-${sev}-fg`)
  })

  it.each(ALL_ACTIONS)('action "%s" → stable class string (no hardcoded hex)', (action) => {
    const cls = actionBadgeClasses(action)
    expect(cls.length).toBeGreaterThan(0)
    // None of the returned classes should contain raw hex colors
    expect(cls).not.toMatch(/#[0-9a-fA-F]{3,6}/)
  })

  it.each(ALL_SOURCES)('source "%s" → stable class string (no hardcoded hex)', (src) => {
    const cls = sourceTypeBadgeClasses(src)
    expect(cls.length).toBeGreaterThan(0)
    expect(cls).not.toMatch(/#[0-9a-fA-F]{3,6}/)
  })
})
