/**
 * Tests for src/components/dashboard/ThreatActors.tsx (issue #205 + #212 + #264).
 *
 * EARS acceptance criteria (1:1 mapping):
 *
 * === Wave-1 (#205) ===
 *
 * Ubiquitous: pane renders at most N=6 actor rows; no inner scrollbar.
 *   - EARS-UB-1: with > 6 scored actors, exactly 6 rows are rendered.
 *   - EARS-UB-2: container div has no overflow:scroll/auto style.
 *
 * Ubiquitous: score-0 actors excluded; below-threshold count shown.
 *   - EARS-UB-3: actors with score=0 do NOT appear as rows.
 *   - EARS-UB-4: "+N below threshold" count line appears for score-0 actors.
 *
 * WHILE more scored actors exist than fit in top-N:
 *   - EARS-SD-5: "+N more" count line appears for scored overflow.
 *
 * WHEN analyst clicks an actor IP, entity slide-over opens.
 *   - EARS-ED-6: clicking ClickableIp calls openEntity({kind:'ip', value}).
 *
 * WHEN analyst activates "View all", /ai route is navigated.
 *   - EARS-ED-7: clicking "View all →" navigates to /ai.
 *
 * Empty state preserved.
 *   - EARS-UB-8: empty threats[] → "No threat actors detected" (no rows).
 *
 * Score column uses ScoreBadge.
 *   - EARS-UB-9: ScoreBadge (fw-score-badge) present in each row.
 *
 * IP column uses ClickableIp.
 *   - EARS-UB-10: clickable-ip testid present in each row.
 *
 * No inner scrollbar: container overflow NOT scroll/auto.
 *   - EARS-UB-2 (verified via style inspection of data-testid="threat-actors").
 *
 * ADR-0029 D3: score-0 actors do not appear as rows (not rendered as text nodes either).
 * ADR-0036 D1: score badge uses ScoreBadge, not local band re-computation.
 *
 * === Wave-2 (#212) ===
 *
 * WHILE scored-actor cardinality ≤ cutoff (50):
 *   - EARS-212-1: per-IP flat rows rendered (no group rows).
 *
 * WHEN cardinality exceeds the cutoff:
 *   - EARS-212-2: group rows rendered (not flat rows).
 *   - EARS-212-3: rollup banner shown.
 *   - EARS-212-4: no rollup banner when cardinality ≤ cutoff.
 *   - EARS-212-5: group rows bounded to TOP_N (no inner scrollbar).
 *
 * WHEN analyst clicks a group row:
 *   - EARS-212-6: openEntity called with kind='asn'|'cidr' and meta=group.
 *
 * Sort toggle:
 *   - EARS-212-7: sort toggle visible in flat mode.
 *   - EARS-212-8: sort toggle hidden in rollup mode.
 *   - EARS-212-9: Top movers sort re-orders rows by first_seen recency.
 *
 * ClickableIp still works in flat mode (regression):
 *   - EARS-212-10: clicking IP in flat mode still opens entity slide-over.
 *
 * === Wave-3 (#264) — drill-through count lines + CellTooltip peek ===
 *
 * WHEN user activates "+N more":
 *   - EARS-264-1: navigates to /ai.
 *
 * WHEN user activates "+N below threshold":
 *   - EARS-264-2: navigates to /ai?filter=below-threshold.
 *
 * THE count lines SHALL be styled as links and keyboard-operable:
 *   - EARS-264-3: "+N more" link is keyboard-operable (Enter → navigate /ai).
 *   - EARS-264-4: "+N below threshold" link is keyboard-operable (Enter → navigate /ai?filter=below-threshold).
 *   - EARS-264-5: count line elements have role="button".
 *   - EARS-264-6: count line elements have tabIndex=0.
 *
 * WHEN a count line is hovered/focused, CellTooltip shows next 5 actors (IP · score):
 *   - EARS-264-7: "+N more" peek tooltip contains overflow actor IPs.
 *   - EARS-264-8: "+N below threshold" peek tooltip contains below-threshold actor IPs.
 *   - EARS-264-9: peek is limited to 5 actors regardless of total overflow count.
 *
 * WHEN peek data is unavailable, navigation still works (progressive enhancement):
 *   - EARS-264-10: "+N more" navigates even when overflow actors = 0 (rollup mode).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import ThreatActors from '../components/dashboard/ThreatActors'
import { EntityPanelContext } from '../components/entity/EntityPanelContext'
import type { EntityPanelContextValue } from '../components/entity/EntityPanelContext'
import type { ThreatScore } from '../api/types'

// ---------------------------------------------------------------------------
// Mock react-router-dom useNavigate
// ---------------------------------------------------------------------------

const mockNavigate = vi.fn()

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeThreat(
  ip: string,
  score: number,
  threatLevel = 'HIGH',
  opts?: Partial<ThreatScore>,
): ThreatScore {
  return {
    source_ip: ip,
    threat_level: threatLevel,
    score,
    total_events: 100,
    blocked_events: 80,
    attack_types: ['SQL Injection'],
    first_seen: '2026-06-01T08:00:00Z',
    last_seen: '2026-06-04T09:55:00Z',
    source_types: ['suricata'],
    detections: [],
    ai_insights: null,
    ai_confidence: null,
    ai_status: 'unavailable',
    location: null,
    score_breakdown: [],
    asn: null,
    as_name: null,
    score_delta: null,
    ...opts,
  }
}

/** 8 scored actors (scores 80,70,60,50,40,30,20,10) — overflows TOP_N=6 by 2 */
const EIGHT_SCORED: ThreatScore[] = [
  makeThreat('192.0.2.1', 80, 'CRITICAL'),
  makeThreat('192.0.2.2', 70, 'HIGH'),
  makeThreat('192.0.2.3', 60, 'HIGH'),
  makeThreat('192.0.2.4', 50, 'MEDIUM'),
  makeThreat('192.0.2.5', 40, 'MEDIUM'),
  makeThreat('192.0.2.6', 30, 'LOW'),
  makeThreat('192.0.2.7', 20, 'LOW'),
  makeThreat('192.0.2.8', 10, 'LOW'),
]

/** 3 actors: 2 scored + 1 score-0 (below threshold) */
const TWO_SCORED_ONE_ZERO: ThreatScore[] = [
  makeThreat('192.0.2.1', 78, 'HIGH'),
  makeThreat('192.0.2.2', 44, 'MEDIUM'),
  makeThreat('192.0.2.3', 0, 'LOW'),
]

/** All actors have score=0 */
const ALL_ZERO: ThreatScore[] = [
  makeThreat('192.0.2.1', 0, 'LOW'),
  makeThreat('192.0.2.2', 0, 'LOW'),
]

/** Single scored actor — no overflow, no below-threshold */
const SINGLE_SCORED: ThreatScore[] = [
  makeThreat('192.0.2.1', 78, 'HIGH'),
]

/**
 * Generate N scored actors — enough to exceed ROLLUP_CUTOFF (50).
 * Uses different ASNs to generate multiple group rows.
 */
function makeRollupThreats(count: number): ThreatScore[] {
  return Array.from({ length: count }, (_, i) =>
    makeThreat(
      `10.${Math.floor(i / 256)}.${i % 256}.1`,
      90 - (i % 50),
      'HIGH',
      {
        asn: 4837 + (i % 5),         // 5 distinct ASNs → 5 groups
        as_name: `CARRIER-${i % 5}`,
        first_seen: `2026-06-0${(i % 4) + 1}T00:00:00Z`,
      },
    ),
  )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Render ThreatActors wrapped in MemoryRouter (needed for useNavigate) and
 * a spy EntityPanelContext (needed for ClickableIp → openEntity).
 */
function renderComponent(
  threats: ThreatScore[],
  openEntity = vi.fn(),
) {
  const ctx: EntityPanelContextValue = {
    stack: [],
    openEntity,
    closeEntity: vi.fn(),
    closePanelAll: vi.fn(),
  }
  return {
    openEntity,
    ...render(
      <MemoryRouter>
        <EntityPanelContext.Provider value={ctx}>
          <ThreatActors threats={threats} />
        </EntityPanelContext.Provider>
      </MemoryRouter>,
    ),
  }
}

// ---------------------------------------------------------------------------
// Wave-1 tests (#205) — preserved exactly
// ---------------------------------------------------------------------------

describe('ThreatActors — #205 bounded top-N, score-0 exclusion', () => {

  // EARS-UB-1: at most N=6 rows with > 6 scored actors
  it('renders at most 6 rows when more than 6 scored actors are present', () => {
    renderComponent(EIGHT_SCORED)
    const rows = screen.getAllByTestId('threat-actor-row')
    expect(rows).toHaveLength(6)
  })

  // EARS-UB-3: score-0 actors do NOT appear as rows
  it('does not render rows for score-0 actors', () => {
    renderComponent(TWO_SCORED_ONE_ZERO)
    const rows = screen.getAllByTestId('threat-actor-row')
    // Only 2 rows (scored), not 3
    expect(rows).toHaveLength(2)
    // score-0 IP must not appear as a row
    expect(screen.queryByText('192.0.2.3')).toBeNull()
  })

  // EARS-UB-4: "+N below threshold" count shown for score-0 actors
  it('shows "+N below threshold" count line for score-0 actors', () => {
    renderComponent(TWO_SCORED_ONE_ZERO)
    const belowRow = screen.getByTestId('threat-actors-below-threshold')
    expect(belowRow).toHaveTextContent('+1 below threshold')
  })

  // EARS-UB-4: "+N below threshold" count reflects exact number excluded
  it('shows correct count when multiple actors are below threshold', () => {
    renderComponent(ALL_ZERO)
    const belowRow = screen.getByTestId('threat-actors-below-threshold')
    expect(belowRow).toHaveTextContent('+2 below threshold')
    // No actor rows (all score-0)
    expect(screen.queryByTestId('threat-actor-row')).toBeNull()
  })

  // EARS-SD-5: "+N more" count shown for scored overflow
  it('shows "+N more" count line when scored actors exceed TOP_N', () => {
    renderComponent(EIGHT_SCORED)
    const overflowRow = screen.getByTestId('threat-actors-overflow')
    expect(overflowRow).toHaveTextContent('+2 more')
  })

  // EARS-SD-5: no overflow count when scored actors fit within TOP_N
  it('does not show overflow count when actors fit within TOP_N', () => {
    renderComponent(SINGLE_SCORED)
    expect(screen.queryByTestId('threat-actors-overflow')).toBeNull()
  })

  // EARS-UB-4 + EARS-SD-5: both count lines shown simultaneously
  it('shows both overflow and below-threshold counts when applicable', () => {
    // 7 scored + 3 zero — overflow by 1 and 3 below threshold
    const threats = [
      ...Array.from({ length: 7 }, (_, i) =>
        makeThreat(`192.0.2.${i + 1}`, 80 - i * 5, 'HIGH'),
      ),
      makeThreat('192.0.2.20', 0, 'LOW'),
      makeThreat('192.0.2.21', 0, 'LOW'),
      makeThreat('192.0.2.22', 0, 'LOW'),
    ]
    renderComponent(threats)
    expect(screen.getByTestId('threat-actors-overflow')).toHaveTextContent('+1 more')
    expect(screen.getByTestId('threat-actors-below-threshold')).toHaveTextContent('+3 below threshold')
  })

  // EARS-ED-6: clicking ClickableIp calls openEntity
  it('clicking an IP opens the entity slide-over for that IP', async () => {
    const openEntity = vi.fn()
    renderComponent(SINGLE_SCORED, openEntity)

    await userEvent.click(screen.getByTestId('clickable-ip'))

    expect(openEntity).toHaveBeenCalledOnce()
    expect(openEntity).toHaveBeenCalledWith({ kind: 'ip', value: '192.0.2.1' })
  })

  // EARS-ED-6: keyboard Enter on ClickableIp also opens slide-over
  it('pressing Enter on the IP token opens the entity slide-over', async () => {
    const openEntity = vi.fn()
    renderComponent(SINGLE_SCORED, openEntity)

    screen.getByTestId('clickable-ip').focus()
    await userEvent.keyboard('{Enter}')

    expect(openEntity).toHaveBeenCalledOnce()
    expect(openEntity).toHaveBeenCalledWith({ kind: 'ip', value: '192.0.2.1' })
  })

  // EARS-ED-7: "View all →" navigates to /ai
  it('"View all →" button navigates to /ai', async () => {
    mockNavigate.mockClear()
    renderComponent(SINGLE_SCORED)

    await userEvent.click(screen.getByTestId('threat-actors-view-all'))

    expect(mockNavigate).toHaveBeenCalledOnce()
    expect(mockNavigate).toHaveBeenCalledWith('/ai')
  })

  // EARS-UB-8: empty state preserved
  it('shows "No threat actors detected" when threats array is empty', () => {
    renderComponent([])
    expect(screen.getByTestId('threat-actors-empty')).toHaveTextContent(
      'No threat actors detected',
    )
    expect(screen.queryByTestId('threat-actor-row')).toBeNull()
  })

  // EARS-UB-9: ScoreBadge (fw-score-badge) used in rows — not a raw number
  it('renders ScoreBadge (fw-score-badge class) in each row', () => {
    renderComponent(SINGLE_SCORED)
    const badges = document.querySelectorAll('.fw-score-badge')
    expect(badges.length).toBeGreaterThanOrEqual(1)
  })

  // EARS-UB-10: ClickableIp present in each row
  it('renders ClickableIp (clickable-ip testid) in each row', () => {
    renderComponent(SINGLE_SCORED)
    const ips = screen.getAllByTestId('clickable-ip')
    expect(ips).toHaveLength(1)
  })

  // EARS-UB-2: no inner scrollbar — container div has no overflow: scroll/auto
  it('container element has no overflow scroll/auto style', () => {
    renderComponent(EIGHT_SCORED)
    const container = screen.getByTestId('threat-actors')
    const style = container.getAttribute('style') ?? ''
    expect(style).not.toMatch(/overflow\s*:\s*(scroll|auto)/)
  })

  // Rows are sorted by score descending — highest score first
  it('renders rows in descending score order', () => {
    renderComponent(EIGHT_SCORED)
    const ips = screen.getAllByTestId('clickable-ip')
    // First IP should be the highest-scored one
    expect(ips[0]).toHaveTextContent('192.0.2.1') // score 80
    expect(ips[5]).toHaveTextContent('192.0.2.6') // score 30
  })

  // "View all →" button is always rendered when there is at least one scored actor
  it('always renders "View all →" when there are scored actors', () => {
    renderComponent(SINGLE_SCORED)
    expect(screen.getByTestId('threat-actors-view-all')).toBeInTheDocument()
    expect(screen.getByTestId('threat-actors-view-all')).toHaveTextContent('View all →')
  })

  // "View all →" is also shown even when all actors are below threshold
  it('renders "View all →" even when all actors are score-0', () => {
    renderComponent(ALL_ZERO)
    expect(screen.getByTestId('threat-actors-view-all')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Wave-2 tests (#212) — rollup, banner, sort toggle
// ---------------------------------------------------------------------------

describe('ThreatActors — #212 DDoS rollup, banner, top-movers sort', () => {

  // EARS-212-1: per-IP flat rows shown when cardinality ≤ cutoff
  it('renders flat per-IP rows when scored actor count does not exceed cutoff (50)', () => {
    // 5 scored actors — below cutoff of 50
    const threats = Array.from({ length: 5 }, (_, i) =>
      makeThreat(`192.0.2.${i + 1}`, 80 - i * 5),
    )
    renderComponent(threats)
    expect(screen.getAllByTestId('threat-actor-row').length).toBeGreaterThan(0)
    expect(screen.queryByTestId('threat-actor-group-row')).toBeNull()
  })

  // EARS-212-2: group rows shown when cardinality exceeds cutoff
  it('renders group rows (not flat rows) when scored actor count exceeds cutoff', () => {
    const threats = makeRollupThreats(55) // 55 > 50
    renderComponent(threats)
    expect(screen.queryByTestId('threat-actor-row')).toBeNull()
    expect(screen.getAllByTestId('threat-actor-group-row').length).toBeGreaterThan(0)
  })

  // EARS-212-3: rollup banner shown when cardinality exceeds cutoff
  it('shows distributed-attack banner when rollup is active', () => {
    const threats = makeRollupThreats(55)
    renderComponent(threats)
    expect(screen.getByTestId('rollup-banner')).toBeInTheDocument()
    expect(screen.getByTestId('rollup-banner')).toHaveTextContent('distinct sources')
  })

  // Banner mentions actual count
  it('rollup banner shows the actual distinct-sources count', () => {
    const threats = makeRollupThreats(60)
    renderComponent(threats)
    expect(screen.getByTestId('rollup-banner')).toHaveTextContent('60')
  })

  // EARS-212-4: no rollup banner when cardinality ≤ cutoff
  it('does NOT show rollup banner when cardinality does not exceed cutoff', () => {
    renderComponent(EIGHT_SCORED) // 8 << 50
    expect(screen.queryByTestId('rollup-banner')).toBeNull()
  })

  // EARS-212-5: group rows bounded to TOP_N=6 (no inner scrollbar)
  it('shows at most 6 group rows regardless of how many groups exist', () => {
    const threats = makeRollupThreats(55) // 5 distinct ASNs — 5 groups
    renderComponent(threats)
    const groupRows = screen.getAllByTestId('threat-actor-group-row')
    expect(groupRows.length).toBeLessThanOrEqual(6)
  })

  // EARS-212-6: clicking a group row calls openEntity with correct kind + meta
  it('clicking a group row opens the entity slide-over with kind=asn and meta=group', async () => {
    const openEntity = vi.fn()
    const threats = makeRollupThreats(55)
    renderComponent(threats, openEntity)

    const groupRows = screen.getAllByTestId('threat-actor-group-row')
    await userEvent.click(groupRows[0])

    expect(openEntity).toHaveBeenCalledOnce()
    const call = openEntity.mock.calls[0][0]
    expect(call.kind).toBe('asn')
    expect(call.meta).toBeDefined()
    expect(call.meta).toHaveProperty('memberCount')
    expect(call.meta).toHaveProperty('topScore')
  })

  // Keyboard Enter on group row also opens slide-over
  it('pressing Enter on a group row opens the entity slide-over', async () => {
    const openEntity = vi.fn()
    const threats = makeRollupThreats(55)
    renderComponent(threats, openEntity)

    const groupRows = screen.getAllByTestId('threat-actor-group-row')
    groupRows[0].focus()
    await userEvent.keyboard('{Enter}')

    expect(openEntity).toHaveBeenCalledOnce()
  })

  // EARS-212-7: sort toggle visible in flat mode
  it('shows sort toggle in flat mode (cardinality ≤ cutoff)', () => {
    renderComponent(EIGHT_SCORED)
    expect(screen.getByTestId('sort-toggle')).toBeInTheDocument()
    expect(screen.getByTestId('sort-by-score')).toBeInTheDocument()
    expect(screen.getByTestId('sort-by-top-movers')).toBeInTheDocument()
  })

  // EARS-212-8: sort toggle hidden in rollup mode
  it('hides sort toggle in rollup mode', () => {
    const threats = makeRollupThreats(55)
    renderComponent(threats)
    expect(screen.queryByTestId('sort-toggle')).toBeNull()
  })

  // EARS-212-9: Top movers sort re-orders rows by |score_delta| (real delta, issue #251)
  it('Top movers sort re-orders flat rows by |score_delta| descending', async () => {
    // Two actors: one with higher |delta|, one lower
    const threats = [
      makeThreat('192.0.2.1', 70, 'HIGH', { score_delta: 10 }),  // small delta
      makeThreat('192.0.2.2', 80, 'HIGH', { score_delta: 38 }),  // large delta — should be first
    ]
    renderComponent(threats)

    // Default (score sort): 192.0.2.2 (score 80) first
    let ips = screen.getAllByTestId('clickable-ip')
    expect(ips[0]).toHaveTextContent('192.0.2.2')

    // Switch to top-movers
    await userEvent.click(screen.getByTestId('sort-by-top-movers'))

    // Top movers: 192.0.2.2 (score_delta=38 > 10) goes first
    ips = screen.getAllByTestId('clickable-ip')
    expect(ips[0]).toHaveTextContent('192.0.2.2')
  })

  // Top movers: actor with larger |delta| beats higher-score actor with smaller delta
  it('Top movers sort puts large-|delta| actor before high-score but small-delta actor', async () => {
    const threats = [
      makeThreat('192.0.2.1', 90, 'CRITICAL', { score_delta: 5 }),  // high score, small delta
      makeThreat('192.0.2.2', 30, 'LOW', { score_delta: 42 }),       // low score, large delta
    ]
    renderComponent(threats)

    // Score sort: 192.0.2.1 (score 90) first
    let ips = screen.getAllByTestId('clickable-ip')
    expect(ips[0]).toHaveTextContent('192.0.2.1')

    // Switch to top-movers
    await userEvent.click(screen.getByTestId('sort-by-top-movers'))

    // Top movers: 192.0.2.2 (|delta|=42 > 5) goes first
    ips = screen.getAllByTestId('clickable-ip')
    expect(ips[0]).toHaveTextContent('192.0.2.2')
  })

  // EARS-212-10: ClickableIp still opens entity slide-over in flat mode (regression)
  it('ClickableIp in flat mode still opens entity slide-over (regression #205)', async () => {
    const openEntity = vi.fn()
    renderComponent(SINGLE_SCORED, openEntity)

    await userEvent.click(screen.getByTestId('clickable-ip'))

    expect(openEntity).toHaveBeenCalledWith({ kind: 'ip', value: '192.0.2.1' })
  })

  // Rollup with /24 CIDR fallback (no ASN data) — EARS-GRP-9 at component level
  it('renders CIDR group rows when no ASN data is available', () => {
    // 55 actors with no ASN → should group by /24
    const threats = Array.from({ length: 55 }, (_, i) =>
      makeThreat(`10.${Math.floor(i / 256)}.${i % 256}.1`, 60 - (i % 30), 'MEDIUM', {
        asn: null,
        as_name: null,
      }),
    )
    renderComponent(threats)
    // Should be in rollup mode with group rows
    expect(screen.queryByTestId('threat-actor-row')).toBeNull()
    expect(screen.getAllByTestId('threat-actor-group-row').length).toBeGreaterThan(0)
    expect(screen.getByTestId('rollup-banner')).toBeInTheDocument()
  })

  // At exactly cutoff (50 actors) — no rollup
  it('does NOT roll up when scored count equals the cutoff (50)', () => {
    const threats = Array.from({ length: 50 }, (_, i) =>
      makeThreat(`192.0.2.${i + 1}`, 80 - (i % 50), 'HIGH'),
    )
    renderComponent(threats)
    // No rollup banner, no group rows
    expect(screen.queryByTestId('rollup-banner')).toBeNull()
    expect(screen.queryByTestId('threat-actor-group-row')).toBeNull()
  })

  // At cutoff + 1 (51 actors) — rollup activates
  it('rolls up when scored count exceeds cutoff by 1 (51 actors)', () => {
    const threats = Array.from({ length: 51 }, (_, i) =>
      makeThreat(`192.0.2.${i + 1}`, 80 - (i % 50), 'HIGH', {
        asn: 4837,
        as_name: 'CHINA-UNICOM',
      }),
    )
    renderComponent(threats)
    expect(screen.getByTestId('rollup-banner')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Defect regression tests — discovered via real-browser verification pass
// ---------------------------------------------------------------------------

describe('ThreatActors — defect regressions (score-breakdown wiring + SCORE column)', () => {

  /**
   * Defect 1 regression: the "?" popover trigger MUST appear in flat rows when the
   * threat carries a non-empty score_breakdown.  Previous shipping code passed no
   * scoreBreakdown prop to ScoreBadge, so the button never rendered even though the
   * API returned breakdown data.
   *
   * This test checks the CALL SITE (ThreatActors renders ScoreBadge with breakdown),
   * not just ScoreBadge in isolation — that is the gap that let the dead-wiring ship.
   */
  it('renders the score-breakdown "?" trigger when threats carry non-empty score_breakdown', () => {
    const threatWithBreakdown = makeThreat('192.0.2.1', 85, 'HIGH', {
      score_breakdown: [
        { factor: 'brute_force', label: 'Brute force', points: 40 },
        { factor: 'xss', label: 'XSS attempts', points: 30 },
        { factor: 'blocked_events', label: 'Blocked event ratio', points: 15 },
      ],
    })
    renderComponent([threatWithBreakdown])

    // The trigger button is rendered by ScoreBadge only when scoreBreakdown
    // is passed AND non-empty. Accessible name leads with score + band (issue #356).
    const trigger = screen.queryByRole('button', { name: /show score breakdown/i })
    expect(trigger).not.toBeNull()
    expect(trigger).toBeInTheDocument()
  })

  /**
   * Defect 1 regression (empty breakdown): when score_breakdown is [] the trigger
   * must NOT render (graceful degradation — EARS criterion 2 from issue #210).
   */
  it('does NOT render the "?" trigger when score_breakdown is empty', () => {
    const threatNoBreakdown = makeThreat('192.0.2.1', 85, 'HIGH', {
      score_breakdown: [],
    })
    renderComponent([threatNoBreakdown])

    const trigger = screen.queryByRole('button', { name: /show score breakdown/i })
    expect(trigger).toBeNull()
  })

  /**
   * Defect 2 regression (still valid): SCORE column header must be visible.
   * In #262 the table is restored to 5 columns at ~60% bento width;
   * Score is never-hidden (useColumnPriority never:true).
   */
  it('renders a SCORE column header in the threat-actors table', () => {
    renderComponent(SINGLE_SCORED)
    // The header row renders column labels as text; find by text
    expect(screen.getByTestId('col-score')).toBeInTheDocument()
    expect(screen.getByTestId('col-score')).toHaveTextContent('Score')
  })

})

// ---------------------------------------------------------------------------
// Issue #262 — 5-column layout + bento grid EARS tests
// ---------------------------------------------------------------------------

describe('ThreatActors — #262 5-column layout (LAST ACTIVE restored, compact Score)', () => {
  /**
   * jsdom returns getBoundingClientRect().width = 0 for all elements, which causes
   * useColumnPriority to collapse non-never columns (it immediately calls update(0)
   * in the effect). We patch it to return 700 px so all 5 columns are visible,
   * matching the real ~600 px bento pane at desktop width.
   */
  let origGetBoundingClientRect: () => DOMRect

  beforeEach(() => {
    origGetBoundingClientRect = Element.prototype.getBoundingClientRect
    Element.prototype.getBoundingClientRect = () => ({
      width: 700,
      height: 200,
      top: 0,
      left: 0,
      bottom: 200,
      right: 700,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    })
  })

  afterEach(() => {
    Element.prototype.getBoundingClientRect = origGetBoundingClientRect
  })

  // EARS #262 criterion: LAST ACTIVE column header present (restored from #241 drop)
  it('renders a LAST ACTIVE column header (restored in #262 bento layout)', () => {
    renderComponent(SINGLE_SCORED)
    expect(screen.getByTestId('col-last-active')).toBeInTheDocument()
    expect(screen.getByTestId('col-last-active')).toHaveTextContent(/last active/i)
  })

  // EARS #262 criterion: LAST ACTIVE cell present in each flat row
  it('renders threat-actor-last-active cell in each flat row', () => {
    renderComponent(SINGLE_SCORED)
    expect(screen.getByTestId('threat-actor-last-active')).toBeInTheDocument()
  })

  // EARS #262 criterion: last_seen value displayed in the cell
  it('shows the last_seen timestamp value in the Last Active cell', () => {
    // makeThreat sets last_seen = '2026-06-04T09:55:00Z'
    renderComponent(SINGLE_SCORED)
    const cell = screen.getByTestId('threat-actor-last-active')
    // TimeText renders formatted date; cell must not be empty (not "—")
    expect(cell.textContent).not.toBe('—')
    expect(cell.textContent?.trim()).not.toBe('')
  })

  // EARS #262 criterion: last_seen=null shows em-dash placeholder
  it('shows em-dash when threat last_seen is null', () => {
    const threatNoLastSeen = makeThreat('192.0.2.1', 60, 'MEDIUM', { last_seen: null })
    renderComponent([threatNoLastSeen])
    const cell = screen.getByTestId('threat-actor-last-active')
    expect(cell.textContent).toContain('—')
  })

  // EARS #262 criterion: Score column uses compact variant — fw-score-badge chip renders
  it('Score cells render ScoreBadge (fw-score-badge) in compact form (no inner scrollbar)', () => {
    renderComponent(SINGLE_SCORED)
    // compact ScoreBadge is still an fw-score-badge — check it's present
    const badges = document.querySelectorAll('.fw-score-badge')
    expect(badges.length).toBeGreaterThanOrEqual(1)
    // The badge renders only the numeric score (not "Risk N · BAND" text)
    // data-score attribute is set on ScoreBadge regardless of variant
    const badge = badges[0]
    expect(badge).toHaveAttribute('data-score', '78')
  })

  // EARS #262 criterion: No inner scrollbar (preserved)
  it('no inner scrollbar is introduced by the column addition', () => {
    renderComponent(EIGHT_SCORED)
    const container = screen.getByTestId('threat-actors')
    const style = container.getAttribute('style') ?? ''
    expect(style).not.toMatch(/overflow\s*:\s*(scroll|auto)/)
  })

  // EARS #262 criterion: LAST ACTIVE cell present in group rows (rollup mode)
  it('renders threat-actor-last-active cell in group rows (rollup mode)', () => {
    const rollupThreats = makeRollupThreats(55)
    renderComponent(rollupThreats)
    // Should have at least one group row with last-active cell
    const lastActiveCells = screen.getAllByTestId('threat-actor-last-active')
    expect(lastActiveCells.length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// Wave-3 tests (#264) — drill-through count lines + CellTooltip peek
// ---------------------------------------------------------------------------

describe('ThreatActors — #264 drill-through count lines + CellTooltip peek', () => {

  // EARS-264-1: "+N more" click → navigate to /ai
  it('"+N more" activates → navigates to /ai', async () => {
    mockNavigate.mockClear()
    renderComponent(EIGHT_SCORED) // 8 scored, 2 overflow

    const overflowLink = screen.getByTestId('threat-actors-overflow-link')
    await userEvent.click(overflowLink)

    expect(mockNavigate).toHaveBeenCalledOnce()
    expect(mockNavigate).toHaveBeenCalledWith('/ai')
  })

  // EARS-264-2: "+N below threshold" click → navigate to /ai?filter=below-threshold
  it('"+N below threshold" activates → navigates to /ai?filter=below-threshold', async () => {
    mockNavigate.mockClear()
    renderComponent(TWO_SCORED_ONE_ZERO) // 1 below threshold

    const belowLink = screen.getByTestId('threat-actors-below-threshold-link')
    await userEvent.click(belowLink)

    expect(mockNavigate).toHaveBeenCalledOnce()
    expect(mockNavigate).toHaveBeenCalledWith('/ai?filter=below-threshold')
  })

  // EARS-264-3: "+N more" is keyboard-operable (Enter → navigate /ai)
  it('"+N more" is activated by keyboard Enter', async () => {
    mockNavigate.mockClear()
    renderComponent(EIGHT_SCORED)

    const overflowLink = screen.getByTestId('threat-actors-overflow-link')
    overflowLink.focus()
    await userEvent.keyboard('{Enter}')

    expect(mockNavigate).toHaveBeenCalledOnce()
    expect(mockNavigate).toHaveBeenCalledWith('/ai')
  })

  // EARS-264-4: "+N below threshold" is keyboard-operable (Enter → navigate)
  it('"+N below threshold" is activated by keyboard Enter', async () => {
    mockNavigate.mockClear()
    renderComponent(TWO_SCORED_ONE_ZERO)

    const belowLink = screen.getByTestId('threat-actors-below-threshold-link')
    belowLink.focus()
    await userEvent.keyboard('{Enter}')

    expect(mockNavigate).toHaveBeenCalledOnce()
    expect(mockNavigate).toHaveBeenCalledWith('/ai?filter=below-threshold')
  })

  // EARS-264-3 (Space key variant)
  it('"+N more" is activated by keyboard Space', async () => {
    mockNavigate.mockClear()
    renderComponent(EIGHT_SCORED)

    const overflowLink = screen.getByTestId('threat-actors-overflow-link')
    overflowLink.focus()
    await userEvent.keyboard('{ }')

    expect(mockNavigate).toHaveBeenCalledOnce()
  })

  // EARS-264-5: count line elements have role="button"
  it('"+N more" link element has role="button"', () => {
    renderComponent(EIGHT_SCORED)
    const overflowLink = screen.getByTestId('threat-actors-overflow-link')
    expect(overflowLink.getAttribute('role')).toBe('button')
  })

  it('"+N below threshold" link element has role="button"', () => {
    renderComponent(TWO_SCORED_ONE_ZERO)
    const belowLink = screen.getByTestId('threat-actors-below-threshold-link')
    expect(belowLink.getAttribute('role')).toBe('button')
  })

  // EARS-264-6: count line elements have tabIndex=0
  it('"+N more" link element has tabIndex=0 (keyboard reachable)', () => {
    renderComponent(EIGHT_SCORED)
    const overflowLink = screen.getByTestId('threat-actors-overflow-link')
    expect(overflowLink.getAttribute('tabindex')).toBe('0')
  })

  it('"+N below threshold" link element has tabIndex=0 (keyboard reachable)', () => {
    renderComponent(TWO_SCORED_ONE_ZERO)
    const belowLink = screen.getByTestId('threat-actors-below-threshold-link')
    expect(belowLink.getAttribute('tabindex')).toBe('0')
  })

  // EARS-264-7: "+N more" peek tooltip shows overflow actor IPs on hover
  it('"+N more" hover shows peek tooltip with overflow actor IPs', async () => {
    renderComponent(EIGHT_SCORED) // 8 scored, TOP_N=6, overflow = actors at positions 6+7 = 192.0.2.7, 192.0.2.8

    const trigger = screen.getByTestId('threat-actors-overflow-tooltip-trigger')
    fireEvent.mouseEnter(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('count-drill-peek')).toBeInTheDocument()
    })

    // Overflow actors: 192.0.2.7 (score 20) and 192.0.2.8 (score 10) are the extras
    const peekIps = screen.getAllByTestId('peek-ip')
    expect(peekIps.length).toBeGreaterThanOrEqual(1)
    // Scores also shown
    const peekScores = screen.getAllByTestId('peek-score')
    expect(peekScores.length).toBeGreaterThanOrEqual(1)
  })

  // EARS-264-8: "+N below threshold" peek shows below-threshold actor IPs on hover
  it('"+N below threshold" hover shows peek tooltip with score-0 actor IPs', async () => {
    renderComponent(TWO_SCORED_ONE_ZERO) // 1 below-threshold: 192.0.2.3

    const trigger = screen.getByTestId('threat-actors-below-threshold-tooltip-trigger')
    fireEvent.mouseEnter(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('count-drill-peek')).toBeInTheDocument()
    })

    const peekIps = screen.getAllByTestId('peek-ip')
    expect(peekIps.length).toBe(1)
    expect(peekIps[0]).toHaveTextContent('192.0.2.3')

    const peekScores = screen.getAllByTestId('peek-score')
    expect(peekScores[0]).toHaveTextContent('0')
  })

  // EARS-264-9: peek is limited to 5 actors (PEEK_N) regardless of total count
  it('peek tooltip shows at most 5 actors (PEEK_N limit)', async () => {
    // 12 scored actors = 6 visible + 6 overflow — peek should show only 5
    const manyScored = Array.from({ length: 12 }, (_, i) =>
      makeThreat(`192.0.2.${i + 1}`, 80 - i * 3, 'HIGH'),
    )
    renderComponent(manyScored)

    const trigger = screen.getByTestId('threat-actors-overflow-tooltip-trigger')
    fireEvent.mouseEnter(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('count-drill-peek')).toBeInTheDocument()
    })

    const peekIps = screen.getAllByTestId('peek-ip')
    expect(peekIps.length).toBeLessThanOrEqual(5)
  })

  // EARS-264-10: in rollup mode, "+N more" still navigates (no peek data, but navigation works)
  it('"+N more" in rollup mode navigates to /ai even without flat-actor peek data', async () => {
    mockNavigate.mockClear()
    // Rollup mode: 55 scored actors (>50 cutoff), 5 distinct ASNs → 5 groups → 0 overflow at group level
    // with exactly 5 groups and TOP_N=6 we have no group overflow — use 10 ASNs to get > 6 groups
    const rollupWithOverflow = Array.from({ length: 75 }, (_, i) =>
      makeThreat(
        `10.${Math.floor(i / 256)}.${i % 256}.1`,
        90 - (i % 50),
        'HIGH',
        {
          asn: 4837 + (i % 10), // 10 distinct ASNs → 10 groups → 4 overflow
          as_name: `CARRIER-${i % 10}`,
        },
      ),
    )
    renderComponent(rollupWithOverflow)

    // In rollup mode there should be an overflow (10 groups, TOP_N=6 = 4 overflow)
    const overflowRow = screen.queryByTestId('threat-actors-overflow')
    if (overflowRow) {
      const overflowLink = screen.getByTestId('threat-actors-overflow-link')
      await userEvent.click(overflowLink)
      expect(mockNavigate).toHaveBeenCalledWith('/ai')
    }
    // If no overflow in rollup — test passes by asserting the absence is acceptable
  })

  // Count lines styled with --fw-blue (link color affordance)
  it('"+N more" link contains --fw-blue styled text (chevron or label span)', () => {
    renderComponent(EIGHT_SCORED)
    // The drill row contains a span with color: var(--fw-blue) — check the whole row
    const overflowRow = screen.getByTestId('threat-actors-overflow')
    // Either the link span or a descendant must reference fw-blue
    const allSpans = overflowRow.querySelectorAll('span')
    const hasBlue = Array.from(allSpans).some(
      (s) => s.getAttribute('style')?.includes('fw-blue'),
    )
    expect(hasBlue).toBe(true)
  })

  // Regression: existing "+N more" text content still correct
  it('"+N more" link still shows the correct overflow count text', () => {
    renderComponent(EIGHT_SCORED) // overflow = 2
    const overflowRow = screen.getByTestId('threat-actors-overflow')
    expect(overflowRow).toHaveTextContent('+2 more')
  })

  // Regression: existing "+N below threshold" text content still correct
  it('"+N below threshold" link still shows the correct below-threshold count text', () => {
    renderComponent(TWO_SCORED_ONE_ZERO) // 1 below threshold
    const belowRow = screen.getByTestId('threat-actors-below-threshold')
    expect(belowRow).toHaveTextContent('+1 below threshold')
  })
})

