/**
 * Tests for src/components/dashboard/RiskMovers.tsx (issue #251).
 *
 * Consumer-level integration test — exercises the component with a mocked
 * /threats + score-history pair (the #241 dead-wire lesson: assert integration,
 * not just the unit).
 *
 * EARS acceptance criteria (1:1 mapping):
 *
 * Ubiquitous: the former "IP threat scores" card SHALL NOT render; Risk Movers SHALL render.
 *   - EARS-RM-1: no "ip-threat-scores" testid; "risk-movers" testid present.
 *
 * Ubiquitous: each mover row SHALL show ClickableIp, banded ScoreBadge, signed delta, Sparkline.
 *   - EARS-RM-2: rows contain clickable-ip, fw-score-badge, mover-delta testids.
 *   - EARS-RM-3: sparkline rendered (role="img") for each known-delta actor.
 *
 * WHEN score_delta is null (new actor): row SHALL show a NEW badge, no fabricated delta.
 *   - EARS-RM-4: null-delta rows show "new-actor-badge", not "mover-delta".
 *
 * Ubiquitous: movers sorted by |score_delta| descending.
 *   - EARS-RM-5: rows are ordered by |delta| (highest first).
 *
 * WHILE threats array is empty: empty state renders.
 *   - EARS-RM-6: "risk-movers-empty" testid shown when no movers.
 *
 * WHILE #213 is unshipped: no AI-attributed text renders (ADR-0035).
 *   - EARS-RM-7: no text starting with "AI" or "LLM" in the rendered pane.
 *
 * No inner scrollbar (ADR-0017).
 *   - EARS-RM-8: container element has no overflow: scroll/auto.
 *
 * Pane title states the window (abbreviated).
 *   - EARS-RM-9: AiSidebar renders "Risk Movers · 1h" in the heading (issue #331).
 *
 * WHEN a row renders: the time window SHALL NOT appear in the row (issue #331).
 *   - EARS-RM-11: no "1h" or "last" text in the mover-delta span.
 *
 * Ubiquitous: every Risk Movers row SHALL render on a single line — no wrap (issue #331).
 *   - EARS-RM-12: table cell nodes have white-space: nowrap (table layout replaces flex-nowrap).
 *
 * Issue #615 — real <table> with colgroup (IP | Score | Delta/NEW).
 *   - EARS-615-1: risk-movers container is a <table> element.
 *   - EARS-615-2: <colgroup> with 3 <col>s is present.
 *   - EARS-615-3: sparkline is preserved in a colspan=3 detail row per entry.
 *
 * Issue #616 — ScoreBadge compact variant, no '?' glyph.
 *   - EARS-616-1: data-variant="compact" on every score badge inside the table.
 *   - EARS-616-2: no literal '?' character in the risk-movers container text.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import RiskMovers from '../components/dashboard/RiskMovers'
import AiSidebar from '../components/dashboard/AiSidebar'
import { EntityPanelContext } from '../components/entity/EntityPanelContext'
import type { EntityPanelContextValue } from '../components/entity/EntityPanelContext'
import type { ThreatScore } from '../api/types'
import { fetchScoreHistory } from '../api/client'

// ---------------------------------------------------------------------------
// Mock fetchScoreHistory — returns empty series (score-history endpoint has a
// known wiring gap in #250; component degrades gracefully per Sparkline contract)
// ---------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  fetchScoreHistory: vi.fn().mockResolvedValue([]),
}))

const mockFetchScoreHistory = vi.mocked(fetchScoreHistory)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeThreat(
  ip: string,
  score: number,
  score_delta: number | null,
  opts?: Partial<ThreatScore>,
): ThreatScore {
  return {
    source_ip: ip,
    threat_level: score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW',
    score,
    total_events: 100,
    blocked_events: 60,
    attack_types: ['SQL Injection'],
    first_seen: '2026-06-01T00:00:00Z',
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
    score_delta,
    ...opts,
  }
}

/** Two scored actors: one with a known delta, one new. */
const MIXED_FIXTURE: ThreatScore[] = [
  makeThreat('192.0.2.1', 78, 38),    // known delta
  makeThreat('192.0.2.2', 50, null),  // new actor
]

/** Three scored actors ordered to test delta sort. */
const THREE_MOVERS: ThreatScore[] = [
  makeThreat('192.0.2.1', 60, 10),
  makeThreat('192.0.2.2', 70, 38),   // largest |delta|
  makeThreat('192.0.2.3', 50, 5),
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderRiskMovers(threats: ThreatScore[]) {
  const ctx: EntityPanelContextValue = {
    stack: [],
    openEntity: vi.fn(),
    closeEntity: vi.fn(),
    closePanelAll: vi.fn(),
  }
  return render(
    <MemoryRouter>
      <EntityPanelContext.Provider value={ctx}>
        <RiskMovers threats={threats} />
      </EntityPanelContext.Provider>
    </MemoryRouter>,
  )
}

function renderAiSidebar(threats: ThreatScore[]) {
  const ctx: EntityPanelContextValue = {
    stack: [],
    openEntity: vi.fn(),
    closeEntity: vi.fn(),
    closePanelAll: vi.fn(),
  }
  return render(
    <MemoryRouter>
      <EntityPanelContext.Provider value={ctx}>
        {/* CR6 (#617): AiSidebar now requires onAction (passed to compact RecommendationCards) */}
        <AiSidebar threats={threats} onAction={vi.fn()} />
      </EntityPanelContext.Provider>
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// Clear mocks between tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
})

// ---------------------------------------------------------------------------
// EARS-RM-1: Risk Movers replaces "IP threat scores"
// ---------------------------------------------------------------------------

describe('RiskMovers — replaces "IP threat scores" card', () => {
  it('renders the risk-movers container (not ip-threat-scores)', () => {
    renderRiskMovers(MIXED_FIXTURE)
    expect(screen.getByTestId('risk-movers')).toBeInTheDocument()
    expect(screen.queryByTestId('ip-threat-scores')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// EARS-RM-2 + EARS-RM-3: Row anatomy (ClickableIp, ScoreBadge, delta, Sparkline)
// ---------------------------------------------------------------------------

describe('RiskMovers — row anatomy', () => {
  it('renders ClickableIp in each row', () => {
    renderRiskMovers(MIXED_FIXTURE)
    const rows = screen.getAllByTestId('risk-mover-row')
    expect(rows.length).toBeGreaterThanOrEqual(1)
    // ClickableIp should appear in rows
    const ips = screen.getAllByTestId('clickable-ip')
    expect(ips.length).toBeGreaterThanOrEqual(1)
  })

  it('renders a ScoreBadge (fw-score-badge) in each row', () => {
    renderRiskMovers(MIXED_FIXTURE)
    const badges = document.querySelectorAll('.fw-score-badge')
    expect(badges.length).toBeGreaterThanOrEqual(1)
  })

  it('renders mover-delta for known-delta actors', () => {
    renderRiskMovers(MIXED_FIXTURE)
    // 192.0.2.1 has delta=38 → mover-delta shown
    const deltas = screen.getAllByTestId('mover-delta')
    expect(deltas.length).toBeGreaterThanOrEqual(1)
    expect(deltas[0]).toHaveTextContent('+38')
  })

  // EARS-RM-3: Sparkline for known-delta actors (rendered as role="img")
  // Override the default empty-history mock for this test so the sparkline row
  // actually renders (the detail row only appears when history is non-empty after
  // the #MR layout fix that dropped the empty-placeholder row).
  it('renders sparkline (role="img") for each known-delta actor when history is available', async () => {
    mockFetchScoreHistory.mockResolvedValueOnce([{ t: '2026-06-04T08:00:00Z', value: 60 }, { t: '2026-06-04T09:00:00Z', value: 70 }] as never)
    renderRiskMovers([makeThreat('192.0.2.1', 70, 22)])
    // Wait for the async fetchScoreHistory to resolve and state to update
    await waitFor(() => {
      expect(screen.getAllByRole('img').length).toBeGreaterThanOrEqual(1)
    })
  })
})

// ---------------------------------------------------------------------------
// EARS-RM-4: NEW badge for null-delta actors
// ---------------------------------------------------------------------------

describe('RiskMovers — NEW badge for null-delta (new actor)', () => {
  it('shows NEW badge for null-delta actors', () => {
    renderRiskMovers([makeThreat('192.0.2.2', 50, null)])
    expect(screen.getByTestId('new-actor-badge')).toBeInTheDocument()
    expect(screen.getByTestId('new-actor-badge')).toHaveTextContent('NEW')
  })

  it('does NOT render mover-delta for null-delta actors', () => {
    renderRiskMovers([makeThreat('192.0.2.2', 50, null)])
    expect(screen.queryByTestId('mover-delta')).toBeNull()
  })

  it('renders both NEW badge and known-delta row in a mixed fixture', () => {
    renderRiskMovers(MIXED_FIXTURE)
    // Known-delta actor: has mover-delta
    expect(screen.getByTestId('mover-delta')).toBeInTheDocument()
    // Null-delta actor: has NEW badge
    expect(screen.getByTestId('new-actor-badge')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-RM-5: Rows ordered by |score_delta| descending
// ---------------------------------------------------------------------------

describe('RiskMovers — delta sort order', () => {
  it('renders rows in |score_delta| descending order', () => {
    renderRiskMovers(THREE_MOVERS)
    const ips = screen.getAllByTestId('clickable-ip')
    // 192.0.2.2 has |delta|=38 (largest) → first
    expect(ips[0]).toHaveTextContent('192.0.2.2')
    // 192.0.2.1 has |delta|=10 → second
    expect(ips[1]).toHaveTextContent('192.0.2.1')
    // 192.0.2.3 has |delta|=5 → third
    expect(ips[2]).toHaveTextContent('192.0.2.3')
  })
})

// ---------------------------------------------------------------------------
// EARS-RM-6: Empty state
// ---------------------------------------------------------------------------

describe('RiskMovers — empty state', () => {
  it('shows empty state when threats array is empty', () => {
    renderRiskMovers([])
    expect(screen.getByTestId('risk-movers-empty')).toBeInTheDocument()
    expect(screen.queryByTestId('risk-movers')).toBeNull()
  })

  it('shows empty state when all actors have score=0', () => {
    const zeroScoreThreats = [makeThreat('192.0.2.1', 0, null)]
    renderRiskMovers(zeroScoreThreats)
    expect(screen.getByTestId('risk-movers-empty')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-RM-7: No AI-attributed text (ADR-0035)
// ---------------------------------------------------------------------------

describe('RiskMovers — no AI-attributed text (ADR-0035)', () => {
  it('does not render any AI-attributed mover rationale text', () => {
    renderRiskMovers(MIXED_FIXTURE)
    // No text starting with "AI" or "LLM" should appear in the pane
    const container = screen.getByTestId('risk-movers')
    expect(container.textContent).not.toMatch(/\b(AI|LLM)\b/)
  })
})

// ---------------------------------------------------------------------------
// EARS-RM-8: No inner scrollbar (ADR-0017)
// ---------------------------------------------------------------------------

describe('RiskMovers — no inner scrollbar', () => {
  it('container element has no overflow: scroll/auto', () => {
    renderRiskMovers(THREE_MOVERS)
    const container = screen.getByTestId('risk-movers')
    const style = container.getAttribute('style') ?? ''
    expect(style).not.toMatch(/overflow\s*:\s*(scroll|auto)/)
  })
})

// ---------------------------------------------------------------------------
// EARS-RM-9: Pane title states the window (via AiSidebar)
// ---------------------------------------------------------------------------

describe('AiSidebar — Risk Movers pane title', () => {
  it('renders "Risk Movers · 1h" heading in the sidebar (abbreviated, issue #331)', () => {
    renderAiSidebar(MIXED_FIXTURE)
    // The SbCard title "📈 Risk Movers · 1h" should appear in the DOM
    const headings = screen.getAllByRole('heading')
    const riskMoversHeading = headings.find((h) =>
      h.textContent?.toLowerCase().includes('risk movers'),
    )
    expect(riskMoversHeading).toBeDefined()
    expect(riskMoversHeading?.textContent).toContain('1h')
  })

  it('does NOT use "last 1h" prose — abbreviation only (issue #331)', () => {
    renderAiSidebar(MIXED_FIXTURE)
    const headings = screen.getAllByRole('heading')
    const riskMoversHeading = headings.find((h) =>
      h.textContent?.toLowerCase().includes('risk movers'),
    )
    // "last 1h" is the old prose format — must not appear; "1h" stands alone
    expect(riskMoversHeading?.textContent).not.toContain('last 1h')
  })

  it('does NOT render "IP threat scores" heading (replaced by Risk Movers)', () => {
    renderAiSidebar(MIXED_FIXTURE)
    const headings = screen.getAllByRole('heading')
    const ipScoresHeading = headings.find((h) =>
      h.textContent?.toLowerCase().includes('ip threat scores'),
    )
    expect(ipScoresHeading).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// EARS-RM-364: pane title renders emoji + mixed-case (issue #364)
// ---------------------------------------------------------------------------

describe('AiSidebar — Risk Movers pane title: emoji present, not uppercased (issue #364)', () => {
  // CR6 (#617): AiSidebar now has TWO sb-card-title elements (Risk Movers + Recommended actions).
  // Use getAllByTestId and locate the Risk Movers heading specifically.

  it('renders the 📈 emoji in the sb-card heading', () => {
    renderAiSidebar(MIXED_FIXTURE)
    // getAllByTestId — CR6 sidebar now has two sb-card-title elements
    const headings = screen.getAllByTestId('sb-card-title')
    const riskMoversHeading = headings.find((h) => h.textContent?.includes('Risk Movers'))
    expect(riskMoversHeading).toBeDefined()
    expect(riskMoversHeading?.textContent).toContain('📈')
  })

  it('renders "Risk Movers" in mixed case — not all-caps "RISK MOVERS"', () => {
    renderAiSidebar(MIXED_FIXTURE)
    const headings = screen.getAllByTestId('sb-card-title')
    const heading = headings.find((h) => h.textContent?.includes('Risk Movers'))
    // textContent reflects DOM text, not CSS; the string must NOT be stored all-caps
    expect(heading?.textContent).toContain('Risk Movers')
    expect(heading?.textContent).not.toBe(heading?.textContent?.toUpperCase())
  })

  it('renders "1h" lowercase — CSS uppercase must not mutate the stored value to "1H"', () => {
    renderAiSidebar(MIXED_FIXTURE)
    const headings = screen.getAllByTestId('sb-card-title')
    const heading = headings.find((h) => h.textContent?.includes('Risk Movers'))
    expect(heading?.textContent).toContain('1h')
    // "1H" would mean the string itself was stored uppercased (the pre-#364 bug)
    expect(heading?.textContent).not.toContain('1H')
  })

  it('sb-card heading has no textTransform: uppercase inline style (issue #364)', () => {
    renderAiSidebar(MIXED_FIXTURE)
    const headings = screen.getAllByTestId('sb-card-title')
    const heading = headings.find((h) => h.textContent?.includes('Risk Movers'))
    const style = heading?.getAttribute('style') ?? ''
    expect(style).not.toMatch(/text-transform\s*:\s*uppercase/)
  })
})

// ---------------------------------------------------------------------------
// Consumer-level integration: mocked score-history pair (#241 lesson)
// ---------------------------------------------------------------------------

describe('RiskMovers — consumer-level integration (score-history endpoint)', () => {
  it('renders from mocked /threats + score-history pair without crash', async () => {
    // This test validates the integration wiring (not just the unit).
    // fetchScoreHistory is mocked to return [] (graceful degradation for the
    // known #250 endpoint wiring gap).  After the #MR layout fix the sparkline
    // detail row is only rendered when history is non-empty, so with an empty
    // mock no sparkline SVG is added — only ScoreBadge role="img" spans remain.
    renderRiskMovers(MIXED_FIXTURE)
    // Should render at least one mover row
    expect(screen.getAllByTestId('risk-mover-row').length).toBeGreaterThanOrEqual(1)
    // With empty history, no Sparkline detail row is rendered — no SVG sparkline;
    // the sparkline-no-history placeholder is also gone (#MR fix).
    expect(screen.queryByTestId('sparkline-no-history')).toBeNull()
    // The known-delta actor's tbody has only 1 <tr> (no detail row)
    const rows = screen.getAllByTestId('risk-mover-row')
    const knownDeltaRow = rows[0] // first mover is 192.0.2.1 with delta=38
    expect(knownDeltaRow.querySelectorAll('tr').length).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// EARS-RM-10 (regression #309): fetchScoreHistory MUST be called with a
// numeric window, never a string — backend expects float, "1h" causes 422.
// ---------------------------------------------------------------------------

describe('RiskMovers — score-history window type regression guard (#309)', () => {
  it('calls fetchScoreHistory with a numeric window (not a string)', async () => {
    // Fixture: one known-delta actor triggers a score-history fetch.
    renderRiskMovers([makeThreat('192.0.2.10', 70, 25)])

    // Wait for the useEffect to fire the fetch
    await waitFor(() => {
      expect(mockFetchScoreHistory).toHaveBeenCalled()
    })

    // Every invocation MUST pass a number, never the string '1h'.
    for (const call of mockFetchScoreHistory.mock.calls) {
      const windowArg = call[1]
      expect(typeof windowArg).toBe('number')
      expect(windowArg).toBe(1)
    }
  })

  it('does NOT pass a string window to fetchScoreHistory', async () => {
    renderRiskMovers([makeThreat('192.0.2.11', 65, 15)])

    await waitFor(() => {
      expect(mockFetchScoreHistory).toHaveBeenCalled()
    })

    for (const call of mockFetchScoreHistory.mock.calls) {
      const windowArg = call[1]
      expect(typeof windowArg).not.toBe('string')
    }
  })
})

// ---------------------------------------------------------------------------
// EARS-RM-11 (issue #331): window label NOT in rows — appears only in pane title
// ---------------------------------------------------------------------------

describe('RiskMovers — window label not repeated in rows (issue #331)', () => {
  it('mover-delta span shows only the delta value, no window label', () => {
    renderRiskMovers([makeThreat('192.0.2.1', 78, 38)])
    const delta = screen.getByTestId('mover-delta')
    // Delta text must be "+38" only — "1h" or "last" must NOT appear inside the span
    expect(delta.textContent).toBe('+38')
    expect(delta.textContent).not.toMatch(/1h|last/)
  })

  it('mover-delta span shows negative delta without window label', () => {
    renderRiskMovers([makeThreat('192.0.2.1', 50, -12)])
    const delta = screen.getByTestId('mover-delta')
    expect(delta.textContent).toBe('-12')
    expect(delta.textContent).not.toMatch(/1h|last/)
  })
})

// ---------------------------------------------------------------------------
// EARS-RM-12 (issue #331 / #615): rows do not wrap.
// The table layout replaced the old flex-div. Table cells with white-space:nowrap
// on the Score and Delta columns serve the same "no wrap" purpose — the table
// model constrains columns to their content widths automatically.
// ---------------------------------------------------------------------------

describe('RiskMovers — rows do not wrap (issue #331)', () => {
  it('score and delta cells have white-space: nowrap to prevent cell content wrapping', () => {
    renderRiskMovers([makeThreat('192.0.2.1', 78, 38)])
    // The row is now a <tbody>; primary row is first <tr>.
    const row = screen.getByTestId('risk-mover-row')
    const cells = row.querySelectorAll('tr:first-child td')
    // Cells [1] (score) and [2] (delta) must be nowrap
    expect(cells.length).toBeGreaterThanOrEqual(3)
    const scoreCell = cells[1] as HTMLElement
    const deltaCell = cells[2] as HTMLElement
    expect(scoreCell.getAttribute('style') ?? '').toMatch(/white-space\s*:\s*nowrap/)
    expect(deltaCell.getAttribute('style') ?? '').toMatch(/white-space\s*:\s*nowrap/)
  })
})

// ---------------------------------------------------------------------------
// EARS-615: table layout with colgroup (issue #615)
// ---------------------------------------------------------------------------

describe('RiskMovers — table layout with colgroup (issue #615)', () => {
  it('renders a <table> element as the risk-movers container', () => {
    renderRiskMovers(MIXED_FIXTURE)
    const container = screen.getByTestId('risk-movers')
    expect(container.tagName.toLowerCase()).toBe('table')
  })

  it('has a <colgroup> with 3 <col> elements (IP | Score | Delta/NEW)', () => {
    renderRiskMovers(MIXED_FIXTURE)
    const container = screen.getByTestId('risk-movers')
    const colgroup = container.querySelector('colgroup')
    expect(colgroup).not.toBeNull()
    const cols = colgroup?.querySelectorAll('col')
    expect(cols?.length).toBe(3)
  })

  it('renders only ONE row (no detail row) for known-delta actors when history is empty', () => {
    // fetchScoreHistory is mocked to return [] — after the #MR layout fix the
    // empty-placeholder row is omitted entirely; no "no history" label, no gap.
    renderRiskMovers([makeThreat('192.0.2.1', 70, 22)])
    const row = screen.getByTestId('risk-mover-row')
    const trs = row.querySelectorAll('tr')
    // Only the primary row; detail row suppressed because history is empty
    expect(trs.length).toBe(1)
    expect(row.querySelector('[data-testid="sparkline-no-history"]')).toBeNull()
  })

  it('renders sparkline detail row (colspan=3) for known-delta actors when history is available', async () => {
    // Override mock to return non-empty history so the detail row is rendered.
    mockFetchScoreHistory.mockResolvedValueOnce([{ t: '2026-06-04T08:00:00Z', value: 60 }, { t: '2026-06-04T09:00:00Z', value: 70 }] as never)
    renderRiskMovers([makeThreat('192.0.2.1', 70, 22)])
    await waitFor(() => {
      const row = screen.getByTestId('risk-mover-row')
      const trs = row.querySelectorAll('tr')
      expect(trs.length).toBe(2) // primary + sparkline detail row
      const sparklineTd = trs[1].querySelector('td')
      expect(sparklineTd?.getAttribute('colspan')).toBe('3')
      expect(trs[1].querySelector('[role="img"]')).not.toBeNull()
    })
  })

  it('new actors render only ONE row (no sparkline row)', () => {
    renderRiskMovers([makeThreat('192.0.2.2', 50, null)])
    const row = screen.getByTestId('risk-mover-row')
    const trs = row.querySelectorAll('tr')
    // new actors: only the primary row, no sparkline detail row
    expect(trs.length).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// EARS-616: compact variant on ScoreBadge suppresses '?' glyph (issue #616)
// ---------------------------------------------------------------------------

describe('RiskMovers — compact ScoreBadge variant, no "?" artifact (issue #616)', () => {
  it('every ScoreBadge inside risk-movers has data-variant="compact"', () => {
    renderRiskMovers(MIXED_FIXTURE)
    const badges = document.querySelectorAll('[data-testid="risk-movers"] .fw-score-badge, table[data-testid="risk-movers"] .fw-score-badge')
    expect(badges.length).toBeGreaterThanOrEqual(1)
    badges.forEach((badge) => {
      expect(badge.getAttribute('data-variant')).toBe('compact')
    })
  })

  it('no literal "?" character appears inside the risk-movers table text', () => {
    // scoreBreakdown=[] means hasBreakdown=false → presentational path, no "?" at all.
    // This test guards against the default-variant "?" regression (issue #616).
    renderRiskMovers(MIXED_FIXTURE)
    const container = screen.getByTestId('risk-movers')
    expect(container.textContent).not.toContain('?')
  })
})
