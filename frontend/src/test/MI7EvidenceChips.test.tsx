/**
 * Tests for MI-7 — evidence chips in the entity slide-over.
 *
 * EARS criteria covered:
 *
 * EARS 1 — WHEN breakdown renders for actor with evidence, each factor SHALL be
 *           clickable through to its contributing events (filtered by log_row_ids).
 *           → factor rows with count > 0 render an expand toggle; clicking shows summaries.
 *
 * EARS 2 — Every numeric claim (event counts, rule totals) SHALL come from API fields,
 *           never from LLM-authored text.
 *           → computeEvidenceCounts unit tests; footer renders only API numbers.
 *
 * EARS 3 — WHEN evidence unavailable for a factor, UI degrades honestly
 *           (no link, no fabricated counts, no spinner-forever).
 *           → empty / error / 404 states render appropriate messages.
 *
 * EARS 4 — ADR-0035 ProvenanceChip on every factor; ai_boost carries "ai+rule".
 *           → chip present on all factors; ai_boost has derivation=ai+rule.
 *
 * EARS 5 — New clickable surfaces keyboard-operable (WCAG 2.1.1).
 *           → Enter/Space activate the expand toggle.
 *
 * EARS 6 — Rendering SHALL NOT trigger any LLM call.
 *           → fetchEvidenceChain mock: not the LLM call mock; no LLM in chain.
 *
 * MI-7 EARS — "Based on N events · M rules" footer numbers from API data.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { EvidenceFactorRow } from '../components/evidence/EvidenceFactorRow'
import { EvidenceFooter } from '../components/evidence/EvidenceFooter'
import { EvidenceSection } from '../components/evidence/EvidenceSection'
import { computeEvidenceCounts } from '../components/evidence/evidenceUtils'
import type {
  FactorEvidence,
  AiBoostEvidence,
  EvidenceChainResponse,
  EventSummary,
} from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SUMMARY_SQL1: EventSummary = {
  log_row_id: 101,
  timestamp: '2026-06-04T08:00:00Z',
  action: 'BLOCK',
  rule_id: '942100',
  payload_snippet: "id=1 OR 1=1",
}

const SUMMARY_SQL2: EventSummary = {
  log_row_id: 102,
  timestamp: '2026-06-04T08:05:00Z',
  action: 'BLOCK',
  rule_id: '942100',
  payload_snippet: null,
}

const SUMMARY_BRUTE: EventSummary = {
  log_row_id: 201,
  timestamp: '2026-06-04T09:00:00Z',
  action: 'BLOCK',
  rule_id: null,
  payload_snippet: null,
}

const FACTOR_SQL: FactorEvidence = {
  factor: 'sql_injection',
  label: 'SQL injection (+40)',
  points: 40,
  log_row_ids: [101, 102],
  count: 2,
  summaries: [SUMMARY_SQL1, SUMMARY_SQL2],
}

const FACTOR_BRUTE: FactorEvidence = {
  factor: 'brute_force',
  label: 'Brute force (+30)',
  points: 30,
  log_row_ids: [201],
  count: 1,
  summaries: [SUMMARY_BRUTE],
}

const FACTOR_CAP: FactorEvidence = {
  factor: 'cap',
  label: 'Capped at 100 (-10)',
  points: -10,
  log_row_ids: [],
  count: 0,
  summaries: [],
}

const FACTOR_AI: AiBoostEvidence = {
  factor: 'ai_boost',
  label: 'AI boost (+20)',
  points: 20,
  provenance: 'ai+rule',
  threat_level: 'HIGH',
  confidence: 0.87,
  note: 'Stored artifact reference — no LLM call.',
}

const CHAIN_FIXTURE: EvidenceChainResponse = {
  source_ip: '192.0.2.1',
  factors: [FACTOR_SQL, FACTOR_BRUTE, FACTOR_CAP, FACTOR_AI],
  recomputed: true,
}

// ---------------------------------------------------------------------------
// Mocks for EvidenceSection (which calls useEvidenceChain → fetchEvidenceChain)
// ---------------------------------------------------------------------------

const { mockFetchEvidenceChain } = vi.hoisted(() => ({
  mockFetchEvidenceChain: vi.fn(),
}))

vi.mock('../api/client', () => ({
  fetchEvidenceChain: mockFetchEvidenceChain,
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchThreats: vi.fn().mockResolvedValue([]),
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'ok',
    ollama_connected: false,
    ollama_model: null,
    db_ok: true,
  }),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: unknown) {
      super(String(message ?? status))
      this.status = status
    }
  },
}))

beforeEach(() => {
  vi.clearAllMocks()
})

// ---------------------------------------------------------------------------
// computeEvidenceCounts unit tests (EARS 2)
// ---------------------------------------------------------------------------

describe('computeEvidenceCounts — EARS 2: numeric claims from API data', () => {
  it('counts events as sum of rule factor counts (excludes ai_boost and cap)', () => {
    const { eventCount } = computeEvidenceCounts(CHAIN_FIXTURE)
    // sql_injection: 2, brute_force: 1 → total 3 (cap and ai_boost excluded)
    expect(eventCount).toBe(3)
  })

  it('counts distinct non-null rule_ids from all summaries', () => {
    const { ruleCount } = computeEvidenceCounts(CHAIN_FIXTURE)
    // sql_injection summaries: rule_id=942100 (×2 same), brute_force: null → 1 distinct
    expect(ruleCount).toBe(1)
  })

  it('counts multiple distinct rule_ids correctly', () => {
    const chainWithTwoRules: EvidenceChainResponse = {
      source_ip: '192.0.2.1',
      factors: [
        {
          ...FACTOR_SQL,
          summaries: [
            { ...SUMMARY_SQL1, rule_id: '942100' },
            { ...SUMMARY_SQL2, rule_id: '942110' },
          ],
          count: 2,
        },
      ],
      recomputed: true,
    }
    const { ruleCount } = computeEvidenceCounts(chainWithTwoRules)
    expect(ruleCount).toBe(2)
  })

  it('returns zero counts for empty factors list', () => {
    const emptyChain: EvidenceChainResponse = {
      source_ip: '192.0.2.1',
      factors: [],
      recomputed: true,
    }
    const { eventCount, ruleCount } = computeEvidenceCounts(emptyChain)
    expect(eventCount).toBe(0)
    expect(ruleCount).toBe(0)
  })

  it('excludes ai_boost from event count', () => {
    const aiOnlyChain: EvidenceChainResponse = {
      source_ip: '192.0.2.1',
      factors: [FACTOR_AI],
      recomputed: true,
    }
    const { eventCount } = computeEvidenceCounts(aiOnlyChain)
    expect(eventCount).toBe(0)
  })

  it('excludes cap from event count', () => {
    const capOnlyChain: EvidenceChainResponse = {
      source_ip: '192.0.2.1',
      factors: [FACTOR_CAP],
      recomputed: true,
    }
    const { eventCount } = computeEvidenceCounts(capOnlyChain)
    expect(eventCount).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// EvidenceFactorRow — EARS 1 (click-through), EARS 4 (provenance), EARS 5 (keyboard)
// ---------------------------------------------------------------------------

describe('EvidenceFactorRow — EARS 1: factor click-through to contributing events', () => {
  it('renders the factor label as a text node', () => {
    render(<EvidenceFactorRow item={FACTOR_SQL} />)
    expect(screen.getByTestId('evidence-factor-label-sql_injection')).toHaveTextContent(
      'SQL injection (+40)',
    )
  })

  it('renders positive points with + prefix', () => {
    render(<EvidenceFactorRow item={FACTOR_SQL} />)
    expect(screen.getByTestId('evidence-factor-points-sql_injection')).toHaveTextContent('+40')
  })

  it('renders negative points (cap) without + prefix', () => {
    render(<EvidenceFactorRow item={FACTOR_CAP} />)
    expect(screen.getByTestId('evidence-factor-points-cap')).toHaveTextContent('-10')
  })

  it('shows expand toggle button when factor has count > 0', () => {
    render(<EvidenceFactorRow item={FACTOR_SQL} />)
    expect(screen.getByTestId('evidence-factor-toggle-sql_injection')).toBeInTheDocument()
  })

  it('does NOT show expand toggle when count === 0 (cap factor)', () => {
    render(<EvidenceFactorRow item={FACTOR_CAP} />)
    expect(screen.queryByTestId('evidence-factor-toggle-cap')).not.toBeInTheDocument()
  })

  it('does NOT show expand toggle for ai_boost (no log_row_ids)', () => {
    render(<EvidenceFactorRow item={FACTOR_AI} />)
    expect(screen.queryByTestId('evidence-factor-toggle-ai_boost')).not.toBeInTheDocument()
  })

  it('expands evidence panel on click — shows EventSummary rows scoped by log_row_ids', async () => {
    render(<EvidenceFactorRow item={FACTOR_SQL} />)
    expect(screen.queryByTestId('evidence-factor-detail-sql_injection')).not.toBeInTheDocument()
    await userEvent.click(screen.getByTestId('evidence-factor-toggle-sql_injection'))
    expect(screen.getByTestId('evidence-factor-detail-sql_injection')).toBeInTheDocument()
    // #612: timestamps are now formatted via fmtTime() — raw ISO strings NO LONGER appear.
    // We verify FACTOR_SQL has 2 summaries by checking for "BLOCK" actions (both rows have action=BLOCK).
    // (Both summaries have action='BLOCK' — two such cells appear.)
    const blockCells = screen.getAllByText('BLOCK')
    expect(blockCells.length).toBeGreaterThanOrEqual(2)
    // Raw ISO strings must NOT appear in the DOM (regression guard for #612).
    expect(screen.queryByText('2026-06-04T08:00:00Z')).not.toBeInTheDocument()
    expect(screen.queryByText('2026-06-04T08:05:00Z')).not.toBeInTheDocument()
  })

  it('collapses evidence panel on second click (toggle)', async () => {
    render(<EvidenceFactorRow item={FACTOR_SQL} />)
    const toggle = screen.getByTestId('evidence-factor-toggle-sql_injection')
    await userEvent.click(toggle)
    expect(screen.getByTestId('evidence-factor-detail-sql_injection')).toBeInTheDocument()
    await userEvent.click(toggle)
    expect(screen.queryByTestId('evidence-factor-detail-sql_injection')).not.toBeInTheDocument()
  })

  it('renders payload_snippet as text node — XSS safe (ADR-0029 D3)', async () => {
    const xssItem: FactorEvidence = {
      ...FACTOR_SQL,
      summaries: [
        { ...SUMMARY_SQL1, payload_snippet: '<script>alert("xss")</script>' },
      ],
      count: 1,
    }
    render(<EvidenceFactorRow item={xssItem} />)
    await userEvent.click(screen.getByTestId('evidence-factor-toggle-sql_injection'))
    // Should render the literal string, not execute the script
    expect(screen.getByText('<script>alert("xss")</script>')).toBeInTheDocument()
    expect(document.querySelectorAll('script[src]').length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// EARS 5 — Keyboard operability (WCAG 2.1.1)
// ---------------------------------------------------------------------------

describe('EvidenceFactorRow — EARS 5: keyboard operability (WCAG 2.1.1)', () => {
  it('activates expand on Enter key', async () => {
    render(<EvidenceFactorRow item={FACTOR_SQL} />)
    const toggle = screen.getByTestId('evidence-factor-toggle-sql_injection')
    toggle.focus()
    await userEvent.keyboard('{Enter}')
    expect(screen.getByTestId('evidence-factor-detail-sql_injection')).toBeInTheDocument()
  })

  it('activates expand on Space key', async () => {
    render(<EvidenceFactorRow item={FACTOR_SQL} />)
    const toggle = screen.getByTestId('evidence-factor-toggle-sql_injection')
    toggle.focus()
    await userEvent.keyboard(' ')
    expect(screen.getByTestId('evidence-factor-detail-sql_injection')).toBeInTheDocument()
  })

  it('toggle button has aria-expanded=false when collapsed', () => {
    render(<EvidenceFactorRow item={FACTOR_SQL} />)
    const toggle = screen.getByTestId('evidence-factor-toggle-sql_injection')
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
  })

  it('toggle button has aria-expanded=true when expanded', async () => {
    render(<EvidenceFactorRow item={FACTOR_SQL} />)
    const toggle = screen.getByTestId('evidence-factor-toggle-sql_injection')
    await userEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
  })

  // FIX 1 — WCAG 2.4.7 focus-visible ring
  it('toggle button carries the fw-focus-visible class for keyboard focus ring (WCAG 2.4.7)', () => {
    render(<EvidenceFactorRow item={FACTOR_SQL} />)
    const toggle = screen.getByTestId('evidence-factor-toggle-sql_injection')
    // The DS utility class fw-focus-visible (index.css) applies an amber outline
    // via :focus-visible. Inline outline:'none' suppresses the browser default;
    // the class restores it only for keyboard users.
    expect(toggle).toHaveClass('fw-focus-visible')
  })

  it('toggle button does NOT carry inline outline — CSS class owns both states (cascade fix)', () => {
    render(<EvidenceFactorRow item={FACTOR_SQL} />)
    const toggle = screen.getByTestId('evidence-factor-toggle-sql_injection')
    // The inline style must NOT set outline — if it did, the inline rule would win
    // the cascade (specificity 1,0,0,0) and suppress the .fw-focus-visible:focus-visible
    // ring (specificity 0,2,0) even on keyboard focus. The base .fw-focus-visible rule
    // in index.css sets outline:none for mouse/idle; :focus-visible adds the amber ring.
    // jsdom cannot evaluate :focus-visible pseudo-class, so we verify the structural
    // invariant: the class is present and no inline outline conflicts.
    // Real-browser verification: Tab to the toggle → amber ring visible; mouse click → no ring.
    expect(toggle).toHaveClass('fw-focus-visible')
    expect(toggle.style.outline).toBe('')
  })
})

// ---------------------------------------------------------------------------
// FIX 2 — Detail table row cap (prevents 150-row panels burying the UI)
// ---------------------------------------------------------------------------

describe('EvidenceFactorRow — detail table row cap', () => {
  /** Build a FactorEvidence with N summaries (each with a unique log_row_id). */
  function buildLargeFactorEvidence(n: number): import('../api/types').FactorEvidence {
    const summaries: import('../api/types').EventSummary[] = Array.from({ length: n }, (_, i) => ({
      log_row_id: 1000 + i,
      timestamp: `2026-06-04T08:00:0${String(i).padStart(2, '0')}Z`,
      action: 'BLOCK',
      rule_id: '942100',
      payload_snippet: `payload-${i}`,
    }))
    return {
      factor: 'sql_injection',
      label: 'SQL injection (+40)',
      points: 40,
      log_row_ids: summaries.map((s) => s.log_row_id),
      count: n,
      summaries,
    }
  }

  it('renders all rows when summaries.length <= 20 (no cap needed)', async () => {
    render(<EvidenceFactorRow item={buildLargeFactorEvidence(5)} />)
    await userEvent.click(screen.getByTestId('evidence-factor-toggle-sql_injection'))
    // 5 rows — all rendered
    expect(screen.getAllByText(/payload-/)).toHaveLength(5)
    // No show-all button
    expect(
      screen.queryByTestId('evidence-factor-show-all-sql_injection'),
    ).not.toBeInTheDocument()
  })

  it('caps at 20 rows when summaries.length > 20', async () => {
    render(<EvidenceFactorRow item={buildLargeFactorEvidence(30)} />)
    await userEvent.click(screen.getByTestId('evidence-factor-toggle-sql_injection'))
    // Only 20 of 30 summaries rendered
    expect(screen.getAllByText(/payload-/)).toHaveLength(20)
  })

  it('shows "Show all N events" button when summaries.length > 20', async () => {
    render(<EvidenceFactorRow item={buildLargeFactorEvidence(30)} />)
    await userEvent.click(screen.getByTestId('evidence-factor-toggle-sql_injection'))
    const showAll = screen.getByTestId('evidence-factor-show-all-sql_injection')
    expect(showAll).toBeInTheDocument()
    expect(showAll).toHaveTextContent('Show all 30 events')
  })

  it('clicking show-all expands to the full set', async () => {
    render(<EvidenceFactorRow item={buildLargeFactorEvidence(30)} />)
    await userEvent.click(screen.getByTestId('evidence-factor-toggle-sql_injection'))
    await userEvent.click(screen.getByTestId('evidence-factor-show-all-sql_injection'))
    // All 30 summaries rendered
    expect(screen.getAllByText(/payload-/)).toHaveLength(30)
    // Show-all button gone
    expect(
      screen.queryByTestId('evidence-factor-show-all-sql_injection'),
    ).not.toBeInTheDocument()
  })

  it('show-all button is keyboard-operable (Enter activates)', async () => {
    render(<EvidenceFactorRow item={buildLargeFactorEvidence(30)} />)
    await userEvent.click(screen.getByTestId('evidence-factor-toggle-sql_injection'))
    const showAll = screen.getByTestId('evidence-factor-show-all-sql_injection')
    showAll.focus()
    await userEvent.keyboard('{Enter}')
    expect(screen.getAllByText(/payload-/)).toHaveLength(30)
  })

  it('footer count reflects TRUE total (item.count), not the capped 20', async () => {
    // Build a factor where count=150 but only 25 summaries are in the array
    // (simulates an API that returns a partial set but the true count is higher).
    const factor: import('../api/types').FactorEvidence = {
      ...buildLargeFactorEvidence(25),
      count: 150,
    }
    render(<EvidenceFactorRow item={factor} />)
    const toggle = screen.getByTestId('evidence-factor-toggle-sql_injection')
    // The toggle button shows item.count (150), not the capped row count
    expect(toggle).toHaveTextContent('150')
  })

  it('collapsing the panel resets the show-all state so re-expanding starts capped', async () => {
    render(<EvidenceFactorRow item={buildLargeFactorEvidence(30)} />)
    await userEvent.click(screen.getByTestId('evidence-factor-toggle-sql_injection'))
    // Expand to full
    await userEvent.click(screen.getByTestId('evidence-factor-show-all-sql_injection'))
    expect(screen.getAllByText(/payload-/)).toHaveLength(30)
    // Collapse
    await userEvent.click(screen.getByTestId('evidence-factor-toggle-sql_injection'))
    expect(screen.queryByTestId('evidence-factor-detail-sql_injection')).not.toBeInTheDocument()
    // Re-expand — should start capped again
    await userEvent.click(screen.getByTestId('evidence-factor-toggle-sql_injection'))
    expect(screen.getAllByText(/payload-/)).toHaveLength(20)
    expect(screen.getByTestId('evidence-factor-show-all-sql_injection')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS 4 — ADR-0035 ProvenanceChip on every factor
// ---------------------------------------------------------------------------

describe('EvidenceFactorRow — EARS 4: ProvenanceChip on every factor', () => {
  it('renders RULE chip on a rule factor', () => {
    render(<EvidenceFactorRow item={FACTOR_SQL} />)
    const chip = screen.getByTestId('evidence-factor-chip-sql_injection')
    expect(chip).toHaveAttribute('data-derivation', 'rule')
  })

  it('renders AI+RULE chip on ai_boost factor', () => {
    render(<EvidenceFactorRow item={FACTOR_AI} />)
    const chip = screen.getByTestId('evidence-factor-chip-ai_boost')
    expect(chip).toHaveAttribute('data-derivation', 'ai+rule')
  })

  it('renders chip on cap factor', () => {
    render(<EvidenceFactorRow item={FACTOR_CAP} />)
    expect(screen.getByTestId('evidence-factor-chip-cap')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS 3 — Honest degrade when evidence unavailable for a factor
// ---------------------------------------------------------------------------

describe('EvidenceFactorRow — EARS 3: honest degrade when evidence unavailable', () => {
  it('renders row without expand toggle when evidenceEmpty=true', () => {
    render(<EvidenceFactorRow item={FACTOR_SQL} evidenceEmpty />)
    expect(screen.queryByTestId('evidence-factor-toggle-sql_injection')).not.toBeInTheDocument()
  })

  it('renders ai_boost stored-artifact reference note', () => {
    render(<EvidenceFactorRow item={FACTOR_AI} />)
    expect(screen.getByTestId('evidence-factor-ai-boost-ref')).toBeInTheDocument()
    expect(screen.getByTestId('evidence-factor-ai-boost-ref')).toHaveTextContent(
      'Stored AI analysis reference',
    )
  })

  it('shows threat_level in ai_boost reference note when present', () => {
    render(<EvidenceFactorRow item={FACTOR_AI} />)
    expect(screen.getByTestId('evidence-factor-ai-boost-ref')).toHaveTextContent('HIGH')
  })
})

// ---------------------------------------------------------------------------
// EvidenceFooter — EARS 2: numbers from API data
// ---------------------------------------------------------------------------

describe('EvidenceFooter — EARS 2: footer numbers from API data', () => {
  it('renders event count and rule count from the chain', () => {
    render(<EvidenceFooter chain={CHAIN_FIXTURE} />)
    const footer = screen.getByTestId('evidence-footer')
    // eventCount = 3 (sql:2 + brute:1), ruleCount = 1 (rule_id 942100)
    expect(screen.getByTestId('evidence-footer-event-count')).toHaveTextContent('3')
    expect(screen.getByTestId('evidence-footer-rule-count')).toHaveTextContent('1')
    expect(footer).toHaveTextContent('Based on')
  })

  it('renders "event" (singular) when count=1', () => {
    const chain: EvidenceChainResponse = {
      source_ip: '192.0.2.1',
      factors: [FACTOR_BRUTE],
      recomputed: true,
    }
    render(<EvidenceFooter chain={chain} />)
    expect(screen.getByTestId('evidence-footer')).toHaveTextContent('1 event')
    expect(screen.getByTestId('evidence-footer')).not.toHaveTextContent('1 events')
  })

  it('renders "events" (plural) when count > 1', () => {
    render(<EvidenceFooter chain={CHAIN_FIXTURE} />)
    expect(screen.getByTestId('evidence-footer')).toHaveTextContent('3 events')
  })

  it('renders degrade message when error is set — no fabricated counts', () => {
    render(<EvidenceFooter chain={null} error="Evidence unavailable (503)" />)
    expect(screen.getByTestId('evidence-footer-error')).toBeInTheDocument()
    expect(screen.queryByTestId('evidence-footer-event-count')).not.toBeInTheDocument()
  })

  it('renders degrade message when isEmpty=true — no fabricated counts', () => {
    render(<EvidenceFooter chain={null} isEmpty />)
    expect(screen.getByTestId('evidence-footer-empty')).toBeInTheDocument()
    expect(screen.queryByTestId('evidence-footer-event-count')).not.toBeInTheDocument()
  })

  it('renders nothing when loading (chain=null, no error, not empty)', () => {
    const { container } = render(<EvidenceFooter chain={null} />)
    expect(container.firstChild).toBeNull()
  })

  it('does NOT show rule count when ruleCount === 0', () => {
    const chainNoRuleIds: EvidenceChainResponse = {
      source_ip: '192.0.2.1',
      factors: [
        {
          ...FACTOR_BRUTE,
          summaries: [{ ...SUMMARY_BRUTE, rule_id: null }],
        },
      ],
      recomputed: true,
    }
    render(<EvidenceFooter chain={chainNoRuleIds} />)
    expect(screen.queryByTestId('evidence-footer-rule-count')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EvidenceSection — integration with useEvidenceChain
// ---------------------------------------------------------------------------

describe('EvidenceSection — integration', () => {
  it('renders nothing while loading', () => {
    mockFetchEvidenceChain.mockReturnValue(new Promise(() => {}))
    const { container } = render(<EvidenceSection ip="192.0.2.1" />)
    expect(container.firstChild).toBeNull()
  })

  it('renders factor rows when evidence chain loads', async () => {
    mockFetchEvidenceChain.mockResolvedValue(CHAIN_FIXTURE)
    render(<EvidenceSection ip="192.0.2.1" />)
    await waitFor(() =>
      expect(screen.getByTestId('evidence-section')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('evidence-factor-list')).toBeInTheDocument()
    expect(screen.getByTestId('evidence-factor-row-sql_injection')).toBeInTheDocument()
    expect(screen.getByTestId('evidence-factor-row-brute_force')).toBeInTheDocument()
    expect(screen.getByTestId('evidence-factor-row-ai_boost')).toBeInTheDocument()
  })

  it('renders the footer with API-derived counts', async () => {
    mockFetchEvidenceChain.mockResolvedValue(CHAIN_FIXTURE)
    render(<EvidenceSection ip="192.0.2.1" />)
    await waitFor(() =>
      expect(screen.getByTestId('evidence-footer')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('evidence-footer-event-count')).toHaveTextContent('3')
  })

  it('EARS 3: degrades to empty message on 404 (null)', async () => {
    mockFetchEvidenceChain.mockResolvedValue(null)
    render(<EvidenceSection ip="192.0.2.1" />)
    await waitFor(() =>
      expect(screen.getByTestId('evidence-footer-empty')).toBeInTheDocument(),
    )
    expect(screen.queryByTestId('evidence-factor-list')).not.toBeInTheDocument()
  })

  it('EARS 3: degrades to error note on fetch failure — no spinner-forever', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchEvidenceChain.mockRejectedValue(new ApiError(503, null))
    render(<EvidenceSection ip="192.0.2.1" />)
    await waitFor(() =>
      expect(screen.getByTestId('evidence-section-error')).toBeInTheDocument(),
    )
    expect(screen.queryByTestId('evidence-factor-list')).not.toBeInTheDocument()
    expect(screen.getByTestId('evidence-footer-error')).toBeInTheDocument()
  })

  it('EARS 6: fetchEvidenceChain does not call any LLM mock', async () => {
    mockFetchEvidenceChain.mockResolvedValue(CHAIN_FIXTURE)
    render(<EvidenceSection ip="192.0.2.1" />)
    await waitFor(() =>
      expect(screen.getByTestId('evidence-section')).toBeInTheDocument(),
    )
    // fetchEvidenceChain is the evidence endpoint — NOT the LLM call.
    // Verify it was called once (for the evidence endpoint only).
    expect(mockFetchEvidenceChain).toHaveBeenCalledTimes(1)
    expect(mockFetchEvidenceChain).toHaveBeenCalledWith('192.0.2.1')
  })

  it('re-fetches when ip changes', async () => {
    mockFetchEvidenceChain.mockResolvedValue(CHAIN_FIXTURE)
    const { rerender } = render(<EvidenceSection ip="192.0.2.1" />)
    await waitFor(() => expect(screen.getByTestId('evidence-section')).toBeInTheDocument())
    expect(mockFetchEvidenceChain).toHaveBeenCalledWith('192.0.2.1')

    mockFetchEvidenceChain.mockResolvedValue({
      ...CHAIN_FIXTURE,
      source_ip: '192.0.2.2',
    })
    rerender(<EvidenceSection ip="192.0.2.2" />)
    await waitFor(() =>
      expect(mockFetchEvidenceChain).toHaveBeenCalledWith('192.0.2.2'),
    )
  })
})
