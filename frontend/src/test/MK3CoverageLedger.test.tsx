/**
 * Tests for MK-3 — Coverage Ledger + Verdict Cards (issue #408, ADR-0043/0044).
 *
 * EARS criteria covered:
 *
 * Coverage ledger (pane a):
 *   EARS-MK3-1: Coverage headline templated from real data (RULE chip, numbers from API).
 *   EARS-MK3-2: AI-specific columns only (verdict/threat_level, ConfidenceLabel, age, ai_status,
 *               ScoreBadge) — NOT Dashboard's Events/Blocked/Location/Attacks columns.
 *   EARS-MK3-3: Bounded top-N + view-all; no inner scrollbars.
 *   EARS-MK3-4: ?filter=below-threshold folds as a coverage facet (existing testid preserved).
 *
 * Verdict cards (pane b):
 *   EARS-MK3-5: WHEN analyses exist → verdict cards with AI ProvenanceChip, model, created_at,
 *               ConfidenceLabel, ScoreBadge (ADR-0035/0036).
 *   EARS-MK3-6: WHEN no analyses → honest EmptyState (not a spinner-forever, not fabricated).
 *   EARS-MK3-7: All model/attacker strings rendered as text nodes (ADR-0029 D3).
 *   EARS-MK3-8: Cards are keyboard-focusable (WCAG 2.1.1).
 *
 * coverage.ts unit:
 *   EARS-MK3-9: computeCoverageRollup derives correct counts from threats + analyses.
 *   EARS-MK3-10: formatCoverageHeadline produces honest sentence (no invented numbers).
 *   EARS-MK3-11: formatAnalysisAge returns correct relative strings.
 *
 * AIRoute integration:
 *   EARS-MK3-12: AiThreatTable is gone from the page (no duplicate Dashboard columns).
 *   EARS-MK3-13: Verdict cards panel present in the page.
 *   EARS-MK3-14: ?filter=below-threshold backward-compat banner still shown.
 *
 * Backward-compat testids preserved:
 *   ai-page, ai-page-title, ai-page-subtitle, ai-summary-panel, ai-generate-btn,
 *   ai-below-threshold-banner, ai-route-error.
 *
 * FIX MK3-1 (analysed count from ledger):
 *   aiAnalysed = distinct IPs in the ledger (GET /ai/analyses), NOT ai_status='active'.
 *   An actor with ai_status='disabled' but a ledger entry IS counted as analysed
 *   (model ran, confidence < threshold, score stayed rule-derived).
 *
 * FIX MK3-2 (VerdictCard chip is AI-authored):
 *   VerdictCard ProvenanceChip must be 'ai' or 'ai+rule' — never pure 'rule'.
 *   A ledger record is always AI-authored content even when score_derivation='rule'.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

// ---------------------------------------------------------------------------
// coverage.ts unit tests (no React needed)
// ---------------------------------------------------------------------------

import {
  computeCoverageRollup,
  formatCoverageHeadline,
  formatAnalysisAge,
} from '../components/ai/ledger/coverage'
import { PAGE_SIZE } from '../components/ai/ledger/useCoverageLedgerTable'
import type { ThreatScore } from '../api/types'
import type { AnalysisSummary } from '../api/types'
import { THREATS_FIXTURE, THREATS_AI_UNAVAILABLE_FIXTURE } from './readFixtures'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Minimal AnalysisSummary for tests — RFC 5737 IP. */
const ANALYSIS_FIXTURE: AnalysisSummary = {
  id: 1,
  ip: '192.0.2.1',
  kind: 'concise',
  model: 'qwen3:8b',
  endpoint_host: '127.0.0.1:11434',
  ai_status: 'ok',
  threat_level: 'HIGH',
  confidence: 0.87,
  score: 78,
  score_derivation: 'ai',
  latency_ms: 1200,
  prompt_tokens: null,
  completion_tokens: null,
  schema_version: 1,
  created_at: '2026-06-12T10:00:00Z',
}

const ANALYSIS_LOW_CONFIDENCE: AnalysisSummary = {
  ...ANALYSIS_FIXTURE,
  id: 2,
  ip: '192.0.2.2',
  confidence: 0.30,
  threat_level: 'MEDIUM',
  score: 44,
  score_derivation: 'ai+rule',
  created_at: '2026-06-12T08:00:00Z',
}

/**
 * FIX MK3-1: An analysis where AI ran but score stayed rule-derived
 * (confidence < threshold → ai_status='disabled', but ledger entry exists).
 * This is the 192.0.2.10 case reproduced with an RFC 5737 IP.
 */
const ANALYSIS_RULE_DERIVED_SCORE: AnalysisSummary = {
  ...ANALYSIS_FIXTURE,
  id: 3,
  ip: '192.0.2.3',
  confidence: 0.5,
  ai_status: 'disabled',
  score_derivation: 'rule',
  created_at: '2026-06-12T09:00:00Z',
}

// ---------------------------------------------------------------------------
// EARS-MK3-9: computeCoverageRollup
// ---------------------------------------------------------------------------

describe('coverage.ts — computeCoverageRollup', () => {
  it('counts ai_analysed from ledger (distinct IPs in analyses, not ai_status)', () => {
    // THREATS_FIXTURE: 192.0.2.1 (ai_status='active') + 192.0.2.2 (ai_status='unavailable')
    // ANALYSIS_FIXTURE: only 192.0.2.1 in ledger → aiAnalysed = 1
    const rollup = computeCoverageRollup(THREATS_FIXTURE, [ANALYSIS_FIXTURE])
    expect(rollup.totalActors).toBe(2)
    expect(rollup.aiAnalysed).toBe(1)
    // 192.0.2.2 has no ledger entry → rulesOnly = 1
    expect(rollup.rulesOnly).toBe(1)
    expect(rollup.ledgerCount).toBe(1)
  })

  it('FIX MK3-1: actor with ai_status=disabled but in ledger is counted as analysed', () => {
    // Threat has ai_status='disabled' (score stayed rule-derived, confidence < threshold)
    // but AI DID run and persisted an analysis → must count as AI-analysed.
    const threatWithDisabledStatus: ThreatScore[] = [
      {
        ...THREATS_FIXTURE[0],
        source_ip: '192.0.2.3',
        ai_status: 'disabled',
        ai_confidence: 0.5,
      },
    ]
    const rollup = computeCoverageRollup(threatWithDisabledStatus, [ANALYSIS_RULE_DERIVED_SCORE])
    expect(rollup.aiAnalysed).toBe(1) // was 0 in buggy version (used ai_status='active')
    expect(rollup.rulesOnly).toBe(0)  // actor IS in ledger → not rules-only
  })

  it('FIX MK3-1: headline shows "analysed 1" for 1 ledger entry with ai_status=disabled', () => {
    const threatWithDisabledStatus: ThreatScore[] = [
      {
        ...THREATS_FIXTURE[0],
        source_ip: '192.0.2.3',
        ai_status: 'disabled',
        ai_confidence: 0.5,
      },
    ]
    const rollup = computeCoverageRollup(threatWithDisabledStatus, [ANALYSIS_RULE_DERIVED_SCORE])
    const headline = formatCoverageHeadline(rollup)
    // Was "0 of 1 actors have AI verdicts" before fix — must now show 1
    expect(headline).toContain('1 of 1 actors have AI verdicts')
  })

  it('counts below-threshold actors (score === 0)', () => {
    const threatsWithZero: ThreatScore[] = [
      { ...THREATS_FIXTURE[0], score: 0 },
      THREATS_FIXTURE[1],
    ]
    const rollup = computeCoverageRollup(threatsWithZero, null)
    expect(rollup.belowThreshold).toBe(1)
  })

  it('returns zero ledgerCount when analyses is null (ledger not wired)', () => {
    const rollup = computeCoverageRollup(THREATS_FIXTURE, null)
    expect(rollup.ledgerCount).toBe(0)
    expect(rollup.aiAnalysed).toBe(0) // no ledger → no AI-analysed actors
  })

  it('handles empty threats array gracefully', () => {
    const rollup = computeCoverageRollup([], null)
    expect(rollup.totalActors).toBe(0)
    expect(rollup.aiAnalysed).toBe(0)
    expect(rollup.rulesOnly).toBe(0)
    expect(rollup.belowThreshold).toBe(0)
    expect(rollup.ledgerCount).toBe(0)
  })

  it('counts all actors as rules-only when ledger is empty (no AI analyses)', () => {
    const rollup = computeCoverageRollup(THREATS_AI_UNAVAILABLE_FIXTURE, [])
    expect(rollup.aiAnalysed).toBe(0)
    expect(rollup.rulesOnly).toBe(THREATS_AI_UNAVAILABLE_FIXTURE.length)
  })

  it('deduplicates IPs: multiple ledger entries for same IP count as 1 analysed actor', () => {
    const duplicateIpAnalyses: AnalysisSummary[] = [
      ANALYSIS_FIXTURE,
      { ...ANALYSIS_FIXTURE, id: 99 }, // same IP, second analysis run
    ]
    const rollup = computeCoverageRollup(THREATS_FIXTURE, duplicateIpAnalyses)
    expect(rollup.aiAnalysed).toBe(1) // still 1 distinct IP
  })

  it('marks rollup as capped when analysesHasMore=true', () => {
    const rollup = computeCoverageRollup(THREATS_FIXTURE, [ANALYSIS_FIXTURE], true)
    expect(rollup.analysesHasMore).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// EARS-MK3-10: formatCoverageHeadline
// ---------------------------------------------------------------------------

describe('coverage.ts — formatCoverageHeadline', () => {
  it('produces headline with real ai_analysed count from ledger', () => {
    const rollup = computeCoverageRollup(THREATS_FIXTURE, [ANALYSIS_FIXTURE])
    const headline = formatCoverageHeadline(rollup)
    expect(headline).toContain('1 of 2 actors have AI verdicts')
    expect(headline).toContain('1 rules-only')
  })

  it('handles no actors (returns honest empty message)', () => {
    const rollup = computeCoverageRollup([], null)
    const headline = formatCoverageHeadline(rollup)
    expect(headline).toContain('No actors observed yet')
    // Never fabricate numbers
    expect(headline).not.toMatch(/\d+ of \d+/)
  })

  it('handles all-rules-only (no ledger entries → aiAnalysed = 0)', () => {
    const rollup = computeCoverageRollup(THREATS_AI_UNAVAILABLE_FIXTURE, [])
    const headline = formatCoverageHeadline(rollup)
    expect(headline).toContain('0 of 1 actors have AI verdicts')
    expect(headline).toContain('1 rules-only')
  })

  it('never invents numbers — headline derived from real rollup counts', () => {
    // Verify the headline matches the rollup exactly
    const rollup = { totalActors: 10, aiAnalysed: 7, rulesOnly: 3, belowThreshold: 1, ledgerCount: 5 }
    const headline = formatCoverageHeadline(rollup)
    expect(headline).toContain('7 of 10')
    expect(headline).toContain('3 rules-only')
  })

  it('renders "N+" when analysesHasMore=true (API was capped — honest lower bound)', () => {
    const rollup = { totalActors: 10, aiAnalysed: 200, rulesOnly: 0, belowThreshold: 0, ledgerCount: 200, analysesHasMore: true }
    const headline = formatCoverageHeadline(rollup)
    // Must not show bare "200" — must show "200+" to signal cap
    expect(headline).toContain('200+ of 10')
    // Must not show bare "200" — must show "200+" to signal cap
    expect(headline).not.toMatch(/200 of \d+ actors have AI verdicts(?!\+)/)  // bare 200 without + is wrong
    // The + form is checked separately — just ensure the capped label is used
  })
})

// ---------------------------------------------------------------------------
// EARS-MK3-11: formatAnalysisAge
// ---------------------------------------------------------------------------

describe('coverage.ts — formatAnalysisAge', () => {
  it('returns "just now" for events < 60 seconds ago', () => {
    const now = Date.now()
    const created = new Date(now - 30_000).toISOString()
    expect(formatAnalysisAge(created, now)).toBe('just now')
  })

  it('returns "Xm ago" for minutes', () => {
    const now = Date.now()
    const created = new Date(now - 5 * 60_000).toISOString()
    expect(formatAnalysisAge(created, now)).toBe('5m ago')
  })

  it('returns "Xh ago" for hours', () => {
    const now = Date.now()
    const created = new Date(now - 2 * 3_600_000).toISOString()
    expect(formatAnalysisAge(created, now)).toBe('2h ago')
  })

  it('returns "Xd ago" for days', () => {
    const now = Date.now()
    const created = new Date(now - 3 * 86_400_000).toISOString()
    expect(formatAnalysisAge(created, now)).toBe('3d ago')
  })

  it('returns the raw string for unparseable dates', () => {
    expect(formatAnalysisAge('not-a-date')).toBe('not-a-date')
  })
})

// ---------------------------------------------------------------------------
// Component tests — need React + mocks
// ---------------------------------------------------------------------------

const { mockFetchThreats, mockFetchHealth, mockFetchAnalyses } = vi.hoisted(() => ({
  mockFetchThreats: vi.fn(),
  mockFetchHealth: vi.fn(),
  mockFetchAnalyses: vi.fn(),
}))

vi.mock('../api/client', () => {
  class ApiError extends Error {
    status: number
    detail: unknown
    constructor(status: number, detail: unknown, message?: string) {
      super(message ?? `API error ${status}`)
      this.status = status
      this.detail = detail
    }
  }
  return {
    fetchThreats: mockFetchThreats,
    fetchHealth: mockFetchHealth,
    fetchAnalyses: mockFetchAnalyses,
    // MK-6: AgreementStat — default to null (503 degrade, renders nothing, non-fatal)
    fetchFeedbackSummary: vi.fn().mockResolvedValue(null),
    // EntityPanelProvider fetches discovery cache on mount (non-fatal)
    fetchSourceTypes: vi.fn().mockResolvedValue([]),
    // MK-9: DriftPanel (useBaselineDrift calls these; default to no-baseline — non-fatal)
    fetchBaselineStatus: vi.fn().mockResolvedValue({ exists: false }),
    fetchDriftReport: vi.fn().mockResolvedValue(null),
    ApiError,
  }
})

// IpPanel fetches — mock to avoid real network calls in tests
vi.mock('../api/logs', () => ({
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
}))

import AIRoute from '../routes/AIRoute'
import { CoverageLedger } from '../components/ai/ledger/CoverageLedger'
import { VerdictCard } from '../components/ai/ledger/VerdictCard'
import { VerdictCardList } from '../components/ai/ledger/VerdictCardList'
import type { VerdictLedgerState } from '../components/ai/ledger/useVerdictLedger'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import { HEALTH_AI_ONLINE } from './readFixtures'

function renderRoute(initialEntries = ['/ai']) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <AIRoute />
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// EARS-MK3-1: Coverage headline templated from real data
// ---------------------------------------------------------------------------

describe('CoverageLedger — coverage headline (EARS-MK3-1)', () => {
  it('renders coverage headline with AI ProvenanceChip (RULE derivation)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger
            threats={THREATS_FIXTURE}
            analyses={[ANALYSIS_FIXTURE]}
            filterParam={null}
          />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    expect(screen.getByTestId('coverage-headline')).toBeInTheDocument()
    // RULE chip is present (deterministic arithmetic, ADR-0035)
    const chip = screen.getByTestId('coverage-provenance-chip')
    expect(chip.getAttribute('data-derivation')).toBe('rule')
  })

  it('headline shows real actor counts from ledger (not ai_status)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger
            threats={THREATS_FIXTURE}
            analyses={[ANALYSIS_FIXTURE]}
            filterParam={null}
          />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const headline = screen.getByTestId('coverage-headline')
    // ANALYSIS_FIXTURE has ip='192.0.2.1' → 1 distinct IP in ledger → aiAnalysed=1
    expect(headline).toHaveTextContent('1 of 2 actors have AI verdicts')
  })

  it('FIX MK3-1: headline shows "analysed 1" for actor with ai_status=disabled but in ledger', () => {
    // Simulate 192.0.2.10 case: AI ran, confidence 0.5 < threshold, ai_status='disabled'
    // but analysis IS in the ledger. The headline must count it as analysed.
    const threatDisabled: ThreatScore[] = [
      {
        ...THREATS_FIXTURE[0],
        source_ip: '192.0.2.3',
        ai_status: 'disabled',
        ai_confidence: 0.5,
      },
    ]
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger
            threats={threatDisabled}
            analyses={[ANALYSIS_RULE_DERIVED_SCORE]}
            filterParam={null}
          />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const headline = screen.getByTestId('coverage-headline')
    // Must show 1, not 0 (the bug that was fixed)
    expect(headline).toHaveTextContent('1 of 1 actors have AI verdicts')
  })

  it('shows honest empty state when threats array is empty (no fabricated counts)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger threats={[]} analyses={null} filterParam={null} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    expect(screen.getByTestId('coverage-ledger-empty')).toBeInTheDocument()
    // Headline still present but says "No actors observed yet"
    expect(screen.getByTestId('coverage-headline')).toHaveTextContent('No actors observed yet')
  })
})

// ---------------------------------------------------------------------------
// EARS-MK3-2: AI-specific columns only — NOT Dashboard duplicates (ADR-0043 D1)
// ---------------------------------------------------------------------------

describe('CoverageLedger — AI-specific columns only (EARS-MK3-2)', () => {
  it('renders AI-specific threat_level column', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger
            threats={THREATS_FIXTURE}
            analyses={[ANALYSIS_FIXTURE]}
            filterParam={null}
          />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    expect(screen.getByTestId('coverage-actor-table')).toBeInTheDocument()
    // Actor threat level rendered (AI-specific column)
    const threatLevels = screen.getAllByTestId('actor-threat-level')
    expect(threatLevels.length).toBeGreaterThan(0)
    // HIGH from THREATS_FIXTURE[0]
    expect(threatLevels[0]).toHaveTextContent('HIGH')
  })

  it('renders ConfidenceLabel (AI-specific column, not in Dashboard)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger
            threats={THREATS_FIXTURE}
            analyses={[ANALYSIS_FIXTURE]}
            filterParam={null}
          />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const labels = screen.getAllByTestId('actor-confidence-label')
    expect(labels.length).toBeGreaterThan(0)
  })

  it('renders ScoreBadge (AI-specific column)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger
            threats={THREATS_FIXTURE}
            analyses={[ANALYSIS_FIXTURE]}
            filterParam={null}
          />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const badges = screen.getAllByTestId('actor-score-badge')
    expect(badges.length).toBeGreaterThan(0)
  })

  it('renders AI status column (not in Dashboard)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger
            threats={THREATS_FIXTURE}
            analyses={[ANALYSIS_FIXTURE]}
            filterParam={null}
          />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const statuses = screen.getAllByTestId('actor-ai-status')
    expect(statuses.length).toBeGreaterThan(0)
  })

  it('renders analysis age column from ledger data (AI-specific)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger
            threats={THREATS_FIXTURE}
            analyses={[ANALYSIS_FIXTURE]}
            filterParam={null}
            now={Date.parse('2026-06-12T12:00:00Z')}
          />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const ageCells = screen.getAllByTestId('actor-analysis-age')
    expect(ageCells.length).toBeGreaterThan(0)
    // First actor (192.0.2.1) has a ledger entry — shows relative age
    expect(ageCells[0]).not.toHaveTextContent('—')
  })

  it('shows "—" for analysis age when no ledger entry for that actor', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger
            threats={THREATS_FIXTURE}
            analyses={[ANALYSIS_FIXTURE]} // only 192.0.2.1 in ledger
            filterParam={null}
          />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const ageCells = screen.getAllByTestId('actor-analysis-age')
    // 192.0.2.2 has no ledger entry — shows "—"
    const hasPlaceholder = ageCells.some((cell) => cell.textContent === '—')
    expect(hasPlaceholder).toBe(true)
  })

  it('does NOT render Events/Blocked/Location/Attacks columns (no Dashboard duplication)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger
            threats={THREATS_FIXTURE}
            analyses={[ANALYSIS_FIXTURE]}
            filterParam={null}
          />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const table = screen.getByTestId('coverage-actor-table')
    // Dashboard-specific headers must NOT appear in this table
    expect(table).not.toHaveTextContent('Events')
    expect(table).not.toHaveTextContent('Blocked')
    expect(table).not.toHaveTextContent('Location')
    expect(table).not.toHaveTextContent('Attacks')
  })
})

// ---------------------------------------------------------------------------
// EARS-MK3-3: Bounded top-N; no inner scrollbars
// ---------------------------------------------------------------------------

describe('CoverageLedger — bounded top-N (EARS-MK3-3)', () => {
  it('shows page 1 of 2 when more than PAGE_SIZE actors exist and exposes pagination controls', () => {
    // Create PAGE_SIZE + 5 actors (exactly 2 pages) — previously TOP_N hard-cut, now paginated (MM #457)
    const totalActors = PAGE_SIZE + 5
    const manyThreats: ThreatScore[] = Array.from({ length: totalActors }, (_, i) => ({
      ...THREATS_FIXTURE[0],
      source_ip: `192.0.2.${i + 1}`,
    }))

    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger threats={manyThreats} analyses={null} filterParam={null} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    // Pager controls are shown (MM #457 — pagination replaces the hard "+N more" cut)
    expect(screen.getByTestId('coverage-pager')).toBeInTheDocument()
    // Honest count label shows "Showing {PAGE_SIZE} of {totalActors} actors" (not "+N more actors")
    expect(screen.getByTestId('coverage-remaining-count')).toBeInTheDocument()
    expect(screen.getByTestId('coverage-remaining-count')).toHaveTextContent(`Showing ${PAGE_SIZE} of ${totalActors} actors`)
    // Next page is reachable (MM #457 — no dead-end)
    expect(screen.getByTestId('coverage-pager-next')).not.toBeDisabled()
    // Page info shows "Page 1 of 2"
    expect(screen.getByTestId('coverage-pager-info')).toHaveTextContent('Page 1 of 2')
  })
})

// ---------------------------------------------------------------------------
// EARS-MK3-4: ?filter=below-threshold as coverage facet (#264 backward-compat)
// ---------------------------------------------------------------------------

describe('CoverageLedger — ?filter=below-threshold facet (EARS-MK3-4)', () => {
  it('renders below-threshold facet indicator when filter is active', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger
            threats={THREATS_FIXTURE}
            analyses={null}
            filterParam="below-threshold"
          />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    expect(screen.getByTestId('coverage-below-threshold-facet')).toBeInTheDocument()
  })

  it('shows only score-0 actors when filter is below-threshold', () => {
    const threatsWithZero: ThreatScore[] = [
      { ...THREATS_FIXTURE[0], score: 75 },
      { ...THREATS_FIXTURE[1], score: 0, source_ip: '192.0.2.99' },
    ]

    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger
            threats={threatsWithZero}
            analyses={null}
            filterParam="below-threshold"
          />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    // Only the score-0 actor (192.0.2.99) should appear
    expect(screen.getByText('192.0.2.99')).toBeInTheDocument()
    // Scored actor must NOT appear
    expect(screen.queryByText('192.0.2.1')).not.toBeInTheDocument()
  })

  it('does NOT render facet indicator when filterParam is null', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger threats={THREATS_FIXTURE} analyses={null} filterParam={null} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    expect(screen.queryByTestId('coverage-below-threshold-facet')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-MK3-5: Verdict cards with AI ProvenanceChip, model, age, ConfidenceLabel, ScoreBadge
// ---------------------------------------------------------------------------

describe('VerdictCard — per-analysis card (EARS-MK3-5)', () => {
  it('renders AI ProvenanceChip on the card (ADR-0035)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard
            analysis={ANALYSIS_FIXTURE}
            now={Date.parse('2026-06-12T12:00:00Z')}
          />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const chip = screen.getByTestId('verdict-provenance-chip')
    expect(chip).toBeInTheDocument()
    // score_derivation is 'ai' — chip should be 'ai'
    expect(chip.getAttribute('data-derivation')).toBe('ai')
  })

  it('FIX MK3-2: chip is "ai" (not "rule") when score_derivation="rule" — content is AI-authored', () => {
    // This is the 192.0.2.10 case: AI ran, confidence < threshold, score stayed rule-derived.
    // The card prose IS AI-authored. Chip must NOT show RULE on an AI-authored card.
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_RULE_DERIVED_SCORE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const chip = screen.getByTestId('verdict-provenance-chip')
    // Must be 'ai', not 'rule' (ADR-0035 / ADR-0043 content authorship)
    expect(chip.getAttribute('data-derivation')).toBe('ai')
    expect(chip.getAttribute('data-derivation')).not.toBe('rule')
  })

  it('chip is "ai+rule" when score_derivation="ai+rule" (mixed signal)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_LOW_CONFIDENCE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const chip = screen.getByTestId('verdict-provenance-chip')
    expect(chip.getAttribute('data-derivation')).toBe('ai+rule')
  })

  it('renders ConfidenceLabel (ADR-0036 word-banded)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_FIXTURE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const label = screen.getByTestId('verdict-confidence-label')
    expect(label).toBeInTheDocument()
    // 0.87 is >= 0.7 → High band
    expect(label.getAttribute('data-confidence-word')).toBe('High')
  })

  it('FIX B: ScoreBadge uses ENGINE band (derived from score), NOT the AI threat_level (ADR-0036 D1)', () => {
    // score=78 → engine band = CRITICAL (78 >= 76), even though AI said HIGH
    // The AI threat_level='HIGH' appears in the verdict area, not on ScoreBadge.
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_FIXTURE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const badge = screen.getByTestId('verdict-score-badge')
    expect(badge).toBeInTheDocument()
    expect(badge.getAttribute('data-score')).toBe('78')
    // Engine band for 78 = CRITICAL (not the AI threat_level='HIGH')
    expect(badge.getAttribute('data-band')).toBe('CRITICAL')
    // AI verdict label is shown separately, not on the badge
    const aiLevelEl = screen.getByTestId('verdict-ai-level')
    expect(aiLevelEl).toHaveTextContent('AI verdict: HIGH')
  })

  it('renders model identity with authored-by text', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_FIXTURE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const modelEl = screen.getByTestId('verdict-model-identity')
    expect(modelEl).toHaveTextContent('authored by')
    expect(modelEl).toHaveTextContent('qwen3:8b')
  })

  it('renders analysis age as time element', () => {
    const fixedNow = Date.parse('2026-06-12T12:00:00Z')
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_FIXTURE} now={fixedNow} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const ageEl = screen.getByTestId('verdict-age')
    expect(ageEl).toBeInTheDocument()
    // created_at = 2026-06-12T10:00:00Z, now = 2026-06-12T12:00:00Z → 2h ago
    expect(ageEl).toHaveTextContent('2h ago')
    expect(ageEl.getAttribute('dateTime')).toBe(ANALYSIS_FIXTURE.created_at)
  })

  it('renders kind chip (concise/detailed)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_FIXTURE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    expect(screen.getByTestId('verdict-kind-chip')).toHaveTextContent('concise')
  })

  it('renders low confidence band correctly', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_LOW_CONFIDENCE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const label = screen.getByTestId('verdict-confidence-label')
    expect(label.getAttribute('data-confidence-word')).toBe('Low')
  })
})

// ---------------------------------------------------------------------------
// EARS-MK3-6: Honest empty state when no analyses
// ---------------------------------------------------------------------------

describe('VerdictCardList — honest empty state (EARS-MK3-6)', () => {
  it('renders honest EmptyState when analyses array is empty (not a spinner)', () => {
    const emptyLedger: VerdictLedgerState = {
      status: 'empty',
      analyses: [],
      nextCursor: null,
      hasMore: false,
      error: null,
    }

    render(<VerdictCardList ledger={emptyLedger} />)

    expect(screen.getByTestId('verdict-list-empty')).toBeInTheDocument()
    expect(screen.getByText('No AI verdicts recorded yet')).toBeInTheDocument()
    // Must NOT be a loading spinner
    expect(screen.queryByTestId('verdict-list-loading')).not.toBeInTheDocument()
  })

  it('renders honest EmptyState when ledger is unavailable (503)', () => {
    // 503 → status 'empty' (honest degrade from useVerdictLedger)
    const emptyLedger: VerdictLedgerState = {
      status: 'empty',
      analyses: [],
      nextCursor: null,
      hasMore: false,
      error: null,
    }

    render(<VerdictCardList ledger={emptyLedger} />)

    const emptyState = screen.getByTestId('verdict-list-empty')
    expect(emptyState).toBeInTheDocument()
    // Call-to-action for the user (honest guidance)
    expect(emptyState).toHaveTextContent('Run a deep analysis')
    // NO fabricated counts
    expect(emptyState.textContent).not.toMatch(/\d+ verdicts/)
  })

  it('renders loading state while fetching', () => {
    const loadingLedger: VerdictLedgerState = {
      status: 'loading',
      analyses: [],
      nextCursor: null,
      hasMore: false,
      error: null,
    }

    render(<VerdictCardList ledger={loadingLedger} />)

    expect(screen.getByTestId('verdict-list-loading')).toBeInTheDocument()
    expect(screen.queryByTestId('verdict-list-empty')).not.toBeInTheDocument()
  })

  it('renders error state on fetch failure', () => {
    const errorLedger: VerdictLedgerState = {
      status: 'error',
      analyses: [],
      nextCursor: null,
      hasMore: false,
      error: 'AI verdicts unavailable (503)',
    }

    render(<VerdictCardList ledger={errorLedger} />)

    expect(screen.getByTestId('verdict-list-error')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('503')
  })
})

// ---------------------------------------------------------------------------
// EARS-MK3-5 continued: card list renders cards when analyses present
// ---------------------------------------------------------------------------

describe('VerdictCardList — renders cards when analyses exist (EARS-MK3-5)', () => {
  it('renders a VerdictCard for each analysis in the list', () => {
    const okLedger: VerdictLedgerState = {
      status: 'ok',
      analyses: [ANALYSIS_FIXTURE, ANALYSIS_LOW_CONFIDENCE],
      nextCursor: null,
      hasMore: false,
      error: null,
    }

    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCardList ledger={okLedger} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const cards = screen.getAllByTestId('verdict-card')
    expect(cards.length).toBe(2)
  })

  it('shows honest count with N+ when hasMore is true (MM #456 — verdict-list-count)', () => {
    const okLedger: VerdictLedgerState = {
      status: 'ok',
      analyses: [ANALYSIS_FIXTURE],
      nextCursor: 'cursor123',
      hasMore: true,
      error: null,
    }

    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCardList ledger={okLedger} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    // MM #456: verdict-list-view-all replaced by verdict-list-count (honest N+ copy)
    expect(screen.getByTestId('verdict-list-count')).toBeInTheDocument()
    expect(screen.getByTestId('verdict-list-count')).toHaveTextContent('1+')
  })
})

// ---------------------------------------------------------------------------
// EARS-MK3-7: Text-node-only rendering (ADR-0029 D3)
// ---------------------------------------------------------------------------

describe('VerdictCard — text-node-only security (EARS-MK3-7)', () => {
  it('renders model string as text node — no script execution for XSS payload', () => {
    const xssAnalysis: AnalysisSummary = {
      ...ANALYSIS_FIXTURE,
      model: '<script>alert("xss")</script>',
    }

    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={xssAnalysis} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    // Literal XSS string visible as text
    expect(screen.getByTestId('verdict-model-identity').textContent).toContain('<script>')
    // No actual script element created
    expect(document.querySelector('script[src]')).toBeNull()
  })

  it('renders ip as text node via ClickableIp (ADR-0029 D3)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_FIXTURE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    // ClickableIp renders ip as text node
    const ipEl = screen.getByTestId('clickable-ip')
    expect(ipEl.textContent).toBe('192.0.2.1')
    expect(ipEl.tagName).toBe('BUTTON') // not a script or iframe
  })
})

// ---------------------------------------------------------------------------
// EARS-MK3-8: WCAG keyboard paths
// ---------------------------------------------------------------------------

describe('VerdictCard — WCAG keyboard (EARS-MK3-8)', () => {
  it('card is focusable (has tabIndex=0)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_FIXTURE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const card = screen.getByTestId('verdict-card')
    expect(card.getAttribute('tabIndex')).toBe('0')
  })

  it('card has role="article" for screen readers', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_FIXTURE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    expect(screen.getByRole('article')).toBeInTheDocument()
  })

  it('card has descriptive aria-label', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_FIXTURE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const card = screen.getByTestId('verdict-card')
    expect(card.getAttribute('aria-label')).toContain('192.0.2.1')
    expect(card.getAttribute('aria-label')).toContain('HIGH')
    expect(card.getAttribute('aria-label')).toContain('qwen3:8b')
  })
})

// ---------------------------------------------------------------------------
// EARS-MK3-12/13: AIRoute integration — AiThreatTable gone, new panels present
// ---------------------------------------------------------------------------

describe('AIRoute — MK-3 integration (EARS-MK3-12/13)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
    mockFetchAnalyses.mockResolvedValue({
      items: [ANALYSIS_FIXTURE],
      next_cursor: null,
      has_more: false,
    })
  })

  it('renders coverage ledger panel (not the old AiThreatTable)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('coverage-ledger-panel')).toBeInTheDocument()
    })

    expect(screen.getByTestId('coverage-ledger')).toBeInTheDocument()
  })

  it('renders verdict cards panel', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('verdict-cards-panel')).toBeInTheDocument()
    })
  })

  it('does NOT render the duplicate threat table (ai-threats-table gone)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      // Coverage ledger panel is present
      expect(screen.getByTestId('coverage-ledger-panel')).toBeInTheDocument()
    })

    // The old duplicate table must NOT be present (MK-3 removes AiThreatTable)
    expect(screen.queryByTestId('ai-threats-table')).not.toBeInTheDocument()
  })

  it('renders verdict cards when analyses are returned from API', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getAllByTestId('verdict-card').length).toBeGreaterThan(0)
    })

    // AI ProvenanceChip present on the card (ADR-0035) — must be 'ai', not 'rule'
    const chip = screen.getByTestId('verdict-provenance-chip')
    expect(chip.getAttribute('data-derivation')).toBe('ai')
    expect(chip.getAttribute('data-derivation')).not.toBe('rule')
  })

  it('renders honest EmptyState when analyses API returns empty list', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchAnalyses.mockResolvedValue({ items: [], next_cursor: null, has_more: false })

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('verdict-list-empty')).toBeInTheDocument()
    })

    expect(screen.getByText('No AI verdicts recorded yet')).toBeInTheDocument()
  })

  it('renders honest EmptyState when ledger returns 503 (not wired)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchAnalyses.mockResolvedValue(null) // 503 → fetchAnalyses returns null

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('verdict-list-empty')).toBeInTheDocument()
    })
  })

  // EARS-MK3-14: backward-compat — existing #264 below-threshold banner testid preserved
  it('still shows ai-below-threshold-banner testid when ?filter=below-threshold', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    render(
      <MemoryRouter initialEntries={['/ai?filter=below-threshold']}>
        <AIRoute />
      </MemoryRouter>,
    )

    await waitFor(() => {
      expect(screen.getByTestId('ai-below-threshold-banner')).toBeInTheDocument()
    })

    expect(screen.getByTestId('ai-below-threshold-banner')).toHaveTextContent(
      'below score threshold',
    )
  })

  // MK-1 backward-compat: existing page subtitle test must still pass
  it('still renders the ADR-0043 page subtitle (MK-1 backward-compat)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-page-subtitle')).toHaveTextContent(
        'Every verdict, what the model saw, and proof nothing left this box.',
      )
    })
  })
})

// ---------------------------------------------------------------------------
// FIX A — Score-effect line: "did the AI move the score?"
// ---------------------------------------------------------------------------

describe('VerdictCard — score-effect line (FIX A — updated for MM #455 plain-English causal lines)', () => {
  it('HIGH/under-confident: plain causal text mentions verdict level, confidence band+value, and rule-based score', () => {
    // 192.0.2.10 case: AI ran, verdict HIGH, confidence 0.5 (Medium band), below the 0.70 gate.
    // This is the sole case where confidence-vs-gate is the real reason.
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_RULE_DERIVED_SCORE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const effectLine = screen.getByTestId('verdict-score-effect')
    expect(effectLine).toBeInTheDocument()
    // Plain causal text: "leaned High-risk but wasn't confident enough"
    expect(effectLine).toHaveTextContent("leaned High-risk but wasn't confident enough")
    // Must include confidence band word from data (0.5 = Medium)
    expect(effectLine).toHaveTextContent('Medium')
    // Must include the raw confidence value from data
    expect(effectLine).toHaveTextContent('0.50')
    // Must say rule-based score
    expect(effectLine).toHaveTextContent('rule-based score')
  })

  it('shows "AI was confident enough to raise the score" line when score_derivation="ai" (boost fired)', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_FIXTURE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const effectLine = screen.getByTestId('verdict-score-effect')
    expect(effectLine).toBeInTheDocument()
    expect(effectLine).toHaveTextContent('confident enough to raise the score')
    expect(effectLine).toHaveTextContent('boost applied')
  })

  it('shows "AI was confident enough to raise the score" line when score_derivation="ai+rule"', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_LOW_CONFIDENCE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const effectLine = screen.getByTestId('verdict-score-effect')
    expect(effectLine).toHaveTextContent('confident enough to raise the score')
    expect(effectLine).toHaveTextContent('boost applied')
  })
})

// ---------------------------------------------------------------------------
// FIX B — ScoreBadge uses engine band, AI verdict is labeled separately
// ---------------------------------------------------------------------------

describe('VerdictCard — FIX B engine band vs AI verdict level', () => {
  it('score=0 → ScoreBadge shows LOW band (engine), even when AI said MEDIUM', () => {
    // Simulate exact live data: score=0, threat_level=MEDIUM, score_derivation=rule
    const analysisScoreZero: AnalysisSummary = {
      ...ANALYSIS_RULE_DERIVED_SCORE,
      score: 0,
      threat_level: 'MEDIUM',
    }

    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={analysisScoreZero} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const badge = screen.getByTestId('verdict-score-badge')
    // Engine band for score=0 is LOW (not the AI verdict MEDIUM)
    expect(badge.getAttribute('data-score')).toBe('0')
    expect(badge.getAttribute('data-band')).toBe('LOW')

    // The AI verdict MEDIUM is shown separately, not on the badge
    const aiLevelEl = screen.getByTestId('verdict-ai-level')
    expect(aiLevelEl).toHaveTextContent('AI verdict: MEDIUM')
  })

  it('AI verdict level is NOT shown on the score badge (two artifacts, two places)', () => {
    const analysisScoreZero: AnalysisSummary = {
      ...ANALYSIS_RULE_DERIVED_SCORE,
      score: 0,
      threat_level: 'MEDIUM',
    }

    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={analysisScoreZero} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const badge = screen.getByTestId('verdict-score-badge')
    // Default variant renders "Risk 0 · LOW" — band label is visible
    expect(badge.textContent).toContain('LOW')
    expect(badge.textContent).not.toContain('MEDIUM')
    // The separate label shows the AI verdict
    expect(screen.getByTestId('verdict-ai-level')).toHaveTextContent('AI verdict: MEDIUM')
  })
})

// ---------------------------------------------------------------------------
// FIX C — Coverage headline wording + moved-score facet
// ---------------------------------------------------------------------------

describe('coverage.ts — FIX C moved-score facet (computeCoverageRollup)', () => {
  it('counts movedScore: ledger IPs with score_derivation includes "ai"', () => {
    const analyses: AnalysisSummary[] = [
      { ...ANALYSIS_FIXTURE, ip: '192.0.2.1', score_derivation: 'ai' },
      { ...ANALYSIS_FIXTURE, ip: '192.0.2.2', score_derivation: 'ai+rule' },
      { ...ANALYSIS_FIXTURE, ip: '192.0.2.3', score_derivation: 'rule' },
    ]
    const threats: ThreatScore[] = analyses.map((a) => ({ ...THREATS_FIXTURE[0], source_ip: a.ip }))
    const rollup = computeCoverageRollup(threats, analyses)
    // 2 IPs with ai/ai+rule → movedScore=2; 1 with rule → belowBoostGate=1
    expect(rollup.movedScore).toBe(2)
    expect(rollup.belowBoostGate).toBe(1)
  })

  it('movedScore=0 and belowBoostGate=0 when analyses is null', () => {
    const rollup = computeCoverageRollup(THREATS_FIXTURE, null)
    expect(rollup.movedScore).toBe(0)
    expect(rollup.belowBoostGate).toBe(0)
  })

  it('headline uses "N of M actors have AI verdicts" wording', () => {
    const rollup = computeCoverageRollup(THREATS_FIXTURE, [ANALYSIS_FIXTURE])
    const headline = formatCoverageHeadline(rollup)
    expect(headline).toContain('1 of 2 actors have AI verdicts')
  })

  it('headline appends moved-score sub-split when present', () => {
    const analyses: AnalysisSummary[] = [
      { ...ANALYSIS_FIXTURE, ip: '192.0.2.1', score_derivation: 'ai' },
      { ...ANALYSIS_FIXTURE, ip: '192.0.2.2', score_derivation: 'rule' },
    ]
    const threats: ThreatScore[] = analyses.map((a) => ({ ...THREATS_FIXTURE[0], source_ip: a.ip }))
    const rollup = computeCoverageRollup(threats, analyses)
    const headline = formatCoverageHeadline(rollup)
    // Sub-split: "1 moved the score · 1 below the boost gate"
    expect(headline).toContain('1 moved the score')
    expect(headline).toContain('1 below the boost gate')
  })

  it('headline does NOT show sub-split when all analyses score_derivation=ai (no below-gate)', () => {
    const analyses: AnalysisSummary[] = [
      { ...ANALYSIS_FIXTURE, ip: '192.0.2.1', score_derivation: 'ai' },
    ]
    const threats: ThreatScore[] = [{ ...THREATS_FIXTURE[0], source_ip: '192.0.2.1' }]
    const rollup = computeCoverageRollup(threats, analyses)
    const headline = formatCoverageHeadline(rollup)
    // movedScore=1, belowBoostGate=0 — only "1 moved the score" appears
    expect(headline).toContain('1 moved the score')
    expect(headline).not.toContain('below the boost gate')
  })

  it('zero-case uses "have AI verdicts" wording (matches non-zero wording)', () => {
    // When aiAnalysed=0, headline should be consistent with the non-zero form
    const rollup = computeCoverageRollup(THREATS_AI_UNAVAILABLE_FIXTURE, [])
    const headline = formatCoverageHeadline(rollup)
    expect(headline).toContain('0 of 1 actors have AI verdicts')
  })
})

// ---------------------------------------------------------------------------
// FIX D — ai_status='ok' check in VerdictCard + CoverageLedger
// ---------------------------------------------------------------------------

describe('VerdictCard — FIX D ai_status "ok" green highlight', () => {
  it('ai_status="ok" renders in green (not "active")', () => {
    // ANALYSIS_FIXTURE has ai_status='ok' (fixed from prior 'active')
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_FIXTURE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const statusEl = screen.getByTestId('verdict-ai-status')
    expect(statusEl).toHaveTextContent('ok')
    // The green color is set via inline style when ai_status==='ok'
    expect(statusEl.style.color).toBe('var(--fw-green)')
  })

  it('ai_status not "ok" (e.g. "disabled") renders in muted color', () => {
    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <VerdictCard analysis={ANALYSIS_RULE_DERIVED_SCORE} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const statusEl = screen.getByTestId('verdict-ai-status')
    expect(statusEl).toHaveTextContent('disabled')
    expect(statusEl.style.color).toBe('var(--fw-t3)')
  })
})
