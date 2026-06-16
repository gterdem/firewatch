/**
 * Tests for MM #456 — verdict-cards pagination + workflow filters.
 *
 * EARS criteria covered:
 *
 * EARS-MM456-1: THE verdict-cards pane SHALL provide filter chips for:
 *   "All", "Ungraded" (no analyst feedback), "Disagreed", and "AI moved score"
 *   (score_derivation includes 'ai'). Each chip shows a count badge.
 *
 * EARS-MM456-2: WHEN a filter chip is active, the card grid SHALL show only
 *   verdicts matching that filter. Other verdicts are not rendered.
 *
 * EARS-MM456-3: WHEN the filtered set is empty (but analyses exist), an honest
 *   per-filter empty state SHALL be shown (no fabricated content).
 *
 * EARS-MM456-4: THE pager SHALL show "Page N of M" with prev/next buttons.
 *   Clicking Next advances to page 2; clicking Prev returns to page 1.
 *
 * EARS-MM456-5: THE pager SHALL NOT be rendered when there is only one page.
 *
 * EARS-MM456-6: THE "Showing X–Y of Z (loaded)" count line SHALL be honest:
 *   - Shows current page range and filter total.
 *   - Shows "N+" when hasMore=true (server has more beyond the loaded set).
 *
 * EARS-MM456-7: WHEN hasMore=true, a "Load more from server" button SHALL appear.
 *   Clicking it calls loadMore(). WHEN hasMore=false, the button SHALL NOT be present.
 *
 * EARS-MM456-8: THE pane SHALL NEVER render an inner scrollbar.
 *   (Structural: the card container has no overflow:auto or overflow:scroll style.)
 *
 * EARS-MM456-9: THE existing empty/loading/error states SHALL remain intact.
 *
 * All IPs use RFC 5737 documentation ranges (192.0.2.x).
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { VerdictCardList } from '../components/ai/ledger/VerdictCardList'
import { useVerdictFilters, PAGE_SIZE } from '../components/ai/ledger/useVerdictFilters'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import type { AnalysisSummary } from '../api/types'
import type { VerdictLedgerState } from '../components/ai/ledger/useVerdictLedger'

// ---------------------------------------------------------------------------
// Mocks for all API modules (mirrors MK3 test pattern).
// Mocking ../api/client replaces resolveBaseUrl-dependent modules too.
// ../api/logs is mocked separately (EntityPanelProvider → IpPanel imports it).
// ---------------------------------------------------------------------------

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
    fetchSourceTypes: vi.fn().mockResolvedValue([]),
    fetchAnalyses: vi.fn().mockResolvedValue({ items: [], next_cursor: null, has_more: false }),
    fetchFeedbackSummary: vi.fn().mockResolvedValue(null),
    fetchBaselineStatus: vi.fn().mockResolvedValue({ exists: false }),
    fetchDriftReport: vi.fn().mockResolvedValue(null),
    ApiError,
    resolveBaseUrl: vi.fn().mockReturnValue(''),
  }
})

// IpPanel fetches — mock to avoid real network calls in tests
vi.mock('../api/logs', () => ({
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
}))

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeAnalysis(overrides: Partial<AnalysisSummary> & { id: number; ip: string }): AnalysisSummary {
  return {
    kind: 'concise',
    model: 'qwen3:8b',
    endpoint_host: '127.0.0.1:11434',
    ai_status: 'ok',
    threat_level: 'HIGH',
    confidence: 0.87,
    score: 78,
    score_derivation: 'rule',
    latency_ms: 1200,
    prompt_tokens: null,
    completion_tokens: null,
    schema_version: 1,
    created_at: '2026-06-12T10:00:00Z',
    feedback: null,
    ...overrides,
  }
}

/** 15 analyses so we need 2 pages at PAGE_SIZE=10. */
function makeAnalysesSet(count: number, startId = 1): AnalysisSummary[] {
  return Array.from({ length: count }, (_, i) => {
    const id = startId + i
    const ip = `192.0.2.${(id % 250) + 1}`
    // Spread across cases for filter testing:
    // First third: ungraded + ai-moved
    // Second third: disagreed + rule-derived
    // Last third: agreed + rule-derived
    const third = Math.floor((i / count) * 3)
    if (third === 0) {
      return makeAnalysis({ id, ip, score_derivation: 'ai', feedback: null })
    } else if (third === 1) {
      return makeAnalysis({
        id,
        ip,
        score_derivation: 'rule',
        feedback: { verdict: 'disagree', created_at: '2026-06-12T10:00:00Z' },
      })
    } else {
      return makeAnalysis({
        id,
        ip,
        score_derivation: 'rule',
        feedback: { verdict: 'agree', created_at: '2026-06-12T10:00:00Z' },
      })
    }
  })
}

type TestLedger = VerdictLedgerState & { loadMore?: () => void }

/** Build a test ledger for passing to VerdictCardList. */
function makeLedger(
  analyses: AnalysisSummary[],
  options: {
    hasMore?: boolean
    nextCursor?: string | null
    status?: VerdictLedgerState['status']
    error?: string | null
    loadMore?: () => void
  } = {},
): TestLedger {
  return {
    status: options.status ?? 'ok',
    analyses,
    hasMore: options.hasMore ?? false,
    nextCursor: options.nextCursor ?? null,
    error: options.error ?? null,
    loadMore: options.loadMore,
  }
}

/** Render VerdictCardList with providers. */
function renderList(ledger: TestLedger, now?: number) {
  render(
    <MemoryRouter>
      <EntityPanelProvider>
        <VerdictCardList ledger={ledger} now={now} />
      </EntityPanelProvider>
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// EARS-MM456-9: pre-existing empty/loading/error states
// ---------------------------------------------------------------------------

describe('MM #456 — existing states intact (EARS-MM456-9)', () => {
  it('renders loading state when status=loading', () => {
    renderList(makeLedger([], { status: 'loading' }))
    expect(screen.getByTestId('verdict-list-loading')).toBeInTheDocument()
  })

  it('renders error state when status=error', () => {
    renderList(makeLedger([], { status: 'error', error: 'AI verdicts unavailable (503)' }))
    expect(screen.getByTestId('verdict-list-error')).toBeInTheDocument()
    expect(screen.getByTestId('verdict-list-error')).toHaveTextContent('503')
  })

  it('renders empty state when analyses are empty', () => {
    renderList(makeLedger([], { status: 'empty' }))
    expect(screen.getByTestId('verdict-list-empty')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-MM456-1: filter chips present with correct counts
// ---------------------------------------------------------------------------

describe('MM #456 — filter chips (EARS-MM456-1)', () => {
  it('renders all 4 filter chips when analyses are loaded', () => {
    renderList(makeLedger(makeAnalysesSet(3)))
    expect(screen.getByTestId('verdict-filter-chip-all')).toBeInTheDocument()
    expect(screen.getByTestId('verdict-filter-chip-ungraded')).toBeInTheDocument()
    expect(screen.getByTestId('verdict-filter-chip-disagreed')).toBeInTheDocument()
    expect(screen.getByTestId('verdict-filter-chip-ai-moved')).toBeInTheDocument()
  })

  it('"All" chip is active by default (aria-pressed=true)', () => {
    renderList(makeLedger(makeAnalysesSet(3)))
    const allChip = screen.getByTestId('verdict-filter-chip-all')
    expect(allChip).toHaveAttribute('aria-pressed', 'true')
  })

  it('"Ungraded" chip count equals number of analyses with null feedback', () => {
    // 5 analyses: 2 ungraded, 2 agreed, 1 disagreed
    const analyses = [
      makeAnalysis({ id: 1, ip: '192.0.2.1', feedback: null }),
      makeAnalysis({ id: 2, ip: '192.0.2.2', feedback: null }),
      makeAnalysis({ id: 3, ip: '192.0.2.3', feedback: { verdict: 'agree', created_at: '' } }),
      makeAnalysis({ id: 4, ip: '192.0.2.4', feedback: { verdict: 'agree', created_at: '' } }),
      makeAnalysis({ id: 5, ip: '192.0.2.5', feedback: { verdict: 'disagree', created_at: '' } }),
    ]
    renderList(makeLedger(analyses))
    const ungradedChip = screen.getByTestId('verdict-filter-chip-ungraded')
    expect(ungradedChip).toHaveTextContent('2')
  })

  it('"Disagreed" chip count equals number of analyses with disagree feedback', () => {
    const analyses = [
      makeAnalysis({ id: 1, ip: '192.0.2.1', feedback: { verdict: 'disagree', created_at: '' } }),
      makeAnalysis({ id: 2, ip: '192.0.2.2', feedback: { verdict: 'disagree', created_at: '' } }),
      makeAnalysis({ id: 3, ip: '192.0.2.3', feedback: { verdict: 'agree', created_at: '' } }),
    ]
    renderList(makeLedger(analyses))
    const disagreedChip = screen.getByTestId('verdict-filter-chip-disagreed')
    expect(disagreedChip).toHaveTextContent('2')
  })

  it('"AI moved score" chip count equals analyses where score_derivation includes ai', () => {
    const analyses = [
      makeAnalysis({ id: 1, ip: '192.0.2.1', score_derivation: 'ai' }),
      makeAnalysis({ id: 2, ip: '192.0.2.2', score_derivation: 'ai+rule' }),
      makeAnalysis({ id: 3, ip: '192.0.2.3', score_derivation: 'rule' }),
      makeAnalysis({ id: 4, ip: '192.0.2.4', score_derivation: 'rule' }),
    ]
    renderList(makeLedger(analyses))
    const aiMovedChip = screen.getByTestId('verdict-filter-chip-ai-moved')
    expect(aiMovedChip).toHaveTextContent('2')
  })
})

// ---------------------------------------------------------------------------
// EARS-MM456-2: filter chips narrow the card set correctly
// ---------------------------------------------------------------------------

describe('MM #456 — filter narrows card set (EARS-MM456-2)', () => {
  // 5 analyses: 2 ungraded, 1 disagreed, 2 agreed+rule-derived
  const analyses = [
    makeAnalysis({ id: 1, ip: '192.0.2.1', feedback: null, score_derivation: 'ai' }),
    makeAnalysis({ id: 2, ip: '192.0.2.2', feedback: null, score_derivation: 'rule' }),
    makeAnalysis({ id: 3, ip: '192.0.2.3', feedback: { verdict: 'disagree', created_at: '' }, score_derivation: 'rule' }),
    makeAnalysis({ id: 4, ip: '192.0.2.4', feedback: { verdict: 'agree', created_at: '' }, score_derivation: 'rule' }),
    makeAnalysis({ id: 5, ip: '192.0.2.5', feedback: { verdict: 'agree', created_at: '' }, score_derivation: 'rule' }),
  ]

  it('Ungraded filter shows only analyses with null feedback', () => {
    renderList(makeLedger(analyses))
    fireEvent.click(screen.getByTestId('verdict-filter-chip-ungraded'))
    // Should show 2 cards (id=1 and id=2 are ungraded)
    const cards = screen.getAllByTestId('verdict-card')
    expect(cards).toHaveLength(2)
  })

  it('Disagreed filter shows only analyses with disagree feedback', () => {
    renderList(makeLedger(analyses))
    fireEvent.click(screen.getByTestId('verdict-filter-chip-disagreed'))
    const cards = screen.getAllByTestId('verdict-card')
    expect(cards).toHaveLength(1)
  })

  it('AI-moved filter shows only analyses where score_derivation includes ai', () => {
    renderList(makeLedger(analyses))
    fireEvent.click(screen.getByTestId('verdict-filter-chip-ai-moved'))
    // Only id=1 has score_derivation='ai'
    const cards = screen.getAllByTestId('verdict-card')
    expect(cards).toHaveLength(1)
  })

  it('All filter returns all analyses (no filter applied)', () => {
    renderList(makeLedger(analyses))
    // All chip is active by default
    const cards = screen.getAllByTestId('verdict-card')
    expect(cards).toHaveLength(5)
  })

  it('clicking Disagreed then All restores the full set', () => {
    renderList(makeLedger(analyses))
    fireEvent.click(screen.getByTestId('verdict-filter-chip-disagreed'))
    expect(screen.getAllByTestId('verdict-card')).toHaveLength(1)
    fireEvent.click(screen.getByTestId('verdict-filter-chip-all'))
    expect(screen.getAllByTestId('verdict-card')).toHaveLength(5)
  })
})

// ---------------------------------------------------------------------------
// EARS-MM456-3: per-filter empty states
// ---------------------------------------------------------------------------

describe('MM #456 — per-filter honest empty states (EARS-MM456-3)', () => {
  it('shows filter-specific empty state when Ungraded filter returns zero matches', () => {
    // All analyses are graded (agreed)
    const analyses = [
      makeAnalysis({ id: 1, ip: '192.0.2.1', feedback: { verdict: 'agree', created_at: '' } }),
      makeAnalysis({ id: 2, ip: '192.0.2.2', feedback: { verdict: 'agree', created_at: '' } }),
    ]
    renderList(makeLedger(analyses))
    fireEvent.click(screen.getByTestId('verdict-filter-chip-ungraded'))
    expect(screen.getByTestId('verdict-filter-empty')).toBeInTheDocument()
    // Verdict cards should NOT be rendered
    expect(screen.queryByTestId('verdict-card')).not.toBeInTheDocument()
  })

  it('shows filter-specific empty state when Disagreed filter returns zero matches', () => {
    const analyses = [
      makeAnalysis({ id: 1, ip: '192.0.2.1', feedback: { verdict: 'agree', created_at: '' } }),
    ]
    renderList(makeLedger(analyses))
    fireEvent.click(screen.getByTestId('verdict-filter-chip-disagreed'))
    expect(screen.getByTestId('verdict-filter-empty')).toBeInTheDocument()
  })

  it('shows filter-specific empty state when AI-moved filter returns zero matches', () => {
    // All rule-derived
    const analyses = [
      makeAnalysis({ id: 1, ip: '192.0.2.1', score_derivation: 'rule' }),
      makeAnalysis({ id: 2, ip: '192.0.2.2', score_derivation: 'rule' }),
    ]
    renderList(makeLedger(analyses))
    fireEvent.click(screen.getByTestId('verdict-filter-chip-ai-moved'))
    expect(screen.getByTestId('verdict-filter-empty')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-MM456-4: pagination — next/prev buttons reach beyond page 1
// ---------------------------------------------------------------------------

describe('MM #456 — pager navigates beyond page 1 (EARS-MM456-4)', () => {
  it(`shows ${PAGE_SIZE} cards on page 1 when there are ${PAGE_SIZE + 5} total`, () => {
    renderList(makeLedger(makeAnalysesSet(PAGE_SIZE + 5)))
    const cards = screen.getAllByTestId('verdict-card')
    expect(cards).toHaveLength(PAGE_SIZE)
  })

  it('pager shows "Page 1 of 2" for 15 analyses', () => {
    renderList(makeLedger(makeAnalysesSet(PAGE_SIZE + 5)))
    expect(screen.getByTestId('verdict-pager-indicator')).toHaveTextContent('Page 1 of 2')
  })

  it('clicking Next advances to page 2 and shows remaining cards', () => {
    renderList(makeLedger(makeAnalysesSet(PAGE_SIZE + 5)))
    fireEvent.click(screen.getByTestId('verdict-pager-next'))
    // Page 2 has 5 cards (15 total, 10 on page 1)
    const cards = screen.getAllByTestId('verdict-card')
    expect(cards).toHaveLength(5)
    expect(screen.getByTestId('verdict-pager-indicator')).toHaveTextContent('Page 2 of 2')
  })

  it('clicking Prev on page 2 returns to page 1', () => {
    renderList(makeLedger(makeAnalysesSet(PAGE_SIZE + 5)))
    fireEvent.click(screen.getByTestId('verdict-pager-next'))
    expect(screen.getByTestId('verdict-pager-indicator')).toHaveTextContent('Page 2 of 2')
    fireEvent.click(screen.getByTestId('verdict-pager-prev'))
    expect(screen.getByTestId('verdict-pager-indicator')).toHaveTextContent('Page 1 of 2')
    expect(screen.getAllByTestId('verdict-card')).toHaveLength(PAGE_SIZE)
  })

  it('Prev button is disabled on page 1', () => {
    renderList(makeLedger(makeAnalysesSet(PAGE_SIZE + 5)))
    expect(screen.getByTestId('verdict-pager-prev')).toBeDisabled()
  })

  it('Next button is disabled on the last page', () => {
    renderList(makeLedger(makeAnalysesSet(PAGE_SIZE + 5)))
    fireEvent.click(screen.getByTestId('verdict-pager-next'))
    expect(screen.getByTestId('verdict-pager-next')).toBeDisabled()
  })
})

// ---------------------------------------------------------------------------
// EARS-MM456-5: pager not rendered for single page
// ---------------------------------------------------------------------------

describe('MM #456 — pager absent when only one page (EARS-MM456-5)', () => {
  it('pager is not rendered when there are fewer cards than PAGE_SIZE', () => {
    renderList(makeLedger(makeAnalysesSet(5)))
    expect(screen.queryByTestId('verdict-pager')).not.toBeInTheDocument()
  })

  it('pager IS rendered when there are more cards than PAGE_SIZE', () => {
    renderList(makeLedger(makeAnalysesSet(PAGE_SIZE + 1)))
    expect(screen.getByTestId('verdict-pager')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-MM456-6: honest count line
// ---------------------------------------------------------------------------

describe('MM #456 — honest count line (EARS-MM456-6)', () => {
  it('shows "X–Y of Z (Z loaded)" when hasMore=false', () => {
    renderList(makeLedger(makeAnalysesSet(5)))
    const countLine = screen.getByTestId('verdict-list-count')
    expect(countLine).toHaveTextContent('5')
    expect(countLine).toHaveTextContent('loaded')
  })

  it('shows "N+" when hasMore=true (server has more pages)', () => {
    renderList(makeLedger(makeAnalysesSet(200), { hasMore: true, nextCursor: 'abc' }))
    const countLine = screen.getByTestId('verdict-list-count')
    expect(countLine).toHaveTextContent('200+')
  })

  it('count shows filter context when a filter is active', () => {
    const analyses = [
      makeAnalysis({ id: 1, ip: '192.0.2.1', feedback: null }),
      makeAnalysis({ id: 2, ip: '192.0.2.2', feedback: { verdict: 'agree', created_at: '' } }),
    ]
    renderList(makeLedger(analyses))
    fireEvent.click(screen.getByTestId('verdict-filter-chip-ungraded'))
    const countLine = screen.getByTestId('verdict-list-count')
    // Should include filter label in the count line
    expect(countLine).toHaveTextContent('Ungraded')
  })
})

// ---------------------------------------------------------------------------
// EARS-MM456-7: load-more button for server pagination
// ---------------------------------------------------------------------------

describe('MM #456 — load-more server pagination (EARS-MM456-7)', () => {
  it('Load more button is shown when hasMore=true', () => {
    renderList(makeLedger(makeAnalysesSet(10), { hasMore: true, nextCursor: 'cursor-abc' }))
    expect(screen.getByTestId('verdict-load-more')).toBeInTheDocument()
  })

  it('Load more button is NOT shown when hasMore=false', () => {
    renderList(makeLedger(makeAnalysesSet(10), { hasMore: false }))
    expect(screen.queryByTestId('verdict-load-more')).not.toBeInTheDocument()
  })

  it('clicking Load more calls loadMore()', () => {
    const loadMore = vi.fn()
    renderList(makeLedger(makeAnalysesSet(10), { hasMore: true, nextCursor: 'cursor-abc', loadMore }))
    fireEvent.click(screen.getByTestId('verdict-load-more'))
    expect(loadMore).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// EARS-MM456-8: no inner scrollbar
// ---------------------------------------------------------------------------

describe('MM #456 — no inner scrollbar (EARS-MM456-8)', () => {
  it('the card grid container has no overflow:auto or overflow:scroll style', () => {
    renderList(makeLedger(makeAnalysesSet(5)))
    const cardGrid = screen.getByTestId('verdict-card-list')
    // The outer container should not set overflow to auto or scroll
    const style = cardGrid.getAttribute('style') ?? ''
    expect(style).not.toMatch(/overflow\s*:\s*auto/)
    expect(style).not.toMatch(/overflow\s*:\s*scroll/)
  })
})

// ---------------------------------------------------------------------------
// useVerdictFilters unit tests
// ---------------------------------------------------------------------------

import { renderHook, act } from '@testing-library/react'

describe('useVerdictFilters — unit tests', () => {
  const buildSamples = (): AnalysisSummary[] => [
    makeAnalysis({ id: 1, ip: '192.0.2.1', feedback: null, score_derivation: 'ai' }),
    makeAnalysis({ id: 2, ip: '192.0.2.2', feedback: null, score_derivation: 'rule' }),
    makeAnalysis({ id: 3, ip: '192.0.2.3', feedback: { verdict: 'disagree', created_at: '' }, score_derivation: 'rule' }),
    makeAnalysis({ id: 4, ip: '192.0.2.4', feedback: { verdict: 'agree', created_at: '' }, score_derivation: 'ai+rule' }),
  ]

  it('initial filter is all, page 0', () => {
    const { result } = renderHook(() => useVerdictFilters(buildSamples()))
    expect(result.current.activeFilter).toBe('all')
    expect(result.current.currentPage).toBe(0)
  })

  it('ungraded filter returns only null-feedback analyses', () => {
    const { result } = renderHook(() => useVerdictFilters(buildSamples()))
    act(() => result.current.setFilter('ungraded'))
    expect(result.current.filteredTotal).toBe(2)
    expect(result.current.pageItems.every((a) => a.feedback == null)).toBe(true)
  })

  it('disagreed filter returns only disagree-verdict analyses', () => {
    const { result } = renderHook(() => useVerdictFilters(buildSamples()))
    act(() => result.current.setFilter('disagreed'))
    expect(result.current.filteredTotal).toBe(1)
    expect(result.current.pageItems[0].feedback?.verdict).toBe('disagree')
  })

  it('ai-moved filter returns only ai or ai+rule derivation analyses', () => {
    const { result } = renderHook(() => useVerdictFilters(buildSamples()))
    act(() => result.current.setFilter('ai-moved'))
    expect(result.current.filteredTotal).toBe(2)
    result.current.pageItems.forEach((a) => {
      expect(['ai', 'ai+rule']).toContain(a.score_derivation)
    })
  })

  it('changing filter resets page to 0', () => {
    // Build 25 items so we can advance the page
    const many = Array.from({ length: 25 }, (_, i) =>
      makeAnalysis({ id: i + 1, ip: `192.0.2.${i + 1}`, feedback: null, score_derivation: 'ai' }),
    )
    const { result } = renderHook(() => useVerdictFilters(many))
    act(() => result.current.nextPage())
    expect(result.current.currentPage).toBe(1)
    act(() => result.current.setFilter('ai-moved'))
    expect(result.current.currentPage).toBe(0)
  })

  it('filterCounts are correct', () => {
    const { result } = renderHook(() => useVerdictFilters(buildSamples()))
    expect(result.current.filterCounts.all).toBe(4)
    expect(result.current.filterCounts.ungraded).toBe(2)
    expect(result.current.filterCounts.disagreed).toBe(1)
    expect(result.current.filterCounts['ai-moved']).toBe(2)
  })
})
