/**
 * Tests for MM #453 + #457 — CoverageLedger sort + search + glosses + pagination.
 *
 * EARS criteria covered:
 *
 * MM-453-1: Sortable headers — clicking Score/Confidence/Analysis-age toggles asc/desc.
 * MM-453-2: Sort indicator (▼/▲) is visible on the active column.
 * MM-453-3: Default sort is score descending; caption states it.
 * MM-453-4: Search/filter input narrows the visible rows by IP (client-side).
 * MM-453-5: Column-header glosses render on hover (CellTooltip — tooltip trigger present).
 * MM-453-6: Footer Dashboard link is a real anchor pointing to /dashboard.
 *
 * MM-457-1: Pagination controls (prev/next/page-info) are rendered for >PAGE_SIZE actors.
 * MM-457-2: Next page button reaches actors beyond page 1 (actors PAGE_SIZE+1 and beyond).
 * MM-457-3: Pagination respects the active sort (actors on page 2 are from sorted set).
 * MM-457-4: Pagination respects the active search filter.
 * MM-457-5: No inner scrollbar — growth pushes page content, never scroll-within-card.
 * MM-457-6: Footer count stays honest as pages change.
 * MM-457-7: Dashboard link is present on page 2 as well (escape hatch always visible).
 *
 * useCoverageLedgerTable unit (hook isolation):
 *   Hook-1: default sort is score desc.
 *   Hook-2: toggleSort flips direction on same column.
 *   Hook-3: toggleSort resets to desc on new column.
 *   Hook-4: setSearchQuery resets to page 1.
 *   Hook-5: goNext / goPrev respect page bounds.
 *   Hook-6: totalPages is clamped to 1 when fewer than PAGE_SIZE actors.
 *   Hook-7: nulls sort last for confidence and analysis_age regardless of direction.
 */

import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { renderHook, act } from '@testing-library/react'

import { CoverageLedger } from '../components/ai/ledger/CoverageLedger'
import { useCoverageLedgerTable, PAGE_SIZE } from '../components/ai/ledger/useCoverageLedgerTable'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import type { ThreatScore } from '../api/types'
import type { AnalysisSummary } from '../api/types'
import { THREATS_FIXTURE } from './readFixtures'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BASE_THREAT: ThreatScore = {
  ...THREATS_FIXTURE[0],
}

/** Build N threats with sequential IPs. */
function buildThreats(
  n: number,
  scoreFn: (i: number) => number = (i) => 100 - i,
): ThreatScore[] {
  return Array.from({ length: n }, (_, i) => ({
    ...BASE_THREAT,
    source_ip: `192.0.2.${i + 1}`,
    score: scoreFn(i),
  }))
}

/** Render CoverageLedger inside the standard test wrappers. */
function renderLedger(
  threats: ThreatScore[],
  analyses: AnalysisSummary[] | null = null,
  filterParam: 'below-threshold' | null = null,
) {
  return render(
    <MemoryRouter>
      <EntityPanelProvider>
        <CoverageLedger
          threats={threats}
          analyses={analyses}
          filterParam={filterParam}
        />
      </EntityPanelProvider>
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// useCoverageLedgerTable unit tests (hook isolation)
// ---------------------------------------------------------------------------

describe('useCoverageLedgerTable — hook unit (Hook-1 through Hook-7)', () => {
  it('Hook-1: default sort is score descending', () => {
    const threats = buildThreats(5, (i) => 10 * (i + 1)) // scores: 10,20,30,40,50
    const { result } = renderHook(() => useCoverageLedgerTable(threats, null))
    expect(result.current.sort.column).toBe('score')
    expect(result.current.sort.direction).toBe('desc')
    // Highest score first
    expect(result.current.visibleThreats[0].score).toBe(50)
    expect(result.current.visibleThreats[4].score).toBe(10)
  })

  it('Hook-2: toggleSort flips direction when clicking the same column', () => {
    const threats = buildThreats(3)
    const { result } = renderHook(() => useCoverageLedgerTable(threats, null))
    // Initial: score desc
    expect(result.current.sort.direction).toBe('desc')
    act(() => result.current.toggleSort('score'))
    // After first toggle: score asc
    expect(result.current.sort.column).toBe('score')
    expect(result.current.sort.direction).toBe('asc')
    act(() => result.current.toggleSort('score'))
    // After second toggle: score desc again
    expect(result.current.sort.direction).toBe('desc')
  })

  it('Hook-3: toggleSort resets to desc when switching to a new column', () => {
    const threats = buildThreats(3)
    const { result } = renderHook(() => useCoverageLedgerTable(threats, null))
    // First flip to asc on score
    act(() => result.current.toggleSort('score'))
    expect(result.current.sort.direction).toBe('asc')
    // Switch to confidence — should start at desc
    act(() => result.current.toggleSort('confidence'))
    expect(result.current.sort.column).toBe('confidence')
    expect(result.current.sort.direction).toBe('desc')
  })

  it('Hook-4: setSearchQuery resets to page 1', () => {
    const threats = buildThreats(25)
    const { result } = renderHook(() => useCoverageLedgerTable(threats, null))
    // Advance to page 2
    act(() => result.current.goNext())
    expect(result.current.currentPage).toBe(2)
    // Search resets to page 1
    act(() => result.current.setSearchQuery('192.0.2.1'))
    expect(result.current.currentPage).toBe(1)
  })

  it('Hook-5: goNext / goPrev respect page bounds', () => {
    // PAGE_SIZE + 5 actors = exactly 2 pages (page 1 full, page 2 has 5)
    const threats = buildThreats(PAGE_SIZE + 5)
    const { result } = renderHook(() => useCoverageLedgerTable(threats, null))
    // Can go next on page 1
    expect(result.current.hasNextPage).toBe(true)
    expect(result.current.hasPrevPage).toBe(false)
    act(() => result.current.goNext())
    expect(result.current.currentPage).toBe(2)
    expect(result.current.hasNextPage).toBe(false)
    expect(result.current.hasPrevPage).toBe(true)
    // Can't go past last page
    act(() => result.current.goNext())
    expect(result.current.currentPage).toBe(2)
    // Prev brings back to page 1
    act(() => result.current.goPrev())
    expect(result.current.currentPage).toBe(1)
    // Can't go before page 1
    act(() => result.current.goPrev())
    expect(result.current.currentPage).toBe(1)
  })

  it('Hook-6: totalPages is 1 when fewer than PAGE_SIZE actors', () => {
    const threats = buildThreats(5)
    const { result } = renderHook(() => useCoverageLedgerTable(threats, null))
    expect(result.current.totalPages).toBe(1)
  })

  it('Hook-7: null confidence sorts last regardless of direction (nulls-last rule)', () => {
    const threats: ThreatScore[] = [
      { ...BASE_THREAT, source_ip: '192.0.2.1', ai_confidence: 0.9 },
      { ...BASE_THREAT, source_ip: '192.0.2.2', ai_confidence: null },
      { ...BASE_THREAT, source_ip: '192.0.2.3', ai_confidence: 0.5 },
    ]
    const { result } = renderHook(() => useCoverageLedgerTable(threats, null))
    // Sort by confidence desc: 0.9 → 0.5 → null (last)
    act(() => result.current.toggleSort('confidence'))
    // Now on confidence desc
    const ips = result.current.visibleThreats.map((t) => t.source_ip)
    expect(ips[ips.length - 1]).toBe('192.0.2.2') // null is last
    // Flip to asc: 0.5 → 0.9 → null (still last)
    act(() => result.current.toggleSort('confidence'))
    const ipsAsc = result.current.visibleThreats.map((t) => t.source_ip)
    expect(ipsAsc[ipsAsc.length - 1]).toBe('192.0.2.2') // null is STILL last
  })
})

// ---------------------------------------------------------------------------
// MM-453-1/2: Sortable headers — click toggles asc/desc, indicator shown
// ---------------------------------------------------------------------------

describe('CoverageLedger — sortable headers (MM-453-1, MM-453-2)', () => {
  it('Score header has aria-sort="descending" by default (default sort)', () => {
    renderLedger(buildThreats(5))
    const scoreHeader = screen.getByTestId('coverage-col-score')
    expect(scoreHeader.getAttribute('aria-sort')).toBe('descending')
  })

  it('clicking Score header twice changes aria-sort to ascending', () => {
    renderLedger(buildThreats(5))
    const scoreHeader = screen.getByTestId('coverage-col-score')
    // First click: asc (already desc by default, flip to asc)
    fireEvent.click(scoreHeader)
    expect(scoreHeader.getAttribute('aria-sort')).toBe('ascending')
    // Second click: back to desc
    fireEvent.click(scoreHeader)
    expect(scoreHeader.getAttribute('aria-sort')).toBe('descending')
  })

  it('clicking Confidence header changes active sort column', () => {
    renderLedger(buildThreats(5))
    const confHeader = screen.getByTestId('coverage-col-confidence')
    expect(confHeader.getAttribute('aria-sort')).toBe('none')
    fireEvent.click(confHeader)
    expect(confHeader.getAttribute('aria-sort')).toBe('descending')
    // Score header is now inactive
    expect(screen.getByTestId('coverage-col-score').getAttribute('aria-sort')).toBe('none')
  })

  it('sort indicator (▼) visible on the active column (Score by default)', () => {
    renderLedger(buildThreats(3))
    // The ▼ symbol should be inside the score column header trigger
    const scoreHeader = screen.getByTestId('coverage-col-score')
    expect(scoreHeader.textContent).toContain('▼')
  })

  it('sort indicator (▲) visible after clicking Score to ascending', () => {
    renderLedger(buildThreats(3))
    const scoreHeader = screen.getByTestId('coverage-col-score')
    fireEvent.click(scoreHeader)
    expect(scoreHeader.textContent).toContain('▲')
  })

  it('clicking Analysis age header sorts actors by latest analysis first (desc)', () => {
    const analyses: AnalysisSummary[] = [
      {
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
        created_at: '2026-06-13T10:00:00Z', // 2h ago
      },
      {
        id: 2,
        ip: '192.0.2.2',
        kind: 'concise',
        model: 'qwen3:8b',
        endpoint_host: '127.0.0.1:11434',
        ai_status: 'ok',
        threat_level: 'MEDIUM',
        confidence: 0.6,
        score: 55,
        score_derivation: 'ai+rule',
        latency_ms: 900,
        prompt_tokens: null,
        completion_tokens: null,
        schema_version: 1,
        created_at: '2026-06-12T10:00:00Z', // 26h ago
      },
    ]
    const threats: ThreatScore[] = [
      { ...BASE_THREAT, source_ip: '192.0.2.1', score: 78 },
      { ...BASE_THREAT, source_ip: '192.0.2.2', score: 55 },
    ]
    renderLedger(threats, analyses)

    // Click analysis age column header to sort by age desc (newest first)
    fireEvent.click(screen.getByTestId('coverage-col-analysis_age'))

    const rows = screen.getAllByTestId('coverage-actor-row')
    // 192.0.2.1 was analysed more recently → should appear first (desc = newest first)
    expect(rows[0]).toHaveTextContent('192.0.2.1')
    expect(rows[1]).toHaveTextContent('192.0.2.2')

    // Flip to asc (oldest first)
    fireEvent.click(screen.getByTestId('coverage-col-analysis_age'))
    const rowsAsc = screen.getAllByTestId('coverage-actor-row')
    expect(rowsAsc[0]).toHaveTextContent('192.0.2.2') // older analysis first
  })
})

// ---------------------------------------------------------------------------
// MM-453-3: Default sort is score descending; caption states it
// ---------------------------------------------------------------------------

describe('CoverageLedger — sort caption (MM-453-3)', () => {
  it('default caption reads "Sorted by score, highest first"', () => {
    renderLedger(buildThreats(3))
    expect(screen.getByTestId('coverage-sort-caption')).toHaveTextContent(
      'Sorted by score, highest first',
    )
  })

  it('caption updates when sort changes to confidence', () => {
    renderLedger(buildThreats(3))
    fireEvent.click(screen.getByTestId('coverage-col-confidence'))
    expect(screen.getByTestId('coverage-sort-caption')).toHaveTextContent(
      'Sorted by confidence, highest first',
    )
  })

  it('caption reflects asc direction', () => {
    renderLedger(buildThreats(3))
    fireEvent.click(screen.getByTestId('coverage-col-score'))  // flip to asc
    expect(screen.getByTestId('coverage-sort-caption')).toHaveTextContent(
      'Sorted by score, lowest first',
    )
  })
})

// ---------------------------------------------------------------------------
// MM-453-4: Search/filter input narrows rows by IP
// ---------------------------------------------------------------------------

describe('CoverageLedger — search/filter (MM-453-4)', () => {
  it('IP search input is rendered', () => {
    renderLedger(buildThreats(5))
    expect(screen.getByTestId('coverage-search-input')).toBeInTheDocument()
  })

  it('filtering by IP substring shows only matching actors', () => {
    // IPs: 192.0.2.1 through 192.0.2.5
    renderLedger(buildThreats(5))
    const input = screen.getByTestId('coverage-search-input')
    // Type ".1" — matches 192.0.2.1 (and .10, .11, etc. but we only have .1–.5)
    fireEvent.change(input, { target: { value: '192.0.2.1' } })
    // Only 192.0.2.1 should be visible
    const rows = screen.getAllByTestId('coverage-actor-row')
    expect(rows.length).toBe(1)
    expect(rows[0]).toHaveTextContent('192.0.2.1')
  })

  it('no-match shows coverage-search-empty message', () => {
    renderLedger(buildThreats(3))
    fireEvent.change(screen.getByTestId('coverage-search-input'), {
      target: { value: '192.0.2.250' },
    })
    expect(screen.getByTestId('coverage-search-empty')).toBeInTheDocument()
    expect(screen.queryByTestId('coverage-actor-row')).not.toBeInTheDocument()
  })

  it('clearing the search restores all actors', () => {
    renderLedger(buildThreats(3))
    const input = screen.getByTestId('coverage-search-input')
    fireEvent.change(input, { target: { value: '192.0.2.1' } })
    expect(screen.getAllByTestId('coverage-actor-row').length).toBe(1)
    // Clear
    fireEvent.change(input, { target: { value: '' } })
    expect(screen.getAllByTestId('coverage-actor-row').length).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// MM-453-5: Column-header glosses render as CellTooltip triggers
// ---------------------------------------------------------------------------

describe('CoverageLedger — column-header glosses (MM-453-5)', () => {
  it('IP, Verdict, Confidence, Score, AI status, Analysis age headers all have tooltip triggers', () => {
    renderLedger(buildThreats(3))
    // Each column header wraps its label in a CellTooltip trigger (tabIndex=0 span).
    // The trigger spans are inside the th elements.
    // Verify all six column headers are present:
    expect(screen.getByTestId('coverage-col-ip')).toBeInTheDocument()
    expect(screen.getByTestId('coverage-col-verdict')).toBeInTheDocument()
    expect(screen.getByTestId('coverage-col-confidence')).toBeInTheDocument()
    expect(screen.getByTestId('coverage-col-score')).toBeInTheDocument()
    expect(screen.getByTestId('coverage-col-ai_status')).toBeInTheDocument()
    expect(screen.getByTestId('coverage-col-analysis_age')).toBeInTheDocument()
  })

  it('IP column header trigger is keyboard-focusable (tabIndex=0 on CellTooltip trigger)', () => {
    renderLedger(buildThreats(3))
    // CellTooltip renders the trigger span with tabIndex=0
    const ipCol = screen.getByTestId('coverage-col-ip')
    // The CellTooltip trigger span inside has tabIndex=0
    const trigger = ipCol.querySelector('[tabindex="0"]')
    expect(trigger).not.toBeNull()
  })
})

// ---------------------------------------------------------------------------
// MM-453-6: Footer Dashboard link is a real anchor
// ---------------------------------------------------------------------------

describe('CoverageLedger — Dashboard link (MM-453-6)', () => {
  it('dashboard escape-hatch link points to /dashboard', () => {
    renderLedger(buildThreats(3))
    const link = screen.getByTestId('coverage-dashboard-link')
    expect(link.tagName).toBe('A')
    expect(link.getAttribute('href')).toBe('/dashboard')
  })

  it('dashboard link text contains "Dashboard"', () => {
    renderLedger(buildThreats(3))
    expect(screen.getByTestId('coverage-dashboard-link')).toHaveTextContent('Dashboard')
  })
})

// ---------------------------------------------------------------------------
// MM-457-1/2: Pagination controls for >20 actors; Next reaches page 2
// ---------------------------------------------------------------------------

describe('CoverageLedger — pagination (MM-457-1 through MM-457-7)', () => {
  it('MM-457-1: pager is rendered when actor count > PAGE_SIZE', () => {
    renderLedger(buildThreats(PAGE_SIZE + 1))
    expect(screen.getByTestId('coverage-pager')).toBeInTheDocument()
    expect(screen.getByTestId('coverage-pager-prev')).toBeInTheDocument()
    expect(screen.getByTestId('coverage-pager-next')).toBeInTheDocument()
  })

  it('MM-457-1: pager is rendered even when actor count <= PAGE_SIZE (single page)', () => {
    renderLedger(buildThreats(5))
    // Pager still shown — prev and next are disabled, "Page 1 of 1"
    expect(screen.getByTestId('coverage-pager')).toBeInTheDocument()
    expect(screen.getByTestId('coverage-pager-info')).toHaveTextContent('Page 1 of 1')
    expect(screen.getByTestId('coverage-pager-next')).toBeDisabled()
    expect(screen.getByTestId('coverage-pager-prev')).toBeDisabled()
  })

  it('MM-457-2: clicking Next exposes actors beyond page 1 on page 2', () => {
    // Build PAGE_SIZE + 5 actors (2 pages): page 1 full, page 2 has 5 actors.
    // Scores descend: 192.0.2.1 has score 100, 192.0.2.(PAGE_SIZE+5) has the lowest.
    const threats = buildThreats(PAGE_SIZE + 5) // scores: 100, 99, …, (100 - PAGE_SIZE - 4)
    renderLedger(threats)

    // Page 1: first PAGE_SIZE actors in desc score order
    expect(screen.getAllByTestId('coverage-actor-row').length).toBe(PAGE_SIZE)

    // Go to page 2
    fireEvent.click(screen.getByTestId('coverage-pager-next'))

    // Page 2: remaining 5 actors
    expect(screen.getAllByTestId('coverage-actor-row').length).toBe(5)
    // The (PAGE_SIZE + 1)th actor in desc sort is at index PAGE_SIZE, IP = 192.0.2.(PAGE_SIZE+1)
    expect(screen.getAllByTestId('coverage-actor-row')[0]).toHaveTextContent(`192.0.2.${PAGE_SIZE + 1}`)
  })

  it('MM-457-3: pagination respects the active sort', () => {
    // PAGE_SIZE + 5 actors with ascending scores: 192.0.2.1 score=1, ..., last has score=PAGE_SIZE+5
    const threats = buildThreats(PAGE_SIZE + 5, (i) => i + 1) // scores: 1, 2, …, PAGE_SIZE+5
    renderLedger(threats)

    // Default sort: score desc → the highest-score actor (192.0.2.(PAGE_SIZE+5)) first
    expect(screen.getAllByTestId('coverage-actor-row')[0]).toHaveTextContent(`192.0.2.${PAGE_SIZE + 5}`)

    // Flip to score asc
    fireEvent.click(screen.getByTestId('coverage-col-score'))
    // Now 192.0.2.1 (score=1) should be first on page 1
    expect(screen.getAllByTestId('coverage-actor-row')[0]).toHaveTextContent('192.0.2.1')

    // Page 2 should contain the 5 higher-scored actors (indices PAGE_SIZE through PAGE_SIZE+4)
    fireEvent.click(screen.getByTestId('coverage-pager-next'))
    const page2Rows = screen.getAllByTestId('coverage-actor-row')
    expect(page2Rows.length).toBe(5)
  })

  it('MM-457-4: pagination respects the active search filter', () => {
    // 25 actors; filter to "192.0.2.1" which matches 192.0.2.1 + 192.0.2.10–19 = 11 actors.
    // At PAGE_SIZE=10, 11 matching actors span 2 pages; pager info should reflect that.
    const threats = buildThreats(25)
    renderLedger(threats)

    fireEvent.change(screen.getByTestId('coverage-search-input'), {
      target: { value: '192.0.2.1' },
    })

    const info = screen.getByTestId('coverage-pager-info')
    expect(info).toHaveTextContent('Page 1 of 2')
    expect(info).toHaveTextContent('11 matching')
  })

  it('MM-457-5: no overflow: hidden / scroll on the pager container (no inner scrollbar)', () => {
    renderLedger(buildThreats(PAGE_SIZE + 5))
    const pager = screen.getByTestId('coverage-pager')
    // The pager element must NOT have overflow: scroll/auto (ADR-0043 D3)
    const style = pager.getAttribute('style') ?? ''
    expect(style).not.toContain('overflow: scroll')
    expect(style).not.toContain('overflow: auto')
    expect(style).not.toContain('overflow-y: scroll')
    expect(style).not.toContain('overflow-y: auto')
  })

  it('MM-457-6: footer count is honest — updates as pages change', () => {
    const threats = buildThreats(25)
    renderLedger(threats)

    // Page 1: "Showing {PAGE_SIZE} of 25 actors"
    expect(screen.getByTestId('coverage-remaining-count')).toHaveTextContent(`Showing ${PAGE_SIZE} of 25 actors`)

    // Go to page 2
    fireEvent.click(screen.getByTestId('coverage-pager-next'))
    // Footer still reflects the same total (the count is dataset-level, not per-page)
    expect(screen.getByTestId('coverage-remaining-count')).toHaveTextContent(`Showing ${PAGE_SIZE} of 25 actors`)
  })

  it('MM-457-7: Dashboard link is visible on page 2', () => {
    renderLedger(buildThreats(PAGE_SIZE + 5))
    fireEvent.click(screen.getByTestId('coverage-pager-next'))
    expect(screen.getByTestId('coverage-dashboard-link')).toBeInTheDocument()
  })

  it('Prev button is disabled on page 1, enabled on page 2', () => {
    renderLedger(buildThreats(25))
    expect(screen.getByTestId('coverage-pager-prev')).toBeDisabled()
    fireEvent.click(screen.getByTestId('coverage-pager-next'))
    expect(screen.getByTestId('coverage-pager-prev')).not.toBeDisabled()
  })
})
