/**
 * useVerdictFilters — client-side filter + page-state for VerdictCardList (MM #456).
 *
 * Manages:
 *   - active filter chip: 'all' | 'ungraded' | 'disagreed' | 'ai-moved'
 *   - current page index (0-based) within the filtered set
 *   - page size (fixed at PAGE_SIZE = 10)
 *
 * Filter semantics (derived entirely from AnalysisSummary fields — no server call):
 *   'all'        — every loaded analysis (no filter)
 *   'ungraded'   — analyses where feedback is null/absent
 *   'disagreed'  — analyses where feedback.verdict === 'disagree'
 *   'ai-moved'   — analyses where score_derivation includes 'ai' (boost fired)
 *
 * Pager: prev/next over the filtered subset; resets to page 0 on filter change.
 * No inner scrollbar (ADR-0043 D3) — growth via paging only.
 *
 * Security: no attacker-controlled strings enter the filter logic; all comparisons
 * are on server-validated enum fields.
 */

import { useState, useMemo, useCallback } from 'react'
import type { AnalysisSummary } from '../../../api/types'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Cards shown per page — mirrors legacy TOP_N; keeps each page scannable. */
export const PAGE_SIZE = 10

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** The active workflow filter chip value. */
export type VerdictFilter = 'all' | 'ungraded' | 'disagreed' | 'ai-moved'

export interface UseVerdictFiltersResult {
  /** Currently active filter. */
  activeFilter: VerdictFilter
  /** Set the active filter and reset to page 0. */
  setFilter: (f: VerdictFilter) => void

  /** Cards on the current page (already filtered + sliced). */
  pageItems: AnalysisSummary[]
  /** Total cards that match the active filter. */
  filteredTotal: number
  /** Total number of pages in the filtered set. */
  pageCount: number
  /** 0-based index of the current page. */
  currentPage: number
  /** Go to previous page (no-op on page 0). */
  prevPage: () => void
  /** Go to next page (no-op on last page). */
  nextPage: () => void

  /** Count of analyses matching each filter chip — for badge display. */
  filterCounts: Record<VerdictFilter, number>
}

// ---------------------------------------------------------------------------
// Filter predicate helpers
// ---------------------------------------------------------------------------

function isUngraded(a: AnalysisSummary): boolean {
  return a.feedback == null
}

function isDisagreed(a: AnalysisSummary): boolean {
  return a.feedback?.verdict === 'disagree'
}

function isAiMoved(a: AnalysisSummary): boolean {
  const d = a.score_derivation
  return d === 'ai' || d === 'ai+rule'
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Client-side filter + pagination over a loaded set of AnalysisSummary rows.
 *
 * @param analyses — the full loaded set (up to 200 from useVerdictLedger)
 */
export function useVerdictFilters(analyses: AnalysisSummary[]): UseVerdictFiltersResult {
  const [activeFilter, setActiveFilterRaw] = useState<VerdictFilter>('all')
  const [currentPage, setCurrentPage] = useState(0)

  // Pre-compute counts for all filter badges from the full set.
  const filterCounts = useMemo<Record<VerdictFilter, number>>(
    () => ({
      all: analyses.length,
      ungraded: analyses.filter(isUngraded).length,
      disagreed: analyses.filter(isDisagreed).length,
      'ai-moved': analyses.filter(isAiMoved).length,
    }),
    [analyses],
  )

  // Apply the active filter predicate.
  const filtered = useMemo(() => {
    switch (activeFilter) {
      case 'ungraded':
        return analyses.filter(isUngraded)
      case 'disagreed':
        return analyses.filter(isDisagreed)
      case 'ai-moved':
        return analyses.filter(isAiMoved)
      default:
        return analyses
    }
  }, [analyses, activeFilter])

  const filteredTotal = filtered.length
  const pageCount = Math.max(1, Math.ceil(filteredTotal / PAGE_SIZE))

  // Clamp currentPage when filter change shrinks the set.
  const safePage = Math.min(currentPage, pageCount - 1)

  const pageItems = useMemo(
    () => filtered.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE),
    [filtered, safePage],
  )

  const setFilter = useCallback((f: VerdictFilter) => {
    setActiveFilterRaw(f)
    setCurrentPage(0) // reset to first page on filter change
  }, [])

  const prevPage = useCallback(() => {
    setCurrentPage((p) => Math.max(0, p - 1))
  }, [])

  const nextPage = useCallback(() => {
    setCurrentPage((p) => Math.min(pageCount - 1, p + 1))
  }, [pageCount])

  return {
    activeFilter,
    setFilter,
    pageItems,
    filteredTotal,
    pageCount,
    currentPage: safePage,
    prevPage,
    nextPage,
    filterCounts,
  }
}
