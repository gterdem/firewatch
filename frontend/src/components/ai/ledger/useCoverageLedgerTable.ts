/**
 * useCoverageLedgerTable — sort + search + pagination state for CoverageLedger (MM #453 #457).
 *
 * Encapsulates all table-state logic so CoverageLedger stays under ~250 lines.
 * All operations are client-side over the already-loaded threats array; no
 * server-side sort/filter params are needed at this scale.
 *
 * Sort columns: score (default desc), confidence, analysis_age.
 * Search: IP prefix/substring filter (case-insensitive).
 * Pagination: page-at-a-time over the sorted+filtered set; no inner scrollbar.
 *
 * Confidence sort: actors with no ledger entry (null confidence) sort last in
 * ascending mode and first in descending mode (null = "not applicable").
 *
 * Analysis age sort: actors with no ledger record (null age) sort last always
 * (no analysis = oldest possible, pushed to the end regardless of direction).
 */

import { useState, useMemo } from 'react'
import type { ThreatScore } from '../../../api/types'
import type { AnalysisSummary } from '../../../api/types'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** The columns the user can sort by. */
export type SortColumn = 'score' | 'confidence' | 'analysis_age'

/** Sort direction. */
export type SortDirection = 'asc' | 'desc'

export interface SortState {
  column: SortColumn
  direction: SortDirection
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Actors shown per page (no inner scrollbar constraint). */
export const PAGE_SIZE = 10

/** Default sort: score descending — "top threat actors first" (most meaningful). */
export const DEFAULT_SORT: SortState = { column: 'score', direction: 'desc' }

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export interface UseCoverageLedgerTableResult {
  /** The actors visible on the current page (already sorted + filtered). */
  visibleThreats: ThreatScore[]
  /** Current page (1-based). */
  currentPage: number
  /** Total pages over the sorted+filtered set. */
  totalPages: number
  /** Total actor count after filtering (before paging). */
  filteredCount: number
  /** Whether there are more pages. */
  hasNextPage: boolean
  /** Whether we can go back. */
  hasPrevPage: boolean
  /** Navigate to the next page. */
  goNext: () => void
  /** Navigate to the previous page. */
  goPrev: () => void
  /** Navigate to a specific page (1-based). */
  goToPage: (page: number) => void
  /** Current IP search string. */
  searchQuery: string
  /** Update the IP search string (resets to page 1). */
  setSearchQuery: (q: string) => void
  /** Current sort state. */
  sort: SortState
  /** Toggle sort: clicking the same column flips direction; a new column sets desc first. */
  toggleSort: (column: SortColumn) => void
}

/**
 * Build a lookup map from IP → most-recent AnalysisSummary for O(1) access.
 */
function buildAnalysisMap(analyses: AnalysisSummary[] | null): Map<string, AnalysisSummary> {
  const map = new Map<string, AnalysisSummary>()
  if (!analyses) return map
  // Analyses arrive newest-first from the API; take the first occurrence per IP.
  for (const a of analyses) {
    if (!map.has(a.ip)) {
      map.set(a.ip, a)
    }
  }
  return map
}

/**
 * Compare nulls last: null values always sort after non-null values regardless
 * of direction. This prevents null from "winning" in ascending mode.
 */
function compareNullsLast(
  a: number | null,
  b: number | null,
  direction: SortDirection,
): number {
  if (a === null && b === null) return 0
  if (a === null) return 1   // null always last
  if (b === null) return -1  // null always last
  return direction === 'desc' ? b - a : a - b
}

export function useCoverageLedgerTable(
  threats: ThreatScore[],
  analyses: AnalysisSummary[] | null,
): UseCoverageLedgerTableResult {
  const [sort, setSort] = useState<SortState>(DEFAULT_SORT)
  const [searchQuery, setSearchQueryRaw] = useState('')
  const [currentPage, setCurrentPage] = useState(1)

  // Build analysis map once per analyses reference change.
  const analysisMap = useMemo(() => buildAnalysisMap(analyses), [analyses])

  // 1. Filter by IP search query.
  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return threats
    return threats.filter((t) => t.source_ip.toLowerCase().includes(q))
  }, [threats, searchQuery])

  // 2. Sort the filtered set.
  const sorted = useMemo(() => {
    const arr = [...filtered]
    arr.sort((a, b) => {
      switch (sort.column) {
        case 'score': {
          return sort.direction === 'desc'
            ? b.score - a.score
            : a.score - b.score
        }
        case 'confidence': {
          // Prefer ledger confidence; fall back to threat ai_confidence.
          const ca = analysisMap.get(a.source_ip)?.confidence ?? a.ai_confidence ?? null
          const cb = analysisMap.get(b.source_ip)?.confidence ?? b.ai_confidence ?? null
          return compareNullsLast(ca, cb, sort.direction)
        }
        case 'analysis_age': {
          // Sort by created_at timestamp (ms); no ledger = null → nulls last.
          const ta = analysisMap.get(a.source_ip)?.created_at
          const tb = analysisMap.get(b.source_ip)?.created_at
          const ma = ta ? Date.parse(ta) : null
          const mb = tb ? Date.parse(tb) : null
          // For analysis age, "newest first" = desc (most recently analysed top).
          return compareNullsLast(ma, mb, sort.direction)
        }
      }
    })
    return arr
  }, [filtered, sort, analysisMap])

  // 3. Pagination over the sorted+filtered set.
  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE))

  // Clamp currentPage when filter narrows the set.
  const safePage = Math.min(currentPage, totalPages)

  const startIdx = (safePage - 1) * PAGE_SIZE
  const visibleThreats = sorted.slice(startIdx, startIdx + PAGE_SIZE)

  const hasNextPage = safePage < totalPages
  const hasPrevPage = safePage > 1

  function goNext() {
    setCurrentPage((p) => Math.min(p + 1, totalPages))
  }
  function goPrev() {
    setCurrentPage((p) => Math.max(p - 1, 1))
  }
  function goToPage(page: number) {
    setCurrentPage(Math.max(1, Math.min(page, totalPages)))
  }

  function toggleSort(column: SortColumn) {
    setSort((prev) => {
      if (prev.column === column) {
        // Same column → flip direction.
        return { column, direction: prev.direction === 'desc' ? 'asc' : 'desc' }
      }
      // New column → start descending (most extreme values first).
      return { column, direction: 'desc' }
    })
    // Reset to page 1 on sort change.
    setCurrentPage(1)
  }

  function setSearchQuery(q: string) {
    setSearchQueryRaw(q)
    setCurrentPage(1)
  }

  return {
    visibleThreats,
    currentPage: safePage,
    totalPages,
    filteredCount: sorted.length,
    hasNextPage,
    hasPrevPage,
    goNext,
    goPrev,
    goToPage,
    searchQuery,
    setSearchQuery,
    sort,
    toggleSort,
  }
}
