/**
 * useVerdictLedger — fetch hook for GET /ai/analyses (ADR-0044 / MK-3).
 *
 * Fetches the first page of AI analysis summary records from the ledger.
 * Cursor-aware: exposes ``nextCursor`` so callers can implement "view all" pagination.
 *
 * MM #456 additive: exposes ``loadMore`` to fetch additional server pages when
 * ``has_more`` is true (cursor pagination — never offset math). Items are appended
 * to the existing set; the component stays honest about the ceiling.
 *
 * States:
 *   - 'loading'        — initial fetch in-flight.
 *   - 'ok'             — data loaded (may be empty list — honest empty state).
 *   - 'empty'          — 503 (ledger not wired yet) or API returned zero items.
 *   - 'error'          — non-503 fetch failure.
 *   - 'loadingMore'    — cursor fetch in-flight; existing items remain visible.
 *
 * No LLM call is triggered — this hook is read-only (ai-engine-invariants boundary).
 * SECURITY (ADR-0029 D3): all string fields in AnalysisSummary are attacker-influenced
 * or model-authored. Callers must render them as text nodes only.
 */

import { useEffect, useReducer, useCallback } from 'react'
import { fetchAnalyses } from '../../../api/client'
import { ApiError } from '../../../api/client'
import type { AnalysisSummary } from '../../../api/types'

// ---------------------------------------------------------------------------
// State shape + reducer
// ---------------------------------------------------------------------------

export type VerdictLedgerStatus = 'loading' | 'ok' | 'empty' | 'error' | 'loadingMore'

export interface VerdictLedgerState {
  status: VerdictLedgerStatus
  analyses: AnalysisSummary[]
  nextCursor: string | null
  hasMore: boolean
  /** Human-readable error when status === 'error'. */
  error: string | null
}

type Action =
  | { type: 'RESET' }
  | { type: 'OK'; items: AnalysisSummary[]; nextCursor: string | null; hasMore: boolean }
  | { type: 'EMPTY' }
  | { type: 'ERROR'; error: string }
  /** MM #456: cursor-fetch in-flight; existing items remain visible. */
  | { type: 'LOADING_MORE' }
  /** MM #456: append additional cursor-fetched items to the existing set. */
  | { type: 'APPEND'; items: AnalysisSummary[]; nextCursor: string | null; hasMore: boolean }

const LOADING_STATE: VerdictLedgerState = {
  status: 'loading',
  analyses: [],
  nextCursor: null,
  hasMore: false,
  error: null,
}

function reducer(state: VerdictLedgerState, action: Action): VerdictLedgerState {
  switch (action.type) {
    case 'RESET':
      return LOADING_STATE
    case 'OK':
      return {
        status: action.items.length > 0 ? 'ok' : 'empty',
        analyses: action.items,
        nextCursor: action.nextCursor,
        hasMore: action.hasMore,
        error: null,
      }
    case 'EMPTY':
      return { ...LOADING_STATE, status: 'empty' }
    case 'ERROR':
      return { status: 'error', analyses: [], nextCursor: null, hasMore: false, error: action.error }
    case 'LOADING_MORE':
      return { ...state, status: 'loadingMore' }
    case 'APPEND':
      return {
        status: 'ok',
        analyses: [...state.analyses, ...action.items],
        nextCursor: action.nextCursor,
        hasMore: action.hasMore,
        error: null,
      }
    default:
      return state
  }
}

// ---------------------------------------------------------------------------
// Hook return type
// ---------------------------------------------------------------------------

export interface VerdictLedgerResult extends VerdictLedgerState {
  /**
   * MM #456: fetch the next server page and append items.
   * No-op when hasMore=false or a fetch is already in-flight.
   */
  loadMore: () => void
}

// ---------------------------------------------------------------------------
// Hook options
// ---------------------------------------------------------------------------

export interface UseVerdictLedgerOptions {
  /** Filter to analyses for this IP only (passed as ?ip= query param). */
  ip?: string
  /** Page size (1–200; defaults to 20 for top-N display). */
  limit?: number
  /**
   * MK-11: bump to force a re-fetch after a Re-run analysis completes.
   * When this value changes the effect re-runs, re-fetching the ledger.
   * Pattern mirrors feedbackVersion in AIRoute (D2 reactivity).
   */
  refreshKey?: number
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Fetch the first page of verdict summaries from the AI analyses ledger.
 *
 * Re-fetches when ip, limit, or refreshKey change.
 * Returns honest states — no spinner-forever, no fabricated counts.
 *
 * MM #456: exposes loadMore() to append next server page via cursor.
 */
export function useVerdictLedger(options?: UseVerdictLedgerOptions): VerdictLedgerResult {
  const { ip, limit = 20, refreshKey = 0 } = options ?? {}
  const [state, dispatch] = useReducer(reducer, LOADING_STATE)

  useEffect(() => {
    dispatch({ type: 'RESET' })
    let cancelled = false

    fetchAnalyses({ ip, limit })
      .then((page) => {
        if (cancelled) return
        if (page === null) {
          // 503 — ledger not wired yet (pre-MK-2 or service starting up)
          dispatch({ type: 'EMPTY' })
        } else {
          dispatch({ type: 'OK', items: page.items, nextCursor: page.next_cursor, hasMore: page.has_more })
        }
      })
      .catch((err: unknown) => {
        if (cancelled) return
        const msg =
          err instanceof ApiError
            ? `AI verdicts unavailable (${err.status})`
            : 'Failed to load AI verdicts'
        dispatch({ type: 'ERROR', error: msg })
      })

    return () => {
      cancelled = true
    }
  }, [ip, limit, refreshKey])

  /**
   * MM #456: fetch next server page by echoing nextCursor back to the API.
   * Appends to the existing analyses set — cursor echo, never offset math.
   * Guard: no-op when hasMore=false, no cursor, or a fetch is in-flight.
   */
  const loadMore = useCallback(() => {
    if (!state.hasMore || !state.nextCursor) return
    if (state.status === 'loading' || state.status === 'loadingMore') return

    dispatch({ type: 'LOADING_MORE' })

    fetchAnalyses({ ip, limit, cursor: state.nextCursor })
      .then((page) => {
        if (page === null) {
          // 503 after initial load — retain existing items, mark no-more
          dispatch({ type: 'APPEND', items: [], nextCursor: null, hasMore: false })
        } else {
          dispatch({ type: 'APPEND', items: page.items, nextCursor: page.next_cursor, hasMore: page.has_more })
        }
      })
      .catch(() => {
        // On cursor fetch error: revert loadingMore → ok so the UI stays usable.
        // Don't overwrite the existing set — just drop the status back to ok.
        dispatch({ type: 'OK', items: state.analyses, nextCursor: state.nextCursor, hasMore: state.hasMore })
      })
  }, [state.hasMore, state.nextCursor, state.status, state.analyses, ip, limit])

  return { ...state, loadMore }
}
