/**
 * useFeedback — POST/upsert feedback + summary fetch (MK-6, ADR-0045).
 *
 * Two exported hooks:
 *
 *   useFeedbackSubmit(analysisId, onSuccess?)
 *     POST /ai/analyses/{id}/feedback — optimistic UI with server reconciliation.
 *     Re-clicking upserts: latest wins (ADR-0045 D1 unique-constraint upsert).
 *     onSuccess is called after server confirms (not on optimistic phase / error).
 *
 *   useFeedbackSummary(refreshKey?)
 *     GET /ai/feedback/summary — fetches {graded, agreed, agreement_pct}.
 *     Returns null on 503 (ledger not wired); honest degrade, no fabricated counts.
 *     refreshKey: incrementing it re-runs the fetch (D2 reactivity — AgreementStat
 *     re-fetches after each successful submit without a full page reload).
 *
 * Constraints:
 * - Never logs reason values (operator text, potentially sensitive — ADR-0029 D3).
 * - No spinner-forever: errors surface as error strings, not infinite loading states.
 * - No fabricated counts: only data from the server is surfaced.
 */

import { useState, useEffect, useCallback } from 'react'
import { postFeedback, fetchFeedbackSummary } from '../../../api/client'
import { ApiError } from '../../../api/client'
import type { FeedbackVerdict, FeedbackRow, FeedbackSummary } from '../../../api/types'

// ---------------------------------------------------------------------------
// useFeedbackSubmit
// ---------------------------------------------------------------------------

/** Maximum reason length mirrored client-side from the server cap (ADR-0045 D1). */
export const REASON_MAX_CHARS = 1_000

export type FeedbackSubmitStatus = 'idle' | 'submitting' | 'ok' | 'error'

export interface FeedbackSubmitState {
  /** Current submit lifecycle state. */
  status: FeedbackSubmitStatus
  /** Stored feedback row from the server (null until first successful submit). */
  stored: FeedbackRow | null
  /** Human-readable error when status === 'error'; null otherwise. */
  error: string | null
}

export interface UseFeedbackSubmitResult extends FeedbackSubmitState {
  /**
   * Submit (or re-submit) feedback for this analysis.
   * Re-submitting upserts — latest wins (ADR-0045 D1).
   * ``reason`` is trimmed and capped at REASON_MAX_CHARS before sending.
   */
  submit: (verdict: FeedbackVerdict, reason?: string) => Promise<void>
}

/**
 * Hook for submitting analyst feedback on one analysis record.
 *
 * Optimistic UI: the UI updates immediately on submit, then reconciles to
 * the server response (or rolls back on error) per the issue constraint.
 *
 * State starts as 'idle' (ungraded) and transitions to 'ok' once the server
 * responds with the stored FeedbackRow. The full FeedbackRow (id, reason,
 * created_at) is only available from the POST response — not from the list-row
 * additive field which has a narrower shape.
 *
 * @param onSuccess Called after the server confirms (reconciliation — not during
 *   the optimistic phase and not on error). Used to trigger a re-fetch of the
 *   agreement summary stat (D2 reactivity fix).
 */
export function useFeedbackSubmit(
  analysisId: number,
  onSuccess?: () => void,
): UseFeedbackSubmitResult {
  const [state, setState] = useState<FeedbackSubmitState>({
    status: 'idle',
    stored: null,
    error: null,
  })

  const submit = useCallback(
    async (verdict: FeedbackVerdict, reason?: string) => {
      const trimmedReason = reason?.trim()
      const cappedReason =
        trimmedReason && trimmedReason.length > 0
          ? trimmedReason.slice(0, REASON_MAX_CHARS)
          : undefined

      // Optimistic update: reflect the verdict immediately.
      // The stored row is fabricated with a temp timestamp until the server responds.
      const optimisticRow: FeedbackRow = {
        id: -1, // temp sentinel — replaced by the server id on reconciliation
        analysis_id: analysisId,
        verdict,
        reason: cappedReason ?? null,
        created_at: new Date().toISOString(),
      }
      setState({ status: 'submitting', stored: optimisticRow, error: null })

      try {
        const serverRow = await postFeedback(analysisId, {
          verdict,
          ...(cappedReason !== undefined ? { reason: cappedReason } : {}),
        })
        // Reconcile to the server row (canonical id + created_at from DB).
        setState({ status: 'ok', stored: serverRow, error: null })
        // Notify parent only after server confirms — not on optimistic phase or error.
        // This allows AgreementStat to re-fetch the summary which is computed server-side.
        onSuccess?.()
      } catch (err: unknown) {
        // Roll back: clear the optimistic row; surface the error.
        const msg =
          err instanceof ApiError
            ? `Feedback save failed (${err.status})`
            : 'Feedback could not be saved'
        setState({ status: 'error', stored: null, error: msg })
      }
    },
    [analysisId, onSuccess],
  )

  return { ...state, submit }
}

// ---------------------------------------------------------------------------
// useFeedbackSummary
// ---------------------------------------------------------------------------

export type FeedbackSummaryStatus = 'loading' | 'ok' | 'empty' | 'error'

export interface FeedbackSummaryState {
  status: FeedbackSummaryStatus
  summary: FeedbackSummary | null
  error: string | null
}

/**
 * Hook for fetching the agreement rollup from GET /ai/feedback/summary.
 *
 * States:
 *   loading — initial fetch in-flight.
 *   ok      — data loaded (graded may be 0 — honest empty denominator).
 *   empty   — 503 (ledger not wired); degrade gracefully.
 *   error   — non-503 fetch failure.
 *
 * No fabricated counts are returned at any state.
 *
 * @param refreshKey Incrementing this value re-runs the fetch (D2 reactivity).
 *   AgreementStat passes feedbackVersion from AIRoute so the stat updates
 *   automatically after each successful submit — no full page reload needed.
 *   The cancelled cleanup guard prevents setState after unmount / stale resolves.
 */
export function useFeedbackSummary(refreshKey: number = 0): FeedbackSummaryState {
  const [state, setState] = useState<FeedbackSummaryState>({
    status: 'loading',
    summary: null,
    error: null,
  })

  useEffect(() => {
    let cancelled = false

    fetchFeedbackSummary()
      .then((data) => {
        if (cancelled) return
        if (data === null) {
          // 503 — ledger not wired; show nothing rather than a broken state.
          setState({ status: 'empty', summary: null, error: null })
        } else {
          setState({ status: 'ok', summary: data, error: null })
        }
      })
      .catch((err: unknown) => {
        if (cancelled) return
        const msg =
          err instanceof ApiError
            ? `Agreement stat unavailable (${err.status})`
            : 'Agreement stat could not be loaded'
        setState({ status: 'error', summary: null, error: msg })
      })

    return () => {
      cancelled = true
    }
  }, [refreshKey])

  return state
}
