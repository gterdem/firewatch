/**
 * useAnalysisDetail — fetch GET /ai/analyses/{id} with per-id caching.
 *
 * Fetches the full analysis record (prompt_text, response_text, validated_json,
 * model, latency_ms, token counts, truncation flags) on first call for a given
 * id; subsequent calls with the same id return the cached result without
 * re-fetching (fetch-on-expand semantics).
 *
 * States:
 *   idle     — not yet requested (trigger has not fired).
 *   loading  — fetch in-flight.
 *   ok       — data loaded successfully.
 *   error    — fetch failed or server returned null (404 / 503 degrade).
 *
 * SECURITY: this hook only fetches and caches — it does NOT render. Callers are
 * responsible for rendering prompt_text and response_text as text nodes only
 * (ADR-0029 D3 / OWASP LLM05 — attacker-controlled strings; never innerHTML).
 *
 * Cache is module-level (Map<id, AnalysisDetail>) — persists across
 * component remounts within the same page session. This is intentional: the
 * stored analysis record is immutable (write-once-at-analysis-time) so a
 * module-level cache is safe and avoids redundant fetches when a drawer is
 * opened, closed, and reopened.
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import { fetchAnalysisDetail } from '../../../api/client'
import { ApiError } from '../../../api/client'
import type { AnalysisDetail } from '../../../api/types'

// ---------------------------------------------------------------------------
// Module-level cache — immutable records, safe to cache indefinitely.
// ---------------------------------------------------------------------------

const detailCache = new Map<number, AnalysisDetail>()

/**
 * Clear the module-level detail cache.
 * Exported for use in tests — do NOT call in production code.
 * (The cache is intentionally persistent across component remounts in production.)
 */
export function clearDetailCache(): void {
  detailCache.clear()
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AnalysisDetailStatus = 'idle' | 'loading' | 'ok' | 'error'

export interface AnalysisDetailState {
  status: AnalysisDetailStatus
  detail: AnalysisDetail | null
  /** Human-readable error message when status === 'error'; null otherwise. */
  error: string | null
}

export interface UseAnalysisDetailResult extends AnalysisDetailState {
  /**
   * Trigger the fetch for this analysis id.
   * Idempotent: calling again while loading or after ok is a no-op.
   * Safe to call on every render — the hook guards against duplicate fetches.
   */
  fetch: () => void
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Fetch and cache the full analysis detail record for one analysis id.
 *
 * @param id  The numeric analysis record id (from AnalysisSummary.id).
 */
export function useAnalysisDetail(id: number): UseAnalysisDetailResult {
  const [state, setState] = useState<AnalysisDetailState>(() => {
    // Hydrate from cache if available (e.g. re-mount after close → re-open).
    const cached = detailCache.get(id)
    if (cached !== undefined) {
      return { status: 'ok', detail: cached, error: null }
    }
    return { status: 'idle', detail: null, error: null }
  })

  // fetchRequested: set to true by the triggerFetch callback.
  // Using a ref alongside state avoids an extra render cycle while still
  // providing the reactive trigger the effect needs.
  const fetchRequestedRef = useRef(false)
  const [fetchTick, setFetchTick] = useState(0)

  useEffect(() => {
    // Only proceed when a fetch has been explicitly requested.
    if (!fetchRequestedRef.current) return

    // Guard: skip if already loading or ok.
    if (state.status === 'loading' || state.status === 'ok') return

    let cancelled = false

    // Kick off the async fetch; state transitions happen inside the callbacks
    // (not synchronously in the effect body) to satisfy the react-hooks/set-state-in-effect
    // lint rule and avoid cascading renders.
    ;(async () => {
      // Check module-level cache first — may have been populated by a sibling
      // instance since this component mounted.
      const cached = detailCache.get(id)
      if (cached !== undefined) {
        if (!cancelled) setState({ status: 'ok', detail: cached, error: null })
        return
      }

      if (!cancelled) setState({ status: 'loading', detail: null, error: null })

      try {
        const data = await fetchAnalysisDetail(id)
        if (cancelled) return

        if (data === null) {
          // 404 or 503 — honest degrade.
          setState({
            status: 'error',
            detail: null,
            error: "couldn't load the stored analysis",
          })
        } else {
          detailCache.set(id, data)
          setState({ status: 'ok', detail: data, error: null })
        }
      } catch (err: unknown) {
        if (cancelled) return
        const msg =
          err instanceof ApiError
            ? `couldn't load the stored analysis (${err.status})`
            : "couldn't load the stored analysis"
        setState({ status: 'error', detail: null, error: msg })
      }
    })()

    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fetchTick, id])

  const triggerFetch = useCallback(() => {
    fetchRequestedRef.current = true
    // Bump the tick to trigger the effect even if fetchRequested was already true.
    setFetchTick((t) => t + 1)
  }, [])

  return { ...state, fetch: triggerFetch }
}
