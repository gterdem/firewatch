/**
 * useDeepAnalysis — health-gated deep AI analysis hook for the IP entity panel (issue #268).
 *
 * Owns the AI call lifecycle:
 *   1. Consults the session analysis cache (issue #269 / #310) — cache hit → phase='complete'
 *      immediately with fromCache=true, no LLM call issued.
 *   2. On cache miss, consults GET /health — if AI offline, stays idle (parent renders
 *      "AI offline" badge).
 *   3. When AI is healthy, enters phase='analyzing' in STREAM-DRIVEN mode: the SSE stream
 *      (useStageTicker → GET /threats/{ip}/detailed/stream) is the PRIMARY analysis trigger.
 *      useDeepAnalysis does NOT fire the non-streaming fetch concurrently, preventing the
 *      self-inflicted 409 that hid the stage ticker on first open (fix: MK-11 / issue #416).
 *   4. The stream's terminal `result` event delivers the analysis payload via
 *      `receiveStreamResult` (called by DeepAnalysisControl → IpPanel).
 *   5. On stream error (genuine non-conflict failure), `triggerStreamFallback` fires
 *      the non-streaming GET /threats/{ip}/detailed so the analysis still completes.
 *   6. On successful completion, writes result to the session cache.
 *   7. Owns the client-side elapsed timer so the panel can show "analyzing (Ns)".
 *   8. On failure / timeout: never claims "complete" — exposes `failed` state.
 *   9. Retry/Re-run: calling `runDeepAnalysis()` invalidates the cache entry for this IP,
 *      re-checks health, then enters stream-driven mode again.
 *
 * Stream-driven path (the primary path, issue #416):
 *   - `startStreamDrivenAnalysis()`: sets phase='analyzing' + timer; does NOT call
 *     fetchDetailedAnalysis. useStageTicker (mounted in DeepAnalysisControl) opens the SSE
 *     stream and delivers stage events + terminal result.
 *   - `receiveStreamResult(payload)`: called when stream's terminal `result` SSE event arrives.
 *     Stops timer, writes cache, dispatches COMPLETE with the stream payload.
 *   - `triggerStreamFallback()`: called when stream errors (non-conflict). Falls back to the
 *     non-streaming fetchDetailedAnalysis so the analysis still completes.
 *
 * Cache wiring (issue #310):
 *   - getCachedAnalysis(ip) checked at the start of each ip change.
 *   - setCachedAnalysis(ip, ...) written on COMPLETE (stream result or fallback).
 *   - invalidateCachedAnalysis(ip) called by runDeepAnalysis before refetch.
 *   - fromCache=true and fetchedAt expose the "cached · age" stamp in DeepAnalysisControl.
 *
 * The hook is intentionally isolated so IpPanel.tsx can gate the AI section
 * on its state without touching the rule-analysis flow.
 *
 * SECURITY (ADR-0029 D3): all attacker-controlled fields must be rendered as text nodes.
 */

import { useCallback, useEffect, useReducer, useRef } from 'react'
import { fetchDetailedAnalysis } from '../../../api/logs'
import { fetchHealth } from '../../../api/client'
import type { DetailedAnalysis, HealthResponse } from '../../../api/types'
import { ApiError } from '../../../api/client'
import {
  getCachedAnalysis,
  setCachedAnalysis,
  invalidateCachedAnalysis,
} from '../analysisCache'

// ---------------------------------------------------------------------------
// State shape + reducer
// ---------------------------------------------------------------------------

/** The lifecycle state of the deep-analysis AI call. */
export type DeepAnalysisPhase =
  /** Panel just opened — checking /health. */
  | 'health_check'
  /** AI offline per /health — not calling the LLM. */
  | 'ai_offline'
  /** AI online — LLM call in progress. */
  | 'analyzing'
  /** AI call completed successfully (live or from cache). */
  | 'complete'
  /** AI call failed or timed out (never shows "complete"). */
  | 'failed'
  /**
   * A concurrent analysis is already running for this IP — 409 received on both
   * the SSE stream AND the non-streaming fallback (issue #525).
   * Distinct from 'failed' so the UI shows "Analysis already running — please wait"
   * instead of the generic error badge.
   */
  | 'conflict'
  /** Not yet started (ip=null or reset before first run). */
  | 'idle'

export interface DeepAnalysisState {
  phase: DeepAnalysisPhase
  /** AI-augmented analysis result (present only when phase='complete'). */
  deepAnalysis: DetailedAnalysis | null
  /** Client-measured elapsed seconds (set while analyzing, final value when complete). */
  elapsedSeconds: number
  /** Model name from /health, if available. */
  modelName: string | null
  /** Error message — set when phase='failed'. Never set on success. */
  error: string | null
  /**
   * True when the result was served from the session cache (issue #310).
   * Controls the "cached · age" stamp in DeepAnalysisControl.
   */
  fromCache: boolean
  /**
   * Unix-ms timestamp of when the analysis was originally fetched (issue #310).
   * Present when fromCache=true so DeepAnalysisControl can render "cached · X min ago".
   */
  fetchedAt: number | null
}

type DeepAction =
  | { type: 'RESET' }
  | { type: 'HEALTH_OK'; modelName: string | null }
  | { type: 'AI_OFFLINE' }
  | { type: 'ANALYZING' }
  | { type: 'TICK'; elapsed: number }
  | { type: 'COMPLETE'; analysis: DetailedAnalysis | null; elapsed: number; fromCache?: boolean; fetchedAt?: number }
  | { type: 'FAILED'; payload: string; elapsed: number }
  /**
   * Dispatched when the non-streaming fallback fetch returns HTTP 409 (issue #525).
   * Signals that the analysis slot is occupied by a concurrent request; the UI should
   * show "Analysis already running — please wait" rather than the generic error badge.
   */
  | { type: 'CONFLICT'; elapsed: number }

const IDLE_STATE: DeepAnalysisState = {
  phase: 'idle',
  deepAnalysis: null,
  elapsedSeconds: 0,
  modelName: null,
  error: null,
  fromCache: false,
  fetchedAt: null,
}

function reducer(state: DeepAnalysisState, action: DeepAction): DeepAnalysisState {
  switch (action.type) {
    case 'RESET':
      return IDLE_STATE
    case 'HEALTH_OK':
      return { ...state, phase: 'analyzing', modelName: action.modelName, error: null }
    case 'AI_OFFLINE':
      return { ...state, phase: 'ai_offline', error: null }
    case 'ANALYZING':
      return { ...state, phase: 'analyzing', error: null, fromCache: false, fetchedAt: null }
    case 'TICK':
      return { ...state, elapsedSeconds: action.elapsed }
    case 'COMPLETE':
      return {
        ...state,
        phase: 'complete',
        deepAnalysis: action.analysis,
        elapsedSeconds: action.elapsed,
        error: null,
        fromCache: action.fromCache ?? false,
        fetchedAt: action.fetchedAt ?? null,
      }
    case 'FAILED':
      return {
        ...state,
        phase: 'failed',
        elapsedSeconds: action.elapsed,
        error: action.payload,
      }
    case 'CONFLICT':
      // issue #525: fallback fetch returned 409 — a concurrent analysis is running.
      // Set phase='conflict' so the UI can show "Analysis already running — please wait".
      return {
        ...state,
        phase: 'conflict',
        elapsedSeconds: action.elapsed,
        error: null,
      }
    default:
      return state
  }
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export interface UseDeepAnalysisReturn extends DeepAnalysisState {
  /**
   * Trigger a (re-)run of the deep AI analysis.
   * Invalidates the session cache for this IP before firing a fresh LLM call.
   * Safe to call at any phase — resets elapsed timer and enters stream-driven mode.
   * Used by DeepAnalysisControl's "Run deep analysis" / "Retry" / "Re-run" buttons.
   */
  runDeepAnalysis: () => void
  /**
   * Called by DeepAnalysisControl when the SSE stream's terminal `result` event arrives.
   * Stops the elapsed timer, writes to session cache, and transitions to phase='complete'.
   * This is the NORMAL completion path — no separate non-streaming fetch needed.
   *
   * Issue #416: stream is the PRIMARY analysis trigger. This callback lets the stream
   * result bypass the non-streaming fetchDetailedAnalysis entirely.
   */
  receiveStreamResult: (payload: Record<string, unknown>) => void
  /**
   * Called by DeepAnalysisControl when the SSE stream fails for a non-conflict reason
   * (network error, parse error, SSE `error` event, etc.).
   * Falls back to the non-streaming GET /threats/{ip}/detailed so the analysis still
   * completes even when streaming is unavailable or errored.
   *
   * Issue #416: a 409 from our own concurrent duplicate is eliminated by the stream-driven
   * approach, so this fallback only fires for genuine stream errors.
   */
  triggerStreamFallback: () => void
}

/**
 * Manage the deep AI analysis lifecycle for one IP.
 *
 * On mount (when ip changes):
 *  - Checks the session cache (issue #310); cache hit → phase='complete' instantly.
 *  - On cache miss: fetches GET /health; if AI offline → phase='ai_offline' (instant).
 *  - If AI online → enters stream-driven mode (phase='analyzing'); the SSE stream in
 *    DeepAnalysisControl is the PRIMARY trigger; receiveStreamResult delivers the result.
 *  - On stream error: triggerStreamFallback fires the non-streaming path as a safety net.
 *  - On successful completion → writes to cache, phase='complete'.
 *
 * `runDeepAnalysis` is stable across renders and calls `invalidateCachedAnalysis` before
 * re-issuing the AI call.
 */
export function useDeepAnalysis(ip: string | null): UseDeepAnalysisReturn {
  const [state, dispatch] = useReducer(reducer, IDLE_STATE)

  // Stable ref to ip so callbacks always have the current value.
  // Updated in an effect (not during render) to satisfy the react-hooks/refs rule.
  const ipRef = useRef<string | null>(ip)
  useEffect(() => {
    ipRef.current = ip
  })

  // Elapsed timer ref — cleared on each new run.
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const startRef = useRef<number>(0)
  const cancelledRef = useRef(false)
  // NB-1 (issue #306): gate concurrent calls — prevents rapid Re-run clicks from
  // queuing sequential LLM calls. Set true when a run starts; cleared on complete/fail.
  const inFlightRef = useRef(false)

  const clearTimer = useCallback(() => {
    if (timerRef.current !== null) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }
  }, [])

  // ---------------------------------------------------------------------------
  // Stream-driven entry: sets phase='analyzing' + starts timer WITHOUT firing
  // the non-streaming fetch. The SSE stream (useStageTicker in DeepAnalysisControl)
  // is the analysis trigger; receiveStreamResult delivers the result.
  //
  // Issue #416: this replaces the old fireAiCall-on-open pattern that caused the
  // self-inflicted 409 (two concurrent requests for the same IP on first open).
  // ---------------------------------------------------------------------------
  const startStreamDrivenAnalysis = useCallback(
    () => {
      // NB-1: cancel any prior in-flight call before starting a new one.
      cancelledRef.current = true
      cancelledRef.current = false
      inFlightRef.current = true
      dispatch({ type: 'ANALYZING' })
      startRef.current = Date.now()

      // Tick every second so the UI can show "analyzing (Ns)".
      clearTimer()
      timerRef.current = setInterval(() => {
        if (!cancelledRef.current) {
          dispatch({ type: 'TICK', elapsed: Math.floor((Date.now() - startRef.current) / 1000) })
        }
      }, 1000)

      // No fetchDetailedAnalysis call here — the stream delivers the result.
      // receiveStreamResult() is the COMPLETE path; triggerStreamFallback() is the fallback.
    },
    [clearTimer],
  )

  // ---------------------------------------------------------------------------
  // Non-streaming fetch — used ONLY as a fallback when the SSE stream errors.
  // Not called on the primary (first open / normal) path.
  // ---------------------------------------------------------------------------
  const fireNonStreamingFetch = useCallback(
    (currentIp: string) => {
      fetchDetailedAnalysis(currentIp, /* includeAi */ true)
        .then((analysis) => {
          if (!cancelledRef.current) {
            clearTimer()
            inFlightRef.current = false
            const elapsed = Math.floor((Date.now() - startRef.current) / 1000)
            const fetchedAt = Date.now()
            setCachedAnalysis(currentIp, { analysis, rules: [], fetchedAt })
            dispatch({ type: 'COMPLETE', analysis, elapsed, fromCache: false, fetchedAt })
          }
        })
        .catch((err: unknown) => {
          if (!cancelledRef.current) {
            clearTimer()
            inFlightRef.current = false
            const elapsed = Math.floor((Date.now() - startRef.current) / 1000)
            // issue #525: 409 from the fallback fetch means a concurrent analysis is
            // already running (the SSE stream also returned 409, and the non-streaming
            // path has the same lock). Surface this as 'conflict' so the UI shows
            // "Analysis already running — please wait" instead of the generic error badge.
            if (err instanceof ApiError && err.status === 409) {
              dispatch({ type: 'CONFLICT', elapsed })
            } else {
              dispatch({
                type: 'FAILED',
                elapsed,
                payload:
                  err instanceof ApiError
                    ? `AI analysis failed (${err.status})`
                    : 'AI analysis failed',
              })
            }
          }
        })
    },
    [clearTimer],
  )

  // ---------------------------------------------------------------------------
  // receiveStreamResult — called by DeepAnalysisControl when the stream's
  // terminal `result` SSE event arrives (the NORMAL completion path).
  // ---------------------------------------------------------------------------
  const receiveStreamResult = useCallback(
    (payload: Record<string, unknown>) => {
      if (cancelledRef.current) return
      clearTimer()
      inFlightRef.current = false
      const elapsed = Math.floor((Date.now() - startRef.current) / 1000)
      const fetchedAt = Date.now()
      const currentIp = ipRef.current

      // Cast the stream payload to DetailedAnalysis — it carries the same shape
      // as the non-streaming response (ADR-0046 terminal `result` event contract).
      const analysis = payload as unknown as DetailedAnalysis

      if (currentIp) {
        setCachedAnalysis(currentIp, { analysis, rules: [], fetchedAt })
      }
      dispatch({ type: 'COMPLETE', analysis, elapsed, fromCache: false, fetchedAt })
    },
    [clearTimer],
  )

  // ---------------------------------------------------------------------------
  // triggerStreamFallback — called by DeepAnalysisControl when the SSE stream
  // errors for a genuine (non-self-inflicted) reason. Falls back to the
  // non-streaming fetchDetailedAnalysis so the analysis still completes.
  // ---------------------------------------------------------------------------
  const triggerStreamFallback = useCallback(() => {
    const currentIp = ipRef.current
    if (!currentIp || cancelledRef.current) return
    fireNonStreamingFetch(currentIp)
  }, [fireNonStreamingFetch])

  // ---------------------------------------------------------------------------
  // runDeepAnalysis — exposed to DeepAnalysisControl for Run / Retry / Re-run.
  //
  // Invalidates the session cache for this IP, re-checks /health (NB-1, issue #306),
  // and enters stream-driven mode if AI is healthy.
  //
  // NB-1 (issue #306): guarded by inFlightRef so rapid clicks do not queue sequential
  // LLM calls. Health check is always re-run so a re-run after a stale 'complete'
  // cannot bypass the offline guard (ADR-0035 honesty).
  // ---------------------------------------------------------------------------
  const runDeepAnalysis = useCallback(() => {
    const currentIp = ipRef.current
    if (!currentIp) return
    // NB-1: bail out if a call is already in flight (debounce guard).
    // Set true immediately — before fetchHealth() — so the window between
    // "Re-run clicked" and "startStreamDrivenAnalysis() called" is also guarded.
    if (inFlightRef.current) return
    inFlightRef.current = true

    // Invalidate cache so the next open triggers a fresh fetch (issue #310).
    invalidateCachedAnalysis(currentIp)

    // NB-1: re-check /health on every re-run — do not bypass the offline guard.
    fetchHealth()
      .then((health: HealthResponse) => {
        if (cancelledRef.current) {
          inFlightRef.current = false
          return
        }
        if (health.ollama_connected) {
          const modelName = health.ollama_model ?? null
          dispatch({ type: 'HEALTH_OK', modelName })
          // Enter stream-driven mode: phase becomes 'analyzing'; useStageTicker
          // (in DeepAnalysisControl) opens the SSE stream as the primary trigger.
          startStreamDrivenAnalysis()
        } else {
          inFlightRef.current = false
          dispatch({ type: 'AI_OFFLINE' })
        }
      })
      .catch(() => {
        inFlightRef.current = false
        if (!cancelledRef.current) dispatch({ type: 'AI_OFFLINE' })
      })
  }, [startStreamDrivenAnalysis])

  // Auto-run on IP change: check cache first, then health check → stream-driven or offline.
  useEffect(() => {
    if (!ip) {
      dispatch({ type: 'RESET' })
      return
    }

    dispatch({ type: 'RESET' })
    cancelledRef.current = false
    inFlightRef.current = false
    clearTimer()

    // Cache check first (issue #310): if we have a valid cached result, use it immediately
    // without hitting /health or the LLM endpoint.
    const cached = getCachedAnalysis(ip)
    if (cached !== null) {
      dispatch({
        type: 'COMPLETE',
        analysis: cached.analysis,
        elapsed: 0,
        fromCache: true,
        fetchedAt: cached.fetchedAt,
      })
      return
    }

    // Health check first — fast, usually cached by the app-level health poller.
    fetchHealth()
      .then((health: HealthResponse) => {
        if (cancelledRef.current) return
        if (health.ollama_connected) {
          const modelName = health.ollama_model ?? null
          dispatch({ type: 'HEALTH_OK', modelName })
          // Issue #416: enter stream-driven mode — do NOT fire the non-streaming fetch
          // concurrently. The SSE stream (useStageTicker) is the sole analysis trigger.
          startStreamDrivenAnalysis()
        } else {
          dispatch({ type: 'AI_OFFLINE' })
        }
      })
      .catch(() => {
        // Health check failure → treat AI as offline (fail-safe).
        if (!cancelledRef.current) dispatch({ type: 'AI_OFFLINE' })
      })

    return () => {
      cancelledRef.current = true
      inFlightRef.current = false
      clearTimer()
    }
  }, [ip, clearTimer, startStreamDrivenAnalysis])

  return { ...state, runDeepAnalysis, receiveStreamResult, triggerStreamFallback }
}
