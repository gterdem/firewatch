/**
 * useStageTicker — fetch-stream lifecycle hook for the SSE stage ticker.
 *
 * ADR-0046 D2: consumes GET /threats/{ip}/detailed/stream via fetch +
 * ReadableStream + AbortController — NOT EventSource (cannot send the
 * Authorization header and lacks deterministic abort).
 *
 * Lifecycle:
 *   1. On mount (when ip is set and enabled=true): open fetch stream.
 *   2. As SSE frames arrive: parse stage facts and accumulate into state.
 *   3. On terminal `result` frame: resolve with the analysis payload.
 *   4. On `error` frame or fetch failure: signal streamError=true so the
 *      caller can fall back to the non-streaming useDeepAnalysis path.
 *   5. On unmount / slide-over close / navigation: AbortController.abort()
 *      is called. This frees the Ollama GPU slot server-side (ADR-0046 §5).
 *
 * 409 RETRY (StrictMode / rapid re-subscribe hardening):
 *   React 18 StrictMode double-invokes useEffect in dev. Mount 1 opens the
 *   stream; StrictMode cleanup aborts it; mount 2 immediately opens another.
 *   The backend's single-flight set only clears the IP asynchronously (after
 *   CancelledError propagates through the generator's finally block -- ~5-50ms).
 *   Mount 2's request therefore lands while the IP is still marked in-flight ->
 *   spurious HTTP 409 -> ticker hidden. Same race can hit production on a fast
 *   navigate-away-and-back.
 *
 *   Fix: treat 409 as transiently retryable (up to MAX_409_RETRIES extra
 *   attempts, with RETRY_DELAY_MS between them). The delay is abortable via
 *   the existing AbortController -- unmounting during the wait cancels the timer
 *   immediately (no setState-after-unmount, no leaked timer). If all retries
 *   are still 409, that signals a genuine concurrent analysis elsewhere and we
 *   fall back normally. All other non-OK statuses fall back immediately.
 *
 * PRE-FLIGHT DELAY (rapid slide-over re-open for same IP — issue #571):
 *   When the slide-over closes and immediately re-opens for the same IP, the
 *   useEffect cleanup aborts the prior in-flight stream, then the new effect
 *   fires and immediately issues a new fetch. The backend's single-flight lock
 *   clears asynchronously (~5-50ms after the abort propagates), so the first
 *   new request can arrive BEFORE the lock clears -> spurious HTTP 409 -> console
 *   error logged by the browser even though the retry mechanism ultimately
 *   recovers.
 *
 *   Fix: track whether a live stream was aborted just before this new stream
 *   starts (priorStreamAbortedRef). If so, apply RETRY_DELAY_MS before the very
 *   first fetch attempt. This pre-flight pause lets the server clear its lock
 *   before the request arrives, preventing the 409 from ever occurring instead
 *   of merely recovering from it. The delay uses the same abortableDelay helper
 *   so unmounting during the wait cancels it immediately (no setState-after-unmount,
 *   no leaked timer).
 *
 * SECURITY (ADR-0029 D3): no model-authored text appears in stage events --
 * prose arrives only in the terminal `result`, passed through unchanged to
 * the existing rendering path.
 */

import { useEffect, useReducer, useRef, useCallback } from 'react'
import type { StageFact } from './stages'
import { parseSseBlock, parseStageFact } from './stages'
import { resolveBaseUrl } from '../../../../api/client'

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

export interface StageTickerState {
  /** Accumulated stage facts so far (excluding heartbeats that are overwritten). */
  stages: StageFact[]
  /** Latest generating heartbeat elapsed_ms (overwritten on each heartbeat). */
  generatingElapsedMs: number | null
  /** Terminal result payload -- set when the `result` SSE event is received. */
  result: Record<string, unknown> | null
  /** True when the stream itself errored or returned an `error` event. */
  streamError: boolean
  /**
   * True when all 409 retries were exhausted — meaning a concurrent analysis is genuinely
   * running elsewhere (not a StrictMode race or transient backend timing issue).
   * UT-02 (#502): callers should surface "Analysis already running — please wait" UX
   * and NOT trigger the non-streaming fallback fetch (which would also 409).
   * Distinct from streamError so callers can differentiate transient vs conflict cases.
   */
  persistentConflict: boolean
  /** True while the stream is open and in progress. */
  streaming: boolean
  /** True when the stream has ended (result or error received, or aborted). */
  done: boolean
}

type TickerAction =
  | { type: 'STREAM_STARTED' }
  | { type: 'STAGE'; fact: StageFact }
  | { type: 'RESULT'; payload: Record<string, unknown> }
  | { type: 'STREAM_ERROR' }
  /** UT-02 (#502): all 409 retries exhausted — genuine concurrent stream running elsewhere. */
  | { type: 'PERSISTENT_CONFLICT' }
  | { type: 'DONE' }

const INITIAL_STATE: StageTickerState = {
  stages: [],
  generatingElapsedMs: null,
  result: null,
  streamError: false,
  persistentConflict: false,
  streaming: false,
  done: false,
}

function tickerReducer(state: StageTickerState, action: TickerAction): StageTickerState {
  switch (action.type) {
    case 'STREAM_STARTED':
      return { ...INITIAL_STATE, streaming: true }

    case 'STAGE':
      // Generating heartbeats overwrite the elapsed counter; do not accumulate.
      if (action.fact.stage === 'generating') {
        return { ...state, generatingElapsedMs: action.fact.elapsed_ms }
      }
      return { ...state, stages: [...state.stages, action.fact] }

    case 'RESULT':
      return { ...state, result: action.payload, streaming: false, done: true }

    case 'STREAM_ERROR':
      return { ...state, streamError: true, streaming: false, done: true }

    case 'PERSISTENT_CONFLICT':
      // UT-02 (#502): 409 persisted through all retries — concurrent stream is genuinely running.
      // Set persistentConflict (not streamError) so callers can show a distinct user message
      // and skip the non-streaming fallback (which would also 409).
      return { ...state, persistentConflict: true, streaming: false, done: true }

    case 'DONE':
      return { ...state, streaming: false, done: true }

    default:
      return state
  }
}

// ---------------------------------------------------------------------------
// Hook options
// ---------------------------------------------------------------------------

export interface UseStageTickerOptions {
  /** IP address to stream for. */
  ip: string | null
  /**
   * When false the stream is not started even if ip is set.
   * Use this to gate the ticker on a "Run" click.
   */
  enabled?: boolean
}

export interface UseStageTickerReturn extends StageTickerState {
  /** Call to abort the in-flight stream and reset state. */
  abort: () => void
}

// ---------------------------------------------------------------------------
// Constants -- 409 retry policy
// ---------------------------------------------------------------------------

/**
 * Maximum number of extra attempts after the first 409.
 * Total attempts = 1 (initial) + MAX_409_RETRIES = 3.
 */
const MAX_409_RETRIES = 2

/**
 * Milliseconds to wait between 409 retries.
 * 200 ms is comfortably longer than the ~5-50 ms backend cleanup window.
 */
const RETRY_DELAY_MS = 200

/**
 * Returns a Promise that resolves after `ms` milliseconds, but rejects
 * immediately with an AbortError if the signal is already aborted or fires
 * during the wait. This makes retry sleeps abortable -- no setState after
 * unmount, no leaked timer.
 */
function abortableDelay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException('Aborted', 'AbortError'))
      return
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    function onAbort() {
      clearTimeout(timer)
      reject(new DOMException('Aborted', 'AbortError'))
    }
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Manages the fetch-stream SSE lifecycle for one IP's detailed analysis.
 *
 * ABORT SEMANTICS (ADR-0046 §5):
 *   The hook holds an AbortController ref. The controller is aborted on:
 *   - Component unmount (React cleanup in useEffect)
 *   - The `abort()` function returned by the hook (manual abort)
 *   - A new stream starting for a different IP (prior stream cancelled)
 *
 * FALLBACK SIGNAL:
 *   When the stream itself fails (network error, non-200, `error` SSE event),
 *   `streamError` is set to true. The parent component checks this and falls
 *   back to the non-streaming useDeepAnalysis path -- the ticker is presentation,
 *   never a new failure mode for the analysis itself.
 *
 * 409 RETRY (StrictMode / rapid re-subscribe hardening):
 *   A 409 means "analysis already in-flight". After our own abort, the backend
 *   clears the single-flight lock asynchronously. Rather than immediately
 *   falling back, we retry up to MAX_409_RETRIES times after RETRY_DELAY_MS.
 *   The retry sleep is abortable -- unmounting during the wait cancels the timer
 *   immediately (no setState-after-unmount). Only after all retries are still
 *   409 do we signal streamError (genuine concurrent analysis elsewhere).
 */
export function useStageTicker({
  ip,
  enabled = true,
}: UseStageTickerOptions): UseStageTickerReturn {
  const [state, dispatch] = useReducer(tickerReducer, INITIAL_STATE)

  // AbortController ref -- new controller per stream; never shared across streams.
  const abortRef = useRef<AbortController | null>(null)

  /**
   * Issue #571 — tracks the timestamp of the most recent abort of a live stream.
   * Updated by BOTH the abort() callback (effect-body path) AND the useEffect
   * cleanup (direct-abort path, which happens when React batches rapid rerenders).
   * When a new stream starts within RETRY_DELAY_MS of this timestamp, a pre-flight
   * delay is applied so the server can clear its single-flight lock before the
   * request arrives.
   */
  const lastAbortTimeRef = useRef<number>(0)

  /** Abort the current in-flight stream (if any). */
  const abort = useCallback(() => {
    if (abortRef.current && !abortRef.current.signal.aborted) {
      // Record when a LIVE stream was aborted so the next stream start can
      // apply a pre-flight delay if it happens rapidly (issue #571).
      lastAbortTimeRef.current = Date.now()
      abortRef.current.abort()
    }
    abortRef.current = null
  }, [])

  useEffect(() => {
    if (!ip || !enabled) {
      // Not enabled -- ensure any prior stream is aborted.
      abort()
      return
    }

    // Cancel any prior in-flight stream before starting a new one.
    abort()

    const controller = new AbortController()
    abortRef.current = controller
    const { signal } = controller

    // Issue #571 — pre-flight delay: if a live stream was recently aborted (rapid
    // slide-over re-open for the same IP), the backend's single-flight lock may
    // not have cleared yet. Apply a pre-flight pause to let the server clear its
    // lock before the request arrives, preventing the spurious HTTP 409 that
    // the browser would log as a console error.
    //
    // "Recently" = within RETRY_DELAY_MS of the last live-stream abort.
    // This avoids adding latency when the panel is opened long after the prior
    // stream ended cleanly (no abort needed; not a rapid re-open scenario).
    //
    // We read lastAbortTimeRef AFTER calling abort() above so that the effect-body
    // abort path (which updates lastAbortTimeRef) is captured. The cleanup path
    // (direct controller.abort()) is handled by the cleanup below, which also
    // updates lastAbortTimeRef when aborting a live controller.
    const needsPreflightDelay =
      Date.now() - lastAbortTimeRef.current < RETRY_DELAY_MS

    dispatch({ type: 'STREAM_STARTED' })

    async function runStream() {
      try {
        const base = resolveBaseUrl(
          (import.meta as { env?: { VITE_API_BASE_URL?: string; DEV?: boolean } }).env ?? {},
        )
        const url = `${base}/threats/${encodeURIComponent(ip!)}/detailed/stream`

        // Issue #571 — pre-flight delay: pause before the first fetch so the
        // server can clear its single-flight lock after an abort.
        // The delay is abortable — unmounting during the wait cancels it immediately.
        if (needsPreflightDelay) {
          await abortableDelay(RETRY_DELAY_MS, signal)
        }

        // Attempt up to (1 + MAX_409_RETRIES) times for 409 responses only.
        for (let attempt = 0; attempt <= MAX_409_RETRIES; attempt++) {
          // On a retry (not the first attempt), wait before re-requesting.
          // The delay is abortable -- unmounting cancels the timer immediately.
          if (attempt > 0) {
            await abortableDelay(RETRY_DELAY_MS, signal)
          }

          const res = await fetch(url, {
            method: 'GET',
            headers: {
              Accept: 'text/event-stream',
              'Cache-Control': 'no-cache',
            },
            signal,
          })

          // 409: analysis already in-flight (possibly our own prior mount still
          // clearing). Retry transiently; fall back only after all retries exhausted.
          if (res.status === 409) {
            if (attempt < MAX_409_RETRIES) {
              continue // next loop iteration -> wait then retry
            }
            // All retries exhausted -- genuine concurrent analysis elsewhere.
            // UT-02 (#502): signal PERSISTENT_CONFLICT (not STREAM_ERROR) so the
            // caller (DeepAnalysisControl) shows a "please wait" message and does NOT
            // trigger the non-streaming fallback fetch (which would also 409).
            dispatch({ type: 'PERSISTENT_CONFLICT' })
            return
          }

          if (!res.ok || !res.body) {
            // Non-409 non-OK response -> immediate fallback (no retry).
            dispatch({ type: 'STREAM_ERROR' })
            return
          }

          // --- Success path: consume the SSE stream ---
          const reader = res.body.getReader()
          const decoder = new TextDecoder()
          let buffer = ''

          for (;;) {
            const { done, value } = await reader.read()
            if (done) break

            buffer += decoder.decode(value, { stream: true })

            // SSE messages are separated by double newlines.
            const blocks = buffer.split('\n\n')
            // Keep the last (potentially incomplete) chunk in the buffer.
            buffer = blocks.pop() ?? ''

            for (const block of blocks) {
              const trimmed = block.trim()
              if (!trimmed) continue

              const frame = parseSseBlock(trimmed)
              if (!frame) continue

              if (frame.event === 'stage') {
                const fact = parseStageFact(frame)
                if (fact !== null) {
                  dispatch({ type: 'STAGE', fact })
                }
                // Unknown stage names are dropped (forward-compat -- parseStageFact returns null).
              } else if (frame.event === 'result') {
                try {
                  const payload = JSON.parse(frame.data) as Record<string, unknown>
                  dispatch({ type: 'RESULT', payload })
                } catch {
                  dispatch({ type: 'STREAM_ERROR' })
                }
                return
              } else if (frame.event === 'error') {
                dispatch({ type: 'STREAM_ERROR' })
                return
              }
              // Other event types (e.g. heartbeats with no event field) are dropped.
            }
          }

          // Stream ended without a `result` event -- treat as done (not an error).
          dispatch({ type: 'DONE' })
          return // exit the retry loop -- stream completed normally
        }
      } catch (err) {
        // AbortError means the component unmounted or the user closed the panel --
        // this is expected behaviour (ADR-0046 §5). Do NOT signal streamError.
        if (err instanceof DOMException && err.name === 'AbortError') {
          dispatch({ type: 'DONE' })
          return
        }
        // Any other error (network failure, resolveBaseUrl failure, etc.) -> signal fallback.
        dispatch({ type: 'STREAM_ERROR' })
      }
    }

    void runStream()

    // Cleanup: abort the in-flight stream on unmount or ip/enabled change.
    // This is the mandatory ADR-0046 §5 abort-on-unmount contract.
    //
    // Issue #571: when the cleanup aborts a LIVE stream (not already aborted by
    // our abort() callback), record the abort timestamp so a rapid re-open gets
    // the pre-flight delay. This covers the React batched-rerender case where the
    // intermediate enabled:false effect is skipped and only the cleanup of the
    // previous enabled:true effect runs.
    return () => {
      if (!controller.signal.aborted) {
        lastAbortTimeRef.current = Date.now()
        controller.abort()
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ip, enabled])

  return { ...state, abort }
}
