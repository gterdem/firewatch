/**
 * useNarrationStream — coordinates the ADR-0046 stage stream with the narration
 * fetch for the NarrationPanel "watch it think" feature (CR3, issue #614).
 *
 * Strategy:
 *   The narration endpoint internally calls `analyze_ip_detailed` — the same
 *   pipeline that the ADR-0046 `/detailed/stream` endpoint streams stage facts
 *   from.  To surface real stage facts during narration:
 *   1. Open the `/detailed/stream` SSE stream via `useStageTicker` (real stages).
 *   2. The stage ticker is presentation only — it never blocks the narration.
 *
 *   Graceful degradation (ADR-0046 §7):
 *   - If the stream errors (network, non-OK status, etc.), `streamError` is set
 *     → the parent renders the plain "Running local model…" fallback.
 *   - The narration prose is fetched by the parent (`fetchNarration`) and is
 *     independent of this hook.  This hook is purely the stream/ticker concern.
 *
 * Honest provenance (ADR-0035):
 *   When `aiAvailable === false`, NO stream is opened, no inference stages are
 *   implied.  The parent shows "Building rule summary…" instead.
 *
 * SECURITY (ADR-0029 D3):
 *   No model-authored text is returned from this hook.  Stage facts are typed
 *   via the closed StageFact union (stages.ts) — only numeric / enum values.
 */

import { useStageTicker } from './ticker/useStageTicker'
import type { StageTickerState } from './ticker/useStageTicker'

// ---------------------------------------------------------------------------
// Hook options
// ---------------------------------------------------------------------------

export interface UseNarrationStreamOptions {
  ip: string
  /**
   * When false, stream is NOT opened (ADR-0035 honesty: never imply AI ran).
   * The parent shows "Building rule summary…" instead of the ticker.
   */
  aiAvailable: boolean
  /**
   * Whether narration has been triggered (Explain was clicked).
   * The stream opens when this is true and aiAvailable is true.
   */
  enabled: boolean
}

// ---------------------------------------------------------------------------
// Return type — exposes only the ticker-relevant slice of StageTickerState
// ---------------------------------------------------------------------------

export interface UseNarrationStreamReturn {
  /** Accumulated stage facts from the stream (excl. generating heartbeats). */
  stages: StageTickerState['stages']
  /** Latest generating heartbeat elapsed_ms (for the collapsed-line live counter). */
  generatingElapsedMs: StageTickerState['generatingElapsedMs']
  /** True while the SSE stream is open. */
  streamStreaming: boolean
  /** True when the stream has completed or errored. */
  streamDone: boolean
  /**
   * True when the stream errored — parent should hide the ticker and show
   * the "Running local model…" fallback (ADR-0046 §7).
   */
  streamError: boolean
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Opens the ADR-0046 `/detailed/stream` SSE for the given IP when narration
 * is triggered in AI mode.  Returns stage-ticker state for the
 * `NarrationInferenceTicker` UI.
 *
 * Lifecycle:
 *   - `enabled=true` + `aiAvailable=true` → stream opens (useStageTicker).
 *   - Stream errors (network, 503, 404, absent endpoint) → `streamError=true`
 *     → parent renders plain "Running local model…" fallback.
 *   - `aiAvailable=false` → no stream (ADR-0035 honesty).
 *   - Unmount → AbortController aborts the stream (ADR-0046 §5).
 */
export function useNarrationStream({
  ip,
  aiAvailable,
  enabled,
}: UseNarrationStreamOptions): UseNarrationStreamReturn {
  // Open the stream only in AI mode while narration is in progress.
  const tickerEnabled = enabled && aiAvailable

  const ticker = useStageTicker({
    ip: tickerEnabled ? ip : null,
    enabled: tickerEnabled,
  })

  return {
    stages: ticker.stages,
    generatingElapsedMs: ticker.generatingElapsedMs,
    streamStreaming: ticker.streaming,
    streamDone: ticker.done,
    // persistentConflict (all 409 retries exhausted) also counts as stream error
    // for our purposes — the ticker is presentation; fall back gracefully.
    streamError: ticker.streamError || ticker.persistentConflict,
  }
}
