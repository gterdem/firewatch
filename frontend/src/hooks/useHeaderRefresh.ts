/**
 * useHeaderRefresh — thin context reader returning the AppHeader freshness shape.
 *
 * ADR-0064 D1: The polling body has been lifted into useStatsHeartbeat
 * (src/app/refresh/useStatsHeartbeat.ts) which RefreshProvider calls once at
 * the app root.  This hook is now a THIN READER over useRefreshSignal() that
 * returns the SAME UseHeaderRefreshResult shape as before so AppHeader.tsx
 * (and its tests) require NO changes.  Backward-compatible by construction.
 *
 * The LIVE badge semantics are unchanged (distinct from per-source dots):
 *   live=true  — polling active, last poll succeeded.
 *   live=false — polling failed or was never seeded.
 *
 * ADR-0032 D: dot color is driven by server-computed `health`; this hook does
 * NOT re-derive color from recency — it only surfaces freshness metadata.
 *
 * Security: no secret values pass through; event counts are unsigned integers.
 * ADR-0019: React + TS hooks; no per-source hardcode.
 * ADR-0026: loopback-only; no off-host requests.
 */

import type { SourceHealthItem } from '../lib/sourceHealth'
import { useRefreshSignal } from '../app/refresh/RefreshContext'

// Re-export the polling constant so AppHeader tooltip can reference it without
// importing from the new module path (backward-compatible consumers).
export { HEALTH_POLL_MS, PULSE_CLEAR_MS } from '../app/refresh/useStatsHeartbeat'

/** The public shape returned by the hook — UNCHANGED from before ADR-0064. */
export interface UseHeaderRefreshResult {
  /** Health items for the source-filter strip. */
  healthItems: SourceHealthItem[]
  /**
   * True when polling is active and the last poll completed without error.
   * Drives LiveBadge `live` prop — green pulsing when true; grey Paused when false.
   */
  isLive: boolean
  /**
   * ISO timestamp of the last successful poll, or null before the first success.
   * Shown in the LiveBadge tooltip: "last update Xs ago".
   */
  lastPollAt: string | null
  /**
   * Net increase in total ingested events since the previous poll.
   * > 0 triggers a sync banner; 0 means no new data this cycle.
   * Reset to 0 after the caller reads it via `clearSyncDelta()`.
   */
  lastSyncDeltaCount: number
  /**
   * Monotonically-increasing counter incremented each time a positive delta is
   * detected. The AppHeader banner effect depends on this value instead of
   * `lastSyncDeltaCount` so that clearing the count (clearSyncDelta) never
   * destructively flips the effect's own dependency and cancels the dismiss
   * timer. The id only ever increases — it is safe to depend on it.
   */
  syncEventId: number
  /**
   * Set of source_type keys whose event_count grew in the last poll cycle.
   * HealthDot adds a brief pulse class when its sourceType is in this set.
   * Cleared after `PULSE_CLEAR_MS` ms automatically.
   */
  pulsingSources: ReadonlySet<string>
  /**
   * Clear the sync delta after the caller has shown the banner/toast.
   * Prevents the banner re-triggering on the next render without a new poll.
   */
  clearSyncDelta: () => void
  /**
   * Server freshness window in minutes from GET /stats `freshness_minutes`.
   * ADR-0032 Amendment 1 R1 (issue #377): passed to HealthCard so the legend
   * renders the live server constant, never a hardcoded client copy.
   * Defaults to 5 before the first successful poll.
   */
  freshnessMinutes: number
}

/**
 * useHeaderRefresh — returns the existing AppHeader freshness shape.
 *
 * Now reads from RefreshContext instead of owning the interval.
 * AppHeader.tsx and all existing tests are UNCHANGED by this refactor.
 */
export function useHeaderRefresh(): UseHeaderRefreshResult {
  const signal = useRefreshSignal()

  return {
    healthItems: signal.healthItems,
    isLive: signal.isLive,
    lastPollAt: signal.lastPollAt,
    lastSyncDeltaCount: signal.lastSyncDeltaCount,
    syncEventId: signal.syncEventId,
    pulsingSources: signal.pulsingSources,
    clearSyncDelta: signal.clearSyncDelta,
    freshnessMinutes: signal.freshnessMinutes,
  }
}
