/**
 * types.ts — shared signal contract for the app-wide live-refresh system.
 *
 * ADR-0064 D2: RefreshSignal is the single freshness descriptor that flows from
 * the one shared polling interval (GET /stats every HEALTH_POLL_MS) to every
 * routed page and the header.  Pages subscribe via useRefreshSignal(); the
 * AppHeader reads the same signal via useHeaderRefresh() (the thin reader).
 *
 * ADR-0019: TS interface only — no React imports.
 * ADR-0026: loopback-only; no off-host data.
 */

import type { SourceHealthItem } from '../../lib/sourceHealth'

/**
 * RefreshSignal — the shared freshness descriptor published by RefreshProvider
 * and consumed by useRefreshSignal() / useHeaderRefresh().
 *
 * ADR-0064 D2: dataVersion increments by exactly 1 ONLY when the net
 * new-event delta between two consecutive polls is > 0.  Empty cycles
 * (delta = 0) must NOT change dataVersion, so pages that depend on it
 * only refetch when real data arrives — no refetch storms on idle polls.
 */
export interface RefreshSignal {
  // -----------------------------------------------------------------------
  // Page-subscription fields (ADR-0064 D2 / D3)
  // -----------------------------------------------------------------------

  /**
   * Monotonically-increasing counter, starts at 0, increments by 1 on every
   * poll cycle where the net new-event delta > 0.  Never resets.
   *
   * Pages add this to their fetch-effect deps:
   *   useEffect(() => { fetch... }, [dataVersion])
   * Empty polls leave dataVersion unchanged → zero downstream refetches.
   */
  dataVersion: number

  /**
   * Source types whose event_count grew in the most recent positive-delta
   * cycle.  Lets a page skip refetch when none of its relevant sources grew
   * (optional optimisation — default is to refetch on any dataVersion bump).
   * Empty set between positive-delta cycles.
   */
  grewSources: ReadonlySet<string>

  /**
   * Net new-event count for the latest positive-delta cycle.
   * Drives the "N new events — click to load" pill copy (ADR-0064 D4).
   * Stays at 0 between positive cycles.
   */
  lastDeltaCount: number

  // -----------------------------------------------------------------------
  // Header / freshness fields (carried through from useHeaderRefresh today)
  // -----------------------------------------------------------------------

  /** Health items for the source-filter strip. */
  healthItems: SourceHealthItem[]

  /**
   * True when polling is active and the last poll succeeded.
   * Drives LiveBadge live prop — green pulsing when true; grey Paused otherwise.
   */
  isLive: boolean

  /**
   * ISO timestamp of the last successful poll, or null before the first success.
   * Shown in the LiveBadge tooltip: "last update Xs ago".
   */
  lastPollAt: string | null

  /**
   * Net increase in total ingested events since the previous poll.
   * > 0 triggers the sync banner; 0 means no new data this cycle.
   * Cleared after the banner reads it via clearSyncDelta().
   */
  lastSyncDeltaCount: number

  /**
   * Monotonically-increasing counter incremented each time a positive delta is
   * detected.  AppHeader banner effect depends on this instead of
   * lastSyncDeltaCount so clearSyncDelta() never cancels the dismiss timer.
   * Only ever increases — safe to depend on.
   */
  syncEventId: number

  /**
   * Source types that received new events on the last poll cycle.
   * HealthDot adds a brief pulse animation when its sourceType is in this set.
   * Cleared automatically after PULSE_CLEAR_MS.
   */
  pulsingSources: ReadonlySet<string>

  /**
   * Clear the sync delta after the banner has been shown.
   * Prevents the banner re-triggering on the next render without a new poll.
   */
  clearSyncDelta: () => void

  /**
   * Server freshness window in minutes from GET /stats freshness_minutes.
   * ADR-0032 Amendment 1 R1: passed to HealthCard so the legend renders the
   * live server constant, never a hardcoded client copy.
   * Defaults to 5 before the first successful poll.
   */
  freshnessMinutes: number
}
