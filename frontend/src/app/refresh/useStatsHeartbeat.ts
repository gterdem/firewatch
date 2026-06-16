/**
 * useStatsHeartbeat — the single GET /stats polling interval for the entire app.
 *
 * ADR-0064 D1: This hook is the ONE interval.  It is called exactly once by
 * RefreshProvider at the app root; no other component or hook may create a
 * second GET /stats interval.
 *
 * Responsibilities (moved verbatim from the former useHeaderRefresh body):
 *   1. Poll GET /stats every HEALTH_POLL_MS milliseconds.
 *   2. Track isLive + lastPollAt (the LIVE badge state).
 *   3. Compute lastSyncDeltaCount — net new-event delta between polls.
 *   4. Maintain syncEventId — monotonic counter for the toast/banner effect.
 *   5. Maintain pulsingSources — source types with new events, cleared after
 *      PULSE_CLEAR_MS.
 *   6. Compute freshnessMinutes from the server response (ADR-0032 Amendment 1).
 *
 * ADR-0064 D2 additions (new relative to the old useHeaderRefresh body):
 *   7. dataVersion — increments by 1 only when delta > 0; never resets.
 *   8. grewSources — ReadonlySet<string> of source types that grew.
 *   9. lastDeltaCount — net count of the latest positive cycle.
 *
 * Security: no secret values pass through; event counts are unsigned integers.
 * ADR-0019: React + TS; no per-source hardcode.
 * ADR-0026: loopback-only; no off-host requests.
 */

import { useEffect, useRef, useState } from 'react'
import type { SourceHealthItem } from '../../lib/sourceHealth'
import { toSourceHealthItems } from '../../lib/sourceHealth'
import { fetchStats } from '../../api/client'
import type { RefreshSignal } from './types'

/** How often (ms) to poll GET /stats.  Exported so AppHeader tooltip can show it. */
export const HEALTH_POLL_MS = 30_000

/** How long (ms) a source dot pulses after new events arrive. */
export const PULSE_CLEAR_MS = 8_000

// ---------------------------------------------------------------------------
// Pure helpers (same as original useHeaderRefresh — moved here verbatim)
// ---------------------------------------------------------------------------

/**
 * Sum total event_count across all health items (for delta calculation).
 * Only counts items whose event_count is a positive integer.
 */
function sumEventCounts(items: SourceHealthItem[]): number {
  return items.reduce((acc, it) => acc + Math.max(0, it.eventCount), 0)
}

/**
 * Return the set of source_type keys whose event_count grew between the
 * previous and current SourceHealthItem arrays.
 */
function sourcesWithNewEvents(
  prev: SourceHealthItem[],
  next: SourceHealthItem[],
): Set<string> {
  const prevMap = new Map<string, number>()
  for (const item of prev) {
    const existing = prevMap.get(item.sourceType) ?? 0
    prevMap.set(item.sourceType, existing + item.eventCount)
  }

  const nextMap = new Map<string, number>()
  for (const item of next) {
    const existing = nextMap.get(item.sourceType) ?? 0
    nextMap.set(item.sourceType, existing + item.eventCount)
  }

  const grew = new Set<string>()
  for (const [type, count] of nextMap) {
    const prevCount = prevMap.get(type) ?? 0
    if (count > prevCount) grew.add(type)
  }
  return grew
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * useStatsHeartbeat — the one shared polling interval for the app.
 *
 * Returns the full RefreshSignal so RefreshProvider can publish it via context.
 * Called exactly once at the app root (RefreshProvider).
 */
export function useStatsHeartbeat(): RefreshSignal {
  const [healthItems, setHealthItems] = useState<SourceHealthItem[]>([])
  const [isLive, setIsLive] = useState(false)
  const [lastPollAt, setLastPollAt] = useState<string | null>(null)
  const [lastSyncDeltaCount, setLastSyncDeltaCount] = useState(0)
  // Monotonically-increasing ID incremented on every positive delta. The banner
  // effect in AppHeader depends on this rather than lastSyncDeltaCount so that
  // calling clearSyncDelta() (which resets the count to 0) does NOT flip the
  // effect's dependency and accidentally cancel the dismiss timer.
  const [syncEventId, setSyncEventId] = useState(0)
  const [pulsingSources, setPulsingSources] = useState<ReadonlySet<string>>(new Set())
  // R1 (ADR-0032 Amendment 1 / issue #377): live freshness threshold from server.
  // Defaults to 5 (the server constant) before the first successful poll.
  const [freshnessMinutes, setFreshnessMinutes] = useState(5)

  // ADR-0064 D2 additions:
  // dataVersion — increments by 1 only when delta > 0; never resets.
  const [dataVersion, setDataVersion] = useState(0)
  // grewSources — the source types that grew in the latest positive cycle.
  const [grewSources, setGrewSources] = useState<ReadonlySet<string>>(new Set())
  // lastDeltaCount — the net count for the latest positive cycle.
  const [lastDeltaCount, setLastDeltaCount] = useState(0)

  // Previous health items snapshot for delta computation — stored in a ref
  // so it doesn't trigger re-renders.
  const prevItemsRef = useRef<SourceHealthItem[]>([])
  // Track whether this is the first successful poll (no delta on the first fetch).
  const firstPollRef = useRef(true)
  // Cleanup ref for the pulse clear timer.
  const pulseTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const clearSyncDelta = () => setLastSyncDeltaCount(0)

  useEffect(() => {
    let cancelled = false

    function doRefresh() {
      fetchStats()
        .then((stats) => {
          if (cancelled) return

          const statsHealth = stats.source_health ?? []
          const items = toSourceHealthItems(statsHealth)
          // R1: capture freshness_minutes from the server response (ADR-0032 Amendment 1).
          if (typeof stats.freshness_minutes === 'number' && stats.freshness_minutes > 0) {
            setFreshnessMinutes(stats.freshness_minutes)
          }

          // Compute event-count delta against the previous snapshot.
          if (!firstPollRef.current) {
            const prevTotal = sumEventCounts(prevItemsRef.current)
            const nextTotal = sumEventCounts(items)
            const delta = nextTotal - prevTotal

            if (delta > 0) {
              setLastSyncDeltaCount(delta)
              // Increment the monotonic sync event id so the banner effect in
              // AppHeader can depend on a value that is never reset to 0.
              setSyncEventId((id) => id + 1)

              // Identify which source types gained new events.
              const newSources = sourcesWithNewEvents(prevItemsRef.current, items)
              setPulsingSources(newSources)

              // ADR-0064 D2: increment dataVersion only on positive delta.
              setDataVersion((v) => v + 1)
              // grewSources is the same set as pulsingSources but kept
              // separately so it stays stable after PULSE_CLEAR_MS clears
              // pulsingSources (pages may read grewSources between cycles).
              setGrewSources(new Set(newSources))
              setLastDeltaCount(delta)

              // Clear the pulse animation after PULSE_CLEAR_MS.
              if (pulseTimerRef.current !== null) {
                clearTimeout(pulseTimerRef.current)
              }
              pulseTimerRef.current = setTimeout(() => {
                if (!cancelled) setPulsingSources(new Set())
              }, PULSE_CLEAR_MS)
            }
          }

          prevItemsRef.current = items
          firstPollRef.current = false

          setHealthItems(items)
          setIsLive(true)
          setLastPollAt(new Date().toISOString())
        })
        .catch((err: unknown) => {
          if (cancelled) return
          // Leave healthItems unchanged (503-safe); signal LIVE as false.
          setIsLive(false)
          console.warn('[useStatsHeartbeat] GET /stats failed:', err)
        })
    }

    doRefresh()
    const t = setInterval(doRefresh, HEALTH_POLL_MS)

    return () => {
      cancelled = true
      clearInterval(t)
      if (pulseTimerRef.current !== null) {
        clearTimeout(pulseTimerRef.current)
      }
    }
  }, [])

  return {
    // ADR-0064 D2 additions
    dataVersion,
    grewSources,
    lastDeltaCount,
    // Header / freshness fields (carried through)
    healthItems,
    isLive,
    lastPollAt,
    lastSyncDeltaCount,
    syncEventId,
    pulsingSources,
    clearSyncDelta,
    freshnessMinutes,
  }
}
