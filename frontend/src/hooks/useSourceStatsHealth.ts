/**
 * useSourceStatsHealth — one-time (non-polling) fetch of GET /stats to resolve
 * the server-computed `health` field (ADR-0032 §B) for each installed source.
 *
 * Used by SettingsList to supply server health values to each SourceCard without
 * double-polling.  The AppHeader already polls /stats on a 30 s interval via
 * useHeaderRefresh; this hook fires a single fetch when the Settings page mounts.
 * Both reads are independent: the AppHeader manages its own poller; the Settings
 * page needs health exactly once per visit (the card dot doesn't need to animate
 * live — it is a static diagnostic color, not a live stream).
 *
 * Returns two lookup functions:
 *   `getHealth(source_type) → server health string | null`  — kept for backward compat
 *   `getHealthItem(source_type) → SourceHealthItem | null`  — full item including
 *     event_count and last_event_at for the card's "Events" and "Last event" fields.
 *
 * Returns null per-source while loading or if the fetch fails — SourceCard treats
 * null as "unavailable" and falls back gracefully to idle/grey (not red).
 *
 * Multi-instance aggregation: when a source type has multiple instances:
 *   - health: worst-of across instances (consistent with header dot, ADR-0032 §C)
 *   - event_count: summed across instances (total events for the type)
 *   - last_event_at: most-recent across instances (most recent actual event)
 *
 * ADR-0032 Decision C: the dot color is driven by server-computed `health`.
 * ADR-0026: loopback-only; no off-host request.
 */

import { useEffect, useRef, useState } from 'react'
import { fetchStats } from '../api/client'
import { toSourceHealthItems } from '../lib/sourceHealth'
import type { SourceHealthItem } from '../lib/sourceHealth'

/** Lookup function: source_type → server health string | null */
export type SourceHealthLookup = (sourceType: string) => string | null

/** Lookup function: source_type → full SourceHealthItem | null */
export type SourceHealthItemLookup = (sourceType: string) => SourceHealthItem | null

/** State returned by the hook. */
export interface UseSourceStatsHealthResult {
  /** Lookup server health by source_type. Returns null until fetched / if fetch fails. */
  getHealth: SourceHealthLookup
  /**
   * Lookup the full SourceHealthItem for a source_type.
   * Returns null until the fetch settles or if the fetch fails.
   * Use this to populate "Events" (event_count) and "Last event" (last_event_at) in the card.
   */
  getHealthItem: SourceHealthItemLookup
  /** True once the first fetch has settled (success or failure). */
  settled: boolean
}

/** Severity rank for worst-of aggregation (ADR-0032 §C). */
const HEALTH_RANK: Record<string, number> = { red: 3, amber: 2, not_configured: 1, ok: 0 }

/**
 * Fetch GET /stats once and expose health lookups keyed by source_type.
 * On error: `settled` becomes true, lookups return null for all types.
 */
export function useSourceStatsHealth(): UseSourceStatsHealthResult {
  // Map from source_type → aggregated SourceHealthItem — populated after the first fetch.
  const itemMapRef = useRef<Map<string, SourceHealthItem>>(new Map())
  const [settled, setSettled] = useState(false)

  useEffect(() => {
    let cancelled = false

    fetchStats()
      .then((stats) => {
        if (cancelled) return
        const items = toSourceHealthItems(stats.source_health ?? [])
        const map = new Map<string, SourceHealthItem>()

        for (const item of items) {
          const existing = map.get(item.sourceType)
          if (!existing) {
            // First instance for this type — store a copy so we can mutate safely.
            map.set(item.sourceType, { ...item })
          } else {
            // Multi-instance aggregation (ADR-0032 §C):
            //   health:       worst-of (red > amber > not_configured > ok)
            //   eventCount:   sum across all instances
            //   lastEventAt:  most-recent across all instances
            const existingRank = HEALTH_RANK[existing.health] ?? 0
            const newRank = HEALTH_RANK[item.health] ?? 0
            existing.health = newRank > existingRank ? item.health : existing.health
            existing.eventCount = (existing.eventCount ?? 0) + (item.eventCount ?? 0)
            // Keep the most-recent lastEventAt
            if (item.lastEventAt) {
              if (!existing.lastEventAt || item.lastEventAt > existing.lastEventAt) {
                existing.lastEventAt = item.lastEventAt
              }
            }
          }
        }

        itemMapRef.current = map
        setSettled(true)
      })
      .catch(() => {
        if (!cancelled) setSettled(true) // settled=true; map stays empty → null for all types
      })

    return () => {
      cancelled = true
    }
  }, [])

  const getHealth: SourceHealthLookup = (sourceType: string) =>
    itemMapRef.current.get(sourceType)?.health ?? null

  const getHealthItem: SourceHealthItemLookup = (sourceType: string) =>
    itemMapRef.current.get(sourceType) ?? null

  return { getHealth, getHealthItem, settled }
}
