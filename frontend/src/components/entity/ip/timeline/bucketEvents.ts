/**
 * bucketEvents — pure clustering logic for the accordion timeline (issue #270).
 *
 * Separates timeline events into:
 *   - Notable events: correlated source transitions, first seen, last seen,
 *     or first firing of a new rule. Always rendered expanded, chronologically.
 *   - Routine events: collapsed into time-bucketed cluster rows labeled with
 *     bucket window · event count · distinct rules · dominant disposition.
 *
 * PURE module — no React, no side effects.
 * Time formatting goes through lib/time seam (#244).
 *
 * Bucket size: 1 hour (3600 seconds). Matches the default granularity used
 * in the dashboard timeline chart (EARS: "09:00–10:00 · 47 events · 3 rules").
 *
 * ADR-0029 D3: all label/payload values stay as raw strings for callers to
 * render as text nodes only — no sanitisation applied here.
 *
 * Notable-event detection criteria (EARS):
 *   1. correlated=true — cross-source event.
 *   2. First event in the list (earliest time — "first seen").
 *   3. Last event in the list (latest time — "last seen").
 *   4. First occurrence of a rule label not seen before in the sorted list
 *      ("first firing of a new rule").
 */

import { parseApiTimestamp, formatLocal } from '../../../../lib/time'
import type { IpTimelineEventItem } from '../../../../api/types'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface NotableEventEntry {
  kind: 'notable'
  event: IpTimelineEventItem
  /** Human-readable reason this event is notable (shown as a tag). */
  reason: 'first-seen' | 'last-seen' | 'correlated' | 'new-rule'
  /** Original index in the sorted events array (for keys). */
  index: number
}

export interface ClusterEntry {
  kind: 'cluster'
  /**
   * Bucket window label, e.g. "09:00–10:00".
   * Both start and end formatted through lib/time formatLocal (UTC-correct).
   */
  label: string
  /** Start of the bucket (UTC instant, for sorting). */
  startMs: number
  /** Total event count in this bucket. */
  count: number
  /** Distinct rule/label strings seen in this bucket. */
  distinctRules: number
  /** Dominant disposition: "BLOCK" if >50% are blocked, else "ALERT". */
  dominantDisposition: 'BLOCK' | 'ALERT'
  /** All events in this bucket (used when the user expands the cluster). */
  events: Array<{ event: IpTimelineEventItem; index: number }>
}

export type AccordionRow = NotableEventEntry | ClusterEntry

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BUCKET_MS = 60 * 60 * 1_000 // 1 hour

function bucketKey(eventTimeMs: number): number {
  return Math.floor(eventTimeMs / BUCKET_MS) * BUCKET_MS
}

// ---------------------------------------------------------------------------
// Main function
// ---------------------------------------------------------------------------

/**
 * Bucket events into an accordion-ready row list.
 *
 * Returns rows in ascending chronological order:
 *   - Notable events stay in their natural position.
 *   - Routine events are collapsed into hourly ClusterEntry rows.
 *   - A ClusterEntry is always inserted at the earliest event time in that bucket.
 *
 * @param events  Sorted ascending time-ordered events from the API.
 * @param notableThreshold  How many events triggers bucketing. Defaults to 10 —
 *   when total events ≤ threshold, all events become NotableRows (nothing to collapse).
 */
export function bucketEvents(
  events: IpTimelineEventItem[],
  notableThreshold = 10,
): AccordionRow[] {
  if (events.length === 0) return []

  // When the total is small enough, show every event as notable (first+last rules apply).
  if (events.length <= notableThreshold) {
    return events.map((event, index): NotableEventEntry => ({
      kind: 'notable',
      event,
      reason: detectReason(event, index, events),
      index,
    }))
  }

  // --- Detect notable events ---
  const notableIndexes = new Set<number>()
  // First and last (by position — caller must pass sorted events).
  notableIndexes.add(0)
  notableIndexes.add(events.length - 1)
  // Correlated events + new-rule events.
  const seenRules = new Set<string>()
  for (let i = 0; i < events.length; i++) {
    const ev = events[i]
    if (ev.correlated) notableIndexes.add(i)
    const ruleKey = ev.label ?? ''
    if (ruleKey && !seenRules.has(ruleKey)) {
      seenRules.add(ruleKey)
      notableIndexes.add(i)
    }
  }

  // --- Build rows: notable events stay as-is; routine events collapse into buckets ---
  // We accumulate per-bucket clusters as we iterate, merging adjacent routine events.
  const result: AccordionRow[] = []
  // pendingBuckets: bucket start-ms → ClusterEntry (in-progress accumulation)
  const pendingBuckets = new Map<number, ClusterEntry>()
  // Track insertion order (first time we encounter a bucket, it goes into result list).
  const bucketOrder: number[] = []

  function flushBucketAt(key: number) {
    // No-op: buckets are added to result lazily; they're already in result by ref.
    // This function is kept for clarity — nothing to flush eagerly.
    void key
  }

  for (let i = 0; i < events.length; i++) {
    const ev = events[i]
    if (notableIndexes.has(i)) {
      result.push({
        kind: 'notable',
        event: ev,
        reason: detectReason(ev, i, events),
        index: i,
      })
      continue
    }

    // Routine event — accumulate into its bucket.
    const timeMs = parseApiTimestamp(ev.time).getTime()
    const key = isNaN(timeMs) ? 0 : bucketKey(timeMs)

    if (pendingBuckets.has(key)) {
      const cluster = pendingBuckets.get(key)!
      cluster.count++
      cluster.events.push({ event: ev, index: i })
      const ruleSet = new Set(cluster.events.map((e) => e.event.label ?? '').filter(Boolean))
      cluster.distinctRules = ruleSet.size
      const blockCount = cluster.events.filter((e) => e.event.action === 'BLOCK').length
      cluster.dominantDisposition = blockCount > cluster.events.length / 2 ? 'BLOCK' : 'ALERT'
    } else {
      const startMs = key
      const endMs = key + BUCKET_MS
      const startDate = new Date(startMs)
      const endDate = new Date(endMs)
      const bucketLabel = `${formatLocal(startDate, 'time')}–${formatLocal(endDate, 'time')}`
      const cluster: ClusterEntry = {
        kind: 'cluster',
        label: bucketLabel,
        startMs,
        count: 1,
        distinctRules: ev.label ? 1 : 0,
        dominantDisposition: ev.action === 'BLOCK' ? 'BLOCK' : 'ALERT',
        events: [{ event: ev, index: i }],
      }
      pendingBuckets.set(key, cluster)
      bucketOrder.push(key)
      result.push(cluster)
    }

    flushBucketAt(key)
  }

  // Sort result rows chronologically.
  result.sort((a, b) => rowStartMs(a) - rowStartMs(b))

  return result
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function rowStartMs(row: AccordionRow): number {
  if (row.kind === 'cluster') return row.startMs
  const ms = parseApiTimestamp(row.event.time).getTime()
  return isNaN(ms) ? 0 : ms
}

/**
 * Detect the reason a notable event is notable.
 * Priority: first-seen > last-seen > correlated > new-rule.
 *
 * The `seenRules` set is the complete set after full traversal — used only
 * for correctness on the small-events path (all events are notable).
 */
function detectReason(
  event: IpTimelineEventItem,
  index: number,
  events: IpTimelineEventItem[],
): NotableEventEntry['reason'] {
  if (index === 0) return 'first-seen'
  if (index === events.length - 1) return 'last-seen'
  if (event.correlated) return 'correlated'
  return 'new-rule'
}
