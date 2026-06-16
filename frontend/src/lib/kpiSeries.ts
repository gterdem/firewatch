/**
 * lib/kpiSeries.ts — KPI-strip series derivation helpers (issue #254).
 *
 * Derives per-KPI time series from the GET /logs/timeline bucket array
 * (the same data already fetched for the Activity Timeline chart).
 *
 * Contract:
 *   - Input: TimelineBucket[] from GET /logs/timeline — each bucket carries
 *     `hour` (UTC ISO, tz-naive = UTC), `total`, and `blocked`.
 *   - Output: SeriesPoint[] ready for the Sparkline component.
 *
 * KPI gaps (no derivable series from the current API):
 *   - "Unique IPs" — GET /logs/timeline does not include a per-bucket IP count.
 *     Flagged to architect; KpiTile renders number-only for this KPI.
 *
 * All functions are pure — no fetching, no side-effects.
 * Series are built against SeriesPoint (lib/series.ts) for Sparkline compatibility.
 */

import type { TimelineBucket } from '../api/types'
import type { SeriesPoint } from './series'

/**
 * Derive a total-events series from timeline buckets.
 * Maps each bucket's `total` to a SeriesPoint keyed by `hour`.
 *
 * @param buckets  - GET /logs/timeline response array.
 * @returns        - SeriesPoint[] aligned to timeline bucket keys.
 */
export function totalEventsSeries(buckets: TimelineBucket[]): SeriesPoint[] {
  return buckets.map((b) => ({ t: b.hour, value: b.total }))
}

/**
 * Derive a blocked-events series from timeline buckets.
 * Maps each bucket's `blocked` to a SeriesPoint keyed by `hour`.
 *
 * @param buckets  - GET /logs/timeline response array.
 * @returns        - SeriesPoint[] aligned to timeline bucket keys.
 */
export function blockedEventsSeries(buckets: TimelineBucket[]): SeriesPoint[] {
  return buckets.map((b) => ({ t: b.hour, value: b.blocked }))
}

/**
 * Derive a block-rate series (%) from timeline buckets.
 * Block rate = (blocked / total) * 100, rounded to nearest integer.
 * Buckets with total=0 produce a zero-value point to avoid NaN/Infinity.
 *
 * @param buckets  - GET /logs/timeline response array.
 * @returns        - SeriesPoint[] of block-rate percentages.
 */
export function blockRateSeries(buckets: TimelineBucket[]): SeriesPoint[] {
  return buckets.map((b) => ({
    t: b.hour,
    value: b.total === 0 ? 0 : Math.round((b.blocked / b.total) * 100),
  }))
}

/**
 * NOTE — "Unique IPs" KPI has no derivable series:
 * GET /logs/timeline does not include a per-bucket IP count.
 * KpiTile for "Unique IPs" renders number-only with no sparkline.
 * Flagged to architect for potential future contract extension.
 */
