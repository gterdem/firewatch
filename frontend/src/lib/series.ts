/**
 * lib/series.ts — Pure helpers for UTC-bucketed numeric series (issue #245).
 *
 * Used by Sparkline and its consumers: Risk Movers (P8), KPI strip (P10),
 * spike-annotation context (P7).
 *
 * Contract:
 *   - Series points arrive as `{ t: string, value: number }` where `t` is a
 *     UTC ISO bucket key — either offset-bearing ("2026-06-11T04:00Z") or
 *     tz-naive ("2026-06-11T04:00", "2026-06-11"). Tz-naive keys are always
 *     UTC per the server contract.
 *   - `parseApiTimestamp` (lib/time.ts) is the single seam for string→Date;
 *     no raw `new Date(s)` calls here.
 *
 * All functions are pure (no side-effects, no fetching).
 */

import { parseApiTimestamp } from './time'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SeriesPoint {
  /** UTC ISO bucket key — offset-bearing or tz-naive. */
  t: string
  /** Numeric value for this bucket. */
  value: number
}

export interface NormalizedPoint {
  /** UTC millisecond timestamp (from parseApiTimestamp). */
  ts: number
  /** Raw value. */
  value: number
  /** 0–1 normalized value; 0 when all values are equal. */
  norm: number
}

export type TrendDirection = 'rising' | 'falling' | 'flat'

// ---------------------------------------------------------------------------
// fillGaps — insert zero-value synthetic points for missing buckets
// ---------------------------------------------------------------------------

/**
 * Given a sparse series and a list of canonical bucket keys (in order),
 * return a dense series with zero-filled gaps.
 *
 * `buckets` must be supplied by the consumer; the gap-filler does not
 * attempt to infer the bucket stride (hourly vs daily etc.) from the data
 * to keep this function pure and dependency-free.
 *
 * Usage:
 *   const dense = fillGaps(sparseSeries, allBuckets)
 *
 * @param series    - Input (possibly sparse) series. Order does not matter.
 * @param buckets   - All expected bucket keys in desired display order.
 * @returns         - Dense series with one point per bucket, missing → 0.
 */
export function fillGaps(series: SeriesPoint[], buckets: string[]): SeriesPoint[] {
  const lookup = new Map<string, number>()
  for (const p of series) {
    // Normalize to UTC millisecond key for matching
    const ms = parseApiTimestamp(p.t).getTime()
    if (!isNaN(ms)) {
      lookup.set(ms.toString(), p.value)
    }
  }

  return buckets.map((t) => {
    const ms = parseApiTimestamp(t).getTime()
    const value = isNaN(ms) ? 0 : (lookup.get(ms.toString()) ?? 0)
    return { t, value }
  })
}

// ---------------------------------------------------------------------------
// buildDenseSeries — parse + sort + gap-fill in one call
// ---------------------------------------------------------------------------

/**
 * Take an arbitrary (possibly sparse, possibly unsorted) series, sort it by
 * UTC time, derive the canonical bucket list, and gap-fill.
 *
 * This is the preferred entry-point for Sparkline consumers that do not
 * already have the canonical bucket list.
 *
 * @param series  - Input points, may be sparse and unsorted.
 * @returns       - Dense, sorted series covering all inferred buckets.
 */
export function buildDenseSeries(series: SeriesPoint[]): SeriesPoint[] {
  if (series.length === 0) return []

  // Parse and sort by UTC instant
  const parsed = series
    .map((p) => ({ ...p, ms: parseApiTimestamp(p.t).getTime() }))
    .filter((p) => !isNaN(p.ms))
    .sort((a, b) => a.ms - b.ms)

  if (parsed.length === 0) return []

  // Build the canonical bucket list from the sorted parsed set
  // (assumes the series already includes all intended buckets; callers that
  //  know about additional empty buckets should use fillGaps directly)
  const buckets = parsed.map((p) => p.t)
  return fillGaps(series, buckets)
}

// ---------------------------------------------------------------------------
// windowDelta — signed change between first and last value in a series
// ---------------------------------------------------------------------------

/**
 * Return the signed change (last.value - first.value) over the series.
 *
 * Returns 0 for empty or single-point series.
 */
export function windowDelta(series: SeriesPoint[]): number {
  if (series.length < 2) return 0
  return series[series.length - 1].value - series[0].value
}

// ---------------------------------------------------------------------------
// trendDirection — classify rising/falling/flat
// ---------------------------------------------------------------------------

/**
 * Classify the overall trend as 'rising', 'falling', or 'flat'.
 *
 * 'flat' when the absolute delta is 0 or when the series has < 2 points.
 */
export function trendDirection(series: SeriesPoint[]): TrendDirection {
  const delta = windowDelta(series)
  if (delta > 0) return 'rising'
  if (delta < 0) return 'falling'
  return 'flat'
}

// ---------------------------------------------------------------------------
// minMaxNormalize — normalize values to 0–1 for SVG rendering
// ---------------------------------------------------------------------------

/**
 * Normalize each point's value to the [0, 1] range based on the series
 * min and max. Returns `norm: 0` for all points when the series is
 * constant (max === min) to produce a flat midline rather than crashing.
 *
 * @param series  - Dense series (after gap-fill).
 * @returns       - Array of NormalizedPoint with ts, value, norm fields.
 */
export function minMaxNormalize(series: SeriesPoint[]): NormalizedPoint[] {
  if (series.length === 0) return []

  const values = series.map((p) => p.value)
  const min = Math.min(...values)
  const max = Math.max(...values)
  const range = max - min

  return series.map((p) => ({
    ts: parseApiTimestamp(p.t).getTime(),
    value: p.value,
    norm: range === 0 ? 0 : (p.value - min) / range,
  }))
}

// ---------------------------------------------------------------------------
// trendAriaLabel — build an accessible aria-label for a sparkline
// ---------------------------------------------------------------------------

/**
 * Build an aria-label string summarizing the trend for screen readers.
 *
 * Examples:
 *   "Trend: rising, +38 over 24 points"
 *   "Trend: falling, -12 over 6 points"
 *   "Trend: flat over 12 points"
 *   "Trend: no data"
 *
 * Trend direction is ALSO communicated by the directional text (not by
 * color alone) to satisfy WCAG 1.4.1 (use of color).
 */
export function trendAriaLabel(series: SeriesPoint[], label?: string): string {
  if (series.length === 0) return label ? `${label}: no data` : 'Trend: no data'

  const prefix = label ? `${label}: ` : 'Trend: '
  const dir = trendDirection(series)
  const delta = windowDelta(series)
  const n = series.length

  if (dir === 'flat') {
    return `${prefix}flat over ${n} point${n === 1 ? '' : 's'}`
  }

  const sign = delta > 0 ? '+' : ''
  return `${prefix}${dir}, ${sign}${delta} over ${n} point${n === 1 ? '' : 's'}`
}
