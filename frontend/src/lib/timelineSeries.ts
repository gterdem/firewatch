/**
 * timelineSeries.ts — pure transforms for the Activity Timeline stacked bars.
 *
 * Consumes raw TimelineBucket[] from GET /logs/timeline and produces
 * flat stacked-segment arrays for each rendering mode:
 *   - "severity" mode  → four severity-keyed segments per bucket
 *   - "disposition" mode → blocked / allowed segments per bucket (free,
 *     derived from existing total/blocked — no refetch needed)
 *
 * Design:
 *   - All functions are pure (no side effects, no state).
 *   - Segment percentages are relative to the global maximum so that all
 *     bars share a common scale and the tallest bar fills 100%.
 *   - Zero-event buckets produce all-zero segments with a "no events" flag.
 *   - Attacker-controlled strings (top_source_ip, top_category) pass through
 *     as-is — they MUST be rendered as text nodes by the consumer (ADR-0029 D3).
 *
 * Issue #247.
 */

import type { TimelineBucket, BucketSeverityCounts } from '../api/types'

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** One coloured segment within a bar. pct is 0–100 relative to the global max. */
export interface BarSegment {
  key: string
  /** Absolute event count for this segment. */
  count: number
  /** Width percentage relative to the global maximum (0–100). */
  pct: number
  /** Tailwind / CSS class name for the colour token. */
  colorClass: string
}

/** One assembled bar row ready for rendering. */
export interface TimelineBarRow {
  /** Original bucket.hour value — passed to lib/time.ts by the component. */
  hour: string
  granularity: string
  total: number
  /** True when total === 0 (empty bucket — hover should say "no events"). */
  isEmpty: boolean
  segments: BarSegment[]
  /** Hover data (issue #247). Attacker-controlled strings; render as text only. */
  hover: BucketHoverData
}

/**
 * Rich per-bucket hover data (issue #247).
 * All string fields are attacker-controlled — render as text nodes (ADR-0029 D3).
 */
export interface BucketHoverData {
  total: number
  blocked: number
  allowed: number
  /** Most-frequent attack category in this bucket; null when none. */
  topCategory: string | null
  /**
   * Most-frequent source IP in this bucket; null when none.
   * SECURITY: attacker-controlled — render as text node (ADR-0029 D3).
   */
  topSourceIp: string | null
  /** Per-severity counts (fallback to zeros when backend omits them). */
  severity: BucketSeverityCounts
}

// ---------------------------------------------------------------------------
// Severity palette — DS severity token classes (issue #247).
// Ordered critical → high → medium → low (most-severe first, fills from left).
// ---------------------------------------------------------------------------

const SEVERITY_SEGMENTS: Array<{ key: keyof BucketSeverityCounts; colorClass: string; label: string }> = [
  { key: 'critical', colorClass: 'bg-soc-critical-fg',  label: 'Critical' },
  { key: 'high',     colorClass: 'bg-soc-high-fg',      label: 'High'     },
  { key: 'medium',   colorClass: 'bg-soc-medium-fg',    label: 'Medium'   },
  { key: 'low',      colorClass: 'bg-soc-low-fg',       label: 'Low'      },
]

// Disposition palette (already in the DS — kept here for co-location).
const DISPOSITION_BLOCKED_CLASS = 'bg-soc-enforced-fg'
const DISPOSITION_ALLOWED_CLASS  = 'bg-soc-ok-fg'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Zero-fill severity counts when the backend omits the additive field. */
function resolveSeverity(bucket: TimelineBucket): BucketSeverityCounts {
  return bucket.severity ?? { critical: 0, high: 0, medium: 0, low: 0 }
}

function buildHover(bucket: TimelineBucket): BucketHoverData {
  return {
    total:       bucket.total,
    blocked:     bucket.blocked,
    allowed:     bucket.total - bucket.blocked,
    topCategory: bucket.top_category ?? null,
    topSourceIp: bucket.top_source_ip ?? null,
    severity:    resolveSeverity(bucket),
  }
}

function makePct(count: number, globalMax: number): number {
  if (globalMax === 0) return 0
  return Math.round((count / globalMax) * 100)
}

// ---------------------------------------------------------------------------
// Public transforms
// ---------------------------------------------------------------------------

/**
 * Build severity-stacked bar rows.
 *
 * Each bucket becomes four coloured segments in order: critical, high,
 * medium, low.  Segments are proportioned relative to the global maximum
 * so that visual width encodes magnitude consistently across all buckets.
 */
export function buildSeverityRows(buckets: TimelineBucket[]): TimelineBarRow[] {
  const globalMax = Math.max(...buckets.map((b) => b.total), 1)

  return buckets.map((bucket): TimelineBarRow => {
    const sev = resolveSeverity(bucket)
    const segments: BarSegment[] = SEVERITY_SEGMENTS.map((def) => ({
      key:        def.key,
      count:      sev[def.key],
      pct:        makePct(sev[def.key], globalMax),
      colorClass: def.colorClass,
    }))

    return {
      hour:        bucket.hour,
      granularity: bucket.granularity ?? 'hourly',
      total:       bucket.total,
      isEmpty:     bucket.total === 0,
      segments,
      hover:       buildHover(bucket),
    }
  })
}

/**
 * Build disposition-stacked bar rows (blocked vs allowed).
 *
 * Derived entirely from existing bucket.total / bucket.blocked — no refetch.
 * This is the "free" mode described in the issue spec.
 */
export function buildDispositionRows(buckets: TimelineBucket[]): TimelineBarRow[] {
  const globalMax = Math.max(...buckets.map((b) => b.total), 1)

  return buckets.map((bucket): TimelineBarRow => {
    const allowed = bucket.total - bucket.blocked
    const segments: BarSegment[] = [
      {
        key:        'blocked',
        count:      bucket.blocked,
        pct:        makePct(bucket.blocked, globalMax),
        colorClass: DISPOSITION_BLOCKED_CLASS,
      },
      {
        key:        'allowed',
        count:      allowed,
        pct:        makePct(allowed, globalMax),
        colorClass: DISPOSITION_ALLOWED_CLASS,
      },
    ]

    return {
      hour:        bucket.hour,
      granularity: bucket.granularity ?? 'hourly',
      total:       bucket.total,
      isEmpty:     bucket.total === 0,
      segments,
      hover:       buildHover(bucket),
    }
  })
}

/**
 * Severity segment metadata (key, label, colorClass) — exported so the
 * legend component can render the correct tokens without re-declaring them.
 */
export const SEVERITY_LEGEND = SEVERITY_SEGMENTS.map(({ key, label, colorClass }) => ({
  key,
  label,
  colorClass,
}))

export const DISPOSITION_LEGEND = [
  { key: 'blocked', label: 'Blocked', colorClass: DISPOSITION_BLOCKED_CLASS },
  { key: 'allowed', label: 'Allowed', colorClass: DISPOSITION_ALLOWED_CLASS  },
]
