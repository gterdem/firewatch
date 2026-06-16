/**
 * Tests for lib/series.ts — UTC-bucketed series helpers (issue #245).
 *
 * EARS acceptance criteria covered:
 *
 * 1. fillGaps: WHEN buckets are missing from the series, fillGaps SHALL
 *    return zero-valued points for the missing buckets.
 *
 * 2. fillGaps: tz-naive bucket keys SHALL be interpreted as UTC (not local)
 *    when matching against the canonical bucket list.
 *
 * 3. buildDenseSeries: sorts the input by UTC time and gap-fills in one call.
 *
 * 4. windowDelta: returns last.value - first.value; 0 for <2 points.
 *
 * 5. trendDirection: classifies rising/falling/flat from the delta.
 *
 * 6. minMaxNormalize:
 *    - normalizes values to [0, 1];
 *    - returns norm=0 for all-equal (flat/constant) series;
 *    - empty input → empty output.
 *
 * 7. trendAriaLabel:
 *    - empty series → "Trend: no data";
 *    - rising → contains "rising" and "+" delta;
 *    - falling → contains "falling" and negative delta;
 *    - flat → contains "flat";
 *    - optional label prefix included.
 *
 * Fixtures:
 *   flat     — all same value
 *   spike    — one high outlier
 *   ramp     — monotonically increasing
 *   sparse   — missing a middle bucket
 *   single   — one point only
 *   empty    — zero points
 *   tznaive  — keys without offset; must match Z-suffixed equivalents
 */

import { describe, it, expect } from 'vitest'
import {
  fillGaps,
  buildDenseSeries,
  windowDelta,
  trendDirection,
  minMaxNormalize,
  trendAriaLabel,
} from '../lib/series'
import type { SeriesPoint } from '../lib/series'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const FLAT: SeriesPoint[] = [
  { t: '2026-06-11T00:00Z', value: 5 },
  { t: '2026-06-11T01:00Z', value: 5 },
  { t: '2026-06-11T02:00Z', value: 5 },
]

const RAMP: SeriesPoint[] = [
  { t: '2026-06-11T00:00Z', value: 0 },
  { t: '2026-06-11T01:00Z', value: 10 },
  { t: '2026-06-11T02:00Z', value: 20 },
  { t: '2026-06-11T03:00Z', value: 30 },
]

const SPIKE: SeriesPoint[] = [
  { t: '2026-06-11T00:00Z', value: 2 },
  { t: '2026-06-11T01:00Z', value: 40 },
  { t: '2026-06-11T02:00Z', value: 3 },
]

// Sparse: bucket 01:00 is missing
const SPARSE_DATA: SeriesPoint[] = [
  { t: '2026-06-11T00:00Z', value: 10 },
  { t: '2026-06-11T02:00Z', value: 30 },
]
const SPARSE_BUCKETS = [
  '2026-06-11T00:00Z',
  '2026-06-11T01:00Z',
  '2026-06-11T02:00Z',
]

const SINGLE: SeriesPoint[] = [{ t: '2026-06-11T00:00Z', value: 7 }]

const EMPTY: SeriesPoint[] = []

// Tz-naive keys (no Z / offset) — must be treated as UTC
const TZNAIVE: SeriesPoint[] = [
  { t: '2026-06-11T00:00', value: 1 },
  { t: '2026-06-11T01:00', value: 2 },
]

// ---------------------------------------------------------------------------
// fillGaps
// ---------------------------------------------------------------------------

describe('fillGaps — zero-fill missing buckets', () => {
  it('returns the same series when all buckets are present', () => {
    const result = fillGaps(RAMP, RAMP.map((p) => p.t))
    expect(result).toHaveLength(RAMP.length)
    result.forEach((p, i) => {
      expect(p.value).toBe(RAMP[i].value)
    })
  })

  it('inserts zero for the missing bucket (sparse series)', () => {
    const result = fillGaps(SPARSE_DATA, SPARSE_BUCKETS)
    expect(result).toHaveLength(3)
    // Bucket at index 1 (01:00) is missing → value must be 0
    expect(result[1].t).toBe('2026-06-11T01:00Z')
    expect(result[1].value).toBe(0)
  })

  it('preserves present values around the gap', () => {
    const result = fillGaps(SPARSE_DATA, SPARSE_BUCKETS)
    expect(result[0].value).toBe(10)
    expect(result[2].value).toBe(30)
  })

  it('returns all-zero output for empty series against bucket list', () => {
    const result = fillGaps([], SPARSE_BUCKETS)
    expect(result).toHaveLength(3)
    result.forEach((p) => expect(p.value).toBe(0))
  })

  it('returns empty array when bucket list is empty', () => {
    const result = fillGaps(RAMP, [])
    expect(result).toHaveLength(0)
  })

  it('tz-naive bucket key in series matches Z-suffixed canonical bucket', () => {
    // Series has naive key; bucket list has Z-suffixed key — should match.
    const series: SeriesPoint[] = [{ t: '2026-06-11T00:00', value: 99 }]
    const buckets = ['2026-06-11T00:00Z']
    const result = fillGaps(series, buckets)
    expect(result[0].value).toBe(99)
  })

  it('Z-suffixed bucket key in series matches naive canonical bucket', () => {
    // Series has Z key; canonical bucket list has naive key.
    const series: SeriesPoint[] = [{ t: '2026-06-11T01:00Z', value: 77 }]
    const buckets = ['2026-06-11T01:00']
    const result = fillGaps(series, buckets)
    expect(result[0].value).toBe(77)
  })
})

// ---------------------------------------------------------------------------
// buildDenseSeries
// ---------------------------------------------------------------------------

describe('buildDenseSeries — sort + gap-fill in one call', () => {
  it('returns empty for empty input', () => {
    expect(buildDenseSeries([])).toHaveLength(0)
  })

  it('sorts an unsorted input by UTC time', () => {
    const unsorted: SeriesPoint[] = [
      { t: '2026-06-11T02:00Z', value: 3 },
      { t: '2026-06-11T00:00Z', value: 1 },
      { t: '2026-06-11T01:00Z', value: 2 },
    ]
    const result = buildDenseSeries(unsorted)
    expect(result).toHaveLength(3)
    expect(result[0].value).toBe(1)
    expect(result[1].value).toBe(2)
    expect(result[2].value).toBe(3)
  })

  it('handles a tz-naive series and produces the correct order', () => {
    const result = buildDenseSeries(TZNAIVE)
    expect(result).toHaveLength(2)
    expect(result[0].value).toBe(1)
    expect(result[1].value).toBe(2)
  })

  it('single-point series returns that single point', () => {
    const result = buildDenseSeries(SINGLE)
    expect(result).toHaveLength(1)
    expect(result[0].value).toBe(7)
  })
})

// ---------------------------------------------------------------------------
// windowDelta
// ---------------------------------------------------------------------------

describe('windowDelta — signed change first→last', () => {
  it('returns 0 for empty series', () => {
    expect(windowDelta(EMPTY)).toBe(0)
  })

  it('returns 0 for single-point series', () => {
    expect(windowDelta(SINGLE)).toBe(0)
  })

  it('returns positive delta for rising ramp', () => {
    expect(windowDelta(RAMP)).toBe(30)
  })

  it('returns 0 for flat series', () => {
    expect(windowDelta(FLAT)).toBe(0)
  })

  it('returns negative delta for falling series', () => {
    const falling: SeriesPoint[] = [
      { t: '2026-06-11T00:00Z', value: 100 },
      { t: '2026-06-11T01:00Z', value: 50 },
      { t: '2026-06-11T02:00Z', value: 20 },
    ]
    expect(windowDelta(falling)).toBe(-80)
  })

  it('spike: net delta is last-first, not peak', () => {
    // SPIKE: 2→40→3, net = 3-2 = +1
    expect(windowDelta(SPIKE)).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// trendDirection
// ---------------------------------------------------------------------------

describe('trendDirection — rising/falling/flat', () => {
  it('flat series → flat', () => {
    expect(trendDirection(FLAT)).toBe('flat')
  })

  it('rising ramp → rising', () => {
    expect(trendDirection(RAMP)).toBe('rising')
  })

  it('falling series → falling', () => {
    const falling: SeriesPoint[] = [
      { t: '2026-06-11T00:00Z', value: 100 },
      { t: '2026-06-11T01:00Z', value: 10 },
    ]
    expect(trendDirection(falling)).toBe('falling')
  })

  it('empty series → flat', () => {
    expect(trendDirection(EMPTY)).toBe('flat')
  })

  it('single-point → flat', () => {
    expect(trendDirection(SINGLE)).toBe('flat')
  })
})

// ---------------------------------------------------------------------------
// minMaxNormalize
// ---------------------------------------------------------------------------

describe('minMaxNormalize — 0–1 normalization', () => {
  it('empty input returns empty array', () => {
    expect(minMaxNormalize([])).toHaveLength(0)
  })

  it('single point normalizes to norm=0 (constant series)', () => {
    const result = minMaxNormalize(SINGLE)
    expect(result).toHaveLength(1)
    expect(result[0].norm).toBe(0)
  })

  it('flat series returns norm=0 for all points (no divide-by-zero)', () => {
    const result = minMaxNormalize(FLAT)
    result.forEach((p) => {
      expect(p.norm).toBe(0)
    })
  })

  it('ramp: min value → norm=0, max value → norm=1', () => {
    const result = minMaxNormalize(RAMP)
    expect(result[0].norm).toBe(0)    // value=0, min
    expect(result[result.length - 1].norm).toBe(1)  // value=30, max
  })

  it('ramp: intermediate points are correctly normalized', () => {
    const result = minMaxNormalize(RAMP)
    // value=10, min=0, max=30 → norm=10/30=0.333...
    expect(result[1].norm).toBeCloseTo(1 / 3, 5)
    // value=20 → norm=20/30=0.666...
    expect(result[2].norm).toBeCloseTo(2 / 3, 5)
  })

  it('spike: the spike point is norm=1, others < 1', () => {
    const result = minMaxNormalize(SPIKE)
    // SPIKE values: 2, 40, 3. max=40 → norm=1
    expect(result[1].norm).toBe(1)
    // min=2 → norm=0; value=3 → norm=(3-2)/(40-2)=1/38
    expect(result[0].norm).toBe(0)
    expect(result[2].norm).toBeCloseTo(1 / 38, 5)
  })

  it('preserves ts (UTC ms) and value in each normalized point', () => {
    const result = minMaxNormalize(RAMP)
    expect(typeof result[0].ts).toBe('number')
    expect(result[0].value).toBe(0)
    expect(result[1].value).toBe(10)
  })
})

// ---------------------------------------------------------------------------
// trendAriaLabel
// ---------------------------------------------------------------------------

describe('trendAriaLabel — accessible summary string', () => {
  it('empty series → "Trend: no data"', () => {
    expect(trendAriaLabel([])).toBe('Trend: no data')
  })

  it('empty series with label → "<label>: no data"', () => {
    expect(trendAriaLabel([], 'Requests')).toBe('Requests: no data')
  })

  it('single-point series → flat description', () => {
    const label = trendAriaLabel(SINGLE)
    expect(label).toContain('flat')
  })

  it('flat series → "Trend: flat over N points"', () => {
    const label = trendAriaLabel(FLAT)
    expect(label).toContain('flat')
    expect(label).toContain('3 points')
  })

  it('rising ramp → contains "rising" and positive delta', () => {
    const label = trendAriaLabel(RAMP)
    expect(label).toContain('rising')
    expect(label).toContain('+30')
  })

  it('falling series → contains "falling" and negative delta', () => {
    const falling: SeriesPoint[] = [
      { t: '2026-06-11T00:00Z', value: 50 },
      { t: '2026-06-11T01:00Z', value: 20 },
    ]
    const label = trendAriaLabel(falling)
    expect(label).toContain('falling')
    expect(label).toContain('-30')
  })

  it('label prefix is prepended when provided', () => {
    const label = trendAriaLabel(RAMP, 'Blocked')
    expect(label.startsWith('Blocked:')).toBe(true)
    expect(label).toContain('rising')
  })

  it('trend direction is in text (not only color)', () => {
    // WCAG 1.4.1: direction must not be conveyed by color alone.
    // The aria-label must carry the direction word.
    const rising = trendAriaLabel(RAMP)
    const falling = trendAriaLabel([
      { t: '2026-06-11T00:00Z', value: 10 },
      { t: '2026-06-11T01:00Z', value: 2 },
    ])
    expect(rising).toMatch(/rising|falling|flat/)
    expect(falling).toMatch(/rising|falling|flat/)
    expect(rising).not.toBe(falling)
  })
})

// ---------------------------------------------------------------------------
// UTC correctness (tz-naive key regression)
// ---------------------------------------------------------------------------

describe('series UTC correctness — tz-naive keys treated as UTC', () => {
  it('tz-naive and Z-suffixed keys for the same instant match in fillGaps', () => {
    // The series has a naive key; the canonical bucket has a Z key.
    // They MUST match (represent the same UTC instant), so the value is preserved.
    const series: SeriesPoint[] = [{ t: '2026-06-11T06:00', value: 42 }]
    const buckets = ['2026-06-11T06:00Z']
    const result = fillGaps(series, buckets)
    // If naive was treated as local (e.g. UTC-5 → 11:00Z) they would NOT match,
    // and the result would be 0 (gap-filled). A non-zero result proves UTC handling.
    expect(result[0].value).toBe(42)
  })

  it('minMaxNormalize uses UTC ms for ts field', () => {
    const series: SeriesPoint[] = [
      { t: '2026-06-11T00:00', value: 0 },
      { t: '2026-06-11T01:00', value: 1 },
    ]
    const result = minMaxNormalize(series)
    // Both ts values must be valid UTC milliseconds
    result.forEach((p) => {
      expect(isNaN(p.ts)).toBe(false)
      expect(p.ts).toBeGreaterThan(0)
    })
    // 01:00Z must be exactly 3600 seconds after 00:00Z
    expect(result[1].ts - result[0].ts).toBe(3600 * 1000)
  })
})
