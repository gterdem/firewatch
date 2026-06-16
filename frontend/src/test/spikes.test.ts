/**
 * Tests for lib/spikes.ts — deterministic spike detection (issue #248).
 *
 * EARS acceptance criteria covered:
 *
 * 1. UBIQUITOUS: Detection SHALL be deterministic — same series → same marks.
 *    (verified by running detectSpikes twice and comparing outputs)
 *
 * 2. UBIQUITOUS: SHALL NOT flag any bucket on a flat series.
 *    (flat series fixture — no marks expected)
 *
 * 3. UBIQUITOUS: SHALL NOT flag any bucket on a smoothly-ramping series.
 *    (ramp fixture — no marks expected)
 *
 * 4. WHEN a bucket's value exceeds the spike threshold relative to the rolling
 *    window, a marker SHALL render at that bucket.
 *    (single genuine spike fixture — exactly one mark)
 *
 * 5. WHEN the series is shorter than the detection window, no markers SHALL
 *    render (no crash).
 *    (short series fixture, series.length <= window)
 *
 * 6. Sparse/zero-heavy buckets → no false marks.
 *    (all-zeros fixture)
 *
 * 7. SpikeMark shape — bucketIndex, ratio, value, windowMedian are correct.
 *
 * 8. detectSpikes is pure: no mutations to the input array.
 *
 * Note: IPs in fixtures use RFC-5737 ranges (192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24) per project convention (gitleaks gate).
 */

import { describe, it, expect } from 'vitest'
import { detectSpikes, DEFAULT_WINDOW, DEFAULT_K } from '../lib/spikes'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a flat series of length n with value v. */
function flat(n: number, v = 10): number[] {
  return Array.from({ length: n }, () => v)
}

/** Build a linear ramp from `start` to `end` (inclusive) with `steps` points. */
function ramp(start: number, end: number, steps: number): number[] {
  return Array.from({ length: steps }, (_, i) => {
    const t = steps === 1 ? 0 : i / (steps - 1)
    return Math.round(start + (end - start) * t)
  })
}

// ---------------------------------------------------------------------------
// 1. Determinism
// ---------------------------------------------------------------------------

describe('detectSpikes — determinism', () => {
  it('returns identical results on repeated calls with the same input', () => {
    const series = [...flat(6, 10), 120, ...flat(4, 10)]
    const a = detectSpikes(series)
    const b = detectSpikes(series)
    expect(a).toEqual(b)
  })

  it('returns empty array on repeated calls for a flat series', () => {
    const series = flat(20, 50)
    expect(detectSpikes(series)).toEqual([])
    expect(detectSpikes(series)).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// 2. Flat series — no marks
// ---------------------------------------------------------------------------

describe('detectSpikes — flat series', () => {
  it('produces no marks for a flat series of value 10 (length 20)', () => {
    expect(detectSpikes(flat(20, 10))).toHaveLength(0)
  })

  it('produces no marks for a flat series of value 1 (length 12)', () => {
    expect(detectSpikes(flat(12, 1))).toHaveLength(0)
  })

  it('produces no marks for a flat series of value 0 (all zeros, length 15)', () => {
    // All-zero window → MAD = 0 → skip; no false positives.
    expect(detectSpikes(flat(15, 0))).toHaveLength(0)
  })

  it('produces no marks for a flat series of value 100 (length 24)', () => {
    expect(detectSpikes(flat(24, 100))).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// 3. Smooth ramp — no marks
// ---------------------------------------------------------------------------

describe('detectSpikes — smooth ramp', () => {
  it('produces no marks for a linear ramp 10→100 over 20 points', () => {
    expect(detectSpikes(ramp(10, 100, 20))).toHaveLength(0)
  })

  it('produces no marks for a slow ramp 1→24 over 24 points', () => {
    expect(detectSpikes(ramp(1, 24, 24))).toHaveLength(0)
  })

  it('produces no marks for a descending ramp 100→10 over 20 points', () => {
    // A downward trend should not flag any bucket.
    expect(detectSpikes(ramp(100, 10, 20))).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// 4. Genuine spike — exactly one mark
// ---------------------------------------------------------------------------

describe('detectSpikes — single genuine spike', () => {
  it('flags the spike bucket when one bucket is far above the flat window', () => {
    // 6 flat baseline buckets (window = 6), then a spike, then quiet again.
    const series = [...flat(6, 10), 200, ...flat(5, 10)]
    const marks = detectSpikes(series)
    expect(marks).toHaveLength(1)
    expect(marks[0].bucketIndex).toBe(6)
  })

  it('spike mark has the correct value', () => {
    const series = [...flat(6, 10), 200, ...flat(5, 10)]
    const marks = detectSpikes(series)
    expect(marks[0].value).toBe(200)
  })

  it('spike mark has a positive ratio', () => {
    const series = [...flat(6, 10), 200, ...flat(5, 10)]
    const marks = detectSpikes(series)
    expect(marks[0].ratio).toBeGreaterThan(1)
  })

  it('spike mark ratio reflects magnitude vs window median', () => {
    // Window is all-10; spike is 200 → ratio = 200/10 = 20.
    const series = [...flat(6, 10), 200, ...flat(5, 10)]
    const marks = detectSpikes(series)
    // Allow small floating point tolerance.
    expect(marks[0].ratio).toBeCloseTo(20, 1)
  })

  it('windowMedian is set correctly on the spike mark', () => {
    const series = [...flat(6, 10), 200, ...flat(5, 10)]
    const marks = detectSpikes(series)
    expect(marks[0].windowMedian).toBe(10)
  })

  it('a bucket at k=3.5 exactly on the threshold is NOT flagged (strictly greater)', () => {
    // Flat window of 10s → MAD = 0 → the threshold check is skipped.
    // Use a window with slight variation to get a non-zero MAD.
    // Window: [8, 9, 10, 10, 11, 12] → median = 10, MAD = 1
    // threshold = 10 + 3.5 * 1 = 13.5 → bucket = 13 should NOT be flagged.
    const series = [8, 9, 10, 10, 11, 12, 13]
    const marks = detectSpikes(series)
    expect(marks).toHaveLength(0)
  })

  it('a bucket just above the threshold IS flagged', () => {
    // Window: [8, 9, 10, 10, 11, 12] → median = 10, MAD = 1, threshold = 13.5
    // bucket = 14 should be flagged.
    const series = [8, 9, 10, 10, 11, 12, 14]
    const marks = detectSpikes(series)
    expect(marks).toHaveLength(1)
    expect(marks[0].bucketIndex).toBe(6)
  })
})

// ---------------------------------------------------------------------------
// 5. Series shorter than window — no marks, no crash
// ---------------------------------------------------------------------------

describe('detectSpikes — series shorter than window', () => {
  it('returns empty array for empty series', () => {
    expect(detectSpikes([])).toHaveLength(0)
  })

  it('returns empty array for series of length 1', () => {
    expect(detectSpikes([999])).toHaveLength(0)
  })

  it('returns empty array for series exactly equal to window length', () => {
    // DEFAULT_WINDOW = 6; series.length === 6 → no candidate buckets (need length > 6).
    expect(detectSpikes(flat(DEFAULT_WINDOW, 10))).toHaveLength(0)
  })

  it('returns empty array for series one shorter than window', () => {
    expect(detectSpikes(flat(DEFAULT_WINDOW - 1, 10))).toHaveLength(0)
  })

  it('does NOT throw for a series shorter than the default window', () => {
    expect(() => detectSpikes([5, 3, 7])).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// 6. Sparse / zero-heavy buckets — no false marks
// ---------------------------------------------------------------------------

describe('detectSpikes — sparse/zero-heavy buckets', () => {
  it('all-zero buckets produce no marks', () => {
    expect(detectSpikes(flat(20, 0))).toHaveLength(0)
  })

  it('mostly-zero buckets with small non-zero values produce no marks', () => {
    // Intersperse tiny values; no genuine spike.
    const series = [0, 0, 1, 0, 0, 2, 0, 1, 0, 0, 0, 1, 0, 0]
    expect(detectSpikes(series)).toHaveLength(0)
  })

  it('a large value after an all-zero window IS detected via the MAD floor', () => {
    // Window all-zeros → MAD = 0 → floor kicks in (max(0*0.05, 1.0) = 1.0).
    // threshold = 0 + 3.5*1.0 = 3.5.  Candidate 500 > 3.5 → IS flagged.
    // This is correct: a 500-event spike against a silent baseline IS anomalous.
    const series = [0, 0, 0, 0, 0, 0, 500]
    expect(detectSpikes(series)).toHaveLength(1)
  })
})

// ---------------------------------------------------------------------------
// 7. SpikeMark shape
// ---------------------------------------------------------------------------

describe('detectSpikes — SpikeMark shape', () => {
  it('each mark has bucketIndex, ratio, value, windowMedian', () => {
    const series = [...flat(6, 10), 200]
    const marks = detectSpikes(series)
    expect(marks).toHaveLength(1)
    const mark = marks[0]
    expect(typeof mark.bucketIndex).toBe('number')
    expect(typeof mark.ratio).toBe('number')
    expect(typeof mark.value).toBe('number')
    expect(typeof mark.windowMedian).toBe('number')
  })

  it('llmReason is NOT set by detectSpikes (ADR-0035 seam)', () => {
    const series = [...flat(6, 10), 200]
    const marks = detectSpikes(series)
    expect(marks[0].llmReason).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// 8. Input immutability
// ---------------------------------------------------------------------------

describe('detectSpikes — input immutability', () => {
  it('does not mutate the input array', () => {
    const series = [...flat(6, 10), 200, ...flat(5, 10)]
    const copy = [...series]
    detectSpikes(series)
    expect(series).toEqual(copy)
  })
})

// ---------------------------------------------------------------------------
// 9. Custom options
// ---------------------------------------------------------------------------

describe('detectSpikes — custom options', () => {
  it('a lower k value flags more buckets (looser threshold)', () => {
    // With k=1, a modestly elevated value should be flagged.
    const series = [8, 9, 10, 10, 11, 12, 20]
    // Window median = 10, MAD = 1, threshold(k=1) = 11 → 20 > 11 → flagged.
    const marks = detectSpikes(series, { k: 1 })
    expect(marks.length).toBeGreaterThan(0)
  })

  it('a higher k value flags fewer buckets (tighter threshold)', () => {
    // With k=10 the threshold is very high; the 20-above example should not fire.
    const series = [8, 9, 10, 10, 11, 12, 20]
    const marks = detectSpikes(series, { k: 10 })
    expect(marks).toHaveLength(0)
  })

  it('a larger window requires more preceding buckets before flagging', () => {
    // With window=10, series.length must be >10 before any mark can appear.
    const series = [...flat(6, 10), 200] // length 7; window 10 → no marks
    expect(detectSpikes(series, { window: 10 })).toHaveLength(0)
  })

  it('DEFAULT_WINDOW is 6 and DEFAULT_K is 3.5', () => {
    expect(DEFAULT_WINDOW).toBe(6)
    expect(DEFAULT_K).toBe(3.5)
  })
})
