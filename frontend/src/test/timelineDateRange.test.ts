/**
 * Unit tests for lib/timelineDateRange helpers.
 *
 * EARS acceptance criteria covered:
 *
 * A. toDatetimeLocalValue:
 *    - Produces "YYYY-MM-DDTHH:mm" without seconds or timezone suffix.
 *    - Minutes are zero-padded.
 *
 * B. datetimeLocalToIso:
 *    - Converts a datetime-local string to a UTC ISO-8601 string.
 *    - The round-trip (local → ISO → back to same Date) is lossless.
 *
 * C. deriveEndOnStartChange:
 *    - Empty end → End = Start + 12h.
 *    - End ≤ Start (equal) → End = Start + 12h.
 *    - End − Start > 24h → End = Start + 24h (cap).
 *    - End in valid window → End unchanged.
 *
 * D. deriveEndOnEndChange:
 *    - End ≤ Start → End = Start + 12h (reset).
 *    - End − Start > 24h → End = Start + 24h (clamp).
 *    - Valid End → End unchanged.
 *
 * E. isValidCustomRange:
 *    - Empty start or end → false.
 *    - End ≤ Start → false.
 *    - End − Start > 24h → false.
 *    - Valid range → true.
 */

import { describe, it, expect } from 'vitest'
import {
  toDatetimeLocalValue,
  datetimeLocalToIso,
  deriveEndOnStartChange,
  deriveEndOnEndChange,
  isValidCustomRange,
  MAX_RANGE_MS,
  DEFAULT_WINDOW_MS,
} from '../lib/timelineDateRange'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a datetime-local string from a Date (UTC components forced to a known value). */
function makeDatetimeLocal(isoStr: string): string {
  return toDatetimeLocalValue(new Date(isoStr))
}

// ---------------------------------------------------------------------------
// A. toDatetimeLocalValue
// ---------------------------------------------------------------------------

describe('toDatetimeLocalValue', () => {
  it('returns a string in YYYY-MM-DDTHH:mm format (no seconds, no Z)', () => {
    const d = new Date('2026-06-10T14:00:00Z')
    const result = toDatetimeLocalValue(d)
    // Format: exactly 16 chars, contains T
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/)
  })

  it('zero-pads month, day, hours, minutes', () => {
    // Use a fixed local time to test padding (works with any timezone)
    const d = new Date(2026, 0, 5, 9, 5) // Jan 5, 09:05 local
    const result = toDatetimeLocalValue(d)
    expect(result).toMatch(/^\d{4}-01-05T09:05$/)
  })
})

// ---------------------------------------------------------------------------
// B. datetimeLocalToIso
// ---------------------------------------------------------------------------

describe('datetimeLocalToIso', () => {
  it('returns a UTC ISO-8601 string ending in Z', () => {
    const localStr = makeDatetimeLocal('2026-06-10T14:00:00Z')
    const iso = datetimeLocalToIso(localStr)
    expect(iso).toMatch(/Z$/)
  })

  it('round-trips through toDatetimeLocalValue without data loss (minute precision)', () => {
    const original = new Date(2026, 5, 10, 14, 30, 0, 0) // fixed local time
    const localStr = toDatetimeLocalValue(original)
    const isoStr = datetimeLocalToIso(localStr)
    const roundTripped = new Date(isoStr)
    // Difference must be < 1 minute (datetime-local has minute precision)
    expect(Math.abs(roundTripped.getTime() - original.getTime())).toBeLessThan(60000)
  })
})

// ---------------------------------------------------------------------------
// C. deriveEndOnStartChange
// ---------------------------------------------------------------------------

describe('deriveEndOnStartChange', () => {
  // Use a fixed start for deterministic assertions
  const fixedStart = '2026-06-10T08:00'

  it('empty end → End = Start + 12h', () => {
    const result = deriveEndOnStartChange(fixedStart, '')
    const startMs = new Date(fixedStart).getTime()
    const endMs = new Date(result).getTime()
    expect(endMs - startMs).toBeCloseTo(DEFAULT_WINDOW_MS, -3) // within 1s
  })

  it('End equal to Start → End = Start + 12h', () => {
    const result = deriveEndOnStartChange(fixedStart, fixedStart)
    const startMs = new Date(fixedStart).getTime()
    const endMs = new Date(result).getTime()
    expect(endMs - startMs).toBeCloseTo(DEFAULT_WINDOW_MS, -3)
  })

  it('End before Start → End = Start + 12h', () => {
    const endBefore = '2026-06-10T06:00' // 2h before start
    const result = deriveEndOnStartChange(fixedStart, endBefore)
    const startMs = new Date(fixedStart).getTime()
    const endMs = new Date(result).getTime()
    expect(endMs - startMs).toBeCloseTo(DEFAULT_WINDOW_MS, -3)
  })

  it('End − Start > 24h → End = Start + 24h (cap)', () => {
    const endTooFar = '2026-06-11T10:00' // 26h after start
    const result = deriveEndOnStartChange(fixedStart, endTooFar)
    const startMs = new Date(fixedStart).getTime()
    const endMs = new Date(result).getTime()
    expect(endMs - startMs).toBeCloseTo(MAX_RANGE_MS, -3)
  })

  it('End in valid window (e.g. Start + 6h) → End unchanged', () => {
    const validEnd = '2026-06-10T14:00' // 6h after start
    const result = deriveEndOnStartChange(fixedStart, validEnd)
    expect(result).toBe(validEnd)
  })

  it('End exactly at Start + 24h → End unchanged (boundary valid)', () => {
    const startMs = new Date(fixedStart).getTime()
    const exactEnd = toDatetimeLocalValue(new Date(startMs + MAX_RANGE_MS))
    const result = deriveEndOnStartChange(fixedStart, exactEnd)
    expect(result).toBe(exactEnd)
  })
})

// ---------------------------------------------------------------------------
// D. deriveEndOnEndChange
// ---------------------------------------------------------------------------

describe('deriveEndOnEndChange', () => {
  const fixedStart = '2026-06-10T08:00'

  it('End ≤ Start → End = Start + 12h (reject)', () => {
    const result = deriveEndOnEndChange(fixedStart, fixedStart)
    const startMs = new Date(fixedStart).getTime()
    const endMs = new Date(result).getTime()
    expect(endMs - startMs).toBeCloseTo(DEFAULT_WINDOW_MS, -3)
  })

  it('End − Start > 24h → End = Start + 24h (clamp)', () => {
    const tooFar = '2026-06-11T10:00' // 26h after
    const result = deriveEndOnEndChange(fixedStart, tooFar)
    const startMs = new Date(fixedStart).getTime()
    const endMs = new Date(result).getTime()
    expect(endMs - startMs).toBeCloseTo(MAX_RANGE_MS, -3)
  })

  it('valid End → End unchanged', () => {
    const validEnd = '2026-06-10T20:00' // 12h after start
    const result = deriveEndOnEndChange(fixedStart, validEnd)
    expect(result).toBe(validEnd)
  })

  it('End exactly 1 min after Start → valid (not rejected)', () => {
    const startMs = new Date(fixedStart).getTime()
    const oneMinLater = toDatetimeLocalValue(new Date(startMs + 60000))
    const result = deriveEndOnEndChange(fixedStart, oneMinLater)
    expect(result).toBe(oneMinLater)
  })
})

// ---------------------------------------------------------------------------
// E. isValidCustomRange
// ---------------------------------------------------------------------------

describe('isValidCustomRange', () => {
  const start = '2026-06-10T08:00'

  it('empty start → false', () => {
    expect(isValidCustomRange('', '2026-06-10T20:00')).toBe(false)
  })

  it('empty end → false', () => {
    expect(isValidCustomRange(start, '')).toBe(false)
  })

  it('End equal to Start → false', () => {
    expect(isValidCustomRange(start, start)).toBe(false)
  })

  it('End before Start → false', () => {
    expect(isValidCustomRange(start, '2026-06-10T06:00')).toBe(false)
  })

  it('End − Start > 24h → false', () => {
    expect(isValidCustomRange(start, '2026-06-11T10:00')).toBe(false)
  })

  it('End exactly at Start + 24h → true (boundary valid)', () => {
    const startMs = new Date(start).getTime()
    const exactEnd = toDatetimeLocalValue(new Date(startMs + MAX_RANGE_MS))
    expect(isValidCustomRange(start, exactEnd)).toBe(true)
  })

  it('valid range within 24h → true', () => {
    expect(isValidCustomRange(start, '2026-06-10T20:00')).toBe(true)
  })
})
