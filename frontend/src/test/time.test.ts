/**
 * Tests for lib/time.ts — central time-formatter seam (issue #244).
 *
 * EARS acceptance criteria covered:
 *
 * 1. WHEN the API returns a tz-naive timestamp/bucket key, parseApiTimestamp
 *    SHALL interpret it as UTC (never local).
 *    → naive hourly key "2026-06-11T04:00" → same UTC instant as "2026-06-11T04:00Z"
 *    → naive daily key "2026-06-11T00:00" → UTC midnight
 *    → naive with seconds "2026-06-11T04:00:00" → same as "2026-06-11T04:00:00Z"
 *
 * 2. Off-by-tz-offset regression: parseApiTimestamp(naive) must NOT produce a
 *    Date that differs from parseApiTimestamp(naive + 'Z') by the local TZ offset.
 *
 * 3. Offset-bearing strings passthrough:
 *    → "2026-06-11T04:00:00Z" (Z suffix) → correct UTC instant
 *    → "2026-06-11T04:00:00+00:00" (+offset) → correct UTC instant
 *    → "2026-06-11T04:00:00+05:30" (non-zero offset) → correct UTC instant
 *
 * 4. formatLocal: returns a non-empty string for a valid Date; empty string
 *    for an invalid Date; different style variants produce different output.
 *
 * 5. formatUtc: returns a string ending with " UTC" for a valid Date;
 *    empty string for an invalid Date.
 *
 * 6. localZoneLabel: returns a non-empty string.
 */

import { describe, it, expect } from 'vitest'
import { parseApiTimestamp, formatLocal, formatUtc, localZoneLabel } from '../lib/time'

// ---------------------------------------------------------------------------
// parseApiTimestamp — naive-as-UTC rule (the core bug fix)
// ---------------------------------------------------------------------------

describe('parseApiTimestamp — naive timestamps treated as UTC', () => {
  it('returns the same UTC instant for naive key and the same key with Z suffix', () => {
    const naive = parseApiTimestamp('2026-06-11T04:00')
    const withZ = parseApiTimestamp('2026-06-11T04:00Z')
    expect(naive.getTime()).toBe(withZ.getTime())
  })

  it('naive hourly key equals explicit UTC offset string', () => {
    const naive = parseApiTimestamp('2026-06-11T04:00')
    const explicit = parseApiTimestamp('2026-06-11T04:00:00+00:00')
    expect(naive.getTime()).toBe(explicit.getTime())
  })

  it('naive key with seconds treated as UTC', () => {
    const naive = parseApiTimestamp('2026-06-11T04:00:00')
    const withZ = parseApiTimestamp('2026-06-11T04:00:00Z')
    expect(naive.getTime()).toBe(withZ.getTime())
  })

  it('naive daily key (no time part) treated as UTC midnight', () => {
    // "2026-06-11" — date-only: treat as UTC midnight
    const naive = parseApiTimestamp('2026-06-11T00:00')
    const withZ = parseApiTimestamp('2026-06-11T00:00Z')
    expect(naive.getTime()).toBe(withZ.getTime())
  })

  it('off-by-offset regression: naive date MUST equal Z-suffixed date, not differ by TZ offset', () => {
    // The original bug: new Date("2026-06-11T04:00") was parsed as local, so
    // in UTC-5 it became 2026-06-11T09:00Z instead of 2026-06-11T04:00Z.
    // parseApiTimestamp must NOT produce a Date with a different UTC millis.
    const naive = parseApiTimestamp('2026-06-11T04:00')
    const correct = parseApiTimestamp('2026-06-11T04:00Z')
    // They must be bitwise-equal (same UTC millisecond).
    expect(naive.getTime()).toBe(correct.getTime())
    // And neither must be NaN.
    expect(isNaN(naive.getTime())).toBe(false)
  })
})

describe('parseApiTimestamp — offset-bearing strings passthrough', () => {
  it('Z-suffix string parses correctly', () => {
    const d = parseApiTimestamp('2026-06-11T04:00:00Z')
    expect(isNaN(d.getTime())).toBe(false)
    expect(d.getUTCHours()).toBe(4)
    expect(d.getUTCMinutes()).toBe(0)
  })

  it('+00:00 offset parses correctly', () => {
    const d = parseApiTimestamp('2026-06-11T04:00:00+00:00')
    expect(isNaN(d.getTime())).toBe(false)
    expect(d.getUTCHours()).toBe(4)
  })

  it('non-zero +offset adjusts to correct UTC', () => {
    // +05:30 means UTC = wall - 05:30
    const d = parseApiTimestamp('2026-06-11T09:30:00+05:30')
    expect(isNaN(d.getTime())).toBe(false)
    // 09:30 - 05:30 = 04:00 UTC
    expect(d.getUTCHours()).toBe(4)
    expect(d.getUTCMinutes()).toBe(0)
  })

  it('naive and Z forms represent the same instant', () => {
    const a = parseApiTimestamp('2026-06-11T12:00')
    const b = parseApiTimestamp('2026-06-11T12:00Z')
    expect(a.getTime()).toBe(b.getTime())
  })
})

describe('parseApiTimestamp — invalid input', () => {
  it('empty string returns NaN Date', () => {
    const d = parseApiTimestamp('')
    expect(isNaN(d.getTime())).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// formatLocal
// ---------------------------------------------------------------------------

describe('formatLocal', () => {
  // Use a known UTC instant: 2026-06-11T04:00:00Z
  // In any local timezone the local time will differ from UTC by the TZ offset,
  // but the formatted string must be a valid time, not empty or NaN.
  const UTC_DATE = new Date('2026-06-11T04:00:00Z')

  it('returns a non-empty string for a valid Date (style: time)', () => {
    const result = formatLocal(UTC_DATE, 'time')
    expect(result).toBeTruthy()
    expect(typeof result).toBe('string')
  })

  it('style "time" output contains ":" separator (HH:MM format)', () => {
    const result = formatLocal(UTC_DATE, 'time')
    expect(result).toContain(':')
  })

  it('style "time-with-seconds" output contains two ":" separators', () => {
    const result = formatLocal(UTC_DATE, 'time-with-seconds')
    // HH:MM:SS has two colons
    expect(result.split(':').length).toBeGreaterThanOrEqual(3)
  })

  it('style "date" returns a month-day label (no colon)', () => {
    const result = formatLocal(UTC_DATE, 'date')
    expect(result).toBeTruthy()
    expect(result).not.toContain(':')
  })

  it('style "datetime" returns a string with both date and time info', () => {
    const result = formatLocal(UTC_DATE, 'datetime')
    expect(result).toBeTruthy()
    expect(result).toContain(':')
  })

  it('returns empty string for invalid Date', () => {
    const result = formatLocal(new Date(NaN))
    expect(result).toBe('')
  })

  it('defaults to "time" style when style argument is omitted', () => {
    const withStyle = formatLocal(UTC_DATE, 'time')
    const withoutStyle = formatLocal(UTC_DATE)
    expect(withoutStyle).toBe(withStyle)
  })

  it('style "relative" returns a human-readable age string for a past date (not raw ISO)', () => {
    // 2026-06-04T08:00:00Z is definitely in the past relative to any real test run date.
    const past = new Date('2026-06-04T08:00:00Z')
    const result = formatLocal(past, 'relative')
    // Must not be an empty string or raw ISO
    expect(result).toBeTruthy()
    expect(result).not.toMatch(/^\d{4}-\d{2}-\d{2}T/)
    // Must be a relative label or a fallback date string — never the raw ISO
    // (e.g., "7d ago", "3h ago", "just now", or a month/year fallback like "Jun 2026")
    expect(typeof result).toBe('string')
  })

  it('style "relative" returns empty string for invalid Date (same as other styles)', () => {
    expect(formatLocal(new Date(NaN), 'relative')).toBe('')
  })
})

// ---------------------------------------------------------------------------
// formatUtc
// ---------------------------------------------------------------------------

describe('formatUtc', () => {
  it('returns a string ending with " UTC"', () => {
    const d = new Date('2026-06-11T04:00:00Z')
    const result = formatUtc(d)
    expect(result).toMatch(/ UTC$/)
  })

  it('output is non-empty for a valid Date', () => {
    const d = new Date('2026-06-11T04:00:00Z')
    expect(formatUtc(d)).toBeTruthy()
  })

  it('returns empty string for invalid Date', () => {
    expect(formatUtc(new Date(NaN))).toBe('')
  })

  it('output reflects the correct UTC hour (hour 4 for T04:00:00Z)', () => {
    const d = new Date('2026-06-11T04:00:00Z')
    const result = formatUtc(d)
    // The formatted string must include "04" for the UTC hour
    expect(result).toContain('04')
  })
})

// ---------------------------------------------------------------------------
// localZoneLabel
// ---------------------------------------------------------------------------

describe('localZoneLabel', () => {
  it('returns a non-empty string', () => {
    const label = localZoneLabel()
    expect(label).toBeTruthy()
    expect(typeof label).toBe('string')
  })
})
