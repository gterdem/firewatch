/**
 * timelineDateRange — helpers for the Activity-timeline custom date-range pickers.
 *
 * The browser's datetime-local input always works in LOCAL time.
 * The API expects UTC ISO-8601 strings.  These helpers mediate the conversion.
 *
 * Port notes: the legacy dashboard (line 740) used the same two-step pattern:
 *   fmtLocal(d)        → "YYYY-MM-DDTHH:mm"  (datetime-local value)
 *   localToUTC(str)    → new Date(str).toISOString()  (UTC ISO for the API)
 * We reproduce that pattern here with typed helpers and the 24h cap rule.
 *
 * Rules (per the issue spec):
 *   - On Start change: if End is empty, or End ≤ Start, or End − Start > 24h
 *       → set End = Start + 12h.
 *   - On End change: enforce End > Start and End − Start ≤ 24h.
 *       If the user picks an End more than 24h after Start → clamp End to Start + 24h.
 *   - The 24h cap maps to ≤ 24 hourly bars (the chart's bucket limit).
 */

/** Maximum allowed range in milliseconds (24 hours). */
export const MAX_RANGE_MS = 24 * 60 * 60 * 1000

/** Default window when End is missing/invalid after a Start change (12 hours). */
export const DEFAULT_WINDOW_MS = 12 * 60 * 60 * 1000

/**
 * Convert a Date to the "YYYY-MM-DDTHH:mm" string expected by datetime-local inputs.
 * The value is always expressed in the browser's LOCAL time zone.
 *
 * Port of legacy/dashboard.html fmtLocal(d).
 */
export function toDatetimeLocalValue(d: Date): string {
  const y = d.getFullYear()
  const mo = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  const hh = String(d.getHours()).padStart(2, '0')
  const mm = String(d.getMinutes()).padStart(2, '0')
  return `${y}-${mo}-${dd}T${hh}:${mm}`
}

/**
 * Convert a datetime-local string (local time) to a UTC ISO-8601 string
 * suitable for passing to GET /logs/timeline as start= or end=.
 *
 * The browser parses "YYYY-MM-DDTHH:mm" (no Z) as LOCAL time, so
 * new Date(localStr).toISOString() correctly gives the UTC equivalent.
 *
 * Port of legacy/dashboard.html localToUTC(localStr).
 */
export function datetimeLocalToIso(localStr: string): string {
  return new Date(localStr).toISOString()
}

/**
 * Derive the End value that should be applied when Start changes.
 *
 * Rules (per spec):
 *  - If endStr is empty          → End = Start + 12h
 *  - If End ≤ Start              → End = Start + 12h
 *  - If End − Start > 24h        → End = Start + 24h (cap)
 *  - Otherwise                   → keep existing endStr unchanged
 *
 * @param startStr  datetime-local value for the new Start.
 * @param endStr    current datetime-local value for End (may be empty).
 * @returns         the corrected datetime-local value for End.
 */
export function deriveEndOnStartChange(startStr: string, endStr: string): string {
  const startMs = new Date(startStr).getTime()

  if (!endStr) {
    return toDatetimeLocalValue(new Date(startMs + DEFAULT_WINDOW_MS))
  }

  const endMs = new Date(endStr).getTime()

  if (endMs <= startMs) {
    return toDatetimeLocalValue(new Date(startMs + DEFAULT_WINDOW_MS))
  }

  if (endMs - startMs > MAX_RANGE_MS) {
    return toDatetimeLocalValue(new Date(startMs + MAX_RANGE_MS))
  }

  return endStr
}

/**
 * Derive the End value that should be applied when End changes directly.
 *
 * Rules (per spec):
 *  - If End ≤ Start              → End = Start + 12h  (reject, reset to default)
 *  - If End − Start > 24h        → End = Start + 24h  (clamp to cap)
 *  - Otherwise                   → keep endStr as-is (valid)
 *
 * @param startStr  datetime-local value for the current Start.
 * @param newEndStr datetime-local value that the user just picked for End.
 * @returns         the corrected datetime-local value for End.
 */
export function deriveEndOnEndChange(startStr: string, newEndStr: string): string {
  const startMs = new Date(startStr).getTime()
  const endMs = new Date(newEndStr).getTime()

  if (endMs <= startMs) {
    return toDatetimeLocalValue(new Date(startMs + DEFAULT_WINDOW_MS))
  }

  if (endMs - startMs > MAX_RANGE_MS) {
    return toDatetimeLocalValue(new Date(startMs + MAX_RANGE_MS))
  }

  return newEndStr
}

/**
 * Return true if the given start/end string pair forms a valid custom range.
 * A valid range has both values non-empty, End > Start, and End − Start ≤ 24h.
 */
export function isValidCustomRange(startStr: string, endStr: string): boolean {
  if (!startStr || !endStr) return false
  const startMs = new Date(startStr).getTime()
  const endMs = new Date(endStr).getTime()
  return endMs > startMs && endMs - startMs <= MAX_RANGE_MS
}
