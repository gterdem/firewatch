/**
 * lib/time.ts — Central time-formatting seam (issue #244).
 *
 * Convention: UTC store → browser-local display → UTC available on hover.
 * Matches Splunk/Elastic per-user time-display precedent.
 *
 * Contract:
 *   - API timestamps may be offset-bearing ("2026-06-11T04:00:00Z" or
 *     "2026-06-11T04:00:00+00:00") OR tz-naive ("2026-06-11T04:00").
 *   - Tz-naive strings are ALWAYS interpreted as UTC (the server always stores UTC;
 *     naive = the offset was just omitted from the serialization).
 *   - `parseApiTimestamp` handles both forms and returns a correct Date.
 *   - `formatLocal` / `formatUtc` accept that Date and produce display strings.
 *
 * This seam is the single place that knows about the naive-UTC rule.
 * All Dashboard time rendering goes through here; no inline toLocale* calls
 * remain in frontend/src/components/dashboard/ after this migration.
 *
 * ADR-0028 D6: no raw hex; ADR-0029 D3: no attacker data logged.
 */

// ---------------------------------------------------------------------------
// parseApiTimestamp — naive → UTC fix
// ---------------------------------------------------------------------------

/**
 * Parse a timestamp string returned by the FireWatch API and return a Date
 * that correctly represents the UTC instant.
 *
 * The API may return:
 *   a) An offset-bearing string:  "2026-06-11T04:00:00Z"
 *                                 "2026-06-11T04:00:00+00:00"
 *   b) A tz-naive string:         "2026-06-11T04:00"
 *                                 "2026-06-11T04:00:00"
 *
 * JS parses case (a) correctly (UTC offset present → correct instant).
 * JS parses case (b) as LOCAL time on most engines (per ECMA-262: date-time
 * strings without an offset are treated as local, not UTC) — which is wrong
 * for us because the DB stores UTC.
 *
 * Fix: append "Z" to strings that have no offset designator (no Z, +, or -
 * after the time part) before handing to `new Date()`.
 */
export function parseApiTimestamp(s: string): Date {
  if (!s) return new Date(NaN)

  // Detect offset: present if the string ends with 'Z'/'z', or has a '+'/'-'
  // in the time portion (i.e., after the 'T' separator).
  const hasOffset = /[Zz]$/.test(s) || /T.*[+-]\d{2}:\d{2}$/.test(s)

  if (hasOffset) {
    return new Date(s)
  }

  // Tz-naive → append 'Z' so JS parses it as UTC.
  return new Date(s + 'Z')
}

// ---------------------------------------------------------------------------
// localZoneLabel — e.g. "EDT", "UTC+5", "UTC"
// ---------------------------------------------------------------------------

/**
 * Return a short label for the browser's local timezone, e.g. "EDT", "UTC",
 * "UTC+5:30". Suitable for the Dashboard zone chip ("times in EDT").
 *
 * We use Intl.DateTimeFormat to extract the short timezone name because it
 * handles DST transitions correctly (JS Date has no native zone abbreviation).
 */
export function localZoneLabel(): string {
  try {
    const formatter = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' })
    const parts = formatter.formatToParts(new Date())
    const part = parts.find((p) => p.type === 'timeZoneName')
    return part?.value ?? 'local'
  } catch {
    return 'local'
  }
}

// ---------------------------------------------------------------------------
// Style variants for formatLocal
// ---------------------------------------------------------------------------

export type TimeStyle = 'time' | 'time-with-seconds' | 'date' | 'datetime' | 'relative'

// ---------------------------------------------------------------------------
// formatLocal — UTC instant → browser-local display string
// ---------------------------------------------------------------------------

/**
 * Format a Date (UTC instant) for display in the analyst's browser-local zone.
 *
 * `style` controls the output:
 *   'time'             → "HH:MM"          (default — timeline bucket labels)
 *   'time-with-seconds'→ "HH:MM:SS"       (log table Time column)
 *   'date'             → "Jun 11"         (daily bucket labels)
 *   'datetime'         → "Jun 11, 14:30"  (general datetime cells)
 *   'relative'         → "2m ago"         (slide-over timeline + recent-logs Time column)
 *                        Falls back to formatLocal('datetime') when relativeTime returns ''.
 *
 * Returns an empty string if `d` is not a valid Date.
 */
export function formatLocal(d: Date, style: TimeStyle = 'time'): string {
  if (isNaN(d.getTime())) return ''

  switch (style) {
    case 'time':
      return d.toLocaleString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      })
    case 'time-with-seconds':
      return d.toLocaleTimeString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      })
    case 'date':
      return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
    case 'datetime':
      return d.toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      })
    case 'relative': {
      const rel = relativeTime(d)
      // relativeTime returns '' for future dates — fall back to local datetime.
      return rel !== '' ? rel : d.toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      })
    }
  }
}

// ---------------------------------------------------------------------------
// formatUtc — UTC instant → fixed UTC string for hover tooltip
// ---------------------------------------------------------------------------

/**
 * Format a Date as a fixed UTC string for the hover/focus tooltip.
 * Always shows "UTC" suffix so the analyst knows which zone is shown.
 *
 * Example: "06/11/2026, 04:00 UTC"
 */
export function formatUtc(d: Date): string {
  if (isNaN(d.getTime())) return ''
  return (
    d.toLocaleString(undefined, {
      timeZone: 'UTC',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }) + ' UTC'
  )
}

// ---------------------------------------------------------------------------
// fmtTime — shared table-cell timestamp formatter (#612)
// ---------------------------------------------------------------------------

/**
 * Format an API timestamp string for display in a compact table cell.
 *
 * Used by LogsTable (main log table) and EvidenceFactorRow (score-evidence
 * detail table) so both render timestamps identically — single source of
 * truth, no drift between the two sites (issue #612).
 *
 * Convention: parses via parseApiTimestamp (naive → UTC fix), then formats
 * via formatLocal 'datetime' style → e.g. "Jun 11, 14:30".
 * Falls back to the raw string when parsing fails (defensive).
 *
 * ADR-0029 D3: caller is responsible for rendering as text node.
 */
export function fmtTime(iso: string): string {
  if (!iso) return iso
  try {
    const d = parseApiTimestamp(iso)
    const formatted = formatLocal(d, 'datetime')
    return formatted !== '' ? formatted : iso
  } catch {
    return iso
  }
}

// ---------------------------------------------------------------------------
// fmtTimeCompact — fixed-width compact timestamp for table cells (#666)
// ---------------------------------------------------------------------------

/**
 * Format an API timestamp string as a compact, fixed-width table-cell value
 * that never truncates: "MM-DD HH:mm:ss" (e.g. "06-14 13:25:07").
 *
 * Added in #666 to replace the `fmtTime` 'datetime' style which produces
 * locale-variable output like "Jun 14, 13:25" that may truncate in narrow cells.
 * This form uses fixed 2-digit fields (no month abbreviations, no locale-varying
 * separators) so the rendered width is always 14 chars — the cell never ellipsises.
 *
 * Additive: existing `fmtTime` callers (EvidenceFactorRow) are unaffected.
 * LogsTable now calls fmtTimeCompact; EvidenceFactorRow keeps fmtTime.
 *
 * ADR-0029 D3: caller renders as text node.
 */
export function fmtTimeCompact(iso: string): string {
  if (!iso) return iso
  try {
    const d = parseApiTimestamp(iso)
    if (isNaN(d.getTime())) return iso
    // Use fixed 2-digit UTC fields → "MM-DD HH:mm:ss"
    // We show local time (to match the existing fmtTime/formatLocal convention),
    // but with a stable format so cell width never varies.
    const mo  = String(d.getMonth() + 1).padStart(2, '0')
    const day = String(d.getDate()).padStart(2, '0')
    const hh  = String(d.getHours()).padStart(2, '0')
    const mm  = String(d.getMinutes()).padStart(2, '0')
    const ss  = String(d.getSeconds()).padStart(2, '0')
    return `${mo}-${day} ${hh}:${mm}:${ss}`
  } catch {
    return iso
  }
}

// ---------------------------------------------------------------------------
// isEpochOrNull / fmtTimestampNever — epoch-zero sentinel detection
// ---------------------------------------------------------------------------

/**
 * Unix epoch (seconds) threshold below which a timestamp is treated as "never
 * synced" rather than a real timestamp.  Any value before 2020-01-01T00:00:00Z
 * (Unix 1577836800 s) is a DB min-date sentinel or clock-skew artifact — not a
 * genuine last-success time.  The same threshold works for both numeric epoch
 * (seconds) values from supervisor DTOs and ISO strings parsed into ms.
 *
 * 1577836800 s = 2020-01-01T00:00:00Z
 */
const EPOCH_SENTINEL_THRESHOLD_S = 1_577_836_800

/**
 * Return true when a timestamp value represents "never synced":
 *   - null or undefined
 *   - numeric Unix epoch (seconds) below 2020-01-01
 *   - ISO string that parses to a date before 2020-01-01
 *
 * Used by fmtTimestampNever and anywhere "Last success / Last sync" is rendered
 * to prevent DB min-date sentinels (e.g. 1970-01-01) showing as real dates.
 */
export function isEpochOrNull(
  ts: number | string | null | undefined,
): boolean {
  if (ts == null) return true
  if (typeof ts === 'number') {
    return ts < EPOCH_SENTINEL_THRESHOLD_S
  }
  // ISO string — parse and check against the threshold
  try {
    const d = parseApiTimestamp(ts)
    if (isNaN(d.getTime())) return true
    return d.getTime() / 1000 < EPOCH_SENTINEL_THRESHOLD_S
  } catch {
    return true
  }
}

/**
 * Format a supervisor timestamp (Unix epoch seconds OR ISO string) for display,
 * returning "Never" instead of a formatted date when the value is null, undefined,
 * or a DB min-date sentinel (before 2020-01-01).
 *
 * This is the single formatting seam for "Last success" and "Last sync" fields
 * in both SourceDiagnosticsPanel and CollectControls, replacing inline
 * fmtTimestamp / formatLastSync calls that let 1970 dates leak to the UI.
 *
 * SECURITY: ts is supervisor-provided (not attacker-controlled); rendered as text.
 */
export function fmtTimestampNever(
  ts: number | string | null | undefined,
): string {
  if (isEpochOrNull(ts)) return 'Never'
  try {
    const d =
      typeof ts === 'number' ? new Date(ts * 1000) : parseApiTimestamp(ts as string)
    if (isNaN(d.getTime())) return 'Never'
    return d.toLocaleString()
  } catch {
    return String(ts)
  }
}

// ---------------------------------------------------------------------------
// relativeTime — human-readable age from a Date to now
// ---------------------------------------------------------------------------

/**
 * Return a concise relative-time string for a Date in the past, e.g.:
 *   "just now"   (< 60 s)
 *   "2m ago"     (< 1 h)
 *   "3h ago"     (< 24 h)
 *   "5d ago"     (< 30 d)
 *   "Jun 2026"   (>= 30 d — month/year, browser-local locale)
 *
 * Returns "" when `d` is an invalid Date or in the future.
 * Used by IpHeaderMeta for the first-seen field (issue #265).
 */
export function relativeTime(d: Date): string {
  if (isNaN(d.getTime())) return ''
  const nowMs = Date.now()
  const diffMs = nowMs - d.getTime()
  if (diffMs < 0) return ''

  const seconds = Math.floor(diffMs / 1000)
  if (seconds < 60) return 'just now'

  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`

  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`

  const days = Math.floor(hours / 24)
  if (days < 30) return `${days}d ago`

  // Older than 30 days — show month/year so the analyst understands scale.
  return d.toLocaleDateString(undefined, { month: 'short', year: 'numeric' })
}
