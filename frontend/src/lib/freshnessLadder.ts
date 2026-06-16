/**
 * freshnessLadder — relative-time helper for health tooltip context (issue #335).
 *
 * Separated from HealthCard.tsx to satisfy react-refresh/only-export-components
 * (a file with both React component exports and non-component exports cannot be
 * hot-reloaded safely).
 *
 * ADR-0032 Amendment 1 R1 (issue #377): the old recency-ladder constants
 * (STALE_THRESHOLD_MS = 2m, OFFLINE_THRESHOLD_MS = 60m) are DELETED.  They
 * described a CrowdStrike-style recency model (green ≤2m / amber 2–60m / red >60m)
 * that contradicts ADR-0032 Decision C (stale-but-no-error is always amber,
 * never red; the green/amber boundary is the server's FRESHNESS_MINUTES = 5,
 * not 2 min).  The legend now renders the OPERATIONAL vocabulary — dot meaning
 * is driven by what the collector IS DOING, not how old the newest event is.
 *
 * The freshness boundary (green/amber threshold) comes from GET /stats
 * `freshness_minutes` so the legend never hardcodes a second copy of the
 * server constant.
 */

/**
 * Format a nullable ISO timestamp as a human-relative string.
 * Returns e.g. "< 1m ago", "8m ago", "2h ago", or "" when null.
 *
 * Used for the "last event" context line in the tooltip (issue #335).
 * Not used to compute dot color (ADR-0032 Decision C).
 */
export function formatRelativeTime(iso: string | null): string {
  if (!iso) return ''
  const secondsAgo = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (secondsAgo < 60) return '< 1m ago'
  const minsAgo = Math.round(secondsAgo / 60)
  if (minsAgo < 60) return `${minsAgo}m ago`
  const hoursAgo = Math.round(minsAgo / 60)
  return `${hoursAgo}h ago`
}
