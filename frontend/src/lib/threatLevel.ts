/**
 * threatLevel — shared threat-level ordering utilities (issue #650, ADR-0059 D2).
 *
 * Provides a canonical ordering for the four named severity bands so that any
 * two-axis alert-worthiness checks (banner, notifier) use a single, drift-proof
 * implementation.
 *
 * Order (ascending): LOW < MEDIUM < HIGH < CRITICAL
 * (mirrors the backend ThreatLevelLiteral enum)
 *
 * The key export is ``bandMeets(level, threshold)``:
 *   true  when `level` is AT LEAST as severe as `threshold`.
 *   false for any unrecognised level (safe default — unknown threats do NOT
 *         auto-surface; operators can investigate via the full table).
 */

/**
 * Canonical severity band order — higher index = more severe.
 * Do not reorder; other modules (bandMeets, deriveTriageActors) rely on this.
 */
const BAND_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const

export type ThreatBand = (typeof BAND_ORDER)[number]

/**
 * Return the ordinal rank of a severity band (0 = LOW … 3 = CRITICAL).
 * Returns -1 for any unrecognised string so that bandMeets returns false safely.
 */
export function bandRank(level: string): number {
  return BAND_ORDER.indexOf(level.toUpperCase() as ThreatBand)
}

/**
 * Returns true when `level` meets or exceeds `threshold`.
 *
 * Usage in the triage banner:
 *   bandMeets(threat.threat_level, triageThreshold)
 *       → true  when the threat's severity band is at least as high as the
 *               configured Triage threshold.
 *       → false for unrecognised levels (safe non-surface default).
 *
 * The escalation-tier half of the alert-worthiness predicate is SEPARATE
 * and must remain unconditional (ADR-0036 — the two axes are never collapsed).
 *
 * Mirrors the backend ``band_meets()`` helper in ``escalation/worthiness.py``.
 */
export function bandMeets(level: string, threshold: string): boolean {
  const levelRank = bandRank(level)
  const thresholdRank = bandRank(threshold)
  // Both must be recognised; -1 means unknown → does NOT meet threshold.
  if (levelRank < 0 || thresholdRank < 0) return false
  return levelRank >= thresholdRank
}
