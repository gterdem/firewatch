/**
 * Drift utility functions — issue #477 directional / de-escalation-emphasis polish.
 *
 * Extracted to a non-component module so that react-refresh/only-export-components
 * lint rule is satisfied (DriftDiffRow.tsx can re-export or import these without
 * mixing component and non-component exports in one file).
 *
 * ADR-0029 D3: all functions return plain strings — callers render as text nodes.
 */

/**
 * Severity ranking used for direction classification.
 * Higher number = higher severity.
 */
const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
}

/**
 * Classify the direction of a verdict change.
 *
 * - 'escalation'   — candidate moved to a HIGHER severity (new model more alarmed)
 * - 'deescalation' — candidate moved to a LOWER severity (new model less alarmed)
 *                    This is the dangerous case: a model that became less alarmed
 *                    about a known attack probe needs review.
 * - 'unchanged'    — verdicts are the same (should not appear in a diff list, but
 *                    handled defensively)
 */
export function driftDirection(
  baseline: string,
  candidate: string,
): 'escalation' | 'deescalation' | 'unchanged' {
  const baseRank = SEVERITY_ORDER[baseline.toUpperCase()] ?? 0
  const candRank = SEVERITY_ORDER[candidate.toUpperCase()] ?? 0

  if (candRank > baseRank) return 'escalation'
  if (candRank < baseRank) return 'deescalation'
  return 'unchanged'
}

/**
 * Derive a human-readable category label from a scenario identifier key.
 *
 * Scenario keys are synthetic fixture names (e.g. "concise_waf_no_corr",
 * "detailed_security_with_corr", "suricata_port_scan"). This function maps
 * them to analyst-friendly labels for use in story sentences.
 *
 * The mapping is based on the canonical scenario registry in
 * firewatch_core.ai.baseline.fixtures. Unknown keys fall back to the raw key
 * rendered with spaces ("concise waf no corr") so future scenarios degrade
 * gracefully without requiring a frontend edit.
 *
 * ADR-0029 D3: returned string is always used as a text node, never HTML.
 */
export function scenarioLabel(scenario: string): string {
  const key = scenario.toLowerCase()

  // Named mapping for canonical scenario categories.
  const KNOWN: Record<string, string> = {
    concise_waf_no_corr: 'WAF attack probe (no IDS correlation)',
    concise_waf_with_corr: 'WAF attack probe (with IDS correlation)',
    concise_security_no_corr: 'security-mode probe (no IDS correlation)',
    concise_security_with_corr: 'security-mode probe (with IDS correlation)',
    detailed_waf_no_corr: 'WAF attack probe — detailed path',
    detailed_waf_with_descs: 'WAF attack probe — detailed path with rule descriptions',
    detailed_security_with_corr: 'security-mode probe — detailed path',
    detailed_security_with_descs_and_corr: 'security-mode probe — detailed path with correlations',
    // Additional commonly-used scenario key patterns
    suricata_port_scan: 'Suricata port-scan probe',
    sql_injection: 'SQL-injection probe',
    xss_probe: 'cross-site scripting probe',
  }

  if (KNOWN[key] !== undefined) return KNOWN[key]

  // Graceful fallback: replace underscores with spaces (text node — always safe)
  return scenario.replace(/_/g, ' ')
}

/**
 * Compose the concrete story sentence for a diff row summary.
 *
 * Format (per issue #477 EARS):
 *   "On a [category], your old model called this [BASELINE];
 *    the new model calls it [CANDIDATE] — the new model is [less/more] alarmed."
 *
 * De-escalation phrase: "less alarmed" (the new model calmed down — risky)
 * Escalation phrase:    "more alarmed" (the new model is more cautious — notable)
 *
 * All interpolated values are plain strings (ADR-0029 D3: text node callers).
 */
export function diffStorySentence(
  scenario: string,
  baselineVerdict: string,
  candidateVerdict: string,
): string {
  const category = scenarioLabel(scenario)
  const direction = driftDirection(baselineVerdict, candidateVerdict)
  const alarmPhrase = direction === 'deescalation' ? 'less alarmed' : 'more alarmed'

  return (
    `On a ${category}, your old model called this ${baselineVerdict.toUpperCase()}; `
    + `the new model calls it ${candidateVerdict.toUpperCase()} `
    + `— the new model is ${alarmPhrase}.`
  )
}
