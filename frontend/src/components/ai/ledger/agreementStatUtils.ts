/**
 * Utility for formatting the agreement stat text (ADR-0045 D4 / issue #411, #454).
 *
 * Kept in a separate module so react-refresh/only-export-components is satisfied
 * (AgreementStat.tsx can export the component cleanly; tests import this directly).
 */

/** Minimum graded count before the percentage is shown (small-n honesty rule). */
export const SMALL_N_THRESHOLD = 10

/**
 * Format the agreement stat text per the honest-denominator and small-n rules.
 *
 * ADR-0045 D4 / issue #411 EARS:
 *   graded >= 10 → "Analyst agreement: 84% over 120 graded verdicts"
 *   graded  <  10 → "7 of 9 graded verdicts agreed" (no percentage)
 *   graded === 0  → "No graded verdicts yet"
 *
 * @deprecated Prefer formatAgreementStatPlain for new UI — this form is preserved
 * for backward-compatibility with existing tests and callers.
 */
export function formatAgreementStat(
  graded: number,
  agreed: number,
  agreementPct: number,
): string {
  if (graded === 0) {
    return 'No graded verdicts yet'
  }
  if (graded < SMALL_N_THRESHOLD) {
    // Small-n: counts only, no percentage.
    return `${agreed} of ${graded} graded verdicts agreed`
  }
  // Sufficient sample: percentage + denominator (honest denominator rule).
  const pct = Math.round(agreementPct)
  return `Analyst agreement: ${pct}% over ${graded} graded verdicts`
}

/**
 * Plain-language agreement stat headline (issue #454, ADR-0045 D4).
 *
 * Returns a two-element tuple: [mainLine, subLine | null].
 *
 * Rules:
 *   graded === 0  → "You haven't graded any AI verdicts yet." / null
 *   graded < 10   → "You've reviewed N AI verdict(s) so far and agreed with M."
 *                   / "(Agreement % appears once you've graded 10+.)"
 *   graded >= 10  → "You've agreed with M of N AI verdicts you've graded (P%)."
 *                   / null
 *
 * The honest-denominator rule (ADR-0045 D4) is preserved: the graded count is
 * always visible; no bare percentage is ever emitted.
 * The small-n rule is preserved: no percentage below SMALL_N_THRESHOLD.
 */
export function formatAgreementStatPlain(
  graded: number,
  agreed: number,
  agreementPct: number,
): [string, string | null] {
  if (graded === 0) {
    return ["You haven't graded any AI verdicts yet.", null]
  }
  if (graded < SMALL_N_THRESHOLD) {
    const verdictWord = graded === 1 ? 'verdict' : 'verdicts'
    return [
      `You've reviewed ${graded} AI ${verdictWord} so far and agreed with ${agreed}.`,
      `(Agreement % appears once you've graded ${SMALL_N_THRESHOLD}+.)`,
    ]
  }
  // Sufficient sample: percentage + denominator (honest denominator rule).
  const pct = Math.round(agreementPct)
  return [
    `You've agreed with ${agreed} of ${graded} AI verdicts you've graded (${pct}%).`,
    null,
  ]
}
