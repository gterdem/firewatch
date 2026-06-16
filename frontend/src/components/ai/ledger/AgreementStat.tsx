/**
 * AgreementStat — headline agreement stat from GET /ai/feedback/summary (MK-6, ADR-0045).
 *
 * Honest denominator rule (ADR-0045 D4):
 *   - The denominator (graded count) is ALWAYS visible — never a bare percentage.
 *   - When graded < 10: show counts only in plain language.
 *     No percentage — small-n honesty (not statistically meaningful).
 *   - When graded >= 10: show percentage WITH denominator in plain language.
 *
 * Plain-language headline (issue #454): first-person, explains the small-n threshold,
 * explains what "graded" means (you reviewed it), makes it obvious whose action drives
 * the stat. The RULE chip carries a title gloss "Computed from your grades — not AI"
 * (reusing the #451 gloss system) to clarify the chip meaning without prior knowledge.
 *
 * The stat carries a RULE ProvenanceChip (deterministic arithmetic over analyst
 * input — ADR-0035).
 *
 * States driven by useFeedbackSummary:
 *   loading — lightweight text placeholder (no spinner-forever).
 *   empty   — 503 / ledger not wired; renders nothing (non-fatal degrade).
 *   error   — concise error note.
 *   ok      — stat line + RULE chip.
 *
 * SECURITY (ADR-0029 D3): all values are numeric from the server; no
 * attacker-controlled strings are rendered.
 *
 * D2 reactivity: accepts refreshKey prop; passes it to useFeedbackSummary so
 * the stat re-fetches automatically after each successful analyst submit
 * (feedbackVersion counter lifted to AIRoute, no page reload needed).
 */

import { ProvenanceChip } from '../../ds'
import { useFeedbackSummary } from './useFeedback'
import { formatAgreementStatPlain } from './agreementStatUtils'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface AgreementStatProps {
  /**
   * Incrementing this value triggers a re-fetch of the summary stat.
   * AIRoute bumps feedbackVersion on every successful submit and passes it here
   * so the headline stays current without a full page reload (D2 reactivity fix).
   */
  refreshKey?: number
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * Page-level agreement headline stat — mounted once on the AI Engine page.
 *
 * Accepts refreshKey to re-fetch after a successful submit (D2 reactivity).
 *
 * Plain-language headline (issue #454): instead of the opaque "1 of 1 graded
 * verdicts agreed RULE", the stat now reads in first-person and the RULE chip
 * carries a gloss explaining it is computed from analyst grades, not AI output.
 */
export function AgreementStat({ refreshKey = 0 }: AgreementStatProps) {
  const { status, summary, error } = useFeedbackSummary(refreshKey)

  // Loading — lightweight placeholder (not spinner-forever, ADR-0043 D3).
  if (status === 'loading') {
    return (
      <p
        data-testid="agreement-stat-loading"
        style={{ color: 'var(--fw-t3)', fontSize: 'var(--fw-fs-body)' }}
        role="status"
      >
        Loading agreement stat…
      </p>
    )
  }

  // Empty — 503 / ledger not wired; non-fatal degrade (render nothing).
  if (status === 'empty') {
    return null
  }

  // Error — concise note (no fabricated counts).
  if (status === 'error') {
    return (
      <p
        data-testid="agreement-stat-error"
        role="alert"
        style={{
          color: 'var(--fw-red)',
          fontSize: 'var(--fw-fs-body)',
          margin: 0,
        }}
      >
        {error ?? 'Agreement stat unavailable.'}
      </p>
    )
  }

  // OK state — show the stat line.
  if (summary === null) {
    return null
  }

  const { graded, agreed, agreement_pct } = summary
  const [mainLine, subLine] = formatAgreementStatPlain(graded, agreed, agreement_pct)

  return (
    <div
      data-testid="agreement-stat"
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 2,
        fontFamily: 'var(--fw-font-ui)',
      }}
    >
      {/* Main stat line + RULE chip on the same row */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          flexWrap: 'wrap',
        }}
      >
        <span
          data-testid="agreement-stat-text"
          style={{
            fontSize: 'var(--fw-fs-body)',
            color: 'var(--fw-t1)',
          }}
        >
          {/* All values from server — numeric, no attacker-controlled strings */}
          {mainLine}
        </span>

        {/*
         * RULE ProvenanceChip — deterministic arithmetic over analyst input (ADR-0035).
         * The agreement percentage is computed from graded/agreed counts (not AI-derived).
         * title gloss (issue #454 / #451 gloss system): clarifies "Computed from your grades — not AI"
         * so the RULE chip meaning is immediately obvious without prior knowledge.
         */}
        <ProvenanceChip
          derivation="rule"
          data-testid="agreement-stat-rule-chip"
          title="Computed from your grades — not AI"
        />
      </div>

      {/* Sub-line: small-n notice (only shown when graded < SMALL_N_THRESHOLD) */}
      {subLine !== null && (
        <span
          data-testid="agreement-stat-subline"
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t3)',
          }}
        >
          {subLine}
        </span>
      )}
    </div>
  )
}
