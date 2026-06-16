/**
 * EvidenceFooter — "Based on N events · M rules" footer line.
 *
 * Every number is templated from MI-6 API fields — never from LLM-authored text
 * (EARS criterion: every numeric claim from API data).
 *
 * Counts computed from the evidence chain by computeEvidenceCounts (evidenceUtils.ts):
 *   N events — sum of factor counts across all rule factors (not ai_boost, not cap).
 *   M rules  — count of distinct non-null rule_ids from all EventSummary records.
 *
 * When the evidence chain is unavailable (status=empty/error), renders a degrade
 * message without fabricated counts and without a spinner.
 *
 * SECURITY (ADR-0029 D3): all EventSummary fields are attacker-controlled.
 * rule_ids are rendered only as counts (numbers) — never as raw strings here.
 */

import type { EvidenceChainResponse } from '../../api/types'
import { computeEvidenceCounts } from './evidenceUtils'

// ---------------------------------------------------------------------------
// EvidenceFooter
// ---------------------------------------------------------------------------

export interface EvidenceFooterProps {
  /**
   * Evidence chain data from the API. When null (loading or unavailable),
   * the footer degrades honestly with no fabricated counts.
   */
  chain: EvidenceChainResponse | null
  /**
   * When true, the evidence is confirmed empty (IP has no stored events).
   * Render a clear "no evidence available" message — no spinner.
   */
  isEmpty?: boolean
  /**
   * Human-readable error string from useEvidenceChain.
   * When set, renders an error message in place of counts.
   */
  error?: string | null
}

export function EvidenceFooter({ chain, isEmpty, error }: EvidenceFooterProps) {
  // Degrade: error state
  if (error) {
    return (
      <p
        data-testid="evidence-footer-error"
        style={{ fontSize: 11, color: 'var(--fw-t3)', marginTop: 8 }}
      >
        Evidence data unavailable
      </p>
    )
  }

  // Degrade: empty state (IP has no stored events — 404 from endpoint)
  if (isEmpty) {
    return (
      <p
        data-testid="evidence-footer-empty"
        style={{ fontSize: 11, color: 'var(--fw-t3)', marginTop: 8 }}
      >
        No stored events — evidence chain not available
      </p>
    )
  }

  // Still loading (chain === null, not empty, no error)
  if (chain === null) {
    return null
  }

  // Counts from API data — never from LLM text
  const { eventCount, ruleCount } = computeEvidenceCounts(chain)

  return (
    <p
      data-testid="evidence-footer"
      style={{
        fontSize: 11,
        color: 'var(--fw-t3)',
        marginTop: 8,
        fontFamily: 'var(--fw-font-ui)',
      }}
    >
      Based on{' '}
      <span
        data-testid="evidence-footer-event-count"
        style={{ color: 'var(--fw-t2)', fontWeight: 600 }}
      >
        {eventCount}
      </span>{' '}
      {eventCount === 1 ? 'event' : 'events'}
      {ruleCount > 0 && (
        <>
          {' · '}
          <span
            data-testid="evidence-footer-rule-count"
            style={{ color: 'var(--fw-t2)', fontWeight: 600 }}
          >
            {ruleCount}
          </span>{' '}
          {ruleCount === 1 ? 'rule' : 'rules'}
        </>
      )}
    </p>
  )
}
