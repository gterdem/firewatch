/**
 * evidenceUtils — pure helpers for the evidence chain UI.
 *
 * Separated from component files so that the react-refresh fast-reload
 * constraint (components must export only components) is respected.
 *
 * SECURITY (ADR-0029 D3): rule_ids counted as numbers, never rendered as strings.
 */

import type { EvidenceChainResponse, FactorEvidence, EvidenceItem } from '../../api/types'

const AI_BOOST_FACTOR = 'ai_boost'
const CAP_FACTOR = 'cap'

function isRuleFactor(item: EvidenceItem): item is FactorEvidence {
  return item.factor !== AI_BOOST_FACTOR && item.factor !== CAP_FACTOR
}

function isFactorEvidence(item: EvidenceItem): item is FactorEvidence {
  return 'summaries' in item
}

/**
 * Compute event count and distinct-rule count from the evidence chain.
 *
 * Every number comes from API-returned data — no inference, no LLM input
 * (EARS: every numeric claim SHALL come from API fields).
 *
 * - eventCount: sum of factor.count across all rule factors (not ai_boost, not cap).
 * - ruleCount:  count of distinct non-null rule_ids from all EventSummary records.
 */
export function computeEvidenceCounts(chain: EvidenceChainResponse): {
  eventCount: number
  ruleCount: number
} {
  let eventCount = 0
  const ruleIds = new Set<string>()

  for (const item of chain.factors) {
    if (!isRuleFactor(item)) continue
    if (!isFactorEvidence(item)) continue

    eventCount += item.count

    for (const summary of item.summaries) {
      if (summary.rule_id !== null) {
        ruleIds.add(String(summary.rule_id))
      }
    }
  }

  return { eventCount, ruleCount: ruleIds.size }
}
