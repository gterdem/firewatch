/**
 * recommendationQueue — pure merge/sort/dedupe logic for the unified
 * "Recommended actions" queue (issue #208).
 *
 * Each `QueueItem` is one recommendation card. Items originate from two sources:
 *   RULE — derived from block-rate heuristic (always available; engine rule output).
 *   AI   — derived from ai_insights on the threat actor (only when ai_status === 'active').
 *
 * Merge contract:
 *   1. Start with RULE items for all actors (rules always run; AI is additive).
 *   2. When aiOnline AND ai_status === 'active' AND ai_insights are present for an
 *      actor, upgrade that actor's item to provenance 'ai+rule' and attach the
 *      AI-authored rationale.
 *   3. Dedupe by source_ip — one item per actor (AI upgrade wins on duplicate).
 *   4. Sort: by recAction priority (block > investigate > monitor), then by
 *      score descending within the same action tier.
 *
 * Priority map: block=0, investigate=1, monitor=2 (lower = higher priority).
 *
 * Copyable snippet: a paste-ready iptables block command for the operator.
 * The format is source-agnostic (multi-source platform); WAF-vendor-specific
 * syntax is deferred to the SOAR executor milestone (ADR-0033).
 *
 * This module is PURE — no React, no side effects, no API calls.
 * All helpers are exported for unit testing.
 *
 * ADR-0033: queue items are advice only; no item implies auto-execution.
 * ADR-0035: provenance derivation is honest — 'rule' when only rules ran.
 * SECURITY (ADR-0029 D3): all attacker-controlled strings (source_ip, ai_insights)
 * are passed through as-is; the render layer must use text nodes only.
 */

import type { ThreatScore } from '../api/types'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** The triage action recommended for an actor. */
export type RecAction = 'block' | 'investigate' | 'monitor'

/** Provenance of a recommendation item. */
export type ItemProvenance = 'rule' | 'ai+rule'

/**
 * One item in the unified recommendations queue.
 *
 * `id` is unique per actor (source_ip) — used as React key.
 * `provenance` is 'ai+rule' when AI insights upgraded the recommendation.
 * `rationale` is a one-line "because …" string derived from measurable data.
 * `aiRationale` is the first AI-authored insight shown when provenance is 'ai+rule'.
 * `copySnippet` is a paste-ready block command for the operator.
 * `actor` is the original ThreatScore so cards can pass it to onAction.
 * `counterfactualLine` is the "#215 seam" — a human-readable string such as
 *   "Would have stopped 1,204 of 1,350 requests" or
 *   "All 150 requests already blocked" or null when total_events is 0.
 *   Derived from ThreatScore.total_events / blocked_events — no extra API call.
 */
export interface QueueItem {
  id: string
  actor: ThreatScore
  recAction: RecAction
  provenance: ItemProvenance
  /** One-line "because …" rationale derived from rule data (always present). */
  rationale: string
  /**
   * AI-authored insight shown below the rationale when AI ran.
   * null when provenance === 'rule'.
   */
  aiRationale: string | null
  /** Paste-ready snippet for the operator. */
  copySnippet: string
  /** blockRate 0-100, retained for display. */
  blockRate: number
  /**
   * Counterfactual impact line (issue #215).
   * Human-readable "would have stopped N of M requests" derived from
   * ThreatScore.total_events and blocked_events — arithmetic over stored events,
   * never from LLM text (ADR-0033).
   * null when total_events === 0 (no stored events; nothing to show).
   */
  counterfactualLine: string | null
}

// ---------------------------------------------------------------------------
// Action derivation
// ---------------------------------------------------------------------------

/** Priority map for sorting: lower = higher priority. */
const ACTION_PRIORITY: Record<RecAction, number> = {
  block: 0,
  investigate: 1,
  monitor: 2,
}

/**
 * Derive the recommended triage action from block rate.
 *   ≥ 80% → block, ≥ 30% → investigate, else → monitor
 *
 * Matches the identical thresholds used in AiSidebar and RecommendationCards.
 */
export function deriveRecAction(blockRate: number): RecAction {
  if (blockRate >= 80) return 'block'
  if (blockRate >= 30) return 'investigate'
  return 'monitor'
}

// ---------------------------------------------------------------------------
// Rationale derivation
// ---------------------------------------------------------------------------

/**
 * Build the one-line "because …" rationale from rule-engine data.
 *
 * Examples:
 *   "100% of 150 events blocked — exceeds block threshold"
 *   "79% of 30 events blocked — above investigate threshold"
 *   "8% of 25 events blocked — below investigation threshold"
 *
 * All inputs are numbers from ThreatScore — not attacker-controlled free text.
 */
export function buildRationale(
  blockRate: number,
  totalEvents: number,
  recAction: RecAction,
): string {
  const pctStr = `${blockRate}%`
  const countStr = `${totalEvents.toLocaleString()} event${totalEvents === 1 ? '' : 's'}`

  switch (recAction) {
    case 'block':
      return `${pctStr} of ${countStr} blocked — exceeds block threshold`
    case 'investigate':
      return `${pctStr} of ${countStr} blocked — above investigate threshold`
    case 'monitor':
      return `${pctStr} of ${countStr} blocked — below investigation threshold`
  }
}

// ---------------------------------------------------------------------------
// Copyable snippet generation
// ---------------------------------------------------------------------------

/**
 * Build a paste-ready blocking snippet for the given IP.
 *
 * Uses generic iptables syntax as the lowest-common-denominator format.
 * Vendor-specific WAF syntax (Azure CLI, AWS WAF rules, etc.) is deferred
 * to the SOAR executor milestone (ADR-0033).
 *
 * SECURITY: source_ip is passed as-is. The render layer must write the snippet
 * via navigator.clipboard.writeText() (text-only), never via innerHTML.
 */
export function buildCopySnippet(sourceIp: string): string {
  return `iptables -A INPUT -s ${sourceIp} -j DROP`
}

// ---------------------------------------------------------------------------
// Counterfactual line (issue #215)
// ---------------------------------------------------------------------------

/**
 * Build the "would have stopped N of M requests" counterfactual line.
 *
 * Semantics (ADR-0033 — retrospective/descriptive, never an executed action):
 *   unblocked = totalEvents − blockedEvents
 *
 * ADR-0012: Suricata IDS events carry action='ALERT' (detected, not stopped).
 * They are correctly counted in `unblocked` because they were NOT blocked.
 * A block on this IP would have stopped them.  No per-source special-casing.
 *
 * Returns null when totalEvents === 0 — no events means nothing to show.
 * When all events are already blocked the caller learns this from the returned
 * copy ("all N requests already blocked") rather than a bare "0".
 *
 * All inputs are numbers from ThreatScore — not attacker-controlled free text.
 */
export function buildCounterfactualLine(
  totalEvents: number,
  blockedEvents: number,
): string | null {
  if (totalEvents === 0) return null

  const unblocked = totalEvents - blockedEvents
  const totalStr = totalEvents.toLocaleString()
  const reqStr = (n: number) => `${n.toLocaleString()} request${n === 1 ? '' : 's'}`

  if (unblocked === 0) {
    // All events already blocked — honest and itself informative.
    return `All ${reqStr(totalEvents)} already blocked`
  }
  return `Would have stopped ${reqStr(unblocked)} of ${totalStr}`
}

// ---------------------------------------------------------------------------
// Merge + sort
// ---------------------------------------------------------------------------

/**
 * Build the unified recommendations queue from the threats array.
 *
 * Algorithm:
 *   1. Filter out dismissed actors via the optional `isActorDismissed` predicate
 *      (issue #564: keeps card-queue in sync with the triage banner).
 *   2. Compute RULE item for every remaining actor.
 *   3. Where aiOnline AND ai_status === 'active' AND ai_insights are non-empty,
 *      upgrade to 'ai+rule' provenance and attach the first AI insight as aiRationale.
 *   4. Sort by ACTION_PRIORITY asc, then score desc within same tier.
 *
 * The caller passes `aiOnline` (derived from GET /health) so the queue
 * respects the authoritative engine state rather than per-actor ai_status quirks.
 * When aiOnline=false, all items stay 'rule' provenance regardless of individual
 * ai_status fields — the "Rules-only mode · AI engine offline" badge shows.
 *
 * @param threats            Threat actors from GET /threats.
 * @param aiOnline           Whether the AI engine is active (health.ai === 'active';
 *                           see resolveHealthAiState in components/aiStatusCopy.ts —
 *                           issue #93, ADR-0066 tri-state).
 *                           Defaults to false (safe default: degrade to rules-only when unknown).
 * @param isActorDismissed   Optional predicate — return true for actors that have been dismissed.
 *                           When provided, dismissed actors are excluded from the output so the
 *                           card queue stays consistent with the triage banner (issue #564).
 *                           Defaults to () => false (no filtering — backward-compatible).
 */
export function buildRecommendationQueue(
  threats: ThreatScore[],
  aiOnline = false,
  isActorDismissed: (actor: ThreatScore) => boolean = () => false,
): QueueItem[] {
  const itemMap = new Map<string, QueueItem>()

  // Issue #564: exclude dismissed actors so the card queue matches the triage banner.
  const activeThreats = threats.filter((t) => !isActorDismissed(t))

  for (const actor of activeThreats) {
    const blockRate =
      actor.total_events > 0
        ? Math.round((actor.blocked_events / actor.total_events) * 100)
        : 0
    const recAction = deriveRecAction(blockRate)

    // AI upgrade: only when global engine is online AND this actor has insights
    const hasAiInsights =
      aiOnline &&
      actor.ai_status === 'active' &&
      Array.isArray(actor.ai_insights) &&
      actor.ai_insights.length > 0

    const provenance: ItemProvenance = hasAiInsights ? 'ai+rule' : 'rule'
    const aiRationale: string | null = hasAiInsights
      ? String((actor.ai_insights as string[])[0])
      : null

    const item: QueueItem = {
      id: actor.source_ip,
      actor,
      recAction,
      provenance,
      rationale: buildRationale(blockRate, actor.total_events, recAction),
      aiRationale,
      copySnippet: buildCopySnippet(actor.source_ip),
      blockRate,
      counterfactualLine: buildCounterfactualLine(actor.total_events, actor.blocked_events),
    }

    // Dedupe by source_ip — AI upgrade wins over a prior rule-only item
    const existing = itemMap.get(actor.source_ip)
    if (!existing || provenance === 'ai+rule') {
      itemMap.set(actor.source_ip, item)
    }
  }

  // Sort: action priority asc, then score desc within same tier
  return Array.from(itemMap.values()).sort((a, b) => {
    const priorityDiff = ACTION_PRIORITY[a.recAction] - ACTION_PRIORITY[b.recAction]
    if (priorityDiff !== 0) return priorityDiff
    return b.actor.score - a.actor.score
  })
}
