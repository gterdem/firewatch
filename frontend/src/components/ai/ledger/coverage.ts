/**
 * coverage.ts — pure rollup helpers for the AI coverage ledger (MK-3, ADR-0043).
 *
 * These functions derive coverage counts from the threats array (GET /threats)
 * and the analyses list (GET /ai/analyses). All logic is deterministic arithmetic
 * and must carry RULE provenance in the UI (ADR-0035).
 *
 * No side-effects. No network calls. Unit-testable in isolation.
 *
 * Derivation:
 *   - total actors     = threats.length (from /threats payload)
 *   - ai_analysed      = distinct IPs present in the verdict ledger (GET /ai/analyses).
 *                        An IP is AI-analysed if the model produced a verdict for it,
 *                        regardless of whether that verdict changed the score.
 *                        NOTE: the ledger's score_derivation field ('ai', 'ai+rule', 'rule')
 *                        distinguishes whether the AI verdict boosted the score;
 *                        the /threats payload ai_status ('active', 'disabled', 'unavailable', …)
 *                        reflects a different signal — do NOT conflate these two.
 *   - moved_score      = ledger IPs whose score_derivation includes 'ai' (boost fired).
 *                        Derivable from analyses array directly — never from /threats ai_status.
 *   - below_boost_gate = ledger IPs whose score_derivation === 'rule'
 *                        (AI ran but confidence was below the boost gate → score stayed rule-derived).
 *   - rules_only       = actors with NO ledger entry (AI never ran for them)
 *   - below_threshold  = threats with score === 0 (the ?filter=below-threshold bucket)
 *   - ledger_count     = items.length from /ai/analyses (persisted analyses in ledger)
 *   - analysesHasMore  = true when the ledger has >200 rows (rollup fetch was capped)
 */

import type { ThreatScore } from '../../../api/types'
import type { AnalysisSummary } from '../../../api/types'

/** Coverage rollup derived from the threats payload and the ledger list. */
export interface CoverageRollup {
  /** Total distinct IP actors (from /threats). */
  totalActors: number
  /**
   * Actors present in the verdict ledger (AI actually analysed them).
   * Derived from distinct IPs in GET /ai/analyses, NOT from ai_status='active'.
   * An actor can have ai_status='disabled' (rules-only) but still be in the ledger
   * when the model ran on-demand and produced a verdict for it.
   */
  aiAnalysed: number
  /** Actors with NO ledger entry (rule-only scoring path — AI never ran). */
  rulesOnly: number
  /** Actors with score === 0 (below sampling threshold, ?filter=below-threshold). */
  belowThreshold: number
  /** Count of persisted analysis rows in the ledger (from /ai/analyses). */
  ledgerCount: number
  /**
   * Count of ledger IPs whose score_derivation includes 'ai' (boost fired, score moved).
   * Derivable directly from the analyses array score_derivation field.
   * Optional — defaults to 0 when constructing rollup objects in tests.
   */
  movedScore?: number
  /**
   * Count of ledger IPs whose score_derivation === 'rule'
   * (AI ran and produced a verdict, but confidence was below the boost gate →
   * score stayed rule-derived). These actors ARE counted in aiAnalysed.
   * Optional — defaults to 0 when constructing rollup objects in tests.
   */
  belowBoostGate?: number
  /**
   * True when the ledger fetch was capped (has_more=true from the API).
   * When true, the aiAnalysed count should be displayed as "N+" to avoid
   * falsely claiming an exact total (never invent a number — ADR-0043 D1).
   * Optional — defaults to false when constructing rollup objects in tests.
   */
  analysesHasMore?: boolean
}

/**
 * Derive coverage rollup from threats and ledger items.
 *
 * @param threats           - Array from GET /threats (may be empty).
 * @param analyses          - Array from GET /ai/analyses items (may be empty or null when ledger absent).
 * @param analysesHasMore   - Whether the ledger API returned has_more=true (rollup is a lower bound).
 */
export function computeCoverageRollup(
  threats: ThreatScore[],
  analyses: AnalysisSummary[] | null,
  analysesHasMore = false,
): CoverageRollup {
  const totalActors = threats.length

  // "AI analysed" = distinct IPs in the verdict ledger.
  // score_derivation on the analysis record tells us whether the AI verdict moved the score
  // ('ai' / 'ai+rule' = boost fired; 'rule' = AI ran but score stayed rule-derived).
  // This is different from the /threats payload ai_status ('active' / 'disabled' / 'unavailable')
  // which reflects a different runtime signal — the two must NOT be conflated.
  const analysesList = analyses ?? []
  const ledgerIpSet = new Set(analysesList.map((a) => a.ip))
  const aiAnalysed = ledgerIpSet.size

  // moved_score = distinct IPs in the ledger whose score_derivation includes 'ai' (boost fired).
  const movedScoreSet = new Set(
    analysesList
      .filter((a) => a.score_derivation === 'ai' || a.score_derivation === 'ai+rule')
      .map((a) => a.ip),
  )
  const movedScore = movedScoreSet.size

  // below_boost_gate = ledger IPs where AI ran but score stayed rule-derived.
  const belowBoostGate = aiAnalysed - movedScore

  // rules_only = actors with no ledger entry at all (AI never touched them).
  const rulesOnly = threats.filter((t) => !ledgerIpSet.has(t.source_ip)).length
  const belowThreshold = threats.filter((t) => t.score === 0).length
  const ledgerCount = analysesList.length

  return {
    totalActors,
    aiAnalysed,
    rulesOnly,
    belowThreshold,
    ledgerCount,
    movedScore,
    belowBoostGate,
    analysesHasMore,
  }
}

/**
 * Format the coverage headline sentence from real rollup numbers.
 *
 * Preferred wording: "N of M actors have AI verdicts · K rules-only · …"
 * When no AI ran: "0 of M actors have AI verdicts · M rules-only."
 * Never invents or fabricates numbers — all come from API fields.
 *
 * When analysesHasMore is true (ledger was capped at 200), the analysed count
 * is rendered as "N+" to honestly reflect the lower bound (ADR-0043 D1).
 *
 * When movedScore / belowBoostGate are non-zero, a sub-split facet is appended:
 * "…of which X moved the score · Y below the boost gate."
 */
export function formatCoverageHeadline(rollup: CoverageRollup): string {
  const {
    totalActors,
    aiAnalysed,
    rulesOnly,
    movedScore = 0,
    belowBoostGate = 0,
    analysesHasMore = false,
  } = rollup

  if (totalActors === 0) return 'No actors observed yet.'

  // When the rollup fetch was capped, signal "at least N" to avoid a false exact count.
  const analysedLabel = analysesHasMore ? `${aiAnalysed}+` : String(aiAnalysed)

  const parts: string[] = []
  parts.push(`${analysedLabel} of ${totalActors} actors have AI verdicts`)
  if (rulesOnly > 0) parts.push(`${rulesOnly} rules-only`)

  let headline = parts.join(' · ') + '.' 

  // Sub-split facet — only append when AI did run for some actors.
  if (aiAnalysed > 0 && (movedScore > 0 || belowBoostGate > 0)) {
    const facetParts: string[] = []
    if (movedScore > 0) facetParts.push(`${movedScore} moved the score`)
    if (belowBoostGate > 0) facetParts.push(`${belowBoostGate} below the boost gate`)
    if (facetParts.length > 0) {
      headline += ` Of which: ${facetParts.join(' · ')}.`
    }
  }

  return headline
}

// ---------------------------------------------------------------------------
// AI status label helpers (BUG-1b fix, #448; semantics corrected MM)
// ---------------------------------------------------------------------------

/**
 * Map the ThreatScore ai_status enum to a plain, honest user-facing label.
 *
 * ThreatScore.ai_status reflects the REAL-TIME (fast-path) score pipeline:
 *   'active'      — AI actually ran on this actor's real-time score and produced a verdict.
 *   'disabled'    — AI was NOT run (use_ai=False / rules-only path). The default for ALL
 *                   actors in the live /threats payload. It does NOT mean "AI ran but was
 *                   below a threshold" — it means AI was not invoked at all. Honest label: "Rules-only".
 *   'unavailable' — AI was attempted but the engine was unreachable → rules-only score.
 *   'degraded'    — AI ran in a degraded state.
 *   'error'       — AI pipeline raised an error.
 *   'skipped'     — Caller passed ?ai=false (issue #268 fast-path, no AI ran).
 *
 * 'ok' is a LEDGER ai_status (AnalysisSummary.ai_status), NEVER a ThreatScore value.
 *
 * NEVER renders the raw enum string as user-facing text (ADR-0029 D3).
 * Tone is non-alarming per ADR-0015: rules-only is the normal floor, not an error.
 */
export function formatAiStatus(aiStatus: string): string {
  switch (aiStatus) {
    case 'active':
      return 'AI-analyzed'
    case 'unavailable':
      return 'AI unavailable'
    case 'degraded':
      return 'AI degraded'
    // 'disabled', 'error', 'skipped', and any future/unknown value all mean AI did not run
    // on this actor → the honest label is "Rules-only". Never imply AI reviewed a
    // rules-only actor.
    default:
      return 'Rules-only'
  }
}

/**
 * Derive the CSS color token for the ai_status label.
 * Green for 'active' (AI ran on this actor); muted for all other states (ADR-0015).
 */
export function aiStatusColor(aiStatus: string): string {
  return aiStatus === 'active' ? 'var(--fw-green)' : 'var(--fw-t3)'
}

/**
 * Format the age of an analysis for display.
 *
 * Returns human-readable relative time: "2h ago", "5m ago", "just now", "3d ago".
 * Falls back to the ISO string if the date cannot be parsed.
 *
 * @param createdAt - UTC ISO-8601 string from the ledger.
 * @param now - Optional current time (for testability); defaults to Date.now().
 */
export function formatAnalysisAge(createdAt: string, now: number = Date.now()): string {
  const ms = Date.parse(createdAt)
  if (isNaN(ms)) return createdAt

  const diffMs = now - ms
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHour = Math.floor(diffMin / 60)
  const diffDay = Math.floor(diffHour / 24)

  if (diffSec < 60) return 'just now'
  if (diffMin < 60) return `${diffMin}m ago`
  if (diffHour < 24) return `${diffHour}h ago`
  return `${diffDay}d ago`
}
