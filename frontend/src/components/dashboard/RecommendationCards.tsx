/**
 * RecommendationCards — unified "Recommended actions" queue (issue #208).
 *
 * Replaces both the old RecommendationCards (AI-only cards) and the
 * AiSidebar "⚡ Recommendations" sb-card. One queue, one place.
 *
 * Features (EARS #208):
 *   - Every card has a ProvenanceChip (RULE or AI+RULE, ADR-0035).
 *   - Every card has a "because …" rationale derived from measurable data.
 *   - Evidence link: ClickableIp → entity slide-over (#202).
 *   - Per-card dismiss/done via onAction(actor, "dismiss") — no local state.
 *   - Copy affordance: paste-ready snippet via navigator.clipboard.writeText().
 *   - AI-offline fallback: queue header gains a rules-only badge when AI is not
 *     active; rule-derived cards always show; queue never goes blank. Badge tone
 *     differentiates WHY (issue #93, ADR-0066 tri-state): health.ai='unreachable'
 *     shows attention-worthy amber ("AI unreachable · rules-only"); health.ai=
 *     'disabled' shows the neutral RULES_ONLY_DEGRADED_WORDING. The two are never
 *     collapsed into the same treatment (the honesty bug #41 fixes elsewhere).
 *   - Actions are phrased as recommendations — "Consider blocking …" (ADR-0033).
 *   - Block/Investigate/Dismiss buttons call onAction(actor, verb) — zero per-verb
 *     logic in this component (ADR-0033 action seam).
 *
 * Module structure:
 *   RecommendationCards (this file) — presentational queue + card rendering.
 *   lib/recommendationQueue.ts       — pure merge/sort/dedupe logic + types.
 *
 * Provenance (ADR-0035):
 *   - RULE chip → derived from heuristic block-rate rule.
 *   - AI+RULE chip → AI insight upgraded the rationale (aiOnline=true required).
 *
 * SECURITY (ADR-0029 D3): source_ip and ai_insights are attacker-controlled.
 * Rendered as text nodes only — never via dangerouslySetInnerHTML.
 *
 * ADR-0028 D6: no raw hex — all colors via var(--fw-*) tokens.
 * a11y (#67): real focusable <button> elements with aria-label.
 *
 * #215 (implemented): QueueItem.counterfactualLine carries the
 * "would have stopped N requests" line — rendered below the AI rationale.
 * Derived from ThreatScore.total_events / blocked_events in buildRecommendationQueue;
 * no extra API call and no component structural change needed (as noted in the seam).
 *
 * CR6 (#617): compact mode for sidebar placement — top-N=3 cards with a
 * "view all" affordance; rationale/snippet/counterfactual hidden to fit sidebar
 * density (compress layout, not meaning — provenance + IP retained per ADR-0035).
 * No inner scrollbar: top-N prevents overflow.
 */

import { useRef, useState } from 'react'
import type { ThreatScore, HealthResponse } from '../../api/types'
import type { OnAction } from '../../lib/triageActions'
import { isSuppressed } from '../../lib/triageDecisions'
import { buildRecommendationQueue } from '../../lib/recommendationQueue'
import type { QueueItem, RecAction } from '../../lib/recommendationQueue'
import { ProvenanceChip } from '../ds'
import { RULES_ONLY_DEGRADED_WORDING } from '../../lib/provenance'
import { AI_STATUS_COPY, resolveHealthAiState } from '../aiStatusCopy'
import ClickableIp from '../entity/ClickableIp'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

/** Number of cards shown in compact (sidebar) mode before "view all" appears. */
export const COMPACT_TOP_N = 3

interface RecommendationCardsProps {
  /** All threat actors from GET /threats. */
  threats: ThreatScore[]
  /** Action seam — onAction(actor, verb). Component holds ZERO per-verb logic. */
  onAction: OnAction
  /**
   * Authoritative AI engine state from GET /health.
   * null = health not yet loaded or fetch failed (degrade to rules-only).
   */
  health?: HealthResponse | null
  /**
   * compact=true — sidebar mode (CR6 #617).
   * Shows top-3 cards in a denser layout (provenance chip + IP + action label +
   * action buttons); hides rationale, copy snippet and counterfactual to match
   * sidebar density. "View all" affordance appears when queue.length > COMPACT_TOP_N.
   * No inner scrollbar: top-N prevents overflow.
   * Default: false (full dash-main view).
   */
  compact?: boolean
}

// ---------------------------------------------------------------------------
// Styling helpers
// ---------------------------------------------------------------------------

const ACTION_STRIPE: Record<RecAction, string> = {
  block: 'var(--fw-red)',
  investigate: 'var(--fw-orange)',
  monitor: 'var(--fw-blue)',
}

const ACTION_LABEL: Record<RecAction, string> = {
  block: 'Consider blocking',
  investigate: 'Consider investigating',
  monitor: 'Consider monitoring',
}

// ---------------------------------------------------------------------------
// CopyButton — inline copy affordance
// ---------------------------------------------------------------------------

interface CopyButtonProps {
  snippet: string
  ariaLabel: string
}

function CopyButton({ snippet, ariaLabel }: CopyButtonProps) {
  // Fire-and-forget clipboard write — no state update needed in the triage queue
  const copiedRef = useRef(false)

  function handleCopy() {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      void navigator.clipboard.writeText(snippet)
    }
    copiedRef.current = true
  }

  return (
    <button
      type="button"
      data-testid="rec-card-copy"
      aria-label={ariaLabel}
      onClick={handleCopy}
      style={{
        padding: '2px 8px',
        borderRadius: 4,
        fontSize: 11,
        cursor: 'pointer',
        border: '1px solid var(--fw-border)',
        background: 'transparent',
        color: 'var(--fw-t3)',
        fontFamily: 'var(--fw-font-ui)',
      }}
    >
      Copy snippet
    </button>
  )
}

// ---------------------------------------------------------------------------
// RecCard — one item in the queue
// ---------------------------------------------------------------------------

interface RecCardProps {
  item: QueueItem
  onAction: OnAction
  /** compact=true — sidebar mode: shows only provenance + IP + action label + action buttons */
  compact?: boolean
}

function RecCard({ item, onAction, compact = false }: RecCardProps) {
  const { actor, recAction, provenance, rationale, aiRationale, copySnippet, counterfactualLine } = item
  const stripe = ACTION_STRIPE[recAction]
  const actionLabel = ACTION_LABEL[recAction]

  return (
    <div
      data-testid="rec-card"
      style={{
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border)',
        borderLeft: `4px solid ${stripe}`,
        borderRadius: 8,
        padding: compact ? '8px 10px' : '12px 14px',
      }}
    >
      {/* Card header: provenance chip + advice label + IP evidence link */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 6,
          marginBottom: compact ? 4 : 6,
        }}
      >
        <ProvenanceChip
          derivation={provenance}
          data-testid="rec-card-provenance"
        />
        <span
          style={{ fontSize: compact ? 11 : 12, color: 'var(--fw-t2)' }}
          data-testid="rec-card-action-label"
        >
          {actionLabel}
        </span>
        {/* ClickableIp is the evidence link (#202) — opens entity slide-over */}
        <ClickableIp
          value={actor.source_ip}
          style={{ fontSize: compact ? 11 : 12 }}
          aria-label={`Open entity panel for ${actor.source_ip}`}
        />
      </div>

      {/* Full mode only: "Because …" rationale (ADR-0035 — derived from rule data) */}
      {!compact && (
        <div
          style={{ fontSize: 11, color: 'var(--fw-t3)', marginBottom: aiRationale ? 4 : 8 }}
          data-testid="rec-card-rationale"
        >
          Because: {rationale}
        </div>
      )}

      {/* Full mode only: AI insight (attacker-controlled: text node only) */}
      {!compact && aiRationale !== null && (
        <div
          style={{
            fontSize: 11,
            color: 'var(--fw-accent)',
            marginBottom: 4,
            fontStyle: 'italic',
          }}
          data-testid="rec-card-ai-rationale"
        >
          {String(aiRationale)}
        </div>
      )}

      {/* Full mode only: counterfactual impact line (#215) */}
      {!compact && counterfactualLine !== null && (
        <div
          style={{
            fontSize: 11,
            color: 'var(--fw-t2)',
            marginBottom: 8,
            fontWeight: 500,
          }}
          data-testid="rec-card-counterfactual"
        >
          {counterfactualLine}
        </div>
      )}

      {/* Full mode only: copyable snippet */}
      {!compact && (
        <div
          style={{
            fontFamily: 'var(--fw-font-mono)',
            fontSize: 11,
            color: 'var(--fw-t3)',
            background: 'var(--fw-bg-input)',
            border: '1px solid var(--fw-border)',
            borderRadius: 4,
            padding: '4px 8px',
            marginBottom: 10,
            wordBreak: 'break-all',
          }}
          data-testid="rec-card-snippet"
        >
          {copySnippet}
        </div>
      )}

      {/* Action buttons — via onAction seam only (ADR-0033); zero per-verb logic here.
          Present in both full and compact modes (advisory actions, ADR-0033).
          compact mode: smaller padding to match sidebar density.
          NOTE (issue #758): Block button removed from UI — SOAR enforcement not yet
          available. The 'block' verb + onBlock seam remain dormant in triageActions.ts
          for future SOAR wiring (ADR-0033 / issue #653). */}
      <div
        style={{ display: 'flex', gap: compact ? 4 : 8, flexWrap: 'wrap', alignItems: 'center' }}
        data-testid="rec-card-actions"
      >
        <button
          type="button"
          data-testid="rec-card-investigate"
          aria-label={`Investigate ${actor.source_ip}`}
          onClick={() => onAction(actor, 'investigate')}
          style={{
            padding: compact ? '2px 8px' : '4px 12px',
            borderRadius: 5,
            fontSize: compact ? 11 : 12,
            fontWeight: 600,
            cursor: 'pointer',
            border: '1px solid var(--fw-border)',
            background: 'transparent',
            color: 'var(--fw-blue)',
          }}
        >
          Investigate
        </button>

        <button
          type="button"
          data-testid="rec-card-dismiss"
          aria-label={`Dismiss ${actor.source_ip}`}
          onClick={() => onAction(actor, 'dismiss')}
          style={{
            padding: compact ? '2px 8px' : '4px 12px',
            borderRadius: 5,
            fontSize: compact ? 11 : 12,
            cursor: 'pointer',
            border: '1px solid var(--fw-border)',
            background: 'transparent',
            color: 'var(--fw-t3)',
          }}
        >
          Done
        </button>

        {/* Full mode only: copy snippet button */}
        {!compact && (
          <div style={{ marginLeft: 'auto' }}>
            <CopyButton
              snippet={copySnippet}
              ariaLabel={`Copy blocking snippet for ${actor.source_ip}`}
            />
          </div>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// RecommendationCards — the unified queue (issue #208)
// ---------------------------------------------------------------------------

export default function RecommendationCards({ threats, onAction, health, compact = false }: RecommendationCardsProps) {
  // CR6 (#617): compact mode "view all" toggle — local expand state.
  // Starts collapsed; user expands inline (no inner scrollbar; no route navigation).
  const [expanded, setExpanded] = useState(false)

  // Determine AI engine state (issue #93, ADR-0066 tri-state) — health.ai is
  // authoritative via resolveHealthAiState; fall back to any threat having
  // ai_status=active when health fetch has not resolved yet (health=null).
  // The fallback mirrors AiPanel.tsx: any non-'active' threat-derived signal
  // degrades to the conservative 'disabled' bucket (never asserts a fault from
  // threat data alone).
  const aiState: 'active' | 'disabled' | 'unreachable' =
    health != null
      ? resolveHealthAiState(health)
      : threats.some((t) => t.ai_status === 'active')
        ? 'active'
        : 'disabled'
  const aiOnline: boolean = aiState === 'active'

  // Issue #564 / ADR-0072 D3: pass isSuppressed so server-decided actors are
  // excluded from the queue. This keeps the card queue consistent with the
  // triage banner (which also filters via isSuppressed in deriveTriageActors).
  // The predicate reads the server-computed `triage_decision.suppressed`
  // annotation on GET /threats — no client-side lifecycle logic (ADR-0072
  // must-NOT criterion) and no localStorage.
  const queue = buildRecommendationQueue(threats, aiOnline, isSuppressed)

  if (queue.length === 0) {
    return (
      <p
        style={{ fontSize: 12, color: 'var(--fw-t3)', padding: compact ? '8px 0' : '12px 0' }}
        data-testid="rec-cards-empty"
      >
        No threat actors to recommend action on.
      </p>
    )
  }

  // CR6 (#617): compact mode shows top COMPACT_TOP_N unless expanded; full mode shows top 5.
  // No inner scrollbar in either mode — top-N prevents overflow.
  const topN = compact && !expanded ? COMPACT_TOP_N : 5
  const top = queue.slice(0, topN)
  const hiddenCount = queue.length - top.length

  return (
    <div
      data-testid="recommendation-cards"
      style={{ display: 'flex', flexDirection: 'column', gap: compact ? 6 : 10 }}
    >
      {/* Queue header — AI-offline badge when engine is unreachable (EARS #208 criterion 3) */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 6,
          marginBottom: 2,
        }}
        data-testid="rec-queue-header"
      >
        <span
          style={{
            fontSize: 11,
            color: 'var(--fw-t3)',
            textTransform: 'uppercase',
            letterSpacing: '0.4px',
          }}
          data-testid="rec-queue-count"
        >
          {top.length} action{top.length === 1 ? '' : 's'}
        </span>
        {!aiOnline && (
          <span
            style={{
              fontSize: 11,
              // Issue #93 / ADR-0066: 'unreachable' (a real fault) reads amber and
              // attention-worthy — NEVER the same neutral treatment as 'disabled'
              // (a deliberate choice). Never collapse the two.
              color: aiState === 'unreachable' ? 'var(--soc-watch-fg)' : 'var(--fw-t3)',
              fontStyle: aiState === 'unreachable' ? 'normal' : 'italic',
            }}
            data-testid="rec-queue-offline-badge"
          >
            {aiState === 'unreachable' ? AI_STATUS_COPY.unreachable : RULES_ONLY_DEGRADED_WORDING}
          </span>
        )}
      </div>

      {top.map((item) => (
        <RecCard key={item.id} item={item} onAction={onAction} compact={compact} />
      ))}

      {/* CR6 (#617): "View all N actions" affordance — compact mode only.
          Shown when queue exceeds top-N and list is collapsed.
          Expands inline — no inner scrollbar, no route navigation.
          ADR-0033: actions remain advisory. */}
      {compact && hiddenCount > 0 && (
        <button
          type="button"
          data-testid="rec-view-all"
          aria-label={`View all ${queue.length} recommended actions`}
          onClick={() => setExpanded(true)}
          style={{
            alignSelf: 'flex-start',
            fontSize: 11,
            color: 'var(--fw-accent)',
            background: 'transparent',
            border: 'none',
            cursor: 'pointer',
            padding: '2px 0',
            textDecoration: 'underline',
            fontFamily: 'var(--fw-font-ui)',
          }}
        >
          View all {queue.length} actions
        </button>
      )}
    </div>
  )
}
