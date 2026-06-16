/**
 * ThreatActorSummary — merged top-actor block (issue #207, ADR-0035 honesty).
 *
 * Replaces both the old AiPanel ("AI Signal — top actor") and the
 * "🧠 AI threat summary" SbCard inside AiSidebar. ONE provenance-tagged
 * block for the top threat actor.
 *
 * Provenance honesty (ADR-0035 §3):
 *   - Title is ALWAYS "Threat summary" — never "AI threat summary" because
 *     rule-templated text must not claim AI authorship (ADR-0035 naming rule).
 *   - Chip derivation = score_derivation from the backend when present;
 *     falls back to "rule" (most conservative stance per ADR-0035 §1).
 *   - When AI ran AND ai_insights are present, the insights list gets an
 *     additional inline AI chip (wave-2 will add executive_summary here).
 *
 * Score/confidence presentation (ADR-0036):
 *   - Scores render via ScoreBadge: "Risk 100 · CRITICAL" (never naked numbers).
 *   - Confidence renders via ConfidenceLabel: word band, NEVER a percentage.
 *   - When AI is offline: confidence is rendered as "n/a (AI off)".
 *
 * IPs render via ClickableIp (#202) — opens the entity slide-over.
 *
 * Degraded wording (ADR-0035 §4): RULES_ONLY_DEGRADED_WORDING constant shown
 * in the block body when AI is offline (the global engine chip lives in the
 * KPI strip — this body wording is the in-pane degraded signal, not duplicate).
 *
 * Security (ADR-0029 D3): source_ip and ai_insights are attacker-controlled.
 * Rendered as text nodes only — never via dangerouslySetInnerHTML.
 *
 * ADR-0028 D6: no raw hex — all colors via var(--fw-*) tokens.
 */

import type { ThreatScore, HealthResponse } from '../../api/types'
import { ProvenanceChip, ScoreBadge, ConfidenceLabel } from '../ds'
import { RULES_ONLY_DEGRADED_WORDING } from '../../lib/provenance'
import ClickableIp from '../entity/ClickableIp'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface ThreatActorSummaryProps {
  /** All threats from GET /threats — picks the top-scored actor. */
  threats: ThreatScore[]
  /**
   * Health from GET /health — authoritative AI engine state (fix #180).
   * null = still in-flight or fetch failed; falls back to top.ai_status.
   */
  health?: HealthResponse | null
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Derive whether the AI engine is considered active.
 * health is authoritative; falls back to threat-level ai_status field.
 * Mirrors the same derivation used in AiPanel and KpiStrip (fix #180).
 */
function resolveAiActive(top: ThreatScore, health: HealthResponse | null | undefined): boolean {
  if (health != null) return health.ollama_connected
  return top.ai_status === 'active'
}

/**
 * Derive block provenance for the top-actor summary block.
 *
 * Uses score_derivation from the backend when present (ADR-0035 §1:
 * derivation determined at authorship, not inferred downstream).
 * Falls back to "rule" regardless of aiActive: ai_status=active does not
 * guarantee the boost actually applied — only the backend can assert that.
 */
function resolveDerivation(top: ThreatScore & { score_derivation?: string }): string {
  if (top.score_derivation && typeof top.score_derivation === 'string') {
    return top.score_derivation
  }
  return 'rule'
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function ThreatActorSummary({ threats, health }: ThreatActorSummaryProps) {
  if (threats.length === 0) return null

  const sorted = [...threats].sort((a, b) => b.score - a.score)
  const top = sorted[0] as ThreatScore & { score_derivation?: string }

  const aiActive = resolveAiActive(top, health)
  const derivation = resolveDerivation(top)

  const criticalCount = threats.filter((t) => t.threat_level === 'CRITICAL').length
  const highCount = threats.filter((t) => t.threat_level === 'HIGH').length
  const hasInsights = aiActive && Array.isArray(top.ai_insights) && top.ai_insights.length > 0

  const blockPct =
    top.total_events > 0 ? Math.round((top.blocked_events / top.total_events) * 100) : 0

  return (
    <div
      data-testid="threat-actor-summary"
      style={{
        background: 'var(--fw-bg-input)',
        border: '1px solid var(--fw-border-l)',
        borderRadius: 8,
        padding: '14px 16px',
        marginBottom: 16,
      }}
    >
      {/* Header: title always "Threat summary" + provenance chip (ADR-0035 §3) */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: 10,
        }}
      >
        <h3
          style={{
            fontSize: 12,
            fontWeight: 600,
            color: 'var(--fw-t1)',
            textTransform: 'uppercase',
            letterSpacing: '0.5px',
            margin: 0,
          }}
          data-testid="tas-title"
        >
          Threat summary
        </h3>

        {/* Block-level provenance — never "AI" for a score block (ADR-0035 §1) */}
        <ProvenanceChip
          derivation={derivation}
          data-testid="tas-provenance-chip"
        />
      </div>

      {/* Severity summary line */}
      <div
        style={{ fontSize: 12, color: 'var(--fw-t2)', lineHeight: 1.55, marginBottom: 10 }}
        data-testid="tas-summary-text"
      >
        {criticalCount > 0 && (
          <span>
            <b style={{ color: 'var(--fw-red)' }}>
              {criticalCount} critical
            </b>{' '}
            actor{criticalCount > 1 ? 's' : ''} detected.{' '}
          </span>
        )}
        {highCount > 0 && criticalCount === 0 && (
          <span>
            <b style={{ color: 'var(--fw-orange)' }}>
              {highCount} high
            </b>{' '}
            threat{highCount > 1 ? 's' : ''} detected.{' '}
          </span>
        )}
        {'Top threat '}
        <ClickableIp
          value={top.source_ip}
          style={{ fontSize: 12 }}
          aria-label={`Open entity panel for ${top.source_ip}`}
        />
        {top.attack_types.length > 0 && (
          <>
            {' ran '}
            <span style={{ color: 'var(--fw-orange)' }}>
              {top.attack_types.slice(0, 2).join(' + ')}
            </span>
          </>
        )}
        {` with ${blockPct}% block rate.`}
      </div>

      {/* Score + confidence (ADR-0036: banded score, word confidence) */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          marginBottom: hasInsights ? 10 : 0,
          flexWrap: 'wrap',
        }}
        data-testid="tas-score-row"
      >
        <ScoreBadge
          score={top.score}
          threatLevel={top.threat_level}
          scoreBreakdown={
            top.score_breakdown && top.score_breakdown.length > 0
              ? top.score_breakdown
              : undefined
          }
          data-testid="tas-score-badge"
        />
        {/* Confidence: null when AI offline so ConfidenceLabel shows "n/a (AI off)" */}
        <ConfidenceLabel
          confidence={aiActive ? top.ai_confidence : null}
          data-testid="tas-confidence-label"
        />
      </div>

      {/* AI insights — only when AI ran AND insights are present (wave-2: exec summary) */}
      {hasInsights && (
        <div data-testid="tas-ai-insights-section" style={{ marginTop: 8 }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              marginBottom: 4,
            }}
          >
            <span
              style={{
                fontSize: 11,
                color: 'var(--fw-t3)',
                textTransform: 'uppercase',
                letterSpacing: '0.4px',
              }}
            >
              AI insights
            </span>
            {/* AI chip on the insights sub-section — this content IS AI-authored */}
            <ProvenanceChip derivation="ai" data-testid="tas-insights-chip" />
          </div>
          <ul
            style={{
              fontSize: 12,
              color: 'var(--fw-t2)',
              paddingLeft: 16,
              lineHeight: 1.6,
              margin: 0,
            }}
            data-testid="tas-insights-list"
          >
            {(top.ai_insights as string[]).map((insight, i) => (
              /* attacker-controlled — text node only (ADR-0029 D3) */
              <li key={i}>{String(insight)}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Degraded wording — AI offline (ADR-0035 §4, shown in body when degraded) */}
      {!aiActive && (
        <p
          style={{
            fontSize: 12,
            color: 'var(--fw-t3)',
            margin: '8px 0 0',
            fontStyle: 'italic',
          }}
          data-testid="tas-degraded-wording"
        >
          {RULES_ONLY_DEGRADED_WORDING}
        </p>
      )}
    </div>
  )
}
