/**
 * AiPanel — per-IP AI signal panel folded into the dashboard (MF-2 / issue #159).
 *
 * Shows the top-scored actor's AI insights + recommended action.
 * AI is both a dedicated page (AI Analysis) AND pervasive here.
 *
 * Degrades gracefully:
 *   - no threats → nothing rendered (non-fatal, ADR-0015)
 *   - ai_status unavailable/disabled → show rule-based summary
 *   - insights null → skip the insights section
 *
 * AI status derivation mirrors AiSummaryPanel (MF-3 #160 / fix #180):
 *   health provided + ollama_connected=true  → "AI active"
 *   health provided + ollama_connected=false → "rules-only"
 *   health=null (loading/fetch failed)       → falls back to top.ai_status
 *
 * SECURITY (ADR-0029 D3): source_ip and ai_insights are attacker-controlled.
 * Rendered as text nodes only — never via dangerouslySetInnerHTML.
 *
 * ADR-0028 D6: no raw hex — all colors via var(--fw-*) tokens.
 */

import type { ThreatScore, HealthResponse } from '../../api/types'

interface AiPanelProps {
  /** All threats from GET /threats — panel picks the top scored actor. */
  threats: ThreatScore[]
  /**
   * Health response from GET /health — authoritative AI engine state (#180 fix).
   * When null (loading or fetch failed), falls back to top actor's ai_status.
   */
  health?: HealthResponse | null
}

function scoreColor(score: number): string {
  if (score >= 76) return 'var(--fw-red)'
  if (score >= 51) return 'var(--fw-orange)'
  if (score >= 26) return 'var(--fw-blue)'
  return 'var(--fw-green)'
}

export default function AiPanel({ threats, health }: AiPanelProps) {
  if (threats.length === 0) return null

  // Top scored actor
  const top = [...threats].sort((a, b) => b.score - a.score)[0]

  // Derive AI active state from health (authoritative, mirrors AiSummaryPanel — fix #180).
  // health=null means health is still in flight: fall back to threat-derived ai_status.
  const aiActive =
    health != null
      ? health.ollama_connected
      : top.ai_status === 'active'

  const hasInsights = Array.isArray(top.ai_insights) && top.ai_insights.length > 0

  return (
    <div
      data-testid="ai-panel"
      style={{
        background: 'var(--fw-bg-input)',
        border: '1px solid var(--fw-border-l)',
        borderRadius: 8,
        padding: '14px 16px',
        marginBottom: 16,
      }}
    >
      {/* Header */}
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
            color: 'var(--fw-accent)',
            textTransform: 'uppercase',
            letterSpacing: '0.5px',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          <span aria-hidden="true">🧠</span>
          <span>AI Signal — top actor</span>
        </h3>
        <span
          style={{
            fontFamily: 'var(--fw-font-mono)',
            fontSize: 11,
            color: aiActive ? 'var(--fw-green)' : 'var(--fw-t3)',
          }}
          data-testid="ai-panel-status"
        >
          {aiActive ? 'AI active' : 'rules-only'}
        </span>
      </div>

      {/* Top actor IP + score */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          marginBottom: 8,
        }}
      >
        <span
          style={{
            fontFamily: 'var(--fw-font-mono)',
            fontSize: 13,
            color: 'var(--fw-blue)',
          }}
          data-testid="ai-panel-ip"
        >
          {top.source_ip}
        </span>
        <span
          style={{
            fontFamily: 'var(--fw-font-mono)',
            fontSize: 16,
            fontWeight: 700,
            color: scoreColor(top.score),
          }}
          data-testid="ai-panel-score"
        >
          {top.score}
        </span>
        {top.ai_confidence !== null && top.ai_confidence !== undefined && (
          <span style={{ fontSize: 11, color: 'var(--fw-t3)' }}>
            conf {Math.round(top.ai_confidence * 100)}%
          </span>
        )}
      </div>

      {/* AI insights list */}
      {hasInsights && (
        <ul
          style={{
            fontSize: 12,
            color: 'var(--fw-t2)',
            paddingLeft: 16,
            lineHeight: 1.6,
            margin: 0,
          }}
          data-testid="ai-panel-insights"
        >
          {(top.ai_insights as string[]).map((insight, i) => (
            /* attacker-controlled — text node only */
            <li key={i}>{String(insight)}</li>
          ))}
        </ul>
      )}

      {/* Fallback when AI is not active */}
      {!aiActive && !hasInsights && (
        <p
          style={{ fontSize: 12, color: 'var(--fw-t3)', margin: 0 }}
          data-testid="ai-panel-degraded"
        >
          AI offline — rule-based scoring. Score: {top.score}.
        </p>
      )}
    </div>
  )
}
