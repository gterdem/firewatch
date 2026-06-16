/**
 * RichDetailSection — structured AI/rule fields from DetailedAnalysis.
 *
 * Extracted from IpDrilldownModal (#94 rich fields — rules-only path).
 * Renders executive_summary, attack_progression, intent, ioc_indicators,
 * insights (patterns/risks/mitigations), and meta badges (action/stage/confidence).
 *
 * SECURITY (ADR-0029 D3): All fields are attacker-controlled.
 * NEVER use dangerouslySetInnerHTML. All values rendered as text nodes only.
 */

import type { DetailedAnalysis } from '../../../api/types'
import { safeText, SEC_LBL } from './ipHelpers'

interface RichDetailSectionProps {
  analysis: DetailedAnalysis
}

export default function RichDetailSection({ analysis }: RichDetailSectionProps) {
  const hasSummary = Boolean(analysis.executive_summary)
  const hasProgression =
    Array.isArray(analysis.attack_progression) && analysis.attack_progression.length > 0
  const hasIntent = Boolean(analysis.intent)
  const hasIoc =
    Array.isArray(analysis.ioc_indicators) && analysis.ioc_indicators.length > 0
  const hasInsights =
    analysis.insights !== null &&
    analysis.insights !== undefined &&
    (
      (Array.isArray(analysis.insights.patterns) && analysis.insights.patterns.length > 0) ||
      (Array.isArray(analysis.insights.risks) && analysis.insights.risks.length > 0) ||
      (Array.isArray(analysis.insights.mitigations) && analysis.insights.mitigations.length > 0)
    )
  const hasRecommendation = Boolean(analysis.recommended_action)
  const hasStage = Boolean(analysis.attack_stage)
  const hasConfidence =
    analysis.confidence !== null && analysis.confidence !== undefined

  const hasAnyRichField =
    hasSummary || hasProgression || hasIntent || hasIoc || hasInsights ||
    hasRecommendation || hasStage || hasConfidence

  if (!hasAnyRichField) return null

  return (
    <div style={{ marginTop: 12 }} data-testid="modal-rich-detail">
      {hasSummary && (
        <div data-testid="modal-executive-summary" style={{ marginBottom: 8 }}>
          <p style={{ ...SEC_LBL, marginBottom: 2 }}>Executive Summary</p>
          <p style={{ fontSize: 12, color: 'var(--fw-t2)', lineHeight: 1.5 }}>
            {safeText(analysis.executive_summary)}
          </p>
        </div>
      )}

      {hasIntent && (
        <div data-testid="modal-intent" style={{ marginBottom: 8 }}>
          <p style={{ ...SEC_LBL, marginBottom: 2 }}>Intent</p>
          <p style={{ fontSize: 12, color: 'var(--fw-t2)', lineHeight: 1.5 }}>
            {safeText(analysis.intent)}
          </p>
        </div>
      )}

      {hasProgression && (
        <div data-testid="modal-attack-progression" style={{ marginBottom: 8 }}>
          <p style={{ ...SEC_LBL, marginBottom: 2 }}>Attack Progression</p>
          <ol style={{ fontSize: 12, color: 'var(--fw-t2)', paddingLeft: 16, lineHeight: 1.6 }}>
            {(analysis.attack_progression as string[]).map((step, i) => (
              <li key={i}>{safeText(step)}</li>
            ))}
          </ol>
        </div>
      )}

      {hasIoc && (
        <div data-testid="modal-ioc-indicators" style={{ marginBottom: 8 }}>
          <p style={{ ...SEC_LBL, marginBottom: 2 }}>Indicators of Compromise</p>
          <ul style={{ fontSize: 12, color: 'var(--fw-t2)', paddingLeft: 16, lineHeight: 1.6 }}>
            {(analysis.ioc_indicators as string[]).map((ioc, i) => (
              <li key={i}>{safeText(ioc)}</li>
            ))}
          </ul>
        </div>
      )}

      {hasInsights && analysis.insights && (
        <div data-testid="modal-insights" style={{ marginBottom: 8 }}>
          {Array.isArray(analysis.insights.patterns) && analysis.insights.patterns.length > 0 && (
            <div style={{ marginBottom: 6 }}>
              <p style={{ ...SEC_LBL, marginBottom: 2 }}>Patterns</p>
              <ul
                style={{ fontSize: 12, color: 'var(--fw-t2)', paddingLeft: 16, lineHeight: 1.6 }}
                data-testid="modal-insights-patterns"
              >
                {analysis.insights.patterns.map((p, i) => (
                  <li key={i}>{safeText(p)}</li>
                ))}
              </ul>
            </div>
          )}
          {Array.isArray(analysis.insights.risks) && analysis.insights.risks.length > 0 && (
            <div style={{ marginBottom: 6 }}>
              <p style={{ ...SEC_LBL, marginBottom: 2 }}>Risks</p>
              <ul
                style={{ fontSize: 12, color: 'var(--fw-t2)', paddingLeft: 16, lineHeight: 1.6 }}
                data-testid="modal-insights-risks"
              >
                {analysis.insights.risks.map((r, i) => (
                  <li key={i}>{safeText(r)}</li>
                ))}
              </ul>
            </div>
          )}
          {Array.isArray(analysis.insights.mitigations) &&
            analysis.insights.mitigations.length > 0 && (
            <div>
              <p style={{ ...SEC_LBL, marginBottom: 2 }}>Mitigations</p>
              <ul
                style={{ fontSize: 12, color: 'var(--fw-t2)', paddingLeft: 16, lineHeight: 1.6 }}
                data-testid="modal-insights-mitigations"
              >
                {analysis.insights.mitigations.map((m, i) => (
                  <li key={i}>{safeText(m)}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {(hasRecommendation || hasStage || hasConfidence) && (
        <div
          style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 12 }}
          data-testid="modal-meta-badges"
        >
          {hasRecommendation && (
            <span style={{ fontSize: 12 }}>
              <span style={{ fontWeight: 600 }}>Action:</span>{' '}
              <span style={{ fontFamily: 'var(--fw-font-mono)' }}>
                {safeText(analysis.recommended_action)}
              </span>
            </span>
          )}
          {hasStage && (
            <span style={{ fontSize: 12 }}>
              <span style={{ fontWeight: 600 }}>Stage:</span>{' '}
              {safeText(analysis.attack_stage)}
            </span>
          )}
          {hasConfidence && (
            <span style={{ fontSize: 12 }}>
              <span style={{ fontWeight: 600 }}>Confidence:</span>{' '}
              {Math.round((analysis.confidence as number) * 100)}%
            </span>
          )}
        </div>
      )}
    </div>
  )
}
