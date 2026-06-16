/**
 * IpScoreSection — score header, 4-up m-stats, and attack-type badges.
 *
 * Extracted from IpDrilldownModal (#94 progressive loading).
 * Renders from the fast /threats/{ip} ThreatScore — available immediately (~5ms).
 * SECURITY (ADR-0029 D3): all attacker-controlled values rendered as text nodes only.
 */

import type { ThreatScore, IpEventTimelineResponse } from '../../../api/types'
import { Badge, Spinner, ScoreBadge } from '../../ds'
import SourceProvenanceBadges from '../../threats/SourceProvenanceBadges'
import { scoreColor, categoryColor, levelTone } from './ipHelpers'

// ---------------------------------------------------------------------------
// MStat — individual 4-up tile
// ---------------------------------------------------------------------------

interface MStatProps {
  value: string | number
  label: string
  valueColor?: string
}

function MStat({ value, label, valueColor }: MStatProps) {
  return (
    <div
      style={{
        background: 'var(--fw-bg-input)',
        borderRadius: 6,
        padding: 10,
        textAlign: 'center',
      }}
    >
      <div
        style={{
          fontSize: 22,
          fontWeight: 700,
          fontFamily: 'var(--fw-font-mono)',
          color: valueColor ?? 'var(--fw-t1)',
        }}
      >
        {value}
      </div>
      <div
        style={{
          fontSize: 10,
          color: 'var(--fw-t3)',
          textTransform: 'uppercase',
          marginTop: 2,
        }}
      >
        {label}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// IpScoreSection
// ---------------------------------------------------------------------------

interface IpScoreSectionProps {
  scoreLoading: boolean
  score: ThreatScore | null
  scoreError: string | null
  /** Whether ipEvents have finished loading (needed for rulesCount). */
  ipEventsResolved: boolean
  ipEvents: IpEventTimelineResponse | null | 'loading'
  /** Whether detailed analysis has been resolved (needed for fallback rulesCount). */
  detailResolved: boolean
  /** Detections from analysis (for fallback rules count when ipEvents is 404). */
  detections: Record<string, unknown>[]
}

export default function IpScoreSection({
  scoreLoading,
  score,
  scoreError,
  ipEventsResolved,
  ipEvents,
  detailResolved,
  detections,
}: IpScoreSectionProps) {
  // Block rate — derived from fast score data.
  const blockRate =
    score && score.total_events > 0
      ? Math.round((score.blocked_events / score.total_events) * 100)
      : 0

  // Rules triggered count — distinct rule_ids the IP actually triggered.
  // NOT the catalog size (rules.length would be the full GET /rules result, e.g. 10,000).
  //
  // Priority:
  //   1. ipEvents resolved + non-null: count distinct non-null labels (label = rule_id per schema).
  //   2. ipEvents null (404/error) + analysisData resolved: count distinct sid/rule_id from detections.
  //   3. Still loading: show '—'.
  const rulesCount: number | '—' = (() => {
    if (ipEventsResolved && ipEvents !== null && ipEvents !== 'loading') {
      const distinctIds = new Set(
        (ipEvents as NonNullable<typeof ipEvents>).events
          .map((e) => e.label)
          .filter((l): l is string => l !== null && l !== ''),
      )
      return distinctIds.size
    }
    if (ipEventsResolved && ipEvents === null && detailResolved) {
      const distinctIds = new Set(
        detections
          .map((d) => d.sid ?? d.rule_id)
          .filter((id): id is string | number => id !== null && id !== undefined)
          .map(String),
      )
      return distinctIds.size
    }
    return '—'
  })()

  return (
    <>
      {/* Score-level error */}
      {scoreError !== null && (
        <p
          role="alert"
          data-testid="modal-error"
          style={{ color: 'var(--fw-red)', fontSize: 13, marginBottom: 12 }}
        >
          {scoreError}
        </p>
      )}

      {/* ── m-stats 4-up grid ── */}
      {scoreLoading ? (
        <div data-testid="modal-score-loading" style={{ marginBottom: 16 }}>
          <span data-testid="detail-spinner">
            <Spinner label="Loading threat score…" />
          </span>
        </div>
      ) : score !== null ? (
        <section aria-label="Threat score" data-testid="modal-score-section">
          {/* Threat level + score row */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              marginBottom: 12,
              flexWrap: 'wrap',
            }}
          >
            <Badge tone={levelTone(score.threat_level)}>{score.threat_level}</Badge>
            {/*
              ScoreBadge renders score + band label with canonical ADR-0036 D1 color.
              scoreBreakdown wires the "why this score?" popover (#210 / defect-1).
              Replaces the former plain-text "Score: N" that had no breakdown affordance.
            */}
            <ScoreBadge
              score={score.score}
              threatLevel={score.threat_level}
              scoreBreakdown={score.score_breakdown}
            />
            <SourceProvenanceBadges sourceTypes={score.source_types} />
          </div>

          {/* m-stats 4-up grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: 10,
              marginBottom: 16,
            }}
          >
            <MStat value={score.total_events} label="Events" />
            <MStat value={score.blocked_events} label="Blocked" valueColor="var(--fw-red)" />
            <MStat value={rulesCount} label="Rules" />
            <MStat
              value={`${blockRate}%`}
              label="Block rate"
              valueColor={scoreColor(score.score)}
            />
          </div>

          {/* Attack-type badges (.at-badge row) */}
          {score.attack_types.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              {score.attack_types.map((a, i) => {
                const col = categoryColor(String(a))
                return (
                  <span
                    key={i}
                    style={{
                      display: 'inline-block',
                      padding: '2px 10px',
                      borderRadius: 8,
                      fontSize: 11,
                      fontWeight: 600,
                      margin: 2,
                      border: `1px solid ${col}`,
                      color: col,
                    }}
                  >
                    {String(a)}
                  </span>
                )
              })}
            </div>
          )}
        </section>
      ) : (
        <p
          style={{ fontSize: 12, color: 'var(--fw-t3)', marginBottom: 16 }}
          data-testid="modal-no-score"
        >
          No threat record for this IP.
        </p>
      )}

      {/* Separator between score and analysis sections */}
      {score !== null && !scoreLoading && (
        <div
          style={{
            borderBottom: '1px solid var(--fw-border)',
            marginBottom: 14,
          }}
        />
      )}
    </>
  )
}

