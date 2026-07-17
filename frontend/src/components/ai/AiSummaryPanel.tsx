/**
 * AiSummaryPanel — Threat summary panel (AI Engine page).
 *
 * MK-1 honesty fixes (ADR-0035, ADR-0033, ADR-0036):
 *   - Title is "Threat summary" (no AI label — body is a rule template, not LLM output).
 *   - RULE ProvenanceChip in the header signals deterministic derivation.
 *   - AI coverage sentence templated from real per-row ai_status counts, not a false
 *     claim of "one Local AI prompt per actor".
 *   - Block recommendation reframed as advisory copy (ADR-0033 SIEM-now framing);
 *     RULE chip, no "immediately" imperative under an AI label.
 *   - No brain/robot AI iconography on a rule-templated panel.
 *
 * MM #452 (drop "Reveal scores" gate):
 *   - Scores are shown by default — no mandatory gate, no button.
 *   - summaryRun / onSummaryRun props removed.
 *
 * MM #452 (plain framing line):
 *   - A one-line plain-English framing sentence explains what this page does
 *     for first-time viewers, complementing the ADR-0043 D2 subtitle.
 *
 * MM #450 (clickable priority IPs, ADR-0037):
 *   - "Highest-priority actors to review" IPs rendered via ClickableIp (ADR-0037)
 *     so clicking opens the entity slide-over, consistent with every other IP on
 *     the page. ADR-0029 D3 is preserved: ClickableIp renders IP as a text node.
 *
 * EARS (MK-1 #406):
 *   - Panel title SHALL be "Threat summary" with a RULE ProvenanceChip.
 *   - Coverage sentence SHALL be templated from real ai_status counts.
 *   - Block recommendation SHALL be advisory with a RULE chip.
 *
 * Health is the authoritative source for chip status (MF-3 EARS; three-state
 * rework issue #41 / ADR-0066 — `health.ai` tri-state, NOT the deprecated
 * `ollama_connected` boolean, which collapses "off by choice" and "unreachable"
 * into one ambiguous value):
 *   health provided + health.ai='active'      → chip shows "AI active"
 *   health provided + health.ai='disabled'    → chip shows "AI off · rules-only" (neutral)
 *   health provided + health.ai='unreachable' → chip shows "AI unreachable · rules-only" (amber)
 *   health=null (loading / fetch failed)      → falls back to threat-derived aiStatus
 *                                                (boolean `ollama_connected` used ONLY
 *                                                as this loading-time fallback path)
 *
 * ADR-0029 D3: all attacker-controlled fields (ai_insights, IPs) rendered as text nodes.
 */

import type { ThreatScore, AiStatus, HealthResponse, AnalysisSummary } from '../../api/types'
import { Panel, Badge, ProvenanceChip } from '../ds'
import AiStatusChip from '../AiStatusChip'
import { resolveHealthAiState } from '../aiStatusCopy'
import { computeCoverageRollup } from './ledger/coverage'
import ClickableIp from '../entity/ClickableIp'

interface AiSummaryPanelProps {
  threats: ThreatScore[]
  aiStatus: AiStatus | null
  /**
   * Health response from GET /health — drives the page-level AiStatusChip so it
   * reflects the Local AI panel state (MF-3 #160 EARS). When null (loading or
   * fetch failed), chip falls back to threat-derived aiStatus (ADR-0015).
   */
  health?: HealthResponse | null
  /**
   * Ledger analyses from GET /ai/analyses (BUG-1a fix, #447).
   * Used to derive the honest coverage split: "N actors have AI verdicts, M awaiting".
   * When null (ledger unavailable / still loading), coverage sentence uses threats only.
   */
  analyses?: AnalysisSummary[] | null
}

/** Count threats at a given threat level (case-insensitive). */
function countLevel(threats: ThreatScore[], level: string): number {
  return threats.filter((t) => t.threat_level.toUpperCase() === level.toUpperCase()).length
}

/**
 * Highest-priority actors to review (CRITICAL or HIGH + score >= 70).
 * ADR-0033 SIEM-now framing: advisory, not imperative.
 */
function reviewCandidates(threats: ThreatScore[]): string[] {
  return threats
    .filter(
      (t) =>
        t.threat_level.toUpperCase() === 'CRITICAL' ||
        (t.threat_level.toUpperCase() === 'HIGH' && t.score >= 70),
    )
    .map((t) => t.source_ip)
    .slice(0, 3)
}

export default function AiSummaryPanel({
  threats,
  aiStatus,
  health,
  analyses,
}: AiSummaryPanelProps) {
  // Derive chip status from health.ai (authoritative tri-state, ADR-0066 / issue #41).
  // Fallback to threat-derived aiStatus only while health is not yet available
  // (health === null, i.e. the request is still in flight or failed).
  const healthAiState = health != null ? resolveHealthAiState(health) : null
  const chipStatus: AiStatus | null = healthAiState ?? aiStatus

  const isAiOffline = chipStatus !== 'active'
  const isAiUnreachable = healthAiState === 'unreachable'

  // BUG-1a fix (#447): derive coverage counts from the verdict ledger via
  // computeCoverageRollup — the same source CoverageLedger uses (single source of truth).
  // analyses=null means ledger is still loading or unavailable; we fall back to zero.
  const rollup = computeCoverageRollup(threats, analyses ?? null)
  const aiAnalysedCount = rollup.aiAnalysed
  const rulesOnlyCount = rollup.rulesOnly

  const criticalCount = countLevel(threats, 'CRITICAL')
  const highCount = countLevel(threats, 'HIGH')
  const mediumCount = countLevel(threats, 'MEDIUM')
  const lowCount = countLevel(threats, 'LOW')
  const topReview = reviewCandidates(threats)

  const actions = (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      {/* RULE chip: this panel's body is a rule template, not AI-authored (ADR-0035). */}
      <ProvenanceChip derivation="rule" data-testid="summary-provenance-chip" />
      {/* chipStatus derived from health (authoritative) or aiStatus (fallback) */}
      <AiStatusChip status={chipStatus} />
    </div>
  )

  return (
    <Panel
      title="Threat summary"
      actions={actions}
      data-testid="ai-summary-panel"
    >
      {/* MM #452: plain-language framing line — what this page does for first-time viewers.
          Complements the ADR-0043 D2 subtitle ("Every verdict, what the model saw…") with
          a concrete one-sentence explanation of the scoring pipeline. */}
      <p
        data-testid="ai-summary-framing"
        style={{
          marginTop: 0,
          marginBottom: 12,
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          lineHeight: 1.5,
        }}
      >
        FireWatch scores every attacker with fast rules, then a local AI model double-checks the
        interesting ones — and shows you its work.
      </p>

      {/* AI-not-active informational banner (ADR-0015: rules-only is the floor).
          Copy + tone differ by WHY, per ADR-0066: a deliberate "off" is neutral;
          "unreachable" is attention-worthy amber (never critical/red — detection
          continues either way). */}
      {isAiOffline && (
        <p
          data-testid="ai-degradation-notice"
          style={{
            marginBottom: 12,
            padding: '8px 12px',
            borderRadius: 'var(--fw-r-sm)',
            background: isAiUnreachable ? 'var(--soc-watch-bg)' : 'var(--fw-bg-input)',
            border: `1px solid ${isAiUnreachable ? 'var(--soc-watch-border)' : 'var(--fw-border)'}`,
            fontSize: 'var(--fw-fs-xs)',
            color: isAiUnreachable ? 'var(--soc-watch-fg)' : 'var(--fw-t2)',
          }}
        >
          {isAiUnreachable
            ? 'AI unreachable — showing rule-based detection scores only. Detection continues (ADR-0015).'
            : 'AI off — showing rule-based detection scores only (ADR-0015).'}
        </p>
      )}

      {/* Summary body — scores shown by default (MM #452: no reveal gate). */}
      <div
        style={{
          fontSize: 'var(--fw-fs-body)',
          color: 'var(--fw-t2)',
          lineHeight: 1.7,
        }}
        data-testid="ai-summary-body"
      >
        {threats.length > 0 ? (
          <span>
            <strong style={{ color: 'var(--fw-t1)' }}>{threats.length} actors</strong> scored.{' '}
            {/* BUG-1a fix (#447) + MM semantics fix: coverage derived from verdict ledger.
                ai_status='disabled' is the default for ALL actors (AI is on-demand, not a sweep).
                AI analysis is on-demand (deep analysis) — never implies an automatic background crawl.
                Honest wording separates ENGINE state from per-actor coverage (ADR-0066 tri-state):
                  - engine active + verdicts recorded → "AI engine active · N of M actors have an AI verdict"
                  - engine active + no verdicts yet   → "AI engine active · 0 of N actors have an AI verdict yet"
                  - engine off by choice              → "AI off · all N actors are rules-only"
                  - engine unreachable (fault)         → "AI unreachable · all N actors are rules-only"
                Never says "AI offline or disabled" when health.ai === 'active'. */}
            <span data-testid="ai-summary-coverage">
              {health === null
                // health=null means still loading — neutral, never assert "offline"
                ? `${threats.length} actors scored. AI status loading…`
                : !isAiOffline
                  // Engine is active (health.ai === 'active', or threat-derived fallback)
                  ? aiAnalysedCount > 0
                    ? `AI engine active · ${aiAnalysedCount} of ${threats.length} actors have an AI verdict · ${rulesOnlyCount} are rules-only (open an actor → Run deep analysis to add one).`
                    : `AI engine active · 0 of ${threats.length} actors have an AI verdict yet · all are rules-only (open an actor → Run deep analysis to add one).`
                  // Engine is not active — differentiate WHY (ADR-0066): a deliberate
                  // "off" is neutral wording; "unreachable" is the fault wording.
                  : isAiUnreachable
                    ? `AI unreachable · all ${threats.length} actors are rules-only.`
                    : `AI off · all ${threats.length} actors are rules-only.`
              }
            </span>{' '}
            {criticalCount > 0 && (
              <>
                <Badge tone="critical" data-testid="ai-summary-critical">{criticalCount} CRITICAL</Badge>{' '}
              </>
            )}
            {highCount > 0 && (
              <>
                <Badge tone="high" data-testid="ai-summary-high">{highCount} HIGH</Badge>{' '}
              </>
            )}
            {mediumCount > 0 && (
              <>{mediumCount} MEDIUM{lowCount > 0 ? ', ' : '. '}</>
            )}
            {lowCount > 0 && (
              <>{lowCount} LOW. </>
            )}
            {/* ADR-0033 advisory framing: never imperative "Recommend … immediately" under
                an AI label. RULE chip clarifies this is a heuristic, not AI output. */}
            {topReview.length > 0 && (
              <span data-testid="ai-summary-advice">
                Highest-priority actors to review:{' '}
                <ProvenanceChip derivation="rule" data-testid="advice-provenance-chip" />{' '}
                {topReview.map((ip, i) => (
                  <span key={ip}>
                    {i > 0 && ', '}
                    {/* MM #450 (ADR-0037): ClickableIp opens entity slide-over on click.
                        ADR-0029 D3 preserved: ClickableIp renders IP as a text node. */}
                    <ClickableIp value={String(ip)} />
                  </span>
                ))}
                .
              </span>
            )}
          </span>
        ) : (
          <span data-testid="ai-summary-prompt">
            No threat data yet. Events will appear here once the collector processes telemetry.
          </span>
        )}
      </div>
    </Panel>
  )
}
