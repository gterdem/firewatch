/**
 * IpPanel — IP entity content hosted inside the SlideOver shell (ADR-0037).
 *
 * Orchestrates three fetch-phases with staged honest AI loading (issue #268):
 *   1. SectionChips    — jump-chip strip (#270)
 *   2. IpScoreSection  — fast, renders immediately from /threats/{ip}
 *   3. Rule sections   — fast (p95 <1s), from /threats/{ip}/detailed?ai=false
 *   4. AI section      — health-gated; skeleton + staged status while LLM runs;
 *                         "AI offline — rules-only" + Run button when AI down;
 *                         "AI analysis failed · [Retry]" on error (never "complete");
 *                         "Deep analysis complete · Ns · model X · [Re-run]" on success.
 *   5. AccordionTimeline — correlation-first accordion (#270)
 *      DEF-1: live /threats/{ip}/events; fallback to coarse OD-3
 *   6. Recent logs table — Signature cells use RuleCellTooltip (peek-then-pin, #283)
 *      Date cells use CellTooltip showing absolute UTC + correlated context (#270, #363)
 *   7. Rule descriptions (backward compat — shown when no recent logs)
 *
 * Progressive loading preserved from IpDrilldownModal (#94):
 *   Score section renders fast from /threats/{ip}; ai=false rules path p95 <1s (#313).
 *
 * #270: correlation-first accordion timeline replaces flat EventTimeline.
 *   Notable events (correlated, first/last seen, new-rule) always expanded.
 *   Routine events collapse into hourly ClusterRows — no inner scroll region (no 3rd scrollbar).
 *   SectionChips (Score · AI · Timeline · Logs) scroll-to the relevant section.
 *   Date cell in Recent Logs gets a CellTooltip with correlated context.
 *
 * #283: Signature cells now use RuleCellTooltip (anchored body-portal popover) instead
 * of RulePopup (center-screen aria-modal overlay). Peek-then-pin grammar:
 *   hover/focus = peek; click/Enter = pin (description + ADR-0034 hint); Esc = layered dismiss.
 *
 * #284: Payload cells now use PayloadCellTooltip — anchored popover with full sanitized payload
 * text on hover/focus when truncated. No popover when content fits. ADR-0029 D3: text nodes only.
 *
 * Issue #45 (ADR-0072 D6): Recent-logs Signature cells additionally show a
 * FalsePositiveButton when the raw stored event carries a `rule_name`
 * identity — this is the "detection row" placement the D6 maintainer ruling
 * requires (False Positive targets a rule, not the actor; it must NOT sit on
 * the triage-queue actor card — see TriageBanner.tsx's ActorChip).
 *
 * SECURITY (ADR-0029 D3): All attacker-controlled fields rendered as text nodes only.
 * discoveryCache drives RuleCellTooltip hints (ADR-0034, D2 #195) — zero per-source branching.
 */

import { Badge, Button, Spinner, EmptyState, SourceBadge, CellTooltip } from '../../ds'
import SourceProvenanceBadges from '../../threats/SourceProvenanceBadges'
import { RuleCellTooltip } from '../../logs/RuleCellTooltip'
import { PayloadCellTooltip } from '../../logs/PayloadCellTooltip'
import { findActionHint } from '../../../lib/actionHints'
import type { SourceTypeEntry } from '../../../schema/types'
import { useIpDetails } from './useIpDetails'
import { useRuleAnalysis } from './useRuleAnalysis'
import { useDeepAnalysis } from './useDeepAnalysis'
import AiSectionSkeleton from './AiSectionSkeleton'
import DeepAnalysisControl from './DeepAnalysisControl'
import NarrationPanel from './NarrationPanel'
import IpScoreSection from './IpScoreSection'
import RichDetailSection from './RichDetailSection'
import FalsePositiveButton from './FalsePositiveButton'
import { SectionChips } from '../SectionChips'
import { EvidenceSection } from '../../evidence/EvidenceSection'
import { AccordionTimeline } from './timeline/AccordionTimeline'
import TimeText from '../../dashboard/TimeText'
import { parseApiTimestamp, formatUtc } from '../../../lib/time'
import type { IpTimelineEventItem } from '../../../api/types'
import {
  safeText,
  scoreColor,
  SEC_LBL,
  buildTimelineEvents,
} from './ipHelpers'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface IpPanelProps {
  ip: string
  /**
   * Discovery cache from GET /sources/types — passed from the layout provider
   * so no per-click network request is needed.
   * Used by findActionHint when a rule-link is clicked (ADR-0034 / D2 #195).
   * When absent, no hint is shown — backward-compatible.
   */
  discoveryCache?: SourceTypeEntry[]
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function IpPanel({ ip, discoveryCache }: IpPanelProps) {
  // --- Score + events (fast path) ---
  const { score, scoreError, ipEvents } = useIpDetails(ip)

  // --- Rule-only analysis (fast, ?ai=false) ---
  const { ruleAnalysis, rules, error: detailError } = useRuleAnalysis(ip)

  // --- Deep AI analysis (health-gated, issue #268; cache-wired, issue #310) ---
  const {
    phase: deepPhase,
    deepAnalysis,
    elapsedSeconds,
    modelName,
    fromCache,
    fetchedAt,
    runDeepAnalysis,
    receiveStreamResult,
    triggerStreamFallback,
  } = useDeepAnalysis(ip)

  const scoreResolved = score !== 'loading'
  const ruleResolved = ruleAnalysis !== 'loading'
  const ipEventsResolved = ipEvents !== 'loading'
  const scoreData = scoreResolved ? (score ?? null) : null

  // ruleData: rule-derived content (always fast).
  const ruleData = ruleResolved ? (ruleAnalysis ?? null) : null
  // aiData: AI-augmented content (only when deep analysis completed).
  const aiData = deepPhase === 'complete' ? deepAnalysis : null

  // analysisData: merged for rendering. AI result takes precedence when available
  // (for fields like analysis, ai_insights, mitre_techniques, score boost).
  // Rule fields are always from ruleData or aiData (both have the same rule-derived fields).
  const analysisData = aiData ?? ruleData

  // DEF-1: AccordionTimeline events — prefer live per-IP endpoint; fall back to coarse.
  // #270: AccordionTimeline takes IpTimelineEventItem[] directly (not the mapped TimelineEvent shape).
  const timelineEvents: IpTimelineEventItem[] = (() => {
    if (ipEventsResolved && ipEvents !== null) {
      return (ipEvents as NonNullable<typeof ipEvents>).events
    }
    // 404 fallback or still loading: use coarse build (OD-3 approved).
    // buildTimelineEvents returns TimelineEvent[] — map to IpTimelineEventItem shape.
    if (scoreData) {
      return buildTimelineEvents(scoreData).map((ev) => ({
        source: ev.source,
        time: ev.time,
        label: typeof ev.label === 'string' ? ev.label : null,
        payload: typeof ev.payload === 'string' ? ev.payload : null,
        correlated: ev.correlated ?? false,
        action: 'ALERT',
        severity: null,
        category: null,
      }))
    }
    return []
  })()

  // Recent logs — from analysis detections (up to 8 rows, matching kit).
  const recentLogs = (analysisData?.detections ?? []).slice(0, 8) as Record<string, unknown>[]

  // Detections for rules-count fallback.
  const detections = (analysisData?.detections ?? []) as Record<string, unknown>[]

  // Effective AI status for provenance badge fallback (when deep phase is idle/health_check).
  const effectiveAiStatus = aiData?.ai_status ?? ruleData?.ai_status ?? null

  return (
    <>
      {/* ── Section jump-chips (#270) ─────────────────────────── */}
      <SectionChips
        chips={[
          { label: 'Score', targetId: 'ip-section-score' },
          { label: 'AI', targetId: 'ip-section-ai' },
          { label: 'Timeline', targetId: 'ip-section-timeline' },
          { label: 'Logs', targetId: 'ip-section-logs' },
        ]}
      />

      {/* ── Score section (fast path) ─────────────────────────── */}
      <div id="ip-section-score">
        <IpScoreSection
          scoreLoading={!scoreResolved}
          score={scoreData}
          scoreError={scoreError}
          ipEventsResolved={ipEventsResolved}
          ipEvents={ipEvents}
          detailResolved={ruleResolved}
          detections={detections}
        />
        {/* ── Evidence section (MI-7 / ADR-0041) ──
            Renders after score is resolved. Shows clickable factor rows
            with evidence summaries scoped to log_row_ids.
            Fetched separately — does not block the fast score render. */}
        {scoreResolved && scoreData !== null && (
          <EvidenceSection ip={ip} />
        )}
      </div>

      {/* ── AI box (.ai-box) ───────────────────────────────────── */}
      <section id="ip-section-ai" aria-label="AI threat assessment" data-testid="modal-analysis-section">
        {detailError !== null && (
          <p
            role="alert"
            data-testid="modal-detail-error"
            style={{ color: 'var(--fw-red)', fontSize: 13, marginBottom: 8 }}
          >
            {detailError}
          </p>
        )}

        {/* Spinner while rule-only fast-path is loading */}
        {!ruleResolved ? (
          <span data-testid="detail-spinner">
            <Spinner label="Loading analysis…" />
          </span>
        ) : analysisData !== null ? (
          <div
            style={{
              background: 'var(--fw-bg-input)',
              border: '1px solid var(--fw-border-l)',
              borderRadius: 8,
              padding: 14,
              marginBottom: 16,
            }}
          >
            {/* AI box header */}
            <h3
              style={{
                fontSize: 13,
                color: 'var(--fw-accent)',
                marginBottom: 10,
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <span aria-hidden="true">🧠</span> AI threat assessment
            </h3>

            {/* .ai-meta: score bar + confidence + stage */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                flexWrap: 'wrap',
                marginBottom: 10,
              }}
            >
              <span style={{ fontSize: 11, color: 'var(--fw-t3)' }}>Score</span>
              {/* Score bar */}
              <span
                style={{
                  width: 60,
                  height: 6,
                  background: 'var(--fw-bg-card)',
                  borderRadius: 3,
                  overflow: 'hidden',
                  display: 'inline-block',
                  verticalAlign: 'middle',
                }}
              >
                <span
                  style={{
                    display: 'block',
                    height: '100%',
                    width: `${Math.min(100, Math.max(0, analysisData.score))}%`,
                    background: scoreColor(analysisData.score),
                    borderRadius: 3,
                  }}
                />
              </span>
              <span
                style={{
                  fontFamily: 'var(--fw-font-mono)',
                  fontSize: 12,
                  color: scoreColor(analysisData.score),
                }}
              >
                {analysisData.score}
              </span>
              {analysisData.ai_confidence !== null &&
                analysisData.ai_confidence !== undefined && (
                <Badge tone="neutral">
                  conf {Math.round(analysisData.ai_confidence * 100)}%
                </Badge>
              )}
              {analysisData.attack_stage && (
                <span style={{ fontSize: 11, color: 'var(--fw-t3)' }}>
                  · stage: {safeText(analysisData.attack_stage)}
                </span>
              )}
            </div>

            {/* Rich structured fields */}
            <RichDetailSection analysis={analysisData} />

            {/* AI analysis narrative — present when AI ran (deepPhase=complete) */}
            {analysisData.analysis && (
              <p
                style={{
                  fontSize: 12,
                  color: 'var(--fw-t2)',
                  lineHeight: 1.5,
                  marginTop: 8,
                  whiteSpace: 'pre-wrap',
                }}
                data-testid="modal-analysis-text"
              >
                {safeText(analysisData.analysis)}
              </p>
            )}

            {/* AI insights list */}
            {analysisData.ai_insights && analysisData.ai_insights.length > 0 && (
              <ul
                style={{
                  fontSize: 12,
                  color: 'var(--fw-t2)',
                  paddingLeft: 16,
                  lineHeight: 1.6,
                  marginTop: 8,
                }}
                data-testid="modal-ai-insights"
              >
                {analysisData.ai_insights.map((insight, i) => (
                  <li key={i}>{safeText(insight)}</li>
                ))}
              </ul>
            )}

            {/* MITRE ATT&CK techniques */}
            {analysisData.mitre_techniques && analysisData.mitre_techniques.length > 0 && (
              <div data-testid="modal-mitre" style={{ marginTop: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 600 }}>MITRE: </span>
                {analysisData.mitre_techniques.map((t, i) => (
                  <span
                    key={i}
                    style={{
                      fontFamily: 'var(--fw-font-mono)',
                      fontSize: 11,
                      background: 'var(--fw-bg-card)',
                      borderRadius: 4,
                      padding: '1px 6px',
                      marginRight: 4,
                      color: 'var(--fw-t2)',
                    }}
                  >
                    {safeText(t)}
                  </span>
                ))}
              </div>
            )}

            {/* AI degraded note — only when AI status is degraded and no structured fields */}
            {(effectiveAiStatus === 'unavailable' ||
              effectiveAiStatus === 'disabled') &&
              !analysisData.analysis &&
              !(analysisData.ai_insights && analysisData.ai_insights.length > 0) &&
              !analysisData.executive_summary &&
              !(
                Array.isArray(analysisData.attack_progression) &&
                analysisData.attack_progression.length > 0
              ) && (
              <p
                style={{ fontSize: 12, color: 'var(--fw-t3)', marginTop: 8 }}
                data-testid="modal-ai-degraded"
              >
                AI analysis unavailable — rule-based scoring only.
              </p>
            )}

            {/* health_check skeleton: only shown during the brief /health call before
                the LLM starts. Once analyzing begins, DeepAnalysisControl owns the
                StageTicker. AiSectionSkeleton import is still used here (issue #268). */}
            {deepPhase === 'health_check' && (
              <AiSectionSkeleton
                elapsedSeconds={elapsedSeconds}
                modelName={modelName}
              />
            )}

            {/* ── AI provenance status (ADR-0035) + DeepAnalysisControl (issue #268) ── */}
            {/* MK-11: DeepAnalysisControl now owns the StageTicker (replacing the
                blind AiSectionSkeleton wait) when phase='analyzing'. The skeleton
                is still rendered as fallback when the SSE stream errors.
                Test-ID preserved for backward-compat. */}
            <div
              style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 10 }}
              data-testid="modal-ai-provenance-status"
            >
              {deepPhase === 'complete' || deepPhase === 'failed' ||
               deepPhase === 'conflict' || deepPhase === 'ai_offline' ||
               deepPhase === 'analyzing' ? (
                <DeepAnalysisControl
                  phase={deepPhase}
                  elapsedSeconds={elapsedSeconds}
                  modelName={modelName}
                  onRun={runDeepAnalysis}
                  ip={ip}
                  fromCache={fromCache}
                  fetchedAt={fetchedAt}
                  onStreamResult={receiveStreamResult}
                  onStreamError={triggerStreamFallback}
                />
              ) : (
                /* Idle / health_check: fall back to static provenance badge from ai_status. */
                effectiveAiStatus === 'active' || effectiveAiStatus === 'ok' ? (
                  <Button variant="deep" size="sm" icon="🔬" disabled>
                    Deep analysis complete
                  </Button>
                ) : (
                  <span
                    style={{
                      fontSize: 11,
                      color: 'var(--fw-t3)',
                      background: 'var(--fw-bg-card)',
                      border: '1px solid var(--fw-border)',
                      borderRadius: 4,
                      padding: '3px 8px',
                      fontFamily: 'var(--fw-font-mono)',
                    }}
                    data-testid="modal-ai-rules-only-badge"
                    aria-label="Rules-only — AI offline"
                  >
                    {effectiveAiStatus === 'disabled'
                      ? 'Rules-only — AI disabled'
                      : effectiveAiStatus === 'error'
                        ? 'Rules-only — AI error'
                        : effectiveAiStatus === 'skipped'
                          ? 'AI offline — rules-only'
                          : 'Rules-only — AI offline'}
                  </span>
                )
              )}
            </div>
          </div>
        ) : (
          <p
            style={{ fontSize: 12, color: 'var(--fw-t3)', marginBottom: 16 }}
            data-testid="modal-no-analysis"
          >
            No detailed analysis available for this IP.
          </p>
        )}
      </section>

      {/* ── Narration section (ML-7, issue #435) ────────────────
          Placed after the AI box so the analyst has context before clicking.
          NarrationPanel is self-contained — Explain button triggers on demand.
          aiAvailable: false when AI is offline per deepPhase so the rule-only
          fast path is used immediately (EARS-4 / ADR-0015 degrade). */}
      {ruleResolved && analysisData !== null && (
        <section
          data-testid="narration-section"
          aria-label="IP narration"
        >
          <NarrationPanel
            ip={ip}
            aiAvailable={deepPhase !== 'ai_offline'}
          />
        </section>
      )}

      {/* ── Correlated event timeline ──
          DEF-1: shows the real per-event timeline when /threats/{ip}/events resolves;
          falls back to the coarse score-derived build on 404 (OD-3 approved).
          #270: AccordionTimeline replaces flat EventTimeline — correlation-first,
          no inner scroll region, notable events always expanded. */}
      {timelineEvents.length > 0 && (
        <section id="ip-section-timeline" aria-label="Correlated event timeline" data-testid="modal-event-timeline">
          <div style={{ ...SEC_LBL, marginBottom: 6 }}>
            Correlated event timeline
            {ipEventsResolved && ipEvents !== null && (ipEvents as NonNullable<typeof ipEvents>).capped && (
              <span
                style={{ marginLeft: 8, fontSize: 10, color: 'var(--fw-t3)', fontWeight: 400 }}
                data-testid="timeline-capped-notice"
              >
                (showing first {(ipEvents as NonNullable<typeof ipEvents>).total} events)
              </span>
            )}
          </div>
          <AccordionTimeline events={timelineEvents} />
        </section>
      )}

      {/* ── Recent logs table ── */}
      {ruleResolved && recentLogs.length > 0 && (
        <section id="ip-section-logs" aria-label="Recent logs" data-testid="modal-recent-logs">
          <div style={{ ...SEC_LBL, margin: '16px 0 6px' }}>Recent logs</div>
          {/* overflowX:auto + tableLayout:fixed mirror LogsTable (#353):
              prevents the payload column from blowing out the slide-over width.
              CellDetailPopover is portaled to body so overflow:hidden on the td
              does not clip the popover. */}
          <div style={{ overflowX: 'auto', maxWidth: '100%' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            {/* #613 column re-weighting: Time/Src narrower, Signature/Payload wider.
                tableLayout:fixed + colgroup = safe re-weight with no responsiveness regression.
                Time 18%: relative timestamps ("2m ago") are short — 18% is generous.
                Src  14%: source badge (short label) — doesn't need 25%.
                Signature 34%, Payload 34%: both deserve density for readable content.
                Min widths preserved: Time min 64px, Src min 48px prevents wrap. */}
            <colgroup>
              <col style={{ width: '18%', minWidth: 64 }} />
              <col style={{ width: '14%', minWidth: 48 }} />
              <col style={{ width: '34%', minWidth: 120 }} />
              <col style={{ width: '34%', minWidth: 120 }} />
            </colgroup>
            <thead>
              <tr>
                {(['Time', 'Src', 'Signature', 'Payload'] as const).map((h) => (
                  <th
                    key={h}
                    style={{
                      textAlign: 'left',
                      padding: '8px 10px',
                      fontSize: 10,
                      color: 'var(--fw-t3)',
                      textTransform: 'uppercase',
                      letterSpacing: '.5px',
                      borderBottom: '1px solid var(--fw-border)',
                      fontWeight: 600,
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {recentLogs.map((log, i) => {
                const timestamp = safeText(log.timestamp ?? log.date)
                const sourceType = safeText(log.source_type ?? log.source ?? '')
                const signature = safeText(log.signature ?? log.category ?? '')
                const sid = safeText(log.sid ?? log.rule_id ?? signature)
                const payload = safeText(log.payload_snippet ?? '') || '—'
                // D2 (#195 / #283): findActionHint per-row, zero per-source branching.
                const matchedRule = rules.find((r) => String(r.rule_id) === sid)
                const ruleName = matchedRule?.name ?? null
                const hint = discoveryCache != null
                  ? findActionHint(discoveryCache, sourceType, ruleName)
                  : null
                // Issue #45 (ADR-0072 D6/D1): the False Positive identity is the
                // raw stored event's `rule_name` (SecurityEvent.rule_name,
                // source-declared free text) — NOT `ruleName` above, which is the
                // rule-CATALOG display name resolved from GET /rules. Suppression
                // matches against `EscalationVerdict.qualifying_rules`, which is
                // built server-side from this same raw `rule_name` field. A
                // detection with no `rule_name` gets no button — ADR-0072's
                // fail-toward-visibility boundary: an anonymous detection can
                // never be FP-suppressed, so offering the action would be a
                // silent no-op.
                const fpRuleName =
                  typeof log.rule_name === 'string' && log.rule_name.trim() !== ''
                    ? log.rule_name
                    : null
                // #270: Find correlated context for this log entry's timestamp.
                // Match timeline events within ±5min of this log's timestamp.
                const logTimeMs = (() => {
                  const ts = safeText(log.timestamp ?? log.date)
                  const d = new Date(ts)
                  return isNaN(d.getTime()) ? null : d.getTime()
                })()
                const correlatedContext = logTimeMs !== null
                  ? timelineEvents.filter((ev) => {
                      const evMs = new Date(ev.time).getTime()
                      return !isNaN(evMs) && Math.abs(evMs - logTimeMs) <= 5 * 60 * 1000 && ev.correlated
                    })
                  : []
                const hasCorrelatedContext = correlatedContext.length > 0

                return (
                  <tr key={i}>
                    <td
                      style={{
                        padding: '7px 10px',
                        borderBottom: '1px solid var(--fw-border)',
                        fontSize: 12,
                        fontFamily: 'var(--fw-font-mono)',
                        color: 'var(--fw-t3)',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {/* #270: Date cell shows correlated context tooltip on hover/focus.
                          #337: TimeText style="relative" — relative primary, absolute ISO on hover.
                          #363: CellTooltip content always includes the absolute UTC time so the
                          ISO timestamp is reachable via hover even when correlated context is shown.
                          The TimeText title attr is also present (for screen readers + non-CellTooltip path). */}
                      {hasCorrelatedContext ? (
                        <CellTooltip
                          data-testid={`log-date-tooltip-trigger-${i}`}
                          content={
                            <div>
                              {/* Absolute UTC timestamp — #363: always shown first so hover exposes ISO. */}
                              <div
                                style={{ fontSize: 11, fontFamily: 'var(--fw-font-mono)', color: 'var(--fw-t2)', marginBottom: 6 }}
                                data-testid={`log-date-tooltip-utc-${i}`}
                              >
                                {formatUtc(parseApiTimestamp(timestamp))}
                              </div>
                              <div style={{ fontSize: 11, fontWeight: 600, marginBottom: 4, color: 'var(--fw-orange)' }}>
                                Correlated events near this time
                              </div>
                              {correlatedContext.slice(0, 3).map((ev, ci) => (
                                <div key={ci} style={{ fontSize: 11, color: 'var(--fw-t2)', marginBottom: 2 }}>
                                  <span style={{ fontFamily: 'var(--fw-font-mono)', color: 'var(--fw-t3)' }}>{ev.source}</span>
                                  {ev.label ? ` · ${ev.label}` : ''}
                                  {ev.category ? ` · ${ev.category}` : ''}
                                </div>
                              ))}
                            </div>
                          }
                        >
                          <span style={{ borderBottom: '1px dotted var(--fw-orange)', cursor: 'help' }}>
                            <TimeText
                              date={parseApiTimestamp(timestamp)}
                              style="relative"
                              data-testid={`log-time-${i}`}
                            />
                          </span>
                        </CellTooltip>
                      ) : (
                        <TimeText
                          date={parseApiTimestamp(timestamp)}
                          style="relative"
                          data-testid={`log-time-${i}`}
                        />
                      )}
                    </td>
                    <td
                      style={{
                        padding: '7px 10px',
                        borderBottom: '1px solid var(--fw-border)',
                        fontSize: 12,
                      }}
                    >
                      {sourceType ? <SourceBadge source={sourceType} /> : null}
                    </td>
                    <td
                      style={{
                        padding: '7px 10px',
                        borderBottom: '1px solid var(--fw-border)',
                        fontSize: 12,
                      }}
                    >
                      {/* #283: RuleCellTooltip replaces the old role="button" span +
                          RulePopup. Peek on hover/focus; pin on click/Enter. */}
                      <span style={{ display: 'inline-flex', alignItems: 'center' }}>
                        <RuleCellTooltip
                          ruleName={ruleName}
                          ruleId={sid}
                          category={safeText(log.category ?? '')}
                          sourceType={sourceType}
                          rules={rules}
                          hint={hint}
                        />
                        {/* Issue #45 (ADR-0072 D6): False Positive targets THIS
                            detection row's rule, never the actor — only shown
                            when the raw event carries a rule_name identity. */}
                        {fpRuleName !== null && (
                          <FalsePositiveButton
                            actorIp={ip}
                            ruleName={fpRuleName}
                            data-testid={`false-positive-button-${i}`}
                          />
                        )}
                      </span>
                    </td>
                    {/* Payload — PayloadCellTooltip: anchored popover on hover/focus
                        when truncated (#284, #353). ADR-0029 D3: text nodes only.
                        overflow:hidden + maxWidth constrains cell like LogsTable TD_STYLE;
                        PayloadCellTooltip inner span applies ellipsis truncation.
                        CellDetailPopover is portaled so overflow:hidden does not clip it.
                        #613: preferAbove=true → popover opens above the trigger row so
                        it does not read as "opens in place" (existing right-clamp preserved). */}
                    <td
                      style={{
                        padding: '7px 10px',
                        borderBottom: '1px solid var(--fw-border)',
                        fontSize: 12,
                        overflow: 'hidden',
                        maxWidth: 200,
                      }}
                      data-testid="recent-log-payload-cell"
                    >
                      <PayloadCellTooltip payload={payload} preferAbove={true} />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          </div>
        </section>
      )}

      {/* ── Rule descriptions (#94 backward-compat — shown when no recent logs) ── */}
      {ruleResolved && rules.length > 0 && recentLogs.length === 0 && (
        <section aria-label="Rule descriptions" data-testid="modal-rules-section">
          <div style={{ ...SEC_LBL, marginBottom: 6 }}>Rule Descriptions</div>
          <ul style={{ fontSize: 12, color: 'var(--fw-t3)', listStyle: 'none', padding: 0 }}>
            {rules.slice(0, 5).map((rule) => (
              <li
                key={safeText(rule.rule_id)}
                style={{ display: 'flex', gap: 8, marginBottom: 4 }}
              >
                <span style={{ fontFamily: 'var(--fw-font-mono)', flexShrink: 0 }}>
                  {safeText(rule.rule_id)}
                </span>
                <span>{safeText(rule.name)}</span>
              </li>
            ))}
            {rules.length > 5 && (
              <li>… and {rules.length - 5} more rules</li>
            )}
          </ul>
        </section>
      )}

      {/* DS EmptyState — flagged: no data available for this IP */}
      {ruleResolved && ruleData === null && scoreData === null && (
        <EmptyState icon="🔍" title="No data for this IP">
          This IP address has no recorded events or analysis.
        </EmptyState>
      )}

    </>
  )
}

// Re-export for use in the breadcrumb by EntityPanelProvider.
export { SourceProvenanceBadges }
