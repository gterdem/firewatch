/**
 * LogsTable — curated 7-column spine + per-row detail panel (ADR-0063).
 *
 * Columns (spine): Time · Source · Source IP · Action · Severity · Signature · AI Verdict
 * Plus a trailing expand chevron column.
 *
 * ADR-0063 D1 — curated spine:
 *   All seven columns are `never: true` for useColumnPriority (never viewport-collapsed).
 *   Long-tail optional fields (Destination, Dest Port, Protocol, JA4, DNS/DGA,
 *   HTTP Payload) move into the per-row detail panel (LogDetailPanel).
 *
 * ADR-0063 D2 — inline row-expand:
 *   Clicking the chevron (or the row body, excluding the IP button and Signature
 *   trigger) expands an inline <tr> beneath the row that hosts LogDetailPanel.
 *   Independent per-row; multiple rows may be expanded simultaneously.
 *   Keyboard: Enter/Space on the chevron toggles; Esc collapses from the expanded region.
 *   ARIA: chevron has aria-expanded; expanded region has role="region" + aria-label.
 *
 * ADR-0063 D4 — coexistence:
 *   Source IP click → entity panel (ADR-0037), never toggles the row.
 *   Signature cell → CellDetailPopover, row click does NOT toggle.
 *
 * ADR-0063 D5 — de-folded Action cell:
 *   Action is a single-line badge. AI verdict is its own column (no fold).
 *
 * ADR-0063 D6 — structural hiding retired:
 *   structurallyAbsent prop removed; HiddenFieldsChip / FieldAvailabilityLegend
 *   no longer mounted from this table.
 *
 * SECURITY (ADR-0029 D3):
 *   raw_log and all native fields are attacker-controlled. No dangerouslySetInnerHTML
 *   anywhere in this file or in LogDetailPanel.
 *
 * ADR-0028 D6: severity/action/source badges use DS Badge + SourceBadge over
 *   --fw-* tokens; no hardcoded hex or socTokens class strings at call sites.
 *
 * ADR-0012: ALERT (IDS) renders as solid-orange chip (tone="alert").
 * ADR-0015: absent threatMap or IP not found → AI verdict column cell is empty, no error.
 */

import { useCallback, Fragment } from 'react'
import { useNavigate } from 'react-router-dom'
import type { LogEntry, ThreatScore } from '../../api/types'
import { Badge, SourceBadge, useColumnPriority, ProvenanceChip } from '../ds'
import type { BadgeTone, ColumnDef } from '../ds'
import { RuleCellTooltip } from './RuleCellTooltip'
import { formatIpGeoLabel } from '../../lib/ipGeoCell'
import { fmtTimeCompact } from '../../lib/time'
import { useRowExpansion } from './useRowExpansion'
import { LogDetailPanel } from './detail/LogDetailPanel'

// ---------------------------------------------------------------------------
// Column definitions — 7 spine columns (all never:true) + expand chevron
// ---------------------------------------------------------------------------

const COLUMN_DEFS: ColumnDef[] = [
  { key: 'expand',    priority: 1, never: true,  minWidth: 32  },
  { key: 'time',      priority: 1, never: true,  minWidth: 112 },
  { key: 'source',    priority: 1, never: true,  minWidth: 56  },
  { key: 'sourceip',  priority: 1, never: true,  minWidth: 120 },
  { key: 'action',    priority: 1, never: true,  minWidth: 72  },
  { key: 'severity',  priority: 1, never: true,  minWidth: 72  },
  { key: 'signature', priority: 1, never: true,  minWidth: 200 },
  { key: 'verdict',   priority: 2,               minWidth: 120 },
]

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Derived verdict recommendation for the AI verdict chip. */
type VerdictAction = 'block' | 'investigate' | 'monitor'

interface LogsTableProps {
  logs: LogEntry[]
  /** Called when the user clicks a Source IP cell to open the entity slide-over. */
  onIpClick: (ip: string) => void
  /**
   * Optional map of source_ip → ThreatScore for AI verdict column (ADR-0063 D1 #7).
   * ADR-0015: absent or partial map is gracefully tolerated — empty cell shown.
   */
  threatMap?: ReadonlyMap<string, ThreatScore>
}

// ---------------------------------------------------------------------------
// Column widths for <colgroup>
// ---------------------------------------------------------------------------

const COLUMN_WIDTHS: Record<string, string> = {
  expand:    '3%',    // chevron
  time:      '11%',   // 112px compact timestamp
  source:    '6%',    // 56px badge
  sourceip:  '14%',   // IP + geo label
  action:    '8%',    // single-line badge
  severity:  '8%',    // severity badge
  signature: '32%',   // most readable text column; gets remaining share
  verdict:   '18%',   // AI verdict chip (or empty)
}

// ---------------------------------------------------------------------------
// Badge tone helpers
// ---------------------------------------------------------------------------

function severityTone(sev: string): BadgeTone {
  switch (sev.toLowerCase()) {
    case 'critical': return 'critical'
    case 'high':     return 'high'
    case 'medium':   return 'medium'
    case 'low':      return 'low'
    default:         return 'neutral'
  }
}

function actionTone(action: string): BadgeTone {
  switch (action.toLowerCase()) {
    case 'alert':
    case 'alerted':  return 'alert'
    case 'block':
    case 'blocked':  return 'block'
    case 'drop':
    case 'dropped':  return 'drop'
    case 'allow':
    case 'allowed':
    case 'pass':
    case 'passed':   return 'allow'
    default:         return 'neutral'
  }
}

function verdictTone(verdict: VerdictAction): BadgeTone {
  switch (String(verdict).toLowerCase()) {
    case 'block':       return 'block'
    case 'investigate': return 'alert'
    case 'monitor':     return 'neutral'
    default:            return 'neutral'
  }
}

function deriveVerdict(threat: ThreatScore): VerdictAction {
  if (threat.score >= 70) return 'block'
  if (threat.score >= 40) return 'investigate'
  return 'monitor'
}

// ---------------------------------------------------------------------------
// Field extraction helpers
// ---------------------------------------------------------------------------

function getSignature(log: LogEntry): string {
  const rule_name = (log as Record<string, unknown>).rule_name
  if (rule_name != null && String(rule_name) !== '') return String(rule_name)
  const signature = (log as Record<string, unknown>).signature
  if (signature != null && String(signature) !== '') return String(signature)
  const rule_id = (log as Record<string, unknown>).rule_id
  if (rule_id != null) return String(rule_id)
  return '—'
}

// ---------------------------------------------------------------------------
// Shared cell styles
// ---------------------------------------------------------------------------

const TH_STYLE: React.CSSProperties = {
  padding: '6px 10px',
  textAlign: 'left',
  fontWeight: 'var(--fw-fw-semibold)',
  fontSize: 'var(--fw-fs-2xs)',
  color: 'var(--fw-t3)',
  textTransform: 'uppercase',
  letterSpacing: 'var(--fw-ls-table)',
  borderBottom: '1px solid var(--fw-border)',
  whiteSpace: 'nowrap',
  background: 'var(--fw-bg-card)',
}

const TD_STYLE: React.CSSProperties = {
  padding: '5px 10px',
  fontSize: 'var(--fw-fs-sm)',
  color: 'var(--fw-t1)',
  borderBottom: '1px solid var(--fw-border)',
  verticalAlign: 'middle',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
}

// ---------------------------------------------------------------------------
// AI Verdict chip — promoted to its own column (ADR-0063 D1 #7, D5)
// ---------------------------------------------------------------------------

interface AiVerdictChipProps {
  threat: ThreatScore
}

/**
 * Single-line AI verdict chip for the dedicated AI verdict column.
 * Moved OUT of the Action cell (ADR-0063 D5 — Action is now single-line).
 *
 * Shows: ProvenanceChip + verdict Badge + score (+ confidence% when AI active).
 * ADR-0015: rendered only when threat is non-null; caller handles empty case.
 * ADR-0035: ProvenanceChip makes RULE vs AI derivation legible.
 *
 * SECURITY (ADR-0029 D3): verdict + score are scoring-layer values, not raw
 * attacker data. All rendered as text nodes.
 */
function AiVerdictChip({ threat }: AiVerdictChipProps) {
  const verdict = deriveVerdict(threat)
  const score = threat.score
  const aiActive = threat.ai_status === 'active'
  const confidence = aiActive && threat.ai_confidence != null && threat.ai_confidence > 0
    ? threat.ai_confidence
    : null
  const derivation = aiActive ? 'ai' : 'rule'

  return (
    <div
      style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'nowrap' }}
      data-testid="log-row-ai-verdict"
    >
      <ProvenanceChip
        derivation={derivation}
        data-testid="log-row-provenance-chip"
        style={{ fontSize: 9, padding: '1px 4px' }}
      />
      <Badge
        tone={verdictTone(verdict)}
        data-testid="log-row-ai-verdict-badge"
        style={{ fontSize: 9, padding: '1px 5px' }}
      >
        {verdict}
      </Badge>
      <span
        style={{
          fontFamily: 'var(--fw-font-mono)',
          fontSize: 'var(--fw-fs-2xs)',
          color: 'var(--fw-t3)',
        }}
        data-testid="log-row-ai-score"
      >
        {score}
        {confidence !== null ? ` ${Math.round(confidence * 100)}%` : ''}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Chevron icon
// ---------------------------------------------------------------------------

function ChevronIcon({ expanded }: { expanded: boolean }) {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 12 12"
      fill="none"
      aria-hidden="true"
      style={{
        transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)',
        transition: 'transform 0.15s ease',
        flexShrink: 0,
      }}
    >
      <path
        d="M2.5 4.5L6 8L9.5 4.5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function LogsTable({ logs, onIpClick, threatMap }: LogsTableProps) {
  const navigate = useNavigate()
  const { containerRef, visibleColumns } = useColumnPriority(COLUMN_DEFS)
  const { isExpanded, toggle, makeChevronKeyDown, makeRegionKeyDown } = useRowExpansion()

  const makeSignatureNavigate = useCallback(
    (value: string) => () => {
      if (value && value !== '—') {
        navigate(`/logs?signature=${encodeURIComponent(value)}`)
      }
    },
    [navigate],
  )

  if (logs.length === 0) {
    return (
      <p
        style={{
          textAlign: 'center',
          color: 'var(--fw-t3)',
          padding: 20,
          fontFamily: 'var(--fw-font-ui)',
          fontSize: 'var(--fw-fs-sm)',
        }}
        data-testid="logs-empty"
      >
        No logs matching filter
      </p>
    )
  }

  // All spine columns are never:true; verdict may narrow at very small widths.
  const vis = (key: string) => visibleColumns.has(key)

  // Total number of visible columns for the expanded-row colspan.
  const colCount = COLUMN_DEFS.filter((c) => vis(c.key)).length

  return (
    <div
      ref={containerRef as React.RefObject<HTMLDivElement>}
      style={{ width: '100%', minWidth: 0 }}
      data-testid="logs-table"
    >
      <div
        data-testid="logs-table-scroll-container"
        style={{ overflowX: 'auto', overflowY: 'auto', maxHeight: 680 }}
      >
        <table
          style={{
            width: '100%',
            borderCollapse: 'collapse',
            tableLayout: 'fixed',
            fontFamily: 'var(--fw-font-ui)',
          }}
        >
          <colgroup>
            {vis('expand')    && <col style={{ width: COLUMN_WIDTHS.expand }} />}
            {vis('time')      && <col style={{ width: COLUMN_WIDTHS.time }} />}
            {vis('source')    && <col style={{ width: COLUMN_WIDTHS.source }} />}
            {vis('sourceip')  && <col style={{ width: COLUMN_WIDTHS.sourceip }} />}
            {vis('action')    && <col style={{ width: COLUMN_WIDTHS.action }} />}
            {vis('severity')  && <col style={{ width: COLUMN_WIDTHS.severity }} />}
            {vis('signature') && <col style={{ width: COLUMN_WIDTHS.signature }} />}
            {vis('verdict')   && <col style={{ width: COLUMN_WIDTHS.verdict }} />}
          </colgroup>

          <thead style={{ position: 'sticky', top: 0, zIndex: 10 }}>
            <tr>
              {vis('expand')    && <th style={{ ...TH_STYLE, width: COLUMN_WIDTHS.expand }} aria-label="Expand row" />}
              {vis('time')      && <th style={TH_STYLE}>Time</th>}
              {vis('source')    && <th style={TH_STYLE}>Source</th>}
              {vis('sourceip')  && <th style={TH_STYLE}>Source IP</th>}
              {vis('action')    && <th style={TH_STYLE}>Action</th>}
              {vis('severity')  && <th style={TH_STYLE}>Severity</th>}
              {vis('signature') && <th style={TH_STYLE}>Signature</th>}
              {vis('verdict')   && <th style={TH_STYLE}>AI Verdict</th>}
            </tr>
          </thead>

          <tbody>
            {logs.map((log) => {
              const signature = getSignature(log)
              const threat = threatMap?.get(String(log.source_ip))
              const expanded = isExpanded(log.id)

              const ipGeoLabel = formatIpGeoLabel(
                String(log.source_ip),
                log.geo_city as string | null | undefined,
                log.geo_country as string | null | undefined,
              )

              const rowLabel = `${fmtTimeCompact(log.timestamp)} ${String(log.source_ip)}`

              return (
                <Fragment key={log.id}>
                  {/* Main data row */}
                  <tr
                    style={{
                      background: 'transparent',
                      cursor: 'default',
                    }}
                    className="fw-log-row"
                    data-testid="log-row"
                    onClick={(e) => {
                      // Toggle on row body click — but NOT on IP button or Signature trigger.
                      // We let those elements stop propagation themselves.
                      const target = e.target as HTMLElement
                      const isIpBtn = !!target.closest('[data-testid="log-row-ip"]')
                      const isSigTrigger = !!target.closest('[data-testid="log-row-signature"]')
                      const isChevron = !!target.closest('[data-testid="log-row-chevron"]')
                      if (!isIpBtn && !isSigTrigger && !isChevron) {
                        toggle(log.id)
                      }
                    }}
                  >
                    {/* Expand chevron */}
                    {vis('expand') && (
                      <td
                        style={{
                          ...TD_STYLE,
                          padding: '5px 6px',
                          overflow: 'visible',
                          color: 'var(--fw-t3)',
                        }}
                      >
                        <button
                          type="button"
                          data-testid="log-row-chevron"
                          aria-expanded={expanded}
                          aria-label={expanded ? 'Collapse event detail' : 'Expand event detail'}
                          onClick={(e) => {
                            e.stopPropagation()
                            toggle(log.id)
                          }}
                          onKeyDown={makeChevronKeyDown(log.id)}
                          style={{
                            background: 'none',
                            border: 'none',
                            padding: 2,
                            cursor: 'pointer',
                            color: 'var(--fw-t2)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            borderRadius: 'var(--fw-r-sm)',
                          }}
                        >
                          <ChevronIcon expanded={expanded} />
                        </button>
                      </td>
                    )}

                    {/* Time */}
                    {vis('time') && (
                      <td style={{
                        ...TD_STYLE,
                        fontFamily: 'var(--fw-font-mono)',
                        color: 'var(--fw-t3)',
                        overflow: 'visible',
                        minWidth: 112,
                        whiteSpace: 'nowrap',
                      }}
                        data-testid="log-row-time"
                      >
                        {fmtTimeCompact(log.timestamp)}
                      </td>
                    )}

                    {/* Source */}
                    {vis('source') && (
                      <td style={TD_STYLE}>
                        <SourceBadge
                          source={String(log.source_type)}
                          data-testid="log-row-source-badge"
                        />
                      </td>
                    )}

                    {/* Source IP — clicking opens entity panel (ADR-0037); does NOT toggle row */}
                    {vis('sourceip') && (
                      <td
                        style={TD_STYLE}
                        title={
                          log.geo_city || log.geo_country
                            ? `${String(log.source_ip)} · ${[log.geo_city, log.geo_country].filter(Boolean).join(', ')}${(log as Record<string, unknown>).geo_asn ? ` · ASN ${String((log as Record<string, unknown>).geo_asn)}` : ''} (geo cached locally — no external lookup)`
                            : String(log.source_ip)
                        }
                      >
                        <button
                          type="button"
                          data-testid="log-row-ip"
                          aria-label={`Open drill-down for IP ${log.source_ip}`}
                          onClick={(e) => {
                            e.stopPropagation()
                            onIpClick(String(log.source_ip))
                          }}
                          style={{
                            background: 'none',
                            border: 'none',
                            padding: 0,
                            cursor: 'pointer',
                            fontFamily: 'var(--fw-font-mono)',
                            fontSize: 'var(--fw-fs-sm)',
                            color: 'var(--fw-blue)',
                            textDecoration: 'underline',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            maxWidth: '100%',
                            display: 'inline-block',
                          }}
                        >
                          {ipGeoLabel}
                        </button>
                      </td>
                    )}

                    {/* Action — single-line badge (ADR-0063 D5: AI verdict de-folded) */}
                    {vis('action') && (
                      <td style={{ ...TD_STYLE, whiteSpace: 'nowrap' }}>
                        {log.action != null ? (
                          <Badge
                            tone={actionTone(String(log.action))}
                            data-testid="log-row-action-badge"
                          >
                            {String(log.action)}
                          </Badge>
                        ) : (
                          <span
                            style={{ color: 'var(--fw-t3)', fontFamily: 'var(--fw-font-mono)' }}
                            data-testid="log-row-action-badge"
                          >
                            —
                          </span>
                        )}
                      </td>
                    )}

                    {/* Severity */}
                    {vis('severity') && (
                      <td style={TD_STYLE}>
                        <Badge
                          tone={severityTone(String(log.severity))}
                          data-testid="log-row-severity-badge"
                        >
                          {String(log.severity)}
                        </Badge>
                      </td>
                    )}

                    {/* Signature — keeps CellDetailPopover via RuleCellTooltip (ADR-0063 D4) */}
                    {vis('signature') && (
                      <td
                        style={{
                          ...TD_STYLE,
                          fontSize: 'var(--fw-fs-xs)',
                          overflow: 'visible',
                        }}
                        data-testid="log-row-signature"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {signature === '—' ? (
                          <span style={{ color: 'var(--fw-t3)' }}>—</span>
                        ) : (
                          <RuleCellTooltip
                            ruleName={(log as Record<string, unknown>).rule_name != null
                              ? String((log as Record<string, unknown>).rule_name)
                              : null}
                            ruleId={(log as Record<string, unknown>).rule_id != null
                              ? String((log as Record<string, unknown>).rule_id)
                              : null}
                            category={log.category != null ? String(log.category) : null}
                            sourceType={String(log.source_type)}
                            onNavigate={makeSignatureNavigate(signature)}
                          />
                        )}
                      </td>
                    )}

                    {/* AI Verdict — own column (ADR-0063 D1 #7, D5) */}
                    {vis('verdict') && (
                      <td
                        style={{ ...TD_STYLE, whiteSpace: 'nowrap', overflow: 'visible' }}
                        data-testid="log-row-verdict-cell"
                      >
                        {/* ADR-0015: empty cell when no threat score — never an error */}
                        {threat != null ? <AiVerdictChip threat={threat} /> : null}
                      </td>
                    )}
                  </tr>

                  {/* Expanded detail row — inline beneath the data row (ADR-0063 D2) */}
                  {expanded && (
                    <tr
                      role="region"
                      aria-label={`Event detail: ${rowLabel}`}
                      data-testid="log-detail-row"
                      onKeyDown={makeRegionKeyDown(log.id)}
                    >
                      <td
                        colSpan={colCount}
                        style={{
                          padding: 0,
                          borderBottom: '2px solid var(--fw-border)',
                        }}
                      >
                        <LogDetailPanel entry={log} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
