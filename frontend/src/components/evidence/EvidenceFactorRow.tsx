/**
 * EvidenceFactorRow — one score-breakdown factor row with expandable evidence.
 *
 * Each factor is keyboard-operable (WCAG 2.1.1): Enter/Space toggles the
 * expanded evidence panel. When expanded, it shows the EventSummary list
 * (action, rule_id, payload_snippet, timestamp) scoped to the factor's
 * log_row_ids from the MI-6 evidence chain.
 *
 * Provenance chips (ADR-0035):
 *   - Rule factors → ProvenanceChip derivation="rule"
 *   - ai_boost factor → ProvenanceChip derivation from AiBoostEvidence.provenance
 *
 * Degrade honestly when evidence is empty:
 *   - count === 0 (cap / unknown future factor) → row renders without expand toggle.
 *   - No log_row_ids → row renders without expand toggle.
 *   - status=empty (IP has no stored events) → rows render without links.
 *
 * SECURITY (ADR-0029 D3): all EventSummary fields are attacker-controlled.
 * All string values rendered as text nodes — never via dangerouslySetInnerHTML.
 *
 * No LLM call is triggered here or by clicking. The evidence comes from the
 * already-fetched evidence chain (ai-engine-invariants boundary).
 *
 * Detail-table cap (WCAG / usability):
 *   When a factor has more than DETAIL_ROW_CAP summaries, the expanded panel
 *   renders only the first DETAIL_ROW_CAP rows plus a "Show all N events"
 *   button. The footer count always reflects the TRUE total (from item.count),
 *   not the capped view. The show-all button is keyboard-operable.
 *
 * Focus ring (WCAG 2.4.7):
 *   The expand toggle carries className="fw-focus-visible". The base CSS rule
 *   sets outline:none (no ring on mouse/idle) and the :focus-visible selector
 *   paints an amber ring for keyboard users. No inline outline is set — inline
 *   styles win the cascade and would suppress the :focus-visible rule.
 */

import { useState, useCallback, type KeyboardEvent } from 'react'
import type { EvidenceItem, FactorEvidence, AiBoostEvidence, EventSummary } from '../../api/types'
import { ProvenanceChip } from '../ds'
import { fmtTime } from '../../lib/time'
import { PayloadCellTooltip } from '../logs/PayloadCellTooltip'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Factor key for the AI-boost contribution (discriminator). */
const AI_BOOST_FACTOR = 'ai_boost'

/**
 * Maximum number of event rows rendered in the expanded detail table by default.
 * When a factor has more than this many summaries, only the first N are shown
 * and a "Show all N events" affordance lets the user expand the full set.
 * Prevents a very-busy factor (e.g. 150 SQL hits) from burying the AI section.
 */
const DETAIL_ROW_CAP = 20

// ---------------------------------------------------------------------------
// Type guards
// ---------------------------------------------------------------------------

function isAiBoost(item: EvidenceItem): item is AiBoostEvidence {
  return item.factor === AI_BOOST_FACTOR
}

function isFactorEvidence(item: EvidenceItem): item is FactorEvidence {
  return !isAiBoost(item)
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

interface EventSummaryRowProps {
  summary: EventSummary
}

/**
 * One row in the expanded evidence table — attacker-controlled, text nodes only.
 *
 * #612 table-cell discipline:
 *   - Time: formatted via shared fmtTime() (no raw ISO string), mono, nowrap.
 *   - Action: mono, nowrap, no overflow.
 *   - Rule: mono, nowrap, ellipsis truncation.
 *   - Payload: keyboard-reachable PayloadCellTooltip (replaces weak native title=).
 *
 * SECURITY (ADR-0029 D3): all fields are attacker-controlled — text nodes only.
 */
function EventSummaryRow({ summary }: EventSummaryRowProps) {
  const payloadText = summary.payload_snippet !== null ? String(summary.payload_snippet) : '—'
  return (
    <tr>
      {/* Time — shared fmtTime() (#612: no raw ISO string), mono, muted */}
      <td
        style={{
          padding: '4px 8px',
          borderBottom: '1px solid var(--fw-border)',
          fontSize: 11,
          fontFamily: 'var(--fw-font-mono)',
          color: 'var(--fw-t3)',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {/* fmtTime parses naive timestamps as UTC (ADR-0029 D3: text node) */}
        {fmtTime(String(summary.timestamp))}
      </td>
      {/* Action — mono, nowrap */}
      <td
        style={{
          padding: '4px 8px',
          borderBottom: '1px solid var(--fw-border)',
          fontSize: 11,
          fontFamily: 'var(--fw-font-mono)',
          color: 'var(--fw-t2)',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {String(summary.action)}
      </td>
      {/* Rule — mono, ellipsis truncation */}
      <td
        style={{
          padding: '4px 8px',
          borderBottom: '1px solid var(--fw-border)',
          fontSize: 11,
          fontFamily: 'var(--fw-font-mono)',
          color: 'var(--fw-t2)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {/* rule_id — attacker-controlled, text node only */}
        {summary.rule_id !== null ? String(summary.rule_id) : '—'}
      </td>
      {/* Payload — PayloadCellTooltip: keyboard-reachable, dismissible (#612).
          Replaces the weak native title= (not WCAG-1.4.13 compliant).
          ADR-0029 D3: PayloadCellTooltip renders text nodes only.
          ADR-0057 tactical-now: reuse existing portal-popover pattern. */}
      <td
        style={{
          padding: '4px 8px',
          borderBottom: '1px solid var(--fw-border)',
          fontSize: 11,
          overflow: 'hidden',
        }}
        data-testid="evidence-summary-payload-cell"
      >
        <PayloadCellTooltip
          payload={payloadText}
          style={{ fontSize: 11, color: 'var(--fw-t3)' }}
          data-testid="evidence-summary-payload-tooltip"
        />
      </td>
    </tr>
  )
}

// ---------------------------------------------------------------------------
// EvidenceFactorRow
// ---------------------------------------------------------------------------

export interface EvidenceFactorRowProps {
  /** Evidence item from the chain (FactorEvidence or AiBoostEvidence). */
  item: EvidenceItem
  /**
   * True when the evidence chain returned empty (IP has no stored events, 404).
   * In this case the row renders without an expand toggle — degrade honestly.
   */
  evidenceEmpty?: boolean
}

export function EvidenceFactorRow({ item, evidenceEmpty = false }: EvidenceFactorRowProps) {
  const [expanded, setExpanded] = useState(false)
  /**
   * When the detail table has more than DETAIL_ROW_CAP rows and the user clicks
   * "Show all N events", this flips to true and renders the full set.
   */
  const [showAllRows, setShowAllRows] = useState(false)

  const toggle = useCallback(() => {
    setExpanded((v) => {
      // Collapsing the panel also resets the show-all state so re-expanding
      // starts from the capped view again (less surprising).
      if (v) setShowAllRows(false)
      return !v
    })
  }, [])

  const handleKeyDown = useCallback(
    (e: KeyboardEvent<HTMLButtonElement>) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        toggle()
      }
    },
    [toggle],
  )

  // Determine provenance for the ADR-0035 chip.
  const derivation: string = isAiBoost(item) ? item.provenance : 'rule'

  // Determine whether this row has evidence to show.
  // ai_boost has no log_row_ids (it's a stored-artifact reference).
  // cap has count=0 by design.
  const hasEvidence =
    !evidenceEmpty &&
    isFactorEvidence(item) &&
    item.count > 0 &&
    item.summaries.length > 0

  // Points formatting: "+30" / "-10" / "0".
  const pointsStr = item.points >= 0 ? `+${item.points}` : String(item.points)
  const pointsColor =
    item.points > 0
      ? 'var(--fw-green)'
      : item.points < 0
        ? 'var(--fw-t3)'
        : 'var(--fw-t2)'

  return (
    <div
      data-testid={`evidence-factor-row-${item.factor}`}
      style={{ borderBottom: '1px solid var(--fw-border)', paddingBottom: 4, marginBottom: 4 }}
    >
      {/* ── Factor header row ── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          paddingTop: 4,
        }}
      >
        {/* Points */}
        <span
          data-testid={`evidence-factor-points-${item.factor}`}
          style={{
            fontFamily: 'var(--fw-font-mono)',
            fontWeight: 'var(--fw-fw-bold)',
            color: pointsColor,
            minWidth: 36,
            textAlign: 'right',
            fontSize: 'var(--fw-fs-xs)',
          }}
          aria-label={`${pointsStr} points`}
        >
          {pointsStr}
        </span>

        {/* Label — text node only (ADR-0029 D3) */}
        <span
          data-testid={`evidence-factor-label-${item.factor}`}
          style={{ flex: 1, fontSize: 'var(--fw-fs-xs)', color: 'var(--fw-t1)' }}
        >
          {String(item.label)}
        </span>

        {/* ADR-0035 Provenance chip — on every factor */}
        <ProvenanceChip
          derivation={derivation}
          data-testid={`evidence-factor-chip-${item.factor}`}
        />

        {/* Expand toggle — only when the factor has evidence summaries.
            className="fw-focus-visible" owns both focus states:
              base rule  → outline:none  (no ring on mouse/idle)
              :focus-visible → amber ring (keyboard users only, WCAG 2.4.7)
            No inline outline needed — inline styles win the cascade and would
            suppress the ring even when :focus-visible matches. */}
        {hasEvidence && (
          <button
            type="button"
            aria-expanded={expanded}
            aria-label={`${expanded ? 'Collapse' : 'Expand'} evidence for ${String(item.label)}`}
            data-testid={`evidence-factor-toggle-${item.factor}`}
            className="fw-focus-visible"
            onClick={toggle}
            onKeyDown={handleKeyDown}
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              color: 'var(--fw-accent)',
              fontSize: 'var(--fw-fs-2xs)',
              padding: '0 4px',
              fontFamily: 'var(--fw-font-ui)',
              borderRadius: 'var(--fw-r-xs)',
            }}
          >
            {expanded ? '▲' : '▼'}
            {' '}
            {(item as FactorEvidence).count}
          </button>
        )}

        {/* When evidence is empty (404) or ai_boost: show count badge without toggle */}
        {!hasEvidence && isFactorEvidence(item) && item.count > 0 && evidenceEmpty && (
          <span
            style={{
              fontSize: 'var(--fw-fs-2xs)',
              color: 'var(--fw-t3)',
              fontFamily: 'var(--fw-font-mono)',
            }}
            data-testid={`evidence-factor-count-${item.factor}`}
          >
            {item.count} events
          </span>
        )}
      </div>

      {/* ── AI boost extra: stored-artifact reference note ── */}
      {isAiBoost(item) && (
        <div
          data-testid="evidence-factor-ai-boost-ref"
          style={{
            marginLeft: 44,
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
            marginTop: 2,
          }}
        >
          Stored AI analysis reference · No new LLM call (ADR-0041)
          {item.threat_level !== null && (
            <span style={{ marginLeft: 6, color: 'var(--fw-accent)' }}>
              · level: {String(item.threat_level)}
            </span>
          )}
        </div>
      )}

      {/* ── Expanded evidence panel ── */}
      {expanded && hasEvidence && (
        <div
          data-testid={`evidence-factor-detail-${item.factor}`}
          style={{ marginLeft: 44, marginTop: 6 }}
          role="region"
          aria-label={`Contributing events for ${String(item.label)}`}
        >
          <div
            style={{
              overflowX: 'auto',
              maxWidth: '100%',
              border: '1px solid var(--fw-border)',
              borderRadius: 'var(--fw-r-sm)',
              background: 'var(--fw-bg-input)',
            }}
          >
            <table
              style={{
                width: '100%',
                borderCollapse: 'collapse',
                tableLayout: 'fixed',
                fontSize: 11,
              }}
            >
              {/* #612 column widths: Time narrowed (formatted datetime fits ~20%),
                  Action stays ~12%, Rule ~18%, Payload gets remaining 50% for
                  PayloadCellTooltip to truncate with ellipsis cleanly. */}
              <colgroup>
                <col style={{ width: '20%' }} />
                <col style={{ width: '12%' }} />
                <col style={{ width: '18%' }} />
                <col style={{ width: '50%' }} />
              </colgroup>
              <thead>
                <tr>
                  {(['Time', 'Action', 'Rule', 'Payload'] as const).map((h) => (
                    <th
                      key={h}
                      style={{
                        textAlign: 'left',
                        padding: '4px 8px',
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
                {/* Cap at DETAIL_ROW_CAP rows unless show-all is active.
                    item.count is the TRUE total from the API — it may exceed
                    summaries.length when the API returns a capped slice.
                    We cap the rendered rows; the footer always shows the true total. */}
                {(showAllRows
                  ? (item as FactorEvidence).summaries
                  : (item as FactorEvidence).summaries.slice(0, DETAIL_ROW_CAP)
                ).map((s) => (
                  <EventSummaryRow key={s.log_row_id} summary={s} />
                ))}
              </tbody>
            </table>
          </div>

          {/* Show-all affordance — rendered when the summaries array exceeds the cap
              and the full view is not yet active. Keyboard-operable (native button).
              The count displayed is summaries.length (the set the API actually returned),
              not item.count — honest about what can be shown here. */}
          {!showAllRows && (item as FactorEvidence).summaries.length > DETAIL_ROW_CAP && (
            <button
              type="button"
              data-testid={`evidence-factor-show-all-${item.factor}`}
              onClick={() => setShowAllRows(true)}
              style={{
                marginTop: 4,
                background: 'none',
                border: 'none',
                color: 'var(--fw-blue)',
                cursor: 'pointer',
                fontSize: 'var(--fw-fs-2xs)',
                fontFamily: 'var(--fw-font-ui)',
                padding: 0,
              }}
            >
              Show all {(item as FactorEvidence).summaries.length} events
            </button>
          )}
        </div>
      )}
    </div>
  )
}
