/**
 * AttackDispositionFlow — compact attack→disposition flow strip (issue #214).
 *
 * Renders a mini "Sankey-style" horizontal bar strip showing, per top attack
 * category, the proportional split of dispositions: Blocked / Detected / Allowed.
 * This is the "detection vs enforcement at a glance" view that footers the P5 panes.
 *
 * Data source: GET /analytics/attack-dispositions → [{attack_type, action, count}].
 * Already bounded to top-5 categories + Other by the backend.
 *
 * Layout: one row per attack category.  Each row is a 100%-width bar split into
 * three colour segments (Blocked = red, Detected = orange, Allowed = green).
 * Segments with count=0 are omitted to avoid zero-width renders.
 *
 * Click-through: clicking any row navigates to /logs?q=<attack_type> so the
 * analyst can reach filtered evidence in one click (EARS criterion 2).
 *
 * Hover: the tooltip shows exact counts for each disposition group.
 *
 * Degrade-to-hidden: when the cross-tab is empty, nothing renders (no broken
 * layout). The parent should gate the Panel render on data.length > 0.
 *
 * SVG approach: uses plain `<div>` flexbox segments instead of SVG paths to
 * keep it lightweight (no new charting dep) and accessibility-friendly.
 * Each segment is a `<div>` with title= tooltip text (EARS: counts on hover).
 *
 * ADR-0028 D6: all colors via var(--fw-*) tokens (see attackDispositionUtils.ts).
 * ADR-0029 D3: attack_type rendered as text node only, never via innerHTML.
 * ADR-0019: no raw hex, no heavy chart dep (custom SVG-equivalent layout).
 */

import { useNavigate } from 'react-router-dom'
import type { AttackDispositionRow } from '../../api/types'
import { buildFlowRows, DISPOSITION_COLORS } from './attackDispositionUtils'
import type { FlowRow } from './attackDispositionUtils'

interface AttackDispositionFlowProps {
  /** Raw rows from GET /analytics/attack-dispositions. */
  rows: AttackDispositionRow[]
}

/** Render a single attack→disposition flow row. */
function FlowStrip({
  row,
  onClick,
}: {
  row: FlowRow
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      data-testid="flow-row"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        width: '100%',
        background: 'none',
        border: 'none',
        padding: '3px 0',
        cursor: 'pointer',
        textAlign: 'left',
      }}
    >
      {/* Attack label — left-fixed width */}
      <span
        style={{
          width: 110,
          flexShrink: 0,
          fontSize: 11,
          color: 'var(--fw-t1)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
        title={row.label}
      >
        {row.label}
      </span>

      {/* Proportional bar — three colour segments */}
      <div
        style={{
          flex: 1,
          height: 14,
          display: 'flex',
          borderRadius: 3,
          overflow: 'hidden',
        }}
      >
        {row.blockedFraction > 0 && (
          <div
            data-testid="flow-segment-blocked"
            style={{
              width: `${row.blockedFraction * 100}%`,
              background: DISPOSITION_COLORS.Blocked,
              opacity: 0.85,
            }}
            title={`Blocked: ${row.blocked.toLocaleString()} events (${Math.round(row.blockedFraction * 100)}%)`}
          />
        )}
        {row.detectedFraction > 0 && (
          <div
            data-testid="flow-segment-detected"
            style={{
              width: `${row.detectedFraction * 100}%`,
              background: DISPOSITION_COLORS.Detected,
              opacity: 0.85,
            }}
            title={`Detected: ${row.detected.toLocaleString()} events (${Math.round(row.detectedFraction * 100)}%)`}
          />
        )}
        {row.allowedFraction > 0 && (
          <div
            data-testid="flow-segment-allowed"
            style={{
              width: `${row.allowedFraction * 100}%`,
              background: DISPOSITION_COLORS.Allowed,
              opacity: 0.85,
            }}
            title={`Allowed: ${row.allowed.toLocaleString()} events (${Math.round(row.allowedFraction * 100)}%)`}
          />
        )}
      </div>

      {/* Total count — right-aligned */}
      <span
        style={{
          width: 36,
          flexShrink: 0,
          fontSize: 10,
          color: 'var(--fw-t3)',
          textAlign: 'right',
        }}
      >
        {row.total.toLocaleString()}
      </span>
    </button>
  )
}

export default function AttackDispositionFlow({ rows }: AttackDispositionFlowProps) {
  const navigate = useNavigate()
  const flowRows = buildFlowRows(rows)

  // Degrade to hidden (not broken) when the cross-tab is empty (EARS ubiquitous).
  if (flowRows.length === 0) {
    return null
  }

  function handleRowClick(label: string) {
    navigate(`/logs?q=${encodeURIComponent(label)}`)
  }

  return (
    <div
      data-testid="attack-disposition-flow"
      style={{ marginTop: 12 }}
    >
      {/* Strip header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 6,
        }}
      >
        <span
          style={{
            fontSize: 10,
            fontWeight: 600,
            letterSpacing: '0.06em',
            textTransform: 'uppercase',
            color: 'var(--fw-t3)',
          }}
        >
          Attack → Disposition
        </span>
        {/* Legend */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {(['Blocked', 'Detected', 'Allowed'] as const).map((group) => (
            <span
              key={group}
              style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 10, color: 'var(--fw-t2)' }}
            >
              <span
                style={{
                  display: 'inline-block',
                  width: 8,
                  height: 8,
                  borderRadius: 2,
                  background: DISPOSITION_COLORS[group],
                  flexShrink: 0,
                }}
              />
              {group}
            </span>
          ))}
        </div>
      </div>

      {/* Flow rows.
          key uses the composite `attack_type:total` form so the identifier
          remains unique even if `buildFlowRows` is later changed to preserve
          multiple rows per attack type (issue #314 hardening). */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {flowRows.map((row) => (
          <FlowStrip
            key={`${row.label}:${row.total}`}
            row={row}
            onClick={() => handleRowClick(row.label)}
          />
        ))}
      </div>
    </div>
  )
}
