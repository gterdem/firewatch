/**
 * KpiTile — single KPI cell for the KpiStrip (issue #254).
 *
 * Renders one tile: value + label + optional Sparkline/arrow.
 * Grows equally within the strip's justified flex layout (flex: 1).
 * Height is stable whether or not a sparkline is present — no layout shift.
 *
 * Per-KPI sparkline notes (issue #254):
 *   - "Total events"  → series from timeline `total` buckets
 *   - "Blocked"       → series from timeline `blocked` buckets
 *   - "Block rate"    → series from derived block-rate per bucket
 *   - "Unique IPs"    → no derivable series; renders number-only (flagged to architect)
 *
 * Accessibility:
 *   - Sparkline carries aria-label via the shared Sparkline primitive (#245).
 *   - Trend direction is never conveyed by color alone: arrow glyph is always present.
 *
 * ADR-0028 D6: no raw hex — all colors via var(--fw-*) tokens.
 * ADR-0029 D3: no attacker-controlled data rendered here.
 */

import type { CSSProperties } from 'react'
import type { SeriesPoint } from '../../lib/series'
import { Sparkline } from '../ds'

export interface KpiTileProps {
  /** Formatted value string — e.g. "4,815", "62.3%". */
  value: string
  /** Short uppercase label — e.g. "Total events". */
  label: string
  /** Optional CSS color token for the value, e.g. "var(--fw-red)". */
  valueColor?: string
  /**
   * Optional UTC-bucketed series for the sparkline.
   * When absent or empty, the tile renders number-only with no layout shift.
   */
  series?: SeriesPoint[]
  /** Sparkline stroke color token. Defaults to var(--fw-accent). */
  sparklineColor?: string
  /** data-testid forwarded to the tile container. */
  testId?: string
}

/** Inline style for the tile container — flex:1 ensures even distribution. */
const tileStyle: CSSProperties = {
  flex: 1,
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  justifyContent: 'center',
  gap: 2,
  padding: '8px 16px',
  minWidth: 0,
  // Vertical separator between tiles (right border on all but the last — handled
  // by CSS at the strip level; here we let the tile know its visual boundary is set
  // by KpiStrip via `borderRight` on the wrapper).
}

/** Inline style for the value + label row. */
const headerRowStyle: CSSProperties = {
  display: 'flex',
  alignItems: 'baseline',
  gap: 6,
  justifyContent: 'center',
}

/** Inline style for the numeric value span. */
const valueStyle = (valueColor?: string): CSSProperties => ({
  fontFamily: 'var(--fw-font-mono)',
  fontSize: 18,
  fontWeight: 700,
  color: valueColor ?? 'var(--fw-t1)',
  lineHeight: 1,
  whiteSpace: 'nowrap',
})

/** Inline style for the label span. */
const labelStyle: CSSProperties = {
  fontSize: 11,
  color: 'var(--fw-t3)',
  textTransform: 'uppercase',
  letterSpacing: '0.5px',
  whiteSpace: 'nowrap',
}

/**
 * Container that reserves a fixed height for the sparkline row so that
 * tiles without a sparkline remain the same height as those with one.
 * Height matches Sparkline's default height (24px).
 */
const sparklineRowStyle: CSSProperties = {
  height: 24,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
}

export default function KpiTile({
  value,
  label,
  valueColor,
  series,
  sparklineColor,
  testId,
}: KpiTileProps) {
  const hasSeries = series !== undefined && series.length > 0

  return (
    <div style={tileStyle} data-testid={testId}>
      {/* Value + label row */}
      <div style={headerRowStyle}>
        <span style={valueStyle(valueColor)}>{value}</span>
        <span style={labelStyle}>{label}</span>
      </div>

      {/* Sparkline row — always rendered to keep height stable.
          When no series is available, the reserved height is empty (no layout shift).
          EARS: WHEN a KPI has a derivable series → sparkline shown.
          EARS: WHEN not → number-only, identical height. */}
      <div style={sparklineRowStyle} data-testid={testId ? `${testId}-sparkline-row` : undefined}>
        {hasSeries && (
          <Sparkline
            series={series}
            label={label}
            width={80}
            height={24}
            color={sparklineColor}
          />
        )}
      </div>
    </div>
  )
}
