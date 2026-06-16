/**
 * TimelineBucketHover — rich per-bucket tooltip content (issue #247).
 *
 * Renders inside CellTooltip (#246) and shows:
 *   - Total / blocked / allowed counts
 *   - Top category (most-frequent attack category in the bucket)
 *   - Top source IP (most-frequent attacker IP in the bucket)
 *   - Severity mix (mini-stacked bar + counts)
 *
 * SECURITY (ADR-0029 D3):
 *   top_source_ip and top_category are attacker-controlled fields from the
 *   logs table.  They MUST be rendered as text nodes — never via
 *   dangerouslySetInnerHTML.  This component never sets innerHTML.
 *
 * Accessibility (ADR-0028 / WCAG 1.4.13):
 *   The content element has no interactive children — it is purely informational.
 *   Colour-coded severity swatches carry aria-label for screen-reader parity
 *   (WCAG 1.4.1 — not colour alone).
 *
 * Zero-bucket contract:
 *   When BucketHoverData.total === 0, renders a "No events in this period"
 *   message to satisfy the EARS zero-bucket criterion.
 */

import type { BucketHoverData } from '../../lib/timelineSeries'
import { SEVERITY_LEGEND } from '../../lib/timelineSeries'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface TimelineBucketHoverProps {
  data: BucketHoverData
}

// ---------------------------------------------------------------------------
// Sub-component: severity mini-bar
// ---------------------------------------------------------------------------

function SeverityMiniBar({ data }: { data: BucketHoverData }) {
  const { severity } = data
  const total = severity.critical + severity.high + severity.medium + severity.low
  if (total === 0) return null

  return (
    <div style={{ marginTop: 6 }}>
      <div
        style={{
          fontSize: 10,
          color: 'var(--fw-t3)',
          marginBottom: 3,
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
        }}
      >
        Severity mix
      </div>
      {/* Mini stacked bar */}
      <div
        style={{
          display: 'flex',
          height: 6,
          borderRadius: 3,
          overflow: 'hidden',
          background: 'var(--fw-bg-input)',
        }}
        role="img"
        aria-label={`Severity mix: ${severity.critical} critical, ${severity.high} high, ${severity.medium} medium, ${severity.low} low`}
      >
        {SEVERITY_LEGEND.map((seg) => {
          const count = severity[seg.key as keyof typeof severity]
          if (count === 0) return null
          const pct = Math.round((count / total) * 100)
          return (
            <div
              key={seg.key}
              className={seg.colorClass}
              style={{ width: `${pct}%`, height: '100%' }}
            />
          )
        })}
      </div>
      {/* Counts row */}
      <div
        style={{
          display: 'flex',
          gap: 8,
          marginTop: 4,
          flexWrap: 'wrap',
        }}
      >
        {SEVERITY_LEGEND.map((seg) => {
          const count = severity[seg.key as keyof typeof severity]
          return (
            <span
              key={seg.key}
              style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 10, color: 'var(--fw-t2)' }}
            >
              <span
                aria-hidden="true"
                className={`inline-block rounded-sm ${seg.colorClass}`}
                style={{ width: 8, height: 8, borderRadius: 2, flexShrink: 0 }}
              />
              {/* Text node — not innerHTML */}
              {String(count)}
            </span>
          )
        })}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function TimelineBucketHover({ data }: TimelineBucketHoverProps) {
  if (data.total === 0) {
    return (
      <div
        data-testid="timeline-hover-empty"
        style={{ color: 'var(--fw-t3)', fontSize: 12 }}
      >
        No events in this period
      </div>
    )
  }

  return (
    <div data-testid="timeline-hover-content" style={{ fontSize: 12 }}>
      {/* Count summary */}
      <div
        style={{
          display: 'flex',
          gap: 12,
          fontFamily: 'var(--fw-font-mono)',
          fontSize: 12,
          marginBottom: 4,
        }}
      >
        <span style={{ color: 'var(--fw-t1)' }}>
          {data.total.toLocaleString()}
          {' '}
          <span style={{ color: 'var(--fw-t3)' }}>total</span>
        </span>
        <span className="text-soc-enforced-fg">
          {data.blocked.toLocaleString()}
          {' '}
          <span style={{ color: 'var(--fw-t3)' }}>blocked</span>
        </span>
        <span className="text-soc-ok-fg">
          {data.allowed.toLocaleString()}
          {' '}
          <span style={{ color: 'var(--fw-t3)' }}>allowed</span>
        </span>
      </div>

      {/* Top category — rule-engine output, render as text node */}
      {data.topCategory != null && (
        <div style={{ color: 'var(--fw-t2)', marginBottom: 2 }}>
          <span style={{ color: 'var(--fw-t3)' }}>Top category: </span>
          {/* text node only — ADR-0029 D3 */}
          {String(data.topCategory)}
        </div>
      )}

      {/* Top source IP — attacker-controlled, render as text node */}
      {data.topSourceIp != null && (
        <div style={{ color: 'var(--fw-t2)', marginBottom: 2 }}>
          <span style={{ color: 'var(--fw-t3)' }}>Top source: </span>
          {/* text node only — ADR-0029 D3 */}
          {String(data.topSourceIp)}
        </div>
      )}

      {/* Severity mini-bar */}
      <SeverityMiniBar data={data} />
    </div>
  )
}
