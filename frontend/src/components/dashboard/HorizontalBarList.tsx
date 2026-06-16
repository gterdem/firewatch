/**
 * HorizontalBarList — shared bar-chart rows for the Attacks / Dispositions panes (issue #206).
 *
 * Renders at most `maxBars` (default 5) horizontal bars from the supplied rows,
 * plus an "Other (n)" bucket for the tail when there are more than `maxBars` rows.
 * No inner scrollbar: height is bounded by the fixed row count.
 *
 * Styling: DS tokens only — no raw hex, no raw px literals in color properties.
 * Click: onBarClick(label) optional; when supplied each bar is a button so the
 *        analyst can reach filtered evidence in one click.
 *
 * Bucketing logic lives in barListUtils.ts (react-refresh rule: component files export
 * components only).
 *
 * ADR-0028 D6: all colors via var(--fw-*) tokens.
 * ADR-0029 D3: labels are attacker-influenced; they must be rendered as text nodes only.
 */

import { bucketRows } from './barListUtils'

export interface BarRow {
  label: string
  count: number
}

interface HorizontalBarListProps {
  /** Pre-sorted rows (highest count first). Already-aggregated by the caller. */
  rows: BarRow[]
  /**
   * Hue resolver — given a label returns a var(--fw-*) color token string.
   * Must NOT return raw hex values (ADR-0028 D6).
   */
  colorFor: (label: string) => string
  /** Maximum number of bars before collapsing the tail into Other. Default: 5. */
  maxBars?: number
  /**
   * Called when the analyst clicks a bar.
   * The caller navigates to the appropriate filtered view.
   */
  onBarClick?: (label: string) => void
  /** data-testid for the list wrapper. */
  'data-testid'?: string
}

export default function HorizontalBarList({
  rows,
  colorFor,
  maxBars = 5,
  onBarClick,
  'data-testid': testId,
}: HorizontalBarListProps) {
  if (rows.length === 0) {
    return (
      <p
        className="text-sm text-muted-foreground text-center py-4"
        data-testid="hbl-empty"
      >
        No data
      </p>
    )
  }

  const { topRows, otherCount } = bucketRows(rows, maxBars)
  const allDisplayed: Array<BarRow & { isOther?: boolean }> = [
    ...topRows,
    ...(otherCount > 0 ? [{ label: `Other`, count: otherCount, isOther: true }] : []),
  ]
  const max = Math.max(...allDisplayed.map((r) => r.count), 1)

  return (
    <div data-testid={testId ?? 'horizontal-bar-list'}>
      {allDisplayed.map(({ label, count, isOther }) => {
        const pct = ((count / max) * 100).toFixed(0)
        const color = isOther ? 'var(--fw-t3)' : colorFor(label)
        const displayLabel = isOther ? `Other (${count.toLocaleString()})` : label

        const rowContent = (
          <>
            {/* .cat-lbl — label column (160px) */}
            <div
              style={{
                width: 160,
                fontSize: 12,
                fontWeight: 500,
                flexShrink: 0,
                color: 'var(--fw-t1)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
              title={displayLabel}
            >
              {displayLabel}
            </div>
            {/* .cat-bar-w — track */}
            <div
              style={{
                flex: 1,
                height: 18,
                background: 'var(--fw-bg-input)',
                borderRadius: 3,
                overflow: 'hidden',
              }}
            >
              {/* .cat-bar — hue fill */}
              <div
                data-testid="category-bar"
                style={{
                  height: '100%',
                  width: `${pct}%`,
                  background: color,
                  borderRadius: 3,
                  minWidth: 2,
                }}
              />
            </div>
            {/* .cat-cnt — count */}
            <div
              style={{
                width: 56,
                textAlign: 'right',
                fontFamily: 'var(--fw-font-mono)',
                fontSize: 12,
                color: 'var(--fw-t2)',
                flexShrink: 0,
              }}
            >
              {count.toLocaleString()}
            </div>
          </>
        )

        const rowStyle: React.CSSProperties = {
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '6px 0',
          borderBottom: '1px solid var(--fw-border)',
          width: '100%',
        }

        if (!isOther && onBarClick) {
          return (
            <button
              key={label}
              data-testid="category-row"
              onClick={() => onBarClick(label)}
              style={{
                ...rowStyle,
                background: 'none',
                border: 'none',
                borderBottom: '1px solid var(--fw-border)',
                cursor: 'pointer',
                textAlign: 'left',
              }}
              aria-label={`Filter by ${label}`}
            >
              {rowContent}
            </button>
          )
        }

        return (
          <div key={isOther ? '__other__' : label} data-testid="category-row" style={rowStyle}>
            {rowContent}
          </div>
        )
      })}
    </div>
  )
}
