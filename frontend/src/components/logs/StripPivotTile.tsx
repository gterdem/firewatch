/**
 * StripPivotTile — pivot tile with a ▾ popover for the Network Logs header strip (#665).
 *
 * Used for "Top Talker" and "Top Protocol" tiles.
 *
 * Layout:
 *   ┌──────────────────────────────────────┐
 *   │  192.0.2.1   [●]   500  ▾            │  ← #1 item + blocked-ratio dot + count
 *   │  TOP TALKER                           │  ← label
 *   └──────────────────────────────────────┘
 *
 * The ▾ opens a Popover listing the top 5 rows. Each clickable row calls
 * onFilterChange to cross-filter the logs table.
 *
 * Props allow it to be used for both Top Talker (source_ip, blocked ratio dot) and
 * Top Protocol (protocol + % share; non-clickable "(unknown)" sentinel rows).
 *
 * SECURITY (ADR-0029 D3): primaryLabel, rows[].label are attacker-controlled telemetry
 * (source IPs, protocol strings). Rendered as React text nodes ONLY — never via
 * dangerouslySetInnerHTML. Never interpolated into hrefs or event handlers.
 */

import { Popover } from '../ds/Popover'

// ---------------------------------------------------------------------------
// Sub-types
// ---------------------------------------------------------------------------

export interface StripPivotRow {
  /**
   * Unique key for this row (source_ip or protocol raw value).
   * SECURITY: attacker-controlled — used as React key and filter value; text node only.
   */
  key: string
  /**
   * Display label (may differ from key for the "(unknown)" sentinel, which becomes "Other").
   * SECURITY: attacker-controlled — text node only.
   */
  label: string
  /** Event count for this row. */
  count: number
  /**
   * Optional secondary value shown as a smaller hint (e.g. "40%" for protocol share
   * or blocked ratio for a talker). Rendered as text node only.
   */
  hint?: string
  /**
   * When true, this row renders as a non-clickable display-only entry.
   * Used for the "(unknown)"→"Other" protocol row per UT-10 / #508.
   */
  nonClickable?: boolean
}

export interface StripPivotTileProps {
  /** Tile label, shown below the primary value (e.g. "Top Talker", "Top Protocol"). */
  label: string
  /**
   * Primary display value — the #1 item label (e.g. "192.0.2.1" or "TCP").
   * null while loading.
   * SECURITY: attacker-controlled — text node only.
   */
  primaryLabel: string | null
  /**
   * Secondary hint shown next to the primary label (e.g. "500" or "64%").
   * null while loading.
   */
  primaryHint?: string | null
  /**
   * Optional blocked-ratio dot: ratio of blocked / total for the #1 item [0, 1].
   * Shown as a colored dot when present (red if ratio > 0.5, accent/amber if > 0.2, else muted).
   */
  blockedRatio?: number | null
  /** Top 5 rows for the popover. */
  rows: StripPivotRow[]
  /**
   * Called when a popover row is activated (click or keyboard).
   * The filter patch is { ip: row.key } for Top Talker or { protocol: row.key } for Protocol.
   */
  onFilterChange: (filterKey: string, filterValue: string) => void
  /**
   * The LogsFilter key this tile filters on (e.g. "ip" for Top Talker, "protocol" for Top Protocol).
   * Used to build the cross-filter patch.
   */
  filterKey: string
  /** data-testid for the tile container. */
  'data-testid'?: string
  /** data-testid for the popover trigger button. */
  triggerTestId?: string
  /** data-testid for the popover content panel. */
  popoverTestId?: string
}

// ---------------------------------------------------------------------------
// Blocked-ratio dot
// ---------------------------------------------------------------------------

function BlockedDot({ ratio }: { ratio: number }) {
  const color =
    ratio > 0.5
      ? 'var(--fw-red)'
      : ratio > 0.2
        ? 'var(--fw-accent)'
        : 'var(--fw-t3)'
  return (
    <span
      aria-label={`Blocked ratio: ${Math.round(ratio * 100)}%`}
      title={`${Math.round(ratio * 100)}% blocked`}
      style={{
        display: 'inline-block',
        width: 7,
        height: 7,
        borderRadius: '50%',
        background: color,
        flexShrink: 0,
        marginLeft: 2,
      }}
    />
  )
}

// ---------------------------------------------------------------------------
// Popover row
// ---------------------------------------------------------------------------

function PivotRow({
  row,
  filterKey,
  onFilterChange,
}: {
  row: StripPivotRow
  filterKey: string
  onFilterChange: (key: string, value: string) => void
}) {
  const isClickable = !row.nonClickable

  return (
    <div
      role={isClickable ? 'button' : undefined}
      tabIndex={isClickable ? 0 : undefined}
      aria-label={isClickable ? `Filter by ${row.label}` : undefined}
      data-testid={isClickable ? `pivot-row-${row.key}` : undefined}
      onClick={
        isClickable
          ? () => onFilterChange(filterKey, row.key)
          : undefined
      }
      onKeyDown={
        isClickable
          ? (e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onFilterChange(filterKey, row.key)
              }
            }
          : undefined
      }
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '5px 12px',
        cursor: isClickable ? 'pointer' : 'default',
        opacity: row.nonClickable ? 0.6 : 1,
      }}
    >
      {/* Label — SECURITY: text node only */}
      <span
        style={{
          flex: 1,
          fontFamily: 'var(--fw-font-mono)',
          fontSize: 11,
          color: isClickable ? 'var(--fw-t1)' : 'var(--fw-t3)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {String(row.label)}
      </span>

      {/* Hint (optional — e.g. "64%" or "200 blocked") */}
      {row.hint != null && (
        <span
          style={{
            fontSize: 10,
            color: 'var(--fw-t3)',
            flexShrink: 0,
            fontVariantNumeric: 'tabular-nums',
          }}
        >
          {row.hint}
        </span>
      )}

      {/* Count */}
      <span
        style={{
          fontFamily: 'var(--fw-font-mono)',
          fontSize: 11,
          color: 'var(--fw-t2)',
          flexShrink: 0,
          fontVariantNumeric: 'tabular-nums',
          minWidth: 40,
          textAlign: 'right',
        }}
      >
        {row.count.toLocaleString()}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// StripPivotTile component
// ---------------------------------------------------------------------------

export function StripPivotTile({
  label,
  primaryLabel,
  primaryHint,
  blockedRatio,
  rows,
  onFilterChange,
  filterKey,
  'data-testid': testId,
  triggerTestId,
  popoverTestId,
}: StripPivotTileProps) {
  const hasData = primaryLabel !== null && rows.length > 0

  const popoverContent = (
    <>
      {rows.map((row) => (
        <PivotRow
          key={row.key}
          row={row}
          filterKey={filterKey}
          onFilterChange={onFilterChange}
        />
      ))}
    </>
  )

  const triggerContent = (
    <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
      {/* Primary label — SECURITY: text node only */}
      <span
        style={{
          fontFamily: 'var(--fw-font-mono)',
          fontSize: 13,
          fontWeight: 600,
          color: 'var(--fw-t1)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          maxWidth: 130,
        }}
      >
        {primaryLabel !== null ? String(primaryLabel) : '—'}
      </span>

      {/* Blocked-ratio dot */}
      {blockedRatio !== null && blockedRatio !== undefined && (
        <BlockedDot ratio={blockedRatio} />
      )}

      {/* Primary hint (e.g. count or %) */}
      {primaryHint != null && (
        <span
          style={{
            fontFamily: 'var(--fw-font-mono)',
            fontSize: 11,
            color: 'var(--fw-t3)',
            fontVariantNumeric: 'tabular-nums',
          }}
        >
          {primaryHint}
        </span>
      )}

      {/* Chevron — visual affordance for popover */}
      {hasData && (
        <span
          aria-hidden="true"
          style={{
            fontSize: 10,
            color: 'var(--fw-t3)',
            marginLeft: 2,
          }}
        >
          ▾
        </span>
      )}
    </span>
  )

  return (
    <div
      data-testid={testId}
      style={{
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border)',
        borderRadius: 'var(--fw-r-md, 8px)',
        padding: '8px 16px',
        display: 'flex',
        flexDirection: 'column',
        gap: 2,
        minWidth: 160,
        flex: '1 1 auto',
      }}
    >
      {/* Top row: primary value + popover trigger */}
      {hasData ? (
        <Popover
          trigger={triggerContent}
          triggerAriaLabel={`${label}: top 5 — click to expand`}
          data-testid={triggerTestId}
          contentTestId={popoverTestId}
        >
          {popoverContent}
        </Popover>
      ) : (
        <span
          style={{
            fontFamily: 'var(--fw-font-mono)',
            fontSize: 13,
            fontWeight: 600,
            color: 'var(--fw-t3)',
          }}
        >
          —
        </span>
      )}

      {/* Tile label */}
      <span
        style={{
          fontSize: 10,
          color: 'var(--fw-t3)',
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
        }}
      >
        {label}
      </span>
    </div>
  )
}
