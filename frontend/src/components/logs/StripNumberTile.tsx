/**
 * StripNumberTile — plain number tile for the Network Logs header strip (issue #665).
 *
 * Renders a single metric as:
 *   ┌────────────────┐
 *   │  1,234         │  ← large mono number
 *   │  EVENTS        │  ← label (uppercase, muted)
 *   └────────────────┘
 *
 * Used for Events / Blocked / Distinct IPs tiles — all fed from GET /logs/stats.
 * No click-to-filter (these are aggregate totals, not a drill-down entry point).
 *
 * SECURITY (ADR-0029 D3): value is a number (not attacker-controlled text) —
 * formatted via Number.toLocaleString(). Label is a string literal from the caller
 * (never user-supplied); rendered as a text node.
 */

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface StripNumberTileProps {
  /** The label shown below the number (e.g. "Events", "Blocked"). */
  label: string
  /**
   * The numeric value to display. Pass null while loading to show a skeleton.
   * The component renders an em-dash when value is null (loading state).
   */
  value: number | null
  /** data-testid for the outer tile container. */
  'data-testid'?: string
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function StripNumberTile({
  label,
  value,
  'data-testid': testId,
}: StripNumberTileProps) {
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
        minWidth: 110,
        flex: '1 1 auto',
      }}
    >
      {/* Number — text node only; never attacker-controlled */}
      <span
        data-testid={testId ? `${testId}-value` : undefined}
        style={{
          fontFamily: 'var(--fw-font-mono)',
          fontSize: 18,
          fontWeight: 700,
          color: 'var(--fw-t1)',
          lineHeight: 1,
          fontVariantNumeric: 'tabular-nums',
        }}
      >
        {value === null ? '—' : value.toLocaleString()}
      </span>

      {/* Label */}
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
