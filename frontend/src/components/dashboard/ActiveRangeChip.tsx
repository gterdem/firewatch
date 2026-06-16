/**
 * ActiveRangeChip — shows the active brush range with one-click clear (issue #249).
 *
 * Rendered in the DashboardRoute header area when a brush range is active.
 *
 * Format: "filtered to HH:MM–HH:MM TZ ✕"
 *   - HH:MM labels via formatLocal (browser-local zone, issue #244).
 *   - TZ label via localZoneLabel (e.g. "EDT", "UTC").
 *   - ✕ button clears the range and returns all panes to their default windows.
 *
 * ADR-0028 D6: uses --fw-* tokens only; no raw hex.
 * WCAG 2.1 SC 1.4.3: "filtered to" text colour meets contrast on --fw-bg-hover.
 * WCAG 2.1 SC 1.4.11 (non-text contrast): the amber border meets 3:1 on dark bg.
 */

import { formatLocal, localZoneLabel, parseApiTimestamp } from '../../lib/time'
import type { TimeRange } from '../../app/timeRange'

export interface ActiveRangeChipProps {
  /** The active range — renders nothing when null. */
  range: TimeRange
  /** Called when the ✕ button is clicked. */
  onClear: () => void
}

export default function ActiveRangeChip({ range, onClear }: ActiveRangeChipProps) {
  const startDate = parseApiTimestamp(range.start)
  const endDate = parseApiTimestamp(range.end)

  const startLabel = formatLocal(startDate, 'time')
  const endLabel = formatLocal(endDate, 'time')
  const zone = localZoneLabel()

  return (
    <div
      data-testid="active-range-chip"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '3px 10px',
        borderRadius: 14,
        background: 'var(--fw-bg-hover)',
        border: '1px solid var(--fw-accent-amber)',
        fontSize: 12,
        fontFamily: 'var(--fw-font-ui)',
        color: 'var(--fw-t1)',
      }}
    >
      <span
        data-testid="active-range-label"
        aria-live="polite"
        aria-atomic="true"
      >
        filtered to{' '}
        <span data-testid="active-range-start">{startLabel}</span>
        {'–'}
        <span data-testid="active-range-end">{endLabel}</span>
        {' '}
        <span data-testid="active-range-zone" style={{ color: 'var(--fw-t2)' }}>
          {zone}
        </span>
      </span>
      <button
        type="button"
        data-testid="active-range-clear"
        onClick={onClear}
        aria-label={`Clear time filter (currently filtered to ${startLabel}–${endLabel} ${zone})`}
        style={{
          background: 'transparent',
          border: 'none',
          cursor: 'pointer',
          color: 'var(--fw-t2)',
          fontSize: 13,
          lineHeight: 1,
          padding: '0 2px',
          display: 'flex',
          alignItems: 'center',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        ✕
      </button>
    </div>
  )
}
