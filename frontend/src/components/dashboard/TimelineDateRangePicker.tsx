/**
 * TimelineDateRangePicker — custom Start → End datetime picker row for the
 * Activity-timeline panel header (part-4 P3 follow-up).
 *
 * Renders two <input type="datetime-local"> inputs ("From" / "To") with
 * hour granularity (step=3600).  Styled with --fw-* design-system tokens
 * so it fits the SOC dark theme without any raw hex (ADR-0028 D6).
 *
 * The component is purely controlled: it calls `onStartChange` / `onEndChange`
 * with corrected datetime-local values after applying the range rules, and
 * calls `onApply(startUtcIso, endUtcIso)` when both values form a valid range.
 *
 * Range rules (enforced here via the helpers in lib/timelineDateRange):
 *   - On Start change: if End is empty, ≤ Start, or > 24h after Start
 *       → auto-set End = Start + 12h.
 *   - On End change: if End ≤ Start → reset End = Start + 12h.
 *       If End − Start > 24h → clamp End = Start + 24h.
 *
 * Accessibility:
 *   - Each input carries an aria-label ("From" / "To") providing its accessible name.
 *   - Keyboard-operable (native datetime-local is keyboard-accessible).
 *   - The picker row does NOT overlap the chart area (lives in the Panel header).
 *
 * The `isActive` prop dims the pickers when a preset window is active, giving
 * a clear visual cue about which mode is driving the chart.
 */

import type { ChangeEvent } from 'react'
import { deriveEndOnStartChange, deriveEndOnEndChange, datetimeLocalToIso, isValidCustomRange } from '../../lib/timelineDateRange'

export interface TimelineDateRangePickerProps {
  /** Current datetime-local value for the start input (may be empty string). */
  startValue: string
  /** Current datetime-local value for the end input (may be empty string). */
  endValue: string
  /**
   * Whether the custom range is the active mode driving the chart.
   * When false (a preset is active), the inputs are dimmed but remain editable.
   */
  isActive: boolean
  /**
   * Called with the corrected datetime-local value whenever Start changes.
   * The parent must update its state with this value.
   */
  onStartChange: (newStart: string, correctedEnd: string) => void
  /**
   * Called with the corrected datetime-local value whenever End changes.
   * The parent must update its state with this value.
   */
  onEndChange: (correctedEnd: string) => void
  /**
   * Called when a valid range is committed (both values non-empty, End > Start,
   * End − Start ≤ 24h).  Arguments are UTC ISO-8601 strings for the API.
   */
  onApply: (startUtc: string, endUtc: string) => void
}

export default function TimelineDateRangePicker({
  startValue,
  endValue,
  isActive,
  onStartChange,
  onEndChange,
  onApply,
}: TimelineDateRangePickerProps) {
  const inputStyle: React.CSSProperties = {
    background: 'var(--fw-bg-input)',
    border: '1px solid var(--fw-border-l)',
    borderRadius: 4,
    color: isActive ? 'var(--fw-t1)' : 'var(--fw-t3)',
    fontFamily: 'var(--fw-font-ui)',
    fontSize: 11,
    padding: '3px 6px',
    outline: 'none',
    width: 158,
    cursor: 'pointer',
    transition: 'border-color 0.15s',
    colorScheme: 'dark',
  }

  function handleStartChange(e: ChangeEvent<HTMLInputElement>) {
    const newStart = e.target.value
    if (!newStart) return
    const correctedEnd = deriveEndOnStartChange(newStart, endValue)
    onStartChange(newStart, correctedEnd)
    if (isValidCustomRange(newStart, correctedEnd)) {
      onApply(datetimeLocalToIso(newStart), datetimeLocalToIso(correctedEnd))
    }
  }

  function handleEndChange(e: ChangeEvent<HTMLInputElement>) {
    if (!startValue || !e.target.value) return
    const correctedEnd = deriveEndOnEndChange(startValue, e.target.value)
    onEndChange(correctedEnd)
    if (isValidCustomRange(startValue, correctedEnd)) {
      onApply(datetimeLocalToIso(startValue), datetimeLocalToIso(correctedEnd))
    }
  }

  return (
    <div
      data-testid="timeline-date-range-picker"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 6,
        opacity: isActive ? 1 : 0.6,
      }}
    >
      {/* From input */}
      <input
        id="timeline-range-start"
        data-testid="timeline-range-start"
        aria-label="From"
        type="datetime-local"
        step={3600}
        value={startValue}
        onChange={handleStartChange}
        style={inputStyle}
      />

      {/* Separator */}
      <span
        aria-hidden="true"
        style={{
          fontSize: 11,
          color: 'var(--fw-t3)',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        to
      </span>

      {/* To input */}
      <input
        id="timeline-range-end"
        data-testid="timeline-range-end"
        aria-label="To"
        type="datetime-local"
        step={3600}
        value={endValue}
        onChange={handleEndChange}
        style={inputStyle}
      />
    </div>
  )
}
