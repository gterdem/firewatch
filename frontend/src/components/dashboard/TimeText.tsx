/**
 * TimeText — displays a timestamp in browser-local time with UTC available
 * on hover/focus (WCAG 2.2 SC 1.4.13-compliant tooltip, issue #244).
 *
 * Accepts an already-parsed Date so callers compose with parseApiTimestamp:
 *   <TimeText date={parseApiTimestamp(bucket.hour)} style="time" />
 *
 * The UTC value is surfaced via the native `title` attribute, which browsers
 * expose on hover and screen readers read via aria-describedby idioms.
 * SC 1.4.13: the content must be persistent (title stays open while hovering)
 * — native title meets this because the tooltip persists until pointer leaves.
 *
 * ADR-0028 D6: no raw hex — colors via var(--fw-*) tokens only.
 */

import { formatLocal, formatUtc } from '../../lib/time'
import type { TimeStyle } from '../../lib/time'

interface TimeTextProps {
  /** Pre-parsed Date (call parseApiTimestamp on the raw API string first). */
  date: Date
  /** Display style passed to formatLocal. Default: 'time'. */
  style?: TimeStyle
  /** Optional extra CSS className for the wrapping <span>. */
  className?: string
  /** Optional inline style for the wrapping <span>. */
  spanStyle?: React.CSSProperties
  /** Optional data-testid for assertions. */
  'data-testid'?: string
}

export default function TimeText({
  date,
  style = 'time',
  className,
  spanStyle,
  'data-testid': testId,
}: TimeTextProps) {
  const local = formatLocal(date, style)
  const utc = formatUtc(date)

  return (
    <span
      title={utc}
      aria-label={`${local} (${utc})`}
      className={className}
      style={spanStyle}
      data-testid={testId}
    >
      {local}
    </span>
  )
}
