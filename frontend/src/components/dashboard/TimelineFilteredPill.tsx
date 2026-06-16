/**
 * TimelineFilteredPill — local echo chip for the Activity Timeline pane header.
 *
 * Rendered in the "Activity timeline" Panel's `actions` slot when a brush range
 * is active.  Communicates to the analyst that the timeline bars are currently
 * filtered — while the global ActiveRangeChip (above the KPI strip) communicates
 * that EVERY pane is affected.
 *
 * This is the LOCAL echo described in issue #332:
 *   - Global chip (ActiveRangeChip) = affects all panes → stays in DashboardRoute header
 *   - Local echo (this pill) = "this pane is filtered" → lives in the Panel header
 *
 * Renders nothing when `active` is false (no range set).
 *
 * ADR-0028 D6: DS tokens only — no raw hex.
 */

interface TimelineFilteredPillProps {
  /** Whether a brush range is currently active. */
  active: boolean
}

export default function TimelineFilteredPill({ active }: TimelineFilteredPillProps) {
  if (!active) return null

  return (
    <span
      data-testid="timeline-filtered-pill"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '1px 7px',
        borderRadius: 10,
        background: 'var(--fw-accent-amber)',
        color: 'var(--fw-bg-base)',
        fontSize: 10,
        fontFamily: 'var(--fw-font-ui)',
        fontWeight: 600,
        letterSpacing: '0.03em',
        lineHeight: 1.2,
        userSelect: 'none',
      }}
      aria-label="Timeline is filtered to selected range"
    >
      filtered
    </span>
  )
}
