/**
 * NotTimeScopedMarker — visible marker for panes whose endpoint does not
 * support time-range filtering (issue #249).
 *
 * EARS requirement: WHERE a pane's endpoint cannot be time-scoped, the pane
 * SHALL indicate it is not range-filtered (no silent wrong data).
 *
 * This component renders ONLY when a brush range is active.  When no range
 * is set, it returns null — zero impact on the default layout.
 *
 * Usage:
 *   <NotTimeScopedMarker active={activeRange !== null} />
 *
 * ADR-0028 D6: colours via --fw-* tokens only; no raw hex.
 *
 * Gap list (architect follow-up, issue #249):
 *   The following endpoints do not yet accept start/end range params.
 *   They are marked with this component rather than silently showing unfiltered data.
 *   Architect should add range support to each:
 *     - GET /threats         → ThreatActors, AiSidebar, TriageBanner, RecommendationCards, ThreatActorSummary panes
 *     - GET /logs/categories → CategoryBreakdown (Dispositions pane) + BlockedLogsPanel category tabs
 *     - GET /analytics/attack-dispositions → AttackDispositionFlow pane
 *     - GET /stats           → KpiStrip (global totals; scoped stats would be a new endpoint)
 */

export interface NotTimeScopedMarkerProps {
  /**
   * Whether a range is currently active.
   * When false, this component renders nothing (zero footprint on default layout).
   */
  active: boolean
  /** Optional additional className for positioning. */
  className?: string
}

export default function NotTimeScopedMarker({ active, className }: NotTimeScopedMarkerProps) {
  if (!active) return null

  return (
    <div
      data-testid="not-time-scoped-marker"
      className={className}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        padding: '2px 7px',
        borderRadius: 4,
        background: 'var(--fw-bg-input)',
        border: '1px solid var(--fw-border-l)',
        fontSize: 10,
        fontFamily: 'var(--fw-font-ui)',
        color: 'var(--fw-t3)',
        userSelect: 'none',
      }}
      title="This pane's data source does not support time-range filtering yet — showing all-time data"
    >
      <span aria-hidden="true">⏱</span>
      not time-scoped
    </div>
  )
}
