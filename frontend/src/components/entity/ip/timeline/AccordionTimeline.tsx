/**
 * AccordionTimeline — correlation-first accordion timeline orchestrator (#270).
 *
 * Replaces the flat EventTimeline in IpPanel for the IP entity panel.
 *
 * Behaviour:
 *   - Notable events (correlated, first/last seen, new-rule) always render expanded.
 *   - Routine events collapse into hourly ClusterRow rows.
 *   - When total > notableThreshold, a "+N routine events" expander shows/hides all clusters.
 *   - No inner fixed-height scrollable region (no 3rd scrollbar — EARS).
 *
 * Correlation-first: correlated events are tagged with "correlated" reason and carry the
 * orange left stripe inherited from EventTimeline. Notable entries always surface at
 * their natural chronological position.
 *
 * "Correlation-first ordering": rows are sorted chronologically (ascending).  Correlated
 * events are labelled so they visually stand out — they don't reorder, which would
 * destroy the attack narrative chronology that Sentinel-like tools preserve.
 *
 * ADR-0029 D3: all attacker-controlled values rendered as text only (delegated to children).
 */

import { useState, useMemo } from 'react'
import type { IpTimelineEventItem } from '../../../../api/types'
import { bucketEvents } from './bucketEvents'
import { NotableRow } from './NotableRow'
import { ClusterRow } from './ClusterRow'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface AccordionTimelineProps {
  events: IpTimelineEventItem[]
  /**
   * When the number of events exceeds this threshold, routine events collapse
   * into cluster rows. Default: 10 (shows up to 10 notable events before collapsing).
   */
  notableThreshold?: number
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AccordionTimeline({ events, notableThreshold = 10 }: AccordionTimelineProps) {
  const [routineExpanded, setRoutineExpanded] = useState(false)

  const rows = useMemo(() => bucketEvents(events, notableThreshold), [events, notableThreshold])

  if (events.length === 0) return null

  // Separate cluster rows for the summary/expander pattern.
  const clusterRows = rows.filter((r) => r.kind === 'cluster')
  const routineCount = clusterRows.reduce(
    (sum, r) => (r.kind === 'cluster' ? sum + r.count : sum),
    0,
  )

  // When everything fits in notable rows (no clusters), just render them directly.
  const hasClusters = clusterRows.length > 0

  return (
    <div
      data-testid="accordion-timeline"
      style={{
        position: 'relative',
        paddingLeft: 24,
        borderLeft: '2px solid var(--fw-border)',
        marginTop: 8,
      }}
    >
      {/* Render ALL rows in chronological order.
          Clusters are conditionally hidden via the +N expander. */}
      {rows.map((row, i) => {
        if (row.kind === 'notable') {
          return <NotableRow key={`notable-${row.index}`} entry={row} />
        }
        // Cluster row — hidden until the user expands.
        if (!routineExpanded) return null
        return <ClusterRow key={`cluster-${row.startMs}`} cluster={row} rowIndex={i} />
      })}

      {/* +N routine events expander — only shown when there are clusters */}
      {hasClusters && (
        <button
          type="button"
          data-testid="timeline-routine-expander"
          aria-expanded={routineExpanded}
          aria-label={
            routineExpanded
              ? 'Hide routine events'
              : `Show ${routineCount} routine events`
          }
          onClick={() => setRoutineExpanded((prev) => !prev)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '5px 10px',
            marginTop: 4,
            background: 'none',
            border: '1px dashed var(--fw-border)',
            borderRadius: 'var(--fw-r-sm)',
            cursor: 'pointer',
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-blue)',
          }}
        >
          <span aria-hidden="true">{routineExpanded ? '▲' : '▼'}</span>
          {routineExpanded ? 'Hide routine events' : `+${routineCount} routine events`}
        </button>
      )}
    </div>
  )
}
