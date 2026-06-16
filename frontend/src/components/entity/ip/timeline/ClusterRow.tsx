/**
 * ClusterRow — collapsible cluster row for bucketed routine events (#270).
 *
 * Renders a summary row: "09:00–10:00 · 47 events · 3 rules · mostly blocked".
 * Expands in-place (no inner scroll!) to show its individual events when activated.
 * Collapsing restores the summary row.
 *
 * Keyboard: button for expand/collapse (Enter / Space).
 * No inner fixed-height scroll region — events render in the document flow (EARS: no 3rd scrollbar).
 *
 * SECURITY: event.label / event.payload are attacker-controlled — rendered as text only.
 */

import { useState } from 'react'
import type { ClusterEntry } from './bucketEvents'
import TimeText from '../../../dashboard/TimeText'
import { parseApiTimestamp } from '../../../../lib/time'

// ---------------------------------------------------------------------------
// Source dot colour (mirrors EventTimeline DOT_COLOR)
// ---------------------------------------------------------------------------

const DOT_COLOR: Record<string, string> = {
  azure_waf: 'var(--fw-src-waf)',
  waf: 'var(--fw-src-waf)',
  suricata: 'var(--fw-src-ids)',
  ids: 'var(--fw-src-ids)',
  syslog: 'var(--fw-src-syslog)',
  file: 'var(--fw-src-file)',
}

function dotColorFor(source: string): string {
  return DOT_COLOR[source] ?? 'var(--fw-t3)'
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface ClusterRowProps {
  cluster: ClusterEntry
  /** Chronological index of this cluster in the full row list (for keys). */
  rowIndex: number
}

export function ClusterRow({ cluster, rowIndex }: ClusterRowProps) {
  const [expanded, setExpanded] = useState(false)

  const ruleText = cluster.distinctRules === 1
    ? '1 rule'
    : `${cluster.distinctRules} rules`
  const dispositionText = cluster.dominantDisposition === 'BLOCK' ? 'mostly blocked' : 'mostly alerted'

  return (
    <div
      data-testid={`timeline-cluster-${rowIndex}`}
      style={{ marginBottom: 10 }}
    >
      {/* Cluster summary row — keyboard-operable button */}
      <button
        type="button"
        data-testid={`timeline-cluster-toggle-${rowIndex}`}
        aria-expanded={expanded}
        aria-label={`${cluster.label} · ${cluster.count} events — ${expanded ? 'collapse' : 'expand'}`}
        onClick={() => setExpanded((prev) => !prev)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          width: '100%',
          padding: '8px 12px',
          background: 'var(--fw-bg-input)',
          border: '1px dashed var(--fw-border)',
          borderRadius: 'var(--fw-r-sm)',
          cursor: 'pointer',
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          textAlign: 'left',
        }}
      >
        {/* Expand/collapse indicator */}
        <span
          aria-hidden="true"
          style={{
            fontSize: 10,
            transition: 'transform 0.15s ease',
            transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)',
            flexShrink: 0,
          }}
        >
          ▶
        </span>

        {/* Bucket time window */}
        <span style={{ fontFamily: 'var(--fw-font-mono)' }}>{cluster.label}</span>

        {/* Event count */}
        <span
          data-testid={`cluster-count-${rowIndex}`}
          style={{ color: 'var(--fw-t2)', fontWeight: 600 }}
        >
          {cluster.count} events
        </span>

        <span style={{ color: 'var(--fw-t3)' }}>·</span>
        <span>{ruleText}</span>
        <span style={{ color: 'var(--fw-t3)' }}>·</span>
        <span
          style={{
            color: cluster.dominantDisposition === 'BLOCK' ? 'var(--fw-red)' : 'var(--fw-t3)',
          }}
        >
          {dispositionText}
        </span>
      </button>

      {/* Expanded individual events — rendered in-flow (no inner scroll!) */}
      {expanded && (
        <div
          data-testid={`timeline-cluster-events-${rowIndex}`}
          style={{
            borderLeft: '2px solid var(--fw-border)',
            marginLeft: 20,
            marginTop: 4,
            paddingLeft: 12,
          }}
        >
          {cluster.events.map(({ event, index }) => (
            <div
              key={index}
              data-testid={`timeline-event-${index}`}
              data-correlated={event.correlated ? 'true' : 'false'}
              style={{
                position: 'relative',
                marginBottom: 8,
                padding: '6px 10px',
                background: 'var(--fw-bg-input)',
                borderRadius: 'var(--fw-r-sm)',
                fontSize: 'var(--fw-fs-xs)',
                borderLeft: event.correlated ? '3px solid var(--fw-orange)' : '3px solid transparent',
              }}
            >
              {/* Source dot */}
              <span
                data-testid={`timeline-dot-${index}`}
                aria-hidden="true"
                style={{
                  position: 'absolute',
                  left: -17,
                  top: 11,
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  border: '2px solid var(--fw-bg-card)',
                  background: dotColorFor(event.source),
                }}
              />

              {/* Meta row */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 5,
                  color: 'var(--fw-t3)',
                  flexWrap: 'wrap',
                }}
              >
                <TimeText
                  date={parseApiTimestamp(event.time)}
                  style="relative"
                  spanStyle={{ fontFamily: 'var(--fw-font-mono)' }}
                  data-testid={`timeline-time-${index}`}
                />
                {event.label ? <span>· {event.label}</span> : null}
                {event.category ? (
                  <span style={{ color: 'var(--fw-t2)' }}>· {event.category}</span>
                ) : null}
                {event.action && (
                  <span
                    style={{
                      fontSize: 10,
                      color: event.action === 'BLOCK' ? 'var(--fw-red)' : 'var(--fw-t3)',
                      fontFamily: 'var(--fw-font-mono)',
                    }}
                  >
                    {event.action}
                  </span>
                )}
              </div>

              {/* Payload — SECURITY: attacker-controlled, text only */}
              {event.payload ? (
                <div
                  style={{
                    color: 'var(--fw-t2)',
                    fontFamily: 'var(--fw-font-mono)',
                    fontSize: 'var(--fw-fs-2xs)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {event.payload}
                </div>
              ) : null}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
