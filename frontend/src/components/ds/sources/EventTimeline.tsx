/**
 * EventTimeline — vertical multi-source timeline for the IP drill-down.
 *
 * Ported from legacy/FireWatch SOC Design System/components/sources/EventTimeline.jsx.
 * Runtime CSS injection replaced with inline styles over --fw-* tokens (F2 pattern).
 *
 * Each entry is colour-dotted by its source; entries flagged `correlated`
 * (the same actor seen across feeds) get an orange left stripe — the v2
 * cross-source correlation signal.
 *
 * OD-3 (approved): built from existing detections + source_types (coarser).
 * A richer per-event cross-source feed is a flagged backend follow-up (#118),
 * not built here.
 *
 * EARS:
 *   - State-driven: WHEN an EventTimeline entry is `correlated`, it shall render
 *     the orange left-stripe + "correlated" label.
 *
 * ADR-0019: React + TS. ADR-0016: multi-source. No per-source hardcoding.
 */

import type { HTMLAttributes, ReactNode } from 'react'

export interface TimelineEvent {
  /** Source module — colours the dot (waf=blue, ids=orange, syslog=green, file=purple). */
  source: string
  /** Timestamp text (monospace). */
  time: string
  /** Short description (rule/signature name). */
  label?: ReactNode
  /** Raw payload / message (mono, truncated). SECURITY: render as text only, never as HTML. */
  payload?: ReactNode
  /** Mark as a cross-source correlated event — adds the orange stripe. */
  correlated?: boolean
}

export interface EventTimelineProps extends HTMLAttributes<HTMLDivElement> {
  events: TimelineEvent[]
}

/** Maps source id → dot colour token. */
const DOT_COLOR: Record<string, string> = {
  azure_waf: 'var(--fw-src-waf)',
  waf: 'var(--fw-src-waf)',
  suricata: 'var(--fw-src-ids)',
  ids: 'var(--fw-src-ids)',
  syslog: 'var(--fw-src-syslog)',
  file: 'var(--fw-src-file)',
}

/** Returns the dot background colour for a source id (neutral fallback). */
function dotColorFor(source: string): string {
  return DOT_COLOR[source] ?? 'var(--fw-t3)'
}

export function EventTimeline({ events = [], className = '', style, ...rest }: EventTimelineProps) {
  return (
    <div
      className={`fw-evtl ${className}`}
      style={{
        position: 'relative',
        paddingLeft: 24,
        borderLeft: '2px solid var(--fw-border)',
        marginTop: 8,
        ...style,
      }}
      {...rest}
    >
      {events.map((e, i) => (
        <div
          key={i}
          data-testid={`timeline-event-${i}`}
          data-correlated={e.correlated ? 'true' : 'false'}
          style={{
            position: 'relative',
            marginBottom: 10,
            padding: '8px 12px',
            background: 'var(--fw-bg-input)',
            borderRadius: 'var(--fw-r-sm)',
            fontSize: 'var(--fw-fs-xs)',
            // Orange left stripe for correlated events (OD-3)
            borderLeft: e.correlated ? '3px solid var(--fw-orange)' : '3px solid transparent',
          }}
        >
          {/* Source-coloured dot */}
          <span
            data-testid={`timeline-dot-${i}`}
            aria-hidden="true"
            style={{
              position: 'absolute',
              left: -29,
              top: 14,
              width: 10,
              height: 10,
              borderRadius: '50%',
              border: '2px solid var(--fw-bg-card)',
              background: dotColorFor(e.source),
            }}
          />

          {/* Meta row: time · label · correlated tag */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              marginBottom: 3,
              color: 'var(--fw-t3)',
            }}
          >
            <span style={{ fontFamily: 'var(--fw-font-mono)' }}>{e.time}</span>
            {e.label ? <span>· {e.label}</span> : null}
            {e.correlated ? (
              <span style={{ color: 'var(--fw-orange)' }}>· correlated</span>
            ) : null}
          </div>

          {/* Payload — SECURITY: attacker-controlled, render as text only */}
          {e.payload ? (
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
              {e.payload}
            </div>
          ) : null}
        </div>
      ))}
    </div>
  )
}
