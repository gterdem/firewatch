/**
 * NotableRow — always-expanded timeline entry for notable events (#270).
 *
 * Renders a single IpTimelineEventItem with:
 *   - Source-coloured dot on the left.
 *   - Orange left stripe for correlated events (carries forward EventTimeline pattern).
 *   - A reason tag (first-seen / last-seen / correlated / new-rule).
 *   - Time, label, payload — all as text nodes only (ADR-0029 D3).
 *
 * SECURITY: label and payload are attacker-controlled — rendered as text only.
 */

import type { NotableEventEntry } from './bucketEvents'
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
// Reason tag labels
// ---------------------------------------------------------------------------

const REASON_LABEL: Record<NotableEventEntry['reason'], string> = {
  'first-seen': 'first seen',
  'last-seen': 'last seen',
  correlated: 'correlated',
  'new-rule': 'new rule',
}

const REASON_COLOR: Record<NotableEventEntry['reason'], string> = {
  'first-seen': 'var(--fw-green)',
  'last-seen': 'var(--fw-blue)',
  correlated: 'var(--fw-orange)',
  'new-rule': 'var(--fw-purple)',
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface NotableRowProps {
  entry: NotableEventEntry
}

export function NotableRow({ entry }: NotableRowProps) {
  const { event, reason, index } = entry
  const isCorrelated = event.correlated

  return (
    <div
      data-testid={`timeline-event-${index}`}
      data-correlated={isCorrelated ? 'true' : 'false'}
      data-notable="true"
      style={{
        position: 'relative',
        marginBottom: 10,
        padding: '8px 12px',
        background: 'var(--fw-bg-input)',
        borderRadius: 'var(--fw-r-sm)',
        fontSize: 'var(--fw-fs-xs)',
        borderLeft: isCorrelated ? '3px solid var(--fw-orange)' : '3px solid transparent',
      }}
    >
      {/* Source-coloured dot */}
      <span
        data-testid={`timeline-dot-${index}`}
        aria-hidden="true"
        style={{
          position: 'absolute',
          left: -29,
          top: 14,
          width: 10,
          height: 10,
          borderRadius: '50%',
          border: '2px solid var(--fw-bg-card)',
          background: dotColorFor(event.source),
        }}
      />

      {/* Meta row: time · label · reason tag */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          marginBottom: event.payload ? 3 : 0,
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
        {/* Reason tag */}
        <span
          data-testid={`notable-reason-${index}`}
          style={{
            fontSize: 10,
            color: REASON_COLOR[reason],
            background: 'var(--fw-bg-card)',
            borderRadius: 3,
            padding: '1px 5px',
            fontWeight: 600,
            fontFamily: 'var(--fw-font-mono)',
          }}
        >
          {REASON_LABEL[reason]}
        </span>
        {/* Action tag */}
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

      {/* Payload — SECURITY: attacker-controlled, render as text only */}
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
  )
}
