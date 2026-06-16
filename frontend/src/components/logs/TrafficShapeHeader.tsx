/**
 * TrafficShapeHeader — ML-4 (#432) traffic-shape header for the Network Logs page.
 *
 * Three-part compact header rendered above the logs table:
 *   (a) Volume timeline — events over time via GET /logs/timeline (EARS-1).
 *   (b) Top talkers    — top source IPs by count via GET /logs/top-talkers (EARS-2).
 *       Clicking an IP cross-filters the table below (EARS-3).
 *   (c) Protocol mix   — per-protocol counts via GET /logs/protocol-mix (EARS-2).
 *       Clicking a protocol cross-filters (EARS-3).
 *
 * Totals strip (EARS-4): events / blocked / distinct IPs from the same fetches.
 *
 * Reuses TimelineChart (the chart primitive already used on the Dashboard).
 * No new chart libraries — CSS-only bars for the protocol mix and top-talkers.
 *
 * Source-agnostic: no per-source branching. Azure WAF rows that lack a protocol
 * appear under the "(unknown)" bucket — honest about L7-only sources.
 *
 * SECURITY (ADR-0029 D3):
 *   source_ip and protocol values are attacker-controlled telemetry. They are
 *   rendered as React text nodes only — never via dangerouslySetInnerHTML.
 *   IPs are not interpolated into hrefs or event handlers that could execute code.
 */

import { useEffect, useState } from 'react'
import { fetchTimeline } from '../../api/client'
import { fetchTopTalkers, fetchProtocolMix } from '../../api/logs'
import type { TimelineBucket, TopTalkerRow, ProtocolMixRow } from '../../api/types'
import type { LogsFilter } from '../../api/types'
import TimelineChart from '../dashboard/TimelineChart'
import { Panel } from '../ds'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface TrafficShapeHeaderProps {
  /**
   * Called when the user clicks a top-talker IP or a protocol row to cross-filter
   * the logs table below. Merges into the current filter (EARS-3).
   */
  onFilterChange: (patch: Partial<LogsFilter>) => void
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Sentinel returned by the backend store when an event has no protocol field
 * (NULL rows are grouped under this key server-side, e.g. Azure WAF L7 events).
 * We accept this as the canonical "no protocol" bucket identifier.
 *
 * UT-10 / #508: display it as "Other" instead of the raw sentinel — the raw
 * value is still used for comparisons (non-clickable check, key prop) so the
 * behaviour is unchanged; only the visible label improves.
 */
const UNKNOWN_PROTOCOL_SENTINEL = '(unknown)'

/**
 * Returns the display label for a protocol row.
 * Maps the backend sentinel to a cleaner label for the UI (UT-10 / #508).
 */
function protocolDisplayLabel(protocol: string): string {
  return protocol === UNKNOWN_PROTOCOL_SENTINEL ? 'Other' : protocol
}

// ---------------------------------------------------------------------------
// Small rendering helpers (no state — pure visual)
// ---------------------------------------------------------------------------

/**
 * Compact horizontal bar row for protocol mix and top-talkers.
 * barPct: 0–100 percentage of max in the list.
 * SECURITY: label is attacker-controlled — rendered as a text node.
 */
function MiniBarRow({
  label,
  count,
  barPct,
  onClick,
}: {
  label: string
  count: number
  barPct: number
  onClick?: () => void
}) {
  const isClickable = onClick !== undefined
  return (
    <div
      role={isClickable ? 'button' : undefined}
      tabIndex={isClickable ? 0 : undefined}
      aria-label={isClickable ? `Filter by ${label}` : undefined}
      onClick={onClick}
      onKeyDown={(e) => {
        if (isClickable && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault()
          onClick()
        }
      }}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 6,
        padding: '3px 0',
        cursor: isClickable ? 'pointer' : 'default',
      }}
    >
      {/* Label — SECURITY: text node only */}
      <span
        style={{
          width: 120,
          fontFamily: 'var(--fw-font-mono)',
          fontSize: 11,
          color: 'var(--fw-t1)',
          flexShrink: 0,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {String(label)}
      </span>

      {/* Bar track */}
      <div
        style={{
          flex: 1,
          height: 10,
          background: 'var(--fw-bg-input)',
          borderRadius: 2,
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            width: `${barPct}%`,
            height: '100%',
            background: 'var(--fw-blue)',
            borderRadius: 2,
          }}
        />
      </div>

      {/* Count */}
      <span
        style={{
          width: 50,
          textAlign: 'right',
          fontFamily: 'var(--fw-font-mono)',
          fontSize: 11,
          color: 'var(--fw-t3)',
          flexShrink: 0,
          fontVariantNumeric: 'tabular-nums',
        }}
      >
        {count.toLocaleString()}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Totals strip
// ---------------------------------------------------------------------------

function TotalsStrip({
  totalEvents,
  blockedEvents,
  distinctIps,
}: {
  totalEvents: number
  blockedEvents: number
  distinctIps: number
}) {
  const items = [
    { label: 'Events (window)', value: totalEvents.toLocaleString(), testid: 'traffic-total-events' },
    { label: 'Blocked', value: blockedEvents.toLocaleString(), testid: 'traffic-blocked-events' },
    { label: 'Distinct IPs', value: distinctIps.toLocaleString(), testid: 'traffic-distinct-ips' },
  ]

  return (
    <div
      data-testid="traffic-totals-strip"
      style={{
        display: 'flex',
        gap: 16,
        marginBottom: 12,
        flexWrap: 'wrap',
      }}
    >
      {items.map((item) => (
        <div
          key={item.label}
          data-testid={item.testid}
          style={{
            background: 'var(--fw-bg-card)',
            border: '1px solid var(--fw-border)',
            borderRadius: 8,
            padding: '8px 16px',
            display: 'flex',
            flexDirection: 'column',
            gap: 2,
            minWidth: 110,
          }}
        >
          <span
            style={{
              fontFamily: 'var(--fw-font-mono)',
              fontSize: 18,
              fontWeight: 700,
              color: 'var(--fw-t1)',
              lineHeight: 1,
            }}
          >
            {item.value}
          </span>
          <span
            style={{
              fontSize: 10,
              color: 'var(--fw-t3)',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
            }}
          >
            {item.label}
          </span>
        </div>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function TrafficShapeHeader({ onFilterChange }: TrafficShapeHeaderProps) {
  const [timeline, setTimeline] = useState<TimelineBucket[]>([])
  const [topTalkers, setTopTalkers] = useState<TopTalkerRow[]>([])
  const [protocolMix, setProtocolMix] = useState<ProtocolMixRow[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false

    Promise.allSettled([
      fetchTimeline(),
      fetchTopTalkers(10),
      fetchProtocolMix(10),
    ]).then(([tlResult, ttResult, pmResult]) => {
      if (cancelled) return
      if (tlResult.status === 'fulfilled') setTimeline(tlResult.value)
      if (ttResult.status === 'fulfilled') setTopTalkers(ttResult.value)
      if (pmResult.status === 'fulfilled') setProtocolMix(pmResult.value)
      setLoading(false)
    })

    return () => { cancelled = true }
  }, [])

  // Derived totals from top-talkers list (best available without a separate stats fetch).
  const totalEvents = topTalkers.reduce((s, r) => s + r.count, 0)
  const blockedEvents = topTalkers.reduce((s, r) => s + r.blocked, 0)
  const distinctIps = topTalkers.length

  const maxTalkerCount = topTalkers[0]?.count ?? 1
  const maxProtocolCount = protocolMix[0]?.count ?? 1

  if (loading) {
    return (
      <div
        data-testid="traffic-header-loading"
        style={{
          padding: '12px 0',
          color: 'var(--fw-t3)',
          fontFamily: 'var(--fw-font-ui)',
          fontSize: 13,
        }}
      >
        Loading traffic summary…
      </div>
    )
  }

  // All-empty: don't render the header at all (nothing to show).
  if (timeline.length === 0 && topTalkers.length === 0 && protocolMix.length === 0) {
    return null
  }

  return (
    <div data-testid="traffic-shape-header" style={{ marginBottom: 16 }}>
      {/* Totals strip */}
      <TotalsStrip
        totalEvents={totalEvents}
        blockedEvents={blockedEvents}
        distinctIps={distinctIps}
      />

      {/* Three-column layout: timeline | top-talkers | protocol-mix */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 200px 200px',
          gap: 12,
          alignItems: 'start',
        }}
      >
        {/* (a) Volume timeline */}
        {timeline.length > 0 && (
          <Panel title="Events Over Time" data-testid="traffic-timeline-panel">
            <TimelineChart buckets={timeline} />
          </Panel>
        )}

        {/* (b) Top talkers */}
        {topTalkers.length > 0 && (
          <Panel title="Top Talkers" data-testid="traffic-top-talkers-panel">
            {topTalkers.slice(0, 8).map((row) => (
              <MiniBarRow
                key={row.source_ip}
                label={row.source_ip}
                count={row.count}
                barPct={Math.round((row.count / maxTalkerCount) * 100)}
                onClick={() => onFilterChange({ ip: row.source_ip })}
              />
            ))}
          </Panel>
        )}

        {/* (c) Protocol mix */}
        {protocolMix.length > 0 && (
          <Panel title="Protocol Mix" data-testid="traffic-protocol-mix-panel">
            {protocolMix.slice(0, 8).map((row) => (
              <MiniBarRow
                key={row.protocol}
                label={protocolDisplayLabel(row.protocol)}
                count={row.count}
                barPct={Math.round((row.count / maxProtocolCount) * 100)}
                onClick={
                  row.protocol !== UNKNOWN_PROTOCOL_SENTINEL
                    ? () => onFilterChange({ protocol: row.protocol })
                    : undefined
                }
              />
            ))}
          </Panel>
        )}
      </div>
    </div>
  )
}
