/**
 * StripTiles — 5-tile header strip for the Network Logs page (issue #665).
 *
 * Replaces TrafficShapeHeader with one horizontal row:
 *   [ Events ] [ Blocked ] [ Distinct IPs ] [ Top Talker ▾ ] [ Top Protocol ▾ ]
 *
 * Data sources:
 *   - Events / Blocked / Distinct IPs — GET /logs/stats (#663). REAL totals, NOT a top-N sum.
 *   - Top Talker ▾ — GET /logs/top-talkers (top 5). Popover lists all 5; click cross-filters.
 *   - Top Protocol ▾ — GET /logs/protocol-mix (top 5). Popover lists top 5; click cross-filters.
 *     "(unknown)" → "Other" (non-clickable, per UT-10 / #508).
 *
 * The "Events Over Time" timeline is intentionally ABSENT here (dropped per #665 scope;
 * it duplicates the Dashboard's Activity timeline).
 *
 * Filter re-query (#667 WS4): the `filter` prop is passed to all three fetches so the
 * tiles re-query when the active filter changes. WS4 wires this end-to-end.
 *
 * SECURITY (ADR-0029 D3):
 *   source_ip and protocol values are attacker-controlled telemetry. They are passed
 *   to StripPivotTile and rendered as React text nodes only — never via
 *   dangerouslySetInnerHTML. IPs are never interpolated into hrefs or event handlers.
 *
 * Source-agnostic: no per-source branching anywhere in this file.
 */

import { useEffect, useState } from 'react'
import { fetchLogsStats, fetchTopTalkers, fetchProtocolMix } from '../../api/logs'
import type { LogsStats, TopTalkerRow, ProtocolMixRow } from '../../api/types'
import type { LogsFilter } from '../../api/types'
import { StripNumberTile } from './StripNumberTile'
import { StripPivotTile } from './StripPivotTile'
import type { StripPivotRow } from './StripPivotTile'

// ---------------------------------------------------------------------------
// Constants (ported from TrafficShapeHeader)
// ---------------------------------------------------------------------------

/**
 * Backend sentinel for events with no protocol field (e.g. Azure WAF L7 events).
 * Displayed as "Other" per UT-10 / #508; kept non-clickable.
 */
const UNKNOWN_PROTOCOL_SENTINEL = '(unknown)'

function protocolDisplayLabel(protocol: string): string {
  return protocol === UNKNOWN_PROTOCOL_SENTINEL ? 'Other' : protocol
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface StripTilesProps {
  /**
   * Active filter — passed to all three fetches so tiles stay in sync with the
   * rest of the page. WS4 (#667) wires the full re-query lifecycle.
   * For this issue (WS1), the tiles fetch with the filter on mount and on filter change.
   */
  filter?: Partial<LogsFilter>
  /**
   * Called when a popover row is activated (click or keyboard).
   * Merges a partial filter patch (ip= or protocol=) into the caller's filter.
   */
  onFilterChange: (patch: Partial<LogsFilter>) => void
}

// ---------------------------------------------------------------------------
// Shape helpers
// ---------------------------------------------------------------------------

function talkersToRows(talkers: TopTalkerRow[]): StripPivotRow[] {
  const max = talkers[0]?.count ?? 1
  return talkers.slice(0, 5).map((t) => ({
    key: t.source_ip,
    label: t.source_ip,
    count: t.count,
    hint:
      t.blocked > 0
        ? `${Math.round((t.blocked / t.count) * 100)}% blk`
        : undefined,
    _barPct: Math.round((t.count / max) * 100),
  }))
}

function protocolToRows(protocols: ProtocolMixRow[]): StripPivotRow[] {
  const total = protocols.reduce((s, r) => s + r.count, 0)
  return protocols.slice(0, 5).map((p) => ({
    key: p.protocol,
    label: protocolDisplayLabel(p.protocol),
    count: p.count,
    hint: total > 0 ? `${Math.round((p.count / total) * 100)}%` : undefined,
    nonClickable: p.protocol === UNKNOWN_PROTOCOL_SENTINEL,
  }))
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function StripTiles({ filter = {}, onFilterChange }: StripTilesProps) {
  const [stats, setStats] = useState<LogsStats | null>(null)
  const [topTalkers, setTopTalkers] = useState<TopTalkerRow[]>([])
  const [protocolMix, setProtocolMix] = useState<ProtocolMixRow[]>([])

  // Stable serialised key for the filter so the useEffect dep comparison
  // is accurate without object reference instability.
  const filterKey = JSON.stringify(filter)

  useEffect(() => {
    let cancelled = false

    Promise.allSettled([
      fetchLogsStats(filter),
      fetchTopTalkers(5),
      fetchProtocolMix(5),
    ]).then(([statsResult, ttResult, pmResult]) => {
      if (cancelled) return
      if (statsResult.status === 'fulfilled') setStats(statsResult.value)
      if (ttResult.status === 'fulfilled') setTopTalkers(ttResult.value)
      if (pmResult.status === 'fulfilled') setProtocolMix(pmResult.value)
    })

    return () => {
      cancelled = true
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterKey])

  // Derive pivot tile data
  const talkerRows = talkersToRows(topTalkers)
  const topTalker = topTalkers[0] ?? null
  const talkerBlockedRatio =
    topTalker !== null && topTalker.count > 0
      ? topTalker.blocked / topTalker.count
      : null

  const protocolRows = protocolToRows(protocolMix)
  const topProtocol = protocolMix[0] ?? null
  const protocolTotal = protocolMix.reduce((s, r) => s + r.count, 0)
  const topProtocolHint =
    topProtocol !== null && protocolTotal > 0
      ? `${Math.round((topProtocol.count / protocolTotal) * 100)}%`
      : null

  return (
    <div
      data-testid="strip-tiles"
      style={{
        display: 'flex',
        gap: 10,
        marginBottom: 16,
        flexWrap: 'wrap',
        alignItems: 'stretch',
      }}
    >
      {/* Tile 1: Events */}
      <StripNumberTile
        label="Events"
        value={stats?.total_events ?? null}
        data-testid="strip-tile-events"
      />

      {/* Tile 2: Blocked */}
      <StripNumberTile
        label="Blocked"
        value={stats?.blocked_events ?? null}
        data-testid="strip-tile-blocked"
      />

      {/* Tile 3: Distinct IPs */}
      <StripNumberTile
        label="Distinct IPs"
        value={stats?.distinct_ips ?? null}
        data-testid="strip-tile-distinct-ips"
      />

      {/* Tile 4: Top Talker */}
      <StripPivotTile
        label="Top Talker"
        primaryLabel={topTalker ? String(topTalker.source_ip) : null}
        primaryHint={topTalker ? topTalker.count.toLocaleString() : null}
        blockedRatio={talkerBlockedRatio}
        rows={talkerRows}
        filterKey="ip"
        onFilterChange={(key, value) => onFilterChange({ [key]: value })}
        data-testid="strip-tile-top-talker"
        triggerTestId="strip-top-talker-trigger"
        popoverTestId="strip-top-talker-popover"
      />

      {/* Tile 5: Top Protocol */}
      <StripPivotTile
        label="Top Protocol"
        primaryLabel={
          topProtocol ? protocolDisplayLabel(topProtocol.protocol) : null
        }
        primaryHint={topProtocolHint}
        rows={protocolRows}
        filterKey="protocol"
        onFilterChange={(key, value) => onFilterChange({ [key]: value })}
        data-testid="strip-tile-top-protocol"
        triggerTestId="strip-top-protocol-trigger"
        popoverTestId="strip-top-protocol-popover"
      />
    </div>
  )
}
