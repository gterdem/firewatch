/**
 * KpiStrip — v2 thin KPI row (MF-2 / issue #159, layout #254).
 *
 * Replaces the tall 5-up StatCard grid with a single horizontal strip.
 * Each KPI is a KpiTile (value + label + optional sparkline/arrow).
 *
 * Layout rules (issue #254):
 *   - Tiles flex edge-to-edge (justify-content: stretch via flex:1 on each tile).
 *   - AiEnginePill is pinned hard-right in a dedicated right slot.
 *   - No left-packed dead space; tiles grow to fill the full strip width.
 *   - If the tile count grows beyond ~6, wrapping handled at the tile level.
 *
 * Sparklines (issue #254 + #245):
 *   - "Total events" → totalEventsSeries(timeline)
 *   - "Blocked"      → blockedEventsSeries(timeline)
 *   - "Block rate"   → blockRateSeries(timeline)
 *   - "Unique IPs"   → no series (GET /logs/timeline has no per-bucket IP count;
 *                       flagged to architect — tile renders number-only, same height).
 *
 * Data: GET /stats → KPI values; GET /logs/timeline → sparkline series (optional).
 * AI engine pill from GET /health (authoritative, fix #180); threat-derived fallback.
 *
 * ADR-0028 D6: no raw hex — all colors via var(--fw-*) tokens.
 * ADR-0029 D3: no attacker-controlled data rendered here.
 * ADR-0017: no inner scrollbar — overflowX omitted; tiles shrink gracefully.
 */

import type { AiStatus, HealthResponse, StatsResponse, TimelineBucket } from '../../api/types'
import AiEnginePill from './AiEnginePill'
import KpiTile from './KpiTile'
import { totalEventsSeries, blockedEventsSeries, blockRateSeries } from '../../lib/kpiSeries'

export interface KpiStripProps {
  stats: StatsResponse
  /** Threat-derived AI status — used as fallback while health is in flight. */
  aiStatus?: AiStatus | null
  /**
   * Health response from GET /health — authoritative AI engine state (fix #180).
   * When provided, overrides threat-derived aiStatus for the chip.
   */
  health?: HealthResponse | null
  /**
   * Timeline buckets from GET /logs/timeline.
   * Used to derive per-KPI sparkline series (issue #254).
   * Optional: when absent, all tiles render number-only (no layout shift).
   */
  timeline?: TimelineBucket[]
}

export default function KpiStrip({
  stats,
  aiStatus = null,
  health,
  timeline = [],
}: KpiStripProps) {
  const blocked = Math.round((stats.total_logs * stats.blocked_percentage) / 100)
  const blockRate = `${stats.blocked_percentage.toFixed(1)}%`

  // Derive per-KPI series from the already-fetched timeline.
  // Memoisation not needed: this is pure map() over at most ~24 hourly buckets.
  const totalSeries = totalEventsSeries(timeline)
  const blockedSeries = blockedEventsSeries(timeline)
  const blockRateSeries_ = blockRateSeries(timeline)
  // "Unique IPs" has no series — GET /logs/timeline carries no per-bucket IP count.
  // Flagged to architect; tile renders number-only.

  return (
    <div
      data-testid="kpi-strip"
      style={{
        display: 'flex',
        alignItems: 'stretch',
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border)',
        borderRadius: 8,
        padding: '6px 0',
        marginBottom: 16,
      }}
    >
      {/* KPI tiles — flex:1 each, evenly distributed across the full strip width.
          Vertical separator between tiles via borderRight on all but the last. */}
      <div
        data-testid="kpi-tiles"
        style={{
          flex: 1,
          display: 'flex',
          alignItems: 'stretch',
          minWidth: 0,
        }}
      >
        <div
          style={{
            flex: 1,
            borderRight: '1px solid var(--fw-border)',
          }}
        >
          <KpiTile
            value={stats.total_logs.toLocaleString()}
            label="Total events"
            series={totalSeries}
            testId="kpi-total-events"
          />
        </div>

        <div
          style={{
            flex: 1,
            borderRight: '1px solid var(--fw-border)',
          }}
        >
          <KpiTile
            value={blocked.toLocaleString()}
            label="Blocked"
            valueColor="var(--fw-red)"
            series={blockedSeries}
            sparklineColor="var(--fw-red)"
            testId="kpi-blocked"
          />
        </div>

        <div
          style={{
            flex: 1,
            borderRight: '1px solid var(--fw-border)',
          }}
        >
          <KpiTile
            value={stats.total_ips.toLocaleString()}
            label="Unique IPs"
            // No series: timeline has no per-bucket IP count. Number-only, same height.
            testId="kpi-unique-ips"
          />
        </div>

        <div style={{ flex: 1 }}>
          <KpiTile
            value={blockRate}
            label="Block rate"
            valueColor="var(--fw-green)"
            series={blockRateSeries_}
            sparklineColor="var(--fw-green)"
            testId="kpi-block-rate"
          />
        </div>
      </div>

      {/* AI engine pill — global always-on engine status (issue #207, ADR-0035 §4).
          Pinned hard-right in the strip (metrics flex-fill left, status pinned right).
          The ONLY always-on AI indicator on the dashboard (EARS: exactly one, #207).
          Non-fatal: hidden while health is in-flight (ADR-0015). */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          padding: '8px 16px',
          borderLeft: '1px solid var(--fw-border)',
          flexShrink: 0,
        }}
        data-testid="kpi-ai-status"
      >
        <AiEnginePill health={health} aiStatus={aiStatus} />
      </div>
    </div>
  )
}
