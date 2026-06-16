/**
 * KpiCards — 5-up KPI tile row (DS StatCard, issue #113).
 *
 * Ports the kit's `.cards` grid exactly:
 *   Total events (📊 amber) · Blocked (🛡️ red) · Unique IPs (🌐 blue) ·
 *   Block rate (✅ green) · AI status (🤖 green/neutral)
 *
 * Data: GET /stats → first 4 cards; AI status derived from GET /threats
 * and passed in as the `aiStatus` prop (non-fatal, ADR-0015).
 *
 * Layout: `grid-template-columns: repeat(5, 1fr)` matching kit `.cards`.
 * Values rendered in DS StatCard monospace font (--fw-font-mono).
 */

import type { AiStatus, StatsResponse } from '../../api/types'
import { StatCard } from '../ds'
import AiStatusChip from '../AiStatusChip'

export interface KpiCardsProps {
  stats: StatsResponse
  /** Aggregate AI status derived from /threats — null while loading (chip hidden). */
  aiStatus?: AiStatus | null
}

export default function KpiCards({ stats, aiStatus = null }: KpiCardsProps) {
  const blocked = Math.round((stats.total_logs * stats.blocked_percentage) / 100)
  const blockRate = `${stats.blocked_percentage.toFixed(1)}%`

  return (
    <div
      data-testid="kpi-cards"
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(5, 1fr)',
        gap: 12,
        marginBottom: 20,
      }}
    >
      <StatCard
        value={stats.total_logs.toLocaleString()}
        label="Total events"
        icon="📊"
        accent="amber"
        data-testid="kpi-total-events"
      />
      <StatCard
        value={blocked.toLocaleString()}
        label="Blocked"
        icon="🛡️"
        accent="red"
        data-testid="kpi-blocked"
      />
      <StatCard
        value={stats.total_ips.toLocaleString()}
        label="Unique IPs"
        icon="🌐"
        accent="blue"
        data-testid="kpi-unique-ips"
      />
      <StatCard
        value={blockRate}
        label="Block rate"
        icon="✅"
        accent="green"
        data-testid="kpi-block-rate"
      />
      {/* AI status card — derived from /threats; non-fatal if unavailable */}
      <div
        style={{
          background: 'var(--fw-bg-card)',
          border: '1px solid var(--fw-border)',
          borderRadius: 'var(--fw-r-card)',
          padding: 16,
          position: 'relative',
          fontFamily: 'var(--fw-font-ui)',
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
        }}
        data-testid="kpi-ai-status"
      >
        <div
          aria-hidden="true"
          style={{
            position: 'absolute',
            top: 14,
            right: 14,
            fontSize: 16,
            opacity: 0.5,
          }}
        >
          🤖
        </div>
        <div style={{ marginTop: 4 }}>
          <AiStatusChip status={aiStatus} />
        </div>
        <div
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t3)',
            textTransform: 'uppercase',
            letterSpacing: 'var(--fw-ls-label)',
            marginTop: 2,
          }}
        >
          AI status
        </div>
      </div>
    </div>
  )
}
