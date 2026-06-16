/**
 * sourceHealth adapter — ADR-0032 binding (supersedes OD-2, issue #134).
 *
 * Maps GET /stats source_health[] (ADR-0032 §B shape) to the SourceHealthItem[]
 * consumed by the SourceHealth DS component.
 *
 * ADR-0032 Decision C: the dot color is driven by the server-computed `health`
 * field.  The front-end RENDERS it; it does NOT re-derive recency policy.
 * The OD-2 recency-only math is removed — that logic moved server-side.
 *
 * 4-color mapping (server `health` → DotState):
 *   "not_configured" → "idle"  (grey)
 *   "amber"          → "warn"  (amber)
 *   "ok"             → "ok"    (green)
 *   "red"            → "down"  (red)
 *   unknown          → "idle"  (safe fallback)
 *
 * This module is the single seam for the binding — swap it here if the backend
 * contract evolves without touching SourceHealth.tsx or AppHeader.tsx.
 *
 * Issue #281: adds worstOfHealth() + groupBySourceType() for the aggregated
 * per-type dot (worst-of-instances) with instance breakdown in the health card.
 */

import type { SourceHealth as ApiSourceHealth } from '../api/types'

/**
 * 4-state dot driven by server `health` (ADR-0032 Decision C).
 * "idle" maps to grey, "warn" to amber, "ok" to green, "down" to red.
 */
export type DotState = 'ok' | 'warn' | 'down' | 'idle'

/** Shape consumed by the SourceHealth component. */
export interface SourceHealthItem {
  /** Source id used as the unique key. */
  id: string
  /** Human-readable label shown next to the dot (display_name from plugin metadata). */
  label: string
  /**
   * Server-computed 4-state health value from ADR-0032 §B.
   * Drives dot color — the front-end does NOT re-derive from last_event_at.
   */
  health: string
  /**
   * Supervisor state — goes in tooltip for diagnostic context.
   * null when no supervisor data is available.
   */
  supervisorState: string | null
  /**
   * ISO8601 timestamp of most recent event — tooltip only.
   * null when no data.
   */
  lastEventAt: string | null
  /**
   * Sanitized last_error string (secrets stripped server-side) — tooltip only.
   * null when no error.
   */
  lastError: string | null
  /**
   * Total events for this instance (from the store — ADR-0032 §B event_count).
   * 0 when no data.
   */
  eventCount: number
  /**
   * Source type key — used to group instances of the same plugin type.
   * Matches source_type from the ADR-0032 §B wire shape.
   */
  sourceType: string
  /**
   * ISO8601 timestamp of last completed pull cycle (ADR-0032 Amendment 1 R2).
   * null for push sources or before first sync cycle completes.
   * Optional for backward compatibility with existing SourceHealthItem literals.
   */
  lastSyncAt?: string | null
  /**
   * Outcome of last completed pull cycle: "ok" | "no_data" | "error" | null.
   * null means no sync has completed yet (push source or pre-first-cycle).
   * Used to split amber into verified-quiet / never-connected / stale sub-states.
   * ADR-0032 Amendment 1 R2.
   * Optional for backward compatibility with existing SourceHealthItem literals.
   */
  lastSyncStatus?: 'ok' | 'no_data' | 'error' | null
  /**
   * Events ingested on last completed pull cycle (ADR-0032 Amendment 1 R2).
   * 0 when no cycle has run.
   * Optional for backward compatibility with existing SourceHealthItem literals.
   */
  lastSyncIngested?: number
}

/**
 * A group of instances sharing the same source type — used by HealthDot
 * to render one dot per type with worst-of aggregation (issue #281).
 */
export interface SourceTypeGroup {
  /** source_type key (the group identity). */
  sourceType: string
  /** Human-readable type name (display_name of the first/representative instance). */
  typeLabel: string
  /** The worst health across all instances (ADR-0032 severity order). */
  worstHealth: string
  /** All instances belonging to this type. */
  instances: SourceHealthItem[]
}

/**
 * Map server `health` string → DotState.
 *
 * ADR-0032 Decision C — 4-color:
 *   "not_configured" → idle  (grey — installed, not configured)
 *   "amber"          → warn  (amber — configured, silent/stale)
 *   "ok"             → ok    (green — recent events)
 *   "red"            → down  (red — supervisor error/parked)
 */
export function dotStateFromHealth(health: string): DotState {
  switch (health) {
    case 'ok':
      return 'ok'
    case 'amber':
      return 'warn'
    case 'red':
      return 'down'
    case 'not_configured':
    default:
      return 'idle'
  }
}

/**
 * Severity rank for worst-of aggregation (issue #281).
 *
 * Higher rank = worse health. Used to pick the worst health across a
 * type's instances for the aggregated dot color.
 *
 * Order (worst → best): red(3) > amber(2) > not_configured(1) > ok(0)
 *
 * Rationale: `not_configured` is shown above `ok` so a type where some
 * instances are healthy but others are unconfigured surfaces the unconfigured
 * state in the header dot (discoverability intent of ADR-0032 Decision A).
 */
const HEALTH_RANK: Record<string, number> = {
  red: 3,
  amber: 2,
  not_configured: 1,
  ok: 0,
}

/**
 * Return the worse of two health strings using the ADR-0032 severity order.
 * Unknown values fall back to rank 0 (treated as ok for aggregation).
 */
function worseHealth(a: string, b: string): string {
  const rankA = HEALTH_RANK[a] ?? 0
  const rankB = HEALTH_RANK[b] ?? 0
  return rankA >= rankB ? a : b
}

/**
 * Return the worst health across an array of health strings.
 * Returns "not_configured" for an empty array (safe fallback).
 *
 * Aggregation is display-only — server-computed per-instance `health` values
 * are not re-derived; only folded into a single worst-of value (ADR-0032 §C).
 */
export function worstOfHealth(healthValues: string[]): string {
  if (healthValues.length === 0) return 'not_configured'
  return healthValues.reduce(worseHealth)
}

/**
 * Group SourceHealthItem[] by source_type into SourceTypeGroup[].
 *
 * Each group exposes the worst-of health across its instances so the header
 * can render one dot per type (issue #281 spec: "one dot per source TYPE").
 *
 * Preserves insertion order of first occurrence for stable header ordering.
 */
export function groupBySourceType(items: SourceHealthItem[]): SourceTypeGroup[] {
  const map = new Map<string, SourceTypeGroup>()

  for (const item of items) {
    const existing = map.get(item.sourceType)
    if (existing) {
      existing.instances.push(item)
      existing.worstHealth = worseHealth(existing.worstHealth, item.health)
    } else {
      map.set(item.sourceType, {
        sourceType: item.sourceType,
        typeLabel: item.label,
        worstHealth: item.health,
        instances: [item],
      })
    }
  }

  return Array.from(map.values())
}

/**
 * Build a human-readable tooltip for a SourceHealthItem.
 *
 * Shows the health status label; if supervisor_state or last_error are
 * present they are appended for diagnostic context.
 * last_event_at is included when available.
 *
 * SECURITY: last_error is sanitized server-side before reaching the front-end
 * (health_assembler strips IPs and credential patterns — ADR-0029 D3).
 * Rendered as tooltip text — never as HTML.
 */
export function buildTooltip(item: SourceHealthItem): string {
  const { id, health, supervisorState, lastEventAt, lastError } = item
  const label = item.label || id

  // Recency suffix for tooltip (display only — not used to compute dot color).
  let recencyPart = ''
  if (lastEventAt) {
    const secondsAgo = Math.max(
      0,
      Math.floor((Date.now() - new Date(lastEventAt).getTime()) / 1000),
    )
    recencyPart =
      secondsAgo < 60
        ? ' (<1m ago)'
        : ` (${Math.round(secondsAgo / 60)}m ago)`
  }

  const healthLabel: Record<string, string> = {
    ok: 'healthy',
    amber: 'no recent events',
    red: 'error',
    not_configured: 'not configured',
  }
  const statusText = healthLabel[health] ?? health

  let tip = `${label}: ${statusText}${recencyPart}`

  if (supervisorState && supervisorState !== 'running' && supervisorState !== 'idle') {
    tip += ` (supervisor: ${supervisorState})`
  }
  if (lastError) {
    tip += ` — ${lastError}`
  }
  return tip
}

/**
 * Convert GET /stats source_health[] → SourceHealthItem[].
 *
 * ADR-0032 Decision A: list membership = installed plugins (every entry in
 * source_health[] is an installed plugin, including unconfigured ones).
 * ADR-0032 Decision C: dot color driven by server `health` field.
 * ADR-0032 Amendment 1 R2: maps three additive sync-evidence fields.
 */
export function toSourceHealthItems(
  statsHealth: ApiSourceHealth[],
): SourceHealthItem[] {
  return statsHealth.map((sh) => ({
    id: sh.source_id,
    label: sh.display_name,
    health: sh.health,
    supervisorState: sh.supervisor_state ?? null,
    lastEventAt: sh.last_event_at ?? null,
    lastError: sh.last_error ?? null,
    eventCount: sh.event_count,
    sourceType: sh.source_type,
    // R2 additive sync-evidence fields (ADR-0032 Amendment 1 R2)
    lastSyncAt: sh.last_sync_at ?? null,
    lastSyncStatus: sh.last_sync_status ?? null,
    lastSyncIngested: sh.last_sync_ingested ?? 0,
  }))
}
