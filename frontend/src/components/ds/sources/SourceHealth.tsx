/**
 * SourceHealth — header strip of per-source-TYPE liveness dots (issue #281).
 *
 * ADR-0032 (issue #134): dot color driven by the server-computed `health` field
 * (Decision C).  The front-end renders it; it does NOT re-derive policy from
 * recency.  OD-2 recency math has been removed — it moved server-side.
 *
 * Issue #281 changes:
 *   - One dot per SOURCE TYPE (not per instance). When a type has N instances
 *     the dot color = worst-of-instances (red > amber > not_configured > ok).
 *   - title= tooltips removed (WCAG 1.4.13 fail). Each dot is now wrapped in a
 *     HealthDot that uses CellTooltip (#246): hoverable, dismissible, persistent,
 *     keyboard-accessible.
 *
 * 4-color mapping (server health → DS token):
 *   "ok"             → --fw-health-ok   (green)
 *   "amber"          → --fw-health-warn (amber)
 *   "red"            → --fw-health-down (red)
 *   "not_configured" → --fw-health-idle (grey)
 *
 * Props accept SourceHealthItem[] from src/lib/sourceHealth.ts (the ADR-0032 adapter).
 * ADR-0019: React + TS. No per-source hardcoding.
 * Issue #335: forwards `pulsingSources` set to HealthDot for post-sync pulse animation.
 */

import type { HTMLAttributes } from 'react'
import type { SourceHealthItem } from '../../../lib/sourceHealth'
import { groupBySourceType } from '../../../lib/sourceHealth'
import { HealthDot } from './HealthDot'

export type { SourceHealthItem }

export interface SourceHealthProps extends HTMLAttributes<HTMLDivElement> {
  sources: SourceHealthItem[]
  /**
   * Build a Settings deep-link href for a given source_type.
   * Forwarded to HealthDot → HealthCard so the "Configure →" link resolves
   * to the correct Settings card.
   * Defaults to "#/settings?source=<type>" when not provided.
   */
  buildSettingsHref?: (sourceType: string) => string
  /**
   * Set of source_type keys currently pulsing after a sync (issue #335).
   * HealthDot adds a brief fw-pulse animation when its sourceType is in this set.
   * Color stays unchanged — animation only (ADR-0032 Decision C).
   */
  pulsingSources?: ReadonlySet<string>
  /**
   * Freshness window in minutes from GET /stats `freshness_minutes` (R1).
   * Forwarded to HealthDot → HealthCard for the operational legend.
   * Defaults to 5 when absent.
   */
  freshnessMinutes?: number
}

export function SourceHealth({
  sources = [],
  buildSettingsHref,
  pulsingSources,
  freshnessMinutes = 5,
  className = '',
  style,
  ...rest
}: SourceHealthProps) {
  const groups = groupBySourceType(sources)

  return (
    <div
      className={`fw-health ${className}`}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '0 8px',
        fontFamily: 'var(--fw-font-ui)',
        ...style,
      }}
      {...rest}
    >
      {groups.map((group) => (
        <HealthDot
          key={group.sourceType}
          group={group}
          buildSettingsHref={buildSettingsHref}
          pulsing={pulsingSources?.has(group.sourceType) ?? false}
          freshnessMinutes={freshnessMinutes}
        />
      ))}
    </div>
  )
}
