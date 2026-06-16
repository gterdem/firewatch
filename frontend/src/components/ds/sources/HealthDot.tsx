/**
 * HealthDot — per-source-type aggregated health dot with CellTooltip popover (issue #281).
 *
 * Renders ONE dot whose color = worst-of-instances for the given SourceTypeGroup.
 * The dot is wrapped in a CellTooltip so hover/keyboard-focus opens the HealthCard
 * mini health-card popover (WCAG 2.2 SC 1.4.13 compliant — hoverable, dismissible,
 * persistent; keyboard path via tabIndex=0 on the CellTooltip trigger).
 *
 * Responsibility split (per issue #281 module sketch):
 *   HealthDot  — worst-of fold + dot render + CellTooltip wiring
 *   HealthCard — popover content rows (display name, fields, instance breakdown)
 *
 * Issue #335: adds `pulsing` prop for the post-sync pulse animation.
 *   When `pulsing=true`, the dot plays the `fw-pulse` CSS animation briefly.
 *   Color does NOT change on pulse — it stays truthful to the server health value
 *   (ADR-0032 Decision C: dot color is server-driven, never re-derived client-side).
 *   The parent (SourceFilterBar / useHeaderRefresh) clears pulsing after PULSE_CLEAR_MS.
 *
 * ADR-0032 Erratum: health vocabulary is ok|amber|red|not_configured — no color words.
 * ADR-0029 D3: all text rendered as text nodes (HealthCard enforces this).
 * ADR-0028 D6: DS tokens only — no raw hex.
 */

import type { SourceTypeGroup } from '../../../lib/sourceHealth'
import { dotStateFromHealth } from '../../../lib/sourceHealth'
import { CellTooltip } from '../core/CellTooltip'
import { HealthCard } from './HealthCard'

// ---------------------------------------------------------------------------
// Token map
// ---------------------------------------------------------------------------

/** DotState → CSS custom-property token (mirrors SourceHealth.tsx mapping). */
const DOT_COLOR: Record<string, string> = {
  ok: 'var(--fw-health-ok)',
  warn: 'var(--fw-health-warn)',
  down: 'var(--fw-health-down)',
  idle: 'var(--fw-health-idle)',
}

// ---------------------------------------------------------------------------
// HealthDot
// ---------------------------------------------------------------------------

export interface HealthDotProps {
  /** The type group: supplies worst-of health + all instances for the card. */
  group: SourceTypeGroup
  /**
   * Build the Settings deep-link href for a given source_type.
   * Forwarded to HealthCard unchanged.
   */
  buildSettingsHref?: (sourceType: string) => string
  /**
   * When true, the dot plays the `fw-pulse` CSS animation (issue #335 post-sync pulse).
   * The COLOR is unchanged — pulse is animation only, not a health-state change.
   * Default: false.
   */
  pulsing?: boolean
  /**
   * Freshness window in minutes from GET /stats `freshness_minutes` (R1).
   * Forwarded to HealthCard for the operational legend green/amber boundary.
   * Defaults to 5 when absent.
   */
  freshnessMinutes?: number
}

/**
 * HealthDot renders the colored liveness dot for one source TYPE and wraps it
 * in a CellTooltip that shows a HealthCard on hover/focus.
 *
 * Color = worst-of-instances (pre-computed by groupBySourceType() into
 * group.worstHealth). The front-end only RENDERS the server-computed values —
 * it does not re-derive health (ADR-0032 Decision C).
 */
export function HealthDot({
  group,
  buildSettingsHref,
  pulsing = false,
  freshnessMinutes = 5,
}: HealthDotProps) {
  const state = dotStateFromHealth(group.worstHealth)
  const color = DOT_COLOR[state] ?? 'var(--fw-health-idle)'
  const opacity = state === 'idle' ? 0.5 : 1

  const cardContent = (
    <HealthCard
      group={group}
      buildSettingsHref={buildSettingsHref}
      freshnessMinutes={freshnessMinutes}
    />
  )

  return (
    <CellTooltip
      content={cardContent}
      data-testid={`health-dot-trigger-${group.sourceType}`}
    >
      <div
        data-testid={`health-item-${group.sourceType}`}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 3,
          whiteSpace: 'nowrap',
        }}
      >
        <span
          data-testid={`health-dot-${group.sourceType}`}
          data-state={state}
          data-pulsing={pulsing ? 'true' : undefined}
          aria-label={`${group.typeLabel} health: ${group.worstHealth}`}
          style={{
            display: 'inline-block',
            width: 8,
            height: 8,
            borderRadius: '50%',
            background: color,
            opacity,
            // Post-sync pulse: uses the existing fw-pulse keyframe (index.css).
            // Color stays unchanged — animation only (issue #335 spec).
            animation: pulsing ? 'fw-pulse var(--fw-dur-pulse) infinite' : 'none',
          }}
        />
        <span
          data-testid={`health-label-${group.sourceType}`}
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t3)',
            fontFamily: 'var(--fw-font-ui)',
          }}
        >
          {group.typeLabel}
        </span>
      </div>
    </CellTooltip>
  )
}
