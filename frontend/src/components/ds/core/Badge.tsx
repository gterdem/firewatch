/**
 * Badge — tinted uppercase pill (DS core, F2 #108).
 *
 * Ports legacy/FireWatch SOC Design System/components/core/Badge.jsx exactly.
 * Replace the kit's ensureStyle() runtime-injection with Tailwind utility
 * classes over --fw-* tokens defined in index.css.
 *
 * Tones:
 *   severity ramp:  critical / high / medium / low
 *   traffic verdict: block / drop / allow / alert (IDS)
 *   ingest source:  waf / ids / syslog / file
 *   neutral:        neutral (counts, metadata)
 *
 * Special: `alert` (IDS ALERT) renders as a SOLID orange chip — the one
 * non-tinted badge, per ADR-0012 and the DS recipe.
 *
 * Unknown tones fall back to `neutral` rather than crashing (EARS).
 */

import type { HTMLAttributes, ReactNode } from 'react'

export type BadgeTone =
  | 'critical' | 'high' | 'medium' | 'low'
  | 'block' | 'allow' | 'alert' | 'drop'
  | 'waf' | 'ids' | 'syslog' | 'file'
  | 'neutral'

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  /**
   * Severity ramp (`low`→`critical`), traffic verdict (`block`/`allow`/`alert`/`drop`),
   * ingest source (`waf`/`ids`/`syslog`/`file`), or `neutral` for counts/metadata.
   * `alert` (IDS) renders as a solid orange chip.
   */
  tone?: BadgeTone
  children?: ReactNode
}

/**
 * Per-tone style objects — applied inline so Tailwind purge never strips them.
 * Tinted (~9% fill / ~19% border) for all tones except `alert` (solid orange).
 */
function toneStyle(tone: BadgeTone): React.CSSProperties {
  switch (tone) {
    case 'critical':
    case 'block':
    case 'drop':
      return {
        background: 'var(--fw-tint-red)',
        color: 'var(--fw-red)',
        borderColor: 'var(--fw-tint-red-bd)',
      }
    case 'high':
    case 'ids':
      return {
        background: 'var(--fw-tint-orange)',
        color: 'var(--fw-orange)',
        borderColor: 'var(--fw-tint-orange-bd)',
      }
    case 'medium':
    case 'waf':
      return {
        background: 'var(--fw-tint-blue)',
        color: 'var(--fw-blue)',
        borderColor: 'var(--fw-tint-blue-bd)',
      }
    case 'low':
    case 'allow':
    case 'syslog':
      return {
        background: 'var(--fw-tint-green)',
        color: 'var(--fw-green)',
        borderColor: 'var(--fw-tint-green-bd)',
      }
    // SOLID orange — the one non-tinted badge (ADR-0012 / DS recipe .fw-badge--alert)
    // Text color: --fw-on-accent (#000 dark theme, #fff light theme) — same high-contrast pairing.
    case 'alert':
      return {
        background: 'var(--fw-orange)',
        color: 'var(--fw-on-accent)',
        borderColor: 'var(--fw-orange)',
      }
    case 'file':
      return {
        background: 'var(--fw-tint-purple)',
        color: 'var(--fw-purple)',
        borderColor: 'var(--fw-tint-purple-bd)',
      }
    case 'neutral':
    default:
      return {
        background: 'var(--fw-bg-input)',
        color: 'var(--fw-t2)',
        borderColor: 'var(--fw-border)',
      }
  }
}

export function Badge({
  tone = 'neutral',
  children,
  className = '',
  style,
  ...rest
}: BadgeProps) {
  // Unknown tones fall back to neutral (EARS: must not crash)
  const resolvedTone: BadgeTone =
    tone in { critical: 1, high: 1, medium: 1, low: 1, block: 1, allow: 1, alert: 1, drop: 1, waf: 1, ids: 1, syslog: 1, file: 1, neutral: 1 }
      ? tone
      : 'neutral'

  return (
    <span
      className={`fw-badge ${className}`}
      data-tone={resolvedTone}
      style={{
        display: 'inline-block',
        padding: '1px 8px',
        borderRadius: 'var(--fw-r-md)',
        fontSize: 'var(--fw-fs-2xs)',
        fontWeight: 'var(--fw-fw-bold)',
        fontFamily: 'var(--fw-font-ui)',
        textTransform: 'uppercase',
        letterSpacing: 'var(--fw-ls-tight)',
        border: '1px solid transparent',
        lineHeight: 1.6,
        ...toneStyle(resolvedTone),
        ...style,
      }}
      {...rest}
    >
      {children}
    </span>
  )
}
