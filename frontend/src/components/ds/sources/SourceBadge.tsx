/**
 * SourceBadge — compact origin tag keyed by source module id.
 *
 * Ported from legacy/FireWatch SOC Design System/components/sources/SourceBadge.jsx.
 * Runtime CSS injection replaced with inline styles over --fw-* tokens (F2 pattern).
 *
 * Hue mapping:
 *   azure_waf / waf  → WAF  (blue)
 *   suricata / ids   → IDS  (orange)
 *   syslog           → SYS  (green)
 *   file             → FILE (purple)
 *   unknown          → raw upper-cased id, neutral style
 *
 * EARS:
 *   - Ubiquitous: renders WAF/IDS/SYS/FILE in the source hue.
 *   - Ubiquitous: unknown source id → raw upper-cased id, neutral style (no crash, no UI edit).
 *
 * ADR-0024: new plugins get a chip automatically (neutral fallback); zero UI edit needed.
 * ADR-0019: React + TS. No per-source hardcoding beyond the canonical map.
 */

import type { HTMLAttributes } from 'react'

export interface SourceBadgeProps extends HTMLAttributes<HTMLSpanElement> {
  /**
   * Pipeline source module id — `azure_waf`/`waf`, `suricata`/`ids`,
   * `syslog`, or `file`. Unknown ids render raw upper-cased in neutral style.
   */
  source: string
}

/** Maps raw source module id → [short label, tone key]. */
const SOURCE_MAP: Record<string, [string, string]> = {
  azure_waf: ['WAF', 'waf'],
  waf: ['WAF', 'waf'],
  suricata: ['IDS', 'ids'],
  ids: ['IDS', 'ids'],
  syslog: ['SYS', 'syslog'],
  file: ['FILE', 'file'],
}

/** Returns inline style for a tone key (mirrors Badge.tsx toneStyle). */
function toneStyle(tone: string): React.CSSProperties {
  switch (tone) {
    case 'waf':
      return {
        background: 'var(--fw-tint-blue)',
        color: 'var(--fw-blue)',
        borderColor: 'var(--fw-tint-blue-bd)',
      }
    case 'ids':
      return {
        background: 'var(--fw-tint-orange)',
        color: 'var(--fw-orange)',
        borderColor: 'var(--fw-tint-orange-bd)',
      }
    case 'syslog':
      return {
        background: 'var(--fw-tint-green)',
        color: 'var(--fw-green)',
        borderColor: 'var(--fw-tint-green-bd)',
      }
    case 'file':
      return {
        background: 'rgba(168,85,247,0.094)',
        color: 'var(--fw-purple)',
        borderColor: 'rgba(168,85,247,0.188)',
      }
    default:
      // neutral — unknown source id
      return {
        background: 'var(--fw-bg-input)',
        color: 'var(--fw-t2)',
        borderColor: 'var(--fw-border)',
      }
  }
}

export function SourceBadge({ source, className = '', style, ...rest }: SourceBadgeProps) {
  const [label, tone] = SOURCE_MAP[source] ?? [String(source || '?').toUpperCase(), 'neutral']

  return (
    <span
      className={`fw-srcbadge fw-srcbadge--${tone} ${className}`}
      data-source={source}
      data-tone={tone}
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
        ...toneStyle(tone),
        ...style,
      }}
      {...rest}
    >
      {label}
    </span>
  )
}
