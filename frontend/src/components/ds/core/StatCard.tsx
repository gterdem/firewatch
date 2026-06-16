/**
 * StatCard — KPI tile (DS core, F2 #108).
 *
 * Ports legacy/FireWatch SOC Design System/components/core/StatCard.jsx.
 * Props exact match to StatCard.d.ts.
 *
 * Layout: big monospace value + uppercase label + faint emoji pinned top-right.
 * `accent` controls the value colour; maps to --fw-* hue tokens.
 */

import type { HTMLAttributes, ReactNode } from 'react'

export type StatCardAccent =
  | 'amber' | 'red' | 'blue' | 'green' | 'orange' | 'purple' | 'cyan' | 'default'

export interface StatCardProps extends HTMLAttributes<HTMLDivElement> {
  /** Big monospace figure (e.g. "8,412", "28%", "Online"). */
  value: ReactNode
  /** Uppercase caption below the value. */
  label: ReactNode
  /** Faint emoji pinned top-right (e.g. "📊", "🛡️", "🤖"). */
  icon?: ReactNode
  /** Value colour signalling meaning. */
  accent?: StatCardAccent
}

const ACCENT_COLOR: Record<StatCardAccent, string> = {
  amber:   'var(--fw-accent)',
  red:     'var(--fw-red)',
  blue:    'var(--fw-blue)',
  green:   'var(--fw-green)',
  orange:  'var(--fw-orange)',
  purple:  'var(--fw-purple)',
  cyan:    'var(--fw-cyan)',
  default: 'var(--fw-t1)',
}

export function StatCard({
  value,
  label,
  icon,
  accent = 'default',
  className = '',
  style,
  ...rest
}: StatCardProps) {
  const valueColor = ACCENT_COLOR[accent] ?? ACCENT_COLOR.default

  return (
    <div
      className={`fw-stat ${className}`}
      style={{
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border)',
        borderRadius: 'var(--fw-r-card)',
        padding: 16,
        position: 'relative',
        fontFamily: 'var(--fw-font-ui)',
        ...style,
      }}
      {...rest}
    >
      {icon ? (
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
          {icon}
        </div>
      ) : null}
      <div
        className="fw-stat__val"
        style={{
          fontSize: 'var(--fw-fs-display)',
          fontWeight: 'var(--fw-fw-bold)',
          fontFamily: 'var(--fw-font-mono)',
          lineHeight: 1,
          color: valueColor,
        }}
      >
        {value}
      </div>
      <div
        className="fw-stat__lbl"
        style={{
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          textTransform: 'uppercase',
          letterSpacing: 'var(--fw-ls-label)',
          marginTop: 4,
        }}
      >
        {label}
      </div>
    </div>
  )
}
