/**
 * LiveBadge — pulsing green capsule for auto-refresh signal (DS feedback, F2 #108).
 *
 * Ports legacy/FireWatch SOC Design System/components/feedback/LiveBadge.jsx.
 * Props exact match to LiveBadge.d.ts.
 *
 * live=true  (default): green tinted capsule with pulsing dot (fw-pulse keyframe).
 * live=false:           static grey "paused" state.
 *
 * Animation: fw-pulse keyframe defined in index.css.
 */

import type { HTMLAttributes, ReactNode } from 'react'

export interface LiveBadgeProps extends HTMLAttributes<HTMLSpanElement> {
  /** `true` (default) = pulsing green "live"; `false` = static grey "paused". */
  live?: boolean
  /** Label text (default "Live"). */
  children?: ReactNode
}

export function LiveBadge({
  live = true,
  children = 'Live',
  className = '',
  style,
  ...rest
}: LiveBadgeProps) {
  return (
    <span
      className={`fw-live ${live ? '' : 'fw-live--idle'} ${className}`}
      data-live={live}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 5,
        background: live ? 'var(--fw-tint-green)' : 'var(--fw-bg-input)',
        border: `1px solid ${live ? 'var(--fw-tint-green-bd)' : 'var(--fw-border)'}`,
        padding: '3px 10px',
        borderRadius: 'var(--fw-r-pill)',
        fontSize: 'var(--fw-fs-xs)',
        color: live ? 'var(--fw-green)' : 'var(--fw-t3)',
        fontWeight: 'var(--fw-fw-semibold)',
        textTransform: 'uppercase',
        letterSpacing: 'var(--fw-ls-table)',
        fontFamily: 'var(--fw-font-ui)',
        ...style,
      }}
      {...rest}
    >
      <span
        className="fw-live__dot"
        aria-hidden="true"
        style={{
          width: 7,
          height: 7,
          background: live ? 'var(--fw-green)' : 'var(--fw-t3)',
          borderRadius: '50%',
          animation: live ? 'fw-pulse var(--fw-dur-pulse) infinite' : 'none',
        }}
      />
      {children}
    </span>
  )
}
