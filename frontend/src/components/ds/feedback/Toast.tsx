/**
 * Toast — transient notification chip with a coloured left stripe (DS feedback, F2 #108).
 *
 * Ports legacy/FireWatch SOC Design System/components/feedback/Toast.jsx.
 * Props exact match to Toast.d.ts.
 *
 * Presentational only — drive show/hide and the top-right slide-in from the
 * parent. The console anchors it at top:60px / right:24px.
 *
 * Tones: ok (green stripe), err (red stripe), info (blue stripe).
 * Default icons: ✅ / ⚠️ / ℹ️ — overrideable via `icon` prop.
 */

import type { HTMLAttributes, ReactNode } from 'react'

export type ToastTone = 'ok' | 'err' | 'info'

export interface ToastProps extends HTMLAttributes<HTMLDivElement> {
  /** Coloured left stripe + default icon. */
  tone?: ToastTone
  /** Override the default emoji icon for the tone. */
  icon?: ReactNode
  children?: ReactNode
}

const DEFAULT_ICON: Record<ToastTone, string> = {
  ok:   '✅',
  err:  '⚠️',
  info: 'ℹ️',
}

const STRIPE_COLOR: Record<ToastTone, string> = {
  ok:   'var(--fw-green)',
  err:  'var(--fw-red)',
  info: 'var(--fw-blue)',
}

export function Toast({
  tone = 'info',
  icon,
  children,
  className = '',
  style,
  ...rest
}: ToastProps) {
  const resolvedTone: ToastTone = tone in DEFAULT_ICON ? tone : 'info'
  const stripeColor = STRIPE_COLOR[resolvedTone]
  const displayIcon = icon ?? DEFAULT_ICON[resolvedTone]

  return (
    <div
      role="status"
      className={`fw-toast fw-toast--${resolvedTone} ${className}`}
      style={{
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border-l)',
        borderLeft: `3px solid ${stripeColor}`,
        borderRadius: 'var(--fw-r-md)',
        padding: '10px 16px',
        fontSize: 'var(--fw-fs-sm)',
        display: 'inline-flex',
        alignItems: 'center',
        gap: 8,
        boxShadow: 'var(--fw-shadow-toast)',
        fontFamily: 'var(--fw-font-ui)',
        color: 'var(--fw-t1)',
        ...style,
      }}
      {...rest}
    >
      <span aria-hidden="true" style={{ fontSize: 14 }}>
        {displayIcon}
      </span>
      {children}
    </div>
  )
}
