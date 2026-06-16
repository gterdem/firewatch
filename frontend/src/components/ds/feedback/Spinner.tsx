/**
 * Spinner — amber-topped rotating ring (DS feedback, F2 #108).
 *
 * Ports legacy/FireWatch SOC Design System/components/feedback/Spinner.jsx.
 * Props exact match to Spinner.d.ts.
 *
 * Bare (no label): renders an inline ring — use inside other components.
 * With label: renders a centered "loading" block used inside empty panels/tables.
 *
 * Animation: fw-spin keyframe defined in index.css.
 */

import type { HTMLAttributes, ReactNode } from 'react'

export interface SpinnerProps extends HTMLAttributes<HTMLElement> {
  /**
   * When set, renders a centered loading block with this caption beside the spinner.
   * Omit for a bare inline ring.
   */
  label?: ReactNode
}

export function Spinner({ label, className = '', style, ...rest }: SpinnerProps) {
  const ring = (
    <span
      className="fw-spinner"
      aria-hidden="true"
      style={{
        display: 'inline-block',
        width: 14,
        height: 14,
        border: '2px solid var(--fw-border-l)',
        borderTopColor: 'var(--fw-accent)',
        borderRadius: '50%',
        animation: 'fw-spin var(--fw-dur-spin) linear infinite',
        verticalAlign: 'middle',
      }}
    />
  )

  if (label == null) {
    return (
      <span
        className={`fw-spinner ${className}`}
        style={{
          display: 'inline-block',
          width: 14,
          height: 14,
          border: '2px solid var(--fw-border-l)',
          borderTopColor: 'var(--fw-accent)',
          borderRadius: '50%',
          animation: 'fw-spin var(--fw-dur-spin) linear infinite',
          verticalAlign: 'middle',
          ...style,
        }}
        {...(rest as HTMLAttributes<HTMLSpanElement>)}
      />
    )
  }

  return (
    <div
      className={`fw-loading ${className}`}
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        textAlign: 'center',
        padding: 30,
        color: 'var(--fw-t3)',
        fontSize: 'var(--fw-fs-body)',
        fontFamily: 'var(--fw-font-ui)',
        ...style,
      }}
      {...(rest as HTMLAttributes<HTMLDivElement>)}
    >
      {ring}
      {label}
    </div>
  )
}
