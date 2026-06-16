/**
 * Button — FireWatch primary action control (DS core, F2 #108).
 *
 * Ports legacy/FireWatch SOC Design System/components/core/Button.jsx.
 * Props exact match to Button.d.ts.
 *
 * Variants:
 *   primary   — amber CTA (signature action: "Sync now", "Generate summary")
 *   danger    — red destructive operation
 *   deep      — purple AI deep-analysis
 *   secondary — low-emphasis border button
 *   ghost     — same as secondary (DS treats them identically)
 *
 * Sizes: md (default), sm (inline/toolbar).
 * `icon` — optional leading element (emoji or ReactNode).
 */

import type { ButtonHTMLAttributes, ReactNode } from 'react'
import React from 'react'

export type ButtonVariant = 'primary' | 'danger' | 'deep' | 'secondary' | 'ghost'
export type ButtonSize = 'md' | 'sm'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  /** Optional leading icon (emoji or node). */
  icon?: ReactNode
  children?: ReactNode
}

function variantStyle(variant: ButtonVariant): React.CSSProperties {
  switch (variant) {
    case 'primary':
      return { background: 'var(--fw-accent)', color: 'var(--fw-on-accent)' }
    case 'danger':
      return { background: 'var(--fw-red)', color: 'var(--fw-on-dark)' }
    case 'deep':
      return { background: 'var(--fw-purple)', color: 'var(--fw-on-dark)' }
    case 'secondary':
    case 'ghost':
      return {
        background: 'var(--fw-bg-input)',
        color: 'var(--fw-t2)',
        border: '1px solid var(--fw-border-l)',
      }
    default:
      return { background: 'var(--fw-accent)', color: 'var(--fw-on-accent)' }
  }
}

function sizeStyle(size: ButtonSize): React.CSSProperties {
  return size === 'sm'
    ? { padding: '4px 10px', fontSize: 'var(--fw-fs-xs)', fontWeight: 'var(--fw-fw-medium)' }
    : { padding: '8px 18px', fontSize: 'var(--fw-fs-body)' }
}

export function Button({
  variant = 'primary',
  size = 'md',
  icon,
  children,
  className = '',
  style,
  ...rest
}: ButtonProps) {
  return (
    <button
      className={`fw-btn ${className}`}
      data-variant={variant}
      data-size={size}
      style={{
        fontFamily: 'var(--fw-font-ui)',
        border: 'none',
        borderRadius: 'var(--fw-r-sm)',
        fontWeight: 'var(--fw-fw-semibold)',
        cursor: 'pointer',
        transition: 'all var(--fw-dur-fast) var(--fw-ease)',
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        lineHeight: 1,
        whiteSpace: 'nowrap',
        ...variantStyle(variant),
        ...sizeStyle(size),
        ...style,
      }}
      {...rest}
    >
      {icon ? <span aria-hidden="true">{icon}</span> : null}
      {children}
    </button>
  )
}
