/**
 * Panel — bordered content container with titled header (DS core, F2 #108).
 *
 * Ports legacy/FireWatch SOC Design System/components/core/Panel.jsx.
 * Props exact match to Panel.d.ts.
 *
 * Recipe: 1px border, 10px radius, no shadow — flat SOC card.
 * Header: title (with optional leading icon) left, actions right.
 * Body: 14px/16px padding by default; `flush` removes padding (for tables).
 */

import type { HTMLAttributes, ReactNode } from 'react'

export interface PanelProps extends Omit<HTMLAttributes<HTMLDivElement>, 'title'> {
  /** Header title text. */
  title?: ReactNode
  /** Leading emoji before the title. */
  icon?: ReactNode
  /** Right-aligned header content (buttons, filters, legend). */
  actions?: ReactNode
  /** Remove body padding — use when the body is a full-bleed table. */
  flush?: boolean
  children?: ReactNode
}

export function Panel({
  title,
  icon,
  actions,
  flush = false,
  children,
  className = '',
  style,
  ...rest
}: PanelProps) {
  const hasHeader = title != null || actions != null

  return (
    <div
      className={`fw-panel ${className}`}
      style={{
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border)',
        borderRadius: 'var(--fw-r-card)',
        overflow: 'hidden',
        fontFamily: 'var(--fw-font-ui)',
        ...style,
      }}
      {...rest}
    >
      {hasHeader && (
        <div
          className="fw-panel__h"
          style={{
            padding: '12px 16px',
            borderBottom: '1px solid var(--fw-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
          }}
        >
          <h2
            style={{
              fontSize: 'var(--fw-fs-h3)',
              fontWeight: 'var(--fw-fw-semibold)',
              color: 'var(--fw-t1)',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              margin: 0,
            }}
          >
            {icon ? <span aria-hidden="true">{icon}</span> : null}
            {title}
          </h2>
          {actions ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              {actions}
            </div>
          ) : null}
        </div>
      )}
      <div
        className="fw-panel__b"
        style={flush ? {} : { padding: '14px 16px' }}
      >
        {children}
      </div>
    </div>
  )
}
