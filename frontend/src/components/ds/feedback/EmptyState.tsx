/**
 * EmptyState — dashed-border zero state (DS feedback, F2 #108).
 *
 * Ports legacy/FireWatch SOC Design System/components/feedback/EmptyState.jsx.
 * Props exact match to EmptyState.d.ts.
 *
 * Replaces the previous #98 EmptyState (which had headline/subLine/icon props).
 * The DS recipe uses: icon (large emoji), title (h3), children (body copy), action (CTA).
 *
 * Call-site migration: #98 EmptyState props → DS EmptyState:
 *   headline → title
 *   subLine  → children
 *   icon     → icon
 *   (no action in old usages)
 *
 * The states/EmptyState.tsx wrapper re-exports the DS component with an adapter
 * so existing call sites keep working without change.
 */

import type { HTMLAttributes, ReactNode } from 'react'

export interface EmptyStateProps extends Omit<HTMLAttributes<HTMLDivElement>, 'title'> {
  /** Optional large emoji displayed above the title. */
  icon?: ReactNode
  /** Headline (h3). */
  title?: ReactNode
  /** Body copy (children). */
  children?: ReactNode
  /** Call-to-action element (usually a primary Button). */
  action?: ReactNode
}

export function EmptyState({
  icon,
  title,
  children,
  action,
  className = '',
  style,
  ...rest
}: EmptyStateProps) {
  return (
    <div
      className={`fw-empty ${className}`}
      data-testid="empty-state"
      role="status"
      style={{
        padding: '50px 30px',
        textAlign: 'center',
        color: 'var(--fw-t2)',
        background: 'var(--fw-bg-card)',
        borderRadius: 'var(--fw-r-card)',
        border: '1px dashed var(--fw-border)',
        margin: '20px 0',
        fontFamily: 'var(--fw-font-ui)',
        ...style,
      }}
      {...rest}
    >
      {icon ? (
        <div
          data-testid="empty-state-icon"
          aria-hidden="true"
          style={{ fontSize: 34, opacity: 0.6, marginBottom: 10 }}
        >
          {icon}
        </div>
      ) : null}
      {title ? (
        <h3
          data-testid="empty-state-headline"
          style={{
            fontSize: 18,
            fontWeight: 'var(--fw-fw-semibold)',
            marginBottom: 8,
            color: 'var(--fw-t1)',
          }}
        >
          {title}
        </h3>
      ) : null}
      {children ? (
        <p
          data-testid="empty-state-subline"
          style={{
            fontSize: 'var(--fw-fs-body)',
            color: 'var(--fw-t3)',
            marginBottom: 16,
            maxWidth: 420,
            marginLeft: 'auto',
            marginRight: 'auto',
          }}
        >
          {children}
        </p>
      ) : null}
      {action}
    </div>
  )
}
