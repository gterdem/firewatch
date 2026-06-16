/**
 * FilterChip — removable chip summarising an active filter ("Source: IDS").
 *
 * Ported from legacy/FireWatch SOC Design System/components/filters/FilterChip.jsx.
 * Runtime CSS injection replaced with inline styles over --fw-* tokens (F2 pattern).
 *
 * EARS:
 *   - WHEN FilterChip ✕ is clicked, onRemove fires (parent drops that facet).
 *
 * Render a row of these under the filter bar.
 * ADR-0019: React + TS. No per-source hardcoding.
 */

import type { HTMLAttributes, MouseEvent, ReactNode } from 'react'

export interface FilterChipProps extends HTMLAttributes<HTMLSpanElement> {
  /** Chip label, e.g. "Source: IDS". */
  children?: ReactNode
  /** Click handler for the ✕ remove affordance. */
  onRemove?: (e: MouseEvent) => void
}

export function FilterChip({ children, onRemove, className = '', style, ...rest }: FilterChipProps) {
  return (
    <span
      className={`fw-chip ${className}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        padding: '2px 8px',
        background: 'var(--fw-bg-input)',
        border: '1px solid var(--fw-border)',
        borderRadius: 12,
        fontSize: 'var(--fw-fs-xs)',
        color: 'var(--fw-t2)',
        fontFamily: 'var(--fw-font-ui)',
        ...style,
      }}
      {...rest}
    >
      {children}
      {onRemove ? (
        <span
          role="button"
          aria-label="Remove filter"
          onClick={onRemove}
          style={{
            cursor: 'pointer',
            color: 'var(--fw-t3)',
            fontWeight: 'bold',
            marginLeft: 2,
            lineHeight: 1,
          }}
        >
          ✕
        </span>
      ) : null}
    </span>
  )
}
