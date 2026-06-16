/**
 * Select — native dropdown styled to match inset fields (DS forms, F2 #108).
 *
 * Ports legacy/FireWatch SOC Design System/components/forms/Select.jsx.
 * Props exact match to Select.d.ts.
 *
 * `options` is an array of strings, or { value, label } pairs.
 * Pass `label` for a stacked field group; omit for a bare inline select.
 */

import type { SelectHTMLAttributes, ReactNode } from 'react'

export type SelectOption = string | { value: string; label: ReactNode }

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  /** Stacked field label; omit for a bare inline select. */
  label?: ReactNode
  /** Option list — plain strings or { value, label } pairs. */
  options: SelectOption[]
}

const BASE_SELECT_STYLE: React.CSSProperties = {
  width: '100%',
  padding: '8px 12px',
  background: 'var(--fw-bg-input)',
  border: '1px solid var(--fw-border-l)',
  borderRadius: 'var(--fw-r-sm)',
  color: 'var(--fw-t1)',
  fontSize: 'var(--fw-fs-body)',
  fontFamily: 'var(--fw-font-mono)',
  outline: 'none',
  cursor: 'pointer',
  transition: 'border-color var(--fw-dur-fast) var(--fw-ease)',
}

export function Select({ label, options = [], id, className = '', style, ...rest }: SelectProps) {
  const selectEl = (
    <select
      id={id}
      className={`fw-select ${className}`}
      style={{ ...BASE_SELECT_STYLE, ...style }}
      {...rest}
    >
      {options.map((o) => {
        const value = typeof o === 'object' ? o.value : o
        const text = typeof o === 'object' ? o.label : o
        return (
          <option key={value} value={value}>
            {text}
          </option>
        )
      })}
    </select>
  )

  if (!label) return selectEl

  return (
    <div style={{ marginBottom: 16 }}>
      <label
        htmlFor={id}
        style={{
          display: 'block',
          fontSize: 'var(--fw-fs-sm)',
          color: 'var(--fw-t2)',
          marginBottom: 4,
          fontWeight: 'var(--fw-fw-medium)',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        {label}
      </label>
      {selectEl}
    </div>
  )
}
