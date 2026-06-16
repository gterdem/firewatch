/**
 * Input — monospace text/number field (DS forms, F2 #108).
 *
 * Ports legacy/FireWatch SOC Design System/components/forms/Input.jsx.
 * Props exact match to Input.d.ts.
 *
 * Monospace font on the inset well; border turns amber (--fw-accent) on focus.
 * Pass `label` for a stacked field group; omit for a bare inline input.
 * `size="sm"` for toolbar/search inputs.
 */

import type { InputHTMLAttributes, ReactNode } from 'react'

export interface InputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'size'> {
  /** Stacked field label; omit for a bare inline input. */
  label?: ReactNode
  /** `md` standalone, `sm` for toolbar/search inputs. */
  size?: 'md' | 'sm'
}

const BASE_INPUT_STYLE: React.CSSProperties = {
  width: '100%',
  background: 'var(--fw-bg-input)',
  border: '1px solid var(--fw-border-l)',
  borderRadius: 'var(--fw-r-sm)',
  color: 'var(--fw-t1)',
  fontFamily: 'var(--fw-font-mono)',
  outline: 'none',
  transition: 'border-color var(--fw-dur-fast) var(--fw-ease)',
}

export function Input({ label, size = 'md', id, className = '', style, ...rest }: InputProps) {
  const paddingStyle: React.CSSProperties =
    size === 'sm'
      ? { padding: '5px 10px', fontSize: 'var(--fw-fs-sm)' }
      : { padding: '8px 12px', fontSize: 'var(--fw-fs-body)' }

  const inputEl = (
    <input
      id={id}
      className={`fw-input ${className}`}
      style={{ ...BASE_INPUT_STYLE, ...paddingStyle, ...style }}
      {...rest}
    />
  )

  if (!label) return inputEl

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
      {inputEl}
    </div>
  )
}
