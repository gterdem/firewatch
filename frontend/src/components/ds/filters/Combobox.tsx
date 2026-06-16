/**
 * Combobox — type-to-filter dropdown with a clear (✕) affordance.
 *
 * Ported from legacy/FireWatch SOC Design System/components/filters/Combobox.jsx.
 * Runtime CSS injection replaced with inline styles over --fw-* tokens (F2 pattern).
 *
 * EARS:
 *   - WHEN text is typed, options filter live (case-insensitive substring).
 *   - WHEN an option is picked, onChange(value, label) fires and the dropdown closes.
 *   - WHEN ✕ is clicked, value clears: onChange("", "") fires.
 *
 * Used for the header source-filter picker and the Logs filter bar.
 * ADR-0019: React + TS. No per-source hardcoding.
 */

import { useState, useRef, useEffect, type HTMLAttributes, type ReactNode } from 'react'

export interface ComboOption {
  value: string
  label: ReactNode
}

export interface ComboboxProps extends Omit<HTMLAttributes<HTMLDivElement>, 'onChange'> {
  /** Uppercase micro-label above the box. */
  label?: ReactNode
  /** Placeholder when nothing is selected (e.g. "All sources"). */
  placeholder?: string
  options: ComboOption[]
  /** Selected value ("" = none). */
  value: string
  /** Called with the chosen (value, label); ("", "") on clear. */
  onChange?: (value: string, label: ReactNode) => void
}

export function Combobox({
  label,
  placeholder = 'All',
  options = [],
  value,
  onChange,
  className = '',
  style,
  ...rest
}: ComboboxProps) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const boxRef = useRef<HTMLDivElement>(null)

  const selected = options.find((o) => o.value === value)
  // While open, show what the user is typing; when closed, show the selected label
  const display = open ? query : selected ? String(selected.label ?? '') : ''
  const filtered = options.filter((o) =>
    String(o.label ?? '')
      .toLowerCase()
      .includes(query.toLowerCase()),
  )

  useEffect(() => {
    function onDoc(e: MouseEvent) {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [])

  function pick(o: ComboOption) {
    onChange?.(o.value, o.label)
    setOpen(false)
    setQuery('')
  }

  function clear(e: React.MouseEvent) {
    e.stopPropagation()
    onChange?.('', '')
    setQuery('')
  }

  return (
    <div
      className={`fw-combo ${className}`}
      style={{ display: 'flex', flexDirection: 'column', gap: 2, fontFamily: 'var(--fw-font-ui)', ...style }}
      {...rest}
    >
      {label ? (
        <span
          style={{
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
            textTransform: 'uppercase',
            letterSpacing: 'var(--fw-ls-table)',
          }}
        >
          {label}
        </span>
      ) : null}
      <div style={{ position: 'relative', minWidth: 150 }} ref={boxRef}>
        <input
          style={{
            width: '100%',
            background: 'var(--fw-bg-input)',
            color: 'var(--fw-t1)',
            border: '1px solid var(--fw-border)',
            borderRadius: 'var(--fw-r-xs)',
            padding: '6px 24px 6px 8px',
            fontSize: 'var(--fw-fs-sm)',
            fontFamily: 'var(--fw-font-ui)',
            outline: 'none',
          }}
          placeholder={placeholder}
          value={display}
          autoComplete="off"
          aria-label={label ? String(label) : placeholder}
          onFocus={() => {
            setOpen(true)
            setQuery('')
          }}
          onBlur={(e) => {
            // Close the dropdown when keyboard focus leaves the combobox container.
            // relatedTarget is the element receiving focus next; if it is outside
            // boxRef (the container) the dropdown should be dismissed (UT-09 / #507).
            if (!boxRef.current?.contains(e.relatedTarget as Node | null)) {
              setOpen(false)
            }
          }}
          onChange={(e) => {
            setQuery(e.target.value)
            setOpen(true)
          }}
        />
        {value ? (
          <span
            role="button"
            aria-label="Clear filter"
            onClick={clear}
            style={{
              position: 'absolute',
              right: 6,
              top: '50%',
              transform: 'translateY(-50%)',
              cursor: 'pointer',
              color: 'var(--fw-t3)',
              fontSize: 13,
              lineHeight: 1,
              padding: '0 2px',
            }}
          >
            ✕
          </span>
        ) : null}
        {open && filtered.length > 0 && (
          <div
            data-testid="combobox-dropdown"
            style={{
              position: 'absolute',
              top: '100%',
              left: 0,
              right: 0,
              maxHeight: 250,
              overflowY: 'auto',
              background: 'var(--fw-bg-card)',
              border: '1px solid var(--fw-border)',
              borderRadius: 'var(--fw-r-xs)',
              zIndex: 100,
              boxShadow: 'var(--fw-shadow-toast)',
              marginTop: 2,
            }}
          >
            {filtered.map((o) => (
              <div
                key={o.value}
                data-testid={`combobox-option-${o.value}`}
                onMouseDown={() => pick(o)}
                style={{
                  padding: '6px 10px',
                  cursor: 'pointer',
                  fontSize: 'var(--fw-fs-sm)',
                  color: o.value === value ? 'var(--fw-on-accent)' : 'var(--fw-t1)',
                  background: o.value === value ? 'var(--fw-accent)' : 'transparent',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {o.label}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
