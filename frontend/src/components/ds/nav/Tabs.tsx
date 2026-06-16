/**
 * Tabs — underline tab bar (DS navigation, F2 #108).
 *
 * Ports legacy/FireWatch SOC Design System/components/navigation/Tabs.jsx.
 * Props exact match to Tabs.d.ts.
 *
 * Active tab is amber with an amber 2px underline (--fw-accent).
 * Each tab may show a monospace count (used for log-category filters).
 * Controlled: pass `value` (active id) and `onChange` (id → void).
 */

import type { HTMLAttributes, ReactNode } from 'react'

export interface TabItem {
  /** Stable identifier returned by onChange. */
  id: string
  /** Visible label. */
  label: ReactNode
  /** Optional monospace count shown after the label. */
  count?: number | string
}

export interface TabsProps extends Omit<HTMLAttributes<HTMLDivElement>, 'onChange'> {
  items: TabItem[]
  /** Id of the active tab. */
  value: string
  /** Called with the clicked tab's id. */
  onChange?: (id: string) => void
}

export function Tabs({ items = [], value, onChange, className = '', style, ...rest }: TabsProps) {
  return (
    <div
      role="tablist"
      className={`fw-tabs ${className}`}
      style={{
        display: 'flex',
        gap: 0,
        borderBottom: '1px solid var(--fw-border)',
        ...style,
      }}
      {...rest}
    >
      {items.map((t) => {
        const isActive = value === t.id
        return (
          <button
            key={t.id}
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange?.(t.id)}
            style={{
              padding: '9px 16px',
              fontSize: 'var(--fw-fs-sm)',
              fontWeight: 'var(--fw-fw-medium)',
              color: isActive ? 'var(--fw-accent)' : 'var(--fw-t3)',
              cursor: 'pointer',
              border: 'none',
              background: 'none',
              fontFamily: 'var(--fw-font-ui)',
              borderBottom: isActive
                ? '2px solid var(--fw-accent)'
                : '2px solid transparent',
              transition: 'color var(--fw-dur-fast) var(--fw-ease)',
              display: 'flex',
              alignItems: 'center',
              gap: 4,
            }}
          >
            {t.label}
            {t.count != null ? (
              <span
                style={{
                  fontFamily: 'var(--fw-font-mono)',
                  fontSize: 'var(--fw-fs-2xs)',
                  opacity: 0.6,
                }}
              >
                {t.count}
              </span>
            ) : null}
          </button>
        )
      })}
    </div>
  )
}
