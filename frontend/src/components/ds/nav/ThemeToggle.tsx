/**
 * ThemeToggle — header icon button to flip dark/light theme (DS navigation, F2 #108).
 *
 * Ports legacy/FireWatch SOC Design System/components/navigation/ThemeToggle.jsx.
 * Props exact match to ThemeToggle.d.ts.
 *
 * Shows 🌙 while dark, ☀️ while light.
 * Controlled: pass the current `theme` and an `onToggle` that flips it.
 * Wired to ThemeContext in AppHeader — updates data-theme on <html>.
 */

import type { ButtonHTMLAttributes } from 'react'

export interface ThemeToggleProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** Current theme — chooses the glyph (🌙 dark / ☀️ light). */
  theme?: 'dark' | 'light'
  /** Click handler — flip the theme and set `data-theme` on <html>. */
  onToggle?: () => void
}

export function ThemeToggle({
  theme = 'dark',
  onToggle,
  className = '',
  style,
  ...rest
}: ThemeToggleProps) {
  return (
    <button
      className={`fw-themebtn ${className}`}
      title="Toggle theme"
      aria-label="Toggle theme"
      data-testid="theme-toggle"
      onClick={onToggle}
      style={{
        background: 'none',
        border: '1px solid var(--fw-border)',
        borderRadius: 'var(--fw-r-sm)',
        padding: '4px 8px',
        cursor: 'pointer',
        fontSize: 16,
        color: 'var(--fw-t2)',
        lineHeight: 1,
        transition: 'background var(--fw-dur-fast) var(--fw-ease)',
        ...style,
      }}
      {...rest}
    >
      {theme === 'dark' ? '🌙' : '☀️'}
    </button>
  )
}
