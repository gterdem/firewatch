/**
 * themeStorage — localStorage persistence and initial-theme resolution for
 * the FireWatch theme system (fix #570).
 *
 * Extracted from ThemeContext.tsx to satisfy the react-refresh/only-export-
 * components lint rule (context files must export only React components/hooks).
 *
 * Preference resolution order (highest wins):
 *   1. Value stored in localStorage ("fw-theme") — explicit user choice.
 *   2. OS/browser prefers-color-scheme media query.
 *   3. Hard-coded default: "dark" (DS "operations" theme, ADR-0028 D6).
 */

import type { Theme } from './ThemeContext'

/** localStorage key for the persisted theme choice. */
export const THEME_STORAGE_KEY = 'fw-theme'

/**
 * Resolve the initial theme without touching the DOM — pure function so it is
 * straightforward to unit-test in isolation.
 */
export function resolveInitialTheme(): Theme {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY)
    if (stored === 'dark' || stored === 'light') return stored
  } catch {
    // localStorage unavailable (e.g. strict private-browsing) — fall through.
  }

  if (typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: light)').matches) {
    return 'light'
  }

  return 'dark'
}

/**
 * Persist the chosen theme to localStorage.  Best-effort: ignores write
 * failures (e.g. storage quota / incognito restrictions).
 */
export function persistTheme(theme: Theme): void {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme)
  } catch {
    // Ignore.
  }
}
