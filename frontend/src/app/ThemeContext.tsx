/**
 * ThemeContext — dark/light theme state for the FireWatch app shell.
 *
 * F1 (#107): provides the seam for the ThemeToggle (built in F2/#108).
 * The authoritative token set lives in index.css as [data-theme="dark|light"].
 * This context syncs React state with the <html data-theme="..."> attribute.
 *
 * Dark is the default "operations" theme per the DS spec (readme.md "Visual
 * foundations"). Light is the swappable "projector" alternate.
 *
 * Fix #570: Theme preference is persisted to localStorage and rehydrated on
 * init.  A companion inline script in index.html applies the persisted value
 * synchronously before first paint to avoid FOUC.  The storage helpers live in
 * ./themeStorage.ts (separate file to satisfy react-refresh/only-export-
 * components — this file must export only React components/hooks).
 *
 * NOTE: useTheme is re-exported from ./useTheme.ts (keeps this file
 * component-only for react-refresh fast-reload compatibility).
 */

import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react'
import { resolveInitialTheme, persistTheme } from './themeStorage'

export type Theme = 'dark' | 'light'

interface ThemeContextValue {
  theme: Theme
  toggleTheme: () => void
  setTheme: (t: Theme) => void
}

const ThemeContext = createContext<ThemeContextValue | null>(null)

export function ThemeProvider({ children }: { children: ReactNode }) {
  // Initialise from localStorage (or OS preference, or default dark).
  const [theme, setThemeState] = useState<Theme>(resolveInitialTheme)

  /**
   * Apply the theme: update React state, write the data-theme attribute so CSS
   * tokens resolve, and persist the choice to localStorage.
   */
  const applyTheme = useCallback((t: Theme) => {
    setThemeState(t)
    document.documentElement.setAttribute('data-theme', t)
    persistTheme(t)
  }, [])

  // On first mount, ensure the DOM attribute matches the resolved initial theme.
  // The index.html inline script handles the pre-React case; this sync covers
  // cases where the attribute was absent or mismatched (e.g. in tests).
  useEffect(() => {
    const current = document.documentElement.getAttribute('data-theme')
    if (current !== theme) {
      document.documentElement.setAttribute('data-theme', theme)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const toggleTheme = useCallback(() => {
    applyTheme(theme === 'dark' ? 'light' : 'dark')
  }, [theme, applyTheme])

  const setTheme = useCallback(
    (t: Theme) => {
      applyTheme(t)
    },
    [applyTheme],
  )

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

/**
 * Consume inside any child of ThemeProvider.
 * eslint-disable-next-line react-refresh/only-export-components — hook is
 * co-located with its context provider intentionally; this is the canonical
 * React context pattern. Re-exported from ./useTheme.ts for consumers.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used inside <ThemeProvider>')
  return ctx
}
