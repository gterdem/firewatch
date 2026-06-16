/**
 * Tests for src/app/ThemeContext.tsx (fix #570)
 *
 * EARS criteria covered:
 *   - WHEN an operator toggles the theme, THE SYSTEM SHALL persist the chosen
 *     theme to localStorage.
 *   - WHEN the app loads, THE SYSTEM SHALL initialize the theme from the
 *     persisted value if present.
 *   - WHERE no persisted value exists, THE SYSTEM SHALL fall back to the
 *     default (dark) — optionally honoring prefers-color-scheme.
 *   - Additional: invalid localStorage value is ignored (falls back to default).
 *   - Additional: setTheme() also persists and updates the DOM attribute.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ThemeProvider, useTheme } from '../app/ThemeContext'
import { resolveInitialTheme, THEME_STORAGE_KEY } from '../app/themeStorage'

// ---------------------------------------------------------------------------
// Helper: a small consumer that surfaces theme context values.
// ---------------------------------------------------------------------------
function ThemeConsumer() {
  const { theme, toggleTheme, setTheme } = useTheme()
  return (
    <div>
      <span data-testid="current-theme">{theme}</span>
      <button data-testid="toggle-btn" onClick={toggleTheme}>
        Toggle
      </button>
      <button data-testid="set-light-btn" onClick={() => setTheme('light')}>
        Set Light
      </button>
      <button data-testid="set-dark-btn" onClick={() => setTheme('dark')}>
        Set Dark
      </button>
    </div>
  )
}

function renderWithProvider() {
  return render(
    <ThemeProvider>
      <ThemeConsumer />
    </ThemeProvider>,
  )
}

// ---------------------------------------------------------------------------
// resolveInitialTheme — pure unit tests (no DOM side-effects)
// ---------------------------------------------------------------------------
describe('resolveInitialTheme', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('returns stored "dark" when localStorage has fw-theme=dark', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'dark')
    expect(resolveInitialTheme()).toBe('dark')
  })

  it('returns stored "light" when localStorage has fw-theme=light', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'light')
    expect(resolveInitialTheme()).toBe('light')
  })

  it('falls back to "dark" (default) when localStorage is empty and no OS preference', () => {
    // jsdom matchMedia returns false for all queries by default.
    expect(resolveInitialTheme()).toBe('dark')
  })

  it('ignores invalid localStorage values and falls back to default', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'solarized')
    expect(resolveInitialTheme()).toBe('dark')
  })

  it('honors prefers-color-scheme: light when no localStorage value is set', () => {
    const mockMatchMedia = (query: string) => ({
      matches: query === '(prefers-color-scheme: light)',
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })
    const original = window.matchMedia
    window.matchMedia = mockMatchMedia as typeof window.matchMedia

    expect(resolveInitialTheme()).toBe('light')

    window.matchMedia = original
  })

  it('localStorage wins over prefers-color-scheme', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'dark')
    const mockMatchMedia = (query: string) => ({
      matches: query === '(prefers-color-scheme: light)',
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })
    const original = window.matchMedia
    window.matchMedia = mockMatchMedia as typeof window.matchMedia

    expect(resolveInitialTheme()).toBe('dark')

    window.matchMedia = original
  })
})

// ---------------------------------------------------------------------------
// ThemeProvider integration tests
// ---------------------------------------------------------------------------
describe('ThemeProvider', () => {
  beforeEach(() => {
    localStorage.clear()
    // Reset data-theme to a neutral state before each test.
    document.documentElement.removeAttribute('data-theme')
  })

  afterEach(() => {
    localStorage.clear()
  })

  // EARS criterion: WHEN the app loads, THE SYSTEM SHALL initialize the theme
  // from the persisted value if present.
  it('initializes to the persisted theme (light) from localStorage', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'light')
    renderWithProvider()
    expect(screen.getByTestId('current-theme').textContent).toBe('light')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  })

  it('initializes to the persisted theme (dark) from localStorage', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'dark')
    renderWithProvider()
    expect(screen.getByTestId('current-theme').textContent).toBe('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  // EARS criterion: WHERE no persisted value exists, THE SYSTEM SHALL fall back
  // to the default (dark).
  it('defaults to dark when localStorage is empty', () => {
    renderWithProvider()
    expect(screen.getByTestId('current-theme').textContent).toBe('dark')
  })

  // EARS criterion: WHEN an operator toggles the theme, THE SYSTEM SHALL
  // persist the chosen theme to localStorage.
  it('persists the toggled theme to localStorage', async () => {
    const user = userEvent.setup()
    renderWithProvider()

    // Initial state: dark (default — localStorage empty).
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBeNull()

    await user.click(screen.getByTestId('toggle-btn'))

    expect(screen.getByTestId('current-theme').textContent).toBe('light')
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('light')
  })

  it('persists again when toggled back to dark', async () => {
    const user = userEvent.setup()
    localStorage.setItem(THEME_STORAGE_KEY, 'light')
    renderWithProvider()

    await user.click(screen.getByTestId('toggle-btn'))

    expect(screen.getByTestId('current-theme').textContent).toBe('dark')
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark')
  })

  // setTheme() must also persist.
  it('persists via setTheme()', async () => {
    const user = userEvent.setup()
    renderWithProvider()

    await user.click(screen.getByTestId('set-light-btn'))

    expect(screen.getByTestId('current-theme').textContent).toBe('light')
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('light')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  })

  // Toggling must update the data-theme DOM attribute.
  it('updates data-theme on <html> when toggled', async () => {
    const user = userEvent.setup()
    renderWithProvider()

    await user.click(screen.getByTestId('toggle-btn'))

    expect(document.documentElement.getAttribute('data-theme')).toBe('light')

    await user.click(screen.getByTestId('toggle-btn'))

    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  // Mount sync: if data-theme on <html> was set differently (e.g. by the inline
  // FOUC script or an earlier test), the provider must reconcile it on mount.
  it('syncs data-theme on mount when the attribute disagrees with initial state', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'light')
    // Simulate the <html> being left in dark (e.g. cold load without the inline script).
    document.documentElement.setAttribute('data-theme', 'dark')
    renderWithProvider()
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  })

  // useTheme must throw outside ThemeProvider.
  it('useTheme throws when used outside ThemeProvider', () => {
    // Suppress React's error boundary console output.
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(() =>
      render(
        // Intentionally render without the provider.
        <ThemeConsumer />,
      ),
    ).toThrow('useTheme must be used inside <ThemeProvider>')
    spy.mockRestore()
  })
})
