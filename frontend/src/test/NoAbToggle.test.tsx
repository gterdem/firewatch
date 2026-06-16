/**
 * MF-1 EARS criterion: no A/B old↔new design toggle.
 *
 * State-driven: WHILE the app renders, there SHALL be no A/B old↔new design
 * toggle; the only header toggle SHALL be the dark/light ThemeToggle.
 *
 * This test group:
 *   1. Verifies no "Tweaks" / design-mode toggle is present in the App shell.
 *   2. Verifies exactly one toggle exists (the dark/light ThemeToggle).
 *   3. Verifies the ThemeToggle switches data-theme between "dark" and "light".
 *
 * The A/B artifact was a design-tool feature from the SOC Design System kit
 * (ui_kits/soc-console/app.js `dashboardMode` prop with "triage"/"classic"
 * options). It was never ported to the MD-era frontend — this test asserts
 * that absence is intentional and permanent (docs/frontend-page-by-page-checklist.md
 * "Drop the A/B Tweaks toggle").
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import App from '../app/App'

// Mock API calls made by AppHeader (SourceFilterBar polls /stats + /sources)
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    fetchStats: vi.fn().mockResolvedValue({
      source_health: [],
      total_logs: 0,
      total_ips: 0,
      blocked_percentage: 0,
      last_updated: null,
    }),
  }
})
vi.mock('../api/sources', () => ({
  fetchSources: vi.fn().mockResolvedValue([]),
}))

// Mock all routes — this test only cares about the shell
vi.mock('../routes/DashboardRoute', () => ({
  default: () => <div data-testid="dashboard-route">Dashboard</div>,
}))
vi.mock('../routes/AIRoute', () => ({
  default: () => <div data-testid="ai-route">AI</div>,
}))
vi.mock('../routes/LogsRoute', () => ({
  default: () => <div data-testid="logs-route">Logs</div>,
}))
vi.mock('../routes/AnalyticsRoute', () => ({
  default: () => <div data-testid="analytics-route">Analytics</div>,
}))
vi.mock('../routes/SettingsRoute', () => ({
  default: () => <div data-testid="settings-route">Settings</div>,
}))

// Reset data-theme and localStorage between tests so ThemeProvider always
// initialises from the known-good default (dark) rather than a prior test's
// persisted preference (fix #570: theme persistence added to ThemeContext).
beforeEach(() => {
  localStorage.clear()
  document.documentElement.setAttribute('data-theme', 'dark')
})

describe('MF-1 — no A/B design toggle', () => {
  it('no "Tweaks" text appears anywhere in the rendered shell', () => {
    render(<App />)
    expect(screen.queryByText(/tweaks/i)).toBeNull()
  })

  it('no "Classic" / "Triage" mode switcher is rendered', () => {
    render(<App />)
    // The kit's dashboardMode selector had "triage" / "classic" options
    expect(screen.queryByText(/classic/i)).toBeNull()
    // "Triage" may appear in real page content later (triage banner) but
    // must NOT be present as a mode-selector control in the shell
    const triageButtons = screen
      .queryAllByRole('button')
      .filter((btn) => /triage/i.test(btn.textContent ?? ''))
    expect(triageButtons).toHaveLength(0)
  })

  it('no "dashboardMode" or design-switch control exists in the header', () => {
    render(<App />)
    // No select/combobox in the header region with design-mode options
    const header = screen.getByTestId('app-header')
    const selects = header.querySelectorAll('select')
    // If any select exists, it must not contain classic/triage mode options
    for (const sel of selects) {
      const options = Array.from(sel.options).map((o) => o.value.toLowerCase())
      expect(options).not.toContain('classic')
      expect(options).not.toContain('triage')
    }
  })

  it('exactly one toggle button exists in the header — the ThemeToggle', () => {
    render(<App />)
    const header = screen.getByTestId('app-header')
    // Count buttons in the header; ThemeToggle is the only toggle
    const themeToggle = header.querySelector('[data-testid="theme-toggle"]')
    expect(themeToggle).not.toBeNull()
    // There should be no second toggle-style button (A/B switcher)
    // We check by testid — no other *-toggle testid exists
    const allToggles = header.querySelectorAll('[data-testid$="-toggle"]')
    expect(allToggles).toHaveLength(1)
  })
})

describe('MF-1 — ThemeToggle is present and functional', () => {
  it('ThemeToggle renders in the header', () => {
    render(<App />)
    expect(screen.getByTestId('theme-toggle')).toBeInTheDocument()
  })

  it('ThemeToggle toggles data-theme from dark to light', () => {
    render(<App />)
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    fireEvent.click(screen.getByTestId('theme-toggle'))
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  })

  it('ThemeToggle toggles back from light to dark', () => {
    render(<App />)
    fireEvent.click(screen.getByTestId('theme-toggle'))
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    fireEvent.click(screen.getByTestId('theme-toggle'))
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })
})
