/**
 * Tests for src/app/App.tsx — the SOC app shell (F1 #107, F3 #109).
 *
 * EARS criteria:
 *   - Shell renders sticky header (wordmark 🔥 FireWatch AI) and tab nav.
 *   - Dark is the default data-theme on <html> before any toggle.
 *   - All five tabs render with correct hrefs (route→tab mapping).
 *   - ThemeToggle is present and toggles data-theme between dark/light.
 *   - Source-filter bar is present (F3 #109 — real Combobox + SourceHealth).
 *   - No source name is hardcoded in the nav (modularity rule).
 *   - Default route redirects to /dashboard.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import App from '../app/App'

// Mock API calls made by SourceFilterBar in AppHeader (F3 #109) and EntityPanelProvider.
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    fetchStats: vi.fn().mockResolvedValue({ source_health: [], total_logs: 0, total_ips: 0, blocked_percentage: 0, last_updated: null }),
    // EntityPanelProvider fetches discovery cache on mount (non-fatal; mock here for test isolation)
    fetchSourceTypes: vi.fn().mockResolvedValue([]),
  }
})
vi.mock('../api/sources', () => ({
  fetchSources: vi.fn().mockResolvedValue([]),
}))

// Mock all routes so App tests focus on shell + nav only
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

describe('App shell — header', () => {
  it('renders the sticky app header', () => {
    render(<App />)
    expect(screen.getByTestId('app-header')).toBeInTheDocument()
  })

  it('renders the FireWatch wordmark with flame emoji', () => {
    render(<App />)
    const wordmark = screen.getByTestId('header-wordmark')
    expect(wordmark).toBeInTheDocument()
    expect(wordmark.textContent).toContain('FireWatch')
    expect(wordmark.textContent).toContain('AI')
  })

  it('renders the live dot indicator', () => {
    render(<App />)
    expect(screen.getByTestId('live-dot')).toBeInTheDocument()
  })

  it('renders the theme toggle button', () => {
    render(<App />)
    expect(screen.getByTestId('theme-toggle')).toBeInTheDocument()
  })

  it('renders the source-filter bar (F3 #109 — real Combobox + SourceHealth)', () => {
    render(<App />)
    expect(screen.getByTestId('source-filter-bar')).toBeInTheDocument()
  })

  it('renders the mono clock', () => {
    render(<App />)
    expect(screen.getByTestId('header-clock')).toBeInTheDocument()
  })
})

describe('App shell — dark-first theme', () => {
  it('data-theme on <html> defaults to "dark" (dark-first DS spec)', () => {
    render(<App />)
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
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

  it('theme toggle button shows moon emoji in dark mode', () => {
    render(<App />)
    expect(screen.getByTestId('theme-toggle').textContent).toContain('🌙')
  })

  it('theme toggle button shows sun emoji after switching to light', () => {
    render(<App />)
    fireEvent.click(screen.getByTestId('theme-toggle'))
    expect(screen.getByTestId('theme-toggle').textContent).toContain('☀️')
  })
})

describe('App shell — nav / route→tab mapping', () => {
  it('renders the main navigation element', () => {
    render(<App />)
    expect(screen.getByRole('navigation', { name: /main navigation/i })).toBeInTheDocument()
  })

  it('renders all five navigation tabs', () => {
    render(<App />)
    expect(screen.getByTestId('nav-dashboard')).toBeInTheDocument()
    expect(screen.getByTestId('nav-ai')).toBeInTheDocument()
    expect(screen.getByTestId('nav-logs')).toBeInTheDocument()
    expect(screen.getByTestId('nav-analytics')).toBeInTheDocument()
    expect(screen.getByTestId('nav-settings')).toBeInTheDocument()
  })

  it('nav-dashboard links to /dashboard', () => {
    render(<App />)
    expect(screen.getByTestId('nav-dashboard').closest('a')).toHaveAttribute('href', '/dashboard')
  })

  it('nav-ai links to /ai', () => {
    render(<App />)
    expect(screen.getByTestId('nav-ai').closest('a')).toHaveAttribute('href', '/ai')
  })

  it('nav-logs links to /logs', () => {
    render(<App />)
    expect(screen.getByTestId('nav-logs').closest('a')).toHaveAttribute('href', '/logs')
  })

  it('nav-analytics links to /analytics', () => {
    render(<App />)
    expect(screen.getByTestId('nav-analytics').closest('a')).toHaveAttribute('href', '/analytics')
  })

  it('nav-settings links to /settings', () => {
    render(<App />)
    expect(screen.getByTestId('nav-settings').closest('a')).toHaveAttribute('href', '/settings')
  })

  it('tab labels match the DS kit navs (no source name hardcoded)', () => {
    render(<App />)
    // "Dashboard" appears in both the nav tab and the mocked route — use nav testId
    expect(screen.getByTestId('nav-dashboard')).toHaveTextContent('Dashboard')
    expect(screen.getByTestId('nav-ai')).toHaveTextContent('AI Engine')
    expect(screen.getByTestId('nav-logs')).toHaveTextContent('Network Logs')
    expect(screen.getByTestId('nav-analytics')).toHaveTextContent('Threat Intelligence')
    expect(screen.getByTestId('nav-settings')).toHaveTextContent('Settings')
    // No source-specific label in the nav
    expect(screen.queryByText(/azure_waf/i)).toBeNull()
    expect(screen.queryByText(/suricata/i)).toBeNull()
  })
})

describe('App shell — layout', () => {
  it('renders the app-shell container', () => {
    render(<App />)
    expect(screen.getByTestId('app-shell')).toBeInTheDocument()
  })

  it('renders the main-content area', () => {
    render(<App />)
    expect(screen.getByTestId('main-content')).toBeInTheDocument()
  })

  it('renders DashboardRoute at root path (default redirect)', () => {
    render(<App />)
    expect(screen.getByTestId('dashboard-route')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// WCAG SC 1.3.1 — single <h1> per page (#567)
// ---------------------------------------------------------------------------

describe('App shell — duplicate <h1> (#567, WCAG SC 1.3.1)', () => {
  it('AppHeader wordmark is NOT an <h1> element (demoted to span)', () => {
    render(<App />)
    const wordmark = screen.getByTestId('header-wordmark')
    // The wordmark container div must contain no h1 descendant (#567 fix)
    const h1sInHeader = wordmark.querySelectorAll('h1')
    expect(h1sInHeader.length).toBe(0)
  })

  it('the whole document renders zero <h1>s when the mocked routes render plain divs', () => {
    // Mocked routes (DashboardRoute, etc.) render plain divs — no h1.
    // AppHeader wordmark must also be non-h1 after the fix.
    render(<App />)
    const allH1s = document.querySelectorAll('h1')
    expect(allH1s.length).toBe(0)
  })
})
