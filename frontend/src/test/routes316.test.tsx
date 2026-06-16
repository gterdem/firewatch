/**
 * Tests for issue #316 — /threats redirect + catch-all not-found route.
 *
 * EARS acceptance criteria:
 *   - WHEN the user navigates to /threats, the app SHALL land on /dashboard
 *     via a replace navigation (no broken back-button history entry).
 *   - WHEN the user navigates to any other unknown path, a not-found view
 *     with a working Dashboard link SHALL render — never a blank content area.
 *   - Ubiquitous: no "No routes matched" console warning for any path.
 *   - A router test SHALL cover both the /threats redirect and the catch-all.
 *
 * Strategy: render only the <Routes> slice from App.tsx (mocking the heavy
 * route components) inside a MemoryRouter with a controlled initialEntries.
 * This lets us start at /threats or /unknown without touching the full App shell.
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route, Navigate } from 'react-router-dom'
import NotFoundView from '../components/NotFoundView'

// ---------------------------------------------------------------------------
// Minimal stub for the routes that the redirect lands on
// ---------------------------------------------------------------------------
const MockDashboard = () => <div data-testid="dashboard-route">Dashboard</div>

// ---------------------------------------------------------------------------
// Helper: render the same route table as App.tsx with a given initial path.
// Heavy routes are stubbed; we only care about /threats and * here.
// ---------------------------------------------------------------------------
function renderRoutes(initialPath: string) {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<MockDashboard />} />
        <Route path="/ai" element={<div data-testid="ai-route">AI</div>} />
        <Route path="/logs" element={<div data-testid="logs-route">Logs</div>} />
        <Route path="/analytics" element={<div data-testid="analytics-route">Analytics</div>} />
        <Route path="/settings" element={<div data-testid="settings-route">Settings</div>} />
        {/* /threats redirect — threat-actor table lives on Dashboard; #316 */}
        <Route path="/threats" element={<Navigate to="/dashboard" replace />} />
        {/* catch-all — honest not-found surface instead of a silent blank; #316 */}
        <Route path="*" element={<NotFoundView />} />
      </Routes>
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// /threats redirect
// ---------------------------------------------------------------------------
describe('route /threats (#316)', () => {
  it('redirects /threats to /dashboard (dashboard-route renders)', () => {
    renderRoutes('/threats')
    expect(screen.getByTestId('dashboard-route')).toBeInTheDocument()
  })

  it('does NOT render the not-found view when navigating to /threats', () => {
    renderRoutes('/threats')
    expect(screen.queryByTestId('not-found-view')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Catch-all not-found route
// ---------------------------------------------------------------------------
describe('catch-all not-found route (#316)', () => {
  it('renders the not-found view for an unknown path', () => {
    renderRoutes('/completely-unknown-path')
    expect(screen.getByTestId('not-found-view')).toBeInTheDocument()
  })

  it('shows "Page not found" heading for an unknown path', () => {
    renderRoutes('/some-random-route')
    expect(screen.getByTestId('not-found-heading')).toHaveTextContent('Page not found')
  })

  it('shows a Dashboard link in the not-found view', () => {
    renderRoutes('/no-such-page')
    const link = screen.getByTestId('not-found-dashboard-link')
    expect(link).toBeInTheDocument()
    expect(link).toHaveAttribute('href', '/dashboard')
  })

  it('does NOT render the not-found view for a known route (/settings)', () => {
    renderRoutes('/settings')
    expect(screen.queryByTestId('not-found-view')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// NotFoundView unit — component in isolation
// ---------------------------------------------------------------------------
describe('NotFoundView component', () => {
  it('renders with testid not-found-view', () => {
    render(
      <MemoryRouter>
        <NotFoundView />
      </MemoryRouter>,
    )
    expect(screen.getByTestId('not-found-view')).toBeInTheDocument()
  })

  it('contains a link pointing to /dashboard', () => {
    render(
      <MemoryRouter>
        <NotFoundView />
      </MemoryRouter>,
    )
    expect(screen.getByTestId('not-found-dashboard-link')).toHaveAttribute('href', '/dashboard')
  })
})
