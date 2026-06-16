/**
 * Tests for issue #282 — hide the non-functional "All Sources" dropdown
 * until ADR-0038 phases A–B (SourceScopeContext seam) land.
 *
 * EARS acceptance criteria (1:1):
 *
 * 1. WHEN the header renders, the system SHALL NOT render the non-functional
 *    source dropdown (data-testid="source-picker" must be absent).
 *
 * 2. WHEN the header renders, the source-health dots (data-testid="source-health-row")
 *    SHALL still appear when the stats API returns source_health entries.
 *
 * 3. The source-filter-bar container SHALL still render (structural slot kept).
 *
 * Refs: ADR-0038 (Proposed), ADR-0035, #282, #286.
 */

// ADR-0064 D4: setup.ts provides a global stub for RefreshContext so that route
// tests that don't wrap components in <RefreshProvider> don't throw.  This file
// renders <RefreshProvider> for real, so we need to unmock it first.
import { vi } from 'vitest'
vi.unmock('../app/refresh/RefreshContext')

import { describe, it, expect } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import type React from 'react'
import { RefreshProvider } from '../app/refresh/RefreshContext'

// ---------------------------------------------------------------------------
// Minimal ThemeContext mock (same pattern as HeaderClockTimezone.test.tsx)
// ---------------------------------------------------------------------------

vi.mock('../app/ThemeContext', () => ({
  useTheme: () => ({ theme: 'dark', toggleTheme: vi.fn() }),
  ThemeProvider: ({ children }: { children: React.ReactNode }) => children,
}))

// ---------------------------------------------------------------------------
// Mock API client — return one source health entry so we can verify the dots
// still render while the picker is gone.
// ---------------------------------------------------------------------------

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    fetchStats: vi.fn().mockResolvedValue({
      source_health: [
        {
          source_id: 'azure_waf',
          source_type: 'azure_waf',
          display_name: 'Azure WAF',
          flavor: 'pull',
          health: 'ok',
          supervisor_state: null,
          last_event_at: null,
          event_count: 42,
          last_error: null,
        },
      ],
      total_logs: 100,
      total_ips: 5,
      blocked_percentage: 50,
      last_updated: null,
    }),
    ApiError: class ApiError extends Error {
      status: number
      detail: unknown
      constructor(status: number, detail: unknown, message?: string) {
        super(message ?? `API error ${status}`)
        this.status = status
        this.detail = detail
      }
    },
    resolveBaseUrl: () => '',
    assertLoopbackBase: () => {},
  }
})

// ---------------------------------------------------------------------------
// Render helper
// ---------------------------------------------------------------------------

async function renderAppHeader() {
  const { default: AppHeader } = await import('../app/AppHeader')
  return render(
    <RefreshProvider>
      <MemoryRouter>
        <AppHeader />
      </MemoryRouter>
    </RefreshProvider>,
  )
}

// ---------------------------------------------------------------------------
// 1. "All Sources" Combobox / source-picker is NOT rendered (#282)
// ---------------------------------------------------------------------------

describe('#282 — All Sources dropdown is hidden', () => {
  it('source-picker testid is NOT present immediately after render', async () => {
    await renderAppHeader()
    expect(screen.queryByTestId('source-picker')).not.toBeInTheDocument()
  })

  it('source-picker testid is NOT present after stats load resolves', async () => {
    await renderAppHeader()
    // Allow the fetchStats promise to settle
    await new Promise((r) => setTimeout(r, 50))
    expect(screen.queryByTestId('source-picker')).not.toBeInTheDocument()
  })

  it('no element with placeholder "All sources" is rendered', async () => {
    await renderAppHeader()
    await new Promise((r) => setTimeout(r, 50))
    // The Combobox input uses this placeholder — must be absent
    expect(screen.queryByPlaceholderText('All sources')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 2. SourceHealth dots remain visible (#282 must not break health indicator)
// ---------------------------------------------------------------------------

describe('#282 — source-health dots are still rendered', () => {
  it('source-health-row appears after stats resolve (health dots intact)', async () => {
    await renderAppHeader()
    await waitFor(() => {
      expect(screen.getByTestId('source-health-row')).toBeInTheDocument()
    })
  })

  it('Azure WAF health dot is visible (health chip from mock data)', async () => {
    await renderAppHeader()
    await waitFor(() => {
      expect(screen.getByTestId('health-item-azure_waf')).toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// 3. source-filter-bar container slot still renders (#282 — structural slot kept)
// ---------------------------------------------------------------------------

describe('#282 — source-filter-bar container is present', () => {
  it('source-filter-bar container is rendered', async () => {
    await renderAppHeader()
    expect(screen.getByTestId('source-filter-bar')).toBeInTheDocument()
  })
})
