/**
 * Tests for issue #524 — AI Engine page: VerdictCardList + DriftPanel must always
 * render on /ai, regardless of viewport size.
 *
 * Regression: #515 added useLazyMount (IntersectionObserver) around VerdictCardList
 * and DriftPanel. When the /ai page fits in one viewport there is no scroll, the
 * 0-area sentinel divs never intersect, so neither panel ever mounted.
 *
 * Fix (#524): revert to eager rendering — no IntersectionObserver gate on either
 * panel. The UT-06 two-phase fetch (no-404 for drift) is preserved in useBaselineDrift.
 *
 * EARS criteria:
 *
 * EARS-524-1: WHEN AIRoute mounts → verdict-cards-panel is present in the DOM
 *             unconditionally (not behind an IntersectionObserver gate).
 *
 * EARS-524-2: WHEN AIRoute mounts → drift-panel testid is present in the DOM
 *             unconditionally.
 *
 * EARS-524-3: VerdictCardList renders even in a simulated 0-scroll-height
 *             environment (IntersectionObserver is available but sentinels would
 *             never fire because there is no scroll overflow).
 *
 * EARS-524-4: DriftPanel renders even in a simulated 0-scroll-height environment.
 *
 * EARS-524-5 (UT-06 regression guard): WHEN no baseline exists, fetchDriftReport is
 *             NOT called — the two-phase fetch fix from #515 is preserved.
 *
 * Security: all fixture IPs use RFC 5737 range.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import AIRoute from '../routes/AIRoute'

// ---------------------------------------------------------------------------
// Mock setup — api/client
// ---------------------------------------------------------------------------

const {
  mockFetchThreats,
  mockFetchHealth,
  mockFetchAnalyses,
  mockFetchFeedbackSummary,
  mockFetchBaselineStatus,
  mockFetchDriftReport,
} = vi.hoisted(() => ({
  mockFetchThreats: vi.fn().mockResolvedValue([]),
  mockFetchHealth: vi.fn().mockResolvedValue({
    status: 'ok',
    ollama_connected: true,
    ollama_model: 'llama3.2',
    db_ok: true,
  }),
  mockFetchAnalyses: vi.fn().mockResolvedValue({ items: [], next_cursor: null, has_more: false }),
  mockFetchFeedbackSummary: vi.fn().mockResolvedValue(null),
  mockFetchBaselineStatus: vi.fn().mockResolvedValue({ exists: false }),
  mockFetchDriftReport: vi.fn().mockResolvedValue(null),
}))

vi.mock('../api/client', () => {
  class ApiError extends Error {
    status: number
    detail: unknown
    constructor(status: number, detail: unknown, message?: string) {
      super(message ?? `API error ${status}`)
      this.status = status
      this.detail = detail
    }
  }
  return {
    ApiError,
    fetchThreats: mockFetchThreats,
    fetchHealth: mockFetchHealth,
    fetchAnalyses: mockFetchAnalyses,
    fetchFeedbackSummary: mockFetchFeedbackSummary,
    fetchBaselineStatus: mockFetchBaselineStatus,
    fetchDriftReport: mockFetchDriftReport,
    fetchSourceTypes: vi.fn().mockResolvedValue([]),
    assertLoopbackBase: vi.fn(),
    resolveBaseUrl: vi.fn(() => ''),
  }
})

vi.mock('../api/logs', () => ({
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderAIRoute() {
  return render(
    <MemoryRouter initialEntries={['/ai']}>
      <EntityPanelProvider>
        <AIRoute />
      </EntityPanelProvider>
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// EARS-524-1 / EARS-524-2 / EARS-524-3 / EARS-524-4
// Core regression: panels must render unconditionally
// ---------------------------------------------------------------------------

describe('Issue #524 — VerdictCardList + DriftPanel render unconditionally', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchThreats.mockResolvedValue([])
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.2',
      db_ok: true,
    })
    mockFetchAnalyses.mockResolvedValue({ items: [], next_cursor: null, has_more: false })
    mockFetchFeedbackSummary.mockResolvedValue(null)
    mockFetchBaselineStatus.mockResolvedValue({ exists: false })
    mockFetchDriftReport.mockResolvedValue(null)
  })

  // EARS-524-1: verdict-cards-panel present without any scroll / IO trigger
  it('EARS-524-1: verdict-cards-panel is present immediately after page loads', async () => {
    renderAIRoute()

    // Page finishes loading
    await waitFor(() => {
      expect(screen.getByTestId('ai-page')).toBeInTheDocument()
    })

    // verdict-cards-panel must be in the DOM — no IntersectionObserver gate
    await waitFor(() => {
      expect(screen.getByTestId('verdict-cards-panel')).toBeInTheDocument()
    })
  })

  // EARS-524-2: drift-panel present without any scroll / IO trigger
  it('EARS-524-2: drift-panel is present immediately after page loads', async () => {
    renderAIRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-page')).toBeInTheDocument()
    })

    await waitFor(() => {
      expect(screen.getByTestId('drift-panel')).toBeInTheDocument()
    })
  })

  // EARS-524-3: VerdictCardList renders even when IntersectionObserver is available
  // (simulates the single-viewport case where sentinels never intersect)
  it('EARS-524-3: verdict-cards-panel renders even when IntersectionObserver is available', async () => {
    // Simulate IntersectionObserver being available (as in a real browser)
    // The callback is accepted but never fired — models the 0-area sentinel case
    // Cast to unknown first to avoid strict IntersectionObserver interface requirements
    const mockIO = vi.fn(() => ({
      observe: vi.fn(),
      unobserve: vi.fn(),
      disconnect: vi.fn(),
      takeRecords: vi.fn(() => []),
      root: null,
      rootMargin: '',
      thresholds: [],
    } as unknown as IntersectionObserver))
    vi.stubGlobal('IntersectionObserver', mockIO)

    try {
      renderAIRoute()

      await waitFor(() => {
        expect(screen.getByTestId('ai-page')).toBeInTheDocument()
      })

      // Must mount regardless — eager rendering, no IO dependency
      await waitFor(() => {
        expect(screen.getByTestId('verdict-cards-panel')).toBeInTheDocument()
      })
    } finally {
      vi.unstubAllGlobals()
    }
  })

  // EARS-524-4: DriftPanel renders even when IntersectionObserver is available
  // and never fires (0-area sentinel, no scroll overflow)
  it('EARS-524-4: drift-panel renders even when IntersectionObserver never fires', async () => {
    const mockIO = vi.fn(() => ({
      observe: vi.fn(),
      unobserve: vi.fn(),
      disconnect: vi.fn(),
      takeRecords: vi.fn(() => []),
      root: null,
      rootMargin: '',
      thresholds: [],
    } as unknown as IntersectionObserver))
    vi.stubGlobal('IntersectionObserver', mockIO)

    try {
      renderAIRoute()

      await waitFor(() => {
        expect(screen.getByTestId('ai-page')).toBeInTheDocument()
      })

      await waitFor(() => {
        expect(screen.getByTestId('drift-panel')).toBeInTheDocument()
      })
    } finally {
      vi.unstubAllGlobals()
    }
  })
})

// ---------------------------------------------------------------------------
// EARS-524-5: UT-06 regression guard — two-phase fetch preserved
// fetchDriftReport must NOT be called when no baseline exists
// ---------------------------------------------------------------------------

describe('Issue #524 — UT-06 two-phase fetch preserved (no-404 regression guard)', () => {
  it('EARS-524-5: fetchDriftReport is NOT called when baseline does not exist', async () => {
    vi.clearAllMocks()
    mockFetchThreats.mockResolvedValue([])
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.2',
      db_ok: true,
    })
    mockFetchAnalyses.mockResolvedValue({ items: [], next_cursor: null, has_more: false })
    mockFetchFeedbackSummary.mockResolvedValue(null)
    // Phase 1: baseline does not exist
    mockFetchBaselineStatus.mockResolvedValue({ exists: false })
    // Phase 2 should never be reached
    mockFetchDriftReport.mockResolvedValue(null)

    renderAIRoute()

    // Wait for the no-baseline state to appear (DriftPanel settles)
    await waitFor(() => {
      expect(screen.getByTestId('drift-no-baseline')).toBeInTheDocument()
    })

    // Phase 2 must not have fired — this is the UT-06 fix from #515
    expect(mockFetchDriftReport).not.toHaveBeenCalled()
  })
})
