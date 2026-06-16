/**
 * Tests for issue #505 — AI baseline/drift 404 should be treated as empty state,
 * not logged as a console error (UT-06).
 *
 * EARS criteria covered:
 *
 * EARS-505-1: WHEN no baseline exists → DriftPanel renders 'no-baseline' empty state
 *             WITHOUT fetchDriftReport being called (the 404 request is never fired).
 * EARS-505-2: WHEN no baseline exists → DriftPanel shows the honest empty state,
 *             not an error view.
 * EARS-505-3: WHEN no baseline exists → fetchDriftReport call count is zero
 *             (the browser never sees the 404 request — CE-01/CE-02 silenced).
 * EARS-505-4: WHEN baseline exists but no drift run → fetchDriftReport IS called
 *             and null return produces the 'baseline-only' state (regression guard).
 * EARS-505-5: WHEN baseline exists and drift report exists → full drift-report view
 *             renders correctly (regression guard — fix must not break the happy path).
 * EARS-505-6: WHEN fetchDriftReport throws ApiError(422) → error state shown
 *             (regression guard — corrupt report path preserved).
 *
 * Security: all IP fixtures are RFC 5737 (no real public IPs).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import type { BaselineStatus, DriftReport } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BASELINE_NOT_EXISTS: BaselineStatus = { exists: false }

const BASELINE_EXISTS: Extract<BaselineStatus, { exists: true }> = {
  exists: true,
  model: 'llama3.2',
  saved_at: '2026-06-10T12:00:00Z',
  scenario_count: 20,
}

const DRIFT_REPORT: DriftReport = {
  baseline_model: 'llama3.2',
  candidate_model: 'qwen3:14b',
  run_at: '2026-06-12T14:00:00Z',
  scenarios: 20,
  changed: 1,
  escalations: 1,
  deescalations: 0,
  diffs: [
    {
      scenario: 'concise_waf_no_corr',
      baseline_verdict: 'HIGH',
      candidate_verdict: 'CRITICAL',
      baseline_confidence: 0.8,
      candidate_confidence: 0.9,
      baseline_summary: 'block',
      candidate_summary: 'block',
    },
  ],
}

// ---------------------------------------------------------------------------
// Mock setup — api/client
// ---------------------------------------------------------------------------

const {
  mockFetchBaselineStatus,
  mockFetchDriftReport,
  mockFetchHealth,
} = vi.hoisted(() => ({
  mockFetchBaselineStatus: vi.fn(),
  mockFetchDriftReport: vi.fn(),
  mockFetchHealth: vi.fn().mockResolvedValue({
    status: 'ok',
    ollama_connected: true,
    ollama_model: 'llama3.2',
    db_ok: true,
  }),
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
    fetchBaselineStatus: mockFetchBaselineStatus,
    fetchDriftReport: mockFetchDriftReport,
    fetchHealth: mockFetchHealth,
    // Other API helpers used transitively
    fetchThreats: vi.fn().mockResolvedValue([]),
    fetchAnalyses: vi.fn().mockResolvedValue({ items: [], next_cursor: null, has_more: false }),
    fetchFeedbackSummary: vi.fn().mockResolvedValue(null),
    fetchSourceTypes: vi.fn().mockResolvedValue([]),
    assertLoopbackBase: vi.fn(),
    resolveBaseUrl: vi.fn(() => ''),
  }
})

// IpPanel/SlideOver fetches — non-fatal mocks
vi.mock('../api/logs', () => ({
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
}))

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { DriftPanel } from '../components/ai/drift/DriftPanel'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderDriftPanel() {
  return render(
    <MemoryRouter>
      <DriftPanel />
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// EARS-505-1, EARS-505-2, EARS-505-3: no-baseline state — no drift request fired
// ---------------------------------------------------------------------------

describe('DriftPanel — no-baseline: drift request not fired (issue #505 UT-06)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_NOT_EXISTS)
    // fetchDriftReport configured but should never be called in this scenario.
    mockFetchDriftReport.mockResolvedValue(null)
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: false,
      ollama_model: null,
      db_ok: true,
    })
  })

  it('EARS-505-3: fetchDriftReport is NOT called when no baseline exists', async () => {
    renderDriftPanel()

    // Wait for the panel to finish loading and settle into the no-baseline state.
    await waitFor(() => {
      expect(screen.getByTestId('drift-no-baseline')).toBeInTheDocument()
    })

    // The drift endpoint must never fire — skipped to avoid guaranteed 404.
    expect(mockFetchDriftReport).not.toHaveBeenCalled()
  })

  it('EARS-505-2: renders the honest no-baseline empty state (not an error state)', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-no-baseline')).toBeInTheDocument()
    })

    // No error state — the missing-baseline case must not produce drift-error.
    expect(screen.queryByTestId('drift-error')).not.toBeInTheDocument()
  })

  it('EARS-505-1: fetchBaselineStatus is called (phase-1 fetch runs)', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-no-baseline')).toBeInTheDocument()
    })

    // Phase 1 fetch must fire.
    expect(mockFetchBaselineStatus).toHaveBeenCalledTimes(1)
    // Phase 2 fetch must not fire.
    expect(mockFetchDriftReport).not.toHaveBeenCalled()
  })

  it('EARS-505-2: no console.error emitted during the no-baseline flow', async () => {
    const capturedErrors: unknown[] = []
    const originalError = console.error
    console.error = (...args: unknown[]) => {
      capturedErrors.push(args)
      originalError(...args)
    }

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-no-baseline')).toBeInTheDocument()
    })

    console.error = originalError

    // Filter out React's internal act() / test-environment warnings (not app errors).
    const appErrors = capturedErrors.filter(
      (e) =>
        !String(e).includes('Warning:') &&
        !String(e).includes('act(') &&
        !String(e).includes('inside a test'),
    )
    expect(appErrors).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// EARS-505-4: baseline exists, drift null → baseline-only (regression guard)
// ---------------------------------------------------------------------------

describe('DriftPanel — baseline-only: drift IS called when baseline exists (EARS-505-4)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_EXISTS)
    // null = fetchDriftReport's 404 handler (no comparison run yet)
    mockFetchDriftReport.mockResolvedValue(null)
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.2',
      db_ok: true,
    })
  })

  it('EARS-505-4: fetchDriftReport IS called when baseline exists', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-baseline-only')).toBeInTheDocument()
    })

    // With a baseline, the drift fetch must fire (phase 2).
    expect(mockFetchDriftReport).toHaveBeenCalledTimes(1)
  })

  it('EARS-505-4: renders baseline-only state (scenario count + CLI instruction)', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-baseline-only')).toBeInTheDocument()
    })

    expect(screen.getByText(/20 synthetic scenarios/)).toBeInTheDocument()
    expect(screen.getByText(/firewatch ai-baseline --compare/)).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-505-5: full drift-report path preserved (regression guard)
// ---------------------------------------------------------------------------

describe('DriftPanel — drift-report renders correctly when baseline + drift both exist (EARS-505-5)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_EXISTS)
    mockFetchDriftReport.mockResolvedValue(DRIFT_REPORT)
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'qwen3:14b',
      db_ok: true,
    })
  })

  it('EARS-505-5: renders drift-report view with both model names', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-headline')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-headline')).toHaveTextContent('llama3.2')
    expect(screen.getByTestId('drift-headline')).toHaveTextContent('qwen3:14b')
  })

  it('EARS-505-5: changed count and diff rows render correctly', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-diff-list')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-changed-count')).toHaveTextContent('1 of 20')
    const rows = screen.getAllByTestId('drift-diff-row')
    expect(rows).toHaveLength(1)
  })

  it('EARS-505-5: fetchDriftReport is called once (drift fetch is not skipped)', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-headline')).toBeInTheDocument()
    })

    expect(mockFetchDriftReport).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// EARS-505-6: 422 error state preserved (regression guard)
// ---------------------------------------------------------------------------

describe('DriftPanel — 422 error state preserved when drift is corrupt (EARS-505-6)', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  it('EARS-505-6: ApiError(422) from fetchDriftReport produces an error state', async () => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_EXISTS)
    const { ApiError } = await import('../api/client')
    mockFetchDriftReport.mockRejectedValue(
      new ApiError(422, { detail: 'corrupt' }, 'API 422: corrupt'),
    )
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.2',
      db_ok: true,
    })

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-error')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-error')).toHaveTextContent('--compare')
  })
})

// ---------------------------------------------------------------------------
// MM #476 regression: model-swap banner still shown after fix
// ---------------------------------------------------------------------------

describe('DriftPanel — model-swap banner still works after issue #505 fix (MM #476 regression)', () => {
  it('banner shows when configured model differs from baseline model', async () => {
    vi.clearAllMocks()
    const baselineWithOldModel: Extract<BaselineStatus, { exists: true }> = {
      exists: true,
      model: 'llama3:8b',
      saved_at: '2026-06-10T12:00:00Z',
      scenario_count: 20,
    }
    mockFetchBaselineStatus.mockResolvedValue(baselineWithOldModel)
    mockFetchDriftReport.mockResolvedValue(null)
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.1:8b',
      db_ok: true,
    })

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('model-swap-banner')).toBeInTheDocument()
    })

    expect(screen.getByTestId('model-swap-banner-from')).toHaveTextContent('llama3:8b')
    expect(screen.getByTestId('model-swap-banner-to')).toHaveTextContent('llama3.1:8b')
  })
})
