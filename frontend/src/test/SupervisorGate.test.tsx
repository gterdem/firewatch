/**
 * Consumer-level tests for the supervisor-offline gate (issue #315).
 *
 * Tests the EARS acceptance criteria that require asserting the fan-out
 * suppression at the consumer (SourceCard) level, not through the hook alone.
 *
 * This follows the dead-wire lesson in docs/lessons.md: test behavior at the
 * consumer level, not internal plumbing.
 *
 * EARS criteria tested here:
 *   - WHEN supervisorOffline=true, SourceCard SHALL NOT call fetchSources
 *     (the per-source GET /sources sub-request).
 *   - WHEN supervisorOffline=true, SourceCard SHALL NOT call getAutoSync
 *     (CollectControls sub-request).
 *   - WHEN supervisorOffline=true, SourceCard SHALL NOT call fetchSourceActions.
 *   - WHEN supervisorOffline=true, SourceCard shows the offline controls label
 *     instead of active CollectControls.
 *   - WHEN supervisorOffline transitions false→true: normal sub-requests resume.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import SourceCard from '../components/SourceCard'
import { SURICATA_SOURCE_ENTRY } from './fixtures'

// Hoist mocks
const {
  mockFetchSources,
  mockGetAutoSync,
  mockFetchSourceConfig,
  mockFetchSourceActions,
} = vi.hoisted(() => ({
  mockFetchSources: vi.fn(),
  mockGetAutoSync: vi.fn(),
  mockFetchSourceConfig: vi.fn(),
  mockFetchSourceActions: vi.fn(),
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
    fetchSourceConfig: mockFetchSourceConfig,
    putSourceConfig: vi.fn().mockResolvedValue(undefined),
    ApiError,
    resolveBaseUrl: () => '',
    assertLoopbackBase: () => undefined,
  }
})

vi.mock('../api/sources', () => ({
  fetchSources: mockFetchSources,
  testSource: vi.fn(),
  syncSource: vi.fn(),
  getAutoSync: mockGetAutoSync,
  setAutoSync: vi.fn(),
}))

vi.mock('../api/sourceActions', () => ({
  fetchSourceActions: mockFetchSourceActions,
  runSourceAction: vi.fn(),
}))

describe('SourceCard supervisor gate — fan-out suppression (issue #315)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({ mode: 'local' })
    mockGetAutoSync.mockResolvedValue({
      enabled: false,
      interval_seconds: 300,
      source_id: 'suricata',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
    mockFetchSources.mockResolvedValue([])
    mockFetchSourceActions.mockResolvedValue([])
  })

  // EARS core criterion: supervisorOffline=true → fetchSources NOT called
  it('does NOT call fetchSources when supervisorOffline=true', async () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} supervisorOffline={true} />)

    // Give React a tick to settle — any spurious fetch would fire in this window
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20))
    })

    expect(mockFetchSources).not.toHaveBeenCalled()
  })

  // supervisorOffline=true → getAutoSync NOT called (CollectControls sub-request suppressed)
  it('does NOT call getAutoSync when supervisorOffline=true', async () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} supervisorOffline={true} />)

    await act(async () => {
      await new Promise((r) => setTimeout(r, 20))
    })

    expect(mockGetAutoSync).not.toHaveBeenCalled()
  })

  // supervisorOffline=true → fetchSourceActions NOT called
  it('does NOT call fetchSourceActions when supervisorOffline=true', async () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} supervisorOffline={true} />)

    await act(async () => {
      await new Promise((r) => setTimeout(r, 20))
    })

    expect(mockFetchSourceActions).not.toHaveBeenCalled()
  })

  // supervisorOffline=true → offline controls label shown, not active CollectControls
  it('shows the offline controls label when supervisorOffline=true (ADR-0035 honesty)', async () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} supervisorOffline={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('source-actions-offline')).toBeInTheDocument()
    })

    // Active control buttons must NOT be present
    expect(screen.queryByTestId('btn-sync-now')).not.toBeInTheDocument()
    expect(screen.queryByTestId('btn-test')).not.toBeInTheDocument()
    expect(screen.queryByTestId('autosync-toggle')).not.toBeInTheDocument()
  })

  // supervisorOffline=false → normal sub-requests DO fire
  it('calls fetchSources normally when supervisorOffline=false', async () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} supervisorOffline={false} />)

    await waitFor(() => {
      expect(mockFetchSources).toHaveBeenCalled()
    })
  })

  // supervisorOffline=false → CollectControls renders (not offline label)
  // ADR-0062: card must be Active (instance present) for body to be expanded.
  // Provide a matching suricata instance so the card starts expanded.
  it('renders CollectControls (not offline label) when supervisorOffline=false', async () => {
    mockFetchSources.mockResolvedValue([{
      source_type: 'suricata',
      source_id: 'suricata',
      flavor: 'pull',
      state: 'running',
      attempt: 0,
      total_crashes: 0,
      total_dlq: 0,
      dropped_count: 0,
      last_success_at: '2026-06-04T10:00:00Z',
      event_count: 100,
      // ADR-0062 A1 §1: source must be enabled for card to expand (#737 fix)
      auto_sync_enabled: true,
    }])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} supervisorOffline={false} />)

    await waitFor(() => {
      expect(screen.getByTestId('collect-controls')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('source-actions-offline')).not.toBeInTheDocument()
  })

  // WHEN supervisorOffline transitions true→false: sub-requests resume
  it('resumes normal data loading when supervisorOffline transitions to false', async () => {
    const { rerender } = render(
      <SourceCard source={SURICATA_SOURCE_ENTRY} supervisorOffline={true} />,
    )

    // Verify suppressed while offline
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20))
    })
    expect(mockFetchSources).not.toHaveBeenCalled()

    // Supervisor comes back online — re-render with supervisorOffline=false
    rerender(<SourceCard source={SURICATA_SOURCE_ENTRY} supervisorOffline={false} />)

    await waitFor(() => {
      expect(mockFetchSources).toHaveBeenCalled()
    })
  })

  // Card itself (config form) still renders while offline (state-driven design)
  it('still renders the source card and config form when supervisorOffline=true', async () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} supervisorOffline={true} />)

    // Card shell and config form must render
    await waitFor(() => {
      expect(screen.getByTestId('source-card-suricata')).toBeInTheDocument()
      expect(screen.getByTestId('source-config-form-suricata')).toBeInTheDocument()
    })
  })
})
