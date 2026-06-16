/**
 * Tests for src/components/sources/CollectControls.tsx (issue #138, ADR-0031).
 *
 * ADR-0062 §B/§D update: the Active toggle has moved to the card header slot
 * (SourceCard page-level). CollectControls now receives `isActive` as a prop.
 *
 * EARS criteria — 1:1 coverage:
 *
 * [SD-1] WHILE flavor="pull": card shows Sync-now + Test + interval (when active).
 * [SD-2] WHILE flavor="push": card shows listener status and NO Sync/interval controls.
 * [ED-3] WHEN isActive=true + interval changes (blur): UI persists it via PUT /auto-sync.
 * [ED-4] WHEN operator clicks "Sync now" (active): calls POST /sync/{type}?source_id=...
 *         and surfaces ingested/last-sync info.
 * [ED-5] WHEN operator clicks "Test" (active): calls POST /test/{type}?source_id=...
 * [UB-6] The card contains NO per-source-type branch; control selection is driven solely by flavor.
 * [UW-7] IF syncSource fails: UI shows an error without a raw status code (ADR-0062 §D).
 *
 * ADR-0062 §D — inactive source gates:
 * [D-1] WHEN isActive=false: Test and Sync buttons are disabled.
 * [D-2] WHEN isActive=false: a human-readable "Turn this source on to test it" hint is shown.
 * [D-3] WHEN isActive=false: NO request is made (never calls with missing source_id).
 * [D-4] Schedule sub-line ("Sync every...") is only shown WHEN isActive=true.
 *
 * #155 NB-1 / #166 NB-A strict-bool contract (interval persistence path):
 * [NB-1c] interval bounds: client rejects < 30 or > 86400 before calling the API.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import CollectControls from '../components/sources/CollectControls'
import {
  SOURCES_FIXTURE,
  SOURCES_BACKOFF_FIXTURE,
  AUTOSYNC_DISABLED,
  AUTOSYNC_ENABLED,
  AUTOSYNC_ERROR,
  SYNC_RESULT_OK,
  SYNC_RESULT_ZERO,
} from './readFixtures'

// ---------------------------------------------------------------------------
// Mock all sources-API functions used by CollectControls
// ---------------------------------------------------------------------------

const {
  mockSyncSource,
  mockTestSource,
  mockGetAutoSync,
  mockSetAutoSync,
} = vi.hoisted(() => ({
  mockSyncSource: vi.fn(),
  mockTestSource: vi.fn(),
  mockGetAutoSync: vi.fn(),
  mockSetAutoSync: vi.fn(),
}))

vi.mock('../api/sources', () => ({
  syncSource: mockSyncSource,
  testSource: mockTestSource,
  getAutoSync: mockGetAutoSync,
  setAutoSync: mockSetAutoSync,
}))

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const PULL_INSTANCE = SOURCES_FIXTURE[0] // { type_key: 'suricata', status: 'ok', ... }
const BACKOFF_INSTANCE = SOURCES_BACKOFF_FIXTURE[0]

// ---------------------------------------------------------------------------
// [SD-1] flavor="pull" — shows Sync-now + Test + controls
// ---------------------------------------------------------------------------

describe('[SD-1] flavor="pull" shows pull controls', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
  })

  it('renders pull-controls subtree (data-testid="pull-controls")', async () => {
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} />)
    await waitFor(() => {
      expect(screen.getByTestId('pull-controls')).toBeInTheDocument()
    })
  })

  it('renders "Sync now" button', async () => {
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} />)
    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })
  })

  it('renders "Test" button', async () => {
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} />)
    await waitFor(() => {
      expect(screen.getByTestId('btn-test')).toBeInTheDocument()
    })
  })

  it('does NOT render push-status subtree when flavor=pull', async () => {
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} />)
    await waitFor(() => {
      expect(screen.getByTestId('pull-controls')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('push-status')).not.toBeInTheDocument()
  })

  // ADR-0062 §B: interval input is in the active schedule section (only shown when Active)
  it('renders interval input when isActive=true', async () => {
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_ENABLED)
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => {
      expect(screen.getByTestId('interval-input')).toBeInTheDocument()
    })
  })

  it('does NOT render interval input when isActive=false (schedule hidden)', async () => {
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={false} />)
    // Wait for async operations to settle
    await waitFor(() => {
      expect(screen.getByTestId('pull-controls')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('interval-input')).not.toBeInTheDocument()
  })

  it('populates interval input from server state on mount (when active)', async () => {
    mockGetAutoSync.mockResolvedValue({ ...AUTOSYNC_DISABLED, interval_seconds: 120 })
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => {
      const input = screen.getByTestId('interval-input') as HTMLInputElement
      expect(input.value).toBe('120')
    })
  })

  it('shows last-sync info when auto-sync state has last_sync data (when active)', async () => {
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_ENABLED)
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => {
      expect(screen.getByTestId('last-sync-info')).toBeInTheDocument()
      expect(screen.getByTestId('last-sync-at')).toBeInTheDocument()
      expect(screen.getByTestId('last-sync-ingested')).toBeInTheDocument()
    })
  })

  it('shows last-sync error when last_sync_status is error (when active)', async () => {
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_ERROR)
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => {
      expect(screen.getByTestId('last-sync-error')).toBeInTheDocument()
      expect(screen.getByTestId('last-sync-error')).toHaveTextContent('SSH connection timed out')
    })
  })
})

// ---------------------------------------------------------------------------
// [SD-2] flavor="push" — shows listener status, NOT Sync/controls
// ---------------------------------------------------------------------------

describe('[SD-2] flavor="push" shows listener status only', () => {
  it('renders push-status subtree (data-testid="push-status")', () => {
    render(<CollectControls typeKey="syslog" flavor="push" instance={null} />)
    expect(screen.getByTestId('push-status')).toBeInTheDocument()
  })

  it('does NOT render pull-controls subtree when flavor=push', () => {
    render(<CollectControls typeKey="syslog" flavor="push" instance={null} />)
    expect(screen.queryByTestId('pull-controls')).not.toBeInTheDocument()
  })

  it('does NOT render Sync-now button for push source', () => {
    render(<CollectControls typeKey="syslog" flavor="push" instance={null} />)
    expect(screen.queryByTestId('btn-sync-now')).not.toBeInTheDocument()
  })

  // D1 fix (#195): uses real DTO fields — state (not status), source_type (not type_key).
  it('shows listener-state when instance is provided', () => {
    const pushInstance: import('../api/types').SourceInstance = {
      ...PULL_INSTANCE,
      source_type: 'syslog',
      source_id: 'syslog-1',
      state: 'running',  // real field
    }
    render(<CollectControls typeKey="syslog" flavor="push" instance={pushInstance} />)
    const listenerState = screen.getByTestId('listener-state')
    expect(listenerState).toBeInTheDocument()
    expect(listenerState).toHaveTextContent('running')
  })

  it('shows "No listener status available" when instance is null', () => {
    render(<CollectControls typeKey="syslog" flavor="push" instance={null} />)
    expect(screen.getByTestId('listener-state')).toHaveTextContent(/no listener status/i)
  })

  it('shows instance state for push instance in error state', () => {
    const errorInstance: import('../api/types').SourceInstance = {
      ...PULL_INSTANCE,
      source_type: 'syslog',
      source_id: 'syslog-1',
      state: 'error',
    }
    render(<CollectControls typeKey="syslog" flavor="push" instance={errorInstance} />)
    expect(screen.getByTestId('listener-state')).toHaveTextContent('error')
    expect(screen.queryByTestId('listener-error')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// [ED-3] interval change on blur (when active) — persists without page reload
// ---------------------------------------------------------------------------

describe('[ED-3] interval change persists on blur when isActive=true', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_ENABLED)
  })

  it('calls setAutoSync with new interval when interval input loses focus (active)', async () => {
    mockSetAutoSync.mockResolvedValue({ ...AUTOSYNC_ENABLED, interval_seconds: 60 })
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('interval-input')).toBeInTheDocument()
    })

    const input = screen.getByTestId('interval-input') as HTMLInputElement

    // Clear and type a new valid interval
    await act(async () => {
      await user.clear(input)
      await user.type(input, '60')
    })

    // Blur the input to trigger persistence
    await act(async () => {
      await user.tab()
    })

    await waitFor(() => {
      expect(mockSetAutoSync).toHaveBeenCalled()
    })

    const [, body] = mockSetAutoSync.mock.calls[0] as [string, { enabled: boolean; interval_seconds?: number }]
    expect(body.enabled).toBe(true)
    expect(body.interval_seconds).toBe(60)
  })

  it('does NOT call setAutoSync when isActive=false — interval input not shown', async () => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={false} />)

    await waitFor(() => {
      // No interval input when inactive
      expect(screen.queryByTestId('interval-input')).not.toBeInTheDocument()
    })

    // setAutoSync must NOT be called
    expect(mockSetAutoSync).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// [ED-4] Sync now — calls POST /sync/{type}?source_id=... and surfaces result
// ---------------------------------------------------------------------------

describe('[ED-4] Sync now button calls syncSource and surfaces result (when active)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
  })

  it('calls syncSource with typeKey and source_id when Sync now is clicked (active)', async () => {
    mockSyncSource.mockResolvedValue(SYNC_RESULT_OK)
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      expect(mockSyncSource).toHaveBeenCalledTimes(1)
    })

    const [typeKey, sourceId] = mockSyncSource.mock.calls[0] as [string, string | undefined]
    expect(typeKey).toBe('suricata')
    expect(sourceId).toBe('suricata-1')
  })

  it('shows sync-result with events_ingested after successful sync', async () => {
    mockSyncSource.mockResolvedValue(SYNC_RESULT_OK)
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('sync-result')).toBeInTheDocument()
    })
    expect(screen.getByTestId('sync-result')).toHaveTextContent('127')
  })

  it('shows sync-error when syncSource fails (no raw status code for remediable errors)', async () => {
    const { ApiError } = await import('../api/client')
    mockSyncSource.mockRejectedValue(new ApiError(500, { detail: 'Sync failed' }, 'Server error'))
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('sync-error')).toBeInTheDocument()
    })
    expect(screen.getByRole('alert')).toHaveTextContent('500')
  })
})

// ---------------------------------------------------------------------------
// [ED-5] Test connectivity button (active)
// ---------------------------------------------------------------------------

describe('[ED-5] Test connectivity button (when active)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
  })

  it('calls testSource with typeKey and source_id (active)', async () => {
    mockTestSource.mockResolvedValue({ ok: true, message: 'Connection OK', detail: null })
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-test')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-test'))
    })

    await waitFor(() => {
      expect(mockTestSource).toHaveBeenCalledTimes(1)
    })
    expect(mockTestSource).toHaveBeenCalledWith('suricata', 'suricata-1')
  })

  it('shows test-result on success', async () => {
    mockTestSource.mockResolvedValue({ ok: true, message: 'Connection OK', detail: null })
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-test')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-test'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('test-result')).toBeInTheDocument()
    })
    expect(screen.getByTestId('test-result')).toHaveTextContent('OK')
  })

  it('shows test-error on failure', async () => {
    const { ApiError } = await import('../api/client')
    mockTestSource.mockRejectedValue(new ApiError(503, { detail: 'Unreachable' }, ''))
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-test')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-test'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('test-error')).toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// [UB-6] Zero per-source-type branches — control selection driven solely by flavor
// ---------------------------------------------------------------------------

describe('[UB-6] flavor is the only discriminant — no per-source-type branching', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
  })

  it('a fictional "my_plugin" pull source renders pull-controls (no hardcoded type check)', async () => {
    render(<CollectControls typeKey="my_plugin" flavor="pull" instance={null} />)
    await waitFor(() => {
      expect(screen.getByTestId('pull-controls')).toBeInTheDocument()
    })
    expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
  })

  it('a fictional "my_plugin" push source renders push-status (no hardcoded type check)', () => {
    render(<CollectControls typeKey="my_plugin" flavor="push" instance={null} />)
    expect(screen.getByTestId('push-status')).toBeInTheDocument()
    expect(screen.queryByTestId('pull-controls')).not.toBeInTheDocument()
  })

  it('data-flavor attribute reflects the flavor prop', async () => {
    render(<CollectControls typeKey="waf" flavor="pull" instance={null} />)
    const root = screen.getByTestId('collect-controls')
    expect(root.getAttribute('data-flavor')).toBe('pull')
  })

  it('data-flavor=push for a push source', () => {
    render(<CollectControls typeKey="waf" flavor="push" instance={null} />)
    const root = screen.getByTestId('collect-controls')
    expect(root.getAttribute('data-flavor')).toBe('push')
  })
})

// ---------------------------------------------------------------------------
// [UW-7] syncSource failure — error shown (no raw code for the inactive case)
// ---------------------------------------------------------------------------

describe('[UW-7] syncSource failure — plain-language error', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
  })

  it('shows sync-error when syncSource rejects (active source, server error)', async () => {
    const { ApiError } = await import('../api/client')
    mockSyncSource.mockRejectedValue(
      new ApiError(502, { error: { code: 'SYNC_FAILED', message: 'Connection refused' } }, 'Bad Gateway'),
    )
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('sync-error')).toBeInTheDocument()
    })
    // Should show the human message, not just "(502)"
    expect(screen.getByTestId('sync-error').textContent).toContain('Connection refused')
  })
})

// ---------------------------------------------------------------------------
// ADR-0062 §D — Inactive source gates Test and Sync
// ---------------------------------------------------------------------------

describe('[D-1/D-2/D-3] isActive=false — Test/Sync disabled, no request made', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
  })

  it('[D-1] Test button is disabled when isActive=false', async () => {
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={false} />)
    await waitFor(() => {
      expect(screen.getByTestId('btn-test')).toBeDisabled()
    })
  })

  it('[D-1] Sync button is disabled when isActive=false', async () => {
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={false} />)
    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeDisabled()
    })
  })

  it('[D-2] shows "Turn this source on to test it" hint when isActive=false', async () => {
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={false} />)
    await waitFor(() => {
      const hint = screen.getByTestId('pull-inactive-hint')
      expect(hint).toBeInTheDocument()
      expect(hint).toHaveTextContent(/turn this source on to test it/i)
    })
  })

  it('[D-3] clicking disabled Test button does NOT call testSource', async () => {
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={false} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-test')).toBeDisabled()
    })

    // disabled buttons don't fire click events in userEvent
    await act(async () => {
      try {
        await user.click(screen.getByTestId('btn-test'))
      } catch {
        // expected — disabled button
      }
    })

    expect(mockTestSource).not.toHaveBeenCalled()
  })

  it('[D-3] inactive-source hint has tooltip on buttons', async () => {
    render(<CollectControls typeKey="suricata" flavor="pull" instance={null} isActive={false} />)
    await waitFor(() => {
      const testBtn = screen.getByTestId('btn-test')
      expect(testBtn.getAttribute('title')).toBe('Turn this source on to test it')
    })
  })

  it('[D-4] schedule section is NOT shown when isActive=false', async () => {
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={false} />)
    await waitFor(() => {
      expect(screen.getByTestId('pull-controls')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('active-schedule-section')).not.toBeInTheDocument()
    expect(screen.queryByTestId('interval-input')).not.toBeInTheDocument()
  })

  it('[D-4] schedule section IS shown when isActive=true', async () => {
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_ENABLED)
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => {
      expect(screen.getByTestId('active-schedule-section')).toBeInTheDocument()
      expect(screen.getByTestId('interval-input')).toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// Inactive instance state: backoff/parked → buttons disabled (when already active)
// ---------------------------------------------------------------------------

describe('Inactive instance (backoff/parked) — buttons disabled', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
  })

  it('disables Sync-now and Test buttons when instance is in backoff (even when isActive=true)', async () => {
    render(<CollectControls typeKey="suricata" flavor="pull" instance={BACKOFF_INSTANCE} isActive={true} />)
    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeDisabled()
      expect(screen.getByTestId('btn-test')).toBeDisabled()
    })
  })

  it('shows pull-inactive note when instance is in backoff (isActive=true)', async () => {
    render(<CollectControls typeKey="suricata" flavor="pull" instance={BACKOFF_INSTANCE} isActive={true} />)
    await waitFor(() => {
      expect(screen.getByTestId('pull-inactive')).toBeInTheDocument()
      expect(screen.getByTestId('pull-inactive')).toHaveTextContent('backoff')
    })
  })

  it('inactive note shows supervisor state, not error_message (real DTO has none)', async () => {
    render(<CollectControls typeKey="suricata" flavor="pull" instance={BACKOFF_INSTANCE} isActive={true} />)
    await waitFor(() => {
      const note = screen.getByTestId('pull-inactive')
      expect(note).toHaveTextContent('backoff')
      expect(note.textContent).not.toContain('SSH connection refused')
    })
  })
})

// ---------------------------------------------------------------------------
// Graceful degradation — 503 from getAutoSync (no supervisor)
// ---------------------------------------------------------------------------

describe('503 from getAutoSync — graceful degradation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('still renders pull-controls when getAutoSync returns 503 (no supervisor)', async () => {
    const { ApiError } = await import('../api/client')
    mockGetAutoSync.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))
    render(<CollectControls typeKey="suricata" flavor="pull" instance={null} />)
    // Should render pull-controls (graceful — not crash)
    await waitFor(() => {
      expect(screen.getByTestId('pull-controls')).toBeInTheDocument()
    })
    // No autosync-error shown for 503 (expected / graceful)
    expect(screen.queryByTestId('autosync-error')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// [NB-1c] interval bounds: client rejects < 30 and > 86400 before calling API
// ---------------------------------------------------------------------------

describe('[NB-1c] interval bounds — client rejects out-of-range values (when active)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Auto-sync is ON so interval is shown and blur persists
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_ENABLED)
  })

  it('shows interval-error for interval < 30 (below minimum)', async () => {
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('interval-input')).toBeInTheDocument()
    })

    const input = screen.getByTestId('interval-input') as HTMLInputElement
    await act(async () => {
      await user.clear(input)
      await user.type(input, '10')
      await user.tab() // blur → triggers validation + persistence attempt
    })

    await waitFor(() => {
      expect(screen.getByTestId('interval-error')).toBeInTheDocument()
    })
    // setAutoSync must NOT be called
    expect(mockSetAutoSync).not.toHaveBeenCalled()
  })

  it('shows interval-error for interval > 86400 (above maximum)', async () => {
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('interval-input')).toBeInTheDocument()
    })

    const input = screen.getByTestId('interval-input') as HTMLInputElement
    await act(async () => {
      await user.clear(input)
      await user.type(input, '999999')
      await user.tab()
    })

    await waitFor(() => {
      expect(screen.getByTestId('interval-error')).toBeInTheDocument()
    })
    expect(mockSetAutoSync).not.toHaveBeenCalled()
  })

  it('accepts valid interval (300 seconds, within 30–86400)', async () => {
    mockSetAutoSync.mockResolvedValue({ ...AUTOSYNC_ENABLED, interval_seconds: 300 })
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('interval-input')).toBeInTheDocument()
    })

    const input = screen.getByTestId('interval-input') as HTMLInputElement
    await act(async () => {
      await user.clear(input)
      await user.type(input, '300')
      await user.tab()
    })

    await waitFor(() => {
      expect(mockSetAutoSync).toHaveBeenCalled()
    })
    expect(screen.queryByTestId('interval-error')).not.toBeInTheDocument()
  })

  it('accepts boundary value 30 (minimum allowed)', async () => {
    mockSetAutoSync.mockResolvedValue({ ...AUTOSYNC_ENABLED, interval_seconds: 30 })
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('interval-input')).toBeInTheDocument()
    })

    const input = screen.getByTestId('interval-input') as HTMLInputElement
    await act(async () => {
      await user.clear(input)
      await user.type(input, '30')
      await user.tab()
    })

    await waitFor(() => {
      expect(mockSetAutoSync).toHaveBeenCalled()
    })
    expect(screen.queryByTestId('interval-error')).not.toBeInTheDocument()
  })

  it('accepts boundary value 86400 (maximum allowed)', async () => {
    mockSetAutoSync.mockResolvedValue({ ...AUTOSYNC_ENABLED, interval_seconds: 86400 })
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('interval-input')).toBeInTheDocument()
    })

    const input = screen.getByTestId('interval-input') as HTMLInputElement
    await act(async () => {
      await user.clear(input)
      await user.type(input, '86400')
      await user.tab()
    })

    await waitFor(() => {
      expect(mockSetAutoSync).toHaveBeenCalled()
    })
    expect(screen.queryByTestId('interval-error')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// #573 — Structured error envelope from backend (#569/PR #586)
// extractErrorMessage must surface the message ONCE (not tripled).
// HTTP 502 shape: { "detail": { "error": { "code": "SYNC_FAILED", "message": "…" } } }
// ---------------------------------------------------------------------------

describe('#573 — structured sync-error envelope rendered once', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
  })

  it('surfaces the message from { error: { code, message } } envelope once on sync failure', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockSyncSource.mockRejectedValue(
      new ApiError(502, { error: { code: 'SYNC_FAILED', message: 'WorkspaceNotFoundError: workspace abc not found' } }, 'Bad Gateway'),
    )

    render(<CollectControls typeKey="azure_waf" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await user.click(screen.getByTestId('btn-sync-now'))

    await waitFor(() => {
      const errEl = screen.getByTestId('sync-error')
      expect(errEl.textContent).toContain('WorkspaceNotFoundError')
      const occurrences = (errEl.textContent ?? '').split('WorkspaceNotFoundError').length - 1
      expect(occurrences).toBe(1)
    })
  })

  it('surfaces the message from double-wrapped { detail: { error: { code, message } } } once', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockSyncSource.mockRejectedValue(
      new ApiError(502, { detail: { error: { code: 'SYNC_FAILED', message: 'workspace not found' } } }, 'Bad Gateway'),
    )

    render(<CollectControls typeKey="azure_waf" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await user.click(screen.getByTestId('btn-sync-now'))

    await waitFor(() => {
      const errEl = screen.getByTestId('sync-error')
      expect(errEl.textContent).toContain('workspace not found')
      const occurrences = (errEl.textContent ?? '').split('workspace not found').length - 1
      expect(occurrences).toBe(1)
    })
  })

  it('falls back to generic error message when error shape is unrecognised', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockSyncSource.mockRejectedValue(
      new ApiError(500, null, 'Internal Server Error'),
    )

    render(<CollectControls typeKey="azure_waf" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await user.click(screen.getByTestId('btn-sync-now'))

    await waitFor(() => {
      const errEl = screen.getByTestId('sync-error')
      expect(errEl.textContent).toContain('failed')
    })
  })
})

// ---------------------------------------------------------------------------
// #744 — EARS-1/2/3: Sync-result message branches by events_ingested count
// ---------------------------------------------------------------------------

describe('#744 — EARS-1: 0 ingested events → success-styled "no new events" + hint', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
  })

  it('renders success-styled sync-result (not error-styled) when events_ingested=0', async () => {
    mockSyncSource.mockResolvedValue(SYNC_RESULT_ZERO)
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      const result = screen.getByTestId('sync-result')
      expect(result).toBeInTheDocument()
      // Must contain the reassuring zero-events label
      expect(result.textContent).toMatch(/no new events/i)
    })
  })

  it('does NOT apply error (destructive) styling when events_ingested=0', async () => {
    mockSyncSource.mockResolvedValue(SYNC_RESULT_ZERO)
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      const result = screen.getByTestId('sync-result')
      // Success classes must be present; destructive classes must be absent
      expect(result.className).toContain('border-green-300')
      expect(result.className).not.toContain('border-destructive')
    })
  })

  it('shows the explanatory hint when events_ingested=0', async () => {
    mockSyncSource.mockResolvedValue(SYNC_RESULT_ZERO)
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      const result = screen.getByTestId('sync-result')
      // Hint tells the operator why 0 is expected (rule-match-only + watermark semantics)
      expect(result.textContent).toMatch(/rule.*match|generate traffic/i)
    })
  })

  it('does NOT show "0 events ingested" text when events_ingested=0 (issue #744)', async () => {
    mockSyncSource.mockResolvedValue(SYNC_RESULT_ZERO)
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      const result = screen.getByTestId('sync-result')
      // The confusing "0 events ingested" phrasing must NOT appear
      expect(result.textContent).not.toMatch(/0 events ingested/i)
    })
  })
})

describe('#744 — EARS-2: ≥1 ingested events → existing "N events ingested" message', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
  })

  it('shows "N events ingested" when events_ingested > 0 (unchanged behaviour)', async () => {
    mockSyncSource.mockResolvedValue(SYNC_RESULT_OK) // events_ingested: 127
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      const result = screen.getByTestId('sync-result')
      expect(result.textContent).toContain('127')
      expect(result.textContent).toMatch(/events ingested/i)
    })
  })

  it('does NOT show "no new events" hint when events_ingested > 0', async () => {
    mockSyncSource.mockResolvedValue(SYNC_RESULT_OK)
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      const result = screen.getByTestId('sync-result')
      expect(result.textContent).not.toMatch(/no new events/i)
    })
  })
})

describe('#744 — EARS-3: sync failure → error message shown (no regression)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
  })

  it('shows sync-error element (not sync-result) when syncSource rejects', async () => {
    const { ApiError } = await import('../api/client')
    mockSyncSource.mockRejectedValue(new ApiError(502, { error: { code: 'SYNC_FAILED', message: 'SSH refused' } }, 'Bad Gateway'))
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('sync-error')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('sync-result')).not.toBeInTheDocument()
    // Error message surfaced (not swallowed)
    expect(screen.getByTestId('sync-error').textContent).toContain('SSH refused')
  })

  it('shows sync-result error banner when ok=false (result returned, not thrown)', async () => {
    mockSyncSource.mockResolvedValue({ ok: false, message: 'SSH connection refused', events_ingested: 0 })
    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      const result = screen.getByTestId('sync-result')
      expect(result).toBeInTheDocument()
      // Failure banner uses destructive styling
      expect(result.className).toContain('border-destructive')
      expect(result.textContent).toMatch(/sync failed/i)
    })
  })
})
