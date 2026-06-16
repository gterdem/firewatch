/**
 * Tests for issue #491 — parked/offline recovery banner (R7, UT-15/UT-16).
 *
 * EARS acceptance criteria mapped to tests:
 *
 * State-driven (parked/backoff/error → recovery banner at TOP of card body):
 *   TC-1  WHILE state="parked"  → ParkedRecoveryBanner renders in card body
 *   TC-2  WHILE state="backoff" → ParkedRecoveryBanner renders in card body
 *   TC-3  WHILE state="error"   → ParkedRecoveryBanner renders in card body
 *   TC-4  WHILE state="running" → ParkedRecoveryBanner NOT rendered
 *   TC-5  WHILE no instance     → ParkedRecoveryBanner NOT rendered
 *   TC-6  State label: "parked" → "Paused"; "backoff" → "In backoff"; "error" → "Error"
 *
 * Event-driven ("Why?" reveals SourceDiagnosticsPanel):
 *   TC-7  WHEN "Why?" clicked → diagnosticsPanel scrolled into view (scrollIntoView called)
 *   TC-8  SourceDiagnosticsPanel still renders in the card when instance is parked
 *
 * Event-driven (Sync now → ADR-0023 §D unpark):
 *   TC-9  WHEN "Sync now to resume" clicked → syncSource called with correct args
 *   TC-10 WHEN sync succeeds → success feedback shown; button re-enabled
 *   TC-11 WHEN sync fails    → error feedback shown as text (never innerHTML)
 *
 * Ubiquitous (modularity — driven by instance.state, no per-source branching):
 *   TC-12 Banner renders for a generic source fixture (not just suricata) with parked state
 *   TC-13 No per-source-type code: banner driven by instance.state only
 *
 * Supervisor offline — one notice per card, with recovery hint (UT-15/UT-16):
 *   TC-14 WHILE supervisorOffline=true → source-actions-offline badge present ONCE per card
 *   TC-15 WHILE supervisorOffline=true → ParkedRecoveryBanner NOT rendered (no instance loaded)
 *   TC-16 SupervisorOfflineBanner → recovery hint paragraph present
 *   TC-17 SupervisorOfflineBanner → "Retry now" button present
 *   TC-18 SupervisorOfflineBanner → renders nothing when online/unknown (regression guard)
 *
 * Security:
 *   TC-19 syncError text is rendered as a text node — never via dangerouslySetInnerHTML
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SourceCard from '../components/SourceCard'
import SupervisorOfflineBanner from '../components/SupervisorOfflineBanner'
import { SURICATA_SOURCE_ENTRY, MINIMAL_SOURCE_ENTRY } from './fixtures'
import type { SourceInstance } from '../api/types'
import type { SupervisorStatus } from '../hooks/useSupervisorGate'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const PARKED_INSTANCE: SourceInstance = {
  source_type: 'suricata',
  source_id: 'vm-target',
  flavor: 'pull',
  state: 'parked',
  attempt: 5,
  total_crashes: 3,
  total_dlq: 1,
  dropped_count: 0,
  last_success_at: '2026-06-10T08:00:00Z',
  event_count: 200,
  last_sync_at: 1749600000,
  last_sync_ingested: 0,
  last_sync_status: 'error',
  last_error: 'Max retries exceeded',
  // ADR-0062 A1 §1: source was enabled before it entered recovery state (#737 fix)
  auto_sync_enabled: true,
}

const BACKOFF_INSTANCE: SourceInstance = {
  ...PARKED_INSTANCE,
  state: 'backoff',
  attempt: 3,
  last_error: 'Connection refused to 10.0.0.1:22',
}

const ERROR_INSTANCE: SourceInstance = {
  ...PARKED_INSTANCE,
  state: 'error',
  last_error: 'Authentication failed',
}

const RUNNING_INSTANCE: SourceInstance = {
  ...PARKED_INSTANCE,
  state: 'running',
  attempt: 0,
  last_error: null,
  last_sync_status: 'ok',
}

const XSS_ERROR_INSTANCE: SourceInstance = {
  ...PARKED_INSTANCE,
  state: 'parked',
  last_error: '<script>alert("xss")</script>',
}

// ---------------------------------------------------------------------------
// vi.hoisted mocks
// ---------------------------------------------------------------------------

const {
  mockFetchSources,
  mockGetAutoSync,
  mockFetchSourceConfig,
  mockFetchSourceActions,
  mockSyncSource,
} = vi.hoisted(() => ({
  mockFetchSources: vi.fn(),
  mockGetAutoSync: vi.fn(),
  mockFetchSourceConfig: vi.fn(),
  mockFetchSourceActions: vi.fn(),
  mockSyncSource: vi.fn(),
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
  syncSource: mockSyncSource,
  getAutoSync: mockGetAutoSync,
  setAutoSync: vi.fn(),
}))

vi.mock('../api/sourceActions', () => ({
  fetchSourceActions: mockFetchSourceActions,
  runSourceAction: vi.fn(),
}))

// ---------------------------------------------------------------------------
// Shared beforeEach
// ---------------------------------------------------------------------------

function setupDefaults() {
  vi.clearAllMocks()
  mockFetchSourceConfig.mockResolvedValue({ mode: 'local' })
  mockGetAutoSync.mockResolvedValue({
    enabled: false,
    interval_seconds: 300,
    source_id: 'suricata',
    last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
  })
  mockFetchSourceActions.mockResolvedValue([])
  mockSyncSource.mockResolvedValue({ ok: true, events_ingested: 5 })
}

// ---------------------------------------------------------------------------
// TC-1 through TC-6: State-driven banner rendering
// ---------------------------------------------------------------------------

describe('SourceCard #491 — ParkedRecoveryBanner state-driven rendering', () => {
  beforeEach(setupDefaults)

  // TC-1: parked state → banner renders
  it('TC-1: renders ParkedRecoveryBanner when instance.state is "parked"', async () => {
    mockFetchSources.mockResolvedValue([PARKED_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-banner')).toBeInTheDocument()
    })
  })

  // TC-2: backoff state → banner renders
  it('TC-2: renders ParkedRecoveryBanner when instance.state is "backoff"', async () => {
    mockFetchSources.mockResolvedValue([BACKOFF_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-banner')).toBeInTheDocument()
    })
  })

  // TC-3: error state → banner renders
  it('TC-3: renders ParkedRecoveryBanner when instance.state is "error"', async () => {
    mockFetchSources.mockResolvedValue([ERROR_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-banner')).toBeInTheDocument()
    })
  })

  // TC-4: running (healthy) state → NO banner
  it('TC-4: does NOT render ParkedRecoveryBanner when instance.state is "running"', async () => {
    mockFetchSources.mockResolvedValue([RUNNING_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      // Wait for the instance fetch to settle — controls should be present
      expect(screen.getByTestId('collect-controls')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('parked-recovery-banner')).not.toBeInTheDocument()
  })

  // TC-5: no instance → NO banner
  // ADR-0062: card starts collapsed when inactive (no instance). The banner
  // lives in the card body — hidden when collapsed. We wait for the card shell
  // (always visible) and then assert the banner is absent.
  it('TC-5: does NOT render ParkedRecoveryBanner when no instance is available', async () => {
    mockFetchSources.mockResolvedValue([])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    // Wait for the card shell (header always visible, even when body is collapsed)
    await waitFor(() => {
      expect(screen.getByTestId('ds-source-card')).toBeInTheDocument()
    })
    // Banner is in the body — not rendered when card is collapsed (no instance)
    expect(screen.queryByTestId('parked-recovery-banner')).not.toBeInTheDocument()
  })

  // TC-6: state label text is human-readable
  it('TC-6a: banner shows "Paused" label for parked state', async () => {
    mockFetchSources.mockResolvedValue([PARKED_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-state-label')).toHaveTextContent('Paused')
    })
  })

  it('TC-6b: banner shows "In backoff" label for backoff state', async () => {
    mockFetchSources.mockResolvedValue([BACKOFF_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-state-label')).toHaveTextContent('In backoff')
    })
  })

  it('TC-6c: banner shows "Error" label for error state', async () => {
    mockFetchSources.mockResolvedValue([ERROR_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-state-label')).toHaveTextContent('Error')
    })
  })

  // Banner data-instance-state attribute carries the raw state for testing
  it('banner carries data-instance-state attribute matching instance.state', async () => {
    mockFetchSources.mockResolvedValue([PARKED_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-banner')).toHaveAttribute('data-instance-state', 'parked')
    })
  })

  // Banner renders ABOVE the config form (before SourceConfigForm in the DOM)
  it('banner appears before the config form in the DOM (top of card body)', async () => {
    mockFetchSources.mockResolvedValue([PARKED_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      const banner = screen.getByTestId('parked-recovery-banner')
      const form = screen.getByTestId('source-config-form-suricata')
      // compareDocumentPosition: 4 = banner comes before form
      expect(banner.compareDocumentPosition(form) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    })
  })
})

// ---------------------------------------------------------------------------
// TC-7, TC-8: Event-driven — "Why?" reveals SourceDiagnosticsPanel
// ---------------------------------------------------------------------------

describe('SourceCard #491 — "Why?" button reveals diagnostics panel', () => {
  beforeEach(setupDefaults)

  // TC-7: "Why?" scrolls diagnostics into view
  it('TC-7: clicking "Why?" scrolls SourceDiagnosticsPanel into view', async () => {
    const user = userEvent.setup()
    const scrollMock = vi.fn()
    window.HTMLElement.prototype.scrollIntoView = scrollMock

    mockFetchSources.mockResolvedValue([PARKED_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-why')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('parked-recovery-why'))
    })

    expect(scrollMock).toHaveBeenCalled()
  })

  // TC-8: SourceDiagnosticsPanel still renders when instance is parked
  it('TC-8: SourceDiagnosticsPanel is present in the card when instance is parked', async () => {
    mockFetchSources.mockResolvedValue([PARKED_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('diagnostics-panel')).toBeInTheDocument()
    })
  })

  // The "Why?" button and the health-dot trigger both use the same scroll target
  it('"Why?" and health-dot trigger both scroll to the same diagnostics node', async () => {
    const user = userEvent.setup()
    const scrollMock = vi.fn()
    window.HTMLElement.prototype.scrollIntoView = scrollMock

    mockFetchSources.mockResolvedValue([PARKED_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-why')).toBeInTheDocument()
      expect(screen.getByTestId('health-dot-diagnostics-trigger')).toBeInTheDocument()
    })

    // Click "Why?"
    await act(async () => {
      await user.click(screen.getByTestId('parked-recovery-why'))
    })
    const callsAfterWhy = scrollMock.mock.calls.length
    expect(callsAfterWhy).toBeGreaterThan(0)

    // Click health-dot trigger
    await act(async () => {
      await user.click(screen.getByTestId('health-dot-diagnostics-trigger'))
    })
    expect(scrollMock.mock.calls.length).toBeGreaterThan(callsAfterWhy)
  })
})

// ---------------------------------------------------------------------------
// TC-9 through TC-11: Sync now → ADR-0023 §D unpark
// ---------------------------------------------------------------------------

describe('SourceCard #491 — "Sync now to resume" fires syncSource', () => {
  beforeEach(setupDefaults)

  // TC-9: "Sync now to resume" calls syncSource with correct args
  it('TC-9: clicking "Sync now to resume" calls syncSource with typeKey and source_id', async () => {
    const user = userEvent.setup()
    mockFetchSources.mockResolvedValue([PARKED_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('parked-recovery-sync-now'))
    })

    await waitFor(() => {
      expect(mockSyncSource).toHaveBeenCalledWith('suricata', 'vm-target')
    })
  })

  // TC-10: sync success → success feedback shown
  it('TC-10: shows success feedback after successful sync', async () => {
    const user = userEvent.setup()
    mockFetchSources.mockResolvedValue([PARKED_INSTANCE])
    mockSyncSource.mockResolvedValue({ ok: true, events_ingested: 3 })
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('parked-recovery-sync-now'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-sync-ok')).toBeInTheDocument()
    })
    expect(screen.getByTestId('parked-recovery-sync-ok').textContent).toMatch(/resuming/i)
  })

  // TC-11: sync failure → error feedback as text node
  it('TC-11: shows error feedback as text node when sync fails', async () => {
    const { ApiError } = await import('../api/client')
    const user = userEvent.setup()
    mockFetchSources.mockResolvedValue([PARKED_INSTANCE])
    mockSyncSource.mockRejectedValue(new ApiError(500, { detail: 'Internal server error' }))
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('parked-recovery-sync-now'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-sync-err')).toBeInTheDocument()
    })
    // Error is rendered as a text node — verify it's not an empty element
    const errEl = screen.getByTestId('parked-recovery-sync-err')
    expect(errEl.textContent).toBeTruthy()
    // No <script> elements injected (security: text-node only)
    expect(errEl.querySelector('script')).toBeNull()
  })

  // Button is disabled (aria-busy) while sync is in progress
  it('sync button is disabled with aria-busy while sync is in progress', async () => {
    const user = userEvent.setup()
    mockFetchSources.mockResolvedValue([PARKED_INSTANCE])
    // Never resolves to keep the button in busy state
    mockSyncSource.mockReturnValue(new Promise(() => {}))
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-sync-now')).toBeInTheDocument()
    })

    const btn = screen.getByTestId('parked-recovery-sync-now')
    expect(btn).not.toBeDisabled()

    await act(async () => {
      await user.click(btn)
    })

    expect(btn).toBeDisabled()
    expect(btn).toHaveAttribute('aria-busy', 'true')
  })
})

// ---------------------------------------------------------------------------
// TC-12, TC-13: Ubiquitous (modularity — no per-source branching)
// ---------------------------------------------------------------------------

describe('SourceCard #491 — modularity: banner driven by state, not source type', () => {
  beforeEach(setupDefaults)

  // TC-12: banner renders for a generic (non-suricata) source fixture
  it('TC-12: banner renders for a generic push source fixture (modularity)', async () => {
    const genericParkedInstance: SourceInstance = {
      source_type: 'test_source',  // MINIMAL_SOURCE_ENTRY.type_key
      source_id: 'test-source',
      flavor: 'push',
      state: 'parked',
      attempt: 2,
      total_crashes: 1,
      total_dlq: 0,
      dropped_count: 0,
      last_success_at: null,
      event_count: 0,
      last_sync_at: null,
      last_sync_ingested: 0,
      last_sync_status: 'error',
      last_error: 'Connection refused',
      // ADR-0062 A1 §1: source was enabled before entering recovery (#737 fix)
      auto_sync_enabled: true,
    }
    mockFetchSources.mockResolvedValue([genericParkedInstance])
    mockFetchSourceConfig.mockResolvedValue({ host: 'localhost', api_key: null })
    render(<SourceCard source={MINIMAL_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-banner')).toBeInTheDocument()
    })
    // data-instance-state must match — driven by state, not source type
    expect(screen.getByTestId('parked-recovery-banner')).toHaveAttribute('data-instance-state', 'parked')
  })

  // TC-13: NO per-source-type text in the banner — completely generic
  it('TC-13: banner copy is generic — does not contain any source type_key text', async () => {
    mockFetchSources.mockResolvedValue([PARKED_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      const banner = screen.getByTestId('parked-recovery-banner')
      // Banner must NOT contain the source type_key or display_name
      // (that would be per-source branching — forbidden by ADR-0010)
      expect(banner.textContent).not.toContain('suricata')
      expect(banner.textContent).not.toContain('Suricata IDS/IPS')
    })
  })
})

// ---------------------------------------------------------------------------
// TC-14, TC-15: Supervisor offline — one notice per card (UT-16)
// ---------------------------------------------------------------------------

describe('SourceCard #491 — supervisor offline: ONE notice per card (UT-16)', () => {
  beforeEach(setupDefaults)

  // TC-14: supervisorOffline=true → source-actions-offline badge present (once)
  it('TC-14: supervisorOffline=true renders source-actions-offline badge', () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} supervisorOffline={true} />)
    const badges = screen.queryAllByTestId('source-actions-offline')
    expect(badges).toHaveLength(1)
    expect(badges[0]).toBeInTheDocument()
  })

  // TC-15: supervisorOffline=true → NO ParkedRecoveryBanner (no instance loaded)
  it('TC-15: supervisorOffline=true does not show ParkedRecoveryBanner (instance not loaded)', () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} supervisorOffline={true} />)
    expect(screen.queryByTestId('parked-recovery-banner')).not.toBeInTheDocument()
  })

  // When offline, fetchSources is NOT called (fan-out suppressed per issue #315)
  it('supervisorOffline=true suppresses fetchSources call', async () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} supervisorOffline={true} />)
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50))
    })
    expect(mockFetchSources).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// TC-16 through TC-18: SupervisorOfflineBanner with recovery hint (UT-15)
// ---------------------------------------------------------------------------

describe('SupervisorOfflineBanner #491 — recovery hint (UT-15)', () => {
  // TC-16: recovery hint paragraph is present when offline
  it('TC-16: shows recovery hint when supervisorStatus is "offline"', () => {
    render(
      <SupervisorOfflineBanner
        supervisorStatus="offline"
        retryCountdown={5}
        onRetryNow={vi.fn()}
      />,
    )
    expect(screen.getByTestId('supervisor-offline-recovery-hint')).toBeInTheDocument()
  })

  // TC-17: Retry now button is present when offline
  it('TC-17: shows "Retry now" button when offline', () => {
    render(
      <SupervisorOfflineBanner
        supervisorStatus="offline"
        retryCountdown={0}
        onRetryNow={vi.fn()}
      />,
    )
    expect(screen.getByTestId('supervisor-retry-now')).toBeInTheDocument()
  })

  // TC-16 additional: recovery hint copy mentions "supervisor" for diagnosis
  it('recovery hint text mentions "supervisor" so operator knows what to restart', () => {
    render(
      <SupervisorOfflineBanner
        supervisorStatus="offline"
        retryCountdown={0}
        onRetryNow={vi.fn()}
      />,
    )
    const hint = screen.getByTestId('supervisor-offline-recovery-hint')
    expect(hint.textContent?.toLowerCase()).toMatch(/supervisor/)
  })

  // TC-16 additional: recovery hint tells operator that config editing still works
  it('recovery hint confirms source configuration is still editable', () => {
    render(
      <SupervisorOfflineBanner
        supervisorStatus="offline"
        retryCountdown={0}
        onRetryNow={vi.fn()}
      />,
    )
    const hint = screen.getByTestId('supervisor-offline-recovery-hint')
    expect(hint.textContent?.toLowerCase()).toMatch(/edit|configur/)
  })

  // TC-18: no recovery hint when online (regression guard — banner doesn't render at all)
  it('TC-18: does not render banner (or hint) when supervisorStatus is "online"', () => {
    render(
      <SupervisorOfflineBanner
        supervisorStatus="online"
        retryCountdown={0}
        onRetryNow={vi.fn()}
      />,
    )
    expect(screen.queryByTestId('supervisor-offline-banner')).not.toBeInTheDocument()
    expect(screen.queryByTestId('supervisor-offline-recovery-hint')).not.toBeInTheDocument()
  })

  // TC-18b: no banner when unknown
  it('TC-18b: does not render banner when supervisorStatus is "unknown"', () => {
    const statuses: SupervisorStatus[] = ['online', 'unknown']
    statuses.forEach((status) => {
      const { unmount } = render(
        <SupervisorOfflineBanner supervisorStatus={status} retryCountdown={0} onRetryNow={vi.fn()} />,
      )
      expect(screen.queryByTestId('supervisor-offline-banner')).not.toBeInTheDocument()
      unmount()
    })
  })

  // Existing contract: countdown shown when > 0
  it('still shows countdown when retryCountdown > 0', () => {
    render(
      <SupervisorOfflineBanner
        supervisorStatus="offline"
        retryCountdown={12}
        onRetryNow={vi.fn()}
      />,
    )
    expect(screen.getByTestId('supervisor-retry-countdown').textContent).toBe('12s')
  })

  // Existing contract: onRetryNow fires on button click
  it('onRetryNow fires when "Retry now" is clicked', async () => {
    const user = userEvent.setup()
    const onRetryNow = vi.fn()
    render(
      <SupervisorOfflineBanner
        supervisorStatus="offline"
        retryCountdown={5}
        onRetryNow={onRetryNow}
      />,
    )
    await user.click(screen.getByTestId('supervisor-retry-now'))
    expect(onRetryNow).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// TC-19: Security — syncError rendered as text node (not innerHTML)
// ---------------------------------------------------------------------------

describe('ParkedRecoveryBanner #491 — security: error text is XSS-safe', () => {
  beforeEach(setupDefaults)

  // TC-19: XSS payload in sync error rendered as escaped text, not live HTML
  it('TC-19: syncError with HTML tags is rendered as escaped text — not live HTML', async () => {
    const { ApiError } = await import('../api/client')
    const user = userEvent.setup()
    mockFetchSources.mockResolvedValue([PARKED_INSTANCE])
    mockSyncSource.mockRejectedValue(
      new ApiError(500, { detail: '<script>alert("xss")</script>' }),
    )
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('parked-recovery-sync-now'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-sync-err')).toBeInTheDocument()
    })

    const errEl = screen.getByTestId('parked-recovery-sync-err')
    // Text content includes the raw tag (escaped, not executed)
    expect(errEl.textContent).toContain('<script>')
    // No live <script> child element
    expect(errEl.querySelector('script')).toBeNull()
    // Whole document has no injected scripts
    expect(document.querySelectorAll('script[src]').length).toBe(0)
  })

  // last_error content in the XSS_ERROR_INSTANCE fixture is NOT rendered by ParkedRecoveryBanner
  // (that's the diagnostics panel's job). But verifying the banner itself does not expose last_error.
  it('ParkedRecoveryBanner does not render last_error in its own body', async () => {
    mockFetchSources.mockResolvedValue([XSS_ERROR_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('parked-recovery-banner')).toBeInTheDocument()
    })
    const banner = screen.getByTestId('parked-recovery-banner')
    // last_error value must NOT appear in the banner body (it belongs in the diagnostics panel)
    expect(banner.textContent).not.toContain('<script>')
    expect(banner.querySelector('script')).toBeNull()
  })
})
