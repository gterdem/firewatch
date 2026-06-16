/**
 * Tests for issues #737 and #738 — Settings Active toggle + Sync-UX fixes.
 *
 * #737 (bugs 2a + 2b):
 *   - Tri-valued isActive loading → committed states (null → false / null → true)
 *   - Active toggle disabled with no committed aria-checked while loading (bug 2a fix)
 *   - isActive derived from auto_sync_enabled, not instance-presence (bug 2b fix)
 *   - Status text is "" (not "Off") while loading
 *   - SettingsList partition keyed on auto_sync_enabled
 *
 * #738 (bug 2c):
 *   - Sync in-progress affordance rendered while syncBusy=true
 *   - Sync button label changes to "Syncing…" while in flight
 *   - Terminal success: "Synced — N events ingested"
 *   - Terminal failure: error message surfaced
 *   - In-progress affordance clears on terminal state
 *
 * ADR-0062 Amendment 1 §1/§2/§4.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SourceCard from '../components/SourceCard'
import SettingsList from '../components/SettingsList'
import CollectControls from '../components/sources/CollectControls'
import { SURICATA_SOURCE_ENTRY, MINIMAL_SOURCE_ENTRY } from './fixtures'
import type { SourceTypeEntry } from '../schema/types'
import type { SourceInstance } from '../api/types'
import {
  SOURCES_FIXTURE,
  AUTOSYNC_DISABLED,
  AUTOSYNC_ENABLED,
  SYNC_RESULT_OK,
} from './readFixtures'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const {
  mockFetchSources,
  mockGetAutoSync,
  mockSetAutoSync,
  mockSyncSource,
  mockFetchSourceConfig,
  mockPutSourceConfig,
  mockFetchSourceActions,
} = vi.hoisted(() => ({
  mockFetchSources: vi.fn(),
  mockGetAutoSync: vi.fn(),
  mockSetAutoSync: vi.fn(),
  mockSyncSource: vi.fn(),
  mockFetchSourceConfig: vi.fn(),
  mockPutSourceConfig: vi.fn(),
  mockFetchSourceActions: vi.fn(),
}))

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
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
    ...actual,
    fetchSourceConfig: mockFetchSourceConfig,
    putSourceConfig: mockPutSourceConfig,
    ApiError,
    resolveBaseUrl: () => '',
    assertLoopbackBase: () => undefined,
    fetchStats: vi.fn().mockResolvedValue({ total_logs: 0, total_ips: 0, blocked_percentage: 0, source_health: [], last_updated: null }),
  }
})

vi.mock('../api/sources', () => ({
  fetchSources: mockFetchSources,
  testSource: vi.fn(),
  syncSource: mockSyncSource,
  getAutoSync: mockGetAutoSync,
  setAutoSync: mockSetAutoSync,
}))

vi.mock('../api/sourceActions', () => ({
  fetchSourceActions: mockFetchSourceActions,
  runSourceAction: vi.fn(),
}))

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Instance with auto_sync_enabled=true — pull loop is running. */
const ACTIVE_SURICATA: SourceInstance = {
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
  auto_sync_enabled: true,
}

/** Instance WITHOUT auto_sync_enabled — idle, never-enabled source (bug 2b scenario). */
const IDLE_SURICATA: SourceInstance = {
  source_type: 'suricata',
  source_id: 'suricata',
  flavor: 'pull',
  state: 'idle',
  attempt: 0,
  total_crashes: 0,
  total_dlq: 0,
  dropped_count: 0,
  last_success_at: null,
  event_count: 0,
  // auto_sync_enabled absent → treated as false (safe degrade per spec)
}

const PULL_INSTANCE = SOURCES_FIXTURE[0]

// ---------------------------------------------------------------------------
// #737 — Tri-valued isActive: loading state
// ---------------------------------------------------------------------------

describe('#737 — tri-valued isActive: loading affordance (bug 2a)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({ mode: 'local' })
    mockPutSourceConfig.mockResolvedValue(undefined)
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
    mockFetchSourceActions.mockResolvedValue([])
  })

  it('WHILE loading (GET /sources pending): Active toggle is disabled and has no committed aria-checked', async () => {
    // Never-resolving promise → loading state persists for the duration of this test
    let resolveNever!: () => void
    const neverResolves = new Promise<SourceInstance[]>((res) => { resolveNever = () => res([]) })
    mockFetchSources.mockReturnValue(neverResolves)

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    // Toggle must be in the DOM (it's in the header, always visible)
    const toggle = screen.getByTestId('active-toggle')
    expect(toggle).toBeInTheDocument()

    // WHILE loading: toggle MUST be disabled (no action possible)
    expect(toggle).toBeDisabled()

    // WHILE loading: NO committed aria-checked (neither "true" nor "false")
    // WAI-ARIA Switch loading pattern: omit aria-checked while state unknown
    expect(toggle).not.toHaveAttribute('aria-checked')

    // Label must show "Loading…" not a committed "Off" or "Active"
    const label = screen.getByTestId('active-toggle-label')
    expect(label).toHaveTextContent('Loading…')

    // Cleanup
    resolveNever()
  })

  it('ONCE loading resolves with no instance: aria-checked=false and label "Off"', async () => {
    mockFetchSources.mockResolvedValue([]) // no instance → auto_sync_enabled=false

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      const toggle = screen.getByTestId('active-toggle')
      expect(toggle).toHaveAttribute('aria-checked', 'false')
    })
    expect(screen.getByTestId('active-toggle-label')).toHaveTextContent('Off')
  })

  it('ONCE loading resolves with auto_sync_enabled=true: aria-checked=true and label "Active"', async () => {
    mockFetchSources.mockResolvedValue([ACTIVE_SURICATA])

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      const toggle = screen.getByTestId('active-toggle')
      expect(toggle).toHaveAttribute('aria-checked', 'true')
    })
    expect(screen.getByTestId('active-toggle-label')).toHaveTextContent('Active')
  })

  it('WHILE loading: status text is empty (no committed "Off" flicker)', async () => {
    // Keep the source fetch unresolved
    let resolveNever!: () => void
    const neverResolves = new Promise<SourceInstance[]>((res) => { resolveNever = () => res([]) })
    mockFetchSources.mockReturnValue(neverResolves)

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    // Status text must NOT show "Off" while loading
    const card = screen.getByTestId('source-card-suricata')
    expect(card.textContent).not.toContain('Off')

    resolveNever()
  })

  it('ONCE loading resolves with no instance: status text shows "Off"', async () => {
    mockFetchSources.mockResolvedValue([]) // no instance

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      const card = screen.getByTestId('source-card-suricata')
      expect(card.textContent).toContain('Off')
    })
  })

  it('defaultExpanded stays false while loading (null isActive → collapsed)', async () => {
    // Never-resolving fetch → isActive stays null
    const neverResolves = new Promise<SourceInstance[]>(() => {})
    mockFetchSources.mockReturnValue(neverResolves)

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    // Card must not be expanded while loading
    const card = screen.getByTestId('ds-source-card')
    expect(card.getAttribute('data-expanded')).toBe('false')
  })
})

// ---------------------------------------------------------------------------
// #737 — isActive derived from auto_sync_enabled (bug 2b fix)
// ---------------------------------------------------------------------------

describe('#737 — isActive derived from auto_sync_enabled, not instance-presence (bug 2b)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({ mode: 'local' })
    mockPutSourceConfig.mockResolvedValue(undefined)
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
    mockFetchSourceActions.mockResolvedValue([])
  })

  it('instance present but auto_sync_enabled absent → isActive=false (idle/never-enabled, bug 2b)', async () => {
    // Bug 2b: old code used inst !== null → would incorrectly show "Active"
    // New code: inst?.auto_sync_enabled ?? false → correctly shows "Off"
    mockFetchSources.mockResolvedValue([IDLE_SURICATA]) // instance present, no auto_sync_enabled

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      const toggle = screen.getByTestId('active-toggle')
      expect(toggle).toHaveAttribute('aria-checked', 'false')
    })
    expect(screen.getByTestId('active-toggle-label')).toHaveTextContent('Off')
  })

  it('instance present with auto_sync_enabled=true → isActive=true', async () => {
    mockFetchSources.mockResolvedValue([ACTIVE_SURICATA])

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      const toggle = screen.getByTestId('active-toggle')
      expect(toggle).toHaveAttribute('aria-checked', 'true')
    })
  })

  it('instance present with auto_sync_enabled=false → isActive=false', async () => {
    mockFetchSources.mockResolvedValue([{ ...ACTIVE_SURICATA, auto_sync_enabled: false }])

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      const toggle = screen.getByTestId('active-toggle')
      expect(toggle).toHaveAttribute('aria-checked', 'false')
    })
  })

  it('card stays collapsed when instance has no auto_sync_enabled (idle source)', async () => {
    mockFetchSources.mockResolvedValue([IDLE_SURICATA]) // instance present, no flag

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      // Once resolved, card should be collapsed (isActive=false)
      const card = screen.getByTestId('ds-source-card')
      expect(card.getAttribute('data-expanded')).toBe('false')
    })
  })

  it('card expands when auto_sync_enabled=true (bug 2b inverse)', async () => {
    mockFetchSources.mockResolvedValue([ACTIVE_SURICATA])

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      // Once resolved, card should be expanded (isActive=true)
      const card = screen.getByTestId('ds-source-card')
      expect(card.getAttribute('data-expanded')).toBe('true')
    })
  })
})

// ---------------------------------------------------------------------------
// #737 — SettingsList partition keyed on auto_sync_enabled
// ---------------------------------------------------------------------------

describe('#737 — SettingsList partition uses auto_sync_enabled (not instance-presence)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // SettingsList calls fetchSources; SourceCard also calls it — both use the mock.
    // Default: mock returns nothing; individual tests override as needed.
    mockFetchSources.mockResolvedValue([])
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
    mockFetchSourceConfig.mockResolvedValue({})
    mockFetchSourceActions.mockResolvedValue([])
  })

  it('source with auto_sync_enabled=true is classified active (card renders)', async () => {
    const activeInstance: SourceInstance = {
      ...ACTIVE_SURICATA,
      source_type: 'suricata',
      auto_sync_enabled: true,
    }
    mockFetchSources.mockResolvedValue([activeInstance])

    const sources: SourceTypeEntry[] = [SURICATA_SOURCE_ENTRY, MINIMAL_SOURCE_ENTRY]
    render(<SettingsList sources={sources} loading={false} error={null} />)

    // Both cards render — check they are present
    await waitFor(() => {
      expect(screen.getByTestId('source-card-suricata')).toBeInTheDocument()
      expect(screen.getByTestId('source-card-test_source')).toBeInTheDocument()
    })
  })

  it('source with auto_sync_enabled=false: card renders (inactive group)', async () => {
    const idleInstance: SourceInstance = {
      ...IDLE_SURICATA,
      auto_sync_enabled: false,
    }
    mockFetchSources.mockResolvedValue([idleInstance])

    const sources: SourceTypeEntry[] = [SURICATA_SOURCE_ENTRY]
    render(<SettingsList sources={sources} loading={false} error={null} />)

    await waitFor(() => {
      expect(screen.getByTestId('source-card-suricata')).toBeInTheDocument()
    })
    // Card should be present (inactive group still renders)
  })

  it('source with no instance → classified inactive (auto_sync_enabled absent)', async () => {
    mockFetchSources.mockResolvedValue([]) // no instances

    const sources: SourceTypeEntry[] = [SURICATA_SOURCE_ENTRY]
    render(<SettingsList sources={sources} loading={false} error={null} />)

    await waitFor(() => {
      expect(screen.getByTestId('source-card-suricata')).toBeInTheDocument()
    })
  })

  it('partition: idle instance (no auto_sync_enabled) sorts to inactive group, enabled instance sorts active', async () => {
    // Two sources: suricata (active), test_source (no instance → inactive)
    const activeInstance: SourceInstance = { ...ACTIVE_SURICATA, auto_sync_enabled: true }
    mockFetchSources.mockResolvedValue([activeInstance])
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_ENABLED)

    const sources: SourceTypeEntry[] = [MINIMAL_SOURCE_ENTRY, SURICATA_SOURCE_ENTRY]
    render(<SettingsList sources={sources} loading={false} error={null} />)

    await waitFor(() => {
      // Both cards must render regardless of partition
      expect(screen.getByTestId('source-card-suricata')).toBeInTheDocument()
      expect(screen.getByTestId('source-card-test_source')).toBeInTheDocument()
    })

    // The suricata card (active) should appear before test_source (inactive) in the DOM
    const cards = screen.getAllByTestId(/^source-card-/)
    const suricataIdx = cards.findIndex((c) => c.getAttribute('data-testid') === 'source-card-suricata')
    const testIdx = cards.findIndex((c) => c.getAttribute('data-testid') === 'source-card-test_source')
    expect(suricataIdx).toBeLessThan(testIdx)
  })
})

// ---------------------------------------------------------------------------
// #738 — Sync in-progress affordance and terminal states
// ---------------------------------------------------------------------------

describe('#738 — sync in-progress affordance (bug 2c)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
  })

  it('WHILE syncBusy: renders sync-in-progress affordance with role="status"', async () => {
    // Keep sync in flight
    let resolveSync!: (v: typeof SYNC_RESULT_OK) => void
    mockSyncSource.mockReturnValue(
      new Promise<typeof SYNC_RESULT_OK>((res) => { resolveSync = res }),
    )

    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    // While in flight: in-progress affordance must appear
    expect(screen.getByTestId('sync-in-progress')).toBeInTheDocument()
    expect(screen.getByTestId('sync-in-progress').getAttribute('role')).toBe('status')
    expect(screen.getByTestId('sync-in-progress').textContent).toMatch(/syncing now/i)

    // Cleanup
    await act(async () => { resolveSync(SYNC_RESULT_OK) })
  })

  it('WHILE syncBusy: button label changes to "Syncing…" and aria-busy is set', async () => {
    let resolveSync!: (v: typeof SYNC_RESULT_OK) => void
    mockSyncSource.mockReturnValue(
      new Promise<typeof SYNC_RESULT_OK>((res) => { resolveSync = res }),
    )

    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    const btn = screen.getByTestId('btn-sync-now')
    // Label must be "Syncing…" (not just "Sync now")
    expect(btn.textContent).toMatch(/syncing/i)
    // aria-busy must be true
    expect(btn.getAttribute('aria-busy')).toBe('true')

    // Cleanup
    await act(async () => { resolveSync(SYNC_RESULT_OK) })
  })

  it('AFTER successful sync: in-progress affordance clears and terminal result shows', async () => {
    mockSyncSource.mockResolvedValue(SYNC_RESULT_OK)

    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    // After completion: in-progress affordance must be gone
    await waitFor(() => {
      expect(screen.queryByTestId('sync-in-progress')).not.toBeInTheDocument()
    })

    // Terminal success state must show events ingested
    expect(screen.getByTestId('sync-result')).toBeInTheDocument()
    expect(screen.getByTestId('sync-result').textContent).toContain('127')
  })

  it('AFTER successful sync: terminal result includes "Synced" with events ingested count', async () => {
    mockSyncSource.mockResolvedValue({ ok: true, message: 'Sync complete.', events_ingested: 42 })

    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      const result = screen.getByTestId('sync-result')
      expect(result.textContent).toContain('42')
      expect(result.textContent).toMatch(/synced/i)
    })
  })

  it('AFTER failed sync: in-progress affordance clears and error shown', async () => {
    const { ApiError } = await import('../api/client')
    mockSyncSource.mockRejectedValue(
      new ApiError(502, { error: { code: 'SYNC_FAILED', message: 'SSH timeout' } }, 'Bad Gateway'),
    )

    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    // In-progress must clear on terminal state
    await waitFor(() => {
      expect(screen.queryByTestId('sync-in-progress')).not.toBeInTheDocument()
    })

    // Error must be surfaced
    expect(screen.getByTestId('sync-error')).toBeInTheDocument()
    expect(screen.getByTestId('sync-error').textContent).toContain('SSH timeout')
  })

  it('Sync button returns to "Sync now" label after completion', async () => {
    mockSyncSource.mockResolvedValue(SYNC_RESULT_OK)

    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    // After completion: button must return to "Sync now"
    await waitFor(() => {
      const btn = screen.getByTestId('btn-sync-now')
      expect(btn.textContent).toMatch(/sync now/i)
      expect(btn.getAttribute('aria-busy')).toBe('false')
    })
  })

  it('sync-in-progress affordance includes "can take" timing language', async () => {
    let resolveSync!: (v: typeof SYNC_RESULT_OK) => void
    mockSyncSource.mockReturnValue(
      new Promise<typeof SYNC_RESULT_OK>((res) => { resolveSync = res }),
    )

    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    const affordance = screen.getByTestId('sync-in-progress')
    // Must explain that the sync may take time (ADR-0062 §D / issue #738)
    expect(affordance.textContent).toMatch(/take/i)

    await act(async () => { resolveSync(SYNC_RESULT_OK) })
  })
})

// ---------------------------------------------------------------------------
// #738 — Last-sync info does not flip back to "Never" after a successful sync
// ---------------------------------------------------------------------------

describe('#738 — last-sync-info stays stable after optimistic patch', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('last-sync-at is populated after a successful sync (not flipped back to Never)', async () => {
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_ENABLED) // has real last_sync data
    mockSyncSource.mockResolvedValue({ ok: true, message: 'Sync complete.', events_ingested: 50 })

    const user = userEvent.setup()
    render(<CollectControls typeKey="suricata" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    // Wait for schedule section to appear (isActive=true)
    await waitFor(() => {
      expect(screen.getByTestId('active-schedule-section')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    // After sync: last-sync-at must be set and NOT "Never"
    await waitFor(() => {
      const lastSyncAt = screen.getByTestId('last-sync-at')
      expect(lastSyncAt.textContent).not.toBe('Never')
      expect(lastSyncAt.textContent).not.toBe('—')
    })
  })
})
