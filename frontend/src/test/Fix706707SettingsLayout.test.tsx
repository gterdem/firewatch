/**
 * Tests for issues #706 (Settings card layout) and #707 (sync feedback).
 *
 * EARS criteria covered:
 *
 * #706 — Layout:
 * [L-1] The grid container SHALL use minmax(0,1fr) for both columns so they
 *       are equal width regardless of card content.
 * [L-2] WHEN one card is expanded and its row-neighbor is collapsed, the
 *       collapsed card SHALL render at natural header-only height (not stretched).
 *       The grid SHALL use align-items:start (not stretch).
 * [L-3] The SourceCard section element SHALL NOT carry flex:1 / height:100%
 *       that would balloon a collapsed card to match an expanded row-neighbor.
 * [L-4] The card header's name slot SHALL carry min-width:0 so source_id +
 *       version metadata cannot overflow/overlap the display_name at any width.
 *
 * #707 — Sync feedback:
 * [SF-1] WHEN a manual Sync completes successfully, the card's "Last sync" /
 *        "Ingested" / "Status" fields SHALL reflect the just-completed sync
 *        WITHOUT a page reload.
 * [SF-2] The sync result SHALL be visible on the card immediately — not only
 *        via the delayed global toast.
 * [SF-3] A background getAutoSync re-fetch SHALL confirm the server-persisted
 *        state after the optimistic update.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SettingsList from '../components/SettingsList'
import CollectControls from '../components/sources/CollectControls'
import type { SourceTypeEntry } from '../schema/types'
import { SURICATA_SOURCE_ENTRY, MINIMAL_SOURCE_ENTRY } from './fixtures'
import {
  SOURCES_FIXTURE,
  AUTOSYNC_DISABLED,
  AUTOSYNC_ENABLED,
  SYNC_RESULT_OK,
} from './readFixtures'

// ---------------------------------------------------------------------------
// Shared mocks
// ---------------------------------------------------------------------------

const {
  mockFetchSources,
  mockGetAutoSync,
  mockSyncSource,
  mockTestSource,
  mockSetAutoSync,
} = vi.hoisted(() => ({
  mockFetchSources: vi.fn(),
  mockGetAutoSync: vi.fn(),
  mockSyncSource: vi.fn(),
  mockTestSource: vi.fn(),
  mockSetAutoSync: vi.fn(),
}))

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    fetchSourceConfig: vi.fn().mockResolvedValue({}),
    putSourceConfig: vi.fn().mockResolvedValue(undefined),
    fetchSourceTypes: vi.fn().mockResolvedValue([]),
  }
})

vi.mock('../api/sources', () => ({
  fetchSources: mockFetchSources,
  getAutoSync: mockGetAutoSync,
  setAutoSync: mockSetAutoSync,
  syncSource: mockSyncSource,
  testSource: mockTestSource,
}))

// ---------------------------------------------------------------------------
// #706 — Grid layout tests (SettingsList)
// ---------------------------------------------------------------------------

describe('#706 — Grid layout: equal columns + no collapsed-card balloon', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSources.mockResolvedValue([])
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
  })

  it('[L-1] settings-list grid uses minmax(0,1fr) for both columns', () => {
    const sources: SourceTypeEntry[] = [SURICATA_SOURCE_ENTRY, MINIMAL_SOURCE_ENTRY]
    render(<SettingsList sources={sources} loading={false} error={null} />)

    const grid = screen.getByTestId('settings-list')
    const cols = grid.style.gridTemplateColumns
    // Both columns must be minmax(0,1fr) — not plain '1fr' (which is minmax(auto,1fr))
    expect(cols).toContain('minmax(0, 1fr)')
    // Expect two occurrences (one per column)
    expect(cols.split('minmax(0, 1fr)').length - 1).toBe(2)
  })

  it('[L-2] settings-list grid uses align-items:start, not stretch', () => {
    const sources: SourceTypeEntry[] = [SURICATA_SOURCE_ENTRY]
    render(<SettingsList sources={sources} loading={false} error={null} />)

    const grid = screen.getByTestId('settings-list')
    expect(grid.style.alignItems).toBe('start')
  })

  it('[L-3] SourceCard section does NOT carry flex:1 that would stretch collapsed card', async () => {
    mockFetchSources.mockResolvedValue([])
    const sources: SourceTypeEntry[] = [SURICATA_SOURCE_ENTRY]
    render(<SettingsList sources={sources} loading={false} error={null} />)

    await waitFor(() => {
      expect(screen.getByTestId('source-card-suricata')).toBeInTheDocument()
    })

    const section = screen.getByTestId('source-card-suricata')
    // Must NOT have flex:1 — that was the #574 propagation removed by #706 fix
    expect(section.style.flex).not.toBe('1')
    expect(section.style.flex).not.toBe('1 1 0%') // computed form
  })

  it('[L-4] header name slot has min-width:0 on outer span to prevent overflow', async () => {
    mockFetchSources.mockResolvedValue([SOURCES_FIXTURE[0]])
    const sources: SourceTypeEntry[] = [SURICATA_SOURCE_ENTRY]
    render(<SettingsList sources={sources} loading={false} error={null} />)

    await waitFor(() => {
      expect(screen.getByTestId(`source-name-suricata`)).toBeInTheDocument()
    })

    // The display_name span should be present
    const nameSpan = screen.getByTestId('source-name-suricata')
    expect(nameSpan).toBeInTheDocument()

    // The source-id span should be present with truncation style
    const sourceIdSpan = screen.getByTestId('source-id-suricata')
    expect(sourceIdSpan).toBeInTheDocument()
    // It must have overflow:hidden and text-overflow:ellipsis so it never pushes
    // version off-screen or wraps in an uncontrolled way
    expect(sourceIdSpan.style.overflow).toBe('hidden')
    expect(sourceIdSpan.style.textOverflow).toBe('ellipsis')
    expect(sourceIdSpan.style.minWidth).toBe('0px')
  })

  it('[L-1] two sources render in a 2-column grid with equal minmax(0,1fr) columns', () => {
    const sources: SourceTypeEntry[] = [SURICATA_SOURCE_ENTRY, MINIMAL_SOURCE_ENTRY]
    render(<SettingsList sources={sources} loading={false} error={null} />)

    const grid = screen.getByTestId('settings-list')
    // Both cards must be present (2-column layout still active)
    expect(screen.getByTestId('source-card-suricata')).toBeInTheDocument()
    expect(screen.getByTestId('source-card-test_source')).toBeInTheDocument()
    // Grid columns must be equal
    expect(grid.style.gridTemplateColumns).toBe('minmax(0, 1fr) minmax(0, 1fr)')
  })
})

// ---------------------------------------------------------------------------
// #707 — Sync feedback: card updates immediately after sync POST
// ---------------------------------------------------------------------------

const PULL_INSTANCE = SOURCES_FIXTURE[0]

describe('#707 — Sync feedback: card Last-sync updates immediately', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
  })

  it('[SF-1] last-sync-at is updated immediately after successful sync (no page reload)', async () => {
    // Initially, last_sync shows null (never synced)
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
    mockSyncSource.mockResolvedValue(SYNC_RESULT_OK)
    // Background re-fetch returns the same-or-updated state
    mockGetAutoSync
      .mockResolvedValueOnce(AUTOSYNC_DISABLED) // initial mount fetch
      .mockResolvedValue(AUTOSYNC_ENABLED)       // background re-fetch after sync

    const user = userEvent.setup()
    render(
      <CollectControls
        typeKey="suricata"
        flavor="pull"
        instance={PULL_INSTANCE}
        isActive={true}
      />
    )

    // Wait for the control to mount and the initial getAutoSync to settle
    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })

    // Before sync: last-sync-info may not be present (AUTOSYNC_DISABLED has null last_sync_at)
    // The active-schedule-section is present because isActive=true
    expect(screen.getByTestId('active-schedule-section')).toBeInTheDocument()

    // Click Sync now
    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    // After sync: the sync result should appear
    await waitFor(() => {
      expect(screen.getByTestId('sync-result')).toBeInTheDocument()
    })
    expect(screen.getByTestId('sync-result')).toHaveTextContent('127')

    // The last-sync-info section should now show the update — last_sync_at is patched
    // from the optimistic update (timestamp = now) and last_sync_ingested = 127
    await waitFor(() => {
      expect(screen.getByTestId('last-sync-info')).toBeInTheDocument()
    })

    // last-sync-at must NOT be "Never" after a successful sync
    const lastSyncAt = screen.getByTestId('last-sync-at')
    expect(lastSyncAt.textContent).not.toBe('Never')
    expect(lastSyncAt.textContent?.trim().length).toBeGreaterThan(0)
  })

  it('[SF-1] last-sync-ingested reflects events_ingested from the sync response', async () => {
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
    mockSyncSource.mockResolvedValue({ ok: true, message: 'Sync complete.', events_ingested: 42 })
    mockGetAutoSync
      .mockResolvedValueOnce(AUTOSYNC_DISABLED)
      .mockResolvedValue(AUTOSYNC_DISABLED) // background re-fetch (no update from server yet)

    const user = userEvent.setup()
    render(
      <CollectControls
        typeKey="suricata"
        flavor="pull"
        instance={PULL_INSTANCE}
        isActive={true}
      />
    )

    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    // last-sync-info should appear with the optimistic ingested count
    await waitFor(() => {
      expect(screen.getByTestId('last-sync-info')).toBeInTheDocument()
    })
    const ingested = screen.getByTestId('last-sync-ingested')
    expect(ingested.textContent).toBe('42')
  })

  it('[SF-1] last-sync-status shows "ok" after a successful sync (no page reload)', async () => {
    mockGetAutoSync
      .mockResolvedValueOnce(AUTOSYNC_DISABLED)
      .mockResolvedValue(AUTOSYNC_DISABLED)
    mockSyncSource.mockResolvedValue(SYNC_RESULT_OK)

    const user = userEvent.setup()
    render(
      <CollectControls
        typeKey="suricata"
        flavor="pull"
        instance={PULL_INSTANCE}
        isActive={true}
      />
    )

    await waitFor(() => {
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('last-sync-info')).toBeInTheDocument()
    })
    const status = screen.getByTestId('last-sync-status')
    expect(status.textContent).toBe('ok')
  })

  it('[SF-2] sync-result (ingested count) is visible on the card immediately', async () => {
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_DISABLED)
    mockSyncSource.mockResolvedValue(SYNC_RESULT_OK)

    const user = userEvent.setup()
    render(
      <CollectControls
        typeKey="suricata"
        flavor="pull"
        instance={PULL_INSTANCE}
        isActive={true}
      />
    )

    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    // The per-card sync result (not just a global toast) must appear
    await waitFor(() => {
      expect(screen.getByTestId('sync-result')).toBeInTheDocument()
    })
    // Shows events_ingested inline (updated text per #738 sync-UX fix)
    expect(screen.getByTestId('sync-result')).toHaveTextContent('Synced — 127 events ingested')
  })

  it('[SF-3] background getAutoSync re-fetch is called after sync to confirm server state', async () => {
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_ENABLED)
    mockSyncSource.mockResolvedValue(SYNC_RESULT_OK)

    const user = userEvent.setup()
    render(
      <CollectControls
        typeKey="suricata"
        flavor="pull"
        instance={PULL_INSTANCE}
        isActive={true}
      />
    )

    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    const callsBefore = mockGetAutoSync.mock.calls.length

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    // getAutoSync should be called at least once more after the sync (the background re-fetch)
    await waitFor(() => {
      expect(mockGetAutoSync.mock.calls.length).toBeGreaterThan(callsBefore)
    })
  })

  it('[SF-1] last-sync-at is NOT still "Never" after a sync with events_ingested=0', async () => {
    mockGetAutoSync
      .mockResolvedValueOnce(AUTOSYNC_DISABLED)
      .mockResolvedValue(AUTOSYNC_DISABLED)
    mockSyncSource.mockResolvedValue({ ok: true, message: '0 new events.', events_ingested: 0 })

    const user = userEvent.setup()
    render(
      <CollectControls
        typeKey="suricata"
        flavor="pull"
        instance={PULL_INSTANCE}
        isActive={true}
      />
    )

    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('last-sync-info')).toBeInTheDocument()
    })
    // Should show a real timestamp (not "Never") even when 0 events ingested
    const lastSyncAt = screen.getByTestId('last-sync-at')
    expect(lastSyncAt.textContent).not.toBe('Never')
  })
})
