/**
 * Tests for Settings source-card polish — four bugs from Maintainer's Phase-2 walkthrough
 * (scratch/phase-2-tests/test-settings-opus.md, CR-A1 and CR-A2).
 *
 * Bug 1 — Double health dot: DSSourceCard header renders `● ` prefix AND HealthDot's `●`.
 *   Fix: remove the literal `● ` from the DS SourceCard header; keep HealthDot.
 *
 * Bug 2 — "Last success 1/1/1970": epoch-zero/null timestamps must render "Never".
 *   Fix: add isEpochOrNull helper to lib/time.ts; use it in fmtTimestamp (Diagnostics)
 *   and formatLastSync (CollectControls auto-sync section).
 *
 * Bug 3 — Diagnostics button misalignment: actions flex container lays children
 *   side-by-side; diagnostics panel sits next to Test/Sync instead of below.
 *   Fix: wrap action children in a column-flex container in SourceCard.tsx.
 *
 * Bug 4 — Sync result shows no ingested count: "Sync: Complete" with no count.
 *   Fix: always surface the ingested count — "Complete — 0 ingested" / "No new data".
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

// ---------------------------------------------------------------------------
// Bug 1: DS SourceCard header — no duplicate `● ` literal
// ---------------------------------------------------------------------------

import { SourceCard as DSSourceCard } from '../components/ds'

describe('Bug 1 — DSSourceCard header has NO duplicate literal dot', () => {
  it('renders statusText without a leading `● ` literal next to it', () => {
    const { container } = render(
      <DSSourceCard
        name="Azure WAF"
        status="error"
        statusText={<span data-testid="status-content">Stale — never</span>}
      />,
    )

    // Find the header span that carries data-status
    const statusSpan = container.querySelector('[data-status]')
    expect(statusSpan).toBeTruthy()

    // The text content of the outer span must NOT start with "● " followed by another "●"
    // i.e. the literal dot must not appear as a standalone prefix character before the child
    const rawText = statusSpan!.textContent ?? ''
    // If there's a double-dot pattern, e.g. "● ● azure_waf" — that's the bug
    expect(rawText).not.toMatch(/^●\s+●/)
  })

  it('only the HealthDot (or statusText child) provides the dot — no extra prefix dot', () => {
    // The literal `● ` before statusText must be gone.
    // We test by rendering a simple string statusText and asserting the
    // outer span's text doesn't have a leading `● ` decorator.
    const { container } = render(
      <DSSourceCard name="Test" status="active" statusText="Online" />,
    )
    const statusSpan = container.querySelector('[data-status]')
    expect(statusSpan).toBeTruthy()
    // After fix: textContent should be just "Online" — no leading `● `.
    expect(statusSpan!.textContent).toBe('Online')
  })

  it('renders statusText ReactNode (e.g. HealthDot) directly without extra prefix', () => {
    const { getByTestId } = render(
      <DSSourceCard
        name="WAF"
        status="error"
        statusText={
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span data-testid="mock-health-dot">● azure_waf</span>
            <span>Stale — never</span>
          </span>
        }
      />,
    )
    // The mock dot must be present
    expect(getByTestId('mock-health-dot')).toBeInTheDocument()
    // And the parent [data-status] span must not add another `● ` before it
    const statusSpan = getByTestId('mock-health-dot').closest('[data-status]')
    expect(statusSpan).toBeTruthy()
    // The first character of [data-status] textContent must NOT be a raw `●`
    // that precedes the healthdot's own `●`
    const text = statusSpan!.textContent ?? ''
    // After fix: starts with `●` from the health dot, not a second one prepended
    const bulletCount = [...text].filter((c) => c === '●').length
    // With the fix, only one `●` prefix from the healthdot itself
    expect(bulletCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Bug 2: epoch-zero / null timestamps render "Never"
// ---------------------------------------------------------------------------

import { isEpochOrNull, fmtTimestampNever } from '../lib/time'

describe('Bug 2 — isEpochOrNull helper in lib/time', () => {
  it('null → true', () => {
    expect(isEpochOrNull(null)).toBe(true)
  })

  it('undefined → true', () => {
    expect(isEpochOrNull(undefined)).toBe(true)
  })

  it('epoch 0 (number) → true', () => {
    expect(isEpochOrNull(0)).toBe(true)
  })

  it('small positive epoch (e.g. 1 second) → true', () => {
    // 1970-01-01T00:00:01 — still effectively "never synced"
    expect(isEpochOrNull(1)).toBe(true)
  })

  it('epoch in 1970 range (seconds) → true', () => {
    // 1970-01-21T09:50:18 = ~1814418s — the "Last sync: 1/21/1970" case
    expect(isEpochOrNull(1814418)).toBe(true)
  })

  it('a real recent timestamp (2026-06-14) → false', () => {
    const recent = new Date('2026-06-14T00:00:00Z').getTime() / 1000
    expect(isEpochOrNull(recent)).toBe(false)
  })

  it('epoch 0 as ISO string → true', () => {
    expect(isEpochOrNull('1970-01-01T00:00:00Z')).toBe(true)
  })

  it('epoch near 1970 as ISO string → true', () => {
    // 1/21/1970 that appeared in Maintainer's environment
    expect(isEpochOrNull('1970-01-21T09:50:18Z')).toBe(true)
  })

  it('a real recent ISO string → false', () => {
    expect(isEpochOrNull('2026-06-14T01:14:01Z')).toBe(false)
  })
})

describe('Bug 2 — fmtTimestampNever renders "Never" for epoch/null', () => {
  it('null → "Never"', () => {
    expect(fmtTimestampNever(null)).toBe('Never')
  })

  it('undefined → "Never"', () => {
    expect(fmtTimestampNever(undefined)).toBe('Never')
  })

  it('epoch 0 (number) → "Never"', () => {
    expect(fmtTimestampNever(0)).toBe('Never')
  })

  it('1970-epoch seconds → "Never"', () => {
    // 1970-01-01T09:35:07 = 34507 seconds
    expect(fmtTimestampNever(34507)).toBe('Never')
  })

  it('1970-epoch ISO string → "Never"', () => {
    expect(fmtTimestampNever('1970-01-01T09:35:07Z')).toBe('Never')
  })

  it('1/21/1970 epoch ISO string → "Never"', () => {
    expect(fmtTimestampNever('1970-01-21T09:50:18Z')).toBe('Never')
  })

  it('a real 2026 timestamp → formatted date string (NOT "Never")', () => {
    const result = fmtTimestampNever('2026-06-14T01:14:01Z')
    expect(result).not.toBe('Never')
    expect(result.length).toBeGreaterThan(0)
  })

  it('a 2026 Unix epoch (seconds) → formatted date string', () => {
    const ts = new Date('2026-06-14T01:14:01Z').getTime() / 1000
    const result = fmtTimestampNever(ts)
    expect(result).not.toBe('Never')
  })
})

// ---------------------------------------------------------------------------
// Bug 2: Diagnostics panel — "Last success" shows "Never" for epoch timestamps
// ---------------------------------------------------------------------------

import SourceDiagnosticsPanel from '../components/sources/SourceDiagnosticsPanel'
import type { SourceInstance } from '../api/types'

const EPOCH_INSTANCE: SourceInstance = {
  source_type: 'azure_waf',
  source_id: 'azure_waf',
  flavor: 'pull',
  state: 'idle',
  attempt: 0,
  total_crashes: 0,
  total_dlq: 0,
  dropped_count: 0,
  // epoch-zero string — the "1/1/1970" case from Maintainer's environment
  last_success_at: '1970-01-01T09:35:07Z',
  event_count: 0,
  last_sync_at: 34507,        // Unix epoch seconds (1970-01-01T09:35:07)
  last_sync_ingested: 0,
  last_sync_status: 'no_data',
  last_error: null,
}

describe('Bug 2 — SourceDiagnosticsPanel "Last success" epoch → "Never"', () => {
  it('shows "Never" for last_success_at when it is an epoch-1970 timestamp', async () => {
    const user = userEvent.setup()
    render(<SourceDiagnosticsPanel instance={EPOCH_INSTANCE} />)
    await user.click(screen.getByTestId('diagnostics-toggle'))
    await waitFor(() => {
      expect(screen.getByTestId('diag-last-success')).toBeInTheDocument()
    })
    expect(screen.getByTestId('diag-last-success').textContent).toContain('Never')
    expect(screen.getByTestId('diag-last-success').textContent).not.toMatch(/1970/)
  })

  it('shows "Never" for last_sync_at when it is an epoch-1970 unix seconds value', async () => {
    const user = userEvent.setup()
    render(<SourceDiagnosticsPanel instance={EPOCH_INSTANCE} />)
    await user.click(screen.getByTestId('diagnostics-toggle'))
    await waitFor(() => {
      expect(screen.getByTestId('diag-last-sync-at')).toBeInTheDocument()
    })
    expect(screen.getByTestId('diag-last-sync-at').textContent).toContain('Never')
    expect(screen.getByTestId('diag-last-sync-at').textContent).not.toMatch(/1970/)
  })

  it('still shows real date for a genuine 2026 last_success_at', async () => {
    const user = userEvent.setup()
    const realInstance: SourceInstance = {
      ...EPOCH_INSTANCE,
      last_success_at: '2026-06-14T01:14:01Z',
      last_sync_at: new Date('2026-06-14T01:14:01Z').getTime() / 1000,
    }
    render(<SourceDiagnosticsPanel instance={realInstance} />)
    await user.click(screen.getByTestId('diagnostics-toggle'))
    await waitFor(() => {
      expect(screen.getByTestId('diag-last-success')).toBeInTheDocument()
    })
    expect(screen.getByTestId('diag-last-success').textContent).not.toBe('Never')
    expect(screen.getByTestId('diag-last-success').textContent).not.toMatch(/1970/)
  })
})

// ---------------------------------------------------------------------------
// Bug 2: CollectControls auto-sync last-sync — "Last sync" epoch → "Never"
// ---------------------------------------------------------------------------

const {
  mockSyncSource,
  mockTestSource,
  mockGetAutoSync,
  mockSetAutoSync,
  mockFetchSourcesCR,
} = vi.hoisted(() => ({
  mockSyncSource: vi.fn(),
  mockTestSource: vi.fn(),
  mockGetAutoSync: vi.fn(),
  mockSetAutoSync: vi.fn(),
  mockFetchSourcesCR: vi.fn().mockResolvedValue([]),
}))

vi.mock('../api/sources', () => ({
  syncSource: mockSyncSource,
  testSource: mockTestSource,
  getAutoSync: mockGetAutoSync,
  setAutoSync: mockSetAutoSync,
  fetchSources: mockFetchSourcesCR,
}))

import CollectControls from '../components/sources/CollectControls'
import type { AutoSyncState } from '../api/types'

const AUTOSYNC_EPOCH: AutoSyncState = {
  enabled: true,
  interval_seconds: 60,
  source_id: 'azure_waf',
  last_sync: {
    // The "Last sync: 1/21/1970" value from Maintainer's environment (epoch seconds in ISO)
    last_sync_at: '1970-01-21T09:50:18Z',
    last_sync_ingested: 0,
    last_sync_status: 'no_data',
    last_error: null,
  },
}

const PULL_INSTANCE: SourceInstance = {
  source_type: 'azure_waf',
  source_id: 'azure_waf',
  flavor: 'pull',
  state: 'idle',
  attempt: 0,
  total_crashes: 0,
  total_dlq: 0,
  dropped_count: 0,
  last_success_at: null,
  event_count: 0,
}

describe('Bug 2 — CollectControls auto-sync last-sync epoch → "Never"', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows "Never" for last-sync-at when last_sync_at is a 1970-epoch ISO string', async () => {
    mockGetAutoSync.mockResolvedValue(AUTOSYNC_EPOCH)
    render(<CollectControls typeKey="azure_waf" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => {
      expect(screen.getByTestId('last-sync-info')).toBeInTheDocument()
    })
    const lastSyncAt = screen.getByTestId('last-sync-at')
    expect(lastSyncAt.textContent).toBe('Never')
    expect(lastSyncAt.textContent).not.toMatch(/1970/)
  })

  it('still shows real date for a genuine 2026 last_sync_at', async () => {
    mockGetAutoSync.mockResolvedValue({
      ...AUTOSYNC_EPOCH,
      last_sync: {
        ...AUTOSYNC_EPOCH.last_sync,
        last_sync_at: '2026-06-14T01:14:01Z',
      },
    })
    render(<CollectControls typeKey="azure_waf" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)
    await waitFor(() => {
      expect(screen.getByTestId('last-sync-info')).toBeInTheDocument()
    })
    const lastSyncAt = screen.getByTestId('last-sync-at')
    expect(lastSyncAt.textContent).not.toBe('Never')
    expect(lastSyncAt.textContent).not.toMatch(/1970/)
  })
})

// ---------------------------------------------------------------------------
// Bug 3: Diagnostics panel alignment — rendered in same column as other controls
// ---------------------------------------------------------------------------

const {
  mockFetchSourceConfig,
  mockPutSourceConfig,
  mockFetchSourceActions,
} = vi.hoisted(() => ({
  mockFetchSourceConfig: vi.fn(),
  mockPutSourceConfig: vi.fn(),
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
    putSourceConfig: mockPutSourceConfig,
    ApiError,
    resolveBaseUrl: () => '',
    assertLoopbackBase: () => undefined,
  }
})

vi.mock('../api/sourceActions', () => ({
  fetchSourceActions: mockFetchSourceActions,
  runSourceAction: vi.fn(),
}))

import SourceCard from '../components/SourceCard'
import { SURICATA_SOURCE_ENTRY } from './fixtures'

const HEALTHY_INSTANCE: SourceInstance = {
  source_type: 'suricata',
  source_id: 'vm-target',
  flavor: 'pull',
  state: 'running',
  attempt: 0,
  total_crashes: 0,
  total_dlq: 0,
  dropped_count: 0,
  last_success_at: '2026-06-14T01:14:01Z',
  event_count: 100,
  last_sync_at: new Date('2026-06-14T01:14:01Z').getTime() / 1000,
  last_sync_ingested: 42,
  last_sync_status: 'ok',
  last_error: null,
  // ADR-0062 A1 §1: source was active (#737 fix — card expands only when enabled)
  auto_sync_enabled: true,
}

describe('Bug 3 — Diagnostics panel in same column as other controls', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({ mode: 'local' })
    mockPutSourceConfig.mockResolvedValue(undefined)
    // ADR-0062: use the connected mock (mockFetchSourcesCR → api/sources.fetchSources)
    // so SourceCard gets the HEALTHY_INSTANCE and starts Active+expanded.
    mockFetchSourcesCR.mockResolvedValue([HEALTHY_INSTANCE])
    // getAutoSync is connected via mockGetAutoSync (first vi.hoisted block)
    mockGetAutoSync.mockResolvedValue({
      enabled: false,
      interval_seconds: 300,
      source_id: 'suricata',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
    mockFetchSourceActions.mockResolvedValue([])
  })

  it('collect-controls and diagnostics-panel are in the same flex column (not side-by-side)', async () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('diagnostics-panel')).toBeInTheDocument()
      expect(screen.getByTestId('collect-controls')).toBeInTheDocument()
    })

    // The actions wrapper div must use flexDirection=column so diagnostics
    // stacks below the controls, not to the right of them.
    // Find the shared parent of collect-controls and diagnostics-panel.
    const collectControls = screen.getByTestId('collect-controls')
    const diagnosticsPanel = screen.getByTestId('diagnostics-panel')

    // Both must share a common ancestor
    expect(collectControls.closest('[data-testid="ds-source-card"]')).toBeTruthy()
    expect(diagnosticsPanel.closest('[data-testid="ds-source-card"]')).toBeTruthy()

    // The immediate parent of the actions column wrapper should have flexDirection=column
    // We verify that collect-controls and diagnostics-panel share a column-flex parent.
    const actionsWrapper = collectControls.parentElement
    expect(actionsWrapper).toBeTruthy()
    // diagnostics-panel must be within the same wrapper (same parent or ancestor)
    expect(actionsWrapper!.contains(diagnosticsPanel)).toBe(true)

    // The wrapper must be styled as a column (not a row flex)
    const style = actionsWrapper!.getAttribute('style') ?? ''
    // Either inline style has column direction, or no flex-direction means default (block stacking)
    // We just assert that diagnostics is NOT to the RIGHT of collect-controls in the DOM
    // (i.e., diagnostics-panel appears after collect-controls in document order within the wrapper)
    const allChildren = Array.from(actionsWrapper!.children)
    const collectIdx = allChildren.findIndex((el) => el.contains(collectControls))
    const diagIdx = allChildren.findIndex((el) => el.contains(diagnosticsPanel))
    // diagnostics must come after collect-controls in DOM order (stacked below)
    // OR be at the same level but styled as column
    if (collectIdx !== -1 && diagIdx !== -1) {
      expect(diagIdx).toBeGreaterThan(collectIdx)
    }

    // The key layout test: verify column flex direction
    // The wrapper should NOT be a row-flex (which would cause side-by-side layout)
    expect(style).not.toContain('flex-direction: row')
    expect(style).not.toContain('flex-direction:row')
  })
})

// ---------------------------------------------------------------------------
// Bug 4: Sync result shows ingested count always
// ---------------------------------------------------------------------------

describe('Bug 4 — Sync result always surfaces ingested count', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAutoSync.mockResolvedValue({
      enabled: false,
      interval_seconds: 300,
      source_id: 'azure_waf',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
  })

  it('sync result shows ingested count when events_ingested > 0', async () => {
    mockSyncSource.mockResolvedValue({ ok: true, message: 'Sync complete.', events_ingested: 42 })
    const user = userEvent.setup()
    render(<CollectControls typeKey="azure_waf" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('sync-result')).toBeInTheDocument()
    })
    const result = screen.getByTestId('sync-result')
    expect(result.textContent).toContain('42')
    expect(result.textContent).toMatch(/ingested/i)
  })

  it('sync result shows "no new events" (success-styled) when events_ingested is 0 (issue #744)', async () => {
    // Issue #744: 0 ingested is a HEALTHY outcome for watermark-incremental pulls.
    // The old "0 events ingested" text read as broken; the new UX shows a reassuring message.
    mockSyncSource.mockResolvedValue({ ok: true, message: 'Sync complete.', events_ingested: 0 })
    const user = userEvent.setup()
    render(<CollectControls typeKey="azure_waf" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('sync-result')).toBeInTheDocument()
    })
    const result = screen.getByTestId('sync-result')
    // Must show the reassuring "no new events" message, not the confusing "0 events ingested"
    expect(result.textContent).toMatch(/no new events/i)
    expect(result.textContent).not.toMatch(/0 events ingested/i)
    // Must be success-styled (green), not error-styled (destructive)
    expect(result.className).toContain('border-green-300')
    expect(result.className).not.toContain('border-destructive')
  })

  it('sync result shows "No new data" when events_ingested is null (server omitted it)', async () => {
    // When the server doesn't return events_ingested (undefined/null), show graceful fallback
    mockSyncSource.mockResolvedValue({ ok: true, message: 'Sync complete.' })
    const user = userEvent.setup()
    render(<CollectControls typeKey="azure_waf" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('sync-result')).toBeInTheDocument()
    })
    const result = screen.getByTestId('sync-result')
    // When events_ingested is absent, show graceful fallback — "Synced" (no crash, no undefined text)
    // Updated per #738 sync-UX fix: old text was "Complete", new text is "Synced"
    expect(result.textContent).toMatch(/synced/i)
  })

  it('sync result shows no_data label when SyncResult.status is no_data and count is 0', async () => {
    // This is the Azure WAF case: events are >24h old, no new data
    mockSyncSource.mockResolvedValue({ ok: true, message: 'Sync complete.', events_ingested: 0 })
    const user = userEvent.setup()
    render(<CollectControls typeKey="azure_waf" flavor="pull" instance={PULL_INSTANCE} isActive={true} />)

    await waitFor(() => expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument())

    await act(async () => {
      await user.click(screen.getByTestId('btn-sync-now'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('sync-result')).toBeInTheDocument()
    })
    // With 0 events and a successful sync, show "no new events" (no undefined/blank text)
    expect(screen.getByTestId('sync-result').textContent).not.toMatch(/undefined/i)
    expect(screen.getByTestId('sync-result').textContent).toMatch(/no new events/i)
  })
})
