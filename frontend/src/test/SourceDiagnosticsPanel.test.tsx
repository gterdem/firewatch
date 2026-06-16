/**
 * Tests for src/components/sources/SourceDiagnosticsPanel.tsx
 *
 * EARS criteria (issue #139):
 *
 * Ubiquitous (always):
 *   - Diagnostics panel renders when instance is null (no supervisor).
 *   - Diagnostics panel renders for a healthy (running) instance.
 *   - Diagnostics panel renders for a dark/error instance.
 *   - All diagnostic fields are present: supervisor_state, attempt, total_crashes,
 *     total_dlq, dropped_count, last_success_at, last_sync_at, last_sync_ingested,
 *     last_sync_status, last_error.
 *
 * State-driven:
 *   - When state is "backoff" → panel auto-expands (open=true).
 *   - When state is "parked" → panel auto-expands (open=true).
 *   - When state is "error" → panel auto-expands (open=true).
 *   - When state is "running" (healthy) → panel starts collapsed.
 *   - When instance is null → panel starts collapsed; expanding shows "no data" message.
 *
 * Event-driven:
 *   - Clicking the toggle opens and closes the panel.
 *   - Red-dot diagnostics trigger (in SourceCard) is present when state is dark.
 *   - Red-dot trigger is absent when state is healthy.
 *
 * Security:
 *   - last_error is rendered as a text node — never as innerHTML.
 *   - last_error containing HTML tags is escaped (XSS-safe).
 *   - No value is ever echoed into a dangerouslySetInnerHTML path.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SourceDiagnosticsPanel from '../components/sources/SourceDiagnosticsPanel'
import SourceCard from '../components/SourceCard'
import type { SourceInstance } from '../api/types'
import { SURICATA_SOURCE_ENTRY } from './fixtures'

// ── Fixtures ────────────────────────────────────────────────────────────────

/** Running (healthy) instance — all ADR-0031 §F fields present. */
const HEALTHY_INSTANCE: SourceInstance = {
  source_type: 'suricata',
  source_id: 'vm-target',
  flavor: 'pull',
  state: 'running',
  attempt: 0,
  total_crashes: 1,
  total_dlq: 3,
  dropped_count: 0,
  last_success_at: '2026-06-11T10:00:00Z',
  event_count: 500,
  last_sync_at: 1749638400,      // Unix epoch seconds
  last_sync_ingested: 42,
  last_sync_status: 'ok',
  last_error: null,
  // ADR-0062 A1 §1: source was enabled (#737 fix — card expands only when auto_sync_enabled)
  auto_sync_enabled: true,
}

/** Instance in backoff state — went dark. */
const BACKOFF_INSTANCE: SourceInstance = {
  ...HEALTHY_INSTANCE,
  state: 'backoff',
  attempt: 3,
  total_crashes: 4,
  last_sync_status: 'error',
  last_error: 'Connection refused to 10.0.0.1:22',
}

/** Instance in parked state. */
const PARKED_INSTANCE: SourceInstance = {
  ...HEALTHY_INSTANCE,
  state: 'parked',
  attempt: 5,
  total_crashes: 6,
  last_sync_status: 'error',
  last_error: 'Max retries exceeded',
}

/** Instance where last_error contains HTML (XSS test). */
const XSS_INSTANCE: SourceInstance = {
  ...BACKOFF_INSTANCE,
  last_error: '<script>alert("xss")</script>',
}

// ── vi.hoisted mocks (for SourceCard integration tests) ─────────────────────

const {
  mockFetchSourceConfig,
  mockPutSourceConfig,
  mockFetchSources,
  mockGetAutoSync,
  mockFetchSourceActions,
} = vi.hoisted(() => ({
  mockFetchSourceConfig: vi.fn(),
  mockPutSourceConfig: vi.fn(),
  mockFetchSources: vi.fn(),
  mockGetAutoSync: vi.fn(),
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

// ── Unit tests for SourceDiagnosticsPanel ────────────────────────────────────

describe('SourceDiagnosticsPanel — null instance (no supervisor)', () => {
  it('renders the panel disclosure when instance is null', () => {
    render(<SourceDiagnosticsPanel instance={null} />)
    expect(screen.getByTestId('diagnostics-panel')).toBeInTheDocument()
  })

  it('starts collapsed when instance is null', () => {
    render(<SourceDiagnosticsPanel instance={null} />)
    // Body should not be visible by default
    expect(screen.queryByTestId('diagnostics-body')).not.toBeInTheDocument()
  })

  it('shows "no data available" message when expanded with null instance', async () => {
    const user = userEvent.setup()
    render(<SourceDiagnosticsPanel instance={null} />)
    await user.click(screen.getByTestId('diagnostics-toggle'))
    await waitFor(() => {
      expect(screen.getByTestId('diagnostics-no-data')).toBeInTheDocument()
    })
    expect(screen.getByTestId('diagnostics-no-data').textContent).toContain('No supervisor data')
  })
})

describe('SourceDiagnosticsPanel — healthy (running) instance', () => {
  it('renders the panel in non-error state', () => {
    render(<SourceDiagnosticsPanel instance={HEALTHY_INSTANCE} />)
    const panel = screen.getByTestId('diagnostics-panel')
    expect(panel).toHaveAttribute('data-state', 'ok')
  })

  it('starts collapsed for a healthy instance', () => {
    render(<SourceDiagnosticsPanel instance={HEALTHY_INSTANCE} />)
    expect(screen.queryByTestId('diagnostics-body')).not.toBeInTheDocument()
  })

  it('expands when the toggle is clicked', async () => {
    const user = userEvent.setup()
    render(<SourceDiagnosticsPanel instance={HEALTHY_INSTANCE} />)
    await user.click(screen.getByTestId('diagnostics-toggle'))
    await waitFor(() => {
      expect(screen.getByTestId('diagnostics-body')).toBeInTheDocument()
    })
  })

  it('renders all diagnostic fields when expanded', async () => {
    const user = userEvent.setup()
    render(<SourceDiagnosticsPanel instance={HEALTHY_INSTANCE} />)
    await user.click(screen.getByTestId('diagnostics-toggle'))
    await waitFor(() => {
      expect(screen.getByTestId('diag-state')).toBeInTheDocument()
    })
    // Supervisor state
    expect(screen.getByTestId('diag-state').textContent).toContain('running')
    // attempt
    expect(screen.getByTestId('diag-attempt').textContent).toContain('0')
    // total_crashes
    expect(screen.getByTestId('diag-total-crashes').textContent).toContain('1')
    // total_dlq
    expect(screen.getByTestId('diag-total-dlq').textContent).toContain('3')
    // dropped_count
    expect(screen.getByTestId('diag-dropped-count').textContent).toContain('0')
    // last_success_at (formatted)
    expect(screen.getByTestId('diag-last-success')).toBeInTheDocument()
    // last_sync_at (formatted from Unix epoch)
    expect(screen.getByTestId('diag-last-sync-at')).toBeInTheDocument()
    // last_sync_ingested
    expect(screen.getByTestId('diag-last-sync-ingested').textContent).toContain('42')
    // last_sync_status
    expect(screen.getByTestId('diag-last-sync-status').textContent).toContain('OK')
    // last_error: null → row not rendered
    expect(screen.queryByTestId('diag-last-error')).not.toBeInTheDocument()
  })

  it('collapses again when the toggle is clicked a second time', async () => {
    const user = userEvent.setup()
    render(<SourceDiagnosticsPanel instance={HEALTHY_INSTANCE} />)
    await user.click(screen.getByTestId('diagnostics-toggle'))
    await waitFor(() => {
      expect(screen.getByTestId('diagnostics-body')).toBeInTheDocument()
    })
    await user.click(screen.getByTestId('diagnostics-toggle'))
    await waitFor(() => {
      expect(screen.queryByTestId('diagnostics-body')).not.toBeInTheDocument()
    })
  })
})

describe('SourceDiagnosticsPanel — dark / error states', () => {
  it('auto-expands when state is "backoff"', () => {
    render(<SourceDiagnosticsPanel instance={BACKOFF_INSTANCE} />)
    expect(screen.getByTestId('diagnostics-body')).toBeInTheDocument()
  })

  it('auto-expands when state is "parked"', () => {
    render(<SourceDiagnosticsPanel instance={PARKED_INSTANCE} />)
    expect(screen.getByTestId('diagnostics-body')).toBeInTheDocument()
  })

  it('auto-expands when state is "error"', () => {
    const errorInstance: SourceInstance = { ...BACKOFF_INSTANCE, state: 'error' }
    render(<SourceDiagnosticsPanel instance={errorInstance} />)
    expect(screen.getByTestId('diagnostics-body')).toBeInTheDocument()
  })

  it('marks panel with data-state="error" for dark instances', () => {
    render(<SourceDiagnosticsPanel instance={BACKOFF_INSTANCE} />)
    expect(screen.getByTestId('diagnostics-panel')).toHaveAttribute('data-state', 'error')
  })

  it('renders last_error field when state is backoff with an error', () => {
    render(<SourceDiagnosticsPanel instance={BACKOFF_INSTANCE} />)
    expect(screen.getByTestId('diag-last-error')).toBeInTheDocument()
    // Render as text — must contain the error string
    expect(screen.getByTestId('diag-last-error').textContent).toContain('Connection refused')
  })

  it('renders supervisor state and attempt count for backoff', () => {
    render(<SourceDiagnosticsPanel instance={BACKOFF_INSTANCE} />)
    expect(screen.getByTestId('diag-state').textContent).toContain('backoff')
    expect(screen.getByTestId('diag-attempt').textContent).toContain('3')
  })
})

describe('SourceDiagnosticsPanel — security: last_error as text (XSS-safe)', () => {
  it('renders last_error as text, not HTML — XSS tags are escaped', () => {
    render(<SourceDiagnosticsPanel instance={XSS_INSTANCE} />)
    const errorRow = screen.getByTestId('diag-last-error')
    expect(errorRow).toBeInTheDocument()
    // The text content must contain the raw string (escaped, not executed)
    expect(errorRow.textContent).toContain('<script>')
    // The DOM must NOT have a <script> child (it's text, not parsed HTML)
    expect(errorRow.querySelector('script')).toBeNull()
    // Specifically, innerText must match — no live script elements
    expect(document.querySelectorAll('script[data-xss]').length).toBe(0)
  })

  it('last_error value is never set via dangerouslySetInnerHTML path', () => {
    // This test verifies the component uses text rendering.
    // React's JSX {String(value)} path always escapes — this is the structural check.
    const { container } = render(<SourceDiagnosticsPanel instance={XSS_INSTANCE} />)
    // The container must not contain an active <script> element added by XSS
    const scriptTags = container.querySelectorAll('script')
    expect(scriptTags.length).toBe(0)
  })
})

// ── Integration: SourceCard wires the red-dot diagnostics trigger (ADR-0032) ─

describe('SourceCard — diagnostics panel integration (issue #139)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({ mode: 'local' })
    mockPutSourceConfig.mockResolvedValue(undefined)
    mockGetAutoSync.mockResolvedValue({
      enabled: false,
      interval_seconds: 300,
      source_id: 'suricata',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
    mockFetchSourceActions.mockResolvedValue([])
  })

  it('shows the health-dot diagnostics trigger button when instance is in backoff state', async () => {
    mockFetchSources.mockResolvedValue([BACKOFF_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('health-dot-diagnostics-trigger')).toBeInTheDocument()
    })
  })

  it('does NOT show the diagnostics trigger button when instance is healthy (running)', async () => {
    mockFetchSources.mockResolvedValue([HEALTHY_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('collect-controls')).toBeInTheDocument()
    })
    // Healthy state: no trigger button (dot is static)
    expect(screen.queryByTestId('health-dot-diagnostics-trigger')).not.toBeInTheDocument()
  })

  it('does NOT show the diagnostics trigger button when no instance (idle)', async () => {
    // ADR-0062: card is collapsed when inactive (no instance). The diagnostics trigger
    // is in the card body — not rendered when collapsed. We wait for the header
    // (always visible) and assert absence of the trigger.
    mockFetchSources.mockResolvedValue([])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('ds-source-card')).toBeInTheDocument()
    })
    // Trigger is in card body (collapsed) → not in DOM
    expect(screen.queryByTestId('health-dot-diagnostics-trigger')).not.toBeInTheDocument()
  })

  it('always renders the diagnostics panel in the SourceCard', async () => {
    mockFetchSources.mockResolvedValue([HEALTHY_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('diagnostics-panel')).toBeInTheDocument()
    })
  })

  it('diagnostics panel auto-expands when source is in parked state', async () => {
    mockFetchSources.mockResolvedValue([PARKED_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('diagnostics-body')).toBeInTheDocument()
    })
  })

  it('diagnostics panel shows supervisor state and last_error for dark sources', async () => {
    mockFetchSources.mockResolvedValue([BACKOFF_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('diag-state')).toBeInTheDocument()
    })
    expect(screen.getByTestId('diag-state').textContent).toContain('backoff')
    expect(screen.getByTestId('diag-last-error').textContent).toContain('Connection refused')
  })

  it('clicking the red-dot trigger focuses the diagnostics panel', async () => {
    const user = userEvent.setup()
    // Use a mock for scrollIntoView (jsdom does not implement it)
    const scrollMock = vi.fn()
    window.HTMLElement.prototype.scrollIntoView = scrollMock

    mockFetchSources.mockResolvedValue([BACKOFF_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByTestId('health-dot-diagnostics-trigger')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('health-dot-diagnostics-trigger'))
    })

    // scrollIntoView should have been called on the diagnostics ref container
    expect(scrollMock).toHaveBeenCalled()
  })

  it('diagnostics panel last_error rendered as text — XSS-safe in SourceCard', async () => {
    mockFetchSources.mockResolvedValue([XSS_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('diag-last-error')).toBeInTheDocument()
    })
    const errorRow = screen.getByTestId('diag-last-error')
    expect(errorRow.textContent).toContain('<script>')
    expect(errorRow.querySelector('script')).toBeNull()
  })
})
