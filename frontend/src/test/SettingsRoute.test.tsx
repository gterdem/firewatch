/**
 * Tests for src/routes/SettingsRoute.tsx
 *
 * EARS criteria covered:
 *   - Event-driven: when Settings mounts, it fetches GET /sources/types and renders
 *     exactly the discovered plugins.
 *   - State-driven: empty [] response → FirstRunPanel shown (issue #488 R3).
 *   - State-driven: populated response → cards rendered.
 *   - Event-driven: discovery failure → error shown.
 *   - Ubiquitous (#488 R3): page title "Settings" and one-sentence subtitle are rendered.
 *   - State-driven: "Ingest sources" section label and LocalAiPanel rendered.
 *
 * P5 (#116) / #135: SettingsRoute now includes LocalAiPanel (renamed from OllamaPanel) which uses useTheme().
 * Tests must wrap the component in ThemeProvider.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { ThemeProvider } from '../app/ThemeContext'
import SettingsRoute from '../routes/SettingsRoute'
import { SURICATA_SOURCE_ENTRY } from './fixtures'

const { mockFetchSourceTypes, mockFetchSourceConfig, mockFetchHealth, mockFetchAiModels, mockGetRuntimeConfig } = vi.hoisted(() => ({
  mockFetchSourceTypes: vi.fn(),
  mockFetchSourceConfig: vi.fn(),
  mockFetchHealth: vi.fn(),
  mockFetchAiModels: vi.fn(),
  mockGetRuntimeConfig: vi.fn(),
}))

// importOriginal spreads the real module so helpers like resolveBaseUrl and
// assertLoopbackBase (used by sources.ts after fix #81) are available without
// being explicitly listed in every test mock.
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    fetchSourceTypes: mockFetchSourceTypes,
    fetchSourceConfig: mockFetchSourceConfig,
    putSourceConfig: vi.fn().mockResolvedValue(undefined),
    fetchHealth: mockFetchHealth,
    fetchAiModels: mockFetchAiModels,
    putRuntimeConfig: vi.fn().mockResolvedValue(undefined),
    getRuntimeConfig: mockGetRuntimeConfig,
    // AlertingPolicyPanel (EscalationPolicyTable) fetches /escalation/policy on mount.
    // Return an empty policy so the table renders in a quiet empty state (no extra
    // role="status" or role="alert" elements that would break getByRole queries).
    fetchEscalationPolicy: vi.fn().mockResolvedValue({ policy: [], generated_at: '2026-06-14T12:00:00Z' }),
  }
})

// Mock sources API for the health dot on each source card.
// getAutoSync is called by CollectControls on mount for pull sources (issue #138).
vi.mock('../api/sources', () => ({
  fetchSources: vi.fn().mockResolvedValue([]),
  testSource: vi.fn(),
  syncSource: vi.fn(),
  getAutoSync: vi.fn().mockResolvedValue({
    enabled: false,
    interval_seconds: 300,
    source_id: 'suricata',
    last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
  }),
  setAutoSync: vi.fn(),
}))

function renderWithTheme(ui: React.ReactElement) {
  return render(<ThemeProvider>{ui}</ThemeProvider>)
}

describe('SettingsRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({
      mode: 'local',
      local_path: '/var/log/suricata/eve.json',
      remote_host: '',
      remote_port: 22,
      remote_user: null,
      remote_key: null,
      remote_path: '/var/log/suricata/eve.json',
      verify_host_key: true,
    })
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'qwen3:14b',
      db_ok: true,
    })
    mockFetchAiModels.mockResolvedValue({
      models: ['qwen3:14b', 'llama3.2'],
      current: 'qwen3:14b',
    })
    mockGetRuntimeConfig.mockResolvedValue({
      alert_threshold: 'CRITICAL',
      alert_on_sync: true,
      webhook_url: null,
      webhook_url_set: false,
      api_key_set: false,
      ollama_model: 'qwen3:14b',
      ai_enabled: true,
      ollama_base_url: 'http://localhost:11434',
      geo_provider: 'offline',
      notify_on_auto_escalate: false,
    })
  })

  // EARS event-driven: fetches on mount
  it('calls fetchSourceTypes on mount', async () => {
    mockFetchSourceTypes.mockResolvedValue([])
    renderWithTheme(<SettingsRoute />)
    await waitFor(() => {
      expect(mockFetchSourceTypes).toHaveBeenCalledTimes(1)
    })
  })

  // EARS state-driven: empty discovery → first-run panel (issue #488 R3)
  it('shows the first-run panel when discovery returns []', async () => {
    mockFetchSourceTypes.mockResolvedValue([])
    renderWithTheme(<SettingsRoute />)
    await waitFor(() => {
      expect(screen.getByTestId('first-run-panel')).toBeInTheDocument()
    })
  })

  // EARS state-driven: populated discovery → cards rendered
  it('renders a card for each discovered plugin', async () => {
    mockFetchSourceTypes.mockResolvedValue([SURICATA_SOURCE_ENTRY])
    renderWithTheme(<SettingsRoute />)
    await waitFor(() => {
      expect(screen.getByTestId('source-card-suricata')).toBeInTheDocument()
    })
  })

  // EARS event-driven: discovery failure → error shown
  it('shows error message when discovery fetch fails', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchSourceTypes.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))
    renderWithTheme(<SettingsRoute />)
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
  })

  // Shows loading indicator before discovery resolves
  it('shows loading indicator while discovery is in flight', () => {
    // Never resolves — stays in loading state
    mockFetchSourceTypes.mockReturnValue(new Promise(() => {}))
    renderWithTheme(<SettingsRoute />)
    // Multiple role="status" elements may exist (SettingsList + EscalationPolicyTable)
    // — check at least one contains the source-loading text.
    const statusNodes = screen.getAllByRole('status')
    const loadingNode = statusNodes.find((el) => el.textContent?.includes('Loading source'))
    expect(loadingNode).toBeTruthy()
    expect(loadingNode?.textContent).toContain('Loading source')
  })

  // Issue #488 (R3) EARS: page title and subtitle rendered
  it('renders the page title "Settings"', async () => {
    mockFetchSourceTypes.mockResolvedValue([])
    renderWithTheme(<SettingsRoute />)
    await waitFor(() => {
      expect(screen.getByTestId('settings-page-title')).toBeInTheDocument()
    })
    expect(screen.getByTestId('settings-page-title')).toHaveTextContent('Settings')
  })

  it('renders the page subtitle explaining the install-to-card model', async () => {
    mockFetchSourceTypes.mockResolvedValue([])
    renderWithTheme(<SettingsRoute />)
    await waitFor(() => {
      expect(screen.getByTestId('settings-page-subtitle')).toBeInTheDocument()
    })
    const subtitle = screen.getByTestId('settings-page-subtitle')
    // Must explain that sources install → card appears
    expect(subtitle).toHaveTextContent(/telemetry sources/i)
    expect(subtitle).toHaveTextContent(/settings card/i)
  })

  // P5 (#116) EARS: "Ingest sources" section label rendered
  it('renders the "Ingest sources" section label', async () => {
    mockFetchSourceTypes.mockResolvedValue([])
    renderWithTheme(<SettingsRoute />)
    await waitFor(() => {
      expect(screen.getByTestId('ingest-sources-label')).toBeInTheDocument()
    })
    expect(screen.getByTestId('ingest-sources-label')).toHaveTextContent('Ingest sources')
  })

  // P5 (#116) / #661 EARS: LocalAiPanel rendered + NotificationsPanel rendered
  // Notification threshold (alert_threshold) moved to NotificationsPanel (issue #661).
  it('renders the LocalAiPanel (AI engine) and NotificationsPanel on the settings page', async () => {
    mockFetchSourceTypes.mockResolvedValue([])
    renderWithTheme(<SettingsRoute />)
    await waitFor(() => {
      // LocalAiPanel is present (AI engine card)
      expect(screen.getByTestId('section-ai-engine')).toBeInTheDocument()
      // NotificationsPanel is present (notification threshold is now here)
      expect(screen.getByTestId('notification-threshold-select')).toBeInTheDocument()
    })
  })

  // Issue #686: Escalation Policy card must appear BEFORE Notifications card in DOM order.
  // Uses compareDocumentPosition to assert relative order without brittle index checks.
  it('renders AlertingPolicyPanel before NotificationsPanel in DOM order', async () => {
    mockFetchSourceTypes.mockResolvedValue([])
    renderWithTheme(<SettingsRoute />)
    await waitFor(() => {
      expect(screen.getByTestId('alerting-policy-panel')).toBeInTheDocument()
      expect(screen.getByTestId('notification-threshold-select')).toBeInTheDocument()
    })
    const escalationCard = screen.getByTestId('alerting-policy-panel')
    const notificationControl = screen.getByTestId('notification-threshold-select')
    // Node.DOCUMENT_POSITION_FOLLOWING (4) means notificationControl comes after escalationCard
    const position = escalationCard.compareDocumentPosition(notificationControl)
    expect(position & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  // P5 (#116) EARS: Theme select changes data-theme
  it('theme select is rendered and defaults to dark', async () => {
    mockFetchSourceTypes.mockResolvedValue([])
    renderWithTheme(<SettingsRoute />)
    await waitFor(() => {
      const themeSelect = screen.getByTestId('theme-select') as HTMLSelectElement
      expect(themeSelect).toBeInTheDocument()
      expect(themeSelect.value).toBe('dark')
    })
  })
})
