/**
 * Tests for issue #589 — re-query Settings sources/AI panels on in-session key restore.
 *
 * EARS criterion:
 *   WHEN the API key is restored in-session (via setApiKey after a 401 on mount),
 *   the SettingsRoute sources panel SHALL re-fetch fetchSourceTypes() and clear the
 *   401 error state. Likewise the LocalAiPanel SHALL re-fetch fetchAiModels() and
 *   clear the "Could not reach Local AI endpoint (401)" error.
 *
 * Mechanism under test:
 *   - apiKeyStore._keyVersion bumps on every setApiKey() call.
 *   - useApiKeyVersion() hook returns the current version and re-renders on change.
 *   - SettingsRoute: fetchSourceTypes useEffect dep includes keyVersion → re-runs.
 *   - LocalAiPanel: fetchAiModels useEffect dep includes keyVersion → re-runs.
 *
 * Anti-loop guarantee:
 *   - keyVersion is monotonically increasing — once the re-fetch succeeds the
 *     effect does NOT fire again unless setApiKey is called again.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { ThemeProvider } from '../app/ThemeContext'
import SettingsRoute from '../routes/SettingsRoute'
import LocalAiPanel from '../components/LocalAiPanel'
import { setApiKey, _resetForTest } from '../app/apiKeyStore'
import { ApiError } from '../api/client'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const {
  mockFetchSourceTypes,
  mockFetchSourceConfig,
  mockFetchHealth,
  mockFetchAiModels,
  mockGetRuntimeConfig,
} = vi.hoisted(() => ({
  mockFetchSourceTypes: vi.fn(),
  mockFetchSourceConfig: vi.fn(),
  mockFetchHealth: vi.fn(),
  mockFetchAiModels: vi.fn(),
  mockGetRuntimeConfig: vi.fn(),
}))

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
    // Return a quiet empty state so it doesn't contribute spurious role="alert" elements.
    fetchEscalationPolicy: vi.fn().mockResolvedValue({ policy: [], generated_at: '2026-06-14T12:00:00Z' }),
  }
})

vi.mock('../api/sources', () => ({
  fetchSources: vi.fn().mockResolvedValue([]),
  testSource: vi.fn(),
  syncSource: vi.fn(),
  getAutoSync: vi.fn().mockResolvedValue({
    enabled: false,
    interval_seconds: 300,
    source_id: 'test',
    last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
  }),
  setAutoSync: vi.fn(),
}))

function renderWithTheme(ui: React.ReactElement) {
  return render(<ThemeProvider>{ui}</ThemeProvider>)
}

// ---------------------------------------------------------------------------
// Shared setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
  _resetForTest()

  // Common happy-path defaults for LocalAiPanel's runtime config fetch
  mockGetRuntimeConfig.mockResolvedValue({
    alert_threshold: 'CRITICAL',
    alert_on_sync: true,
    webhook_url: null,
    webhook_url_set: false,
    ollama_model: 'llama3.2',
    ai_enabled: true,
    ollama_base_url: 'http://localhost:11434',
    geo_provider: 'offline',
    api_key_set: false,
  })
  mockFetchHealth.mockResolvedValue({
    status: 'ok',
    ollama_connected: false,
    ollama_model: null,
    db_ok: true,
  })
  // Default: models fetch succeeds (needed by LocalAiPanel rendered inside SettingsRoute)
  mockFetchAiModels.mockResolvedValue({ models: ['llama3.2'], current: 'llama3.2' })
})

// ---------------------------------------------------------------------------
// SettingsRoute — sources panel re-query
// ---------------------------------------------------------------------------

describe('SettingsRoute — re-query sources panel on key restore (#589)', () => {
  it('re-fetches fetchSourceTypes after a 401 when setApiKey is called', async () => {
    // First call: 401 (no key in memory on mount)
    mockFetchSourceTypes.mockRejectedValueOnce(new ApiError(401, null, 'Unauthorized'))
    // Second call: success after key restore
    mockFetchSourceTypes.mockResolvedValue([])

    renderWithTheme(<SettingsRoute />)

    // Wait for the initial 401 error to appear in the DOM
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
    expect(screen.getByRole('alert')).toHaveTextContent('Discovery failed: 401')

    // Simulate the operator re-entering the key in-session
    setApiKey('restored-key')

    // The panel should re-fetch and clear the error
    await waitFor(() => {
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    })

    // fetchSourceTypes was called twice: once on mount (401), once on key restore
    expect(mockFetchSourceTypes).toHaveBeenCalledTimes(2)
  })

  it('does not re-fetch if the key version never changes', async () => {
    mockFetchSourceTypes.mockResolvedValue([])

    renderWithTheme(<SettingsRoute />)

    await waitFor(() => {
      expect(mockFetchSourceTypes).toHaveBeenCalledTimes(1)
    })

    // Wait a tick — no additional calls expected
    await new Promise((r) => setTimeout(r, 50))
    expect(mockFetchSourceTypes).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// LocalAiPanel — AI models re-query
// ---------------------------------------------------------------------------

describe('LocalAiPanel — re-query models on key restore (#589)', () => {
  it('re-fetches fetchAiModels after a 401 when setApiKey is called', async () => {
    // First call: 401 (no key on mount)
    mockFetchAiModels.mockRejectedValueOnce(new ApiError(401, null, 'Unauthorized'))
    // Second call: success after key restore
    mockFetchAiModels.mockResolvedValue({ models: ['llama3.2'], current: 'llama3.2' })

    renderWithTheme(
      <LocalAiPanel health={null} healthLoading={false} />
    )

    // Wait for the 401 error message in the model selector area
    await waitFor(() => {
      expect(screen.getByTestId('model-select-unavailable')).toBeInTheDocument()
    })
    expect(screen.getByTestId('model-select-unavailable')).toHaveTextContent(
      'Could not reach Local AI endpoint (401)'
    )

    // Simulate the operator re-entering the key in-session
    setApiKey('restored-key')

    // The model selector should now show the available model
    await waitFor(() => {
      expect(screen.getByTestId('model-select')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('model-select-unavailable')).not.toBeInTheDocument()

    // fetchAiModels was called twice: once on mount (401), once on key restore
    expect(mockFetchAiModels).toHaveBeenCalledTimes(2)
  })

  it('clears the error and shows loading state before re-fetch completes', async () => {
    // First call: 401
    mockFetchAiModels.mockRejectedValueOnce(new ApiError(401, null, 'Unauthorized'))

    // Second call: deferred — stays in loading state
    let resolveModels!: (v: { models: string[]; current: string }) => void
    mockFetchAiModels.mockReturnValueOnce(
      new Promise<{ models: string[]; current: string }>((resolve) => {
        resolveModels = resolve
      })
    )

    renderWithTheme(
      <LocalAiPanel health={null} healthLoading={false} />
    )

    // Wait for 401 error
    await waitFor(() => {
      expect(screen.getByTestId('model-select-unavailable')).toBeInTheDocument()
    })

    // Restore key — triggers re-fetch
    setApiKey('restored-key')

    // Error should be replaced with loading indicator during re-fetch
    await waitFor(() => {
      expect(screen.getByTestId('model-select-loading')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('model-select-unavailable')).not.toBeInTheDocument()

    // Resolve the second fetch
    resolveModels({ models: ['llama3.2'], current: 'llama3.2' })
    await waitFor(() => {
      expect(screen.getByTestId('model-select')).toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// apiKeyStore — keyVersion signal correctness
// ---------------------------------------------------------------------------

describe('apiKeyStore — keyVersion signal (#589)', () => {
  it('getKeyVersion() starts at 0 after reset', async () => {
    const { getKeyVersion } = await import('../app/apiKeyStore')
    expect(getKeyVersion()).toBe(0)
  })

  it('getKeyVersion() increments on every setApiKey call', async () => {
    const { getKeyVersion } = await import('../app/apiKeyStore')
    setApiKey('key-1')
    expect(getKeyVersion()).toBe(1)
    setApiKey('key-2')
    expect(getKeyVersion()).toBe(2)
    setApiKey(null)
    expect(getKeyVersion()).toBe(3)
  })

  it('subscribeKeyVersion fires listener on setApiKey', async () => {
    const { subscribeKeyVersion } = await import('../app/apiKeyStore')
    const listener = vi.fn()
    const unsub = subscribeKeyVersion(listener)
    setApiKey('test-key')
    expect(listener).toHaveBeenCalledTimes(1)
    unsub()
    setApiKey('another-key')
    // Unsubscribed — should NOT be called again
    expect(listener).toHaveBeenCalledTimes(1)
  })
})
