/**
 * Tests for src/components/LocalAiPanel.tsx  (#135, #131, #492, #493)
 *
 * EARS criteria covered (original #135):
 *   - State-driven: ollama_connected=true → green "Connected" status + model name.
 *   - State-driven: ollama_connected=false → "Disconnected" shown.
 *   - State-driven: health=null → status shows disconnected.
 *   - Event-driven: GET /ai/models returns models → dropdown rendered, current pre-selected.
 *   - Event-driven: operator selects a model → PUT /config/runtime called with ollama_model.
 *   - Event-driven: model change success → "saved" toast shown.
 *   - Event-driven: model change failure → error toast shown.
 *   - State-driven: GET /ai/models returns empty list → unavailable message shown.
 *   - State-driven: GET /ai/models fails (ApiError) → unavailable message shown.
 *   - Rendered: panel title reads "Local AI" (not "Ollama").
 *   - Event-driven: Theme select changes → data-theme flips via ThemeContext.
 *
 * NOTE: alert_threshold, webhook_url, alert_on_sync controls were moved from LocalAiPanel
 * to NotificationsPanel in #661 (ADR-0059 D4 / ADR-0043 IA divide). Those tests now live
 * in NotificationsPanel.test.tsx.
 *
 * EARS criteria added in #493 (R6 — regroup + consequence copy):
 *   - Ubiquitous: "AI engine" section present in the DOM.
 *   - Ubiquitous: "Appearance" section present in the DOM.
 *   - Ubiquitous: alert/webhook controls NOT present in AI card (moved to NotificationsPanel #661).
 *   - Ubiquitous (provenance): scoring provenance line present per ADR-0035.
 *   - State-driven: connected + ai_enabled=true → provenance shows "rules + AI".
 *   - State-driven: disconnected or ai_enabled=false → provenance shows "rules only".
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ThemeProvider } from '../app/ThemeContext'
import LocalAiPanel from '../components/LocalAiPanel'
import type { HealthResponse } from '../api/types'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const { mockFetchAiModels, mockPutRuntimeConfig, mockGetRuntimeConfig } = vi.hoisted(() => ({
  mockFetchAiModels: vi.fn(),
  mockPutRuntimeConfig: vi.fn(),
  mockGetRuntimeConfig: vi.fn(),
}))

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    fetchAiModels: mockFetchAiModels,
    putRuntimeConfig: mockPutRuntimeConfig,
    getRuntimeConfig: mockGetRuntimeConfig,
  }
})

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const HEALTH_CONNECTED: HealthResponse = {
  status: 'ok',
  ollama_connected: true,
  ollama_model: 'qwen3:14b',
  db_ok: true,
}

const HEALTH_DISCONNECTED: HealthResponse = {
  status: 'ok',
  ollama_connected: false,
  ollama_model: null,
  db_ok: true,
}

const MODELS_RESPONSE = {
  models: ['llama3.2', 'qwen3:14b', 'mistral:7b'],
  current: 'qwen3:14b',
}

const MODELS_RESPONSE_NO_CURRENT = {
  models: ['llama3.2', 'mistral:7b'],
  current: null,
}

/** Typical GET /config/runtime response (SecretStr fields masked as null). */
const RUNTIME_CONFIG_RESPONSE = {
  alert_threshold: 'HIGH' as const,
  alert_on_sync: false,
  webhook_url: null,
  /** webhook_url_set: honest boolean from server (#494 / ADR-0006). */
  webhook_url_set: false,
  ollama_model: 'qwen3:14b',
  ai_enabled: true,
  ollama_base_url: 'http://localhost:11434',
  geo_provider: 'offline' as const,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderPanel(health: HealthResponse | null = HEALTH_CONNECTED) {
  return render(
    <ThemeProvider>
      <LocalAiPanel health={health} />
    </ThemeProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests — panel title and rename
// ---------------------------------------------------------------------------

describe('LocalAiPanel — panel title and rename', () => {
  beforeEach(() => {
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
  })

  // EARS ubiquitous: user-facing strings must read "Local AI"
  it('renders panel title "Local AI" (not "Ollama")', async () => {
    renderPanel()
    await waitFor(() => {
      const heading = screen.getByRole('heading', { level: 2 })
      expect(heading.textContent).toContain('Local AI')
      expect(heading.textContent).not.toContain('Ollama')
    })
  })
})

// ---------------------------------------------------------------------------
// Tests — connection status
// ---------------------------------------------------------------------------

describe('LocalAiPanel — connection status', () => {
  beforeEach(() => {
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
  })

  // State-driven: connected
  it('shows connected status when ollama_connected=true', async () => {
    renderPanel(HEALTH_CONNECTED)
    await waitFor(() => {
      const status = screen.getByTestId('local-ai-status')
      expect(status.textContent).toContain('Connected')
      expect(status.textContent).toContain('qwen3:14b')
    })
  })

  // State-driven: disconnected
  it('shows disconnected status when ollama_connected=false', async () => {
    renderPanel(HEALTH_DISCONNECTED)
    await waitFor(() => {
      const status = screen.getByTestId('local-ai-status')
      expect(status.textContent).toContain('Disconnected')
    })
  })

  // State-driven: health=null → disconnected
  it('shows disconnected status when health is null', async () => {
    renderPanel(null)
    await waitFor(() => {
      const status = screen.getByTestId('local-ai-status')
      expect(status.textContent).toContain('Disconnected')
    })
  })
})

// ---------------------------------------------------------------------------
// Tests — model dropdown
// ---------------------------------------------------------------------------

describe('LocalAiPanel — model dropdown', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
  })

  // Event-driven: models returned → dropdown rendered with current pre-selected
  it('renders model dropdown populated with models from GET /ai/models', async () => {
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    renderPanel()

    const select = (await screen.findByTestId('model-select')) as HTMLSelectElement
    expect(select).toBeInTheDocument()

    const options = Array.from(select.options).map((o) => o.value)
    expect(options).toContain('llama3.2')
    expect(options).toContain('qwen3:14b')
    expect(options).toContain('mistral:7b')
  })

  // Event-driven: current model from API is pre-selected
  it('pre-selects the current model from GET /ai/models', async () => {
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    renderPanel()

    const select = (await screen.findByTestId('model-select')) as HTMLSelectElement
    expect(select.value).toBe('qwen3:14b')
  })

  // Event-driven: when current=null, pre-selects first option
  it('pre-selects first model when current is null', async () => {
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE_NO_CURRENT)
    renderPanel(HEALTH_DISCONNECTED)

    const select = (await screen.findByTestId('model-select')) as HTMLSelectElement
    expect(select.value).toBe('llama3.2')
  })

  // Event-driven: operator selects model → PUT /config/runtime called
  it('calls putRuntimeConfig with ollama_model on model change', async () => {
    const user = userEvent.setup()
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    renderPanel()

    const select = await screen.findByTestId('model-select')
    await user.selectOptions(select, 'llama3.2')

    await waitFor(() => {
      expect(mockPutRuntimeConfig).toHaveBeenCalledWith({ ollama_model: 'llama3.2' })
    })
  })

  // Event-driven: model change success → toast shown
  it('shows saved toast after successful model change', async () => {
    const user = userEvent.setup()
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    renderPanel()

    const select = await screen.findByTestId('model-select')
    await user.selectOptions(select, 'mistral:7b')

    await waitFor(() => {
      const toastEl = screen.getByRole('status')
      expect(toastEl.textContent).toContain('mistral:7b')
    })
  })

  // Event-driven: model change failure → error toast shown
  it('shows error toast when putRuntimeConfig fails', async () => {
    const user = userEvent.setup()
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    const { ApiError } = await import('../api/client')
    mockPutRuntimeConfig.mockRejectedValue(new ApiError(500, null, 'Internal Server Error'))
    renderPanel()

    const select = await screen.findByTestId('model-select')
    await user.selectOptions(select, 'llama3.2')

    await waitFor(() => {
      const toastEl = screen.getByRole('status')
      expect(toastEl.textContent).toContain('Save failed')
    })
  })

  // State-driven: empty models list → unavailable message shown (no crash)
  it('shows unavailable message when models list is empty', async () => {
    mockFetchAiModels.mockResolvedValue({ models: [], current: null })
    renderPanel()

    await waitFor(() => {
      expect(screen.getByTestId('model-select-unavailable')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('model-select')).not.toBeInTheDocument()
  })

  // State-driven: endpoint unreachable (ApiError) → unavailable message shown
  it('shows unavailable message when fetchAiModels throws ApiError', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchAiModels.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))
    renderPanel()

    await waitFor(() => {
      expect(screen.getByTestId('model-select-unavailable')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('model-select')).not.toBeInTheDocument()
  })

  // State-driven: loading state shown while models are fetching
  it('shows loading indicator while models are loading', () => {
    mockFetchAiModels.mockReturnValue(new Promise(() => {}))
    renderPanel()
    expect(screen.getByTestId('model-select-loading')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Tests — other controls (pre-existing #135 criteria, updated for #131 mocks)
// NOTE: alert_threshold, webhook_url, alert_on_sync tests moved to NotificationsPanel.test.tsx
// ---------------------------------------------------------------------------

describe('LocalAiPanel — other controls', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
  })

  // EARS event-driven: theme select
  it('theme select defaults to dark', async () => {
    renderPanel()
    await waitFor(() => {
      const themeSelect = screen.getByTestId('theme-select') as HTMLSelectElement
      expect(themeSelect.value).toBe('dark')
    })
  })

  it('theme select changes to light when selected', async () => {
    const user = userEvent.setup()
    renderPanel()

    await waitFor(() => {
      expect(screen.getByTestId('theme-select')).toBeInTheDocument()
    })
    const themeSelect = screen.getByTestId('theme-select') as HTMLSelectElement
    await user.selectOptions(themeSelect, 'light')
    expect(themeSelect.value).toBe('light')
    await waitFor(() => {
      expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    })
  })
})

// ---------------------------------------------------------------------------
// Tests — #492 (R5): ai_enabled, ollama_base_url, geo_provider
// ---------------------------------------------------------------------------

describe('LocalAiPanel — #492 ai_enabled toggle', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockPutRuntimeConfig.mockResolvedValue(undefined)
  })

  // Ubiquitous: ai_enabled checkbox is rendered
  it('renders ai_enabled toggle checkbox', async () => {
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('ai-enabled-toggle')).toBeInTheDocument()
    })
  })

  // Event-driven: GET /config/runtime populates ai_enabled (true)
  it('populates ai_enabled toggle as checked when config returns true', async () => {
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, ai_enabled: true })
    renderPanel()
    await waitFor(() => {
      const cb = screen.getByTestId('ai-enabled-toggle') as HTMLInputElement
      expect(cb.checked).toBe(true)
    })
  })

  // Event-driven: GET /config/runtime populates ai_enabled (false)
  it('populates ai_enabled toggle as unchecked when config returns false', async () => {
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, ai_enabled: false })
    renderPanel()
    await waitFor(() => {
      const cb = screen.getByTestId('ai-enabled-toggle') as HTMLInputElement
      expect(cb.checked).toBe(false)
    })
  })

  // Event-driven: toggle → PUT /config/runtime with ai_enabled
  it('calls putRuntimeConfig with ai_enabled on toggle', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, ai_enabled: true })
    renderPanel()

    const cb = await screen.findByTestId('ai-enabled-toggle')
    await user.click(cb)

    await waitFor(() => {
      expect(mockPutRuntimeConfig).toHaveBeenCalledWith({ ai_enabled: false })
    })
  })

  // Event-driven: success → toast shown
  it('shows success toast after ai_enabled toggle', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, ai_enabled: true })
    renderPanel()

    const cb = await screen.findByTestId('ai-enabled-toggle')
    await user.click(cb)

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('disabled')
    })
  })

  // Event-driven: failure → rollback + error toast
  it('rolls back ai_enabled and shows error toast on PUT failure', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, ai_enabled: true })
    mockPutRuntimeConfig.mockRejectedValue(new ApiError(500, null, 'Server error'))
    renderPanel()

    await waitFor(() => {
      const cb = screen.getByTestId('ai-enabled-toggle') as HTMLInputElement
      expect(cb.checked).toBe(true)
    })

    const cb = screen.getByTestId('ai-enabled-toggle')
    await user.click(cb)

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('Save failed')
    })

    // Checkbox rolled back
    await waitFor(() => {
      const cb2 = screen.getByTestId('ai-enabled-toggle') as HTMLInputElement
      expect(cb2.checked).toBe(true)
    })
  })
})

describe('LocalAiPanel — #492 ollama_base_url field', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockPutRuntimeConfig.mockResolvedValue(undefined)
  })

  // Ubiquitous: endpoint URL input is rendered
  it('renders ollama_base_url input', async () => {
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('ollama-base-url-input')).toBeInTheDocument()
    })
  })

  // Event-driven: GET /config/runtime populates ollama_base_url
  it('populates ollama_base_url from GET /config/runtime on mount', async () => {
    mockGetRuntimeConfig.mockResolvedValue({
      ...RUNTIME_CONFIG_RESPONSE,
      ollama_base_url: 'http://192.168.1.10:11434',
    })
    renderPanel()
    await waitFor(() => {
      const input = screen.getByTestId('ollama-base-url-input') as HTMLInputElement
      expect(input.value).toBe('http://192.168.1.10:11434')
    })
  })

  // Event-driven: Save button calls PUT /config/runtime with ollama_base_url
  it('calls putRuntimeConfig with ollama_base_url when Save is clicked', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
    renderPanel()

    const input = await screen.findByTestId('ollama-base-url-input')
    // Clear existing and type a new URL
    await user.clear(input)
    await user.type(input, 'http://127.0.0.1:8080')

    const saveBtn = screen.getByTestId('ollama-base-url-save')
    await user.click(saveBtn)

    await waitFor(() => {
      expect(mockPutRuntimeConfig).toHaveBeenCalledWith(
        expect.objectContaining({ ollama_base_url: 'http://127.0.0.1:8080' }),
      )
    })
  })

  // Event-driven: save success → "Endpoint URL saved" toast
  it('shows "Endpoint URL saved" toast after successful save', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
    renderPanel()

    await waitFor(() => expect(screen.getByTestId('ollama-base-url-save')).toBeInTheDocument())
    const saveBtn = screen.getByTestId('ollama-base-url-save')
    await user.click(saveBtn)

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('Endpoint URL saved')
    })
  })

  // Event-driven: 422 from local-first validator (ADR-0022) → inline field error (issue #527)
  // NOT a panel-level toast — the error appears directly under the URL input field.
  it('shows inline field error under the endpoint URL input on 422 (issue #527)', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
    mockPutRuntimeConfig.mockRejectedValue(
      new ApiError(422, [{ msg: 'ollama_base_url must resolve to a local address (ADR-0022)' }]),
    )
    renderPanel()

    await waitFor(() => expect(screen.getByTestId('ollama-base-url-save')).toBeInTheDocument())
    const saveBtn = screen.getByTestId('ollama-base-url-save')
    await user.click(saveBtn)

    // Inline error element must appear (not toast).
    await waitFor(() => {
      const errorEl = screen.getByTestId('ollama-base-url-error')
      expect(errorEl.textContent).toContain('ADR-0022')
    })
    // Toast must NOT appear for a 422.
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  // Constraint: 422 sets aria-invalid on the input field (accessibility, issue #527)
  it('sets aria-invalid on the endpoint URL input after a 422 (issue #527)', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
    mockPutRuntimeConfig.mockRejectedValue(
      new ApiError(422, [{ msg: 'Value error, ollama_base_url violates ADR-0022' }]),
    )
    renderPanel()

    await waitFor(() => expect(screen.getByTestId('ollama-base-url-save')).toBeInTheDocument())
    await user.click(screen.getByTestId('ollama-base-url-save'))

    await waitFor(() => {
      const input = screen.getByTestId('ollama-base-url-input')
      expect(input).toHaveAttribute('aria-invalid', 'true')
    })
  })

  // Constraint: typing in the field clears the inline error (issue #527)
  it('clears the inline error when the user edits the endpoint URL field', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
    mockPutRuntimeConfig.mockRejectedValue(
      new ApiError(422, [{ msg: 'Value error, ollama_base_url violates ADR-0022' }]),
    )
    renderPanel()

    await waitFor(() => expect(screen.getByTestId('ollama-base-url-save')).toBeInTheDocument())
    await user.click(screen.getByTestId('ollama-base-url-save'))

    // Error appears
    await waitFor(() => {
      expect(screen.getByTestId('ollama-base-url-error')).toBeInTheDocument()
    })

    // User starts typing → error clears
    const input = screen.getByTestId('ollama-base-url-input')
    await user.type(input, 'x')

    await waitFor(() => {
      expect(screen.queryByTestId('ollama-base-url-error')).not.toBeInTheDocument()
    })
    expect(screen.getByTestId('ollama-base-url-input')).not.toHaveAttribute('aria-invalid', 'true')
  })

  // Constraint: non-422 errors (e.g. 500) still show a panel-level toast (issue #527)
  it('shows panel-level toast for non-422 errors on ollama_base_url save', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
    mockPutRuntimeConfig.mockRejectedValue(new ApiError(500, null, 'Internal Server Error'))
    renderPanel()

    await waitFor(() => expect(screen.getByTestId('ollama-base-url-save')).toBeInTheDocument())
    await user.click(screen.getByTestId('ollama-base-url-save'))

    // Toast must appear for non-422 errors.
    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('Save failed')
    })
    // Inline error must NOT appear for non-422.
    expect(screen.queryByTestId('ollama-base-url-error')).not.toBeInTheDocument()
  })
})

describe('LocalAiPanel — #492 Test endpoint probe', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
  })

  // Ubiquitous: Test button is rendered
  it('renders the Test endpoint button', async () => {
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('test-endpoint-btn')).toBeInTheDocument()
    })
  })

  // Event-driven: Test click → fetchAiModels called (read-only GET /ai/models)
  it('calls fetchAiModels when Test button is clicked', async () => {
    const user = userEvent.setup()
    // Initial mount call + test click call — track call count after mount settles
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    renderPanel()

    // Wait for the initial mount fetch to resolve
    await screen.findByTestId('model-select')
    const callsBefore = mockFetchAiModels.mock.calls.length

    const testBtn = screen.getByTestId('test-endpoint-btn')
    await user.click(testBtn)

    await waitFor(() => {
      expect(mockFetchAiModels.mock.calls.length).toBeGreaterThan(callsBefore)
    })
  })

  // Event-driven: probe shows model list on success
  it('displays available models after Test endpoint succeeds', async () => {
    const user = userEvent.setup()
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    renderPanel()

    await screen.findByTestId('model-select')

    const testBtn = screen.getByTestId('test-endpoint-btn')
    await user.click(testBtn)

    await waitFor(() => {
      const result = screen.getByTestId('test-endpoint-result')
      expect(result.textContent).toContain('llama3.2')
    })
  })

  // Constraint: Test probe does NOT call putRuntimeConfig (SIEM-safe, read-only)
  it('does NOT call putRuntimeConfig when Test endpoint is activated', async () => {
    const user = userEvent.setup()
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    renderPanel()

    await screen.findByTestId('model-select')
    vi.clearAllMocks()
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)

    const testBtn = screen.getByTestId('test-endpoint-btn')
    await user.click(testBtn)

    await waitFor(() => {
      expect(screen.getByTestId('test-endpoint-result')).toBeInTheDocument()
    })

    expect(mockPutRuntimeConfig).not.toHaveBeenCalled()
  })

  // Event-driven: probe shows error when endpoint unreachable
  it('shows error message when Test endpoint is unreachable', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    // First call (mount) returns models; second call (probe) fails
    mockFetchAiModels
      .mockResolvedValueOnce(MODELS_RESPONSE)
      .mockRejectedValueOnce(new ApiError(503, null, 'Service Unavailable'))
    renderPanel()

    await screen.findByTestId('model-select')

    const testBtn = screen.getByTestId('test-endpoint-btn')
    await user.click(testBtn)

    await waitFor(() => {
      const result = screen.getByTestId('test-endpoint-result')
      expect(result.textContent).toContain('unreachable')
    })
  })

  // Event-driven: probe shows "No models found" when endpoint returns empty list
  it('shows "No models found" message when endpoint returns empty model list', async () => {
    const user = userEvent.setup()
    // First call (mount) fails (no models); second call (probe) returns empty
    mockFetchAiModels
      .mockResolvedValueOnce({ models: [], current: null })
      .mockResolvedValueOnce({ models: [], current: null })
    renderPanel()

    await screen.findByTestId('model-select-unavailable')

    const testBtn = screen.getByTestId('test-endpoint-btn')
    await user.click(testBtn)

    await waitFor(() => {
      const result = screen.getByTestId('test-endpoint-result')
      expect(result.textContent).toContain('No models found')
    })
  })
})

describe('LocalAiPanel — #492 geo_provider select', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockPutRuntimeConfig.mockResolvedValue(undefined)
  })

  // Ubiquitous: geo_provider select is rendered
  it('renders geo_provider select', async () => {
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('geo-provider-select')).toBeInTheDocument()
    })
  })

  // Event-driven: GET /config/runtime populates geo_provider
  it('populates geo_provider from GET /config/runtime on mount', async () => {
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, geo_provider: 'offline' })
    renderPanel()
    await waitFor(() => {
      const select = screen.getByTestId('geo-provider-select') as HTMLSelectElement
      expect(select.value).toBe('offline')
    })
  })

  it('populates geo_provider as "online" when config returns online', async () => {
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, geo_provider: 'online' })
    renderPanel()
    await waitFor(() => {
      const select = screen.getByTestId('geo-provider-select') as HTMLSelectElement
      expect(select.value).toBe('online')
    })
  })

  // Event-driven: change → PUT /config/runtime called with geo_provider
  it('calls putRuntimeConfig with geo_provider on selection change', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, geo_provider: 'offline' })
    renderPanel()

    const select = await screen.findByTestId('geo-provider-select')
    await user.selectOptions(select, 'online')

    await waitFor(() => {
      expect(mockPutRuntimeConfig).toHaveBeenCalledWith({ geo_provider: 'online' })
    })
  })

  // Event-driven: success → toast shown
  it('shows success toast after geo_provider change', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, geo_provider: 'offline' })
    renderPanel()

    const select = await screen.findByTestId('geo-provider-select')
    await user.selectOptions(select, 'online')

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('online')
    })
  })

  // Event-driven: failure → error toast
  it('shows error toast when geo_provider PUT fails', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, geo_provider: 'offline' })
    mockPutRuntimeConfig.mockRejectedValue(new ApiError(500, null, 'Server error'))
    renderPanel()

    const select = await screen.findByTestId('geo-provider-select')
    await user.selectOptions(select, 'online')

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('Save failed')
    })
  })

  // State-driven: GET /config/runtime failure → defaults (no crash)
  it('falls back to "offline" default when getRuntimeConfig fails', async () => {
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))
    renderPanel()

    await waitFor(() => {
      const select = screen.getByTestId('geo-provider-select') as HTMLSelectElement
      expect(select).toBeInTheDocument()
      expect(select.value).toBe('offline')
    })
  })
})

// ---------------------------------------------------------------------------
// Tests — #493 (R6): labeled groups, consequence copy, provenance (#493)
// ---------------------------------------------------------------------------

describe('LocalAiPanel — #493 labeled sections', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
  })

  // Ubiquitous: "AI engine" section is present
  it('renders the "AI engine" labeled section', async () => {
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('section-ai-engine')).toBeInTheDocument()
    })
  })

  // Ubiquitous: "Appearance" section is present (Theme moved out of detection config)
  it('renders the "Appearance" labeled section', async () => {
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('section-appearance')).toBeInTheDocument()
    })
  })

  // Ubiquitous: Theme select lives inside Appearance section (not mixed with alerting)
  it('places the theme select inside the Appearance section', async () => {
    renderPanel()
    await waitFor(() => {
      const appearanceSection = screen.getByTestId('section-appearance')
      const themeSelect = screen.getByTestId('theme-select')
      expect(appearanceSection.contains(themeSelect)).toBe(true)
    })
  })

  // Ubiquitous: alert_on_sync is NOT present in the LocalAiPanel (moved to NotificationsPanel #661)
  it('does NOT render alert-on-sync checkbox inside the LocalAI card (#661 IA divide)', async () => {
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('section-ai-engine')).toBeInTheDocument()
    })
    // These controls moved to NotificationsPanel
    expect(screen.queryByTestId('alert-on-sync-blocks')).not.toBeInTheDocument()
    expect(screen.queryByTestId('alert-threshold-select')).not.toBeInTheDocument()
    expect(screen.queryByTestId('webhook-url-input')).not.toBeInTheDocument()
  })
})

describe('LocalAiPanel — #493 ADR-0035 scoring provenance', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPutRuntimeConfig.mockResolvedValue(undefined)
  })

  // Ubiquitous: provenance line is always present
  it('renders scoring provenance element', async () => {
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('scoring-provenance')).toBeInTheDocument()
    })
  })

  // State-driven: ai_enabled=true + connected → provenance shows "rules + AI"
  it('shows "rules + AI" provenance when AI is enabled and connected', async () => {
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, ai_enabled: true })
    renderPanel(HEALTH_CONNECTED)
    await waitFor(() => {
      const prov = screen.getByTestId('scoring-provenance')
      expect(prov.textContent).toContain('rules + AI')
    })
  })

  // State-driven: provenance includes the active model name when connected
  it('includes the connected model name in provenance when AI enabled + connected', async () => {
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, ai_enabled: true })
    renderPanel(HEALTH_CONNECTED)
    await waitFor(() => {
      const prov = screen.getByTestId('scoring-provenance')
      // health fixture has ollama_model: 'qwen3:14b'
      expect(prov.textContent).toContain('qwen3:14b')
    })
  })

  // State-driven: ai_enabled=false → provenance shows "rules only"
  it('shows "rules only" provenance when AI is disabled', async () => {
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, ai_enabled: false })
    renderPanel(HEALTH_CONNECTED)
    await waitFor(() => {
      const prov = screen.getByTestId('scoring-provenance')
      expect(prov.textContent).toContain('rules only')
    })
  })

  // State-driven: disconnected (health.ollama_connected=false) → provenance shows "rules only"
  it('shows "rules only" provenance when AI engine is disconnected', async () => {
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, ai_enabled: true })
    renderPanel(HEALTH_DISCONNECTED)
    await waitFor(() => {
      const prov = screen.getByTestId('scoring-provenance')
      expect(prov.textContent).toContain('rules only')
    })
  })

  // State-driven: health=null → provenance shows "rules only"
  it('shows "rules only" provenance when health is null', async () => {
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_RESPONSE, ai_enabled: true })
    renderPanel(null)
    await waitFor(() => {
      const prov = screen.getByTestId('scoring-provenance')
      expect(prov.textContent).toContain('rules only')
    })
  })
})

// ---------------------------------------------------------------------------
// Tests — #579: AI connection status loading state (no false "Disconnected" flash)
// ---------------------------------------------------------------------------

describe('LocalAiPanel — #579 healthLoading: neutral status during /health fetch', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
  })

  // WHILE healthLoading=true → "Checking…" shown instead of "Disconnected"
  it('shows "Checking…" when healthLoading=true and health is null (fetch in flight)', async () => {
    render(
      <ThemeProvider>
        <LocalAiPanel health={null} healthLoading={true} />
      </ThemeProvider>,
    )
    await waitFor(() => {
      const status = screen.getByTestId('local-ai-status')
      expect(status.textContent).toContain('Checking')
      // Must NOT show "Disconnected" during the loading window
      expect(status.textContent).not.toContain('Disconnected')
    })
  })

  // WHEN healthLoading=false + ollama_connected=true → "Connected" shown
  it('shows "Connected" when healthLoading=false and health.ollama_connected=true', async () => {
    render(
      <ThemeProvider>
        <LocalAiPanel health={HEALTH_CONNECTED} healthLoading={false} />
      </ThemeProvider>,
    )
    await waitFor(() => {
      const status = screen.getByTestId('local-ai-status')
      expect(status.textContent).toContain('Connected')
      expect(status.textContent).not.toContain('Disconnected')
      expect(status.textContent).not.toContain('Checking')
    })
  })

  // WHEN healthLoading=false + health=null (fetch failed) → "Disconnected" shown
  it('shows "Disconnected" when healthLoading=false and health is null (fetch failed)', async () => {
    render(
      <ThemeProvider>
        <LocalAiPanel health={null} healthLoading={false} />
      </ThemeProvider>,
    )
    await waitFor(() => {
      const status = screen.getByTestId('local-ai-status')
      expect(status.textContent).toContain('Disconnected')
    })
  })

  // Default healthLoading=false: existing behaviour unchanged when prop is omitted
  it('defaults to showing "Disconnected" when healthLoading prop is omitted and health is null', async () => {
    render(
      <ThemeProvider>
        <LocalAiPanel health={null} />
      </ThemeProvider>,
    )
    await waitFor(() => {
      const status = screen.getByTestId('local-ai-status')
      expect(status.textContent).toContain('Disconnected')
    })
  })
})

// ---------------------------------------------------------------------------
// Tests — #573: test-endpoint result text wraps (word-break)
// ---------------------------------------------------------------------------

describe('LocalAiPanel — #573 test-endpoint result word-break', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_RESPONSE)
  })

  // Test-endpoint result div must have word-break style to prevent horizontal clipping
  it('applies word-break style to the test-endpoint result element', async () => {
    const user = userEvent.setup()
    mockFetchAiModels.mockResolvedValue(MODELS_RESPONSE)
    render(
      <ThemeProvider>
        <LocalAiPanel health={HEALTH_CONNECTED} />
      </ThemeProvider>,
    )
    await screen.findByTestId('model-select')
    vi.clearAllMocks()
    mockFetchAiModels.mockResolvedValue({
      models: ['llama3.2:latest', 'qwen3:14b-instruct', 'mistral:7b-instruct-v0.2-q4_K_M'],
      current: null,
    })

    const testBtn = screen.getByTestId('test-endpoint-btn')
    await user.click(testBtn)

    await waitFor(() => {
      const result = screen.getByTestId('test-endpoint-result')
      expect(result).toBeInTheDocument()
      // The element must have word-break:break-all or overflow-wrap:break-word
      // to prevent horizontal overflow on long model name lists (#573).
      const style = result.style
      const hasWordBreak = style.wordBreak === 'break-all' || style.overflowWrap === 'break-word'
      expect(hasWordBreak).toBe(true)
    })
  })
})
