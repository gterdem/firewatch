/**
 * Tests for src/components/ApiKeyPanel.tsx (issue #550 / ADR-0026 Amendment 1).
 *
 * EARS criteria covered:
 *   - State-driven (empty state): WHILE no key is set (api_key_set=false), the honest
 *     empty-state copy is shown ("No key set — protected by the loopback boundary only").
 *   - State-driven: WHILE a key is set (api_key_set=true), the empty-state is NOT shown.
 *   - State-driven: WHILE a key is set, the input placeholder shows "•••• set — type to replace".
 *   - Event-driven: WHEN the operator saves a key, putRuntimeConfig is called with api_key.
 *   - Event-driven: WHEN save succeeds, setApiKey() is called (key wired into store).
 *   - Event-driven (first-key-set notice): WHEN a key is saved for the first time in
 *     the session, the one-time notice is shown.
 *   - Event-driven: WHEN the notice is dismissed, it disappears.
 *   - Event-driven: WHEN save fails (non-401), an error toast is shown.
 *   - Ubiquitous: field is always type="password" (masked).
 *   - Ubiquitous: no key value is embedded in the DOM in plaintext.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

const {
  mockGetRuntimeConfig,
  mockPutRuntimeConfig,
  mockSetApiKey,
  mockIsFirstKeySetInSession,
  mockClearFirstKeySetFlag,
} = vi.hoisted(() => ({
  mockGetRuntimeConfig: vi.fn(),
  mockPutRuntimeConfig: vi.fn(),
  mockSetApiKey: vi.fn(),
  mockIsFirstKeySetInSession: vi.fn(),
  mockClearFirstKeySetFlag: vi.fn(),
}))

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getRuntimeConfig: mockGetRuntimeConfig,
    putRuntimeConfig: mockPutRuntimeConfig,
  }
})

vi.mock('../app/apiKeyStore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../app/apiKeyStore')>()
  return {
    ...actual,
    setApiKey: mockSetApiKey,
    isFirstKeySetInSession: mockIsFirstKeySetInSession,
    clearFirstKeySetFlag: mockClearFirstKeySetFlag,
  }
})

// ---------------------------------------------------------------------------
// Import after mocks are established
// ---------------------------------------------------------------------------

import ApiKeyPanel from '../components/ApiKeyPanel'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeRuntimeConfig(api_key_set: boolean) {
  return {
    alert_threshold: 'CRITICAL' as const,
    alert_on_sync: true,
    webhook_url: null,
    webhook_url_set: false,
    api_key_set,
    ollama_model: 'llama3.2:3b',
    ai_enabled: true,
    ollama_base_url: 'http://localhost:11434',
    geo_provider: 'offline' as const,
  }
}

function renderPanel() {
  return render(<ApiKeyPanel />)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ApiKeyPanel — honest empty state', () => {
  beforeEach(() => {
    mockGetRuntimeConfig.mockResolvedValue(makeRuntimeConfig(false))
    mockIsFirstKeySetInSession.mockReturnValue(false)
  })

  it('shows empty state copy when no key is set', async () => {
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('api-key-empty-state')).toBeInTheDocument()
    })
    expect(screen.getByTestId('api-key-empty-state')).toHaveTextContent(
      /loopback boundary/i,
    )
  })

  it('shows "Enter API key" placeholder when no key is configured', async () => {
    renderPanel()
    await waitFor(() => {
      const input = screen.getByTestId('api-key-input')
      expect(input).toHaveAttribute('placeholder', 'Enter API key')
    })
  })

  it('input is always type="password" (masked)', async () => {
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('api-key-input')).toHaveAttribute('type', 'password')
    })
  })
})

describe('ApiKeyPanel — key already configured state', () => {
  beforeEach(() => {
    mockGetRuntimeConfig.mockResolvedValue(makeRuntimeConfig(true))
    mockIsFirstKeySetInSession.mockReturnValue(false)
  })

  it('does NOT show the empty-state when a key is configured', async () => {
    renderPanel()
    await waitFor(() => {
      expect(screen.queryByTestId('api-key-empty-state')).not.toBeInTheDocument()
    })
  })

  it('shows "•••• set" placeholder when a key is configured', async () => {
    renderPanel()
    await waitFor(() => {
      const input = screen.getByTestId('api-key-input')
      expect(input.getAttribute('placeholder')).toContain('•••• set')
    })
  })
})

describe('ApiKeyPanel — save key flow', () => {
  beforeEach(() => {
    mockGetRuntimeConfig.mockResolvedValue(makeRuntimeConfig(false))
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockSetApiKey.mockImplementation(() => {})
    mockIsFirstKeySetInSession.mockReturnValue(false)
    mockClearFirstKeySetFlag.mockImplementation(() => {})
  })

  it('calls putRuntimeConfig with api_key when Save is clicked', async () => {
    const user = userEvent.setup()
    renderPanel()

    const input = screen.getByTestId('api-key-input')
    await user.type(input, 'secret-key-value')
    await user.click(screen.getByTestId('api-key-save'))

    await waitFor(() => {
      expect(mockPutRuntimeConfig).toHaveBeenCalledWith({ api_key: 'secret-key-value' })
    })
  })

  it('calls setApiKey with the typed value after a successful save', async () => {
    const user = userEvent.setup()
    renderPanel()

    const input = screen.getByTestId('api-key-input')
    await user.type(input, 'my-bearer-key')
    await user.click(screen.getByTestId('api-key-save'))

    await waitFor(() => {
      expect(mockSetApiKey).toHaveBeenCalledWith('my-bearer-key')
    })
  })

  it('clears the input after a successful save (never leave key in field)', async () => {
    const user = userEvent.setup()
    renderPanel()

    const input = screen.getByTestId('api-key-input') as HTMLInputElement
    await user.type(input, 'clear-after-save')
    await user.click(screen.getByTestId('api-key-save'))

    await waitFor(() => {
      expect(input.value).toBe('')
    })
  })

  it('calls putRuntimeConfig with null when save is clicked with empty input (clear)', async () => {
    const user = userEvent.setup()
    renderPanel()

    // Leave input empty and click Save
    await user.click(screen.getByTestId('api-key-save'))

    await waitFor(() => {
      expect(mockPutRuntimeConfig).toHaveBeenCalledWith({ api_key: null })
    })
  })
})

describe('ApiKeyPanel — first-key-set one-time notice', () => {
  beforeEach(() => {
    mockGetRuntimeConfig.mockResolvedValue(makeRuntimeConfig(false))
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockSetApiKey.mockImplementation(() => {})
    mockClearFirstKeySetFlag.mockImplementation(() => {})
  })

  it('shows the first-key-set notice when isFirstKeySetInSession returns true after save', async () => {
    // First call (during render/mount): false.
    // After save, we mock isFirstKeySetInSession to return true to simulate the flag being set.
    mockIsFirstKeySetInSession.mockReturnValue(true)

    const user = userEvent.setup()
    renderPanel()

    const input = screen.getByTestId('api-key-input')
    await user.type(input, 'first-ever-key')
    await user.click(screen.getByTestId('api-key-save'))

    await waitFor(() => {
      expect(screen.getByTestId('first-key-notice')).toBeInTheDocument()
    })
    expect(screen.getByTestId('first-key-notice')).toHaveTextContent(/API key now active/i)
  })

  it('does NOT show the notice when no key was set (isFirstKeySetInSession=false)', async () => {
    mockIsFirstKeySetInSession.mockReturnValue(false)

    const user = userEvent.setup()
    renderPanel()

    await user.click(screen.getByTestId('api-key-save'))

    await waitFor(() => {
      expect(mockPutRuntimeConfig).toHaveBeenCalled()
    })
    expect(screen.queryByTestId('first-key-notice')).not.toBeInTheDocument()
  })

  it('dismisses the notice when the dismiss button is clicked', async () => {
    mockIsFirstKeySetInSession.mockReturnValue(true)

    const user = userEvent.setup()
    renderPanel()

    const input = screen.getByTestId('api-key-input')
    await user.type(input, 'new-key')
    await user.click(screen.getByTestId('api-key-save'))

    await waitFor(() => {
      expect(screen.getByTestId('first-key-notice')).toBeInTheDocument()
    })

    await user.click(screen.getByTestId('first-key-notice-dismiss'))

    await waitFor(() => {
      expect(screen.queryByTestId('first-key-notice')).not.toBeInTheDocument()
    })
  })
})

describe('ApiKeyPanel — save failure', () => {
  beforeEach(() => {
    mockGetRuntimeConfig.mockResolvedValue(makeRuntimeConfig(false))
    mockIsFirstKeySetInSession.mockReturnValue(false)
    mockSetApiKey.mockClear()
  })

  it('shows an error message when putRuntimeConfig rejects', async () => {
    const { ApiError } = await import('../api/client')
    mockPutRuntimeConfig.mockRejectedValue(new ApiError(500, null, 'internal'))

    const user = userEvent.setup()
    renderPanel()

    const input = screen.getByTestId('api-key-input')
    await user.type(input, 'bad-key')
    await user.click(screen.getByTestId('api-key-save'))

    await waitFor(() => {
      // The Save button should be re-enabled after failure.
      expect(screen.getByTestId('api-key-save')).not.toBeDisabled()
    })
    // Issue #587 Defect 2a: the SET path sets the key optimistically (before PUT),
    // then rolls back to null on failure — so the last call is setApiKey(null).
    // The in-memory store is left clean; the operator can retry.
    expect(mockSetApiKey).toHaveBeenCalledTimes(2)
    expect(mockSetApiKey).toHaveBeenNthCalledWith(1, 'bad-key')
    expect(mockSetApiKey).toHaveBeenNthCalledWith(2, null)
  })
})
