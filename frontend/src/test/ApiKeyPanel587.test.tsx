/**
 * Tests for ApiKeyPanel.tsx — issue #587 regression guard.
 *
 * EARS criteria covered (defects 2a + 2b):
 *
 * Defect 2a — save ordering:
 *   - SET path: WHEN saving a new key, setApiKey(value) is called BEFORE
 *     putRuntimeConfig so the PUT carries the bearer (the key is wired into
 *     buildHeaders before the request goes out).
 *   - SET path on failure: WHEN putRuntimeConfig rejects, setApiKey is rolled
 *     back to null so no wrong key is stuck in the store.
 *   - CLEAR path: WHEN clearing a key, putRuntimeConfig is called BEFORE
 *     setApiKey(null) so the PUT still carries the existing bearer.
 *
 * Defect 2b — 401 mount awareness:
 *   - WHEN GET /config/runtime returns 401 on mount, the panel shows a
 *     "key configured — re-enter to manage" state (needsReauth / data-testid
 *     "api-key-reauth-state"), NOT the "no key set" empty state.
 *   - WHEN GET /config/runtime returns any other error on mount, the panel
 *     falls back to the honest "no key set" empty state.
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
// Defect 2b — 401 mount awareness
// ---------------------------------------------------------------------------

describe('ApiKeyPanel — 401 on mount (#587 Defect 2b)', () => {
  beforeEach(() => {
    mockIsFirstKeySetInSession.mockReturnValue(false)
    mockSetApiKey.mockClear()
  })

  it('shows the re-enter state when GET /config/runtime returns 401', async () => {
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockRejectedValue(new ApiError(401, null, 'Unauthorized'))

    renderPanel()

    await waitFor(() => {
      expect(screen.getByTestId('api-key-reauth-state')).toBeInTheDocument()
    })
    expect(screen.getByTestId('api-key-reauth-state')).toHaveTextContent(
      /re-enter/i,
    )
  })

  it('does NOT show the empty-state when GET /config/runtime returns 401', async () => {
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockRejectedValue(new ApiError(401, null, 'Unauthorized'))

    renderPanel()

    await waitFor(() => {
      expect(screen.getByTestId('api-key-reauth-state')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('api-key-empty-state')).not.toBeInTheDocument()
  })

  it('shows the "•••• set" placeholder when GET /config/runtime returns 401', async () => {
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockRejectedValue(new ApiError(401, null, 'Unauthorized'))

    renderPanel()

    await waitFor(() => {
      const input = screen.getByTestId('api-key-input') as HTMLInputElement
      expect(input.getAttribute('placeholder')).toContain('•••• set')
    })
  })

  it('shows the empty-state when GET /config/runtime returns a non-401 error', async () => {
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockRejectedValue(new ApiError(503, null, 'Service unavailable'))

    renderPanel()

    // After the async rejection resolves, the empty state should still be shown
    // (no reauth state for non-401 failures).
    await waitFor(() => {
      // The Save button is always rendered — we wait for it to appear to let
      // the effect settle, then assert the empty state is present.
      expect(screen.getByTestId('api-key-save')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('api-key-reauth-state')).not.toBeInTheDocument()
    expect(screen.getByTestId('api-key-empty-state')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Defect 2a — save ordering: SET path
// ---------------------------------------------------------------------------

describe('ApiKeyPanel — SET path save ordering (#587 Defect 2a)', () => {
  beforeEach(() => {
    mockGetRuntimeConfig.mockResolvedValue(makeRuntimeConfig(false))
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockSetApiKey.mockClear()
    mockIsFirstKeySetInSession.mockReturnValue(false)
    mockClearFirstKeySetFlag.mockImplementation(() => {})
  })

  it('calls setApiKey(value) BEFORE putRuntimeConfig on the SET path', async () => {
    // Track the call order to verify setApiKey precedes putRuntimeConfig.
    const callOrder: string[] = []
    mockSetApiKey.mockImplementation(() => { callOrder.push('setApiKey') })
    mockPutRuntimeConfig.mockImplementation(async () => { callOrder.push('putRuntimeConfig') })

    const user = userEvent.setup()
    renderPanel()

    const input = screen.getByTestId('api-key-input')
    await user.type(input, 'new-key-value')
    await user.click(screen.getByTestId('api-key-save'))

    await waitFor(() => {
      expect(mockPutRuntimeConfig).toHaveBeenCalled()
    })

    // setApiKey must have been called before putRuntimeConfig.
    const setIdx = callOrder.indexOf('setApiKey')
    const putIdx = callOrder.indexOf('putRuntimeConfig')
    expect(setIdx).toBeGreaterThanOrEqual(0)
    expect(putIdx).toBeGreaterThanOrEqual(0)
    expect(setIdx).toBeLessThan(putIdx)
  })

  it('rolls back setApiKey to null when putRuntimeConfig rejects on the SET path', async () => {
    const { ApiError } = await import('../api/client')
    mockPutRuntimeConfig.mockRejectedValue(new ApiError(401, null, 'Unauthorized'))

    const user = userEvent.setup()
    renderPanel()

    const input = screen.getByTestId('api-key-input')
    await user.type(input, 'bad-key')
    await user.click(screen.getByTestId('api-key-save'))

    await waitFor(() => {
      expect(screen.getByTestId('api-key-save')).not.toBeDisabled()
    })

    // Should have been called twice: once with the value (optimistic), once with null (rollback).
    expect(mockSetApiKey).toHaveBeenCalledTimes(2)
    expect(mockSetApiKey).toHaveBeenNthCalledWith(1, 'bad-key')
    expect(mockSetApiKey).toHaveBeenNthCalledWith(2, null)
  })
})

// ---------------------------------------------------------------------------
// Defect 2a — save ordering: CLEAR path
// ---------------------------------------------------------------------------

describe('ApiKeyPanel — CLEAR path save ordering (#587 Defect 2a)', () => {
  beforeEach(() => {
    mockGetRuntimeConfig.mockResolvedValue(makeRuntimeConfig(true))
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockSetApiKey.mockClear()
    mockIsFirstKeySetInSession.mockReturnValue(false)
    mockClearFirstKeySetFlag.mockImplementation(() => {})
  })

  it('calls putRuntimeConfig BEFORE setApiKey(null) on the CLEAR path', async () => {
    const callOrder: string[] = []
    mockSetApiKey.mockImplementation(() => { callOrder.push('setApiKey') })
    mockPutRuntimeConfig.mockImplementation(async () => { callOrder.push('putRuntimeConfig') })

    const user = userEvent.setup()
    renderPanel()

    // Leave the input empty (blank = clear) and click Save.
    await waitFor(() => {
      expect(screen.getByTestId('api-key-save')).toBeInTheDocument()
    })
    await user.click(screen.getByTestId('api-key-save'))

    await waitFor(() => {
      expect(mockSetApiKey).toHaveBeenCalled()
    })

    // putRuntimeConfig must have been called before setApiKey(null).
    const putIdx = callOrder.indexOf('putRuntimeConfig')
    const setIdx = callOrder.indexOf('setApiKey')
    expect(putIdx).toBeGreaterThanOrEqual(0)
    expect(setIdx).toBeGreaterThanOrEqual(0)
    expect(putIdx).toBeLessThan(setIdx)
  })

  it('calls setApiKey(null) after the CLEAR PUT succeeds', async () => {
    const user = userEvent.setup()
    renderPanel()

    await waitFor(() => {
      expect(screen.getByTestId('api-key-save')).toBeInTheDocument()
    })
    await user.click(screen.getByTestId('api-key-save'))

    await waitFor(() => {
      expect(mockSetApiKey).toHaveBeenCalledWith(null)
    })
    // Only one setApiKey call (no optimistic + rollback on the clear path).
    expect(mockSetApiKey).toHaveBeenCalledTimes(1)
  })

  it('does NOT call setApiKey(null) when the CLEAR PUT fails', async () => {
    const { ApiError } = await import('../api/client')
    mockPutRuntimeConfig.mockRejectedValue(new ApiError(401, null, 'Unauthorized'))

    const user = userEvent.setup()
    renderPanel()

    await waitFor(() => {
      expect(screen.getByTestId('api-key-save')).toBeInTheDocument()
    })
    await user.click(screen.getByTestId('api-key-save'))

    await waitFor(() => {
      expect(screen.getByTestId('api-key-save')).not.toBeDisabled()
    })

    // On clear failure, setApiKey must NOT be called — the existing bearer stays in place.
    expect(mockSetApiKey).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Defect 2b — reauth state clears after successful save
// ---------------------------------------------------------------------------

describe('ApiKeyPanel — reauth state resolves after successful save (#587)', () => {
  it('hides the reauth state after operator successfully enters a key', async () => {
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockRejectedValue(new ApiError(401, null, 'Unauthorized'))
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockSetApiKey.mockImplementation(() => {})
    mockIsFirstKeySetInSession.mockReturnValue(false)
    mockClearFirstKeySetFlag.mockImplementation(() => {})

    const user = userEvent.setup()
    renderPanel()

    // Wait for the reauth state to appear.
    await waitFor(() => {
      expect(screen.getByTestId('api-key-reauth-state')).toBeInTheDocument()
    })

    // Enter a new key and save.
    const input = screen.getByTestId('api-key-input')
    await user.type(input, 'recovered-key')
    await user.click(screen.getByTestId('api-key-save'))

    // After a successful save, the reauth state should be gone.
    await waitFor(() => {
      expect(screen.queryByTestId('api-key-reauth-state')).not.toBeInTheDocument()
    })
  })
})
