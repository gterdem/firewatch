/**
 * Tests for issue #525 — opening a second IP while first is streaming returns 409
 * and the slide-over closes silently (no "Analysis already running — please wait" message).
 *
 * Root causes fixed:
 *
 *   A. `resultDispatched` (useState) and `errorDispatchedRef` (useRef) in DeepAnalysisControl
 *      are NOT reset when the `ip` prop changes to a new entity. Without the reset:
 *      - If IP-1 completed (resultDispatched=true), IP-2's stream result would never be
 *        forwarded to useDeepAnalysis(ip2), leaving it stuck in 'analyzing'.
 *      - If IP-1 had a stream error (errorDispatched=true), IP-2's stream error would not
 *        trigger the fallback fetch via onStreamError, leaving it stuck similarly.
 *   Fix: useEffect in DeepAnalysisControl resets both flags when `ip` changes.
 *
 *   B. The non-streaming fallback fetch (called by triggerStreamFallback when the SSE
 *      stream errors for a non-409 reason) can also return 409 if the concurrent analysis
 *      is still running. Previously this dispatched FAILED with "AI analysis failed (409)",
 *      showing the generic error badge rather than the honest "please wait" message.
 *   Fix: useDeepAnalysis.fireNonStreamingFetch detects ApiError(409) and dispatches CONFLICT
 *        → phase='conflict' → DeepAnalysisControl renders the "please wait" badge.
 *
 * EARS acceptance criteria:
 *
 *   EARS-525-1: Changing IP prop resets resultDispatched — IP-2's stream result is
 *               forwarded to useDeepAnalysis even if IP-1 had completed earlier.
 *   EARS-525-2: Changing IP prop resets errorDispatchedRef — IP-2's stream error triggers
 *               the fallback fetch even if IP-1 had already triggered it.
 *   EARS-525-3: Non-streaming fallback returning 409 shows "Analysis already running — please wait"
 *               (phase='conflict') instead of the generic error badge (phase='failed').
 *   EARS-525-4: The conflict badge has role="status" and aria-live="polite" for accessibility.
 *   EARS-525-5: useDeepAnalysis exposes phase='conflict' (not 'failed') when fallback returns 409.
 *   EARS-525-6: Same-IP persistentConflict behavior preserved (UT-02 regression guard).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import { useState } from 'react'
import DeepAnalysisControl from '../components/entity/ip/DeepAnalysisControl'
import { useDeepAnalysis } from '../components/entity/ip/useDeepAnalysis'
import { clearAnalysisCache } from '../components/entity/analysisCache'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const { mockFetchHealth, mockFetchDetailedAnalysis, mockResolveBaseUrl } = vi.hoisted(() => ({
  mockFetchHealth: vi.fn(),
  mockFetchDetailedAnalysis: vi.fn(),
  mockResolveBaseUrl: vi.fn().mockReturnValue(''),
}))

vi.mock('../api/client', () => ({
  fetchHealth: mockFetchHealth,
  resolveBaseUrl: mockResolveBaseUrl,
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchThreats: vi.fn().mockResolvedValue([]),
  assertLoopbackBase: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: unknown) {
      super(String(message ?? status))
      this.status = status
    }
  },
}))

vi.mock('../api/logs', () => ({
  fetchDetailedAnalysis: mockFetchDetailedAnalysis,
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
  fetchThreatScore: vi.fn().mockResolvedValue(null),
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build an SSE ReadableStream from a list of raw SSE frame strings. */
function makeSSEStream(frames: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder()
  return new ReadableStream({
    start(controller) {
      for (const frame of frames) {
        controller.enqueue(encoder.encode(frame))
      }
      controller.close()
    },
  })
}

/**
 * Minimal harness mirroring IpPanel's wiring of useDeepAnalysis + DeepAnalysisControl.
 * Accepts an `ip` prop that can change to simulate opening a new entity.
 */
function AnalysisHarness({ ip }: { ip: string }) {
  const {
    phase,
    elapsedSeconds,
    modelName,
    fromCache,
    fetchedAt,
    receiveStreamResult,
    triggerStreamFallback,
    runDeepAnalysis,
  } = useDeepAnalysis(ip)

  return (
    <div>
      <span data-testid="deep-phase">{phase}</span>
      <DeepAnalysisControl
        phase={phase}
        elapsedSeconds={elapsedSeconds}
        modelName={modelName}
        onRun={runDeepAnalysis}
        ip={ip}
        fromCache={fromCache}
        fetchedAt={fetchedAt}
        onStreamResult={receiveStreamResult}
        onStreamError={triggerStreamFallback}
      />
    </div>
  )
}

/**
 * Wrapper that can switch from IP-1 to IP-2 via a button click.
 * Models "clicking a second IP" while the first is still streaming.
 */
function SwitchableHarness() {
  const [ip, setIp] = useState('192.0.2.1')
  return (
    <div>
      <button data-testid="switch-to-ip2" onClick={() => setIp('192.0.2.2')}>
        Open IP-2
      </button>
      <AnalysisHarness ip={ip} />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
  clearAnalysisCache()
  mockResolveBaseUrl.mockReturnValue('')
  // AI is online by default
  mockFetchHealth.mockResolvedValue({
    status: 'ok',
    ollama_connected: true,
    ollama_model: 'gemma3:4b',
    db_ok: true,
  })
})

afterEach(() => {
  vi.useRealTimers()
})

// ---------------------------------------------------------------------------
// EARS-525-1: resultDispatched resets on IP change
// ---------------------------------------------------------------------------

describe('EARS-525-1 — resultDispatched resets when ip prop changes', () => {
  it('IP-2 stream result is forwarded to useDeepAnalysis after IP-1 already completed', async () => {
    // IP-1 stream: sends a result immediately
    const ip1Result = { ip: '192.0.2.1', score: 80, threat_level: 'HIGH' }
    const ip1Stream = makeSSEStream([
      `event: result\ndata: ${JSON.stringify(ip1Result)}\n\n`,
    ])
    // IP-2 stream: also sends a result
    const ip2Result = { ip: '192.0.2.2', score: 55, threat_level: 'MEDIUM' }
    const ip2Stream = makeSSEStream([
      `event: result\ndata: ${JSON.stringify(ip2Result)}\n\n`,
    ])

    let fetchCallCount = 0
    globalThis.fetch = vi.fn().mockImplementation(() => {
      fetchCallCount++
      if (fetchCallCount === 1) {
        return Promise.resolve({ ok: true, status: 200, body: ip1Stream } as Response)
      }
      return Promise.resolve({ ok: true, status: 200, body: ip2Stream } as Response)
    })

    render(<SwitchableHarness />)

    // IP-1 completes: phase should become 'complete'
    await waitFor(() => {
      expect(screen.getByTestId('deep-phase').textContent).toBe('complete')
    }, { timeout: 2000 })

    // Open IP-2 (simulates user clicking a second IP after IP-1 analysis completed)
    await act(async () => {
      screen.getByTestId('switch-to-ip2').click()
    })

    // IP-2 should also reach 'complete' — resultDispatched was reset on IP change
    await waitFor(() => {
      expect(screen.getByTestId('deep-phase').textContent).toBe('complete')
    }, { timeout: 2000 })
  })
})

// ---------------------------------------------------------------------------
// EARS-525-2: errorDispatchedRef resets on IP change
// ---------------------------------------------------------------------------

describe('EARS-525-2 — errorDispatchedRef resets when ip prop changes', () => {
  it('IP-2 stream error triggers fallback fetch even if IP-1 had already triggered it', async () => {
    // IP-1 stream: network error → triggers fallback (errorDispatchedRef → true)
    // IP-2 stream: also network error → fallback should fire again for IP-2
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network failed'))

    // Fallback fetch resolves for both IPs
    mockFetchDetailedAnalysis.mockResolvedValue({
      ip: 'any', score: 60, threat_level: 'LOW', ai_status: 'ok',
    })

    render(<SwitchableHarness />)

    // IP-1: stream errors → fallback fires → should reach 'complete'
    await waitFor(() => {
      expect(screen.getByTestId('deep-phase').textContent).toBe('complete')
    }, { timeout: 2000 })

    // Verify fallback was called once for IP-1
    expect(mockFetchDetailedAnalysis).toHaveBeenCalledTimes(1)

    vi.clearAllMocks()
    // Re-establish the mock so IP-2's stream also errors
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network failed'))
    mockFetchDetailedAnalysis.mockResolvedValue({
      ip: 'any', score: 60, threat_level: 'LOW', ai_status: 'ok',
    })

    // Open IP-2
    await act(async () => {
      screen.getByTestId('switch-to-ip2').click()
    })

    // IP-2: stream errors → fallback fires AGAIN (errorDispatchedRef was reset)
    // → phase should reach 'complete' (not stuck in 'analyzing')
    await waitFor(() => {
      expect(mockFetchDetailedAnalysis).toHaveBeenCalledTimes(1)
    }, { timeout: 2000 })

    await waitFor(() => {
      expect(screen.getByTestId('deep-phase').textContent).toBe('complete')
    }, { timeout: 2000 })
  })
})

// ---------------------------------------------------------------------------
// EARS-525-3: fallback 409 shows conflict badge (not generic error)
// ---------------------------------------------------------------------------

describe('EARS-525-3 — non-streaming fallback returning 409 shows conflict badge', () => {
  it('phase becomes "conflict" and conflict badge is visible when fallback fetch returns 409', async () => {
    // Stream: genuine non-409 error → triggers fallback
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network failed'))

    // Fallback fetch returns 409 (concurrent analysis is running)
    const { ApiError } = await import('../api/client')
    mockFetchDetailedAnalysis.mockRejectedValue(new ApiError(409, 'Conflict'))

    render(<AnalysisHarness ip="192.0.2.99" />)

    // Should reach phase='conflict' (not 'failed')
    await waitFor(() => {
      expect(screen.getByTestId('deep-phase').textContent).toBe('conflict')
    }, { timeout: 2000 })

    // Conflict badge must be visible
    expect(screen.getByTestId('deep-analysis-conflict-badge')).toBeInTheDocument()
    expect(screen.getByTestId('deep-analysis-conflict-badge')).toHaveTextContent(
      'Analysis already running — please wait',
    )
  })

  it('phase stays "failed" (not "conflict") when fallback fetch returns a non-409 error', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network failed'))

    const { ApiError } = await import('../api/client')
    mockFetchDetailedAnalysis.mockRejectedValue(new ApiError(500, 'Internal Server Error'))

    render(<AnalysisHarness ip="192.0.2.100" />)

    await waitFor(() => {
      expect(screen.getByTestId('deep-phase').textContent).toBe('failed')
    }, { timeout: 2000 })

    // Generic error badge, NOT the conflict badge
    expect(screen.getByTestId('deep-analysis-failed-badge')).toBeInTheDocument()
    expect(screen.queryByTestId('deep-analysis-conflict-badge')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// EARS-525-4: conflict badge accessibility
// ---------------------------------------------------------------------------

describe('EARS-525-4 — conflict badge has correct ARIA attributes', () => {
  it('conflict badge has role="status" and aria-live="polite"', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network failed'))
    const { ApiError } = await import('../api/client')
    mockFetchDetailedAnalysis.mockRejectedValue(new ApiError(409, 'Conflict'))

    render(<AnalysisHarness ip="192.0.2.101" />)

    await waitFor(() => {
      expect(screen.getByTestId('deep-analysis-conflict-badge')).toBeInTheDocument()
    }, { timeout: 2000 })

    const badge = screen.getByTestId('deep-analysis-conflict-badge')
    expect(badge).toHaveAttribute('role', 'status')
    expect(badge).toHaveAttribute('aria-live', 'polite')
  })
})

// ---------------------------------------------------------------------------
// EARS-525-5: useDeepAnalysis phase='conflict' exposed correctly
// ---------------------------------------------------------------------------

describe('EARS-525-5 — useDeepAnalysis.phase="conflict" on fallback 409', () => {
  it('phase transitions idle→analyzing→conflict (not failed) when stream errors + fallback 409', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network failed'))
    const { ApiError } = await import('../api/client')
    mockFetchDetailedAnalysis.mockRejectedValue(new ApiError(409, 'Conflict'))

    render(<AnalysisHarness ip="192.0.2.102" />)

    // Starts at health_check/analyzing
    await waitFor(() => {
      const phase = screen.getByTestId('deep-phase').textContent
      expect(phase === 'analyzing' || phase === 'health_check').toBe(true)
    }, { timeout: 1000 })

    // Ends at conflict (not failed)
    await waitFor(() => {
      expect(screen.getByTestId('deep-phase').textContent).toBe('conflict')
    }, { timeout: 2000 })
  })
})

// ---------------------------------------------------------------------------
// EARS-525-6: same-IP persistentConflict behavior preserved (UT-02 regression)
// ---------------------------------------------------------------------------

describe('EARS-525-6 — same-IP persistentConflict behavior preserved (UT-02 regression)', () => {
  let originalFetch: typeof globalThis.fetch

  beforeEach(() => {
    originalFetch = globalThis.fetch
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it('all-409 SSE stream (same IP) still shows "please wait" via persistentConflict path', async () => {
    // ALL fetch calls return 409 — the useStageTicker PERSISTENT_CONFLICT path
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 409,
      ok: false,
      body: null,
    } as Response)

    const onStreamError = vi.fn()

    render(
      <DeepAnalysisControl
        phase="analyzing"
        elapsedSeconds={0}
        modelName={null}
        onRun={vi.fn()}
        ip="192.0.2.1"
        onStreamError={onStreamError}
      />,
    )

    // Conflict badge should appear (via persistentConflict in useStageTicker)
    await waitFor(() => {
      expect(screen.getByTestId('deep-analysis-conflict-badge')).toBeInTheDocument()
    }, { timeout: 3000 })

    expect(screen.getByTestId('deep-analysis-conflict-badge')).toHaveTextContent(
      'Analysis already running — please wait',
    )

    // onStreamError must NOT have been called (UT-02 guarantee preserved)
    expect(onStreamError).not.toHaveBeenCalled()
  })
})
