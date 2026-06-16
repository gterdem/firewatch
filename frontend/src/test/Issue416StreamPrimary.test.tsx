/**
 * Tests for issue #416 — stream is the PRIMARY (sole) deep-analysis trigger.
 *
 * The defect: when the entity slide-over opened for an IP with no cached analysis,
 * BOTH useDeepAnalysis (non-streaming GET /threats/{ip}/detailed?ai=true) AND
 * useStageTicker (streaming GET /threats/{ip}/detailed/stream) fired concurrently.
 * The backend's single-flight guard returned 409 for the second request, causing
 * the stream to error and DeepAnalysisControl to fall back to AiSectionSkeleton.
 * Net effect: the MK-11 stage ticker never appeared on the FIRST (auto-triggered)
 * analysis run.
 *
 * The fix (MK-11 / issue #416):
 *   - useDeepAnalysis enters phase='analyzing' via startStreamDrivenAnalysis() which
 *     does NOT call fetchDetailedAnalysis. The SSE stream is the sole trigger.
 *   - receiveStreamResult() delivers the terminal result to useDeepAnalysis.
 *   - triggerStreamFallback() fires the non-streaming path ONLY on genuine stream errors.
 *
 * EARS acceptance criteria:
 *   #416-1: On slide-over open (AI online, no cache), the stream fires and the
 *           non-streaming fetchDetailedAnalysis(ip, true) does NOT run concurrently.
 *   #416-2: When the stream errors for a genuine reason, the fallback non-streaming
 *           path fires and the analysis still completes.
 *   #416-3: onStreamError is called on DeepAnalysisControl when the stream errors.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import DeepAnalysisControl from '../components/entity/ip/DeepAnalysisControl'
import { useDeepAnalysis } from '../components/entity/ip/useDeepAnalysis'
import { clearAnalysisCache } from '../components/entity/analysisCache'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const { mockFetchDetailedAnalysis, mockFetchHealth, mockResolveBaseUrl } = vi.hoisted(() => ({
  mockFetchDetailedAnalysis: vi.fn(),
  mockFetchHealth: vi.fn(),
  mockResolveBaseUrl: vi.fn().mockReturnValue(''),
}))

vi.mock('../api/logs', () => ({
  fetchDetailedAnalysis: mockFetchDetailedAnalysis,
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
  fetchThreatScore: vi.fn().mockResolvedValue(null),
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
 * Minimal harness that mirrors how IpPanel wires useDeepAnalysis + DeepAnalysisControl.
 * Exposes the `phase` state via data-testid so tests can assert lifecycle progression.
 */
function StreamDrivenHarness({ ip }: { ip: string }) {
  const { phase, receiveStreamResult, triggerStreamFallback } = useDeepAnalysis(ip)
  return (
    <div>
      <span data-testid="deep-phase">{phase}</span>
      <DeepAnalysisControl
        phase={phase}
        elapsedSeconds={0}
        modelName="qwen3:8b"
        onRun={vi.fn()}
        ip={ip}
        onStreamResult={receiveStreamResult}
        onStreamError={triggerStreamFallback}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
  clearAnalysisCache()
  mockResolveBaseUrl.mockReturnValue('')
})

// ---------------------------------------------------------------------------
// #416-1: stream is the sole trigger — no concurrent non-streaming fetch
// ---------------------------------------------------------------------------

describe('Issue #416-1 — no concurrent non-streaming fetch when stream runs', () => {
  it('opening panel with AI online fires the stream only — fetchDetailedAnalysis(ip, true) NOT called', async () => {
    // AI is online.
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'qwen3:8b',
      db_ok: true,
    })

    // Stream: sends validated stage + terminal result.
    const resultPayload = { ip: '192.0.2.200', score: 80, threat_level: 'HIGH' }
    const stream = makeSSEStream([
      'event: stage\ndata: {"stage":"validated"}\n\n',
      `event: result\ndata: ${JSON.stringify(resultPayload)}\n\n`,
    ])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    render(<StreamDrivenHarness ip="192.0.2.200" />)

    // Phase transitions to analyzing — stream has started.
    await waitFor(() => {
      expect(screen.getByTestId('deep-phase').textContent).toBe('analyzing')
    })

    // Non-streaming AI fetch must NOT have been called — stream is the sole trigger.
    // This is the core assertion: eliminates the self-inflicted 409.
    expect(mockFetchDetailedAnalysis).not.toHaveBeenCalledWith('192.0.2.200', true)

    // Stream completes → phase transitions to complete via receiveStreamResult.
    await waitFor(() => {
      expect(screen.getByTestId('deep-phase').textContent).toBe('complete')
    }, { timeout: 2000 })

    // Even after completion, non-streaming fetch was never called.
    expect(mockFetchDetailedAnalysis).not.toHaveBeenCalledWith('192.0.2.200', true)
  })

  it('the stage ticker (StageTicker) is rendered on first open — not just on re-run', async () => {
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'qwen3:8b',
      db_ok: true,
    })

    const encoder = new TextEncoder()
    // Stream: sends a stage event and stays open (simulates live generating).
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(
          encoder.encode('event: stage\ndata: {"stage":"prompt_built","sample_count":10}\n\n'),
        )
        // Don't close — still streaming.
      },
    })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    render(<StreamDrivenHarness ip="192.0.2.201" />)

    // The StageTicker must appear on FIRST open (the defect was it only appeared on re-run).
    await waitFor(() => {
      expect(screen.getByTestId('stage-ticker')).toBeTruthy()
    }, { timeout: 2000 })

    // Confirm it is a real ticker line (not a skeleton).
    expect(screen.queryByTestId('ai-section-skeleton')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// #416-2: stream error falls back to non-streaming path
// ---------------------------------------------------------------------------

describe('Issue #416-2 — stream error triggers non-streaming fallback', () => {
  it('network error on stream → fallback fetch fires → analysis completes', async () => {
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'qwen3:8b',
      db_ok: true,
    })

    // Stream fails immediately.
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network failed'))

    // Fallback non-streaming fetch resolves with a result.
    const fallbackResult = {
      ip: '192.0.2.202',
      score: 65,
      threat_level: 'MEDIUM',
      ai_status: 'ok',
    }
    mockFetchDetailedAnalysis.mockResolvedValue(fallbackResult)

    render(<StreamDrivenHarness ip="192.0.2.202" />)

    // Phase transitions to analyzing.
    await waitFor(() => {
      expect(screen.getByTestId('deep-phase').textContent).toBe('analyzing')
    })

    // Stream fails → AiSectionSkeleton fallback shown.
    await waitFor(() => {
      expect(screen.getByTestId('ai-section-skeleton')).toBeTruthy()
    }, { timeout: 2000 })

    // Fallback: non-streaming fetch MUST have been called (with includeAi=true).
    await waitFor(() => {
      expect(mockFetchDetailedAnalysis).toHaveBeenCalledWith('192.0.2.202', true)
    }, { timeout: 2000 })

    // Analysis completes via fallback.
    await waitFor(() => {
      expect(screen.getByTestId('deep-phase').textContent).toBe('complete')
    }, { timeout: 2000 })
  })

  it('SSE error event on stream → fallback fires → analysis completes', async () => {
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'qwen3:8b',
      db_ok: true,
    })

    // Stream sends an SSE error event.
    const stream = makeSSEStream([
      'event: error\ndata: {"detail":"Internal stream error"}\n\n',
    ])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    mockFetchDetailedAnalysis.mockResolvedValue({
      ip: '192.0.2.203', score: 50, threat_level: 'LOW', ai_status: 'ok',
    })

    render(<StreamDrivenHarness ip="192.0.2.203" />)

    // Stream error → skeleton shown.
    await waitFor(() => {
      expect(screen.getByTestId('ai-section-skeleton')).toBeTruthy()
    }, { timeout: 2000 })

    // Fallback fires.
    await waitFor(() => {
      expect(mockFetchDetailedAnalysis).toHaveBeenCalledWith('192.0.2.203', true)
    }, { timeout: 2000 })

    // Completes via fallback.
    await waitFor(() => {
      expect(screen.getByTestId('deep-phase').textContent).toBe('complete')
    }, { timeout: 2000 })
  })
})

// ---------------------------------------------------------------------------
// #416-3: onStreamError callback fires on DeepAnalysisControl stream error
// ---------------------------------------------------------------------------

describe('Issue #416-3 — onStreamError callback contract on DeepAnalysisControl', () => {
  beforeEach(() => {
    mockResolveBaseUrl.mockReturnValue('')
  })

  it('onStreamError is called exactly once when stream network-errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network failed'))

    const onStreamError = vi.fn()

    render(
      <DeepAnalysisControl
        phase="analyzing"
        elapsedSeconds={0}
        modelName="qwen3:8b"
        onRun={vi.fn()}
        ip="192.0.2.204"
        onStreamError={onStreamError}
      />,
    )

    // Wait for stream error to propagate.
    await waitFor(() => {
      expect(screen.getByTestId('ai-section-skeleton')).toBeTruthy()
    }, { timeout: 2000 })

    // onStreamError called exactly once.
    expect(onStreamError).toHaveBeenCalledTimes(1)
  })

  it('onStreamError is NOT called when stream completes successfully', async () => {
    const stream = makeSSEStream([
      'event: stage\ndata: {"stage":"validated"}\n\n',
      'event: result\ndata: {"ip":"192.0.2.205"}\n\n',
    ])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    const onStreamError = vi.fn()

    render(
      <DeepAnalysisControl
        phase="analyzing"
        elapsedSeconds={0}
        modelName="qwen3:8b"
        onRun={vi.fn()}
        ip="192.0.2.205"
        onStreamError={onStreamError}
      />,
    )

    // Wait for stream to complete (result arrives → stage ticker becomes static).
    await waitFor(() => {
      expect(screen.getByTestId('stage-ticker')).toBeTruthy()
    }, { timeout: 2000 })

    // No error — onStreamError must not have been called.
    expect(onStreamError).not.toHaveBeenCalled()
  })
})
