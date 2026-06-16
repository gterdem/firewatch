/**
 * Tests for MK-11 — Stage ticker on slide-over deep analysis + AI-page re-run.
 * ADR-0046: fetch-stream SSE, AbortController, fallback, honesty.
 *
 * EARS acceptance criteria covered:
 *
 * stages.ts (pure parser):
 *   EARS-MK11-1: parseSseBlock parses event+data fields from an SSE block.
 *   EARS-MK11-2: parseStageFact returns null for unknown stage names (forward-compat drop).
 *   EARS-MK11-3: parseStageFact returns null for non-'stage' events (result/error handled by hook).
 *   EARS-MK11-4: parseStageFact correctly types all closed stage facts.
 *   EARS-MK11-5: formatStageLabel returns correct human-readable labels.
 *
 * useStageTicker.ts:
 *   EARS-MK11-6: AbortController aborts on unmount (abort-on-unmount mandatory test).
 *   EARS-MK11-7: Stream error → streamError=true (fallback signal).
 *   EARS-MK11-8: successful stream → stages accumulate + result received.
 *   EARS-MK11-9: generating heartbeats overwrite generatingElapsedMs (not accumulated in stages).
 *   EARS-MK11-10: unknown event types dropped silently (forward-compat).
 *
 * StageTicker.tsx:
 *   EARS-MK11-11: renders stage lines from facts.
 *   EARS-MK11-12: aria-live="polite" region present.
 *   EARS-MK11-13: generating counter line rendered with aria-hidden (not announced).
 *
 * DeepAnalysisControl.tsx:
 *   EARS-MK11-14: phase='analyzing' renders stage-ticker (not just skeleton).
 *   EARS-MK11-15: phase='analyzing' stream error renders AiSectionSkeleton fallback.
 *
 * VerdictCard.tsx:
 *   EARS-MK11-16: Re-run analysis button present on VerdictCard.
 *   EARS-MK11-17: clicking Re-run mounts the ticker (streaming state visible).
 *   EARS-MK11-18: NO model-authored text rendered from stage events.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  parseSseBlock,
  parseStageFact,
  formatStageLabel,
} from '../components/entity/ip/ticker/stages'
import type { StageFact } from '../components/entity/ip/ticker/stages'
import StageTicker from '../components/entity/ip/ticker/StageTicker'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ANALYSIS_FIXTURE = {
  id: 1,
  ip: '192.0.2.1',
  kind: 'detailed',
  model: 'qwen3:8b',
  endpoint_host: '127.0.0.1:11434',
  ai_status: 'ok',
  threat_level: 'HIGH',
  confidence: 0.87,
  score: 78,
  score_derivation: 'ai',
  latency_ms: 1200,
  prompt_tokens: null,
  completion_tokens: null,
  schema_version: 1,
  created_at: '2026-06-12T10:00:00Z',
  feedback: null,
}

// ---------------------------------------------------------------------------
// EARS-MK11-1 to MK11-5: stages.ts pure parser tests
// ---------------------------------------------------------------------------

describe('stages.ts — parseSseBlock', () => {
  it('EARS-MK11-1: parses event and data fields from a standard SSE block', () => {
    const block = 'event: stage\ndata: {"stage":"prompt_built","sample_count":12}'
    const frame = parseSseBlock(block)
    expect(frame).not.toBeNull()
    expect(frame!.event).toBe('stage')
    expect(frame!.data).toBe('{"stage":"prompt_built","sample_count":12}')
  })

  it('parses multi-data-line blocks by joining with newline', () => {
    const block = 'event: stage\ndata: line1\ndata: line2'
    const frame = parseSseBlock(block)
    expect(frame!.data).toBe('line1\nline2')
  })

  it('returns null for blocks with no data lines', () => {
    const block = 'event: comment\n: ignored'
    const frame = parseSseBlock(block)
    expect(frame).toBeNull()
  })

  it('defaults event to "message" when no event field', () => {
    const block = 'data: {"stage":"validated"}'
    const frame = parseSseBlock(block)
    expect(frame!.event).toBe('message')
  })
})

describe('stages.ts — parseStageFact', () => {
  it('EARS-MK11-2: drops unknown stage names silently (forward-compat)', () => {
    const frame = { event: 'stage', data: '{"stage":"future_unknown_stage","foo":1}' }
    expect(parseStageFact(frame)).toBeNull()
  })

  it('EARS-MK11-3: returns null for non-stage events (result/error handled by hook)', () => {
    const resultFrame = { event: 'result', data: '{"stage":"validated"}' }
    expect(parseStageFact(resultFrame)).toBeNull()

    const errorFrame = { event: 'error', data: '{"detail":"some error"}' }
    expect(parseStageFact(errorFrame)).toBeNull()
  })

  it('EARS-MK11-4a: parses prompt_built fact', () => {
    const frame = { event: 'stage', data: '{"stage":"prompt_built","sample_count":12}' }
    const fact = parseStageFact(frame) as Extract<StageFact, { stage: 'prompt_built' }>
    expect(fact).not.toBeNull()
    expect(fact.stage).toBe('prompt_built')
    expect(fact.sample_count).toBe(12)
  })

  it('EARS-MK11-4b: parses request_sent fact', () => {
    const frame = {
      event: 'stage',
      data: '{"stage":"request_sent","model":"qwen3:8b","endpoint_host":"127.0.0.1:11434"}',
    }
    const fact = parseStageFact(frame) as Extract<StageFact, { stage: 'request_sent' }>
    expect(fact.stage).toBe('request_sent')
    expect(fact.model).toBe('qwen3:8b')
    expect(fact.endpoint_host).toBe('127.0.0.1:11434')
  })

  it('EARS-MK11-4c: parses generating heartbeat fact', () => {
    const frame = { event: 'stage', data: '{"stage":"generating","elapsed_ms":9800}' }
    const fact = parseStageFact(frame) as Extract<StageFact, { stage: 'generating' }>
    expect(fact.stage).toBe('generating')
    expect(fact.elapsed_ms).toBe(9800)
  })

  it('EARS-MK11-4d: parses received fact with completion_tokens', () => {
    const frame = {
      event: 'stage',
      data: '{"stage":"received","latency_ms":9800,"completion_tokens":642}',
    }
    const fact = parseStageFact(frame) as Extract<StageFact, { stage: 'received' }>
    expect(fact.stage).toBe('received')
    expect(fact.latency_ms).toBe(9800)
    expect(fact.completion_tokens).toBe(642)
  })

  it('EARS-MK11-4e: parses validated fact', () => {
    const frame = { event: 'stage', data: '{"stage":"validated"}' }
    const fact = parseStageFact(frame)
    expect(fact).not.toBeNull()
    expect(fact!.stage).toBe('validated')
  })

  it('EARS-MK11-4f: parses projected fact', () => {
    const frame = { event: 'stage', data: '{"stage":"projected","field_count":7}' }
    const fact = parseStageFact(frame) as Extract<StageFact, { stage: 'projected' }>
    expect(fact.stage).toBe('projected')
    expect(fact.field_count).toBe(7)
  })

  it('EARS-MK11-4g: parses failed fact', () => {
    const frame = {
      event: 'stage',
      data: '{"stage":"failed","at_stage":"validated","reason_code":"validation_error"}',
    }
    const fact = parseStageFact(frame) as Extract<StageFact, { stage: 'failed' }>
    expect(fact.stage).toBe('failed')
    expect(fact.at_stage).toBe('validated')
    expect(fact.reason_code).toBe('validation_error')
  })

  it('returns null for malformed JSON', () => {
    const frame = { event: 'stage', data: 'not-valid-json' }
    expect(parseStageFact(frame)).toBeNull()
  })
})

describe('stages.ts — formatStageLabel', () => {
  it('EARS-MK11-5a: prompt_built label', () => {
    const fact: StageFact = { stage: 'prompt_built', sample_count: 12 }
    expect(formatStageLabel(fact)).toBe('prompt built (12 samples)')
  })

  it('EARS-MK11-5b: request_sent label', () => {
    const fact: StageFact = { stage: 'request_sent', model: 'qwen3:8b', endpoint_host: '127.0.0.1:11434' }
    expect(formatStageLabel(fact)).toBe('sent to qwen3:8b @127.0.0.1:11434')
  })

  it('EARS-MK11-5c: generating heartbeat label', () => {
    const fact: StageFact = { stage: 'generating', elapsed_ms: 9800 }
    expect(formatStageLabel(fact)).toBe('generating… (9.8s)')
  })

  it('EARS-MK11-5d: received label with tokens', () => {
    const fact: StageFact = { stage: 'received', latency_ms: 9800, completion_tokens: 642 }
    expect(formatStageLabel(fact)).toBe('received (642 tok · 9.8s)')
  })

  it('EARS-MK11-5e: validated label', () => {
    const fact: StageFact = { stage: 'validated' }
    expect(formatStageLabel(fact)).toBe('schema validated ✓')
  })

  it('EARS-MK11-5f: projected label', () => {
    const fact: StageFact = { stage: 'projected', field_count: 7 }
    expect(formatStageLabel(fact)).toBe('projected to 7 fields ✓')
  })

  it('EARS-MK11-5g: failed label — honest "validation FAILED" messaging', () => {
    const fact: StageFact = { stage: 'failed', at_stage: 'validated', reason_code: 'validation_error' }
    expect(formatStageLabel(fact)).toBe('validation FAILED → rules-only fallback')
  })
})

// ---------------------------------------------------------------------------
// EARS-MK11-6 to MK11-10: useStageTicker.ts tests
// ---------------------------------------------------------------------------

// useStageTicker is a React hook — test via a minimal wrapper component.
import { useStageTicker } from '../components/entity/ip/ticker/useStageTicker'

// Mock resolveBaseUrl from api/client
const { mockResolveBaseUrl } = vi.hoisted(() => ({
  mockResolveBaseUrl: vi.fn().mockReturnValue(''),
}))

vi.mock('../api/client', () => ({
  resolveBaseUrl: mockResolveBaseUrl,
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: unknown) {
      super(String(message ?? status))
      this.status = status
    }
  },
  assertLoopbackBase: vi.fn(),
  fetchHealth: vi.fn().mockResolvedValue({ ollama_connected: false }),
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchThreats: vi.fn().mockResolvedValue([]),
}))

/** Helper to build an SSE response body as a ReadableStream. */
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

/** Render useStageTicker and expose its state via data-testid attributes. */
function TickerHarness({ ip, enabled = true }: { ip: string | null; enabled?: boolean }) {
  const state = useStageTicker({ ip, enabled })
  return (
    <div>
      <span data-testid="streaming">{String(state.streaming)}</span>
      <span data-testid="done">{String(state.done)}</span>
      <span data-testid="stream-error">{String(state.streamError)}</span>
      {/* UT-02 (#502): persistentConflict separates "all 409 retries exhausted" from genuine errors */}
      <span data-testid="persistent-conflict">{String(state.persistentConflict)}</span>
      <span data-testid="stage-count">{state.stages.length}</span>
      <span data-testid="generating-ms">{String(state.generatingElapsedMs)}</span>
      <span data-testid="has-result">{String(state.result !== null)}</span>
    </div>
  )
}

describe('useStageTicker', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    mockResolveBaseUrl.mockReturnValue('')
  })

  it('EARS-MK11-6: AbortController aborts on unmount (abort-on-unmount)', async () => {
    // Setup a stream that never ends (simulates Ollama generating).
    const encoder = new TextEncoder()
    const abortCalled = vi.fn()

    const abortController = new AbortController()
    const originalAbort = abortController.abort.bind(abortController)
    abortController.abort = (...args) => {
      abortCalled()
      return originalAbort(...args)
    }

    // Mock AbortController so we can intercept abort().
    const OriginalAbortController = globalThis.AbortController
    globalThis.AbortController = class MockAbortController {
      signal = abortController.signal
      abort = abortController.abort
    } as unknown as typeof AbortController

    // Infinite stream — only closes when aborted.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        // Send one stage frame, then wait (simulate generating).
        controller.enqueue(
          encoder.encode('event: stage\ndata: {"stage":"generating","elapsed_ms":1000}\n\n'),
        )
        // Don't close — wait for abort.
      },
      cancel() {
        abortCalled()
      },
    })

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      body: stream,
    } as Response)

    const { unmount } = render(<TickerHarness ip="192.0.2.1" />)

    // Wait for the stream to start.
    await waitFor(() => {
      expect(screen.getByTestId('streaming').textContent).toBe('true')
    })

    // Unmount → abort should be called.
    unmount()

    // The abort was called (either on the controller we injected or via stream cancel).
    expect(abortCalled).toHaveBeenCalled()

    globalThis.AbortController = OriginalAbortController
  })

  it('EARS-MK11-7: stream error → streamError=true (fallback signal)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      status: 503,
      body: null,
    } as Response)

    render(<TickerHarness ip="192.0.2.1" />)

    await waitFor(() => {
      expect(screen.getByTestId('stream-error').textContent).toBe('true')
    })
  })

  it('EARS-MK11-7b: network error → streamError=true (fallback signal)', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network failed'))

    render(<TickerHarness ip="192.0.2.1" />)

    await waitFor(() => {
      expect(screen.getByTestId('stream-error').textContent).toBe('true')
    })
  })

  it('EARS-MK11-7c: error SSE event → streamError=true', async () => {
    const stream = makeSSEStream([
      'event: error\ndata: {"detail":"Internal stream error"}\n\n',
    ])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    render(<TickerHarness ip="192.0.2.1" />)

    await waitFor(() => {
      expect(screen.getByTestId('stream-error').textContent).toBe('true')
    })
  })

  it('EARS-MK11-8: successful stream — stages accumulate + result received', async () => {
    const resultPayload = { ip: '192.0.2.1', score: 78 }
    const stream = makeSSEStream([
      'event: stage\ndata: {"stage":"prompt_built","sample_count":12}\n\n',
      'event: stage\ndata: {"stage":"validated"}\n\n',
      `event: result\ndata: ${JSON.stringify(resultPayload)}\n\n`,
    ])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    render(<TickerHarness ip="192.0.2.1" />)

    await waitFor(() => {
      expect(screen.getByTestId('has-result').textContent).toBe('true')
      expect(screen.getByTestId('stage-count').textContent).toBe('2')
      expect(screen.getByTestId('done').textContent).toBe('true')
    })
  })

  it('EARS-MK11-9: generating heartbeats overwrite generatingElapsedMs (not in stages)', async () => {
    const stream = makeSSEStream([
      'event: stage\ndata: {"stage":"generating","elapsed_ms":1000}\n\n',
      'event: stage\ndata: {"stage":"generating","elapsed_ms":5000}\n\n',
      'event: stage\ndata: {"stage":"validated"}\n\n',
      'event: result\ndata: {"ip":"192.0.2.1"}\n\n',
    ])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    render(<TickerHarness ip="192.0.2.1" />)

    await waitFor(() => {
      expect(screen.getByTestId('has-result').textContent).toBe('true')
      // Only 1 non-generating stage (validated).
      expect(screen.getByTestId('stage-count').textContent).toBe('1')
      // Generating elapsed updated to last heartbeat.
      expect(screen.getByTestId('generating-ms').textContent).toBe('5000')
    })
  })

  it('EARS-MK11-10: unknown event types dropped silently', async () => {
    const stream = makeSSEStream([
      'event: stage\ndata: {"stage":"future_unknown_stage","foo":1}\n\n',
      'event: stage\ndata: {"stage":"validated"}\n\n',
      'event: result\ndata: {"ip":"192.0.2.1"}\n\n',
    ])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    render(<TickerHarness ip="192.0.2.1" />)

    await waitFor(() => {
      expect(screen.getByTestId('has-result').textContent).toBe('true')
      // Only 1 known stage (validated). Unknown dropped.
      expect(screen.getByTestId('stage-count').textContent).toBe('1')
    })
  })

  it('does not start stream when ip is null', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    render(<TickerHarness ip={null} />)

    // Wait a tick.
    await new Promise((r) => setTimeout(r, 20))
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('does not start stream when enabled=false', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    render(<TickerHarness ip="192.0.2.1" enabled={false} />)

    await new Promise((r) => setTimeout(r, 20))
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// EARS-MK11-11 to MK11-13: StageTicker.tsx render tests
// ---------------------------------------------------------------------------

describe('StageTicker', () => {
  const STAGES: StageFact[] = [
    { stage: 'prompt_built', sample_count: 12 },
    { stage: 'validated' },
  ]

  it('EARS-MK11-11: renders stage lines from facts', () => {
    render(
      <StageTicker
        stages={STAGES}
        generatingElapsedMs={null}
        streaming={false}
      />,
    )

    expect(screen.getByTestId('stage-ticker')).toBeTruthy()
    const lines = screen.getByTestId('stage-ticker-lines')
    expect(lines.textContent).toContain('prompt built (12 samples)')
    expect(lines.textContent).toContain('schema validated ✓')
  })

  it('EARS-MK11-12: aria-live="polite" region is present', () => {
    render(
      <StageTicker
        stages={STAGES}
        generatingElapsedMs={null}
        streaming={false}
      />,
    )

    const liveRegion = document.querySelector('[aria-live="polite"]')
    expect(liveRegion).not.toBeNull()
  })

  it('EARS-MK11-13: generating counter is aria-hidden (not announced to screen readers)', () => {
    render(
      <StageTicker
        stages={STAGES}
        generatingElapsedMs={5000}
        streaming={true}
      />,
    )

    const generatingEl = screen.getByTestId('stage-ticker-generating')
    expect(generatingEl.getAttribute('aria-hidden')).toBe('true')
    expect(generatingEl.textContent).toContain('generating…')
  })

  it('renders failed state with honest header', () => {
    const failedStages: StageFact[] = [
      { stage: 'prompt_built', sample_count: 8 },
      { stage: 'failed', at_stage: 'validated', reason_code: 'validation_error' },
    ]
    render(
      <StageTicker
        stages={failedStages}
        generatingElapsedMs={null}
        streaming={false}
        hasFailed={true}
      />,
    )

    // Header should say "gauntlet" on failure.
    expect(screen.getByTestId('stage-ticker-header').textContent).toContain('gauntlet')
    // Failed line shows honest message.
    expect(screen.getByTestId('stage-ticker-lines').textContent).toContain('validation FAILED')
  })
})

// ---------------------------------------------------------------------------
// EARS-MK11-14 to MK11-15: DeepAnalysisControl.tsx tests
// ---------------------------------------------------------------------------

// Note: DeepAnalysisControl mounts useStageTicker when phase='analyzing'.
// We need to mock the fetch for SSE stream.

import DeepAnalysisControl from '../components/entity/ip/DeepAnalysisControl'

describe('DeepAnalysisControl — MK-11 ticker integration', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    mockResolveBaseUrl.mockReturnValue('')
  })

  it('EARS-MK11-14: phase=analyzing renders stage-ticker (not just skeleton)', async () => {
    // Return a stream that sends a validated stage and then waits.
    const encoder = new TextEncoder()
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(
          encoder.encode('event: stage\ndata: {"stage":"validated"}\n\n'),
        )
        // Don't close — still streaming.
      },
    })

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    render(
      <DeepAnalysisControl
        phase="analyzing"
        elapsedSeconds={5}
        modelName="qwen3:8b"
        onRun={vi.fn()}
        ip="192.0.2.1"
      />,
    )

    // StageTicker should appear.
    await waitFor(() => {
      expect(screen.getByTestId('stage-ticker')).toBeTruthy()
    })

    // AiSectionSkeleton should NOT appear.
    expect(screen.queryByTestId('ai-section-skeleton')).toBeNull()
  })

  it('EARS-MK11-15: phase=analyzing with stream error renders AiSectionSkeleton fallback', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network failed'))

    render(
      <DeepAnalysisControl
        phase="analyzing"
        elapsedSeconds={5}
        modelName="qwen3:8b"
        onRun={vi.fn()}
        ip="192.0.2.1"
      />,
    )

    // On stream error, should fall back to AiSectionSkeleton.
    await waitFor(() => {
      expect(screen.getByTestId('ai-section-skeleton')).toBeTruthy()
    })

    // StageTicker should NOT appear.
    expect(screen.queryByTestId('stage-ticker')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// EARS-MK11-16 to MK11-18: VerdictCard.tsx re-run tests
// ---------------------------------------------------------------------------

import { VerdictCard } from '../components/ai/ledger/VerdictCard'

describe('VerdictCard — MK-11 Re-run analysis control', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    mockResolveBaseUrl.mockReturnValue('')
  })

  it('EARS-MK11-16: Re-run analysis button is present on the card', () => {
    render(<VerdictCard analysis={ANALYSIS_FIXTURE} />)
    expect(screen.getByTestId('verdict-card-rerun-btn')).toBeTruthy()
  })

  it('EARS-MK11-17: clicking Re-run mounts the ticker (stage-ticker appears)', async () => {
    const user = userEvent.setup()
    const encoder = new TextEncoder()
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(
          encoder.encode('event: stage\ndata: {"stage":"prompt_built","sample_count":10}\n\n'),
        )
        // Don't close — still streaming.
      },
    })

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    render(<VerdictCard analysis={ANALYSIS_FIXTURE} />)

    const rerunBtn = screen.getByTestId('verdict-card-rerun-btn')
    await user.click(rerunBtn)

    // After click, the ticker should mount.
    await waitFor(() => {
      expect(screen.getByTestId('stage-ticker')).toBeTruthy()
    })
  })

  it('EARS-MK11-18: NO model-authored text rendered from stage events', async () => {
    // The stage events contain only numeric/enum values — no model prose.
    const user = userEvent.setup()
    // Simulate a complete stream with a result containing model-authored text.
    const modelText = 'THIS IS MODEL AUTHORED TEXT THAT SHOULD NOT APPEAR IN TICKER'
    const stream = makeSSEStream([
      'event: stage\ndata: {"stage":"validated"}\n\n',
      `event: result\ndata: ${JSON.stringify({ ip: '192.0.2.1', analysis: modelText })}\n\n`,
    ])

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    const { container } = render(<VerdictCard analysis={ANALYSIS_FIXTURE} />)

    const rerunBtn = screen.getByTestId('verdict-card-rerun-btn')
    await user.click(rerunBtn)

    // Wait for stream to complete.
    await waitFor(() => {
      expect(screen.queryByTestId('verdict-card-rerun-btn')).toBeNull()
    }, { timeout: 2000 })

    // Model-authored text must NOT appear anywhere in the ticker output.
    expect(container.textContent).not.toContain(modelText)
  })

  it('calls onRerunComplete when the stream completes', async () => {
    const onRerunComplete = vi.fn()
    const stream = makeSSEStream([
      'event: stage\ndata: {"stage":"validated"}\n\n',
      'event: result\ndata: {"ip":"192.0.2.1"}\n\n',
    ])

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    const user = userEvent.setup()
    render(<VerdictCard analysis={ANALYSIS_FIXTURE} onRerunComplete={onRerunComplete} />)

    await user.click(screen.getByTestId('verdict-card-rerun-btn'))

    await waitFor(() => {
      expect(onRerunComplete).toHaveBeenCalledOnce()
    })
  })
})


// ---------------------------------------------------------------------------
// MK-11 UX-polish fixes — Fix 1: persist completed stage list; Fix 2: no spinner
// ---------------------------------------------------------------------------

import { useState } from 'react'
import type { DeepAnalysisPhase } from '../components/entity/ip/useDeepAnalysis'

/**
 * A controlled wrapper that lets tests drive phase transitions on
 * DeepAnalysisControl without needing to simulate the full useDeepAnalysis hook.
 */
function ControlledDeepAnalysis({
  ip,
  onStreamResult,
}: {
  ip: string
  onStreamResult?: (payload: Record<string, unknown>) => void
}) {
  const [phase, setPhase] = useState<DeepAnalysisPhase>('analyzing')
  return (
    <div>
      {/* Test-only phase switcher */}
      <button data-testid="set-complete" onClick={() => setPhase('complete')} />
      <DeepAnalysisControl
        phase={phase}
        elapsedSeconds={5}
        modelName="qwen3:8b"
        onRun={vi.fn()}
        ip={ip}
        onStreamResult={onStreamResult}
      />
    </div>
  )
}

describe('MK-11 Fix 1 — completed stage list persists after phase=complete', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    mockResolveBaseUrl.mockReturnValue('')
  })

  it('stage-ticker with done=true is in the DOM after phase transitions to complete', async () => {
    // Stream: two real stages, then result (stream closes).
    const stream = makeSSEStream([
      'event: stage\ndata: {"stage":"validated"}\n\n',
      'event: stage\ndata: {"stage":"projected","field_count":7}\n\n',
      'event: result\ndata: {"ip":"192.0.2.1"}\n\n',
    ])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    const user = userEvent.setup()
    render(<ControlledDeepAnalysis ip="192.0.2.1" />)

    // Wait for stages to arrive during 'analyzing'.
    await waitFor(() => {
      expect(screen.getByTestId('stage-ticker')).toBeTruthy()
    })

    // Transition to complete (simulate parent's phase change after result).
    await user.click(screen.getByTestId('set-complete'))

    // The stage ticker (static, done=true) MUST still be in the DOM.
    await waitFor(() => {
      const ticker = screen.getByTestId('stage-ticker')
      expect(ticker).toBeTruthy()
      // done=true is conveyed via data-done attribute.
      expect(ticker.getAttribute('data-done')).toBe('true')
    })

    // Terminal stages (validated ✓, projected ✓) must be in the stage lines.
    const lines = screen.getByTestId('stage-ticker-lines')
    expect(lines.textContent).toContain('schema validated ✓')
    expect(lines.textContent).toContain('projected to 7 fields ✓')
  })

  it('no inner scrollbar or live generating counter in done/static mode', async () => {
    const stream = makeSSEStream([
      'event: stage\ndata: {"stage":"generating","elapsed_ms":5000}\n\n',
      'event: stage\ndata: {"stage":"validated"}\n\n',
      'event: result\ndata: {"ip":"192.0.2.1"}\n\n',
    ])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    const user = userEvent.setup()
    render(<ControlledDeepAnalysis ip="192.0.2.1" />)

    await waitFor(() => {
      expect(screen.getByTestId('stage-ticker')).toBeTruthy()
    })

    await user.click(screen.getByTestId('set-complete'))

    await waitFor(() => {
      expect(screen.getByTestId('stage-ticker').getAttribute('data-done')).toBe('true')
    })

    // Generating counter must NOT appear in static mode.
    expect(screen.queryByTestId('stage-ticker-generating')).toBeNull()
  })

  it('StageTicker done=true prop suppresses generating counter', () => {
    // Direct unit test of the StageTicker done prop.
    const stages: StageFact[] = [
      { stage: 'validated' },
      { stage: 'projected', field_count: 5 },
    ]
    render(
      <StageTicker
        stages={stages}
        generatingElapsedMs={9000}
        streaming={false}
        done={true}
      />,
    )
    // done=true: no generating line even though generatingElapsedMs is set.
    expect(screen.queryByTestId('stage-ticker-generating')).toBeNull()
    // Terminal stages still visible.
    expect(screen.getByTestId('stage-ticker-lines').textContent).toContain('schema validated ✓')
    expect(screen.getByTestId('stage-ticker-lines').textContent).toContain('projected to 5 fields ✓')
    // data-done attribute present.
    expect(screen.getByTestId('stage-ticker').getAttribute('data-done')).toBe('true')
  })
})

describe('MK-11 Fix 2 — no redundant spinner while ticker is streaming', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    mockResolveBaseUrl.mockReturnValue('')
  })

  it('phase=analyzing with live ticker: spinner is NOT rendered', async () => {
    const encoder = new TextEncoder()
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(
          encoder.encode('event: stage\ndata: {"stage":"validated"}\n\n'),
        )
        // Keep stream open — still streaming.
      },
    })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    render(
      <DeepAnalysisControl
        phase="analyzing"
        elapsedSeconds={3}
        modelName="qwen3:8b"
        onRun={vi.fn()}
        ip="192.0.2.1"
      />,
    )

    // Ticker renders (streaming path active).
    await waitFor(() => {
      expect(screen.getByTestId('stage-ticker')).toBeTruthy()
    })

    // Spinner must NOT be present — ticker is the progress indicator.
    expect(screen.queryByTestId('deep-analysis-spinner')).toBeNull()
  })

  it('phase=analyzing with stream-error fallback: spinner IS rendered', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network failed'))

    render(
      <DeepAnalysisControl
        phase="analyzing"
        elapsedSeconds={3}
        modelName="qwen3:8b"
        onRun={vi.fn()}
        ip="192.0.2.1"
      />,
    )

    // Wait for stream error to propagate.
    await waitFor(() => {
      expect(screen.getByTestId('ai-section-skeleton')).toBeTruthy()
    })

    // Spinner MUST be present on fallback path (no ticker to show progress).
    expect(screen.getByTestId('deep-analysis-spinner')).toBeTruthy()
  })
})

describe('MK-11 Fix 1 — VerdictCard RerunControl: static ticker visible after done', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    mockResolveBaseUrl.mockReturnValue('')
  })

  it('completed stage list is in the DOM after re-run stream completes', async () => {
    const stream = makeSSEStream([
      'event: stage\ndata: {"stage":"validated"}\n\n',
      'event: stage\ndata: {"stage":"projected","field_count":9}\n\n',
      'event: result\ndata: {"ip":"192.0.2.1"}\n\n',
    ])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, body: stream } as Response)

    const user = userEvent.setup()
    render(<VerdictCard analysis={ANALYSIS_FIXTURE} />)

    // Click Re-run.
    await user.click(screen.getByTestId('verdict-card-rerun-btn'))

    // Ticker mounts in streaming phase.
    await waitFor(() => {
      expect(screen.getByTestId('stage-ticker')).toBeTruthy()
    })

    // Wait for stream to complete and transition to done.
    await waitFor(() => {
      expect(screen.queryByTestId('verdict-card-rerun-done')).toBeTruthy()
    }, { timeout: 2000 })

    // Static ticker (done=true) MUST still be in the DOM alongside the done note.
    const ticker = screen.getByTestId('stage-ticker')
    expect(ticker.getAttribute('data-done')).toBe('true')
    // Terminal stages visible.
    expect(screen.getByTestId('stage-ticker-lines').textContent).toContain('schema validated ✓')
    expect(screen.getByTestId('stage-ticker-lines').textContent).toContain('projected to 9 fields ✓')
  })
})


// ---------------------------------------------------------------------------
// 409 retry tests — transient 409 hardening (StrictMode / rapid re-subscribe)
// ---------------------------------------------------------------------------

describe('useStageTicker — 409 retry hardening', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    mockResolveBaseUrl.mockReturnValue('')
  })

  it(
    '409-then-200: retries after 409 and renders stages; no streamError/fallback',
    async () => {
      // First call returns 409; second call returns a valid SSE stream.
      const resultPayload = { ip: '192.0.2.1', score: 72 }
      const stream = makeSSEStream([
        'event: stage\ndata: {"stage":"prompt_built","sample_count":5}\n\n',
        'event: stage\ndata: {"stage":"validated"}\n\n',
        `event: result\ndata: ${JSON.stringify(resultPayload)}\n\n`,
      ])

      const fetchSpy = vi
        .spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce({ ok: false, status: 409, body: null } as Response)
        .mockResolvedValueOnce({ ok: true, body: stream } as Response)

      render(<TickerHarness ip="192.0.2.1" />)

      // Wait for the retry to complete and result to arrive.
      // Timeout > 2 * RETRY_DELAY_MS (200ms) to allow for the retry sleep.
      await waitFor(
        () => {
          expect(screen.getByTestId('has-result').textContent).toBe('true')
        },
        { timeout: 1500 },
      )

      expect(screen.getByTestId('stage-count').textContent).toBe('2')
      expect(screen.getByTestId('stream-error').textContent).toBe('false')

      // fetch was called twice: initial 409 + one retry.
      expect(fetchSpy).toHaveBeenCalledTimes(2)
    },
    8000, // overall test timeout: 8s covers 200ms retry delay with margin
  )

  it(
    'persistent-409: sets persistentConflict=true (not streamError) after all retries exhausted',
    async () => {
      // All three attempts return 409 (initial + 2 retries).
      // UT-02 (#502): persistent 409 is now signalled as persistentConflict, not streamError,
      // so callers can show a "please wait" message without triggering the non-streaming fallback.
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
        ok: false,
        status: 409,
        body: null,
      } as Response)

      render(<TickerHarness ip="192.0.2.1" />)

      // Wait until persistentConflict is set — requires 2 retry delays (2 x 200ms).
      await waitFor(
        () => {
          expect(screen.getByTestId('persistent-conflict').textContent).toBe('true')
        },
        { timeout: 2000 },
      )

      // streamError must remain false — this is a conflict, not a generic error.
      expect(screen.getByTestId('stream-error').textContent).toBe('false')

      // All 3 attempts (initial + 2 retries) must have fired.
      expect(fetchSpy).toHaveBeenCalledTimes(3)
    },
    8000,
  )

  it(
    'abort-during-retry: unmount while retry is pending cancels timer; no setState-after-unmount',
    async () => {
      // The fetch is stalled on the first call so the hook is waiting for it,
      // then we let it resolve 409 which starts the retry delay, then we unmount
      // mid-delay. We use a controlled promise to gate when the fetch resolves.
      let resolve409!: () => void
      const fetch409Promise = new Promise<Response>((res) => {
        resolve409 = () => res({ ok: false, status: 409, body: null } as Response)
      })

      // Second fetch would succeed, but we expect it never to be called after abort.
      const fetchSpy = vi
        .spyOn(globalThis, 'fetch')
        .mockReturnValueOnce(fetch409Promise)
        .mockResolvedValue({ ok: true, body: makeSSEStream([]) } as Response)

      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      const { unmount } = render(<TickerHarness ip="192.0.2.1" />)

      // Let the component mount and start the first fetch.
      await new Promise((r) => setTimeout(r, 20))

      // Resolve the 409 — now the hook enters the 200ms retry delay.
      resolve409()

      // Immediately unmount while the retry delay is pending.
      // This should cancel the timer via the AbortController.
      unmount()

      // Wait well past RETRY_DELAY_MS — no second fetch should fire,
      // and no setState-after-unmount warning should appear.
      await new Promise((r) => setTimeout(r, 400))

      // The second fetch must NOT have been called (abort cancelled the retry).
      expect(fetchSpy).toHaveBeenCalledTimes(1)

      // No React setState-after-unmount (or "memory leak") warning.
      const hasWarning = consoleErrorSpy.mock.calls.some((args) =>
        String(args[0]).toLowerCase().includes('unmount') ||
        String(args[0]).toLowerCase().includes('memory leak') ||
        String(args[0]).toLowerCase().includes('cannot update'),
      )
      expect(hasWarning).toBe(false)

      consoleErrorSpy.mockRestore()
    },
    8000,
  )
})

// ---------------------------------------------------------------------------
// Issue #571 — pre-flight delay guard (rapid slide-over re-open for same IP)
// ---------------------------------------------------------------------------
//
// EARS acceptance criteria:
//   EARS-571-1: WHEN a live stream is aborted and a new stream starts for the
//               same IP, THE SYSTEM SHALL apply a pre-flight delay before the
//               first request (no immediate fetch after abort).
//   EARS-571-2: WHEN the pre-flight delay is in effect and the component unmounts,
//               THE SYSTEM SHALL cancel the delay immediately (no leaked timer,
//               no setState-after-unmount).
//   EARS-571-3: WHEN no prior live stream was aborted (fresh mount with no prior
//               stream), THE SYSTEM SHALL NOT apply a pre-flight delay (no added
//               latency on first open).
//   EARS-571-4: AFTER the pre-flight delay, THE SYSTEM SHALL still render the
//               stream's stages correctly (regression guard).

describe('useStageTicker — issue #571: pre-flight delay on rapid re-open', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    mockResolveBaseUrl.mockReturnValue('')
  })

  it(
    'EARS-571-1: live-abort → new stream: first fetch is delayed (no immediate request after abort)',
    async () => {
      // We need to verify that when a live stream is aborted and a new stream
      // starts, the first fetch is NOT immediate.
      //
      // Strategy: start a stream (mount), disable it (abort live stream), then
      // immediately re-enable. Record the timestamp of each fetch call. The gap
      // between the abort and the second fetch should be >= RETRY_DELAY_MS.

      const encoder = new TextEncoder()
      const fetchTimestamps: number[] = []

      // Infinite stream 1 (never resolves on its own — we abort it).
      let streamAbortSignal: AbortSignal | null = null
      const firstStream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(
            encoder.encode('event: stage\ndata: {"stage":"validated"}\n\n'),
          )
          // Keep open (generating).
        },
      })

      // Stream 2: sends a result immediately after the delay.
      const resultPayload = { ip: '192.0.2.1', score: 55 }
      const secondStream = makeSSEStream([
        'event: stage\ndata: {"stage":"validated"}\n\n',
        `event: result\ndata: ${JSON.stringify(resultPayload)}\n\n`,
      ])

      let fetchCallCount = 0
      vi.spyOn(globalThis, 'fetch').mockImplementation((...args) => {
        fetchCallCount++
        fetchTimestamps.push(Date.now())
        // Record the signal from the first call so we know when it was aborted.
        const init = args[1] as RequestInit | undefined
        if (fetchCallCount === 1 && init?.signal) {
          streamAbortSignal = init.signal as AbortSignal
        }
        if (fetchCallCount === 1) {
          return Promise.resolve({ ok: true, body: firstStream } as Response)
        }
        return Promise.resolve({ ok: true, body: secondStream } as Response)
      })

      // Mount: start streaming (enabled=true, ip set).
      const { rerender } = render(<TickerHarness ip="192.0.2.1" enabled={true} />)

      // Wait for the first stream to start (validated stage arrives).
      await waitFor(() => {
        expect(screen.getByTestId('streaming').textContent).toBe('true')
      })

      // Record when the abort happens.
      const abortTime = Date.now()

      // Disable then immediately re-enable — simulates close then reopen.
      // This causes the effect to run with enabled=false (aborting live stream),
      // then immediately with enabled=true (new stream starts after delay).
      rerender(<TickerHarness ip="192.0.2.1" enabled={false} />)
      rerender(<TickerHarness ip="192.0.2.1" enabled={true} />)

      // Wait for the result from the second stream.
      await waitFor(() => {
        expect(screen.getByTestId('has-result').textContent).toBe('true')
      }, { timeout: 2000 })

      // Two fetches should have occurred.
      expect(fetchCallCount).toBe(2)

      // The gap between abort and the second fetch must be >= RETRY_DELAY_MS (200ms).
      // This confirms the pre-flight delay was applied.
      // We add 50ms tolerance for test environment scheduling jitter.
      const secondFetchTime = fetchTimestamps[1]
      expect(secondFetchTime - abortTime).toBeGreaterThanOrEqual(150)

      // The first stream's abort signal should be aborted.
      expect(streamAbortSignal !== null && (streamAbortSignal as AbortSignal).aborted).toBe(true)
    },
    8000,
  )

  it(
    'EARS-571-2: abort-during-preflight-delay: unmounting cancels delay, no setState-after-unmount',
    async () => {
      // Start a stream (live), then abort it, then immediately re-enable.
      // Unmount while the pre-flight delay is in progress.
      // No second fetch should fire; no setState-after-unmount warning.

      const encoder = new TextEncoder()
      const firstStream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(
            encoder.encode('event: stage\ndata: {"stage":"validated"}\n\n'),
          )
          // Keep open — closed when aborted.
        },
      })

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
        if (fetchSpy.mock.calls.length === 1) {
          return Promise.resolve({ ok: true, body: firstStream } as Response)
        }
        // Should never be called.
        return Promise.resolve({ ok: true, body: makeSSEStream([]) } as Response)
      })

      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      const { rerender, unmount } = render(<TickerHarness ip="192.0.2.1" enabled={true} />)

      // Wait for first stream to be live.
      await waitFor(() => {
        expect(screen.getByTestId('streaming').textContent).toBe('true')
      })

      // Abort live stream + re-enable (starts pre-flight delay).
      rerender(<TickerHarness ip="192.0.2.1" enabled={false} />)
      rerender(<TickerHarness ip="192.0.2.1" enabled={true} />)

      // Unmount immediately while pre-flight delay is in progress.
      unmount()

      // Wait well past RETRY_DELAY_MS — no second fetch, no setState warning.
      await new Promise((r) => setTimeout(r, 400))

      // Only the first fetch fired; the delayed second fetch was cancelled.
      expect(fetchSpy.mock.calls.length).toBe(1)

      // No React setState-after-unmount warning.
      const hasWarning = consoleErrorSpy.mock.calls.some((args) =>
        String(args[0]).toLowerCase().includes('unmount') ||
        String(args[0]).toLowerCase().includes('memory leak') ||
        String(args[0]).toLowerCase().includes('cannot update'),
      )
      expect(hasWarning).toBe(false)

      consoleErrorSpy.mockRestore()
    },
    8000,
  )

  it(
    'EARS-571-3: fresh mount with no prior stream — no pre-flight delay (first fetch immediate)',
    async () => {
      // On a fresh mount (no prior live stream aborted), the first fetch should
      // be immediate — no pre-flight delay.

      const fetchTimestamps: number[] = []
      const stream = makeSSEStream([
        'event: stage\ndata: {"stage":"validated"}\n\n',
        'event: result\ndata: {"ip":"192.0.2.1"}\n\n',
      ])

      vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
        fetchTimestamps.push(Date.now())
        return Promise.resolve({ ok: true, body: stream } as Response)
      })

      const mountTime = Date.now()
      render(<TickerHarness ip="192.0.2.1" enabled={true} />)

      await waitFor(() => {
        expect(screen.getByTestId('has-result').textContent).toBe('true')
      }, { timeout: 1000 })

      // First fetch should be nearly immediate (< 100ms, well under RETRY_DELAY_MS=200ms).
      expect(fetchTimestamps[0] - mountTime).toBeLessThan(100)
    },
    8000,
  )

  it(
    'EARS-571-4: after pre-flight delay, stream renders stages correctly (regression)',
    async () => {
      // Full regression: close → reopen for same IP → stages appear after the delay.

      const encoder = new TextEncoder()
      const resultPayload = { ip: '192.0.2.1', score: 70 }

      const firstStream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(
            encoder.encode('event: stage\ndata: {"stage":"validated"}\n\n'),
          )
          // Keep open.
        },
      })
      const secondStream = makeSSEStream([
        'event: stage\ndata: {"stage":"prompt_built","sample_count":8}\n\n',
        'event: stage\ndata: {"stage":"validated"}\n\n',
        `event: result\ndata: ${JSON.stringify(resultPayload)}\n\n`,
      ])

      let fetchCallCount = 0
      vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
        fetchCallCount++
        if (fetchCallCount === 1) {
          return Promise.resolve({ ok: true, body: firstStream } as Response)
        }
        return Promise.resolve({ ok: true, body: secondStream } as Response)
      })

      const { rerender } = render(<TickerHarness ip="192.0.2.1" enabled={true} />)

      // Wait for first stream to be live.
      await waitFor(() => {
        expect(screen.getByTestId('streaming').textContent).toBe('true')
      })

      // Close then reopen (same IP).
      rerender(<TickerHarness ip="192.0.2.1" enabled={false} />)
      rerender(<TickerHarness ip="192.0.2.1" enabled={true} />)

      // Wait for second stream to deliver its result.
      await waitFor(() => {
        expect(screen.getByTestId('has-result').textContent).toBe('true')
      }, { timeout: 2000 })

      // Both stages from the second stream are accumulated.
      expect(screen.getByTestId('stage-count').textContent).toBe('2')
      expect(screen.getByTestId('stream-error').textContent).toBe('false')
      expect(screen.getByTestId('persistent-conflict').textContent).toBe('false')
    },
    8000,
  )
})
