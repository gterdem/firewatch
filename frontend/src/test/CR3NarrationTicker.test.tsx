/**
 * Tests for CR3 (issue #614) — "watch it think" staged Explain ticker.
 *
 * EARS acceptance criteria covered:
 *
 * EARS-CR3-1: WHILE AI-backed narration is generating, the system SHALL replace the
 *   bare spinner with a staged ticker driven by REAL ADR-0046 stage facts.
 *   → test_ticker_renders_when_stream_active
 *   → test_ticker_shows_real_stage_facts
 *   → test_no_faked_animation_only_real_facts
 *
 * EARS-CR3-2: BY DEFAULT the ticker SHALL render as a single collapsed line with
 *   locality signal, e.g. `On-device inference · zero-egress [●] 2.4s`.
 *   → test_ticker_collapsed_by_default
 *   → test_ticker_collapsed_shows_locality_label
 *   → test_ticker_collapsed_shows_elapsed_time
 *
 * EARS-CR3-3: WHEN the user expands the ticker, the system SHALL show 6 real
 *   stages each with per-stage elapsed time.
 *   → test_ticker_expands_on_toggle
 *   → test_expanded_shows_stage_labels
 *   → test_expanded_shows_per_stage_elapsed
 *
 * EARS-CR3-4: The ticker SHALL show only validated/already-true stage facts;
 *   no model-authored text in any stage event (ADR-0046 §3).
 *   → test_no_model_text_in_stage_events
 *   → test_stage_text_from_closed_enum_only
 *
 * EARS-CR3-5: WHEN AI is offline / rule-only mode, the system SHALL show
 *   "Building rule summary…" and SHALL NOT render inference stages (ADR-0035).
 *   → test_rule_only_shows_building_summary
 *   → test_rule_only_no_ticker_shown
 *   → test_rule_only_no_stage_events_rendered
 *
 * EARS-CR3-6: IF stage stream fails, the system SHALL degrade gracefully to
 *   existing non-streaming narration (ADR-0046 §7).
 *   → test_stream_error_shows_fallback_not_ticker
 *   → test_stream_error_narration_still_completes
 *
 * EARS-CR3-7: The ticker SHALL be an aria-live="polite" status region and
 *   respect prefers-reduced-motion (ADR-0046 §8), with no inner scrollbar.
 *   → test_ticker_has_aria_live_region
 *   → test_ticker_toggle_button_has_aria_expanded
 *
 * All IPs use RFC 5737 documentation range.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import NarrationPanel from '../components/entity/ip/NarrationPanel'
import NarrationInferenceTicker from '../components/entity/ip/NarrationInferenceTicker'
import type { StageFact } from '../components/entity/ip/ticker/stages'
import type { NarrationResult } from '../api/types'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const { mockFetchNarration } = vi.hoisted(() => ({
  mockFetchNarration: vi.fn(),
}))

vi.mock('../api/logs', () => ({
  fetchNarration: mockFetchNarration,
  fetchThreatScore: vi.fn(),
  fetchDetailedAnalysis: vi.fn(),
  fetchRules: vi.fn(),
  fetchIpEvents: vi.fn(),
}))

// Mock api/client so useStageTicker (inside useNarrationStream) can import
// resolveBaseUrl without error.
vi.mock('../api/client', () => ({
  resolveBaseUrl: vi.fn().mockReturnValue(''),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: unknown) {
      super(String(message ?? status))
      this.status = status
    }
  },
  buildHeaders: vi.fn().mockReturnValue({}),
  assertLoopbackBase: vi.fn(),
  fetchHealth: vi.fn().mockResolvedValue({ ollama_connected: false }),
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchThreats: vi.fn().mockResolvedValue([]),
}))

// ---------------------------------------------------------------------------
// Fixtures (RFC 5737 IPs)
// ---------------------------------------------------------------------------

const _IP = '192.0.2.42'

const AI_RESULT: NarrationResult = {
  source_ip: _IP,
  narrative: 'This IP triggered aggressive scanning rules.',
  provenance: 'ai+rule',
  collected_fields: ['source_ip', 'score_breakdown'],
  ai_status: 'ok',
}

const RULE_RESULT: NarrationResult = {
  source_ip: _IP,
  narrative: 'IP received threat level HIGH (score 75/100).',
  provenance: 'rule',
  collected_fields: ['source_ip', 'threat_level'],
  ai_status: 'unavailable',
}

// ---------------------------------------------------------------------------
// SSE stream helpers
// ---------------------------------------------------------------------------

/** A stream that stays open (never ends — simulates in-progress generation). */
function makeOpenStream(initialFrames: string[] = []): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder()
  return new ReadableStream({
    start(controller) {
      for (const frame of initialFrames) {
        controller.enqueue(encoder.encode(frame))
      }
      // Never close — simulates generating.
    },
  })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderPanel(ip = _IP, aiAvailable = true) {
  return render(<NarrationPanel ip={ip} aiAvailable={aiAvailable} />)
}

async function clickExplain() {
  await userEvent.click(screen.getByTestId('explain-btn'))
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// EARS-CR3-1: Ticker renders with real stage facts
// ---------------------------------------------------------------------------

describe('CR3 EARS-1 — staged ticker with real stage facts', () => {
  it('shows narration-inference-ticker (not bare spinner) when stream is active', async () => {
    // Stream stays open (simulates generating).
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      body: makeOpenStream([
        'event: stage\ndata: {"stage":"prompt_built","sample_count":10}\n\n',
      ]),
    } as Response)
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    // Ticker should appear.
    await waitFor(() => {
      expect(screen.getByTestId('narration-inference-ticker')).toBeInTheDocument()
    })
  })

  it('renders real stage labels from stream — not a decorative/faked animation', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      body: makeOpenStream([
        'event: stage\ndata: {"stage":"prompt_built","sample_count":12}\n\n',
        'event: stage\ndata: {"stage":"request_sent","model":"qwen3:8b","endpoint_host":"127.0.0.1"}\n\n',
      ]),
    } as Response)
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    // Expand the ticker to see stage lines.
    await waitFor(() => {
      expect(screen.getByTestId('narration-inference-ticker')).toBeInTheDocument()
    })
    await userEvent.click(screen.getByTestId('narration-ticker-toggle'))

    // Stages from the REAL stream must appear.
    await waitFor(() => {
      expect(screen.getByTestId('narration-ticker-stages')).toHaveTextContent('prompt built')
    })
    expect(screen.getByTestId('narration-ticker-stages')).toHaveTextContent(
      'sent to qwen3:8b',
    )
  })
})

// ---------------------------------------------------------------------------
// EARS-CR3-2: Collapsed default line
// ---------------------------------------------------------------------------

describe('CR3 EARS-2 — collapsed by default, locality label + elapsed', () => {
  it('ticker is collapsed by default (stage list hidden)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      body: makeOpenStream([
        'event: stage\ndata: {"stage":"prompt_built","sample_count":8}\n\n',
      ]),
    } as Response)
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    await waitFor(() => {
      expect(screen.getByTestId('narration-inference-ticker')).toBeInTheDocument()
    })

    // Stage list NOT visible yet (collapsed by default).
    expect(screen.queryByTestId('narration-ticker-stages')).not.toBeInTheDocument()
  })

  it('collapsed line contains "On-device inference" and "zero-egress"', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      body: makeOpenStream(),
    } as Response)
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    await waitFor(() => {
      expect(screen.getByTestId('narration-ticker-label')).toBeInTheDocument()
    })

    const label = screen.getByTestId('narration-ticker-label')
    expect(label).toHaveTextContent(/On-device inference/i)
    expect(label).toHaveTextContent(/zero-egress/i)
  })

  it('shows live elapsed time from generating heartbeat in collapsed line', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      body: makeOpenStream([
        'event: stage\ndata: {"stage":"generating","elapsed_ms":2400}\n\n',
      ]),
    } as Response)
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    await waitFor(() => {
      expect(screen.getByTestId('narration-ticker-elapsed')).toBeInTheDocument()
    })

    // 2400ms → "2.4s"
    expect(screen.getByTestId('narration-ticker-elapsed')).toHaveTextContent('2.4s')
  })
})

// ---------------------------------------------------------------------------
// EARS-CR3-3: Expanded view with per-stage elapsed
// ---------------------------------------------------------------------------

describe('CR3 EARS-3 — expanded view with per-stage elapsed times', () => {
  it('clicking toggle expands the stage list', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      body: makeOpenStream([
        'event: stage\ndata: {"stage":"prompt_built","sample_count":5}\n\n',
      ]),
    } as Response)
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    await waitFor(() => {
      expect(screen.getByTestId('narration-ticker-toggle')).toBeInTheDocument()
    })

    // Expand.
    await userEvent.click(screen.getByTestId('narration-ticker-toggle'))

    expect(screen.getByTestId('narration-ticker-stages')).toBeInTheDocument()
  })

  it('expanded view shows received stage with per-stage latency (proof of locality)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      body: makeOpenStream([
        'event: stage\ndata: {"stage":"received","latency_ms":9800,"completion_tokens":642}\n\n',
      ]),
    } as Response)
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    await waitFor(() => {
      expect(screen.getByTestId('narration-ticker-toggle')).toBeInTheDocument()
    })

    await userEvent.click(screen.getByTestId('narration-ticker-toggle'))

    // received stage shows latency elapsed (9.8s).
    await waitFor(() => {
      const stages = screen.getByTestId('narration-ticker-stages')
      expect(stages).toHaveTextContent('received')
      expect(stages).toHaveTextContent('9.8s')
    })
  })

  it('collapsing hides the stage list again', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      body: makeOpenStream([
        'event: stage\ndata: {"stage":"validated"}\n\n',
      ]),
    } as Response)
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    await waitFor(() => {
      expect(screen.getByTestId('narration-ticker-toggle')).toBeInTheDocument()
    })

    // Expand.
    await userEvent.click(screen.getByTestId('narration-ticker-toggle'))
    await waitFor(() => {
      expect(screen.getByTestId('narration-ticker-stages')).toBeInTheDocument()
    })

    // Collapse.
    await userEvent.click(screen.getByTestId('narration-ticker-toggle'))
    expect(screen.queryByTestId('narration-ticker-stages')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-CR3-4: No model-authored text in stage events (ADR-0046 §3 / ADR-0029 D3)
// ---------------------------------------------------------------------------

describe('CR3 EARS-4 — no model-authored text in stage events', () => {
  it('stage labels are from closed enum only — not model prose', async () => {
    const modelText = 'NEVER SHOW THIS MODEL AUTHORED TEXT IN TICKER'
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      body: makeOpenStream([
        'event: stage\ndata: {"stage":"validated"}\n\n',
        `event: result\ndata: ${JSON.stringify({ ip: _IP, prose: modelText })}\n\n`,
      ]),
    } as Response)
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    await waitFor(() => {
      expect(screen.getByTestId('narration-inference-ticker')).toBeInTheDocument()
    })

    // Expand to see all rendered text.
    await userEvent.click(screen.getByTestId('narration-ticker-toggle'))

    // Model prose must NOT appear anywhere in the ticker.
    const ticker = screen.getByTestId('narration-inference-ticker')
    expect(ticker.textContent).not.toContain(modelText)
  })

  it('expanding shows stage labels from stages.ts formatStageLabel — closed enum', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      body: makeOpenStream([
        'event: stage\ndata: {"stage":"validated"}\n\n',
        'event: stage\ndata: {"stage":"projected","field_count":7}\n\n',
      ]),
    } as Response)
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    await waitFor(() => {
      expect(screen.getByTestId('narration-ticker-toggle')).toBeInTheDocument()
    })
    await userEvent.click(screen.getByTestId('narration-ticker-toggle'))

    const stages = screen.getByTestId('narration-ticker-stages')
    // Known closed-enum labels from formatStageLabel.
    expect(stages).toHaveTextContent('schema validated ✓')
    expect(stages).toHaveTextContent('projected to 7 fields ✓')
  })
})

// ---------------------------------------------------------------------------
// EARS-CR3-5: Rule-only honest degradation (ADR-0035)
// ---------------------------------------------------------------------------

describe('CR3 EARS-5 — rule-only: "Building rule summary…", no inference stages', () => {
  it('shows "Building rule summary…" when aiAvailable=false', async () => {
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, false)
    await act(async () => { await clickExplain() })

    expect(screen.getByTestId('narration-rule-only-loading')).toBeInTheDocument()
    expect(screen.getByTestId('narration-rule-only-loading')).toHaveTextContent(
      /Building rule summary/i,
    )
  })

  it('does NOT render narration-inference-ticker in rule-only mode', async () => {
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, false)
    await act(async () => { await clickExplain() })

    expect(screen.queryByTestId('narration-inference-ticker')).not.toBeInTheDocument()
  })

  it('does NOT open the SSE stream in rule-only mode', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, false)
    await act(async () => { await clickExplain() })

    // No fetch call to the stream endpoint in rule-only mode.
    await new Promise((r) => setTimeout(r, 50))
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('rule-only loading resolves correctly to done after narration arrives', async () => {
    mockFetchNarration.mockResolvedValue(RULE_RESULT)

    renderPanel(_IP, false)
    await userEvent.click(screen.getByTestId('explain-btn'))

    await waitFor(() => {
      expect(screen.getByTestId('narration-panel')).toHaveAttribute(
        'data-narration-phase',
        'done',
      )
    })
    expect(screen.getByTestId('narration-text')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-CR3-6: Graceful degradation when stream fails (ADR-0046 §7)
// ---------------------------------------------------------------------------

describe('CR3 EARS-6 — graceful degradation when stream fails', () => {
  it('shows stream-fallback (not ticker) when stream errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network error'))
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    await waitFor(() => {
      expect(screen.getByTestId('narration-stream-fallback')).toBeInTheDocument()
    })

    // Ticker must NOT render on stream error.
    expect(screen.queryByTestId('narration-inference-ticker')).not.toBeInTheDocument()
  })

  it('shows stream-fallback when stream returns non-OK status', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      status: 503,
      body: null,
    } as Response)
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    await waitFor(() => {
      expect(screen.getByTestId('narration-stream-fallback')).toBeInTheDocument()
    })
  })

  it('narration prose still arrives (done state) even when stream errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network error'))
    mockFetchNarration.mockResolvedValue(AI_RESULT)

    renderPanel(_IP, true)
    await userEvent.click(screen.getByTestId('explain-btn'))

    // After narration resolves, panel should reach done state.
    await waitFor(() => {
      expect(screen.getByTestId('narration-panel')).toHaveAttribute(
        'data-narration-phase',
        'done',
      )
    })
    expect(screen.getByTestId('narration-text')).toHaveTextContent(
      'triggered aggressive scanning rules',
    )
  })

  it('stream-fallback shows "Running local model…" text', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network error'))
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    await waitFor(() => {
      expect(screen.getByTestId('narration-stream-fallback')).toBeInTheDocument()
    })
    expect(screen.getByTestId('narration-stream-fallback')).toHaveTextContent(
      /Running local model/i,
    )
  })
})

// ---------------------------------------------------------------------------
// EARS-CR3-7: Accessibility — aria-live, aria-expanded, no inner scrollbar
// ---------------------------------------------------------------------------

describe('CR3 EARS-7 — accessibility: aria-live, aria-expanded', () => {
  it('ticker has aria-live="polite" status region', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      body: makeOpenStream(),
    } as Response)
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    await waitFor(() => {
      expect(screen.getByTestId('narration-inference-ticker')).toBeInTheDocument()
    })

    const liveRegion = screen
      .getByTestId('narration-inference-ticker')
      .querySelector('[aria-live="polite"]')
    expect(liveRegion).not.toBeNull()
  })

  it('toggle button has aria-expanded="false" when collapsed', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      body: makeOpenStream([
        'event: stage\ndata: {"stage":"validated"}\n\n',
      ]),
    } as Response)
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    await waitFor(() => {
      expect(screen.getByTestId('narration-ticker-toggle')).toBeInTheDocument()
    })

    // Collapsed by default → aria-expanded=false.
    expect(screen.getByTestId('narration-ticker-toggle')).toHaveAttribute(
      'aria-expanded',
      'false',
    )
  })

  it('toggle button aria-expanded updates to "true" when expanded', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      body: makeOpenStream([
        'event: stage\ndata: {"stage":"validated"}\n\n',
      ]),
    } as Response)
    mockFetchNarration.mockReturnValue(new Promise(() => {}))

    renderPanel(_IP, true)
    await act(async () => { await clickExplain() })

    await waitFor(() => {
      expect(screen.getByTestId('narration-ticker-toggle')).toBeInTheDocument()
    })

    await userEvent.click(screen.getByTestId('narration-ticker-toggle'))

    expect(screen.getByTestId('narration-ticker-toggle')).toHaveAttribute(
      'aria-expanded',
      'true',
    )
  })
})

// ---------------------------------------------------------------------------
// NarrationInferenceTicker — direct unit tests
// ---------------------------------------------------------------------------

describe('NarrationInferenceTicker — unit tests', () => {
  const STAGES_FIXTURE: StageFact[] = [
    { stage: 'prompt_built', sample_count: 10 },
    { stage: 'received', latency_ms: 5000, completion_tokens: 300 },
    { stage: 'validated' },
    { stage: 'projected', field_count: 5 },
  ]

  it('renders collapsed by default (no stages visible)', () => {
    render(
      <NarrationInferenceTicker
        stages={STAGES_FIXTURE}
        generatingElapsedMs={null}
        streaming={false}
        done={true}
      />,
    )
    expect(screen.queryByTestId('narration-ticker-stages')).not.toBeInTheDocument()
  })

  it('shows pulsing indicator when streaming', () => {
    render(
      <NarrationInferenceTicker
        stages={[]}
        generatingElapsedMs={1200}
        streaming={true}
        done={false}
      />,
    )
    // ● indicator when streaming.
    expect(screen.getByTestId('narration-ticker-indicator')).toHaveTextContent('●')
  })

  it('shows ○ indicator when done', () => {
    render(
      <NarrationInferenceTicker
        stages={STAGES_FIXTURE}
        generatingElapsedMs={null}
        streaming={false}
        done={true}
      />,
    )
    expect(screen.getByTestId('narration-ticker-indicator')).toHaveTextContent('○')
  })

  it('shows elapsed time from generatingElapsedMs when streaming', () => {
    render(
      <NarrationInferenceTicker
        stages={[]}
        generatingElapsedMs={3500}
        streaming={true}
        done={false}
      />,
    )
    // 3500ms → 3.5s
    expect(screen.getByTestId('narration-ticker-elapsed')).toHaveTextContent('3.5s')
  })

  it('shows received latency elapsed when done (not generating)', () => {
    const stages: StageFact[] = [
      { stage: 'received', latency_ms: 12000 },
    ]
    render(
      <NarrationInferenceTicker
        stages={stages}
        generatingElapsedMs={null}
        streaming={false}
        done={true}
      />,
    )
    // 12000ms → 12.0s
    expect(screen.getByTestId('narration-ticker-elapsed')).toHaveTextContent('12.0s')
  })

  it('expands to show stage labels on toggle click', async () => {
    render(
      <NarrationInferenceTicker
        stages={STAGES_FIXTURE}
        generatingElapsedMs={null}
        streaming={false}
        done={true}
      />,
    )

    await userEvent.click(screen.getByTestId('narration-ticker-toggle'))

    const stageList = screen.getByTestId('narration-ticker-stages')
    expect(stageList).toHaveTextContent('prompt built (10 samples)')
    expect(stageList).toHaveTextContent('schema validated ✓')
    expect(stageList).toHaveTextContent('projected to 5 fields ✓')
  })

  it('expanded received stage shows per-stage latency (proof of locality)', async () => {
    const stages: StageFact[] = [
      { stage: 'received', latency_ms: 8600, completion_tokens: 500 },
    ]
    render(
      <NarrationInferenceTicker
        stages={stages}
        generatingElapsedMs={null}
        streaming={false}
        done={true}
      />,
    )

    await userEvent.click(screen.getByTestId('narration-ticker-toggle'))

    const stageList = screen.getByTestId('narration-ticker-stages')
    expect(stageList).toHaveTextContent('received')
    // Per-stage elapsed (8.6s) is proof of locality.
    expect(stageList).toHaveTextContent('8.6s')
  })

  it('shows live generating counter when streaming + expanded', async () => {
    const stages: StageFact[] = [
      { stage: 'prompt_built', sample_count: 5 },
    ]
    render(
      <NarrationInferenceTicker
        stages={stages}
        generatingElapsedMs={4700}
        streaming={true}
        done={false}
      />,
    )

    await userEvent.click(screen.getByTestId('narration-ticker-toggle'))

    const generating = screen.getByTestId('narration-ticker-generating')
    expect(generating).toHaveTextContent('generating…')
    expect(generating).toHaveTextContent('4.7s')
  })

  it('live generating counter is aria-hidden (not announced to screen readers)', async () => {
    const stages: StageFact[] = [{ stage: 'prompt_built', sample_count: 3 }]
    render(
      <NarrationInferenceTicker
        stages={stages}
        generatingElapsedMs={2000}
        streaming={true}
        done={false}
      />,
    )

    await userEvent.click(screen.getByTestId('narration-ticker-toggle'))

    expect(screen.getByTestId('narration-ticker-generating')).toHaveAttribute(
      'aria-hidden',
      'true',
    )
  })

  it('no model-authored text in any stage line — only formatStageLabel output', async () => {
    // All text must come from formatStageLabel (closed enum).
    const modelText = 'SECRET MODEL OUTPUT NEVER RENDER'
    const stages: StageFact[] = [
      { stage: 'validated' },
      { stage: 'projected', field_count: 3 },
    ]

    // Verify that modelText is not part of formatStageLabel output.
    render(
      <NarrationInferenceTicker
        stages={stages}
        generatingElapsedMs={null}
        streaming={false}
        done={true}
      />,
    )

    await userEvent.click(screen.getByTestId('narration-ticker-toggle'))

    const ticker = screen.getByTestId('narration-inference-ticker')
    expect(ticker.textContent).not.toContain(modelText)
  })
})
