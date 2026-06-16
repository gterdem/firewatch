/**
 * Tests for three entity slide-over bugs found in ui-tester sweep 2026-06-13:
 *
 *   UT-01 (#501): slide-over body must scroll — `minHeight: 0` on the body div.
 *   UT-02 (#502): 409 concurrent stream handled gracefully with user-visible message.
 *   UT-03 (#503): Score/AI/Timeline/Logs chips are a proper WAI-ARIA tablist.
 *
 * EARS criteria covered:
 *
 * UT-01 (scroll):
 *   EARS-UT01-1: slide-over-body has `overflow-y: auto` (scrollable).
 *   EARS-UT01-2: slide-over-body has `min-height: 0` (bounded in flex column).
 *   EARS-UT01-3: slide-over-header has `flex-shrink: 0` (stays fixed / not scrolled away).
 *   EARS-UT01-4: slide-over panel has `display: flex, flex-direction: column` (flex container).
 *
 * UT-02 (409 conflict):
 *   EARS-UT02-1: persistent 409 (all retries exhausted) sets persistentConflict=true, not streamError.
 *   EARS-UT02-2: transient 409 (resolved on retry) does NOT set persistentConflict.
 *   EARS-UT02-3: DeepAnalysisControl renders "please wait" badge when persistentConflict is true.
 *   EARS-UT02-4: DeepAnalysisControl does NOT call onStreamError when persistentConflict is true.
 *   EARS-UT02-5: DeepAnalysisControl DOES call onStreamError for a genuine (non-conflict) stream error.
 *
 * UT-03 (a11y tabs):
 *   EARS-UT03-1: section-chips container has role="tablist".
 *   EARS-UT03-2: each chip button has role="tab".
 *   EARS-UT03-3: first chip has aria-selected="true" on initial render.
 *   EARS-UT03-4: clicking a chip sets aria-selected="true" on that chip.
 *   EARS-UT03-5: clicking a chip sets aria-selected="false" on previously-selected chip.
 *   EARS-UT03-6: ArrowRight key moves focus to the next chip.
 *   EARS-UT03-7: ArrowLeft key moves focus to the previous chip.
 *   EARS-UT03-8: ArrowRight from last chip wraps to first chip.
 *   EARS-UT03-9: ArrowLeft from first chip wraps to last chip.
 *   EARS-UT03-10: Home key moves focus to first chip.
 *   EARS-UT03-11: End key moves focus to last chip.
 *   EARS-UT03-12: active chip has tabIndex=0; inactive chips have tabIndex=-1 (roving tabindex).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, renderHook } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SlideOver from '../components/entity/SlideOver'
import { SectionChips } from '../components/entity/SectionChips'
import DeepAnalysisControl from '../components/entity/ip/DeepAnalysisControl'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// resolveBaseUrl is called by useStageTicker
vi.mock('../api/client', () => ({
  resolveBaseUrl: vi.fn(() => 'http://localhost:8000'),
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchHealth: vi.fn().mockResolvedValue({ status: 'ok', ollama_connected: false, ollama_model: null }),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: unknown) {
      super(String(message ?? status))
      this.status = status
    }
  },
}))

// ---------------------------------------------------------------------------
// UT-01: SlideOver scroll geometry (#501)
// ---------------------------------------------------------------------------

describe('UT-01 (#501) — slide-over body scrolls within fixed panel', () => {
  it('EARS-UT01-1: slide-over-body has overflow-y: auto', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test">
        <div>content</div>
      </SlideOver>,
    )
    const body = screen.getByTestId('slide-over-body')
    // Style is applied inline; check the computed style
    expect(body.style.overflowY).toBe('auto')
  })

  it('EARS-UT01-2: slide-over-body has min-height: 0 (prevents flex item expansion past container)', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test">
        <div>content</div>
      </SlideOver>,
    )
    const body = screen.getByTestId('slide-over-body')
    expect(body.style.minHeight).toBe('0px')
  })

  it('EARS-UT01-3: slide-over-header has flex-shrink: 0 (header stays fixed)', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test">
        <div>content</div>
      </SlideOver>,
    )
    const header = screen.getByTestId('slide-over-header')
    expect(header.style.flexShrink).toBe('0')
  })

  it('EARS-UT01-4: slide-over panel is a flex column container', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test">
        <div>content</div>
      </SlideOver>,
    )
    const panel = screen.getByTestId('slide-over-panel')
    expect(panel.style.display).toBe('flex')
    expect(panel.style.flexDirection).toBe('column')
  })
})

// ---------------------------------------------------------------------------
// UT-02: 409 concurrent stream handling (#502)
// ---------------------------------------------------------------------------

/**
 * Helper: build a mock fetch that always returns 409.
 */
function make409Fetch() {
  return vi.fn().mockResolvedValue({
    status: 409,
    ok: false,
    body: null,
  })
}

/**
 * Helper: build a fetch mock that returns 409 on the first N calls, then succeeds
 * with an immediate `result` SSE event.
 */
function make409ThenSuccessFetch(fail409Count: number) {
  let callCount = 0
  return vi.fn().mockImplementation(() => {
    callCount++
    if (callCount <= fail409Count) {
      return Promise.resolve({ status: 409, ok: false, body: null })
    }
    // Success: return a readable stream with a single `result` event.
    const resultPayload = JSON.stringify({ score: 50, analysis: 'test' })
    const sseText = `event: result\ndata: ${resultPayload}\n\n`
    const encoder = new TextEncoder()
    const bytes = encoder.encode(sseText)
    let sent = false
    const stream = new ReadableStream({
      pull(controller) {
        if (!sent) {
          sent = true
          controller.enqueue(bytes)
        } else {
          controller.close()
        }
      },
    })
    return Promise.resolve({
      status: 200,
      ok: true,
      body: stream,
    })
  })
}

describe('UT-02 (#502) — 409 concurrent stream handled gracefully', () => {
  let originalFetch: typeof globalThis.fetch

  beforeEach(() => {
    originalFetch = globalThis.fetch
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
    vi.useRealTimers()
  })

  it('EARS-UT02-1: persistent 409 (all retries exhausted) sets persistentConflict=true, streamError stays false', async () => {
    // useStageTicker makes up to 1 + MAX_409_RETRIES = 3 attempts.
    // All 3 return 409 → persistentConflict=true.
    globalThis.fetch = make409Fetch()

    const { useStageTicker } = await import('../components/entity/ip/ticker/useStageTicker')
    const { result } = renderHook(() =>
      useStageTicker({ ip: '192.0.2.1', enabled: true }),
    )

    await waitFor(() => expect(result.current.done).toBe(true), { timeout: 3000 })

    expect(result.current.persistentConflict).toBe(true)
    expect(result.current.streamError).toBe(false)
  })

  it('EARS-UT02-2: single transient 409 (succeeds on retry) does NOT set persistentConflict', async () => {
    // First call 409, second call succeeds.
    globalThis.fetch = make409ThenSuccessFetch(1)

    const { useStageTicker } = await import('../components/entity/ip/ticker/useStageTicker')
    const { result } = renderHook(() =>
      useStageTicker({ ip: '192.0.2.1', enabled: true }),
    )

    await waitFor(() => expect(result.current.result).not.toBeNull(), { timeout: 3000 })

    expect(result.current.persistentConflict).toBe(false)
    expect(result.current.streamError).toBe(false)
  })

  it('EARS-UT02-3: DeepAnalysisControl renders "please wait" badge when persistentConflict=true', async () => {
    // Render DeepAnalysisControl in analyzing phase with a fetch that always 409s.
    globalThis.fetch = make409Fetch()

    const onRun = vi.fn()
    const onStreamError = vi.fn()
    render(
      <DeepAnalysisControl
        phase="analyzing"
        elapsedSeconds={5}
        modelName="gemma3:4b"
        onRun={onRun}
        ip="192.0.2.1"
        onStreamError={onStreamError}
      />,
    )

    await waitFor(
      () => expect(screen.getByTestId('deep-analysis-conflict-badge')).toBeInTheDocument(),
      { timeout: 3000 },
    )

    expect(screen.getByTestId('deep-analysis-conflict-badge')).toHaveTextContent(
      'Analysis already running — please wait',
    )
  })

  it('EARS-UT02-4: DeepAnalysisControl does NOT call onStreamError when persistentConflict=true', async () => {
    globalThis.fetch = make409Fetch()

    const onStreamError = vi.fn()
    render(
      <DeepAnalysisControl
        phase="analyzing"
        elapsedSeconds={5}
        modelName={null}
        onRun={vi.fn()}
        ip="192.0.2.1"
        onStreamError={onStreamError}
      />,
    )

    // Wait for the conflict badge to appear (all retries exhausted)
    await waitFor(
      () => expect(screen.getByTestId('deep-analysis-conflict-badge')).toBeInTheDocument(),
      { timeout: 3000 },
    )

    // onStreamError must NOT have been called — no fallback fetch should fire
    expect(onStreamError).not.toHaveBeenCalled()
  })

  it('EARS-UT02-5: DeepAnalysisControl DOES call onStreamError for a genuine non-conflict stream error', async () => {
    // Return a genuine non-OK, non-409 response
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 500,
      ok: false,
      body: null,
    })

    const onStreamError = vi.fn()
    render(
      <DeepAnalysisControl
        phase="analyzing"
        elapsedSeconds={5}
        modelName={null}
        onRun={vi.fn()}
        ip="192.0.2.1"
        onStreamError={onStreamError}
      />,
    )

    await waitFor(() => expect(onStreamError).toHaveBeenCalledTimes(1), { timeout: 2000 })
  })
})

// ---------------------------------------------------------------------------
// UT-03: WAI-ARIA tablist on SectionChips (#503)
// ---------------------------------------------------------------------------

const CHIPS = [
  { label: 'Score', targetId: 'ip-section-score' },
  { label: 'AI', targetId: 'ip-section-ai' },
  { label: 'Timeline', targetId: 'ip-section-timeline' },
  { label: 'Logs', targetId: 'ip-section-logs' },
]

describe('UT-03 (#503) — SectionChips WAI-ARIA tablist semantics', () => {
  it('EARS-UT03-1: section-chips container has role="tablist"', () => {
    render(<SectionChips chips={CHIPS} />)
    expect(screen.getByTestId('section-chips')).toHaveAttribute('role', 'tablist')
  })

  it('EARS-UT03-2: each chip button has role="tab"', () => {
    render(<SectionChips chips={CHIPS} />)
    const tabs = screen.getAllByRole('tab')
    expect(tabs).toHaveLength(CHIPS.length)
  })

  it('EARS-UT03-3: first chip has aria-selected="true" on initial render', () => {
    render(<SectionChips chips={CHIPS} />)
    const tabs = screen.getAllByRole('tab')
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
    tabs.slice(1).forEach((tab) => {
      expect(tab).toHaveAttribute('aria-selected', 'false')
    })
  })

  it('EARS-UT03-4: clicking a chip sets aria-selected="true" on that chip', async () => {
    render(<SectionChips chips={CHIPS} />)
    const tabs = screen.getAllByRole('tab')
    await userEvent.click(tabs[2]) // "Timeline"
    expect(tabs[2]).toHaveAttribute('aria-selected', 'true')
  })

  it('EARS-UT03-5: clicking a chip clears aria-selected from previously-selected chip', async () => {
    render(<SectionChips chips={CHIPS} />)
    const tabs = screen.getAllByRole('tab')
    await userEvent.click(tabs[2]) // "Timeline"
    expect(tabs[0]).toHaveAttribute('aria-selected', 'false') // was previously selected
  })

  it('EARS-UT03-6: ArrowRight moves focus to the next chip', async () => {
    render(<SectionChips chips={CHIPS} />)
    const tabs = screen.getAllByRole('tab')
    tabs[0].focus()
    await userEvent.keyboard('{ArrowRight}')
    expect(tabs[1]).toHaveFocus()
  })

  it('EARS-UT03-7: ArrowLeft moves focus to the previous chip', async () => {
    render(<SectionChips chips={CHIPS} />)
    const tabs = screen.getAllByRole('tab')
    // Start from second chip to go left
    await userEvent.click(tabs[1])
    tabs[1].focus()
    await userEvent.keyboard('{ArrowLeft}')
    expect(tabs[0]).toHaveFocus()
  })

  it('EARS-UT03-8: ArrowRight from last chip wraps to first chip', async () => {
    render(<SectionChips chips={CHIPS} />)
    const tabs = screen.getAllByRole('tab')
    const last = tabs[CHIPS.length - 1]
    last.focus()
    await userEvent.keyboard('{ArrowRight}')
    expect(tabs[0]).toHaveFocus()
  })

  it('EARS-UT03-9: ArrowLeft from first chip wraps to last chip', async () => {
    render(<SectionChips chips={CHIPS} />)
    const tabs = screen.getAllByRole('tab')
    tabs[0].focus()
    await userEvent.keyboard('{ArrowLeft}')
    expect(tabs[CHIPS.length - 1]).toHaveFocus()
  })

  it('EARS-UT03-10: Home key moves focus to the first chip', async () => {
    render(<SectionChips chips={CHIPS} />)
    const tabs = screen.getAllByRole('tab')
    await userEvent.click(tabs[2])
    tabs[2].focus()
    await userEvent.keyboard('{Home}')
    expect(tabs[0]).toHaveFocus()
  })

  it('EARS-UT03-11: End key moves focus to the last chip', async () => {
    render(<SectionChips chips={CHIPS} />)
    const tabs = screen.getAllByRole('tab')
    tabs[0].focus()
    await userEvent.keyboard('{End}')
    expect(tabs[CHIPS.length - 1]).toHaveFocus()
  })

  it('EARS-UT03-12: active chip has tabIndex=0; inactive chips have tabIndex=-1 (roving tabindex)', () => {
    render(<SectionChips chips={CHIPS} />)
    const tabs = screen.getAllByRole('tab')
    expect(tabs[0]).toHaveAttribute('tabindex', '0')
    tabs.slice(1).forEach((tab) => {
      expect(tab).toHaveAttribute('tabindex', '-1')
    })
  })
})
