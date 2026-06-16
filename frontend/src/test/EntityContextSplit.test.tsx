/**
 * Tests for issue #324 — EntityPanelContext split (stable actions vs state).
 *
 * EARS criteria covered:
 *
 * Acceptance criteria (#324):
 *   - WHEN the slide-over opens or closes, dashboard data panels SHALL NOT re-render
 *     (verified by asserting the openEntity reference is the same object before/after
 *     open/close, and by asserting a useEntityActions() consumer does not re-render).
 *   - The openEntity action reference SHALL be stable across open/close cycles.
 *   - useEntityActions() returns the same object reference on every render
 *     (open/close does not change the actions context value).
 *   - useEntityPanel() continues to return combined state+actions (backward compat).
 *   - useEntityState() returns the panel stack (changes on open/close).
 *   - No regression to #269 pin/push: openEntity still opens the slide-over.
 *
 * RFC-5737 IPs used throughout (192.0.2.0/24).
 *
 * Render-count strategy:
 *   The react-hooks lint rules forbid (a) mutating module-scope variables during
 *   render and (b) accessing ref.current during render. We therefore rely on
 *   reference-stability assertions rather than direct render-count counters:
 *   if the actions context value never changes, React skips re-rendering any
 *   consumer of that context. We verify this by checking that the openEntity
 *   function reference captured before and after an open/close cycle is the
 *   same JS object identity, AND by checking that a vi.fn() spy passed as an
 *   `onRender` prop to an ActionsConsumer is called exactly once (the initial
 *   mount) even after open/close.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import {
  useEntityPanel,
  useEntityActions,
  useEntityState,
} from '../components/entity/EntityPanelContext'
import type { EntityRef } from '../components/entity/EntityPanelContext'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchThreats: vi.fn().mockResolvedValue([]),
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'ok',
    ollama_connected: false,
    ollama_model: null,
    db_ok: true,
  }),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: unknown) {
      super(String(message ?? status))
      this.status = status
    }
  },
}))

vi.mock('../api/logs', () => ({
  fetchThreatScore: vi.fn().mockReturnValue(new Promise(() => {})),
  fetchDetailedAnalysis: vi.fn().mockReturnValue(new Promise(() => {})),
  fetchRules: vi.fn().mockReturnValue(new Promise(() => {})),
  fetchIpEvents: vi.fn().mockReturnValue(new Promise(() => {})),
}))

// ---------------------------------------------------------------------------
// Top-level components (must not be declared inside render functions per
// react-hooks/static-components lint rule).
// ---------------------------------------------------------------------------

/**
 * ActionsConsumer — subscribes to useEntityActions() (stable context).
 * Calls `onRender` spy during every render so the test can count re-renders.
 * Exposes buttons to trigger open/close/closePanelAll.
 */
function ActionsConsumer({
  onRender,
  onRefCapture,
}: {
  onRender: () => void
  onRefCapture: (fn: (ref: EntityRef) => void) => void
}) {
  const { openEntity, closeEntity, closePanelAll } = useEntityActions()
  onRender()
  onRefCapture(openEntity)
  return (
    <div>
      <button
        data-testid="open-btn"
        onClick={() => openEntity({ kind: 'ip', value: '192.0.2.1' })}
      >
        Open
      </button>
      <button data-testid="close-btn" onClick={() => closeEntity()}>
        Close
      </button>
      <button data-testid="close-all-btn" onClick={() => closePanelAll()}>
        Close all
      </button>
    </div>
  )
}

/**
 * StateConsumer — subscribes to useEntityState() (changes on open/close).
 * Shows the current stack length as a testid so tests can observe state changes.
 */
function StateConsumer() {
  const { stack } = useEntityState()
  return <div data-testid="stack-length">{stack.length}</div>
}

/** Backward compat check — useEntityPanel() returns stack + all actions. */
function LegacyConsumer() {
  const ctx = useEntityPanel()
  return (
    <div>
      <div data-testid="has-stack">{Array.isArray(ctx.stack) ? 'yes' : 'no'}</div>
      <div data-testid="has-open">{typeof ctx.openEntity === 'function' ? 'yes' : 'no'}</div>
      <div data-testid="has-close">{typeof ctx.closeEntity === 'function' ? 'yes' : 'no'}</div>
      <div data-testid="has-close-all">
        {typeof ctx.closePanelAll === 'function' ? 'yes' : 'no'}
      </div>
    </div>
  )
}

/** Opener that uses useEntityActions() to open a given entity. */
function ActionsOpener({ testId, ip }: { testId: string; ip: string }) {
  const { openEntity } = useEntityActions()
  return (
    <button
      data-testid={testId}
      onClick={() => openEntity({ kind: 'ip', value: ip })}
    >
      Open
    </button>
  )
}

/** StateOnly — renders only the stack length via useEntityState(). */
function StateOnlyConsumer() {
  const { stack } = useEntityState()
  return <div data-testid="state-stack">{stack.length}</div>
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('EntityPanelContext split (#324)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // -------------------------------------------------------------------------
  // Core acceptance criterion: actions consumer does NOT re-render on open/close.
  //
  // We verify this by:
  //   1. Counting how many times the onRender spy is called (render count).
  //   2. Asserting the openEntity reference is the same object before/after.
  // -------------------------------------------------------------------------

  it('actions consumer does NOT re-render when slide-over opens (onRender spy count stays at 1)', async () => {
    const onRender = vi.fn()
    const capturedRefs: ((ref: EntityRef) => void)[] = []

    render(
      <EntityPanelProvider>
        <ActionsConsumer
          onRender={onRender}
          onRefCapture={(fn) => capturedRefs.push(fn)}
        />
        <StateConsumer />
      </EntityPanelProvider>,
    )

    // After mount: exactly 1 render.
    expect(onRender).toHaveBeenCalledTimes(1)

    // Open the slide-over — triggers a setState in EntityPanelProvider.
    await userEvent.click(screen.getByTestId('open-btn'))

    // StateConsumer must see the updated stack.
    await waitFor(() => expect(screen.getByTestId('stack-length')).toHaveTextContent('1'))

    // ActionsConsumer must NOT have re-rendered — spy still called exactly once.
    expect(onRender).toHaveBeenCalledTimes(1)
  })

  it('actions consumer does NOT re-render when slide-over closes (onRender spy count unchanged)', async () => {
    const onRender = vi.fn()
    const capturedRefs: ((ref: EntityRef) => void)[] = []

    render(
      <EntityPanelProvider>
        <ActionsConsumer
          onRender={onRender}
          onRefCapture={(fn) => capturedRefs.push(fn)}
        />
        <StateConsumer />
      </EntityPanelProvider>,
    )

    // Open first.
    await userEvent.click(screen.getByTestId('open-btn'))
    await waitFor(() => expect(screen.getByTestId('stack-length')).toHaveTextContent('1'))
    const countAfterOpen = onRender.mock.calls.length

    // Now close.
    await userEvent.click(screen.getByTestId('close-btn'))
    await waitFor(() => expect(screen.getByTestId('stack-length')).toHaveTextContent('0'))

    // Must not have re-rendered on close either.
    expect(onRender).toHaveBeenCalledTimes(countAfterOpen)
  })

  it('actions consumer does NOT re-render when closePanelAll is called', async () => {
    const onRender = vi.fn()
    const capturedRefs: ((ref: EntityRef) => void)[] = []

    render(
      <EntityPanelProvider>
        <ActionsConsumer
          onRender={onRender}
          onRefCapture={(fn) => capturedRefs.push(fn)}
        />
        <StateConsumer />
      </EntityPanelProvider>,
    )

    await userEvent.click(screen.getByTestId('open-btn'))
    await waitFor(() => expect(screen.getByTestId('stack-length')).toHaveTextContent('1'))
    const countAfterOpen = onRender.mock.calls.length

    await userEvent.click(screen.getByTestId('close-all-btn'))
    await waitFor(() => expect(screen.getByTestId('stack-length')).toHaveTextContent('0'))

    expect(onRender).toHaveBeenCalledTimes(countAfterOpen)
  })

  // -------------------------------------------------------------------------
  // openEntity reference stability across open/close
  // -------------------------------------------------------------------------

  it('openEntity reference is stable across open/close cycles', async () => {
    const capturedRefs: ((ref: EntityRef) => void)[] = []
    const onRender = vi.fn()

    render(
      <EntityPanelProvider>
        <ActionsConsumer
          onRender={onRender}
          onRefCapture={(fn) => capturedRefs.push(fn)}
        />
        <StateConsumer />
      </EntityPanelProvider>,
    )

    // After mount the first ref is captured.
    expect(capturedRefs.length).toBe(1)
    const refBeforeOpen = capturedRefs[0]

    // Open → state changes → EntityPanelContext re-renders; actions context does not.
    await userEvent.click(screen.getByTestId('open-btn'))
    await waitFor(() => expect(screen.getByTestId('stack-length')).toHaveTextContent('1'))

    // Close.
    await userEvent.click(screen.getByTestId('close-btn'))
    await waitFor(() => expect(screen.getByTestId('stack-length')).toHaveTextContent('0'))

    // ActionsConsumer did not re-render → only 1 ref was ever captured.
    expect(capturedRefs.length).toBe(1)
    // That single ref is the same function as before.
    expect(capturedRefs[0]).toBe(refBeforeOpen)
  })

  // -------------------------------------------------------------------------
  // State consumer re-renders correctly on open/close
  // -------------------------------------------------------------------------

  it('state consumer stack length updates when slide-over opens', async () => {
    const onRender = vi.fn()
    const capturedRefs: ((ref: EntityRef) => void)[] = []

    render(
      <EntityPanelProvider>
        <ActionsConsumer
          onRender={onRender}
          onRefCapture={(fn) => capturedRefs.push(fn)}
        />
        <StateConsumer />
      </EntityPanelProvider>,
    )

    expect(screen.getByTestId('stack-length')).toHaveTextContent('0')

    await userEvent.click(screen.getByTestId('open-btn'))

    await waitFor(() => expect(screen.getByTestId('stack-length')).toHaveTextContent('1'))
  })

  it('state consumer stack length updates when slide-over closes', async () => {
    const onRender = vi.fn()
    const capturedRefs: ((ref: EntityRef) => void)[] = []

    render(
      <EntityPanelProvider>
        <ActionsConsumer
          onRender={onRender}
          onRefCapture={(fn) => capturedRefs.push(fn)}
        />
        <StateConsumer />
      </EntityPanelProvider>,
    )

    await userEvent.click(screen.getByTestId('open-btn'))
    await waitFor(() => expect(screen.getByTestId('stack-length')).toHaveTextContent('1'))

    await userEvent.click(screen.getByTestId('close-btn'))
    await waitFor(() => expect(screen.getByTestId('stack-length')).toHaveTextContent('0'))
  })

  // -------------------------------------------------------------------------
  // useEntityPanel backward compatibility — still returns state + actions
  // -------------------------------------------------------------------------

  it('useEntityPanel() returns both stack and action functions (backward compat)', () => {
    render(
      <EntityPanelProvider>
        <LegacyConsumer />
      </EntityPanelProvider>,
    )

    expect(screen.getByTestId('has-stack')).toHaveTextContent('yes')
    expect(screen.getByTestId('has-open')).toHaveTextContent('yes')
    expect(screen.getByTestId('has-close')).toHaveTextContent('yes')
    expect(screen.getByTestId('has-close-all')).toHaveTextContent('yes')
  })

  // -------------------------------------------------------------------------
  // useEntityState — returns panel stack correctly
  // -------------------------------------------------------------------------

  it('useEntityState() returns current stack (0 before open, 1 after open)', async () => {
    render(
      <EntityPanelProvider>
        <ActionsOpener testId="open-state-test" ip="192.0.2.5" />
        <StateOnlyConsumer />
      </EntityPanelProvider>,
    )

    expect(screen.getByTestId('state-stack')).toHaveTextContent('0')

    await userEvent.click(screen.getByTestId('open-state-test'))

    await waitFor(() => expect(screen.getByTestId('state-stack')).toHaveTextContent('1'))
  })

  // -------------------------------------------------------------------------
  // Slide-over still opens (no regression to #204/#269 openEntity semantics)
  // -------------------------------------------------------------------------

  it('openEntity via useEntityActions() still opens the slide-over panel', async () => {
    render(
      <EntityPanelProvider>
        <ActionsOpener testId="open-panel-test" ip="192.0.2.9" />
      </EntityPanelProvider>,
    )

    // Panel must not exist before click.
    expect(screen.queryByTestId('slide-over-panel')).not.toBeInTheDocument()

    await userEvent.click(screen.getByTestId('open-panel-test'))

    await waitFor(() => expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument())
  })
})
