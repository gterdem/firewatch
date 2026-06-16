/**
 * Layered-Esc tests for the Signature cell tooltip (#283 — replaces RulePopup).
 *
 * These tests verify that the RuleCellTooltip + CellTooltip + useHoverFocusDisclosure
 * stack correctly implements the layered-Esc contract (#226):
 *   - While the tooltip is open (peek OR pin), Esc closes only the tooltip.
 *   - The slide-over's Esc handler does NOT fire on the same keypress.
 *   - After the tooltip closes, the next Esc reaches the EntityPanelProvider.
 *
 * Note: RulePopup was deleted (#283). The tests below are the semantic
 * equivalents of the old RulePopupEsc tests, now exercising RuleCellTooltip.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RuleCellTooltip } from '../components/logs/RuleCellTooltip'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import { useEntityPanel } from '../components/entity/EntityPanelContext'
import SlideOver from '../components/entity/SlideOver'
import type { RuleDescription } from '../api/types'

// ---------------------------------------------------------------------------
// Mock API calls used by EntityPanelProvider / IpPanel
// ---------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchThreats: vi.fn().mockResolvedValue([]),
  // Issue #268: useDeepAnalysis calls fetchHealth; default to AI offline so it resolves instantly.
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'ok', ollama_connected: false, ollama_model: null, db_ok: true,
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
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
}))

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const EMPTY_RULES: RuleDescription[] = []

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Rig: SlideOver + RuleCellTooltip. Used to test propagation of Esc.
 * The panel's onClose is a spy so we can verify it was NOT called.
 */
function PanelAndTooltipRig({ panelOnClose }: { panelOnClose: () => void }) {
  return (
    <>
      <SlideOver open={true} onClose={panelOnClose} ariaLabel="test panel">
        body
      </SlideOver>
      <RuleCellTooltip ruleId="SID-1" rules={EMPTY_RULES} />
    </>
  )
}

/**
 * EntityPanelProvider rig: opens an entity panel, with a RuleCellTooltip trigger.
 * Used to test the real two-layer Esc chain that includes EntityPanelProvider.
 */
function ProviderRig() {
  const { openEntity } = useEntityPanel()
  return (
    <div>
      <button
        data-testid="open-panel-btn"
        onClick={() => openEntity({ kind: 'ip', value: '192.0.2.1' })}
      >
        Open panel
      </button>
      {/* RuleCellTooltip inline — simulates a Signature cell in the slide-over */}
      <RuleCellTooltip ruleId="SID-99" rules={EMPTY_RULES} />
    </div>
  )
}

// ---------------------------------------------------------------------------
// beforeEach
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
})

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RuleCellTooltip layered Esc (#283 — replaces RulePopup Esc tests)', () => {
  // Esc while peek mode open does NOT call panel's onClose.
  it('Esc with tooltip peeking does NOT call panel onClose (propagation stopped)', async () => {
    const user = userEvent.setup()
    const panelOnClose = vi.fn()

    render(<PanelAndTooltipRig panelOnClose={panelOnClose} />)

    // Open peek mode by focusing the trigger
    const trigger = screen.getByTestId('rule-cell-tooltip-trigger')
    fireEvent.focus(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })

    // Esc: tooltip intercepts — panel's onClose must NOT be called
    await user.keyboard('{Escape}')
    expect(panelOnClose).not.toHaveBeenCalled()
  })

  // After peek closes, Esc reaches the bubble-phase handler.
  it('after tooltip closes via Esc, subsequent Esc reaches outer handler', async () => {
    const user = userEvent.setup()
    const bubbleListener = vi.fn()
    document.addEventListener('keydown', bubbleListener)

    try {
      render(
        <RuleCellTooltip ruleId="SID-1" rules={EMPTY_RULES} />,
      )

      const trigger = screen.getByTestId('rule-cell-tooltip-trigger')
      fireEvent.focus(trigger)
      await waitFor(() => {
        expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
      })

      // First Esc: tooltip intercepts → bubble listener blocked
      await user.keyboard('{Escape}')
      expect(bubbleListener).not.toHaveBeenCalled()
      expect(screen.queryByTestId('cell-tooltip-content')).not.toBeInTheDocument()

      // Second Esc: tooltip gone → bubble reaches handler
      await user.keyboard('{Escape}')
      expect(bubbleListener).toHaveBeenCalledTimes(1)
    } finally {
      document.removeEventListener('keydown', bubbleListener)
    }
  })

  // Esc while CellDetailPopover open dismisses it (not the outer slide-over).
  // Post-#329: click opens CellDetailPopover (replaces old peek-then-pin grammar).
  it('Esc with tooltip pinned closes pin only — panel stays visible', async () => {
    const user = userEvent.setup()
    const panelOnClose = vi.fn()

    render(<PanelAndTooltipRig panelOnClose={panelOnClose} />)

    // Open CellDetailPopover via click on the display-name span
    await user.click(screen.getByTestId('rule-cell-display-name'))
    // CellDetailPopover is now open — confirm it's visible
    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument()
    })
    // Panel still open
    expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()

    // Esc: closes CellDetailPopover, panel stays
    await user.keyboard('{Escape}')
    await waitFor(() => {
      expect(screen.queryByTestId('rule-cell-detail-popover')).not.toBeInTheDocument()
    })
    expect(panelOnClose).not.toHaveBeenCalled()
    // Panel stays
    expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
  })

  // Two-stage Esc via EntityPanelProvider (real Esc chain integration).
  it('two-stage Esc: first closes tooltip, second closes EntityPanelProvider panel', async () => {
    const user = userEvent.setup()

    render(
      <EntityPanelProvider>
        <ProviderRig />
      </EntityPanelProvider>,
    )

    // Open the entity panel
    await user.click(screen.getByTestId('open-panel-btn'))
    await waitFor(() => {
      expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
    })

    // Open tooltip peek mode by focusing trigger
    const trigger = screen.getByTestId('rule-cell-tooltip-trigger')
    fireEvent.focus(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })

    // First Esc: closes tooltip only — panel stays
    await user.keyboard('{Escape}')
    expect(screen.queryByTestId('cell-tooltip-content')).not.toBeInTheDocument()
    expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()

    // Second Esc: tooltip gone → EntityPanelProvider's handler runs → closes panel
    await user.keyboard('{Escape}')
    await waitFor(() => {
      expect(screen.queryByTestId('slide-over-panel')).not.toBeInTheDocument()
    })
  })
})
