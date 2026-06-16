/**
 * Popover — shared anchored-overlay DS primitive (issue #665).
 *
 * A generic click-triggered popover that:
 *   - Portals to document.body so it is never clipped by parent stacking contexts.
 *   - Uses the existing useDismissableDisclosure primitive for outside-click dismiss,
 *     Esc dismiss (WCAG 1.4.13), single-open-at-a-time invariant, and focus restoration.
 *   - Uses useTooltipPosition for viewport-aware placement (flip above/below, right-edge
 *     clamp) — the same positioner used by CellDetailPopover and ScoreBreakdownPopover.
 *   - Is keyboard-operable: trigger is a <button> so it receives focus; Enter/Space open;
 *     Esc closes and returns focus to the trigger.
 *
 * Design note (ADR-0057):
 *   ADR-0057 stages the Radix migration into #289 (post-release). Until that lands,
 *   new overlays SHOULD reuse the existing pattern and add a TODO(#289) marker.
 *   This primitive IS that reusable seam — it consolidates the pattern so WS2/WS4
 *   can import it rather than duplicating the useDismissableDisclosure + createPortal
 *   wiring. When #289 migrates to Radix, only this file changes.
 *
 * TODO(#289): migrate the positioner + portal to @radix-ui/react-popover when the
 * #289 sweep lands, giving Floating-UI collision-aware placement and WAI-ARIA wiring.
 *
 * SECURITY (ADR-0029 D3):
 *   Children are attacker-controlled data rendered by the caller. The Popover itself
 *   never calls dangerouslySetInnerHTML — it is a layout shell only. Callers MUST
 *   render attacker-controlled values as text nodes only.
 *
 * Usage:
 *   <Popover
 *     trigger={<span>Top Talker ▾</span>}
 *     triggerAriaLabel="Show top talkers"
 *     data-testid="top-talker-popover"
 *   >
 *     <ul>…list items…</ul>
 *   </Popover>
 */

import { useRef } from 'react'
import { createPortal } from 'react-dom'
import { useDismissableDisclosure } from './core/useDismissableDisclosure'
import { useTooltipPosition } from './core/useTooltipPosition'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface PopoverProps {
  /**
   * The trigger element — rendered inside a <button> wrapper.
   * Using a wrapper keeps the caller from having to supply a button element
   * directly, while ensuring the trigger is always focusable and keyboard-operable.
   */
  trigger: React.ReactNode
  /**
   * ARIA label for the trigger button (for screen readers). Required when the
   * trigger visual content is not descriptive on its own (e.g. icon-only).
   */
  triggerAriaLabel?: string
  /**
   * Popover body content. Rendered when the popover is open.
   * Must render attacker-controlled values as text nodes only (ADR-0029 D3).
   */
  children: React.ReactNode
  /**
   * When true, prefer opening ABOVE the trigger (useful when the trigger is
   * near the bottom of the viewport). Default: false (open below).
   */
  preferAbove?: boolean
  /** data-testid for the trigger button. */
  'data-testid'?: string
  /** data-testid for the popover content panel. */
  contentTestId?: string
  /** Optional extra class applied to the popover panel wrapper. */
  className?: string
}

// ---------------------------------------------------------------------------
// Popover component
// ---------------------------------------------------------------------------

export function Popover({
  trigger,
  triggerAriaLabel,
  children,
  preferAbove = false,
  'data-testid': testId,
  contentTestId,
}: PopoverProps) {
  const contentRef = useRef<HTMLDivElement | null>(null)

  const { open, triggerRef, triggerProps } =
    useDismissableDisclosure()

  const position = useTooltipPosition(
    triggerRef as React.RefObject<HTMLElement | null>,
    open,
    { preferAbove, contentRef },
  )

  const panel = open
    ? createPortal(
        <div
          ref={contentRef}
          data-testid={contentTestId ?? 'popover-content'}
          role="dialog"
          aria-modal="false"
          aria-label={triggerAriaLabel}
          onKeyDown={(e) => {
            // Esc is handled by useDismissableDisclosure's document listener;
            // stopping propagation here prevents the event from reaching parent
            // handlers (layered-Esc contract, #226).
            if (e.key === 'Escape') {
              e.stopPropagation()
            }
          }}
          style={{
            position: 'fixed',
            top: position.top,
            left: position.left,
            zIndex: 120,
            minWidth: 220,
            maxWidth: 360,
            background: 'var(--fw-bg-card)',
            border: '1px solid var(--fw-border-l)',
            borderRadius: 'var(--fw-r-md)',
            boxShadow: 'var(--fw-shadow-popup)',
            padding: '8px 0',
            fontFamily: 'var(--fw-font-ui)',
            fontSize: 12,
            color: 'var(--fw-t1)',
          }}
        >
          {children}
        </div>,
        document.body,
      )
    : null

  return (
    <>
      <button
        ref={triggerRef as React.RefObject<HTMLButtonElement>}
        type="button"
        data-testid={testId}
        aria-label={triggerAriaLabel}
        aria-expanded={open}
        aria-haspopup="dialog"
        {...triggerProps}
        style={{
          background: 'none',
          border: 'none',
          padding: 0,
          cursor: 'pointer',
          fontFamily: 'inherit',
          fontSize: 'inherit',
          color: 'inherit',
          display: 'inline-flex',
          alignItems: 'center',
          gap: 4,
        }}
      >
        {trigger}
      </button>

      {panel}
    </>
  )
}
