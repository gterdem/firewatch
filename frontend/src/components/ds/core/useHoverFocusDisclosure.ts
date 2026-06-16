/**
 * useHoverFocusDisclosure — shared open/close/Esc/hover-intent hook for
 * WCAG 2.2 SC 1.4.13 compliant tooltip triggers.
 *
 * WCAG 1.4.13 requirements implemented here:
 *   - Dismissible:  Esc closes the tooltip without moving the pointer.
 *   - Hoverable:    a small leave-delay lets the pointer travel from the
 *                   trigger onto the tooltip content without the content
 *                   vanishing (clearLeave / scheduleLeave pair).
 *   - Persistent:   content stays until hover/focus ends or Esc dismisses
 *                   it — no auto-timeout ever fires.
 *   - Keyboard parity: focus/blur open and close the tooltip identically
 *                   to pointer hover.
 *
 * Layered-Esc contract (#226):
 *   When the tooltip is open, Esc is intercepted in the CAPTURE phase and
 *   stopImmediatePropagation() prevents the event from reaching the slide-over
 *   provider's Esc handler. This mirrors the RulePopup pattern exactly:
 *   tooltip Esc → close tooltip; next Esc → close slide-over.
 *
 * peek-then-pin support (#283):
 *   When forceOpen=true is passed (the caller has "pinned" the tooltip), the
 *   Esc handler runs even when the hover-open state is false, so the pin can
 *   be cleared by Esc. onEscDismiss is called to let the caller clear forceOpen.
 *
 * Returns event handlers to spread on the trigger element and a pair of
 * hover-intent handlers to spread on the tooltip container.
 */

import { useState, useEffect, useRef, useCallback } from 'react'

// How long (ms) to wait before closing after the pointer leaves the trigger.
// Long enough for the user to move the pointer to the tooltip content.
const LEAVE_DELAY_MS = 80

export interface HoverFocusDisclosureOptions {
  /**
   * When true, the caller has "pinned" the tooltip open. The Esc handler will
   * fire and call onEscDismiss even when hover-open is false, so the pin can
   * be cleared by Esc. (#283 peek-then-pin).
   */
  forceOpen?: boolean
  /**
   * Called when Esc is pressed and the tooltip is visible (hover or pinned).
   * The caller should clear any forceOpen state here.
   */
  onEscDismiss?: () => void
}

export interface HoverFocusDisclosureResult {
  /** Whether the tooltip is currently open (hover/focus — not forceOpen). */
  open: boolean
  /** Spread these onto the trigger element. */
  triggerProps: {
    onMouseEnter: () => void
    onMouseLeave: () => void
    onFocus: () => void
    onBlur: () => void
  }
  /**
   * Spread these onto the tooltip container so moving the pointer from
   * trigger→tooltip keeps it open (WCAG 1.4.13 hoverable).
   */
  tooltipProps: {
    onMouseEnter: () => void
    onMouseLeave: () => void
  }
}

export function useHoverFocusDisclosure(options: HoverFocusDisclosureOptions = {}): HoverFocusDisclosureResult {
  const { forceOpen = false, onEscDismiss } = options
  const [open, setOpen] = useState(false)
  // Ref to the pending leave timeout — cleared when pointer re-enters
  // either the trigger or the tooltip content.
  const leaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const clearLeave = useCallback(() => {
    if (leaveTimer.current !== null) {
      clearTimeout(leaveTimer.current)
      leaveTimer.current = null
    }
  }, [])

  const scheduleLeave = useCallback(() => {
    clearLeave()
    leaveTimer.current = setTimeout(() => {
      setOpen(false)
    }, LEAVE_DELAY_MS)
  }, [clearLeave])

  const show = useCallback(() => {
    clearLeave()
    setOpen(true)
  }, [clearLeave])

  // Esc handler — capture phase so it intercepts before slide-over's bubble-phase handler.
  // Active when hover-open OR forceOpen (pin mode), so Esc always dismisses the visible tooltip.
  const isVisible = open || forceOpen
  useEffect(() => {
    if (!isVisible) return

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        // Stop propagation so the slide-over provider does NOT also close
        // on this same Esc keypress (layered-Esc, #226 pattern).
        e.stopImmediatePropagation()
        setOpen(false)
        // Notify the caller to clear forceOpen (pin state) if set.
        onEscDismiss?.()
      }
    }

    document.addEventListener('keydown', handleKeyDown, { capture: true })
    return () => document.removeEventListener('keydown', handleKeyDown, { capture: true })
  }, [isVisible, onEscDismiss])

  // Clean up the leave timer on unmount to avoid state updates on unmounted component.
  useEffect(() => {
    return () => { clearLeave() }
  }, [clearLeave])

  return {
    open,
    triggerProps: {
      onMouseEnter: show,
      onMouseLeave: scheduleLeave,
      onFocus: show,
      onBlur: scheduleLeave,
    },
    tooltipProps: {
      onMouseEnter: clearLeave,
      onMouseLeave: scheduleLeave,
    },
  }
}
