/**
 * useDismissableDisclosure — shared click-triggered popover/disclosure primitive
 * for WCAG 2.2 SC 1.4.13 compliant disclosures (issue #327).
 *
 * Guarantees:
 *   - Outside-click dismiss: clicking anywhere outside both the trigger and the
 *     popover content closes the disclosure (pointerdown, capture phase).
 *   - Esc dismiss (WCAG 1.4.13 dismissable): Esc closes the disclosure with
 *     focus returned to the trigger; stopImmediatePropagation prevents the
 *     event from reaching the slide-over provider's Esc handler (layered-Esc, #226).
 *   - Single-open invariant: opening any disclosure that uses this hook closes
 *     the previously open one — the page NEVER renders two open click-disclosures
 *     simultaneously (module-level registry).
 *   - Hover-open mode (optional, for badge-style triggers like kpi-ai-status):
 *     when `allowHover=true`, pointer entering the trigger also opens the
 *     disclosure; an 80 ms leave-delay keeps it open while the pointer travels
 *     from the trigger to the popover content (WCAG 1.4.13 hoverable/persistent).
 *
 * Design note: hover-open is OPT-IN via `allowHover`. Cell-tooltip flows
 * (RuleCellTooltip, PayloadCellTooltip) continue to use useHoverFocusDisclosure
 * for hover-primary semantics. This hook is for click-primary disclosures that
 * want to ADD hover convenience on top.
 *
 * Precedent: Elastic EUI DataGrid cell popovers; Datadog DRUIDS Popover.
 * WCAG 1.4.13: https://www.w3.org/TR/WCAG22/#content-on-hover-or-focus
 *
 * Usage:
 *   const { open, triggerRef, contentRef, triggerProps, contentProps, close } =
 *     useDismissableDisclosure()
 *
 *   <button ref={triggerRef} {...triggerProps}>Open</button>
 *   {open && <div ref={contentRef} {...contentProps}>Content</div>}
 */

import { useState, useEffect, useRef, useCallback, useId } from 'react'

// ---------------------------------------------------------------------------
// Module-level registry — single-open invariant (#327)
// ---------------------------------------------------------------------------

/**
 * Registry maps stable disclosure id → close callback.
 * When any disclosure opens, it notifies all OTHER registered disclosures to
 * close — enforcing the single-open-at-a-time invariant without a Context
 * provider (keeps usage ergonomics simple).
 */
const disclosureRegistry = new Map<string, () => void>()

function closeAllExcept(excludeId: string): void {
  disclosureRegistry.forEach((closeFn, id) => {
    if (id !== excludeId) closeFn()
  })
}

// How long (ms) to wait before closing after the pointer leaves the trigger or
// popover content (hover-open mode). Gives the pointer time to travel to the
// popover content without the content vanishing (WCAG 1.4.13 hoverable).
const HOVER_LEAVE_DELAY_MS = 80

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DismissableDisclosureOptions {
  /**
   * When true, pointer entering the trigger also opens the disclosure
   * (hover-open, WCAG 1.4.13 hoverable). Pointer can travel from trigger to
   * popover content without the popover closing.
   * Default: false (click-only).
   */
  allowHover?: boolean
  /**
   * Ref to the element that should receive focus when the disclosure is closed
   * via Esc. Defaults to `triggerRef` when not provided.
   */
  returnFocusRef?: React.RefObject<HTMLElement | null>
}

export interface DismissableDisclosureResult {
  /** Whether the disclosure is currently open. */
  open: boolean
  /** Attach this ref to the trigger element (button / span). */
  triggerRef: React.RefObject<HTMLElement | null>
  /** Attach this ref to the popover content element. */
  contentRef: React.RefObject<HTMLElement | null>
  /**
   * Spread these onto the trigger element.
   * Includes onClick (toggle), onKeyDown (Enter/Space), and optional
   * hover handlers when `allowHover` is true.
   */
  triggerProps: {
    onClick: (e: React.MouseEvent) => void
    onKeyDown: (e: React.KeyboardEvent) => void
    onMouseEnter?: () => void
    onMouseLeave?: () => void
  }
  /**
   * Spread these onto the popover content element.
   * Includes hover handlers when `allowHover` is true (WCAG 1.4.13 hoverable).
   */
  contentProps: {
    onMouseEnter?: () => void
    onMouseLeave?: () => void
  }
  /** Imperatively close the disclosure (e.g. from a dismiss button inside). */
  close: () => void
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useDismissableDisclosure(
  options: DismissableDisclosureOptions = {},
): DismissableDisclosureResult {
  const { allowHover = false, returnFocusRef } = options

  const [isOpen, setIsOpen] = useState(false)
  // Ref mirrors isOpen so toggle() can read the current value synchronously
  // in the event-handler path without capturing stale state. This avoids
  // calling closeAllExcept() inside the setIsOpen updater (which React runs
  // during the render phase) — that was the setState-in-render bug (#359).
  const isOpenRef = useRef(false)
  const triggerRef = useRef<HTMLElement | null>(null)
  const contentRef = useRef<HTMLElement | null>(null)
  const leaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Stable id for the registry — useId returns a string that is stable for
  // the lifetime of this hook instance.
  const id = useId()

  // Keep isOpenRef in sync with isOpen state so event handlers can read the
  // current open state synchronously without stale-closure issues.
  useEffect(() => {
    isOpenRef.current = isOpen
  }, [isOpen])

  // ---------------------------------------------------------------------------
  // Close helper — stable ref so registry entry never changes.
  // ---------------------------------------------------------------------------

  const close = useCallback(() => {
    setIsOpen(false)
  }, [])

  // ---------------------------------------------------------------------------
  // Registry: register this disclosure on mount, deregister on unmount.
  // ---------------------------------------------------------------------------

  useEffect(() => {
    disclosureRegistry.set(id, close)
    return () => {
      disclosureRegistry.delete(id)
    }
  }, [id, close])

  // ---------------------------------------------------------------------------
  // Open helper — enforces single-open invariant before opening.
  // ---------------------------------------------------------------------------

  const openDisclosure = useCallback(() => {
    closeAllExcept(id)
    setIsOpen(true)
  }, [id])

  const toggle = useCallback(() => {
    // Enforce single-open in the event-handler path (NOT inside the setState
    // updater). The updater runs during React's render phase; calling another
    // component's setState there triggers "Cannot update X while rendering Y"
    // (#359). isOpenRef.current is synchronously current at handler call time.
    if (!isOpenRef.current) {
      closeAllExcept(id)
    }
    setIsOpen((prev) => !prev)
  }, [id])

  // ---------------------------------------------------------------------------
  // Outside-click dismiss — pointerdown, capture phase so it fires before
  // any bubble-phase handlers inside the popover.
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (!isOpen) return

    function handlePointerDown(e: PointerEvent) {
      const target = e.target as Node | null
      if (!target) return
      const insideTrigger = triggerRef.current?.contains(target) ?? false
      const insideContent = contentRef.current?.contains(target) ?? false
      if (!insideTrigger && !insideContent) {
        close()
      }
    }

    document.addEventListener('pointerdown', handlePointerDown, { capture: true })
    return () => document.removeEventListener('pointerdown', handlePointerDown, { capture: true })
  }, [isOpen, close])

  // ---------------------------------------------------------------------------
  // Esc dismiss — capture phase, layered-Esc contract (#226).
  // stopImmediatePropagation so the slide-over provider does NOT also fire.
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (!isOpen) return

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.stopImmediatePropagation()
        close()
        // Return focus to the trigger (WCAG: focus restoration after dismiss).
        const focusTarget = returnFocusRef?.current ?? triggerRef.current
        focusTarget?.focus()
      }
    }

    document.addEventListener('keydown', handleKeyDown, { capture: true })
    return () => document.removeEventListener('keydown', handleKeyDown, { capture: true })
  }, [isOpen, close, returnFocusRef])

  // ---------------------------------------------------------------------------
  // Hover-open helpers (allowHover=true only — WCAG 1.4.13 hoverable/persistent)
  // ---------------------------------------------------------------------------

  const clearLeave = useCallback(() => {
    if (leaveTimer.current !== null) {
      clearTimeout(leaveTimer.current)
      leaveTimer.current = null
    }
  }, [])

  const scheduleLeave = useCallback(() => {
    clearLeave()
    leaveTimer.current = setTimeout(close, HOVER_LEAVE_DELAY_MS)
  }, [clearLeave, close])

  // Clean up the leave timer on unmount to prevent state updates on unmounted
  // components.
  useEffect(() => {
    return () => {
      if (leaveTimer.current !== null) {
        clearTimeout(leaveTimer.current)
      }
    }
  }, [])

  // ---------------------------------------------------------------------------
  // Trigger event handlers
  // ---------------------------------------------------------------------------

  const handleClick = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation()
      toggle()
    },
    [toggle],
  )

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        e.stopPropagation()
        toggle()
      }
      // Esc: handled via the document capture listener above; do not duplicate
      // here to avoid a double-close race condition.
    },
    [toggle],
  )

  // ---------------------------------------------------------------------------
  // Build result props (conditional hover handlers)
  // ---------------------------------------------------------------------------

  const hoverTriggerProps = allowHover
    ? {
        onMouseEnter: () => { clearLeave(); openDisclosure() },
        onMouseLeave: scheduleLeave,
      }
    : {}

  const hoverContentProps = allowHover
    ? {
        onMouseEnter: clearLeave,
        onMouseLeave: scheduleLeave,
      }
    : {}

  return {
    open: isOpen,
    triggerRef: triggerRef as React.RefObject<HTMLElement | null>,
    contentRef: contentRef as React.RefObject<HTMLElement | null>,
    triggerProps: {
      onClick: handleClick,
      onKeyDown: handleKeyDown,
      ...hoverTriggerProps,
    },
    contentProps: hoverContentProps,
    close,
  }
}
