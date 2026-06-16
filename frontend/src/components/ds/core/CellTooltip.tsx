/**
 * CellTooltip — WCAG 2.2 SC 1.4.13 compliant tooltip primitive (DS core, #246).
 *
 * https://www.w3.org/TR/WCAG22/#content-on-hover-or-focus
 *
 * Guarantees:
 *   - Dismissible:  Esc closes the tooltip; the slide-over does NOT also close
 *                   (layered-Esc, #226 pattern — capture phase).
 *   - Hoverable:    pointer can move from the trigger onto the tooltip content
 *                   without the content vanishing (80ms leave delay).
 *   - Persistent:   content stays until hover/focus ends or Esc dismisses it.
 *                   No auto-timeout.
 *   - Keyboard parity: trigger is focusable (tabIndex=0); focus shows the same
 *                   content as hover. Hover is never the ONLY path.
 *
 * Accessibility:
 *   - role="tooltip" + aria-describedby wired between trigger span and content.
 *   - trigger renders as an inline span that accepts keyboard focus.
 *
 * Rendering:
 *   - Portal to document.body to escape any parent stacking context.
 *   - Viewport-aware positioning: prefers below the trigger; flips above when
 *     the bottom would be clipped.
 *   - z-index 120 — above slide-over panel (110) and its overlay (109),
 *     leaving room for future layers (toasts 130, command palette 140).
 *
 * peek-then-pin (#283):
 *   Callers can pass forceOpen=true to keep the tooltip visible past hover/focus
 *   (the "pinned" state). When pinned, text selection is re-enabled so the user
 *   can copy description text or click the ADR-0034 action hint. Esc still
 *   dismisses the tooltip first (layered-Esc), leaving the caller responsible
 *   for clearing forceOpen when the Esc callback fires.
 *
 * Usage:
 *   <CellTooltip content={<span>Detailed breakdown…</span>}>
 *     <span>Cell value</span>
 *   </CellTooltip>
 */

import { useRef, useId, type ReactNode, type CSSProperties } from 'react'
import { createPortal } from 'react-dom'
import { useHoverFocusDisclosure } from './useHoverFocusDisclosure'
import { useTooltipPosition } from './useTooltipPosition'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CellTooltipProps {
  /**
   * The rich content rendered inside the tooltip bubble.
   * Keep it small (one to four lines) — this is a hover-detail panel,
   * not a full drawer.
   */
  content: ReactNode
  /**
   * The wrapped trigger element — whatever the user hovers or focuses to
   * reveal the tooltip. Rendered inline so it does not break table-cell layout.
   */
  children: ReactNode
  /**
   * Forwarded to the trigger span so callers can testid / aria-label the trigger.
   */
  'data-testid'?: string
  /**
   * When true, keeps the tooltip visible regardless of hover/focus state
   * (peek-then-pin grammar, #283). Callers are responsible for clearing this
   * flag when the user dismisses via Esc (onEscDismiss callback) or a secondary
   * click on the trigger.
   */
  forceOpen?: boolean
  /**
   * Called when the tooltip is dismissed via Esc while forceOpen=true. Lets the
   * parent clear the pin state so the tooltip fully closes.
   */
  onEscDismiss?: () => void
  /**
   * Optional inline style applied to the trigger span in addition to the base
   * styles.  Use this to override layout-participation properties (e.g.
   * `{ flex: 1, minWidth: 0 }`) when the trigger is a flex child that must
   * grow to fill its container (issue #355, P3a).
   * All other callers omit this prop — no change to their rendered output.
   */
  triggerStyle?: CSSProperties
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function CellTooltip({
  content,
  children,
  'data-testid': testId,
  forceOpen = false,
  onEscDismiss,
  triggerStyle,
}: CellTooltipProps) {
  const id = useId()
  const tooltipId = `cell-tooltip-${id}`
  const triggerRef = useRef<HTMLSpanElement>(null)

  const { open: hoverOpen, triggerProps, tooltipProps } = useHoverFocusDisclosure({ onEscDismiss, forceOpen })
  // The tooltip is visible when hover/focus opens it OR when the caller pins it.
  const open = hoverOpen || forceOpen
  const position = useTooltipPosition(triggerRef, open)

  return (
    <>
      {/* Trigger: inline span, keyboard-focusable */}
      <span
        ref={triggerRef}
        tabIndex={0}
        aria-describedby={open ? tooltipId : undefined}
        data-testid={testId ?? 'cell-tooltip-trigger'}
        style={{
          display: 'inline',
          cursor: 'default',
          outline: 'none',
          // Show a subtle focus ring via box-shadow (matches DS focus convention).
          borderRadius: 2,
          // Caller override — e.g. flex:1 when the trigger is a flex child (issue #355, P3a).
          ...triggerStyle,
        }}
        {...triggerProps}
        onFocus={(e) => {
          triggerProps.onFocus()
          // Allow the native focus outline via CSS :focus-visible; we only
          // suppress the default outline on the span itself.
          e.currentTarget.style.boxShadow = '0 0 0 2px var(--fw-blue)'
        }}
        onBlur={(e) => {
          triggerProps.onBlur()
          e.currentTarget.style.boxShadow = ''
        }}
      >
        {children}
      </span>

      {/* Portal tooltip — rendered at document.body to escape stacking contexts */}
      {open &&
        createPortal(
          <div
            id={tooltipId}
            role="tooltip"
            data-testid="cell-tooltip-content"
            data-pinned={forceOpen ? 'true' : undefined}
            style={{
              position: 'fixed',
              top: position.top,
              left: position.left,
              zIndex: 120,
              maxWidth: 320,
              background: 'var(--fw-bg-card)',
              border: '1px solid var(--fw-border-l)',
              borderRadius: 'var(--fw-r-md)',
              boxShadow: 'var(--fw-shadow-popup)',
              padding: '8px 10px',
              fontSize: 12,
              fontFamily: 'var(--fw-font-ui)',
              color: 'var(--fw-t1)',
              lineHeight: 1.5,
              // When pinned, allow text selection for copy. Otherwise prevent
              // text selection from flickering the tooltip closed (peek mode).
              userSelect: forceOpen ? 'text' : 'none',
              // Tooltip itself must not be pointer-events:none — WCAG 1.4.13 hoverable
              // requires the pointer to land on it without dismissing it.
              pointerEvents: 'auto',
            }}
            {...tooltipProps}
          >
            {content}
          </div>,
          document.body,
        )}
    </>
  )
}
