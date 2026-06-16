/**
 * PayloadCellTooltip — payload-cell popover (#284, upgraded in #329).
 *
 * Shows the FULL payload text in a CellDetailPopover on click, but
 * ONLY when the cell content is actually truncated (overflow-ellipsis). When
 * the content fits without truncation the component renders bare text — no
 * popover noise.
 *
 * Post-#329 grammar (replaces peek-then-pin with dismiss primitive):
 *   - Click/Enter on a truncated cell: opens CellDetailPopover via
 *     useDismissableDisclosure (#327) — outside-click + Esc + single-open.
 *   - The popover shows: (1) full payload text, (2) Copy button,
 *     (3) "View in Network Logs →" deep-link (when onNavigate is provided).
 *   - No metadata rows for payload cells (payload has no rule metadata).
 *
 * DS rule (#284 issue / design-system guideline):
 *   cell context = anchored popover (CellDetailPopover, #246);
 *   modal = focused tasks only.
 *
 * SECURITY (ADR-0029 D3):
 *   Payload is attacker-controlled data (network packet bodies, HTTP fields).
 *   Rendered STRICTLY as React text nodes. No dangerouslySetInnerHTML anywhere
 *   in this file. This prevents XSS / DOM-injection attacks identical to the
 *   prior Leaflet bindPopup innerHTML bug.
 *
 * Truncation detection:
 *   A ResizeObserver watches the inner <span>. When scrollWidth > offsetWidth
 *   the content is truncated and popover is enabled. This avoids adding a
 *   popover to cells that already fit — removing popover noise.
 *
 * Ref strategy:
 *   useDismissableDisclosure provides triggerRef (HTMLElement | null). We assign
 *   it directly to the inner <span> so truncation detection, outside-click, and
 *   popover positioning all share the same DOM node. No double-ref mutation needed.
 */

import { useState, useEffect } from 'react'
import { CellDetailPopover } from './CellDetailPopover'
import { useDismissableDisclosure } from '../ds'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PayloadCellTooltipProps {
  /** Full payload string. Attacker-controlled — rendered as text nodes only. */
  payload: string
  /** Extra inline styles forwarded to the outer wrapper span. */
  style?: React.CSSProperties
  /** data-testid forwarded to the outer wrapper. */
  'data-testid'?: string
  /**
   * Called when "View in Network Logs →" is activated (#329 deep-link).
   * Omit on surfaces that don't support navigation (e.g. dashboard panes).
   */
  onNavigate?: () => void
  /**
   * When true, the CellDetailPopover opens ABOVE the trigger by default
   * (flipping below only when near the viewport top).
   * Delegates to CellDetailPopover.preferAbove → useTooltipPosition.preferAbove.
   * Default: false (existing below-first behavior — backward compatible).
   * Used by the IpPanel "Recent logs" Payload cell (#613).
   */
  preferAbove?: boolean
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function PayloadCellTooltip({
  payload,
  style,
  'data-testid': testId,
  onNavigate,
  preferAbove = false,
}: PayloadCellTooltipProps) {
  // Whether the text is currently overflowing its container (truncated).
  const [truncated, setTruncated] = useState(false)

  // useDismissableDisclosure provides triggerRef which we attach to the inner span.
  // This single ref serves truncation detection, outside-click, and popover positioning.
  const { open, triggerRef, contentRef, triggerProps, close } = useDismissableDisclosure()

  // Detect truncation via ResizeObserver. Runs on mount and on any layout change.
  // Uses triggerRef.current (the inner span) directly — no separate innerRef.
  useEffect(() => {
    const el = triggerRef.current
    if (!el) return

    function check() {
      if (!el) return
      setTruncated(el.scrollWidth > el.offsetWidth)
    }

    check()

    // Watch for font-load / container-resize changes that affect truncation.
    const ro = new ResizeObserver(check)
    ro.observe(el)
    return () => ro.disconnect()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [payload])

  // Dash placeholder — no popover needed.
  if (payload === '—') {
    return (
      <span
        data-testid={testId}
        style={{ color: 'var(--fw-t3)', ...style }}
      >
        —
      </span>
    )
  }

  // When NOT truncated: plain text span, no popover overhead.
  // We still use triggerRef so ResizeObserver can monitor the element.
  if (!truncated) {
    return (
      <span
        ref={triggerRef as React.RefObject<HTMLSpanElement>}
        data-testid={testId}
        data-truncated="false"
        style={{
          fontFamily: 'var(--fw-font-mono)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          display: 'block',
          ...style,
        }}
      >
        {/* Attacker-controlled — text node */}
        {payload}
      </span>
    )
  }

  // Truncated: show CellDetailPopover on click (useDismissableDisclosure).
  return (
    <span
      data-testid={testId}
      data-truncated="true"
      style={{ display: 'block', overflow: 'hidden' }}
    >
      <span
        ref={triggerRef as React.RefObject<HTMLSpanElement>}
        data-testid="payload-cell-tooltip-trigger"
        {...triggerProps}
        style={{
          fontFamily: 'var(--fw-font-mono)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          display: 'block',
          cursor: 'pointer',
          ...style,
        }}
      >
        {/* Attacker-controlled — text node */}
        {payload}
      </span>

      {/* Full-value popover (#329): outside-click + Esc via useDismissableDisclosure.
          preferAbove threads from prop → CellDetailPopover → useTooltipPosition (#613). */}
      {open && (
        <CellDetailPopover
          fullValue={payload}
          metadata={[]}
          onNavigate={onNavigate}
          contentRef={contentRef}
          triggerRef={triggerRef}
          onClose={close}
          preferAbove={preferAbove}
          data-testid="payload-cell-detail-popover"
        />
      )}
    </span>
  )
}
