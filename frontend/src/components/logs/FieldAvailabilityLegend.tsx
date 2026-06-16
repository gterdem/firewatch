/**
 * FieldAvailabilityLegend — ML-5 (#433) EARS-3.
 *
 * Explains WHY certain columns show "—" in the Network Logs table. This is
 * an honesty affordance: "—" is not a bug — it means the source plugin does
 * not produce that field by design.
 *
 * Example: Azure WAF operates at L7 (HTTP). It does not record transport-layer
 * fields (Protocol, Destination IP) because those are not part of its telemetry
 * model. Suricata operates at L3-L7 and does record them.
 *
 * Design (per Maintainer's preference): tooltip/legend, NOT a nested scrollbar.
 * Renders as a small "?" help button that opens a concise legend on hover/focus.
 * The legend is non-nagging — positioned near the column header area.
 *
 * Source-agnostic: the field notes are keyed by column name, not source name.
 * Each entry lists which source types produce it and which don't. Adding a new
 * source that also omits protocol/destination_ip does not require changing this
 * component — it is driven by fieldAvailability.ts (the static notes module).
 *
 * #666: tooltip now portals to document.body via createPortal + useTooltipPosition
 * so it escapes the table's overflow:auto container (no clipping). The existing
 * hover/focus/Esc behaviour is preserved via useHoverFocusDisclosure.
 * TODO(#289): migrate to @radix-ui/react-popover when that sweep lands.
 *
 * SECURITY (ADR-0029 D3): all text is static; no attacker-controlled values.
 */

import { useRef } from 'react'
import { createPortal } from 'react-dom'
import { FIELD_NOTES } from '../../lib/fieldAvailability'
import { useHoverFocusDisclosure, useTooltipPosition } from '../ds'

interface FieldAvailabilityLegendProps {
  /** The column label to look up a note for. */
  column: string
}

/**
 * Renders a small "?" affordance next to a column header when that column
 * may show "—" due to source field availability (not a data error).
 */
export function FieldAvailabilityLegend({ column }: FieldAvailabilityLegendProps) {
  const note = FIELD_NOTES[column]
  if (!note) return null

  return (
    <FieldAvailabilityTooltip note={note} />
  )
}

/**
 * Inline tooltip helper — a small "?" button that reveals an explanatory note
 * on hover/focus. Portals the tooltip bubble to document.body so it escapes
 * the table's overflow:auto wrapper (no clipping, #666).
 *
 * Uses useHoverFocusDisclosure for WCAG 1.4.13 compliance:
 *   - Dismissible: Esc closes the tooltip without moving the pointer.
 *   - Hoverable: leave-delay lets the pointer travel from trigger to tooltip.
 *   - Keyboard parity: focus/blur open/close identically to pointer hover.
 *
 * SECURITY (ADR-0029 D3): `note` is a static string constant from fieldAvailability.ts,
 * never interpolated from attacker-controlled data.
 */
function FieldAvailabilityTooltip({ note }: { note: string }) {
  const triggerRef = useRef<HTMLButtonElement | null>(null)
  const tooltipRef = useRef<HTMLDivElement | null>(null)

  const { open, triggerProps, tooltipProps } = useHoverFocusDisclosure()

  // Position the portaled tooltip anchored to the trigger button rect.
  // preferAbove=true so it opens above the column header (avoids overlapping data rows).
  const position = useTooltipPosition(
    triggerRef as React.RefObject<HTMLElement | null>,
    open,
    { preferAbove: true, contentRef: tooltipRef as React.RefObject<HTMLElement | null> },
  )

  const tooltip = open
    ? createPortal(
        <div
          ref={tooltipRef}
          role="tooltip"
          data-testid="field-availability-tooltip"
          onMouseEnter={tooltipProps.onMouseEnter}
          onMouseLeave={tooltipProps.onMouseLeave}
          style={{
            position: 'fixed',
            top: position.top,
            left: position.left,
            zIndex: 200,
            background: 'var(--fw-bg-card)',
            border: '1px solid var(--fw-border)',
            borderRadius: 6,
            padding: '6px 10px',
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t2)',
            whiteSpace: 'normal',
            width: 240,
            boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
            lineHeight: 1.4,
            fontWeight: 'normal',
            textTransform: 'none',
            letterSpacing: 'normal',
            fontFamily: 'var(--fw-font-ui)',
            pointerEvents: 'auto',
          }}
        >
          {/* Static text from fieldAvailability.ts — not attacker-controlled */}
          {note}
        </div>,
        document.body,
      )
    : null

  return (
    <span
      style={{ position: 'relative', display: 'inline-block', marginLeft: 3, verticalAlign: 'middle' }}
    >
      <button
        ref={triggerRef}
        type="button"
        aria-label="Why does this column show dashes?"
        aria-describedby={open ? 'field-availability-tooltip' : undefined}
        data-testid="field-availability-hint"
        {...triggerProps}
        style={{
          background: 'none',
          border: '1px solid var(--fw-border)',
          borderRadius: '50%',
          width: 13,
          height: 13,
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          cursor: 'help',
          fontSize: 9,
          color: 'var(--fw-t3)',
          padding: 0,
          lineHeight: 1,
          flexShrink: 0,
        }}
      >
        ?
      </button>
      {tooltip}
    </span>
  )
}
