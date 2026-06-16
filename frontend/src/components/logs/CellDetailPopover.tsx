/**
 * CellDetailPopover — shared "full value on demand" popover body for Signature
 * and Payload cells (issue #329, part-4 P5.4).
 *
 * ONE shared content contract for both cell types:
 *   1. Full untruncated cell value (first, prominent).
 *   2. Rule metadata rows when available: SID, source type, category.
 *   3. Actions: Copy (full value to clipboard + confirmation) and
 *      "View in Network Logs →" deep-link that navigates to /logs with the
 *      relevant filter pre-applied.
 *
 * Dismiss behavior: callers wire useDismissableDisclosure (#327 primitive) and
 * pass `contentRef` to this component so outside-click detection covers the
 * portal div. This component owns NO dismiss logic — it is a pure renderer.
 *
 * SECURITY (ADR-0029 D3 / issue #58):
 *   All field values are attacker-controlled telemetry. Rendered as React text
 *   nodes ONLY — no dangerouslySetInnerHTML anywhere in this file.
 *
 * DS tokens (ADR-0028 D6): colors via --fw-* tokens; no raw hex.
 *
 * Future seam:
 *   POST-RELEASE: an "Explain this rule" LLM button can be added below the
 *   actions row once ADR-0035 local-LLM integration is built (issue #339).
 *   Leave the actions div with a predictable structure for that insertion.
 *
 * Usage:
 *   const { open, triggerRef, contentRef, triggerProps } = useDismissableDisclosure()
 *   <button ref={triggerRef} {...triggerProps}>…</button>
 *   {open && (
 *     <CellDetailPopover
 *       fullValue={signature}
 *       metadata={[{ label: 'sid', value: '2001219' }, …]}
 *       onNavigate={() => navigate('/logs?…')}
 *       contentRef={contentRef}
 *       triggerRef={triggerRef}
 *       onClose={close}
 *     />
 *   )}
 */

import { useState, useRef, useEffect, type RefObject } from 'react'
import { createPortal } from 'react-dom'
import { useTooltipPosition } from '../ds'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CellDetailMetaRow {
  /** Label column (e.g. "sid", "source", "category"). */
  label: string
  /** Value column — attacker-controlled; rendered as text node. */
  value: string
}

export interface CellDetailPopoverProps {
  /**
   * The full untruncated value to show first in the popover.
   * Attacker-controlled — rendered as a text node.
   */
  fullValue: string
  /**
   * Optional metadata rows shown below the full value.
   * Typically: SID, source type, category for Signature cells.
   * Omit or pass empty array for Payload cells (no rule metadata).
   */
  metadata?: CellDetailMetaRow[]
  /**
   * Called when "View in Network Logs →" is activated.
   * The caller pre-computes the /logs URL with appropriate filters and
   * passes it as a navigate callback so CellDetailPopover stays route-agnostic
   * and trivially testable.
   */
  onNavigate?: () => void
  /**
   * Ref forwarded from useDismissableDisclosure — attached to the popover div
   * so outside-click detection covers it.
   */
  contentRef: RefObject<HTMLElement | null>
  /**
   * Ref to the trigger element — used to position the popover below/above it.
   */
  triggerRef: RefObject<HTMLElement | null>
  /**
   * Called when the popover should close (e.g. after the user activates
   * "View in Network Logs", which navigates away).
   * useDismissableDisclosure's `close` callback passed straight through.
   */
  onClose: () => void
  /**
   * When true, prefer placing the popover ABOVE the trigger (flip below only
   * when there is insufficient room above).  Delegates to useTooltipPosition
   * `preferAbove` option.
   * Default: false (existing below-first behavior — no regression for callers
   * that do not set this flag, e.g. RuleCellTooltip, LogsTable payload cells).
   * Used by the IpPanel "Recent logs" Payload cell (#613).
   */
  preferAbove?: boolean
  /** data-testid forwarded to the root popover div. */
  'data-testid'?: string
}

// ---------------------------------------------------------------------------
// Copy button with confirmation flash
// ---------------------------------------------------------------------------

interface CopyButtonProps {
  value: string
}

/**
 * Inline Copy button. On click: writes `value` to the clipboard and briefly
 * shows a "Copied!" confirmation label before resetting to "Copy".
 * SECURITY: value is attacker-controlled — written to clipboard only, never to DOM.
 */
function CopyButton({ value }: CopyButtonProps) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  function handleCopy() {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      void navigator.clipboard.writeText(value).then(() => {
        setCopied(true)
        if (timerRef.current) clearTimeout(timerRef.current)
        timerRef.current = setTimeout(() => setCopied(false), 1500)
      })
    }
  }

  // Clean up timer on unmount.
  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [])

  return (
    <button
      type="button"
      data-testid="cell-detail-copy"
      onClick={(e) => {
        e.stopPropagation()
        handleCopy()
      }}
      style={{
        background: copied ? 'var(--fw-accent-dim, var(--fw-bg-input))' : 'var(--fw-bg-input)',
        border: '1px solid var(--fw-border)',
        borderRadius: 'var(--fw-r-sm)',
        padding: '3px 8px',
        cursor: 'pointer',
        fontFamily: 'var(--fw-font-ui)',
        fontSize: 11,
        color: copied ? 'var(--fw-accent)' : 'var(--fw-t2)',
        transition: 'color 0.1s, background 0.1s',
        whiteSpace: 'nowrap',
      }}
      aria-live="polite"
      aria-label={copied ? 'Copied to clipboard' : 'Copy full value to clipboard'}
    >
      {/* Confirmation label — aria-live announces this to screen readers */}
      {copied ? 'Copied!' : 'Copy'}
    </button>
  )
}

// ---------------------------------------------------------------------------
// Popover content body (pure presentation, portal-rendered by caller)
// ---------------------------------------------------------------------------

/**
 * CellDetailPopover — popover body positioned relative to triggerRef.
 *
 * Portals to document.body so it escapes any parent stacking context.
 * z-index 120 — above slide-over (110) and its overlay (109).
 */
export function CellDetailPopover({
  fullValue,
  metadata = [],
  onNavigate,
  contentRef,
  triggerRef,
  onClose,
  preferAbove = false,
  'data-testid': testId = 'cell-detail-popover',
}: CellDetailPopoverProps) {
  // #613: preferAbove threads through from the caller so the IpPanel "Recent
  // logs" Payload popover opens ABOVE the trigger row by default, avoiding the
  // "opens in place" visual when the table row is near the viewport bottom.
  // Existing callers that omit preferAbove retain the original below-first behavior.
  const position = useTooltipPosition(triggerRef, true, { preferAbove, contentRef })

  function handleNavigate(e: React.MouseEvent) {
    e.stopPropagation()
    onNavigate?.()
    onClose()
  }

  const popover = (
    <div
      ref={contentRef as React.RefObject<HTMLDivElement>}
      data-testid={testId}
      role="dialog"
      aria-label="Cell detail"
      style={{
        position: 'fixed',
        top: position.top,
        left: position.left,
        zIndex: 120,
        minWidth: 260,
        maxWidth: 420,
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border-l)',
        borderRadius: 'var(--fw-r-md)',
        boxShadow: 'var(--fw-shadow-popup)',
        padding: '10px 12px',
        fontFamily: 'var(--fw-font-ui)',
        fontSize: 12,
        color: 'var(--fw-t1)',
        userSelect: 'text',
      }}
    >
      {/* Section 1: Full untruncated value */}
      <div
        data-testid="cell-detail-full-value"
        style={{
          fontFamily: 'var(--fw-font-mono)',
          fontSize: 12,
          color: 'var(--fw-t1)',
          lineHeight: 1.6,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-all',
          marginBottom: metadata.length > 0 ? 8 : 0,
        }}
      >
        {/* Attacker-controlled — text node ONLY, never dangerouslySetInnerHTML */}
        {fullValue}
      </div>

      {/* Section 2: Metadata rows (SID, source, category) */}
      {metadata.length > 0 && (
        <div
          data-testid="cell-detail-metadata"
          style={{
            borderTop: '1px solid var(--fw-border)',
            paddingTop: 6,
            marginBottom: 8,
            display: 'flex',
            flexDirection: 'column',
            gap: 2,
          }}
        >
          {metadata.map((row) => (
            <div key={row.label} style={{ display: 'flex', gap: 6 }}>
              <span
                style={{
                  fontFamily: 'var(--fw-font-mono)',
                  fontSize: 11,
                  color: 'var(--fw-t3)',
                  minWidth: 52,
                  flexShrink: 0,
                }}
              >
                {row.label}
              </span>
              <span
                data-testid={`cell-detail-meta-${row.label}`}
                style={{
                  fontFamily: 'var(--fw-font-mono)',
                  fontSize: 11,
                  color: 'var(--fw-t2)',
                  wordBreak: 'break-all',
                }}
              >
                {/* Attacker-controlled — text node ONLY */}
                {row.value}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Section 3: Action row — Copy + View in Network Logs */}
      <div
        data-testid="cell-detail-actions"
        style={{
          borderTop: metadata.length > 0 ? undefined : '1px solid var(--fw-border)',
          paddingTop: metadata.length > 0 ? 0 : 8,
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          flexWrap: 'wrap',
        }}
      >
        <CopyButton value={fullValue} />

        {onNavigate != null && (
          <button
            type="button"
            data-testid="cell-detail-view-in-logs"
            onClick={handleNavigate}
            style={{
              background: 'none',
              border: 'none',
              padding: '3px 0',
              cursor: 'pointer',
              fontFamily: 'var(--fw-font-ui)',
              fontSize: 11,
              color: 'var(--fw-blue)',
              textDecoration: 'underline',
              whiteSpace: 'nowrap',
            }}
          >
            View in Network Logs →
          </button>
        )}
      </div>
    </div>
  )

  return createPortal(popover, document.body)
}
