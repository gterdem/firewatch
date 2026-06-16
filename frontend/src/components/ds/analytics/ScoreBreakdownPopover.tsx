/**
 * ScoreBreakdownPopover — "why this score" popover for ScoreBadge (ADR-0036 D3, issue #210).
 *
 * Renders the top 3 contributing factors from `score_breakdown` (label + points),
 * with a "+N more" overflow line. The AI-boost line carries the AI provenance chip
 * (ADR-0035). Shows "capped at 100" when a cap item is present. Shows "[no AI]" when
 * no ai_boost factor appears in the breakdown.
 *
 * PORTAL FIX (issue #266 / part-3 P12.2):
 *   The popover previously rendered `position:absolute; bottom:calc(100%+6px)` inside
 *   the badge element (zIndex 50). Inside the slide-over the badge sits at the top of
 *   an `overflow:hidden` panel — the popover opened upward into the header and was
 *   clipped by the panel's stacking context.
 *
 *   Fix: render through `document.body` portal at z-120 (above the panel's 110) using
 *   `useTooltipPosition` (preferAbove=true) — prefers above the badge, flips below
 *   when near the top of the viewport (insufficient room above). This is the same
 *   portal mechanism used by CellTooltip (#246).
 *
 * Design rules:
 *   - Self-contained: receives `items` (ScoreBreakdownItem[]), `open` / `onClose`, and
 *     a `triggerRef` pointing to the badge's "?" button for portal positioning.
 *   - Hover-safe: the popover itself is hoverable — pointer entering the popover does
 *     not close it (WCAG 1.4.13 hover rules).
 *   - Keyboard: Esc is handled exclusively by useDismissableDisclosure in ScoreBadge
 *     (capture-phase, stopImmediatePropagation, focus-return). This component does NOT
 *     register its own Esc listener — doing so would race with the hook and break
 *     focus restoration (issue #356).
 *   - Empty/absent items → renders nothing (caller is responsible for not rendering the
 *     trigger when breakdown is empty).
 *
 * SECURITY (ADR-0029 D3):
 *   - All `label` values are rendered as text nodes — never via innerHTML.
 *   - `points` is a number — React renders it as a text node automatically.
 *   - `factor` is only used for identity logic (equality checks), never rendered.
 *
 * Accessibility:
 *   - aria-live="polite" so screen readers announce the content on open.
 *   - role="dialog" is NOT used here (no focus trap) — the popover is a
 *     non-modal disclosure; role="tooltip" is also removed because the popover
 *     is click-opened, not hover-opened (ARIA tooltip semantics do not fit).
 *   - All labels rendered as text nodes only (ADR-0029 D3).
 *
 * Styling:
 *   - Uses --fw-* design tokens only (no raw hex — ADR-0028 D6).
 *   - No deep DS imports (the adherence lint disallows deep paths).
 */

import { type RefObject } from 'react'
import { createPortal } from 'react-dom'
import type { ScoreBreakdownItem } from '../../../api/types'
import { ProvenanceChip } from './ProvenanceChip'
import { useTooltipPosition } from '../core/useTooltipPosition'

// Re-export the registry integration note:
// ScoreBreakdownPopover is a CONTROLLED component — open/onClose are owned by
// ScoreBadge which uses useDismissableDisclosure. The contentRef prop wires the
// portal div into the outside-click detection of that hook (#327).

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum contributors shown before "+N more" overflow. */
const TOP_N = 3

/** Factor key that represents the AI boost contribution. */
const AI_BOOST_FACTOR = 'ai_boost'

/** Factor key that represents the 100-cap deduction. */
const CAP_FACTOR = 'cap'

/**
 * z-index for the portal popover — above slide-over panel (110) and its
 * overlay (109), same layer as CellTooltip (#246).
 */
const PORTAL_Z_INDEX = 120

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Format a points value as a signed string: "+30" / "-10".
 * Zero renders as "+0" to be explicit.
 */
function formatPoints(points: number): string {
  return points >= 0 ? `+${points}` : String(points)
}

/**
 * Pick the foreground color token for a points value.
 * Positive: green; negative (cap): muted/t3; zero: muted.
 */
function pointsColorToken(points: number): string {
  if (points > 0) return 'var(--fw-green)'
  if (points < 0) return 'var(--fw-t3)'
  return 'var(--fw-t2)'
}

// ---------------------------------------------------------------------------
// ScoreBreakdownPopover
// ---------------------------------------------------------------------------

export interface ScoreBreakdownPopoverProps {
  /** Breakdown items to display. Caller should not render the trigger when empty. */
  items: ScoreBreakdownItem[]
  /** Whether the popover is currently visible. */
  open: boolean
  /** Callback to close the popover (Esc key, pointer-leave). */
  onClose: () => void
  /** Optional id for the popover element (used for aria-describedby on the trigger). */
  id?: string
  /**
   * Ref to the "?" trigger button inside ScoreBadge. Used by useTooltipPosition to
   * compute the portal's fixed-position coordinates so the popover is visible even
   * inside overflow:hidden containers such as the slide-over panel (issue #266).
   *
   * When omitted (e.g. standalone tests that render ScoreBreakdownPopover directly),
   * the portal still renders at (0,0) — functional but unpositioned; callers that
   * control placement always pass this ref.
   */
  triggerRef?: RefObject<HTMLElement | null>
  /**
   * Ref forwarded to the portal div — wires the popover into useDismissableDisclosure's
   * outside-click detection in ScoreBadge (#327). When provided, the outside-click
   * handler correctly detects clicks INSIDE the portal as "inside content" and does
   * not dismiss the popover.
   */
  contentRef?: RefObject<HTMLElement | null>
}

export function ScoreBreakdownPopover({
  items,
  open,
  // onClose is kept in the interface for backward compatibility (callers pass
  // it for future use), but Esc + focus-return is exclusively owned by
  // useDismissableDisclosure in ScoreBadge (issue #356 — the duplicate handler
  // raced with the hook and broke focus restoration).
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  onClose: _onClose,
  id,
  triggerRef,
  contentRef,
}: ScoreBreakdownPopoverProps) {
  // Prefer above the badge; flip below when near the top of the viewport.
  // triggerRef may be undefined (standalone usage/tests) — hook accepts null ref.
  // contentRef is forwarded to the hook so it can measure the ACTUAL rendered height
  // instead of the fixed TOOLTIP_ESTIMATED_HEIGHT constant (issue #369 fix).
  const nullRef: RefObject<HTMLElement | null> = { current: null }
  const pos = useTooltipPosition(triggerRef ?? nullRef, open, {
    preferAbove: true,
    contentRef,
  })

  if (!open || items.length === 0) return null

  // Separate the cap item from the regular contributors.
  const capItem = items.find((i) => i.factor === CAP_FACTOR)
  const contributors = items.filter((i) => i.factor !== CAP_FACTOR)

  // Top N visible contributors.
  const visible = contributors.slice(0, TOP_N)
  const overflow = contributors.length - visible.length

  // Check if any contributor is an AI boost.
  const hasAiBoost = contributors.some((i) => i.factor === AI_BOOST_FACTOR)

  const popoverNode = (
    <div
      ref={contentRef as RefObject<HTMLDivElement> | undefined}
      id={id}
      aria-live="polite"
      data-testid="score-breakdown-popover"
      style={{
        position: 'fixed',
        top: pos.top,
        left: pos.left,
        zIndex: PORTAL_Z_INDEX,
        minWidth: 220,
        maxWidth: 300,
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border)',
        borderRadius: 'var(--fw-r-md)',
        boxShadow: '0 4px 16px rgba(0,0,0,0.18)',
        padding: '10px 12px',
        fontSize: 'var(--fw-fs-xs)',
        fontFamily: 'var(--fw-font-ui)',
        color: 'var(--fw-t1)',
      }}
    >
      {/* Header */}
      <div
        style={{
          fontWeight: 'var(--fw-fw-semibold)',
          marginBottom: 8,
          color: 'var(--fw-t2)',
          letterSpacing: 'var(--fw-ls-tight)',
          fontSize: 'var(--fw-fs-2xs)',
          textTransform: 'uppercase',
        }}
      >
        Score contributors
      </div>

      {/* Contributor rows */}
      {visible.map((item) => {
        const isAiBoost = item.factor === AI_BOOST_FACTOR
        return (
          <div
            key={item.factor}
            data-testid="breakdown-row"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              paddingBottom: 4,
              borderBottom: '1px solid var(--fw-border)',
              marginBottom: 4,
            }}
          >
            {/* Points (text node — never innerHTML) */}
            <span
              style={{
                fontFamily: 'var(--fw-font-mono)',
                fontWeight: 'var(--fw-fw-bold)',
                color: pointsColorToken(item.points),
                minWidth: 36,
                textAlign: 'right',
              }}
              aria-label={`${formatPoints(item.points)} points`}
            >
              {formatPoints(item.points)}
            </span>

            {/* Label (attacker-controlled — rendered as text node only) */}
            <span style={{ flex: 1, color: 'var(--fw-t1)' }}>
              {String(item.label)}
            </span>

            {/* AI chip on the ai_boost line (ADR-0035) */}
            {isAiBoost && (
              <ProvenanceChip derivation="ai" />
            )}
          </div>
        )
      })}

      {/* "+N more" overflow */}
      {overflow > 0 && (
        <div
          data-testid="breakdown-overflow"
          style={{ color: 'var(--fw-t3)', fontSize: 'var(--fw-fs-2xs)', marginBottom: 4 }}
        >
          +{overflow} more factor{overflow > 1 ? 's' : ''}
        </div>
      )}

      {/* Cap notice — shown as a separate line with signed points */}
      {capItem !== undefined && (
        <div
          data-testid="breakdown-cap"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            color: 'var(--fw-t3)',
            fontSize: 'var(--fw-fs-2xs)',
            marginTop: 4,
            borderTop: '1px solid var(--fw-border)',
            paddingTop: 4,
          }}
        >
          <span
            style={{
              fontFamily: 'var(--fw-font-mono)',
              fontWeight: 'var(--fw-fw-bold)',
              color: pointsColorToken(capItem.points),
              minWidth: 36,
              textAlign: 'right',
            }}
          >
            {formatPoints(capItem.points)}
          </span>
          <span>{String(capItem.label)}</span>
        </div>
      )}

      {/* "[no AI]" when AI boost is absent (ADR-0035 / issue #210 spec) */}
      {!hasAiBoost && (
        <div
          data-testid="breakdown-no-ai"
          style={{
            marginTop: 4,
            color: 'var(--fw-t3)',
            fontSize: 'var(--fw-fs-2xs)',
          }}
        >
          [no AI]
        </div>
      )}
    </div>
  )

  // Portal to document.body — escapes any overflow:hidden stacking context,
  // including the slide-over panel (overflow:hidden, z-index:110).
  return createPortal(popoverNode, document.body)
}
