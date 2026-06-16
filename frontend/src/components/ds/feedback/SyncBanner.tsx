/**
 * SyncBanner — full-width fixed notification banner that slides in below the
 * AppHeader when new events are ingested.
 *
 * Replaces the top-right toast (issue sync-banner task):
 *   - Spans the full viewport width so the right-side entity slide-over or
 *     sidebar cannot occlude it.
 *   - Anchored via `position: fixed; top: var(--fw-header-h)` so it overlays
 *     content without pushing the page layout (no layout shift).
 *   - z-index 115 — above the slide-over panel (z-index 110) and its overlay
 *     (109), below CellTooltips (120) and the SourceActions confirmation modal
 *     (300). This follows the established FireWatch z-index ladder:
 *       100 = AppHeader (sticky)
 *       109 = slide-over backdrop
 *       110 = slide-over panel
 *       115 = this banner ← new layer
 *       120 = CellTooltip / CellDetailPopover
 *       300 = SourceActions confirmation modal
 *   - Slide-down-in / slide-up-out via CSS transform + opacity so the animation
 *     does not trigger layout recalculation (GPU-composited).
 *
 * Presentational only — show/hide, copy, and close callback come from the
 * parent (SourceFilterBar in AppHeader).  This component holds no timer logic.
 *
 * Tone: always "ok" (green left stripe + check icon) — this is a positive,
 * informational notification.  Matches FireWatch DS color tokens.
 *
 * ADR-0019 / ADR-0028 D6: React + TS; all colors via --fw-* tokens; no raw hex.
 */

import type { HTMLAttributes } from 'react'

export interface SyncBannerProps extends HTMLAttributes<HTMLDivElement> {
  /** Whether the banner is currently shown (drives the slide animation). */
  visible: boolean
  /** Attributed message to display. E.g. "39 new events from azure_waf". */
  message: string
  /** Callback fired when the × close button is clicked. */
  onClose: () => void
}

export function SyncBanner({
  visible,
  message,
  onClose,
  style,
  ...rest
}: SyncBannerProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      aria-atomic="true"
      data-testid="sync-banner"
      style={{
        position: 'fixed',
        // Sits flush below the sticky header.
        top: 'var(--fw-header-h)',
        left: 0,
        right: 0,
        // Above slide-over panel (110) and overlay (109) but below CellTooltip (120).
        zIndex: 115,
        // Slide-down-in on enter, slide-up-out on exit.
        // translateY(-100%) hides it above the header; 0 brings it fully in.
        transform: visible ? 'translateY(0)' : 'translateY(-100%)',
        opacity: visible ? 1 : 0,
        // pointer-events:none when hidden so invisible banner doesn't block clicks.
        pointerEvents: visible ? 'auto' : 'none',
        transition: 'transform 200ms ease-out, opacity 200ms ease-out',
        // DS aesthetics — matches the header gradient source card style.
        background: 'var(--fw-bg-card)',
        borderBottom: '2px solid var(--fw-green)',
        boxShadow: 'var(--fw-shadow-toast)',
        fontFamily: 'var(--fw-font-ui)',
        fontSize: 'var(--fw-fs-base)',
        color: 'var(--fw-t1)',
        ...style,
      }}
      {...rest}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '8px 24px',
          // Center the icon+message group while keeping × pinned to the right.
          justifyContent: 'center',
          position: 'relative',
        }}
      >
        {/* Success icon */}
        <span
          aria-hidden="true"
          style={{
            fontSize: 14,
            color: 'var(--fw-green)',
            flexShrink: 0,
          }}
        >
          ✓
        </span>

        {/* Attributed message */}
        <span
          data-testid="sync-banner-message"
        >
          {message}
        </span>

        {/* Manual close button — absolutely positioned to the right edge so it
            does not affect centering of the icon + message pair. */}
        <button
          type="button"
          aria-label="Dismiss sync notification"
          data-testid="sync-banner-close"
          onClick={onClose}
          style={{
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            color: 'var(--fw-t3)',
            fontSize: 16,
            lineHeight: 1,
            padding: '0 4px',
            fontFamily: 'var(--fw-font-ui)',
            transition: 'color 0.15s',
            // Pin to the right edge so it doesn't push the centered content off-center.
            position: 'absolute',
            right: 24,
            top: '50%',
            transform: 'translateY(-50%)',
          }}
          onMouseEnter={(e) => {
            ;(e.target as HTMLButtonElement).style.color = 'var(--fw-t1)'
          }}
          onMouseLeave={(e) => {
            ;(e.target as HTMLButtonElement).style.color = 'var(--fw-t3)'
          }}
        >
          ×
        </button>
      </div>
    </div>
  )
}
