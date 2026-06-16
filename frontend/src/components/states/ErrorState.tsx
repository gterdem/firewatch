/**
 * ErrorState — critical-styled fetch-failure indicator.
 *
 * Styled from SOC semantic tokens (ADR-0028 D6 / #96):
 *   - Uses soc-critical-fg so the state reads "critical / action required",
 *     matching the severity token palette.
 *   - role="alert" so screen readers announce immediately.
 *
 * Icon: ⚠️ emoji glyph — DS iconography convention (F5 #111).
 *   No stroke-icon library (Lucide/Heroicons) — emoji is the icon system.
 *
 * Usage:
 *   <ErrorState
 *     headline="Analytics unavailable (503)"
 *     subLine="The analytics service could not be reached. Retry or contact support."
 *   />
 *
 * Issue #98, updated F5 #111.
 */

import type { ReactNode } from 'react'

interface ErrorStateProps {
  /** Short headline describing the failure — operator-facing. */
  headline: string
  /** Optional secondary line — context, retry hint, or support note. */
  subLine?: string
  /** Optional icon override (defaults to ⚠️ — DS iconography convention). */
  icon?: ReactNode
  /** Additional CSS class names for the outer wrapper. */
  className?: string
}

/**
 * Renders a centered error state with critical token styling.
 * Always renders role="alert" so screen readers announce it.
 */
export default function ErrorState({
  headline,
  subLine,
  icon,
  className = '',
}: ErrorStateProps) {
  return (
    <div
      className={`flex flex-col items-center justify-center gap-2 py-10 text-center ${className}`}
      data-testid="error-state"
      role="alert"
      aria-label={headline}
    >
      <span
        className="text-soc-critical-fg mb-1"
        data-testid="error-state-icon"
        aria-hidden="true"
      >
        {icon ?? <span style={{ fontSize: '1.5rem', lineHeight: 1 }}>⚠️</span>}
      </span>
      <p
        className="text-sm font-medium text-soc-critical-fg"
        data-testid="error-state-headline"
      >
        {headline}
      </p>
      {subLine && (
        <p
          className="text-xs text-muted-foreground"
          data-testid="error-state-subline"
        >
          {subLine}
        </p>
      )}
    </div>
  )
}
