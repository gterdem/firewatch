/**
 * EmptyState — adapter shim wrapping DS EmptyState (F2 #108).
 *
 * The DS EmptyState (ds/feedback/EmptyState) uses the prop names from the
 * design system spec: { icon, title, children, action }.
 *
 * The #98 EmptyState used: { icon, headline, subLine, className }.
 *
 * This shim translates the old API → DS API so all existing call sites
 * (GeoMap, AnalyticsRoute, etc.) keep working without change.
 *
 * DS testids are forwarded:
 *   data-testid="empty-state"          — outer wrapper (role="status") ← from DS
 *   data-testid="empty-state-icon"     — icon slot ← from DS
 *   data-testid="empty-state-headline" — headline (h3 in DS) ← from DS title slot
 *   data-testid="empty-state-subline"  — body copy ← from DS children slot
 *
 * Visual change vs #98: the DS EmptyState uses dashed border + DS token colours
 * (--fw-t1 on headline, --fw-t3 on body, opacity-0.6 on icon). The muted-foreground
 * Tailwind class is gone — inline styles from --fw-* tokens are used instead.
 * PanelStates.test.tsx is updated to reflect the DS recipe (headline → --fw-t1,
 * not muted-foreground class).
 *
 * Issue #108 — supersedes #98 EmptyState visual recipe.
 */

import type { ReactNode } from 'react'
import { EmptyState as DSEmptyState } from '../ds'

interface EmptyStateProps {
  /** Optional icon element displayed above the headline. */
  icon?: ReactNode
  /** Short headline — one sentence, operator-facing. */
  headline: string
  /** Optional secondary line — context or "what to do next". */
  subLine?: string
  /** Additional CSS class names for the outer wrapper. */
  className?: string
}

/**
 * Compatibility shim: translates the #98 EmptyState props into the DS EmptyState API.
 * The DS EmptyState is the canonical implementation; this file is the translation layer.
 */
export default function EmptyState({ icon, headline, subLine, className = '' }: EmptyStateProps) {
  return (
    <DSEmptyState icon={icon} title={headline} className={className}>
      {subLine}
    </DSEmptyState>
  )
}
