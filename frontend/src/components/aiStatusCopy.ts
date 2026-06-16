/**
 * aiStatusCopy — canonical copy strings for the AI-status chip.
 *
 * Separated from AiStatusChip.tsx so the react-refresh/only-export-components
 * lint rule is satisfied (the component file exports only the component).
 *
 * Issue #97: one string per state, used consistently on both Dashboard and
 * AI Analysis headers via the shared AiStatusChip component.
 *
 * ADR-0015: AI is additive-only. "disabled" is informational, not an error —
 * the copy for the offline state reflects this: "AI offline · rules-only".
 */

/** Canonical copy strings — one per state. */
export const AI_STATUS_COPY = {
  active: 'AI active',
  offline: 'AI offline · rules-only',
} as const
