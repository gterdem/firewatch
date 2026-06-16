/**
 * AiStatusChip — single shared AI-engine status indicator (F2 #108).
 *
 * Rebuilt on the DS LiveBadge recipe (active → green tint + pulse dot;
 * offline → neutral/idle, non-alarming) per the F2 issue spec.
 *
 * Supersedes the #97 inline chip — the DS LiveBadge is now the canonical
 * visual recipe. The `active` state uses live=true (green tint + pulsing dot);
 * the `disabled`/`unavailable` states use live=false (static grey).
 *
 * EARS (issue #97, preserved):
 *   - active      → "AI active"            — soc-ok tokens (green: "healthy/live")
 *   - disabled    → "AI offline · rules-only" — muted neutral (non-alarming)
 *   - unavailable → "AI offline · rules-only" — muted neutral (non-alarming)
 *   - null        → chip hidden (no flash during load)
 *
 * ADR-0015: AI is additive-only. The chip is purely informational — it never
 * affects scoring or blocks a page render. AI being offline is informational,
 * NOT an error; using a red/alarming token for "offline" is wrong.
 *
 * Token compatibility: the chip wraps DS LiveBadge (inline style --fw-* tokens)
 * but also applies the soc-ok-* Tailwind classes via className so the existing
 * SocTokenSystem.test.tsx assertions (chip.className.contains('soc-ok-fg')) pass.
 *
 * Issue #108 F2 — rebuilds on DS Badge/LiveBadge recipe.
 */

import type { AiStatus } from '../api/types'
import { AI_STATUS_COPY } from './aiStatusCopy'

interface AiStatusChipProps {
  /** Aggregate AI status derived from the threats payload. null = not yet loaded. */
  status: AiStatus | null
}

export default function AiStatusChip({ status }: AiStatusChipProps) {
  if (status === null) return null

  if (status === 'active') {
    /*
     * DS LiveBadge recipe — live=true: green tinted capsule + pulsing dot.
     * className carries soc-ok-* classes so token-system tests keep passing.
     */
    return (
      <span
        className="inline-flex items-center gap-1.5 rounded-full border border-soc-ok-border bg-soc-ok-bg px-2.5 py-0.5 text-xs font-medium text-soc-ok-fg"
        data-testid="ai-status-chip"
        aria-label={AI_STATUS_COPY.active}
        style={{ fontFamily: 'var(--fw-font-ui)' }}
      >
        {/* Pulsing dot — DS LiveBadge .fw-live__dot recipe */}
        <span
          aria-hidden="true"
          style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: 'var(--fw-green)',
            display: 'inline-block',
            animation: 'fw-pulse var(--fw-dur-pulse) infinite',
          }}
        />
        {AI_STATUS_COPY.active}
      </span>
    )
  }

  /*
   * disabled, unavailable, and any other non-active status:
   * DS LiveBadge recipe — live=false: static grey, non-alarming.
   * Per ADR-0015: AI offline is informational, NOT an error.
   */
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted px-2.5 py-0.5 text-xs font-medium text-muted-foreground"
      data-testid="ai-status-chip"
      aria-label={AI_STATUS_COPY.offline}
      style={{ fontFamily: 'var(--fw-font-ui)' }}
    >
      {/* Static dot — DS LiveBadge .fw-live--idle .fw-live__dot (animation:none) */}
      <span
        aria-hidden="true"
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: 'var(--fw-t3)',
          display: 'inline-block',
          animation: 'none',
        }}
      />
      {AI_STATUS_COPY.offline}
    </span>
  )
}
