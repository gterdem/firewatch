/**
 * AiStatusChip — single shared AI-engine status indicator (F2 #108; three-state
 * rework issue #41 / ADR-0066).
 *
 * Renders one of THREE honest states — never collapses "off by choice" and
 * "unreachable" into one ambiguous "offline" bucket (the bug ADR-0066 fixes):
 *   - active      → DS LiveBadge live=true recipe — green tint + pulsing dot.
 *   - unreachable → attention-worthy AMBER (soc-watch tokens) — static, not
 *                   critical/red. AI is on but unreachable; detection continues
 *                   (ADR-0015 floor) — copy says so ("… · rules-only").
 *   - disabled (+ any other/unknown status) → static grey/neutral, non-alarming.
 *
 * Accepts status values from either vocabulary (Layer 1 `HealthAiStatus` — the
 * authoritative `/health.ai` tri-state — or Layer 2 `AiStatus`, the threat-derived
 * fallback used while health is still loading; see `dashboard/aiEngineStatus.ts`
 * `deriveAiStatus`). Both fault words ("unreachable" / "unavailable") map to the
 * same attention treatment; every other value (including future/unrecognized
 * ones) degrades to neutral — see `aiStatusCopy.ts` `resolveAiStatusTone`.
 *
 * EARS (issue #97, extended by #41):
 *   - active      → "AI active"                — soc-ok tokens (green: "healthy/live")
 *   - unreachable → "AI unreachable · rules-only" — soc-watch tokens (amber: "attention")
 *   - disabled    → "AI off · rules-only"       — muted neutral (non-alarming)
 *   - null        → chip hidden (no flash during load)
 *
 * ADR-0015: AI is additive-only. The chip is purely informational — it never
 * affects scoring or blocks a page render.
 *
 * Token compatibility: the chip wraps DS LiveBadge (inline style --fw-* tokens)
 * but also applies the soc-* Tailwind classes via className so the existing
 * SocTokenSystem.test.tsx assertions (chip.className.contains('soc-ok-fg')) pass.
 *
 * Issue #108 F2 — rebuilds on DS Badge/LiveBadge recipe. Issue #41 — adds the
 * amber "unreachable" attention state so a real fault is never masked as a
 * deliberate, non-alarming "off".
 */

import type { AiStatus } from '../api/types'
import { AI_STATUS_COPY, resolveAiStatusTone } from './aiStatusCopy'

interface AiStatusChipProps {
  /**
   * Aggregate AI status. Prefer the authoritative `/health.ai` tri-state value
   * ('active' | 'disabled' | 'unreachable'); accepts the threat-derived Layer 2
   * `AiStatus` fallback (incl. 'unavailable') while health is still loading.
   * null = not yet loaded (chip hidden).
   */
  status: AiStatus | null
}

export default function AiStatusChip({ status }: AiStatusChipProps) {
  if (status === null) return null

  const tone = resolveAiStatusTone(status)

  if (tone === 'active') {
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

  if (tone === 'attention') {
    /*
     * Attention-worthy AMBER — soc-watch tokens ("pay attention, not yet
     * blocked" per lib/socTokens.ts). NOT critical/red: detection continues
     * on the rules-only floor (ADR-0015). Static (no pulse) — this is a
     * degraded-but-honest state, not a live/good one.
     */
    return (
      <span
        className="inline-flex items-center gap-1.5 rounded-full border border-soc-watch-border bg-soc-watch-bg px-2.5 py-0.5 text-xs font-medium text-soc-watch-fg"
        data-testid="ai-status-chip"
        aria-label={AI_STATUS_COPY.unreachable}
        style={{ fontFamily: 'var(--fw-font-ui)' }}
      >
        <span
          aria-hidden="true"
          style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: 'var(--fw-accent)',
            display: 'inline-block',
            animation: 'none',
          }}
        />
        {AI_STATUS_COPY.unreachable}
      </span>
    )
  }

  /*
   * disabled, and any other/unknown status: DS LiveBadge recipe — live=false:
   * static grey, non-alarming. Per ADR-0015/ADR-0066: a deliberate choice is
   * never an error.
   */
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted px-2.5 py-0.5 text-xs font-medium text-muted-foreground"
      data-testid="ai-status-chip"
      aria-label={AI_STATUS_COPY.disabled}
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
      {AI_STATUS_COPY.disabled}
    </span>
  )
}
