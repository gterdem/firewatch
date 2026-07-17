/**
 * aiStatusCopy — canonical copy + tri-state resolution for the global AI-status chip.
 *
 * Separated from AiStatusChip.tsx so the react-refresh/only-export-components
 * lint rule is satisfied (the component file exports only the component).
 *
 * ADR-0066 (three-state AI presentation, issue #41): the chip renders one of
 * three honest states, never collapsing "off by choice" and "unreachable" into
 * a single ambiguous "offline" bucket:
 *   - active      — green/live. The engine is on and answered.
 *   - disabled    — neutral grey. The operator turned AI off — nothing is wrong.
 *   - unreachable — attention amber (not critical). AI is on but unreachable —
 *                   detection is unaffected (ADR-0015 floor); go fix something.
 *
 * Two distinct fault words feed the "attention" bucket by design:
 *   - "unreachable"  — the `/health.ai` (Layer 1 engine) fault word.
 *   - "unavailable"  — the per-analysis `AiStatus` (Layer 2) fault word, used as
 *                       the threat-derived fallback while health is still loading
 *                       (see dashboard/aiEngineStatus.ts `deriveAiStatus`).
 * Both mean the same thing to the operator ("something needs fixing") even
 * though the two backend vocabularies spell it differently — see ADR-0066.
 *
 * Any other/unrecognized status (disabled, skipped, no_input, error, future
 * values) degrades to the neutral treatment — never assumed to be a fault.
 */

import type { HealthResponse } from '../api/types'

/** Canonical copy strings — one per chip state. */
export const AI_STATUS_COPY = {
  active: 'AI active',
  disabled: 'AI off · rules-only',
  unreachable: 'AI unreachable · rules-only',
} as const

/** The three visual/tone buckets the chip can render. */
export type AiStatusTone = 'active' | 'neutral' | 'attention'

/** Per-analysis (Layer 2) fault word — see api/types.ts `AiStatus`. */
const LAYER2_FAULT_WORD = 'unavailable'
/** `/health.ai` (Layer 1) fault word — see api/types.ts `HealthAiStatus`. */
const LAYER1_FAULT_WORD = 'unreachable'

/**
 * Resolve the visual tone bucket for a chip status value.
 *
 * Accepts values from either vocabulary (Layer 1 `HealthAiStatus` when health
 * is available, or Layer 2 `AiStatus` as the threat-derived loading fallback —
 * see `dashboard/aiEngineStatus.ts` `deriveAiStatus`). `null`/unrecognized
 * values degrade to neutral (never alarming) — ADR-0066 / issue #41.
 */
export function resolveAiStatusTone(status: string | null | undefined): AiStatusTone {
  if (status === 'active') return 'active'
  if (status === LAYER1_FAULT_WORD || status === LAYER2_FAULT_WORD) return 'attention'
  // 'disabled', 'skipped', 'no_input', 'error', and any unknown/future value
  // all mean "did not run" or "choice" — never alarming.
  return 'neutral'
}

/**
 * Resolve the tri-state `/health.ai` value into the three chip-relevant states.
 * Unrecognized/future `ai` values degrade to 'disabled' (neutral) rather than
 * being assumed to be a fault (ADR-0066 / issue #41 api/types.ts criterion).
 */
export function resolveHealthAiState(health: HealthResponse): 'active' | 'disabled' | 'unreachable' {
  if (health.ai === 'active') return 'active'
  if (health.ai === LAYER1_FAULT_WORD) return 'unreachable'
  return 'disabled'
}
