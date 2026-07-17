/**
 * aiEngineStatus — pure utility for deriving aggregate AI engine status from threats.
 *
 * Separated from AiEngineChip.tsx so react-refresh/only-export-components lint
 * rule is satisfied (the component file exports only the component).
 *
 * ADR-0015: AI is additive-only. This helper never blocks rendering — it degrades
 * gracefully to null when no threat data is available.
 *
 * This is the threat-derived FALLBACK used only while `/health` (the authoritative
 * tri-state source, ADR-0066) has not yet loaded. Once health arrives, callers
 * should prefer `health.ai` / `resolveHealthAiState` — see aiStatusCopy.ts.
 */

import type { AiStatus, ThreatScore } from '../../api/types'

/**
 * Derive aggregate AI status from a list of ThreatScores.
 *
 * Priority (ADR-0066 / issue #41): active > unavailable > disabled — the FAULT
 * state is ranked above the deliberate-choice state, so a real fault is never
 * masked by "disabled" just because some other actor happened to be scored
 * while AI was administratively off. (Previously `disabled` outranked
 * `unavailable`; that ordering under-alarmed a genuinely broken engine.)
 *
 * 'skipped' and 'no_input' are per-analysis annotations only (ADR-0066) and must
 * never drive the global chip — when the only signal available is one of those,
 * this degrades to 'disabled' (the neutral "did not run" bucket) rather than
 * leaking a per-analysis-only value into the aggregate/global status.
 *
 * Returns null when the array is empty (chip is hidden during initial load).
 */
export function deriveAiStatus(threats: ThreatScore[]): AiStatus | null {
  if (threats.length === 0) return null
  if (threats.some((t) => t.ai_status === 'active')) return 'active'
  if (threats.some((t) => t.ai_status === 'unavailable')) return 'unavailable'
  if (threats.some((t) => t.ai_status === 'disabled')) return 'disabled'

  const first = threats[0].ai_status
  // 'skipped' / 'no_input' never drive the global chip — degrade to neutral.
  if (first === 'skipped' || first === 'no_input') return 'disabled'
  // Fallback: any other/unknown value (e.g. legacy 'error') passes through —
  // the chip itself degrades unrecognized values to the neutral treatment.
  return first
}
