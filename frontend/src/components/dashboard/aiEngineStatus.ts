/**
 * aiEngineStatus — pure utility for deriving aggregate AI engine status from threats.
 *
 * Separated from AiEngineChip.tsx so react-refresh/only-export-components lint
 * rule is satisfied (the component file exports only the component).
 *
 * ADR-0015: AI is additive-only. This helper never blocks rendering — it degrades
 * gracefully to null when no threat data is available.
 */

import type { AiStatus, ThreatScore } from '../../api/types'

/**
 * Derive aggregate AI status from a list of ThreatScores.
 *
 * Priority: active > disabled > unavailable > null (no data).
 * If any threat was AI-scored this cycle the engine is considered active.
 * "disabled" takes precedence over "unavailable" because it is an explicit
 * operator-controlled state (_runtime.ai_enabled=false).
 *
 * Returns null when the array is empty (chip is hidden during initial load).
 */
export function deriveAiStatus(threats: ThreatScore[]): AiStatus | null {
  if (threats.length === 0) return null
  if (threats.some((t) => t.ai_status === 'active')) return 'active'
  if (threats.some((t) => t.ai_status === 'disabled')) return 'disabled'
  if (threats.some((t) => t.ai_status === 'unavailable')) return 'unavailable'
  // Fallback: use the first threat's status (covers 'error' and other strings)
  return threats[0].ai_status
}
