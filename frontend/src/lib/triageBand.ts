/**
 * triageBand — shared triage-actor derivation logic (issue #650, ADR-0059 D1+D2).
 *
 * Extracted from DashboardRoute.tsx so it can be imported by tests and other
 * consumers without violating the react-refresh/only-export-components lint rule
 * (which requires route files to export only React components as the default).
 *
 * ``deriveTriageActors`` is the canonical implementation of:
 *   is_alert_worthy(threat, triageThreshold) :=
 *     bandMeets(threat.threat_level, triageThreshold)   // band axis — ADR-0036
 *     OR isHighTierEscalation(threat)                  // action-aware axis — ADR-0058
 *
 * The two axes are OR-combined and NEVER collapsed into a single number (ADR-0036).
 */

import { bandMeets } from './threatLevel'
import { isDismissed } from './triageActions'
import type { ThreatScore } from '../api/types'

/**
 * Return true when an actor carries a high-priority escalation verdict
 * that should surface in the triage banner regardless of threat_level.
 *
 * ADR-0058 §4a: Tier 1 (allowed-through) and Tier 2 (block-status-unknown)
 * are banner-worthy even when the numeric score is LOW or MEDIUM — the
 * action axis is a *second axis* presented alongside the band (ADR-0036).
 */
export function isHighTierEscalation(t: ThreatScore): boolean {
  return t.escalation != null && t.escalation.tier <= 2
}

/**
 * Derive the list of actors that still need a triage decision.
 *
 * "Needs a decision" = bandMeets(threat_level, triageThreshold) OR (escalation tier 1/2)
 * AND not yet dismissed.
 *
 * The band half is parameterised by the operator-configurable Triage threshold
 * (ADR-0059 D1 / issue #650). Default "HIGH" preserves today's {CRITICAL, HIGH} set exactly.
 * The escalation-tier half is UNCONDITIONAL — ADR-0058 D2 / ADR-0036 (two axes never collapsed).
 *
 * Sort order: tier-1 escalations first, then tier-2, then by score descending
 * (so the loudest signals lead — ADR-0058 "Tier 1 = loudest").
 * Actors without an escalation verdict sort as tier 99 (after tiered ones).
 */
export function deriveTriageActors(
  threats: ThreatScore[],
  triageThreshold: string = 'HIGH',
): ThreatScore[] {
  return threats
    .filter(
      (t) =>
        !isDismissed(t) &&
        (bandMeets(t.threat_level, triageThreshold) || isHighTierEscalation(t)),
    )
    .sort((a, b) => {
      // Lower tier = louder = sort first
      const tierA = a.escalation?.tier ?? 99
      const tierB = b.escalation?.tier ?? 99
      if (tierA !== tierB) return tierA - tierB
      // Within same tier: higher score first
      return b.score - a.score
    })
}
