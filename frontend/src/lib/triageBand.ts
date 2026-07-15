/**
 * triageBand — shared triage-actor derivation logic (issue #650, ADR-0059 D1+D2;
 * issue #42, ADR-0067 D2/D7 — the null-tier guard).
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
 *
 * ``deriveObservedRecord`` (issue #43, ADR-0067 D5(2)) is the aggregate-line
 * derivation for the observed stratum: every actor carrying disposition
 * "observed" that did NOT independently earn a banner slot (via the band
 * axis) rolls up into one honest count — never silently dropped. Built from
 * engine integers only (a sum of ``total_events``, a count of distinct
 * ``source_types`` values) — no attacker-controlled text ever reaches the
 * banner (ADR-0035 discipline).
 *
 * SECURITY / correctness (ADR-0067 D2, issue #42): ``EscalationVerdict.tier`` is
 * ``number | null`` — the ADR-0067 observed stratum emits ``tier: null`` for actors
 * with no qualifying escalation signal. In JavaScript, ``null <= 2`` evaluates to
 * ``true`` (null coerces to 0 in a relational comparison) — an unguarded
 * ``t.escalation.tier <= 2`` would silently re-admit EVERY observed actor into the
 * triage banner, reproducing the exact flood ADR-0067 fixes, with no error and no
 * failing type check (TypeScript does not flag `null <= 2`). ``isHighTierEscalation``
 * below explicitly null-guards before the comparison.
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
 *
 * ADR-0067 D2/D7: ``tier`` may be ``null`` (the observed stratum — no
 * escalation claim). Explicitly null-guarded: ``null <= 2`` is ``true`` in
 * JavaScript, so omitting this check would silently treat every observed
 * actor as Tier 1/2 and reproduce the pre-#42 flood in the UI only.
 */
export function isHighTierEscalation(t: ThreatScore): boolean {
  const tier = t.escalation?.tier
  return tier != null && tier <= 2
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

/**
 * Aggregate summary of the observed stratum's "on the record" mass —
 * everything the banner does NOT show as a chip, expressed as one honest
 * count (ADR-0067 D5(2), issue #43).
 */
export interface ObservedRecordSummary {
  /** Sum of `total_events` across all observed-only actors — an engine integer. */
  eventCount: number
  /** Count of distinct `source_types` values across those actors — an engine integer. */
  sourceCount: number
}

/**
 * Derive the "N detections on the record from M sources" aggregate — the
 * ADR-0067 D5(2) safety net that keeps observed events visible without
 * flooding the banner with chips.
 *
 * An actor qualifies for this rollup when:
 *   - its escalation verdict has `disposition === "observed"` (tier: null —
 *     no escalation claim at all, ADR-0067 D2), AND
 *   - it is NOT already present in `pendingActors` (i.e. it did not
 *     independently earn a banner slot via the band axis — ADR-0067 D5(1)).
 *
 * Returns `null` when there is nothing to report (no observed actors, or
 * every observed actor already banded its way into the queue) — the caller
 * renders no aggregate line in that case (EARS: WHEN zero observed-only
 * actors exist, no aggregate line).
 *
 * SECURITY (ADR-0035 / issue #43 hard constraint): both fields are plain
 * engine integers — a summed count and a distinct-value count — never the
 * underlying attacker-influenceable source-type or IP text.
 */
export function deriveObservedRecord(
  threats: ThreatScore[],
  pendingActors: ThreatScore[],
): ObservedRecordSummary | null {
  const pendingIps = new Set(pendingActors.map((t) => t.source_ip))
  const observedOnly = threats.filter(
    (t) =>
      !isDismissed(t) &&
      t.escalation?.disposition === 'observed' &&
      !pendingIps.has(t.source_ip),
  )

  if (observedOnly.length === 0) return null

  const eventCount = observedOnly.reduce((sum, t) => sum + t.total_events, 0)
  const sourceTypes = new Set<string>()
  for (const t of observedOnly) {
    for (const sourceType of t.source_types) sourceTypes.add(sourceType)
  }

  return { eventCount, sourceCount: sourceTypes.size }
}
