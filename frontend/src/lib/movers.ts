/**
 * lib/movers.ts — Pure selection/ordering logic for the Risk Movers pane (issue #251).
 *
 * "Risk Movers" answers: "who is escalating RIGHT NOW?" by ranking IPs by the
 * absolute value of their score_delta (biggest change in either direction first).
 *
 * Contract:
 *   - Input: ThreatScore[] from GET /threats (carries score_delta from issue #250).
 *   - score_delta: null  → new actor (no prior snapshot in window); ranked AFTER actors
 *     with a non-null delta (we know their delta; we don't know new actors' magnitude).
 *   - Ties in |delta|: break by score descending (highest absolute score wins).
 *   - Top-N: bounded; callers pass N (default TOP_MOVERS_N = 6).
 *
 * All functions are pure (no side effects, no React, no fetching).
 *
 * SECURITY (ADR-0029 D3): all string fields are attacker-controlled.
 * Consumers MUST render them as text nodes only.
 */

import type { ThreatScore } from '../api/types'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Maximum number of mover rows to show in the Risk Movers pane.
 * Default 6 — matches the Threat Actors pane TOP_N (ADR-0017 bounded-panes convention).
 */
export const TOP_MOVERS_N = 6

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A single mover row, enriched with metadata for rendering.
 *
 * isNew = true when score_delta is null (no prior snapshot → "NEW" badge).
 * absDelta = |score_delta| for display; undefined when isNew.
 */
export interface MoverRow {
  threat: ThreatScore
  isNew: boolean
  /** Absolute value of score_delta. undefined when isNew. */
  absDelta: number | undefined
  /** Original signed delta. undefined when isNew. */
  delta: number | undefined
}

// ---------------------------------------------------------------------------
// topMovers — select and order
// ---------------------------------------------------------------------------

/**
 * Select the top-N movers from a list of threats, ordered by |score_delta| descending.
 *
 * Rules:
 *   1. Actors with a non-null score_delta are ranked first by |delta| (descending).
 *      Ties: score descending.
 *   2. Actors with score_delta = null (new actors) are appended after the ranked
 *      actors, ordered by score descending (best-effort ranking within unknowns).
 *   3. Result is bounded to topN rows (default TOP_MOVERS_N = 6).
 *
 * Score-0 actors (not yet a threat) are excluded — consistent with ThreatActors.
 *
 * @param threats - All ThreatScore records from GET /threats.
 * @param topN    - Maximum number of rows to return (default TOP_MOVERS_N).
 * @returns       - Array of MoverRow, length ≤ topN.
 */
export function topMovers(threats: ThreatScore[], topN = TOP_MOVERS_N): MoverRow[] {
  // Exclude score-0 actors (not yet a threat).
  const scored = threats.filter((t) => t.score > 0)

  // Partition: known-delta vs new actors.
  const knownDelta: ThreatScore[] = []
  const newActors: ThreatScore[] = []

  for (const t of scored) {
    if (t.score_delta !== null && t.score_delta !== undefined) {
      knownDelta.push(t)
    } else {
      newActors.push(t)
    }
  }

  // Sort known-delta: |delta| descending, tie-break score descending.
  const sortedKnown = [...knownDelta].sort((a, b) => {
    const absDeltaA = Math.abs(a.score_delta as number)
    const absDeltaB = Math.abs(b.score_delta as number)
    if (absDeltaB !== absDeltaA) return absDeltaB - absDeltaA
    return b.score - a.score
  })

  // Sort new actors: score descending.
  const sortedNew = [...newActors].sort((a, b) => b.score - a.score)

  // Combine and bound.
  const combined = [...sortedKnown, ...sortedNew].slice(0, topN)

  // Map to MoverRow.
  return combined.map((t): MoverRow => {
    const isNew = t.score_delta === null || t.score_delta === undefined
    return {
      threat: t,
      isNew,
      absDelta: isNew ? undefined : Math.abs(t.score_delta as number),
      delta: isNew ? undefined : (t.score_delta as number),
    }
  })
}
