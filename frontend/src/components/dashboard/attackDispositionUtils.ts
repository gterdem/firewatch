/**
 * Attack-disposition flow strip utilities (issue #214).
 *
 * Pure functions that transform the raw [{attack_type, action, count}] cross-tab
 * from GET /analytics/attack-dispositions into the data model consumed by the
 * AttackDispositionFlow SVG strip.
 *
 * Design decisions:
 *  - Actions are bucketed into three canonical display groups:
 *      "Blocked"  — BLOCK, DROP
 *      "Detected" — ALERT, LOG (detected but not blocked)
 *      "Allowed"  — ALLOW (explicitly permitted)
 *    Unrecognized action strings fall into "Detected" (conservative label).
 *  - Colors use var(--fw-*) tokens only (ADR-0028 D6 — no raw hex).
 *  - The cross-tab is already bounded to top-5 + Other by the backend.
 *
 * SECURITY (ADR-0029 D3): attack_type strings are rule-engine output rendered
 * as text nodes only; never via dangerouslySetInnerHTML.
 */

import type { AttackDispositionRow } from '../../api/types'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Canonical display bucket for an action disposition. */
export type DispositionGroup = 'Blocked' | 'Detected' | 'Allowed'

/** One attack category with its disposition breakdown. */
export interface FlowAttackNode {
  /** Attack category label (e.g. "SQL Injection", "Other"). */
  label: string
  /** Total events for this attack type (sum across all actions). */
  total: number
  /** Per-disposition breakdown — keys are DispositionGroup. */
  dispositions: Record<DispositionGroup, number>
}

/** Derived display row for the SVG strip — proportions pre-computed. */
export interface FlowRow {
  label: string
  total: number
  /** Fraction of total that was blocked (0–1). */
  blockedFraction: number
  /** Fraction that was detected but not blocked (0–1). */
  detectedFraction: number
  /** Fraction that was allowed (0–1). */
  allowedFraction: number
  /** Absolute counts for tooltip. */
  blocked: number
  detected: number
  allowed: number
}

// ---------------------------------------------------------------------------
// Action → DispositionGroup mapping
// ---------------------------------------------------------------------------

/**
 * Map a canonical action string to a display DispositionGroup.
 * Unrecognized values fall to "Detected" (conservative assumption:
 * the event was observed but disposition is ambiguous).
 */
export function mapActionToGroup(action: string): DispositionGroup {
  const upper = action.toUpperCase()
  if (upper === 'BLOCK' || upper === 'DROP') return 'Blocked'
  if (upper === 'ALLOW') return 'Allowed'
  // ALERT, LOG, and anything unrecognized → Detected
  return 'Detected'
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

/**
 * Aggregate raw cross-tab rows into FlowRow display objects.
 *
 * Groups actions into three display buckets and computes fractions.
 * Rows with total=0 are excluded (shouldn't happen if the backend is correct,
 * but defensive).
 *
 * Preserves the order returned by the backend (top-N by frequency).
 */
export function buildFlowRows(rows: AttackDispositionRow[]): FlowRow[] {
  // Collect per-attack-type data
  const byAttack = new Map<string, Record<DispositionGroup, number>>()
  const orderMap = new Map<string, number>() // preserves server ordering

  for (const row of rows) {
    if (!byAttack.has(row.attack_type)) {
      byAttack.set(row.attack_type, { Blocked: 0, Detected: 0, Allowed: 0 })
      orderMap.set(row.attack_type, orderMap.size)
    }
    const group = mapActionToGroup(row.action)
    byAttack.get(row.attack_type)![group] += row.count
  }

  const result: FlowRow[] = []
  // Sort by insertion order (matches backend top-N ranking)
  const entries = Array.from(byAttack.entries()).sort(
    (a, b) => (orderMap.get(a[0]) ?? 0) - (orderMap.get(b[0]) ?? 0),
  )

  for (const [label, disps] of entries) {
    const total = disps.Blocked + disps.Detected + disps.Allowed
    if (total === 0) continue
    result.push({
      label,
      total,
      blockedFraction: disps.Blocked / total,
      detectedFraction: disps.Detected / total,
      allowedFraction: disps.Allowed / total,
      blocked: disps.Blocked,
      detected: disps.Detected,
      allowed: disps.Allowed,
    })
  }

  return result
}

// ---------------------------------------------------------------------------
// DS color tokens (ADR-0028 D6 — no raw hex)
// ---------------------------------------------------------------------------

/** Color tokens for the three disposition groups. */
export const DISPOSITION_COLORS: Record<DispositionGroup, string> = {
  Blocked: 'var(--fw-red)',
  Detected: 'var(--fw-orange)',
  Allowed: 'var(--fw-green)',
}
