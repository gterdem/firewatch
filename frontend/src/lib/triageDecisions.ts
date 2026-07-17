/**
 * triageDecisions — the server-side triage-decision seam (ADR-0072, issue #47).
 *
 * Two responsibilities, per the ADR-0072 D8 module layout:
 *
 *   1. `migrateLocalStorageDecisions()` — the ONE-SHOT, best-effort migration
 *      of the pre-#47 localStorage `dismissed` entries into the server store
 *      (`POST /decisions {verb: 'dismissed'}`). Runs once per browser
 *      (guarded by a completion sentinel); a failed POST is non-fatal (the
 *      actor simply stays un-migrated and gets a fresh decision if the
 *      operator dismisses it again).
 *
 *      ADR-0072 D6 (maintainer ruling): `acknowledged` entries are NEVER
 *      migrated — their "suppress now, re-surface on material change"
 *      semantics are retired (subsumed by `expected`/`dismissed` + server
 *      re-entry). The legacy acknowledged key is garbage-collected here
 *      (removed, not read for migration) so localStorage is never consulted
 *      again after this function runs.
 *
 *   2. `isSuppressed()` — the queue-membership predicate (ADR-0072 D3):
 *      "queue membership is `escalated && !(triage_decision?.suppressed)`."
 *      This function supplies the `!(triage_decision?.suppressed)` half —
 *      callers (triageBand.ts, RecommendationCards.tsx) AND it with their own
 *      escalation/band check. It reads ONLY the server-computed
 *      `triage_decision.suppressed` field — no client-side lifecycle logic,
 *      no localStorage read, per the ADR-0072 "client contract" must-NOT
 *      criterion.
 *
 * DISMISSED_ACTORS_KEY / ACKNOWLEDGED_ACTORS_KEY (ADR-0072 D7 retire list):
 * these two localStorage keys survive ONLY inside this migration reader —
 * no other module in the frontend may read or write them.
 */

import { createDecision } from '../api/decisions'
import { isValidIpFormat } from './triageActions'
import type { ThreatScore } from '../api/types'

// ---------------------------------------------------------------------------
// Legacy localStorage keys (ADR-0072 D7: survive ONLY here)
// ---------------------------------------------------------------------------

/** Pre-#47 localStorage key for the JSON-serialized dismissed IPs array. */
export const DISMISSED_ACTORS_KEY = 'fw:triage:dismissed'
/** Pre-#47 localStorage key for the JSON-serialized acknowledged actors map. */
export const ACKNOWLEDGED_ACTORS_KEY = 'fw:triage:acknowledged'
/** Sentinel marking the one-shot migration as complete for this browser. */
export const MIGRATION_DONE_KEY = 'fw:triage:migrated-v1'

// ---------------------------------------------------------------------------
// 1. One-shot localStorage → server migration (ADR-0072 D3/D6)
// ---------------------------------------------------------------------------

/**
 * Read the legacy dismissed-actors array out of localStorage.
 * Returns [] on any parse failure or absence — never throws.
 */
function readLegacyDismissed(): string[] {
  try {
    const raw = localStorage.getItem(DISMISSED_ACTORS_KEY)
    if (raw == null) return []
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.filter(
      (v): v is string => typeof v === 'string' && isValidIpFormat(v),
    )
  } catch {
    return []
  }
}

/**
 * One-shot, best-effort migration of pre-#47 localStorage `dismissed` state
 * into the server-side decision store (ADR-0072 D3).
 *
 * Idempotent: a `MIGRATION_DONE_KEY` sentinel guards against re-running on
 * every mount/reload — call this once, e.g. on dashboard mount. Safe to call
 * multiple times regardless (a warm sentinel makes every call after the
 * first a no-op) and safe to await or fire-and-forget.
 *
 * ADR-0072 D6: `acknowledged` entries are deliberately NOT read for
 * migration — only garbage-collected (removed) below.
 *
 * Failures are non-fatal (ADR-0072 D3 "best-effort push"): a POST that
 * fails leaves that one IP un-migrated; it is not retried within this run,
 * and localStorage is still cleared afterward — a stale entry is not worth
 * re-attempting indefinitely against an unreachable API.
 */
export async function migrateLocalStorageDecisions(): Promise<void> {
  let alreadyMigrated: boolean
  try {
    alreadyMigrated = localStorage.getItem(MIGRATION_DONE_KEY) != null
  } catch {
    // localStorage unavailable (e.g. disabled/private mode) — nothing to
    // migrate and nowhere to persist the sentinel; treat as a no-op.
    return
  }
  if (alreadyMigrated) return

  const dismissedIps = readLegacyDismissed()

  await Promise.allSettled(
    dismissedIps.map((actor_ip) => createDecision({ actor_ip, verb: 'dismissed' })),
  )

  try {
    localStorage.setItem(MIGRATION_DONE_KEY, '1')
    // Garbage-collect both legacy keys — localStorage is never authoritative
    // for queue membership after this point (ADR-0072 must-NOT criterion).
    localStorage.removeItem(DISMISSED_ACTORS_KEY)
    localStorage.removeItem(ACKNOWLEDGED_ACTORS_KEY)
  } catch {
    // Non-fatal — if we can't write the sentinel, the migration may re-run
    // next load; createDecision POSTs are tolerant of being re-sent (a
    // second `dismissed` decision for the same actor is simply a newer row,
    // append-only per ADR-0072 D2 — the evaluator reads the latest active one).
  }
}

// ---------------------------------------------------------------------------
// 2. Queue-membership predicate (ADR-0072 D3)
// ---------------------------------------------------------------------------

/**
 * Returns true when the server has annotated this actor as suppressed
 * (ADR-0072 D4: an OR of actor-identity and false-positive suppression).
 *
 * This is HALF of the ADR-0072 D3 queue-membership contract:
 *   escalated && !(triage_decision?.suppressed)
 * Callers AND this with their own escalation/band predicate
 * (see `triageBand.ts`'s `deriveTriageActors` / `deriveObservedRecord`).
 *
 * Reads ONLY the server-computed `triage_decision.suppressed` field — no
 * lifecycle logic, no localStorage read (ADR-0072 must-NOT criterion).
 */
export function isSuppressed(actor: ThreatScore): boolean {
  return actor.triage_decision?.suppressed ?? false
}
