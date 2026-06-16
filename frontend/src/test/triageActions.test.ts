/**
 * Tests for frontend/src/lib/triageActions.ts — the action seam (ADR-0033, issue #158).
 *
 * Updated for MH (issue #204, ADR-0037):
 *   investigate → openEntity({kind:'ip', value}) — opens the entity slide-over.
 *   No route navigation on investigate.
 *
 * Updated for issue #727 — localStorage persistence + Acknowledge/Dismiss distinction:
 *   - Acknowledge vs Dismiss two-state model and localStorage round-trip.
 *   - Material change detection (hasMaterialChange) and re-surface logic.
 *   - Bounded-cap + IP-format-guard invariants survive persistence.
 *
 * EARS criteria mapped to tests:
 *
 * Ubiquitous: the action seam SHALL expose exactly one entrypoint `onAction(actor, verb)`.
 *   → test: onAction is a function with arity 2, created by makeOnAction
 *
 * Event-driven: WHEN `onAction(actor, "investigate")` fires, the slide-over SHALL open
 * for that actor's IP (ADR-0037); no route navigation SHALL occur.
 *   → test: investigate calls openEntity with {kind:'ip', value:actor.source_ip};
 *            navigate is NOT called
 *
 * Event-driven: WHEN `onAction(actor, "acknowledge")` fires, the actor is suppressed
 * from the triage queue but re-surfaces on material change (issue #727 EARS-1/2).
 *   → test: acknowledge marks actor as isDismissed → true;
 *            re-surfaces on score increase / block_status flip / tier decrease
 *
 * Event-driven: WHEN `onAction(actor, "dismiss")` fires, the actor SHALL be suppressed
 * and NOT re-surface on material change (stronger suppression, issue #727 EARS-3).
 *   → test: dismiss marks actor as isDismissed → true; does NOT re-surface; persists reload
 *
 * Event-driven: WHEN `onAction(actor, "block")` fires, the UI SHALL record the block
 * decision / raise the alert (SIEM) and SHALL NOT attempt to execute an enforcement action.
 *   → test: block fires onBlock callback; actor removed from triage queue (isDismissed);
 *            no external fetch or side-effectful call is made beyond the callback
 *
 * Issue #727 EARS-4: WHILE persisting, the store SHALL keep bounded-cap + IP-format-guard.
 *   → tests: cap eviction survives localStorage round-trip; malformed IPs blocked at guard
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  makeOnAction,
  isDismissed,
  clearDismissed,
  reconcileAcknowledged,
  isValidIpFormat,
  hasMaterialChange,
  snapshotOf,
  DISMISSED_ACTORS_CAP,
  DISMISSED_ACTORS_KEY,
  ACKNOWLEDGED_ACTORS_KEY,
  MATERIAL_SCORE_DELTA,
  type ThreatActionVerb,
  type OnAction,
  type AcknowledgedSnapshot,
} from '../lib/triageActions'
import type { ThreatScore } from '../api/types'
import type { EntityRef } from '../components/entity/EntityPanelContext'

// ---------------------------------------------------------------------------
// Fixture actor
// ---------------------------------------------------------------------------

const ACTOR: ThreatScore = {
  source_ip: '192.0.2.1',
  threat_level: 'CRITICAL',
  score: 92,
  total_events: 150,
  blocked_events: 120,
  attack_types: ['SQLi'],
  first_seen: '2026-06-01T00:00:00Z',
  last_seen: '2026-06-10T12:00:00Z',
  source_types: ['azure_waf'],
  detections: [],
  ai_insights: ['Persistent SQLi pattern'],
  ai_confidence: 0.95,
  ai_status: 'active',
  location: null,
  score_breakdown: [],
  asn: null,
  as_name: null,
  score_delta: null,
}

// ---------------------------------------------------------------------------
// Setup: clear dismiss state and mocks between tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  clearDismissed()
})

// ---------------------------------------------------------------------------
// 1. Ubiquitous: single entrypoint
// ---------------------------------------------------------------------------

describe('triageActions — action seam entrypoint', () => {
  it('makeOnAction returns a function (the single onAction entrypoint)', () => {
    const openEntity = vi.fn()
    const action: OnAction = makeOnAction({ openEntity })
    expect(typeof action).toBe('function')
  })

  it('onAction accepts exactly (actor, verb) — arity 2', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })
    // Should not throw when called with both args
    expect(() => onAction(ACTOR, 'investigate')).not.toThrow()
  })

  it('verb type is the union "block" | "investigate" | "acknowledge" | "dismiss"', () => {
    // Compile-time assertion: ThreatActionVerb should accept all four verbs.
    const verbs: ThreatActionVerb[] = ['block', 'investigate', 'acknowledge', 'dismiss']
    expect(verbs).toHaveLength(4)
    expect(verbs).toContain('block')
    expect(verbs).toContain('investigate')
    expect(verbs).toContain('acknowledge')
    expect(verbs).toContain('dismiss')
  })
})

// ---------------------------------------------------------------------------
// 2. Event-driven: investigate → open entity slide-over (MH #204, ADR-0037)
// ---------------------------------------------------------------------------

describe('triageActions — investigate verb', () => {
  it('WHEN investigate fires, openEntity is called with {kind:"ip", value:actor.source_ip}', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'investigate')

    expect(openEntity).toHaveBeenCalledOnce()
    expect(openEntity).toHaveBeenCalledWith<[EntityRef]>({
      kind: 'ip',
      value: ACTOR.source_ip,
    })
  })

  it('investigate openEntity call uses the correct IP value', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'investigate')

    const ref = openEntity.mock.calls[0][0] as EntityRef
    expect(ref.kind).toBe('ip')
    expect(ref.value).toBe('192.0.2.1')
  })

  it('investigate does NOT navigate (no route navigation — issue #204)', () => {
    // navigate is deprecated in the callbacks but we pass it to confirm it is not called.
    const openEntity = vi.fn()
    const navigate = vi.fn()
    const onAction = makeOnAction({ openEntity, navigate })

    onAction(ACTOR, 'investigate')

    expect(navigate).not.toHaveBeenCalled()
  })

  it('investigate does NOT add actor to dismissed set', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'investigate')

    expect(isDismissed(ACTOR)).toBe(false)
  })

  it('investigate does NOT call onDismiss or onBlock', () => {
    const openEntity = vi.fn()
    const onDismiss = vi.fn()
    const onBlock = vi.fn()
    const onAction = makeOnAction({ openEntity, onDismiss, onBlock })

    onAction(ACTOR, 'investigate')

    expect(onDismiss).not.toHaveBeenCalled()
    expect(onBlock).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// 3. Event-driven: acknowledge → suppress with re-surface on material change (#727)
// ---------------------------------------------------------------------------

describe('triageActions — acknowledge verb (issue #727 EARS-1/2)', () => {
  it('WHEN acknowledge fires, isDismissed returns true (actor is suppressed)', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    expect(isDismissed(ACTOR)).toBe(false)
    onAction(ACTOR, 'acknowledge')
    expect(isDismissed(ACTOR)).toBe(true)
  })

  it('WHEN acknowledge fires, the onDismiss callback is called with the actor', () => {
    const openEntity = vi.fn()
    const onDismiss = vi.fn()
    const onAction = makeOnAction({ openEntity, onDismiss })

    onAction(ACTOR, 'acknowledge')

    expect(onDismiss).toHaveBeenCalledOnce()
    expect(onDismiss).toHaveBeenCalledWith(ACTOR)
  })

  it('acknowledge does NOT call openEntity', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'acknowledge')

    expect(openEntity).not.toHaveBeenCalled()
  })

  it('acknowledge does NOT call onBlock', () => {
    const openEntity = vi.fn()
    const onBlock = vi.fn()
    const onAction = makeOnAction({ openEntity, onBlock })

    onAction(ACTOR, 'acknowledge')

    expect(onBlock).not.toHaveBeenCalled()
  })

  // EARS-2: acknowledged actor re-surfaces on material score increase
  it('EARS-2: acknowledged actor re-surfaces when score increases by >= MATERIAL_SCORE_DELTA', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'acknowledge')
    expect(isDismissed(ACTOR)).toBe(true)

    // Simulate a material score increase.
    const actorAfterEscalation: ThreatScore = {
      ...ACTOR,
      score: ACTOR.score + MATERIAL_SCORE_DELTA,
    }
    // reconcileAcknowledged runs the eviction on the data-refresh path (issue #755):
    // it detects the material change and removes the actor from the acknowledged store.
    reconcileAcknowledged([actorAfterEscalation])
    // After reconciliation, isDismissed is now false (actor re-surfaces).
    expect(isDismissed(actorAfterEscalation)).toBe(false)
  })

  it('EARS-2: acknowledged actor stays suppressed when score increases by < MATERIAL_SCORE_DELTA', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'acknowledge')

    const actorWithMinorIncrease: ThreatScore = {
      ...ACTOR,
      score: ACTOR.score + MATERIAL_SCORE_DELTA - 1,
    }
    expect(isDismissed(actorWithMinorIncrease)).toBe(true)
  })

  // EARS-2: acknowledged actor re-surfaces on block_status flip (blocked → allowed)
  it('EARS-2: acknowledged actor re-surfaces when block_status flips blocked→allowed', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    const actorBlocked: ThreatScore = {
      ...ACTOR,
      escalation: {
        tier: 3,
        disposition: 'blocked_persistent',
        justification: '[RULE] Blocked',
        block_status: 'blocked',
      },
    }
    onAction(actorBlocked, 'acknowledge')
    expect(isDismissed(actorBlocked)).toBe(true)

    const actorNowAllowed: ThreatScore = {
      ...actorBlocked,
      escalation: {
        ...actorBlocked.escalation!,
        block_status: 'allowed',
      },
    }
    // reconcileAcknowledged evicts the stale acknowledged entry on data-refresh (issue #755).
    reconcileAcknowledged([actorNowAllowed])
    expect(isDismissed(actorNowAllowed)).toBe(false)
  })

  // EARS-2: acknowledged actor re-surfaces on tier decrease
  it('EARS-2: acknowledged actor re-surfaces when tier decreases (louder = more urgent)', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    const actorTier3: ThreatScore = {
      ...ACTOR,
      escalation: {
        tier: 3,
        disposition: 'blocked_persistent',
        justification: '[RULE] Blocked',
        block_status: 'blocked',
      },
    }
    onAction(actorTier3, 'acknowledge')
    expect(isDismissed(actorTier3)).toBe(true)

    const actorNowTier1: ThreatScore = {
      ...actorTier3,
      escalation: {
        ...actorTier3.escalation!,
        tier: 1,
      },
    }
    // reconcileAcknowledged evicts the stale acknowledged entry on data-refresh (issue #755).
    reconcileAcknowledged([actorNowTier1])
    expect(isDismissed(actorNowTier1)).toBe(false)
  })

  // localStorage persistence: acknowledged actor survives a simulated reload
  it('EARS-1: acknowledged state persists in localStorage (survives reload)', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'acknowledge')

    // Verify it's stored in localStorage
    const raw = localStorage.getItem(ACKNOWLEDGED_ACTORS_KEY)
    expect(raw).not.toBeNull()
    const parsed: unknown = JSON.parse(raw!)
    expect(parsed).toHaveProperty(ACTOR.source_ip)
    // After "reload" isDismissed still returns true (reads localStorage)
    expect(isDismissed(ACTOR)).toBe(true)
  })

  // Acknowledge with a snapshot captures the correct state
  it('snapshotOf captures score, tier, and blockStatus correctly', () => {
    const actorWithEsc: ThreatScore = {
      ...ACTOR,
      score: 80,
      escalation: {
        tier: 2,
        disposition: 'block_status_unknown',
        justification: '[RULE] Test',
        block_status: 'unknown',
      },
    }
    const snap: AcknowledgedSnapshot = snapshotOf(actorWithEsc)
    expect(snap.score).toBe(80)
    expect(snap.tier).toBe(2)
    expect(snap.blockStatus).toBe('unknown')
  })

  it('snapshotOf returns null for tier and blockStatus when escalation is absent', () => {
    const actorNoEsc: ThreatScore = { ...ACTOR, escalation: undefined }
    const snap: AcknowledgedSnapshot = snapshotOf(actorNoEsc)
    expect(snap.score).toBe(ACTOR.score)
    expect(snap.tier).toBeNull()
    expect(snap.blockStatus).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// 4. Event-driven: dismiss → stronger suppression, no re-surface (#727 EARS-3)
// ---------------------------------------------------------------------------

describe('triageActions — dismiss verb (issue #727 EARS-3)', () => {
  it('WHEN dismiss fires, isDismissed returns true for that actor', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    expect(isDismissed(ACTOR)).toBe(false)
    onAction(ACTOR, 'dismiss')
    expect(isDismissed(ACTOR)).toBe(true)
  })

  it('WHEN dismiss fires, the onDismiss callback is called with the actor', () => {
    const openEntity = vi.fn()
    const onDismiss = vi.fn()
    const onAction = makeOnAction({ openEntity, onDismiss })

    onAction(ACTOR, 'dismiss')

    expect(onDismiss).toHaveBeenCalledOnce()
    expect(onDismiss).toHaveBeenCalledWith(ACTOR)
  })

  // EARS-3: dismiss does NOT re-surface on material change (stronger than acknowledge)
  it('EARS-3: dismissed actor does NOT re-surface even after material score increase', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'dismiss')

    const actorWithBigScoreIncrease: ThreatScore = {
      ...ACTOR,
      score: ACTOR.score + MATERIAL_SCORE_DELTA * 10, // very large increase
    }
    // Dismissed (not acknowledged) — still suppressed regardless
    expect(isDismissed(actorWithBigScoreIncrease)).toBe(true)
  })

  it('EARS-3: dismissed actor does NOT re-surface on block_status flip', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    const actorBlocked: ThreatScore = {
      ...ACTOR,
      escalation: {
        tier: 3,
        disposition: 'blocked_persistent',
        justification: '[RULE] Blocked',
        block_status: 'blocked',
      },
    }
    onAction(actorBlocked, 'dismiss')

    const actorNowAllowed: ThreatScore = {
      ...actorBlocked,
      escalation: {
        ...actorBlocked.escalation!,
        block_status: 'allowed',
      },
    }
    // dismiss = no re-surface
    expect(isDismissed(actorNowAllowed)).toBe(true)
  })

  // localStorage persistence for dismiss
  it('EARS-1: dismissed state persists in localStorage', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'dismiss')

    const raw = localStorage.getItem(DISMISSED_ACTORS_KEY)
    expect(raw).not.toBeNull()
    const arr = JSON.parse(raw!) as string[]
    expect(arr).toContain(ACTOR.source_ip)
    // Still suppressed (simulates reload)
    expect(isDismissed(ACTOR)).toBe(true)
  })

  // Dismiss upgrades acknowledge: if acknowledged, dismiss removes from ack store
  it('dismiss promotes an acknowledged actor to the dismissed store', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    // First acknowledge
    onAction(ACTOR, 'acknowledge')
    // Now verify it's in the ack store
    const ackRaw = localStorage.getItem(ACKNOWLEDGED_ACTORS_KEY)
    expect(JSON.parse(ackRaw!)).toHaveProperty(ACTOR.source_ip)

    // Now dismiss — should move out of ack and into dismissed
    onAction(ACTOR, 'dismiss')
    const ackAfter = localStorage.getItem(ACKNOWLEDGED_ACTORS_KEY)
    expect(JSON.parse(ackAfter!)).not.toHaveProperty(ACTOR.source_ip)
    const dismissRaw = localStorage.getItem(DISMISSED_ACTORS_KEY)
    expect(JSON.parse(dismissRaw!) as string[]).toContain(ACTOR.source_ip)
  })

  it('dismiss does NOT call openEntity (no slide-over side-effect)', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'dismiss')

    expect(openEntity).not.toHaveBeenCalled()
  })

  it('dismiss does NOT call onBlock', () => {
    const openEntity = vi.fn()
    const onBlock = vi.fn()
    const onAction = makeOnAction({ openEntity, onBlock })

    onAction(ACTOR, 'dismiss')

    expect(onBlock).not.toHaveBeenCalled()
  })

  it('a second dismiss on the same actor is idempotent (still dismissed)', () => {
    const openEntity = vi.fn()
    const onDismiss = vi.fn()
    const onAction = makeOnAction({ openEntity, onDismiss })

    onAction(ACTOR, 'dismiss')
    onAction(ACTOR, 'dismiss')

    expect(isDismissed(ACTOR)).toBe(true)
  })

  it('dismiss is actor-scoped — a different IP remains undismissed', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })
    const otherActor: ThreatScore = { ...ACTOR, source_ip: '10.0.0.99' }

    onAction(ACTOR, 'dismiss')

    expect(isDismissed(ACTOR)).toBe(true)
    expect(isDismissed(otherActor)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// 5. hasMaterialChange — material change detection unit tests (#727 EARS-2)
// ---------------------------------------------------------------------------

describe('hasMaterialChange (issue #727 EARS-2 — material change definition)', () => {
  const BASE_SNAP: AcknowledgedSnapshot = {
    score: 80,
    tier: 3,
    blockStatus: 'blocked',
  }

  it('returns false when actor is identical to the snapshot', () => {
    const actor: ThreatScore = {
      ...ACTOR,
      score: 80,
      escalation: { tier: 3, disposition: 'blocked_persistent', justification: '', block_status: 'blocked' },
    }
    expect(hasMaterialChange(actor, BASE_SNAP)).toBe(false)
  })

  it('returns true when score increases by exactly MATERIAL_SCORE_DELTA', () => {
    const actor: ThreatScore = {
      ...ACTOR,
      score: 80 + MATERIAL_SCORE_DELTA,
      escalation: { tier: 3, disposition: 'blocked_persistent', justification: '', block_status: 'blocked' },
    }
    expect(hasMaterialChange(actor, BASE_SNAP)).toBe(true)
  })

  it('returns false when score increases by less than MATERIAL_SCORE_DELTA', () => {
    const actor: ThreatScore = {
      ...ACTOR,
      score: 80 + MATERIAL_SCORE_DELTA - 1,
      escalation: { tier: 3, disposition: 'blocked_persistent', justification: '', block_status: 'blocked' },
    }
    expect(hasMaterialChange(actor, BASE_SNAP)).toBe(false)
  })

  it('returns true when block_status flips from blocked to allowed', () => {
    const actor: ThreatScore = {
      ...ACTOR,
      score: 80,
      escalation: { tier: 3, disposition: 'blocked_persistent', justification: '', block_status: 'allowed' },
    }
    expect(hasMaterialChange(actor, BASE_SNAP)).toBe(true)
  })

  it('returns true when block_status flips from allowed to blocked', () => {
    const snapAllowed: AcknowledgedSnapshot = { ...BASE_SNAP, blockStatus: 'allowed' }
    const actor: ThreatScore = {
      ...ACTOR,
      score: 80,
      escalation: { tier: 3, disposition: 'blocked_persistent', justification: '', block_status: 'blocked' },
    }
    expect(hasMaterialChange(actor, snapAllowed)).toBe(true)
  })

  it('returns true when tier decreases (louder / more urgent)', () => {
    const actor: ThreatScore = {
      ...ACTOR,
      score: 80,
      escalation: { tier: 1, disposition: 'allowed_through', justification: '', block_status: 'allowed' },
    }
    // tier 3 → 1 = decrease = material change
    expect(hasMaterialChange(actor, BASE_SNAP)).toBe(true)
  })

  it('returns false when tier increases (less urgent)', () => {
    const actor: ThreatScore = {
      ...ACTOR,
      score: 80,
      escalation: { tier: 4, disposition: 'blocked_one_off', justification: '', block_status: 'blocked' },
    }
    // tier 3 → 4 = increase = NOT material
    expect(hasMaterialChange(actor, BASE_SNAP)).toBe(false)
  })

  it('returns false when snap has no tier and actor has no tier (no change)', () => {
    const snapNoTier: AcknowledgedSnapshot = { score: 80, tier: null, blockStatus: null }
    const actor: ThreatScore = { ...ACTOR, score: 80, escalation: null }
    expect(hasMaterialChange(actor, snapNoTier)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// 6. Event-driven: block → record decision / raise alert (SIEM), NOT execute
// ---------------------------------------------------------------------------

describe('triageActions — block verb', () => {
  it('WHEN block fires, the onBlock callback is called with the actor', () => {
    const openEntity = vi.fn()
    const onBlock = vi.fn()
    const onAction = makeOnAction({ openEntity, onBlock })

    onAction(ACTOR, 'block')

    expect(onBlock).toHaveBeenCalledOnce()
    expect(onBlock).toHaveBeenCalledWith(ACTOR)
  })

  it('WHEN block fires, the actor is removed from triage (isDismissed → true)', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    expect(isDismissed(ACTOR)).toBe(false)
    onAction(ACTOR, 'block')
    expect(isDismissed(ACTOR)).toBe(true)
  })

  it('block does NOT call openEntity (no slide-over opened on block)', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'block')

    expect(openEntity).not.toHaveBeenCalled()
  })

  it('block does NOT call global fetch (no enforcement API call in MH)', () => {
    // Assert that no HTTP request is fired — enforcement is deferred to SOAR.
    const openEntity = vi.fn()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'block')

    expect(fetchSpy).not.toHaveBeenCalled()
    fetchSpy.mockRestore()
  })

  it('block without optional callbacks does not throw (callbacks are optional)', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })
    expect(() => onAction(ACTOR, 'block')).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// 7. isDismissed / clearDismissed utility
// ---------------------------------------------------------------------------

describe('triageActions — isDismissed / clearDismissed', () => {
  it('isDismissed is false for a fresh actor', () => {
    expect(isDismissed(ACTOR)).toBe(false)
  })

  it('clearDismissed resets state — isDismissed becomes false again after dismiss', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'dismiss')
    expect(isDismissed(ACTOR)).toBe(true)

    clearDismissed()
    expect(isDismissed(ACTOR)).toBe(false)
  })

  it('clearDismissed resets state — isDismissed becomes false again after acknowledge', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'acknowledge')
    expect(isDismissed(ACTOR)).toBe(true)

    clearDismissed()
    expect(isDismissed(ACTOR)).toBe(false)
  })

  it('clearDismissed removes both dismissed and acknowledged keys from localStorage', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'acknowledge')
    onAction({ ...ACTOR, source_ip: '10.0.0.1' }, 'dismiss')

    clearDismissed()

    expect(localStorage.getItem(DISMISSED_ACTORS_KEY)).toBeNull()
    expect(localStorage.getItem(ACKNOWLEDGED_ACTORS_KEY)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// 7b. isDismissed purity (issue #755 EARS-1)
//
// After the in-memory cache is warm (first call initializes from localStorage),
// subsequent calls to isDismissed MUST NOT touch localStorage at all.
// ---------------------------------------------------------------------------

describe('triageActions — isDismissed is pure after warm-up (issue #755 EARS-1)', () => {
  it('isDismissed does not call localStorage.getItem after the cache is warm', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    // Warm up the cache: dismiss an actor so both stores are initialized.
    onAction(ACTOR, 'dismiss')
    // The above write (addDismissed) calls setItem — reset spy AFTER the warm-up.
    const getSpy = vi.spyOn(Storage.prototype, 'getItem')
    const setSpy = vi.spyOn(Storage.prototype, 'setItem')

    // isDismissed is now a pure in-memory lookup.
    isDismissed(ACTOR)
    isDismissed({ ...ACTOR, source_ip: '10.0.0.1' })

    expect(getSpy).not.toHaveBeenCalled()
    expect(setSpy).not.toHaveBeenCalled()

    getSpy.mockRestore()
    setSpy.mockRestore()
  })

  it('isDismissed does not call localStorage.getItem/setItem for an acknowledged actor', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    // Warm up: acknowledge an actor (initializes acknowledged map + writes once).
    onAction(ACTOR, 'acknowledge')
    // Reset spy AFTER the warm-up mutation.
    const getSpy = vi.spyOn(Storage.prototype, 'getItem')
    const setSpy = vi.spyOn(Storage.prototype, 'setItem')

    // Pure in-memory lookup — should hit neither getItem nor setItem.
    isDismissed(ACTOR)

    expect(getSpy).not.toHaveBeenCalled()
    expect(setSpy).not.toHaveBeenCalled()

    getSpy.mockRestore()
    setSpy.mockRestore()
  })
})

// ---------------------------------------------------------------------------
// 7c. reconcileAcknowledged — material-change eviction on data-refresh path
//     (issue #755: eviction moved OUT of isDismissed, into reconcile)
// ---------------------------------------------------------------------------

describe('triageActions — reconcileAcknowledged (issue #755)', () => {
  it('returns false and makes no changes when no acknowledged actors are present', () => {
    const result = reconcileAcknowledged([ACTOR])
    expect(result).toBe(false)
  })

  it('returns false when acknowledged actor has NOT had a material change', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })
    onAction(ACTOR, 'acknowledge')

    const actorUnchanged: ThreatScore = { ...ACTOR, score: ACTOR.score + MATERIAL_SCORE_DELTA - 1 }
    const result = reconcileAcknowledged([actorUnchanged])
    expect(result).toBe(false)
    // Actor still suppressed.
    expect(isDismissed(actorUnchanged)).toBe(true)
  })

  it('returns true and evicts actor with material score increase', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })
    onAction(ACTOR, 'acknowledge')

    const actorEscalated: ThreatScore = { ...ACTOR, score: ACTOR.score + MATERIAL_SCORE_DELTA }
    const result = reconcileAcknowledged([actorEscalated])
    expect(result).toBe(true)
    // Evicted — actor re-surfaces.
    expect(isDismissed(actorEscalated)).toBe(false)
  })

  it('evicts actor with block_status flip and updates localStorage', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })
    const actorBlocked: ThreatScore = {
      ...ACTOR,
      escalation: { tier: 3, disposition: 'blocked_persistent', justification: '', block_status: 'blocked' },
    }
    onAction(actorBlocked, 'acknowledge')

    const actorAllowed: ThreatScore = {
      ...actorBlocked,
      escalation: { ...actorBlocked.escalation!, block_status: 'allowed' },
    }
    reconcileAcknowledged([actorAllowed])
    expect(isDismissed(actorAllowed)).toBe(false)
    // Confirm localStorage is updated too.
    const raw = localStorage.getItem(ACKNOWLEDGED_ACTORS_KEY)
    const parsed = JSON.parse(raw ?? '{}') as Record<string, unknown>
    expect(Object.keys(parsed)).not.toContain(ACTOR.source_ip)
  })

  it('does not evict a dismissed (hard-dismissed) actor — reconcile only touches acknowledged', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })
    onAction(ACTOR, 'dismiss')

    // reconcileAcknowledged does not touch the dismissed set.
    const actorEscalated: ThreatScore = { ...ACTOR, score: ACTOR.score + MATERIAL_SCORE_DELTA * 10 }
    reconcileAcknowledged([actorEscalated])
    // Still hard-dismissed.
    expect(isDismissed(actorEscalated)).toBe(true)
  })

  it('only evicts actors with material changes — non-material ones remain acknowledged', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })
    const actor2: ThreatScore = { ...ACTOR, source_ip: '10.0.0.2' }
    onAction(ACTOR, 'acknowledge')
    onAction(actor2, 'acknowledge')

    // Only ACTOR has material change; actor2 stays below threshold.
    const actorEscalated: ThreatScore = { ...ACTOR, score: ACTOR.score + MATERIAL_SCORE_DELTA }
    const actor2Unchanged: ThreatScore = { ...actor2, score: actor2.score + MATERIAL_SCORE_DELTA - 1 }
    reconcileAcknowledged([actorEscalated, actor2Unchanged])

    expect(isDismissed(actorEscalated)).toBe(false) // re-surfaced
    expect(isDismissed(actor2Unchanged)).toBe(true) // still suppressed
  })
})

// ---------------------------------------------------------------------------
// 8. N-2 — isValidIpFormat guard (issue #171)
// ---------------------------------------------------------------------------

describe('triageActions — isValidIpFormat (N-2, issue #171)', () => {
  it('accepts valid IPv4 addresses', () => {
    expect(isValidIpFormat('192.0.2.1')).toBe(true)
    expect(isValidIpFormat('10.0.0.1')).toBe(true)
    expect(isValidIpFormat('255.255.255.255')).toBe(true)
    expect(isValidIpFormat('0.0.0.0')).toBe(true)
  })

  it('accepts valid IPv6 addresses', () => {
    expect(isValidIpFormat('2001:db8::1')).toBe(true)
    expect(isValidIpFormat('::1')).toBe(true)
    expect(isValidIpFormat('fe80::1')).toBe(true)
    expect(isValidIpFormat('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe(true)
  })

  it('rejects empty string', () => {
    expect(isValidIpFormat('')).toBe(false)
  })

  it('rejects a hostname', () => {
    expect(isValidIpFormat('evil.example.com')).toBe(false)
  })

  it('rejects a URL-shaped string', () => {
    expect(isValidIpFormat('http://malicious.example')).toBe(false)
  })

  it('rejects an excessively long string', () => {
    expect(isValidIpFormat('A'.repeat(256))).toBe(false)
  })

  it('rejects strings with spaces', () => {
    expect(isValidIpFormat('192.0.2.1 ')).toBe(false)
    expect(isValidIpFormat(' 192.0.2.1')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// 9. N-2 — malformed source_ip is rejected by the guard (issue #171)
//    Verifies the guard fires in makeOnAction, not just in isValidIpFormat.
// ---------------------------------------------------------------------------

describe('triageActions — malformed source_ip rejected at action time (N-2)', () => {
  it('investigate is a no-op when source_ip is malformed', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })
    const badActor: ThreatScore = { ...ACTOR, source_ip: 'not-an-ip' }

    onAction(badActor, 'investigate')

    expect(openEntity).not.toHaveBeenCalled()
  })

  it('acknowledge is a no-op when source_ip is malformed — isDismissed stays false', () => {
    const openEntity = vi.fn()
    const onDismiss = vi.fn()
    const onAction = makeOnAction({ openEntity, onDismiss })
    const badActor: ThreatScore = { ...ACTOR, source_ip: 'evil.example.com' }

    onAction(badActor, 'acknowledge')

    expect(onDismiss).not.toHaveBeenCalled()
    expect(isDismissed(badActor)).toBe(false)
  })

  it('dismiss is a no-op when source_ip is malformed — isDismissed stays false', () => {
    const openEntity = vi.fn()
    const onDismiss = vi.fn()
    const onAction = makeOnAction({ openEntity, onDismiss })
    const badActor: ThreatScore = { ...ACTOR, source_ip: 'evil.example.com' }

    onAction(badActor, 'dismiss')

    expect(onDismiss).not.toHaveBeenCalled()
    expect(isDismissed(badActor)).toBe(false)
  })

  it('block is a no-op when source_ip is malformed — onBlock is not called', () => {
    const openEntity = vi.fn()
    const onBlock = vi.fn()
    const onAction = makeOnAction({ openEntity, onBlock })
    const badActor: ThreatScore = { ...ACTOR, source_ip: 'http://malicious.example' }

    onAction(badActor, 'block')

    expect(onBlock).not.toHaveBeenCalled()
    expect(isDismissed(badActor)).toBe(false)
  })

  it('malformed IP not stored in localStorage after acknowledge', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })
    const badActor: ThreatScore = { ...ACTOR, source_ip: 'not-an-ip' }

    onAction(badActor, 'acknowledge')

    const raw = localStorage.getItem(ACKNOWLEDGED_ACTORS_KEY)
    if (raw != null) {
      const parsed = JSON.parse(raw) as Record<string, unknown>
      expect(Object.keys(parsed)).not.toContain('not-an-ip')
    }
    // Either null (never written) or doesn't contain the bad IP
  })
})

// ---------------------------------------------------------------------------
// 10. N-1 — boundedactor stores with FIFO eviction at DISMISSED_ACTORS_CAP (#171, #727)
// ---------------------------------------------------------------------------

describe('triageActions — capped dismissed-actors Set (N-1, issue #171 + #727)', () => {
  it('dismissed store evicts the oldest entry when the cap is reached', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    const firstIp = '10.0.0.0'
    const firstActor: ThreatScore = { ...ACTOR, source_ip: firstIp }

    // Add the first actor.
    onAction(firstActor, 'dismiss')
    expect(isDismissed(firstActor)).toBe(true)

    // Fill the remaining cap - 1 slots with distinct IPs.
    for (let i = 1; i < DISMISSED_ACTORS_CAP; i++) {
      const a = Math.floor(i / (256 * 256)) % 256
      const b = Math.floor(i / 256) % 256
      const c = i % 256
      const ip = `10.${a}.${b}.${c}`
      onAction({ ...ACTOR, source_ip: ip }, 'dismiss')
    }

    // At this point firstActor is still present (set is exactly at cap).
    expect(isDismissed(firstActor)).toBe(true)

    // Adding one more entry should evict the oldest (firstActor).
    const overflowActor: ThreatScore = { ...ACTOR, source_ip: '192.168.99.1' }
    onAction(overflowActor, 'dismiss')

    expect(isDismissed(firstActor)).toBe(false) // evicted
    expect(isDismissed(overflowActor)).toBe(true) // newly added
  })

  it('dismissing the same actor twice does not grow the store past cap', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    // Fill the store to the cap.
    for (let i = 0; i < DISMISSED_ACTORS_CAP; i++) {
      const a = Math.floor(i / (256 * 256)) % 256
      const b = Math.floor(i / 256) % 256
      const c = i % 256
      onAction({ ...ACTOR, source_ip: `10.${a}.${b}.${c}` }, 'dismiss')
    }

    // Re-dismissing an existing actor should be a no-op (already in store).
    const existingActor: ThreatScore = { ...ACTOR, source_ip: '10.0.0.0' }
    onAction(existingActor, 'dismiss') // already present — should not evict anything

    // The actor we just re-dismissed should still be tracked.
    expect(isDismissed(existingActor)).toBe(true)
  })

  it('EARS-4: bounded-cap invariant is preserved across localStorage round-trip (persistence)', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    // Fill the store to cap via dismiss.
    for (let i = 0; i < DISMISSED_ACTORS_CAP; i++) {
      const a = Math.floor(i / (256 * 256)) % 256
      const b = Math.floor(i / 256) % 256
      const c = i % 256
      onAction({ ...ACTOR, source_ip: `10.${a}.${b}.${c}` }, 'dismiss')
    }

    // The raw localStorage array should not exceed DISMISSED_ACTORS_CAP entries.
    const raw = localStorage.getItem(DISMISSED_ACTORS_KEY)
    const arr = JSON.parse(raw!) as string[]
    expect(arr.length).toBeLessThanOrEqual(DISMISSED_ACTORS_CAP)
  })
})
