/**
 * Tests for frontend/src/lib/triageActions.ts — the action seam (ADR-0033, issue #158),
 * shrunk per ADR-0072 D7's retire list (issue #47 Part 2/frontend).
 *
 * Updated for MH (issue #204, ADR-0037):
 *   investigate → openEntity({kind:'ip', value}) — opens the entity slide-over.
 *   No route navigation on investigate.
 *
 * Updated for issue #47 (ADR-0072 D3/D6/D7) — server-side persistence:
 *   - `acknowledge` is retired: removed from ThreatActionVerb, no branch, no
 *     localStorage acknowledged-store semantics.
 *   - `dismiss`/`block` persist via `POST /decisions` (createDecision,
 *     mocked here) instead of a localStorage write — isDismissed,
 *     reconcileAcknowledged, hasMaterialChange, snapshotOf, clearDismissed,
 *     and both localStorage keys are RETIRED from this module (they survive
 *     only inside lib/triageDecisions.ts's migration reader — see that
 *     module's own tests).
 *   - Persistence is best-effort: a rejected createDecision call is caught
 *     and logged, never thrown back at the caller.
 *
 * EARS criteria mapped to tests:
 *
 * Ubiquitous: the action seam SHALL expose exactly one entrypoint `onAction(actor, verb)`.
 *   → test: onAction is a function with arity 2, created by makeOnAction
 *
 * Event-driven: WHEN `onAction(actor, "investigate")` fires, the slide-over SHALL open
 * for that actor's IP (ADR-0037); no route navigation SHALL occur; no decision persists.
 *
 * Event-driven: WHEN `onAction(actor, "dismiss")` fires, a `dismissed` decision SHALL be
 * recorded via `POST /decisions {actor_ip, verb: 'dismissed'}` (ADR-0072 D3) — the client
 * never self-reports decided_tier/decided_score.
 *
 * Event-driven: WHEN `onAction(actor, "block")` fires, the UI SHALL record the block
 * decision (persisted the same way as dismiss — ADR-0072's store vocabulary has no
 * separate "block" verb) and SHALL NOT attempt to execute an enforcement action.
 *
 * Event-driven: WHEN the `POST /decisions` call fails, the failure SHALL be swallowed
 * (logged, not thrown) — a persistence failure must not break the SIEM action.
 *
 * N-2 (issue #171): malformed source_ip is rejected by the guard before any network call.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { makeOnAction, isValidIpFormat, type ThreatActionVerb, type OnAction } from '../lib/triageActions'
import type { ThreatScore } from '../api/types'
import type { EntityRef } from '../components/entity/EntityPanelContext'

// ---------------------------------------------------------------------------
// Mock the decisions API client — triageActions.ts calls createDecision
// directly for dismiss/block (ADR-0072 D3).
// ---------------------------------------------------------------------------

const { mockCreateDecision } = vi.hoisted(() => ({
  mockCreateDecision: vi.fn(),
}))

vi.mock('../api/decisions', () => ({
  createDecision: mockCreateDecision,
}))

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
  triage_decision: null,
}

beforeEach(() => {
  mockCreateDecision.mockReset()
  mockCreateDecision.mockResolvedValue({
    id: 1,
    actor_ip: ACTOR.source_ip,
    verb: 'dismissed',
    rule_name: null,
    decided_tier: null,
    decided_score: 0,
    decided_at: '2026-07-17T00:00:00Z',
    revoked_at: null,
    author: 'local operator',
    note: null,
  })
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
    expect(() => onAction(ACTOR, 'investigate')).not.toThrow()
  })

  it('verb type is the union "block" | "investigate" | "dismiss" — acknowledge retired (ADR-0072 D6)', () => {
    const verbs: ThreatActionVerb[] = ['block', 'investigate', 'dismiss']
    expect(verbs).toHaveLength(3)
    expect(verbs).toContain('block')
    expect(verbs).toContain('investigate')
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

  it('investigate does NOT navigate (no route navigation — issue #204)', () => {
    const openEntity = vi.fn()
    const navigate = vi.fn()
    const onAction = makeOnAction({ openEntity, navigate })

    onAction(ACTOR, 'investigate')

    expect(navigate).not.toHaveBeenCalled()
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

  it('investigate does NOT persist any decision (no createDecision call)', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'investigate')

    expect(mockCreateDecision).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// 3. Event-driven: dismiss → persists a 'dismissed' decision server-side
//    (ADR-0072 D3, issue #47)
// ---------------------------------------------------------------------------

describe('triageActions — dismiss verb (ADR-0072 D3, issue #47)', () => {
  it('WHEN dismiss fires, POST /decisions is called with {actor_ip, verb: "dismissed"}', async () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    await onAction(ACTOR, 'dismiss')

    expect(mockCreateDecision).toHaveBeenCalledOnce()
    expect(mockCreateDecision).toHaveBeenCalledWith({
      actor_ip: ACTOR.source_ip,
      verb: 'dismissed',
    })
  })

  it('dismiss never sends decided_tier/decided_score (server is the sole snapshot authority)', async () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    await onAction(ACTOR, 'dismiss')

    const body = mockCreateDecision.mock.calls[0][0] as Record<string, unknown>
    expect(body).not.toHaveProperty('decided_tier')
    expect(body).not.toHaveProperty('decided_score')
  })

  it('WHEN dismiss fires, the onDismiss callback is called with the actor (synchronously)', () => {
    const openEntity = vi.fn()
    const onDismiss = vi.fn()
    const onAction = makeOnAction({ openEntity, onDismiss })

    onAction(ACTOR, 'dismiss')

    expect(onDismiss).toHaveBeenCalledOnce()
    expect(onDismiss).toHaveBeenCalledWith(ACTOR)
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

  it('a second dismiss on the same actor persists a second decision call (append-only, ADR-0072 D2)', async () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    await onAction(ACTOR, 'dismiss')
    await onAction(ACTOR, 'dismiss')

    expect(mockCreateDecision).toHaveBeenCalledTimes(2)
  })

  it('dismiss is actor-scoped — persists the correct source_ip per actor', async () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })
    const otherActor: ThreatScore = { ...ACTOR, source_ip: '10.0.0.99' }

    await onAction(ACTOR, 'dismiss')
    await onAction(otherActor, 'dismiss')

    expect(mockCreateDecision).toHaveBeenNthCalledWith(1, { actor_ip: '192.0.2.1', verb: 'dismissed' })
    expect(mockCreateDecision).toHaveBeenNthCalledWith(2, { actor_ip: '10.0.0.99', verb: 'dismissed' })
  })

  it('a rejected createDecision is swallowed — dismiss does not throw', async () => {
    mockCreateDecision.mockRejectedValueOnce(new Error('network error'))
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

    await expect(onAction(ACTOR, 'dismiss')).resolves.toBeUndefined()
    expect(warnSpy).toHaveBeenCalled()

    warnSpy.mockRestore()
  })
})

// ---------------------------------------------------------------------------
// 4. Event-driven: block → record decision / raise alert (SIEM), NOT execute
//    (persisted the same way as dismiss — ADR-0072 has no separate "block" verb)
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

  it('WHEN block fires, POST /decisions is called with verb: "dismissed" (consumes the queue entry)', async () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    await onAction(ACTOR, 'block')

    expect(mockCreateDecision).toHaveBeenCalledWith({
      actor_ip: ACTOR.source_ip,
      verb: 'dismissed',
    })
  })

  it('block does NOT call openEntity (no slide-over opened on block)', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })

    onAction(ACTOR, 'block')

    expect(openEntity).not.toHaveBeenCalled()
  })

  it('block does NOT call global fetch directly (enforcement deferred to SOAR)', () => {
    // Assert no raw fetch is fired by triageActions itself — persistence goes
    // through the mocked createDecision, never a direct fetch call.
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
// 5. N-2 — isValidIpFormat guard (issue #171)
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
// 6. N-2 — malformed source_ip is rejected at action time, before any network
//    call (issue #171)
// ---------------------------------------------------------------------------

describe('triageActions — malformed source_ip rejected at action time (N-2)', () => {
  it('investigate is a no-op when source_ip is malformed', () => {
    const openEntity = vi.fn()
    const onAction = makeOnAction({ openEntity })
    const badActor: ThreatScore = { ...ACTOR, source_ip: 'not-an-ip' }

    onAction(badActor, 'investigate')

    expect(openEntity).not.toHaveBeenCalled()
  })

  it('dismiss is a no-op when source_ip is malformed — no createDecision call, no onDismiss', () => {
    const openEntity = vi.fn()
    const onDismiss = vi.fn()
    const onAction = makeOnAction({ openEntity, onDismiss })
    const badActor: ThreatScore = { ...ACTOR, source_ip: 'evil.example.com' }

    onAction(badActor, 'dismiss')

    expect(onDismiss).not.toHaveBeenCalled()
    expect(mockCreateDecision).not.toHaveBeenCalled()
  })

  it('block is a no-op when source_ip is malformed — onBlock is not called, no persistence', () => {
    const openEntity = vi.fn()
    const onBlock = vi.fn()
    const onAction = makeOnAction({ openEntity, onBlock })
    const badActor: ThreatScore = { ...ACTOR, source_ip: 'http://malicious.example' }

    onAction(badActor, 'block')

    expect(onBlock).not.toHaveBeenCalled()
    expect(mockCreateDecision).not.toHaveBeenCalled()
  })
})
