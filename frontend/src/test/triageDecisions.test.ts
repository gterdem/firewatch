/**
 * Tests for frontend/src/lib/triageDecisions.ts — issue #47 Part 2/frontend,
 * ADR-0072 D3/D6.
 *
 * EARS criteria mapped to tests:
 *
 * - WHEN localStorage carries pre-#47 dismissed entries, migrateLocalStorageDecisions
 *   SHALL push each as a best-effort `POST /decisions {verb:'dismissed'}` exactly once
 *   across repeated calls (one-shot).
 *   → describe('migrateLocalStorageDecisions — one-shot push')
 * - WHEN localStorage carries acknowledged entries, they SHALL NOT be migrated
 *   (ADR-0072 D6) — only the dismissed array is read for migration.
 *   → describe('migrateLocalStorageDecisions — acknowledged entries are not migrated')
 * - WHEN a createDecision call fails, the migration SHALL NOT throw (best-effort).
 *   → 'tolerates a rejected createDecision call'
 * - WHEN triage_decision.suppressed is true, isSuppressed SHALL return true; when
 *   false/absent, isSuppressed SHALL return false — reading ONLY the server field
 *   (retire-list regression: no localStorage read).
 *   → describe('isSuppressed — the ADR-0072 D3 queue-membership predicate')
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  migrateLocalStorageDecisions,
  isSuppressed,
  DISMISSED_ACTORS_KEY,
  ACKNOWLEDGED_ACTORS_KEY,
  MIGRATION_DONE_KEY,
} from '../lib/triageDecisions'
import type { ThreatScore } from '../api/types'

const { mockCreateDecision } = vi.hoisted(() => ({
  mockCreateDecision: vi.fn(),
}))

vi.mock('../api/decisions', () => ({
  createDecision: mockCreateDecision,
}))

function makeThreat(overrides: Partial<ThreatScore> = {}): ThreatScore {
  return {
    source_ip: '192.0.2.1',
    threat_level: 'HIGH',
    score: 50,
    total_events: 10,
    blocked_events: 5,
    attack_types: [],
    first_seen: '2026-07-01T00:00:00Z',
    last_seen: '2026-07-01T01:00:00Z',
    source_types: ['suricata'],
    detections: [],
    ai_insights: null,
    ai_confidence: null,
    ai_status: 'disabled',
    location: null,
    score_breakdown: [],
    asn: null,
    as_name: null,
    score_delta: null,
    triage_decision: null,
    ...overrides,
  }
}

beforeEach(() => {
  localStorage.clear()
  mockCreateDecision.mockReset()
  mockCreateDecision.mockResolvedValue({
    id: 1,
    actor_ip: '192.0.2.1',
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
// migrateLocalStorageDecisions — one-shot push
// ---------------------------------------------------------------------------

describe('migrateLocalStorageDecisions — one-shot push (ADR-0072 D3)', () => {
  it('pushes each legacy dismissed IP as POST /decisions {verb: "dismissed"}', async () => {
    localStorage.setItem(DISMISSED_ACTORS_KEY, JSON.stringify(['192.0.2.1', '192.0.2.2']))

    await migrateLocalStorageDecisions()

    expect(mockCreateDecision).toHaveBeenCalledTimes(2)
    expect(mockCreateDecision).toHaveBeenCalledWith({ actor_ip: '192.0.2.1', verb: 'dismissed' })
    expect(mockCreateDecision).toHaveBeenCalledWith({ actor_ip: '192.0.2.2', verb: 'dismissed' })
  })

  it('never sends decided_tier/decided_score (server is the sole snapshot authority)', async () => {
    localStorage.setItem(DISMISSED_ACTORS_KEY, JSON.stringify(['192.0.2.1']))

    await migrateLocalStorageDecisions()

    const body = mockCreateDecision.mock.calls[0][0] as Record<string, unknown>
    expect(body).not.toHaveProperty('decided_tier')
    expect(body).not.toHaveProperty('decided_score')
  })

  it('is a no-op when no legacy dismissed entries exist', async () => {
    await migrateLocalStorageDecisions()
    expect(mockCreateDecision).not.toHaveBeenCalled()
  })

  it('runs the network push exactly ONCE across repeated calls (the one-shot guarantee)', async () => {
    localStorage.setItem(DISMISSED_ACTORS_KEY, JSON.stringify(['192.0.2.1']))

    await migrateLocalStorageDecisions()
    expect(mockCreateDecision).toHaveBeenCalledTimes(1)

    // Re-seed the legacy key (simulating another tab writing pre-migration data)
    // and call again — the sentinel must still block a second push.
    localStorage.setItem(DISMISSED_ACTORS_KEY, JSON.stringify(['192.0.2.1']))
    await migrateLocalStorageDecisions()

    expect(mockCreateDecision).toHaveBeenCalledTimes(1)
  })

  it('sets the completion sentinel after running', async () => {
    localStorage.setItem(DISMISSED_ACTORS_KEY, JSON.stringify(['192.0.2.1']))
    await migrateLocalStorageDecisions()
    expect(localStorage.getItem(MIGRATION_DONE_KEY)).not.toBeNull()
  })

  it('garbage-collects both legacy keys after running', async () => {
    localStorage.setItem(DISMISSED_ACTORS_KEY, JSON.stringify(['192.0.2.1']))
    localStorage.setItem(ACKNOWLEDGED_ACTORS_KEY, JSON.stringify({ '192.0.2.9': { score: 1 } }))

    await migrateLocalStorageDecisions()

    expect(localStorage.getItem(DISMISSED_ACTORS_KEY)).toBeNull()
    expect(localStorage.getItem(ACKNOWLEDGED_ACTORS_KEY)).toBeNull()
  })

  it('does nothing when the sentinel is already set (pre-existing "migrated" browser)', async () => {
    localStorage.setItem(MIGRATION_DONE_KEY, '1')
    localStorage.setItem(DISMISSED_ACTORS_KEY, JSON.stringify(['192.0.2.1']))

    await migrateLocalStorageDecisions()

    expect(mockCreateDecision).not.toHaveBeenCalled()
  })

  it('tolerates a rejected createDecision call — does not throw, still marks migrated', async () => {
    mockCreateDecision.mockRejectedValueOnce(new Error('network error'))
    localStorage.setItem(DISMISSED_ACTORS_KEY, JSON.stringify(['192.0.2.1']))

    await expect(migrateLocalStorageDecisions()).resolves.toBeUndefined()
    expect(localStorage.getItem(MIGRATION_DONE_KEY)).not.toBeNull()
  })

  it('filters out malformed IPs from the legacy array before migrating (N-2 defense-in-depth)', async () => {
    localStorage.setItem(
      DISMISSED_ACTORS_KEY,
      JSON.stringify(['192.0.2.1', 'not-an-ip', 'http://evil.example']),
    )

    await migrateLocalStorageDecisions()

    expect(mockCreateDecision).toHaveBeenCalledTimes(1)
    expect(mockCreateDecision).toHaveBeenCalledWith({ actor_ip: '192.0.2.1', verb: 'dismissed' })
  })

  it('treats corrupt JSON in the legacy key as empty — does not throw', async () => {
    localStorage.setItem(DISMISSED_ACTORS_KEY, '{not valid json')

    await expect(migrateLocalStorageDecisions()).resolves.toBeUndefined()
    expect(mockCreateDecision).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// migrateLocalStorageDecisions — acknowledged entries are NOT migrated (D6)
// ---------------------------------------------------------------------------

describe('migrateLocalStorageDecisions — acknowledged entries are not migrated (ADR-0072 D6)', () => {
  it('does not push a decision for an IP that only appears in the acknowledged map', async () => {
    localStorage.setItem(
      ACKNOWLEDGED_ACTORS_KEY,
      JSON.stringify({ '192.0.2.42': { score: 10, tier: null, blockStatus: null } }),
    )

    await migrateLocalStorageDecisions()

    expect(mockCreateDecision).not.toHaveBeenCalled()
  })

  it('migrates only the dismissed IPs when both legacy keys are present', async () => {
    localStorage.setItem(DISMISSED_ACTORS_KEY, JSON.stringify(['192.0.2.1']))
    localStorage.setItem(
      ACKNOWLEDGED_ACTORS_KEY,
      JSON.stringify({ '192.0.2.42': { score: 10, tier: null, blockStatus: null } }),
    )

    await migrateLocalStorageDecisions()

    expect(mockCreateDecision).toHaveBeenCalledTimes(1)
    expect(mockCreateDecision).toHaveBeenCalledWith({ actor_ip: '192.0.2.1', verb: 'dismissed' })
  })
})

// ---------------------------------------------------------------------------
// isSuppressed — the ADR-0072 D3 queue-membership predicate
// ---------------------------------------------------------------------------

describe('isSuppressed — the ADR-0072 D3 queue-membership predicate', () => {
  it('returns false when triage_decision is null (no active decision)', () => {
    const actor = makeThreat({ triage_decision: null })
    expect(isSuppressed(actor)).toBe(false)
  })

  it('returns false when triage_decision is absent (older API response, additive field)', () => {
    const actor = makeThreat()
    delete (actor as { triage_decision?: unknown }).triage_decision
    expect(isSuppressed(actor)).toBe(false)
  })

  it('returns true when triage_decision.suppressed is true (a decided, suppressed actor)', () => {
    const actor = makeThreat({
      triage_decision: {
        verb: 'dismissed',
        decided_at: '2026-07-17T00:00:00Z',
        decided_tier: 3,
        decided_score: 40,
        suppressed: true,
        reentry: null,
      },
    })
    expect(isSuppressed(actor)).toBe(true)
  })

  it('returns false when a decision exists but suppressed is false (still renders in the record)', () => {
    // e.g. a false_positive decision that does not cover every qualifying rule,
    // or a decision the server re-entry evaluator no longer honours (#56).
    const actor = makeThreat({
      triage_decision: {
        verb: 'expected',
        decided_at: '2026-07-17T00:00:00Z',
        decided_tier: 2,
        decided_score: 60,
        suppressed: false,
        reentry: null,
      },
    })
    expect(isSuppressed(actor)).toBe(false)
  })

  it('never reads localStorage (retire-list regression — server field only)', () => {
    const getSpy = vi.spyOn(Storage.prototype, 'getItem')
    const actor = makeThreat({
      triage_decision: {
        verb: 'dismissed',
        decided_at: '2026-07-17T00:00:00Z',
        decided_tier: null,
        decided_score: 10,
        suppressed: true,
        reentry: null,
      },
    })

    isSuppressed(actor)

    expect(getSpy).not.toHaveBeenCalled()
    getSpy.mockRestore()
  })
})
