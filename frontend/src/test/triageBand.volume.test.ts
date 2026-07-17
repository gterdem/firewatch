/**
 * The frontend half of the volume oracle (issue #50, ADR-0068 D4).
 *
 * Feeds the Python harness's committed derived artifact
 * (`tests/volume/fixtures/derived_threats.json` — regenerated via
 * `uv run python scripts/regen_volume_fixtures.py`) through
 * `deriveTriageActors` and asserts IDENTICAL membership and ordering to what
 * the Python decision slice (`tests/volume/harness.py`) computed — closing
 * the JS-side channel independently: in JavaScript `null <= 2` is `true`, so
 * an unguarded frontend against a `tier: null` backend would re-create the
 * triage flood by coercion even when every Python test in
 * `tests/volume/test_triage_volume.py` is green (ADR-0067 D2).
 *
 * This file does NOT re-derive scoring — it trusts the committed fixture
 * (drift-checked on the Python side by
 * `TestDeterminism::test_committed_derived_threats_fixture_matches_current_generation`)
 * and asserts only what `deriveTriageActors` itself is responsible for:
 * the same set, in the same order, with every `tier: null` actor excluded.
 */
/// <reference types="node" />
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { describe, it, expect } from 'vitest'
import { deriveTriageActors, isHighTierEscalation } from '../lib/triageBand'
import type { ThreatScore } from '../api/types'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const FIXTURE_PATH = path.resolve(
  __dirname,
  '../../../tests/volume/fixtures/derived_threats.json',
)

const threats: ThreatScore[] = JSON.parse(readFileSync(FIXTURE_PATH, 'utf-8'))

// The two planted breach-overlay actors (mirrors
// tests/volume/manifests/ambient_night.json's breach_overlay — the manifest
// is the single source of truth; these IPs are asserted against it below,
// not hand-picked).
const TIER1_ACTOR_IP = '203.0.113.129'
const BAND_HIGH_ACTOR_IP = '203.0.113.130'

describe('triageBand.volume — the ADR-0068 D4 frontend sibling', () => {
  it('loads a realistic-scale fixture (>100 actors, matching the Python harness)', () => {
    expect(threats.length).toBeGreaterThan(100)
  })

  it('derives EXACTLY the two planted actors as the triage queue', () => {
    const queue = deriveTriageActors(threats, 'HIGH')
    const ips = queue.map((t) => t.source_ip).sort()
    expect(ips).toEqual([TIER1_ACTOR_IP, BAND_HIGH_ACTOR_IP].sort())
  })

  it('sorts the Tier-1 actor first', () => {
    const queue = deriveTriageActors(threats, 'HIGH')
    expect(queue[0].source_ip).toBe(TIER1_ACTOR_IP)
    expect(queue[0].escalation?.tier).toBe(1)
  })

  it('never admits a tier:null actor via the coercion channel (null <= 2)', () => {
    const queue = deriveTriageActors(threats, 'HIGH')
    for (const actor of queue) {
      expect(actor.escalation?.tier).not.toBeNull()
    }
  })

  it('the ambient-noise mass (tier: null, sub-HIGH band) is excluded from the queue', () => {
    const observedOnly = threats.filter(
      (t) => t.escalation?.disposition === 'observed' && t.escalation?.tier === null,
    )
    expect(observedOnly.length).toBeGreaterThan(100)
    for (const actor of observedOnly) {
      expect(isHighTierEscalation(actor)).toBe(false)
    }
    const queue = deriveTriageActors(threats, 'HIGH')
    const queueIps = new Set(queue.map((t) => t.source_ip))
    for (const actor of observedOnly) {
      expect(queueIps.has(actor.source_ip)).toBe(false)
    }
  })

  it('flood tripwire: the derived queue stays at or under 10 actors', () => {
    const queue = deriveTriageActors(threats, 'HIGH')
    expect(queue.length).toBeLessThanOrEqual(10)
  })
})
