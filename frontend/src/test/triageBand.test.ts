/**
 * Tests for frontend/src/lib/triageBand.ts — issue #42, ADR-0067 D2/D7.
 *
 * The crux under test: EscalationVerdict.tier widens to `number | null` (the
 * ADR-0067 observed stratum). In JavaScript, `null <= 2` evaluates to `true`
 * (null coerces to 0), so an unguarded `tier <= 2` comparison would silently
 * re-admit every observed actor into the triage banner — reproducing the
 * exact flood ADR-0067 fixes, in the UI only, with no error and no failing
 * type check. `isHighTierEscalation` / `deriveTriageActors` MUST null-guard.
 *
 * EARS criteria -> test mapping:
 * - WHEN escalation.tier is null (the observed stratum), isHighTierEscalation
 *   SHALL return false (not throw, not silently coerce to true).
 *   -> TestIsHighTierEscalation.tier null returns false
 * - WHEN escalation is absent, isHighTierEscalation SHALL return false.
 *   -> TestIsHighTierEscalation.no escalation returns false
 * - WHEN escalation.tier is 1 or 2, isHighTierEscalation SHALL return true.
 *   -> TestIsHighTierEscalation.tier 1/2 returns true
 * - WHEN escalation.tier is 3 or 4, isHighTierEscalation SHALL return false.
 *   -> TestIsHighTierEscalation.tier 3/4 returns false
 * - WHEN an actor has tier=null and a LOW/MEDIUM threat_level below the triage
 *   threshold, deriveTriageActors SHALL NOT admit it to the banner (the
 *   flood-reproduction regression guard).
 *   -> TestDeriveTriageActorsNullTier
 * - WHEN actors include a mix of tier=null (observed) and tiered actors,
 *   deriveTriageActors SHALL sort tier=null actors after all tiered actors.
 *   -> TestDeriveTriageActorsNullTier.sort order
 *
 * Fixture IPs are RFC 5737 documentation ranges only (192.0.2.0/24).
 */
import { describe, it, expect } from 'vitest'
import { isHighTierEscalation, deriveTriageActors, deriveObservedRecord } from '../lib/triageBand'
import type { EscalationVerdict, ThreatScore } from '../api/types'

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function makeVerdict(overrides: Partial<EscalationVerdict> = {}): EscalationVerdict {
  return {
    tier: null,
    disposition: 'observed',
    justification: '[RULE] test',
    block_status: 'unknown',
    ...overrides,
  }
}

function makeThreat(overrides: Partial<ThreatScore> = {}): ThreatScore {
  return {
    source_ip: '192.0.2.1',
    threat_level: 'LOW',
    score: 10,
    total_events: 5,
    blocked_events: 0,
    attack_types: [],
    first_seen: '2026-06-01T00:00:00Z',
    last_seen: '2026-06-01T00:05:00Z',
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
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// isHighTierEscalation — the null-guard crux
// ---------------------------------------------------------------------------

describe('isHighTierEscalation — ADR-0067 D2/D7 null-tier guard', () => {
  it('returns false when escalation.tier is null (the observed stratum)', () => {
    const t = makeThreat({ escalation: makeVerdict({ tier: null, disposition: 'observed' }) })
    expect(isHighTierEscalation(t)).toBe(false)
  })

  it('does not throw when escalation.tier is null', () => {
    const t = makeThreat({ escalation: makeVerdict({ tier: null }) })
    expect(() => isHighTierEscalation(t)).not.toThrow()
  })

  it('returns false when escalation is absent (undefined)', () => {
    const t = makeThreat({})
    expect(isHighTierEscalation(t)).toBe(false)
  })

  it('returns false when escalation is explicitly null', () => {
    const t = makeThreat({ escalation: null })
    expect(isHighTierEscalation(t)).toBe(false)
  })

  it('returns true when tier is 1', () => {
    const t = makeThreat({
      escalation: makeVerdict({ tier: 1, disposition: 'allowed_through', block_status: 'allowed' }),
    })
    expect(isHighTierEscalation(t)).toBe(true)
  })

  it('returns true when tier is 2', () => {
    const t = makeThreat({
      escalation: makeVerdict({ tier: 2, disposition: 'block_status_unknown' }),
    })
    expect(isHighTierEscalation(t)).toBe(true)
  })

  it('returns false when tier is 3', () => {
    const t = makeThreat({
      escalation: makeVerdict({ tier: 3, disposition: 'blocked_persistent', block_status: 'blocked' }),
    })
    expect(isHighTierEscalation(t)).toBe(false)
  })

  it('returns false when tier is 4', () => {
    const t = makeThreat({
      escalation: makeVerdict({ tier: 4, disposition: 'blocked_one_off', block_status: 'blocked' }),
    })
    expect(isHighTierEscalation(t)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// deriveTriageActors — the flood-reproduction regression guard
// ---------------------------------------------------------------------------

describe('deriveTriageActors — observed (tier=null) actors do not flood the banner', () => {
  it('excludes a LOW-band observed actor below the triage threshold', () => {
    const observed = makeThreat({
      source_ip: '192.0.2.10',
      threat_level: 'LOW',
      escalation: makeVerdict({ tier: null, disposition: 'observed', block_status: 'unknown' }),
    })
    const result = deriveTriageActors([observed], 'HIGH')
    expect(result).toEqual([])
  })

  it('excludes a MEDIUM-band observed actor below the triage threshold', () => {
    const observed = makeThreat({
      source_ip: '192.0.2.11',
      threat_level: 'MEDIUM',
      escalation: makeVerdict({ tier: null, disposition: 'observed', block_status: 'allowed' }),
    })
    const result = deriveTriageActors([observed], 'HIGH')
    expect(result).toEqual([])
  })

  it('a mass of observed actors never floods the banner (the regression this issue fixes)', () => {
    const flood: ThreatScore[] = Array.from({ length: 200 }, (_, i) =>
      makeThreat({
        source_ip: `192.0.2.${(i % 250) + 1}`,
        threat_level: 'LOW',
        escalation: makeVerdict({ tier: null, disposition: 'observed', block_status: 'unknown' }),
      }),
    )
    const result = deriveTriageActors(flood, 'HIGH')
    expect(result).toEqual([])
  })

  it('still admits a tier-1 actor with a LOW threat_level (action axis unconditional)', () => {
    const tier1 = makeThreat({
      source_ip: '192.0.2.20',
      threat_level: 'LOW',
      escalation: makeVerdict({ tier: 1, disposition: 'allowed_through', block_status: 'allowed' }),
    })
    const result = deriveTriageActors([tier1], 'HIGH')
    expect(result).toHaveLength(1)
  })

  it('still admits an actor via the band axis regardless of tier=null', () => {
    const highBand = makeThreat({
      source_ip: '192.0.2.21',
      threat_level: 'CRITICAL',
      escalation: makeVerdict({ tier: null, disposition: 'observed', block_status: 'unknown' }),
    })
    const result = deriveTriageActors([highBand], 'HIGH')
    expect(result).toHaveLength(1)
  })

  it('sorts tier=null actors after tiered actors', () => {
    const tier2 = makeThreat({
      source_ip: '192.0.2.30',
      threat_level: 'CRITICAL',
      score: 10,
      escalation: makeVerdict({ tier: 2, disposition: 'block_status_unknown' }),
    })
    const observedButBanded = makeThreat({
      source_ip: '192.0.2.31',
      threat_level: 'CRITICAL',
      score: 99,
      escalation: makeVerdict({ tier: null, disposition: 'observed', block_status: 'unknown' }),
    })
    const result = deriveTriageActors([observedButBanded, tier2], 'HIGH')
    expect(result.map((t) => t.source_ip)).toEqual(['192.0.2.30', '192.0.2.31'])
  })

  // Issue #43 DoD: "Sorting SHALL be regression-tested for tier: null actors
  // (existing ?? 99 fallback)". Full ladder regression: tier 1 through 4 plus
  // a band-qualified tier=null actor, all CRITICAL band so every actor is
  // admitted — the ONLY thing under test here is sort order (tier asc, the
  // ?? 99 fallback placing tier=null last).
  it('sorts a mixed tier-1/2/3/4/null ladder with tier=null always last (the ?? 99 fallback)', () => {
    const t1 = makeThreat({
      source_ip: '192.0.2.40',
      threat_level: 'CRITICAL',
      score: 50,
      escalation: makeVerdict({ tier: 1, disposition: 'allowed_through', block_status: 'allowed' }),
    })
    const t2 = makeThreat({
      source_ip: '192.0.2.41',
      threat_level: 'CRITICAL',
      score: 50,
      escalation: makeVerdict({ tier: 2, disposition: 'block_status_unknown' }),
    })
    const t3 = makeThreat({
      source_ip: '192.0.2.42',
      threat_level: 'CRITICAL',
      score: 50,
      escalation: makeVerdict({ tier: 3, disposition: 'blocked_persistent', block_status: 'blocked' }),
    })
    const t4 = makeThreat({
      source_ip: '192.0.2.43',
      threat_level: 'CRITICAL',
      score: 50,
      escalation: makeVerdict({ tier: 4, disposition: 'blocked_one_off', block_status: 'blocked' }),
    })
    const tNull = makeThreat({
      source_ip: '192.0.2.44',
      threat_level: 'CRITICAL',
      score: 100, // highest score of all — would sort first if tier=null coerced to 0
      escalation: makeVerdict({ tier: null, disposition: 'observed', block_status: 'unknown' }),
    })

    // Deliberately shuffled input order — sort must not depend on input order.
    const result = deriveTriageActors([tNull, t3, t1, t4, t2], 'HIGH')

    expect(result.map((t) => t.source_ip)).toEqual([
      '192.0.2.40', // tier 1
      '192.0.2.41', // tier 2
      '192.0.2.42', // tier 3
      '192.0.2.43', // tier 4
      '192.0.2.44', // tier null — last, despite the highest score
    ])
  })
})

// ---------------------------------------------------------------------------
// deriveObservedRecord — the ADR-0067 D5(2) aggregate record line (issue #43)
// ---------------------------------------------------------------------------

describe('deriveObservedRecord — the aggregate "on the record" line (issue #43, ADR-0067 D5(2))', () => {
  it('returns null when there are no observed-disposition actors', () => {
    const tier1 = makeThreat({
      source_ip: '192.0.2.50',
      escalation: makeVerdict({ tier: 1, disposition: 'allowed_through', block_status: 'allowed' }),
    })
    const result = deriveObservedRecord([tier1], [tier1])
    expect(result).toBeNull()
  })

  it('returns null when every observed actor already earned a banner slot via the band axis', () => {
    const bandQualifiedObserved = makeThreat({
      source_ip: '192.0.2.51',
      threat_level: 'CRITICAL',
      escalation: makeVerdict({ tier: null, disposition: 'observed', block_status: 'unknown' }),
    })
    // bandQualifiedObserved is present in pendingActors (it qualified via the band axis).
    const result = deriveObservedRecord([bandQualifiedObserved], [bandQualifiedObserved])
    expect(result).toBeNull()
  })

  it('sums total_events and counts distinct source_types for observed-only actors', () => {
    const observedA = makeThreat({
      source_ip: '192.0.2.52',
      total_events: 10,
      source_types: ['suricata'],
      escalation: makeVerdict({ tier: null, disposition: 'observed', block_status: 'unknown' }),
    })
    const observedB = makeThreat({
      source_ip: '192.0.2.53',
      total_events: 32,
      source_types: ['syslog', 'suricata'],
      escalation: makeVerdict({ tier: null, disposition: 'observed', block_status: 'allowed' }),
    })
    const result = deriveObservedRecord([observedA, observedB], [])
    expect(result).toEqual({ eventCount: 42, sourceCount: 2 })
  })

  it('excludes actors already present in pendingActors (band-qualified, not "only observed")', () => {
    const bandQualified = makeThreat({
      source_ip: '192.0.2.54',
      threat_level: 'CRITICAL',
      total_events: 10,
      source_types: ['suricata'],
      escalation: makeVerdict({ tier: null, disposition: 'observed', block_status: 'unknown' }),
    })
    const observedOnly = makeThreat({
      source_ip: '192.0.2.55',
      threat_level: 'LOW',
      total_events: 5,
      source_types: ['azure_waf'],
      escalation: makeVerdict({ tier: null, disposition: 'observed', block_status: 'allowed' }),
    })
    // bandQualified is in pendingActors — only observedOnly should count.
    const result = deriveObservedRecord([bandQualified, observedOnly], [bandQualified])
    expect(result).toEqual({ eventCount: 5, sourceCount: 1 })
  })

  it('ignores tiered (non-observed) actors even when absent from pendingActors', () => {
    // A tier-4 actor that isn't band-qualified never enters pendingActors, but
    // it is NOT part of the observed stratum (it has a real disposition) —
    // it must not be swept into the aggregate line.
    const tier4 = makeThreat({
      source_ip: '192.0.2.56',
      threat_level: 'LOW',
      total_events: 7,
      escalation: makeVerdict({ tier: 4, disposition: 'blocked_one_off', block_status: 'blocked' }),
    })
    const result = deriveObservedRecord([tier4], [])
    expect(result).toBeNull()
  })

  it('ignores actors with no escalation verdict at all', () => {
    const noVerdict = makeThreat({ source_ip: '192.0.2.57', total_events: 9 })
    const result = deriveObservedRecord([noVerdict], [])
    expect(result).toBeNull()
  })

  it('returns an integer-only summary — no source_ip or source_type text in the result', () => {
    const observed = makeThreat({
      source_ip: '192.0.2.58',
      total_events: 3,
      source_types: ['suricata'],
      escalation: makeVerdict({ tier: null, disposition: 'observed', block_status: 'unknown' }),
    })
    const result = deriveObservedRecord([observed], [])
    expect(result).not.toBeNull()
    expect(Object.values(result!).every((v) => typeof v === 'number')).toBe(true)
  })
})
