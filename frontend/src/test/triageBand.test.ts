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
import { isHighTierEscalation, deriveTriageActors } from '../lib/triageBand'
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
})
