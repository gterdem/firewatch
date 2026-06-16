/**
 * Tests for src/lib/actorRollup.ts (issue #212).
 *
 * EARS acceptance criteria (1:1 mapping):
 *
 * Ubiquitous: grouping logic is O(n), pure, deterministic.
 *
 * WHILE scored-actor cardinality ≤ ROLLUP_CUTOFF:
 *   - EARS-GRP-1: isRollup should be false when count ≤ 50.
 *
 * WHEN cardinality exceeds ROLLUP_CUTOFF:
 *   - EARS-GRP-2: groupThreats groups by ASN when asn is present.
 *   - EARS-GRP-3: groupThreats falls back to /24 when asn is null.
 *   - EARS-GRP-4: mixed ASN + no-ASN actors are grouped correctly.
 *   - EARS-GRP-5: groups are sorted by topScore descending.
 *   - EARS-GRP-6: topMembers contains at most 10 IPs per group.
 *   - EARS-GRP-7: totalEvents and totalBlockedEvents are summed correctly.
 *   - EARS-GRP-8: memberCount reflects the full group size (not just topMembers).
 *
 * WHEN AS data is absent for all members:
 *   - EARS-GRP-9: fallback is /24 with no error.
 *
 * WHEN 'Top movers' sort is selected:
 *   - EARS-SORT-10: sortThreats('top-movers') sorts by first_seen descending.
 *   - EARS-SORT-11: sortThreats('score') sorts by score descending (unchanged).
 *
 * /24 helper:
 *   - EARS-CIDR-12: cidr24 extracts the /24 prefix correctly.
 *   - EARS-CIDR-13: cidr24 returns null for non-IPv4 strings.
 *
 * Performance guard:
 *   - EARS-PERF-14: groupThreats handles 5,000 actors in < 100ms.
 */

import { describe, it, expect } from 'vitest'
import type { ThreatScore } from '../api/types'
import {
  ROLLUP_CUTOFF,
  groupThreats,
  sortThreats,
  cidr24,
} from '../lib/actorRollup'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeThreat(
  ip: string,
  score: number,
  asn: number | null = null,
  as_name: string | null = null,
  opts?: Partial<ThreatScore>,
): ThreatScore {
  return {
    source_ip: ip,
    threat_level: score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW',
    score,
    total_events: 100,
    blocked_events: 80,
    attack_types: ['DDoS'],
    first_seen: '2026-06-01T00:00:00Z',
    last_seen: '2026-06-04T09:55:00Z',
    source_types: ['azure_waf'],
    detections: [],
    ai_insights: null,
    ai_confidence: null,
    ai_status: 'unavailable',
    location: null,
    score_breakdown: [],
    asn,
    as_name,
    score_delta: null,
    ...opts,
  }
}

/** Make N threats in the same ASN. */
function makeAsnGroup(
  count: number,
  asn: number,
  as_name: string,
  ipPrefix: string,
  baseScore = 80,
): ThreatScore[] {
  return Array.from({ length: count }, (_, i) =>
    makeThreat(`${ipPrefix}.${i + 1}`, baseScore - i, asn, as_name),
  )
}

/** Make N threats with no ASN (same /24 prefix). */
function makeCidrGroup(count: number, ipPrefix: string, baseScore = 50): ThreatScore[] {
  return Array.from({ length: count }, (_, i) =>
    makeThreat(`${ipPrefix}.${i + 1}`, baseScore - i, null, null),
  )
}

// ---------------------------------------------------------------------------
// Constants check
// ---------------------------------------------------------------------------

describe('ROLLUP_CUTOFF', () => {
  it('is 50', () => {
    expect(ROLLUP_CUTOFF).toBe(50)
  })
})

// ---------------------------------------------------------------------------
// cidr24 helper
// ---------------------------------------------------------------------------

describe('cidr24', () => {
  // EARS-CIDR-12
  it('extracts the /24 prefix from a valid IPv4 address', () => {
    expect(cidr24('192.168.1.100')).toBe('192.168.1')
    expect(cidr24('10.0.0.1')).toBe('10.0.0')
    expect(cidr24('203.0.113.5')).toBe('203.0.113')
  })

  // EARS-CIDR-13
  it('returns null for non-IPv4 strings', () => {
    expect(cidr24('not-an-ip')).toBeNull()
    expect(cidr24('::1')).toBeNull()
    expect(cidr24('')).toBeNull()
    expect(cidr24('192.168.1')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// groupThreats — ASN grouping
// ---------------------------------------------------------------------------

describe('groupThreats — ASN grouping', () => {
  // EARS-GRP-2: groups by ASN when asn is present
  it('groups actors by ASN when asn is present', () => {
    const threats = [
      ...makeAsnGroup(5, 4837, 'CHINA-UNICOM', '203.0.113'),
      ...makeAsnGroup(3, 15169, 'GOOGLE', '198.51.100'),
    ]
    const groups = groupThreats(threats)
    expect(groups).toHaveLength(2)
    const asnKeys = groups.map((g) => g.kind)
    expect(asnKeys.every((k) => k === 'asn')).toBe(true)
    const memberCounts = groups.map((g) => g.memberCount).sort((a, b) => b - a)
    expect(memberCounts).toEqual([5, 3])
  })

  // EARS-GRP-5: groups sorted by topScore descending
  it('sorts groups by topScore descending', () => {
    const threats = [
      ...makeAsnGroup(3, 15169, 'GOOGLE', '198.51.100', 30),   // lower scores
      ...makeAsnGroup(3, 4837, 'CHINA-UNICOM', '203.0.113', 80), // higher scores
    ]
    const groups = groupThreats(threats)
    expect(groups[0].topScore).toBeGreaterThan(groups[1].topScore)
    expect(groups[0].key).toBe('AS4837')
  })

  // EARS-GRP-7: totalEvents and totalBlockedEvents summed correctly
  it('sums totalEvents and totalBlockedEvents across group members', () => {
    const threats = makeAsnGroup(4, 4837, 'CHINA-UNICOM', '203.0.113', 80)
    const groups = groupThreats(threats)
    expect(groups).toHaveLength(1)
    expect(groups[0].totalEvents).toBe(4 * 100)       // each has total_events=100
    expect(groups[0].totalBlockedEvents).toBe(4 * 80) // each has blocked_events=80
  })

  // EARS-GRP-8: memberCount reflects full group size
  it('memberCount reflects the full group size including members beyond topMembers cap', () => {
    const threats = makeAsnGroup(15, 4837, 'CHINA-UNICOM', '203.0.113', 80)
    const groups = groupThreats(threats)
    expect(groups[0].memberCount).toBe(15)
    expect(groups[0].topMembers.length).toBeLessThanOrEqual(10)
  })

  // EARS-GRP-6: topMembers contains at most 10 IPs per group
  it('topMembers contains at most 10 IPs', () => {
    const threats = makeAsnGroup(20, 4837, 'CHINA-UNICOM', '203.0.113', 80)
    const groups = groupThreats(threats)
    expect(groups[0].topMembers.length).toBe(10)
  })

  // label uses as_name when present
  it('uses as_name in the label when present', () => {
    const threats = makeAsnGroup(3, 4837, 'CHINA-UNICOM', '203.0.113', 80)
    const groups = groupThreats(threats)
    expect(groups[0].label).toContain('CHINA-UNICOM')
    expect(groups[0].label).toContain('AS4837')
  })

  // label falls back to ASN string when as_name is null
  it('uses ASN string only when as_name is null', () => {
    const threats = [
      makeThreat('203.0.113.1', 80, 4837, null),
      makeThreat('203.0.113.2', 70, 4837, null),
    ]
    const groups = groupThreats(threats)
    expect(groups[0].label).toBe('AS4837')
  })
})

// ---------------------------------------------------------------------------
// groupThreats — /24 CIDR fallback
// ---------------------------------------------------------------------------

describe('groupThreats — /24 CIDR fallback', () => {
  // EARS-GRP-3: falls back to /24 when asn is null
  it('groups by /24 prefix when asn is null', () => {
    const threats = [
      ...makeCidrGroup(5, '192.0.2', 60),
      ...makeCidrGroup(3, '198.51.100', 40),
    ]
    const groups = groupThreats(threats)
    expect(groups).toHaveLength(2)
    expect(groups.every((g) => g.kind === 'cidr')).toBe(true)
    const labels = groups.map((g) => g.label)
    expect(labels).toContain('192.0.2.0/24')
    expect(labels).toContain('198.51.100.0/24')
  })

  // EARS-GRP-9: no error when AS data is absent for all members
  it('does not throw when AS data is absent for all actors', () => {
    const threats = makeCidrGroup(10, '10.0.0', 50)
    expect(() => groupThreats(threats)).not.toThrow()
    const groups = groupThreats(threats)
    expect(groups).toHaveLength(1)
    expect(groups[0].kind).toBe('cidr')
    expect(groups[0].memberCount).toBe(10)
  })
})

// ---------------------------------------------------------------------------
// groupThreats — mixed ASN + no-ASN
// ---------------------------------------------------------------------------

describe('groupThreats — mixed grouping', () => {
  // EARS-GRP-4: mixed ASN + no-ASN actors grouped correctly
  it('handles a mix of ASN-enriched and unenriched actors in one pass', () => {
    const threats = [
      makeThreat('203.0.113.1', 90, 4837, 'CHINA-UNICOM'),
      makeThreat('203.0.113.2', 85, 4837, 'CHINA-UNICOM'),
      makeThreat('198.51.100.1', 70, null, null),
      makeThreat('198.51.100.2', 65, null, null),
    ]
    const groups = groupThreats(threats)
    // Expect 2 groups: one ASN, one /24
    expect(groups).toHaveLength(2)
    const kinds = groups.map((g) => g.kind).sort()
    expect(kinds).toEqual(['asn', 'cidr'])
  })
})

// ---------------------------------------------------------------------------
// sortThreats
// ---------------------------------------------------------------------------

describe('sortThreats', () => {
  const threats = [
    makeThreat('10.0.0.1', 30, null, null, { score_delta: 5 }),
    makeThreat('10.0.0.2', 90, null, null, { score_delta: 40 }),
    makeThreat('10.0.0.3', 60, null, null, { score_delta: 20 }),
    makeThreat('10.0.0.4', 10, null, null, { score_delta: 10 }),
  ]

  // EARS-SORT-11: 'score' mode sorts by score descending
  it('sorts by score descending in score mode', () => {
    const sorted = sortThreats(threats, 'score')
    const scores = sorted.map((t) => t.score)
    expect(scores).toEqual([90, 60, 30, 10])
  })

  // EARS-SORT-10: 'top-movers' mode sorts by |score_delta| descending (real delta, issue #251)
  it('sorts by |score_delta| descending in top-movers mode', () => {
    const sorted = sortThreats(threats, 'top-movers')
    // Largest |delta| first: 40, 20, 10, 5
    const ips = sorted.map((t) => t.source_ip)
    expect(ips[0]).toBe('10.0.0.2') // score_delta=40 (largest)
    expect(ips[3]).toBe('10.0.0.1') // score_delta=5 (smallest)
  })

  // Does not mutate the input array
  it('does not mutate the input array', () => {
    const original = [...threats]
    sortThreats(threats, 'score')
    expect(threats).toEqual(original)
  })

  // Actors with null score_delta (new actors) go after actors with known deltas
  it('places null-delta (new) actors after known-delta actors in top-movers mode', () => {
    const withNull = [
      makeThreat('10.0.0.5', 50, null, null, { score_delta: null }),   // new actor
      makeThreat('10.0.0.6', 80, null, null, { score_delta: 15 }),     // known delta
    ]
    const sorted = sortThreats(withNull, 'top-movers')
    // Known-delta actor must come before null-delta actor
    expect(sorted[0].source_ip).toBe('10.0.0.6')
    expect(sorted[1].source_ip).toBe('10.0.0.5')
  })
})

// ---------------------------------------------------------------------------
// Performance guard
// ---------------------------------------------------------------------------

describe('groupThreats — performance', () => {
  // EARS-PERF-14: 5,000 actors in < 100ms
  it('handles 5,000 scored actors in under 100ms', () => {
    const threats: ThreatScore[] = []
    // Mix of ASN groups and CIDR groups
    for (let i = 0; i < 2500; i++) {
      threats.push(makeThreat(`203.${Math.floor(i / 256)}.${i % 256}.1`, 50, 4837, 'CHINA-UNICOM'))
    }
    for (let i = 0; i < 2500; i++) {
      threats.push(makeThreat(`198.${Math.floor(i / 256)}.${i % 256}.1`, 40, null, null))
    }
    const start = performance.now()
    groupThreats(threats)
    const elapsed = performance.now() - start
    expect(elapsed).toBeLessThan(100)
  })
})
