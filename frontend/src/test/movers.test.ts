/**
 * Tests for src/lib/movers.ts (issue #251).
 *
 * EARS acceptance criteria (1:1 mapping):
 *
 * Ubiquitous: movers sorted by |score_delta| descending.
 *   - EARS-251-1: actors with higher |delta| rank first.
 *   - EARS-251-2: negative delta is ranked by |delta| (e.g. |-38| > |+10|).
 *   - EARS-251-3: tie in |delta| breaks by score descending.
 *
 * WHEN score_delta is null (new actor):
 *   - EARS-251-4: null-delta actors appear AFTER all known-delta actors.
 *   - EARS-251-5: among null-delta actors, order is by score descending.
 *   - EARS-251-6: null-delta rows have isNew=true and undefined delta/absDelta.
 *
 * Ubiquitous: result bounded to topN.
 *   - EARS-251-7: result length ≤ topN (default TOP_MOVERS_N = 6).
 *   - EARS-251-8: custom topN honored.
 *
 * Score-0 actors are excluded.
 *   - EARS-251-9: actors with score=0 are not included in the movers list.
 *
 * Edge cases:
 *   - EARS-251-10: empty threats array → empty movers list.
 *   - EARS-251-11: all null-delta → null-delta actors still returned, ordered by score.
 *   - EARS-251-12: all known-delta → ordered by |delta| desc, no null-delta actors.
 */

import { describe, it, expect } from 'vitest'
import type { ThreatScore } from '../api/types'
import { topMovers, TOP_MOVERS_N } from '../lib/movers'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeThreat(
  ip: string,
  score: number,
  score_delta: number | null,
  opts?: Partial<ThreatScore>,
): ThreatScore {
  return {
    source_ip: ip,
    threat_level: score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW',
    score,
    total_events: 100,
    blocked_events: 60,
    attack_types: ['SQL Injection'],
    first_seen: '2026-06-01T00:00:00Z',
    last_seen: '2026-06-04T09:55:00Z',
    source_types: ['suricata'],
    detections: [],
    ai_insights: null,
    ai_confidence: null,
    ai_status: 'unavailable',
    location: null,
    score_breakdown: [],
    asn: null,
    as_name: null,
    score_delta,
    ...opts,
  }
}

// ---------------------------------------------------------------------------
// TOP_MOVERS_N constant
// ---------------------------------------------------------------------------

describe('TOP_MOVERS_N', () => {
  it('is 6', () => {
    expect(TOP_MOVERS_N).toBe(6)
  })
})

// ---------------------------------------------------------------------------
// Basic delta ordering
// ---------------------------------------------------------------------------

describe('topMovers — delta ordering', () => {
  // EARS-251-1: higher |delta| ranks first
  it('ranks actors by |score_delta| descending (highest change first)', () => {
    const threats = [
      makeThreat('192.0.2.1', 60, 10),
      makeThreat('192.0.2.2', 70, 38),
      makeThreat('192.0.2.3', 50, 5),
    ]
    const result = topMovers(threats)
    expect(result.map((m) => m.threat.source_ip)).toEqual([
      '192.0.2.2', // |38| = 38 (largest)
      '192.0.2.1', // |10| = 10
      '192.0.2.3', // |5|  = 5 (smallest)
    ])
  })

  // EARS-251-2: negative delta ranked by absolute value
  it('treats negative delta by absolute value (|-38| > |+10|)', () => {
    const threats = [
      makeThreat('192.0.2.1', 70, 10),   // falling slightly
      makeThreat('192.0.2.2', 80, -38),  // falling sharply — |38| > |10|
    ]
    const result = topMovers(threats)
    expect(result[0].threat.source_ip).toBe('192.0.2.2') // |delta|=38
    expect(result[0].delta).toBe(-38)
    expect(result[0].absDelta).toBe(38)
  })

  // EARS-251-3: tie in |delta| breaks by score descending
  it('breaks ties in |delta| by score descending', () => {
    const threats = [
      makeThreat('192.0.2.1', 60, 20),  // same |delta|, lower score
      makeThreat('192.0.2.2', 90, 20),  // same |delta|, higher score — wins
    ]
    const result = topMovers(threats)
    expect(result[0].threat.source_ip).toBe('192.0.2.2') // higher score
  })
})

// ---------------------------------------------------------------------------
// Null-delta (new actor) handling
// ---------------------------------------------------------------------------

describe('topMovers — null-delta (new actor) handling', () => {
  // EARS-251-4: null-delta actors appear after known-delta actors
  it('places null-delta actors after all known-delta actors', () => {
    const threats = [
      makeThreat('192.0.2.1', 80, null),  // new actor
      makeThreat('192.0.2.2', 50, 15),    // known delta
      makeThreat('192.0.2.3', 90, null),  // new actor
      makeThreat('192.0.2.4', 40, 30),    // known delta
    ]
    const result = topMovers(threats)
    const ips = result.map((m) => m.threat.source_ip)
    // Known-delta actors first (sorted by |delta|)
    expect(ips[0]).toBe('192.0.2.4') // |delta|=30
    expect(ips[1]).toBe('192.0.2.2') // |delta|=15
    // Null-delta actors after (sorted by score desc)
    expect(ips[2]).toBe('192.0.2.3') // score=90
    expect(ips[3]).toBe('192.0.2.1') // score=80
  })

  // EARS-251-5: null-delta actors ordered by score descending among themselves
  it('orders null-delta actors by score descending', () => {
    const threats = [
      makeThreat('192.0.2.1', 30, null),
      makeThreat('192.0.2.2', 90, null),
      makeThreat('192.0.2.3', 60, null),
    ]
    const result = topMovers(threats)
    const scores = result.map((m) => m.threat.score)
    expect(scores).toEqual([90, 60, 30])
  })

  // EARS-251-6: null-delta rows have correct MoverRow metadata
  it('sets isNew=true and undefined delta/absDelta for null-delta actors', () => {
    const threats = [makeThreat('192.0.2.1', 70, null)]
    const result = topMovers(threats)
    expect(result).toHaveLength(1)
    expect(result[0].isNew).toBe(true)
    expect(result[0].delta).toBeUndefined()
    expect(result[0].absDelta).toBeUndefined()
  })

  // Non-null delta row has correct metadata
  it('sets isNew=false and correct delta/absDelta for known-delta actors', () => {
    const threats = [makeThreat('192.0.2.1', 70, -25)]
    const result = topMovers(threats)
    expect(result).toHaveLength(1)
    expect(result[0].isNew).toBe(false)
    expect(result[0].delta).toBe(-25)
    expect(result[0].absDelta).toBe(25)
  })
})

// ---------------------------------------------------------------------------
// Bounding
// ---------------------------------------------------------------------------

describe('topMovers — bounding', () => {
  // EARS-251-7: result bounded to TOP_MOVERS_N by default
  it('returns at most TOP_MOVERS_N actors by default', () => {
    const threats = Array.from({ length: 10 }, (_, i) =>
      makeThreat(`192.0.2.${i + 1}`, 80 - i, i * 5),
    )
    const result = topMovers(threats)
    expect(result.length).toBeLessThanOrEqual(TOP_MOVERS_N)
    expect(result).toHaveLength(TOP_MOVERS_N)
  })

  // EARS-251-8: custom topN honored
  it('respects a custom topN parameter', () => {
    const threats = Array.from({ length: 10 }, (_, i) =>
      makeThreat(`192.0.2.${i + 1}`, 80 - i, i * 5),
    )
    const result = topMovers(threats, 3)
    expect(result).toHaveLength(3)
  })
})

// ---------------------------------------------------------------------------
// Score-0 exclusion
// ---------------------------------------------------------------------------

describe('topMovers — score-0 exclusion', () => {
  // EARS-251-9: actors with score=0 excluded
  it('excludes actors with score=0 from the result', () => {
    const threats = [
      makeThreat('192.0.2.1', 50, 20),  // scored
      makeThreat('192.0.2.2', 0, 10),   // score=0 — excluded
      makeThreat('192.0.2.3', 30, 5),   // scored
    ]
    const result = topMovers(threats)
    const ips = result.map((m) => m.threat.source_ip)
    expect(ips).not.toContain('192.0.2.2')
    expect(ips).toContain('192.0.2.1')
    expect(ips).toContain('192.0.2.3')
  })
})

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('topMovers — edge cases', () => {
  // EARS-251-10: empty input → empty output
  it('returns empty array when threats is empty', () => {
    expect(topMovers([])).toEqual([])
  })

  // EARS-251-11: all null-delta → returned ordered by score
  it('handles all-null-delta input correctly (returns all as new actors by score)', () => {
    const threats = [
      makeThreat('192.0.2.1', 40, null),
      makeThreat('192.0.2.2', 80, null),
      makeThreat('192.0.2.3', 60, null),
    ]
    const result = topMovers(threats)
    expect(result.every((m) => m.isNew)).toBe(true)
    expect(result.map((m) => m.threat.score)).toEqual([80, 60, 40])
  })

  // EARS-251-12: all known-delta → no null-delta actors in result
  it('handles all-known-delta input correctly (no new actors)', () => {
    const threats = [
      makeThreat('192.0.2.1', 60, 10),
      makeThreat('192.0.2.2', 70, 38),
    ]
    const result = topMovers(threats)
    expect(result.every((m) => !m.isNew)).toBe(true)
  })

  // Does not mutate input
  it('does not mutate the input threats array', () => {
    const threats = [
      makeThreat('192.0.2.1', 60, 10),
      makeThreat('192.0.2.2', 70, 38),
    ]
    const original = [...threats]
    topMovers(threats)
    expect(threats).toEqual(original)
  })

  // delta=0 (score unchanged) is a known delta (not null → not new actor)
  it('treats delta=0 as a known delta (not a new actor)', () => {
    const threats = [makeThreat('192.0.2.1', 60, 0)]
    const result = topMovers(threats)
    expect(result[0].isNew).toBe(false)
    expect(result[0].delta).toBe(0)
    expect(result[0].absDelta).toBe(0)
  })
})
