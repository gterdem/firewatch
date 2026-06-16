/**
 * Tests for lib/recommendationQueue.ts (issue #208).
 *
 * EARS acceptance criteria covered:
 *   - deriveRecAction: correct thresholds (80/30).
 *   - buildRationale: correct text for each action tier.
 *   - buildCopySnippet: returns paste-ready iptables string.
 *   - buildRecommendationQueue — core contract:
 *     RULE items: every actor gets a RULE item; never empty when threats are present.
 *     AI upgrade: aiOnline=true + ai_status=active + ai_insights → 'ai+rule' provenance.
 *     AI offline: aiOnline=false → ALL items are 'rule' even if ai_status=active.
 *     Sort order: block > investigate > monitor, then score desc within same tier.
 *     Dedupe: one item per source_ip (AI upgrade wins).
 *     Empty input: returns empty array.
 *
 * RFC 5737 IPs only (192.0.2.x / 198.51.100.x) — gitleaks gate.
 */

import { describe, it, expect } from 'vitest'
import {
  deriveRecAction,
  buildRationale,
  buildCopySnippet,
  buildCounterfactualLine,
  buildRecommendationQueue,
} from '../lib/recommendationQueue'
import type { ThreatScore } from '../api/types'

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function makeThreat(
  ip: string,
  score: number,
  totalEvents: number,
  blockedEvents: number,
  opts: Partial<ThreatScore> = {},
): ThreatScore {
  return {
    source_ip: ip,
    threat_level: 'HIGH',
    score,
    total_events: totalEvents,
    blocked_events: blockedEvents,
    attack_types: ['SQL Injection'],
    first_seen: '2026-06-04T06:00:00Z',
    last_seen: '2026-06-04T10:00:00Z',
    source_types: ['suricata'],
    detections: [],
    ai_insights: null,
    ai_confidence: null,
    ai_status: 'unavailable',
    location: null,
    score_breakdown: [],
    asn: null,
    as_name: null,
    score_delta: null,
    ...opts,
  }
}

// ---------------------------------------------------------------------------
// deriveRecAction
// ---------------------------------------------------------------------------

describe('deriveRecAction', () => {
  it('returns "block" when blockRate >= 80', () => {
    expect(deriveRecAction(80)).toBe('block')
    expect(deriveRecAction(100)).toBe('block')
    expect(deriveRecAction(99)).toBe('block')
  })

  it('returns "investigate" when blockRate >= 30 and < 80', () => {
    expect(deriveRecAction(30)).toBe('investigate')
    expect(deriveRecAction(50)).toBe('investigate')
    expect(deriveRecAction(79)).toBe('investigate')
  })

  it('returns "monitor" when blockRate < 30', () => {
    expect(deriveRecAction(0)).toBe('monitor')
    expect(deriveRecAction(10)).toBe('monitor')
    expect(deriveRecAction(29)).toBe('monitor')
  })
})

// ---------------------------------------------------------------------------
// buildRationale
// ---------------------------------------------------------------------------

describe('buildRationale', () => {
  it('produces correct rationale for block action', () => {
    const r = buildRationale(100, 150, 'block')
    expect(r).toContain('100%')
    expect(r).toContain('150')
    expect(r).toContain('exceeds block threshold')
  })

  it('produces correct rationale for investigate action', () => {
    const r = buildRationale(45, 30, 'investigate')
    expect(r).toContain('45%')
    expect(r).toContain('30')
    expect(r).toContain('above investigate threshold')
  })

  it('produces correct rationale for monitor action', () => {
    const r = buildRationale(8, 25, 'monitor')
    expect(r).toContain('8%')
    expect(r).toContain('25')
    expect(r).toContain('below investigation threshold')
  })

  it('uses singular "event" for a single event', () => {
    const r = buildRationale(100, 1, 'block')
    expect(r).toContain('1 event ')
    expect(r).not.toContain('1 events')
  })
})

// ---------------------------------------------------------------------------
// buildCopySnippet
// ---------------------------------------------------------------------------

describe('buildCopySnippet', () => {
  it('returns a string containing the IP and iptables DROP command', () => {
    const snippet = buildCopySnippet('192.0.2.1')
    expect(snippet).toContain('192.0.2.1')
    expect(snippet).toContain('DROP')
  })

  it('uses the provided IP as-is', () => {
    const snippet = buildCopySnippet('198.51.100.50')
    expect(snippet).toContain('198.51.100.50')
  })
})

// ---------------------------------------------------------------------------
// buildRecommendationQueue
// ---------------------------------------------------------------------------

describe('buildRecommendationQueue', () => {
  it('returns empty array for empty threats', () => {
    expect(buildRecommendationQueue([])).toEqual([])
  })

  it('returns one item per actor', () => {
    const threats = [
      makeThreat('192.0.2.1', 80, 100, 90),
      makeThreat('192.0.2.2', 50, 30, 10),
    ]
    const queue = buildRecommendationQueue(threats, false)
    expect(queue).toHaveLength(2)
  })

  it('assigns RULE provenance when aiOnline=false (even if ai_status=active)', () => {
    const threats = [
      makeThreat('192.0.2.1', 80, 100, 90, {
        ai_status: 'active',
        ai_insights: ['Intent: exfiltration'],
      }),
    ]
    const queue = buildRecommendationQueue(threats, false)
    expect(queue[0].provenance).toBe('rule')
    expect(queue[0].aiRationale).toBeNull()
  })

  it('assigns RULE provenance when ai_status is not active', () => {
    const threats = [
      makeThreat('192.0.2.1', 80, 100, 90, { ai_status: 'unavailable' }),
    ]
    const queue = buildRecommendationQueue(threats, true)
    expect(queue[0].provenance).toBe('rule')
  })

  it('upgrades to ai+rule when aiOnline=true AND ai_status=active AND has insights', () => {
    const threats = [
      makeThreat('192.0.2.1', 80, 100, 90, {
        ai_status: 'active',
        ai_insights: ['Intent: exfiltration', 'Risk: lateral movement'],
      }),
    ]
    const queue = buildRecommendationQueue(threats, true)
    expect(queue[0].provenance).toBe('ai+rule')
    expect(queue[0].aiRationale).toBe('Intent: exfiltration')
  })

  it('keeps RULE when aiOnline=true but ai_insights is null', () => {
    const threats = [
      makeThreat('192.0.2.1', 80, 100, 90, {
        ai_status: 'active',
        ai_insights: null,
      }),
    ]
    const queue = buildRecommendationQueue(threats, true)
    expect(queue[0].provenance).toBe('rule')
  })

  it('keeps RULE when aiOnline=true but ai_insights is empty array', () => {
    const threats = [
      makeThreat('192.0.2.1', 80, 100, 90, {
        ai_status: 'active',
        ai_insights: [],
      }),
    ]
    const queue = buildRecommendationQueue(threats, true)
    expect(queue[0].provenance).toBe('rule')
  })

  it('sorts block before investigate, investigate before monitor', () => {
    // monitor (8% blocked), investigate (50% blocked), block (90% blocked)
    const threats = [
      makeThreat('192.0.2.1', 50, 25, 2),   // 8% → monitor
      makeThreat('192.0.2.2', 60, 30, 15),  // 50% → investigate
      makeThreat('192.0.2.3', 70, 100, 90), // 90% → block
    ]
    const queue = buildRecommendationQueue(threats, false)
    expect(queue[0].recAction).toBe('block')
    expect(queue[1].recAction).toBe('investigate')
    expect(queue[2].recAction).toBe('monitor')
  })

  it('sorts by score desc within the same action tier', () => {
    const threats = [
      makeThreat('192.0.2.1', 60, 100, 90), // block, score 60
      makeThreat('192.0.2.2', 90, 100, 85), // block, score 90 (87% blocked = block)
    ]
    const queue = buildRecommendationQueue(threats, false)
    // Both are block-tier; higher score first
    expect(queue[0].actor.source_ip).toBe('192.0.2.2') // score 90
    expect(queue[1].actor.source_ip).toBe('192.0.2.1') // score 60
  })

  it('deduplicates by source_ip', () => {
    // Same IP appearing twice — should only produce one item
    const threats = [
      makeThreat('192.0.2.1', 80, 100, 90),
      makeThreat('192.0.2.1', 80, 100, 90),
    ]
    const queue = buildRecommendationQueue(threats, false)
    expect(queue).toHaveLength(1)
  })

  it('ai+rule provenance wins over rule on deduplicated actor', () => {
    // Same IP: first without AI, second with AI
    const threats = [
      makeThreat('192.0.2.1', 80, 100, 90, { ai_status: 'unavailable' }),
      makeThreat('192.0.2.1', 80, 100, 90, {
        ai_status: 'active',
        ai_insights: ['Intent: exfiltration'],
      }),
    ]
    const queue = buildRecommendationQueue(threats, true)
    expect(queue).toHaveLength(1)
    expect(queue[0].provenance).toBe('ai+rule')
  })

  it('each item includes a non-empty copySnippet containing the IP', () => {
    const threats = [makeThreat('192.0.2.5', 80, 100, 90)]
    const queue = buildRecommendationQueue(threats, false)
    expect(queue[0].copySnippet).toContain('192.0.2.5')
    expect(queue[0].copySnippet.length).toBeGreaterThan(0)
  })

  it('each item has a rationale string', () => {
    const threats = [makeThreat('192.0.2.1', 80, 100, 90)]
    const queue = buildRecommendationQueue(threats, false)
    expect(typeof queue[0].rationale).toBe('string')
    expect(queue[0].rationale.length).toBeGreaterThan(0)
  })

  it('item id equals source_ip', () => {
    const threats = [makeThreat('192.0.2.1', 80, 100, 90)]
    const queue = buildRecommendationQueue(threats, false)
    expect(queue[0].id).toBe('192.0.2.1')
  })

  it('actor reference is the original ThreatScore', () => {
    const threat = makeThreat('192.0.2.1', 80, 100, 90)
    const queue = buildRecommendationQueue([threat], false)
    expect(queue[0].actor).toBe(threat)
  })

  it('each item includes counterfactualLine derived from total/blocked events', () => {
    // 100 total, 10 blocked → 90 unblocked → "Would have stopped 90 of 100"
    const threats = [makeThreat('192.0.2.1', 80, 100, 10)]
    const queue = buildRecommendationQueue(threats, false)
    expect(queue[0].counterfactualLine).not.toBeNull()
    expect(queue[0].counterfactualLine).toContain('90')
    expect(queue[0].counterfactualLine).toContain('100')
  })

  it('counterfactualLine is null when total_events is 0', () => {
    const threats = [makeThreat('192.0.2.1', 0, 0, 0)]
    const queue = buildRecommendationQueue(threats, false)
    expect(queue[0].counterfactualLine).toBeNull()
  })

  // ---------------------------------------------------------------------------
  // Issue #564 — isActorDismissed predicate
  // EARS: dismissed actors are excluded from buildRecommendationQueue output so
  // the card queue matches the triage banner.
  // ---------------------------------------------------------------------------

  it('excludes actors for which isActorDismissed returns true (issue #564)', () => {
    const t1 = makeThreat('192.0.2.1', 80, 100, 90)
    const t2 = makeThreat('192.0.2.2', 60, 30, 15)
    // Dismiss t1 only
    const queue = buildRecommendationQueue([t1, t2], false, (a) => a.source_ip === '192.0.2.1')
    expect(queue).toHaveLength(1)
    expect(queue[0].id).toBe('192.0.2.2')
  })

  it('returns empty queue when all actors are dismissed (issue #564)', () => {
    const threats = [
      makeThreat('192.0.2.1', 80, 100, 90),
      makeThreat('192.0.2.2', 60, 30, 15),
    ]
    const queue = buildRecommendationQueue(threats, false, () => true)
    expect(queue).toHaveLength(0)
  })

  it('returns full queue when no actors are dismissed — isActorDismissed always false (issue #564)', () => {
    const threats = [
      makeThreat('192.0.2.1', 80, 100, 90),
      makeThreat('192.0.2.2', 60, 30, 15),
    ]
    const queue = buildRecommendationQueue(threats, false, () => false)
    expect(queue).toHaveLength(2)
  })

  it('omitting isActorDismissed is backward-compatible — defaults to no filtering (issue #564)', () => {
    // Pre-fix callers that don't pass the third arg still get all actors.
    const threats = [
      makeThreat('192.0.2.1', 80, 100, 90),
      makeThreat('192.0.2.2', 60, 30, 15),
    ]
    const queue = buildRecommendationQueue(threats, false)
    expect(queue).toHaveLength(2)
  })
})

// ---------------------------------------------------------------------------
// buildCounterfactualLine
// ---------------------------------------------------------------------------

describe('buildCounterfactualLine', () => {
  it('returns null when total_events is 0', () => {
    expect(buildCounterfactualLine(0, 0)).toBeNull()
  })

  it('returns "Would have stopped N of M" when unblocked > 0', () => {
    const line = buildCounterfactualLine(1350, 146)
    expect(line).not.toBeNull()
    expect(line).toContain('1,204')
    expect(line).toContain('1,350')
    expect(line).toMatch(/Would have stopped/)
  })

  it('uses singular "request" for 1 unblocked event', () => {
    const line = buildCounterfactualLine(2, 1)
    expect(line).toContain('1 request ')
    expect(line).not.toContain('1 requests')
  })

  it('uses plural "requests" for >1 unblocked events', () => {
    const line = buildCounterfactualLine(100, 90)
    expect(line).toContain('10 requests')
  })

  it('returns "All N requests already blocked" when unblocked_events is 0', () => {
    const line = buildCounterfactualLine(150, 150)
    expect(line).not.toBeNull()
    expect(line).toMatch(/All/)
    expect(line).toContain('150')
    expect(line).toMatch(/already blocked/)
  })

  it('EARS: count is reproducible — unblocked = total - blocked', () => {
    // The arithmetic invariant: the number shown equals total - blocked
    const total = 500
    const blocked = 123
    const line = buildCounterfactualLine(total, blocked)
    // line contains the unblocked count (377)
    expect(line).toContain('377')
  })
})
