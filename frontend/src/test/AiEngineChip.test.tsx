/**
 * Tests for src/components/dashboard/aiEngineStatus.ts — deriveAiStatus utility.
 *
 * Note (issue #97): AiEngineChip has been deleted and replaced by the shared
 * AiStatusChip component (src/components/AiStatusChip.tsx). The AiEngineChip
 * component render tests have moved to AiStatusChip.test.tsx.
 *
 * This file retains the deriveAiStatus unit tests because that module is still
 * used by both DashboardRoute and AIRoute.
 */

import { describe, it, expect } from 'vitest'
import { deriveAiStatus } from '../components/dashboard/aiEngineStatus'
import type { ThreatScore } from '../api/types'

function makeThreat(ai_status: string): ThreatScore {
  return {
    source_ip: '192.0.2.1',
    threat_level: 'LOW',
    score: 10,
    total_events: 5,
    blocked_events: 1,
    attack_types: [],
    first_seen: null,
    last_seen: null,
    source_types: ['suricata'],
    detections: [],
    ai_insights: null,
    ai_confidence: null,
    ai_status,
    location: null,
    score_breakdown: [],
    asn: null,
    as_name: null,
    score_delta: null,
  }
}

describe('deriveAiStatus', () => {
  it('returns null for an empty threats array', () => {
    expect(deriveAiStatus([])).toBeNull()
  })

  it('returns "active" when any threat has ai_status=active', () => {
    const threats = [makeThreat('unavailable'), makeThreat('active')]
    expect(deriveAiStatus(threats)).toBe('active')
  })

  it('returns "disabled" when no active but some disabled', () => {
    const threats = [makeThreat('unavailable'), makeThreat('disabled')]
    expect(deriveAiStatus(threats)).toBe('disabled')
  })

  it('returns "unavailable" when all threats are unavailable', () => {
    const threats = [makeThreat('unavailable'), makeThreat('unavailable')]
    expect(deriveAiStatus(threats)).toBe('unavailable')
  })

  it('returns first threat status as fallback for unknown values', () => {
    const threats = [makeThreat('error')]
    expect(deriveAiStatus(threats)).toBe('error')
  })
})
