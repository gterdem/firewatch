/**
 * ipHelpers — shared helpers for the IP entity panel sections (ADR-0037).
 *
 * Ported from IpDrilldownModal.tsx; all functions are pure and side-effect free.
 * SECURITY (ADR-0029 D3): safeText ensures attacker-controlled values are
 * rendered as plain strings — callers must use them in text nodes only.
 */

import type { TimelineEvent } from '../../ds'
import type { ThreatScore } from '../../../api/types'

// ---------------------------------------------------------------------------
// Safe text renderer
// ---------------------------------------------------------------------------

/** Coerce any value to a plain string for text-node rendering. */
export function safeText(v: unknown): string {
  if (v === null || v === undefined) return ''
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  try {
    return JSON.stringify(v)
  } catch {
    return '[unserializable]'
  }
}

// ---------------------------------------------------------------------------
// Score → color token (kit's scoreColor mapped to --fw-* tokens)
// ---------------------------------------------------------------------------

export function scoreColor(score: number): string {
  if (score >= 76) return 'var(--fw-red)'
  if (score >= 51) return 'var(--fw-orange)'
  if (score >= 26) return 'var(--fw-blue)'
  return 'var(--fw-green)'
}

// ---------------------------------------------------------------------------
// Attack category → color token (kit's CAT_COLOR mapped to --fw-* tokens)
// ---------------------------------------------------------------------------

export function categoryColor(cat: string): string {
  const lower = cat.toLowerCase()
  if (lower.includes('sql')) return 'var(--fw-orange)'
  if (lower.includes('rate') || lower.includes('limit')) return 'var(--fw-red)'
  if (lower.includes('xss')) return 'var(--fw-accent)'
  if (lower.includes('anomaly')) return 'var(--fw-purple)'
  if (lower.includes('bot')) return 'var(--fw-blue)'
  if (lower.includes('geo')) return 'var(--fw-cyan)'
  if (lower.includes('command') || lower.includes('injection')) return 'var(--fw-purple)'
  if (lower.includes('local file') || lower.includes('lfi')) return 'var(--fw-orange)'
  if (lower.includes('protocol')) return 'var(--fw-t2)'
  if (lower.includes('scanner') || lower.includes('scan')) return 'var(--fw-blue)'
  return 'var(--fw-t2)'
}

// ---------------------------------------------------------------------------
// Threat level → Badge tone
// ---------------------------------------------------------------------------

export function levelTone(level: string): 'critical' | 'high' | 'medium' | 'low' | 'neutral' {
  switch (level.toUpperCase()) {
    case 'CRITICAL': return 'critical'
    case 'HIGH': return 'high'
    case 'MEDIUM': return 'medium'
    case 'LOW': return 'low'
    default: return 'neutral'
  }
}

// ---------------------------------------------------------------------------
// Shared section label style (kit's SEC_LBL)
// ---------------------------------------------------------------------------

export const SEC_LBL: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 600,
  textTransform: 'uppercase',
  letterSpacing: '.5px',
  color: 'var(--fw-t3)',
}

// ---------------------------------------------------------------------------
// Build coarse EventTimeline events from ThreatScore (OD-3 fallback)
// ---------------------------------------------------------------------------

/**
 * Build cross-source EventTimeline entries from the fast ThreatScore data.
 * OD-3 (approved): coarser than per-event feed; used as fallback when
 * /threats/{ip}/events returns 404 or is still loading.
 */
export function buildTimelineEvents(score: ThreatScore): TimelineEvent[] {
  const sources = score.source_types ?? []
  const isCorrelated = sources.length > 1
  const lastSeen = score.last_seen ?? ''
  const firstSeen = score.first_seen ?? ''

  return sources.map((src, i): TimelineEvent => ({
    source: src,
    time: i === 0 ? lastSeen : firstSeen,
    label: src,
    payload: `${score.total_events} total events · ${score.blocked_events} blocked`,
    correlated: isCorrelated,
  }))
}
