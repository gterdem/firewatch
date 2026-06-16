/**
 * actorRollup.ts — pure grouping/rollup logic for the DDoS-aware ThreatActors pane (issue #212).
 *
 * When the number of scored actors exceeds ROLLUP_CUTOFF, per-IP rows are rolled up into
 * group rows — keyed by ASN first, falling back to /24 CIDR prefix when ASN data is absent.
 *
 * All functions here are pure (no side effects, no React) and O(n) so they are safe to call
 * inside useMemo with a large actor list.
 *
 * SECURITY: all string fields (as_name, source_ip) are attacker-controlled.
 * Consumers MUST render them as text nodes only — never via dangerouslySetInnerHTML.
 *
 * Wave-3 (#251): the "Top movers" sort now uses the real ``score_delta`` field added to the
 * ThreatScore DTO in issue #250. Actors with score_delta=null (new actors, no prior snapshot
 * in the 1h window) are sorted to the end by score descending. The first_seen DELTA_PROXY
 * has been removed.
 */

import type { ThreatScore } from '../api/types'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * When the number of scored actors in the window exceeds this value, the pane
 * switches from per-IP rows to ASN//24 group rows plus a rollup banner.
 *
 * Default: 50 (issue #212 EARS). Not user-configurable yet (later Settings concern).
 */
export const ROLLUP_CUTOFF = 50

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A rollup group — either keyed by ASN or by /24 CIDR prefix.
 */
export interface ActorGroup {
  /** Grouping key discriminator. */
  kind: 'asn' | 'cidr'
  /**
   * For kind="asn": the ASN number as string (e.g. "AS4837").
   * For kind="cidr": the /24 prefix (e.g. "192.0.2").
   */
  key: string
  /**
   * Human-readable display label.
   * For kind="asn": "<AS name> (AS<num>)" or "AS<num>" if no name.
   * For kind="cidr": "<prefix>.0/24"
   */
  label: string
  /** Total number of distinct IPs in this group (across all scored actors). */
  memberCount: number
  /** Top score among group members. */
  topScore: number
  /** Top threat level string among group members (highest by score). */
  topThreatLevel: string
  /** Top member IPs by score (up to 10, for the group slide-over). */
  topMembers: ThreatScore[]
  /** Sum of all events from group members. */
  totalEvents: number
  /** Sum of all blocked events from group members. */
  totalBlockedEvents: number
}

// ---------------------------------------------------------------------------
// /24 prefix helpers
// ---------------------------------------------------------------------------

/**
 * Extract the /24 prefix from an IPv4 address string.
 *
 * Examples:
 *   cidr24("192.168.1.100") → "192.168.1"
 *   cidr24("10.0.0.1")     → "10.0.0"
 *   cidr24("not-an-ip")    → null
 */
export function cidr24(ip: string): string | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  return `${parts[0]}.${parts[1]}.${parts[2]}`
}

// ---------------------------------------------------------------------------
// Grouping logic
// ---------------------------------------------------------------------------

/**
 * Group a list of scored threats into ActorGroup records.
 *
 * Strategy (per issue #212 EARS):
 *   1. If a threat has a non-null ASN, group by ASN.
 *   2. Otherwise, group by /24 CIDR prefix.
 *   3. Threats whose IP cannot be parsed as an IPv4 address AND have no ASN
 *      are placed in a fallback "unknown" cidr group (key = "unknown").
 *
 * @param threats - Array of scored ThreatScore records (score > 0).
 * @returns Array of ActorGroup records, sorted by topScore descending.
 */
export function groupThreats(threats: ThreatScore[]): ActorGroup[] {
  // Map: groupKey → accumulated data
  const map = new Map<
    string,
    {
      kind: 'asn' | 'cidr'
      key: string
      label: string
      members: ThreatScore[]
    }
  >()

  for (const t of threats) {
    let groupKey: string
    let kind: 'asn' | 'cidr'
    let label: string

    if (t.asn !== null && t.asn !== undefined) {
      // ASN grouping — preferred
      const asnStr = `AS${t.asn}`
      groupKey = asnStr
      kind = 'asn'
      label = t.as_name ? `${t.as_name} (${asnStr})` : asnStr
    } else {
      // /24 CIDR fallback
      const prefix = cidr24(t.source_ip)
      if (prefix !== null) {
        groupKey = `cidr:${prefix}`
        kind = 'cidr'
        label = `${prefix}.0/24`
      } else {
        // Unparseable IP, no ASN — use "unknown" bucket
        groupKey = 'cidr:unknown'
        kind = 'cidr'
        label = 'unknown'
      }
    }

    const existing = map.get(groupKey)
    if (existing) {
      existing.members.push(t)
      // Keep the label from the first member that has an as_name
      if (kind === 'asn' && t.as_name && existing.label === existing.key) {
        existing.label = label
      }
    } else {
      map.set(groupKey, { kind, key: groupKey, label, members: [t] })
    }
  }

  const groups: ActorGroup[] = []
  for (const { kind, key, label, members } of map.values()) {
    // Sort members by score descending, take top 10 for the group view
    const sorted = [...members].sort((a, b) => b.score - a.score)
    const topScore = sorted[0]?.score ?? 0
    const topThreatLevel = sorted[0]?.threat_level ?? 'LOW'
    const totalEvents = members.reduce((acc, m) => acc + m.total_events, 0)
    const totalBlockedEvents = members.reduce((acc, m) => acc + m.blocked_events, 0)

    groups.push({
      kind,
      key,
      label,
      memberCount: members.length,
      topScore,
      topThreatLevel,
      topMembers: sorted.slice(0, 10),
      totalEvents,
      totalBlockedEvents,
    })
  }

  // Sort groups by topScore descending
  return groups.sort((a, b) => b.topScore - a.topScore)
}

// ---------------------------------------------------------------------------
// Sort helpers
// ---------------------------------------------------------------------------

/** Sort mode for the ThreatActors pane. */
export type SortMode = 'score' | 'top-movers'

/**
 * Sort a list of threats by the given sort mode.
 *
 * 'score':      Descending by score (existing default).
 * 'top-movers': Descending by |score_delta| (biggest mover first — real delta from #250).
 *               Actors with score_delta=null (new actors, no prior snapshot in the 1h
 *               window) are ranked after all actors with a known delta, then by score.
 *
 * @param threats - Array of ThreatScore records.
 * @param mode    - Sort mode.
 * @returns New sorted array (original is not mutated).
 */
export function sortThreats(threats: ThreatScore[], mode: SortMode): ThreatScore[] {
  const copy = [...threats]
  if (mode === 'score') {
    return copy.sort((a, b) => b.score - a.score)
  }
  // top-movers: rank by |score_delta| descending; null-delta actors go last.
  return copy.sort((a, b) => {
    const aHasDelta = a.score_delta !== null && a.score_delta !== undefined
    const bHasDelta = b.score_delta !== null && b.score_delta !== undefined
    // Known-delta actors always rank before null-delta actors.
    if (aHasDelta && !bHasDelta) return -1
    if (!aHasDelta && bHasDelta) return 1
    // Both have deltas: sort by |delta| descending.
    if (aHasDelta && bHasDelta) {
      const absDeltaA = Math.abs(a.score_delta as number)
      const absDeltaB = Math.abs(b.score_delta as number)
      if (absDeltaB !== absDeltaA) return absDeltaB - absDeltaA
    }
    // Tie-break (both null or equal |delta|): score descending.
    return b.score - a.score
  })
}
