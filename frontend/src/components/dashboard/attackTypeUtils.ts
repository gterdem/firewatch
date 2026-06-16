/**
 * Attack-type aggregation and MITRE label mapping utilities (issue #206).
 *
 * Pure functions extracted from AttackCategoriesPane.tsx so the component file
 * exports only the React component (react-refresh/only-export-components rule).
 *
 * MITRE mapping is static and conservative: only clean, well-known mappings are
 * included. Unknown labels pass through verbatim (ADR-0014).
 *
 * Sources:
 *   MITRE ATT&CK v18 tactic names — https://attack.mitre.org/tactics/enterprise/
 *   CRS/Suricata category strings from engine runtime output observed in tests.
 */

import type { ThreatScore } from '../../api/types'
import type { BarRow } from './HorizontalBarList'

/**
 * Conservative MITRE ATT&CK tactic label mapping (ADR-0014).
 *
 * Maps common engine rule-category strings to MITRE tactic names where a
 * clean mapping exists. Unknown / ambiguous labels pass through verbatim.
 */
const MITRE_LABEL_MAP: Record<string, string> = {
  // T1190 Exploit Public-Facing Application — SQL/XSS/LFI injection families
  'sql injection': 'SQL Injection (T1190)',
  'sqli': 'SQL Injection (T1190)',
  'sql_injection': 'SQL Injection (T1190)',
  'xss': 'XSS — Injection (T1190)',
  'lfi': 'LFI — Path Traversal (T1083)',
  // T1595 Active Scanning
  'scan': 'Active Scanning (T1595)',
  'scanner': 'Active Scanning (T1595)',
  'port scan': 'Active Scanning (T1595)',
  'port_scan': 'Active Scanning (T1595)',
  // T1110 Brute Force
  'brute force': 'Brute Force (T1110)',
  'brute_force': 'Brute Force (T1110)',
  // T1059 Command and Scripting Interpreter
  'cmdi': 'Command Injection (T1059)',
  'command injection': 'Command Injection (T1059)',
  // T1587.001 Malware
  'malware': 'Malware (T1587)',
  // Geo-block (not a MITRE tactic — leave verbatim)
  'geo block': 'Geo Block',
  'geo-block': 'Geo Block',
  'geo_block': 'Geo Block',
}

/**
 * Apply the MITRE label mapping. Unknown labels pass through unchanged.
 */
export function applyMitreLabel(raw: string): string {
  const key = raw.trim().toLowerCase()
  return MITRE_LABEL_MAP[key] ?? raw
}

/**
 * Aggregate attack_types across all threat actors.
 * Each actor counts once per attack type it reported (actor-frequency, not event-count).
 * Returns rows sorted by count descending.
 */
export function aggregateAttackTypes(threats: ThreatScore[]): BarRow[] {
  const tally = new Map<string, number>()
  for (const actor of threats) {
    // Deduplicate within a single actor (an actor shouldn't double-count a type)
    const seen = new Set<string>()
    for (const raw of actor.attack_types) {
      if (!raw || seen.has(raw)) continue
      seen.add(raw)
      const label = applyMitreLabel(raw)
      tally.set(label, (tally.get(label) ?? 0) + 1)
    }
  }
  return Array.from(tally.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count)
}
