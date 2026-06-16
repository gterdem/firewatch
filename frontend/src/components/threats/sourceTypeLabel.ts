/**
 * sourceTypeLabel — maps a server-provided source_type key to a human-readable label.
 *
 * Separated from SourceProvenanceBadges.tsx to satisfy the react-refresh
 * only-export-components lint rule.
 *
 * ADR-0024 modular-UI principle: the lookup table is a convenience only.
 * New sources appear via the generic title-case fallback — never gate on this table.
 */

const KNOWN_SOURCE_LABELS: Record<string, string> = {
  suricata: 'Suricata',
  azure_waf: 'Azure WAF',
  syslog: 'Syslog',
}

/**
 * Map a source_type key to a human-readable label.
 *
 * Known keys get a short label; anything else gets a title-cased version
 * of the key (e.g. "my_source" → "My Source"). Never returns empty string
 * for a non-empty key — the fallback always produces something displayable.
 */
export function sourceTypeLabel(key: string): string {
  if (!key) return '?'
  const known = KNOWN_SOURCE_LABELS[key]
  if (known !== undefined) return known
  // Generic fallback: replace underscores/hyphens with spaces, title-case each word.
  return key
    .replace(/[_-]/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
}
