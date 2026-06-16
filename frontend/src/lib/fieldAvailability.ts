/**
 * fieldAvailability — ML-5 (#433) static field-availability notes.
 *
 * Extended in issue #664 (ADR-0060) with a column-key → canonical SecurityEvent
 * field name map, used by useStructuralColumns to implement Option-B structural
 * empty-column hiding (structural, value-blind — NOT "every cell is empty").
 *
 * Separated from the React component per fast-refresh rules
 * (react-refresh/only-export-components: constants and components must not share a file).
 *
 * SECURITY (ADR-0029 D3): all entries are static string constants — no attacker-
 * controlled data is stored or interpolated here.
 */

/**
 * Static notes for columns that may show "—" due to source field availability.
 * Keyed by the display-label of the column (matches the header label in LogsTable).
 */
export const FIELD_NOTES: Record<string, string> = {
  Destination: 'L7-only sources (e.g. Azure WAF) do not record destination IP — they inspect HTTP, not TCP flows. Suricata and similar L3–L7 sources do populate this field.',
  Protocol: 'L7-only sources (e.g. Azure WAF) do not record transport protocol — no TCP/UDP layer is visible to an HTTP WAF. Suricata and similar L3–L7 sources do populate this field.',
  'Dest Port': 'L7-only sources may not record destination port separately from the HTTP request context.',
  JA4: 'JA4 TLS fingerprints are emitted by Suricata/Zeek when configured with the ja4 output plugin. Azure WAF and other L7 sources do not emit JA4 fingerprints.',
  'DNS / DGA': 'DNS query fields are emitted by sources with DNS logging enabled (e.g. Suricata with dns.log). Azure WAF and HTTP-only sources do not record DNS queries.',
} as const

/** Set of column labels that have a field-availability note. */
export const COLUMNS_WITH_NOTES = new Set(Object.keys(FIELD_NOTES))

/**
 * Maps LogsTable column keys to their canonical SecurityEvent field name
 * and display label for structural-absence checking (ADR-0060 D4).
 *
 * Only optional columns whose canonical field may be declared in
 * SourceMetadata.produces are listed here. Always-present columns (time, source,
 * sourceip, severity, action, signature, payload) are omitted — they are never
 * structurally hidden.
 *
 * The displayLabel is used in the +N chip popover alongside FIELD_NOTES copy.
 */
export const COLUMN_CANONICAL_FIELDS: Record<string, { canonicalField: string; displayLabel: string }> = {
  destip:   { canonicalField: 'destination_ip',   displayLabel: 'Destination' },
  protocol: { canonicalField: 'protocol',          displayLabel: 'Protocol' },
  destport: { canonicalField: 'destination_port',  displayLabel: 'Dest Port' },
  tls_ja4:  { canonicalField: 'tls_ja4',           displayLabel: 'JA4' },
  dns:      { canonicalField: 'dns_query',          displayLabel: 'DNS / DGA' },
} as const
