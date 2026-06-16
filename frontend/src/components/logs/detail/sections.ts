/**
 * sections.ts — declarative section model for LogDetailPanel (ADR-0063 D3).
 *
 * Ordered list of { id, title, fields } that drives the panel renderer.
 * Grouping is defined here, not in JSX, so it is independently testable
 * and reorderable without touching the render layer.
 *
 * SECURITY (ADR-0029 D3): every field accessor value is rendered as a React
 * text node by DetailField; no section definition here permits HTML injection.
 *
 * Sections are omitted from the rendered panel when all their fields are empty
 * (honesty: never fabricate a "—" wall for sections that have no data).
 */

import type { LogEntry } from '../../../api/types'

/** One field row in the detail panel. */
export interface PanelField {
  /** Label shown in the left column. */
  label: string
  /**
   * Value accessor: a key on LogEntry, or a function from LogEntry → string|null.
   * Function accessors resolve multi-alias fields (e.g. payload_snippet | http_payload).
   * Returns null/undefined/'' → field is considered absent; omit the row.
   */
  accessor: keyof LogEntry | ((entry: LogEntry) => string | null | undefined)
  /** When true, render value in monospace. */
  mono?: boolean
  /** When true, show a Copy affordance for the full value. */
  copyable?: boolean
  /**
   * Optional hint text rendered beneath the label — used for provenance notes
   * (e.g. "RULE — local heuristic, zero-egress" on DGA score) per ADR-0035.
   */
  hint?: string
}

/** One section group in the detail panel. */
export interface PanelSection {
  id: string
  title: string
  fields: PanelField[]
}

// ---------------------------------------------------------------------------
// Field helpers (typed accessors)
// ---------------------------------------------------------------------------

function getString(entry: LogEntry, key: string): string | null | undefined {
  const v = (entry as Record<string, unknown>)[key]
  if (v == null) return null
  const s = String(v)
  return s === '' ? null : s
}

/** Resolve payload from payload_snippet → http_payload → payload (native fallback). */
function getPayload(entry: LogEntry): string | null | undefined {
  const v =
    (entry as Record<string, unknown>).payload_snippet ??
    (entry as Record<string, unknown>).http_payload ??
    (entry as Record<string, unknown>).payload
  if (v == null) return null
  const s = String(v)
  return s === '' ? null : s
}

/** Resolve signature from rule_name → signature → rule_id. */
function getSignature(entry: LogEntry): string | null | undefined {
  const ruleName = (entry as Record<string, unknown>).rule_name
  if (ruleName != null && String(ruleName) !== '') return String(ruleName)
  const signature = (entry as Record<string, unknown>).signature
  if (signature != null && String(signature) !== '') return String(signature)
  const ruleId = (entry as Record<string, unknown>).rule_id
  if (ruleId != null) return String(ruleId)
  return null
}

/** Resolve destination port from destination_port → dest_port → dp. */
function getDestPort(entry: LogEntry): string | null | undefined {
  const v =
    (entry as Record<string, unknown>).destination_port ??
    (entry as Record<string, unknown>).dest_port ??
    (entry as Record<string, unknown>).dp
  if (v == null) return null
  return String(v)
}

/** Resolve raw_log as a string. */
function getRawLog(entry: LogEntry): string | null | undefined {
  const v = entry.raw_log
  if (v == null) return null
  if (typeof v === 'string') return v === '' ? null : v
  try {
    return JSON.stringify(v, null, 2)
  } catch {
    return String(v)
  }
}

// ---------------------------------------------------------------------------
// Section definitions (ADR-0063 D3 grouping)
// ---------------------------------------------------------------------------

export const DETAIL_SECTIONS: PanelSection[] = [
  {
    id: 'identity',
    title: 'Identity',
    fields: [
      { label: 'Event ID',    accessor: 'id',          mono: true },
      { label: 'Timestamp',   accessor: 'timestamp',   mono: true },
      { label: 'Source',      accessor: 'source_type' },
      { label: 'Source ID',   accessor: 'source_id' },
      { label: 'Category',    accessor: 'category' },
    ],
  },
  {
    id: 'network',
    title: 'Network',
    fields: [
      {
        label: 'Source IP',
        accessor: 'source_ip',
        mono: true,
      },
      {
        label: 'Destination IP',
        accessor: 'destination_ip',
        mono: true,
      },
      {
        label: 'Destination Port',
        accessor: getDestPort,
        mono: true,
      },
      {
        label: 'Protocol',
        accessor: 'protocol',
        mono: true,
      },
    ],
  },
  {
    id: 'tls',
    title: 'TLS / JA4',
    fields: [
      {
        label: 'JA4',
        accessor: 'tls_ja4',
        mono: true,
        copyable: true,
      },
      {
        label: 'JA4S',
        accessor: 'tls_ja4s',
        mono: true,
        copyable: true,
      },
      {
        label: 'SNI',
        accessor: 'tls_sni',
        mono: true,
      },
      {
        label: 'TLS Version',
        accessor: 'tls_version',
        mono: true,
      },
    ],
  },
  {
    id: 'dns',
    title: 'DNS',
    fields: [
      {
        label: 'DNS Query',
        accessor: 'dns_query',
        mono: true,
        copyable: true,
      },
      {
        label: 'DGA Score',
        accessor: (entry: LogEntry): string | null => {
          const v = (entry as Record<string, unknown>).dga_score
          if (v == null) return null
          if (typeof v !== 'number') return null
          return v.toFixed(3)
        },
        mono: true,
        hint: '[RULE] Local heuristic (entropy/consonant/digit ratios) — zero-egress, no DNS lookups.',
      },
    ],
  },
  {
    id: 'http',
    title: 'HTTP',
    fields: [
      {
        label: 'Payload',
        accessor: getPayload,
        mono: true,
        copyable: true,
      },
    ],
  },
  {
    id: 'detection',
    title: 'Detection',
    fields: [
      {
        label: 'Rule Name',
        accessor: getSignature,
      },
      {
        label: 'Rule ID',
        accessor: (entry: LogEntry): string | null => {
          const v = (entry as Record<string, unknown>).rule_id
          return v != null ? String(v) : null
        },
        mono: true,
      },
      {
        label: 'Severity',
        accessor: 'severity',
      },
      {
        label: 'Action',
        accessor: (entry: LogEntry): string | null => {
          return entry.action != null ? String(entry.action) : null
        },
      },
    ],
  },
  {
    id: 'geo',
    title: 'Geo',
    fields: [
      { label: 'City',    accessor: 'geo_city' },
      { label: 'Country', accessor: 'geo_country' },
      {
        label: 'ASN',
        accessor: (entry: LogEntry): string | null => {
          const v = getString(entry, 'asn') ?? getString(entry, 'geo_asn')
          return v ?? null
        },
        mono: true,
      },
      {
        label: 'AS Name',
        accessor: (entry: LogEntry): string | null => {
          return (getString(entry, 'as_name') ?? getString(entry, 'geo_as_name')) ?? null
        },
      },
    ],
  },
  {
    id: 'raw',
    title: 'Provenance / Raw',
    fields: [
      {
        label: 'raw_log',
        accessor: getRawLog,
        mono: true,
        copyable: true,
        hint: 'Attacker-controlled — shown verbatim.',
      },
    ],
  },
]

// ---------------------------------------------------------------------------
// Accessor resolution helper — used by both DetailField and tests.
// ---------------------------------------------------------------------------

/**
 * Resolve the value for a PanelField from a LogEntry.
 * Returns null/undefined when the field is absent or empty.
 */
export function resolveFieldValue(
  field: PanelField,
  entry: LogEntry,
): string | null | undefined {
  if (typeof field.accessor === 'function') {
    return field.accessor(entry)
  }
  const v = entry[field.accessor as keyof LogEntry]
  if (v == null) return null
  const s = String(v)
  return s === '' ? null : s
}

/**
 * Check whether a section has at least one populated field for the given entry.
 * A section is omitted entirely when all fields resolve to null/empty.
 */
export function sectionHasData(section: PanelSection, entry: LogEntry): boolean {
  return section.fields.some((f) => {
    const v = resolveFieldValue(f, entry)
    return v != null && v !== ''
  })
}
