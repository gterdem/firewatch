/**
 * LogDetailPanel — expanded-row detail view for a single LogEntry (ADR-0063 D3).
 *
 * Container that takes one LogEntry and renders the grouped section list defined
 * in sections.ts. Sections are omitted when all their fields are empty (honest
 * absence — never a fabricated "—" wall).
 *
 * The Provenance/Raw section uses RawLogField instead of DetailField so raw_log
 * is collapsed by default and carries the attacker-controlled warning label.
 *
 * No network calls. Zero-egress (ADR-0047/0039): geo/asn values are server-joined
 * and already present on the LogEntry row.
 *
 * SECURITY (ADR-0029 D3): all field values are rendered as React text nodes via
 * DetailField / RawLogField — no dangerouslySetInnerHTML anywhere.
 *
 * Module layout (ADR-0063 sketch):
 *   LogDetailPanel.tsx — this file (container, owns layout)
 *   sections.ts        — declarative section model (testable, no JSX)
 *   DetailField.tsx    — one label/value row
 *   RawLogField.tsx    — raw_log viewer (collapsed by default)
 *   CopyButton.tsx     — clipboard affordance
 */

import type { LogEntry } from '../../../api/types'
import { DETAIL_SECTIONS, resolveFieldValue, sectionHasData } from './sections'
import { DetailField } from './DetailField'
import { RawLogField } from './RawLogField'

interface LogDetailPanelProps {
  /** The LogEntry to render detail for. */
  entry: LogEntry
  /** data-testid for the panel root. */
  'data-testid'?: string
}

const SECTION_TITLE_STYLE: React.CSSProperties = {
  fontSize: 'var(--fw-fs-2xs)',
  fontWeight: 'var(--fw-fw-semibold)',
  color: 'var(--fw-t3)',
  textTransform: 'uppercase',
  letterSpacing: 'var(--fw-ls-table)',
  fontFamily: 'var(--fw-font-ui)',
  marginBottom: 2,
  marginTop: 8,
  paddingBottom: 2,
  borderBottom: '1px solid var(--fw-border)',
}

export function LogDetailPanel({
  entry,
  'data-testid': testId = 'log-detail-panel',
}: LogDetailPanelProps) {
  return (
    <div
      data-testid={testId}
      style={{
        padding: '12px 16px',
        background: 'var(--fw-bg-subtle)',
        fontFamily: 'var(--fw-font-ui)',
      }}
    >
      {DETAIL_SECTIONS.map((section) => {
        // Omit sections that have no populated fields for this entry.
        if (!sectionHasData(section, entry)) return null

        return (
          <div
            key={section.id}
            data-testid={`detail-section-${section.id}`}
          >
            <div style={SECTION_TITLE_STYLE}>{section.title}</div>
            {section.fields.map((field) => {
              // The Provenance/Raw section's raw_log uses RawLogField (collapsed by default).
              if (section.id === 'raw' && field.label === 'raw_log') {
                const rawValue = (() => {
                  if (typeof field.accessor === 'function') {
                    return field.accessor(entry)
                  }
                  const v = entry[field.accessor as keyof LogEntry]
                  if (v == null) return null
                  if (typeof v === 'string') return v === '' ? null : v
                  try {
                    return JSON.stringify(v, null, 2)
                  } catch {
                    return String(v)
                  }
                })()
                return (
                  <RawLogField key={field.label} value={rawValue} />
                )
              }

              // All other fields go through DetailField.
              const value = resolveFieldValue(field, entry)
              return (
                <DetailField
                  key={field.label}
                  label={field.label}
                  value={typeof value === 'number' ? String(value) : value}
                  mono={field.mono}
                  copyable={field.copyable}
                  hint={field.hint}
                />
              )
            })}
          </div>
        )
      })}
    </div>
  )
}
