/**
 * DetailField — one label/value row in the detail panel (ADR-0063 D3).
 *
 * Renders a label and value as a two-column grid row. Value is always a
 * React text node — NEVER dangerouslySetInnerHTML (ADR-0029 D3).
 *
 * Optional hint text is rendered beneath the label in a muted, smaller font
 * (used for provenance notes, e.g. "[RULE] local heuristic…" on DGA score).
 *
 * Optional Copy affordance: when copyable=true and value is non-empty, a
 * CopyButton is shown inline after the value.
 *
 * When value is null/undefined/'', this component returns null (field omitted).
 *
 * SECURITY (ADR-0029 D3): all values are attacker-controlled telemetry;
 * rendered as React text nodes only — no dangerouslySetInnerHTML.
 */

import { CopyButton } from './CopyButton'

interface DetailFieldProps {
  label: string
  /** Value to display. null/undefined/'' → component returns null (field absent). */
  value: string | null | undefined
  /** Render value in monospace font. */
  mono?: boolean
  /** Show Copy affordance when true and value is non-empty. */
  copyable?: boolean
  /** Optional hint shown below the label (provenance notes, etc.). */
  hint?: string
  /** data-testid for the row wrapper. */
  'data-testid'?: string
}

/**
 * Shared label style for the detail panel field grid.
 */
const LABEL_STYLE: React.CSSProperties = {
  fontSize: 'var(--fw-fs-xs)',
  color: 'var(--fw-t3)',
  fontFamily: 'var(--fw-font-ui)',
  fontWeight: 'var(--fw-fw-semibold)',
  flexShrink: 0,
  minWidth: 120,
  maxWidth: 140,
  paddingRight: 8,
  lineHeight: 1.4,
}

const HINT_STYLE: React.CSSProperties = {
  fontSize: 'var(--fw-fs-2xs)',
  color: 'var(--fw-t3)',
  fontFamily: 'var(--fw-font-ui)',
  fontStyle: 'italic',
  lineHeight: 1.3,
  marginTop: 2,
}

export function DetailField({
  label,
  value,
  mono = false,
  copyable = false,
  hint,
  'data-testid': testId,
}: DetailFieldProps) {
  // Absent/empty → omit this row entirely (honest absence, ADR-0063 D3).
  if (value == null || value === '') return null

  return (
    <div
      data-testid={testId ?? `detail-field-${label.toLowerCase().replace(/\s+/g, '-')}`}
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        padding: '3px 0',
        borderBottom: '1px solid var(--fw-border)',
      }}
    >
      {/* Label column */}
      <div style={{ ...LABEL_STYLE }}>
        <div>{label}</div>
        {hint != null && (
          <div style={HINT_STYLE} data-testid="detail-field-hint">
            {/* Hint is a static string constant — not attacker-controlled */}
            {hint}
          </div>
        )}
      </div>

      {/* Value column */}
      <div
        style={{
          flex: 1,
          display: 'flex',
          alignItems: 'flex-start',
          gap: 6,
          minWidth: 0,
        }}
      >
        <span
          data-testid="detail-field-value"
          style={{
            fontFamily: mono ? 'var(--fw-font-mono)' : 'var(--fw-font-ui)',
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t1)',
            lineHeight: 1.5,
            wordBreak: 'break-all',
            whiteSpace: 'pre-wrap',
            flex: 1,
          }}
        >
          {/* Attacker-controlled — rendered as a React text node ONLY, never innerHTML */}
          {value}
        </span>
        {copyable && (
          <CopyButton value={value} data-testid="detail-field-copy" />
        )}
      </div>
    </div>
  )
}
