/**
 * RawLogField — collapsed-by-default raw_log viewer for the detail panel (ADR-0063 D3).
 *
 * raw_log is attacker-controlled — shown verbatim as a text node with a clear
 * "attacker-controlled" warning label. Collapsed by default to avoid visual
 * noise; expanded on user demand via a toggle button.
 *
 * Copy affordance writes the full raw_log string to the clipboard.
 *
 * SECURITY (ADR-0029 D3):
 *   - raw_log value is attacker-controlled telemetry; MUST be rendered as a
 *     React text node — never via dangerouslySetInnerHTML.
 *   - Value is written to clipboard only; never echoed into the DOM as HTML.
 */

import { useState } from 'react'
import { CopyButton } from './CopyButton'

interface RawLogFieldProps {
  /** The raw_log value. null/'' → component returns null. */
  value: string | null | undefined
}

export function RawLogField({ value }: RawLogFieldProps) {
  const [expanded, setExpanded] = useState(false)

  if (value == null || value === '') return null

  return (
    <div
      data-testid="raw-log-field"
      style={{
        padding: '4px 0',
      }}
    >
      {/* Header row: label + toggle + copy */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: expanded ? 6 : 0,
        }}
      >
        <div style={{ flex: 1 }}>
          <span
            style={{
              fontSize: 'var(--fw-fs-xs)',
              color: 'var(--fw-t3)',
              fontFamily: 'var(--fw-font-ui)',
              fontWeight: 'var(--fw-fw-semibold)',
            }}
          >
            raw_log
          </span>
          <span
            data-testid="raw-log-warning"
            style={{
              fontSize: 'var(--fw-fs-2xs)',
              color: 'var(--fw-t3)',
              fontFamily: 'var(--fw-font-ui)',
              fontStyle: 'italic',
              marginLeft: 6,
            }}
          >
            attacker-controlled — shown verbatim
          </span>
        </div>
        <CopyButton value={value} data-testid="raw-log-copy" />
        <button
          type="button"
          aria-expanded={expanded}
          aria-label={expanded ? 'Collapse raw_log' : 'Expand raw_log'}
          data-testid="raw-log-toggle"
          onClick={() => setExpanded((prev) => !prev)}
          style={{
            background: 'none',
            border: '1px solid var(--fw-border)',
            borderRadius: 'var(--fw-r-sm)',
            padding: '1px 8px',
            cursor: 'pointer',
            fontFamily: 'var(--fw-font-ui)',
            fontSize: 10,
            color: 'var(--fw-t2)',
            whiteSpace: 'nowrap',
            flexShrink: 0,
          }}
        >
          {expanded ? 'Collapse' : 'Expand'}
        </button>
      </div>

      {/* Content (shown only when expanded) */}
      {expanded && (
        <pre
          data-testid="raw-log-content"
          style={{
            fontFamily: 'var(--fw-font-mono)',
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t2)',
            background: 'var(--fw-bg-subtle)',
            border: '1px solid var(--fw-border)',
            borderRadius: 'var(--fw-r-sm)',
            padding: '6px 8px',
            overflowX: 'auto',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
            margin: 0,
            lineHeight: 1.5,
            maxHeight: 300,
            overflowY: 'auto',
          }}
        >
          {/* Attacker-controlled — React text node ONLY, never dangerouslySetInnerHTML */}
          {value}
        </pre>
      )}
    </div>
  )
}
