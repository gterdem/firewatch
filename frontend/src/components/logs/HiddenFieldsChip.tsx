/**
 * HiddenFieldsChip — "+N fields not produced by this source" toolbar chip (issue #664, ADR-0060).
 *
 * Rendered in the LogsTable toolbar when at least one column has been structurally
 * hidden by useStructuralColumns (Option-B structural empty-column hiding).
 *
 * Clicking (or pressing Enter/Space) opens a popover listing each hidden column
 * with its FIELD_NOTES explanation — solving discoverability without fabrication.
 *
 * Uses the shared Popover DS primitive (issue #665, frontend/src/components/ds/Popover.tsx)
 * for outside-click dismiss, Esc dismiss (WCAG 1.4.13), and keyboard operability.
 *
 * FIELD_NOTES is reused from fieldAvailability.ts — no prose duplication.
 *
 * Source-agnostic: no per-source branching — the chip body is driven entirely by
 * which column keys are in the structurallyAbsent set and what FIELD_NOTES says
 * about their display label.
 *
 * SECURITY (ADR-0029 D3): all rendered text is from static FIELD_NOTES constants.
 * No attacker-controlled values are rendered here.
 *
 * TODO(#289): migrate Popover to @radix-ui/react-popover when the #289 sweep lands.
 */

import { COLUMN_CANONICAL_FIELDS, FIELD_NOTES } from '../../lib/fieldAvailability'
import { Popover } from '../ds/Popover'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HiddenFieldsChipProps {
  /** Set of column keys that are structurally absent in the current scope. */
  structurallyAbsent: ReadonlySet<string>
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function HiddenFieldsChip({ structurallyAbsent }: HiddenFieldsChipProps) {
  if (structurallyAbsent.size === 0) return null

  // Build the list of hidden columns with their display label and note.
  // Order: same as COLUMN_CANONICAL_FIELDS declaration order for stability.
  const hiddenColumns = Object.entries(COLUMN_CANONICAL_FIELDS)
    .filter(([colKey]) => structurallyAbsent.has(colKey))
    .map(([, { displayLabel }]) => ({
      displayLabel,
      note: FIELD_NOTES[displayLabel] ?? null,
    }))

  const count = hiddenColumns.length

  return (
    <Popover
      trigger={
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 4,
            background: 'var(--fw-bg-subtle)',
            border: '1px solid var(--fw-border)',
            borderRadius: 'var(--fw-r-full)',
            padding: '2px 10px',
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t2)',
            fontFamily: 'var(--fw-font-ui)',
            cursor: 'pointer',
            userSelect: 'none',
          }}
        >
          +{count} field{count !== 1 ? 's' : ''} not produced by this source
          <svg
            width="10"
            height="10"
            viewBox="0 0 10 10"
            fill="none"
            aria-hidden="true"
            style={{ flexShrink: 0 }}
          >
            <path
              d="M2 4L5 7L8 4"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </span>
      }
      triggerAriaLabel={`Show ${count} field${count !== 1 ? 's' : ''} hidden because no present source produces them`}
      data-testid="hidden-fields-chip"
      contentTestId="hidden-fields-popover"
      preferAbove={false}
    >
      <div style={{ padding: '4px 0' }}>
        <div
          style={{
            padding: '6px 12px 4px',
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
            fontWeight: 'var(--fw-fw-semibold)',
            textTransform: 'uppercase',
            letterSpacing: 'var(--fw-ls-table)',
            borderBottom: '1px solid var(--fw-border)',
            marginBottom: 4,
            fontFamily: 'var(--fw-font-ui)',
          }}
        >
          Fields hidden — not produced by present sources
        </div>
        <ul
          style={{
            listStyle: 'none',
            margin: 0,
            padding: 0,
          }}
          data-testid="hidden-fields-list"
        >
          {hiddenColumns.map(({ displayLabel, note }) => (
            <li
              key={displayLabel}
              style={{
                padding: '5px 12px',
                borderBottom: '1px solid var(--fw-border)',
                fontFamily: 'var(--fw-font-ui)',
              }}
            >
              <div
                style={{
                  fontWeight: 'var(--fw-fw-semibold)',
                  fontSize: 'var(--fw-fs-xs)',
                  color: 'var(--fw-t1)',
                  marginBottom: note ? 2 : 0,
                }}
                data-testid="hidden-field-label"
              >
                {displayLabel}
              </div>
              {note !== null && (
                <div
                  style={{
                    fontSize: 'var(--fw-fs-2xs)',
                    color: 'var(--fw-t3)',
                    lineHeight: 1.4,
                  }}
                  data-testid="hidden-field-note"
                >
                  {note}
                </div>
              )}
            </li>
          ))}
        </ul>
      </div>
    </Popover>
  )
}
