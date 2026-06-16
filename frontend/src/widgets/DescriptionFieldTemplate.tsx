/**
 * DescriptionFieldTemplate — two-tier field help disclosure (R1, #489).
 *
 * Renders a field's `description` as:
 *   - Lead line: the first sentence of the description, clamped to one line.
 *   - Full text: available behind a keyboard-operable "Details" native <details>
 *     element, which requires zero custom JS for toggle state.
 *
 * Derivation rule for the lead sentence (fallback — no re-authoring required):
 *   - Split `description` on the first sentence boundary (`. `, `! `, `? ` or
 *     end of string) and take the first sentence.
 *   - Clamp to a maximum of 90 characters to avoid placeholder-like overflow;
 *     append `…` if trimmed.
 *   - If the schema provides a `ui:help` string (future convention), prefer it
 *     over the derived sentence (EARS event-driven criterion).
 *
 * Accessibility:
 *   - Uses native `<details>` / `<summary>` which browsers expose as
 *     role="group" + disclosure button with aria-expanded — keyboard-operable
 *     without custom ARIA. WCAG 1.4.13 satisfied: hover is NOT the sole path.
 *   - When description is empty or missing, renders nothing (no empty elements).
 *
 * Modularity: no per-source branching. This template applies to every field of
 * every plugin via the shared template registry (ADR-0010, ADR-0028).
 *
 * ADR-0028: registered in widgets/registry.ts as DescriptionFieldTemplate.
 */

import type { DescriptionFieldProps } from '@rjsf/utils'
import { deriveLeadSentence, shouldShowDisclosure } from './descriptionUtils'

/** Inline style constants — DS token-based, matching the project design system. */
const DESCRIPTION_WRAPPER_STYLE: React.CSSProperties = {
  marginTop: 4,
  fontSize: 'var(--fw-fs-sm)',
  color: 'var(--fw-t3)',
  lineHeight: 1.4,
}

const LEAD_STYLE: React.CSSProperties = {
  display: 'block',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
}

const DETAILS_STYLE: React.CSSProperties = {
  marginTop: 2,
}

const SUMMARY_STYLE: React.CSSProperties = {
  cursor: 'pointer',
  color: 'var(--fw-accent)',
  fontSize: 'var(--fw-fs-sm)',
  fontWeight: 'var(--fw-fw-medium)',
  userSelect: 'none',
  listStyle: 'none',
  display: 'inline-flex',
  alignItems: 'center',
  gap: 2,
}

const FULL_TEXT_STYLE: React.CSSProperties = {
  marginTop: 4,
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-word',
}

/**
 * DescriptionFieldTemplate — registered in widgets/registry.ts.
 *
 * Renders nothing when description is empty/missing (rjsf will call this
 * with an empty string for fields with no description).
 */
export default function DescriptionFieldTemplate({ id, description, uiSchema }: DescriptionFieldProps) {
  // rjsf may pass ReactElement descriptions for rich text schemas; we only
  // handle strings (the case for all FireWatch plugin schemas).
  if (!description || typeof description !== 'string') return null

  const trimmed = description.trim()
  if (!trimmed) return null

  // ui:help takes precedence over derived lead sentence (EARS event-driven criterion).
  const uiHelp = (uiSchema?.['ui:help'] as string | undefined) ?? undefined
  const lead = uiHelp ?? deriveLeadSentence(trimmed)
  const hasMore = shouldShowDisclosure(lead, trimmed)

  return (
    <div id={id} style={DESCRIPTION_WRAPPER_STYLE} data-fw-description="">
      {/* Lead sentence — always visible, clamped to one line */}
      <span style={LEAD_STYLE}>{lead}</span>

      {/* "Details" disclosure — only shown when the full text is longer */}
      {hasMore && (
        <details style={DETAILS_STYLE} data-fw-description-details="">
          <summary style={SUMMARY_STYLE} aria-label="Show full description">
            Details
          </summary>
          <p style={FULL_TEXT_STYLE} data-fw-description-full="">
            {trimmed}
          </p>
        </details>
      )}
    </div>
  )
}
