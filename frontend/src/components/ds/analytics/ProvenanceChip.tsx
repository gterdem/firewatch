/**
 * ProvenanceChip — renders the ADR-0035 derivation tag on analytic artifacts.
 *
 * Three valid values: RULE / AI / AI+RULE.
 * Every analyst-facing score, summary, recommendation, or label carries one;
 * panes NEVER hand-roll provenance labels (ADR-0035 §2).
 *
 * Styling rules (ADR-0035 / ADR-0028 D6):
 *   - Token-based only: --fw-* custom properties, never raw hex.
 *   - Each derivation has a visually distinct style so misreads are hard.
 *   - RULE  → muted/neutral (deterministic — expected baseline).
 *   - AI    → amber/accent (LLM-authored content — intentionally warm).
 *   - AI+RULE → amber tint (merged result — similar warmth to AI but lighter).
 *
 * Accessibility:
 *   - The chip is a non-interactive presentational element (role="status").
 *   - `aria-label` is set to the full human description so screen-readers get
 *     more context than "RULE" or "AI+RULE".
 *   - On hover or keyboard-focus, a CellTooltip surfaces the plain-language
 *     gloss from PROVENANCE_GLOSS in lib/provenance (MM #451 progressive
 *     disclosure). The tooltip wires aria-describedby automatically (WCAG 1.4.13).
 *
 * XSS safety (ADR-0029 D3):
 *   - The `derivation` prop is validated and mapped to a static string before
 *     render; attacker-controlled input can only produce one of three labels.
 *
 * Props:
 *   derivation — wire value: 'rule' | 'ai' | 'ai+rule' (case-insensitive).
 *   className  — optional extra CSS classes.
 */

import type { HTMLAttributes } from 'react'
import { normaliseDerivation, PROVENANCE_LABEL, PROVENANCE_GLOSS } from '../../../lib/provenance'
import type { ProvenanceDerivation } from '../../../lib/provenance'
import { CellTooltip } from '../core/CellTooltip'

export type { ProvenanceDerivation }

export interface ProvenanceChipProps extends Omit<HTMLAttributes<HTMLSpanElement>, 'children'> {
  /**
   * The derivation wire value returned by the backend, or the statically
   * determined derivation for UI-composed text.
   * Accepts: 'rule' | 'ai' | 'ai+rule' (case-insensitive; unknown → 'rule').
   */
  derivation: string
}

/** Inline style map for each derivation — token-based, never raw hex. */
function chipStyle(derivation: ProvenanceDerivation): React.CSSProperties {
  switch (derivation) {
    case 'ai':
      return {
        background: 'rgba(245, 158, 11, 0.094)', // --fw-tint-amber equivalent
        color: 'var(--fw-accent)',
        borderColor: 'rgba(245, 158, 11, 0.188)',
      }
    case 'ai+rule':
      return {
        background: 'rgba(245, 158, 11, 0.06)',
        color: 'var(--fw-accent)',
        borderColor: 'rgba(245, 158, 11, 0.14)',
      }
    case 'rule':
    default:
      return {
        background: 'var(--fw-bg-input)',
        color: 'var(--fw-t2)',
        borderColor: 'var(--fw-border)',
      }
  }
}

/** Accessible descriptions for each derivation value. */
const ARIA_LABEL: Record<ProvenanceDerivation, string> = {
  rule: 'Derivation: rule-engine (deterministic)',
  ai: 'Derivation: AI (LLM-authored)',
  'ai+rule': 'Derivation: AI + rule-engine (merged)',
} as const

export function ProvenanceChip({
  derivation,
  className = '',
  style,
  ...rest
}: ProvenanceChipProps) {
  const resolved = normaliseDerivation(derivation)
  const label = PROVENANCE_LABEL[resolved]

  const chip = (
    <span
      role="status"
      aria-label={ARIA_LABEL[resolved]}
      data-derivation={resolved}
      className={`fw-provenance-chip ${className}`}
      style={{
        display: 'inline-block',
        padding: '1px 6px',
        borderRadius: 'var(--fw-r-xs)',
        fontSize: 'var(--fw-fs-2xs)',
        fontWeight: 'var(--fw-fw-semibold)',
        fontFamily: 'var(--fw-font-ui)',
        textTransform: 'uppercase',
        letterSpacing: 'var(--fw-ls-label)',
        border: '1px solid transparent',
        lineHeight: 1.6,
        whiteSpace: 'nowrap',
        ...chipStyle(resolved),
        ...style,
      }}
      {...rest}
    >
      {label}
    </span>
  )

  return (
    <CellTooltip content={PROVENANCE_GLOSS[resolved]}>
      {chip}
    </CellTooltip>
  )
}
