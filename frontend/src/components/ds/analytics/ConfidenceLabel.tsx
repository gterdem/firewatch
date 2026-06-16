/**
 * ConfidenceLabel — word-based confidence presentation (ADR-0036 D2).
 *
 * Maps a 0–1 confidence float to a word band:
 *   - null / undefined  → "n/a (AI off)"  (AI did not run)
 *   - ≥ 0.7             → "High"          (confident enough to move the score)
 *   - 0.4–0.69          → "Medium"
 *   - < 0.4             → "Low"
 *
 * NEVER renders a percentage (ADR-0036 D2 — uncalibrated local LLMs make
 * percentage confidence fake precision; OCSF itself uses a Low/Medium/High enum).
 *
 * The 0.7 cut is deliberate: it is the same threshold `merge_score` uses to
 * gate the AI boost (ADR-0036). "High" in the UI means exactly "the model was
 * confident enough to change the final score."
 *
 * Styling:
 *   - "n/a (AI off)" → muted faint text (not a badge — just metadata).
 *   - High  → green (same semantic as "Low" risk — confidence is good).
 *   - Medium → amber (same semantic as "watch").
 *   - Low   → red (low confidence is concerning — like "Critical" risk).
 *
 * XSS safety (ADR-0029 D3):
 *   - `confidence` is a number; the rendered text is from a static constant map.
 *
 * Accessibility:
 *   - role="status" with aria-label giving the full human description.
 *
 * Props:
 *   confidence — 0–1 float from the backend, or null/undefined when AI did not run.
 *   className  — optional extra CSS classes.
 */

import type { HTMLAttributes } from 'react'
import { confidenceToWord } from '../../../lib/provenance'
import type { ConfidenceWord } from '../../../lib/provenance'

export type { ConfidenceWord }

export interface ConfidenceLabelProps extends Omit<HTMLAttributes<HTMLSpanElement>, 'children'> {
  /**
   * 0–1 confidence score from the AI analysis result.
   * Pass `null` or `undefined` when AI did not run (`ai_status != "ok"` or
   * no confidence field present) — renders "n/a (AI off)".
   */
  confidence: number | null | undefined
  /** Optional extra CSS classes. */
  className?: string
}

/** Inline style map for each confidence word. */
function wordStyle(word: ConfidenceWord): React.CSSProperties {
  switch (word) {
    case 'High':
      return {
        color: 'var(--fw-green)',
        background: 'var(--fw-tint-green)',
        borderColor: 'var(--fw-tint-green-bd)',
      }
    case 'Medium':
      return {
        color: 'var(--fw-accent)',
        background: 'rgba(245, 158, 11, 0.094)',
        borderColor: 'rgba(245, 158, 11, 0.188)',
      }
    case 'Low':
      return {
        color: 'var(--fw-red)',
        background: 'var(--fw-tint-red)',
        borderColor: 'var(--fw-tint-red-bd)',
      }
    case 'n/a (AI off)':
      // Not a badge — plain muted inline text (no background/border)
      return {
        color: 'var(--fw-t3)',
        background: 'transparent',
        borderColor: 'transparent',
      }
  }
}

const ARIA_LABEL_MAP: Record<ConfidenceWord, string> = {
  'High': 'AI confidence: High (≥0.7 — sufficient to move the score)',
  'Medium': 'AI confidence: Medium (0.4–0.69)',
  'Low': 'AI confidence: Low (<0.4)',
  'n/a (AI off)': 'AI confidence: not available (AI engine did not run)',
} as const

export function ConfidenceLabel({
  confidence,
  className = '',
  style,
  ...rest
}: ConfidenceLabelProps) {
  const word: ConfidenceWord = confidenceToWord(confidence)
  const isNA = word === 'n/a (AI off)'

  return (
    <span
      role="status"
      aria-label={ARIA_LABEL_MAP[word]}
      data-confidence-word={word}
      data-confidence-raw={confidence ?? 'null'}
      className={`fw-confidence-label ${className}`}
      style={{
        display: 'inline-block',
        padding: isNA ? '0' : '1px 6px',
        borderRadius: isNA ? 0 : 'var(--fw-r-xs)',
        fontSize: 'var(--fw-fs-xs)',
        fontWeight: isNA ? 'var(--fw-fw-regular)' : 'var(--fw-fw-medium)',
        fontFamily: 'var(--fw-font-ui)',
        letterSpacing: isNA ? 0 : 'var(--fw-ls-tight)',
        border: isNA ? 'none' : '1px solid transparent',
        lineHeight: 1.6,
        whiteSpace: 'nowrap',
        ...wordStyle(word),
        ...style,
      }}
      {...rest}
    >
      {word}
    </span>
  )
}
