/**
 * FieldErrorTemplate — re-skinned to DS error style (F4, #110).
 *
 * Overrides @rjsf/shadcn's default FieldErrorTemplate to:
 *   1. Add role="alert" + aria-live="assertive" so screen readers announce errors (WCAG 4.1.3).
 *   2. Style errors in DS critical/red token (--fw-red) instead of shadcn text-destructive.
 *
 * DS error treatment: --fw-red color, --fw-fs-sm font size, --fw-fw-medium weight.
 * The semantic a11y attributes (role, aria-live, aria-atomic) are UNCHANGED.
 *
 * ADR-0028: part of the project-local widget/template registry.
 */

import { errorId } from '@rjsf/utils'
import type { FieldErrorProps } from '@rjsf/utils'

/** DS error text style: --fw-red, small, medium weight. */
const ERROR_SPAN_STYLE: React.CSSProperties = {
  color: 'var(--fw-red)',
  fontSize: 'var(--fw-fs-sm)',
  fontWeight: 'var(--fw-fw-medium)',
  display: 'block',
  marginTop: 2,
}

export default function FieldErrorTemplate({ errors = [], fieldPathId }: FieldErrorProps) {
  if (errors.length === 0) return null
  const id = errorId(fieldPathId)
  return (
    <div
      style={{ display: 'flex', flexDirection: 'column', gap: 2 }}
      id={id}
      role="alert"
      aria-live="assertive"
      aria-atomic="true"
    >
      {errors.map((error, i) => (
        <span key={i} data-fw-error="" style={ERROR_SPAN_STYLE}>
          {error}
        </span>
      ))}
    </div>
  )
}
