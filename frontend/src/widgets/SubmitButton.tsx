/**
 * SubmitButton — rjsf submit button override (MF-6, issue #163).
 *
 * Replaces the default rjsf/shadcn "Submit" label with "Save" to match
 * the v2 SOC Design System kit oracle (Settings.jsx) and the SOC console
 * UX expectation (sweep finding F10: "Submit" → "Save").
 *
 * The uiSchema `ui:submitButtonOptions.submitText` override is honoured
 * via getSubmitButtonOptions — callers can still override the label if needed.
 *
 * Uses the DS Button component (variant="primary") for consistent amber CTA
 * styling across all source config forms.
 *
 * ADR-0028: part of the project-local widget/template registry.
 * ADR-0010: schema-driven; this template renders for ALL source types.
 */

import { getSubmitButtonOptions } from '@rjsf/utils'
import type { SubmitButtonProps } from '@rjsf/utils'
import { Button } from '../components/ds'

/**
 * SubmitButton — renders "Save" (overrides rjsf default "Submit").
 *
 * Styled with DS Button variant="primary" (amber CTA) at default size.
 * Margin-top provides separation from the last form field row.
 */
export default function SubmitButton({ uiSchema }: SubmitButtonProps) {
  const { submitText, norender, props: submitButtonProps } = getSubmitButtonOptions(uiSchema)

  if (norender) return null

  // Use the uiSchema-overridden submitText if set; otherwise default to "Save"
  // (rjsf default is "Submit" — we deliberately override to "Save").
  const label = submitText !== 'Submit' ? submitText : 'Save'

  return (
    <div style={{ marginTop: 12 }}>
      <Button
        type="submit"
        variant="primary"
        size="sm"
        {...submitButtonProps}
      >
        {label}
      </Button>
    </div>
  )
}
