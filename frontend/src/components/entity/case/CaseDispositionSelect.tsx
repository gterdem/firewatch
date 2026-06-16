/**
 * CaseDispositionSelect — inline disposition selector for a case file.
 *
 * EARS-5: analyst can set disposition (true-positive / false-positive /
 * benign / open), persisted on case_files via PATCH /cases/{id}/disposition.
 *
 * Renders a labeled <select> with the four valid values.
 * Optimistic update: sets local state immediately, reverts on API error.
 *
 * SECURITY: disposition is validated server-side (Pydantic Literal).
 * The UI never echoes the raw server error value back into the DOM.
 */

import { useState, useCallback } from 'react'
import { setDisposition } from '../../../api/cases'
import type { CaseDisposition } from '../../../api/cases'
import { ApiError } from '../../../api/client'
import { Select } from '../../ds'
import type { SelectOption } from '../../ds'

const DISPOSITION_OPTIONS: SelectOption[] = [
  { value: 'open',           label: 'Open' },
  { value: 'true-positive',  label: 'True positive' },
  { value: 'false-positive', label: 'False positive' },
  { value: 'benign',         label: 'Benign' },
]

export interface CaseDispositionSelectProps {
  caseId: number
  /** Current disposition from the loaded case file. */
  current: CaseDisposition
  /** Called after a successful save. */
  onChange?: (next: CaseDisposition) => void
}

export function CaseDispositionSelect({
  caseId,
  current,
  onChange,
}: CaseDispositionSelectProps) {
  const [value, setValue] = useState<CaseDisposition>(current)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleChange = useCallback(
    async (next: CaseDisposition) => {
      const previous = value
      // Optimistic update
      setValue(next)
      setSaving(true)
      setError(null)

      try {
        await setDisposition(caseId, next)
        onChange?.(next)
      } catch (err) {
        // Revert on failure
        setValue(previous)
        const msg =
          err instanceof ApiError
            ? `Could not save disposition (${err.status})`
            : 'Could not save disposition'
        setError(msg)
      } finally {
        setSaving(false)
      }
    },
    [caseId, value, onChange],
  )

  return (
    <div data-testid="disposition-select" style={{ maxWidth: 220 }}>
      <Select
        id={`case-${caseId}-disposition`}
        label="Disposition"
        options={DISPOSITION_OPTIONS}
        value={value}
        disabled={saving}
        aria-label="Set case disposition"
        onChange={(e) => {
          void handleChange(e.target.value as CaseDisposition)
        }}
      />
      {error !== null && (
        <p
          role="alert"
          style={{
            color: 'var(--fw-red)',
            fontSize: 'var(--fw-fs-xs)',
            margin: '4px 0 0',
          }}
        >
          {error}
        </p>
      )}
    </div>
  )
}
