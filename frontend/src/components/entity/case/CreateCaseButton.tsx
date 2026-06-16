/**
 * CreateCaseButton — find-or-create a case and open it in the slide-over.
 *
 * EARS-1 (issue #757): WHEN 'Open case' is clicked AND an open case already
 *   exists for that subject, THE UI SHALL open the existing case (no new case).
 * EARS-2 (issue #757): WHEN no case exists for that subject, THE UI SHALL
 *   create one then open it.
 *
 * Find-or-create algorithm:
 *   1. GET /cases?subject=<subject>&limit=10 (newest-first).
 *   2. If any returned case has status "open", openEntity to the first one.
 *   3. Otherwise POST /cases → openEntity to the new case.
 *   4. On listCases error or null response → fall back to create (graceful degrade).
 *
 * Usage (generic — no per-source code):
 *   <CreateCaseButton title="WAF alert investigation" subject={ip} />
 *   <CreateCaseButton title={`Analysis #${analysisId}`} subject={analysisId} />
 *
 * Props are minimal and generic; the caller supplies title + subject.
 * Caller may optionally pass onCreated() for post-create side effects.
 */

import { useState, useCallback } from 'react'
import { createCase, listCases } from '../../../api/cases'
import type { CaseFile } from '../../../api/cases'
import { useEntityActions } from '../EntityPanelContext'
import { Button } from '../../ds'
import type { ButtonVariant, ButtonSize } from '../../ds'
import { ApiError } from '../../../api/client'

export interface CreateCaseButtonProps {
  /** Case title (operator text — not attacker-controlled). */
  title: string
  /**
   * Subject under investigation — an IP, hostname, or analysis ID.
   * Used as the deduplication key for find-or-create (issue #757).
   * Stored as operator metadata; not echoed to the DOM (ADR-0029 D3).
   */
  subject: string
  /** Optional custom button label (default: "Open case"). */
  label?: string
  variant?: ButtonVariant
  size?: ButtonSize
  /** Called after a NEW case is created (not called when an existing case is opened). */
  onCreated?: (caseId: number) => void
}

export function CreateCaseButton({
  title,
  subject,
  label = 'Open case',
  variant = 'secondary',
  size = 'sm',
  onCreated,
}: CreateCaseButtonProps) {
  const { openEntity } = useEntityActions()
  const [busy, setBusy] = useState(false)
  const [openError, setOpenError] = useState<string | null>(null)

  const handleClick = useCallback(async () => {
    setBusy(true)
    setOpenError(null)

    try {
      // EARS-1: try to find an existing open case for this subject first.
      // On any failure (network, 503, etc.) fall through to create.
      const existingId = await findOpenCase(subject)

      if (existingId !== null) {
        // Found an existing open case — open it without creating a new one.
        openEntity({ kind: 'case', value: String(existingId) })
        return
      }

      // EARS-2: no open case for this subject — create one then open it.
      const id = await createCase({ title, subject })
      openEntity({ kind: 'case', value: String(id) })
      onCreated?.(id)
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? `Could not open case (${err.status})`
          : 'Could not open case'
      setOpenError(msg)
    } finally {
      setBusy(false)
    }
  }, [title, subject, openEntity, onCreated])

  return (
    <div data-testid="create-case-button-wrapper" style={{ display: 'inline-block' }}>
      <Button
        data-testid="create-case-button"
        variant={variant}
        size={size}
        disabled={busy}
        onClick={() => { void handleClick() }}
        aria-label={`Open case for: ${title}`}
      >
        {busy ? 'Opening…' : label}
      </Button>
      {openError !== null && (
        <p
          role="alert"
          style={{
            color: 'var(--fw-red)',
            fontSize: 'var(--fw-fs-xs)',
            margin: '4px 0 0',
          }}
        >
          {openError}
        </p>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// findOpenCase — find an existing open case for the given subject
//
// Returns the case id if found, null if no open case exists or on any error.
// Errors are swallowed intentionally: a list-cases failure MUST NOT block
// the analyst from creating a new case (graceful degrade per EARS-2).
// ---------------------------------------------------------------------------

async function findOpenCase(subject: string): Promise<number | null> {
  try {
    const page = await listCases({ subject, limit: 10 })
    if (page === null) return null // 503 degrade
    const openCase = page.items.find((c: CaseFile) => c.status === 'open')
    return openCase !== undefined ? openCase.id : null
  } catch {
    // Network error or unexpected API error — fall back to create.
    return null
  }
}
