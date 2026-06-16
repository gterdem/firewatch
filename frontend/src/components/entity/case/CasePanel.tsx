/**
 * CasePanel — body content rendered inside the ADR-0037 SlideOver shell when
 * kind="case" is on the entity stack.
 *
 * ADR-0053 D1: Case File is a slide-over hosted in the existing entity
 * slide-over shell, registered as {kind:"case", value:caseId}.
 *
 * ADR-0053 D2 composition (top to bottom):
 *   1. CaseHeader           — id, title, subject, disposition chip, timestamps
 *   2. CaseDispositionSelect — inline disposition selector (EARS-5)
 *   3. CaseTimeline         — linked event/analysis refs (EARS-2)
 *   4. CaseSummary          — one-click AI-draft summary (B1-polish, issue #535)
 *   5. CaseNotes            — analyst-editable notes, add-note form (EARS-3/4)
 *
 * SECURITY (ADR-0029 D3):
 *   All operator-text and attacker-influenced strings (title, subject,
 *   note bodies, ref_ids) are rendered as text nodes only — never as HTML.
 */

import { useState, useEffect, useCallback } from 'react'
import { getCase } from '../../../api/cases'
import type { CaseFile, CaseDisposition } from '../../../api/cases'
import { Spinner } from '../../ds'
import { CaseHeader } from './CaseHeader'
import { CaseDispositionSelect } from './CaseDispositionSelect'
import { CaseTimeline } from './CaseTimeline'
import { CaseNotes } from './CaseNotes'
import { CaseSummary } from './CaseSummary'

// ---------------------------------------------------------------------------
// Section heading helper (reused for Timeline + Notes)
// ---------------------------------------------------------------------------

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <h3
      style={{
        fontSize: 'var(--fw-fs-sm)',
        fontWeight: 'var(--fw-fw-semibold)',
        color: 'var(--fw-t2)',
        textTransform: 'uppercase',
        letterSpacing: 'var(--fw-ls-tight)',
        margin: '20px 0 8px',
        fontFamily: 'var(--fw-font-ui)',
      }}
    >
      {children}
    </h3>
  )
}

// ---------------------------------------------------------------------------
// CasePanel
// ---------------------------------------------------------------------------

export interface CasePanelProps {
  /** String caseId from the entity stack value. */
  caseId: string
}

export default function CasePanel({ caseId }: CasePanelProps) {
  const numericId = Number(caseId)

  const [caseFile, setCaseFile] = useState<CaseFile | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // notesRevision bumps when CaseSummary saves an analyst note, triggering CaseNotes reload.
  const [notesRevision, setNotesRevision] = useState(0)
  const handleNoteAdded = useCallback(() => {
    setNotesRevision((n) => n + 1)
  }, [])

  useEffect(() => {
    let cancelled = false

    // All setState calls happen in the async IIFE body (not synchronously in
    // the effect body) to satisfy the react-hooks/set-state-in-effect rule.
    void (async () => {
      if (isNaN(numericId)) {
        if (!cancelled) {
          setError(`Invalid case ID: ${caseId}`)
          setLoading(false)
        }
        return
      }

      if (!cancelled) {
        setLoading(true)
        setError(null)
      }

      try {
        const data = await getCase(numericId)
        if (!cancelled) {
          if (data === null) {
            setError(`Case #${caseId} not found.`)
          } else {
            setCaseFile(data)
          }
          setLoading(false)
        }
      } catch {
        if (!cancelled) {
          setError('Failed to load case file.')
          setLoading(false)
        }
      }
    })()

    return () => { cancelled = true }
  }, [numericId, caseId])

  if (loading) {
    return <Spinner label="Loading case file…" />
  }

  if (error !== null) {
    return (
      <p
        role="alert"
        data-testid="case-panel-error"
        style={{ color: 'var(--fw-red)', fontSize: 'var(--fw-fs-sm)' }}
      >
        {error}
      </p>
    )
  }

  if (!caseFile) return null

  // Disposition change callback — updates local caseFile so the chip stays in sync.
  function handleDispositionChange(next: CaseDisposition) {
    setCaseFile((prev) => prev ? { ...prev, disposition: next } : prev)
  }

  return (
    <div data-testid="case-panel">
      {/* 1. Header: id, title, subject, disposition chip, timestamps */}
      <CaseHeader caseFile={caseFile} />

      {/* 2. Disposition selector (EARS-5) */}
      <CaseDispositionSelect
        caseId={numericId}
        current={caseFile.disposition}
        onChange={handleDispositionChange}
      />

      {/* 3. Timeline (EARS-2) */}
      <SectionHeading>Timeline</SectionHeading>
      <CaseTimeline caseId={numericId} />

      {/* 4. AI-drafted summary (B1-polish, issue #535 / ADR-0053 D2) */}
      <SectionHeading>AI summary</SectionHeading>
      <CaseSummary caseId={numericId} onNoteAdded={handleNoteAdded} />

      {/* 5. Notes (EARS-3 / EARS-4) */}
      <SectionHeading>Analyst notes</SectionHeading>
      {/* key=notesRevision remounts CaseNotes when a summary note is saved (EARS-4). */}
      <CaseNotes key={notesRevision} caseId={numericId} />
    </div>
  )
}
