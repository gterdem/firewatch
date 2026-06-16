/**
 * CaseNotes — analyst-editable markdown notes panel for a case.
 *
 * ADR-0053 D2 / EARS-3 / EARS-4:
 *   - Shows all notes for a case (chronological, author + created_at each).
 *   - Provides a textarea to add a new note.
 *   - body_md is RENDERED AS TEXT (no raw HTML) — ADR-0029 D3.
 *   - author defaults to "local operator" (ADR-0053 D3 auth-aware seam).
 *
 * SECURITY (ADR-0029 D3):
 *   body_md may embed attacker-controlled content. This component renders
 *   note bodies as plain text via a <pre> element (preserves newlines without
 *   HTML injection). When a markdown renderer is introduced it MUST sanitize.
 *
 * Note: The AI-draft summary (B1-polish) is a SEPARATE issue (#535).
 *   ai_drafted notes are labeled with an "AI" marker for future proofing,
 *   but the draft action itself is NOT in scope here.
 */

import { useState, useEffect, useCallback } from 'react'
import { listNotes, addNote } from '../../../api/cases'
import type { CaseNote } from '../../../api/cases'
import { Spinner, Button } from '../../ds'
import { ApiError } from '../../../api/client'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return iso
  }
}

// ---------------------------------------------------------------------------
// NoteCard — single note row
// ---------------------------------------------------------------------------

function NoteCard({ note }: { note: CaseNote }) {
  return (
    <div
      data-testid="note-card"
      style={{
        padding: '10px 0',
        borderBottom: '1px solid var(--fw-border)',
      }}
    >
      {/* Meta row: author + timestamp + AI badge if applicable */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 6,
          flexWrap: 'wrap',
        }}
      >
        <span
          data-testid="note-author"
          style={{
            fontSize: 'var(--fw-fs-xs)',
            fontWeight: 'var(--fw-fw-medium)',
            color: 'var(--fw-t2)',
            fontFamily: 'var(--fw-font-ui)',
          }}
        >
          {note.author}
        </span>
        <span
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t3)',
            fontFamily: 'var(--fw-font-ui)',
          }}
        >
          {formatDate(note.created_at)}
        </span>
        {note.ai_drafted && (
          <span
            data-testid="note-ai-badge"
            style={{
              fontSize: 'var(--fw-fs-2xs)',
              fontWeight: 'var(--fw-fw-bold)',
              color: 'var(--fw-purple)',
              background: 'var(--fw-tint-purple)',
              border: '1px solid var(--fw-tint-purple-bd)',
              borderRadius: 'var(--fw-r-sm)',
              padding: '1px 6px',
              textTransform: 'uppercase',
              letterSpacing: 'var(--fw-ls-tight)',
              lineHeight: 1.6,
            }}
          >
            AI
          </span>
        )}
      </div>

      {/*
       * Note body — rendered as plain text (ADR-0029 D3).
       * <pre> preserves whitespace/newlines and never injects HTML.
       * A markdown renderer may replace this in B1-polish (#535) — it MUST sanitize.
       */}
      <pre
        data-testid="note-body"
        style={{
          margin: 0,
          fontFamily: 'var(--fw-font-ui)',
          fontSize: 'var(--fw-fs-sm)',
          color: 'var(--fw-t1)',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          lineHeight: 1.55,
        }}
      >
        {note.body_md}
      </pre>
    </div>
  )
}

// ---------------------------------------------------------------------------
// AddNoteForm — inline textarea + submit (EARS-3)
// ---------------------------------------------------------------------------

interface AddNoteFormProps {
  caseId: number
  onSuccess: () => void
}

function AddNoteForm({ caseId, onSuccess }: AddNoteFormProps) {
  const [text, setText] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)

  const handleSubmit = useCallback(async () => {
    const trimmed = text.trim()
    if (!trimmed) return

    setSubmitting(true)
    setSubmitError(null)

    try {
      // author defaults to "local operator" on the server (ADR-0053 D3).
      // Never log text value (operator content may be sensitive).
      await addNote(caseId, { body_md: trimmed })
      setText('')
      onSuccess()
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? `Failed to add note (${err.status})`
          : 'Failed to add note'
      setSubmitError(msg)
    } finally {
      setSubmitting(false)
    }
  }, [caseId, text, onSuccess])

  return (
    <div data-testid="add-note-form" style={{ marginTop: 12 }}>
      <textarea
        data-testid="note-textarea"
        aria-label="New note (markdown)"
        placeholder="Add a note… (plain text or markdown)"
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={4}
        style={{
          width: '100%',
          padding: '8px 10px',
          background: 'var(--fw-bg-input)',
          border: '1px solid var(--fw-border-l)',
          borderRadius: 'var(--fw-r-sm)',
          color: 'var(--fw-t1)',
          fontSize: 'var(--fw-fs-sm)',
          fontFamily: 'var(--fw-font-ui)',
          resize: 'vertical',
          outline: 'none',
          lineHeight: 1.5,
          boxSizing: 'border-box',
        }}
        disabled={submitting}
      />
      {submitError !== null && (
        <p
          role="alert"
          style={{
            color: 'var(--fw-red)',
            fontSize: 'var(--fw-fs-xs)',
            margin: '4px 0 0',
          }}
        >
          {submitError}
        </p>
      )}
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 6 }}>
        <Button
          data-testid="add-note-submit"
          variant="secondary"
          size="sm"
          disabled={submitting || text.trim().length === 0}
          onClick={() => { void handleSubmit() }}
        >
          {submitting ? 'Saving…' : 'Add note'}
        </Button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// CaseNotes — main component
// ---------------------------------------------------------------------------

export interface CaseNotesProps {
  caseId: number
}

export function CaseNotes({ caseId }: CaseNotesProps) {
  const [notes, setNotes] = useState<CaseNote[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)

  const loadNotes = useCallback(() => {
    let cancelled = false

    // All setState calls in async IIFE to satisfy react-hooks/set-state-in-effect.
    void (async () => {
      if (!cancelled) {
        setLoading(true)
        setFetchError(null)
      }
      try {
        const data = await listNotes(caseId)
        if (!cancelled) {
          setNotes(data?.notes ?? [])
          setLoading(false)
        }
      } catch {
        if (!cancelled) {
          setFetchError('Could not load notes.')
          setLoading(false)
        }
      }
    })()

    return () => { cancelled = true }
  }, [caseId])

  useEffect(() => {
    return loadNotes()
  }, [loadNotes])

  if (loading) {
    return <Spinner label="Loading notes…" />
  }

  if (fetchError !== null) {
    return (
      <p
        role="alert"
        style={{ color: 'var(--fw-red)', fontSize: 'var(--fw-fs-sm)' }}
      >
        {fetchError}
      </p>
    )
  }

  return (
    <div data-testid="case-notes">
      {/* Existing notes list */}
      {notes && notes.length > 0 ? (
        <div data-testid="notes-list" role="list" aria-label="Case notes">
          {notes.map((note) => (
            <NoteCard key={note.id} note={note} />
          ))}
        </div>
      ) : (
        <p
          data-testid="notes-empty"
          style={{
            color: 'var(--fw-t3)',
            fontSize: 'var(--fw-fs-sm)',
            fontStyle: 'italic',
            marginBottom: 8,
          }}
        >
          No notes yet. Add the first note below.
        </p>
      )}

      {/* Add-note form (EARS-3) */}
      <AddNoteForm caseId={caseId} onSuccess={loadNotes} />
    </div>
  )
}
