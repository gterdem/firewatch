/**
 * CaseSummary — one-click AI-drafted case summary (B1-polish, issue #535).
 *
 * ADR-0053 D2: "AI-drafted summary: a one-click local-LLM draft summary,
 * reusing the shipped ML-7 narration path (ADR-0043), explicitly labeled
 * AI-drafted (AI chip, ADR-0035), with every claim linked back to
 * verdict-ledger evidence (ADR-0041). The analyst edits and owns the result."
 *
 * EARS implementation:
 *   EARS-1  "Draft summary" triggers POST /cases/{id}/summary — reuses ML-7 narration.
 *   EARS-2  Draft is labeled with ProvenanceChip ("AI" / "RULE") + stored as ai_drafted note.
 *   EARS-3  Provenance + collected_fields surfaced in glass-box disclosure section.
 *   EARS-4  Analyst can edit the draft; saving forks it as an operator-authored note.
 *   EARS-5  Rule-only degrade when LLM unavailable (provenance="rule").
 *   EARS-6  Drafting is suggest-only — no auto-close or auto-disposition.
 *
 * SECURITY (ADR-0029 D3):
 *   The narrative is attacker-influenced (LLM may include event data).
 *   Rendered as text node only — never via dangerouslySetInnerHTML.
 *   Never logged (operator content may be sensitive).
 *
 * Zero-egress disclosure: a one-line badge tells the analyst the draft was
 * generated on-box (ADR-0022/0047) before they read it. This is the
 * "glass-box honesty" differentiator (ADR-0043).
 */

import { useState, useCallback } from 'react'
import { draftCaseSummary, addNote } from '../../../api/cases'
import type { CaseSummaryResponse } from '../../../api/cases'
import { Button, ProvenanceChip, Spinner } from '../../ds'
import { ApiError } from '../../../api/client'

// ---------------------------------------------------------------------------
// ZeroEgressBadge — one-line disclosure (ADR-0022/0047 / ADR-0043 glass-box)
// ---------------------------------------------------------------------------

function ZeroEgressBadge() {
  return (
    <span
      data-testid="zero-egress-badge"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        fontSize: 'var(--fw-fs-2xs)',
        fontFamily: 'var(--fw-font-ui)',
        color: 'var(--fw-t3)',
        border: '1px solid var(--fw-border)',
        borderRadius: 'var(--fw-r-xs)',
        padding: '1px 6px',
        whiteSpace: 'nowrap',
      }}
      aria-label="Generated on-box — no data leaves this machine (ADR-0022)"
    >
      On-box · zero egress
    </span>
  )
}

// ---------------------------------------------------------------------------
// GlassBoxDisclosure — provenance + collected fields (EARS-3 / ADR-0035/0041)
// ---------------------------------------------------------------------------

interface GlassBoxDisclosureProps {
  provenance: string
  collectedFields: string[]
  aiStatus: string
}

function GlassBoxDisclosure({ provenance, collectedFields, aiStatus }: GlassBoxDisclosureProps) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div
      data-testid="glass-box-disclosure"
      style={{
        marginTop: 8,
        padding: '6px 8px',
        background: 'var(--fw-bg-input)',
        border: '1px solid var(--fw-border)',
        borderRadius: 'var(--fw-r-sm)',
        fontSize: 'var(--fw-fs-xs)',
        fontFamily: 'var(--fw-font-ui)',
        color: 'var(--fw-t3)',
      }}
    >
      {/* Summary row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ color: 'var(--fw-t2)', fontWeight: 'var(--fw-fw-medium)' }}>
          AI-drafted
        </span>
        <ProvenanceChip derivation={provenance} />
        <ZeroEgressBadge />
        {aiStatus !== 'unavailable' && aiStatus !== 'skipped' && (
          <span style={{ color: 'var(--fw-t3)' }}>
            · AI status: {aiStatus}
          </span>
        )}
        {collectedFields.length > 0 && (
          <button
            data-testid="disclosure-toggle"
            onClick={() => setExpanded((v) => !v)}
            style={{
              background: 'none',
              border: 'none',
              padding: '0 2px',
              cursor: 'pointer',
              color: 'var(--fw-link)',
              fontSize: 'var(--fw-fs-xs)',
              fontFamily: 'var(--fw-font-ui)',
              marginLeft: 'auto',
            }}
            aria-expanded={expanded}
            aria-controls="disclosure-fields"
          >
            {expanded ? 'Hide sources' : 'Show sources'}
          </button>
        )}
      </div>

      {/* Expanded: collected fields (evidence chain, ADR-0041) */}
      {expanded && collectedFields.length > 0 && (
        <div
          id="disclosure-fields"
          data-testid="disclosure-fields"
          style={{ marginTop: 6 }}
        >
          <span style={{ color: 'var(--fw-t3)' }}>Evidence fields used: </span>
          {collectedFields.map((f, i) => (
            <span key={f}>
              <span
                style={{
                  fontFamily: 'var(--fw-font-mono)',
                  fontSize: 'var(--fw-fs-xs)',
                  color: 'var(--fw-t2)',
                }}
              >
                {f}
              </span>
              {i < collectedFields.length - 1 && (
                <span style={{ color: 'var(--fw-t3)' }}>, </span>
              )}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// DraftView — displays the generated draft + edit affordance (EARS-4)
// ---------------------------------------------------------------------------

interface DraftViewProps {
  caseId: number
  draft: CaseSummaryResponse
  /** Called when the analyst saves an edited version as their own note. */
  onSaved: () => void
  /** Called when the analyst clicks "Re-draft". */
  onRedraft: () => void
}

function DraftView({ caseId, draft, onSaved, onRedraft }: DraftViewProps) {
  const [editText, setEditText] = useState(draft.narrative)
  const [editing, setEditing] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  // Save the analyst's edited text as a new operator-authored note (EARS-4).
  // ai_drafted is cleared (false) — the human edit is the source of truth.
  // The original AI draft (draft.note_id) is retained with its ai_drafted=1 provenance.
  const handleSave = useCallback(async () => {
    const trimmed = editText.trim()
    if (!trimmed) return

    setSaving(true)
    setSaveError(null)

    try {
      // SECURITY: never log editText — analyst content may embed sensitive event data.
      await addNote(caseId, {
        body_md: trimmed,
        ai_drafted: false,  // human edit — ai_drafted cleared (EARS-4)
      })
      setEditing(false)
      onSaved()
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? `Failed to save note (${err.status})`
          : 'Failed to save note'
      setSaveError(msg)
    } finally {
      setSaving(false)
    }
  }, [caseId, editText, onSaved])

  return (
    <div data-testid="draft-view">
      {/* Glass-box provenance disclosure (EARS-2 / EARS-3 / ADR-0035/0041) */}
      <GlassBoxDisclosure
        provenance={draft.provenance}
        collectedFields={draft.collected_fields}
        aiStatus={draft.ai_status}
      />

      {/* Draft text — text node only (ADR-0029 D3) */}
      <div style={{ marginTop: 10 }}>
        {editing ? (
          <>
            <textarea
              data-testid="summary-edit-textarea"
              aria-label="Edit AI draft summary"
              value={editText}
              onChange={(e) => setEditText(e.target.value)}
              rows={8}
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
                lineHeight: 1.55,
                boxSizing: 'border-box',
              }}
              disabled={saving}
            />
            {saveError !== null && (
              <p
                role="alert"
                style={{
                  color: 'var(--fw-red)',
                  fontSize: 'var(--fw-fs-xs)',
                  margin: '4px 0 0',
                }}
              >
                {saveError}
              </p>
            )}
            <div
              style={{
                display: 'flex',
                gap: 8,
                justifyContent: 'flex-end',
                marginTop: 6,
              }}
            >
              <Button
                data-testid="summary-cancel-edit"
                variant="ghost"
                size="sm"
                disabled={saving}
                onClick={() => {
                  setEditText(draft.narrative)
                  setEditing(false)
                  setSaveError(null)
                }}
              >
                Cancel
              </Button>
              <Button
                data-testid="summary-save-edit"
                variant="secondary"
                size="sm"
                disabled={saving || editText.trim().length === 0}
                onClick={() => { void handleSave() }}
              >
                {saving ? 'Saving…' : 'Save as my note'}
              </Button>
            </div>
          </>
        ) : (
          <>
            {/* Narrative as text node — never raw HTML (ADR-0029 D3) */}
            <pre
              data-testid="summary-narrative"
              style={{
                margin: 0,
                fontFamily: 'var(--fw-font-ui)',
                fontSize: 'var(--fw-fs-sm)',
                color: 'var(--fw-t1)',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                lineHeight: 1.6,
                padding: '8px 0',
              }}
            >
              {draft.narrative}
            </pre>
            <div
              style={{
                display: 'flex',
                gap: 8,
                marginTop: 8,
                flexWrap: 'wrap',
              }}
            >
              <Button
                data-testid="summary-edit-button"
                variant="secondary"
                size="sm"
                onClick={() => setEditing(true)}
              >
                Edit &amp; own this draft
              </Button>
              <Button
                data-testid="summary-redraft-button"
                variant="ghost"
                size="sm"
                onClick={onRedraft}
              >
                Re-draft
              </Button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// CaseSummary — main component
// ---------------------------------------------------------------------------

export interface CaseSummaryProps {
  caseId: number
  /** Called after the analyst saves an edit, so CaseNotes can reload. */
  onNoteAdded?: () => void
}

export function CaseSummary({ caseId, onNoteAdded }: CaseSummaryProps) {
  const [draft, setDraft] = useState<CaseSummaryResponse | null>(null)
  const [drafting, setDrafting] = useState(false)
  const [draftError, setDraftError] = useState<string | null>(null)

  const handleDraft = useCallback(async () => {
    setDrafting(true)
    setDraftError(null)

    try {
      const result = await draftCaseSummary(caseId)
      setDraft(result)
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? `Failed to generate draft (${err.status})`
          : 'Failed to generate draft'
      setDraftError(msg)
    } finally {
      setDrafting(false)
    }
  }, [caseId])

  const handleSaved = useCallback(() => {
    // Reload notes so the analyst-owned note appears in the Notes section.
    onNoteAdded?.()
  }, [onNoteAdded])

  const handleRedraft = useCallback(() => {
    // Clear the current draft and let the analyst re-trigger.
    setDraft(null)
  }, [])

  return (
    <div data-testid="case-summary">
      {draft !== null ? (
        <DraftView
          caseId={caseId}
          draft={draft}
          onSaved={handleSaved}
          onRedraft={handleRedraft}
        />
      ) : (
        <>
          {/* "Draft summary" button (EARS-1) */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <Button
              data-testid="draft-summary-button"
              variant="secondary"
              size="sm"
              disabled={drafting}
              onClick={() => { void handleDraft() }}
            >
              {drafting ? (
                <>
                  <Spinner />
                  {' Drafting…'}
                </>
              ) : (
                'Draft summary'
              )}
            </Button>
            {!drafting && (
              <span
                style={{
                  fontSize: 'var(--fw-fs-xs)',
                  color: 'var(--fw-t3)',
                  fontFamily: 'var(--fw-font-ui)',
                }}
              >
                Generates a local-LLM draft grounded in case evidence — on-box, zero egress
              </span>
            )}
          </div>

          {/* Inline spinner while drafting */}
          {drafting && (
            <p
              style={{
                marginTop: 8,
                fontSize: 'var(--fw-fs-xs)',
                color: 'var(--fw-t3)',
                fontFamily: 'var(--fw-font-ui)',
              }}
            >
              Generating draft from case evidence…
            </p>
          )}

          {/* Error display */}
          {draftError !== null && (
            <p
              role="alert"
              data-testid="draft-error"
              style={{
                marginTop: 8,
                color: 'var(--fw-red)',
                fontSize: 'var(--fw-fs-sm)',
              }}
            >
              {draftError}
            </p>
          )}
        </>
      )}
    </div>
  )
}
