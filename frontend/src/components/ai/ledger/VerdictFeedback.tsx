/**
 * VerdictFeedback — Agree / Disagree controls mounted by VerdictCard (MK-6, ADR-0045).
 *
 * Renders two toggle buttons (Agree / Disagree). Choosing Disagree reveals an
 * optional bounded reason textarea (≤ REASON_MAX_CHARS chars, mirrored client-side
 * and enforced server-side). Submitting calls POST /ai/analyses/{id}/feedback via
 * useFeedbackSubmit. Re-clicking upserts — latest wins (ADR-0045 D1).
 *
 * After a successful submit the card shows the stored state (selected verdict +
 * formatted timestamp) from the API response. Optimistic UI is used but reconciles
 * to the server row — the server's id and created_at win.
 *
 * WCAG:
 *   - Controls are keyboard-operable <button> elements with visible labels.
 *   - Buttons carry aria-pressed to reflect toggle state.
 *   - Reason textarea has an associated <label> (htmlFor).
 *   - Submitting state shows aria-busy on the submit button.
 *
 * SECURITY (ADR-0029 D3):
 *   - reason is operator text; rendered as a text node only.
 *   - reason is never logged (console or telemetry).
 *   - The stored reason from the server row is rendered via textContent, not innerHTML.
 *
 * ADR-0045 D3: feedback never influences scores, prompts, or model calls.
 *
 * Consequence caption (issue #454): a one-line caption visible at the Agree/Disagree
 * buttons states what the action does and what it does NOT do — "Your grade is recorded
 * to track how often the AI agrees with analysts. It does not change this score or
 * retrain the model." This converts Maintainer's explicit uncertainty into a trust statement
 * and is a competitive differentiator (no silent feedback-to-retrain).
 *
 * D2 reactivity: onSubmitted is called after the server confirms a submit
 * (forwarded from VerdictCard → VerdictCardList → AIRoute handleFeedbackChange).
 * This lets AgreementStat re-fetch without a full page reload.
 */

import { useState } from 'react'
import type { FeedbackVerdict } from '../../../api/types'
import { useFeedbackSubmit, REASON_MAX_CHARS } from './useFeedback'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface VerdictFeedbackProps {
  /** The ledger analysis id — used for POST /ai/analyses/{id}/feedback. */
  analysisId: number
  /**
   * Pre-seeded verdict from the list-row additive field (MK-5 additive join).
   * Null/undefined when this analysis has not been graded yet.
   * When present, the corresponding toggle button starts in active state.
   * The full FeedbackRow (with id, reason, created_at) is only available
   * after a POST — seeded from the server response at that point.
   */
  initialVerdict?: FeedbackVerdict | null
  /**
   * Called after the server confirms a successful submit (not on the optimistic
   * phase, not on error). Forwarded to useFeedbackSubmit as onSuccess.
   * AIRoute uses this to bump feedbackVersion → AgreementStat re-fetches (D2 fix).
   */
  onSubmitted?: () => void
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Format a UTC ISO-8601 timestamp for the "graded at" display.
 * Shows a short absolute date+time so the analyst can see when they last graded.
 */
function formatGradedAt(isoString: string): string {
  try {
    return new Date(isoString).toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return isoString
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * Agree / Disagree controls for one VerdictCard.
 *
 * Isolated component so VerdictCard stays focused on rendering the analysis
 * summary. All feedback lifecycle state lives here (useFeedbackSubmit).
 */
export function VerdictFeedback({ analysisId, initialVerdict, onSubmitted }: VerdictFeedbackProps) {
  const { status, stored, error, submit } = useFeedbackSubmit(analysisId, onSubmitted)

  // Local UI state — which verdict button is active and the reason draft.
  // Initialised from initialVerdict (list-row seed) or the stored POST response.
  const [activeverdict, setActiveVerdict] = useState<FeedbackVerdict | null>(
    stored?.verdict ?? initialVerdict ?? null,
  )
  const [showReason, setShowReason] = useState(false)
  const [reasonDraft, setReasonDraft] = useState(stored?.reason ?? '')

  const isSubmitting = status === 'submitting'

  /**
   * Handle a verdict button click.
   *
   * If the same verdict is clicked again (re-grade): upserts immediately.
   * If Disagree is clicked: shows the reason field; submit waits for the
   *   explicit "Submit" button (so the analyst can add a reason).
   * If Agree is clicked: submits immediately (no reason needed).
   */
  function handleVerdictClick(verdict: FeedbackVerdict) {
    setActiveVerdict(verdict)
    if (verdict === 'agree') {
      setShowReason(false)
      // Agree: submit immediately (reason not applicable).
      void submit(verdict, undefined)
    } else {
      // Disagree: show reason field; analyst submits explicitly.
      setShowReason(true)
    }
  }

  /** Submit the Disagree verdict with optional reason. */
  function handleDisagreeSubmit() {
    void submit('disagree', reasonDraft || undefined)
    setShowReason(false)
  }

  /** Stored verdict + timestamp shown after a successful submit. */
  const gradedAt = stored?.created_at ? formatGradedAt(stored.created_at) : null

  return (
    <div
      data-testid="verdict-feedback"
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 6,
        marginTop: 4,
      }}
    >
      {/* Consequence caption — visible at the buttons, not hidden behind hover (issue #454).
       *
       * ADR-0045 D3: feedback is stored to track analyst agreement and NEVER changes
       * the AI score, rewrites the prompt, or retrains the model. Stating this plainly
       * is a deliberate trust differentiator — FireWatch shows its own disagreement rate
       * on-device and makes clear that the analyst's grade is an annotation, not an
       * input to scoring.
       */}
      <p
        data-testid="feedback-consequence-caption"
        style={{
          margin: 0,
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          fontFamily: 'var(--fw-font-ui)',
          lineHeight: 1.5,
        }}
      >
        Your grade is recorded to track how often the AI agrees with analysts. It does not change this score or retrain the model.
      </p>

      {/* Verdict toggle row */}
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}
      >
        <span
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t3)',
            fontFamily: 'var(--fw-font-ui)',
          }}
        >
          Your verdict:
        </span>

        {/* Agree button */}
        <button
          type="button"
          data-testid="feedback-agree-btn"
          aria-pressed={activeverdict === 'agree'}
          disabled={isSubmitting}
          onClick={() => handleVerdictClick('agree')}
          style={{
            padding: '2px 10px',
            fontSize: 'var(--fw-fs-xs)',
            fontFamily: 'var(--fw-font-ui)',
            fontWeight: 'var(--fw-fw-medium)',
            borderRadius: 'var(--fw-r-xs)',
            border: '1px solid',
            cursor: isSubmitting ? 'not-allowed' : 'pointer',
            background:
              activeverdict === 'agree'
                ? 'rgba(16, 185, 129, 0.12)'
                : 'var(--fw-bg-input)',
            borderColor:
              activeverdict === 'agree'
                ? 'rgba(16, 185, 129, 0.4)'
                : 'var(--fw-border)',
            color:
              activeverdict === 'agree'
                ? 'var(--fw-green)'
                : 'var(--fw-t2)',
            opacity: isSubmitting ? 0.6 : 1,
          }}
        >
          Agree
        </button>

        {/* Disagree button */}
        <button
          type="button"
          data-testid="feedback-disagree-btn"
          aria-pressed={activeverdict === 'disagree'}
          disabled={isSubmitting}
          onClick={() => handleVerdictClick('disagree')}
          style={{
            padding: '2px 10px',
            fontSize: 'var(--fw-fs-xs)',
            fontFamily: 'var(--fw-font-ui)',
            fontWeight: 'var(--fw-fw-medium)',
            borderRadius: 'var(--fw-r-xs)',
            border: '1px solid',
            cursor: isSubmitting ? 'not-allowed' : 'pointer',
            background:
              activeverdict === 'disagree'
                ? 'rgba(239, 68, 68, 0.08)'
                : 'var(--fw-bg-input)',
            borderColor:
              activeverdict === 'disagree'
                ? 'rgba(239, 68, 68, 0.3)'
                : 'var(--fw-border)',
            color:
              activeverdict === 'disagree'
                ? 'var(--fw-red)'
                : 'var(--fw-t2)',
            opacity: isSubmitting ? 0.6 : 1,
          }}
        >
          Disagree
        </button>

        {/* Graded-at timestamp — shown after successful submit */}
        {stored != null && gradedAt !== null && (
          <span
            data-testid="feedback-graded-at"
            style={{
              fontSize: 'var(--fw-fs-2xs)',
              color: 'var(--fw-t3)',
              fontFamily: 'var(--fw-font-ui)',
            }}
          >
            {/* ISO timestamp rendered as formatted text — ADR-0029 D3 */}
            Graded {gradedAt}
          </span>
        )}
      </div>

      {/* Reason field — shown when Disagree is active and no stored reason yet */}
      {showReason && (
        <div
          data-testid="feedback-reason-section"
          style={{ display: 'flex', flexDirection: 'column', gap: 4 }}
        >
          <label
            htmlFor={`feedback-reason-${analysisId}`}
            style={{
              fontSize: 'var(--fw-fs-xs)',
              color: 'var(--fw-t3)',
              fontFamily: 'var(--fw-font-ui)',
            }}
          >
            Reason (optional, ≤{REASON_MAX_CHARS} chars)
          </label>
          <textarea
            id={`feedback-reason-${analysisId}`}
            data-testid="feedback-reason-input"
            value={reasonDraft}
            maxLength={REASON_MAX_CHARS}
            rows={3}
            disabled={isSubmitting}
            onChange={(e) => setReasonDraft(e.target.value)}
            placeholder="Describe why you disagree with this verdict…"
            style={{
              width: '100%',
              boxSizing: 'border-box',
              padding: '6px 8px',
              fontSize: 'var(--fw-fs-xs)',
              fontFamily: 'var(--fw-font-ui)',
              background: 'var(--fw-bg-input)',
              border: '1px solid var(--fw-border)',
              borderRadius: 'var(--fw-r-xs)',
              color: 'var(--fw-t1)',
              resize: 'vertical',
              /* Bounded height — no inner scrollbar beyond this */
              maxHeight: 120,
              outline: 'none',
            }}
          />
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 8,
            }}
          >
            <span
              data-testid="feedback-reason-counter"
              style={{
                fontSize: 'var(--fw-fs-2xs)',
                color: reasonDraft.length > REASON_MAX_CHARS * 0.9 ? 'var(--fw-accent)' : 'var(--fw-t3)',
              }}
            >
              {/* Character count — honest feedback on length constraint */}
              {reasonDraft.length} / {REASON_MAX_CHARS}
            </span>
            <button
              type="button"
              data-testid="feedback-submit-btn"
              aria-busy={isSubmitting}
              disabled={isSubmitting}
              onClick={handleDisagreeSubmit}
              style={{
                padding: '3px 12px',
                fontSize: 'var(--fw-fs-xs)',
                fontFamily: 'var(--fw-font-ui)',
                fontWeight: 'var(--fw-fw-medium)',
                borderRadius: 'var(--fw-r-xs)',
                border: '1px solid var(--fw-border)',
                cursor: isSubmitting ? 'not-allowed' : 'pointer',
                background: 'var(--fw-bg-input)',
                color: 'var(--fw-t1)',
                opacity: isSubmitting ? 0.6 : 1,
              }}
            >
              {isSubmitting ? 'Saving…' : 'Submit'}
            </button>
          </div>
        </div>
      )}

      {/* Stored reason from the server row — rendered after submit */}
      {stored?.reason != null && !showReason && (
        <div
          data-testid="feedback-stored-reason"
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t3)',
            fontStyle: 'italic',
            fontFamily: 'var(--fw-font-ui)',
          }}
        >
          {/* reason is operator text — render as text node only (ADR-0029 D3) */}
          Reason: {String(stored.reason)}
        </div>
      )}

      {/* Error state */}
      {status === 'error' && error !== null && (
        <p
          data-testid="feedback-error"
          role="alert"
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-red)',
            margin: 0,
            fontFamily: 'var(--fw-font-ui)',
          }}
        >
          {error}
        </p>
      )}
    </div>
  )
}
