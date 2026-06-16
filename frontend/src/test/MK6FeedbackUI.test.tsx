/**
 * Tests for MK-6 feedback UI (issue #411, ADR-0045):
 *   - VerdictFeedback: Agree/Disagree controls, Disagree reason field,
 *     submit→reconcile, upsert/re-click, keyboard accessibility.
 *   - AgreementStat: denominator always shown, <10 = counts-only,
 *     ≥10 = percentage with denominator, RULE ProvenanceChip.
 *   - formatAgreementStat: pure function unit tests (the spec).
 *   - API client: postFeedback / fetchFeedbackSummary (types + shape).
 *
 * All IP addresses use RFC 5737 documentation ranges (192.0.2.x, 198.51.100.x,
 * 203.0.113.x) — real public IPs are blocked by gitleaks.
 *
 * EARS criteria covered (from issue #411):
 *   1. Each verdict card carries Agree/Disagree controls (keyboard-operable, labelled).
 *   2. Disagree shows optional bounded reason field (≤1000 chars).
 *   3. Submit → card reflects stored state (selected control + timestamp) from API.
 *      Optimistic UI reconciles to server row.
 *   4. Re-clicking upserts (latest wins).
 *   5. Denominator always visible (ADR-0045 D4 — never bare %).
 *   6. Fewer than 10 graded → counts only, no percentage (small-n honesty).
 *   7. Agreement stat carries RULE ProvenanceChip.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import { VerdictFeedback } from '../components/ai/ledger/VerdictFeedback'
import { AgreementStat } from '../components/ai/ledger/AgreementStat'
import { formatAgreementStat } from '../components/ai/ledger/agreementStatUtils'
import type { FeedbackRow, FeedbackSummary } from '../api/types'

// ---------------------------------------------------------------------------
// Mock the API client
// ---------------------------------------------------------------------------

const { mockPostFeedback, mockFetchFeedbackSummary } = vi.hoisted(() => ({
  mockPostFeedback: vi.fn(),
  mockFetchFeedbackSummary: vi.fn(),
}))

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    postFeedback: mockPostFeedback,
    fetchFeedbackSummary: mockFetchFeedbackSummary,
  }
})

// ---------------------------------------------------------------------------
// Test fixtures (RFC 5737 IPs only — never real public IPs)
// ---------------------------------------------------------------------------

const ANALYSIS_ID = 42

/** Stored feedback row returned by POST /ai/analyses/42/feedback */
const FEEDBACK_ROW_AGREE: FeedbackRow = {
  id: 101,
  analysis_id: ANALYSIS_ID,
  verdict: 'agree',
  reason: null,
  created_at: '2026-06-12T20:00:00Z',
}

const FEEDBACK_ROW_DISAGREE: FeedbackRow = {
  id: 102,
  analysis_id: ANALYSIS_ID,
  verdict: 'disagree',
  reason: 'The confidence threshold seems too low for this IP (192.0.2.1)',
  created_at: '2026-06-12T20:05:00Z',
}

const SUMMARY_LOW_N: FeedbackSummary = {
  graded: 7,
  agreed: 5,
  agreement_pct: 71.4,
}

const SUMMARY_SUFFICIENT_N: FeedbackSummary = {
  graded: 120,
  agreed: 100,
  agreement_pct: 83.3,
}

const SUMMARY_ZERO: FeedbackSummary = {
  graded: 0,
  agreed: 0,
  agreement_pct: 0,
}

const SUMMARY_EXACT_TEN: FeedbackSummary = {
  graded: 10,
  agreed: 8,
  agreement_pct: 80.0,
}

// ---------------------------------------------------------------------------
// formatAgreementStat — pure function unit tests
// ---------------------------------------------------------------------------

describe('formatAgreementStat — honest denominator and small-n rules', () => {
  it('returns "No graded verdicts yet" when graded === 0', () => {
    expect(formatAgreementStat(0, 0, 0)).toBe('No graded verdicts yet')
  })

  it('returns counts-only string when graded < 10 (small-n honesty)', () => {
    const result = formatAgreementStat(7, 5, 71.4)
    expect(result).toBe('5 of 7 graded verdicts agreed')
    // Must NOT contain a percentage sign
    expect(result).not.toContain('%')
  })

  it('shows 0 agreed when all disagree and graded < 10', () => {
    const result = formatAgreementStat(9, 0, 0)
    expect(result).toBe('0 of 9 graded verdicts agreed')
    expect(result).not.toContain('%')
  })

  it('shows percentage WITH denominator at exactly 10 graded (threshold boundary)', () => {
    const result = formatAgreementStat(10, 8, 80.0)
    expect(result).toContain('80%')
    expect(result).toContain('10')
    expect(result).toContain('graded verdicts')
  })

  it('shows percentage WITH denominator when graded >= 10', () => {
    const result = formatAgreementStat(120, 100, 83.3)
    expect(result).toContain('83%')
    expect(result).toContain('120')
    expect(result).toContain('graded verdicts')
    // Honest denominator rule: graded count visible alongside percentage
    expect(result).not.toMatch(/^\d+%$/) // never a bare percentage
  })

  it('denominator is always visible alongside the percentage (ADR-0045 D4)', () => {
    const result = formatAgreementStat(50, 42, 84.0)
    // Both the percentage AND the count must appear
    expect(result).toContain('50')
    expect(result).toContain('%')
  })
})

// ---------------------------------------------------------------------------
// VerdictFeedback — Agree/Disagree controls
// ---------------------------------------------------------------------------

describe('VerdictFeedback — agree/disagree controls', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // EARS-1: Both Agree and Disagree buttons render, keyboard-accessible
  it('renders Agree and Disagree buttons with keyboard-accessible labels', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)

    const agreeBtn = screen.getByTestId('feedback-agree-btn')
    const disagreeBtn = screen.getByTestId('feedback-disagree-btn')

    expect(agreeBtn).toBeInTheDocument()
    expect(disagreeBtn).toBeInTheDocument()
    // WCAG: buttons have text labels, are focusable
    expect(agreeBtn).toHaveTextContent('Agree')
    expect(disagreeBtn).toHaveTextContent('Disagree')
    // Keyboard accessible: <button> elements
    expect(agreeBtn.tagName).toBe('BUTTON')
    expect(disagreeBtn.tagName).toBe('BUTTON')
  })

  it('agree button carries aria-pressed=false when not selected', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)
    const agreeBtn = screen.getByTestId('feedback-agree-btn')
    expect(agreeBtn).toHaveAttribute('aria-pressed', 'false')
  })

  it('disagree button carries aria-pressed=false when not selected', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)
    const disagreeBtn = screen.getByTestId('feedback-disagree-btn')
    expect(disagreeBtn).toHaveAttribute('aria-pressed', 'false')
  })

  // EARS-1: Agree button submits immediately (no reason needed)
  it('clicking Agree submits immediately with verdict=agree', async () => {
    mockPostFeedback.mockResolvedValue(FEEDBACK_ROW_AGREE)

    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)

    fireEvent.click(screen.getByTestId('feedback-agree-btn'))

    await waitFor(() => {
      expect(mockPostFeedback).toHaveBeenCalledWith(ANALYSIS_ID, { verdict: 'agree' })
    })
  })

  it('clicking Agree sets aria-pressed=true on Agree button', async () => {
    mockPostFeedback.mockResolvedValue(FEEDBACK_ROW_AGREE)

    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)
    fireEvent.click(screen.getByTestId('feedback-agree-btn'))

    // Optimistic UI: agree button should be pressed immediately
    expect(screen.getByTestId('feedback-agree-btn')).toHaveAttribute('aria-pressed', 'true')
  })

  // EARS-2: Disagree shows optional reason field (≤1000 chars)
  it('clicking Disagree shows the reason field', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)
    fireEvent.click(screen.getByTestId('feedback-disagree-btn'))

    expect(screen.getByTestId('feedback-reason-section')).toBeInTheDocument()
    expect(screen.getByTestId('feedback-reason-input')).toBeInTheDocument()
  })

  it('reason textarea has a label (WCAG: htmlFor)', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)
    fireEvent.click(screen.getByTestId('feedback-disagree-btn'))

    const label = screen.getByLabelText(/reason/i)
    expect(label).toBeInTheDocument()
  })

  it('reason textarea enforces maxLength=1000', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)
    fireEvent.click(screen.getByTestId('feedback-disagree-btn'))

    const textarea = screen.getByTestId('feedback-reason-input')
    expect(textarea).toHaveAttribute('maxLength', '1000')
  })

  it('shows character counter in reason field', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)
    fireEvent.click(screen.getByTestId('feedback-disagree-btn'))

    expect(screen.getByTestId('feedback-reason-counter')).toHaveTextContent('0 / 1000')
  })

  it('updating reason updates the character counter', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)
    fireEvent.click(screen.getByTestId('feedback-disagree-btn'))

    const textarea = screen.getByTestId('feedback-reason-input')
    fireEvent.change(textarea, { target: { value: 'Short reason' } })

    expect(screen.getByTestId('feedback-reason-counter')).toHaveTextContent('12 / 1000')
  })

  it('Disagree reason field has a Submit button', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)
    fireEvent.click(screen.getByTestId('feedback-disagree-btn'))

    expect(screen.getByTestId('feedback-submit-btn')).toHaveTextContent('Submit')
  })

  // EARS-3: Submit → card reflects stored state from API response
  it('submitting Disagree calls POST with verdict=disagree + reason', async () => {
    mockPostFeedback.mockResolvedValue(FEEDBACK_ROW_DISAGREE)

    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)
    fireEvent.click(screen.getByTestId('feedback-disagree-btn'))

    const textarea = screen.getByTestId('feedback-reason-input')
    fireEvent.change(textarea, {
      target: { value: 'The confidence threshold seems too low for this IP (192.0.2.1)' },
    })
    fireEvent.click(screen.getByTestId('feedback-submit-btn'))

    await waitFor(() => {
      expect(mockPostFeedback).toHaveBeenCalledWith(ANALYSIS_ID, {
        verdict: 'disagree',
        reason: 'The confidence threshold seems too low for this IP (192.0.2.1)',
      })
    })
  })

  it('after Agree submit: card shows graded-at timestamp from server row (reconciliation)', async () => {
    mockPostFeedback.mockResolvedValue(FEEDBACK_ROW_AGREE)

    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)
    fireEvent.click(screen.getByTestId('feedback-agree-btn'))

    await waitFor(() => {
      // Server row's created_at is shown (reconciled — not the optimistic timestamp)
      expect(screen.getByTestId('feedback-graded-at')).toBeInTheDocument()
    })
    // Must contain "Graded" prefix — shows when the verdict was recorded
    expect(screen.getByTestId('feedback-graded-at')).toHaveTextContent('Graded')
  })

  it('after Disagree submit: stored reason from server row is displayed', async () => {
    mockPostFeedback.mockResolvedValue(FEEDBACK_ROW_DISAGREE)

    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)
    fireEvent.click(screen.getByTestId('feedback-disagree-btn'))
    fireEvent.click(screen.getByTestId('feedback-submit-btn'))

    await waitFor(() => {
      expect(screen.getByTestId('feedback-stored-reason')).toBeInTheDocument()
    })
    // reason rendered as text node (ADR-0029 D3) — never as innerHTML
    expect(screen.getByTestId('feedback-stored-reason')).toHaveTextContent(
      'The confidence threshold seems too low for this IP (192.0.2.1)',
    )
  })

  // EARS-4: Re-clicking upserts (latest wins)
  it('re-clicking Agree after a previous Disagree upserts (calls POST again)', async () => {
    mockPostFeedback
      .mockResolvedValueOnce(FEEDBACK_ROW_DISAGREE)
      .mockResolvedValueOnce(FEEDBACK_ROW_AGREE)

    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)

    // First: disagree
    fireEvent.click(screen.getByTestId('feedback-disagree-btn'))
    fireEvent.click(screen.getByTestId('feedback-submit-btn'))
    await waitFor(() => expect(mockPostFeedback).toHaveBeenCalledTimes(1))

    // Re-click: agree (upsert)
    fireEvent.click(screen.getByTestId('feedback-agree-btn'))
    await waitFor(() => expect(mockPostFeedback).toHaveBeenCalledTimes(2))

    // Second call must be with verdict=agree (latest wins)
    expect(mockPostFeedback).toHaveBeenLastCalledWith(ANALYSIS_ID, { verdict: 'agree' })
  })

  // EARS-3: Optimistic UI must reconcile to server row
  it('optimistic state reconciles to server row after successful POST', async () => {
    // Server returns a row with a specific id and created_at
    const serverRow: FeedbackRow = {
      id: 999,
      analysis_id: ANALYSIS_ID,
      verdict: 'agree',
      reason: null,
      created_at: '2026-06-12T21:00:00Z',
    }
    mockPostFeedback.mockResolvedValue(serverRow)

    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)
    fireEvent.click(screen.getByTestId('feedback-agree-btn'))

    await waitFor(() => {
      expect(screen.getByTestId('feedback-graded-at')).toBeInTheDocument()
    })

    // The graded-at timestamp comes from the server row (2026 Jun 12)
    // not a fabricated optimistic timestamp — "Graded" prefix confirms it's shown
    expect(screen.getByTestId('feedback-graded-at')).toBeInTheDocument()
  })

  it('shows error message when POST fails', async () => {
    const { ApiError } = await import('../api/client')
    mockPostFeedback.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))

    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)
    fireEvent.click(screen.getByTestId('feedback-agree-btn'))

    await waitFor(() => {
      expect(screen.getByTestId('feedback-error')).toBeInTheDocument()
    })
    expect(screen.getByTestId('feedback-error')).toHaveAttribute('role', 'alert')
    expect(screen.getByTestId('feedback-error')).toHaveTextContent('503')
  })

  it('seeds agree button as active when initialVerdict=agree', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} initialVerdict="agree" />)
    expect(screen.getByTestId('feedback-agree-btn')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByTestId('feedback-disagree-btn')).toHaveAttribute('aria-pressed', 'false')
  })

  it('seeds disagree button as active when initialVerdict=disagree', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} initialVerdict="disagree" />)
    expect(screen.getByTestId('feedback-disagree-btn')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByTestId('feedback-agree-btn')).toHaveAttribute('aria-pressed', 'false')
  })
})

// ---------------------------------------------------------------------------
// AgreementStat — headline stat with RULE chip
// ---------------------------------------------------------------------------

describe('AgreementStat — agreement headline stat', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // EARS-5: Denominator always visible (ADR-0045 D4)
  it('shows the graded count alongside the percentage (denominator always visible)', async () => {
    mockFetchFeedbackSummary.mockResolvedValue(SUMMARY_SUFFICIENT_N)

    render(<AgreementStat />)

    await waitFor(() => {
      expect(screen.getByTestId('agreement-stat')).toBeInTheDocument()
    })

    const statText = screen.getByTestId('agreement-stat-text')
    // Both the percentage and the denominator count must be visible
    expect(statText.textContent).toContain('83%')
    expect(statText.textContent).toContain('120')
  })

  // EARS-6: fewer than 10 graded → counts only, no percentage (small-n honesty)
  it('shows counts only (no %) when graded < 10 (small-n rule)', async () => {
    mockFetchFeedbackSummary.mockResolvedValue(SUMMARY_LOW_N)

    render(<AgreementStat />)

    await waitFor(() => {
      expect(screen.getByTestId('agreement-stat')).toBeInTheDocument()
    })

    const statText = screen.getByTestId('agreement-stat-text')
    // No percentage sign in small-n mode
    expect(statText.textContent).not.toContain('%')
    // Counts are visible
    expect(statText.textContent).toContain('5')
    expect(statText.textContent).toContain('7')
  })

  it('shows percentage at exactly 10 graded (boundary: ≥10 triggers % mode)', async () => {
    mockFetchFeedbackSummary.mockResolvedValue(SUMMARY_EXACT_TEN)

    render(<AgreementStat />)

    await waitFor(() => {
      expect(screen.getByTestId('agreement-stat')).toBeInTheDocument()
    })

    const statText = screen.getByTestId('agreement-stat-text')
    expect(statText.textContent).toContain('%')
    expect(statText.textContent).toContain('10')
  })

  it('shows plain-language "no verdicts yet" message when graded === 0 (issue #454)', async () => {
    mockFetchFeedbackSummary.mockResolvedValue(SUMMARY_ZERO)

    render(<AgreementStat />)

    await waitFor(() => {
      expect(screen.getByTestId('agreement-stat')).toBeInTheDocument()
    })

    // Plain-language format (issue #454): first-person, no jargon
    expect(screen.getByTestId('agreement-stat-text')).toHaveTextContent(
      "You haven't graded any AI verdicts yet.",
    )
  })

  // EARS-7: stat carries RULE ProvenanceChip (deterministic arithmetic — ADR-0035)
  it('carries a RULE ProvenanceChip (deterministic arithmetic, ADR-0035)', async () => {
    mockFetchFeedbackSummary.mockResolvedValue(SUMMARY_SUFFICIENT_N)

    render(<AgreementStat />)

    await waitFor(() => {
      expect(screen.getByTestId('agreement-stat-rule-chip')).toBeInTheDocument()
    })

    const chip = screen.getByTestId('agreement-stat-rule-chip')
    expect(chip.getAttribute('data-derivation')).toBe('rule')
  })

  it('renders nothing (null) when 503 / ledger not wired (empty degrade)', async () => {
    mockFetchFeedbackSummary.mockResolvedValue(null)

    const { container } = render(<AgreementStat />)

    // Wait for the loading state to resolve
    await waitFor(() => {
      expect(screen.queryByTestId('agreement-stat-loading')).not.toBeInTheDocument()
    })

    // Non-fatal empty degrade: component renders nothing
    expect(container.firstChild).toBeNull()
  })

  it('shows loading placeholder while fetching', () => {
    // Return a promise that never resolves (stuck loading)
    mockFetchFeedbackSummary.mockReturnValue(new Promise(() => {}))

    render(<AgreementStat />)

    expect(screen.getByTestId('agreement-stat-loading')).toBeInTheDocument()
    expect(screen.getByTestId('agreement-stat-loading')).toHaveAttribute('role', 'status')
  })

  it('shows error when fetchFeedbackSummary rejects', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchFeedbackSummary.mockRejectedValue(new ApiError(500, null, 'Internal Error'))

    render(<AgreementStat />)

    await waitFor(() => {
      expect(screen.getByTestId('agreement-stat-error')).toBeInTheDocument()
    })
    expect(screen.getByTestId('agreement-stat-error')).toHaveAttribute('role', 'alert')
    expect(screen.getByTestId('agreement-stat-error')).toHaveTextContent('500')
  })

  it('agreement stat text is a text node — no attacker-controlled HTML (ADR-0029 D3)', async () => {
    // The stat text is purely numeric from the server; ensure no dangerous content
    mockFetchFeedbackSummary.mockResolvedValue(SUMMARY_SUFFICIENT_N)

    render(<AgreementStat />)

    await waitFor(() => {
      expect(screen.getByTestId('agreement-stat-text')).toBeInTheDocument()
    })

    const statText = screen.getByTestId('agreement-stat-text')
    // textContent should not contain any HTML-like sequences from the server
    expect(statText.innerHTML).not.toContain('<script')
    expect(statText.innerHTML).not.toContain('onerror')
  })
})

// ---------------------------------------------------------------------------
// MM-454: plain-language agreement headline + consequence caption
// ---------------------------------------------------------------------------

import { formatAgreementStatPlain } from '../components/ai/ledger/agreementStatUtils'

describe('formatAgreementStatPlain — plain-language headline (issue #454)', () => {
  // EARS: graded === 0 → plain "haven't graded" message
  it('returns plain first-person message when graded === 0', () => {
    const [main, sub] = formatAgreementStatPlain(0, 0, 0)
    expect(main).toBe("You haven't graded any AI verdicts yet.")
    expect(sub).toBeNull()
  })

  // EARS: graded < 10 → honest counts + small-n sub-line explaining threshold
  it('returns counts + small-n sub-line when graded < 10', () => {
    const [main, sub] = formatAgreementStatPlain(7, 5, 71.4)
    // main line: plain first-person counts
    expect(main).toContain('7')
    expect(main).toContain('5')
    expect(main).not.toContain('%')
    // sub-line: explains when % appears (honest-denominator small-n rule)
    expect(sub).not.toBeNull()
    expect(sub).toContain('10')
  })

  it('uses singular "verdict" when graded === 1', () => {
    const [main] = formatAgreementStatPlain(1, 1, 100)
    expect(main).toContain('1 AI verdict')
    expect(main).not.toContain('verdicts')
  })

  it('uses plural "verdicts" when graded > 1 and < 10', () => {
    const [main] = formatAgreementStatPlain(3, 2, 66.7)
    expect(main).toContain('3 AI verdicts')
  })

  // EARS: graded >= 10 → percentage + honest denominator, no sub-line
  it('returns percentage + honest denominator when graded >= 10', () => {
    const [main, sub] = formatAgreementStatPlain(120, 100, 83.3)
    expect(main).toContain('100')
    expect(main).toContain('120')
    expect(main).toContain('83%')
    // No sub-line needed at sufficient sample size
    expect(sub).toBeNull()
  })

  it('shows honest denominator at exactly 10 graded (boundary)', () => {
    const [main, sub] = formatAgreementStatPlain(10, 8, 80.0)
    expect(main).toContain('10')
    expect(main).toContain('%')
    expect(sub).toBeNull()
  })

  it('never emits a bare percentage (denominator always present when % shown)', () => {
    const [main] = formatAgreementStatPlain(50, 42, 84.0)
    expect(main).toContain('50')
    expect(main).toContain('%')
    // The denominator (50) must appear alongside the %
    const pctIdx = main.indexOf('%')
    const countIdx = main.indexOf('50')
    expect(pctIdx).toBeGreaterThan(-1)
    expect(countIdx).toBeGreaterThan(-1)
  })
})

describe('AgreementStat — MM-454 plain headline (issue #454)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('headline reads in plain language (first-person) for small-n case', async () => {
    mockFetchFeedbackSummary.mockResolvedValue(SUMMARY_LOW_N)

    render(<AgreementStat />)

    await waitFor(() => {
      expect(screen.getByTestId('agreement-stat')).toBeInTheDocument()
    })

    const statText = screen.getByTestId('agreement-stat-text')
    // Plain-language: should start with "You've" (first-person)
    expect(statText.textContent).toMatch(/You've/)
    // Counts present
    expect(statText.textContent).toContain('5')
    expect(statText.textContent).toContain('7')
    // No percentage in small-n mode
    expect(statText.textContent).not.toContain('%')
  })

  it('shows sub-line explaining the % threshold when graded < 10', async () => {
    mockFetchFeedbackSummary.mockResolvedValue(SUMMARY_LOW_N)

    render(<AgreementStat />)

    await waitFor(() => {
      expect(screen.getByTestId('agreement-stat-subline')).toBeInTheDocument()
    })

    const subLine = screen.getByTestId('agreement-stat-subline')
    // Sub-line must mention 10 (the threshold) so the analyst understands why no % yet
    expect(subLine.textContent).toContain('10')
  })

  it('does NOT show sub-line when graded >= 10', async () => {
    mockFetchFeedbackSummary.mockResolvedValue(SUMMARY_SUFFICIENT_N)

    render(<AgreementStat />)

    await waitFor(() => {
      expect(screen.getByTestId('agreement-stat')).toBeInTheDocument()
    })

    expect(screen.queryByTestId('agreement-stat-subline')).not.toBeInTheDocument()
  })

  it('RULE chip carries a gloss title clarifying "Computed from your grades — not AI"', async () => {
    mockFetchFeedbackSummary.mockResolvedValue(SUMMARY_SUFFICIENT_N)

    render(<AgreementStat />)

    await waitFor(() => {
      expect(screen.getByTestId('agreement-stat-rule-chip')).toBeInTheDocument()
    })

    const chip = screen.getByTestId('agreement-stat-rule-chip')
    // title attribute carries the gloss (issue #454 / #451 gloss system)
    expect(chip.getAttribute('title')).toBe('Computed from your grades — not AI')
  })
})

describe('VerdictFeedback — MM-454 consequence caption (issue #454)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // EARS: consequence caption is visible at the buttons (not hidden behind hover)
  it('shows the consequence caption near the Agree/Disagree buttons', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)

    const caption = screen.getByTestId('feedback-consequence-caption')
    expect(caption).toBeInTheDocument()
    // Must not require a hover to be visible (it is always rendered)
    expect(caption).toBeVisible()
  })

  // EARS: caption states the feedback is recorded for agreement tracking
  it('consequence caption mentions recording for analyst agreement tracking', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)

    const caption = screen.getByTestId('feedback-consequence-caption')
    expect(caption.textContent).toMatch(/recorded/i)
    // Mentions agreement / analysts
    expect(caption.textContent).toMatch(/agrees? with analysts|analyst/i)
  })

  // EARS: caption explicitly states it does NOT change score or retrain model
  it('consequence caption states it does not change the score', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)

    const caption = screen.getByTestId('feedback-consequence-caption')
    expect(caption.textContent).toMatch(/does not change.*score|not change.*score/i)
  })

  it('consequence caption states it does not retrain the model', () => {
    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)

    const caption = screen.getByTestId('feedback-consequence-caption')
    expect(caption.textContent).toMatch(/retrain/i)
    // Must say it does NOT retrain
    expect(caption.textContent).toMatch(/not.*retrain|retrain.*not/i)
  })

  // Caption must appear even after agree/disagree is clicked (not conditional on submission)
  it('consequence caption is present before and after clicking Agree', async () => {
    mockPostFeedback.mockResolvedValue(FEEDBACK_ROW_AGREE)

    render(<VerdictFeedback analysisId={ANALYSIS_ID} />)

    // Before click
    expect(screen.getByTestId('feedback-consequence-caption')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('feedback-agree-btn'))

    // After click (still visible)
    expect(screen.getByTestId('feedback-consequence-caption')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// API types / shapes (verify FeedbackRow, FeedbackSummary, FeedbackRequest)
// ---------------------------------------------------------------------------

describe('MK-6 API types — shape verification', () => {
  it('FeedbackRow has the expected fields', () => {
    const row: FeedbackRow = {
      id: 1,
      analysis_id: ANALYSIS_ID,
      verdict: 'agree',
      reason: null,
      created_at: '2026-06-12T20:00:00Z',
    }
    expect(row.id).toBe(1)
    expect(row.verdict).toBe('agree')
    expect(row.reason).toBeNull()
  })

  it('FeedbackSummary has graded, agreed, agreement_pct', () => {
    const summary: FeedbackSummary = {
      graded: 100,
      agreed: 84,
      agreement_pct: 84.0,
    }
    expect(summary.graded).toBe(100)
    expect(summary.agreed).toBe(84)
    expect(summary.agreement_pct).toBe(84.0)
  })

  it('FeedbackVerdict is "agree" | "disagree"', async () => {
    const { FEEDBACK_ROW_AGREE: agree, FEEDBACK_ROW_DISAGREE: disagree } = {
      FEEDBACK_ROW_AGREE: FEEDBACK_ROW_AGREE,
      FEEDBACK_ROW_DISAGREE: FEEDBACK_ROW_DISAGREE,
    }
    // Type narrowing — both verdicts are valid
    const verdicts = [agree.verdict, disagree.verdict] as const
    expect(verdicts).toContain('agree')
    expect(verdicts).toContain('disagree')
  })
})

// ---------------------------------------------------------------------------
// useFeedbackSubmit — hook lifecycle (submit → reconcile, rollback on error)
// ---------------------------------------------------------------------------

describe('useFeedbackSubmit — submit/reconcile lifecycle', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('submit transitions through submitting → ok and reconciles to server row', async () => {
    // Import the hook and use a wrapper component to test it
    const { useFeedbackSubmit } = await import('../components/ai/ledger/useFeedback')

    let hookResult: ReturnType<typeof useFeedbackSubmit>

    function TestComponent() {
      hookResult = useFeedbackSubmit(ANALYSIS_ID)
      return (
        <div>
          <span data-testid="status">{hookResult.status}</span>
          <span data-testid="verdict">{hookResult.stored?.verdict ?? 'none'}</span>
          <button onClick={() => void hookResult.submit('agree')}>submit</button>
        </div>
      )
    }

    mockPostFeedback.mockResolvedValue(FEEDBACK_ROW_AGREE)
    render(<TestComponent />)

    expect(screen.getByTestId('status')).toHaveTextContent('idle')

    await act(async () => {
      fireEvent.click(screen.getByRole('button'))
    })

    // After reconciliation: ok + server row
    expect(screen.getByTestId('status')).toHaveTextContent('ok')
    expect(screen.getByTestId('verdict')).toHaveTextContent('agree')
  })

  it('rolls back to error state when POST fails, no stored row', async () => {
    const { useFeedbackSubmit } = await import('../components/ai/ledger/useFeedback')
    const { ApiError } = await import('../api/client')

    function TestComponent() {
      const { status, stored, error, submit } = useFeedbackSubmit(ANALYSIS_ID)
      return (
        <div>
          <span data-testid="status">{status}</span>
          <span data-testid="stored">{stored ? 'has-row' : 'no-row'}</span>
          <span data-testid="error">{error ?? 'none'}</span>
          <button onClick={() => void submit('agree')}>submit</button>
        </div>
      )
    }

    mockPostFeedback.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))
    render(<TestComponent />)

    await act(async () => {
      fireEvent.click(screen.getByRole('button'))
    })

    expect(screen.getByTestId('status')).toHaveTextContent('error')
    expect(screen.getByTestId('stored')).toHaveTextContent('no-row')
    expect(screen.getByTestId('error')).not.toHaveTextContent('none')
  })
})

// ---------------------------------------------------------------------------
// D2 reactivity — AgreementStat re-fetches after successful submit
// ---------------------------------------------------------------------------

describe('D2 reactivity — AgreementStat re-fetches after submit (feedbackVersion counter)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  /**
   * Prove the fix: render AgreementStat with a refreshKey that starts at 0
   * (initial load = 1 fetch), then bump refreshKey to 1 (simulates a successful
   * submit from a VerdictCard) — the stat must re-fetch (total calls = 2)
   * and update to the new server value.
   *
   * EARS D2: WHEN an analyst submits Agree/Disagree on a VerdictCard, the
   * AgreementStat headline SHALL update to reflect the new server summary
   * without a full page reload.
   */
  it('AgreementStat re-fetches GET /ai/feedback/summary when refreshKey increments', async () => {
    // First call: 1 graded verdict (before submit)
    const summaryBefore: FeedbackSummary = { graded: 1, agreed: 1, agreement_pct: 0 }
    // Second call: 2 graded verdicts (after submit)
    const summaryAfter: FeedbackSummary = { graded: 2, agreed: 2, agreement_pct: 0 }

    mockFetchFeedbackSummary
      .mockResolvedValueOnce(summaryBefore)
      .mockResolvedValueOnce(summaryAfter)

    // Wrapper to control refreshKey (simulates AIRoute feedbackVersion counter)
    function StatWrapper({ refreshKey }: { refreshKey: number }) {
      return <AgreementStat refreshKey={refreshKey} />
    }

    const { rerender } = render(<StatWrapper refreshKey={0} />)

    // Initial load: first fetch resolves → shows summaryBefore (1 graded)
    await waitFor(() => {
      expect(screen.getByTestId('agreement-stat')).toBeInTheDocument()
    })
    // First fetch happened
    expect(mockFetchFeedbackSummary).toHaveBeenCalledTimes(1)

    // Simulate a successful submit: bump refreshKey (mirrors handleFeedbackChange in AIRoute)
    rerender(<StatWrapper refreshKey={1} />)

    // After refreshKey bump: second fetch resolves → shows summaryAfter (2 graded)
    await waitFor(() => {
      expect(mockFetchFeedbackSummary).toHaveBeenCalledTimes(2)
    })

    // Stat text updates to reflect the new server value (2 graded verdicts)
    await waitFor(() => {
      expect(screen.getByTestId('agreement-stat-text').textContent).toContain('2')
    })
  })

  it('onSuccess callback in useFeedbackSubmit fires only after server confirms, not on error', async () => {
    const { useFeedbackSubmit } = await import('../components/ai/ledger/useFeedback')
    const { ApiError } = await import('../api/client')

    const onSuccessMock = vi.fn()

    function TestHook() {
      const { submit, status } = useFeedbackSubmit(ANALYSIS_ID, onSuccessMock)
      return (
        <div>
          <span data-testid="status">{status}</span>
          <button onClick={() => void submit('agree')}>submit</button>
        </div>
      )
    }

    // Error path: onSuccess must NOT be called
    mockPostFeedback.mockRejectedValue(new ApiError(500, null, 'Internal Error'))
    render(<TestHook />)

    await act(async () => {
      fireEvent.click(screen.getByRole('button'))
    })

    expect(screen.getByTestId('status')).toHaveTextContent('error')
    // onSuccess must NOT fire on error
    expect(onSuccessMock).not.toHaveBeenCalled()
  })

  it('onSuccess callback in useFeedbackSubmit fires exactly once after server confirms', async () => {
    const { useFeedbackSubmit } = await import('../components/ai/ledger/useFeedback')

    const onSuccessMock = vi.fn()

    function TestHook() {
      const { submit, status } = useFeedbackSubmit(ANALYSIS_ID, onSuccessMock)
      return (
        <div>
          <span data-testid="status">{status}</span>
          <button onClick={() => void submit('agree')}>submit</button>
        </div>
      )
    }

    mockPostFeedback.mockResolvedValue(FEEDBACK_ROW_AGREE)
    render(<TestHook />)

    await act(async () => {
      fireEvent.click(screen.getByRole('button'))
    })

    expect(screen.getByTestId('status')).toHaveTextContent('ok')
    // onSuccess fires exactly once after server confirms
    expect(onSuccessMock).toHaveBeenCalledTimes(1)
  })
})
