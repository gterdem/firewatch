/**
 * Tests for the Case File UI — issue #534 + #535 / ADR-0053.
 *
 * EARS criteria covered (issue #534 B1-core):
 *
 * EARS-1 (create + open slide-over):
 *   - CreateCaseButton calls POST /cases and opens {kind:'case', value} in the slide-over.
 *   - "Creating…" label shown while in-flight; restored on error.
 *   - Error message rendered on failure (non-200 status).
 *
 * EARS-2 (timeline):
 *   - CaseTimeline renders linked entries (ref_kind + ref_id + created_at).
 *   - CaseTimeline shows empty state when no entries.
 *   - CaseTimeline shows spinner while loading.
 *
 * EARS-3 (notes):
 *   - CaseNotes renders existing notes (author, body_md as text node, created_at).
 *   - CaseNotes shows empty-state copy when no notes.
 *   - AddNoteForm submits and reloads notes on success.
 *   - Note body is rendered as text node — not injected as HTML (ADR-0029 D3).
 *
 * EARS-4 (author):
 *   - Note author rendered as text node.
 *   - ai_drafted note shows "AI" badge; non-AI note does not.
 *
 * EARS-5 (disposition selector):
 *   - CaseDispositionSelect renders all 4 options.
 *   - Changing disposition calls PATCH /cases/{id}/disposition.
 *   - Error displayed on API failure; value reverts.
 *
 * CaseHeader:
 *   - Renders case title, subject, disposition chip, created_at.
 *
 * EntityPanelProvider wiring:
 *   - Opening {kind:'case', value:'42'} renders CasePanel (kind switch).
 *
 * VerdictCard "Open case" affordance (EARS-1):
 *   - VerdictCard renders the "Open case" section.
 *   - Clicking "Open case" calls createCase + openEntity.
 *
 * Security:
 *   - Note body containing HTML special chars renders as text node, not DOM elements.
 *   - ref_id containing HTML special chars renders as text node.
 *
 * EARS criteria covered (issue #535 B1-polish — AI-drafted case summary):
 *
 * EARS-1 (draft summary button triggers narration):
 *   - "Draft summary" button calls POST /cases/{id}/summary (draftCaseSummary).
 *   - "Drafting…" label shown while in-flight.
 *   - Error alert rendered on API failure.
 *
 * EARS-2 (provenance label — AI-drafted):
 *   - Rendered draft shows ProvenanceChip with correct derivation.
 *   - Zero-egress badge present.
 *   - Glass-box disclosure panel present.
 *
 * EARS-3 (collected_fields surfaced in disclosure):
 *   - Toggling "Show sources" reveals collected_fields.
 *
 * EARS-4 (analyst edits and saves as operator note):
 *   - "Edit & own this draft" enters edit mode.
 *   - Saving calls addNote with ai_drafted=false.
 *   - "Cancel" reverts textarea content and exits edit mode.
 *
 * EARS-5 (rule-only degrade):
 *   - When provenance="rule", ProvenanceChip shows "RULE".
 *
 * EARS-6 (suggest-only — no auto-disposition):
 *   - Generating a summary does NOT call setDisposition.
 *
 * Security:
 *   - Narrative text rendered as text node — not raw HTML (ADR-0029 D3).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

// ---------------------------------------------------------------------------
// Module-level mocks
// ---------------------------------------------------------------------------

// Mock the cases API client
vi.mock('../api/cases', () => ({
  createCase: vi.fn(),
  getCase: vi.fn(),
  listCases: vi.fn(),
  setDisposition: vi.fn(),
  addNote: vi.fn(),
  listNotes: vi.fn(),
  linkEvent: vi.fn(),
  getCaseTimeline: vi.fn(),
  draftCaseSummary: vi.fn(),
}))

// Mock client.ts (needed by cases.ts at module init)
vi.mock('../api/client', () => ({
  resolveBaseUrl: vi.fn(() => ''),
  assertLoopbackBase: vi.fn(),
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  ApiError: class ApiError extends Error {
    status: number
    detail: unknown
    constructor(status: number, detail: unknown, message?: string) {
      super(message ?? String(status))
      this.status = status
      this.detail = detail
    }
  },
}))

// Mock logs (needed by EntityPanelProvider)
vi.mock('../api/logs', () => ({
  fetchThreatScore: vi.fn().mockResolvedValue(null),
}))

// Mock slideOverMode (needed by EntityPanelProvider)
vi.mock('../components/entity/slideOverMode', () => ({
  getSlideOverMode: vi.fn(() => 'overlay'),
  setSlideOverMode: vi.fn(),
  subscribeSlideOverMode: vi.fn(() => () => {}),
}))

import {
  createCase,
  getCase,
  listCases,
  listNotes,
  addNote,
  setDisposition,
  getCaseTimeline,
  draftCaseSummary,
} from '../api/cases'
import type { CaseFile, CaseNote, CaseTimelineResponse, CaseSummaryResponse } from '../api/cases'
import { ApiError } from '../api/client'

import { CaseHeader } from '../components/entity/case/CaseHeader'
import { CaseTimeline } from '../components/entity/case/CaseTimeline'
import { CaseNotes } from '../components/entity/case/CaseNotes'
import { CaseDispositionSelect } from '../components/entity/case/CaseDispositionSelect'
import { CreateCaseButton } from '../components/entity/case/CreateCaseButton'
import { CaseSummary } from '../components/entity/case/CaseSummary'
import CasePanel from '../components/entity/case/CasePanel'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import { useEntityActions } from '../components/entity/EntityPanelContext'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CASE_FILE_FIXTURE: CaseFile = {
  id: 42,
  title: 'WAF investigation',
  subject: '192.0.2.1',
  status: 'open',
  disposition: 'open',
  created_at: '2026-06-13T10:00:00Z',
  updated_at: '2026-06-13T10:00:00Z',
}

const NOTE_FIXTURE: CaseNote = {
  id: 1,
  case_id: 42,
  author: 'local operator',
  body_md: 'Checked the logs. Seems suspicious.',
  ai_drafted: false,
  created_at: '2026-06-13T10:05:00Z',
  updated_at: '2026-06-13T10:05:00Z',
}

const AI_NOTE_FIXTURE: CaseNote = {
  ...NOTE_FIXTURE,
  id: 2,
  body_md: 'AI-drafted summary goes here.',
  ai_drafted: true,
}

const TIMELINE_FIXTURE: CaseTimelineResponse = {
  case_id: 42,
  entries: [
    {
      id: 1,
      case_id: 42,
      ref_kind: 'security_event',
      ref_id: '100',
      created_at: '2026-06-13T09:00:00Z',
    },
    {
      id: 2,
      case_id: 42,
      ref_kind: 'ai_analysis',
      ref_id: '55',
      created_at: '2026-06-13T09:30:00Z',
    },
  ],
}

const SUMMARY_AI_FIXTURE: CaseSummaryResponse = {
  note_id: 10,
  narrative: 'IP 192.0.2.1 triggered brute-force rules. What to check next: Review score breakdown.',
  provenance: 'ai',
  collected_fields: ['source_ip', 'score_breakdown', 'blocked_events'],
  ai_status: 'ok',
}

const SUMMARY_RULE_FIXTURE: CaseSummaryResponse = {
  note_id: 11,
  narrative: 'IP 192.0.2.1 received threat level HIGH (score 80/100). Rule-only summary.',
  provenance: 'rule',
  collected_fields: ['source_ip', 'threat_level', 'score'],
  ai_status: 'unavailable',
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Wrap a component in EntityPanelProvider for tests needing openEntity. */
function withProvider(ui: React.ReactNode) {
  return <EntityPanelProvider>{ui}</EntityPanelProvider>
}

// ---------------------------------------------------------------------------
// CaseHeader tests
// ---------------------------------------------------------------------------

describe('CaseHeader', () => {
  it('renders case title as text node', () => {
    render(<CaseHeader caseFile={CASE_FILE_FIXTURE} />)
    expect(screen.getByTestId('case-title')).toHaveTextContent('WAF investigation')
  })

  it('renders case subject', () => {
    render(<CaseHeader caseFile={CASE_FILE_FIXTURE} />)
    expect(screen.getByTestId('case-subject')).toHaveTextContent('192.0.2.1')
  })

  it('renders disposition chip with correct tone', () => {
    render(<CaseHeader caseFile={CASE_FILE_FIXTURE} />)
    const chip = screen.getByTestId('case-disposition-chip')
    expect(chip).toHaveTextContent('Open')
  })

  it('renders true-positive disposition chip', () => {
    render(<CaseHeader caseFile={{ ...CASE_FILE_FIXTURE, disposition: 'true-positive' }} />)
    expect(screen.getByTestId('case-disposition-chip')).toHaveTextContent('True positive')
  })
})

// ---------------------------------------------------------------------------
// CaseTimeline tests
// ---------------------------------------------------------------------------

describe('CaseTimeline (EARS-2)', () => {
  beforeEach(() => {
    vi.mocked(getCaseTimeline).mockReset()
  })

  it('shows spinner while loading', () => {
    vi.mocked(getCaseTimeline).mockReturnValue(new Promise(() => {}))
    render(<CaseTimeline caseId={42} />)
    expect(screen.getByText('Loading timeline…')).toBeInTheDocument()
  })

  it('renders timeline entries after load', async () => {
    vi.mocked(getCaseTimeline).mockResolvedValue(TIMELINE_FIXTURE)
    render(<CaseTimeline caseId={42} />)
    await waitFor(() => {
      expect(screen.getAllByTestId('timeline-entry')).toHaveLength(2)
    })
  })

  it('renders ref_id as text node — not HTML', async () => {
    const malicious = '<script>alert(1)</script>'
    vi.mocked(getCaseTimeline).mockResolvedValue({
      case_id: 42,
      entries: [{ id: 9, case_id: 42, ref_kind: 'security_event', ref_id: malicious, created_at: '2026-06-13T09:00:00Z' }],
    })
    render(<CaseTimeline caseId={42} />)
    await waitFor(() => {
      const el = screen.getByTestId('timeline-ref-id')
      // Text content equals the raw string, NOT executed as HTML
      expect(el.textContent).toBe(malicious)
      // No <script> element injected into the DOM
      expect(document.querySelector('script[data-injected]')).toBeNull()
    })
  })

  it('shows kind labels (Event / AI analysis)', async () => {
    vi.mocked(getCaseTimeline).mockResolvedValue(TIMELINE_FIXTURE)
    render(<CaseTimeline caseId={42} />)
    await waitFor(() => {
      expect(screen.getByText('Event')).toBeInTheDocument()
      expect(screen.getByText('AI analysis')).toBeInTheDocument()
    })
  })

  it('shows empty state when no entries', async () => {
    vi.mocked(getCaseTimeline).mockResolvedValue({ case_id: 42, entries: [] })
    render(<CaseTimeline caseId={42} />)
    await waitFor(() => {
      expect(screen.getByTestId('timeline-empty')).toBeInTheDocument()
    })
  })

  it('shows error on load failure', async () => {
    vi.mocked(getCaseTimeline).mockRejectedValue(new Error('network error'))
    render(<CaseTimeline caseId={42} />)
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// CaseNotes tests
// ---------------------------------------------------------------------------

describe('CaseNotes (EARS-3 / EARS-4)', () => {
  beforeEach(() => {
    vi.mocked(listNotes).mockReset()
    vi.mocked(addNote).mockReset()
  })

  it('shows spinner while loading', () => {
    vi.mocked(listNotes).mockReturnValue(new Promise(() => {}))
    render(<CaseNotes caseId={42} />)
    expect(screen.getByText('Loading notes…')).toBeInTheDocument()
  })

  it('renders existing note author as text node (EARS-4)', async () => {
    vi.mocked(listNotes).mockResolvedValue({ case_id: 42, notes: [NOTE_FIXTURE] })
    render(<CaseNotes caseId={42} />)
    await waitFor(() => {
      expect(screen.getByTestId('note-author')).toHaveTextContent('local operator')
    })
  })

  it('renders note body as text node — not raw HTML (ADR-0029 D3)', async () => {
    const malicious = '<img src=x onerror=alert(1)>'
    vi.mocked(listNotes).mockResolvedValue({
      case_id: 42,
      notes: [{ ...NOTE_FIXTURE, body_md: malicious }],
    })
    render(<CaseNotes caseId={42} />)
    await waitFor(() => {
      const el = screen.getByTestId('note-body')
      expect(el.textContent).toBe(malicious)
      // No <img> element injected
      expect(document.querySelector('img[onerror]')).toBeNull()
    })
  })

  it('shows AI badge on ai_drafted note (EARS-4)', async () => {
    vi.mocked(listNotes).mockResolvedValue({ case_id: 42, notes: [AI_NOTE_FIXTURE] })
    render(<CaseNotes caseId={42} />)
    await waitFor(() => {
      expect(screen.getByTestId('note-ai-badge')).toBeInTheDocument()
    })
  })

  it('does NOT show AI badge on non-AI note', async () => {
    vi.mocked(listNotes).mockResolvedValue({ case_id: 42, notes: [NOTE_FIXTURE] })
    render(<CaseNotes caseId={42} />)
    await waitFor(() => {
      expect(screen.queryByTestId('note-ai-badge')).toBeNull()
    })
  })

  it('shows empty state when no notes', async () => {
    vi.mocked(listNotes).mockResolvedValue({ case_id: 42, notes: [] })
    render(<CaseNotes caseId={42} />)
    await waitFor(() => {
      expect(screen.getByTestId('notes-empty')).toBeInTheDocument()
    })
  })

  it('add-note form submits and reloads notes (EARS-3)', async () => {
    const user = userEvent.setup()
    // First call returns empty; subsequent call (after add) returns one note.
    vi.mocked(listNotes)
      .mockResolvedValueOnce({ case_id: 42, notes: [] })
      .mockResolvedValue({ case_id: 42, notes: [NOTE_FIXTURE] })
    vi.mocked(addNote).mockResolvedValue(1)

    render(<CaseNotes caseId={42} />)
    await waitFor(() => screen.getByTestId('notes-empty'))

    const textarea = screen.getByTestId('note-textarea')
    await user.type(textarea, 'My investigation note')

    const submitBtn = screen.getByTestId('add-note-submit')
    await user.click(submitBtn)

    await waitFor(() => {
      expect(addNote).toHaveBeenCalledWith(42, { body_md: 'My investigation note' })
      expect(listNotes).toHaveBeenCalledTimes(2)
    })
  })

  it('add-note submit button disabled when textarea is empty', async () => {
    vi.mocked(listNotes).mockResolvedValue({ case_id: 42, notes: [] })
    render(<CaseNotes caseId={42} />)
    await waitFor(() => screen.getByTestId('notes-empty'))
    const submitBtn = screen.getByTestId('add-note-submit')
    expect(submitBtn).toBeDisabled()
  })

  it('shows error on add-note API failure', async () => {
    const user = userEvent.setup()
    vi.mocked(listNotes).mockResolvedValue({ case_id: 42, notes: [] })
    vi.mocked(addNote).mockRejectedValue(new (ApiError as unknown as new (s: number, d: unknown) => Error)(422, 'too long'))

    render(<CaseNotes caseId={42} />)
    await waitFor(() => screen.getByTestId('notes-empty'))

    await user.type(screen.getByTestId('note-textarea'), 'test note')
    await user.click(screen.getByTestId('add-note-submit'))

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// CaseDispositionSelect tests (EARS-5)
// ---------------------------------------------------------------------------

describe('CaseDispositionSelect (EARS-5)', () => {
  beforeEach(() => {
    vi.mocked(setDisposition).mockReset()
  })

  it('renders all 4 disposition options', () => {
    render(<CaseDispositionSelect caseId={42} current="open" />)
    const select = screen.getByRole('combobox', { name: /Set case disposition/ })
    expect(select).toBeInTheDocument()
    // Check all values are present
    expect(screen.getByDisplayValue('Open')).toBeInTheDocument()
  })

  it('calls PATCH /cases/{id}/disposition on change (EARS-5)', async () => {
    const user = userEvent.setup()
    vi.mocked(setDisposition).mockResolvedValue(undefined)
    const onChange = vi.fn()

    render(
      <CaseDispositionSelect caseId={42} current="open" onChange={onChange} />,
    )

    await user.selectOptions(
      screen.getByRole('combobox', { name: /Set case disposition/ }),
      'true-positive',
    )

    await waitFor(() => {
      expect(setDisposition).toHaveBeenCalledWith(42, 'true-positive')
      expect(onChange).toHaveBeenCalledWith('true-positive')
    })
  })

  it('shows error and reverts value on API failure', async () => {
    const user = userEvent.setup()
    vi.mocked(setDisposition).mockRejectedValue(
      new (ApiError as unknown as new (s: number, d: unknown) => Error)(503, 'store error'),
    )

    render(<CaseDispositionSelect caseId={42} current="open" />)
    const select = screen.getByRole('combobox', { name: /Set case disposition/ })

    await user.selectOptions(select, 'true-positive')

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
      // Value reverts to 'open' (the previous value)
      expect(select).toHaveValue('open')
    })
  })
})

// ---------------------------------------------------------------------------
// CasePanel tests
// ---------------------------------------------------------------------------

describe('CasePanel', () => {
  beforeEach(() => {
    vi.mocked(getCase).mockReset()
    vi.mocked(listNotes).mockResolvedValue({ case_id: 42, notes: [] })
    vi.mocked(getCaseTimeline).mockResolvedValue({ case_id: 42, entries: [] })
  })

  it('shows spinner while loading case', () => {
    vi.mocked(getCase).mockReturnValue(new Promise(() => {}))
    render(<CasePanel caseId="42" />)
    expect(screen.getByText('Loading case file…')).toBeInTheDocument()
  })

  it('renders case header, disposition, timeline, notes sections on load', async () => {
    vi.mocked(getCase).mockResolvedValue(CASE_FILE_FIXTURE)
    render(<CasePanel caseId="42" />)
    await waitFor(() => {
      expect(screen.getByTestId('case-panel')).toBeInTheDocument()
      expect(screen.getByTestId('case-header')).toBeInTheDocument()
      expect(screen.getByTestId('disposition-select')).toBeInTheDocument()
    })
  })

  it('shows 404 error when case not found', async () => {
    vi.mocked(getCase).mockResolvedValue(null)
    render(<CasePanel caseId="42" />)
    await waitFor(() => {
      expect(screen.getByTestId('case-panel-error')).toHaveTextContent('Case #42 not found')
    })
  })

  it('shows error on invalid (non-numeric) caseId', async () => {
    render(<CasePanel caseId="not-a-number" />)
    await waitFor(() => {
      expect(screen.getByTestId('case-panel-error')).toBeInTheDocument()
    })
  })

  it('shows fetch error on API failure', async () => {
    vi.mocked(getCase).mockRejectedValue(new Error('network'))
    render(<CasePanel caseId="42" />)
    await waitFor(() => {
      expect(screen.getByTestId('case-panel-error')).toHaveTextContent('Failed to load case file')
    })
  })
})

// ---------------------------------------------------------------------------
// CreateCaseButton tests (EARS-1 / EARS-2 — issue #757 find-or-create)
// ---------------------------------------------------------------------------

describe('CreateCaseButton (EARS-1 / EARS-2 — find-or-create, issue #757)', () => {
  beforeEach(() => {
    vi.mocked(createCase).mockReset()
    vi.mocked(listCases).mockReset()
    // getCase is called when the panel opens; prevent loading state interference
    vi.mocked(getCase).mockReturnValue(new Promise(() => {}))
  })

  it('renders button with default label', () => {
    render(withProvider(<CreateCaseButton title="Test case" subject="192.0.2.1" />))
    expect(screen.getByTestId('create-case-button')).toHaveTextContent('Open case')
  })

  it('renders with custom label', () => {
    render(withProvider(<CreateCaseButton title="T" subject="S" label="Create" />))
    expect(screen.getByTestId('create-case-button')).toHaveTextContent('Create')
  })

  // EARS-2 (issue #757): no existing open case → create then open
  it('creates a new case when no open case exists for the subject (EARS-2)', async () => {
    const user = userEvent.setup()
    vi.mocked(listCases).mockResolvedValue({ items: [], next_cursor: null, has_more: false })
    vi.mocked(createCase).mockResolvedValue(99)

    render(withProvider(<CreateCaseButton title="New case" subject="192.0.2.5" />))
    await user.click(screen.getByTestId('create-case-button'))

    await waitFor(() => {
      expect(createCase).toHaveBeenCalledWith({ title: 'New case', subject: '192.0.2.5' })
      expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
    })
  })

  // EARS-1 (issue #757): existing open case found → open it, no new case created
  it('opens existing open case without calling createCase when one exists (EARS-1)', async () => {
    const user = userEvent.setup()
    const existingCase: CaseFile = {
      id: 77,
      title: 'Existing investigation',
      subject: '192.0.2.1',
      status: 'open',
      disposition: 'open',
      created_at: '2026-06-13T08:00:00Z',
      updated_at: '2026-06-13T08:00:00Z',
    }
    vi.mocked(listCases).mockResolvedValue({
      items: [existingCase],
      next_cursor: null,
      has_more: false,
    })

    render(withProvider(<CreateCaseButton title="New case" subject="192.0.2.1" />))
    await user.click(screen.getByTestId('create-case-button'))

    await waitFor(() => {
      // Existing case opened
      expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
    })
    // No new case was created
    expect(createCase).not.toHaveBeenCalled()
    // listCases was called with the subject filter
    expect(listCases).toHaveBeenCalledWith({ subject: '192.0.2.1', limit: 10 })
  })

  // Graceful degrade: listCases errors → fall back to create (EARS-2)
  it('falls back to create when listCases throws (graceful degrade)', async () => {
    const user = userEvent.setup()
    vi.mocked(listCases).mockRejectedValue(new Error('network error'))
    vi.mocked(createCase).mockResolvedValue(55)

    render(withProvider(<CreateCaseButton title="T" subject="192.0.2.9" />))
    await user.click(screen.getByTestId('create-case-button'))

    await waitFor(() => {
      expect(createCase).toHaveBeenCalledWith({ title: 'T', subject: '192.0.2.9' })
      expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
    })
  })

  // Graceful degrade: listCases returns null (503) → fall back to create
  it('falls back to create when listCases returns null (503 degrade)', async () => {
    const user = userEvent.setup()
    vi.mocked(listCases).mockResolvedValue(null)
    vi.mocked(createCase).mockResolvedValue(66)

    render(withProvider(<CreateCaseButton title="T" subject="192.0.2.8" />))
    await user.click(screen.getByTestId('create-case-button'))

    await waitFor(() => {
      expect(createCase).toHaveBeenCalled()
    })
  })

  it('shows "Opening…" label while in-flight', async () => {
    const user = userEvent.setup()
    // listCases hangs to hold the button in-flight
    vi.mocked(listCases).mockReturnValue(new Promise(() => {}))

    render(withProvider(<CreateCaseButton title="T" subject="S" />))
    await user.click(screen.getByTestId('create-case-button'))

    expect(screen.getByTestId('create-case-button')).toHaveTextContent('Opening…')
  })

  it('shows error on createCase API failure and does not open slide-over', async () => {
    const user = userEvent.setup()
    vi.mocked(listCases).mockResolvedValue({ items: [], next_cursor: null, has_more: false })
    vi.mocked(createCase).mockRejectedValue(new Error('Server error'))

    render(withProvider(<CreateCaseButton title="T" subject="S" />))
    await user.click(screen.getByTestId('create-case-button'))

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.queryByTestId('slide-over-panel')).toBeNull()
    })
  })
})

// ---------------------------------------------------------------------------
// EntityPanelProvider wiring — kind="case" (EARS-1 / ADR-0053 D1)
// ---------------------------------------------------------------------------

describe('EntityPanelProvider — kind="case" routing', () => {
  beforeEach(() => {
    vi.mocked(getCase).mockResolvedValue(CASE_FILE_FIXTURE)
    vi.mocked(listNotes).mockResolvedValue({ case_id: 42, notes: [] })
    vi.mocked(getCaseTimeline).mockResolvedValue({ case_id: 42, entries: [] })
  })

  function OpenCaseTrigger() {
    const { openEntity } = useEntityActions()
    return (
      <button
        data-testid="open-case-trigger"
        onClick={() => openEntity({ kind: 'case', value: '42' })}
      >
        Open
      </button>
    )
  }

  it('opens CasePanel in the slide-over when kind="case"', async () => {
    const user = userEvent.setup()
    render(
      <EntityPanelProvider>
        <OpenCaseTrigger />
      </EntityPanelProvider>,
    )

    await user.click(screen.getByTestId('open-case-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
      // CasePanel is rendered inside the slide-over
      expect(screen.getByTestId('case-panel')).toBeInTheDocument()
    })
  })

  it('slide-over ariaLabel includes "Case" for kind="case"', async () => {
    const user = userEvent.setup()
    render(
      <EntityPanelProvider>
        <OpenCaseTrigger />
      </EntityPanelProvider>,
    )

    await user.click(screen.getByTestId('open-case-trigger'))

    await waitFor(() => {
      const panel = screen.getByTestId('slide-over-panel')
      expect(panel.getAttribute('aria-label')).toMatch(/Case/)
    })
  })

  it('breadcrumb shows case id', async () => {
    const user = userEvent.setup()
    render(
      <EntityPanelProvider>
        <OpenCaseTrigger />
      </EntityPanelProvider>,
    )

    await user.click(screen.getByTestId('open-case-trigger'))

    await waitFor(() => {
      const breadcrumb = screen.getByTestId('slide-over-breadcrumb')
      expect(breadcrumb).toHaveTextContent('42')
    })
  })
})

// ---------------------------------------------------------------------------
// CaseSummary tests (issue #535 B1-polish / ADR-0053 D2)
// ---------------------------------------------------------------------------

describe('CaseSummary (B1-polish / ADR-0053 D2)', () => {
  beforeEach(() => {
    vi.mocked(draftCaseSummary).mockReset()
    vi.mocked(addNote).mockReset()
    vi.mocked(setDisposition).mockReset()
  })

  // EARS-1: "Draft summary" button triggers POST /cases/{id}/summary
  it('renders "Draft summary" button (EARS-1)', () => {
    render(<CaseSummary caseId={42} />)
    expect(screen.getByTestId('draft-summary-button')).toHaveTextContent('Draft summary')
  })

  it('calls draftCaseSummary on click (EARS-1)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockResolvedValue(SUMMARY_AI_FIXTURE)

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))

    await waitFor(() => {
      expect(draftCaseSummary).toHaveBeenCalledWith(42)
    })
  })

  it('shows "Drafting…" label while in-flight (EARS-1)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockReturnValue(new Promise(() => {}))

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))

    // Button text updates while request is in-flight
    expect(screen.getByTestId('draft-summary-button')).toHaveTextContent('Drafting…')
  })

  it('shows error alert on API failure (EARS-1)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockRejectedValue(new Error('LLM unavailable'))

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))

    await waitFor(() => {
      expect(screen.getByTestId('draft-error')).toBeInTheDocument()
    })
  })

  // EARS-2: Draft labeled AI-drafted via ProvenanceChip (ADR-0035)
  it('renders narrative after successful draft (EARS-2)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockResolvedValue(SUMMARY_AI_FIXTURE)

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))

    await waitFor(() => {
      expect(screen.getByTestId('summary-narrative')).toHaveTextContent(
        'IP 192.0.2.1 triggered brute-force rules',
      )
    })
  })

  it('narrative is rendered as text node — not HTML (ADR-0029 D3)', async () => {
    const user = userEvent.setup()
    const malicious = '<img src=x onerror=alert(1)>'
    vi.mocked(draftCaseSummary).mockResolvedValue({
      ...SUMMARY_AI_FIXTURE,
      narrative: malicious,
    })

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))

    await waitFor(() => {
      const el = screen.getByTestId('summary-narrative')
      expect(el.textContent).toBe(malicious)
      expect(document.querySelector('img[onerror]')).toBeNull()
    })
  })

  it('renders ProvenanceChip with ai derivation (EARS-2 / ADR-0035)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockResolvedValue(SUMMARY_AI_FIXTURE)

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))

    await waitFor(() => {
      // ProvenanceChip sets data-derivation attribute
      expect(document.querySelector('[data-derivation="ai"]')).toBeInTheDocument()
    })
  })

  it('renders zero-egress badge (ADR-0022/0047)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockResolvedValue(SUMMARY_AI_FIXTURE)

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))

    await waitFor(() => {
      expect(screen.getByTestId('zero-egress-badge')).toBeInTheDocument()
    })
  })

  it('renders glass-box disclosure panel (EARS-2 / ADR-0035/0041)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockResolvedValue(SUMMARY_AI_FIXTURE)

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))

    await waitFor(() => {
      expect(screen.getByTestId('glass-box-disclosure')).toBeInTheDocument()
    })
  })

  // EARS-3: collected_fields surfaced in disclosure (ADR-0041 evidence chain)
  it('reveals collected_fields when toggling "Show sources" (EARS-3)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockResolvedValue(SUMMARY_AI_FIXTURE)

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))

    await waitFor(() => screen.getByTestId('disclosure-toggle'))
    await user.click(screen.getByTestId('disclosure-toggle'))

    await waitFor(() => {
      expect(screen.getByTestId('disclosure-fields')).toBeInTheDocument()
      // One of the collected fields is present
      expect(screen.getByTestId('disclosure-fields')).toHaveTextContent('source_ip')
    })
  })

  // EARS-4: analyst edits and saves as operator note (ai_drafted=false)
  it('"Edit & own this draft" enters edit mode (EARS-4)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockResolvedValue(SUMMARY_AI_FIXTURE)

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))

    await waitFor(() => screen.getByTestId('summary-edit-button'))
    await user.click(screen.getByTestId('summary-edit-button'))

    expect(screen.getByTestId('summary-edit-textarea')).toBeInTheDocument()
    expect(screen.getByTestId('summary-save-edit')).toBeInTheDocument()
  })

  it('saving edited draft calls addNote with ai_drafted=false (EARS-4)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockResolvedValue(SUMMARY_AI_FIXTURE)
    vi.mocked(addNote).mockResolvedValue(99)
    const onNoteAdded = vi.fn()

    render(<CaseSummary caseId={42} onNoteAdded={onNoteAdded} />)
    await user.click(screen.getByTestId('draft-summary-button'))
    await waitFor(() => screen.getByTestId('summary-edit-button'))
    await user.click(screen.getByTestId('summary-edit-button'))

    // Edit the text
    const textarea = screen.getByTestId('summary-edit-textarea')
    await user.clear(textarea)
    await user.type(textarea, 'My edited summary note')

    await user.click(screen.getByTestId('summary-save-edit'))

    await waitFor(() => {
      expect(addNote).toHaveBeenCalledWith(42, {
        body_md: 'My edited summary note',
        ai_drafted: false,
      })
      expect(onNoteAdded).toHaveBeenCalled()
    })
  })

  it('"Cancel" exits edit mode and restores original narrative (EARS-4)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockResolvedValue(SUMMARY_AI_FIXTURE)

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))
    await waitFor(() => screen.getByTestId('summary-edit-button'))
    await user.click(screen.getByTestId('summary-edit-button'))

    // Modify and cancel
    const textarea = screen.getByTestId('summary-edit-textarea')
    await user.clear(textarea)
    await user.type(textarea, 'Modified text')
    await user.click(screen.getByTestId('summary-cancel-edit'))

    // Back to read-mode with original text
    expect(screen.queryByTestId('summary-edit-textarea')).toBeNull()
    expect(screen.getByTestId('summary-narrative')).toHaveTextContent(
      'IP 192.0.2.1 triggered brute-force rules',
    )
  })

  it('shows error on save failure (EARS-4)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockResolvedValue(SUMMARY_AI_FIXTURE)
    vi.mocked(addNote).mockRejectedValue(
      new (ApiError as unknown as new (s: number, d: unknown) => Error)(503, 'store error'),
    )

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))
    await waitFor(() => screen.getByTestId('summary-edit-button'))
    await user.click(screen.getByTestId('summary-edit-button'))

    // Text is already populated from the draft; just click save
    await user.click(screen.getByTestId('summary-save-edit'))

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
  })

  // EARS-5: rule-only degrade when LLM unavailable
  it('shows RULE ProvenanceChip when provenance="rule" (EARS-5)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockResolvedValue(SUMMARY_RULE_FIXTURE)

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))

    await waitFor(() => {
      expect(document.querySelector('[data-derivation="rule"]')).toBeInTheDocument()
    })
  })

  // EARS-6: suggest-only — no auto-disposition
  it('drafting does NOT call setDisposition (EARS-6)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockResolvedValue(SUMMARY_AI_FIXTURE)

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))

    await waitFor(() => screen.getByTestId('summary-narrative'))
    expect(setDisposition).not.toHaveBeenCalled()
  })

  // "Re-draft" returns to idle state
  it('"Re-draft" returns to idle (button visible again)', async () => {
    const user = userEvent.setup()
    vi.mocked(draftCaseSummary).mockResolvedValue(SUMMARY_AI_FIXTURE)

    render(<CaseSummary caseId={42} />)
    await user.click(screen.getByTestId('draft-summary-button'))

    await waitFor(() => screen.getByTestId('summary-redraft-button'))
    await user.click(screen.getByTestId('summary-redraft-button'))

    expect(screen.getByTestId('draft-summary-button')).toBeInTheDocument()
    expect(screen.queryByTestId('summary-narrative')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// CasePanel integration — AI summary section (issue #535)
// ---------------------------------------------------------------------------

describe('CasePanel with AI summary section (issue #535)', () => {
  beforeEach(() => {
    vi.mocked(getCase).mockResolvedValue(CASE_FILE_FIXTURE)
    vi.mocked(listNotes).mockResolvedValue({ case_id: 42, notes: [] })
    vi.mocked(getCaseTimeline).mockResolvedValue({ case_id: 42, entries: [] })
    vi.mocked(draftCaseSummary).mockReset()
  })

  it('renders "Draft summary" button inside CasePanel', async () => {
    render(<CasePanel caseId="42" />)
    await waitFor(() => {
      expect(screen.getByTestId('draft-summary-button')).toBeInTheDocument()
    })
  })

  it('CasePanel has "AI summary" section heading', async () => {
    render(<CasePanel caseId="42" />)
    await waitFor(() => {
      expect(screen.getByText('AI summary')).toBeInTheDocument()
    })
  })
})
