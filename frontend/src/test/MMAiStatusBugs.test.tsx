/**
 * Tests for MM — AI-status honesty bugs:
 *   BUG-1a (#447): AiSummaryPanel headline falsely said "AI offline or disabled"
 *                  while AI is active (countAiAnalysed used ai_status='active' which
 *                  is not a valid /threats enum — count was always 0).
 *   BUG-1b (#448): CoverageLedger rendered raw enum values ('disabled', 'ok', etc.)
 *                  as user-facing text.
 *   BUG-2  (#449): ai-status-chip was stale because GET /health was fetched only once;
 *                  chip stayed "AI offline" after Ollama restarted until page reload.
 *
 * EARS coverage:
 *   BUG-1a:
 *     - WHILE engine active + ledger verdicts → headline says "AI has reached N" (not "offline")
 *     - WHILE engine active + no verdicts yet → headline says "AI review in progress"
 *     - WHILE engine offline                  → headline says "rules-only"
 *     - WHILE health=null (loading)           → headline is neutral, never asserts "offline"
 *   BUG-1b (semantics corrected MM):
 *     - actor-ai-status never renders raw 'active' / 'disabled' / 'unavailable' enum text
 *     - 'active'      → "AI-analyzed" (AI actually ran on this actor)
 *     - 'disabled'    → "Rules-only" (AI did NOT run — the honest common case; NEVER "AI reviewed")
 *     - 'unavailable' → "AI unavailable" (AI attempted, engine unreachable)
 *     - 'ok'/unknown  → "Rules-only" ('ok' is a ledger value, never a ThreatScore value)
 *   BUG-2:
 *     - changing mocked /health response updates chip within one poll interval
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import AIRoute from '../routes/AIRoute'
import { CoverageLedger } from '../components/ai/ledger/CoverageLedger'
import { formatAiStatus } from '../components/ai/ledger/coverage'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import {
  THREATS_FIXTURE,
  THREATS_AI_UNAVAILABLE_FIXTURE,
  HEALTH_AI_ONLINE,
  HEALTH_AI_OFFLINE,
  HEALTH_AI_DISABLED,
} from './readFixtures'
import type { AnalysisSummary } from '../api/types'

// ---------------------------------------------------------------------------
// Shared mocks
// ---------------------------------------------------------------------------

const {
  mockFetchThreats,
  mockFetchHealth,
  mockFetchAnalyses,
  mockFetchFeedbackSummary,
} = vi.hoisted(() => ({
  mockFetchThreats: vi.fn(),
  mockFetchHealth: vi.fn(),
  mockFetchAnalyses: vi.fn().mockResolvedValue({ items: [], next_cursor: null, has_more: false }),
  mockFetchFeedbackSummary: vi.fn().mockResolvedValue(null),
}))

vi.mock('../api/client', () => {
  class ApiError extends Error {
    status: number
    detail: unknown
    constructor(status: number, detail: unknown, message?: string) {
      super(message ?? `API error ${status}`)
      this.status = status
      this.detail = detail
    }
  }
  return {
    fetchThreats: mockFetchThreats,
    fetchHealth: mockFetchHealth,
    fetchAnalyses: mockFetchAnalyses,
    fetchFeedbackSummary: mockFetchFeedbackSummary,
    fetchSourceTypes: vi.fn().mockResolvedValue([]),
    fetchBaselineStatus: vi.fn().mockResolvedValue({ exists: false }),
    fetchDriftReport: vi.fn().mockResolvedValue(null),
    ApiError,
  }
})

vi.mock('../api/logs', () => ({
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
}))

/** Minimal AnalysisSummary fixture — RFC 5737 IP. */
const ANALYSIS_192_0_2_1: AnalysisSummary = {
  id: 1,
  ip: '192.0.2.1',
  kind: 'concise',
  model: 'qwen3:8b',
  endpoint_host: '127.0.0.1:11434',
  ai_status: 'ok',
  threat_level: 'HIGH',
  confidence: 0.87,
  score: 78,
  score_derivation: 'ai',
  latency_ms: 1200,
  prompt_tokens: null,
  completion_tokens: null,
  schema_version: 1,
  created_at: '2026-06-12T10:00:00Z',
}

function renderRoute(initialEntries = ['/ai']) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <AIRoute />
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// BUG-1a (#447) — AiSummaryPanel headline honesty
// EARS: headline derived from ledger, distinguishes active/offline/loading states
// ---------------------------------------------------------------------------

describe('BUG-1a (#447) — AiSummaryPanel headline never says "AI offline or disabled" while engine is active', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchFeedbackSummary.mockResolvedValue(null)
  })

  it('EARS-1a-1: with engine active and ledger verdicts, headline says correct count (not "offline")', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
    mockFetchAnalyses.mockResolvedValue({
      items: [ANALYSIS_192_0_2_1],
      next_cursor: null,
      has_more: false,
    })

    renderRoute()

    // Coverage shown by default — no button click needed (MM #452)
    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-coverage')).toBeInTheDocument()
    })

    const coverage = screen.getByTestId('ai-summary-coverage')
    // Engine active + 1 verdict → honest wording: 'AI engine active · N of M actors have an AI verdict'
    // NO implied automatic sweep (not 'AI has reached' / not 'awaiting AI review')
    expect(coverage.textContent).toContain('AI engine active')
    expect(coverage.textContent).toContain('have an AI verdict')
    expect(coverage.textContent).toContain('rules-only')
    // MUST NOT say 'offline or disabled' when engine is active
    expect(coverage.textContent).not.toContain('AI offline or disabled')
    expect(coverage.textContent).not.toContain('offline or disabled')
    // MUST NOT imply automatic sweep
    expect(coverage.textContent).not.toContain('AI has reached')
    expect(coverage.textContent).not.toContain('awaiting AI review')
  })

  it('EARS-1a-2: engine active + no ledger verdicts → honest active-but-no-verdicts (not "offline/disabled")', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
    mockFetchAnalyses.mockResolvedValue({ items: [], next_cursor: null, has_more: false })

    renderRoute()

    // Coverage shown by default — no button click needed (MM #452)
    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-coverage')).toBeInTheDocument()
    })

    const coverage = screen.getByTestId('ai-summary-coverage')
    // Engine active, zero verdicts → honest: engine active, no verdicts yet, all rules-only
    expect(coverage.textContent).toContain('AI engine active')
    expect(coverage.textContent).toContain('rules-only')
    // MUST NOT imply automatic sweep
    expect(coverage.textContent).not.toContain('AI review in progress')
    expect(coverage.textContent).not.toContain('AI offline or disabled')
    expect(coverage.textContent).not.toContain('offline or disabled')
  })

  it('EARS-1a-3: engine unreachable (fault) → headline says "AI unreachable · rules-only" (ADR-0066)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_AI_UNAVAILABLE_FIXTURE)
    // HEALTH_AI_OFFLINE now carries ai='unreachable' (the fault word) — ADR-0066 three-state.
    mockFetchHealth.mockResolvedValue(HEALTH_AI_OFFLINE)
    mockFetchAnalyses.mockResolvedValue({ items: [], next_cursor: null, has_more: false })

    renderRoute()

    // Coverage shown by default — no button click needed (MM #452)
    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-coverage')).toBeInTheDocument()
    })

    const coverage = screen.getByTestId('ai-summary-coverage')
    // Fault (unreachable) → honest: 'AI unreachable · all N actors are rules-only'
    expect(coverage.textContent).toContain('AI unreachable')
    expect(coverage.textContent).toContain('rules-only')
  })

  it('EARS-1a-3b: engine disabled (choice) → headline says "AI off · rules-only", never "unreachable" (ADR-0066)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_AI_UNAVAILABLE_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_DISABLED)
    mockFetchAnalyses.mockResolvedValue({ items: [], next_cursor: null, has_more: false })

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-coverage')).toBeInTheDocument()
    })

    const coverage = screen.getByTestId('ai-summary-coverage')
    // Deliberate off (choice) → honest neutral wording, never the fault word.
    expect(coverage.textContent).toContain('AI off')
    expect(coverage.textContent).toContain('rules-only')
    expect(coverage.textContent).not.toContain('unreachable')
  })

  it('EARS-1a-4: health=null (loading) → neutral loading message, never asserts "offline"', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    // health fetch is pending: return a never-resolving promise
    mockFetchHealth.mockReturnValue(new Promise(() => {}))
    mockFetchAnalyses.mockResolvedValue({ items: [], next_cursor: null, has_more: false })

    renderRoute()

    // Coverage shown by default — no button click needed (MM #452)
    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-coverage')).toBeInTheDocument()
    })

    const coverage = screen.getByTestId('ai-summary-coverage')
    // health is null (still loading) — must NOT say "offline" or assert any definitive state
    expect(coverage.textContent).not.toContain('AI offline or disabled')
    // Shows neutral loading message
    expect(coverage.textContent).toContain('loading')
  })

  it('EARS-1a-5: raw enum "active" never appears in the headline text', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
    mockFetchAnalyses.mockResolvedValue({
      items: [ANALYSIS_192_0_2_1],
      next_cursor: null,
      has_more: false,
    })

    renderRoute()

    // Coverage shown by default — no button click needed (MM #452)
    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-coverage')).toBeInTheDocument()
    })

    const coverage = screen.getByTestId('ai-summary-coverage')
    // The raw enum 'active' must not appear as a standalone word/label.
    // Note: 'AI engine active' is intentional prose and is fine.
    expect(coverage.textContent).not.toBe('active')
    // Coverage sentence must use human-readable prose, not raw enum value as label
    expect(coverage.textContent).not.toMatch(/^active$/)
  })
})

// ---------------------------------------------------------------------------
// BUG-1b (#448) — CoverageLedger status column plain labels (semantics corrected MM)
// EARS: never renders raw enum as text; disabled = Rules-only (AI did not run), active = AI-analyzed
// ---------------------------------------------------------------------------

describe('BUG-1b (#448) — CoverageLedger: formatAiStatus maps raw enum to plain labels', () => {
  // Unit tests for the exported formatAiStatus mapper

  it('maps "ok" → "Rules-only" (ok is a ledger value, never a ThreatScore value)', () => {
    // 'ok' is AnalysisSummary.ai_status only — ThreatScore.ai_status never carries 'ok'.
    // Falls through to the default case: Rules-only.
    expect(formatAiStatus('ok')).toBe('Rules-only')
  })

  it('maps "disabled" → "Rules-only" (disabled = AI did NOT run on this actor)', () => {
    expect(formatAiStatus('disabled')).toBe('Rules-only')
  })

  it('maps "unavailable" → "AI unavailable" (AI attempted but engine unreachable)', () => {
    expect(formatAiStatus('unavailable')).toBe('AI unavailable')
  })

  it('maps "active" → "AI-analyzed" (the real AI-ran value)', () => {
    expect(formatAiStatus('active')).toBe('AI-analyzed')
  })

  it('maps "no_input" → "AI not run — nothing to analyze" (issue #41 / ADR-0066)', () => {
    // no_input is a non-event, NOT a fault and NOT a choice — distinct honest copy.
    expect(formatAiStatus('no_input')).toBe('AI not run — nothing to analyze')
  })

  it('maps "disabled" → "Rules-only" (NEVER implies AI reviewed the actor)', () => {
    const label = formatAiStatus('disabled')
    expect(label).toBe('Rules-only')
    expect(label).not.toContain('AI reviewed')
    expect(label).not.toContain('reviewed')
  })

  it('maps unknown/error/skipped values → "Rules-only" (graceful default — AI did not run)', () => {
    expect(formatAiStatus('unknown-future-value')).toBe('Rules-only')
    expect(formatAiStatus('error')).toBe('Rules-only')
    expect(formatAiStatus('skipped')).toBe('Rules-only')
    expect(formatAiStatus('')).toBe('Rules-only')
  })

  it('EARS-1b-1: actor-ai-status cells never render raw enum and disabled is NEVER "AI reviewed"', () => {
    const threatsWithDisabled = [
      { ...THREATS_FIXTURE[0], ai_status: 'disabled' as const },
      { ...THREATS_FIXTURE[1], ai_status: 'active' as const },
    ]

    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger threats={threatsWithDisabled} analyses={null} filterParam={null} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const statuses = screen.getAllByTestId('actor-ai-status')
    for (const el of statuses) {
      // Raw enum must NEVER be the user-facing text
      expect(el.textContent).not.toBe('disabled')
      expect(el.textContent).not.toBe('ok')
      expect(el.textContent).not.toBe('unavailable')
      expect(el.textContent).not.toBe('active')
    }
    // disabled must NEVER imply AI reviewed this actor
    const disabledRow = statuses[0]
    expect(disabledRow.textContent).not.toContain('AI reviewed')
    expect(disabledRow.textContent).toBe('Rules-only')
  })

  it('EARS-1b-2: "active" renders as "AI-analyzed" (the real AI-ran value — green-toned)', () => {
    const threats = [{ ...THREATS_FIXTURE[0], ai_status: 'active' as const }]

    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger threats={threats} analyses={null} filterParam={null} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const statuses = screen.getAllByTestId('actor-ai-status')
    expect(statuses[0].textContent).toBe('AI-analyzed')
  })

  it('EARS-1b-3: "disabled" renders as "Rules-only" (honest: AI did NOT run on this actor)', () => {
    const threats = [{ ...THREATS_FIXTURE[0], ai_status: 'disabled' as const }]

    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger threats={threats} analyses={null} filterParam={null} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const statuses = screen.getAllByTestId('actor-ai-status')
    expect(statuses[0].textContent).toBe('Rules-only')
    // Must NEVER imply AI reviewed this actor — disabled means AI was not invoked
    expect(statuses[0].textContent).not.toContain('AI reviewed')
    expect(statuses[0].textContent).not.toContain('disabled')
  })

  it('EARS-1b-4: "unavailable" renders as "AI unavailable" (AI attempted, engine unreachable)', () => {
    const threats = [{ ...THREATS_FIXTURE[1], ai_status: 'unavailable' as const }]

    render(
      <MemoryRouter>
        <EntityPanelProvider>
          <CoverageLedger threats={threats} analyses={null} filterParam={null} />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    const statuses = screen.getAllByTestId('actor-ai-status')
    expect(statuses[0].textContent).toBe('AI unavailable')
    // 'AI unavailable' is the label — it contains 'unavailable' as part of a phrase, which is fine.
    // The raw bare enum must not appear alone.
    expect(statuses[0].textContent).not.toBe('unavailable')
  })
})

// ---------------------------------------------------------------------------
// Issue #41 / ADR-0066 — three-state /health.ai global chip presentation
//
// Consumer-level regression: each real `/health.ai` value renders the correct
// chip treatment end-to-end through AIRoute → AiSummaryPanel → AiStatusChip.
//   - ai='active'      → green "AI active"
//   - ai='disabled'     → neutral grey "AI off · rules-only" (never amber/attention)
//   - ai='unreachable'  → attention amber "AI unreachable · rules-only" (never grey-only)
// ---------------------------------------------------------------------------

describe('Issue #41 / ADR-0066 — three-state /health.ai global chip presentation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchAnalyses.mockResolvedValue({ items: [], next_cursor: null, has_more: false })
    mockFetchFeedbackSummary.mockResolvedValue(null)
  })

  it('ai="active" → chip renders green "AI active"', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-status-chip')).toBeInTheDocument()
    })
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip).toHaveTextContent('AI active')
    expect(chip.className).toContain('soc-ok')
    expect(chip.className).not.toContain('soc-watch')
  })

  it('ai="disabled" → chip renders neutral grey "AI off · rules-only", never amber (ADR-0066)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_AI_UNAVAILABLE_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_DISABLED)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-status-chip')).toBeInTheDocument()
    })
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip).toHaveTextContent('AI off · rules-only')
    // Neutral/muted tokens only — never the attention/watch tone or an alarming token.
    expect(chip.className).toContain('muted')
    expect(chip.className).not.toContain('soc-watch')
    expect(chip.className).not.toContain('soc-enforced')
  })

  it('ai="unreachable" → chip renders attention-amber "AI unreachable · rules-only", never plain grey (ADR-0066)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_AI_UNAVAILABLE_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_OFFLINE) // ai: 'unreachable'

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-status-chip')).toBeInTheDocument()
    })
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip).toHaveTextContent('AI unreachable · rules-only')
    // Attention-worthy amber (soc-watch), NOT critical/red, NOT the same neutral
    // "muted" bucket as the disabled state — a real fault must look different.
    expect(chip.className).toContain('soc-watch')
    expect(chip.className).not.toContain('soc-enforced')
    expect(chip.className).not.toContain('destructive')
  })

  it('disabled and unreachable render visually distinct chips (no more collapsed "offline" bucket)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_AI_UNAVAILABLE_FIXTURE)

    mockFetchHealth.mockResolvedValue(HEALTH_AI_DISABLED)
    const { unmount } = renderRoute()
    await waitFor(() => expect(screen.getByTestId('ai-status-chip')).toBeInTheDocument())
    const disabledText = screen.getByTestId('ai-status-chip').textContent
    const disabledClass = screen.getByTestId('ai-status-chip').className
    unmount()

    mockFetchHealth.mockResolvedValue(HEALTH_AI_OFFLINE)
    renderRoute()
    await waitFor(() => expect(screen.getByTestId('ai-status-chip')).toBeInTheDocument())
    const unreachableText = screen.getByTestId('ai-status-chip').textContent
    const unreachableClass = screen.getByTestId('ai-status-chip').className

    expect(disabledText).not.toBe(unreachableText)
    expect(disabledClass).not.toBe(unreachableClass)
  })
})

// ---------------------------------------------------------------------------
// BUG-2 (#449) / ADR-0064 D6 — AIRoute health freshness
//
// D6: the standalone 15 s setInterval was removed. Health now refreshes on
// dataVersion bumps (shared heartbeat). These tests verify:
//   EARS-2-1: health is fetched on mount (dataVersion=0 initial effect).
//   EARS-2-2: a /health fetch failure does NOT crash the page (ADR-0015).
//   EARS-2-3: NO setInterval is registered for health (interval removed).
// ---------------------------------------------------------------------------

describe('BUG-2 (#449) / ADR-0064 D6 — AIRoute: health follows shared signal (no own interval)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchAnalyses.mockResolvedValue({ items: [], next_cursor: null, has_more: false })
    mockFetchFeedbackSummary.mockResolvedValue(null)
  })

  it('EARS-2-1: /health is fetched on mount and chip reflects the result', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-status-chip')).toHaveTextContent('AI active')
    })
    // fetchHealth is called at least once on mount (also called by DriftPanel child)
    expect(mockFetchHealth).toHaveBeenCalled()
  })

  it('EARS-2-2: a failed /health fetch does not blank the page or throw (ADR-0015)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchHealth.mockRejectedValue(new Error('network error'))

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-status-chip')).toBeInTheDocument()
    })

    // Page still renders without crash; chip falls back to threat-derived status
    expect(screen.queryByTestId('ai-route-error')).not.toBeInTheDocument()
  })

  it('EARS-2-3: fetchHealth is NOT called 4+ extra times over 60 s (D6 — no own 15 s interval)', async () => {
    // D6 verification: with a 15 s interval in place, advancing 60 s would
    // trigger 4 additional health polls.  With D6 applied, fewer than 4
    // additional calls are expected (0 or at most 1 from async timing noise).
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)

    vi.useFakeTimers({ shouldAdvanceTime: true })

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-status-chip')).toBeInTheDocument()
    })

    const callsAtMount = mockFetchHealth.mock.calls.length
    expect(callsAtMount).toBeGreaterThan(0)

    // If a 15 s interval still ran, this would trigger 4 more calls (60 / 15 = 4).
    await act(async () => { vi.advanceTimersByTime(60_000) })

    const increase = mockFetchHealth.mock.calls.length - callsAtMount
    expect(increase).toBeLessThan(4)

    vi.useRealTimers()
  })
})
