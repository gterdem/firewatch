/**
 * Tests for src/routes/AIRoute.tsx (MK-1 honesty pass #406; MF-3 #160; P4 #115; #264).
 *
 * MK-1 (#406) EARS criteria covered:
 *   — Page subtitle "Every verdict, what the model saw, and proof nothing left this box." present.
 *   — Summary panel titled "Threat summary" (no false AI label) with RULE ProvenanceChip.
 *   — No "AI-generated" pane title without ai derivation (ADR-0035).
 *   — No "Reveal scores" gate — coverage sentence shows by default.
 *   — After page load, coverage sentence uses real ai_status counts.
 *   — Advisory copy shown by default (no imperative "immediately" under AI label).
 *   — Plain-language framing line present (MM #452).
 *   — Priority IPs rendered via ClickableIp (MM #450).
 *   — ?filter=below-threshold behavior (#264) unchanged.
 *
 * Original EARS criteria still covered:
 *   — Summary narrative renders with threat counts by default (no button click needed).
 *   — Per-IP table renders (scores/attack types).
 *   — Correlated IP shows multi-source provenance badges + "correlated" label.
 *   — AI-disabled banner + chip rendered (rule-only mode, ADR-0015).
 *   — IP click opens slide-over panel (ADR-0037).
 *   — Mono data convention: IP and score in mono font.
 *   — Error state renders on fetch failure.
 *   — Empty state renders when no threats returned.
 *
 * MF-3 (#160) EARS additions:
 *   — WHILE Local AI enabled (health.ollama_connected=true) → "AI active" chip.
 *   — WHILE Local AI disabled (health.ollama_connected=false) → "AI offline" chip.
 *   — Health fetch failure does NOT crash the page (ADR-0015 graceful degradation).
 *   — WHEN location present → shown in location column.
 *   — WHEN location null → neutral "—" placeholder, no crash.
 *   — location rendered as plain text (XSS-safe; ADR-0029 D3).
 *
 * Backward-compat testids preserved:
 *   ai-degradation-notice, ai-threats-table, ai-status-cell,
 *   ai-review-empty, ai-status-chip, ai-route-error.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import AIRoute from '../routes/AIRoute'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import {
  THREATS_FIXTURE,
  THREATS_AI_UNAVAILABLE_FIXTURE,
  HEALTH_AI_ONLINE,
  HEALTH_AI_OFFLINE,
} from './readFixtures'

const { mockFetchThreats, mockFetchHealth, mockFetchAnalyses, mockFetchFeedbackSummary } = vi.hoisted(() => ({
  mockFetchThreats: vi.fn(),
  mockFetchHealth: vi.fn(),
  // fetchAnalyses: MK-3 verdict ledger hook — default to empty (honest degrade, non-fatal)
  mockFetchAnalyses: vi.fn().mockResolvedValue({ items: [], next_cursor: null, has_more: false }),
  // fetchFeedbackSummary: MK-6 AgreementStat — default to null (503 degrade, renders nothing)
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
    // MK-3: verdict ledger (useVerdictLedger calls this; default to empty — non-fatal)
    fetchAnalyses: mockFetchAnalyses,
    // MK-6: agreement stat (AgreementStat calls this; default to null — non-fatal 503 degrade)
    fetchFeedbackSummary: mockFetchFeedbackSummary,
    // EntityPanelProvider fetches discovery cache on mount (non-fatal)
    fetchSourceTypes: vi.fn().mockResolvedValue([]),
    // MK-9: DriftPanel (useBaselineDrift calls these; default to no-baseline — non-fatal)
    fetchBaselineStatus: vi.fn().mockResolvedValue({ exists: false }),
    fetchDriftReport: vi.fn().mockResolvedValue(null),
    ApiError,
  }
})

// IpPanel fetches — mock to avoid real network calls in tests
vi.mock('../api/logs', () => ({
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
}))

/**
 * Render AIRoute wrapped in a MemoryRouter (required since #264 added useSearchParams).
 * Pass `initialEntries` to simulate a URL with query params.
 */
function renderRoute(initialEntries = ['/ai']) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <AIRoute />
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// MK-1 (#406) — Honesty triage: panel title, button, coverage, advice framing
// ---------------------------------------------------------------------------

describe('AIRoute — MK-1 honesty triage (issue #406)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
  })

  // EARS-MK1-1: page subtitle (ADR-0043 D2)
  it('renders the ADR-0043 page subtitle under the page title', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-page-subtitle')).toBeInTheDocument()
    })

    expect(screen.getByTestId('ai-page-subtitle')).toHaveTextContent(
      'Every verdict, what the model saw, and proof nothing left this box.',
    )
  })

  // EARS-MK1-2: summary panel title is "Threat summary", NOT "AI-generated ..." (ADR-0035)
  it('summary panel is titled "Threat summary" (not "AI-generated")', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-panel')).toBeInTheDocument()
    })

    expect(screen.getByText('Threat summary')).toBeInTheDocument()
    expect(screen.queryByText('AI-generated threat summary')).not.toBeInTheDocument()
  })

  // EARS-MK1-3: no pane titled "AI …" without an AI chip (ADR-0035 rule #3)
  it('summary panel does NOT use a brain or robot emoji icon (ADR-0035)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-panel')).toBeInTheDocument()
    })

    const panel = screen.getByTestId('ai-summary-panel')
    expect(panel.textContent).not.toContain('🧠')
    expect(panel.textContent).not.toContain('🤖')
  })

  // EARS-MK1-4: RULE ProvenanceChip present in summary panel header (ADR-0035)
  it('summary panel header contains a RULE ProvenanceChip', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('summary-provenance-chip')).toBeInTheDocument()
    })

    const chip = screen.getByTestId('summary-provenance-chip')
    expect(chip.getAttribute('data-derivation')).toBe('rule')
  })

  // EARS-MK1-5: no "Reveal scores" gate — no button present (MM #452)
  it('no "Reveal scores" gate — ai-generate-btn is gone (MM #452)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-panel')).toBeInTheDocument()
    })

    expect(screen.queryByTestId('ai-generate-btn')).not.toBeInTheDocument()
    expect(screen.queryByText('Reveal scores')).not.toBeInTheDocument()
    expect(screen.queryByText('Generate summary')).not.toBeInTheDocument()
  })

  // EARS-MK1-5b: framing line is present (MM #452)
  it('plain-language framing line is rendered by default (MM #452)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-framing')).toBeInTheDocument()
    })

    // Framing line must be plain English — no AI jargon
    expect(screen.getByTestId('ai-summary-framing')).toHaveTextContent(
      'FireWatch scores every attacker with fast rules',
    )
  })

  // EARS-MK1-7: coverage sentence derives from ledger — shown by default (no gate)
  // (BUG-1a fix #447 — when no ledger entries, shows honest message not false counts)
  it('coverage sentence shows honest active-but-no-verdicts when engine active but no verdicts yet', async () => {
    // THREATS_FIXTURE: 2 actors; HEALTH_AI_ONLINE; mockFetchAnalyses default = empty list
    // BUG-1a fix: no longer uses ai_status='active' (always was 0) — uses ledger-derived count
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    // Default mockFetchAnalyses = { items: [], ... } — no ledger entries

    renderRoute()

    // Coverage shown by default — no button click needed (MM #452)
    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-coverage')).toBeInTheDocument()
    })

    const coverage = screen.getByTestId('ai-summary-coverage')
    // With engine active (HEALTH_AI_ONLINE) and 0 ledger verdicts, shows honest message
    // NOT the old false "AI offline or disabled" (which fired when aiAnalysedCount was always 0)
    expect(coverage.textContent).not.toContain('AI offline or disabled')
    expect(coverage.textContent).not.toContain('one Local AI prompt')
    // Engine active + no verdicts → honest: 'AI engine active · 0 of N ... rules-only'
    // NOT 'AI review in progress' (implies automatic sweep that isn't happening)
    expect(coverage.textContent).toContain('AI engine active')
    expect(coverage.textContent).toContain('rules-only')
  })

  // EARS-MK1-7-ledger: when ledger has verdicts, coverage shows correct count — shown by default
  it('coverage sentence shows correct AI-verdict count when ledger has verdicts', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    // Provide one ledger entry for 192.0.2.1
    mockFetchAnalyses.mockResolvedValue({
      items: [{
        id: 1, ip: '192.0.2.1', kind: 'concise', model: 'qwen3:8b',
        endpoint_host: '127.0.0.1:11434', ai_status: 'ok', threat_level: 'HIGH',
        confidence: 0.87, score: 78, score_derivation: 'ai', latency_ms: 1200,
        prompt_tokens: null, completion_tokens: null, schema_version: 1,
        created_at: '2026-06-12T10:00:00Z',
      }],
      next_cursor: null,
      has_more: false,
    })

    renderRoute()

    // Coverage shown by default — no button click needed (MM #452)
    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-coverage')).toBeInTheDocument()
    })

    const coverage = screen.getByTestId('ai-summary-coverage')
    // 1 ledger entry for 192.0.2.1 → 'AI engine active · 1 of 2 actors have an AI verdict'
    // NOT 'AI has reached' (implies automatic sweep that isn't happening)
    expect(coverage.textContent).toContain('AI engine active')
    expect(coverage.textContent).toContain('have an AI verdict')
    // Never says "offline or disabled" when engine is active
    expect(coverage.textContent).not.toContain('offline or disabled')
    expect(coverage.textContent).not.toContain('AI has reached')
  })

  // EARS-MK1-7b: when no actors are AI-analysed, says rules-only
  it('coverage sentence says rules-only when AI is offline for all actors', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_AI_UNAVAILABLE_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_OFFLINE)

    renderRoute()

    // Coverage shown by default — no button click needed (MM #452)
    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-coverage')).toBeInTheDocument()
    })

    const coverage = screen.getByTestId('ai-summary-coverage')
    expect(coverage.textContent).toContain('rules-only')
    expect(coverage.textContent).not.toContain('one Local AI prompt')
  })

  // EARS-MK1-8: advisory framing — no "immediately" under an AI label (ADR-0033)
  it('block advice does NOT say "immediately" (ADR-0033 advisory framing)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    // Summary body shown by default (MM #452)
    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-body')).toBeInTheDocument()
    })

    const body = screen.getByTestId('ai-summary-body')
    expect(body.textContent).not.toContain('immediately')
  })

  // EARS-MK1-8b: advisory framing uses "Highest-priority actors to review" (ADR-0033)
  it('block advice uses advisory framing "Highest-priority actors to review"', async () => {
    // THREATS_FIXTURE has HIGH threat with score 78 — qualifies as review candidate
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    // Advice shown by default — no button click needed (MM #452)
    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-advice')).toBeInTheDocument()
    })

    expect(screen.getByTestId('ai-summary-advice')).toHaveTextContent(
      'Highest-priority actors to review',
    )
  })

  // EARS-MK1-8c: advice section has RULE ProvenanceChip (ADR-0035)
  it('advice section carries a RULE ProvenanceChip (ADR-0035)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    // Advice shown by default — no button click needed (MM #452)
    await waitFor(() => {
      expect(screen.getByTestId('advice-provenance-chip')).toBeInTheDocument()
    })

    expect(screen.getByTestId('advice-provenance-chip').getAttribute('data-derivation')).toBe('rule')
  })
})

// ---------------------------------------------------------------------------
// Core behavior (from MF-3 restyle #160; P4 #115)
// Updated for MK-3: AiThreatTable removed; coverage ledger + verdict cards added.
// ---------------------------------------------------------------------------

describe('AIRoute — MF-3 restyle (issue #160; P4 #115 base)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
    mockFetchAnalyses.mockResolvedValue({ items: [], next_cursor: null, has_more: false })
  })

  // -------------------------------------------------------------------------
  // Summary Panel (EARS: renders panel, scores shown by default — MM #452)
  // -------------------------------------------------------------------------

  it('renders the threat summary Panel — no "Reveal scores" gate (MM #452)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-panel')).toBeInTheDocument()
    })

    expect(screen.getByText('Threat summary')).toBeInTheDocument()
    // No gate button (MM #452)
    expect(screen.queryByTestId('ai-generate-btn')).not.toBeInTheDocument()
  })

  it('shows summary narrative by default — no click required (MM #452)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    // actors count shown directly on load
    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-body')).toHaveTextContent('actors')
    })
  })

  it('shows HIGH badge in summary by default when fixture has HIGH threats (MM #452)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    // HIGH badge shown directly on load
    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-high')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Coverage ledger — MK-3 replaces the old per-IP table (ADR-0043 D1).
  // Verifies the AI-specific actor view is present with correct data.
  // -------------------------------------------------------------------------

  it('renders the coverage ledger panel when threats are loaded (MK-3)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('coverage-ledger-panel')).toBeInTheDocument()
    })

    // IPs visible in coverage actor table (via ClickableIp).
    // Scope to the coverage-actor-table since IPs may also appear in the summary advice block.
    const table = screen.getByTestId('coverage-actor-table')
    expect(table.textContent).toContain('192.0.2.1')
    expect(table.textContent).toContain('192.0.2.2')
  })

  it('renders AI status in coverage actor rows as plain labels, not raw enum (BUG-1b fix)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('coverage-actor-table')).toBeInTheDocument()
    })

    const statuses = screen.getAllByTestId('actor-ai-status')

    // BUG-1b: raw enum values must never appear as user-facing text
    for (const el of statuses) {
      expect(el.textContent).not.toBe('active')
      expect(el.textContent).not.toBe('disabled')
      expect(el.textContent).not.toBe('unavailable')
      expect(el.textContent).not.toBe('ok')
    }

    // THREATS_FIXTURE[0] has ai_status='active' → mapped to 'AI-analyzed'
    // THREATS_FIXTURE[1] has ai_status='unavailable' → mapped to 'AI unavailable'
    const unavailableStatus = statuses.find((el) => el.textContent?.includes('AI unavailable'))
    expect(unavailableStatus).toBeDefined()
  })

  it('renders IP addresses via ClickableIp (mono, keyboard-accessible, ADR-0037)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('coverage-actor-table')).toBeInTheDocument()
    })

    const ipButtons = screen.getAllByTestId('clickable-ip')
    expect(ipButtons.length).toBeGreaterThan(0)
    // ClickableIp renders as a button — text node only (ADR-0029 D3)
    for (const btn of ipButtons) {
      expect(btn.tagName).toBe('BUTTON')
    }
  })

  // -------------------------------------------------------------------------
  // AI offline state (ADR-0015)
  // -------------------------------------------------------------------------

  it('shows AI-offline degradation notice when health says AI is disconnected', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_AI_UNAVAILABLE_FIXTURE)
    // Override: health says AI offline — this is the authoritative source (MF-3 #160).
    mockFetchHealth.mockResolvedValue(HEALTH_AI_OFFLINE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-degradation-notice')).toBeInTheDocument()
    })

    // Coverage ledger still renders (not a table error)
    expect(screen.getByTestId('coverage-ledger')).toBeInTheDocument()
    expect(screen.getByText('192.0.2.10')).toBeInTheDocument()
  })

  it('shows "AI offline · rules-only" chip when health says AI is disconnected', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_AI_UNAVAILABLE_FIXTURE)
    // Override: health says AI offline — chip derives from health (MF-3 #160 EARS).
    mockFetchHealth.mockResolvedValue(HEALTH_AI_OFFLINE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-status-chip')).toBeInTheDocument()
    })
    expect(screen.getByTestId('ai-status-chip')).toHaveTextContent('AI offline · rules-only')
    expect(screen.getByTestId('ai-status-chip').className).not.toContain('soc-enforced')
  })

  it('shows "AI active" chip when threats have ai_status=active', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-status-chip')).toBeInTheDocument()
    })
    expect(screen.getByTestId('ai-status-chip')).toHaveTextContent('AI active')
  })

  // -------------------------------------------------------------------------
  // IP drill-down (ADR-0037: WHEN IP clicked → entity slide-over panel opens)
  // Now via ClickableIp in CoverageLedger (same ADR-0037 behavior, new component).
  // -------------------------------------------------------------------------

  it('opens entity slide-over panel when a ClickableIp is clicked (ADR-0037)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    // EntityPanelProvider must wrap the route so openEntity is wired (ADR-0037).
    render(
      <MemoryRouter initialEntries={['/ai']}>
        <EntityPanelProvider>
          <AIRoute />
        </EntityPanelProvider>
      </MemoryRouter>,
    )

    await waitFor(() => {
      expect(screen.getByTestId('coverage-actor-table')).toBeInTheDocument()
    })

    const ipButtons = screen.getAllByTestId('clickable-ip')
    expect(ipButtons.length).toBeGreaterThan(0)
    fireEvent.click(ipButtons[0])

    // Slide-over panel (ADR-0037) should open.
    await waitFor(() => {
      expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Empty and error states
  // -------------------------------------------------------------------------

  it('shows empty state when no threats returned (coverage ledger empty, MK-3)', async () => {
    mockFetchThreats.mockResolvedValue([])

    renderRoute()

    // MK-3: empty state is in the coverage ledger pane
    await waitFor(() => {
      expect(screen.getByTestId('coverage-ledger-empty')).toBeInTheDocument()
    })
  })

  it('shows chip from health state even when threats array is empty (MF-3 #160)', async () => {
    // MF-3: chip now reflects health (Local AI panel state), not threats presence.
    // When health reports AI active, chip shows — even with no threat data yet.
    mockFetchThreats.mockResolvedValue([])
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('coverage-ledger-empty')).toBeInTheDocument()
    })

    // Chip reflects health state — shows "AI active" even with empty threats.
    await waitFor(() => {
      expect(screen.getByTestId('ai-status-chip')).toBeInTheDocument()
    })
    expect(screen.getByTestId('ai-status-chip')).toHaveTextContent('AI active')
  })

  it('shows error state when fetchThreats rejects', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchThreats.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-route-error')).toBeInTheDocument()
    })
    expect(screen.getByRole('alert')).toHaveTextContent('503')
  })

  // -------------------------------------------------------------------------
  // Mono data convention (F5 #111) — IP rendered in mono via ClickableIp
  // -------------------------------------------------------------------------

  it('renders IP addresses via ClickableIp (mono font, ADR-0029 D3 text-node only)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('coverage-actor-table')).toBeInTheDocument()
    })

    const ipButtons = screen.getAllByTestId('clickable-ip')
    expect(ipButtons.length).toBeGreaterThan(0)
    // ClickableIp uses fw-font-mono — verify the style token is present
    for (const btn of ipButtons) {
      expect(btn.getAttribute('style')).toContain('fw-font-mono')
    }
  })

  // -------------------------------------------------------------------------
  // MF-3 (#160): Local AI status — chip reflects health.ollama_connected
  // EARS: "WHILE Local AI engine enabled/disabled, the AI page status SHALL
  //        reflect that state (no separate AI-status source of truth)."
  // -------------------------------------------------------------------------

  it('shows "AI active" chip when health.ollama_connected=true (Local AI enabled)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE) // ollama_connected: true

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-status-chip')).toBeInTheDocument()
    })

    expect(screen.getByTestId('ai-status-chip')).toHaveTextContent('AI active')
  })

  it('shows "AI offline" chip when health.ollama_connected=false (Local AI disabled)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_OFFLINE) // ollama_connected: false

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-status-chip')).toBeInTheDocument()
    })

    // When health says disconnected, chip must show the offline label —
    // even if some per-row ai_status is 'active' in the threats payload.
    expect(screen.getByTestId('ai-status-chip')).toHaveTextContent('AI offline')
  })

  it('does not crash when health fetch fails (ADR-0015 graceful degradation)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    // Simulate health endpoint unreachable — route must not error out.
    mockFetchHealth.mockRejectedValue(new Error('network error'))

    renderRoute()

    // Page still renders the coverage ledger without a crash.
    await waitFor(() => {
      expect(screen.getByTestId('coverage-ledger')).toBeInTheDocument()
    })

    // Chip falls back to threat-derived status (THREATS_FIXTURE has 'active' threats).
    expect(screen.getByTestId('ai-status-chip')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// #264 — ?filter=below-threshold deep-link support
// EARS criteria:
//   - WHEN page opens with ?filter=below-threshold → table shows only score-0 actors.
//   - WHEN ?filter= is absent → all actors shown (normal view).
//   - IF ?filter= is not "below-threshold" → silently ignored (format guard).
//   - Below-threshold filter banner shown when filter is active.
// ---------------------------------------------------------------------------

describe('AIRoute — #264 ?filter=below-threshold deep-link', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
    mockFetchAnalyses.mockResolvedValue({ items: [], next_cursor: null, has_more: false })
  })

  // EARS-264-AI-1: ?filter=below-threshold → coverage ledger shows only score-0 actors
  it('shows only score-0 actors when ?filter=below-threshold is in the URL', async () => {
    // Mix: 1 scored (score > 0) + 1 below-threshold (score = 0)
    const mixedThreats = [
      { ...THREATS_FIXTURE[0], score: 75 },
      { ...THREATS_FIXTURE[1], score: 0, source_ip: '192.0.2.99' },
    ]
    mockFetchThreats.mockResolvedValue(mixedThreats)

    render(
      <MemoryRouter initialEntries={['/ai?filter=below-threshold']}>
        <AIRoute />
      </MemoryRouter>,
    )

    await waitFor(() => {
      expect(screen.getByTestId('coverage-ledger')).toBeInTheDocument()
    })

    // Scope checks to coverage-ledger — IPs may also appear in the summary advice block.
    const ledger = screen.getByTestId('coverage-ledger')
    // Only the score-0 actor should be visible in coverage ledger
    expect(ledger.textContent).toContain('192.0.2.99')
    // Scored actor must NOT appear in the filtered coverage table
    expect(ledger.textContent).not.toContain('192.0.2.1')
  })

  // EARS-264-AI-2: no filter → all actors shown (normal view)
  it('shows all actors when no ?filter= param is present', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute() // renders at /ai with no query params

    await waitFor(() => {
      expect(screen.getByTestId('coverage-actor-table')).toBeInTheDocument()
    })

    // Scope to the coverage actor table — IPs may also appear in the summary advice block
    const table = screen.getByTestId('coverage-actor-table')
    expect(table.textContent).toContain(THREATS_FIXTURE[0].source_ip)
    expect(table.textContent).toContain(THREATS_FIXTURE[1].source_ip)
  })

  // EARS-264-AI-3: invalid ?filter= value silently ignored (no crash, all actors shown)
  it('ignores invalid ?filter= values gracefully and shows all actors', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    render(
      <MemoryRouter initialEntries={['/ai?filter=<script>xss</script>']}>
        <AIRoute />
      </MemoryRouter>,
    )

    await waitFor(() => {
      expect(screen.getByTestId('coverage-actor-table')).toBeInTheDocument()
    })

    // Scope to the coverage actor table — IPs may also appear in the summary advice block
    const table = screen.getByTestId('coverage-actor-table')
    expect(table.textContent).toContain(THREATS_FIXTURE[0].source_ip)
    expect(table.textContent).toContain(THREATS_FIXTURE[1].source_ip)
    // No below-threshold banner shown
    expect(screen.queryByTestId('ai-below-threshold-banner')).not.toBeInTheDocument()
  })

  // EARS-264-AI-4: below-threshold filter banner shown when filter is active (backward-compat testid)
  it('shows the below-threshold filter banner when ?filter=below-threshold is set', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    render(
      <MemoryRouter initialEntries={['/ai?filter=below-threshold']}>
        <AIRoute />
      </MemoryRouter>,
    )

    await waitFor(() => {
      expect(screen.getByTestId('ai-below-threshold-banner')).toBeInTheDocument()
    })

    expect(screen.getByTestId('ai-below-threshold-banner')).toHaveTextContent(
      'below score threshold',
    )
  })

  // EARS-264-AI-5: no filter banner when ?filter= is absent
  it('does NOT show the below-threshold banner when no filter param is present', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('coverage-actor-table')).toBeInTheDocument()
    })

    expect(screen.queryByTestId('ai-below-threshold-banner')).not.toBeInTheDocument()
  })

  // EARS-264-AI-6: panel title reflects the filter (title updates to show filter context)
  it('panel title includes "below threshold" context when filter is active', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    render(
      <MemoryRouter initialEntries={['/ai?filter=below-threshold']}>
        <AIRoute />
      </MemoryRouter>,
    )

    await waitFor(() => {
      expect(screen.getByTestId('ai-page')).toBeInTheDocument()
    })

    expect(screen.getByText(/below threshold/i)).toBeInTheDocument()
  })
})
