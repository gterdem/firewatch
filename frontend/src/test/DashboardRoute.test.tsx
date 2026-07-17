/**
 * Tests for src/routes/DashboardRoute.tsx
 * MF-2 update (issue #159) + original #113 P2 restyle + fix #180 AI health unification.
 *
 * EARS criteria covered:
 * Original (#113):
 *   - Event-driven: on mount, fetches /stats, /logs/timeline, /logs/categories, /threats.
 *   - State-driven: populated data → KPI strip, 2-col grid, AI sidebar rendered.
 *   - State-driven: empty stats (total_logs=0) → KPI strip shows 0 + EmptyState.
 *   - State-driven (#97): ai_status active → AiStatusChip shows "AI active".
 *   - State-driven (#97): ai_status disabled → AiStatusChip shows "AI offline · rules-only".
 *   - State-driven (#97): ai_status unavailable → AiStatusChip shows "AI offline · rules-only".
 *   - State-driven (#97): threats fetch fails → chip hidden, dashboard still loads.
 *   - Unwanted: API unreachable → explicit error state shown, not blank crash.
 *   - Layout: dash-grid (1fr 300px), dash-main, grid-2 (attack categories + threat actors).
 *   - Layout: AI sidebar present with threat data.
 *   - Category bars use DS tokens (category-bar testid present).
 *
 * MF-2 (#159):
 *   - State-driven: CRITICAL/HIGH actors present → triage banner is active (count + chips).
 *   - State-driven: no CRITICAL/HIGH actors → triage banner shows all-clear.
 *   - Event-driven: dismiss on chip → removes actor from triage banner count.
 *   - Event-driven: Block/Investigate/Dismiss on recommendation card → calls onAction (no crash).
 *   - Ubiquitous: KPI renders as thin strip (kpi-strip testid, not kpi-cards).
 *   - Layout: recommendation cards section present with action buttons.
 *   - Layout: ThreatActorSummary present with threat data (replaces AiPanel, #207).
 *
 * Fix #180 (AI health unification):
 *   - State-driven: ollama_connected=true + stale threat ai_status=disabled
 *     → KPI AiEnginePill shows engine state (health overrides threat-derived status).
 *   - State-driven: health fetch fails → pill falls back to threat-derived ai_status.
 *   - State-driven: ThreatActorSummary provenance derives from health.ollama_connected.
 *
 * Issue #207 (honest AI block):
 *   - ThreatActorSummary replaces AiPanel + AiSidebar AI summary card.
 *   - Rule-only content never titled "AI" (ADR-0035).
 *   - Degraded wording shown when AI offline (RULES_ONLY_DEGRADED_WORDING).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import DashboardRoute from '../routes/DashboardRoute'
import {
  STATS_FIXTURE,
  STATS_EMPTY_FIXTURE,
  TIMELINE_FIXTURE,
  CATEGORIES_FIXTURE,
  THREATS_FIXTURE,
  THREATS_AI_UNAVAILABLE_FIXTURE,
  HEALTH_AI_ONLINE,
  HEALTH_AI_OFFLINE,
  BANNER_SUMMARY_ACTIVE,
} from './readFixtures'
import type { ThreatScore } from '../api/types'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const {
  mockFetchStats,
  mockFetchTimeline,
  mockFetchCategories,
  mockFetchThreats,
  mockFetchHealth,
  mockFetchBannerSummary,
  mockCreateDecision,
} = vi.hoisted(() => ({
  mockFetchStats: vi.fn(),
  mockFetchTimeline: vi.fn(),
  mockFetchCategories: vi.fn(),
  mockFetchThreats: vi.fn(),
  mockFetchHealth: vi.fn(),
  mockFetchBannerSummary: vi.fn(),
  mockCreateDecision: vi.fn(),
}))

// ADR-0072 (issue #47): dismiss/block persist via POST /decisions instead of
// localStorage. Mock the client so tests never hit a real network call, and
// so persistence can be asserted directly.
vi.mock('../api/decisions', () => ({
  createDecision: mockCreateDecision,
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
    fetchStats: mockFetchStats,
    fetchTimeline: mockFetchTimeline,
    fetchCategories: mockFetchCategories,
    fetchThreats: mockFetchThreats,
    fetchHealth: mockFetchHealth,
    // RiskMovers (in AiSidebar) calls fetchScoreHistory — return empty series
    // (graceful degradation for the known #250 endpoint wiring gap).
    fetchScoreHistory: vi.fn().mockResolvedValue([]),
    // DashboardRoute fetches triage_threshold from /config/runtime (ADR-0059 D1 / #650).
    // Non-blocking; fall back to "HIGH" on failure → mock with a rejecting fn so tests
    // that don't care get the safe default and banner behaviour is unchanged.
    getRuntimeConfig: vi.fn().mockRejectedValue(new Error('not mocked')),
    // GET /banner/summary (issue #55) — non-blocking; rejecting by default keeps
    // attemptSummary null so existing #43 ObservedRecordLine tests are unchanged.
    // Dedicated #55 tests (below) override this per-case via mockFetchBannerSummary.
    fetchBannerSummary: mockFetchBannerSummary,
    ApiError,
    resolveBaseUrl: () => '',
    assertLoopbackBase: () => {},
  }
})

// Mock the logs API used by BlockedLogsPanel
vi.mock('../api/logs', () => ({
  fetchPaginatedLogs: vi.fn().mockResolvedValue({
    logs: [],
    next_cursor: null,
    has_more: false,
    total_matching: 0,
  }),
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
}))

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** threats with only CRITICAL/HIGH actors (pending triage). */
const THREATS_NEEDS_TRIAGE_FIXTURE: ThreatScore[] = [
  {
    source_ip: '192.0.2.1',
    threat_level: 'CRITICAL',
    score: 95,
    total_events: 200,
    blocked_events: 180,
    attack_types: ['SQL Injection'],
    first_seen: '2026-06-04T06:00:00Z',
    last_seen: '2026-06-04T10:00:00Z',
    source_types: ['suricata'],
    detections: [],
    ai_insights: ['Intent: exfiltration'],
    ai_confidence: 0.95,
    ai_status: 'active',
    location: null,
    score_breakdown: [],
    asn: null,
    as_name: null,
    score_delta: 38,
  },
  {
    source_ip: '192.0.2.2',
    threat_level: 'HIGH',
    score: 78,
    total_events: 120,
    blocked_events: 95,
    attack_types: ['Brute Force'],
    first_seen: '2026-06-04T06:00:00Z',
    last_seen: '2026-06-04T10:00:00Z',
    source_types: ['azure_waf'],
    detections: [],
    ai_insights: null,
    ai_confidence: null,
    ai_status: 'unavailable',
    location: null,
    score_breakdown: [],
    asn: null,
    as_name: null,
    score_delta: null,
  },
]

/** Fixture: all threats have ai_status=disabled. */
const THREATS_AI_DISABLED_FIXTURE: ThreatScore[] = [
  {
    source_ip: '192.0.2.10',
    threat_level: 'LOW',
    score: 15,
    total_events: 8,
    blocked_events: 2,
    attack_types: ['Port Scan'],
    first_seen: '2026-06-04T06:00:00Z',
    last_seen: '2026-06-04T07:00:00Z',
    source_types: ['suricata'],
    detections: [],
    ai_insights: null,
    ai_confidence: 0.0,
    ai_status: 'disabled',
    location: null,
    score_breakdown: [],
    asn: null,
    as_name: null,
    score_delta: null,
  },
]

// ---------------------------------------------------------------------------
// Helper: render with router context (required by useNavigate)
// ---------------------------------------------------------------------------

function renderDashboard() {
  return render(
    <MemoryRouter>
      <DashboardRoute />
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DashboardRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Clear dismissed actors between tests so triage banner state is clean
    localStorage.clear()
    // Default: health fetch succeeds with AI online; individual tests override as needed.
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
    // Default: GET /banner/summary fails (non-blocking) so attemptSummary stays null
    // and existing #43 ObservedRecordLine tests are unaffected; #55 tests override.
    mockFetchBannerSummary.mockRejectedValue(new Error('not mocked'))
    // ADR-0072 (issue #47): default createDecision to a resolved record so
    // dismiss/block clicks in tests never hit a real network call.
    mockCreateDecision.mockResolvedValue({
      id: 1,
      actor_ip: '192.0.2.1',
      verb: 'dismissed',
      rule_name: null,
      decided_tier: null,
      decided_score: 0,
      decided_at: '2026-07-17T00:00:00Z',
      revoked_at: null,
      author: 'local operator',
      note: null,
    })
  })

  // EARS event-driven: on mount, calls all four read endpoints
  it('calls fetchStats, fetchTimeline, fetchCategories, and fetchThreats on mount', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(mockFetchStats).toHaveBeenCalledTimes(1)
      expect(mockFetchTimeline).toHaveBeenCalledTimes(1)
      expect(mockFetchCategories).toHaveBeenCalledTimes(1)
      expect(mockFetchThreats).toHaveBeenCalledTimes(1)
    })
  })

  // Ubiquitous (MF-2): KPI renders as THIN STRIP (kpi-strip), not the old 5-up kpi-cards
  it('renders KPI as a thin strip (not the old large card grid)', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('kpi-strip')).toBeInTheDocument()
    })
    // Verify strip values
    expect(screen.getByTestId('kpi-total-events')).toHaveTextContent('4,815')
    expect(screen.getByTestId('kpi-unique-ips')).toHaveTextContent('23')
    expect(screen.getByTestId('kpi-block-rate')).toHaveTextContent('62.3%')
    expect(screen.getByTestId('kpi-ai-status')).toBeInTheDocument()
  })

  // State-driven (MF-2): CRITICAL/HIGH actors → triage banner active
  it('shows active triage banner when CRITICAL/HIGH actors are present', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_NEEDS_TRIAGE_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-active')).toBeInTheDocument()
    })
    expect(screen.getByTestId('triage-banner-headline')).toHaveTextContent('2 actors')
    // Actor chips for both IPs
    const chips = screen.getAllByTestId('triage-actor-chip')
    expect(chips).toHaveLength(2)
  })

  // State-driven (MF-2): no CRITICAL/HIGH → triage banner calm/all-clear
  it('shows calm triage banner when no CRITICAL/HIGH actors are present', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    // THREATS_AI_DISABLED_FIXTURE has only LOW actors
    mockFetchThreats.mockResolvedValue(THREATS_AI_DISABLED_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-calm')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('triage-banner-active')).toBeNull()
  })

  // State-driven (MF-2): empty threats → calm banner
  it('shows calm triage banner when threats array is empty', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue([])

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-calm')).toBeInTheDocument()
    })
  })

  // Event-driven (ADR-0072, issue #47): dismiss chip persists server-side.
  //
  // Queue suppression is now computed SERVER-SIDE and annotated on the next
  // GET /threats (ADR-0072 D3) — the pre-#47 localStorage-driven instant
  // removal is retired (D7). This test asserts the persistence call; the
  // "both surfaces agree" behaviour is covered below by the
  // server-annotated-suppression test, which is the actual contract surface.
  it('dismiss chip persists a "dismissed" decision server-side (ADR-0072 D3)', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_NEEDS_TRIAGE_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-active')).toBeInTheDocument()
    })

    const dismissButtons = screen.getAllByTestId('triage-chip-dismiss')
    await userEvent.click(dismissButtons[0])

    await waitFor(() => {
      expect(mockCreateDecision).toHaveBeenCalledWith({
        actor_ip: THREATS_NEEDS_TRIAGE_FIXTURE[0].source_ip,
        verb: 'dismissed',
      })
    })
    // No local-state removal within this render — the dashboard does not crash
    // and the banner is still present (suppression arrives on the next fetch).
    expect(screen.getByTestId('triage-banner-active')).toBeInTheDocument()
  })

  // Event-driven (MF-2): recommendation card Investigate/Dismiss do not crash
  // (Block button removed per issue #758 — SOAR deferred)
  it('Investigate/Dismiss on recommendation cards call onAction without crashing', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('recommendation-cards')).toBeInTheDocument()
    })

    // Click each remaining button — none should throw or crash
    const investigateBtns = screen.getAllByTestId('rec-card-investigate')
    const dismissBtns = screen.getAllByTestId('rec-card-dismiss')

    await userEvent.click(investigateBtns[0])
    await userEvent.click(dismissBtns[0])

    // Dashboard should still be in the document (no crash)
    expect(screen.getByTestId('kpi-strip')).toBeInTheDocument()
  })

  // F5-D1 EARS (issue #564, superseded by ADR-0072 issue #47): Dismiss on a
  // recommendation card persists server-side. Card-queue exclusion is now
  // driven by the server-computed `triage_decision.suppressed` annotation
  // (see the server-annotated-suppression test below) — the pre-#47
  // localStorage-driven instant removal is retired (D7).
  it('F5-D1: Dismiss on a recommendation card persists a "dismissed" decision (ADR-0072 D3)', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_NEEDS_TRIAGE_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('recommendation-cards')).toBeInTheDocument()
    })

    const cardsBefore = screen.getAllByTestId('rec-card')
    expect(cardsBefore.length).toBeGreaterThan(0)

    const dismissBtns = screen.getAllByTestId('rec-card-dismiss')
    await userEvent.click(dismissBtns[0])

    await waitFor(() => {
      expect(mockCreateDecision).toHaveBeenCalledWith({
        actor_ip: THREATS_NEEDS_TRIAGE_FIXTURE[0].source_ip,
        verb: 'dismissed',
      })
    })
  })

  // F5-D1 EARS (issue #564): Block button removed per issue #758; seam tested via Dismiss
  // The 'block' verb seam stays dormant in triageActions.ts for future SOAR.
  it('F5-D1: Block button is NOT rendered on recommendation cards (issue #758)', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_NEEDS_TRIAGE_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('recommendation-cards')).toBeInTheDocument()
    })

    // Block button must NOT be present
    expect(screen.queryByTestId('rec-card-block')).toBeNull()
    // Investigate and Done buttons are still present
    expect(screen.getAllByTestId('rec-card-investigate').length).toBeGreaterThan(0)
    expect(screen.getAllByTestId('rec-card-dismiss').length).toBeGreaterThan(0)
  })

  // F5-D1 EARS (issue #564) superseded by ADR-0072 D3 "one evaluator, every
  // surface": banner count and card-queue count SHALL stay consistent — now
  // driven by the server-computed `triage_decision.suppressed` annotation on
  // GET /threats rather than a client-side localStorage flag.
  it('ADR-0072 D3: an actor the server marks suppressed is excluded from BOTH the banner and the rec-card queue', async () => {
    const suppressedActor: ThreatScore = {
      ...THREATS_NEEDS_TRIAGE_FIXTURE[0],
      triage_decision: {
        verb: 'dismissed',
        decided_at: '2026-07-16T00:00:00Z',
        decided_tier: null,
        decided_score: 95,
        suppressed: true,
        reentry: null,
      },
    }
    const stillQueuedActor = THREATS_NEEDS_TRIAGE_FIXTURE[1]

    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue([suppressedActor, stillQueuedActor])

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-active')).toBeInTheDocument()
      expect(screen.getByTestId('recommendation-cards')).toBeInTheDocument()
    })

    // Banner: only the non-suppressed actor's chip is present (scoped to the
    // banner's chip container — the IP may legitimately still appear
    // elsewhere on the page, e.g. the Threat Actors table, since lifetime
    // facts are never hidden, ADR-0067 D2).
    expect(screen.getByTestId('triage-banner-headline')).toHaveTextContent('1 actor')
    const bannerChips = within(screen.getByTestId('triage-banner-chips'))
    expect(bannerChips.queryByText(suppressedActor.source_ip)).toBeNull()
    expect(bannerChips.getByText(stillQueuedActor.source_ip)).toBeInTheDocument()

    // Rec-cards: the suppressed actor's IP does not appear in the queue either
    // — same evaluator, same exclusion, both surfaces (ADR-0072 D3).
    const cardIps = within(screen.getByTestId('recommendation-cards'))
      .getAllByTestId('clickable-ip')
      .map((el) => el.textContent)
    expect(cardIps).not.toContain(suppressedActor.source_ip)
    expect(cardIps).toContain(stillQueuedActor.source_ip)
  })

  // Layout (MF-2): recommendation cards panel present
  it('renders recommendation cards section', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('recommendation-cards')).toBeInTheDocument()
    })
    // Each card has Investigate/Done buttons; Block is removed (issue #758)
    const cards = screen.getAllByTestId('rec-card')
    expect(cards.length).toBeGreaterThan(0)
    expect(screen.queryByTestId('rec-card-block')).toBeNull()
    expect(screen.getAllByTestId('rec-card-investigate').length).toBeGreaterThan(0)
    expect(screen.getAllByTestId('rec-card-dismiss').length).toBeGreaterThan(0)
  })

  // Layout (MF-2): AI panel present when threats have data
  it('renders ThreatActorSummary (merged block) when threats data is available', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('threat-actor-summary')).toBeInTheDocument()
    })
    // Title is "Threat summary" — not "AI…" (ADR-0035 naming rule)
    expect(screen.getByTestId('tas-title')).toHaveTextContent('Threat summary')
    // Provenance chip always present
    expect(screen.getByTestId('tas-provenance-chip')).toBeInTheDocument()
    // Score badge present (banded, ADR-0036)
    expect(screen.getByTestId('tas-score-badge')).toBeInTheDocument()
    // Old AiPanel is gone — no duplicate block
    expect(screen.queryByTestId('ai-panel')).not.toBeInTheDocument()
  })

  // EARS state-driven: populated data → dash-grid layout
  it('renders the 1fr/300px dash-grid with dash-main and AI sidebar', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('dash-grid')).toBeInTheDocument())
    expect(screen.getByTestId('dash-main')).toBeInTheDocument()
    expect(screen.getByTestId('ai-sidebar-col')).toBeInTheDocument()
  })

  // Layout: .grid-2 contains attack categories + threat actors panels
  it('renders the grid-2 layout with category breakdown and threat actors', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('grid-2')).toBeInTheDocument())
    expect(screen.getByTestId('category-breakdown')).toBeInTheDocument()
    expect(screen.getByTestId('threat-actors')).toBeInTheDocument()
  })

  // Category bars use DS token colors (not raw hex)
  it('category bars use the DS category-bar testid', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('category-breakdown')).toBeInTheDocument())
    const bars = screen.getAllByTestId('category-bar')
    expect(bars.length).toBeGreaterThan(0)
    for (const bar of bars) {
      expect(bar.style.background).toContain('var(--fw-')
    }
  })

  // CR6 (#617): sidebar IA — Risk Movers (orient) ABOVE Recommended actions (respond)
  it('renders AI sidebar with Risk Movers pane ABOVE Recommended actions (CR6 orient→respond)', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('ai-sidebar')).toBeInTheDocument())
    // The old "ai-recommendations" sb-card testid from issue #208 is NOT present
    expect(screen.queryByTestId('ai-recommendations')).toBeNull()
    // "ip-threat-scores" was replaced by Risk Movers (#251)
    expect(screen.queryByTestId('ip-threat-scores')).toBeNull()
    // Risk Movers pane (or empty state when no movers above threshold)
    const riskMoversPresent = screen.queryByTestId('risk-movers') !== null
    const riskMoversEmptyPresent = screen.queryByTestId('risk-movers-empty') !== null
    expect(riskMoversPresent || riskMoversEmptyPresent).toBe(true)
    // CR6 (#617): compact recommendations queue is now IN the sidebar
    const sidebar = screen.getByTestId('ai-sidebar')
    expect(sidebar.contains(screen.getByTestId('recommendation-cards'))).toBe(true)
    // Panel order: Risk Movers card title must appear BEFORE recommendations card title in DOM
    const sbCardTitles = screen.getAllByTestId('sb-card-title')
    const riskMoversIdx = sbCardTitles.findIndex((t) => t.textContent?.includes('Risk Movers'))
    const recActionsIdx = sbCardTitles.findIndex((t) => t.textContent?.includes('Recommended actions'))
    expect(riskMoversIdx).toBeLessThan(recActionsIdx)
  })

  // Threat actors table renders rows
  it('renders threat actor rows from threats data', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('threat-actors')).toBeInTheDocument())
    const rows = screen.getAllByTestId('threat-actor-row')
    expect(rows).toHaveLength(THREATS_FIXTURE.length)
  })

  // EARS state-driven: populated timeline → timeline rows rendered
  it('renders timeline rows for each bucket', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('timeline-chart')).toBeInTheDocument()
    })
    const rows = screen.getAllByTestId('timeline-row')
    expect(rows).toHaveLength(TIMELINE_FIXTURE.length)
  })

  // EARS state-driven: populated categories → category rows rendered in the Dispositions pane
  // NOTE: category-row testid appears in BOTH the Attacks pane and the Dispositions pane
  // (issue #206 split). Query within the specific Dispositions pane to avoid ambiguity.
  it('renders category breakdown rows in the Dispositions pane', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('category-breakdown')).toBeInTheDocument()
    })
    // Query within the Dispositions pane (category-breakdown) only
    const dispositionsPane = screen.getByTestId('category-breakdown')
    const rows = dispositionsPane.querySelectorAll('[data-testid="category-row"]')
    expect(rows).toHaveLength(CATEGORIES_FIXTURE.length)
    // Use textContent within the pane to avoid ambiguity — SQL Injection also
    // appears in the BlockedLogsPanel category tabs (#253 useBlockedCategories).
    expect(dispositionsPane.textContent).toContain('SQL Injection')
    expect(dispositionsPane.textContent).toContain('Port Scan')
  })

  // EARS state-driven: empty stats → KPI strip with zeroes + EmptyState
  it('renders EmptyState when total_logs is 0', async () => {
    mockFetchStats.mockResolvedValue(STATS_EMPTY_FIXTURE)
    mockFetchTimeline.mockResolvedValue([])
    mockFetchCategories.mockResolvedValue([])
    mockFetchThreats.mockResolvedValue([])

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('kpi-total-events')).toHaveTextContent('0')
    })
    expect(screen.getByTestId('kpi-unique-ips')).toHaveTextContent('0')
    expect(screen.getByTestId('dashboard-empty-state')).toBeInTheDocument()
  })

  // EARS unwanted: API unreachable → explicit error state
  it('shows error state when fetchStats rejects', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchStats.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))
    mockFetchTimeline.mockResolvedValue([])
    mockFetchCategories.mockResolvedValue([])
    mockFetchThreats.mockResolvedValue([])

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('dashboard-error')).toBeInTheDocument()
    })
    expect(screen.getByRole('alert')).toHaveTextContent('503')
  })

  // EARS unwanted: network error → explicit error state
  it('shows error state on network failure (no blank crash)', async () => {
    mockFetchStats.mockRejectedValue(new Error('Network error'))
    mockFetchTimeline.mockResolvedValue([])
    mockFetchCategories.mockResolvedValue([])
    mockFetchThreats.mockResolvedValue([])

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
  })

  // Loading state shown before data resolves
  it('shows loading indicator while data is in flight', () => {
    mockFetchStats.mockReturnValue(new Promise(() => {}))
    mockFetchTimeline.mockReturnValue(new Promise(() => {}))
    mockFetchCategories.mockReturnValue(new Promise(() => {}))
    mockFetchThreats.mockReturnValue(new Promise(() => {}))

    renderDashboard()
    expect(screen.getByRole('status')).toHaveTextContent('Loading')
  })

  // -------------------------------------------------------------------------
  // EARS state-driven (#97 / fix #180) — AI status chip states
  //
  // Fix #180: chip now derives from GET /health (authoritative).
  // Threat-derived ai_status is a fallback only when health is null.
  // -------------------------------------------------------------------------

  it('shows AiEnginePill with model + active label when health.ollama_connected=true', async () => {
    // health=online → pill shows "<model> · active" (issue #207 global engine pill)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE) // ollama_model: 'llama3.2'
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('ai-engine-pill')).toBeInTheDocument()
    })
    // Pill shows model name + active
    expect(screen.getByTestId('ai-engine-pill')).toHaveTextContent('active')
    expect(screen.getByTestId('ai-engine-pill')).toHaveTextContent('llama3.2')
  })

  it('shows AiEnginePill unreachable label when health.ai=unreachable (issue #93 tri-state)', async () => {
    // health.ai=unreachable → pill shows "AI unreachable" (amber, attention) —
    // NOT the collapsed "AI offline" (issue #93 fixes the honesty bug for this pill).
    mockFetchHealth.mockResolvedValue(HEALTH_AI_OFFLINE)
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('ai-engine-pill')).toBeInTheDocument()
    })
    expect(screen.getByTestId('ai-engine-pill')).toHaveTextContent('AI unreachable')
  })

  it('AiEnginePill shows active when health online despite threat ai_status=disabled (fix #180 core case)', async () => {
    // The exact bug from #180: pre-connection events have ai_status=disabled,
    // but Ollama is now connected. Health overrides → pill must show active.
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE) // ollama_connected: true
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_AI_DISABLED_FIXTURE) // ai_status: 'disabled'

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('ai-engine-pill')).toBeInTheDocument()
    })
    // health wins — must show active, NOT offline
    expect(screen.getByTestId('ai-engine-pill')).toHaveTextContent('active')
  })

  it('AiEnginePill falls back to threat-derived ai_status when health fetch fails (fix #180 fallback)', async () => {
    // health fetch fails → null → pill falls back to deriveAiStatus(threats).
    // THREATS_AI_UNAVAILABLE_FIXTURE → deriveAiStatus = 'unavailable' → the
    // health=null fallback is conservative (issue #93): any non-'active'
    // threat-derived status degrades to the neutral 'disabled' bucket ("AI off")
    // rather than asserting the 'unreachable' fault from threat data alone.
    mockFetchHealth.mockRejectedValue(new Error('health unavailable'))
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_AI_UNAVAILABLE_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('ai-engine-pill')).toBeInTheDocument()
    })
    expect(screen.getByTestId('ai-engine-pill')).toHaveTextContent('AI off')
  })

  it('does not show AiEnginePill when both health and threats are unavailable', async () => {
    // health fails → null; threats fail → [] → aiStatus = null → pill hidden
    mockFetchHealth.mockRejectedValue(new Error('health unavailable'))
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockRejectedValue(new Error('threats unavailable'))

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('kpi-strip')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('ai-engine-pill')).not.toBeInTheDocument()
  })

  it('does not show AiEnginePill when health fails and threats array is empty', async () => {
    // health fails → null; threats = [] → aiStatus = null → pill hidden
    mockFetchHealth.mockRejectedValue(new Error('health unavailable'))
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue([])

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('kpi-strip')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('ai-engine-pill')).not.toBeInTheDocument()
  })

  // -------------------------------------------------------------------------
  // EARS state-driven — ThreatActorSummary provenance reflects health (fix #180, #207)
  // AiPanel removed; replaced by ThreatActorSummary (merged block, issue #207).
  // -------------------------------------------------------------------------

  it('ThreatActorSummary renders with RULE chip when health.ollama_connected=true but no score_derivation (honest fallback)', async () => {
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_AI_DISABLED_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('threat-actor-summary')).toBeInTheDocument()
    })
    // Title is always "Threat summary" (ADR-0035 §3 naming rule)
    expect(screen.getByTestId('tas-title')).toHaveTextContent('Threat summary')
    // Provenance chip always present
    expect(screen.getByTestId('tas-provenance-chip')).toBeInTheDocument()
  })

  it('ThreatActorSummary shows degraded wording when health fetch fails (falls back to threat ai_status=disabled)', async () => {
    mockFetchHealth.mockRejectedValue(new Error('health unavailable'))
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_AI_DISABLED_FIXTURE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('threat-actor-summary')).toBeInTheDocument()
    })
    // Degraded wording shown when AI is offline (ADR-0035 §4)
    expect(screen.getByTestId('tas-degraded-wording')).toBeInTheDocument()
    expect(screen.getByTestId('tas-degraded-wording')).toHaveTextContent('Rules-only mode')
  })
})

// ---------------------------------------------------------------------------
// Issue #649 — ADR-0058 D2: escalation axis in deriveTriageActors
// ---------------------------------------------------------------------------

describe('DashboardRoute — #649 escalation-axis banner-worthiness (ADR-0058)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
    mockFetchBannerSummary.mockRejectedValue(new Error('not mocked'))
  })

  // EARS: WHEN actor carries Tier 1 or Tier 2 escalation → admitted to banner
  // even when threat_level is LOW (score well below HIGH threshold).
  it('shows active banner for a Tier-1 escalated actor with LOW threat level', async () => {
    const escalatedLowThreat: ThreatScore = {
      source_ip: '192.0.2.50',
      threat_level: 'LOW',
      score: 30,
      total_events: 2,
      blocked_events: 0,
      attack_types: ['SQL Injection'],
      first_seen: '2026-06-14T09:00:00Z',
      last_seen: '2026-06-14T09:01:00Z',
      source_types: ['azure_waf'],
      detections: [],
      ai_insights: null,
      ai_confidence: null,
      ai_status: 'disabled',
      location: null,
      score_breakdown: [],
      asn: null,
      as_name: null,
      score_delta: null,
      escalation: {
        tier: 1,
        disposition: 'allowed_through',
        justification: '[RULE] SQLi matched on ALLOWED request — possible success',
        block_status: 'allowed',
      },
    }

    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue([escalatedLowThreat])

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-active')).toBeInTheDocument()
    })
    // One chip for the escalated LOW actor
    const chips = screen.getAllByTestId('triage-actor-chip')
    expect(chips).toHaveLength(1)
    // Justification is inside the popover — open it first (issue #708)
    expect(screen.queryByTestId('triage-chip-justification')).toBeNull()
    await userEvent.click(screen.getByTestId('triage-chip-disposition'))
    expect(screen.getByTestId('triage-chip-justification')).toBeInTheDocument()
    expect(screen.getByTestId('triage-chip-justification')).toHaveTextContent(
      '[RULE] SQLi matched on ALLOWED request — possible success',
    )
  })

  // EARS: WHEN actor carries Tier 2 escalation → also admitted
  it('shows active banner for a Tier-2 escalated actor with MEDIUM threat level', async () => {
    const escalatedMedium: ThreatScore = {
      source_ip: '192.0.2.51',
      threat_level: 'MEDIUM',
      score: 45,
      total_events: 5,
      blocked_events: 0,
      attack_types: ['Port Scan'],
      first_seen: '2026-06-14T09:00:00Z',
      last_seen: '2026-06-14T09:05:00Z',
      source_types: ['suricata'],
      detections: [],
      ai_insights: null,
      ai_confidence: null,
      ai_status: 'disabled',
      location: null,
      score_breakdown: [],
      asn: null,
      as_name: null,
      score_delta: null,
      escalation: {
        tier: 2,
        disposition: 'block_status_unknown',
        justification: '[RULE] Suricata ALERT fired — disposition not asserted',
        block_status: 'unknown',
      },
    }

    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue([escalatedMedium])

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-active')).toBeInTheDocument()
    })
    expect(screen.getByTestId('triage-chip-disposition')).toHaveTextContent(
      'Flagged — needs review',
    )
  })

  // EARS: Tier 3+ actor without HIGH/CRITICAL → still shows calm banner (no banner-worthiness)
  it('shows calm banner when only a Tier-3 escalated MEDIUM actor is present', async () => {
    const tier3Medium: ThreatScore = {
      source_ip: '192.0.2.52',
      threat_level: 'MEDIUM',
      score: 40,
      total_events: 50,
      blocked_events: 50,
      attack_types: ['Brute Force'],
      first_seen: '2026-06-14T08:00:00Z',
      last_seen: '2026-06-14T09:00:00Z',
      source_types: ['azure_waf'],
      detections: [],
      ai_insights: null,
      ai_confidence: null,
      ai_status: 'disabled',
      location: null,
      score_breakdown: [],
      asn: null,
      as_name: null,
      score_delta: null,
      escalation: {
        tier: 3,
        disposition: 'blocked_persistent',
        justification: '[RULE] High-volume blocked — consider edge block',
        block_status: 'blocked',
      },
    }

    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue([tier3Medium])

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-calm')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('triage-banner-active')).toBeNull()
  })

  // Calm state shows the escalation legend (EARS: empty-state legend)
  it('shows escalation legend in the calm/all-clear state', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue([])

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-calm')).toBeInTheDocument()
    })
    expect(screen.getByTestId('escalation-legend')).toBeInTheDocument()
    // All 4 tiers present
    for (let t = 1; t <= 4; t++) {
      expect(screen.getByTestId(`legend-tier-${t}`)).toBeInTheDocument()
    }
  })
})

// ---------------------------------------------------------------------------
// Issue #43 — ADR-0067 D2/D5: the observed stratum reaches the dashboard
//
// EARS criteria under test (wired end to end, not just deriveObservedRecord
// in isolation):
//   - WHEN an actor's verdict is observed (tier=None) → NOT rendered as a chip.
//   - WHEN one or more observed-only actors exist → the aggregate record
//     line renders, built from real /threats fixture data.
//   - WHEN zero actors are queue-eligible → the calm state renders, WITH the
//     aggregate line still visible — the "calm is the reachable default day
//     one screen" claim this issue exists to prove.
// ---------------------------------------------------------------------------

describe('DashboardRoute — #43 observed stratum reaches the banner (ADR-0067 D2/D5)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
    // GET /banner/summary (issue #55) — reject so attemptSummary stays null and
    // this describe's #43 ObservedRecordLine assertions are unaffected.
    mockFetchBannerSummary.mockRejectedValue(new Error('not mocked'))
  })

  function makeObserved(overrides: Partial<ThreatScore> = {}): ThreatScore {
    return {
      source_ip: '192.0.2.60',
      threat_level: 'LOW',
      score: 15,
      total_events: 20,
      blocked_events: 0,
      attack_types: [],
      first_seen: '2026-07-15T08:00:00Z',
      last_seen: '2026-07-15T09:00:00Z',
      source_types: ['suricata'],
      detections: [],
      ai_insights: null,
      ai_confidence: null,
      ai_status: 'disabled',
      location: null,
      score_breakdown: [],
      asn: null,
      as_name: null,
      score_delta: null,
      escalation: {
        tier: null,
        disposition: 'observed',
        justification: '[RULE] Suricata ALERT — no qualifying signal',
        block_status: 'unknown',
      },
      ...overrides,
    }
  }

  it('a watch-only install with ONLY observed actors renders the calm state, not a flood', async () => {
    // The exact scenario D2/D3 exist to fix: a mass of unqualified ALERT/LOG
    // actors on a passive install must never flood the banner as chips.
    const flood = Array.from({ length: 50 }, (_, i) =>
      makeObserved({ source_ip: `192.0.2.${60 + (i % 190)}`, total_events: 4 }),
    )

    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(flood)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-calm')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('triage-banner-active')).toBeNull()
    expect(screen.queryByTestId('triage-actor-chip')).toBeNull()
  })

  it('the calm state still shows the aggregate record line built from real fixture data', async () => {
    const observedA = makeObserved({
      source_ip: '192.0.2.61',
      total_events: 30,
      source_types: ['suricata'],
    })
    const observedB = makeObserved({
      source_ip: '192.0.2.62',
      total_events: 12,
      source_types: ['syslog'],
    })

    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue([observedA, observedB])

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-calm')).toBeInTheDocument()
    })
    const line = screen.getByTestId('triage-observed-record')
    expect(line).toHaveTextContent('42 detections on the record from 2 sources')
  })

  it('an observed actor that ALSO crosses the band threshold appears as a chip, not in the aggregate', async () => {
    const bandQualifiedObserved = makeObserved({
      source_ip: '192.0.2.63',
      threat_level: 'CRITICAL',
      total_events: 300,
    })

    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue([bandQualifiedObserved])

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-active')).toBeInTheDocument()
    })
    // It is a chip, not folded into the aggregate line.
    expect(screen.getAllByTestId('triage-actor-chip')).toHaveLength(1)
    expect(screen.queryByTestId('triage-observed-record')).toBeNull()
  })

  it('the aggregate record line renders even while the active banner has chips (mixed population)', async () => {
    const tier1: ThreatScore = {
      source_ip: '192.0.2.64',
      threat_level: 'LOW',
      score: 40,
      total_events: 2,
      blocked_events: 0,
      attack_types: ['SQL Injection'],
      first_seen: '2026-07-15T08:00:00Z',
      last_seen: '2026-07-15T08:05:00Z',
      source_types: ['azure_waf'],
      detections: [],
      ai_insights: null,
      ai_confidence: null,
      ai_status: 'disabled',
      location: null,
      score_breakdown: [],
      asn: null,
      as_name: null,
      score_delta: null,
      escalation: {
        tier: 1,
        disposition: 'allowed_through',
        justification: '[RULE] SQLi matched on ALLOWED request',
        block_status: 'allowed',
      },
    }
    const observedOnly = makeObserved({ source_ip: '192.0.2.65', total_events: 8 })

    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue([tier1, observedOnly])

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-active')).toBeInTheDocument()
    })
    expect(screen.getAllByTestId('triage-actor-chip')).toHaveLength(1)
    expect(screen.getByTestId('triage-observed-record')).toHaveTextContent(
      '8 detections on the record from 1 source',
    )
  })

  it('no aggregate line renders when there are no observed actors at all', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue([])

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-calm')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('triage-observed-record')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Issue #55 — GET /banner/summary wiring: fetch -> attemptSummary -> TriageBanner
// ---------------------------------------------------------------------------

describe('DashboardRoute — attempts headline wiring (issue #55)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
  })

  it('fetches GET /banner/summary on mount and passes the result to TriageBanner', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue([])
    mockFetchBannerSummary.mockResolvedValue(BANNER_SUMMARY_ACTIVE)

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('attempts-headline')).toHaveTextContent(
        '412 hostile attempts from 87 actors — 0 succeeded · 2 need review',
      )
    })
    expect(mockFetchBannerSummary).toHaveBeenCalledTimes(1)
  })

  it('degrades gracefully (no crash, #43 fallback) when GET /banner/summary fails', async () => {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue([])
    mockFetchBannerSummary.mockRejectedValue(new Error('unreachable'))

    renderDashboard()

    await waitFor(() => {
      expect(screen.getByTestId('triage-banner-calm')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('attempts-headline')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Issue #262 — 2×2 bento grid layout
// ---------------------------------------------------------------------------

describe('DashboardRoute — #262 bento grid layout', () => {
  /**
   * jsdom returns getBoundingClientRect().width = 0, which collapses useColumnPriority
   * to never-columns only. Patch to 700 px to simulate the bento pane at desktop width
   * so that all 5 columns (including LAST ACTIVE) are visible.
   */
  let origGetBoundingClientRect: () => DOMRect

  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
    mockFetchBannerSummary.mockRejectedValue(new Error('not mocked'))

    origGetBoundingClientRect = Element.prototype.getBoundingClientRect
    Element.prototype.getBoundingClientRect = () => ({
      width: 700,
      height: 200,
      top: 0,
      left: 0,
      bottom: 200,
      right: 700,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    })
  })

  afterEach(() => {
    Element.prototype.getBoundingClientRect = origGetBoundingClientRect
  })

  // Helper to set up the standard fixture data for bento tests
  function mockStandardData() {
    mockFetchStats.mockResolvedValue(STATS_FIXTURE)
    mockFetchTimeline.mockResolvedValue(TIMELINE_FIXTURE)
    mockFetchCategories.mockResolvedValue(CATEGORIES_FIXTURE)
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
  }

  // EARS #262-1: middle row lays out as 2-column bento (left ~40%, right ~60%)
  // In jsdom we can check the grid-template-columns property on the grid-2 element.
  it('grid-2 uses a 2-column CSS grid template (bento layout)', async () => {
    mockStandardData()
    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('grid-2')).toBeInTheDocument())

    const grid = screen.getByTestId('grid-2')
    const columns = grid.style.gridTemplateColumns
    // Expect a 2-column definition (2fr 3fr or similar), NOT 1fr 1fr 1fr
    expect(columns).not.toBe('')
    // Should have exactly two column fractions (contains two 'fr' tokens)
    const frParts = columns.split(/\s+/).filter((p) => p.endsWith('fr'))
    expect(frParts).toHaveLength(2)
    // Sanity: not the old equal-columns layout
    expect(columns).not.toBe('1fr 1fr 1fr')
  })

  // EARS #262-2: Attack categories pane is present in grid-2
  it('Attack categories panel is present inside grid-2', async () => {
    mockStandardData()
    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('grid-2')).toBeInTheDocument())

    // AttackCategoriesPane renders attack-category-row items
    const grid = screen.getByTestId('grid-2')
    expect(grid.textContent).toContain('Attack categories')
  })

  // EARS #262-3: Dispositions pane is present in grid-2
  it('Dispositions panel is present inside grid-2', async () => {
    mockStandardData()
    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('grid-2')).toBeInTheDocument())

    const grid = screen.getByTestId('grid-2')
    expect(grid.textContent).toContain('Dispositions')
  })

  // EARS #262-4: Threat actors panel is present in grid-2
  it('Threat actors panel is present inside grid-2', async () => {
    mockStandardData()
    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('grid-2')).toBeInTheDocument())

    expect(screen.getByTestId('threat-actors')).toBeInTheDocument()
    // The panel wrapper
    expect(screen.getByTestId('threat-actors-panel')).toBeInTheDocument()
  })

  // EARS #262-5: Threat actors panel spans both rows (gridRow = '1 / span 2')
  it('Threat actors panel has grid row span of 2 (spans full bento height)', async () => {
    mockStandardData()
    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('threat-actors-panel')).toBeInTheDocument())

    const panel = screen.getByTestId('threat-actors-panel')
    // gridRow inline style should contain 'span 2'
    expect(panel.style.gridRow).toContain('span 2')
  })

  // EARS #262-6: Score column header visible in the threat actors table
  it('Score column header is visible inside the threat actors table', async () => {
    mockStandardData()
    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('threat-actors')).toBeInTheDocument())

    // col-score testid is on the Score <th>
    expect(screen.getByTestId('col-score')).toBeInTheDocument()
  })

  // EARS #262-7: Last Active column header present (restored from #241 drop)
  it('Last Active column header is present in threat actors table (restored in #262)', async () => {
    mockStandardData()
    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('threat-actors')).toBeInTheDocument())

    expect(screen.getByTestId('col-last-active')).toBeInTheDocument()
  })

  // EARS #262-8: No inner scrollbar on the threat-actors container
  it('threat-actors container has no overflow scroll/auto (no inner scrollbar)', async () => {
    mockStandardData()
    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('threat-actors')).toBeInTheDocument())

    const container = screen.getByTestId('threat-actors')
    const style = container.getAttribute('style') ?? ''
    expect(style).not.toMatch(/overflow\s*:\s*(scroll|auto)/)
  })

  // EARS #262-9: AI Recommendations and Activity timeline are OUTSIDE grid-2
  // (total row height constraint — they must not be pushed below the fold)
  it('AI Recommendations and Activity timeline are outside the grid-2 pane', async () => {
    mockStandardData()
    renderDashboard()

    await waitFor(() => expect(screen.getByTestId('grid-2')).toBeInTheDocument())

    const grid2 = screen.getByTestId('grid-2')
    // recommendation-cards and timeline-chart must not be inside grid-2
    const recCards = screen.getByTestId('recommendation-cards')
    const timeline = screen.getByTestId('timeline-chart')

    // They should exist in the document but not be descendants of grid-2
    expect(grid2.contains(recCards)).toBe(false)
    expect(grid2.contains(timeline)).toBe(false)
  })
})
