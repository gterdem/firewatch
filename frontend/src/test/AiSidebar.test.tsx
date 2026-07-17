/**
 * Tests for AiSidebar — CR6 (#617) IA reorder + compact recommendations.
 *
 * EARS acceptance criteria mapped to tests:
 *
 * CR6-1: The system SHALL position ⚡ Recommended actions BELOW 📈 Risk Movers.
 *   → DOM order: sb-card-title "Risk Movers" appears before "Recommended actions".
 *
 * CR6-2: The system SHALL shorten Recommended actions to a top-N (3) list with
 *   a "view all" affordance (no inner scrollbar).
 *   → With >3 threats: shows 3 rec-cards + "View all N" button present.
 *   → With ≤3 threats: shows all cards, no "view all" button.
 *
 * CR6-3: Each card SHALL retain provenance tag (RULE/AI) and the IP it concerns.
 *   → rec-card-provenance present + ClickableIp with actor IP visible on each card.
 *
 * CR6-4: Actions SHALL remain advisory — onAction seam only (ADR-0033).
 *   → Block/Investigate/Done buttons call onAction with correct verb.
 *   → "View all" expands the list inline; no route navigation.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import AiSidebar from '../components/dashboard/AiSidebar'
import { COMPACT_TOP_N } from '../components/dashboard/RecommendationCards'
import type { ThreatScore, HealthResponse } from '../api/types'
import type { OnAction } from '../lib/triageActions'

// ---------------------------------------------------------------------------
// EntityPanelContext mock — ClickableIp inside RecommendationCards needs useEntityPanel
// ---------------------------------------------------------------------------

vi.mock('../components/entity/EntityPanelContext', () => ({
  useEntityPanel: () => ({ openEntity: vi.fn() }),
  useEntityActions: () => ({ openEntity: vi.fn() }),
}))

// ---------------------------------------------------------------------------
// fetchScoreHistory mock — RiskMovers calls this; return empty for sidebar tests
// ---------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  fetchScoreHistory: vi.fn().mockResolvedValue([]),
}))

// ---------------------------------------------------------------------------
// Fixtures — RFC 5737 documentation IPs only
// ---------------------------------------------------------------------------

const HEALTH_ONLINE: HealthResponse = {
  status: 'ok',
  ollama_connected: true,
  ollama_model: 'llama3.2',
  db_ok: true,
  ai: 'active',
}

const HEALTH_OFFLINE: HealthResponse = {
  status: 'ok',
  ollama_connected: false,
  ollama_model: null,
  db_ok: true,
  ai: 'unreachable',
}

/** Build N distinct HIGH-threat actors for top-N overflow tests. */
function makeThreats(n: number): ThreatScore[] {
  return Array.from({ length: n }, (_, i) => ({
    source_ip: `192.0.2.${i + 1}`,
    threat_level: 'HIGH' as const,
    score: 80 - i,
    total_events: 100,
    blocked_events: 90,
    attack_types: ['SQL Injection'],
    first_seen: '2026-06-04T06:00:00Z',
    last_seen: '2026-06-04T10:00:00Z',
    source_types: ['suricata'] as ['suricata'],
    detections: [],
    ai_insights: null,
    ai_confidence: null,
    ai_status: 'unavailable' as const,
    location: null,
    score_breakdown: [],
    asn: null,
    as_name: null,
    score_delta: null,
  }))
}

const SINGLE_THREAT = makeThreats(1)
const THREE_THREATS = makeThreats(COMPACT_TOP_N)      // exactly top-N
const FIVE_THREATS = makeThreats(COMPACT_TOP_N + 2)   // exceeds top-N → view-all

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function renderSidebar(threats: ThreatScore[], onAction: OnAction = vi.fn(), health?: HealthResponse | null) {
  return render(<AiSidebar threats={threats} onAction={onAction} health={health} />)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AiSidebar — CR6 (#617) IA reorder + compact recommendations', () => {
  // CR6-1: panel ORDER — Risk Movers appears BEFORE Recommended actions in DOM
  it('CR6-1: Risk Movers sb-card title appears before Recommended actions in DOM order', () => {
    renderSidebar(SINGLE_THREAT)

    const titles = screen.getAllByTestId('sb-card-title')
    const riskIdx = titles.findIndex((t) => t.textContent?.includes('Risk Movers'))
    const recIdx = titles.findIndex((t) => t.textContent?.includes('Recommended actions'))

    expect(riskIdx).toBeGreaterThanOrEqual(0)
    expect(recIdx).toBeGreaterThanOrEqual(0)
    expect(riskIdx).toBeLessThan(recIdx)
  })

  // CR6-1: sidebar contains both panels
  it('CR6-1: sidebar hosts both Risk Movers and Recommended actions panels', () => {
    renderSidebar(SINGLE_THREAT)

    const sidebar = screen.getByTestId('ai-sidebar')
    const titles = sidebar.querySelectorAll('[data-testid="sb-card-title"]')
    const titleTexts = Array.from(titles).map((t) => t.textContent ?? '')

    expect(titleTexts.some((t) => t.includes('Risk Movers'))).toBe(true)
    expect(titleTexts.some((t) => t.includes('Recommended actions'))).toBe(true)
  })

  // CR6-2: with ≤ COMPACT_TOP_N threats → all cards shown, no "view all" button
  it('CR6-2: shows all cards when threat count ≤ top-N (no view-all needed)', () => {
    renderSidebar(THREE_THREATS)

    const cards = screen.getAllByTestId('rec-card')
    expect(cards).toHaveLength(THREE_THREATS.length)
    expect(screen.queryByTestId('rec-view-all')).toBeNull()
  })

  // CR6-2: with > COMPACT_TOP_N threats → only top-N cards + "view all" affordance
  it('CR6-2: shows only top-N cards + view-all affordance when queue exceeds top-N', () => {
    renderSidebar(FIVE_THREATS)

    const cards = screen.getAllByTestId('rec-card')
    expect(cards).toHaveLength(COMPACT_TOP_N)
    expect(screen.getByTestId('rec-view-all')).toBeInTheDocument()
  })

  // CR6-2: "view all" button shows total count
  it('CR6-2: view-all button label shows total action count', () => {
    renderSidebar(FIVE_THREATS)

    const btn = screen.getByTestId('rec-view-all')
    expect(btn.textContent).toContain(`${FIVE_THREATS.length}`)
    expect(btn.textContent).toContain('actions')
  })

  // CR6-2: "view all" click expands the list to show all actions (inline expand, no scrollbar)
  it('CR6-2: clicking view-all expands list inline (no inner scrollbar)', async () => {
    renderSidebar(FIVE_THREATS)

    expect(screen.getAllByTestId('rec-card')).toHaveLength(COMPACT_TOP_N)

    await userEvent.click(screen.getByTestId('rec-view-all'))

    // After expand: up to 5 cards shown (full mode cap), view-all button gone
    const cardsAfter = screen.getAllByTestId('rec-card')
    expect(cardsAfter.length).toBeGreaterThan(COMPACT_TOP_N)
    expect(screen.queryByTestId('rec-view-all')).toBeNull()
  })

  // CR6-3: each compact card retains provenance chip
  it('CR6-3: each card retains provenance chip (RULE or AI+RULE)', () => {
    renderSidebar(SINGLE_THREAT)

    const cards = screen.getAllByTestId('rec-card')
    for (const card of cards) {
      expect(card.querySelector('[data-testid="rec-card-provenance"]')).not.toBeNull()
    }
  })

  // CR6-3: each compact card retains the IP it concerns
  it('CR6-3: each card retains the actor IP', () => {
    renderSidebar(SINGLE_THREAT)

    // ClickableIp renders the IP as a text node — may appear in Risk Movers AND rec card
    const ipEls = screen.getAllByText(SINGLE_THREAT[0].source_ip)
    expect(ipEls.length).toBeGreaterThan(0)
    // Verify at least one IP element is inside the recommendation card
    const recCard = screen.getByTestId('rec-card')
    const ipInCard = Array.from(ipEls).some((el) => recCard.contains(el))
    expect(ipInCard).toBe(true)
  })

  // CR6-3: action label ("Consider blocking/investigating/monitoring") retained
  it('CR6-3: each card retains action label starting with "Consider"', () => {
    renderSidebar(SINGLE_THREAT)

    const label = screen.getByTestId('rec-card-action-label')
    expect(label.textContent).toMatch(/^Consider/)
  })

  // CR6-4: Block button removed per issue #758 (SOAR deferred); seam stays in triageActions.ts
  it('CR6-4: Block button is NOT rendered (issue #758 — SOAR deferred)', () => {
    renderSidebar(SINGLE_THREAT)
    expect(screen.queryByTestId('rec-card-block')).toBeNull()
  })

  // CR6-4: advisory only — Investigate calls onAction(actor, "investigate")
  it('CR6-4: Investigate button calls onAction(actor, "investigate")', async () => {
    const onAction = vi.fn() as OnAction
    renderSidebar(SINGLE_THREAT, onAction)

    await userEvent.click(screen.getByTestId('rec-card-investigate'))
    expect(onAction).toHaveBeenCalledWith(SINGLE_THREAT[0], 'investigate')
  })

  // CR6-4: advisory only — Done calls onAction(actor, "dismiss")
  it('CR6-4: Done button calls onAction(actor, "dismiss")', async () => {
    const onAction = vi.fn() as OnAction
    renderSidebar(SINGLE_THREAT, onAction)

    await userEvent.click(screen.getByTestId('rec-card-dismiss'))
    expect(onAction).toHaveBeenCalledWith(SINGLE_THREAT[0], 'dismiss')
  })

  // No inner scrollbar — container has no overflow:scroll/auto
  it('sidebar container has no overflow scroll (no-inner-scrollbar rule)', () => {
    renderSidebar(FIVE_THREATS)

    const sidebar = screen.getByTestId('ai-sidebar')
    const style = sidebar.getAttribute('style') ?? ''
    expect(style).not.toMatch(/overflow\s*:\s*(scroll|auto)/)
  })

  // Empty state: no threats → empty message (no crash)
  it('renders empty state gracefully when threats array is empty', () => {
    renderSidebar([])

    // RiskMovers degrades; recommendation queue shows empty message
    expect(screen.getByTestId('rec-cards-empty')).toBeInTheDocument()
  })

  // Offline badge shown in sidebar when AI engine is offline
  it('shows rules-only offline badge when health.ollama_connected=false', () => {
    renderSidebar(SINGLE_THREAT, vi.fn(), HEALTH_OFFLINE)

    expect(screen.getByTestId('rec-queue-offline-badge')).toBeInTheDocument()
  })

  // No offline badge when AI engine is online
  it('does NOT show offline badge when health.ollama_connected=true', () => {
    renderSidebar(SINGLE_THREAT, vi.fn(), HEALTH_ONLINE)

    expect(screen.queryByTestId('rec-queue-offline-badge')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Compact mode tests on RecommendationCards (sidebar-specific behaviour)
// ---------------------------------------------------------------------------

describe('RecommendationCards — compact=true (sidebar mode, CR6 #617)', () => {
  it('compact mode hides rationale text (compress layout, not meaning)', () => {
    renderSidebar(SINGLE_THREAT)
    // rationale should not be rendered in compact mode
    expect(screen.queryByTestId('rec-card-rationale')).toBeNull()
  })

  it('compact mode hides copy snippet (compress layout)', () => {
    renderSidebar(SINGLE_THREAT)
    expect(screen.queryByTestId('rec-card-snippet')).toBeNull()
  })

  it('compact mode hides counterfactual line (compress layout)', () => {
    // Threat with 100 total / 90 blocked → would normally show counterfactual
    renderSidebar(SINGLE_THREAT)
    expect(screen.queryByTestId('rec-card-counterfactual')).toBeNull()
  })

  it('compact mode hides copy button (compress layout)', () => {
    renderSidebar(SINGLE_THREAT)
    expect(screen.queryByTestId('rec-card-copy')).toBeNull()
  })
})
