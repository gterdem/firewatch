/**
 * Tests for RecommendationCards — unified "Recommended actions" queue (issue #208).
 *
 * EARS acceptance criteria mapped to tests:
 *
 * #1 Every card SHALL show a provenance chip (RULE or AI+RULE).
 *    → rec-card-provenance present on each card.
 *
 * #2 Every card SHALL show a "because …" rationale from visible data.
 *    → rec-card-rationale contains "Because: ".
 *
 * #3 WHILE AI offline: queue shows rule-derived cards + rules-only badge + NOT blank.
 *    → health={ollama_connected:false} → rec-queue-offline-badge; cards still render.
 *
 * #4 WHEN analyst dismisses a card → onAction(actor, "dismiss") called.
 *    → Done button → onAction with "dismiss".
 *
 * #5 Card text phrases actions as recommendations ("Consider …").
 *    → rec-card-action-label starts with "Consider".
 *
 * #6 WHEN analyst uses copy affordance → paste-ready snippet copied.
 *    → rec-card-copy present; rec-card-snippet contains IP.
 *
 * Issue #758 (EARS-1): THE Recommended-actions UI SHALL NOT render a Block button.
 *    → rec-card-block is NOT present.
 * Issue #758 (EARS-2): 'block' verb seam stays dormant in triageActions.ts (no test here —
 *    triageActions.ts is not modified; its own tests cover the verb handling).
 *
 * Legacy tests preserved: empty state, Investigate/Done seam verbs,
 * cap at 5, security (text node), a11y (aria-label).
 */

import { describe, it, expect, vi, type MockedFunction } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import RecommendationCards from '../components/dashboard/RecommendationCards'
import type { ThreatScore, HealthResponse } from '../api/types'
import type { OnAction } from '../lib/triageActions'
import { THREATS_FIXTURE } from './readFixtures'

// ---------------------------------------------------------------------------
// EntityPanelContext mock — ClickableIp needs useEntityPanel
// ---------------------------------------------------------------------------

vi.mock('../components/entity/EntityPanelContext', () => ({
  useEntityPanel: () => ({ openEntity: vi.fn() }),
}))

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const HEALTH_AI_ONLINE: HealthResponse = {
  status: 'ok',
  ollama_connected: true,
  ollama_model: 'llama3.2',
  db_ok: true,
}

const HEALTH_AI_OFFLINE: HealthResponse = {
  status: 'ok',
  ollama_connected: false,
  ollama_model: null,
  db_ok: true,
}

/** Single HIGH-threat actor — 90% block rate → "block" recommendation. */
const SINGLE_BLOCK_THREAT: ThreatScore = {
  source_ip: '192.0.2.1',
  threat_level: 'HIGH',
  score: 80,
  total_events: 100,
  blocked_events: 90,
  attack_types: ['SQL Injection'],
  first_seen: '2026-06-04T06:00:00Z',
  last_seen: '2026-06-04T10:00:00Z',
  source_types: ['suricata'],
  detections: [],
  ai_insights: null,
  ai_confidence: null,
  ai_status: 'unavailable',
  location: null,
  score_breakdown: [],
  asn: null,
  as_name: null,
  score_delta: null,
}

/** Threat with AI active and ai_insights present. */
const AI_THREAT: ThreatScore = {
  ...SINGLE_BLOCK_THREAT,
  source_ip: '192.0.2.10',
  ai_status: 'active',
  ai_insights: ['Intent: reconnaissance scanning', 'Risk: lateral movement attempt'],
  ai_confidence: 0.87,
}

/** Threat where all events are already blocked (unblocked_events == 0). */
const ALL_BLOCKED_THREAT: ThreatScore = {
  ...SINGLE_BLOCK_THREAT,
  source_ip: '192.0.2.20',
  total_events: 150,
  blocked_events: 150,
}

/** Threat with zero total events (no counterfactual line should appear). */
const ZERO_EVENTS_THREAT: ThreatScore = {
  ...SINGLE_BLOCK_THREAT,
  source_ip: '192.0.2.30',
  total_events: 0,
  blocked_events: 0,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RecommendationCards', () => {
  // Empty state
  it('shows empty message when threats array is empty', () => {
    render(<RecommendationCards threats={[]} onAction={vi.fn()} />)
    expect(screen.getByTestId('rec-cards-empty')).toBeInTheDocument()
    expect(screen.queryByTestId('rec-card')).toBeNull()
  })

  // Renders cards for THREATS_FIXTURE (2 actors)
  it('renders one card per threat actor (up to 5)', () => {
    render(<RecommendationCards threats={THREATS_FIXTURE} onAction={vi.fn()} />)
    expect(screen.getAllByTestId('rec-card')).toHaveLength(THREATS_FIXTURE.length)
  })

  // EARS #1: provenance chip present on each card
  it('each card has a provenance chip', () => {
    render(<RecommendationCards threats={[SINGLE_BLOCK_THREAT]} onAction={vi.fn()} />)
    expect(screen.getByTestId('rec-card-provenance')).toBeInTheDocument()
  })

  // EARS #2: "because …" rationale present
  it('each card has a "Because: …" rationale', () => {
    render(<RecommendationCards threats={[SINGLE_BLOCK_THREAT]} onAction={vi.fn()} />)
    expect(screen.getByTestId('rec-card-rationale').textContent).toMatch(/Because:/)
  })

  // EARS #5: action label phrased as recommendation
  it('action label starts with "Consider"', () => {
    render(<RecommendationCards threats={[SINGLE_BLOCK_THREAT]} onAction={vi.fn()} />)
    expect(screen.getByTestId('rec-card-action-label').textContent).toMatch(/^Consider/)
  })

  // EARS #3: offline badge shown when health.ollama_connected=false
  it('shows rules-only badge when AI engine is offline', () => {
    render(
      <RecommendationCards
        threats={[SINGLE_BLOCK_THREAT]}
        onAction={vi.fn()}
        health={HEALTH_AI_OFFLINE}
      />,
    )
    const badge = screen.getByTestId('rec-queue-offline-badge')
    expect(badge).toBeInTheDocument()
    expect(badge.textContent).toMatch(/AI engine offline/)
  })

  // EARS #3: queue never goes blank when AI offline — rule cards still render
  it('renders rule-derived cards even when AI engine is offline', () => {
    render(
      <RecommendationCards
        threats={[SINGLE_BLOCK_THREAT]}
        onAction={vi.fn()}
        health={HEALTH_AI_OFFLINE}
      />,
    )
    expect(screen.getAllByTestId('rec-card')).toHaveLength(1)
  })

  // No offline badge when AI is online
  it('does NOT show offline badge when health.ollama_connected=true', () => {
    render(
      <RecommendationCards
        threats={[SINGLE_BLOCK_THREAT]}
        onAction={vi.fn()}
        health={HEALTH_AI_ONLINE}
      />,
    )
    expect(screen.queryByTestId('rec-queue-offline-badge')).toBeNull()
  })

  // AI+RULE chip when AI online and actor has insights
  it('shows AI+RULE provenance when aiOnline and actor has ai_insights', () => {
    render(
      <RecommendationCards
        threats={[AI_THREAT]}
        onAction={vi.fn()}
        health={HEALTH_AI_ONLINE}
      />,
    )
    const chip = screen.getByTestId('rec-card-provenance')
    expect(chip).toHaveAttribute('data-derivation', 'ai+rule')
  })

  // AI rationale shown when provenance is ai+rule
  it('shows AI rationale when actor has ai_insights and AI is online', () => {
    render(
      <RecommendationCards
        threats={[AI_THREAT]}
        onAction={vi.fn()}
        health={HEALTH_AI_ONLINE}
      />,
    )
    const aiRationale = screen.getByTestId('rec-card-ai-rationale')
    expect(aiRationale.textContent).toBe('Intent: reconnaissance scanning')
  })

  // AI rationale NOT shown when AI is offline (even if actor has insights)
  it('does NOT show AI rationale when AI engine is offline', () => {
    render(
      <RecommendationCards
        threats={[AI_THREAT]}
        onAction={vi.fn()}
        health={HEALTH_AI_OFFLINE}
      />,
    )
    expect(screen.queryByTestId('rec-card-ai-rationale')).toBeNull()
  })

  // EARS #6: copy button present
  it('each card has a copy snippet button', () => {
    render(<RecommendationCards threats={[SINGLE_BLOCK_THREAT]} onAction={vi.fn()} />)
    expect(screen.getByTestId('rec-card-copy')).toBeInTheDocument()
  })

  // EARS #6: snippet contains the actor's IP
  it('copyable snippet contains the actor IP', () => {
    render(<RecommendationCards threats={[SINGLE_BLOCK_THREAT]} onAction={vi.fn()} />)
    expect(screen.getByTestId('rec-card-snippet').textContent).toContain('192.0.2.1')
  })

  // Issue #758 (EARS-1): Block button SHALL NOT be rendered
  it('does NOT render a Block button (issue #758 EARS-1)', () => {
    render(<RecommendationCards threats={[SINGLE_BLOCK_THREAT]} onAction={vi.fn()} />)
    expect(screen.queryByTestId('rec-card-block')).toBeNull()
  })

  // Action seam: Investigate → onAction(actor, 'investigate')
  it('calls onAction(actor, "investigate") when Investigate is clicked', async () => {
    const onAction: OnAction = vi.fn()
    render(<RecommendationCards threats={[SINGLE_BLOCK_THREAT]} onAction={onAction} />)
    await userEvent.click(screen.getByTestId('rec-card-investigate'))
    expect(onAction).toHaveBeenCalledWith(SINGLE_BLOCK_THREAT, 'investigate')
  })

  // EARS #4: Done → onAction(actor, 'dismiss')
  it('calls onAction(actor, "dismiss") when Done is clicked', async () => {
    const onAction: OnAction = vi.fn()
    render(<RecommendationCards threats={[SINGLE_BLOCK_THREAT]} onAction={onAction} />)
    await userEvent.click(screen.getByTestId('rec-card-dismiss'))
    expect(onAction).toHaveBeenCalledWith(SINGLE_BLOCK_THREAT, 'dismiss')
  })

  // Action seam: Investigate + Dismiss still work (Block removed per issue #758)
  it('Investigate and Done pass correct verbs to onAction', async () => {
    const onAction = vi.fn() as MockedFunction<OnAction>
    render(<RecommendationCards threats={[SINGLE_BLOCK_THREAT]} onAction={onAction} />)

    await userEvent.click(screen.getByTestId('rec-card-investigate'))
    expect(onAction.mock.calls[0][1]).toBe('investigate')

    await userEvent.click(screen.getByTestId('rec-card-dismiss'))
    expect(onAction.mock.calls[1][1]).toBe('dismiss')
  })

  // Capped at 5 cards
  it('renders at most 5 cards even when more threats are provided', () => {
    const manyThreats: ThreatScore[] = Array.from({ length: 10 }, (_, i) => ({
      ...SINGLE_BLOCK_THREAT,
      source_ip: `192.0.2.${i + 1}`,
    }))
    render(<RecommendationCards threats={manyThreats} onAction={vi.fn()} />)
    expect(screen.getAllByTestId('rec-card')).toHaveLength(5)
  })

  // Security: IP rendered as text node (no innerHTML)
  it('renders IP as a text node (no innerHTML injection)', () => {
    const xssThreat: ThreatScore = {
      ...SINGLE_BLOCK_THREAT,
      source_ip: '<script>alert("xss")</script>',
    }
    render(<RecommendationCards threats={[xssThreat]} onAction={vi.fn()} />)
    expect(screen.getByText('<script>alert("xss")</script>')).toBeInTheDocument()
    document.querySelectorAll('script').forEach((el) => {
      expect(el.textContent).not.toContain('xss')
    })
  })

  // a11y: buttons have aria-label with IP
  it('Investigate button has aria-label containing the IP', () => {
    render(<RecommendationCards threats={[SINGLE_BLOCK_THREAT]} onAction={vi.fn()} />)
    expect(screen.getByTestId('rec-card-investigate')).toHaveAttribute(
      'aria-label',
      `Investigate ${SINGLE_BLOCK_THREAT.source_ip}`,
    )
  })

  it('Done button has aria-label containing the IP', () => {
    render(<RecommendationCards threats={[SINGLE_BLOCK_THREAT]} onAction={vi.fn()} />)
    expect(screen.getByTestId('rec-card-dismiss')).toHaveAttribute(
      'aria-label',
      `Dismiss ${SINGLE_BLOCK_THREAT.source_ip}`,
    )
  })

  it('Copy button has aria-label containing the IP', () => {
    render(<RecommendationCards threats={[SINGLE_BLOCK_THREAT]} onAction={vi.fn()} />)
    expect(screen.getByTestId('rec-card-copy')).toHaveAttribute(
      'aria-label',
      expect.stringContaining(SINGLE_BLOCK_THREAT.source_ip),
    )
  })

  // #215 — Counterfactual impact line
  it('shows counterfactual line with unblocked count when actor has non-blocked events', () => {
    // SINGLE_BLOCK_THREAT: 100 total, 90 blocked → 10 unblocked
    render(<RecommendationCards threats={[SINGLE_BLOCK_THREAT]} onAction={vi.fn()} />)
    const cf = screen.getByTestId('rec-card-counterfactual')
    expect(cf).toBeInTheDocument()
    // 10 unblocked of 100 total
    expect(cf.textContent).toContain('10')
    expect(cf.textContent).toContain('100')
  })

  it('shows "already blocked" copy when all events are blocked', () => {
    // ALL_BLOCKED_THREAT: 150/150 blocked → unblocked = 0
    render(<RecommendationCards threats={[ALL_BLOCKED_THREAT]} onAction={vi.fn()} />)
    const cf = screen.getByTestId('rec-card-counterfactual')
    expect(cf.textContent).toMatch(/already blocked/)
    expect(cf.textContent).toContain('150')
  })

  it('does NOT render counterfactual line when total_events is 0', () => {
    // ZERO_EVENTS_THREAT has no stored events
    render(<RecommendationCards threats={[ZERO_EVENTS_THREAT]} onAction={vi.fn()} />)
    expect(screen.queryByTestId('rec-card-counterfactual')).toBeNull()
  })

  it('#215 EARS: counterfactual line is derived from stored events, never from LLM text', () => {
    // Verify the line is computable from total_events/blocked_events, not ai_insights
    const threat: ThreatScore = {
      ...SINGLE_BLOCK_THREAT,
      source_ip: '192.0.2.40',
      total_events: 200,
      blocked_events: 50,
      ai_status: 'active',
      ai_insights: ['Intent: recon'],
    }
    render(
      <RecommendationCards threats={[threat]} onAction={vi.fn()} health={HEALTH_AI_ONLINE} />,
    )
    const cf = screen.getByTestId('rec-card-counterfactual')
    // 200 - 50 = 150 unblocked
    expect(cf.textContent).toContain('150')
    expect(cf.textContent).toContain('200')
    // The LLM text must NOT appear in the counterfactual element
    expect(cf.textContent).not.toContain('recon')
  })
})
