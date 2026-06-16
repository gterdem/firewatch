/**
 * Tests for MM #452 + #450 — AiSummaryPanel:
 *
 *   #452 Drop "Reveal scores" gate + add plain framing line:
 *     EARS-452-1: scores shown by default — no "Reveal scores" gate or button present.
 *     EARS-452-2: framing line renders with plain-English text.
 *     EARS-452-3: coverage sentence (ai-summary-coverage) visible without any user interaction.
 *
 *   #450 Priority-actor IPs are clickable (ClickableIp, ADR-0037):
 *     EARS-450-1: priority IPs render via ClickableIp (data-testid="clickable-ip", tag=BUTTON).
 *     EARS-450-2: clicking a priority IP opens the entity slide-over (ADR-0037).
 *     EARS-450-3: IP is rendered as a text node (ADR-0029 D3 — ClickableIp contract).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import AIRoute from '../routes/AIRoute'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import {
  THREATS_FIXTURE,
  HEALTH_AI_ONLINE,
} from './readFixtures'

// ---------------------------------------------------------------------------
// Shared mocks
// ---------------------------------------------------------------------------

const { mockFetchThreats, mockFetchHealth, mockFetchAnalyses, mockFetchFeedbackSummary } =
  vi.hoisted(() => ({
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

/** Render AIRoute wrapped in router + EntityPanelProvider (required for ClickableIp). */
function renderRoute() {
  return render(
    <MemoryRouter initialEntries={['/ai']}>
      <EntityPanelProvider>
        <AIRoute />
      </EntityPanelProvider>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
  mockFetchAnalyses.mockResolvedValue({ items: [], next_cursor: null, has_more: false })
  mockFetchFeedbackSummary.mockResolvedValue(null)
})

// ---------------------------------------------------------------------------
// #452 — Drop "Reveal scores" gate
// ---------------------------------------------------------------------------

describe('MM #452 — no "Reveal scores" gate', () => {
  it('EARS-452-1: no "Reveal scores" button present — gate removed entirely', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-panel')).toBeInTheDocument()
    })

    // No gate button — removed per MM #452
    expect(screen.queryByTestId('ai-generate-btn')).not.toBeInTheDocument()
    expect(screen.queryByText('Reveal scores')).not.toBeInTheDocument()
    expect(screen.queryByText('Hide scores')).not.toBeInTheDocument()
  })

  it('EARS-452-2: scores (ai-summary-body with actor count) shown by default — no click needed', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    // Actor count visible immediately on load — no button interaction required
    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-body')).toHaveTextContent('actors')
    })
  })

  it('EARS-452-3: coverage sentence (ai-summary-coverage) visible by default — no click needed', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    // Coverage sentence must be present without any user interaction
    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-coverage')).toBeInTheDocument()
    })

    expect(screen.getByTestId('ai-summary-coverage').textContent).toContain('AI engine active')
  })
})

// ---------------------------------------------------------------------------
// #452 — Plain-language framing line
// ---------------------------------------------------------------------------

describe('MM #452 — plain-language framing line', () => {
  it('EARS-452-4: framing line renders with ai-summary-framing testid', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-framing')).toBeInTheDocument()
    })
  })

  it('EARS-452-5: framing line uses plain English — mentions rules and local AI model', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-framing')).toBeInTheDocument()
    })

    const framing = screen.getByTestId('ai-summary-framing')
    // Must mention the scoring pipeline in plain English
    expect(framing.textContent).toContain('FireWatch scores every attacker')
    expect(framing.textContent).toContain('fast rules')
    expect(framing.textContent).toContain('local AI model')
  })

  it('EARS-452-6: framing line renders even when threats list is empty', async () => {
    mockFetchThreats.mockResolvedValue([])

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-panel')).toBeInTheDocument()
    })

    // Framing is always shown (it describes the page, not the data)
    expect(screen.getByTestId('ai-summary-framing')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// #450 — Priority-actor IPs are clickable (ClickableIp, ADR-0037)
// ---------------------------------------------------------------------------

describe('MM #450 — priority-actor IPs rendered via ClickableIp', () => {
  it('EARS-450-1: priority IPs in ai-summary-advice render as ClickableIp buttons', async () => {
    // THREATS_FIXTURE has a HIGH actor with score 78 — qualifies as a review candidate
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-advice')).toBeInTheDocument()
    })

    // ClickableIp renders as a button with data-testid="clickable-ip"
    const clickableIps = screen.getAllByTestId('clickable-ip')
    // At least one IP inside the advice block
    expect(clickableIps.length).toBeGreaterThan(0)

    // Each must be a BUTTON element (ADR-0037 keyboard accessibility)
    for (const btn of clickableIps) {
      expect(btn.tagName).toBe('BUTTON')
    }
  })

  it('EARS-450-2: IP is rendered as a text node — not set via innerHTML (ADR-0029 D3)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-advice')).toBeInTheDocument()
    })

    const clickableIps = screen.getAllByTestId('clickable-ip')
    // ClickableIp puts the IP as its text content (text node), never dangerouslySetInnerHTML
    for (const btn of clickableIps) {
      // textContent is the IP string itself
      expect(btn.textContent).toMatch(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)
      // No innerHTML injection — the element should not contain child elements
      expect(btn.children.length).toBe(0)
    }
  })

  it('EARS-450-3: clicking a priority IP opens the entity slide-over (ADR-0037)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-advice')).toBeInTheDocument()
    })

    // Find ClickableIp buttons in the advice block specifically
    const adviceBlock = screen.getByTestId('ai-summary-advice')
    const ipBtn = adviceBlock.querySelector('[data-testid="clickable-ip"]') as HTMLElement
    expect(ipBtn).not.toBeNull()

    fireEvent.click(ipBtn)

    // Entity slide-over should open (ADR-0037)
    await waitFor(() => {
      expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
    })
  })

  it('EARS-450-4: priority IPs are inside clickable-ip buttons, not dead spans (regression guard)', async () => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-summary-advice')).toBeInTheDocument()
    })

    // All IPs in advice must be clickable buttons (ClickableIp), not plain non-interactive spans.
    // A "dead span" is a <span> that has no button descendant and whose own text is an IP.
    const adviceBlock = screen.getByTestId('ai-summary-advice')
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/

    // Spans whose direct textContent is an IP AND that are not buttons themselves
    // AND whose children include no button element are dead spans.
    const spans = Array.from(adviceBlock.querySelectorAll('span'))
    const deadIpSpans = spans.filter((s) => {
      const text = s.textContent?.trim() ?? ''
      if (!ipPattern.test(text)) return false
      // If it contains a button descendant, it's a valid wrapper (not dead)
      if (s.querySelector('button')) return false
      return true
    })
    // No dead IP spans — every IP must be reachable via a ClickableIp button
    expect(deadIpSpans.length).toBe(0)
  })
})
