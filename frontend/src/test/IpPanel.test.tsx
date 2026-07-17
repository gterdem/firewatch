/**
 * Tests for src/components/entity/ip/IpPanel.tsx
 *
 * This is the migration of IpDrilldownModal.test.tsx to the new slide-over panel
 * architecture (ADR-0037). All EARS criteria from the original modal tests are
 * preserved. The component hierarchy changed (IpPanel inside SlideOver inside
 * EntityPanelProvider) but every behavior is identical.
 *
 * Key change: data-testid="ip-drilldown-modal" → data-testid="slide-over-panel"
 * All other testids (modal-score-section, modal-analysis-text, etc.) are UNCHANGED
 * in IpPanel — they were tested by ID, not by component name.
 *
 * EARS criteria covered (#94):
 *
 * Loading state:
 *   - While fast fetch (/threats/{ip}) is pending, a spinner is shown (not static text).
 *   - While slow fetch (/threats/{ip}/detailed) is pending, a spinner is shown in the
 *     Deep Analysis section.
 *   - Once fast fetch resolves, score section renders immediately (before detail resolves).
 *
 * Rich fields (rules-only path — AI disabled):
 *   - executive_summary rendered as text.
 *   - attack_progression rendered as an ordered list.
 *   - intent rendered as text.
 *   - ioc_indicators rendered as a list.
 *   - insights.patterns, .risks, .mitigations rendered as lists.
 *   - recommended_action, attack_stage, confidence rendered as meta badges.
 *
 * AI narrative path (AI active):
 *   - analysis and ai_insights still rendered when present.
 *   - MITRE techniques still rendered.
 *
 * Degraded / error states:
 *   - 404 on score → "no threat record" message.
 *   - AI unavailable + no rich fields → "AI analysis unavailable" note.
 *   - Fetch failure → error message with status code.
 *
 * Security:
 *   - values from ai_insights rendered as text nodes — no HTML injection.
 *
 * MC.3 (#88): source_types provenance badges in score section.
 * DEF-1 (#159): live /threats/{ip}/events timeline wiring.
 * #179: RULES stat shows IP-triggered rules, not catalog size.
 * D2 (#195): findActionHint wired through IpPanel into RulePopup.
 * ADR-0037: slide-over ARIA semantics (role=dialog, aria-modal, focus).
 * ADR-0037: pivot breadcrumb stack.
 * ADR-0037: ClickableIp keyboard operability.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import IpPanel from '../components/entity/ip/IpPanel'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import { useEntityPanel } from '../components/entity/EntityPanelContext'
import ClickableIp from '../components/entity/ClickableIp'
import SlideOver from '../components/entity/SlideOver'
import type { IpEventTimelineResponse } from '../api/types'
import { clearAnalysisCache } from '../components/entity/analysisCache'
import {
  THREATS_FIXTURE,
  DETAILED_ANALYSIS_FIXTURE,
  DETAILED_ANALYSIS_RULES_ONLY_FIXTURE,
  DETAILED_ANALYSIS_CORRELATED_FIXTURE,
  THREATS_CORRELATED_FIXTURE,
  RULES_FIXTURE,
  IP_EVENTS_SINGLE_SOURCE_FIXTURE,
  IP_EVENTS_CORRELATED_FIXTURE,
  IP_EVENTS_CAPPED_FIXTURE,
} from './readFixtures'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const {
  mockFetchThreatScore,
  mockFetchDetailedAnalysis,
  mockFetchRules,
  mockFetchIpEvents,
  mockFetchHealth,
  mockCreateDecision,
} =
  vi.hoisted(() => ({
    mockFetchThreatScore: vi.fn(),
    mockFetchDetailedAnalysis: vi.fn(),
    mockFetchRules: vi.fn(),
    mockFetchIpEvents: vi.fn(),
    mockFetchHealth: vi.fn(),
    mockCreateDecision: vi.fn(),
  }))

vi.mock('../api/logs', () => ({
  fetchThreatScore: mockFetchThreatScore,
  fetchDetailedAnalysis: mockFetchDetailedAnalysis,
  fetchRules: mockFetchRules,
  fetchIpEvents: mockFetchIpEvents,
}))

// Issue #45 (ADR-0072 D6): the Recent-Logs FalsePositiveButton calls
// recordFalsePositive (lib/triageActions.ts) → createDecision (api/decisions.ts).
vi.mock('../api/decisions', () => ({
  createDecision: mockCreateDecision,
}))

// Mock fetchSourceTypes + fetchHealth for EntityPanelProvider + useDeepAnalysis.
// fetchHealth defaults to AI offline so existing tests don't hang on the deep analysis call.
// fetchEvidenceChain (MI-7): defaults to never-resolving promise so it does not affect
// existing IpPanel tests that focus on the score/analysis sections.
vi.mock('../api/client', () => ({
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchThreats: vi.fn().mockResolvedValue([]),
  fetchHealth: mockFetchHealth,
  fetchEvidenceChain: vi.fn().mockReturnValue(new Promise(() => {})),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: unknown) {
      super(String(message ?? status))
      this.status = status
    }
  },
}))

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Render IpPanel directly (no provider context needed for the panel itself). */
function renderPanel(ip: string, discoveryCache?: Parameters<typeof IpPanel>[0]['discoveryCache']) {
  return render(<IpPanel ip={ip} discoveryCache={discoveryCache} />)
}

/**
 * Render EntityPanelProvider with a button that opens the panel.
 * Used for ADR-0037 slide-over / ClickableIp / breadcrumb tests.
 */
function renderWithProvider(ip: string) {
  function TestConsumer() {
    const { openEntity } = useEntityPanel()
    return (
      <div>
        <button
          data-testid="open-panel-btn"
          onClick={() => openEntity({ kind: 'ip', value: ip })}
        >
          Open
        </button>
      </div>
    )
  }
  return render(
    <EntityPanelProvider>
      <TestConsumer />
    </EntityPanelProvider>,
  )
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
  // Issue #269: clear analysis cache between tests so cache state from one
  // test does not prevent mockFetchDetailedAnalysis from being called in another.
  clearAnalysisCache()
  // DEF-1: default to 404 (null) so existing tests use the coarse fallback.
  mockFetchIpEvents.mockResolvedValue(null)
  // Issue #268: default to AI offline so useDeepAnalysis resolves quickly
  // (phase='ai_offline') and does not block existing tests on a pending LLM call.
  mockFetchHealth.mockResolvedValue({
    status: 'ok',
    ollama_connected: false,
    ollama_model: null,
    db_ok: true,
  })
})

// ---------------------------------------------------------------------------
// ADR-0037: SlideOver shell semantics
// ---------------------------------------------------------------------------

describe('SlideOver — WAI-ARIA dialog semantics (ADR-0037)', () => {
  it('renders nothing when open=false', () => {
    const { container } = render(
      <SlideOver open={false} onClose={vi.fn()} ariaLabel="test panel">
        <div>content</div>
      </SlideOver>,
    )
    expect(container.firstChild).toBeNull()
  })

  it('renders dialog with role=dialog and aria-modal=true when open=true', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="IP 192.0.2.1 details">
        <div>content</div>
      </SlideOver>,
    )
    const panel = screen.getByTestId('slide-over-panel')
    expect(panel).toHaveAttribute('role', 'dialog')
    expect(panel).toHaveAttribute('aria-modal', 'true')
    expect(panel).toHaveAttribute('aria-label', 'IP 192.0.2.1 details')
  })

  it('renders close button with keyboard-accessible label', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test">
        content
      </SlideOver>,
    )
    const closeBtn = screen.getByTestId('slide-over-close')
    expect(closeBtn).toHaveAttribute('aria-label', 'Close (Esc)')
  })

  it('calls onClose when close button is clicked', async () => {
    const onClose = vi.fn()
    render(
      <SlideOver open={true} onClose={onClose} ariaLabel="test">
        content
      </SlideOver>,
    )
    await userEvent.click(screen.getByTestId('slide-over-close'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('calls onClose when overlay is clicked', async () => {
    const onClose = vi.fn()
    render(
      <SlideOver open={true} onClose={onClose} ariaLabel="test">
        content
      </SlideOver>,
    )
    await userEvent.click(screen.getByTestId('slide-over-overlay'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('renders breadcrumb trail', () => {
    render(
      <SlideOver
        open={true}
        onClose={vi.fn()}
        ariaLabel="test"
        breadcrumbs={[{ label: '192.0.2.1' }]}
      >
        content
      </SlideOver>,
    )
    expect(screen.getByTestId('breadcrumb-0')).toHaveTextContent('192.0.2.1')
  })

  it('renders breadcrumb back-button for non-last items', () => {
    const handleBack = vi.fn()
    render(
      <SlideOver
        open={true}
        onClose={vi.fn()}
        ariaLabel="test"
        breadcrumbs={[
          { label: '192.0.2.1', onClick: handleBack },
          { label: '192.0.2.2' },
        ]}
      >
        content
      </SlideOver>,
    )
    const backBtn = screen.getByTestId('breadcrumb-0')
    expect(backBtn.tagName).toBe('BUTTON')
  })
})

// ---------------------------------------------------------------------------
// ADR-0037: EntityPanelProvider + useEntityPanel + openEntity
// ---------------------------------------------------------------------------

describe('EntityPanelProvider — openEntity opens slide-over (ADR-0037)', () => {
  it('panel is not shown before openEntity is called', () => {
    mockFetchThreatScore.mockReturnValue(new Promise(() => {}))
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    renderWithProvider('192.0.2.1')
    expect(screen.queryByTestId('slide-over-panel')).not.toBeInTheDocument()
  })

  it('panel opens when openEntity is called', async () => {
    mockFetchThreatScore.mockReturnValue(new Promise(() => {}))
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    renderWithProvider('192.0.2.1')
    await userEvent.click(screen.getByTestId('open-panel-btn'))
    expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
  })

  it('panel shows the correct ariaLabel for the opened IP', async () => {
    mockFetchThreatScore.mockReturnValue(new Promise(() => {}))
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    renderWithProvider('192.0.2.1')
    await userEvent.click(screen.getByTestId('open-panel-btn'))
    expect(screen.getByTestId('slide-over-panel')).toHaveAttribute(
      'aria-label',
      'IP 192.0.2.1 details',
    )
  })

  it('panel closes when close button is clicked', async () => {
    mockFetchThreatScore.mockReturnValue(new Promise(() => {}))
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    renderWithProvider('192.0.2.1')
    await userEvent.click(screen.getByTestId('open-panel-btn'))
    expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
    await userEvent.click(screen.getByTestId('slide-over-close'))
    expect(screen.queryByTestId('slide-over-panel')).not.toBeInTheDocument()
  })

  it('breadcrumb shows the IP value', async () => {
    mockFetchThreatScore.mockReturnValue(new Promise(() => {}))
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    renderWithProvider('192.0.2.1')
    await userEvent.click(screen.getByTestId('open-panel-btn'))
    expect(screen.getByTestId('breadcrumb-0')).toHaveTextContent('192.0.2.1')
  })
})

// ---------------------------------------------------------------------------
// ADR-0037: ClickableIp
// ---------------------------------------------------------------------------

describe('ClickableIp — keyboard-operable entity token (ADR-0037)', () => {
  it('renders IP as a button with mono-blue styling cue', () => {
    render(
      <EntityPanelProvider>
        <ClickableIp value="192.0.2.1" />
      </EntityPanelProvider>,
    )
    const btn = screen.getByTestId('clickable-ip')
    expect(btn.tagName).toBe('BUTTON')
    expect(btn).toHaveTextContent('192.0.2.1')
  })

  it('opens the panel when clicked', async () => {
    mockFetchThreatScore.mockReturnValue(new Promise(() => {}))
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    render(
      <EntityPanelProvider>
        <ClickableIp value="192.0.2.1" />
      </EntityPanelProvider>,
    )
    await userEvent.click(screen.getByTestId('clickable-ip'))
    expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
  })

  it('opens the panel on Enter keypress', async () => {
    mockFetchThreatScore.mockReturnValue(new Promise(() => {}))
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    render(
      <EntityPanelProvider>
        <ClickableIp value="192.0.2.1" />
      </EntityPanelProvider>,
    )
    screen.getByTestId('clickable-ip').focus()
    await userEvent.keyboard('{Enter}')
    expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
  })

  it('opens the panel on Space keypress', async () => {
    mockFetchThreatScore.mockReturnValue(new Promise(() => {}))
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    render(
      <EntityPanelProvider>
        <ClickableIp value="192.0.2.1" />
      </EntityPanelProvider>,
    )
    screen.getByTestId('clickable-ip').focus()
    await userEvent.keyboard(' ')
    expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// IpPanel — Loading state (#94 Part 1)
// ---------------------------------------------------------------------------

describe('IpPanel — loading state', () => {
  it('shows a spinner while fast score fetch is pending', () => {
    mockFetchThreatScore.mockReturnValue(new Promise(() => {}))
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    renderPanel('192.0.2.1')
    const spinners = screen.getAllByTestId('detail-spinner')
    expect(spinners.length).toBeGreaterThan(0)
    expect(screen.queryByText(/Loading analysis\.\.\./)).not.toBeInTheDocument()
  })

  it('shows a spinner in Deep Analysis section while detail fetch is pending', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-score-section')).toBeInTheDocument())
    const spinners = screen.getAllByTestId('detail-spinner')
    expect(spinners.length).toBeGreaterThan(0)
  })

  it('renders score section immediately after fast fetch, before detail resolves', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-score-section')).toBeInTheDocument())
    // "HIGH" now appears in both the threat-level Badge and inside ScoreBadge (band label)
    expect(screen.getAllByText('HIGH').length).toBeGreaterThanOrEqual(1)
    const scoreSection = screen.getByTestId('modal-score-section')
    // ScoreBadge renders "Risk 78 · HIGH" — check for the numeric score value
    expect(scoreSection).toHaveTextContent('78')
    // ScoreBadge aria-label provides the full label for assistive tech
    expect(scoreSection.querySelector('[aria-label="Risk score 78, severity HIGH"]')).not.toBeNull()
    const spinners = screen.getAllByTestId('detail-spinner')
    expect(spinners.length).toBeGreaterThan(0)
    expect(screen.queryByTestId('modal-rich-detail')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// IpPanel — fetch + render tests
// ---------------------------------------------------------------------------

describe('IpPanel — fetch and render', () => {
  it('fetches score, detailed analysis, and rules when ip is set', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_FIXTURE)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')
    await waitFor(() => {
      expect(mockFetchThreatScore).toHaveBeenCalledWith('192.0.2.1')
      // useRuleAnalysis calls fetchDetailedAnalysis with includeAi=false (issue #268 fast path).
      expect(mockFetchDetailedAnalysis).toHaveBeenCalledWith('192.0.2.1', false)
      expect(mockFetchRules).toHaveBeenCalledTimes(1)
    })
  })

  it('renders threat level and score from concise ThreatScore', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-score-section')).toBeInTheDocument())
    // "HIGH" appears in the threat-level Badge and inside ScoreBadge band label
    expect(screen.getAllByText('HIGH').length).toBeGreaterThanOrEqual(1)
    const scoreSection = screen.getByTestId('modal-score-section')
    // ScoreBadge renders "Risk 78 · HIGH" — numeric score must be present
    expect(scoreSection).toHaveTextContent('78')
    // ScoreBadge replaces the old "Score: N" pattern (defect-1 fix: breakdown popover wired)
    expect(scoreSection.querySelector('.fw-score-badge')).not.toBeNull()
  })

  it('renders deep analysis narrative as text (AI active path)', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-analysis-text')).toBeInTheDocument())
    expect(screen.getByTestId('modal-analysis-text')).toHaveTextContent(
      'This IP shows aggressive SQL injection probing',
    )
  })

  it('renders AI insights as text nodes — no HTML injection', async () => {
    const xssAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      ai_insights: ['<script>alert("xss")</script>', 'Normal insight'],
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(xssAnalysis)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-ai-insights')).toBeInTheDocument())
    expect(screen.getByText('<script>alert("xss")</script>')).toBeInTheDocument()
    document.querySelectorAll('script').forEach((el) => {
      expect(el.textContent).not.toContain('xss')
    })
    expect(document.querySelectorAll('img[onerror]').length).toBe(0)
  })

  it('renders rule descriptions', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_FIXTURE)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-rules-section')).toBeInTheDocument())
    expect(screen.getByText('ET SCAN Potential VNC Scan')).toBeInTheDocument()
  })

  it('shows "no threat record" when score is 404/null', async () => {
    mockFetchThreatScore.mockResolvedValue(null)
    mockFetchDetailedAnalysis.mockResolvedValue(null)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.3')
    await waitFor(() => expect(screen.getByTestId('modal-no-score')).toBeInTheDocument())
  })

  it('shows AI degraded note when ai_status is unavailable and no rich fields', async () => {
    const degradedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      ai_status: 'unavailable' as const,
      ai_insights: null,
      analysis: null,
      executive_summary: null,
      attack_progression: null,
      intent: null,
      ioc_indicators: null,
      insights: null,
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(degradedAnalysis)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-ai-degraded')).toBeInTheDocument())
  })

  it('shows error state when fetch fails', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchThreatScore.mockRejectedValue(new ApiError(503, null))
    mockFetchDetailedAnalysis.mockResolvedValue(null)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-error')).toBeInTheDocument())
    expect(screen.getByRole('alert')).toHaveTextContent('503')
  })
})

// ---------------------------------------------------------------------------
// IpPanel — Rich fields (#94 Part 2) — rules-only path (AI disabled)
// ---------------------------------------------------------------------------

describe('IpPanel #94 — rich structured fields (rules-only path)', () => {
  it('renders executive_summary as text', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_RULES_ONLY_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-executive-summary')).toBeInTheDocument())
    expect(screen.getByTestId('modal-executive-summary')).toHaveTextContent(
      'two SQL injection attacks',
    )
  })

  it('renders attack_progression as an ordered list', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_RULES_ONLY_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-attack-progression')).toBeInTheDocument())
    expect(screen.getByTestId('modal-attack-progression')).toHaveTextContent(
      'Probed the /api/users',
    )
    expect(screen.getByTestId('modal-attack-progression')).toHaveTextContent('Reiterated the attack')
  })

  it('renders intent as text', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_RULES_ONLY_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-intent')).toBeInTheDocument())
    expect(screen.getByTestId('modal-intent')).toHaveTextContent('SQL injection')
  })

  it('renders ioc_indicators as a list', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_RULES_ONLY_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-ioc-indicators')).toBeInTheDocument())
    expect(screen.getByTestId('modal-ioc-indicators')).toHaveTextContent('192.0.2.10')
    expect(screen.getByTestId('modal-ioc-indicators')).toHaveTextContent('942100')
  })

  it('renders insights.patterns, .risks, and .mitigations', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_RULES_ONLY_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-insights')).toBeInTheDocument())
    expect(screen.getByTestId('modal-insights-patterns')).toHaveTextContent('OR 1=1')
    expect(screen.getByTestId('modal-insights-risks')).toHaveTextContent('user data')
    expect(screen.getByTestId('modal-insights-mitigations')).toHaveTextContent('WAF rules')
  })

  it('renders recommended_action, attack_stage, and confidence as meta badges', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_RULES_ONLY_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-meta-badges')).toBeInTheDocument())
    expect(screen.getByTestId('modal-meta-badges')).toHaveTextContent('block')
    expect(screen.getByTestId('modal-meta-badges')).toHaveTextContent('exploitation')
    expect(screen.getByTestId('modal-meta-badges')).toHaveTextContent('85%')
  })

  it('does NOT show AI degraded note when rich fields are present', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_RULES_ONLY_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-rich-detail')).toBeInTheDocument())
    expect(screen.queryByTestId('modal-ai-degraded')).toBeNull()
  })

  it('renders both rich fields AND AI narrative when both are present (AI active path)', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-analysis-text')).toBeInTheDocument())
    expect(screen.getByTestId('modal-analysis-text')).toHaveTextContent(
      'This IP shows aggressive SQL injection probing',
    )
    expect(screen.getByTestId('modal-executive-summary')).toBeInTheDocument()
    expect(screen.getByTestId('modal-attack-progression')).toBeInTheDocument()
  })

  it('renders MITRE techniques from the AI active fixture', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-mitre')).toBeInTheDocument())
    expect(screen.getByTestId('modal-mitre')).toHaveTextContent('T1190')
    expect(screen.getByTestId('modal-mitre')).toHaveTextContent('T1595')
  })
})

// ---------------------------------------------------------------------------
// IpPanel MC.3 (#88) — source_types provenance badges
// ---------------------------------------------------------------------------

describe('IpPanel MC.3 — source provenance badges', () => {
  it('renders two provenance badges + "correlated" label for a multi-source IP', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_CORRELATED_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_CORRELATED_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.50')
    await waitFor(() => expect(screen.getByTestId('modal-score-section')).toBeInTheDocument())
    const badges = screen.getAllByTestId('source-provenance-badge')
    expect(badges).toHaveLength(2)
    expect(badges[0]).toHaveTextContent('Azure WAF')
    expect(badges[1]).toHaveTextContent('Suricata')
    expect(screen.getByTestId('source-correlated-label')).toBeInTheDocument()
  })

  it('renders one provenance badge and no correlated label for a single-source IP', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-score-section')).toBeInTheDocument())
    const badges = screen.getAllByTestId('source-provenance-badge')
    expect(badges).toHaveLength(1)
    expect(badges[0]).toHaveTextContent('Suricata')
    expect(screen.queryByTestId('source-correlated-label')).toBeNull()
  })

  it('renders no provenance badges when source_types is empty', async () => {
    const threatNoSources = { ...THREATS_FIXTURE[0], source_types: [] }
    mockFetchThreatScore.mockResolvedValue(threatNoSources)
    mockFetchDetailedAnalysis.mockResolvedValue({ ...DETAILED_ANALYSIS_FIXTURE, source_types: [] })
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-score-section')).toBeInTheDocument())
    expect(screen.queryByTestId('source-provenance-badges')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// IpPanel DS restyle — EventTimeline, rule popup, kit layout
// ---------------------------------------------------------------------------

describe('IpPanel DS restyle', () => {
  it('renders the EventTimeline section when score data has source_types', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-event-timeline')).toBeInTheDocument())
  })

  it('renders one EventTimeline entry per source_type (single source)', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-event-timeline')).toBeInTheDocument())
    const entries = screen.getAllByTestId(/^timeline-event-/)
    expect(entries).toHaveLength(1)
    expect(entries[0]).toHaveAttribute('data-correlated', 'false')
  })

  it('renders correlated EventTimeline entries when source_types has >1 entry', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_CORRELATED_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_CORRELATED_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.50')
    await waitFor(() => expect(screen.getByTestId('modal-event-timeline')).toBeInTheDocument())
    const entries = screen.getAllByTestId(/^timeline-event-/)
    expect(entries).toHaveLength(2)
    for (const entry of entries) {
      expect(entry).toHaveAttribute('data-correlated', 'true')
    }
  })

  it('does not render EventTimeline when source_types is empty', async () => {
    const threatNoSources = { ...THREATS_FIXTURE[0], source_types: [] }
    mockFetchThreatScore.mockResolvedValue(threatNoSources)
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-score-section')).toBeInTheDocument())
    expect(screen.queryByTestId('modal-event-timeline')).toBeNull()
  })

  it('does not show a center-screen modal overlay for Signature cells (#283 — RulePopup deleted)', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(null)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-analysis-section')).toBeInTheDocument())
    // Confirm the old center-screen modal is gone
    expect(screen.queryByTestId('rule-popup')).toBeNull()
    // Confirm there is no aria-modal dialog (which was the RulePopup)
    expect(screen.queryByRole('dialog', { name: /rule details/i })).toBeNull()
  })

  it('shows anchored RuleCellTooltip (peek) when Signature cell is hovered (#283)', async () => {
    const analysisWithDetections: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'suricata',
          category: 'SQL Injection',
          sid: '2001219',
          signature: 'ET SCAN Potential VNC Scan',
          raw_log: 'test',
        },
      ],
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithDetections)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('rule-cell-trigger-wrap')).toBeInTheDocument())
    // Hover to peek
    const { fireEvent: fe } = await import('@testing-library/react')
    fe.mouseEnter(screen.getByTestId('rule-cell-tooltip-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })
    // Peek shows sid
    expect(screen.getByTestId('rule-cell-tooltip-content').textContent).toContain('2001219')
    // No center-screen modal
    expect(screen.queryByTestId('rule-popup')).toBeNull()
  })

  it('pins RuleCellTooltip with description when Signature cell is clicked (#283)', async () => {
    const analysisWithDetections: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'suricata',
          category: 'SQL Injection',
          sid: '2001219',
          signature: 'ET SCAN Potential VNC Scan',
          raw_log: 'test',
        },
      ],
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithDetections)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('rule-cell-trigger-wrap')).toBeInTheDocument())
    await userEvent.click(screen.getByTestId('rule-cell-display-name'))
    // Popover open: full value + description visible
    await waitFor(() => expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument())
    expect(screen.getByTestId('cell-detail-meta-desc').textContent).toContain(
      'Detects potential VNC scanning activity.',
    )
    // No center-screen modal
    expect(screen.queryByTestId('rule-popup')).toBeNull()
  })

  it('unpins RuleCellTooltip (closes detail) when Signature cell is clicked again (#283)', async () => {
    const analysisWithDetections: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'suricata',
          category: 'SQL Injection',
          sid: '2001219',
          signature: 'ET SCAN Potential VNC Scan',
          raw_log: 'test',
        },
      ],
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithDetections)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('rule-cell-trigger-wrap')).toBeInTheDocument())
    // First click: open popover
    await userEvent.click(screen.getByTestId('rule-cell-display-name'))
    await waitFor(() => expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument())
    // Second click: close popover (toggle)
    await userEvent.click(screen.getByTestId('rule-cell-display-name'))
    expect(screen.queryByTestId('rule-cell-detail-popover')).not.toBeInTheDocument()
  })

  it('RuleCellTooltip shows fallback description when rule id not in list (#283)', async () => {
    const analysisWithUnknownRule: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'suricata',
          category: 'Unknown',
          sid: '9999999',
          signature: 'Unknown Rule',
          raw_log: 'test',
        },
      ],
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithUnknownRule)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('rule-cell-trigger-wrap')).toBeInTheDocument())
    await userEvent.click(screen.getByTestId('rule-cell-display-name'))
    await waitFor(() => expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument())
    // Fallback desc not shown in metadata when it equals FALLBACK_DESC constant —
    // the popover still shows the full value (signature/rule_id).
    expect(screen.getByTestId('cell-detail-full-value').textContent).toContain('9999999')
  })

  it('renders the 4-up stat grid with Events/Blocked/Rules/Block-rate', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0]) // total=120, blocked=95
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-score-section')).toBeInTheDocument())
    const scoreSection = screen.getByTestId('modal-score-section')
    expect(scoreSection).toHaveTextContent('120')
    expect(scoreSection).toHaveTextContent('95')
    expect(scoreSection).toHaveTextContent('Events')
    expect(scoreSection).toHaveTextContent('Blocked')
    expect(scoreSection).toHaveTextContent('Block rate')
  })

  it('renders attack-type category badges in the score section', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0]) // attack_types: ['SQL Injection', 'Scanner']
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-score-section')).toBeInTheDocument())
    expect(screen.getByText('SQL Injection')).toBeInTheDocument()
    expect(screen.getByText('Scanner')).toBeInTheDocument()
  })

  it('198.51.100.50 shows both source badges + correlated + correlated timeline entries', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_CORRELATED_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_CORRELATED_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.50')
    await waitFor(() => expect(screen.getByTestId('modal-score-section')).toBeInTheDocument())
    const badges = screen.getAllByTestId('source-provenance-badge')
    expect(badges).toHaveLength(2)
    expect(badges[0]).toHaveTextContent('Azure WAF')
    expect(badges[1]).toHaveTextContent('Suricata')
    expect(screen.getByTestId('source-correlated-label')).toBeInTheDocument()
    const timelineEntries = screen.getAllByTestId(/^timeline-event-/)
    expect(timelineEntries).toHaveLength(2)
    for (const entry of timelineEntries) {
      expect(entry).toHaveAttribute('data-correlated', 'true')
    }
  })
})

// ---------------------------------------------------------------------------
// IpPanel DEF-1 (#159) — live /threats/{ip}/events timeline wiring
// ---------------------------------------------------------------------------

describe('IpPanel DEF-1 — live event timeline', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchHealth.mockResolvedValue({
      status: 'ok', ollama_connected: false, ollama_model: null, db_ok: true,
    })
  })

  it('fetches GET /threats/{ip}/events when ip is set', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(null)
    mockFetchRules.mockResolvedValue([])
    mockFetchIpEvents.mockResolvedValue(IP_EVENTS_SINGLE_SOURCE_FIXTURE)
    renderPanel('192.0.2.1')
    await waitFor(() => expect(mockFetchIpEvents).toHaveBeenCalledWith('192.0.2.1'))
  })

  it('renders real per-event timeline entries from /threats/{ip}/events', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(null)
    mockFetchRules.mockResolvedValue([])
    mockFetchIpEvents.mockResolvedValue(IP_EVENTS_SINGLE_SOURCE_FIXTURE)
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-event-timeline')).toBeInTheDocument())
    const entries = screen.getAllByTestId(/^timeline-event-/)
    expect(entries).toHaveLength(IP_EVENTS_SINGLE_SOURCE_FIXTURE.events.length)
  })

  it('renders correlated entries when live events have correlated=true', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_CORRELATED_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_CORRELATED_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    mockFetchIpEvents.mockResolvedValue(IP_EVENTS_CORRELATED_FIXTURE)
    renderPanel('192.0.2.50')
    await waitFor(() => expect(screen.getByTestId('modal-event-timeline')).toBeInTheDocument())
    const entries = screen.getAllByTestId(/^timeline-event-/)
    expect(entries).toHaveLength(IP_EVENTS_CORRELATED_FIXTURE.events.length)
    for (const entry of entries) {
      expect(entry).toHaveAttribute('data-correlated', 'true')
    }
  })

  it('falls back to coarse timeline when /threats/{ip}/events returns 404 (null)', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(null)
    mockFetchRules.mockResolvedValue([])
    mockFetchIpEvents.mockResolvedValue(null)
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-event-timeline')).toBeInTheDocument())
    const entries = screen.getAllByTestId(/^timeline-event-/)
    expect(entries).toHaveLength(1)
  })

  it('falls back to coarse timeline when /threats/{ip}/events throws', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(null)
    mockFetchRules.mockResolvedValue([])
    mockFetchIpEvents.mockRejectedValue(new Error('503 Service Unavailable'))
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-event-timeline')).toBeInTheDocument())
    const entries = screen.getAllByTestId(/^timeline-event-/)
    expect(entries).toHaveLength(1)
  })

  it('shows capped notice when live event response is capped', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(null)
    mockFetchRules.mockResolvedValue([])
    mockFetchIpEvents.mockResolvedValue(IP_EVENTS_CAPPED_FIXTURE)
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('timeline-capped-notice')).toBeInTheDocument())
  })

  it('does not show capped notice when capped=false', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(null)
    mockFetchRules.mockResolvedValue([])
    mockFetchIpEvents.mockResolvedValue(IP_EVENTS_SINGLE_SOURCE_FIXTURE) // capped: false
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-event-timeline')).toBeInTheDocument())
    expect(screen.queryByTestId('timeline-capped-notice')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// IpPanel #179 — RULES stat shows IP-triggered rules, not catalog size
// ---------------------------------------------------------------------------

describe('IpPanel #179 — RULES stat from IP events, not catalog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchHealth.mockResolvedValue({
      status: 'ok', ollama_connected: false, ollama_model: null, db_ok: true,
    })
  })

  it('shows distinct rule count from live events (not catalog size)', async () => {
    const bigCatalog = Array.from({ length: 10000 }, (_, i) => ({
      rule_id: String(i + 1),
      name: `Rule ${i + 1}`,
    }))

    const fourRuleEvents: IpEventTimelineResponse = {
      events: [
        { source: 'suricata', time: '2026-06-04T08:00:00Z', label: '2001219', payload: null, correlated: false, action: 'BLOCK', severity: 'high', category: 'SQL Injection' },
        { source: 'suricata', time: '2026-06-04T08:01:00Z', label: '2001219', payload: null, correlated: false, action: 'BLOCK', severity: 'high', category: 'SQL Injection' },
        { source: 'suricata', time: '2026-06-04T08:02:00Z', label: '2006546', payload: null, correlated: false, action: 'ALERT', severity: 'medium', category: 'Port Scan' },
        { source: 'suricata', time: '2026-06-04T08:03:00Z', label: '2100498', payload: null, correlated: false, action: 'ALERT', severity: 'medium', category: 'Malware' },
        { source: 'suricata', time: '2026-06-04T08:04:00Z', label: '2009358', payload: null, correlated: false, action: 'BLOCK', severity: 'high', category: 'Brute Force' },
      ],
      total: 5,
      correlated: false,
      source_types: ['suricata'],
      capped: false,
    }

    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_FIXTURE)
    mockFetchRules.mockResolvedValue(bigCatalog)
    mockFetchIpEvents.mockResolvedValue(fourRuleEvents)

    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-score-section')).toBeInTheDocument())
    const scoreSection = screen.getByTestId('modal-score-section')
    expect(scoreSection).toHaveTextContent('4')
    expect(scoreSection).not.toHaveTextContent('10000')
    expect(scoreSection).toHaveTextContent('Rules')
  })

  it('shows — while events are still loading', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))
    mockFetchIpEvents.mockReturnValue(new Promise(() => {}))
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-score-section')).toBeInTheDocument())
    const scoreSection = screen.getByTestId('modal-score-section')
    expect(scoreSection).toHaveTextContent('—')
    expect(scoreSection).toHaveTextContent('Rules')
  })

  it('falls back to detections when ipEvents is 404 (null)', async () => {
    const analysisWithDetections: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        { sid: '942100', timestamp: '2026-06-04T08:00:00Z', source_type: 'azure_waf' },
        { sid: '942100', timestamp: '2026-06-04T08:01:00Z', source_type: 'azure_waf' },
        { sid: '942110', timestamp: '2026-06-04T08:02:00Z', source_type: 'azure_waf' },
        { rule_id: '930100', timestamp: '2026-06-04T08:03:00Z', source_type: 'azure_waf' },
      ],
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithDetections)
    mockFetchRules.mockResolvedValue([])
    mockFetchIpEvents.mockResolvedValue(null)
    renderPanel('192.0.2.1')
    await waitFor(() => {
      const scoreSection = screen.getByTestId('modal-score-section')
      expect(scoreSection).toHaveTextContent('3')
    })
    const scoreSection = screen.getByTestId('modal-score-section')
    expect(scoreSection).toHaveTextContent('Rules')
  })
})

// ---------------------------------------------------------------------------
// IpPanel D2 (#195 / #283) — findActionHint wired through IpPanel into RuleCellTooltip
// ---------------------------------------------------------------------------

describe('IpPanel D2 — action hint wired to RuleCellTooltip (#283)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchIpEvents.mockResolvedValue(null)
    mockFetchHealth.mockResolvedValue({
      status: 'ok', ollama_connected: false, ollama_model: null, db_ok: true,
    })
  })

  it('D2: hint renders in pin mode when bare-SID rule is clicked and source declares rule_descriptions action', async () => {
    const idsSource = {
      type_key: 'demo_ids',
      display_name: 'Demo IDS',
      version: '1.0.0',
      flavor: 'pull' as const,
      config_schema: { type: 'object', properties: {} },
      actions: [
        {
          id: 'fetch_rules',
          label: 'Download rules',
          description: 'Downloads the rule catalog.',
          long_running: true,
          confirm: 'This will download ~40 MB.',
          provides: ['rule_descriptions'],
        },
      ],
    }

    const analysisWithDetection: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'demo_ids',
          category: 'IDS alert',
          sid: '9999999',
          signature: '9999999',
          raw_log: 'test',
        },
      ],
    }

    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithDetection)
    mockFetchRules.mockResolvedValue([])

    renderPanel('192.0.2.1', [idsSource])

    await waitFor(() => expect(screen.getByTestId('rule-cell-trigger-wrap')).toBeInTheDocument())
    await userEvent.click(screen.getByTestId('rule-cell-display-name'))

    await waitFor(() => expect(screen.getByTestId('rule-cell-hint')).toBeInTheDocument())
    expect(screen.getByTestId('rule-cell-hint-source').textContent).toContain('Demo IDS')
    // No center-screen modal
    expect(screen.queryByTestId('rule-popup')).toBeNull()
  })

  it('D2: no hint when source declares no rule_descriptions action', async () => {
    const wafSource = {
      type_key: 'azure_waf',
      display_name: 'Azure WAF',
      version: '1.0.0',
      flavor: 'pull' as const,
      config_schema: { type: 'object', properties: {} },
      actions: [],
    }

    const analysisWithDetection: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'azure_waf',
          category: 'SQL Injection',
          sid: '942100',
          signature: '942100',
          raw_log: 'test',
        },
      ],
    }

    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithDetection)
    mockFetchRules.mockResolvedValue([])

    renderPanel('192.0.2.1', [wafSource])

    await waitFor(() => expect(screen.getByTestId('rule-cell-trigger-wrap')).toBeInTheDocument())
    await userEvent.click(screen.getByTestId('rule-cell-display-name'))

    await waitFor(() => expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument())
    expect(screen.queryByTestId('rule-cell-hint')).toBeNull()
  })

  it('D2: no hint when discoveryCache is not passed (backward compat)', async () => {
    const analysisWithDetection: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'suricata',
          category: 'IDS alert',
          sid: '1234567',
          signature: '1234567',
          raw_log: 'test',
        },
      ],
    }

    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithDetection)
    mockFetchRules.mockResolvedValue([])

    renderPanel('192.0.2.1') // no discoveryCache

    await waitFor(() => expect(screen.getByTestId('rule-cell-trigger-wrap')).toBeInTheDocument())
    await userEvent.click(screen.getByTestId('rule-cell-display-name'))

    await waitFor(() => expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument())
    expect(screen.queryByTestId('rule-cell-hint')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// IpPanel #267/#268 — ADR-0035 provenance honesty: staged AI loading
// ---------------------------------------------------------------------------

describe('IpPanel #267 — AI provenance honesty (ADR-0035)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchIpEvents.mockResolvedValue(null)
    // Default: AI offline (phase=ai_offline → DeepAnalysisControl shows offline badge).
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: false,
      ollama_model: null,
      db_ok: true,
    })
  })

  it('shows "Deep analysis complete" ONLY when deep AI call succeeded (issue #268)', async () => {
    // AI online + deep call returns active result.
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.2',
      db_ok: true,
    })
    // First call (useRuleAnalysis, ai=false): rule-only result.
    // Second call (useDeepAnalysis, ai=true): AI-active result.
    mockFetchDetailedAnalysis
      .mockResolvedValueOnce({ ...DETAILED_ANALYSIS_FIXTURE, ai_status: 'skipped' as const })
      .mockResolvedValue(DETAILED_ANALYSIS_FIXTURE) // ai_status: 'active'
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() =>
      expect(screen.getByTestId('deep-analysis-complete-btn')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('deep-analysis-complete-btn')).toHaveTextContent(
      'Deep analysis complete',
    )
    expect(screen.queryByTestId('modal-ai-rules-only-badge')).toBeNull()
    expect(screen.queryByTestId('deep-analysis-offline-badge')).toBeNull()
  })

  it('does NOT show "Deep analysis complete" when AI is offline (shows offline badge + Run button)', async () => {
    // fetchHealth returns AI offline (default) → deepPhase=ai_offline.
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_RULES_ONLY_FIXTURE)
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-ai-provenance-status')).toBeInTheDocument())
    // DeepAnalysisControl shows the offline badge (phase=ai_offline).
    await waitFor(() =>
      expect(screen.getByTestId('deep-analysis-offline-badge')).toBeInTheDocument(),
    )
    expect(screen.queryByText('Deep analysis complete')).toBeNull()
    expect(screen.queryByTestId('deep-analysis-complete-btn')).toBeNull()
    // Run button is enabled.
    expect(screen.getByTestId('deep-analysis-run-btn')).toBeInTheDocument()
    expect(screen.getByTestId('deep-analysis-run-btn')).not.toBeDisabled()
  })

  it('shows "AI analysis failed · Retry" when deep AI call fails — NEVER shows "complete"', async () => {
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.2',
      db_ok: true,
    })
    // First call (useRuleAnalysis, ai=false): rule-only result.
    // Second call (useDeepAnalysis, ai=true): throws.
    const { ApiError: LocalApiError } = await import('../api/client')
    mockFetchDetailedAnalysis
      .mockResolvedValueOnce({ ...DETAILED_ANALYSIS_FIXTURE, ai_status: 'skipped' as const })
      .mockRejectedValue(new LocalApiError(503, 'LLM unavailable'))
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() =>
      expect(screen.getByTestId('deep-analysis-failed-badge')).toBeInTheDocument(),
    )
    expect(screen.queryByText('Deep analysis complete')).toBeNull()
    expect(screen.queryByTestId('deep-analysis-complete-btn')).toBeNull()
    // Retry button is present and enabled.
    expect(screen.getByTestId('deep-analysis-run-btn')).not.toBeDisabled()
    expect(screen.getByTestId('deep-analysis-run-btn')).toHaveTextContent('Retry')
  })

  it('rule-derived sections remain visible when AI is offline (rules-only is still a result)', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_RULES_ONLY_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-rich-detail')).toBeInTheDocument())
    // Rule-derived rich fields still render
    expect(screen.getByTestId('modal-executive-summary')).toBeInTheDocument()
    expect(screen.getByTestId('modal-attack-progression')).toBeInTheDocument()
    // But no false "complete" claim
    expect(screen.queryByText('Deep analysis complete')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// IpPanel #310 — session analysis cache: dead-wire consumer-level regression guard
// ---------------------------------------------------------------------------
// These tests assert the cache is actually wired into the production path,
// not just that the cache module works in isolation.  Per the dead-wire lesson
// (docs/lessons.md): a consumer-level test is required so that removing the
// wiring re-breaks the test, catching the #268-style regression.
//
// Design:
//  - AI online (mockFetchHealth resolves with ollama_connected:true).
//  - First open: deep analysis fetch fires, result written to cache.
//  - Panel unmounted (user closes), then remounted for the same IP.
//  - Second open: cache HIT → fetch NOT called again; control shows "cached · …".
//  - Re-run: invalidates cache → fetch fires once more.

describe('IpPanel #310 — session analysis cache consumer-level tests', () => {
  const HEALTH_ONLINE = {
    status: 'ok',
    ollama_connected: true,
    ollama_model: 'llama3.2',
    db_ok: true,
  }

  beforeEach(() => {
    vi.clearAllMocks()
    clearAnalysisCache()
    mockFetchIpEvents.mockResolvedValue(null)
  })

  it('does NOT re-fire the analysis fetch when the same IP is reopened (cache hit)', async () => {
    // First open: rule-only fast path + deep AI call both resolve.
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis
      .mockResolvedValueOnce({ ...DETAILED_ANALYSIS_FIXTURE, ai_status: 'skipped' as const })
      .mockResolvedValue(DETAILED_ANALYSIS_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    mockFetchHealth.mockResolvedValue(HEALTH_ONLINE)

    const { unmount } = renderPanel('192.0.2.1')

    // Wait for the deep analysis to complete and be written to cache.
    await waitFor(() =>
      expect(screen.getByTestId('deep-analysis-complete-btn')).toBeInTheDocument(),
    )

    // Record how many times fetchDetailedAnalysis was called on first open
    // (1 for useRuleAnalysis ?ai=false + 1 for useDeepAnalysis ?ai=true).
    const callsAfterFirstOpen = mockFetchDetailedAnalysis.mock.calls.length
    expect(callsAfterFirstOpen).toBe(2)

    // Unmount (simulate user closing the panel).
    unmount()

    // Second open — same IP.
    renderPanel('192.0.2.1')

    // Wait for the panel to settle: the control must appear immediately (cache hit).
    await waitFor(() =>
      expect(screen.getByTestId('deep-analysis-complete-btn')).toBeInTheDocument(),
    )

    // CRITICAL: no additional fetchDetailedAnalysis call was made for the AI path.
    // Only the rule-only ?ai=false call for useRuleAnalysis may fire again.
    // The deep analysis call count must NOT have incremented beyond the first open's AI call.
    const deepAnalysisCalls = mockFetchDetailedAnalysis.mock.calls.filter(
      ([, includeAi]) => includeAi === true,
    )
    expect(deepAnalysisCalls).toHaveLength(1) // only the first open's deep call
  })

  it('shows "cached · …" stamp on cache-hit reopen', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis
      .mockResolvedValueOnce({ ...DETAILED_ANALYSIS_FIXTURE, ai_status: 'skipped' as const })
      .mockResolvedValue(DETAILED_ANALYSIS_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    mockFetchHealth.mockResolvedValue(HEALTH_ONLINE)

    const { unmount } = renderPanel('192.0.2.1')

    // Wait for first-open deep analysis to complete.
    await waitFor(() =>
      expect(screen.getByTestId('deep-analysis-complete-btn')).toBeInTheDocument(),
    )
    unmount()

    // Second open.
    renderPanel('192.0.2.1')

    await waitFor(() =>
      expect(screen.getByTestId('deep-analysis-complete-btn')).toBeInTheDocument(),
    )

    // The "cached · …" stamp must be present (fromCache=true path in DeepAnalysisControl).
    // textContent includes the emoji icon prefix from the Button component.
    const completeBtn = screen.getByTestId('deep-analysis-complete-btn')
    expect(completeBtn.textContent).toMatch(/cached · /)
  })

  it('Re-run invalidates cache and fires a fresh deep analysis fetch', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis
      .mockResolvedValueOnce({ ...DETAILED_ANALYSIS_FIXTURE, ai_status: 'skipped' as const })
      .mockResolvedValue(DETAILED_ANALYSIS_FIXTURE)
    mockFetchRules.mockResolvedValue([])
    mockFetchHealth.mockResolvedValue(HEALTH_ONLINE)

    const { unmount } = renderPanel('192.0.2.1')

    // Wait for first-open deep analysis to complete.
    await waitFor(() =>
      expect(screen.getByTestId('deep-analysis-complete-btn')).toBeInTheDocument(),
    )
    unmount()

    // Second open — cache hit.
    mockFetchDetailedAnalysis
      .mockResolvedValueOnce({ ...DETAILED_ANALYSIS_FIXTURE, ai_status: 'skipped' as const })
      .mockResolvedValue(DETAILED_ANALYSIS_FIXTURE)

    renderPanel('192.0.2.1')

    await waitFor(() =>
      expect(screen.getByTestId('deep-analysis-rerun-btn')).toBeInTheDocument(),
    )

    const deepCallsBeforeRerun = mockFetchDetailedAnalysis.mock.calls.filter(
      ([, includeAi]) => includeAi === true,
    ).length

    // Click Re-run.
    await userEvent.click(screen.getByTestId('deep-analysis-rerun-btn'))

    // A fresh deep analysis fetch must fire.
    await waitFor(() => {
      const deepCallsAfterRerun = mockFetchDetailedAnalysis.mock.calls.filter(
        ([, includeAi]) => includeAi === true,
      ).length
      expect(deepCallsAfterRerun).toBe(deepCallsBeforeRerun + 1)
    })

    // After Re-run completes, the label must NOT say "cached · …" (it's now a fresh result).
    await waitFor(() =>
      expect(screen.getByTestId('deep-analysis-complete-btn')).toBeInTheDocument(),
    )
    const completeBtn = screen.getByTestId('deep-analysis-complete-btn')
    expect(completeBtn.textContent).not.toMatch(/cached · /)
  })
})

describe('IpPanel #284 — PayloadCellTooltip in Recent Logs', () => {
  it('renders PayloadCellTooltip (data-truncated span) in the payload cell — not a bare text node (#284)', async () => {
    const analysisWithPayload: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'suricata',
          category: 'SQL Injection',
          sid: '2001219',
          signature: 'ET SCAN Potential VNC Scan',
          payload_snippet: 'GET /api/users?id=1 OR 1=1',
        },
      ],
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithPayload)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')
    // Wait for the recent-logs section to appear (ruleResolved + detections.length > 0)
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    // PayloadCellTooltip renders a span with data-truncated (JSDOM: "false").
    // If the bare {payload} text node is still there instead, this span won't exist.
    const logsSection = screen.getByTestId('modal-recent-logs')
    expect(logsSection.querySelector('span[data-truncated]'))
      .not.toBeNull()
  })
})

describe('IpPanel #328 — Recent Logs Payload column reads payload_snippet', () => {
  /**
   * EARS-1: WHEN an IP has events whose payload_snippet is non-null, the slide-over
   * Recent Logs Payload column SHALL render the snippet (and the #284 PayloadCellTooltip
   * SHALL show it on demand).
   */
  it('renders payload_snippet content in the PayloadCellTooltip when present (#328 EARS-1)', async () => {
    const snippet = 'GET /api/users?id=1 OR 1=1'
    const analysisWithSnippet: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'suricata',
          category: 'SQL Injection',
          rule_id: '942100',
          payload_snippet: snippet,
        },
      ],
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithSnippet)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    // The snippet text must appear in the payload cell.
    expect(screen.getByTestId('modal-recent-logs').textContent).toContain(snippet)
  })

  /**
   * EARS-2: WHEN payload_snippet is null for a row, the cell SHALL render an explicit
   * empty state ("—"), never a broken/blank tooltip trigger.
   */
  it('renders dash placeholder when payload_snippet is absent (#328 EARS-2)', async () => {
    const analysisWithNoSnippet: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'suricata',
          category: 'SQL Injection',
          rule_id: '942100',
          // payload_snippet intentionally absent — simulates a row with no payload
        },
      ],
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithNoSnippet)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    // Cell shows "—" placeholder (PayloadCellTooltip dash-branch).
    expect(screen.getByTestId('modal-recent-logs').textContent).toContain('—')
  })

  /**
   * Regression guard: the old mismatch fields (raw_log / payload) SHALL NOT
   * be used as the payload source — only payload_snippet is canonical (#328).
   */
  it('does NOT render raw_log or legacy payload field as payload content (#328 regression)', async () => {
    const analysisWithLegacyFields: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'suricata',
          category: 'SQL Injection',
          rule_id: '942100',
          // These are the old wrong field names that used to be read.
          // payload_snippet is absent, so payload column should show "—".
          raw_log: 'SHOULD NOT APPEAR IN PAYLOAD CELL',
          payload: 'ALSO SHOULD NOT APPEAR',
        },
      ],
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithLegacyFields)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    const logsSection = screen.getByTestId('modal-recent-logs')
    // Old wrong field values must NOT appear in the logs table.
    expect(logsSection.textContent).not.toContain('SHOULD NOT APPEAR IN PAYLOAD CELL')
    expect(logsSection.textContent).not.toContain('ALSO SHOULD NOT APPEAR')
    // The cell should show "—" because payload_snippet is absent.
    expect(logsSection.textContent).toContain('—')
  })
})

// ---------------------------------------------------------------------------
// IpPanel #337 — Recent Logs TIME column: relative primary, absolute on hover
// ---------------------------------------------------------------------------

describe('IpPanel #337 — Recent Logs time format via TimeText/lib/time seam', () => {
  /**
   * EARS: The Recent Logs TIME column SHALL render via TimeText/lib/time.ts —
   * relative time primary ("2m ago") with the absolute ISO 8601 + offset on hover.
   * No raw ISO strings visible at rest.
   * Test fixture uses RFC-5737 IPs (203.0.113.x) — never real public IPs.
   */
  const RAW_ISO_TIMESTAMP = '2026-06-04T10:00:00Z'

  const analysisWithDetection = {
    ...DETAILED_ANALYSIS_FIXTURE,
    detections: [
      {
        timestamp: RAW_ISO_TIMESTAMP,
        source_type: 'suricata',
        category: 'SQL Injection',
        sid: '2001219',
        signature: 'ET SCAN Potential VNC Scan',
        raw_log: 'test',
      },
    ],
  }

  it('#337 EARS-1: Recent Logs TIME cell does NOT show the raw ISO string at rest', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithDetection)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('203.0.113.1')
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    // The raw ISO timestamp must not appear as visible text in the TIME column
    const timeEl = screen.getByTestId('log-time-0')
    expect(timeEl.textContent).not.toBe(RAW_ISO_TIMESTAMP)
    expect(timeEl.textContent).not.toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })

  it('#337 EARS-2: Recent Logs TIME cell has title with absolute UTC string (for hover)', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithDetection)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('203.0.113.1')
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    const timeEl = screen.getByTestId('log-time-0')
    // title attribute holds the absolute UTC timestamp (formatUtc output contains "UTC")
    expect(timeEl).toHaveAttribute('title')
    expect(timeEl.getAttribute('title')).toContain('UTC')
  })

  it('#337: timeline and Recent Logs time seam are consistent — both use TimeText data-testid pattern', async () => {
    // When timeline events and detections have matching timestamps, both must use the same seam.
    // This test asserts that the TIME column uses TimeText (data-testid="log-time-N")
    // and the timeline uses TimeText (data-testid="timeline-time-N") — same component, same seam.
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithDetection)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    mockFetchIpEvents.mockResolvedValue({
      events: [
        {
          source: 'suricata',
          time: RAW_ISO_TIMESTAMP,
          label: 'ET SCAN',
          payload: null,
          correlated: false,
          action: 'ALERT',
          severity: 'medium',
          category: 'SQL Injection',
        },
      ],
      total: 1,
      correlated: false,
      source_types: ['suricata'],
      capped: false,
    })
    renderPanel('203.0.113.1')
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    // Both must exist and neither should show raw ISO
    const logTimeEl = screen.getByTestId('log-time-0')
    const timelineTimeEl = screen.getByTestId('timeline-time-0')
    expect(logTimeEl.textContent).not.toMatch(/^\d{4}-\d{2}-\d{2}T/)
    expect(timelineTimeEl.textContent).not.toMatch(/^\d{4}-\d{2}-\d{2}T/)
    // Both must have UTC absolute on hover
    expect(logTimeEl.getAttribute('title')).toContain('UTC')
    expect(timelineTimeEl.getAttribute('title')).toContain('UTC')
  })
})

// ---------------------------------------------------------------------------
// IpPanel #363 — Recent Logs TIME cell: ISO/UTC accessible when correlated context present
// ---------------------------------------------------------------------------

describe('IpPanel #363 — Recent Logs TIME cell exposes UTC on hover (correlated + non-correlated)', () => {
  /**
   * EARS (issue #363):
   *   - WHEN a Recent Logs TIME cell has NO correlated context, the TimeText span
   *     SHALL carry a `title` attribute containing "UTC" (native hover tooltip).
   *   - WHEN a Recent Logs TIME cell HAS correlated context (wrapped in CellTooltip),
   *     the CellTooltip content SHALL include the absolute UTC timestamp so the
   *     analyst can see the ISO time even when the correlated context popup is shown.
   *   - TimeText `title` attribute SHALL still be present in the correlated case
   *     (for screen readers and fallback).
   *
   * RFC-5737 IPs used throughout — no real production IPs.
   * Correlated context requires a live ipEvents response with correlated=true events
   * whose timestamp is within ±5 min of the detection timestamp.
   */

  const DETECTION_ISO = '2026-06-04T10:00:00Z'

  /** Detection with a correlated timeline event within ±5 minutes. */
  const analysisWithDetection: import('../api/types').DetailedAnalysis = {
    ...DETAILED_ANALYSIS_FIXTURE,
    detections: [
      {
        timestamp: DETECTION_ISO,
        source_type: 'suricata',
        category: 'SQL Injection',
        sid: '2001219',
        signature: 'ET SCAN Potential VNC Scan',
        raw_log: 'test',
      },
    ],
  }

  /** ipEvents fixture: one correlated event at the same timestamp as the detection. */
  const correlatedEvents: IpEventTimelineResponse = {
    events: [
      {
        source: 'azure_waf',
        time: DETECTION_ISO,
        label: '942100',
        payload: null,
        correlated: true,
        action: 'BLOCK',
        severity: 'high',
        category: 'sql_injection',
      },
    ],
    total: 1,
    correlated: true,
    source_types: ['azure_waf', 'suricata'],
    capped: false,
  }

  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchHealth.mockResolvedValue({
      status: 'ok', ollama_connected: false, ollama_model: null, db_ok: true,
    })
    // Default: no live events (non-correlated path).
    mockFetchIpEvents.mockResolvedValue(null)
  })

  it('#363 EARS-1: non-correlated TIME cell — title attribute carries UTC (regression guard)', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithDetection)
    mockFetchRules.mockResolvedValue([])
    renderPanel('203.0.113.1')
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    const timeEl = screen.getByTestId('log-time-0')
    // Non-correlated path: TimeText rendered without CellTooltip wrapper.
    // title must hold the absolute UTC string so the browser can show it on hover.
    expect(timeEl).toHaveAttribute('title')
    expect(timeEl.getAttribute('title')).toContain('UTC')
  })

  it('#363 EARS-2: correlated TIME cell — CellTooltip content includes absolute UTC', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_CORRELATED_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithDetection)
    mockFetchRules.mockResolvedValue([])
    mockFetchIpEvents.mockResolvedValue(correlatedEvents)
    renderPanel('203.0.113.50')
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())

    // Hover the time cell to open the CellTooltip.
    const trigger = screen.getByTestId('log-date-tooltip-trigger-0')
    const { fireEvent: fe } = await import('@testing-library/react')
    fe.mouseEnter(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })

    // The CellTooltip popup content MUST include the UTC timestamp string (#363 fix).
    const utcEl = screen.getByTestId('log-date-tooltip-utc-0')
    expect(utcEl.textContent).toContain('UTC')
  })

  it('#363 EARS-3: correlated TIME cell — inner TimeText title still carries UTC (screen reader / fallback)', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_CORRELATED_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithDetection)
    mockFetchRules.mockResolvedValue([])
    mockFetchIpEvents.mockResolvedValue(correlatedEvents)
    renderPanel('203.0.113.50')
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    // TimeText span is inside the CellTooltip trigger — title must still be present.
    const timeEl = screen.getByTestId('log-time-0')
    expect(timeEl).toHaveAttribute('title')
    expect(timeEl.getAttribute('title')).toContain('UTC')
  })
})

// ---------------------------------------------------------------------------
// IpPanel #353 — Recent Logs Payload cell width constraint (no h-scroll)
// ---------------------------------------------------------------------------

describe('IpPanel #353 — Recent Logs Payload cell is width-constrained (no h-scroll)', () => {
  /**
   * EARS-1: WHEN a Recent Logs row has a long payload, the Payload cell SHALL
   * render within a fixed max width and SHALL NOT cause a horizontal scrollbar
   * on the slide-over panel.
   *
   * Test fixture uses RFC-5737 IPs (203.0.113.x) — never real public IPs.
   */

  const analysisWithLongPayload: import('../api/types').DetailedAnalysis = {
    ...DETAILED_ANALYSIS_FIXTURE,
    detections: [
      {
        timestamp: '2026-06-04T10:00:00Z',
        source_type: 'suricata',
        category: 'SQL Injection',
        sid: '2001219',
        signature: 'ET SCAN Potential VNC Scan',
        // Very long payload that would cause overflow without width constraint.
        payload_snippet:
          'GET /api/users?id=1+OR+1%3D1+--+UNION+SELECT+username%2Cpassword+FROM+users--&token=aaabbbccc&extra=aaabbbccc&x=longpadding',
      },
    ],
  }

  it('#353 EARS-1: payload <td> has overflow:hidden so long payloads do not overflow the panel', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithLongPayload)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('203.0.113.1')
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    const payloadCell = screen.getByTestId('recent-log-payload-cell')
    // overflow:hidden prevents the cell from expanding past its constrained width.
    expect(payloadCell).toHaveStyle({ overflow: 'hidden' })
  })

  it('#353 EARS-1: payload <td> has a maxWidth so the column is fixed-width', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithLongPayload)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('203.0.113.1')
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    const payloadCell = screen.getByTestId('recent-log-payload-cell')
    // maxWidth constrains the cell to a fixed width (matches LogsTable column discipline).
    const style = payloadCell.getAttribute('style') ?? ''
    expect(style).toContain('max-width')
  })

  it('#353 EARS-1: the Recent Logs table has tableLayout:fixed (like LogsTable)', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithLongPayload)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('203.0.113.1')
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    // The table inside the recent-logs section must use tableLayout:fixed
    // so column widths are clamped even without explicit <col> widths.
    const logsSection = screen.getByTestId('modal-recent-logs')
    const table = logsSection.querySelector('table')
    expect(table).not.toBeNull()
    expect(table!.style.tableLayout).toBe('fixed')
  })

  it('#353 EARS-1: the Recent Logs table wrapper has overflowX:auto (like LogsTable outer div)', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithLongPayload)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('203.0.113.1')
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    // The wrapper div must have overflowX:auto — this is the only way to allow a
    // horizontal scrollbar on the table itself rather than on the panel.
    const logsSection = screen.getByTestId('modal-recent-logs')
    const table = logsSection.querySelector('table')
    // The wrapper div is the table's parentElement.
    const wrapper = table?.parentElement
    expect(wrapper).not.toBeNull()
    expect(wrapper!.style.overflowX).toBe('auto')
  })

  it('#353 EARS-2: full payload text is still reachable via PayloadCellTooltip (data-truncated span present)', async () => {
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithLongPayload)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('203.0.113.1')
    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    // PayloadCellTooltip must still be present so the full value is reachable via popover.
    const logsSection = screen.getByTestId('modal-recent-logs')
    expect(logsSection.querySelector('span[data-truncated]')).not.toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Issue #45 (ADR-0072 D6 O-1) — False Positive on the detection row
//
// The button targets a RULE, not the actor: it must only appear when the raw
// stored event carries a `rule_name` identity (the same field the server's
// `qualifying_rules` suppression evaluator reads), and it must call
// recordFalsePositive(ip, rule_name) — NOT the rule-catalog display name.
// ---------------------------------------------------------------------------

describe('IpPanel #45 — False Positive on the detection row (ADR-0072 D6 O-1)', () => {
  it('renders a False Positive button on a detection row that carries rule_name', async () => {
    const analysisWithRuleName: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'suricata',
          category: 'SQL Injection',
          sid: '2001219',
          rule_name: 'waf_sqli',
          signature: 'ET SCAN Potential VNC Scan',
          payload_snippet: 'GET /api/users?id=1 OR 1=1',
        },
      ],
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithRuleName)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')

    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    expect(screen.getByTestId('false-positive-button-0')).toBeInTheDocument()
  })

  it('does NOT render a False Positive button on a detection row with no rule_name (fail-toward-visibility, ADR-0072)', async () => {
    const analysisNoRuleName: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'suricata',
          category: 'SQL Injection',
          sid: '2001219',
          signature: 'ET SCAN Potential VNC Scan',
          payload_snippet: 'GET /api/users?id=1 OR 1=1',
        },
      ],
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisNoRuleName)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')

    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    expect(screen.queryByTestId('false-positive-button-0')).toBeNull()
  })

  it('clicking False Positive POSTs /decisions with {actor_ip: ip, verb: "false_positive", rule_name} — the RAW event rule_name, not the catalog display name', async () => {
    const analysisWithRuleName: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'suricata',
          category: 'SQL Injection',
          sid: '2001219',
          rule_name: 'waf_sqli',
          signature: 'ET SCAN Potential VNC Scan',
          payload_snippet: 'GET /api/users?id=1 OR 1=1',
        },
      ],
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithRuleName)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')

    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    await userEvent.click(screen.getByTestId('false-positive-button-0'))

    expect(mockCreateDecision).toHaveBeenCalledOnce()
    expect(mockCreateDecision).toHaveBeenCalledWith({
      actor_ip: '192.0.2.1',
      verb: 'false_positive',
      rule_name: 'waf_sqli',
    })
  })

  it('shows a local "Reported" confirmation after clicking (no server round-trip needed to render feedback)', async () => {
    const analysisWithRuleName: import('../api/types').DetailedAnalysis = {
      ...DETAILED_ANALYSIS_FIXTURE,
      detections: [
        {
          timestamp: '2026-06-04T10:00:00Z',
          source_type: 'suricata',
          rule_name: 'waf_sqli',
          sid: '2001219',
        },
      ],
    }
    mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis.mockResolvedValue(analysisWithRuleName)
    mockFetchRules.mockResolvedValue(RULES_FIXTURE)
    renderPanel('192.0.2.1')

    await waitFor(() => expect(screen.getByTestId('modal-recent-logs')).toBeInTheDocument())
    const button = screen.getByTestId('false-positive-button-0')
    await userEvent.click(button)

    expect(button).toHaveTextContent('Reported')
    expect(button).toBeDisabled()
  })
})
