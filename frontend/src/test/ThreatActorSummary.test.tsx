/**
 * Tests for ThreatActorSummary — merged top-actor block (issue #207).
 *
 * EARS acceptance criteria covered:
 *
 *   EARS-1 (ADR-0035): No dashboard pane titled "AI …" SHALL contain zero
 *     AI-derived content. Title is always "Threat summary", never "AI…".
 *
 *   EARS-2 (ADR-0035): Rule-templated summaries SHALL carry a RULE chip
 *     and a non-AI title.
 *
 *   EARS-3 (ADR-0035): WHEN ai_status != ok, the block SHALL render the
 *     degraded wording and confidence "n/a (AI off)".
 *
 *   Issue #93 (fast-follow to #41 / ADR-0066): the degraded wording tone/text
 *   differentiates WHY — health.ai='unreachable' (a real fault) renders
 *   attention-worthy amber (AI_STATUS_COPY.unreachable); health.ai='disabled'
 *   (a deliberate choice) renders the neutral RULES_ONLY_DEGRADED_WORDING. The
 *   two are never collapsed into the same treatment.
 *
 *   EARS-4 (ADR-0036): Scores SHALL render via ScoreBadge (banded: "Risk N · BAND").
 *     Confidence SHALL never render as a percentage.
 *
 *   EARS-5 (ADR-0035): Both AiPanel and AiSidebar AI summary card SHALL no
 *     longer both render. Only ThreatActorSummary renders (one block).
 *
 *   EARS-6 (ADR-0035 §4): WHEN AI offline, pane body shows the standard
 *     degraded wording (the global chip is elsewhere — this is the in-pane signal).
 *
 *   EARS-7 (Security): WHEN the analyst clicks the AI chip area in the
 *     block, the inference host SHALL NOT be rendered.
 *
 *   EARS-8 (ADR-0035 §1): ProvenanceChip derivation comes from score_derivation
 *     when present; falls back to "rule" (conservative) when absent.
 *
 * Also covers:
 *   - No render when threats=[] (non-fatal, ADR-0015).
 *   - ClickableIp rendered for the top actor IP (ADR-0037).
 *   - AI insights section only present when AI ran AND insights exist.
 *   - Insights section carries its own AI chip (those items ARE AI-authored).
 *   - Score breakdown popover trigger shown when breakdown available (ADR-0036 D3).
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import ThreatActorSummary from '../components/dashboard/ThreatActorSummary'
import { EntityPanelContext } from '../components/entity/EntityPanelContext'
import type { EntityPanelContextValue } from '../components/entity/EntityPanelContext'
import type { ThreatScore, HealthResponse } from '../api/types'
import { RULES_ONLY_DEGRADED_WORDING } from '../lib/provenance'
import { AI_STATUS_COPY } from '../components/aiStatusCopy'

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function makeThreat(overrides: Partial<ThreatScore> = {}): ThreatScore {
  return {
    source_ip: '192.0.2.1',
    threat_level: 'HIGH',
    score: 78,
    total_events: 100,
    blocked_events: 80,
    attack_types: ['SQL Injection'],
    first_seen: '2026-06-01T08:00:00Z',
    last_seen: '2026-06-04T09:55:00Z',
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
    ...overrides,
  }
}

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

/** Deliberately disabled (ai_enabled=false) — neutral, non-alarming (issue #93). */
const HEALTH_DISABLED: HealthResponse = {
  status: 'ok',
  ollama_connected: false,
  ollama_model: null,
  db_ok: true,
  ai: 'disabled',
}

/**
 * Render with EntityPanelContext directly (pattern from TriageBanner.test.tsx).
 * Avoids needing EntityPanelProvider (which tries to mount the full SlideOver).
 */
function renderSummary(
  threats: ThreatScore[],
  health?: HealthResponse | null,
) {
  const ctx: EntityPanelContextValue = {
    stack: [],
    openEntity: vi.fn(),
    closeEntity: vi.fn(),
    closePanelAll: vi.fn(),
  }
  return render(
    <MemoryRouter>
      <EntityPanelContext.Provider value={ctx}>
        <ThreatActorSummary threats={threats} health={health} />
      </EntityPanelContext.Provider>
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// EARS-1 & EARS-2: title is always "Threat summary", never "AI…" title
// ---------------------------------------------------------------------------

describe('ThreatActorSummary — title honesty (EARS-1, EARS-2, ADR-0035 §3)', () => {
  it('title is "Threat summary" when AI is offline (EARS-1: no AI content → no AI title)', () => {
    const threats = [makeThreat({ ai_status: 'disabled' })]
    renderSummary(threats, HEALTH_OFFLINE)
    expect(screen.getByTestId('tas-title')).toHaveTextContent('Threat summary')
    // Never "AI…"
    expect(screen.getByTestId('tas-title').textContent).not.toContain('AI')
  })

  it('title is "Threat summary" even when AI ran (EARS-2: non-AI title always)', () => {
    const threats = [makeThreat({
      ai_status: 'active',
      ai_insights: ['Some AI insight'],
      ai_confidence: 0.85,
    })]
    renderSummary(threats, HEALTH_ONLINE)
    expect(screen.getByTestId('tas-title')).toHaveTextContent('Threat summary')
    expect(screen.getByTestId('tas-title').textContent).not.toContain('AI threat summary')
  })

  it('renders nothing when threats=[] (non-fatal, ADR-0015)', () => {
    const { container } = renderSummary([], HEALTH_ONLINE)
    expect(container.firstChild).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// EARS-2: RULE chip when ai_status != ok
// ---------------------------------------------------------------------------

describe('ThreatActorSummary — RULE provenance chip (EARS-2, ADR-0035)', () => {
  it('renders ProvenanceChip with data-testid tas-provenance-chip', () => {
    const threats = [makeThreat({ ai_status: 'unavailable' })]
    renderSummary(threats, HEALTH_OFFLINE)
    expect(screen.getByTestId('tas-provenance-chip')).toBeInTheDocument()
  })

  it('RULE chip when health is offline (rule-only state)', () => {
    const threats = [makeThreat({ ai_status: 'unavailable' })]
    renderSummary(threats, HEALTH_OFFLINE)
    // data-derivation="rule" → renders RULE
    const chip = screen.getByTestId('tas-provenance-chip')
    expect(chip.getAttribute('data-derivation')).toBe('rule')
    expect(chip).toHaveTextContent('RULE')
  })

  it('RULE chip when no score_derivation field (conservative fallback per ADR-0035 §1)', () => {
    // Even if AI is online, without score_derivation we cannot assert the boost ran
    const threats = [makeThreat({ ai_status: 'active' })]
    renderSummary(threats, HEALTH_ONLINE)
    const chip = screen.getByTestId('tas-provenance-chip')
    // No score_derivation → falls back to 'rule'
    expect(chip.getAttribute('data-derivation')).toBe('rule')
  })

  it('AI+RULE chip when score_derivation="ai+rule" is provided by the backend (EARS-8)', () => {
    const threats = [makeThreat({
      ai_status: 'active',
      // score_derivation is an additive field not yet in the TS type but we can cast
      ...(({ score_derivation: 'ai+rule' } as unknown) as Partial<ThreatScore>),
    })]
    renderSummary(threats, HEALTH_ONLINE)
    const chip = screen.getByTestId('tas-provenance-chip')
    expect(chip.getAttribute('data-derivation')).toBe('ai+rule')
    expect(chip).toHaveTextContent('AI+RULE')
  })
})

// ---------------------------------------------------------------------------
// EARS-3: AI offline degraded wording + n/a confidence
// ---------------------------------------------------------------------------

describe('ThreatActorSummary — AI offline degraded state (EARS-3, ADR-0035 §4)', () => {
  // Issue #93: health.ai='unreachable' is a real fault — attention-worthy amber,
  // distinct wording (AI_STATUS_COPY.unreachable), never the neutral collapsed text.
  it('shows AI_STATUS_COPY.unreachable (amber) when health.ai=unreachable', () => {
    const threats = [makeThreat({ ai_status: 'unavailable' })]
    renderSummary(threats, HEALTH_OFFLINE)
    const wording = screen.getByTestId('tas-degraded-wording')
    expect(wording).toHaveTextContent(AI_STATUS_COPY.unreachable)
    expect(wording.style.color).toBe('var(--soc-watch-fg)')
  })

  // Issue #93: health.ai='disabled' is a deliberate choice — neutral, non-alarming.
  it('shows RULES_ONLY_DEGRADED_WORDING (neutral) when health.ai=disabled', () => {
    const threats = [makeThreat({ ai_status: 'disabled' })]
    renderSummary(threats, HEALTH_DISABLED)
    const wording = screen.getByTestId('tas-degraded-wording')
    expect(wording).toHaveTextContent(RULES_ONLY_DEGRADED_WORDING)
    expect(wording.style.color).toBe('var(--fw-t3)')
  })

  // Issue #93: never collapse unreachable and disabled into the same treatment.
  it('never collapses unreachable and disabled into the same treatment', () => {
    const threats = [makeThreat({ ai_status: 'unavailable' })]
    const { unmount } = renderSummary(threats, HEALTH_OFFLINE)
    const unreachableWording = screen.getByTestId('tas-degraded-wording')
    const unreachableColor = unreachableWording.style.color
    const unreachableText = unreachableWording.textContent
    unmount()

    renderSummary([makeThreat({ ai_status: 'disabled' })], HEALTH_DISABLED)
    const disabledWording = screen.getByTestId('tas-degraded-wording')
    expect(disabledWording.style.color).not.toBe(unreachableColor)
    expect(disabledWording.textContent).not.toBe(unreachableText)
  })

  it('shows RULES_ONLY_DEGRADED_WORDING when health=null and ai_status=disabled', () => {
    const threats = [makeThreat({ ai_status: 'disabled' })]
    renderSummary(threats, null) // health=null, falls back to ai_status
    expect(screen.getByTestId('tas-degraded-wording')).toBeInTheDocument()
  })

  it('does NOT show degraded wording when AI is active', () => {
    const threats = [makeThreat({
      ai_status: 'active',
      ai_insights: ['Insight text'],
      ai_confidence: 0.85,
    })]
    renderSummary(threats, HEALTH_ONLINE)
    expect(screen.queryByTestId('tas-degraded-wording')).not.toBeInTheDocument()
  })

  it('shows confidence "n/a (AI off)" when AI is offline (ADR-0036 D2 — never a percentage)', () => {
    const threats = [makeThreat({ ai_status: 'disabled', ai_confidence: 0.0 })]
    renderSummary(threats, HEALTH_OFFLINE)
    const confLabel = screen.getByTestId('tas-confidence-label')
    // Confidence rendered via ConfidenceLabel — shows "n/a (AI off)", never "0%"
    expect(confLabel).toHaveTextContent('n/a (AI off)')
    expect(confLabel.textContent).not.toContain('%')
  })
})

// ---------------------------------------------------------------------------
// EARS-4: banded score (ScoreBadge), confidence as word (ConfidenceLabel)
// ---------------------------------------------------------------------------

describe('ThreatActorSummary — banded score + word confidence (EARS-4, ADR-0036)', () => {
  it('renders ScoreBadge via tas-score-badge testid', () => {
    const threats = [makeThreat({ score: 78, threat_level: 'HIGH' })]
    renderSummary(threats, HEALTH_OFFLINE)
    expect(screen.getByTestId('tas-score-badge')).toBeInTheDocument()
  })

  it('ScoreBadge shows "Risk 78 · HIGH" (banded, not naked score)', () => {
    const threats = [makeThreat({ score: 78, threat_level: 'HIGH' })]
    renderSummary(threats, HEALTH_OFFLINE)
    const badge = screen.getByTestId('tas-score-badge')
    expect(badge.textContent).toContain('Risk')
    expect(badge.textContent).toContain('78')
    expect(badge.textContent).toContain('HIGH')
  })

  it('ScoreBadge shows "Risk 100 · CRITICAL" for CRITICAL score', () => {
    const threats = [makeThreat({ score: 100, threat_level: 'CRITICAL' })]
    renderSummary(threats, HEALTH_OFFLINE)
    const badge = screen.getByTestId('tas-score-badge')
    expect(badge.textContent).toContain('100')
    expect(badge.textContent).toContain('CRITICAL')
  })

  it('NEVER renders naked score without band (EARS-4)', () => {
    const threats = [makeThreat({ score: 100, threat_level: 'CRITICAL' })]
    renderSummary(threats, HEALTH_OFFLINE)
    // The badge MUST contain "Risk" prefix — not just the bare number
    const badge = screen.getByTestId('tas-score-badge')
    expect(badge.textContent).toContain('Risk')
  })

  it('renders High confidence when AI active and ai_confidence=0.85', () => {
    const threats = [makeThreat({
      ai_status: 'active',
      ai_confidence: 0.85,
    })]
    renderSummary(threats, HEALTH_ONLINE)
    const confLabel = screen.getByTestId('tas-confidence-label')
    expect(confLabel).toHaveTextContent('High')
    expect(confLabel.textContent).not.toContain('%')
  })

  it('renders Medium confidence when ai_confidence=0.5', () => {
    const threats = [makeThreat({
      ai_status: 'active',
      ai_confidence: 0.5,
    })]
    renderSummary(threats, HEALTH_ONLINE)
    expect(screen.getByTestId('tas-confidence-label')).toHaveTextContent('Medium')
  })

  it('renders "n/a (AI off)" when ai_confidence is null and AI offline', () => {
    const threats = [makeThreat({ ai_status: 'unavailable', ai_confidence: null })]
    renderSummary(threats, HEALTH_OFFLINE)
    expect(screen.getByTestId('tas-confidence-label')).toHaveTextContent('n/a (AI off)')
  })

  it('score breakdown popover trigger is NOT shown when score_breakdown=[] (graceful degradation)', () => {
    const threats = [makeThreat({ score_breakdown: [] })]
    renderSummary(threats, HEALTH_OFFLINE)
    // No "?" trigger without breakdown items
    expect(screen.queryByRole('button', { name: 'Why this score?' })).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-5: only ThreatActorSummary renders — AiPanel and AiSidebar AI summary gone
// ---------------------------------------------------------------------------

describe('ThreatActorSummary — single merged block (EARS-5)', () => {
  it('renders threat-actor-summary testid (single merged block)', () => {
    const threats = [makeThreat()]
    renderSummary(threats, HEALTH_OFFLINE)
    // One block
    expect(screen.getAllByTestId('threat-actor-summary')).toHaveLength(1)
  })

  it('does NOT render the old ai-panel testid', () => {
    const threats = [makeThreat()]
    renderSummary(threats, HEALTH_OFFLINE)
    expect(screen.queryByTestId('ai-panel')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// AI insights section (AI-authored content gets AI chip)
// ---------------------------------------------------------------------------

describe('ThreatActorSummary — AI insights section', () => {
  it('does NOT render insights section when AI is offline', () => {
    const threats = [makeThreat({
      ai_status: 'unavailable',
      ai_insights: ['Some cached insight from a previous run'],
    })]
    renderSummary(threats, HEALTH_OFFLINE)
    expect(screen.queryByTestId('tas-ai-insights-section')).not.toBeInTheDocument()
  })

  it('renders insights section when AI active and insights present', () => {
    const threats = [makeThreat({
      ai_status: 'active',
      ai_insights: ['Intent: reconnaissance', 'Risk: lateral movement'],
      ai_confidence: 0.85,
    })]
    renderSummary(threats, HEALTH_ONLINE)
    expect(screen.getByTestId('tas-ai-insights-section')).toBeInTheDocument()
    expect(screen.getByTestId('tas-insights-list')).toBeInTheDocument()
    // Two insight items
    const items = screen.getAllByRole('listitem')
    expect(items).toHaveLength(2)
    expect(items[0]).toHaveTextContent('Intent: reconnaissance')
    expect(items[1]).toHaveTextContent('Risk: lateral movement')
  })

  it('insights sub-section carries an AI chip (those items ARE AI-authored, ADR-0035 §1)', () => {
    const threats = [makeThreat({
      ai_status: 'active',
      ai_insights: ['Intent: data exfiltration'],
      ai_confidence: 0.92,
    })]
    renderSummary(threats, HEALTH_ONLINE)
    const insightsChip = screen.getByTestId('tas-insights-chip')
    expect(insightsChip).toBeInTheDocument()
    expect(insightsChip.getAttribute('data-derivation')).toBe('ai')
    expect(insightsChip).toHaveTextContent('AI')
  })

  it('does NOT render insights section when ai_insights=null', () => {
    const threats = [makeThreat({
      ai_status: 'active',
      ai_insights: null,
    })]
    renderSummary(threats, HEALTH_ONLINE)
    expect(screen.queryByTestId('tas-ai-insights-section')).not.toBeInTheDocument()
  })

  it('does NOT render insights section when ai_insights=[] (empty array)', () => {
    const threats = [makeThreat({
      ai_status: 'active',
      ai_insights: [],
    })]
    renderSummary(threats, HEALTH_ONLINE)
    expect(screen.queryByTestId('tas-ai-insights-section')).not.toBeInTheDocument()
  })

  it('renders insights as plain text nodes (XSS safe — ADR-0029 D3)', () => {
    const threats = [makeThreat({
      ai_status: 'active',
      ai_insights: ['<script>alert("xss")</script>'],
      ai_confidence: 0.8,
    })]
    renderSummary(threats, HEALTH_ONLINE)
    const list = screen.getByTestId('tas-insights-list')
    // Script tag must NOT be injected as a DOM element
    expect(list.querySelector('script')).toBeNull()
    // The text content should contain the literal string
    expect(list.textContent).toContain('<script>')
  })
})

// ---------------------------------------------------------------------------
// EARS-6: health=null fallback (health in-flight)
// ---------------------------------------------------------------------------

describe('ThreatActorSummary — health=null fallback', () => {
  it('falls back to top.ai_status when health=null and ai_status=active', () => {
    // health=null (in-flight) → falls back to ai_status='active'
    const threats = [makeThreat({
      ai_status: 'active',
      ai_insights: ['Insight from active run'],
      ai_confidence: 0.8,
    })]
    renderSummary(threats, null) // health=null
    // AI is considered active → insights visible, no degraded wording
    expect(screen.getByTestId('tas-ai-insights-section')).toBeInTheDocument()
    expect(screen.queryByTestId('tas-degraded-wording')).not.toBeInTheDocument()
  })

  it('shows degraded wording when health=null and ai_status=unavailable', () => {
    const threats = [makeThreat({ ai_status: 'unavailable' })]
    renderSummary(threats, null) // health=null → ai_status fallback
    expect(screen.getByTestId('tas-degraded-wording')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Summary text and ClickableIp
// ---------------------------------------------------------------------------

describe('ThreatActorSummary — summary text and ClickableIp', () => {
  it('renders the summary text section', () => {
    const threats = [makeThreat()]
    renderSummary(threats, HEALTH_OFFLINE)
    expect(screen.getByTestId('tas-summary-text')).toBeInTheDocument()
  })

  it('renders the top actor IP via ClickableIp (data-testid="clickable-ip")', () => {
    const threats = [makeThreat({ source_ip: '192.0.2.42' })]
    renderSummary(threats, HEALTH_OFFLINE)
    // ClickableIp renders a button with the IP text
    const ipButton = screen.getByTestId('clickable-ip')
    expect(ipButton).toBeInTheDocument()
    expect(ipButton).toHaveTextContent('192.0.2.42')
  })

  it('picks the top-scored actor when multiple threats exist', () => {
    const threats = [
      makeThreat({ source_ip: '192.0.2.1', score: 50, threat_level: 'MEDIUM' }),
      makeThreat({ source_ip: '192.0.2.99', score: 95, threat_level: 'CRITICAL' }),
    ]
    renderSummary(threats, HEALTH_OFFLINE)
    // The top IP (192.0.2.99) should appear in the ClickableIp
    expect(screen.getByTestId('clickable-ip')).toHaveTextContent('192.0.2.99')
    // CRITICAL badge shown (top actor's band)
    expect(screen.getByTestId('tas-score-badge').textContent).toContain('CRITICAL')
  })

  it('renders attack types in the summary text', () => {
    const threats = [makeThreat({ attack_types: ['SQL Injection', 'Scanner'] })]
    renderSummary(threats, HEALTH_OFFLINE)
    const text = screen.getByTestId('tas-summary-text').textContent ?? ''
    expect(text).toContain('SQL Injection')
  })

  it('renders critical count when CRITICAL actors exist', () => {
    const threats = [
      makeThreat({ source_ip: '192.0.2.1', threat_level: 'CRITICAL', score: 90 }),
      makeThreat({ source_ip: '192.0.2.2', threat_level: 'HIGH', score: 70 }),
    ]
    renderSummary(threats, HEALTH_OFFLINE)
    const text = screen.getByTestId('tas-summary-text').textContent ?? ''
    expect(text).toContain('critical')
  })
})

// ---------------------------------------------------------------------------
// Security: inference host NEVER rendered (PR #191 topology-leak posture)
// ---------------------------------------------------------------------------

describe('ThreatActorSummary — security: no topology leak', () => {
  it('does not render the inference endpoint host anywhere', () => {
    const threats = [makeThreat({
      ai_status: 'active',
      ai_insights: ['Intent: recon'],
      ai_confidence: 0.8,
    })]
    const { container } = renderSummary(threats, {
      ...HEALTH_ONLINE,
      // Even if health had a host field (it doesn't, by design), it must not appear
    })
    // No URL patterns should be in the rendered output
    const html = container.innerHTML
    expect(html).not.toMatch(/https?:\/\/.*\/v1/)
    expect(html).not.toMatch(/localhost:\d{4}/)
    expect(html).not.toMatch(/127\.0\.0\.1:\d{4}/)
  })
})
