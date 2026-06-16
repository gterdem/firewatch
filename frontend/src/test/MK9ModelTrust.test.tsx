/**
 * Tests for MK-9 — Model Trust panel: verdict-drift report (issue #414, ADR-0043 D3).
 *
 * EARS criteria covered:
 *
 * EARS-MK9-1: WHEN drift report exists → DriftPanel shows headline (two models, run_at,
 *             changed/total, escalations/de-escalations).
 * EARS-MK9-2: WHEN drift report exists → bounded diff list rendered (DriftDiffRow per diff).
 * EARS-MK9-3: WHEN diff row expanded → side-by-side DriftDiffDetail shows baseline-vs-candidate
 *             verdict, ConfidenceLabel (banded), and summary prose.
 * EARS-MK9-4: WHEN diff row expanded → both sides carry an AI ProvenanceChip with authoring
 *             model named beside it (ADR-0035 model identity provenance).
 * EARS-MK9-5: WHEN no baseline (GET /ai/baseline returns {exists:false}) → honest empty state
 *             with "firewatch ai-baseline --save" and "firewatch ai-baseline --compare" CLI commands.
 * EARS-MK9-6: WHEN baseline exists but no comparison run (GET /ai/baseline/drift returns 404) →
 *             pane shows baseline metadata (scenario_count) + "--compare" instruction.
 * EARS-MK9-7: WHEN drift report returns 422 → error message shown with "--compare" re-run hint.
 * EARS-MK9-8: DriftDiffRow is keyboard-focusable and aria-expanded toggles on click (WCAG 2.1.1).
 * EARS-MK9-9: Changed/total count uses honest numbers from the API only (no fabricated numbers).
 * EARS-MK9-10: Scenarios described as "synthetic baseline scenarios" (not production verdicts).
 * EARS-MK9-11: DriftPanel mounts in AIRoute as the last block (ADR-0043 D3 page block 4).
 * EARS-MK9-12: WHEN no changes (changed=0) → "no verdict changes detected" message shown.
 *
 * Security:
 *   - All model IDs, scenario names, verdicts, summary prose rendered as text nodes only
 *     (ADR-0029 D3 — no dangerouslySetInnerHTML).
 *   - IP addresses in fixtures use RFC 5737 range (192.0.2.x) — gitleaks compliant.
 *
 * Fixture integrity: only RFC 5737 IPs (192.0.2.x, 198.51.100.x) — no real public IPs.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

// ---------------------------------------------------------------------------
// Fixtures — RFC 5737 IPs only; no real public IPs (gitleaks)
// ---------------------------------------------------------------------------

import type { BaselineStatus, DriftReport, DriftDiff } from '../api/types'

/** GET /ai/baseline — no baseline saved */
const BASELINE_NOT_EXISTS: BaselineStatus = { exists: false }

/** GET /ai/baseline — baseline saved, metadata available */
const BASELINE_EXISTS: Extract<BaselineStatus, { exists: true }> = {
  exists: true,
  model: 'llama3.2',
  saved_at: '2026-06-10T12:00:00Z',
  scenario_count: 25,
}

/** One diff entry — escalation (HIGH → CRITICAL) */
const DIFF_ESCALATION: DriftDiff = {
  scenario: 'concise_waf_no_corr',
  baseline_verdict: 'HIGH',
  candidate_verdict: 'CRITICAL',
  baseline_confidence: 0.85,
  candidate_confidence: 0.9,
  baseline_summary: 'block',
  candidate_summary: 'block',
}

/** One diff entry — de-escalation (CRITICAL → HIGH) */
const DIFF_DEESCALATION: DriftDiff = {
  scenario: 'suricata_port_scan',
  baseline_verdict: 'CRITICAL',
  candidate_verdict: 'HIGH',
  baseline_confidence: 0.9,
  candidate_confidence: 0.7,
  baseline_summary: 'block',
  candidate_summary: 'monitor',
}

/** GET /ai/baseline/drift — drift report with 2 changes */
const DRIFT_REPORT: DriftReport = {
  baseline_model: 'llama3.2',
  candidate_model: 'qwen3:14b',
  run_at: '2026-06-12T14:00:00Z',
  scenarios: 25,
  changed: 2,
  escalations: 1,
  deescalations: 1,
  diffs: [DIFF_ESCALATION, DIFF_DEESCALATION],
}

/** GET /ai/baseline/drift — report with no changes */
const DRIFT_REPORT_NO_CHANGES: DriftReport = {
  baseline_model: 'llama3.2',
  candidate_model: 'llama3.2',
  run_at: '2026-06-12T14:00:00Z',
  scenarios: 25,
  changed: 0,
  escalations: 0,
  deescalations: 0,
  diffs: [],
}

// ---------------------------------------------------------------------------
// Mock setup — api/client
// ---------------------------------------------------------------------------

const {
  mockFetchBaselineStatus,
  mockFetchDriftReport,
  mockFetchThreats,
  mockFetchHealth,
  mockFetchAnalyses,
  mockFetchFeedbackSummary,
} = vi.hoisted(() => ({
  mockFetchBaselineStatus: vi.fn(),
  mockFetchDriftReport: vi.fn(),
  mockFetchThreats: vi.fn().mockResolvedValue([]),
  mockFetchHealth: vi.fn().mockResolvedValue({
    status: 'ok',
    ollama_connected: true,
    ollama_model: 'llama3.2',
    db_ok: true,
  }),
  mockFetchAnalyses: vi.fn().mockResolvedValue({ items: [], next_cursor: null, has_more: false }),
  // AgreementStat (MK-6) calls this; default to null (503 degrade, renders nothing)
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
    ApiError,
    fetchBaselineStatus: mockFetchBaselineStatus,
    fetchDriftReport: mockFetchDriftReport,
    fetchThreats: mockFetchThreats,
    fetchHealth: mockFetchHealth,
    fetchAnalyses: mockFetchAnalyses,
    // MK-6: AgreementStat calls this; default to null (503 degrade, renders nothing)
    fetchFeedbackSummary: mockFetchFeedbackSummary,
    // EntityPanelProvider fetches discovery cache on mount (non-fatal)
    fetchSourceTypes: vi.fn().mockResolvedValue([]),
    // Passthrough for loopback guard helpers
    assertLoopbackBase: vi.fn(),
    resolveBaseUrl: vi.fn(() => ''),
  }
})

// IpPanel fetches — mock to avoid real network calls in tests
vi.mock('../api/logs', () => ({
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
}))

// ---------------------------------------------------------------------------
// Component imports (after mock setup)
// ---------------------------------------------------------------------------

import { DriftPanel } from '../components/ai/drift/DriftPanel'
import { DriftDiffRow } from '../components/ai/drift/DriftDiffRow'
import { driftDirection, scenarioLabel, diffStorySentence } from '../components/ai/drift/driftUtils'
import { DriftDiffDetail } from '../components/ai/drift/DriftDiffDetail'
import AIRoute from '../routes/AIRoute'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderDriftPanel() {
  return render(
    <MemoryRouter>
      <DriftPanel />
    </MemoryRouter>,
  )
}

function renderAIRoute() {
  return render(
    <MemoryRouter>
      <EntityPanelProvider>
        <AIRoute />
      </EntityPanelProvider>
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DriftDiffDetail (unit)', () => {
  it('renders both sides with AI chips and model names (ADR-0035)', () => {
    render(
      <DriftDiffDetail
        diff={DIFF_ESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
      />,
    )

    // Both sides present
    expect(screen.getByTestId('drift-diff-baseline')).toBeInTheDocument()
    expect(screen.getByTestId('drift-diff-candidate')).toBeInTheDocument()

    // EARS-MK9-4: AI chips on both sides (ADR-0035)
    const chips = screen.getAllByTestId(/drift-diff-(baseline|candidate)-chip/)
    expect(chips).toHaveLength(2)
    chips.forEach((chip) => {
      expect(chip).toHaveAttribute('data-derivation', 'ai')
    })

    // Model names beside the chips
    expect(screen.getByTestId('drift-diff-baseline-model')).toHaveTextContent('llama3.2')
    expect(screen.getByTestId('drift-diff-candidate-model')).toHaveTextContent('qwen3:14b')
  })

  it('renders verdicts as text nodes (ADR-0029 D3)', () => {
    render(
      <DriftDiffDetail
        diff={DIFF_ESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
      />,
    )

    expect(screen.getByTestId('drift-diff-baseline-verdict')).toHaveTextContent('HIGH')
    expect(screen.getByTestId('drift-diff-candidate-verdict')).toHaveTextContent('CRITICAL')
  })

  it('renders ConfidenceLabel (banded) on both sides (ADR-0036)', () => {
    render(
      <DriftDiffDetail
        diff={DIFF_ESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
      />,
    )

    // ConfidenceLabel components (role="status" from the component)
    const confidenceLabels = screen.getAllByTestId(/drift-diff-(baseline|candidate)-confidence/)
    expect(confidenceLabels).toHaveLength(2)
    // Both have confidence values set (non-null)
    confidenceLabels.forEach((label) => {
      expect(label).toHaveAttribute('data-confidence-raw')
      // Should not be 'null' since both diffs have confidence values
      expect(label.getAttribute('data-confidence-raw')).not.toBe('null')
    })
  })

  it('renders summary prose as text nodes (ADR-0029 D3)', () => {
    render(
      <DriftDiffDetail
        diff={DIFF_ESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
      />,
    )

    expect(screen.getByTestId('drift-diff-baseline-summary')).toHaveTextContent('block')
    expect(screen.getByTestId('drift-diff-candidate-summary')).toHaveTextContent('block')
  })
})

describe('DriftDiffRow (unit)', () => {
  it('renders collapsed by default with scenario name and verdicts', () => {
    render(
      <DriftDiffRow
        diff={DIFF_ESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    expect(screen.getByTestId('drift-diff-scenario')).toHaveTextContent('concise_waf_no_corr')
    expect(screen.getByTestId('drift-diff-baseline-badge')).toHaveTextContent('HIGH')
    expect(screen.getByTestId('drift-diff-candidate-badge')).toHaveTextContent('CRITICAL')
    // Detail not visible initially
    expect(screen.queryByTestId('drift-diff-detail')).not.toBeInTheDocument()
  })

  it('EARS-MK9-8: toggle button has aria-expanded=false initially', () => {
    render(
      <DriftDiffRow
        diff={DIFF_ESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    const toggle = screen.getByTestId('drift-diff-toggle')
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
  })

  it('EARS-MK9-3 + EARS-MK9-8: clicking row expands detail and toggles aria-expanded', () => {
    render(
      <DriftDiffRow
        diff={DIFF_ESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    const toggle = screen.getByTestId('drift-diff-toggle')
    fireEvent.click(toggle)

    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByTestId('drift-diff-detail')).toBeInTheDocument()
  })

  it('EARS-MK9-3 + EARS-MK9-4: expanded detail shows both AI chips with model names', () => {
    render(
      <DriftDiffRow
        diff={DIFF_ESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    fireEvent.click(screen.getByTestId('drift-diff-toggle'))

    const chips = screen.getAllByTestId(/drift-diff-(baseline|candidate)-chip/)
    expect(chips).toHaveLength(2)
    chips.forEach((chip) => {
      expect(chip).toHaveAttribute('data-derivation', 'ai')
    })

    expect(screen.getByTestId('drift-diff-baseline-model')).toHaveTextContent('llama3.2')
    expect(screen.getByTestId('drift-diff-candidate-model')).toHaveTextContent('qwen3:14b')
  })

  it('EARS-MK9-8: toggle button is keyboard-focusable (type=button, not div)', () => {
    render(
      <DriftDiffRow
        diff={DIFF_ESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    const toggle = screen.getByTestId('drift-diff-toggle')
    expect(toggle.tagName.toLowerCase()).toBe('button')
    expect(toggle).toHaveAttribute('type', 'button')
  })

  it('collapse re-hides detail on second click', () => {
    render(
      <DriftDiffRow
        diff={DIFF_ESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    const toggle = screen.getByTestId('drift-diff-toggle')
    fireEvent.click(toggle)
    expect(screen.getByTestId('drift-diff-detail')).toBeInTheDocument()

    fireEvent.click(toggle)
    expect(screen.queryByTestId('drift-diff-detail')).not.toBeInTheDocument()
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
  })
})

describe('DriftPanel — no baseline state (EARS-MK9-5)', () => {
  beforeEach(() => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_NOT_EXISTS)
    mockFetchDriftReport.mockResolvedValue(null)
  })

  it('shows honest empty state with CLI commands', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-no-baseline')).toBeInTheDocument()
    })

    // Must show both CLI commands
    expect(screen.getByText(/firewatch ai-baseline --save/)).toBeInTheDocument()
    expect(screen.getByText(/firewatch ai-baseline --compare/)).toBeInTheDocument()
  })

  it('EARS-MK9-10: describes scenarios as synthetic (not production verdicts)', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-no-baseline')).toBeInTheDocument()
    })

    expect(screen.getByText(/synthetic/i)).toBeInTheDocument()
  })

  it('does NOT show a run button (CLI-triggered per ADR-0043)', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-no-baseline')).toBeInTheDocument()
    })

    // No button except what's in the CLI code examples
    const buttons = screen.queryAllByRole('button')
    expect(buttons).toHaveLength(0)
  })
})

describe('DriftPanel — baseline-only state (EARS-MK9-6)', () => {
  beforeEach(() => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_EXISTS)
    mockFetchDriftReport.mockResolvedValue(null) // 404 → null
  })

  it('shows baseline metadata and --compare instruction', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-baseline-only')).toBeInTheDocument()
    })

    // Scenario count
    expect(screen.getByText(/25 synthetic scenarios/)).toBeInTheDocument()
    // --compare instruction
    expect(screen.getByText(/firewatch ai-baseline --compare/)).toBeInTheDocument()
  })

  it('EARS-MK9-10: scenario count from API, described as synthetic', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-baseline-only')).toBeInTheDocument()
    })

    expect(screen.getByText(/25 synthetic scenarios/)).toBeInTheDocument()
  })

  it('does NOT show a run button', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-baseline-only')).toBeInTheDocument()
    })

    const buttons = screen.queryAllByRole('button')
    expect(buttons).toHaveLength(0)
  })
})

describe('DriftPanel — drift report state (EARS-MK9-1, -2, -9)', () => {
  beforeEach(() => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_EXISTS)
    mockFetchDriftReport.mockResolvedValue(DRIFT_REPORT)
  })

  it('EARS-MK9-1: shows headline with both model names', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-headline')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-headline')).toHaveTextContent('llama3.2')
    expect(screen.getByTestId('drift-headline')).toHaveTextContent('qwen3:14b')
  })

  it('EARS-MK9-9: shows honest changed/total count from API', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-changed-count')).toBeInTheDocument()
    })

    // "2 of 25 synthetic baseline scenarios changed"
    expect(screen.getByTestId('drift-changed-count')).toHaveTextContent('2 of 25')
    expect(screen.getByTestId('drift-changed-count')).toHaveTextContent('synthetic baseline scenarios')
  })

  it('EARS-MK9-1: shows escalations count', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-escalations')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-escalations')).toHaveTextContent('1 escalation')
  })

  it('EARS-MK9-1: shows de-escalations count', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-deescalations')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-deescalations')).toHaveTextContent('1 de-escalation')
  })

  it('EARS-MK9-1: shows run_at timestamp', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-run-at')).toBeInTheDocument()
    })

    // Rendered via toLocaleString — just check it's non-empty
    expect(screen.getByTestId('drift-run-at').textContent?.length).toBeGreaterThan(0)
  })

  it('EARS-MK9-2: renders one DriftDiffRow per changed scenario', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-diff-list')).toBeInTheDocument()
    })

    const rows = screen.getAllByTestId('drift-diff-row')
    expect(rows).toHaveLength(2) // Two diffs in DRIFT_REPORT
  })

  it('EARS-MK9-10: headline describes scenarios as synthetic', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-headline')).toBeInTheDocument()
    })

    expect(screen.getByText(/synthetic baseline scenarios/)).toBeInTheDocument()
  })
})

describe('DriftPanel — no changes state (EARS-MK9-12)', () => {
  beforeEach(() => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_EXISTS)
    mockFetchDriftReport.mockResolvedValue(DRIFT_REPORT_NO_CHANGES)
  })

  it('shows "no verdict changes detected" message', async () => {
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-no-changes')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-no-changes')).toHaveTextContent(
      'No verdict changes detected',
    )
  })
})

describe('DriftPanel — error state (EARS-MK9-7)', () => {
  it('shows error message when 422 (corrupt report)', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_EXISTS)
    mockFetchDriftReport.mockRejectedValue(
      new ApiError(422, { detail: 'corrupt' }, 'API 422: corrupt'),
    )

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-error')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-error')).toHaveTextContent('--compare')
  })

  it('shows generic error message on network failure', async () => {
    mockFetchBaselineStatus.mockRejectedValue(new Error('Network error'))
    mockFetchDriftReport.mockRejectedValue(new Error('Network error'))

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-error')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-error')).toHaveTextContent('Could not load model trust data')
  })
})

describe('EARS-MK9-11: DriftPanel mounted in AIRoute as last block', () => {
  beforeEach(() => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_NOT_EXISTS)
    mockFetchDriftReport.mockResolvedValue(null)
    mockFetchThreats.mockResolvedValue([])
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.2',
      db_ok: true,
    })
    mockFetchAnalyses.mockResolvedValue({ items: [], next_cursor: null, has_more: false })
  })

  it('drift-panel testid present on the AI Engine page', async () => {
    renderAIRoute()

    await waitFor(() => {
      // Page loaded (ai-page present)
      expect(screen.getByTestId('ai-page')).toBeInTheDocument()
    })

    // DriftPanel mounted
    await waitFor(() => {
      expect(screen.getByTestId('drift-panel')).toBeInTheDocument()
    })
  })

  it('drift panel is after the verdict-cards panel (last block)', async () => {
    renderAIRoute()

    await waitFor(() => {
      expect(screen.getByTestId('drift-panel')).toBeInTheDocument()
    })

    const verdictPanel = screen.getByTestId('verdict-cards-panel')
    const driftPanel = screen.getByTestId('drift-panel')

    // document order: verdict-cards comes before drift
    const order = verdictPanel.compareDocumentPosition(driftPanel)
    // DOCUMENT_POSITION_FOLLOWING = 4 means driftPanel comes after verdictPanel
    expect(order & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })
})

describe('DriftDiffDetail — security (ADR-0029 D3)', () => {
  it('renders attacker-influenced strings as text nodes (not HTML)', () => {
    const xssDiff: DriftDiff = {
      scenario: '<script>alert(1)</script>',
      baseline_verdict: '<b>CRITICAL</b>',
      candidate_verdict: '<img src=x onerror=alert(1)>',
      baseline_confidence: 0.9,
      candidate_confidence: 0.8,
      baseline_summary: '<b>block</b>',
      candidate_summary: '<script>evil()</script>',
    }

    render(
      <DriftDiffDetail
        diff={xssDiff}
        baselineModel="<script>evil()</script>"
        candidateModel="<b>model</b>"
      />,
    )

    // Verdicts should be literal text, not parsed HTML
    const baseVerdict = screen.getByTestId('drift-diff-baseline-verdict')
    expect(baseVerdict.innerHTML).not.toContain('<b>')
    expect(baseVerdict.textContent).toContain('<b>CRITICAL</b>')

    const baseModel = screen.getByTestId('drift-diff-baseline-model')
    expect(baseModel.innerHTML).not.toContain('<script>')
    expect(baseModel.textContent).toContain('<script>')
  })
})

// ---------------------------------------------------------------------------
// issue #477 — Directional / de-escalation-emphasis polish (EARS criteria)
// ---------------------------------------------------------------------------

describe('driftDirection (unit) — issue #477', () => {
  it('returns escalation when candidate is higher severity', () => {
    expect(driftDirection('HIGH', 'CRITICAL')).toBe('escalation')
    expect(driftDirection('LOW', 'HIGH')).toBe('escalation')
    expect(driftDirection('MEDIUM', 'CRITICAL')).toBe('escalation')
  })

  it('returns deescalation when candidate is lower severity', () => {
    expect(driftDirection('CRITICAL', 'HIGH')).toBe('deescalation')
    expect(driftDirection('HIGH', 'MEDIUM')).toBe('deescalation')
    expect(driftDirection('HIGH', 'LOW')).toBe('deescalation')
  })

  it('returns unchanged when verdicts are identical', () => {
    expect(driftDirection('HIGH', 'HIGH')).toBe('unchanged')
    expect(driftDirection('CRITICAL', 'CRITICAL')).toBe('unchanged')
  })

  it('is case-insensitive', () => {
    expect(driftDirection('high', 'critical')).toBe('escalation')
    expect(driftDirection('CRITICAL', 'low')).toBe('deescalation')
  })
})

describe('scenarioLabel (unit) — issue #477', () => {
  it('returns human-readable label for known canonical scenarios', () => {
    expect(scenarioLabel('concise_waf_no_corr')).toBe('WAF attack probe (no IDS correlation)')
    expect(scenarioLabel('concise_security_no_corr')).toBe('security-mode probe (no IDS correlation)')
    expect(scenarioLabel('detailed_waf_no_corr')).toBe('WAF attack probe — detailed path')
    expect(scenarioLabel('suricata_port_scan')).toBe('Suricata port-scan probe')
  })

  it('falls back to space-separated raw key for unknown scenarios', () => {
    expect(scenarioLabel('new_future_scenario_type')).toBe('new future scenario type')
    expect(scenarioLabel('some_unknown_key')).toBe('some unknown key')
  })

  it('is case-insensitive for known keys', () => {
    expect(scenarioLabel('CONCISE_WAF_NO_CORR')).toBe('WAF attack probe (no IDS correlation)')
  })
})

describe('diffStorySentence (unit) — issue #477', () => {
  it('produces de-escalation story with "less alarmed" for CRITICAL→HIGH', () => {
    const sentence = diffStorySentence('concise_waf_no_corr', 'CRITICAL', 'HIGH')
    expect(sentence).toContain('WAF attack probe (no IDS correlation)')
    expect(sentence).toContain('CRITICAL')
    expect(sentence).toContain('HIGH')
    expect(sentence).toContain('less alarmed')
    expect(sentence).not.toContain('more alarmed')
  })

  it('produces escalation story with "more alarmed" for HIGH→CRITICAL', () => {
    const sentence = diffStorySentence('concise_waf_no_corr', 'HIGH', 'CRITICAL')
    expect(sentence).toContain('more alarmed')
    expect(sentence).not.toContain('less alarmed')
  })

  it('interpolates scenario human-readable category into the story', () => {
    const sentence = diffStorySentence('suricata_port_scan', 'HIGH', 'MEDIUM')
    expect(sentence).toContain('Suricata port-scan probe')
  })

  it('renders all text as plain strings — no HTML markup (ADR-0029 D3)', () => {
    const sentence = diffStorySentence('<script>evil</script>', '<b>HIGH</b>', '<img>LOW</img>')
    // Should contain the raw strings — no HTML parsing occurs in this pure function
    expect(sentence).toContain('<script>evil</script>')
    expect(sentence).toContain('<B>HIGH</B>') // toUpperCase is called on verdict
  })
})

describe('DriftDiffRow — de-escalation treatment (EARS #477)', () => {
  it('EARS-477-1: de-escalation row gets "Review this" badge', () => {
    render(
      <DriftDiffRow
        diff={DIFF_DEESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    expect(screen.getByTestId('drift-diff-review-badge')).toBeInTheDocument()
    expect(screen.getByTestId('drift-diff-review-badge')).toHaveTextContent('Review this')
  })

  it('EARS-477-1: escalation row does NOT get "Review this" badge', () => {
    render(
      <DriftDiffRow
        diff={DIFF_ESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    expect(screen.queryByTestId('drift-diff-review-badge')).not.toBeInTheDocument()
  })

  it('EARS-477-2: de-escalation row has data-direction="deescalation"', () => {
    render(
      <DriftDiffRow
        diff={DIFF_DEESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    expect(screen.getByTestId('drift-diff-row')).toHaveAttribute('data-direction', 'deescalation')
  })

  it('EARS-477-2: escalation row has data-direction="escalation"', () => {
    render(
      <DriftDiffRow
        diff={DIFF_ESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    expect(screen.getByTestId('drift-diff-row')).toHaveAttribute('data-direction', 'escalation')
  })

  it('EARS-477-3: direction label reads "de-escalation" for de-escalation row', () => {
    render(
      <DriftDiffRow
        diff={DIFF_DEESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    expect(screen.getByTestId('drift-diff-direction-label')).toHaveTextContent('de-escalation')
  })

  it('EARS-477-3: direction label reads "escalation" for escalation row', () => {
    render(
      <DriftDiffRow
        diff={DIFF_ESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    expect(screen.getByTestId('drift-diff-direction-label')).toHaveTextContent('escalation')
  })

  it('EARS-477-4: story sentence renders with human-readable category and verdicts', () => {
    render(
      <DriftDiffRow
        diff={DIFF_DEESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    const story = screen.getByTestId('drift-diff-story')
    // Must include human-readable category (not raw scenario key)
    expect(story).toHaveTextContent('Suricata port-scan probe')
    // Must include both verdicts
    expect(story).toHaveTextContent('CRITICAL')
    expect(story).toHaveTextContent('HIGH')
    // Must include "less alarmed" for de-escalation
    expect(story).toHaveTextContent('less alarmed')
  })

  it('EARS-477-4: story sentence for escalation uses "more alarmed"', () => {
    render(
      <DriftDiffRow
        diff={DIFF_ESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    const story = screen.getByTestId('drift-diff-story')
    expect(story).toHaveTextContent('more alarmed')
    expect(story).not.toHaveTextContent('less alarmed')
  })

  it('EARS-477-5: story sentence renders as text node (ADR-0029 D3 — no HTML injection)', () => {
    const xssDiff: DriftDiff = {
      scenario: '<script>evil</script>',
      baseline_verdict: 'CRITICAL',
      candidate_verdict: 'HIGH',
      baseline_confidence: 0.9,
      candidate_confidence: 0.8,
      baseline_summary: 'block',
      candidate_summary: 'monitor',
    }

    render(
      <DriftDiffRow
        diff={xssDiff}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    const story = screen.getByTestId('drift-diff-story')
    // innerHTML must not contain parsed HTML tags — only text
    expect(story.innerHTML).not.toContain('<script>')
    // The text content should include the raw angle-bracket string as text
    expect(story.textContent).toContain('<script>evil</script>')
  })

  it('EARS-477-6: expand/collapse still works on de-escalation row (regression)', () => {
    render(
      <DriftDiffRow
        diff={DIFF_DEESCALATION}
        baselineModel="llama3.2"
        candidateModel="qwen3:14b"
        index={0}
      />,
    )

    const toggle = screen.getByTestId('drift-diff-toggle')
    expect(toggle).toHaveAttribute('aria-expanded', 'false')

    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByTestId('drift-diff-detail')).toBeInTheDocument()

    // AI chips present on both sides (ADR-0035 regression)
    const chips = screen.getAllByTestId(/drift-diff-(baseline|candidate)-chip/)
    expect(chips).toHaveLength(2)
    chips.forEach((chip) => {
      expect(chip).toHaveAttribute('data-derivation', 'ai')
    })
  })
})

// ---------------------------------------------------------------------------
// MM #474 — value-first empty-state + "what is this panel" header
// ---------------------------------------------------------------------------

describe('MM #474 — PanelExplainer renders in every DriftPanel state', () => {
  it('EARS-474-1: header renders in the no-baseline state (before any instructions)', async () => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_NOT_EXISTS)
    mockFetchDriftReport.mockResolvedValue(null)

    renderDriftPanel()

    // Explainer must be present alongside the empty state
    await waitFor(() => {
      expect(screen.getByTestId('drift-no-baseline')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-panel-explainer')).toBeInTheDocument()
    expect(screen.getByTestId('drift-panel-tagline')).toBeInTheDocument()
    expect(screen.getByTestId('drift-panel-subline')).toBeInTheDocument()
  })

  it('EARS-474-1: header renders in the baseline-only state', async () => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_EXISTS)
    mockFetchDriftReport.mockResolvedValue(null)

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-baseline-only')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-panel-explainer')).toBeInTheDocument()
  })

  it('EARS-474-1: header renders in the drift-report state', async () => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_EXISTS)
    mockFetchDriftReport.mockResolvedValue(DRIFT_REPORT)

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-report-view')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-panel-explainer')).toBeInTheDocument()
  })

  it('EARS-474-1: header renders in the error state', async () => {
    mockFetchBaselineStatus.mockRejectedValue(new Error('Network error'))
    mockFetchDriftReport.mockRejectedValue(new Error('Network error'))

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-error')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-panel-explainer')).toBeInTheDocument()
  })

  it('EARS-474-2: no-baseline state leads with value framing BEFORE CLI instructions', async () => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_NOT_EXISTS)
    mockFetchDriftReport.mockResolvedValue(null)

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-no-baseline')).toBeInTheDocument()
    })

    const explainer = screen.getByTestId('drift-panel-explainer')
    const noBaseline = screen.getByTestId('drift-no-baseline')

    // Explainer must appear BEFORE the no-baseline block in document order
    const order = explainer.compareDocumentPosition(noBaseline)
    // DOCUMENT_POSITION_FOLLOWING (4) means noBaseline comes after explainer
    expect(order & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it('EARS-474-3: tagline frames drift as operational integrity, not ML statistics', async () => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_NOT_EXISTS)
    mockFetchDriftReport.mockResolvedValue(null)

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-panel-tagline')).toBeInTheDocument()
    })

    // Must mention "judge attacks" (operational integrity frame) — not "distribution shift"
    expect(screen.getByTestId('drift-panel-tagline')).toHaveTextContent(/judge attacks/i)
    expect(screen.queryByText(/distribution shift/i)).not.toBeInTheDocument()
  })

  it('EARS-474-4: sub-line reinforces zero-egress ("nothing leaves")', async () => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_NOT_EXISTS)
    mockFetchDriftReport.mockResolvedValue(null)

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-panel-subline')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-panel-subline')).toHaveTextContent(/nothing leaves/i)
  })

  it('EARS-474-5: tagline is a plain text node (no raw HTML injected)', async () => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_NOT_EXISTS)
    mockFetchDriftReport.mockResolvedValue(null)

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-panel-tagline')).toBeInTheDocument()
    })

    // The tagline text is static and must not contain script-like HTML
    const tagline = screen.getByTestId('drift-panel-tagline')
    // Static text — no dynamic model/scenario strings interpolated here
    expect(tagline.innerHTML).not.toContain('<script>')
    expect(tagline.innerHTML).not.toContain('dangerouslySetInnerHTML')
  })

  it('EARS-474-2: no-baseline empty state still shows CLI commands after value framing', async () => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_NOT_EXISTS)
    mockFetchDriftReport.mockResolvedValue(null)

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-no-baseline')).toBeInTheDocument()
    })

    // CLI commands must still be present (the path to enable is preserved)
    expect(screen.getByText(/firewatch ai-baseline --save/)).toBeInTheDocument()
    expect(screen.getByText(/firewatch ai-baseline --compare/)).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Issue #475 — Model Consistency Score headline
//
// EARS-475-1: WHEN drift report with changed>0 → score renders as "N% consistent"
// EARS-475-2: WHEN changed===0 → score reads 100% with green reassurance badge
// EARS-475-3: Score derived correctly: (scenarios - changed) / scenarios * 100, rounded
// EARS-475-4: "consistent" self-explains via visible sub-caption / gloss
// EARS-475-5: Existing counts and diff list still render below the score
// EARS-475-6: Score is top-line — consistency score DOM node precedes drift-headline
// EARS-475-7: Score percent is a text node (ADR-0029 D3)
// EARS-475-8: scenarios===0 → flags unavailable, never invents a score
// EARS-475-9: No-drift badge absent when there ARE changes (only shown for perfect state)
// ---------------------------------------------------------------------------

describe('ConsistencyScoreHeadline — issue #475', () => {
  beforeEach(() => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_EXISTS)
  })

  it('EARS-475-1: renders score headline for a changed>0 report', async () => {
    // DRIFT_REPORT: changed=2, scenarios=25 → unchanged=23, score=92%
    mockFetchDriftReport.mockResolvedValue(DRIFT_REPORT)
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-consistency-score')).toBeInTheDocument()
    })

    const scoreEl = screen.getByTestId('drift-score-percent')
    expect(scoreEl).toBeInTheDocument()
    expect(scoreEl).toHaveTextContent('92%')

    expect(screen.getByTestId('drift-score-label')).toHaveTextContent('consistent with baseline')
  })

  it('EARS-475-3: formula (scenarios - changed) / scenarios rounded to whole percent', async () => {
    // 23/25 = 0.92 → 92%
    mockFetchDriftReport.mockResolvedValue(DRIFT_REPORT)
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-score-percent')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-score-percent')).toHaveTextContent('92%')
    // Detail line shows unchanged/total
    expect(screen.getByTestId('drift-score-detail')).toHaveTextContent('23 of 25 scenarios unchanged')
  })

  it('EARS-475-2: changed===0 → score reads 100% with green reassurance badge', async () => {
    mockFetchDriftReport.mockResolvedValue(DRIFT_REPORT_NO_CHANGES)
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-consistency-score')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-score-percent')).toHaveTextContent('100%')

    const badge = screen.getByTestId('drift-score-perfect-badge')
    expect(badge).toBeInTheDocument()
    expect(badge).toHaveAttribute('role', 'status')
    expect(badge).toHaveTextContent('No drift detected')
  })

  it('EARS-475-4: "consistent" self-explains — visible gloss sub-caption present', async () => {
    mockFetchDriftReport.mockResolvedValue(DRIFT_REPORT)
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-score-gloss')).toBeInTheDocument()
    })

    const gloss = screen.getByTestId('drift-score-gloss')
    expect(gloss.textContent).toMatch(/same verdict as the saved baseline/i)
    // Hover tooltip also present
    expect(gloss).toHaveAttribute('title', expect.stringMatching(/same verdict as the saved baseline/i))
  })

  it('EARS-475-5: counts and diff list still render below the score', async () => {
    mockFetchDriftReport.mockResolvedValue(DRIFT_REPORT)
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-diff-list')).toBeInTheDocument()
    })

    expect(screen.getByTestId('drift-consistency-score')).toBeInTheDocument()
    expect(screen.getByTestId('drift-changed-count')).toBeInTheDocument()
    expect(screen.getByTestId('drift-diff-list')).toBeInTheDocument()

    const rows = screen.getAllByTestId('drift-diff-row')
    expect(rows).toHaveLength(2)
  })

  it('EARS-475-6: consistency score precedes drift-headline in DOM (top-line)', async () => {
    mockFetchDriftReport.mockResolvedValue(DRIFT_REPORT)
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-consistency-score')).toBeInTheDocument()
    })

    const scoreNode = screen.getByTestId('drift-consistency-score')
    const headlineNode = screen.getByTestId('drift-headline')

    // DOCUMENT_POSITION_FOLLOWING (4) means headlineNode comes after scoreNode
    const order = scoreNode.compareDocumentPosition(headlineNode)
    expect(order & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it('EARS-475-7: score percent is a plain text node (ADR-0029 D3 — no child elements)', async () => {
    mockFetchDriftReport.mockResolvedValue(DRIFT_REPORT)
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-score-percent')).toBeInTheDocument()
    })

    const scoreEl = screen.getByTestId('drift-score-percent')
    // No child element nodes — content is a text node only
    expect(scoreEl.children).toHaveLength(0)
    expect(scoreEl.textContent).toBe('92%')
  })

  it('EARS-475-8: scenarios===0 flags unavailable rather than inventing a score', async () => {
    const zeroScenariosReport: DriftReport = {
      ...DRIFT_REPORT,
      scenarios: 0,
      changed: 0,
      diffs: [],
    }
    mockFetchDriftReport.mockResolvedValue(zeroScenariosReport)
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-consistency-unavailable')).toBeInTheDocument()
    })

    expect(screen.queryByTestId('drift-score-percent')).not.toBeInTheDocument()
    expect(screen.getByTestId('drift-consistency-unavailable')).toHaveTextContent(
      'Consistency score unavailable',
    )
  })

  it('EARS-475-9: no-drift badge is absent when there ARE changes', async () => {
    mockFetchDriftReport.mockResolvedValue(DRIFT_REPORT) // changed=2
    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-consistency-score')).toBeInTheDocument()
    })

    expect(screen.queryByTestId('drift-score-perfect-badge')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Issue #476 — Model-swap detection banner
//
// EARS-476-1: WHEN configured model ≠ baseline model → banner appears with
//             the "from" (baseline) and "to" (configured) model IDs.
// EARS-476-2: WHEN configured model === baseline model → banner absent.
// EARS-476-3: WHEN baseline.model is null (old _meta-less file) → banner absent.
// EARS-476-4: WHEN no baseline exists → banner absent.
// EARS-476-5: Banner action points to CLI --compare (compare-only, never auto-save).
// EARS-476-6: Model IDs are text nodes (ADR-0029 D3): banner model elements contain
//             literal model strings, not parsed HTML.
// ---------------------------------------------------------------------------

describe('ModelSwapBanner — issue #476', () => {
  it('EARS-476-1: banner appears in baseline-only state when configured model ≠ baseline model', async () => {
    // Baseline saved with llama3:8b; now running llama3.1:8b
    const baselineWithOldModel: Extract<BaselineStatus, { exists: true }> = {
      exists: true,
      model: 'llama3:8b',
      saved_at: '2026-06-10T12:00:00Z',
      scenario_count: 25,
    }
    mockFetchBaselineStatus.mockResolvedValue(baselineWithOldModel)
    mockFetchDriftReport.mockResolvedValue(null) // baseline-only state
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.1:8b',
      db_ok: true,
    })

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('model-swap-banner')).toBeInTheDocument()
    })

    // From and to model names must be present as text nodes
    expect(screen.getByTestId('model-swap-banner-from')).toHaveTextContent('llama3:8b')
    expect(screen.getByTestId('model-swap-banner-to')).toHaveTextContent('llama3.1:8b')

    // Banner message copy
    const msg = screen.getByTestId('model-swap-banner-message')
    expect(msg).toHaveTextContent('Your model changed from')
    expect(msg).toHaveTextContent('since your last baseline')
    expect(msg).toHaveTextContent('Run a drift check')
  })

  it('EARS-476-1: banner appears in drift-report state when configured model ≠ baseline model', async () => {
    // Baseline saved with llama3:8b; now running llama3.1:8b (a third model after compare)
    const baselineWithOldModel: Extract<BaselineStatus, { exists: true }> = {
      exists: true,
      model: 'llama3:8b',
      saved_at: '2026-06-10T12:00:00Z',
      scenario_count: 25,
    }
    mockFetchBaselineStatus.mockResolvedValue(baselineWithOldModel)
    mockFetchDriftReport.mockResolvedValue(DRIFT_REPORT) // drift-report state
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.1:8b',
      db_ok: true,
    })

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('model-swap-banner')).toBeInTheDocument()
    })

    expect(screen.getByTestId('model-swap-banner-from')).toHaveTextContent('llama3:8b')
    expect(screen.getByTestId('model-swap-banner-to')).toHaveTextContent('llama3.1:8b')
  })

  it('EARS-476-2: banner absent when configured model === baseline model', async () => {
    // Both sides are llama3.2 — models match, no banner
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_EXISTS) // model: 'llama3.2'
    mockFetchDriftReport.mockResolvedValue(null)
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.2',
      db_ok: true,
    })

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-baseline-only')).toBeInTheDocument()
    })

    expect(screen.queryByTestId('model-swap-banner')).not.toBeInTheDocument()
  })

  it('EARS-476-3: banner absent when baseline.model is null (old _meta-less file)', async () => {
    const baselineNoMeta: Extract<BaselineStatus, { exists: true }> = {
      exists: true,
      model: null, // old file without _meta
      saved_at: null,
      scenario_count: 25,
    }
    mockFetchBaselineStatus.mockResolvedValue(baselineNoMeta)
    mockFetchDriftReport.mockResolvedValue(null)
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.2',
      db_ok: true,
    })

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-baseline-only')).toBeInTheDocument()
    })

    // No banner — baseline model unknown, cannot detect swap
    expect(screen.queryByTestId('model-swap-banner')).not.toBeInTheDocument()
  })

  it('EARS-476-4: banner absent when no baseline exists (no-baseline state)', async () => {
    mockFetchBaselineStatus.mockResolvedValue(BASELINE_NOT_EXISTS)
    mockFetchDriftReport.mockResolvedValue(null)
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.1:8b',
      db_ok: true,
    })

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('drift-no-baseline')).toBeInTheDocument()
    })

    // No baseline → no banner (nothing to compare against)
    expect(screen.queryByTestId('model-swap-banner')).not.toBeInTheDocument()
  })

  it('EARS-476-5: banner action points to CLI --compare (compare-only, no auto-save)', async () => {
    const baselineWithOldModel: Extract<BaselineStatus, { exists: true }> = {
      exists: true,
      model: 'llama3:8b',
      saved_at: '2026-06-10T12:00:00Z',
      scenario_count: 25,
    }
    mockFetchBaselineStatus.mockResolvedValue(baselineWithOldModel)
    mockFetchDriftReport.mockResolvedValue(null)
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.1:8b',
      db_ok: true,
    })

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('model-swap-banner')).toBeInTheDocument()
    })

    // CLI action must mention --compare
    const action = screen.getByTestId('model-swap-banner-action')
    expect(action).toHaveTextContent('firewatch ai-baseline --compare')

    // Must NOT mention --save (compare-only, never auto-overwrite the baseline)
    expect(action.textContent).not.toMatch(/--save/)

    // No button that could trigger an auto-save (compare-only constraint)
    const buttons = screen.queryAllByRole('button')
    // Only expand/collapse buttons from DriftDiffRows should exist — none here
    expect(buttons).toHaveLength(0)
  })

  it('EARS-476-6: model IDs in banner are text nodes, not parsed HTML (ADR-0029 D3)', async () => {
    const xssBaseline: Extract<BaselineStatus, { exists: true }> = {
      exists: true,
      model: '<script>evil()</script>',
      saved_at: null,
      scenario_count: 25,
    }
    mockFetchBaselineStatus.mockResolvedValue(xssBaseline)
    mockFetchDriftReport.mockResolvedValue(null)
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: '<img src=x onerror=alert(1)>',
      db_ok: true,
    })

    renderDriftPanel()

    await waitFor(() => {
      expect(screen.getByTestId('model-swap-banner')).toBeInTheDocument()
    })

    // From model ID must be literal text — no parsed script tag
    const fromEl = screen.getByTestId('model-swap-banner-from')
    expect(fromEl.innerHTML).not.toContain('<script>')
    expect(fromEl.textContent).toContain('<script>evil()</script>')

    // To model ID must be literal text — no parsed img/event
    const toEl = screen.getByTestId('model-swap-banner-to')
    expect(toEl.innerHTML).not.toContain('<img')
    expect(toEl.textContent).toContain('<img src=x onerror=alert(1)>')
  })
})
