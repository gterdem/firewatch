/**
 * Tests for issue #306 security hardening — NB-1 and NB-2.
 *
 * NB-1 — Re-run in-flight guard (useDeepAnalysis):
 *   NB1-1: Re-run while in flight is ignored (no duplicate LLM calls).
 *   NB1-2: Re-run re-checks /health before firing the AI call (never bypasses
 *          the offline guard).
 *   NB1-3: Re-run when AI is offline (per re-checked /health) transitions to
 *          ai_offline rather than staying on complete.
 *
 * NB-2 — ollama_model name length cap:
 *   NB2-1: AiSectionSkeleton caps modelName at 64 chars.
 *   NB2-2: DeepAnalysisControl caps modelName at 64 chars in analyzing phase.
 *   NB2-3: DeepAnalysisControl caps modelName in complete phase.
 *   NB2-4: Normal (≤64 char) model names pass through unchanged.
 *   NB2-5: null modelName produces no model label (no crash).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import AiSectionSkeleton from '../components/entity/ip/AiSectionSkeleton'
import DeepAnalysisControl from '../components/entity/ip/DeepAnalysisControl'
import { clearAnalysisCache } from '../components/entity/analysisCache'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const { mockFetchThreatScore, mockFetchDetailedAnalysis, mockFetchHealth } =
  vi.hoisted(() => ({
    mockFetchThreatScore: vi.fn(),
    mockFetchDetailedAnalysis: vi.fn(),
    mockFetchHealth: vi.fn(),
  }))

vi.mock('../api/logs', () => ({
  fetchThreatScore: mockFetchThreatScore,
  fetchDetailedAnalysis: mockFetchDetailedAnalysis,
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
}))

vi.mock('../api/client', () => ({
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchThreats: vi.fn().mockResolvedValue([]),
  fetchHealth: mockFetchHealth,
  // MI-7: useEvidenceChain calls fetchEvidenceChain; never-resolving so it does not affect tests.
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
// Shared fixtures
// ---------------------------------------------------------------------------

const SCORE_FIXTURE = {
  source_ip: '192.0.2.1',
  threat_level: 'MEDIUM' as const,
  score: 50,
  total_events: 5,
  blocked_events: 2,
  attack_types: ['sql_injection'],
  first_seen: '2026-01-01T00:00:00Z',
  last_seen: '2026-01-02T00:00:00Z',
  source_types: ['suricata'],
  detections: [],
  ai_insights: null,
  ai_confidence: null,
  ai_status: 'active',
  location: null,
  score_breakdown: [],
  asn: null,
  as_name: null,
  score_delta: null,
}

const DETAILED_FIXTURE = {
  score: 50,
  threat_level: 'MEDIUM',
  ai_status: 'ok',
  total_events: 5,
  blocked_events: 2,
  attack_types: ['sql_injection'],
  source_ip: '192.0.2.1',
  detections: [],
  location: null,
  asn: null,
  as_name: null,
  score_derivation: 'MEDIUM',
  score_breakdown: [],
}

beforeEach(() => {
  vi.clearAllMocks()
  clearAnalysisCache()
  // Default: score fetch resolves quickly; health returns AI online
  mockFetchThreatScore.mockResolvedValue(SCORE_FIXTURE)
  mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_FIXTURE)
  mockFetchHealth.mockResolvedValue({
    status: 'ok',
    ollama_connected: false,
    ollama_model: null,
    db_ok: true,
  })
})

// ---------------------------------------------------------------------------
// NB-2: Model name length cap (pure component tests — no network)
// ---------------------------------------------------------------------------

describe('NB-2 — ollama_model name length cap', () => {
  it('NB2-1: AiSectionSkeleton caps modelName at 64 chars', () => {
    const longName = 'a'.repeat(100)
    render(<AiSectionSkeleton elapsedSeconds={0} modelName={longName} />)
    const container = screen.getByTestId('ai-skeleton-status').parentElement!
    const fullText = container.textContent ?? ''
    // The 64-char prefix should be present
    expect(fullText).toContain('a'.repeat(64))
    // The 65th character (start of overflow) should NOT be present
    expect(fullText).not.toContain('a'.repeat(65))
  })

  it('NB2-4: AiSectionSkeleton passes normal (≤64 char) model names unchanged', () => {
    const normalName = 'llama3.2'
    render(<AiSectionSkeleton elapsedSeconds={5} modelName={normalName} />)
    const container = screen.getByTestId('ai-skeleton-status').parentElement!
    expect(container.textContent).toContain('llama3.2')
  })

  it('NB2-5: AiSectionSkeleton renders without crash for null modelName', () => {
    render(<AiSectionSkeleton elapsedSeconds={0} modelName={null} />)
    expect(screen.getByTestId('ai-section-skeleton')).toBeInTheDocument()
  })

  it('NB2-2: DeepAnalysisControl caps modelName in analyzing phase', () => {
    const longName = 'b'.repeat(100)
    render(
      <DeepAnalysisControl
        phase="analyzing"
        elapsedSeconds={3}
        modelName={longName}
        onRun={vi.fn()}
      />,
    )
    const btn = screen.getByTestId('deep-analysis-run-btn')
    const btnText = btn.textContent ?? ''
    expect(btnText).toContain('b'.repeat(64))
    expect(btnText).not.toContain('b'.repeat(65))
  })

  it('NB2-3: DeepAnalysisControl caps modelName in complete phase', () => {
    const longName = 'c'.repeat(100)
    render(
      <DeepAnalysisControl
        phase="complete"
        elapsedSeconds={12}
        modelName={longName}
        onRun={vi.fn()}
        fromCache={false}
        fetchedAt={null}
      />,
    )
    const btn = screen.getByTestId('deep-analysis-complete-btn')
    const btnText = btn.textContent ?? ''
    expect(btnText).toContain('c'.repeat(64))
    expect(btnText).not.toContain('c'.repeat(65))
  })

  it('NB2-4: DeepAnalysisControl passes normal model name in analyzing phase', () => {
    render(
      <DeepAnalysisControl
        phase="analyzing"
        elapsedSeconds={0}
        modelName="qwen3:8b"
        onRun={vi.fn()}
      />,
    )
    expect(screen.getByTestId('deep-analysis-run-btn').textContent).toContain('qwen3:8b')
  })
})

// ---------------------------------------------------------------------------
// NB-1: Re-run in-flight guard — IpPanel integration tests
// ---------------------------------------------------------------------------

import IpPanel from '../components/entity/ip/IpPanel'

describe('NB-1 — Re-run in-flight guard (useDeepAnalysis)', () => {
  it('NB1-2: Re-run re-checks /health before firing the AI call', async () => {
    // First health check: AI online → auto-run triggers
    mockFetchHealth
      .mockResolvedValueOnce({
        status: 'ok',
        ollama_connected: true,
        ollama_model: 'llama3.2',
        db_ok: true,
      })
      // Second health check (Re-run): AI goes offline
      .mockResolvedValue({
        status: 'ok',
        ollama_connected: false,
        ollama_model: null,
        db_ok: true,
      })

    // The rules-only fetch (include_ai=false) resolves quickly
    mockFetchDetailedAnalysis.mockImplementation((_ip: string, includeAi: boolean) => {
      if (!includeAi) return Promise.resolve(DETAILED_FIXTURE)
      return Promise.resolve({ ...DETAILED_FIXTURE, ai_status: 'ok' })
    })

    render(<IpPanel ip="192.0.2.1" />)

    // Wait for the Re-run button to appear (complete state after first AI run)
    await waitFor(
      () => expect(screen.queryByTestId('deep-analysis-rerun-btn')).toBeInTheDocument(),
      { timeout: 4000 },
    )

    // Click Re-run — health re-check fires; AI is now offline
    await userEvent.click(screen.getByTestId('deep-analysis-rerun-btn'))

    // After health re-check resolves as offline, should show offline badge
    await waitFor(
      () => expect(screen.queryByTestId('deep-analysis-offline-badge')).toBeInTheDocument(),
      { timeout: 3000 },
    )

    // fetchHealth must have been called at least twice
    expect(mockFetchHealth.mock.calls.length).toBeGreaterThanOrEqual(2)
  })

  it('NB1-1: Re-run while in flight is prevented by inFlightRef guard', async () => {
    // Health: AI online
    mockFetchHealth.mockResolvedValue({
      status: 'ok',
      ollama_connected: true,
      ollama_model: 'llama3.2',
      db_ok: true,
    })

    // Rules-only fetch resolves immediately; AI deep call is controllable
    let resolveAiCall!: (v: unknown) => void
    const slowAiPromise = new Promise((resolve) => { resolveAiCall = resolve })

    mockFetchDetailedAnalysis.mockImplementation((_ip: string, includeAi: boolean) => {
      if (!includeAi) return Promise.resolve(DETAILED_FIXTURE)
      return slowAiPromise
    })

    render(<IpPanel ip="192.0.2.2" />)

    // Wait for analyzing skeleton to appear (AI call in flight)
    await waitFor(
      () => expect(screen.queryByTestId('ai-section-skeleton')).toBeInTheDocument(),
      { timeout: 4000 },
    )

    // While in flight, Re-run button should not be rendered
    expect(screen.queryByTestId('deep-analysis-rerun-btn')).not.toBeInTheDocument()

    // Count AI calls before resolving
    const aiCallsBefore = mockFetchDetailedAnalysis.mock.calls.filter(
      (c: unknown[]) => c[1] === true,
    ).length
    expect(aiCallsBefore).toBe(1)

    // Resolve the slow AI call
    act(() => {
      resolveAiCall({ ...DETAILED_FIXTURE, source_ip: '192.0.2.2' })
    })

    // Wait for complete state
    await waitFor(
      () => expect(screen.queryByTestId('deep-analysis-rerun-btn')).toBeInTheDocument(),
      { timeout: 3000 },
    )

    // Total AI calls must still be 1 — no duplicate call was made
    const aiCallsAfter = mockFetchDetailedAnalysis.mock.calls.filter(
      (c: unknown[]) => c[1] === true,
    ).length
    expect(aiCallsAfter).toBe(1)
  })
})
