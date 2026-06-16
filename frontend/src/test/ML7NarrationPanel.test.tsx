/**
 * Tests for ML-7 (#435) — NarrationPanel one-click local-LLM IP narration.
 *
 * EARS criteria covered:
 *
 * EARS-1: WHEN the analyst clicks Explain, the narration is grounded in real fields.
 *   → test_explain_button_visible_initially
 *   → test_explain_button_triggers_fetch
 *   → test_narration_renders_after_fetch
 *   → test_narration_shows_grounded_collected_fields
 *
 * EARS-2: Every claim carries a RULE/AI provenance chip.
 *   → test_provenance_chip_shows_rule_when_rule_only
 *   → test_provenance_chip_shows_ai_when_ai_narrated
 *   → test_provenance_chip_present_after_explain
 *
 * EARS-3 (anti-fabrication): NULL fields not asserted.
 *   → test_null_geo_not_in_collected_fields_display
 *   → test_collected_fields_list_shown_when_non_empty
 *
 * EARS-4: AI-unavailable degrade path is non-fatal.
 *   → test_rule_only_degrade_shows_notice
 *   → test_ai_unavailable_still_shows_narrative
 *   → test_ai_false_prop_calls_fetchNarration_with_false
 *
 * Additional:
 *   → test_spinner_shown_while_loading
 *   → test_error_state_shows_retry
 *   → test_retry_resets_to_idle
 *   → test_re_explain_resets_to_idle
 *   → test_narrative_rendered_as_text_no_html_injection (SECURITY ADR-0029 D3)
 *
 * All IPs use RFC 5737 documentation range.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import NarrationPanel from '../components/entity/ip/NarrationPanel'
import type { NarrationResult } from '../api/types'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const { mockFetchNarration } = vi.hoisted(() => ({
  mockFetchNarration: vi.fn(),
}))

vi.mock('../api/logs', () => ({
  fetchNarration: mockFetchNarration,
  // Other exports not used in this test file.
  fetchThreatScore: vi.fn(),
  fetchDetailedAnalysis: vi.fn(),
  fetchRules: vi.fn(),
  fetchIpEvents: vi.fn(),
}))

// CR3 (issue #614): NarrationPanel's loading state mounts useNarrationStream →
// useStageTicker → resolveBaseUrl.  Mock api/client so the hook doesn't error
// on import, and mock fetch to immediately fail so the stream falls back and
// the narration-spinner / fallback UI is visible (ADR-0046 §7).
vi.mock('../api/client', () => ({
  resolveBaseUrl: vi.fn().mockReturnValue(''),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: unknown) {
      super(String(message ?? status))
      this.status = status
    }
  },
  buildHeaders: vi.fn().mockReturnValue({}),
  assertLoopbackBase: vi.fn(),
  fetchHealth: vi.fn().mockResolvedValue({ ollama_connected: false }),
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchThreats: vi.fn().mockResolvedValue([]),
}))

// ---------------------------------------------------------------------------
// Fixtures (RFC 5737 IPs)
// ---------------------------------------------------------------------------

const _IP = '192.0.2.77'

const RULE_ONLY_RESULT: NarrationResult = {
  source_ip: _IP,
  narrative:
    'IP 192.0.2.77 received threat level HIGH (score 75/100). ' +
    '120 events observed (95 blocked). ' +
    'Rule signals: Brute force. ' +
    'What to check next: Review the score breakdown.',
  provenance: 'rule',
  collected_fields: ['source_ip', 'threat_level', 'score', 'blocked_events', 'score_breakdown'],
  ai_status: 'unavailable',
}

const AI_RESULT: NarrationResult = {
  source_ip: _IP,
  narrative:
    'This IP triggered aggressive SQL injection rules targeting /api endpoints. ' +
    'All 95 of 120 events were blocked. ' +
    'What to check next: Review triggered rule IDs in the evidence panel.',
  provenance: 'ai+rule',
  collected_fields: ['source_ip', 'score_breakdown', 'ai_intent', 'geo location'],
  ai_status: 'ok',
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderPanel(ip = _IP, aiAvailable = true) {
  return render(<NarrationPanel ip={ip} aiAvailable={aiAvailable} />)
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
})

// ---------------------------------------------------------------------------
// EARS-1: grounded narration on click
// ---------------------------------------------------------------------------

describe('NarrationPanel EARS-1 — Explain button triggers fetch', () => {
  it('renders Explain button in idle state', () => {
    renderPanel()
    expect(screen.getByTestId('explain-btn')).toBeInTheDocument()
  })

  it('calls fetchNarration when Explain is clicked', async () => {
    mockFetchNarration.mockResolvedValue(RULE_ONLY_RESULT)
    renderPanel()
    await userEvent.click(screen.getByTestId('explain-btn'))
    expect(mockFetchNarration).toHaveBeenCalledWith(_IP, true)
  })

  it('renders narrative text after fetch resolves', async () => {
    mockFetchNarration.mockResolvedValue(RULE_ONLY_RESULT)
    renderPanel()
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-text')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('narration-text')).toHaveTextContent('threat level HIGH')
  })

  it('renders panel in done phase after fetch', async () => {
    mockFetchNarration.mockResolvedValue(RULE_ONLY_RESULT)
    renderPanel()
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-panel')).toHaveAttribute(
        'data-narration-phase',
        'done',
      ),
    )
  })

  it('shows collected_fields disclosure when non-empty', async () => {
    mockFetchNarration.mockResolvedValue(RULE_ONLY_RESULT)
    renderPanel()
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-collected-fields')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('narration-fields-list')).toHaveTextContent('source_ip')
  })
})

// ---------------------------------------------------------------------------
// EARS-2: provenance chips
// ---------------------------------------------------------------------------

describe('NarrationPanel EARS-2 — provenance chip', () => {
  it('shows RULE provenance chip when narration is rule-only', async () => {
    mockFetchNarration.mockResolvedValue(RULE_ONLY_RESULT)
    renderPanel()
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-provenance-chip')).toBeInTheDocument(),
    )
    const chip = screen.getByTestId('narration-provenance-chip')
    expect(chip).toHaveAttribute('data-derivation', 'rule')
  })

  it('shows AI or AI+RULE provenance chip when AI narrated', async () => {
    mockFetchNarration.mockResolvedValue(AI_RESULT)
    renderPanel()
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-provenance-chip')).toBeInTheDocument(),
    )
    const chip = screen.getByTestId('narration-provenance-chip')
    const derivation = chip.getAttribute('data-derivation')
    expect(['ai', 'ai+rule']).toContain(derivation)
  })

  it('provenance chip is present after Explain click', async () => {
    mockFetchNarration.mockResolvedValue(RULE_ONLY_RESULT)
    renderPanel()
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-header')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('narration-provenance-chip')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-3: anti-fabrication / collected_fields
// ---------------------------------------------------------------------------

describe('NarrationPanel EARS-3 — anti-fabrication (collected fields)', () => {
  it('shows collected fields disclosure listing used field names', async () => {
    mockFetchNarration.mockResolvedValue(AI_RESULT)
    renderPanel()
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-fields-list')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('narration-fields-list')).toHaveTextContent('geo location')
  })

  it('null fields absent from collected_fields display (they are not in API result)', async () => {
    const resultNoGeo: NarrationResult = {
      ...RULE_ONLY_RESULT,
      collected_fields: ['source_ip', 'score'],
    }
    mockFetchNarration.mockResolvedValue(resultNoGeo)
    renderPanel()
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-fields-list')).toBeInTheDocument(),
    )
    // geo location was NOT in collected_fields — must not appear
    expect(screen.getByTestId('narration-fields-list')).not.toHaveTextContent('geo location')
  })

  it('does not show collected fields section when list is empty', async () => {
    const resultEmpty: NarrationResult = {
      ...RULE_ONLY_RESULT,
      collected_fields: [],
    }
    mockFetchNarration.mockResolvedValue(resultEmpty)
    renderPanel()
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-panel')).toHaveAttribute(
        'data-narration-phase',
        'done',
      ),
    )
    expect(screen.queryByTestId('narration-collected-fields')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-4: AI-unavailable degrade path
// ---------------------------------------------------------------------------

describe('NarrationPanel EARS-4 — AI-unavailable degrade', () => {
  it('shows "Rules-only mode · AI engine offline" notice when ai_status is unavailable', async () => {
    mockFetchNarration.mockResolvedValue(RULE_ONLY_RESULT)
    renderPanel(_IP, false)  // aiAvailable=false
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-rule-only-notice')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('narration-rule-only-notice')).toHaveTextContent(
      'Rules-only mode · AI engine offline',
    )
  })

  it('rule-only degrade still shows a narrative (non-fatal, ADR-0015)', async () => {
    mockFetchNarration.mockResolvedValue(RULE_ONLY_RESULT)
    renderPanel(_IP, false)
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-text')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('narration-text').textContent?.length ?? 0).toBeGreaterThan(0)
  })

  it('calls fetchNarration with includeAi=false when aiAvailable=false', async () => {
    mockFetchNarration.mockResolvedValue(RULE_ONLY_RESULT)
    renderPanel(_IP, false)
    await userEvent.click(screen.getByTestId('explain-btn'))
    expect(mockFetchNarration).toHaveBeenCalledWith(_IP, false)
  })

  it('does not show rule-only notice when AI did narrate (provenance contains ai)', async () => {
    mockFetchNarration.mockResolvedValue(AI_RESULT)
    renderPanel(_IP, true)
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-panel')).toHaveAttribute(
        'data-narration-phase',
        'done',
      ),
    )
    expect(screen.queryByTestId('narration-rule-only-notice')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Loading state
// ---------------------------------------------------------------------------

describe('NarrationPanel — loading state', () => {
  it('shows spinner while fetch is pending', async () => {
    // CR3 (issue #614): mock fetch so the stream errors immediately → fallback shown.
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network error'))
    mockFetchNarration.mockReturnValue(new Promise(() => {}))
    renderPanel()
    // Use act to flush the click through React's synthetic event system.
    // The promise never resolves, so state stays 'loading'.
    await act(async () => {
      screen.getByTestId('explain-btn').click()
    })
    expect(screen.getByTestId('narration-panel')).toHaveAttribute(
      'data-narration-phase',
      'loading',
    )
  })

  it('shows AI message while loading with aiAvailable=true', async () => {
    // CR3 (issue #614): stream will error (fetch not mocked → immediate failure)
    // → ticker hidden → falls back to "Running local model…" text (ADR-0046 §7).
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network error'))
    mockFetchNarration.mockReturnValue(new Promise(() => {}))
    renderPanel(_IP, true)
    await act(async () => {
      screen.getByTestId('explain-btn').click()
    })
    // In fallback mode, the stream-fallback div is rendered.
    await waitFor(() => {
      expect(screen.getByTestId('narration-stream-fallback')).toBeInTheDocument()
    })
    // Text is in the fallback container.
    expect(screen.getByTestId('narration-stream-fallback')).toHaveTextContent(
      /Running local model/i,
    )
  })

  it('shows rule summary message while loading with aiAvailable=false', async () => {
    // CR3 (issue #614): rule-only mode — no stream opened (ADR-0035 honesty).
    // "Building rule summary…" shown in narration-rule-only-loading.
    mockFetchNarration.mockReturnValue(new Promise(() => {}))
    renderPanel(_IP, false)
    await act(async () => {
      screen.getByTestId('explain-btn').click()
    })
    expect(screen.getByTestId('narration-rule-only-loading')).toBeInTheDocument()
    expect(screen.getByTestId('narration-rule-only-loading')).toHaveTextContent(
      /Building rule summary/i,
    )
  })
})

// ---------------------------------------------------------------------------
// Error state
// ---------------------------------------------------------------------------

describe('NarrationPanel — error state', () => {
  it('shows error message and retry button on fetch failure', async () => {
    mockFetchNarration.mockRejectedValue(new Error('Network error'))
    renderPanel()
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('narration-error')).toHaveTextContent('Network error')
    expect(screen.getByTestId('narration-retry-btn')).toBeInTheDocument()
  })

  it('retry button resets to idle state', async () => {
    mockFetchNarration.mockRejectedValue(new Error('Network error'))
    renderPanel()
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-retry-btn')).toBeInTheDocument(),
    )
    await userEvent.click(screen.getByTestId('narration-retry-btn'))
    expect(screen.getByTestId('explain-btn')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Re-explain
// ---------------------------------------------------------------------------

describe('NarrationPanel — re-explain', () => {
  it('Re-explain button resets to idle so analyst can re-trigger', async () => {
    mockFetchNarration.mockResolvedValue(RULE_ONLY_RESULT)
    renderPanel()
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-reset-btn')).toBeInTheDocument(),
    )
    await userEvent.click(screen.getByTestId('narration-reset-btn'))
    // Back to idle — Explain button visible
    expect(screen.getByTestId('explain-btn')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// SECURITY (ADR-0029 D3): narrative rendered as text node only
// ---------------------------------------------------------------------------

describe('NarrationPanel — SECURITY: text node rendering', () => {
  it('HTML in narrative is escaped, not rendered as DOM (ADR-0029 D3)', async () => {
    const xssResult: NarrationResult = {
      ...RULE_ONLY_RESULT,
      narrative: '<script>alert("xss")</script> IP behavior shows brute force.',
    }
    mockFetchNarration.mockResolvedValue(xssResult)
    renderPanel()
    await userEvent.click(screen.getByTestId('explain-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('narration-text')).toBeInTheDocument(),
    )
    // The script tag must appear as text, not as a live script element
    expect(screen.getByTestId('narration-text')).toHaveTextContent('<script>')
    expect(document.querySelectorAll('script[data-xss]').length).toBe(0)
    // Confirm no live script nodes were injected
    const allScripts = document.querySelectorAll('script')
    for (const s of allScripts) {
      expect(s.textContent).not.toContain('alert("xss")')
    }
  })
})
