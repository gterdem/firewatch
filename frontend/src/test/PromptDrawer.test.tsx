/**
 * Tests for PromptDrawer.tsx and useAnalysisDetail.ts (MK-7, issue #412).
 *
 * EARS acceptance criteria covered:
 *
 *   EARS-1 (render on expand):
 *     WHEN "What the model saw" is clicked, THE drawer SHALL fetch
 *     GET /ai/analyses/{id} and render: prompt sections, response text,
 *     validated_json, model, latency_ms, tokens (omit when null).
 *
 *   EARS-2 (SECURITY — hostile content renders inert as text nodes):
 *     WHEN prompt_text/response_text contains <img src=x onerror=alert(1)>,
 *     a markdown link [x](javascript:...), and ANSI escapes, THE drawer SHALL
 *     render them as inert literal text:
 *       - the literal text IS present in the DOM.
 *       - NO <img> element is created by the hostile payload.
 *       - NO <a href="javascript:..."> is created.
 *       - NO onerror handler fires.
 *     (ADR-0029 D3 / OWASP LLM05 — zero dangerouslySetInnerHTML in the subtree.)
 *
 *   EARS-3 (truncation notices):
 *     WHEN prompt_truncated or response_truncated is true, THE drawer SHALL
 *     show "truncated at 64 KiB".
 *
 *   EARS-4 (honest loading state):
 *     WHILE the fetch is in-flight, THE drawer SHALL show a loading indicator.
 *
 *   EARS-5 (honest error state):
 *     WHEN the fetch fails or returns null (404/503), THE drawer SHALL show
 *     "couldn't load the stored analysis" — never empty-success.
 *
 *   EARS-6 (token omission):
 *     WHEN prompt_tokens and completion_tokens are null, THE drawer SHALL NOT
 *     render token stat pills — never fabricate a 0.
 *
 *   EARS-7 (Esc close + focus return / WCAG):
 *     WHEN the drawer is open and Escape is pressed, THE drawer SHALL close
 *     and focus SHALL return to the trigger (reuses useDismissableDisclosure).
 *
 *   EARS-8 (VerdictCard mount):
 *     VerdictCard SHALL render the "What the model saw" trigger button.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { AnalysisDetail, AnalysisSummary } from '../api/types'
import { PromptDrawer } from '../components/ai/ledger/PromptDrawer'
import { VerdictCard } from '../components/ai/ledger/VerdictCard'
import { clearDetailCache } from '../components/ai/ledger/useAnalysisDetail'

// ---------------------------------------------------------------------------
// Mock the API client
// ---------------------------------------------------------------------------

const { mockFetchAnalysisDetail } = vi.hoisted(() => ({
  mockFetchAnalysisDetail: vi.fn(),
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
    fetchAnalysisDetail: mockFetchAnalysisDetail,
    // Other client methods used by VerdictFeedback / useDismissableDisclosure consumers
    postFeedback: vi.fn().mockResolvedValue(null),
    fetchFeedbackSummary: vi.fn().mockResolvedValue(null),
    fetchSourceTypes: vi.fn().mockResolvedValue([]),
    ApiError,
  }
})

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Minimal AnalysisDetail fixture for a concise prompt (RFC 5737 IPs only). */
const ANALYSIS_DETAIL_FIXTURE: AnalysisDetail = {
  id: 42,
  ip: '192.0.2.1',
  kind: 'concise',
  model: 'qwen3:8b',
  endpoint_host: '127.0.0.1:11434',
  ai_status: 'active',
  threat_level: 'HIGH',
  confidence: 0.87,
  score: 75,
  score_derivation: 'ai+rule',
  latency_ms: 1234,
  prompt_tokens: 512,
  completion_tokens: 128,
  schema_version: 1,
  created_at: '2026-06-13T10:00:00Z',
  feedback: null,
  prompt_text: `You are a SOC analyst AI assistant.
Analyze this threat actor based on WAF log data.

## Threat Actor Profile
- **IP Address:** 192.0.2.1
- **Total Events:** 120

## Attack Samples (top rules by frequency)
  1. Rule: 942100 (SQL Injection) — triggered 30x
     Sample payload: <untrusted_data>id=1 OR 1=1</untrusted_data>

## Your Task
Provide a threat assessment in JSON format only:
{
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW"
}`,
  response_text: '{"threat_level":"HIGH","confidence":0.87,"intent":"SQL injection","attack_stage":"exploitation","insights":[],"recommended_action":"block"}',
  validated_json: {
    threat_level: 'HIGH',
    confidence: 0.87,
    intent: 'SQL injection scanning',
    attack_stage: 'exploitation',
    insights: [],
    recommended_action: 'block',
  },
  prompt_truncated: false,
  response_truncated: false,
}

/**
 * SECURITY test fixture — hostile attacker payload embedded in prompt/response.
 *
 * This simulates a worst-case attacker who crafts their payload to contain:
 *   1. An XSS img tag with onerror handler.
 *   2. A markdown link with javascript: scheme.
 *   3. ANSI escape codes.
 *
 * The PromptDrawer MUST render all of these as inert literal text.
 */
const HOSTILE_ANALYSIS_DETAIL: AnalysisDetail = {
  ...ANALYSIS_DETAIL_FIXTURE,
  id: 99,
  prompt_text: `You are a SOC analyst.

## Attack Samples (top rules by frequency)
  1. Rule: 942100 — triggered 1x
     Sample payload: <untrusted_data><img src=x onerror=alert(1)>
[x](javascript:alert("xss"))
[31mANSI RED[0m</untrusted_data>

## Your Task
Return JSON.`,
  response_text: 'Raw model response containing <img src=x onerror=alert(2)> and [link](javascript:void(0)) and [31mANSI[0m',
  validated_json: { threat_level: 'LOW' },
}

const ANALYSIS_WITH_TRUNCATION: AnalysisDetail = {
  ...ANALYSIS_DETAIL_FIXTURE,
  id: 55,
  prompt_truncated: true,
  response_truncated: true,
}

const ANALYSIS_NULL_TOKENS: AnalysisDetail = {
  ...ANALYSIS_DETAIL_FIXTURE,
  id: 66,
  prompt_tokens: null,
  completion_tokens: null,
}

/** Minimal AnalysisSummary for VerdictCard mount test. */
const SUMMARY_FIXTURE: AnalysisSummary = {
  id: 42,
  ip: '192.0.2.1',
  kind: 'concise',
  model: 'qwen3:8b',
  endpoint_host: '127.0.0.1:11434',
  ai_status: 'active',
  threat_level: 'HIGH',
  confidence: 0.87,
  score: 75,
  score_derivation: 'ai+rule',
  latency_ms: 1234,
  prompt_tokens: 512,
  completion_tokens: 128,
  schema_version: 1,
  created_at: '2026-06-13T10:00:00Z',
  feedback: null,
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
  // Clear the module-level detail cache between tests to prevent stale
  // cached results from one test leaking into another.
  // (The cache is intentionally persistent across component remounts in production,
  //  but tests need isolation — the cache is cleared via the exported helper.)
  clearDetailCache()
})

// ---------------------------------------------------------------------------
// EARS-1: render on expand — data rendered correctly
// ---------------------------------------------------------------------------

describe('PromptDrawer — render on expand (EARS-1)', () => {
  it('shows the "What the model saw" trigger button before opening', () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)
    expect(screen.getByTestId('prompt-drawer-trigger')).toBeInTheDocument()
  })

  it('drawer content is NOT rendered before the trigger is clicked', () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)
    expect(screen.queryByTestId('prompt-drawer-content')).not.toBeInTheDocument()
  })

  it('clicking the trigger opens the drawer and fetches the detail', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('prompt-drawer-data')).toBeInTheDocument()
    })
    expect(mockFetchAnalysisDetail).toHaveBeenCalledWith(42)
  })

  it('renders model identity stat pill', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('drawer-stat-model')).toBeInTheDocument()
    })
    expect(screen.getByTestId('drawer-stat-model')).toHaveTextContent('qwen3:8b')
  })

  it('renders latency stat pill', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('drawer-stat-latency')).toBeInTheDocument()
    })
    expect(screen.getByTestId('drawer-stat-latency')).toHaveTextContent('1234 ms')
  })

  it('renders prompt_tokens stat pill when not null', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('drawer-stat-prompt-tokens')).toBeInTheDocument()
    })
    expect(screen.getByTestId('drawer-stat-prompt-tokens')).toHaveTextContent('512')
  })

  it('renders completion_tokens stat pill when not null', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('drawer-stat-completion-tokens')).toBeInTheDocument()
    })
    expect(screen.getByTestId('drawer-stat-completion-tokens')).toHaveTextContent('128')
  })

  it('renders the instructions section from the prompt', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('drawer-section-instructions')).toBeInTheDocument()
    })
    expect(screen.getByTestId('drawer-section-instructions')).toHaveTextContent('SOC analyst')
  })

  it('renders the samples section from the prompt', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('drawer-section-samples')).toBeInTheDocument()
    })
    expect(screen.getByTestId('drawer-section-samples')).toHaveTextContent('## Attack Samples')
  })

  it('renders the schema section from the prompt', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('drawer-section-schema')).toBeInTheDocument()
    })
    expect(screen.getByTestId('drawer-section-schema')).toHaveTextContent('## Your Task')
  })

  it('renders the raw model response section', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('drawer-section-response')).toBeInTheDocument()
    })
    expect(screen.getByTestId('drawer-section-response')).toHaveTextContent('threat_level')
  })

  it('renders the validated JSON section', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('drawer-section-validated-json')).toBeInTheDocument()
    })
    expect(screen.getByTestId('drawer-section-validated-json')).toHaveTextContent('threat_level')
  })
})

// ---------------------------------------------------------------------------
// EARS-2: SECURITY — hostile content renders as inert text nodes
// (ADR-0029 D3 / OWASP LLM05 — the core security regression test)
// ---------------------------------------------------------------------------

describe('PromptDrawer — SECURITY: hostile content renders inert (EARS-2)', () => {
  /**
   * This test asserts ADR-0029 D3 / OWASP LLM05:
   *   prompt_text/response_text are the most attacker-controlled strings in
   *   the product. The drawer MUST render them as text nodes only.
   *
   * Hostile sample:
   *   - <img src=x onerror=alert(1)> — would execute JS if rendered as HTML
   *   - [x](javascript:alert("xss")) — markdown link that would inject JS
   *   - ANSI escape codes — terminal injection
   *
   * Assertions:
   *   1. The literal hostile text IS present in the DOM (text content).
   *   2. NO <img> element was created from the hostile payload.
   *   3. NO <a href="javascript:..."> element was created.
   *   4. onerror attribute is NOT present on any element.
   */
  it('renders <img onerror> as literal text — no img element created', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(HOSTILE_ANALYSIS_DETAIL)
    render(<PromptDrawer analysisId={99} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('prompt-drawer-data')).toBeInTheDocument()
    })

    // The literal text must be present as text content.
    expect(screen.getByTestId('drawer-section-samples').textContent).toContain(
      '<img src=x onerror=alert(1)>',
    )

    // NO img element should have been created by the hostile payload.
    // (A real img element from the hostile string would have src=x and
    //  onerror handler — we assert it does not exist.)
    const imgElements = document.querySelectorAll('img[src="x"]')
    expect(imgElements.length).toBe(0)
  })

  it('renders markdown link [x](javascript:...) as literal text — no anchor created', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(HOSTILE_ANALYSIS_DETAIL)
    render(<PromptDrawer analysisId={99} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('prompt-drawer-data')).toBeInTheDocument()
    })

    // The literal markdown link text must be present.
    expect(screen.getByTestId('drawer-section-samples').textContent).toContain(
      '[x](javascript:alert("xss"))',
    )

    // NO <a href="javascript:..."> element should exist.
    const jsAnchors = document.querySelectorAll('a[href^="javascript:"]')
    expect(jsAnchors.length).toBe(0)
  })

  it('renders ANSI escape codes as literal characters — not processed as terminal codes', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(HOSTILE_ANALYSIS_DETAIL)
    render(<PromptDrawer analysisId={99} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('prompt-drawer-data')).toBeInTheDocument()
    })

    // The ANSI sequence must be present as literal text (ESC + [ + codes).
    expect(screen.getByTestId('drawer-section-samples').textContent).toContain('ANSI RED')
  })

  it('hostile content in response_text renders as literal text — no img created', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(HOSTILE_ANALYSIS_DETAIL)
    render(<PromptDrawer analysisId={99} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('drawer-section-response')).toBeInTheDocument()
    })

    // The response section must contain the hostile text as literal characters.
    expect(screen.getByTestId('drawer-section-response').textContent).toContain(
      '<img src=x onerror=alert(2)>',
    )
    // Still no img[src=x] element.
    expect(document.querySelectorAll('img[src="x"]').length).toBe(0)
  })

  it('no element in the drawer subtree has an onerror attribute', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(HOSTILE_ANALYSIS_DETAIL)
    render(<PromptDrawer analysisId={99} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('prompt-drawer-data')).toBeInTheDocument()
    })

    // Query the entire rendered tree for any element with an onerror attribute.
    const onerrorElements = document.querySelectorAll('[onerror]')
    expect(onerrorElements.length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// EARS-3: truncation notices
// ---------------------------------------------------------------------------

describe('PromptDrawer — truncation notices (EARS-3)', () => {
  it('shows "truncated at 64 KiB" when prompt_truncated is true', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_WITH_TRUNCATION)
    render(<PromptDrawer analysisId={55} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('prompt-drawer-data')).toBeInTheDocument()
    })

    // The truncation notice should appear somewhere in the drawer content.
    expect(screen.getByTestId('prompt-drawer-content').textContent).toContain(
      'truncated at 64 KiB',
    )
  })

  it('shows "truncated at 64 KiB" when response_truncated is true', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_WITH_TRUNCATION)
    render(<PromptDrawer analysisId={55} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('drawer-section-response-truncated')).toBeInTheDocument()
    })
    expect(screen.getByTestId('drawer-section-response-truncated')).toHaveTextContent(
      'truncated at 64 KiB',
    )
  })
})

// ---------------------------------------------------------------------------
// EARS-4: honest loading state
// ---------------------------------------------------------------------------

describe('PromptDrawer — loading state (EARS-4)', () => {
  it('shows loading indicator while fetch is in-flight', async () => {
    // Never resolve — keeps the component in loading state.
    mockFetchAnalysisDetail.mockReturnValue(new Promise(() => {}))
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('prompt-drawer-loading')).toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// EARS-5: honest error state
// ---------------------------------------------------------------------------

describe('PromptDrawer — error state (EARS-5)', () => {
  it('shows error message when fetchAnalysisDetail returns null (404/503 degrade)', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(null)
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('prompt-drawer-error')).toBeInTheDocument()
    })
    expect(screen.getByTestId('prompt-drawer-error')).toHaveTextContent(
      "couldn't load the stored analysis",
    )
  })

  it('shows error message when fetchAnalysisDetail throws an ApiError', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchAnalysisDetail.mockRejectedValue(new ApiError(500, null))
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('prompt-drawer-error')).toBeInTheDocument()
    })
    expect(screen.getByTestId('prompt-drawer-error')).toHaveTextContent(
      "couldn't load the stored analysis",
    )
  })

  it('never shows empty-success when fetch returns null', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(null)
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      // After settle, must NOT be in loading state with no error shown.
      expect(screen.queryByTestId('prompt-drawer-loading')).not.toBeInTheDocument()
    })
    // Must show an error, not an empty success.
    expect(screen.getByTestId('prompt-drawer-error')).toBeInTheDocument()
    expect(screen.queryByTestId('prompt-drawer-data')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-6: token omission when null
// ---------------------------------------------------------------------------

describe('PromptDrawer — token omission when null (EARS-6)', () => {
  it('does NOT render prompt_tokens pill when prompt_tokens is null', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_NULL_TOKENS)
    render(<PromptDrawer analysisId={66} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('prompt-drawer-data')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('drawer-stat-prompt-tokens')).not.toBeInTheDocument()
  })

  it('does NOT render completion_tokens pill when completion_tokens is null', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_NULL_TOKENS)
    render(<PromptDrawer analysisId={66} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('prompt-drawer-data')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('drawer-stat-completion-tokens')).not.toBeInTheDocument()
  })

  it('still renders other stats when token counts are null', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_NULL_TOKENS)
    render(<PromptDrawer analysisId={66} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('drawer-stat-model')).toBeInTheDocument()
    })
    expect(screen.getByTestId('drawer-stat-latency')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-7: Esc close + focus return (WCAG / useDismissableDisclosure)
// ---------------------------------------------------------------------------

describe('PromptDrawer — Esc close + focus return (EARS-7)', () => {
  it('Esc closes the drawer', async () => {
    const user = userEvent.setup()
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)

    const trigger = screen.getByTestId('prompt-drawer-trigger')
    fireEvent.click(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('prompt-drawer-content')).toBeInTheDocument()
    })

    await user.keyboard('{Escape}')
    expect(screen.queryByTestId('prompt-drawer-content')).not.toBeInTheDocument()
  })

  it('Esc returns focus to the trigger (WCAG 2.4.7)', async () => {
    const user = userEvent.setup()
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)

    const trigger = screen.getByTestId('prompt-drawer-trigger')
    trigger.focus()
    fireEvent.click(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('prompt-drawer-content')).toBeInTheDocument()
    })

    await user.keyboard('{Escape}')
    expect(document.activeElement).toBe(trigger)
  })
})

// ---------------------------------------------------------------------------
// EARS-9: No nested scrollbar — overflowX must be 'hidden' on <pre> (issue #575)
// ---------------------------------------------------------------------------

describe('CollapsibleText — no nested horizontal scrollbar (EARS-9 / #575)', () => {
  /**
   * WHEN prompt text is shown in the transparency drawer,
   * THE SYSTEM SHALL NOT produce a horizontal-and-vertical scroll-within-scroll
   * region on the <pre> element.
   *
   * Implementation: overflowX must be 'hidden' (not 'auto' or 'scroll').
   * Long lines wrap via whiteSpace:'pre-wrap' + wordBreak:'break-word'.
   */
  it('<pre> element has overflowX hidden, not auto or scroll', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<PromptDrawer analysisId={42} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('drawer-section-instructions')).toBeInTheDocument()
    })

    const pre = screen.getByTestId('drawer-section-instructions')
    const overflowX = pre.style.overflowX
    expect(overflowX).not.toBe('auto')
    expect(overflowX).not.toBe('scroll')
    // Should be 'hidden' so long lines wrap rather than scroll.
    expect(overflowX).toBe('hidden')
  })

  it('a long unbroken line in prompt text does not produce a horizontal scroll region', async () => {
    const longLineDetail: AnalysisDetail = {
      ...ANALYSIS_DETAIL_FIXTURE,
      id: 77,
      // A single very long line with no whitespace — worst-case for horizontal overflow.
      // splitPromptSections finds no section markers, so the whole text lands in
      // 'instructions' and renders under data-testid="drawer-section-instructions".
      prompt_text: 'A'.repeat(2000),
      response_text: null,
      validated_json: null,
      prompt_truncated: false,
      response_truncated: false,
    }
    mockFetchAnalysisDetail.mockResolvedValue(longLineDetail)
    render(<PromptDrawer analysisId={77} />)
    fireEvent.click(screen.getByTestId('prompt-drawer-trigger'))

    await waitFor(() => {
      expect(screen.getByTestId('drawer-section-instructions')).toBeInTheDocument()
    })

    const pre = screen.getByTestId('drawer-section-instructions')
    // The element must not have overflowX set to a scrollable value.
    expect(pre.style.overflowX).toBe('hidden')
    // wordBreak should be 'break-word' so even unbroken strings wrap.
    expect(pre.style.wordBreak).toBe('break-word')
  })
})

// ---------------------------------------------------------------------------
// EARS-8: VerdictCard mounts the prompt drawer trigger
// ---------------------------------------------------------------------------

describe('VerdictCard — mounts PromptDrawer (EARS-8)', () => {
  it('renders the "What the model saw" trigger button inside a VerdictCard', () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<VerdictCard analysis={SUMMARY_FIXTURE} />)
    expect(screen.getByTestId('prompt-drawer-trigger')).toBeInTheDocument()
  })

  it('trigger button is accessible with aria-expanded=false initially', () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<VerdictCard analysis={SUMMARY_FIXTURE} />)
    const trigger = screen.getByTestId('prompt-drawer-trigger')
    expect(trigger.getAttribute('aria-expanded')).toBe('false')
  })

  it('opening the drawer sets aria-expanded=true on the trigger', async () => {
    mockFetchAnalysisDetail.mockResolvedValue(ANALYSIS_DETAIL_FIXTURE)
    render(<VerdictCard analysis={SUMMARY_FIXTURE} />)
    const trigger = screen.getByTestId('prompt-drawer-trigger')
    fireEvent.click(trigger)

    await waitFor(() => {
      expect(trigger.getAttribute('aria-expanded')).toBe('true')
    })
  })
})
