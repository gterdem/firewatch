/**
 * Tests for MM #451 — provenance chip glosses + first-appearance legend.
 *
 * EARS acceptance criteria:
 *
 *   EARS-451-1 (chip gloss on hover):
 *     WHEN a user hovers any ProvenanceChip, THE chip SHALL surface a
 *     plain-language gloss tooltip. Copy:
 *       RULE    → "This number came from deterministic detection rules — no AI involved."
 *       AI      → "A local AI model wrote this verdict."
 *       AI+RULE → "AI and rules both contributed to this score."
 *
 *   EARS-451-2 (chip gloss on focus):
 *     WHEN a user keyboard-focuses any ProvenanceChip, THE same gloss SHALL
 *     appear (keyboard parity — WCAG 1.4.13).
 *
 *   EARS-451-3 (single source):
 *     THE gloss SHALL be defined once in ProvenanceChip (PROVENANCE_GLOSS export)
 *     so it is consistent across all panels.
 *
 *   EARS-451-4 (legend renders):
 *     THE first time provenance chips appear on the AI Engine page, THE page
 *     SHALL show a dismissible one-line legend under the subtitle:
 *     "RULE = deterministic rule · AI = local model verdict · AI+RULE = both.
 *      Nothing here left your machine."
 *
 *   EARS-451-5 (legend is dismissible):
 *     THE legend SHALL be dismissible and SHALL NOT reappear within the same
 *     session once dismissed (sessionStorage persistence).
 *
 *   EARS-451-6 (zero layout cost):
 *     THE gloss/legend additions SHALL NOT alter chip styling tokens or layout
 *     height (chip visual style is unchanged).
 *
 *   EARS-451-7 (AIRoute mounts legend):
 *     THE AIRoute page SHALL render the ProvenanceChipLegend under the subtitle,
 *     and it SHALL be dismissible from the AI Engine page.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ProvenanceChip, ProvenanceChipLegend } from '../components/ds'
import { PROVENANCE_GLOSS } from '../lib/provenance'
import AIRoute from '../routes/AIRoute'
import {
  THREATS_FIXTURE,
  HEALTH_AI_ONLINE,
} from './readFixtures'

// ---------------------------------------------------------------------------
// Mock API client for AIRoute tests
// ---------------------------------------------------------------------------

const { mockFetchThreats, mockFetchHealth, mockFetchAnalyses, mockFetchFeedbackSummary } = vi.hoisted(() => ({
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

// ---------------------------------------------------------------------------
// sessionStorage reset between tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  sessionStorage.clear()
  vi.clearAllMocks()
})

afterEach(() => {
  sessionStorage.clear()
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderRoute(initialEntries = ['/ai']) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <AIRoute />
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// EARS-451-3: PROVENANCE_GLOSS export — single source of truth
// ---------------------------------------------------------------------------

describe('PROVENANCE_GLOSS — single-source gloss constants (EARS-451-3)', () => {
  it('RULE gloss matches EARS spec', () => {
    expect(PROVENANCE_GLOSS['rule']).toBe(
      'This number came from deterministic detection rules — no AI involved.',
    )
  })

  it('AI gloss matches EARS spec', () => {
    expect(PROVENANCE_GLOSS['ai']).toBe('A local AI model wrote this verdict.')
  })

  it('AI+RULE gloss matches EARS spec', () => {
    expect(PROVENANCE_GLOSS['ai+rule']).toBe(
      'AI and rules both contributed to this score.',
    )
  })

  it('all three derivations have a gloss entry', () => {
    expect(PROVENANCE_GLOSS['rule']).toBeTruthy()
    expect(PROVENANCE_GLOSS['ai']).toBeTruthy()
    expect(PROVENANCE_GLOSS['ai+rule']).toBeTruthy()
  })
})

// ---------------------------------------------------------------------------
// EARS-451-1/2: ProvenanceChip — gloss surfaces on hover and focus
// ---------------------------------------------------------------------------

describe('ProvenanceChip — gloss tooltip surfaces on hover (EARS-451-1)', () => {
  it('RULE chip shows correct gloss text on hover', async () => {
    render(<ProvenanceChip derivation="rule" />)
    const trigger = screen.getByTestId('cell-tooltip-trigger')
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByRole('tooltip')).toBeInTheDocument()
    })
    expect(screen.getByRole('tooltip')).toHaveTextContent(
      'This number came from deterministic detection rules — no AI involved.',
    )
  })

  it('AI chip shows correct gloss text on hover', async () => {
    render(<ProvenanceChip derivation="ai" />)
    const trigger = screen.getByTestId('cell-tooltip-trigger')
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByRole('tooltip')).toBeInTheDocument()
    })
    expect(screen.getByRole('tooltip')).toHaveTextContent(
      'A local AI model wrote this verdict.',
    )
  })

  it('AI+RULE chip shows correct gloss text on hover', async () => {
    render(<ProvenanceChip derivation="ai+rule" />)
    const trigger = screen.getByTestId('cell-tooltip-trigger')
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByRole('tooltip')).toBeInTheDocument()
    })
    expect(screen.getByRole('tooltip')).toHaveTextContent(
      'AI and rules both contributed to this score.',
    )
  })

  it('unknown derivation falls back to RULE gloss on hover', async () => {
    // eslint-disable-next-line no-restricted-syntax -- intentional out-of-whitelist value
    render(<ProvenanceChip derivation="mystery" />)
    const trigger = screen.getByTestId('cell-tooltip-trigger')
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByRole('tooltip')).toBeInTheDocument()
    })
    expect(screen.getByRole('tooltip')).toHaveTextContent(
      'This number came from deterministic detection rules — no AI involved.',
    )
  })
})

describe('ProvenanceChip — gloss tooltip surfaces on keyboard focus (EARS-451-2)', () => {
  it('RULE chip shows gloss on focus (keyboard parity)', async () => {
    render(<ProvenanceChip derivation="rule" />)
    const trigger = screen.getByTestId('cell-tooltip-trigger')
    fireEvent.focus(trigger)
    await waitFor(() => {
      expect(screen.getByRole('tooltip')).toBeInTheDocument()
    })
    expect(screen.getByRole('tooltip')).toHaveTextContent(
      'This number came from deterministic detection rules — no AI involved.',
    )
  })

  it('AI chip shows gloss on focus', async () => {
    render(<ProvenanceChip derivation="ai" />)
    const trigger = screen.getByTestId('cell-tooltip-trigger')
    fireEvent.focus(trigger)
    await waitFor(() => {
      expect(screen.getByRole('tooltip')).toBeInTheDocument()
    })
    expect(screen.getByRole('tooltip')).toHaveTextContent(
      'A local AI model wrote this verdict.',
    )
  })

  it('AI+RULE chip shows gloss on focus', async () => {
    render(<ProvenanceChip derivation="ai+rule" />)
    const trigger = screen.getByTestId('cell-tooltip-trigger')
    fireEvent.focus(trigger)
    await waitFor(() => {
      expect(screen.getByRole('tooltip')).toBeInTheDocument()
    })
    expect(screen.getByRole('tooltip')).toHaveTextContent(
      'AI and rules both contributed to this score.',
    )
  })

  it('CellTooltip trigger is keyboard-focusable (tabIndex=0)', () => {
    render(<ProvenanceChip derivation="rule" />)
    const trigger = screen.getByTestId('cell-tooltip-trigger')
    expect(trigger.getAttribute('tabindex')).toBe('0')
  })
})

// ---------------------------------------------------------------------------
// EARS-451-6: chip visual style is unchanged (zero layout cost)
// ---------------------------------------------------------------------------

describe('ProvenanceChip — chip visual style unchanged after tooltip wrap (EARS-451-6)', () => {
  it('RULE chip renders "RULE" label (chip content unchanged)', () => {
    render(<ProvenanceChip derivation="rule" />)
    expect(screen.getByRole('status')).toHaveTextContent('RULE')
  })

  it('AI chip renders "AI" label', () => {
    render(<ProvenanceChip derivation="ai" />)
    expect(screen.getByRole('status')).toHaveTextContent('AI')
  })

  it('AI+RULE chip renders "AI+RULE" label', () => {
    render(<ProvenanceChip derivation="ai+rule" />)
    expect(screen.getByRole('status')).toHaveTextContent('AI+RULE')
  })

  it('RULE chip still uses muted/neutral styling tokens', () => {
    const { container } = render(<ProvenanceChip derivation="rule" />)
    const chip = container.querySelector('.fw-provenance-chip') as HTMLElement
    expect(chip.style.background).toContain('var(--fw-bg-input)')
    expect(chip.style.color).toContain('var(--fw-t2)')
  })

  it('AI chip still uses amber accent token', () => {
    const { container } = render(<ProvenanceChip derivation="ai" />)
    const chip = container.querySelector('.fw-provenance-chip') as HTMLElement
    expect(chip.style.color).toContain('var(--fw-accent)')
  })

  it('chip has data-derivation attribute (backward compat)', () => {
    render(<ProvenanceChip derivation="ai+rule" data-testid="chip" />)
    expect(screen.getByTestId('chip').getAttribute('data-derivation')).toBe('ai+rule')
  })

  it('chip has role="status" (accessibility)', () => {
    render(<ProvenanceChip derivation="rule" />)
    expect(screen.getByRole('status')).toBeInTheDocument()
  })

  it('chip has aria-label (accessibility)', () => {
    render(<ProvenanceChip derivation="ai" data-testid="chip" />)
    const chip = screen.getByTestId('chip')
    expect(chip.getAttribute('aria-label')).toBeTruthy()
    expect(chip.getAttribute('aria-label')).toContain('AI')
  })
})

// ---------------------------------------------------------------------------
// EARS-451-4/5: ProvenanceChipLegend — renders + is dismissible
// ---------------------------------------------------------------------------

describe('ProvenanceChipLegend — first-appearance legend (EARS-451-4)', () => {
  it('renders the legend with correct copy', () => {
    render(<ProvenanceChipLegend />)
    const text = screen.getByTestId('provenance-legend-text')
    expect(text).toBeInTheDocument()
    expect(text.textContent).toContain('RULE')
    expect(text.textContent).toContain('deterministic rule')
    expect(text.textContent).toContain('AI')
    expect(text.textContent).toContain('local model verdict')
    expect(text.textContent).toContain('AI+RULE')
    expect(text.textContent).toContain('both')
    expect(text.textContent).toContain('Nothing here left your machine.')
  })

  it('legend has role="note" (accessible landmark for supplemental info)', () => {
    render(<ProvenanceChipLegend />)
    expect(screen.getByRole('note')).toBeInTheDocument()
  })

  it('renders a dismiss button', () => {
    render(<ProvenanceChipLegend />)
    expect(screen.getByTestId('provenance-legend-dismiss')).toBeInTheDocument()
  })

  it('dismiss button has accessible label', () => {
    render(<ProvenanceChipLegend />)
    const btn = screen.getByTestId('provenance-legend-dismiss')
    expect(btn.getAttribute('aria-label')).toBeTruthy()
  })
})

describe('ProvenanceChipLegend — dismiss + session persistence (EARS-451-5)', () => {
  it('clicking dismiss hides the legend immediately', () => {
    render(<ProvenanceChipLegend />)
    expect(screen.getByTestId('provenance-legend')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('provenance-legend-dismiss'))

    expect(screen.queryByTestId('provenance-legend')).not.toBeInTheDocument()
  })

  it('legend does not reappear after dismiss within the same session', () => {
    // First render — dismiss it
    const { unmount } = render(<ProvenanceChipLegend />)
    fireEvent.click(screen.getByTestId('provenance-legend-dismiss'))
    expect(screen.queryByTestId('provenance-legend')).not.toBeInTheDocument()
    unmount()

    // Second render in the same session — should NOT appear (sessionStorage persists)
    render(<ProvenanceChipLegend />)
    expect(screen.queryByTestId('provenance-legend')).not.toBeInTheDocument()
  })

  it('legend shows again after sessionStorage is cleared (new session)', () => {
    // Simulate a previous session having dismissed the legend
    sessionStorage.setItem('fw-provenance-legend-dismissed', 'true')

    const { unmount } = render(<ProvenanceChipLegend />)
    expect(screen.queryByTestId('provenance-legend')).not.toBeInTheDocument()
    unmount()

    // Clear session storage (new session)
    sessionStorage.clear()

    render(<ProvenanceChipLegend />)
    expect(screen.getByTestId('provenance-legend')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-451-7: AIRoute mounts the legend under the subtitle
// ---------------------------------------------------------------------------

describe('AIRoute — ProvenanceChipLegend mounted on AI Engine page (EARS-451-7)', () => {
  beforeEach(() => {
    mockFetchThreats.mockResolvedValue(THREATS_FIXTURE)
    mockFetchHealth.mockResolvedValue(HEALTH_AI_ONLINE)
  })

  it('renders the provenance legend on the AI Engine page', async () => {
    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-page-subtitle')).toBeInTheDocument()
    })

    expect(screen.getByTestId('provenance-legend')).toBeInTheDocument()
  })

  it('legend text appears after page loads', async () => {
    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('provenance-legend-text')).toBeInTheDocument()
    })

    const text = screen.getByTestId('provenance-legend-text')
    expect(text.textContent).toContain('Nothing here left your machine.')
  })

  it('legend can be dismissed from the AI Engine page', async () => {
    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('provenance-legend')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByTestId('provenance-legend-dismiss'))

    expect(screen.queryByTestId('provenance-legend')).not.toBeInTheDocument()
  })

  it('dismissing legend does NOT affect other page content', async () => {
    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-page-subtitle')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByTestId('provenance-legend-dismiss'))

    // Page subtitle and other elements remain intact
    expect(screen.getByTestId('ai-page-subtitle')).toBeInTheDocument()
    expect(screen.getByTestId('ai-page-title')).toHaveTextContent('AI Engine')
  })

  it('legend does not reappear if sessionStorage says already dismissed', async () => {
    sessionStorage.setItem('fw-provenance-legend-dismissed', 'true')

    renderRoute()

    await waitFor(() => {
      expect(screen.getByTestId('ai-page-subtitle')).toBeInTheDocument()
    })

    expect(screen.queryByTestId('provenance-legend')).not.toBeInTheDocument()
  })
})
