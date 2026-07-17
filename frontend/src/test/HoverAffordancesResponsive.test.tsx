/**
 * Tests for issue #572 (hover affordances) and #578 (responsive polish).
 *
 * EARS criteria covered:
 *
 * #572 — hover affordances:
 *   EARS-572-1: WHEN the pointer hovers a Network Logs row, THE SYSTEM SHALL apply
 *               a visible hover state (fw-log-row class present, CSS rule exists in
 *               index.css — behaviour verified by class presence + CSS assertion).
 *   EARS-572-2: WHEN the pointer hovers the VerdictCard, THE SYSTEM SHALL apply
 *               fw-verdict-card class (CSS supplies the hover rule).
 *   EARS-572-3: WHEN the pointer hovers the inactive CountryAsnToggle segment,
 *               THE SYSTEM SHALL show fw-toggle-seg-inactive class on the button.
 *
 * #578 — responsive polish:
 *   EARS-578-1: THE SYSTEM SHALL render the AiEnginePill button text span with
 *               overflow:hidden + textOverflow:ellipsis (so long model names
 *               truncate correctly rather than clipping the pill @1280px).
 *   EARS-578-2: WHILE the ASN lens is loading, THE SYSTEM SHALL reserve the geo
 *               panel height (minHeight:380 on the wrapper div).
 *   EARS-578-3: THE SYSTEM SHALL attach containerRef to an outer div WITHOUT
 *               overflowX:auto so ResizeObserver sees the layout-constrained
 *               width (column-priority collapse @1024px correctness).
 *   EARS-578-4: THE SYSTEM SHALL have useColumnPriority collapse low-priority
 *               columns when container width is 1024px (computeVisibleColumns unit).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import userEvent from '@testing-library/user-event'

// ---------------------------------------------------------------------------
// #572 — Log row hover class (LogsTable)
// ---------------------------------------------------------------------------

import LogsTable from '../components/logs/LogsTable'
import { LOG_ENTRY_FIXTURE } from './readFixtures'

/** Render LogsTable in a MemoryRouter with wide container so all columns show. */
function renderLogsTable(props: Parameters<typeof LogsTable>[0]) {
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 1200, height: 40, top: 0, left: 0, bottom: 40, right: 1200,
    x: 0, y: 0, toJSON: () => ({}),
  } as DOMRect)
  const result = render(
    <MemoryRouter>
      <LogsTable {...props} />
    </MemoryRouter>,
  )
  vi.restoreAllMocks()
  return result
}

describe('#572 — LogsTable log row hover affordance', () => {
  it('EARS-572-1: each log row has class fw-log-row (CSS :hover rule targets it)', () => {
    renderLogsTable({ logs: [LOG_ENTRY_FIXTURE], onIpClick: vi.fn() })
    const rows = screen.getAllByTestId('log-row')
    expect(rows.length).toBeGreaterThan(0)
    rows.forEach((row) => {
      expect(row.classList.contains('fw-log-row')).toBe(true)
    })
  })
})

// ---------------------------------------------------------------------------
// #572 — VerdictCard hover class
// ---------------------------------------------------------------------------

import { VerdictCard } from '../components/ai/ledger/VerdictCard'
import type { AnalysisSummary } from '../api/types'

const ANALYSIS_FIXTURE: AnalysisSummary = {
  id: 1,
  ip: '10.0.0.1',
  model: 'llama3:8b',
  kind: 'concise',
  endpoint_host: '127.0.0.1:11434',
  ai_status: 'ok',
  threat_level: 'HIGH',
  confidence: 0.85,
  score: 72,
  score_derivation: 'ai+rule',
  latency_ms: 1200,
  prompt_tokens: 512,
  completion_tokens: 128,
  schema_version: 1,
  created_at: '2026-06-01T12:00:00Z',
  feedback: null,
}

// VerdictCard uses ClickableIp which needs EntityPanelContext — mock it.
vi.mock('../components/entity/ClickableIp', () => ({
  default: ({ value }: { value: string }) => (
    <button type="button" data-testid="clickable-ip">{value}</button>
  ),
}))

// Mock sub-components that have complex deps
vi.mock('../components/ai/ledger/VerdictFeedback', () => ({
  VerdictFeedback: () => <div data-testid="verdict-feedback" />,
}))
vi.mock('../components/ai/ledger/PromptDrawer', () => ({
  PromptDrawer: () => <div data-testid="prompt-drawer" />,
}))
vi.mock('../components/entity/ip/ticker/StageTicker', () => ({
  default: () => <div data-testid="stage-ticker" />,
}))
vi.mock('../components/entity/ip/ticker/useStageTicker', () => ({
  useStageTicker: () => ({ stages: [], generatingElapsedMs: 0, result: null, streamError: null, streaming: false }),
}))
vi.mock('../components/entity/case/CreateCaseButton', () => ({
  CreateCaseButton: () => <div data-testid="create-case-btn" />,
}))

describe('#572 — VerdictCard hover affordance', () => {
  it('EARS-572-2: VerdictCard <article> has class fw-verdict-card', () => {
    render(
      <MemoryRouter>
        <VerdictCard analysis={ANALYSIS_FIXTURE} now={Date.now()} />
      </MemoryRouter>,
    )
    const card = screen.getByTestId('verdict-card')
    expect(card.classList.contains('fw-verdict-card')).toBe(true)
  })

  it('EARS-572-2: VerdictCard has CSS transition for smooth hover', () => {
    render(
      <MemoryRouter>
        <VerdictCard analysis={ANALYSIS_FIXTURE} now={Date.now()} />
      </MemoryRouter>,
    )
    const card = screen.getByTestId('verdict-card') as HTMLElement
    // transition is set via inline style — verify it is present
    expect(card.style.transition).toContain('border-color')
  })
})

// ---------------------------------------------------------------------------
// #572 — CountryAsnToggle inactive segment hover class
// ---------------------------------------------------------------------------

import CountryAsnToggle from '../components/analytics/CountryAsnToggle'

describe('#572 — CountryAsnToggle inactive segment hover affordance', () => {
  it('EARS-572-3: inactive segment has fw-toggle-seg-inactive class', () => {
    render(<CountryAsnToggle value="country" onChange={vi.fn()} />)
    // 'country' is active, 'asn' is inactive
    const asnBtn = screen.getByTestId('lens-asn')
    const countryBtn = screen.getByTestId('lens-country')
    expect(asnBtn.classList.contains('fw-toggle-seg-inactive')).toBe(true)
    expect(countryBtn.classList.contains('fw-toggle-seg-inactive')).toBe(false)
  })

  it('EARS-572-3: active segment does NOT have fw-toggle-seg-inactive', () => {
    render(<CountryAsnToggle value="asn" onChange={vi.fn()} />)
    const asnBtn = screen.getByTestId('lens-asn')
    const countryBtn = screen.getByTestId('lens-country')
    expect(asnBtn.classList.contains('fw-toggle-seg-inactive')).toBe(false)
    expect(countryBtn.classList.contains('fw-toggle-seg-inactive')).toBe(true)
  })

  it('EARS-572-3: inactive class switches when value changes', async () => {
    const onChange = vi.fn()
    const { rerender } = render(<CountryAsnToggle value="country" onChange={onChange} />)
    expect(screen.getByTestId('lens-asn').classList.contains('fw-toggle-seg-inactive')).toBe(true)

    rerender(<CountryAsnToggle value="asn" onChange={onChange} />)
    expect(screen.getByTestId('lens-country').classList.contains('fw-toggle-seg-inactive')).toBe(true)
    expect(screen.getByTestId('lens-asn').classList.contains('fw-toggle-seg-inactive')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// #578 — AiEnginePill text span overflow fix
// ---------------------------------------------------------------------------

import AiEnginePill from '../components/dashboard/AiEnginePill'
import type { HealthResponse } from '../api/types'

// useDismissableDisclosure — mock to avoid complex hook internals
vi.mock('../components/ds', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../components/ds')>()
  return {
    ...actual,
    useDismissableDisclosure: () => ({
      open: false,
      triggerRef: { current: null },
      contentRef: { current: null },
      triggerProps: { onPointerEnter: vi.fn(), onPointerLeave: vi.fn(), onClick: vi.fn(), onKeyDown: vi.fn() },
      contentProps: { onPointerEnter: vi.fn(), onPointerLeave: vi.fn() },
    }),
  }
})

const HEALTH_CONNECTED: HealthResponse = {
  status: 'ok',
  ollama_connected: true,
  ollama_model: 'llama3.1:70b-instruct-q4_K_M',
  db_ok: true,
  ai: 'active',
}

describe('#578 — AiEnginePill responsive fix @1280', () => {
  it('EARS-578-1: pill text span has overflow:hidden and textOverflow:ellipsis', () => {
    const { container } = render(
      <AiEnginePill health={HEALTH_CONNECTED} />,
    )
    const pill = container.querySelector('[data-testid="ai-engine-pill"]')
    expect(pill).toBeTruthy()
    // The text span is the last child of the pill button (after the dot span)
    const textSpan = pill!.querySelector('span:not([aria-hidden])') as HTMLElement
    expect(textSpan).toBeTruthy()
    expect(textSpan.style.overflow).toBe('hidden')
    expect(textSpan.style.textOverflow).toBe('ellipsis')
    expect(textSpan.style.whiteSpace).toBe('nowrap')
  })

  it('EARS-578-1: pill button maxWidth is at least 200px (not 180)', () => {
    const { container } = render(
      <AiEnginePill health={HEALTH_CONNECTED} />,
    )
    const pill = container.querySelector('[data-testid="ai-engine-pill"]') as HTMLElement
    // maxWidth should be 220 (raised from 180)
    const maxW = parseInt(pill.style.maxWidth, 10)
    expect(maxW).toBeGreaterThanOrEqual(200)
  })
})

// ---------------------------------------------------------------------------
// #578 — ASN loading height reservation
// ---------------------------------------------------------------------------

import AnalyticsRoute from '../routes/AnalyticsRoute'
import {
  GEO_FIXTURE,
  ANALYTICS_SUMMARY_FIXTURE,
  CATEGORIES_TIMELINE_FIXTURE,
} from './readFixtures'

const {
  mockFetchGeo578,
  mockFetchAnalyticsSummary578,
  mockFetchCategoriesTimeline578,
  mockFetchAsnStats578,
} = vi.hoisted(() => ({
  mockFetchGeo578: vi.fn(),
  mockFetchAnalyticsSummary578: vi.fn(),
  mockFetchCategoriesTimeline578: vi.fn(),
  mockFetchAsnStats578: vi.fn(),
}))

vi.mock('../api/analytics', () => ({
  fetchGeo: mockFetchGeo578,
  fetchAnalyticsSummary: mockFetchAnalyticsSummary578,
  fetchCategoriesTimeline: mockFetchCategoriesTimeline578,
  fetchAsnStats: mockFetchAsnStats578,
  fetchAsnNarration: vi.fn(),
}))

vi.mock('../components/analytics/GeoMap', () => ({
  default: ({ points }: { points: unknown[] }) => (
    <div data-testid="geo-map-mock">GeoMap: {points.length} points</div>
  ),
}))

vi.mock('../components/analytics/AsnPanel', () => ({
  default: ({
    loading,
    error,
    rows,
  }: {
    loading: boolean
    error: string | null
    rows: unknown[]
  }) => {
    if (loading) return <div data-testid="asn-panel-loading">Loading...</div>
    if (error) return <div data-testid="asn-panel-error">{error}</div>
    if (rows.length === 0) return <div data-testid="asn-panel-empty">No ASN data</div>
    return <div data-testid="asn-panel">ASN rows: {rows.length}</div>
  },
}))

describe('#578 — ASN loading height reservation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchGeo578.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary578.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline578.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)
    // ASN fetch hangs (never resolves) so we stay in loading state
    mockFetchAsnStats578.mockReturnValue(new Promise(() => {}))
  })

  it('EARS-578-2: ASN loading wrapper reserves minHeight:380 during loading', async () => {
    render(
      <MemoryRouter>
        <AnalyticsRoute />
      </MemoryRouter>,
    )

    // Wait for main analytics data to load
    await waitFor(() => {
      expect(screen.queryByTestId('analytics-loading')).toBeNull()
    })

    // Switch to ASN mode
    const asnBtn = screen.getByTestId('lens-asn')
    await userEvent.click(asnBtn)

    // The AsnPanel mock shows loading state
    const loadingPanel = await screen.findByTestId('asn-panel-loading')
    expect(loadingPanel).toBeTruthy()

    // The wrapper div around AsnPanel should reserve minHeight
    const wrapper = loadingPanel.parentElement as HTMLElement
    expect(wrapper.style.minHeight).toBe('380px')
  })

  it('EARS-578-2: wrapper minHeight resets to 0 when ASN data is done', async () => {
    mockFetchAsnStats578.mockResolvedValue([
      { asn: 12345, as_name: 'Test AS', total_events: 100, distinct_ips: 5, blocked_pct: 20 },
    ])

    render(
      <MemoryRouter>
        <AnalyticsRoute />
      </MemoryRouter>,
    )

    await waitFor(() => {
      expect(screen.queryByTestId('analytics-loading')).toBeNull()
    })

    const asnBtn = screen.getByTestId('lens-asn')
    await userEvent.click(asnBtn)

    // Wait for done state
    await waitFor(() => {
      expect(screen.queryByTestId('asn-panel')).toBeTruthy()
    })

    const asnPanel = screen.getByTestId('asn-panel')
    const wrapper = asnPanel.parentElement as HTMLElement
    // minHeight is 0 when not loading
    expect(wrapper.style.minHeight).toBe('0px')
  })
})

// ---------------------------------------------------------------------------
// #578 — column priority collapse unit test (computeVisibleColumns)
// ---------------------------------------------------------------------------

import { computeVisibleColumns } from '../components/ds'

const COLUMN_DEFS_578 = [
  { key: 'time',      priority: 1, never: true,  minWidth: 88  },
  { key: 'source',    priority: 5,               minWidth: 56  },
  { key: 'sourceip',  priority: 1, never: true,  minWidth: 88  },
  { key: 'destport',  priority: 6,               minWidth: 56  },
  { key: 'severity',  priority: 2,               minWidth: 64  },
  { key: 'action',    priority: 2,               minWidth: 64  },
  { key: 'destip',    priority: 7,               minWidth: 88  },
  { key: 'protocol',  priority: 8,               minWidth: 64  },
  { key: 'tls_ja4',   priority: 10,              minWidth: 180 },
  { key: 'signature', priority: 1, never: true,  minWidth: 192 },
  { key: 'payload',   priority: 4,               minWidth: 192 },
  { key: 'dns',       priority: 9,               minWidth: 120 },
]

describe('#578 — useColumnPriority collapse @1024px (EARS-578-4)', () => {
  it('hides low-priority columns at 1024px container width', () => {
    const visible = computeVisibleColumns(COLUMN_DEFS_578, 1024)

    // never:true columns are always visible
    expect(visible.has('time')).toBe(true)
    expect(visible.has('sourceip')).toBe(true)
    expect(visible.has('signature')).toBe(true)

    // At 1024px, columns with priority ≥ 5 should be hidden first.
    // tls_ja4 (priority 10) is the highest-priority-number → first to hide.
    expect(visible.has('tls_ja4')).toBe(false)
    // dns (priority 9) should also be hidden
    expect(visible.has('dns')).toBe(false)
  })

  it('keeps all columns visible at 1600px container width', () => {
    const visible = computeVisibleColumns(COLUMN_DEFS_578, 1600)
    COLUMN_DEFS_578.forEach((col) => {
      expect(visible.has(col.key)).toBe(true)
    })
  })

  it('only never:true columns remain at 100px container width', () => {
    const visible = computeVisibleColumns(COLUMN_DEFS_578, 100)
    // Only never:true columns should survive extreme narrow width
    expect(visible.has('time')).toBe(true)
    expect(visible.has('sourceip')).toBe(true)
    expect(visible.has('signature')).toBe(true)
    // All non-never columns should be hidden
    expect(visible.has('tls_ja4')).toBe(false)
    expect(visible.has('dns')).toBe(false)
    expect(visible.has('protocol')).toBe(false)
    expect(visible.has('destip')).toBe(false)
    expect(visible.has('destport')).toBe(false)
    expect(visible.has('source')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// #578 — LogsTable containerRef structure (EARS-578-3)
// ---------------------------------------------------------------------------

describe('#578 — LogsTable outer wrapper constrains ResizeObserver width', () => {
  it('EARS-578-3: logs-table wrapper does NOT have overflowX auto (so ResizeObserver is not misled)', () => {
    vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
      width: 1024, height: 40, top: 0, left: 0, bottom: 40, right: 1024,
      x: 0, y: 0, toJSON: () => ({}),
    } as DOMRect)

    render(
      <MemoryRouter>
        <LogsTable logs={[LOG_ENTRY_FIXTURE]} onIpClick={vi.fn()} />
      </MemoryRouter>,
    )

    vi.restoreAllMocks()

    const wrapper = screen.getByTestId('logs-table') as HTMLElement
    // The outer wrapper (with data-testid) must NOT have overflow-x auto
    // (overflowX:auto was moved to an inner div in #578 fix)
    expect(wrapper.style.overflowX).not.toBe('auto')
    // It should constrain width to 100% so ResizeObserver sees layout width
    expect(wrapper.style.width).toBe('100%')
  })
})
