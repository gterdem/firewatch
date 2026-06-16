/**
 * Issue #533 — ASN / infrastructure lens (A2).
 *
 * Tests mapped 1:1 to EARS criteria:
 *
 * EARS-1: The Threat-Intelligence panel SHALL offer a "Country | ASN" segmented toggle.
 * EARS-2: WHEN ASN mode is active, THE app SHALL show a ranked top-N list of ASNs
 *         beside the map, each row showing AS number, AS name, event count, IP count,
 *         blocked %.
 * EARS-3: THE ASN list SHALL honor the bounded-height convention — top-N + "view all"
 *         (no inner scrollbar; pagination acceptable).
 * EARS-4: WHEN analyst clicks an ASN row, THE app SHALL pivot into Network Logs
 *         filtered to that ASN.
 * EARS-5: WHEN analyst clicks "Narrate" on an ASN, THE app SHALL produce a one-click
 *         local-LLM narrative reusing the shipped ML-7 narration path, labeled with
 *         ADR-0035 provenance chip, degrading to rule-only when LLM unavailable.
 * EARS-6: ALL aggregation and narration SHALL run on-box / zero-egress.
 * EARS-7: Actions SHALL be pivot / narrate only — no auto-block, no suppression.
 *
 * XSS regression (ADR-0029 D3):
 *   as_name is attacker-influenced — must render as text node only.
 *
 * CountryAsnToggle unit tests:
 *   Toggle renders both segments; clicking changes active segment.
 *
 * AsnPanel unit tests:
 *   Renders rows, shows "view all" when > DEFAULT_VISIBLE, handles empty/error/loading.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import CountryAsnToggle from '../components/analytics/CountryAsnToggle'
import AsnPanel from '../components/analytics/AsnPanel'
import AnalyticsRoute from '../routes/AnalyticsRoute'
import type { AsnRow, AsnNarrationResult } from '../api/types'
import {
  GEO_FIXTURE,
  ANALYTICS_SUMMARY_FIXTURE,
  CATEGORIES_TIMELINE_FIXTURE,
} from './readFixtures'

// ---------------------------------------------------------------------------
// Module mocks — must be at top level (Vitest hoists vi.mock calls)
// ---------------------------------------------------------------------------

const {
  mockFetchGeo,
  mockFetchAnalyticsSummary,
  mockFetchCategoriesTimeline,
  mockFetchAsnStats,
  mockFetchAsnNarration,
} = vi.hoisted(() => ({
  mockFetchGeo: vi.fn(),
  mockFetchAnalyticsSummary: vi.fn(),
  mockFetchCategoriesTimeline: vi.fn(),
  mockFetchAsnStats: vi.fn(),
  mockFetchAsnNarration: vi.fn(),
}))

vi.mock('../api/analytics', () => ({
  fetchGeo: mockFetchGeo,
  fetchAnalyticsSummary: mockFetchAnalyticsSummary,
  fetchCategoriesTimeline: mockFetchCategoriesTimeline,
  fetchAsnStats: mockFetchAsnStats,
  fetchAsnNarration: mockFetchAsnNarration,
}))

// GeoMap uses Leaflet + a geojson asset import — mock to avoid parse errors in jsdom.
vi.mock('../components/analytics/GeoMap', () => ({
  default: ({ points }: { points: unknown[] }) => (
    <div data-testid="geo-map-mock">GeoMap: {points.length} points</div>
  ),
}))

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeAsnRow(overrides: Partial<AsnRow> = {}): AsnRow {
  return {
    asn: 16509,
    as_name: 'Amazon',
    total_events: 412,
    distinct_ips: 18,
    blocked: 247,
    blocked_pct: 60.0,
    ...overrides,
  }
}

const ASN_FIXTURE: AsnRow[] = [
  makeAsnRow({ asn: 4837, as_name: 'China Unicom', total_events: 412, distinct_ips: 18, blocked: 247, blocked_pct: 60.0 }),
  makeAsnRow({ asn: 16509, as_name: 'Amazon', total_events: 120, distinct_ips: 5, blocked: 110, blocked_pct: 91.7 }),
  makeAsnRow({ asn: 7922, as_name: 'Comcast Cable', total_events: 85, distinct_ips: 3, blocked: 20, blocked_pct: 23.5 }),
]

const ASN_NARRATION_AI: AsnNarrationResult = {
  asn: 4837,
  narrative: 'AS4837 (China Unicom) generated 412 events from 18 IPs, with 60% blocked. Scanning behavior across 6 endpoints.',
  provenance: 'ai',
  collected_fields: ['asn', 'as_name', 'total_events', 'distinct_ips', 'blocked_pct'],
  ai_status: 'ok',
}

const ASN_NARRATION_RULE: AsnNarrationResult = {
  asn: 4837,
  narrative: 'AS4837 (China Unicom) generated 412 events from 18 IPs. 247 events (60.0%) were blocked.',
  provenance: 'rule',
  collected_fields: ['asn', 'as_name', 'total_events', 'distinct_ips', 'blocked_pct'],
  ai_status: 'unavailable',
}

// 8 rows to test "view all" affordance (> DEFAULT_VISIBLE=5).
const ASN_MANY_ROWS: AsnRow[] = Array.from({ length: 8 }, (_, i) =>
  makeAsnRow({ asn: 1000 + i, as_name: `AS-Name-${i}`, total_events: 100 - i * 5 }),
)

// Render helper — wraps in MemoryRouter for useNavigate support.
function renderInRouter(ui: React.ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>)
}

// ---------------------------------------------------------------------------
// CountryAsnToggle unit tests — EARS-1
// ---------------------------------------------------------------------------

describe('CountryAsnToggle — EARS-1', () => {
  it('renders both Country and ASN segments', () => {
    renderInRouter(<CountryAsnToggle value="country" onChange={vi.fn()} />)
    expect(screen.getByTestId('lens-country')).toBeInTheDocument()
    expect(screen.getByTestId('lens-asn')).toBeInTheDocument()
  })

  it('marks the active segment with aria-checked="true" (country default)', () => {
    renderInRouter(<CountryAsnToggle value="country" onChange={vi.fn()} />)
    expect(screen.getByTestId('lens-country')).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByTestId('lens-asn')).toHaveAttribute('aria-checked', 'false')
  })

  it('marks ASN segment active when value="asn"', () => {
    renderInRouter(<CountryAsnToggle value="asn" onChange={vi.fn()} />)
    expect(screen.getByTestId('lens-asn')).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByTestId('lens-country')).toHaveAttribute('aria-checked', 'false')
  })

  it('calls onChange with "asn" when ASN button is clicked', () => {
    const onChange = vi.fn()
    renderInRouter(<CountryAsnToggle value="country" onChange={onChange} />)
    fireEvent.click(screen.getByTestId('lens-asn'))
    expect(onChange).toHaveBeenCalledWith('asn')
  })

  it('calls onChange with "country" when Country button is clicked', () => {
    const onChange = vi.fn()
    renderInRouter(<CountryAsnToggle value="asn" onChange={onChange} />)
    fireEvent.click(screen.getByTestId('lens-country'))
    expect(onChange).toHaveBeenCalledWith('country')
  })

  it('has role="group" with accessible label', () => {
    renderInRouter(<CountryAsnToggle value="country" onChange={vi.fn()} />)
    expect(screen.getByRole('group', { name: /threat intelligence lens/i })).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// AsnPanel unit tests — EARS-2 / EARS-3 / EARS-4 / EARS-5 / EARS-7
// ---------------------------------------------------------------------------

describe('AsnPanel — EARS-2 row content', () => {
  it('renders a row for each ASN with correct data', () => {
    renderInRouter(<AsnPanel rows={ASN_FIXTURE} loading={false} error={null} />)
    const rows = screen.getAllByTestId('asn-row')
    expect(rows).toHaveLength(ASN_FIXTURE.length)
  })

  it('shows AS number as "AS{n}" in the pivot button (EARS-2)', () => {
    renderInRouter(<AsnPanel rows={[makeAsnRow({ asn: 4837 })]} loading={false} error={null} />)
    expect(screen.getByTestId('asn-pivot-btn')).toHaveTextContent('AS4837')
  })

  it('shows event count (EARS-2)', () => {
    renderInRouter(<AsnPanel rows={[makeAsnRow({ total_events: 412 })]} loading={false} error={null} />)
    expect(screen.getByTestId('asn-events')).toHaveTextContent('412')
  })

  it('shows distinct IP count (EARS-2)', () => {
    renderInRouter(<AsnPanel rows={[makeAsnRow({ distinct_ips: 18 })]} loading={false} error={null} />)
    expect(screen.getByTestId('asn-ips')).toHaveTextContent('18')
  })

  it('shows blocked % (EARS-2)', () => {
    renderInRouter(<AsnPanel rows={[makeAsnRow({ blocked_pct: 60.0 })]} loading={false} error={null} />)
    expect(screen.getByTestId('asn-blocked-pct')).toHaveTextContent('60%')
  })

  it('renders AS name as text node (EARS-2 / ADR-0029 D3)', () => {
    renderInRouter(<AsnPanel rows={[makeAsnRow({ as_name: 'China Unicom' })]} loading={false} error={null} />)
    expect(screen.getByTestId('asn-name')).toHaveTextContent('China Unicom')
  })

  it('XSS: attacker as_name rendered as text — no script injected (ADR-0029 D3)', () => {
    const xssName = '<script>alert("xss")</script>'
    renderInRouter(<AsnPanel rows={[makeAsnRow({ as_name: xssName })]} loading={false} error={null} />)
    const nameEl = screen.getByTestId('asn-name')
    expect(nameEl.textContent).toContain(xssName)
    expect(document.querySelector('script')).toBeNull()
  })

  it('renders "Unresolved ASN" for rows with null asn (EARS-2)', () => {
    renderInRouter(<AsnPanel rows={[makeAsnRow({ asn: null, as_name: null })]} loading={false} error={null} />)
    expect(screen.getByTestId('asn-pivot-btn')).toHaveTextContent('Unresolved ASN')
  })
})

describe('AsnPanel — EARS-3 bounded height', () => {
  it('shows only 5 rows by default', () => {
    renderInRouter(<AsnPanel rows={ASN_MANY_ROWS} loading={false} error={null} />)
    expect(screen.getAllByTestId('asn-row')).toHaveLength(5)
  })

  it('shows "View all N ASNs" button when rows > 5', () => {
    renderInRouter(<AsnPanel rows={ASN_MANY_ROWS} loading={false} error={null} />)
    expect(screen.getByTestId('asn-view-all-btn')).toHaveTextContent(`View all ${ASN_MANY_ROWS.length} ASNs`)
  })

  it('shows all rows after clicking "View all"', () => {
    renderInRouter(<AsnPanel rows={ASN_MANY_ROWS} loading={false} error={null} />)
    fireEvent.click(screen.getByTestId('asn-view-all-btn'))
    expect(screen.getAllByTestId('asn-row')).toHaveLength(ASN_MANY_ROWS.length)
  })

  it('shows "Show less" toggle after expanding', () => {
    renderInRouter(<AsnPanel rows={ASN_MANY_ROWS} loading={false} error={null} />)
    fireEvent.click(screen.getByTestId('asn-view-all-btn'))
    expect(screen.getByTestId('asn-view-all-btn')).toHaveTextContent('Show less')
  })

  it('does NOT show "view all" button when rows <= 5', () => {
    renderInRouter(<AsnPanel rows={ASN_FIXTURE} loading={false} error={null} />)
    expect(screen.queryByTestId('asn-view-all-btn')).not.toBeInTheDocument()
  })
})

describe('AsnPanel — EARS-4 click-to-pivot', () => {
  it('pivot button is present for each resolved ASN row', () => {
    renderInRouter(<AsnPanel rows={[makeAsnRow({ asn: 4837 })]} loading={false} error={null} />)
    expect(screen.getByTestId('asn-pivot-btn')).toBeInTheDocument()
  })

  it('pivot button has accessible label naming the ASN', () => {
    renderInRouter(<AsnPanel rows={[makeAsnRow({ asn: 4837 })]} loading={false} error={null} />)
    expect(screen.getByTestId('asn-pivot-btn')).toHaveAttribute(
      'aria-label',
      'View Network Logs filtered to AS4837',
    )
  })

  it('pivot button for unresolved ASN uses the as_name in label', () => {
    renderInRouter(
      <AsnPanel
        rows={[makeAsnRow({ asn: null, as_name: 'Unknown Org' })]}
        loading={false}
        error={null}
      />,
    )
    expect(screen.getByTestId('asn-pivot-btn')).toHaveAttribute(
      'aria-label',
      'View Network Logs filtered to Unresolved ASN',
    )
  })
})

describe('AsnPanel — EARS-5 click-to-narrate', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows a "Narrate" button per resolved ASN row', () => {
    renderInRouter(<AsnPanel rows={[makeAsnRow({ asn: 4837 })]} loading={false} error={null} />)
    expect(screen.getByTestId('asn-narrate-btn')).toBeInTheDocument()
  })

  it('does NOT show Narrate for unresolved (null asn) rows', () => {
    renderInRouter(<AsnPanel rows={[makeAsnRow({ asn: null })]} loading={false} error={null} />)
    expect(screen.queryByTestId('asn-narrate-btn')).not.toBeInTheDocument()
  })

  it('clicking Narrate calls fetchAsnNarration and shows narrative text', async () => {
    mockFetchAsnNarration.mockResolvedValue(ASN_NARRATION_AI)
    renderInRouter(<AsnPanel rows={[makeAsnRow({ asn: 4837 })]} loading={false} error={null} />)

    fireEvent.click(screen.getByTestId('asn-narrate-btn'))

    await waitFor(() => expect(screen.getByTestId('asn-narration-text')).toBeInTheDocument())
    expect(screen.getByTestId('asn-narration-text')).toHaveTextContent('AS4837')
    expect(mockFetchAsnNarration).toHaveBeenCalledWith(4837, true)
  })

  it('narration result shows ProvenanceChip (ADR-0035)', async () => {
    mockFetchAsnNarration.mockResolvedValue(ASN_NARRATION_AI)
    renderInRouter(<AsnPanel rows={[makeAsnRow({ asn: 4837 })]} loading={false} error={null} />)

    fireEvent.click(screen.getByTestId('asn-narrate-btn'))

    await waitFor(() => expect(screen.getByTestId('asn-narration-provenance')).toBeInTheDocument())
  })

  it('rule-only narration shows "Rules-only · AI offline" notice (EARS-5 degrade)', async () => {
    mockFetchAsnNarration.mockResolvedValue(ASN_NARRATION_RULE)
    renderInRouter(
      <AsnPanel rows={[makeAsnRow({ asn: 4837 })]} loading={false} error={null} aiAvailable={false} />,
    )

    fireEvent.click(screen.getByTestId('asn-narrate-btn'))

    await waitFor(() => expect(screen.getByTestId('asn-narration-rule-only-notice')).toBeInTheDocument())
    expect(mockFetchAsnNarration).toHaveBeenCalledWith(4837, false)
  })

  it('narration error shows message and Retry button', async () => {
    mockFetchAsnNarration.mockRejectedValue(new Error('LLM offline'))
    renderInRouter(<AsnPanel rows={[makeAsnRow({ asn: 4837 })]} loading={false} error={null} />)

    fireEvent.click(screen.getByTestId('asn-narrate-btn'))

    await waitFor(() => expect(screen.getByTestId('asn-narration-error')).toBeInTheDocument())
    expect(screen.getByTestId('asn-narration-error')).toHaveTextContent('LLM offline')
  })

  it('anti-fabrication: shows collected_fields from narration result', async () => {
    mockFetchAsnNarration.mockResolvedValue(ASN_NARRATION_AI)
    renderInRouter(<AsnPanel rows={[makeAsnRow({ asn: 4837 })]} loading={false} error={null} />)

    fireEvent.click(screen.getByTestId('asn-narrate-btn'))

    await waitFor(() => expect(screen.getByTestId('asn-narration-fields')).toBeInTheDocument())
    expect(screen.getByTestId('asn-narration-fields')).toHaveTextContent('asn')
  })

  it('Narrate button hint changes when aiAvailable=false', () => {
    renderInRouter(
      <AsnPanel rows={[makeAsnRow({ asn: 4837 })]} loading={false} error={null} aiAvailable={false} />,
    )
    // The narrate button should show "(rules)" hint
    expect(screen.getByTestId('asn-narrate-btn')).toHaveTextContent('rules')
  })
})

describe('AsnPanel — EARS-7 no auto-block', () => {
  it('panel has no block button (EARS-7 SIEM-now boundary)', () => {
    renderInRouter(<AsnPanel rows={ASN_FIXTURE} loading={false} error={null} />)
    expect(screen.queryByRole('button', { name: /block/i })).not.toBeInTheDocument()
  })

  it('panel has no suppress button (EARS-7 SIEM-now boundary)', () => {
    renderInRouter(<AsnPanel rows={ASN_FIXTURE} loading={false} error={null} />)
    expect(screen.queryByRole('button', { name: /suppress/i })).not.toBeInTheDocument()
  })
})

describe('AsnPanel — states', () => {
  it('shows loading state', () => {
    renderInRouter(<AsnPanel rows={[]} loading={true} error={null} />)
    expect(screen.getByTestId('asn-panel-loading')).toBeInTheDocument()
  })

  it('shows error state', () => {
    renderInRouter(<AsnPanel rows={[]} loading={false} error="ASN data unavailable (503)" />)
    expect(screen.getByTestId('asn-panel-error')).toBeInTheDocument()
  })

  it('shows empty state when no ASN data', () => {
    renderInRouter(<AsnPanel rows={[]} loading={false} error={null} />)
    expect(screen.getByTestId('asn-panel-empty')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// AnalyticsRoute integration: Country | ASN toggle wiring
// ---------------------------------------------------------------------------

describe('AnalyticsRoute — Country|ASN toggle integration', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)
    mockFetchAsnStats.mockResolvedValue(ASN_FIXTURE)
    mockFetchAsnNarration.mockResolvedValue(ASN_NARRATION_AI)
  })

  it('renders the Country|ASN toggle in the Threat Intelligence panel (EARS-1)', async () => {
    render(<MemoryRouter><AnalyticsRoute /></MemoryRouter>)
    await waitFor(() => expect(screen.getByTestId('country-asn-toggle')).toBeInTheDocument())
  })

  it('Country mode is default — shows geo map, not ASN panel (EARS-1)', async () => {
    render(<MemoryRouter><AnalyticsRoute /></MemoryRouter>)
    await waitFor(() => expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument())
    expect(screen.queryByTestId('asn-panel')).not.toBeInTheDocument()
  })

  it('switching to ASN mode shows AsnPanel and fetches ASN data (EARS-1/EARS-2)', async () => {
    render(<MemoryRouter><AnalyticsRoute /></MemoryRouter>)
    await waitFor(() => expect(screen.getByTestId('country-asn-toggle')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('lens-asn'))

    await waitFor(() => expect(screen.getByTestId('asn-panel')).toBeInTheDocument())
    expect(mockFetchAsnStats).toHaveBeenCalledTimes(1)
  })

  it('switching to ASN mode hides the geo map (EARS-1)', async () => {
    render(<MemoryRouter><AnalyticsRoute /></MemoryRouter>)
    await waitFor(() => expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('lens-asn'))
    await waitFor(() => expect(screen.getByTestId('asn-panel')).toBeInTheDocument())

    expect(screen.queryByTestId('geo-map-mock')).not.toBeInTheDocument()
  })

  it('switching back to Country mode restores geo map (EARS-1)', async () => {
    render(<MemoryRouter><AnalyticsRoute /></MemoryRouter>)
    await waitFor(() => expect(screen.getByTestId('country-asn-toggle')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('lens-asn'))
    await waitFor(() => expect(screen.getByTestId('asn-panel')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('lens-country'))
    await waitFor(() => expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument())
    expect(screen.queryByTestId('asn-panel')).not.toBeInTheDocument()
  })

  it('ASN data is NOT fetched on initial Country mode render (lazy load, EARS-6)', async () => {
    render(<MemoryRouter><AnalyticsRoute /></MemoryRouter>)
    await waitFor(() => expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument())
    expect(mockFetchAsnStats).not.toHaveBeenCalled()
  })

  it('ASN data is cached — switching back and forth only fetches once (EARS-6)', async () => {
    render(<MemoryRouter><AnalyticsRoute /></MemoryRouter>)
    await waitFor(() => expect(screen.getByTestId('country-asn-toggle')).toBeInTheDocument())

    // First switch to ASN — triggers fetch
    fireEvent.click(screen.getByTestId('lens-asn'))
    await waitFor(() => expect(screen.getByTestId('asn-panel')).toBeInTheDocument())
    expect(mockFetchAsnStats).toHaveBeenCalledTimes(1)

    // Switch back to country, then to ASN again — no second fetch
    fireEvent.click(screen.getByTestId('lens-country'))
    await waitFor(() => expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('lens-asn'))
    await waitFor(() => expect(screen.getByTestId('asn-panel')).toBeInTheDocument())
    expect(mockFetchAsnStats).toHaveBeenCalledTimes(1)
  })

  it('ASN panel shows ranked rows when data loads (EARS-2)', async () => {
    render(<MemoryRouter><AnalyticsRoute /></MemoryRouter>)
    await waitFor(() => expect(screen.getByTestId('country-asn-toggle')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('lens-asn'))
    await waitFor(() => expect(screen.getAllByTestId('asn-row')).toHaveLength(ASN_FIXTURE.length))
  })

  it('EARS-6: fetchAsnStats is called with top_n=15 (bounded, on-box)', async () => {
    render(<MemoryRouter><AnalyticsRoute /></MemoryRouter>)
    await waitFor(() => expect(screen.getByTestId('country-asn-toggle')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('lens-asn'))
    await waitFor(() => expect(screen.getByTestId('asn-panel')).toBeInTheDocument())
    expect(mockFetchAsnStats).toHaveBeenCalledWith(15)
  })
})

// ---------------------------------------------------------------------------
// Type contract tests
// ---------------------------------------------------------------------------

describe('AsnRow type contract (EARS-2)', () => {
  it('has all required numeric fields', () => {
    const row: AsnRow = makeAsnRow()
    expect(typeof row.total_events).toBe('number')
    expect(typeof row.distinct_ips).toBe('number')
    expect(typeof row.blocked).toBe('number')
    expect(typeof row.blocked_pct).toBe('number')
  })

  it('asn and as_name are nullable', () => {
    const row: AsnRow = makeAsnRow({ asn: null, as_name: null })
    expect(row.asn).toBeNull()
    expect(row.as_name).toBeNull()
  })
})

describe('AsnNarrationResult type contract (EARS-5)', () => {
  it('AI path has correct shape', () => {
    expect(ASN_NARRATION_AI.provenance).toBe('ai')
    expect(ASN_NARRATION_AI.ai_status).toBe('ok')
    expect(Array.isArray(ASN_NARRATION_AI.collected_fields)).toBe(true)
  })

  it('rule-only path has correct shape', () => {
    expect(ASN_NARRATION_RULE.provenance).toBe('rule')
    expect(ASN_NARRATION_RULE.ai_status).toBe('unavailable')
  })
})
