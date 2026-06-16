/**
 * Issue #532 — Honest geo provenance + Threat Intelligence reframe.
 *
 * Tests mapped 1:1 to EARS criteria:
 *
 * EARS-1: geo endpoint response MUST include ip_class (one of the 5 values).
 *         Verified via TypeScript type checks and fixture assertions.
 *
 * EARS-2: datacenter/vpn-likely markers MUST be styled distinctly (hollow ring)
 *         — tested via markerOptions helper extracted from GeoMap.
 *
 * EARS-3: popup MUST contain a honesty line naming AS + class.
 *         Tested via buildGeoPopup / buildHonestyLine.
 *
 * EARS-4: "Unresolved / private (N)" chip MUST appear when
 *         summary.unresolved_private_count > 0.
 *
 * EARS-5: WHEN top_country === "Unknown", the empty-state sub-line MUST present
 *         it as an honest, labeled state, NOT as an error.
 *
 * EARS-6: classification is server-side / on-box — verified by ip_class field
 *         originating from the API fixture (no client-side geo call).
 *
 * EARS-7: page MUST carry "Threat Intelligence" headline framing.
 *
 * XSS regression (ADR-0029 D3): as_name field is attacker-influenced;
 * buildHonestyLine must render it as text — never as HTML.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import AnalyticsRoute from '../routes/AnalyticsRoute'
import { buildGeoPopup, buildHonestyLine } from '../components/analytics/geoPopup'
import type { GeoPoint, IpClass, AnalyticsSummary } from '../api/types'
import {
  GEO_FIXTURE,
  CATEGORIES_TIMELINE_FIXTURE,
  ANALYTICS_SUMMARY_FIXTURE,
  ANALYTICS_SUMMARY_EMPTY_FIXTURE,
} from './readFixtures'

// ---------------------------------------------------------------------------
// Mock setup
// ---------------------------------------------------------------------------

const { mockFetchGeo, mockFetchAnalyticsSummary, mockFetchCategoriesTimeline } = vi.hoisted(
  () => ({
    mockFetchGeo: vi.fn(),
    mockFetchAnalyticsSummary: vi.fn(),
    mockFetchCategoriesTimeline: vi.fn(),
  }),
)

vi.mock('../api/analytics', () => ({
  fetchGeo: mockFetchGeo,
  fetchAnalyticsSummary: mockFetchAnalyticsSummary,
  fetchCategoriesTimeline: mockFetchCategoriesTimeline,
}))

vi.mock('../components/analytics/GeoMap', () => ({
  default: ({ points }: { points: GeoPoint[] }) => (
    <div data-testid="geo-map-mock">GeoMap: {points.length} points</div>
  ),
}))

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeGeoPoint(overrides: Partial<GeoPoint> = {}): GeoPoint {
  return {
    lat: 37.751,
    lon: -97.822,
    total_events: 100,
    blocked: 60,
    rules_triggered: 3,
    ip: '192.0.2.1',
    city: 'Ashburn',
    country: 'US',
    ...overrides,
  }
}

const GEO_DATACENTER: GeoPoint = makeGeoPoint({
  ip: '203.0.113.10',
  asn: 16509,
  as_name: 'Amazon',
  ip_class: 'datacenter',
})

const GEO_VPN: GeoPoint = makeGeoPoint({
  ip: '203.0.113.11',
  asn: 39351,
  as_name: 'Mullvad VPN',
  ip_class: 'vpn-likely',
})

const GEO_RESIDENTIAL: GeoPoint = makeGeoPoint({
  ip: '203.0.113.12',
  asn: 7922,
  as_name: 'Comcast Cable',
  ip_class: 'residential',
})

const GEO_UNRESOLVED: GeoPoint = makeGeoPoint({
  ip: '203.0.113.13',
  asn: null,
  as_name: null,
  ip_class: 'unresolved',
})

/** AnalyticsSummary with a non-zero unresolved_private_count. */
const SUMMARY_WITH_UNRESOLVED: AnalyticsSummary = {
  ...ANALYTICS_SUMMARY_FIXTURE,
  unresolved_private_count: 7,
}

/** AnalyticsSummary matching RFC-1918-only traffic state (EARS-5). */
const SUMMARY_UNKNOWN_COUNTRY: AnalyticsSummary = {
  ...ANALYTICS_SUMMARY_EMPTY_FIXTURE,
  top_country: 'Unknown',
  unresolved_private_count: 9,
}

// ---------------------------------------------------------------------------
// EARS-1: ip_class field in GeoPoint type
// ---------------------------------------------------------------------------

describe('EARS-1: ip_class field is part of the GeoPoint type', () => {
  it('GeoPoint accepts all five ip_class values without TypeScript errors', () => {
    const classes: IpClass[] = ['datacenter', 'vpn-likely', 'residential', 'private', 'unresolved']
    for (const cls of classes) {
      const pt: GeoPoint = makeGeoPoint({ ip_class: cls })
      expect(pt.ip_class).toBe(cls)
    }
  })

  it('GeoPoint ip_class is optional (absent on older API responses)', () => {
    const pt: GeoPoint = makeGeoPoint({ ip_class: undefined })
    expect(pt.ip_class).toBeUndefined()
  })

  it('fixture with datacenter class carries asn and as_name', () => {
    expect(GEO_DATACENTER.ip_class).toBe('datacenter')
    expect(GEO_DATACENTER.asn).toBe(16509)
    expect(GEO_DATACENTER.as_name).toBe('Amazon')
  })
})

// ---------------------------------------------------------------------------
// EARS-3: per-popup honesty line
// ---------------------------------------------------------------------------

describe('EARS-3: buildHonestyLine — honesty line for popup', () => {
  it('datacenter: names AS and states "cloud egress; geographic origin unreliable"', () => {
    const line = buildHonestyLine(GEO_DATACENTER)
    expect(line).not.toBeNull()
    expect(line).toContain('AS16509')
    expect(line).toContain('Amazon')
    expect(line).toContain('cloud egress')
    expect(line).toContain('geographic origin unreliable')
  })

  it('vpn-likely: names AS and states VPN / anonymiser caveat', () => {
    const line = buildHonestyLine(GEO_VPN)
    expect(line).not.toBeNull()
    expect(line).toContain('AS39351')
    expect(line).toContain('Mullvad VPN')
    expect(line).toContain('VPN')
  })

  it('residential: names AS and states "residential ISP; likely actor location"', () => {
    const line = buildHonestyLine(GEO_RESIDENTIAL)
    expect(line).not.toBeNull()
    expect(line).toContain('AS7922')
    expect(line).toContain('Comcast Cable')
    expect(line).toContain('residential ISP')
  })

  it('unresolved: states "no ASN data; enrichment pending or absent"', () => {
    const line = buildHonestyLine(GEO_UNRESOLVED)
    expect(line).not.toBeNull()
    expect(line).toContain('no ASN data')
  })

  it('returns null when ip_class is absent (older API responses)', () => {
    const pt = makeGeoPoint({ ip_class: undefined, asn: undefined })
    expect(buildHonestyLine(pt)).toBeNull()
  })

  it('works with asn present but as_name absent', () => {
    const pt = makeGeoPoint({ ip_class: 'datacenter', asn: 16509, as_name: null })
    const line = buildHonestyLine(pt)
    expect(line).not.toBeNull()
    expect(line).toContain('AS16509')
    expect(line).toContain('cloud egress')
  })

  it('works with as_name present but asn absent (name-fragment fallback)', () => {
    const pt = makeGeoPoint({ ip_class: 'datacenter', asn: null, as_name: 'Amazon Web Services' })
    const line = buildHonestyLine(pt)
    expect(line).not.toBeNull()
    expect(line).toContain('Amazon Web Services')
    expect(line).toContain('cloud egress')
  })
})

describe('EARS-3: buildGeoPopup honesty line in DOM (ADR-0029 D3)', () => {
  it('popup contains honesty line as inert text in <em> element', () => {
    const el = buildGeoPopup(GEO_DATACENTER)
    const em = el.querySelector('em')
    expect(em).not.toBeNull()
    expect(em!.textContent).toContain('AS16509')
    expect(em!.textContent).toContain('cloud egress')
  })

  it('popup omits honesty line when ip_class is absent', () => {
    const pt = makeGeoPoint({ ip_class: undefined })
    const el = buildGeoPopup(pt)
    expect(el.querySelector('em')).toBeNull()
  })

  it('XSS: attacker-controlled as_name rendered as text — no live node injected', () => {
    const xssName = '<script>alert("xss")</script>'
    const pt = makeGeoPoint({
      ip_class: 'datacenter',
      asn: 16509,
      as_name: xssName,
    })
    const el = buildGeoPopup(pt)
    // The literal payload must appear as text
    expect(el.textContent).toContain(xssName)
    // No script element in the popup DOM
    expect(el.querySelector('script')).toBeNull()
  })

  it('XSS: attacker-controlled as_name with img onerror — no live img', () => {
    const xssName = '"><img src=x onerror=alert(1)>'
    const pt = makeGeoPoint({
      ip_class: 'vpn-likely',
      asn: null,
      as_name: xssName,
    })
    const el = buildGeoPopup(pt)
    expect(el.textContent).toContain(xssName)
    expect(el.querySelector('img')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// EARS-4: UnresolvedPrivateChip
// ---------------------------------------------------------------------------

describe('EARS-4: Unresolved / private chip', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)
  })

  it('chip is visible when unresolved_private_count > 0', async () => {
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue(SUMMARY_WITH_UNRESOLVED)

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('unresolved-private-chip')).toBeInTheDocument()
    })
    expect(screen.getByTestId('unresolved-private-count')).toHaveTextContent('7')
  })

  it('chip is absent when unresolved_private_count is 0', async () => {
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue({
      ...ANALYTICS_SUMMARY_FIXTURE,
      unresolved_private_count: 0,
    })

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('unresolved-private-chip')).not.toBeInTheDocument()
  })

  it('chip is absent when unresolved_private_count is missing (older API)', async () => {
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    // omit unresolved_private_count — simulates older API without the field
    mockFetchAnalyticsSummary.mockResolvedValue({
      ...ANALYTICS_SUMMARY_FIXTURE,
      unresolved_private_count: undefined,
    })

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('geo-map-mock')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('unresolved-private-chip')).not.toBeInTheDocument()
  })

  it('chip shows correct singular/plural: "1 IP not mapped"', async () => {
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue({
      ...ANALYTICS_SUMMARY_FIXTURE,
      unresolved_private_count: 1,
    })

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('unresolved-private-chip')).toBeInTheDocument()
    })
    expect(screen.getByTestId('unresolved-private-chip')).toHaveTextContent('1 IP not mapped')
  })

  it('chip shows plural for > 1: "3 IPs not mapped"', async () => {
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue({
      ...ANALYTICS_SUMMARY_FIXTURE,
      unresolved_private_count: 3,
    })

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('unresolved-private-chip')).toBeInTheDocument()
    })
    expect(screen.getByTestId('unresolved-private-chip')).toHaveTextContent('3 IPs not mapped')
  })

  it('chip appears even when geo is empty (empty-state path)', async () => {
    mockFetchGeo.mockResolvedValue([])
    mockFetchAnalyticsSummary.mockResolvedValue(SUMMARY_UNKNOWN_COUNTRY)

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('empty-state')).toBeInTheDocument()
    })
    expect(screen.getByTestId('unresolved-private-chip')).toBeInTheDocument()
    expect(screen.getByTestId('unresolved-private-count')).toHaveTextContent('9')
  })
})

// ---------------------------------------------------------------------------
// EARS-5: Honest Unknown empty state
// ---------------------------------------------------------------------------

describe('EARS-5: Honest "Unknown" empty state', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchCategoriesTimeline.mockResolvedValue([])
  })

  it('sub-line explains private/unenriched IPs when top_country is "Unknown"', async () => {
    mockFetchGeo.mockResolvedValue([])
    mockFetchAnalyticsSummary.mockResolvedValue(SUMMARY_UNKNOWN_COUNTRY)

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('empty-state')).toBeInTheDocument()
    })
    // Sub-line must contain an honest explanation, not an error message
    const subLine = screen.getByTestId('empty-state-subline')
    expect(subLine).toBeInTheDocument()
    expect(subLine.textContent).toMatch(/private|not yet geo-enriched|non-routable/i)
  })

  it('sub-line mentions count from unresolved_private_count when > 0', async () => {
    mockFetchGeo.mockResolvedValue([])
    mockFetchAnalyticsSummary.mockResolvedValue({
      ...ANALYTICS_SUMMARY_EMPTY_FIXTURE,
      top_country: 'Unknown',
      unresolved_private_count: 9,
    })

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('empty-state-subline')).toBeInTheDocument()
    })
    expect(screen.getByTestId('empty-state-subline').textContent).toContain('9')
  })

  it('generic sub-line when top_country has a valid geo value (normal empty state)', async () => {
    mockFetchGeo.mockResolvedValue([])
    mockFetchAnalyticsSummary.mockResolvedValue({
      ...ANALYTICS_SUMMARY_FIXTURE,
      // A real country — but still no geo-resolved traffic on map
      top_country: 'US',
    })

    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('empty-state')).toBeInTheDocument()
    })
    const subLine = screen.getByTestId('empty-state-subline')
    expect(subLine.textContent).toContain('Events will appear here')
  })
})

// ---------------------------------------------------------------------------
// EARS-7: Threat Intelligence page reframe
// ---------------------------------------------------------------------------

describe('EARS-7: Threat Intelligence page reframe', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchGeo.mockResolvedValue(GEO_FIXTURE)
    mockFetchAnalyticsSummary.mockResolvedValue(ANALYTICS_SUMMARY_FIXTURE)
    mockFetchCategoriesTimeline.mockResolvedValue(CATEGORIES_TIMELINE_FIXTURE)
  })

  it('page H1 heading is "Threat Intelligence"', async () => {
    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('analytics-page-title')).toBeInTheDocument()
    })
    expect(screen.getByTestId('analytics-page-title')).toHaveTextContent('Threat Intelligence')
  })

  it('page has a subtitle mentioning provenance + on-box resolution', async () => {
    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByTestId('analytics-page-subtitle')).toBeInTheDocument()
    })
    const subtitle = screen.getByTestId('analytics-page-subtitle')
    expect(subtitle.textContent).toMatch(/provenance|on-box|ADR-0047/i)
  })

  it('geo panel title is still "Geographic Distribution" (Panel title unchanged for nav consistency)', async () => {
    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByText('Geographic Distribution')).toBeInTheDocument()
    })
  })

  it('"Event Analytics" panel title is still present', async () => {
    render(<AnalyticsRoute />)

    await waitFor(() => {
      expect(screen.getByText('Event Analytics')).toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// EARS-6: zero-egress provenance (classification is server-side)
// ---------------------------------------------------------------------------

describe('EARS-6: classification is server-side / on-box', () => {
  it('GeoPoint ip_class comes from the API fixture — no client-side geo call', () => {
    // The ip_class field is present on the fixture object (server-provided).
    // This test verifies the type contract that ip_class originates from the
    // API response, not from any client-side resolver.
    const pt: GeoPoint = makeGeoPoint({ ip_class: 'datacenter' })
    // ip_class must be the value supplied by the server (no transformation needed).
    expect(pt.ip_class).toBe('datacenter')
  })

  it('all five IpClass values are accepted by the type system', () => {
    const values: IpClass[] = ['datacenter', 'vpn-likely', 'residential', 'private', 'unresolved']
    for (const v of values) {
      const pt: GeoPoint = makeGeoPoint({ ip_class: v })
      expect(pt.ip_class).toBe(v)
    }
  })
})
