/**
 * Tests for IpHeaderMeta and the SlideOver `headerMeta` slot (issue #265).
 *
 * EARS acceptance criteria covered:
 *
 * 1. WHEN the IP panel opens, THE SlideOver header SHALL render a meta line with:
 *    - IP in mono font
 *    - (City, Country) from `location`
 *    - AS <asn> <as_name>
 *    - relative first-seen (via lib/time relativeTime)
 *    - a copy-IP affordance
 *
 * 2. WHEN any enrichment field is absent (cache miss), THE header SHALL omit
 *    that fragment gracefully — no placeholders.
 *
 * 3. THE meta line SHALL come from the fast /threats/{ip} DTO — the component
 *    accepts ThreatScore directly (no new fetch).
 *
 * 4. `headerMeta` SHALL be a generic SlideOver slot (ReactNode) — no IP-specific
 *    code inside SlideOver.
 *
 * 5. WHEN geo/ASN is shown, AN enrichment-provenance stamp SHALL be present
 *    ("geo cached locally").
 *
 * 6. lib/time.ts `relativeTime` — unit tests for the new function.
 *
 * Security: location/as_name are attacker-controlled geo strings — rendered
 * as text nodes (no innerHTML injection path).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import IpHeaderMeta from '../components/entity/ip/IpHeaderMeta'
import SlideOver from '../components/entity/SlideOver'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import { useEntityPanel } from '../components/entity/EntityPanelContext'
import { relativeTime } from '../lib/time'
import type { ThreatScore } from '../api/types'
import { THREATS_FIXTURE } from './readFixtures'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('../api/logs', () => ({
  fetchThreatScore: vi.fn(),
  fetchDetailedAnalysis: vi.fn(),
  fetchRules: vi.fn(),
  fetchIpEvents: vi.fn(),
}))

vi.mock('../api/client', () => ({
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchThreats: vi.fn().mockResolvedValue([]),
  // Issue #268: useDeepAnalysis calls fetchHealth; default to AI offline so it resolves instantly.
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'ok', ollama_connected: false, ollama_model: null, db_ok: true,
  }),
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
// Fixtures
// ---------------------------------------------------------------------------

/** Full ThreatScore with geo, ASN, and first_seen populated. */
const SCORE_FULL: ThreatScore = {
  ...THREATS_FIXTURE[0],
  source_ip: '192.0.2.1',
  location: 'Bern, Switzerland',
  asn: 51852,
  as_name: 'PROTON',
  first_seen: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(), // 2h ago
}

/** ThreatScore with all enrichment fields null (cache miss). */
const SCORE_NO_ENRICHMENT: ThreatScore = {
  ...THREATS_FIXTURE[0],
  source_ip: '192.0.2.2',
  location: null,
  asn: null,
  as_name: null,
  first_seen: null,
}

/** ThreatScore with location only (no ASN). */
const SCORE_GEO_ONLY: ThreatScore = {
  ...THREATS_FIXTURE[0],
  source_ip: '192.0.2.3',
  location: 'Chicago, United States',
  asn: null,
  as_name: null,
  first_seen: new Date(Date.now() - 5 * 60 * 1000).toISOString(), // 5m ago
}

/** ThreatScore with ASN only (no location string). */
const SCORE_ASN_ONLY: ThreatScore = {
  ...THREATS_FIXTURE[0],
  source_ip: '192.0.2.4',
  location: null,
  asn: 4837,
  as_name: 'CHINA-UNICOM',
  first_seen: null,
}

// ---------------------------------------------------------------------------
// lib/time relativeTime — unit tests
// ---------------------------------------------------------------------------

describe('relativeTime — unit tests (issue #265)', () => {
  it('returns "just now" for a date < 60s ago', () => {
    const d = new Date(Date.now() - 30_000) // 30s
    expect(relativeTime(d)).toBe('just now')
  })

  it('returns Xm ago for 1–59 minutes', () => {
    const d = new Date(Date.now() - 5 * 60 * 1000) // 5m
    expect(relativeTime(d)).toBe('5m ago')
  })

  it('returns Xh ago for 1–23 hours', () => {
    const d = new Date(Date.now() - 3 * 60 * 60 * 1000) // 3h
    expect(relativeTime(d)).toBe('3h ago')
  })

  it('returns Xd ago for 1–29 days', () => {
    const d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) // 7d
    expect(relativeTime(d)).toBe('7d ago')
  })

  it('returns a month/year label for dates >= 30 days old', () => {
    const d = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000) // 40d
    const result = relativeTime(d)
    // Should be a non-empty string (month + year format)
    expect(result).toBeTruthy()
    expect(result).not.toContain('ago')
  })

  it('returns empty string for an invalid Date', () => {
    expect(relativeTime(new Date(NaN))).toBe('')
  })

  it('returns empty string for a future date', () => {
    const future = new Date(Date.now() + 60_000)
    expect(relativeTime(future)).toBe('')
  })
})

// ---------------------------------------------------------------------------
// IpHeaderMeta — unit tests
// ---------------------------------------------------------------------------

describe('IpHeaderMeta — renders nothing when score is null', () => {
  it('returns null when score prop is null', () => {
    const { container } = render(<IpHeaderMeta score={null} />)
    expect(container.firstChild).toBeNull()
  })
})

describe('IpHeaderMeta — full enrichment', () => {
  it('renders the meta container when geo is present', () => {
    render(<IpHeaderMeta score={SCORE_FULL} />)
    expect(screen.getByTestId('ip-header-meta')).toBeInTheDocument()
  })

  // Issue #336: IP is now in the breadcrumb (exactly once) — IpHeaderMeta no longer
  // renders the IP span. The copy button encodes the IP in its aria-label instead.
  it('does NOT render a redundant IP span (IP lives in breadcrumb per issue #336)', () => {
    render(<IpHeaderMeta score={SCORE_FULL} />)
    expect(screen.queryByTestId('ip-header-meta-ip')).toBeNull()
  })

  it('renders (City, Country) from location field', () => {
    render(<IpHeaderMeta score={SCORE_FULL} />)
    expect(screen.getByTestId('ip-header-meta-geo')).toHaveTextContent('(Bern, Switzerland)')
  })

  it('renders AS number and AS name', () => {
    render(<IpHeaderMeta score={SCORE_FULL} />)
    const asnEl = screen.getByTestId('ip-header-meta-asn')
    expect(asnEl).toHaveTextContent('AS 51852 PROTON')
  })

  it('renders first-seen as relative time', () => {
    render(<IpHeaderMeta score={SCORE_FULL} />)
    const fsEl = screen.getByTestId('ip-header-meta-first-seen')
    // first_seen is 2h ago
    expect(fsEl).toHaveTextContent('first seen')
    expect(fsEl.textContent).toMatch(/\d+(m|h|d) ago|just now/)
  })

  it('renders the copy button', () => {
    render(<IpHeaderMeta score={SCORE_FULL} />)
    const copyBtn = screen.getByTestId('ip-header-meta-copy')
    expect(copyBtn).toBeInTheDocument()
    expect(copyBtn).toHaveAttribute('aria-label', 'Copy IP address 192.0.2.1')
  })

  it('renders the provenance stamp when geo is present', () => {
    render(<IpHeaderMeta score={SCORE_FULL} />)
    expect(screen.getByTestId('ip-header-meta-provenance')).toHaveTextContent('geo cached locally')
  })
})

describe('IpHeaderMeta — graceful degradation (null fields)', () => {
  it('renders nothing when all enrichment fields are null', () => {
    const { container } = render(<IpHeaderMeta score={SCORE_NO_ENRICHMENT} />)
    // No meta container rendered when nothing to show
    expect(container.firstChild).toBeNull()
  })

  it('renders geo without ASN when asn is null', () => {
    render(<IpHeaderMeta score={SCORE_GEO_ONLY} />)
    expect(screen.getByTestId('ip-header-meta-geo')).toHaveTextContent('(Chicago, United States)')
    expect(screen.queryByTestId('ip-header-meta-asn')).toBeNull()
  })

  it('renders ASN without geo when location is null', () => {
    render(<IpHeaderMeta score={SCORE_ASN_ONLY} />)
    expect(screen.queryByTestId('ip-header-meta-geo')).toBeNull()
    const asnEl = screen.getByTestId('ip-header-meta-asn')
    expect(asnEl).toHaveTextContent('AS 4837 CHINA-UNICOM')
  })

  it('omits first-seen when first_seen is null', () => {
    render(<IpHeaderMeta score={SCORE_ASN_ONLY} />)
    expect(screen.queryByTestId('ip-header-meta-first-seen')).toBeNull()
  })

  it('shows provenance stamp when ASN present but no location', () => {
    render(<IpHeaderMeta score={SCORE_ASN_ONLY} />)
    // ASN is geo data too — provenance stamp should show
    expect(screen.getByTestId('ip-header-meta-provenance')).toBeInTheDocument()
  })

  it('renders ASN number alone when as_name is null', () => {
    const scoreAsnNoName: ThreatScore = {
      ...SCORE_FULL,
      as_name: null,
      asn: 4837,
    }
    render(<IpHeaderMeta score={scoreAsnNoName} />)
    const asnEl = screen.getByTestId('ip-header-meta-asn')
    expect(asnEl).toHaveTextContent('AS 4837')
    expect(asnEl.textContent).not.toContain('null')
  })
})

describe('IpHeaderMeta — XSS safety (attacker-controlled geo strings)', () => {
  it('renders malicious location as a text node — no script injection', () => {
    const xssScore: ThreatScore = {
      ...SCORE_FULL,
      location: '<script>alert("xss")</script>',
    }
    render(<IpHeaderMeta score={xssScore} />)
    // Text content should show the raw string, not execute it
    expect(screen.getByTestId('ip-header-meta-geo').textContent).toContain('<script>')
    // No script element injected into the DOM
    expect(document.querySelectorAll('script[src]').length).toBe(0)
  })
})

describe('IpHeaderMeta — copy button', () => {
  beforeEach(() => {
    // Mock clipboard API
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
      configurable: true,
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('calls navigator.clipboard.writeText with the IP on copy click', async () => {
    render(<IpHeaderMeta score={SCORE_FULL} />)
    const copyBtn = screen.getByTestId('ip-header-meta-copy')
    await userEvent.click(copyBtn)
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('192.0.2.1')
  })

  it('shows a check mark after copying', async () => {
    render(<IpHeaderMeta score={SCORE_FULL} />)
    const copyBtn = screen.getByTestId('ip-header-meta-copy')
    await userEvent.click(copyBtn)
    await waitFor(() => {
      expect(screen.getByTestId('ip-header-meta-copy')).toHaveTextContent('✓')
    })
  })
})

// ---------------------------------------------------------------------------
// SlideOver — headerMeta slot is entity-kind-agnostic
// ---------------------------------------------------------------------------

describe('SlideOver — headerMeta slot is entity-kind-agnostic (issue #265)', () => {
  it('renders headerMeta slot when provided', () => {
    render(
      <SlideOver
        open={true}
        onClose={vi.fn()}
        ariaLabel="test panel"
        headerMeta={<div data-testid="custom-meta">group meta here</div>}
      >
        body
      </SlideOver>,
    )
    expect(screen.getByTestId('slide-over-header-meta')).toBeInTheDocument()
    expect(screen.getByTestId('custom-meta')).toHaveTextContent('group meta here')
  })

  it('does NOT render slide-over-header-meta when headerMeta is not provided', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test panel">
        body
      </SlideOver>,
    )
    expect(screen.queryByTestId('slide-over-header-meta')).not.toBeInTheDocument()
  })

  it('SlideOver body is unchanged when headerMeta is present', () => {
    render(
      <SlideOver
        open={true}
        onClose={vi.fn()}
        ariaLabel="test panel"
        headerMeta={<span>meta</span>}
      >
        <div data-testid="body-content">panel body</div>
      </SlideOver>,
    )
    expect(screen.getByTestId('body-content')).toHaveTextContent('panel body')
    expect(screen.getByTestId('slide-over-body')).toBeInTheDocument()
  })

  it('breadcrumbs are unchanged when headerMeta is present', () => {
    render(
      <SlideOver
        open={true}
        onClose={vi.fn()}
        ariaLabel="test panel"
        breadcrumbs={[{ label: '192.0.2.1' }]}
        headerMeta={<span>meta</span>}
      >
        body
      </SlideOver>,
    )
    expect(screen.getByTestId('breadcrumb-0')).toHaveTextContent('192.0.2.1')
  })
})

// ---------------------------------------------------------------------------
// EntityPanelProvider — headerMeta wired for IP entities
// ---------------------------------------------------------------------------

describe('EntityPanelProvider — headerMeta shown for IP entities', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    const { fetchIpEvents, fetchDetailedAnalysis, fetchRules } = await import('../api/logs')
    vi.mocked(fetchIpEvents).mockResolvedValue(null)
    vi.mocked(fetchDetailedAnalysis).mockReturnValue(new Promise(() => {}))
    vi.mocked(fetchRules).mockReturnValue(new Promise(() => {}))
  })

  function TestOpener({ ip }: { ip: string }) {
    const { openEntity } = useEntityPanel()
    return (
      <button data-testid="open-btn" onClick={() => openEntity({ kind: 'ip', value: ip })}>
        Open
      </button>
    )
  }

  it('renders ip-header-meta after score resolves with geo/ASN data', async () => {
    // Use the module-level mocks (already set up via vi.mock above)
    const { fetchThreatScore } = await import('../api/logs')
    vi.mocked(fetchThreatScore).mockResolvedValue(SCORE_FULL)

    render(
      <EntityPanelProvider>
        <TestOpener ip="192.0.2.1" />
      </EntityPanelProvider>,
    )

    await userEvent.click(screen.getByTestId('open-btn'))

    await waitFor(() => {
      expect(screen.getByTestId('ip-header-meta')).toBeInTheDocument()
    })
    expect(screen.getByTestId('ip-header-meta-geo')).toHaveTextContent('(Bern, Switzerland)')
    expect(screen.getByTestId('ip-header-meta-asn')).toHaveTextContent('AS 51852 PROTON')
    expect(screen.getByTestId('ip-header-meta-provenance')).toBeInTheDocument()
  })

  it('does not render ip-header-meta when score is null (no threat record)', async () => {
    const { fetchThreatScore } = await import('../api/logs')
    vi.mocked(fetchThreatScore).mockResolvedValue(null)

    render(
      <EntityPanelProvider>
        <TestOpener ip="192.0.2.9" />
      </EntityPanelProvider>,
    )

    await userEvent.click(screen.getByTestId('open-btn'))
    // Panel opens
    await waitFor(() => expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument())
    // Wait for the score fetch to settle
    await act(async () => { await new Promise((r) => setTimeout(r, 10)) })
    // No meta rendered when score is null
    expect(screen.queryByTestId('ip-header-meta')).not.toBeInTheDocument()
  })

  it('does not render ip-header-meta when score has all nulls (cache miss)', async () => {
    const { fetchThreatScore } = await import('../api/logs')
    vi.mocked(fetchThreatScore).mockResolvedValue(SCORE_NO_ENRICHMENT)

    render(
      <EntityPanelProvider>
        <TestOpener ip="192.0.2.2" />
      </EntityPanelProvider>,
    )

    await userEvent.click(screen.getByTestId('open-btn'))
    await waitFor(() => expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument())
    await act(async () => { await new Promise((r) => setTimeout(r, 10)) })
    // SCORE_NO_ENRICHMENT has no location/asn/first_seen → IpHeaderMeta renders null
    expect(screen.queryByTestId('ip-header-meta')).not.toBeInTheDocument()
  })
})
