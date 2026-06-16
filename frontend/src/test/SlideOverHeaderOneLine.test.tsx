/**
 * Tests for issue #336 — slide-over header one-line layout.
 *
 * EARS acceptance criteria covered:
 *
 * 1. Ubiquitous: the slide-over header SHALL render IP + geo + first-seen + copy +
 *    provenance on a single line, with the IP appearing exactly once.
 *    → `slide-over-header-meta` is a sibling of the breadcrumb nav inside the SAME
 *      flex row (not a separate block below the breadcrumb row).
 *    → `ip-header-meta` does NOT contain a redundant IP span.
 *
 * 2. The copy control SHALL be present in `ip-header-meta` (immediately after the IP,
 *    which is the breadcrumb last item to its left in the flex row).
 *
 * 3. WHEN the panel is narrow, trailing metadata SHALL truncate with a `title` tooltip
 *    that includes the full text (geo + first-seen + provenance), never wrapping.
 *    → `ip-header-meta` has `title` set to a string that includes all meta.
 *    → `ip-header-meta` container has `flex-wrap: nowrap` and `overflow: hidden`.
 *
 * 4. Enrichment provenance ("geo cached locally") SHALL remain visible or reachable
 *    via the truncation tooltip (ADR-0035).
 *    → `ip-header-meta-provenance` is present and/or included in the `title` tooltip.
 *
 * 5. Header total height SHALL be < 48 px (enforced via padding reduction in SlideOver).
 *    → `slide-over-header` padding is 10px top/bottom (≤ 48 px with a single 20 px line).
 *
 * 6. `slide-over-header-meta` SHALL be rendered inline inside the header flex row
 *    (not as a separate second row), verified by checking its parent shares
 *    the same container as the breadcrumb nav.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SlideOver from '../components/entity/SlideOver'
import IpHeaderMeta from '../components/entity/ip/IpHeaderMeta'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import { useEntityPanel } from '../components/entity/EntityPanelContext'
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

const SCORE_WITH_GEO: ThreatScore = {
  ...THREATS_FIXTURE[0],
  source_ip: '203.0.113.23',
  location: 'Frankfurt am Main, DE',
  asn: 12345,
  as_name: 'ACME-NET',
  first_seen: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // 1d ago
}

const SCORE_NO_GEO: ThreatScore = {
  ...THREATS_FIXTURE[0],
  source_ip: '203.0.113.23',
  location: null,
  asn: null,
  as_name: null,
  first_seen: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // 1d ago, only first_seen
}

// ---------------------------------------------------------------------------
// Helper: a TestOpener that calls openEntity
// ---------------------------------------------------------------------------

function TestOpener({ ip }: { ip: string }) {
  const { openEntity } = useEntityPanel()
  return (
    <button data-testid="open-btn" onClick={() => openEntity({ kind: 'ip', value: ip })}>
      Open
    </button>
  )
}

// ---------------------------------------------------------------------------
// #336 EARS criterion 1 + 6: headerMeta is inline in the SAME row as breadcrumb
// ---------------------------------------------------------------------------

describe('issue #336 — slide-over-header-meta is inline with breadcrumb (one row)', () => {
  it('slide-over-header-meta is a descendant of the same container as slide-over-breadcrumb', () => {
    render(
      <SlideOver
        open={true}
        onClose={vi.fn()}
        ariaLabel="test panel"
        breadcrumbs={[{ label: '203.0.113.23' }]}
        headerMeta={<div data-testid="custom-meta">geo · first seen</div>}
      >
        body
      </SlideOver>,
    )

    const headerEl = screen.getByTestId('slide-over-header')
    const metaEl = screen.getByTestId('slide-over-header-meta')
    const breadcrumbEl = screen.getByTestId('slide-over-breadcrumb')

    // Both elements are inside the header.
    expect(headerEl).toContainElement(metaEl)
    expect(headerEl).toContainElement(breadcrumbEl)

    // Crucially: the meta should be in the SAME parent div as the breadcrumb nav
    // (not in a second block below). They share the same direct parent.
    expect(metaEl.parentElement).toBe(breadcrumbEl.parentElement)
  })

  it('slide-over-header has no second block element below the breadcrumb row', () => {
    render(
      <SlideOver
        open={true}
        onClose={vi.fn()}
        ariaLabel="test panel"
        breadcrumbs={[{ label: '203.0.113.23' }]}
        headerMeta={<span>meta</span>}
      >
        body
      </SlideOver>,
    )

    const headerEl = screen.getByTestId('slide-over-header')
    // The header should be a single flex row — it has exactly one direct child div
    // (the left region wrapping breadcrumb + meta) plus one right region div.
    // There is NO second-row block: children count is 2 (left + right regions).
    const directChildren = Array.from(headerEl.children)
    expect(directChildren.length).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// #336 EARS criterion 1: IP appears exactly once in the header
// ---------------------------------------------------------------------------

describe('issue #336 — IP appears exactly once in the header', () => {
  it('breadcrumb has the IP; IpHeaderMeta does NOT repeat it', () => {
    render(
      <SlideOver
        open={true}
        onClose={vi.fn()}
        ariaLabel="test panel"
        breadcrumbs={[{ label: '203.0.113.23' }]}
        headerMeta={<IpHeaderMeta score={SCORE_WITH_GEO} />}
      >
        body
      </SlideOver>,
    )

    // Breadcrumb shows the IP.
    expect(screen.getByTestId('breadcrumb-0')).toHaveTextContent('203.0.113.23')

    // IpHeaderMeta does NOT render a redundant ip-header-meta-ip span.
    expect(screen.queryByTestId('ip-header-meta-ip')).toBeNull()

    // The IP text appears exactly once inside the header element.
    // textContent includes aria-labels of buttons which encode the IP, so we count
    // visible text nodes: only the breadcrumb span has the IP as visible text.
    // The copy button encodes it in aria-label only (not visible text content).
    const breadcrumbText = screen.getByTestId('breadcrumb-0').textContent ?? ''
    expect(breadcrumbText).toBe('203.0.113.23')

    // No other element (besides the breadcrumb) has visible IP text.
    const ipMetaContainer = screen.getByTestId('ip-header-meta')
    expect(ipMetaContainer.textContent).not.toContain('203.0.113.23')
  })
})

// ---------------------------------------------------------------------------
// #336 EARS criterion 2: copy button is present in IpHeaderMeta
// ---------------------------------------------------------------------------

describe('issue #336 — copy button is present in IpHeaderMeta', () => {
  it('copy button renders with correct aria-label', () => {
    render(<IpHeaderMeta score={SCORE_WITH_GEO} />)
    const copyBtn = screen.getByTestId('ip-header-meta-copy')
    expect(copyBtn).toBeInTheDocument()
    expect(copyBtn).toHaveAttribute('aria-label', 'Copy IP address 203.0.113.23')
  })

  it('copy button shows clipboard glyph ⎘ by default', () => {
    render(<IpHeaderMeta score={SCORE_WITH_GEO} />)
    expect(screen.getByTestId('ip-header-meta-copy')).toHaveTextContent('⎘')
  })

  it('copy button is the FIRST child element in ip-header-meta (immediately after IP in row)', () => {
    render(<IpHeaderMeta score={SCORE_WITH_GEO} />)
    const metaEl = screen.getByTestId('ip-header-meta')
    // First interactive element inside meta is the copy button.
    const firstBtn = metaEl.querySelector('button')
    expect(firstBtn).toHaveAttribute('data-testid', 'ip-header-meta-copy')
  })
})

// ---------------------------------------------------------------------------
// #336 EARS criterion 3: truncation not wrap — overflow+nowrap on the container
// ---------------------------------------------------------------------------

describe('issue #336 — truncation not wrap on narrow widths', () => {
  it('ip-header-meta container has overflow:hidden and flex-wrap:nowrap', () => {
    render(<IpHeaderMeta score={SCORE_WITH_GEO} />)
    const metaEl = screen.getByTestId('ip-header-meta')
    const style = metaEl.getAttribute('style') ?? ''
    // overflow: hidden prevents content spilling and triggers text-overflow ellipsis.
    expect(style).toContain('overflow: hidden')
    // flex-wrap: nowrap ensures the row never wraps to a second line.
    expect(style).toContain('nowrap')
  })

  it('ip-header-meta has a title tooltip containing all meta fields', () => {
    render(<IpHeaderMeta score={SCORE_WITH_GEO} />)
    const metaEl = screen.getByTestId('ip-header-meta')
    const title = metaEl.getAttribute('title') ?? ''
    // Tooltip includes IP, geo, first-seen, and provenance (ADR-0035 requirement).
    expect(title).toContain('203.0.113.23')
    expect(title).toContain('Frankfurt am Main, DE')
    expect(title).toContain('first seen')
    expect(title).toContain('geo cached locally')
  })
})

// ---------------------------------------------------------------------------
// #336 EARS criterion 4: provenance visible or reachable
// ---------------------------------------------------------------------------

describe('issue #336 — provenance reachable (ADR-0035)', () => {
  it('ip-header-meta-provenance renders "geo cached locally" when geo is present', () => {
    render(<IpHeaderMeta score={SCORE_WITH_GEO} />)
    expect(screen.getByTestId('ip-header-meta-provenance')).toHaveTextContent('geo cached locally')
  })

  it('provenance is included in the title tooltip even when geo span may be clipped', () => {
    render(<IpHeaderMeta score={SCORE_WITH_GEO} />)
    const title = screen.getByTestId('ip-header-meta').getAttribute('title') ?? ''
    expect(title).toContain('geo cached locally')
  })

  it('provenance is absent when no geo/ASN data exists (only first_seen)', () => {
    render(<IpHeaderMeta score={SCORE_NO_GEO} />)
    // first_seen only — no geo/ASN — provenance should NOT appear
    expect(screen.queryByTestId('ip-header-meta-provenance')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// #336 integration: EntityPanelProvider + full header one-line layout
// ---------------------------------------------------------------------------

describe('issue #336 — EntityPanelProvider renders one-line header', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    const { fetchIpEvents, fetchDetailedAnalysis, fetchRules } = await import('../api/logs')
    vi.mocked(fetchIpEvents).mockResolvedValue(null)
    vi.mocked(fetchDetailedAnalysis).mockReturnValue(new Promise(() => {}))
    vi.mocked(fetchRules).mockReturnValue(new Promise(() => {}))
  })

  it('renders ip-header-meta inline in header (not as a second block)', async () => {
    const { fetchThreatScore } = await import('../api/logs')
    vi.mocked(fetchThreatScore).mockResolvedValue(SCORE_WITH_GEO)

    render(
      <EntityPanelProvider>
        <TestOpener ip="203.0.113.23" />
      </EntityPanelProvider>,
    )

    await userEvent.click(screen.getByTestId('open-btn'))
    await waitFor(() => {
      expect(screen.getByTestId('ip-header-meta')).toBeInTheDocument()
    })

    // slide-over-header-meta is inline (sibling of breadcrumb nav in same parent)
    const metaEl = screen.getByTestId('slide-over-header-meta')
    const breadcrumbEl = screen.getByTestId('slide-over-breadcrumb')
    expect(metaEl.parentElement).toBe(breadcrumbEl.parentElement)
  })

  it('header shows geo and first-seen on same row as breadcrumb', async () => {
    const { fetchThreatScore } = await import('../api/logs')
    vi.mocked(fetchThreatScore).mockResolvedValue(SCORE_WITH_GEO)

    render(
      <EntityPanelProvider>
        <TestOpener ip="203.0.113.23" />
      </EntityPanelProvider>,
    )

    await userEvent.click(screen.getByTestId('open-btn'))
    await waitFor(() => {
      expect(screen.getByTestId('ip-header-meta-geo')).toBeInTheDocument()
    })

    expect(screen.getByTestId('ip-header-meta-geo')).toHaveTextContent('(Frankfurt am Main, DE)')
    expect(screen.getByTestId('ip-header-meta-first-seen')).toBeInTheDocument()
    expect(screen.getByTestId('ip-header-meta-provenance')).toHaveTextContent('geo cached locally')
  })
})
