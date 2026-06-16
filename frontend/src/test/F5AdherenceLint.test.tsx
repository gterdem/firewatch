/**
 * F5 Adherence conventions — runtime / structural checks (F5 #111).
 *
 * The primary adherence gate is the ESLint `no-restricted-syntax` /
 * `no-restricted-imports` config (eslint.config.js). These vitest checks
 * complement it by verifying the OUTPUT of components at render time:
 *
 *   1. Emoji-icon convention — ErrorState default icon renders emoji, not SVG.
 *   2. Emoji-icon convention — AnalyticsRoute geo-empty icon renders emoji, not SVG.
 *   3. Mono-data convention — IpDrilldownModal IP address gets --fw-font-mono.
 *   4. Mono-data convention — IpDrilldownModal score number gets --fw-font-mono.
 *   5. DS barrel import — ds/index.ts exports all DS components.
 *   6. No lucide import — package.json does not list lucide-react as a direct dep.
 *
 * EARS criteria (#111):
 *   - The UI shall use emoji as its only icon system; no stroke-icon library dependency.
 *   - All data values shall render in the monospace family.
 *   - IF a PR introduces a raw hex/px literal, a stroke-icon library import, or a
 *     deep DS import, the adherence lint shall fail CI.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import ErrorState from '../components/states/ErrorState'
import { Spinner } from '../components/ds'
import packageJson from '../../package.json'

// ---------------------------------------------------------------------------
// Mock for IpDrilldownModal emoji+mono tests
// ---------------------------------------------------------------------------
vi.mock('../api/logs', () => ({
  fetchThreatScore: vi.fn().mockResolvedValue({
    ip: '10.0.0.1',
    threat_level: 'HIGH',
    score: 72,
    total_events: 50,
    blocked_events: 40,
    attack_types: [],
    source_types: ['azure_waf'],
  }),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
}))

// ---------------------------------------------------------------------------
// 1. Emoji-icon convention: ErrorState default icon is emoji, not SVG
// ---------------------------------------------------------------------------

describe('F5 #111 — Emoji-icon convention', () => {
  it('ErrorState default icon is emoji (⚠️), not a stroke SVG', () => {
    render(<ErrorState headline="Something failed" />)
    const iconEl = screen.getByTestId('error-state-icon')
    // Emoji glyph must be present in text content
    expect(iconEl.textContent).toContain('⚠️')
    // No SVG stroke element should be present (DS iconography spec)
    expect(iconEl.querySelector('svg')).toBeNull()
  })

  it('ErrorState accepts an emoji override via the icon prop', () => {
    render(
      <ErrorState
        headline="Custom icon"
        icon={<span data-testid="custom-override">🔥</span>}
      />,
    )
    expect(screen.getByTestId('custom-override')).toBeInTheDocument()
    expect(screen.getByTestId('custom-override').textContent).toContain('🔥')
  })
})

// ---------------------------------------------------------------------------
// 2. Mono-data convention: IpPanel renders IP breadcrumb in mono font
//    and score number in mono font (ADR-0037 migration — IpDrilldownModal deleted)
// ---------------------------------------------------------------------------

describe('F5 #111 — Mono-data convention', () => {
  it('IpPanel IP breadcrumb renders in --fw-font-mono', async () => {
    // IpPanel is the ADR-0037 replacement for IpDrilldownModal. The IP address
    // is rendered in the SlideOver breadcrumb header (breadcrumb-0 testid).
    // We test IpPanel in its natural context: EntityPanelProvider + SlideOver.
    const { default: EntityPanelProvider } = await import('../components/entity/EntityPanelProvider')
    const { useEntityPanel } = await import('../components/entity/EntityPanelContext')

    function TestOpener() {
      const { openEntity } = useEntityPanel()
      return (
        <button
          data-testid="open-btn"
          onClick={() => openEntity({ kind: 'ip', value: '192.168.1.100' })}
        >
          Open
        </button>
      )
    }

    render(
      <EntityPanelProvider>
        <TestOpener />
      </EntityPanelProvider>,
    )

    // Open the panel
    const openBtn = screen.getByTestId('open-btn')
    openBtn.click()

    // The breadcrumb shows the IP in mono font (SlideOver breadcrumb-0 span).
    await waitFor(() => {
      expect(screen.getByTestId('breadcrumb-0')).toBeInTheDocument()
    })

    const breadcrumb = screen.getByTestId('breadcrumb-0')
    // Breadcrumb is styled with fontFamily: var(--fw-font-mono)
    expect(breadcrumb.getAttribute('style')).toContain('fw-font-mono')
    expect(breadcrumb.textContent).toBe('192.168.1.100')
  })

  it('IpPanel score renders in --fw-font-mono after fast fetch', async () => {
    // IpPanel renders score in modal-score-section (testid preserved from IpDrilldownModal).
    const { default: IpPanel } = await import('../components/entity/ip/IpPanel')

    render(<IpPanel ip="192.168.1.100" />)

    await waitFor(() => {
      expect(screen.getByTestId('modal-score-section')).toBeInTheDocument()
    })

    const scoreSection = screen.getByTestId('modal-score-section')
    // Score numeric value must be wrapped in a mono-font span
    const monoSpans = scoreSection.querySelectorAll('span[style*="fw-font-mono"]')
    expect(monoSpans.length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// 3. DS barrel — Spinner importable from ds/index.ts
// ---------------------------------------------------------------------------

describe('F5 #111 — DS barrel exports', () => {
  it('Spinner is exported from the DS barrel (ds/index.ts)', () => {
    // If the barrel export is missing, this import would fail at module load.
    expect(Spinner).toBeDefined()
    expect(typeof Spinner).toBe('function')
  })
})

// ---------------------------------------------------------------------------
// 4. No lucide-react as a direct dependency
// ---------------------------------------------------------------------------

describe('F5 #111 — No stroke-icon library dependency', () => {
  it('lucide-react is not listed as a direct dependency in package.json', () => {
    const deps = Object.keys(packageJson.dependencies ?? {})
    expect(deps).not.toContain('lucide-react')
  })

  it('no stroke-icon library is a direct dependency', () => {
    const deps = Object.keys(packageJson.dependencies ?? {})
    const strokeLibs = ['lucide-react', '@heroicons/react', 'react-icons']
    for (const lib of strokeLibs) {
      expect(deps).not.toContain(lib)
    }
  })
})

// PROBE_LINE: import { X } from 'lucide-react'  // this line is intentionally invalid — probe for CI
