/**
 * Tests for issue #269 — slide-over pin/dock push-mode + session analysis cache.
 *
 * EARS criteria covered:
 *
 * Analysis cache:
 *   - WHEN a detailed analysis completes, the client retains it in session cache.
 *   - WHEN the panel reopens for a cached IP, content renders instantly (no 2nd fetch).
 *   - Cache stamp "cached · <age>" is shown with a Re-run affordance.
 *   - Re-run invalidates cache and fires fresh fetches.
 *   - THE cache is session-memory only (no persistence between instances).
 *
 * Pin / push mode:
 *   - Pin toggle is present in the SlideOver header.
 *   - Toggling pin changes mode from overlay to push and back.
 *   - In overlay mode: overlay backdrop is rendered; role=dialog; aria-modal present.
 *   - In push mode: no overlay backdrop; role=complementary; aria-modal absent.
 *   - In push mode: data-mode="push" on panel; data-mode="overlay" unpinned.
 *   - In push mode: Esc does NOT close the panel.
 *   - In overlay mode: Esc closes the panel.
 *   - In push mode: overlay-click does not fire (no overlay element).
 *   - Close via ✕ button works in both modes.
 *   - Pin toggle aria-pressed reflects current mode.
 *
 * RFC-5737 IPs used throughout (192.0.2.0/24).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SlideOver from '../components/entity/SlideOver'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import { useEntityPanel } from '../components/entity/EntityPanelContext'
import {
  getCachedAnalysis,
  setCachedAnalysis,
  invalidateCachedAnalysis,
  clearAnalysisCache,
  analysisCacheSize,
} from '../components/entity/analysisCache'
import {
  getSlideOverMode,
  setSlideOverMode,
  resetSlideOverMode,
} from '../components/entity/slideOverMode'
import { DETAILED_ANALYSIS_FIXTURE, THREATS_FIXTURE, RULES_FIXTURE } from './readFixtures'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const { mockFetchThreatScore, mockFetchDetailedAnalysis, mockFetchRules, mockFetchIpEvents } =
  vi.hoisted(() => ({
    mockFetchThreatScore: vi.fn(),
    mockFetchDetailedAnalysis: vi.fn(),
    mockFetchRules: vi.fn(),
    mockFetchIpEvents: vi.fn(),
  }))

vi.mock('../api/logs', () => ({
  fetchThreatScore: mockFetchThreatScore,
  fetchDetailedAnalysis: mockFetchDetailedAnalysis,
  fetchRules: mockFetchRules,
  fetchIpEvents: mockFetchIpEvents,
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
// Helpers
// ---------------------------------------------------------------------------

function renderWithProvider(ip: string) {
  function TestConsumer() {
    const { openEntity } = useEntityPanel()
    return (
      <div>
        <button
          data-testid="open-panel-btn"
          onClick={() => openEntity({ kind: 'ip', value: ip })}
        >
          Open
        </button>
      </div>
    )
  }
  return render(
    <EntityPanelProvider>
      <div data-testid="main-content" style={{ padding: '20px 24px' }}>
        <TestConsumer />
      </div>
    </EntityPanelProvider>,
  )
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
  clearAnalysisCache()
  resetSlideOverMode()
  mockFetchIpEvents.mockResolvedValue(null)
  mockFetchThreatScore.mockResolvedValue(THREATS_FIXTURE[0])
  mockFetchDetailedAnalysis.mockResolvedValue(DETAILED_ANALYSIS_FIXTURE)
  mockFetchRules.mockResolvedValue(RULES_FIXTURE)
})

afterEach(() => {
  clearAnalysisCache()
  resetSlideOverMode()
})

// ---------------------------------------------------------------------------
// analysisCache unit tests
// ---------------------------------------------------------------------------

describe('analysisCache — session-scoped LRU (issue #269)', () => {
  it('returns null for an uncached IP', () => {
    expect(getCachedAnalysis('192.0.2.1')).toBeNull()
  })

  it('returns the entry for a cached IP', () => {
    const entry = { analysis: DETAILED_ANALYSIS_FIXTURE, rules: RULES_FIXTURE, fetchedAt: Date.now() }
    setCachedAnalysis('192.0.2.1', entry)
    expect(getCachedAnalysis('192.0.2.1')).toEqual(entry)
  })

  it('evicts the oldest entry when max capacity (10) is reached', () => {
    for (let i = 1; i <= 10; i++) {
      setCachedAnalysis(`192.0.2.${i}`, { analysis: null, rules: [], fetchedAt: Date.now() })
    }
    expect(analysisCacheSize()).toBe(10)
    // Insert an 11th — the first entry (192.0.2.1) should be evicted.
    setCachedAnalysis('192.0.2.11', { analysis: null, rules: [], fetchedAt: Date.now() })
    expect(analysisCacheSize()).toBe(10)
    expect(getCachedAnalysis('192.0.2.1')).toBeNull()
    expect(getCachedAnalysis('192.0.2.11')).not.toBeNull()
  })

  it('moving an existing key to most-recent prevents premature eviction', () => {
    for (let i = 1; i <= 10; i++) {
      setCachedAnalysis(`192.0.2.${i}`, { analysis: null, rules: [], fetchedAt: Date.now() })
    }
    // Touch the oldest entry — it moves to tail.
    setCachedAnalysis('192.0.2.1', { analysis: null, rules: [], fetchedAt: Date.now() })
    // Insert an 11th — now 192.0.2.2 should be evicted (oldest remaining).
    setCachedAnalysis('192.0.2.11', { analysis: null, rules: [], fetchedAt: Date.now() })
    expect(getCachedAnalysis('192.0.2.1')).not.toBeNull()
    expect(getCachedAnalysis('192.0.2.2')).toBeNull()
  })

  it('invalidateCachedAnalysis removes a specific entry', () => {
    setCachedAnalysis('192.0.2.1', { analysis: null, rules: [], fetchedAt: Date.now() })
    invalidateCachedAnalysis('192.0.2.1')
    expect(getCachedAnalysis('192.0.2.1')).toBeNull()
  })

  it('clearAnalysisCache empties the store', () => {
    setCachedAnalysis('192.0.2.1', { analysis: null, rules: [], fetchedAt: Date.now() })
    setCachedAnalysis('192.0.2.2', { analysis: null, rules: [], fetchedAt: Date.now() })
    clearAnalysisCache()
    expect(analysisCacheSize()).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// useRuleAnalysis fetch integration (issue #268 — replaces useIpDetails cache tests)
// ---------------------------------------------------------------------------

describe('useRuleAnalysis — rule-only fetch integration (issue #268)', () => {
  it('calls fetchDetailedAnalysis with ai=false (fast path) on panel open', async () => {
    renderWithProvider('192.0.2.1')
    await userEvent.click(screen.getByTestId('open-panel-btn'))
    // useRuleAnalysis always calls fetchDetailedAnalysis with includeAi=false.
    await waitFor(() =>
      expect(mockFetchDetailedAnalysis).toHaveBeenCalledWith('192.0.2.1', false),
    )
  })

  it('fast-path fetch fires every open (no caching; rule call is fast)', async () => {
    renderWithProvider('192.0.2.1')
    await userEvent.click(screen.getByTestId('open-panel-btn'))
    await waitFor(() => expect(mockFetchDetailedAnalysis).toHaveBeenCalledWith('192.0.2.1', false))
    expect(mockFetchDetailedAnalysis).toHaveBeenCalledTimes(1)
  })

  it('score fetch fires on panel open', async () => {
    renderWithProvider('192.0.2.1')
    await userEvent.click(screen.getByTestId('open-panel-btn'))
    await waitFor(() => expect(mockFetchThreatScore).toHaveBeenCalledWith('192.0.2.1'))
  })
})

// ---------------------------------------------------------------------------
// IpPanel — no cache stamp in issue #268 architecture
// ---------------------------------------------------------------------------

describe('IpPanel — issue #268 arch: no cache stamp (AI offline → offline badge)', () => {
  it('does NOT show analysis-cache-stamp (cache stamp removed in #268 refactor)', async () => {
    renderWithProvider('192.0.2.1')
    await userEvent.click(screen.getByTestId('open-panel-btn'))
    await waitFor(() => expect(screen.getByTestId('modal-analysis-section')).toBeInTheDocument())
    await waitFor(() => expect(screen.queryByTestId('detail-spinner')).not.toBeInTheDocument())
    expect(screen.queryByTestId('analysis-cache-stamp')).not.toBeInTheDocument()
    expect(screen.queryByTestId('analysis-rerun-btn')).not.toBeInTheDocument()
  })

  it('AI offline: shows offline badge from DeepAnalysisControl', async () => {
    renderWithProvider('192.0.2.1')
    await userEvent.click(screen.getByTestId('open-panel-btn'))
    // useDeepAnalysis sees AI offline → DeepAnalysisControl shows offline badge.
    await waitFor(() =>
      expect(screen.getByTestId('deep-analysis-offline-badge')).toBeInTheDocument(),
    )
  })
})

// ---------------------------------------------------------------------------
// SlideOver pin toggle — mode control
// ---------------------------------------------------------------------------

describe('SlideOver — pin toggle (issue #269)', () => {
  it('renders pin toggle button in the header', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" onPinToggle={vi.fn()}>
        content
      </SlideOver>,
    )
    expect(screen.getByTestId('slide-over-pin-toggle')).toBeInTheDocument()
  })

  it('does NOT render pin toggle when onPinToggle is not provided', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test">
        content
      </SlideOver>,
    )
    expect(screen.queryByTestId('slide-over-pin-toggle')).not.toBeInTheDocument()
  })

  it('pin toggle has aria-pressed=false in overlay mode', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="overlay" onPinToggle={vi.fn()}>
        content
      </SlideOver>,
    )
    const toggle = screen.getByTestId('slide-over-pin-toggle')
    expect(toggle).toHaveAttribute('aria-pressed', 'false')
  })

  it('pin toggle has aria-pressed=true in push mode', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push" onPinToggle={vi.fn()}>
        content
      </SlideOver>,
    )
    const toggle = screen.getByTestId('slide-over-pin-toggle')
    expect(toggle).toHaveAttribute('aria-pressed', 'true')
  })

  it('calls onPinToggle when pin toggle is clicked', async () => {
    const onPinToggle = vi.fn()
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" onPinToggle={onPinToggle}>
        content
      </SlideOver>,
    )
    await userEvent.click(screen.getByTestId('slide-over-pin-toggle'))
    expect(onPinToggle).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// SlideOver ARIA semantics by mode
// ---------------------------------------------------------------------------

describe('SlideOver — ARIA semantics per mode (ADR-0037 addendum)', () => {
  it('overlay mode: role=dialog and aria-modal=true', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="IP 192.0.2.1 details" mode="overlay">
        content
      </SlideOver>,
    )
    const panel = screen.getByTestId('slide-over-panel')
    expect(panel).toHaveAttribute('role', 'dialog')
    expect(panel).toHaveAttribute('aria-modal', 'true')
    expect(panel).toHaveAttribute('data-mode', 'overlay')
  })

  it('push mode: role=complementary and NO aria-modal', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="IP 192.0.2.1 details" mode="push">
        content
      </SlideOver>,
    )
    const panel = screen.getByTestId('slide-over-panel')
    expect(panel).toHaveAttribute('role', 'complementary')
    expect(panel).not.toHaveAttribute('aria-modal')
    expect(panel).toHaveAttribute('data-mode', 'push')
  })

  it('overlay mode: backdrop overlay is rendered', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="overlay">
        content
      </SlideOver>,
    )
    expect(screen.getByTestId('slide-over-overlay')).toBeInTheDocument()
  })

  it('push mode: no backdrop overlay', () => {
    render(
      <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push">
        content
      </SlideOver>,
    )
    expect(screen.queryByTestId('slide-over-overlay')).not.toBeInTheDocument()
  })

  it('overlay mode: overlay click calls onClose', async () => {
    const onClose = vi.fn()
    render(
      <SlideOver open={true} onClose={onClose} ariaLabel="test" mode="overlay">
        content
      </SlideOver>,
    )
    await userEvent.click(screen.getByTestId('slide-over-overlay'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('close button calls onClose in both modes', async () => {
    const onCloseOverlay = vi.fn()
    const onClosePush = vi.fn()

    const { unmount } = render(
      <SlideOver open={true} onClose={onCloseOverlay} ariaLabel="test" mode="overlay">
        content
      </SlideOver>,
    )
    await userEvent.click(screen.getByTestId('slide-over-close'))
    expect(onCloseOverlay).toHaveBeenCalledTimes(1)
    unmount()

    render(
      <SlideOver open={true} onClose={onClosePush} ariaLabel="test" mode="push">
        content
      </SlideOver>,
    )
    await userEvent.click(screen.getByTestId('slide-over-close'))
    expect(onClosePush).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// EntityPanelProvider — Esc behaviour by mode
// ---------------------------------------------------------------------------

describe('EntityPanelProvider — Esc by mode (issue #269)', () => {
  it('Esc closes panel in overlay mode', async () => {
    mockFetchThreatScore.mockReturnValue(new Promise(() => {}))
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))

    renderWithProvider('192.0.2.1')
    await userEvent.click(screen.getByTestId('open-panel-btn'))
    expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()

    // Overlay mode (default) — Esc should close.
    await act(async () => {
      await userEvent.keyboard('{Escape}')
    })
    expect(screen.queryByTestId('slide-over-panel')).not.toBeInTheDocument()
  })

  it('Esc does NOT close panel in push mode', async () => {
    mockFetchThreatScore.mockReturnValue(new Promise(() => {}))
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))

    renderWithProvider('192.0.2.1')
    await userEvent.click(screen.getByTestId('open-panel-btn'))
    expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()

    // Switch to push mode via the pin toggle.
    await userEvent.click(screen.getByTestId('slide-over-pin-toggle'))
    expect(screen.getByTestId('slide-over-panel')).toHaveAttribute('data-mode', 'push')

    // Esc — must NOT close.
    await act(async () => {
      await userEvent.keyboard('{Escape}')
    })
    expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()
  })

  it('pin persists across entity switches (switching entity while pinned)', async () => {
    mockFetchThreatScore.mockReturnValue(new Promise(() => {}))
    mockFetchDetailedAnalysis.mockReturnValue(new Promise(() => {}))
    mockFetchRules.mockReturnValue(new Promise(() => {}))

    function MultiEntityConsumer() {
      const { openEntity } = useEntityPanel()
      return (
        <div>
          <button
            data-testid="open-first"
            onClick={() => openEntity({ kind: 'ip', value: '192.0.2.1' })}
          >
            Open first
          </button>
          <button
            data-testid="open-second"
            onClick={() => openEntity({ kind: 'ip', value: '192.0.2.2' })}
          >
            Open second
          </button>
        </div>
      )
    }

    render(
      <EntityPanelProvider>
        <div data-testid="main-content">
          <MultiEntityConsumer />
        </div>
      </EntityPanelProvider>,
    )

    // Open first entity.
    await userEvent.click(screen.getByTestId('open-first'))
    expect(screen.getByTestId('slide-over-panel')).toBeInTheDocument()

    // Pin it.
    await userEvent.click(screen.getByTestId('slide-over-pin-toggle'))
    expect(screen.getByTestId('slide-over-panel')).toHaveAttribute('data-mode', 'push')

    // Switch entity — pin must persist.
    await userEvent.click(screen.getByTestId('open-second'))
    expect(screen.getByTestId('slide-over-panel')).toHaveAttribute('data-mode', 'push')
  })
})

// ---------------------------------------------------------------------------
// slideOverMode store unit tests
// ---------------------------------------------------------------------------

describe('slideOverMode store (issue #269)', () => {
  it('defaults to overlay mode', () => {
    expect(getSlideOverMode()).toBe('overlay')
  })

  it('resets to overlay mode after resetSlideOverMode()', () => {
    setSlideOverMode('push')
    resetSlideOverMode()
    expect(getSlideOverMode()).toBe('overlay')
  })
})
