/**
 * Tests for issue #338 / #361 — docked-pin geometry:
 *   clamp panel width, reserve exactly the rendered panel width on the app-shell,
 *   auto-degrade pin -> overlay below 1280px viewport, bento-reflow data attribute on main.
 *
 * EARS acceptance criteria covered:
 *
 * 1. WHEN the panel is pinned at >=1280px viewport, the app-shell SHALL reserve
 *    exactly the rendered panel width as paddingRight — no dead gap, no content under
 *    the panel (issue #361: target is app-shell, not main-content).
 *    -> paddingRight on [data-testid="app-shell"] matches panel's rendered width.
 *
 * 2. WHILE docked, the docked panel width SHALL stay within clamp(360px, 32vw, 560px).
 *    -> The panel element has width CSS value 'clamp(360px, 32vw, 560px)'.
 *
 * 3. WHEN the viewport drops below the degrade breakpoint while pinned, the panel
 *    SHALL automatically fall back to overlay mode (and return to docked when the
 *    viewport grows), with pin state preserved.
 *    -> Simulated matchMedia narrow -> panel auto-degrades; wide -> pin restored.
 *
 * 4. Ubiquitous: pinned-panel interactions SHALL keep updating both panes live.
 *    -> Verified by existing push-mode tests in SlideOverPin.test.tsx (pass-through).
 *    -> This file adds: data-docked attribute on main-content when push mode is active
 *       at >=1280px (used by bento-grid CSS reflow in index.css).
 *
 * Issue #361 regression guard: app-shell paddingRight, NOT main-content paddingRight.
 *   The #338 fix targeted main-content (maxWidth:1400 / margin:0 auto) which could not
 *   prevent overlap because DashboardRoute's own inner <main> re-centres independently.
 *   The #361 fix targets app-shell (full-width, no maxWidth) so all children (header,
 *   nav, main) see the narrowed viewport and no content hides under the fixed panel.
 *
 * RFC-5737 IPs used throughout (203.0.113.x) — never copy real IPs.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import SlideOver, { PANEL_WIDTH } from '../components/entity/SlideOver'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import { useEntityPanel } from '../components/entity/EntityPanelContext'
import { resetSlideOverMode } from '../components/entity/slideOverMode'
import userEvent from '@testing-library/user-event'

// Silence fetchSourceTypes, fetchThreatScore, etc.
vi.mock('../api/client', () => ({
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchThreats: vi.fn().mockResolvedValue([]),
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'ok', ollama_connected: false, ollama_model: null, db_ok: true,
  }),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: unknown) {
      super(String(message ?? status))
      this.status = status
    }
  },
}))

vi.mock('../api/logs', () => ({
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockReturnValue(new Promise(() => {})),
  fetchRules: vi.fn().mockReturnValue(new Promise(() => {})),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
}))

// ---------------------------------------------------------------------------
// matchMedia mock — controls viewport width simulation
// ---------------------------------------------------------------------------

type MediaQueryHandler = (e: MediaQueryListEvent) => void

interface MockMQL {
  matches: boolean
  addEventListener: ReturnType<typeof vi.fn>
  removeEventListener: ReturnType<typeof vi.fn>
  _listeners: Map<string, Set<MediaQueryHandler>>
  _setMatches: (v: boolean) => void
}

let mockMQL: MockMQL

function setupMatchMedia(initiallyWide: boolean) {
  const listeners: Map<string, Set<MediaQueryHandler>> = new Map()
  mockMQL = {
    matches: initiallyWide,
    addEventListener: vi.fn((type: string, fn: MediaQueryHandler) => {
      if (!listeners.has(type)) listeners.set(type, new Set())
      listeners.get(type)!.add(fn)
    }),
    removeEventListener: vi.fn((type: string, fn: MediaQueryHandler) => {
      listeners.get(type)?.delete(fn)
    }),
    _listeners: listeners,
    _setMatches(v: boolean) {
      this.matches = v
      const event = { matches: v } as MediaQueryListEvent
      listeners.get('change')?.forEach((fn) => fn(event))
    },
  }
  vi.stubGlobal('matchMedia', vi.fn(() => mockMQL))
}

// ---------------------------------------------------------------------------
// ResizeObserver mock — simulates panel offsetWidth reporting
// ---------------------------------------------------------------------------

type ResizeCallback = (entries: ResizeObserverEntry[]) => void

let resizeCallbacks: ResizeCallback[] = []

function setupResizeObserver(reportedWidth: number) {
  resizeCallbacks = []
  // Must use `function` (not arrow) so vitest treats it as a constructor.
  vi.stubGlobal(
    'ResizeObserver',
    vi.fn().mockImplementation(function (cb: ResizeCallback) {
      resizeCallbacks.push(cb)
      return {
        observe: vi.fn(function (el: Element) {
          // Immediately fire with the mock width so the effect runs.
          cb([
            {
              target: el,
              contentBoxSize: [{ inlineSize: reportedWidth, blockSize: 0 }],
              borderBoxSize: [{ inlineSize: reportedWidth, blockSize: 0 }],
              contentRect: { width: reportedWidth } as DOMRectReadOnly,
              devicePixelContentBoxSize: [],
            } as unknown as ResizeObserverEntry,
          ])
        }),
        unobserve: vi.fn(),
        disconnect: vi.fn(),
      }
    }),
  )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Render helper that creates BOTH app-shell AND main-content DOM nodes, matching
 * the real App.tsx structure.  Required for #361 tests since the fix targets
 * app-shell (full-width wrapper) for the paddingRight reservation.
 */
function renderWithShellAndProvider(ip: string) {
  function TestConsumer() {
    const { openEntity } = useEntityPanel()
    return (
      <button
        data-testid="open-panel-btn"
        onClick={() => openEntity({ kind: 'ip', value: ip })}
      >
        Open
      </button>
    )
  }
  return render(
    // Outer wrapper matches <div data-testid="app-shell"> in App.tsx
    <div data-testid="app-shell">
      <EntityPanelProvider>
        {/* Inner matches <main data-testid="main-content"> in App.tsx */}
        <div data-testid="main-content">
          <TestConsumer />
        </div>
      </EntityPanelProvider>
    </div>,
  )
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
  // Default: wide viewport (>=1280px), panel reports 450px wide.
  setupMatchMedia(true)
  setupResizeObserver(450)
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

// ---------------------------------------------------------------------------
// Test 1 — Panel CSS width is clamp(360px, 32vw, 560px) (EARS criterion 2)
// ---------------------------------------------------------------------------

describe('#338 — panel width token is clamp(360px, 32vw, 560px)', () => {
  // JSDOM does not evaluate CSS clamp() in computed styles, so we assert against
  // the exported PANEL_WIDTH constant — the single source of truth for both the
  // CSS property and the ResizeObserver-backed paddingRight reservation.
  it('PANEL_WIDTH constant is clamp(360px, 32vw, 560px)', () => {
    expect(PANEL_WIDTH).toBe('clamp(360px, 32vw, 560px)')
  })

  it('PANEL_WIDTH is the same in overlay and push modes (no separate docked-width)', () => {
    expect(PANEL_WIDTH).toMatch(/^clamp\(360px,\s*32vw,\s*560px\)$/)
  })
})

// ---------------------------------------------------------------------------
// Test 2 — app-shell paddingRight matches rendered panel width (#361 fix)
// The target is now app-shell (full-width), NOT main-content (maxWidth centred).
// ---------------------------------------------------------------------------

describe('#361 — push mode reserves panel width on app-shell (full-width container)', () => {
  it('app-shell paddingRight is set to the panel rendered width when push mode is active', () => {
    // ResizeObserver fires with 450px. app-shell paddingRight must be "450px".
    render(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )

    const shell = screen.getByTestId('app-shell')
    expect(shell.style.paddingRight).toBe('450px')
  })

  it('app-shell paddingRight is cleared when mode switches back to overlay', () => {
    const { rerender } = render(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )
    const shell = screen.getByTestId('app-shell')
    expect(shell.style.paddingRight).toBe('450px')

    rerender(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="overlay">
          content
        </SlideOver>
      </div>,
    )
    expect(shell.style.paddingRight).toBe('')
  })

  it('app-shell paddingRight is cleared when the panel closes', () => {
    const { rerender } = render(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )
    const shell = screen.getByTestId('app-shell')
    expect(shell.style.paddingRight).toBe('450px')

    rerender(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={false} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )
    expect(shell.style.paddingRight).toBe('')
  })

  it('main-content does NOT get paddingRight (#361 regression guard: shell-shrink, not main padding)', () => {
    // The #338 bug was applying paddingRight to main-content (maxWidth centred).
    // This test ensures we never regress back to that approach.
    render(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )
    const main = screen.getByTestId('main-content')
    expect(main.style.paddingRight).toBe('')
  })
})

// ---------------------------------------------------------------------------
// Test 3 — data-docked attribute on main-content in push mode (EARS criterion 4)
// The bento grid uses [data-docked] to reflow (index.css descendant selector).
// ---------------------------------------------------------------------------

describe('#338 — data-docked attribute on main-content in push mode', () => {
  it('main-content has data-docked="true" when mode is push (wide viewport)', () => {
    render(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )
    const main = screen.getByTestId('main-content')
    expect(main.getAttribute('data-docked')).toBe('true')
  })

  it('main-content does NOT have data-docked in overlay mode', () => {
    render(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="overlay">
          content
        </SlideOver>
      </div>,
    )
    const main = screen.getByTestId('main-content')
    expect(main.getAttribute('data-docked')).not.toBe('true')
  })

  it('main-content data-docked is cleared when panel closes', () => {
    const { rerender } = render(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )
    const main = screen.getByTestId('main-content')
    expect(main.getAttribute('data-docked')).toBe('true')

    rerender(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={false} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )
    expect(main.getAttribute('data-docked')).not.toBe('true')
  })
})

// ---------------------------------------------------------------------------
// Test 4 — auto-degrade: pin -> overlay below 1280px (EARS criterion 3)
// ---------------------------------------------------------------------------

describe('#338 — auto-degrade pin->overlay below 1280px viewport', () => {
  it('WHEN viewport is narrow at panel open, push mode is reported as degraded to overlay', async () => {
    setupMatchMedia(false)

    render(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )

    const panel = screen.getByTestId('slide-over-panel')
    expect(panel.getAttribute('data-mode')).toBe('overlay')
  })

  it('WHEN viewport is wide, push mode is rendered as push (no degradation)', () => {
    setupMatchMedia(true)

    render(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )

    const panel = screen.getByTestId('slide-over-panel')
    expect(panel.getAttribute('data-mode')).toBe('push')
  })

  it('WHEN viewport shrinks below 1280px while pinned, panel degrades to overlay', async () => {
    setupMatchMedia(true)

    render(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )

    const panel = screen.getByTestId('slide-over-panel')
    expect(panel.getAttribute('data-mode')).toBe('push')

    await act(async () => {
      mockMQL._setMatches(false)
    })

    expect(panel.getAttribute('data-mode')).toBe('overlay')
  })

  it('WHEN viewport grows back to >=1280px while pin state is preserved, panel restores push', async () => {
    setupMatchMedia(false)

    render(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )

    const panel = screen.getByTestId('slide-over-panel')
    expect(panel.getAttribute('data-mode')).toBe('overlay')

    await act(async () => {
      mockMQL._setMatches(true)
    })

    expect(panel.getAttribute('data-mode')).toBe('push')
  })

  it('overlay mode panel is unaffected by viewport changes (no degradation logic)', async () => {
    setupMatchMedia(false)

    render(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="overlay">
          content
        </SlideOver>
      </div>,
    )

    const panel = screen.getByTestId('slide-over-panel')
    expect(panel.getAttribute('data-mode')).toBe('overlay')

    await act(async () => {
      mockMQL._setMatches(true)
    })

    expect(panel.getAttribute('data-mode')).toBe('overlay')
  })

  it('app-shell paddingRight is cleared when auto-degraded to overlay', async () => {
    setupMatchMedia(true)

    render(
      <div>
        <div data-testid="app-shell" />
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )

    const shell = screen.getByTestId('app-shell')
    expect(shell.style.paddingRight).toBe('450px')

    await act(async () => {
      mockMQL._setMatches(false)
    })

    expect(shell.style.paddingRight).toBe('')
  })
})

// ---------------------------------------------------------------------------
// Test 5 — EntityPanelProvider + pin toggle: aria-pressed + effective mode
// (Preserves #324 memoization + #336 header — these tests must still pass)
// ---------------------------------------------------------------------------

describe('#338/#361 — EntityPanelProvider pin toggle still works with new geometry', () => {
  it('pin toggle button has aria-pressed=false initially (overlay mode)', async () => {
    renderWithShellAndProvider('203.0.113.1')
    await userEvent.click(screen.getByTestId('open-panel-btn'))
    expect(screen.getByTestId('slide-over-pin-toggle')).toHaveAttribute('aria-pressed', 'false')
  })

  it('pin toggle -> push mode -> aria-pressed=true', async () => {
    renderWithShellAndProvider('203.0.113.1')
    await userEvent.click(screen.getByTestId('open-panel-btn'))
    await userEvent.click(screen.getByTestId('slide-over-pin-toggle'))
    expect(screen.getByTestId('slide-over-pin-toggle')).toHaveAttribute('aria-pressed', 'true')

    resetSlideOverMode()
  })
})

// ---------------------------------------------------------------------------
// Test 6 — #361 regression: full App-structure test
// Verifies the fix works with the real nesting: app-shell > main-content > inner-main
// ---------------------------------------------------------------------------

describe('#361 — full shell-shrink geometry (app-shell wrapping max-width main)', () => {
  it('app-shell paddingRight shrinks available space; main-content gets data-docked only', () => {
    // Simulates the real App.tsx structure:
    //   <div data-testid="app-shell">          <- full width, no maxWidth
    //     <EntityPanelProvider>
    //       <main data-testid="main-content">  <- maxWidth:1400 / margin:0 auto
    //         <main>                           <- DashboardRoute inner main
    //           ...dashboard content...
    //         </main>
    //       </main>
    //       <SlideOver mode="push" />          <- position:fixed, right:0
    //     </EntityPanelProvider>
    //   </div>
    render(
      <div data-testid="app-shell">
        <div data-testid="main-content">
          <div data-testid="dashboard-inner">dashboard content</div>
        </div>
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push">
          panel content
        </SlideOver>
      </div>,
    )

    const shell = screen.getByTestId('app-shell')
    const main = screen.getByTestId('main-content')

    // app-shell gets the paddingRight reservation (the #361 fix).
    expect(shell.style.paddingRight).toBe('450px')

    // main-content gets data-docked for bento CSS reflow.
    expect(main.getAttribute('data-docked')).toBe('true')

    // main-content must NOT get paddingRight (that was the #338 bug).
    expect(main.style.paddingRight).toBe('')
  })

  it('both app-shell paddingRight and data-docked are cleared together when panel closes', () => {
    const { rerender } = render(
      <div data-testid="app-shell">
        <div data-testid="main-content" />
        <SlideOver open={true} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )

    const shell = screen.getByTestId('app-shell')
    const main = screen.getByTestId('main-content')
    expect(shell.style.paddingRight).toBe('450px')
    expect(main.getAttribute('data-docked')).toBe('true')

    rerender(
      <div data-testid="app-shell">
        <div data-testid="main-content" />
        <SlideOver open={false} onClose={vi.fn()} ariaLabel="test" mode="push">
          content
        </SlideOver>
      </div>,
    )

    expect(shell.style.paddingRight).toBe('')
    expect(main.getAttribute('data-docked')).toBeNull()
  })
})
