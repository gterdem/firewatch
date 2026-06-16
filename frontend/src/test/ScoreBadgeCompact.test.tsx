/**
 * Tests for ScoreBadge compact variant + useColumnPriority hook (issue #263).
 *
 * EARS acceptance criteria mapped 1:1:
 *
 * EARS-263-1 — WHEN ScoreBadge renders with variant="compact", IT SHALL render
 *              only the severity-colored numeric chip (score number), with band
 *              color derived from the single ADR-0036 banding function.
 *   → "compact variant renders score number only (no Risk prefix)"
 *   → "compact variant renders no band label text"
 *   → "compact variant derives color from threatLevel (not score)"
 *   → "compact variant has fw-score-badge class"
 *   → "compact variant has data-band attribute set correctly"
 *   → "compact variant has data-variant=compact attribute"
 *
 * EARS-263-2 — WHEN ScoreBadge renders with variant="compact" AND scoreBreakdown
 *              is provided, the "?" score-breakdown affordance SHALL remain available
 *              and operable.
 *   → "compact variant renders ? trigger when scoreBreakdown provided"
 *   → "compact variant popover opens on ? trigger click"
 *   → "compact variant popover shows breakdown contributors"
 *   → "compact variant Esc closes the popover"
 *
 * EARS-263-3 — WHEN ScoreBadge renders without the variant prop (default),
 *              IT SHALL render the existing verbose "Risk N · BAND ?" form unchanged.
 *   → "default variant still renders Risk prefix"
 *   → "default variant still renders band label"
 *   → "variant prop defaults to default (no prop = verbose form)"
 *
 * EARS-263-4 — WHEN a column-priority-enabled DS table is narrower than its
 *              natural width, IT SHALL hide columns in declared low-to-high priority
 *              order; IP and Score columns SHALL never hide; THE table SHALL NOT
 *              horizontal-scroll or clip.
 *
 *   Pure computation tests (via computeVisibleColumns — no ResizeObserver stub needed):
 *   → "computeVisibleColumns: all columns visible when container wide enough"
 *   → "computeVisibleColumns: lowest-priority column hidden first when container shrinks"
 *   → "computeVisibleColumns: never columns are never hidden regardless of width"
 *   → "computeVisibleColumns: hides multiple columns in priority order"
 *   → "computeVisibleColumns: never-columns remain when all non-never columns hidden"
 *   → "computeVisibleColumns: tie-break: highest index hides first"
 *
 *   Hook integration test (ResizeObserver wired to real DOM node):
 *   → "useColumnPriority: containerRef + visibleColumns returned"
 *   → "useColumnPriority: ResizeObserver integration updates columns on resize"
 *
 * EARS-263-5 — Consumer-level regression / barrel exports.
 *   → "DS barrel exports useColumnPriority as a function"
 *   → "DS barrel exports computeVisibleColumns as a function"
 *   → "ColumnDef type is usable (runtime: can construct a conforming object)"
 *
 * Backward-compat (regression guard):
 *   → "default variant: existing aria-label unchanged"
 *   → "default variant: existing data-band / data-score unchanged"
 *   → "compact variant: aria-label still contains score and band (a11y)"
 */

import React from 'react'
import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import { renderHook } from '@testing-library/react'
import { ScoreBadge, useColumnPriority, computeVisibleColumns } from '../components/ds'
import type { ColumnDef } from '../components/ds'
import type { ScoreBreakdownItem } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BREAKDOWN: ScoreBreakdownItem[] = [
  { factor: 'brute_force', label: 'Brute force', points: 40 },
  { factor: 'sql_injection', label: 'SQL injection', points: 35 },
]

/**
 * Column definitions replicating the ThreatActors table priorities.
 *   ip     — priority 1, never:true  (120 px)
 *   score  — priority 1, never:true  (60 px)
 *   blocked— priority 2              (70 px)
 *   events — priority 3              (70 px)
 * Total natural width = 320 px.
 */
const THREAT_ACTOR_COLS: ColumnDef[] = [
  { key: 'ip',      priority: 1, never: true,  minWidth: 120 },
  { key: 'score',   priority: 1, never: true,  minWidth: 60  },
  { key: 'blocked', priority: 2,               minWidth: 70  },
  { key: 'events',  priority: 3,               minWidth: 70  },
]

// ---------------------------------------------------------------------------
// ScoreBadge compact variant — EARS-263-1
// ---------------------------------------------------------------------------

describe('ScoreBadge — compact variant renders chip-only (EARS-263-1)', () => {
  it('compact variant renders score number as text', () => {
    render(<ScoreBadge score={100} threatLevel="CRITICAL" variant="compact" />)
    const badge = screen.getByRole('img')
    expect(badge.textContent).toContain('100')
  })

  it('compact variant does NOT render "Risk" prefix', () => {
    render(<ScoreBadge score={85} threatLevel="HIGH" variant="compact" />)
    const badge = screen.getByRole('img')
    expect(badge.textContent).not.toContain('Risk')
  })

  it('compact variant does NOT render the band label as visible text', () => {
    render(<ScoreBadge score={85} threatLevel="HIGH" variant="compact" data-testid="badge" />)
    const badge = screen.getByTestId('badge')
    // The visible text must only be the score number (plus "?" if breakdown present).
    // "HIGH" must not be in the rendered text content of the badge element.
    expect(badge.textContent).not.toContain('HIGH')
  })

  it('compact variant does NOT render the separator dot', () => {
    render(<ScoreBadge score={50} threatLevel="MEDIUM" variant="compact" />)
    const badge = screen.getByRole('img')
    expect(badge.textContent).not.toContain('·')
  })

  it('compact variant has fw-score-badge class (class-based selector regression guard)', () => {
    const { container } = render(
      <ScoreBadge score={100} threatLevel="CRITICAL" variant="compact" />,
    )
    expect(container.querySelector('.fw-score-badge')).not.toBeNull()
  })

  it('compact variant has data-band set to the normalised band (ADR-0036 D1)', () => {
    render(<ScoreBadge score={85} threatLevel="HIGH" variant="compact" data-testid="badge" />)
    expect(screen.getByTestId('badge').getAttribute('data-band')).toBe('HIGH')
  })

  it('compact variant has data-variant="compact" attribute', () => {
    render(<ScoreBadge score={85} threatLevel="HIGH" variant="compact" data-testid="badge" />)
    expect(screen.getByTestId('badge').getAttribute('data-variant')).toBe('compact')
  })

  it('compact variant CRITICAL band color is --fw-red (ADR-0036 D1, from threatLevel)', () => {
    // Color comes from threatLevel CRITICAL → red, NOT from score thresholds.
    // We pass score=10 (which would be LOW by score) but threatLevel=CRITICAL.
    const { container } = render(
      <ScoreBadge score={10} threatLevel="CRITICAL" variant="compact" />,
    )
    const el = container.querySelector('.fw-score-badge') as HTMLElement
    expect(el.style.color).toContain('var(--fw-red)')
  })

  it('compact variant MEDIUM band color is --fw-blue (ADR-0036 D1)', () => {
    const { container } = render(
      <ScoreBadge score={40} threatLevel="MEDIUM" variant="compact" />,
    )
    const el = container.querySelector('.fw-score-badge') as HTMLElement
    expect(el.style.color).toContain('var(--fw-blue)')
  })

  it('compact variant LOW band color is --fw-green (ADR-0036 D1)', () => {
    const { container } = render(
      <ScoreBadge score={10} threatLevel="LOW" variant="compact" />,
    )
    const el = container.querySelector('.fw-score-badge') as HTMLElement
    expect(el.style.color).toContain('var(--fw-green)')
  })
})

// ---------------------------------------------------------------------------
// ScoreBadge compact variant — "?" popover still works (EARS-263-2)
// ---------------------------------------------------------------------------

describe('ScoreBadge — compact variant "?" popover still operable (EARS-263-2)', () => {
  it('compact variant renders breakdown trigger when scoreBreakdown is provided', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        variant="compact"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    expect(screen.getByRole('button', { name: /show score breakdown/i })).toBeInTheDocument()
  })

  it('compact variant does NOT render breakdown trigger when scoreBreakdown is absent', () => {
    render(<ScoreBadge score={95} threatLevel="CRITICAL" variant="compact" />)
    expect(screen.queryByRole('button', { name: /show score breakdown/i })).not.toBeInTheDocument()
  })

  it('compact variant popover opens on trigger click', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        variant="compact"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /show score breakdown/i }))
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
  })

  it('compact variant popover shows breakdown contributors', () => {
    render(
      <ScoreBadge
        score={75}
        threatLevel="HIGH"
        variant="compact"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /show score breakdown/i }))
    expect(screen.getByText('Brute force')).toBeInTheDocument()
    expect(screen.getByText('SQL injection')).toBeInTheDocument()
  })

  it('compact variant popover closes on Esc', () => {
    render(
      <ScoreBadge
        score={90}
        threatLevel="CRITICAL"
        variant="compact"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /show score breakdown/i }))
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
  })

  it('compact variant trigger aria-expanded reflects popover state', () => {
    render(
      <ScoreBadge
        score={90}
        threatLevel="CRITICAL"
        variant="compact"
        scoreBreakdown={BREAKDOWN}
      />,
    )
    const trigger = screen.getByRole('button', { name: /show score breakdown/i })
    expect(trigger.getAttribute('aria-expanded')).toBe('false')
    fireEvent.click(trigger)
    expect(trigger.getAttribute('aria-expanded')).toBe('true')
  })

  it('compact variant mouse-leave does NOT close popover (issue #356 instant-close fix)', () => {
    render(
      <ScoreBadge
        score={90}
        threatLevel="CRITICAL"
        variant="compact"
        scoreBreakdown={BREAKDOWN}
        data-testid="compact-badge"
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /show score breakdown/i }))
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
    fireEvent.mouseLeave(screen.getByTestId('compact-badge'))
    // Popover MUST remain open — mouseleave only clears hover glow
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// ScoreBadge default variant — unchanged (EARS-263-3 + backward compat)
// ---------------------------------------------------------------------------

describe('ScoreBadge — default variant unchanged (EARS-263-3 backward compat)', () => {
  it('default variant (no prop) renders "Risk" prefix', () => {
    render(<ScoreBadge score={80} threatLevel="CRITICAL" data-testid="badge" />)
    expect(screen.getByTestId('badge').textContent).toContain('Risk')
  })

  it('default variant (no prop) renders band label text', () => {
    render(<ScoreBadge score={80} threatLevel="CRITICAL" data-testid="badge" />)
    expect(screen.getByTestId('badge').textContent).toContain('CRITICAL')
  })

  it('variant="default" explicit also renders verbose form', () => {
    render(<ScoreBadge score={80} threatLevel="HIGH" variant="default" data-testid="badge" />)
    expect(screen.getByTestId('badge').textContent).toContain('Risk')
    expect(screen.getByTestId('badge').textContent).toContain('HIGH')
  })

  it('default variant: data-band still set correctly', () => {
    render(<ScoreBadge score={100} threatLevel="CRITICAL" data-testid="badge" />)
    expect(screen.getByTestId('badge').getAttribute('data-band')).toBe('CRITICAL')
  })

  it('default variant: aria-label still contains score and band', () => {
    render(<ScoreBadge score={100} threatLevel="CRITICAL" data-testid="badge" />)
    const label = screen.getByTestId('badge').getAttribute('aria-label') ?? ''
    expect(label).toContain('100')
    expect(label).toContain('CRITICAL')
  })

  it('default variant: fw-score-badge class still present', () => {
    const { container } = render(<ScoreBadge score={72} threatLevel="HIGH" />)
    expect(container.querySelector('.fw-score-badge')).not.toBeNull()
  })
})

// ---------------------------------------------------------------------------
// ScoreBadge compact accessibility
// ---------------------------------------------------------------------------

describe('ScoreBadge — compact variant accessibility', () => {
  it('compact variant aria-label contains score number', () => {
    render(<ScoreBadge score={77} threatLevel="HIGH" variant="compact" data-testid="badge" />)
    const label = screen.getByTestId('badge').getAttribute('aria-label') ?? ''
    expect(label).toContain('77')
  })

  it('compact variant aria-label contains band name (screen-reader context)', () => {
    render(<ScoreBadge score={77} threatLevel="HIGH" variant="compact" data-testid="badge" />)
    const label = screen.getByTestId('badge').getAttribute('aria-label') ?? ''
    expect(label).toContain('HIGH')
  })

  it('compact variant has role="img"', () => {
    render(<ScoreBadge score={77} threatLevel="HIGH" variant="compact" />)
    expect(screen.getByRole('img')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// computeVisibleColumns — pure logic tests (EARS-263-4)
//
// These test the pure computation function directly, without any DOM/React
// state or ResizeObserver involvement. This is more robust and directly tests
// the hiding contract.
// ---------------------------------------------------------------------------

describe('computeVisibleColumns — column hiding priority logic (EARS-263-4)', () => {
  it('all columns visible when container width >= total natural width', () => {
    // Natural width: 120 + 60 + 70 + 70 = 320 px; container = 500 px
    const visible = computeVisibleColumns(THREAT_ACTOR_COLS, 500)
    expect(visible.has('ip')).toBe(true)
    expect(visible.has('score')).toBe(true)
    expect(visible.has('blocked')).toBe(true)
    expect(visible.has('events')).toBe(true)
  })

  it('lowest-priority column (events, priority=3) hidden first when container shrinks', () => {
    // Natural = 320 px; container = 280 px → need to drop 40 px.
    // events (priority 3, 70 px) hides first → total becomes 250 px → fits.
    const visible = computeVisibleColumns(THREAT_ACTOR_COLS, 280)
    expect(visible.has('events')).toBe(false)
    expect(visible.has('blocked')).toBe(true)
    expect(visible.has('ip')).toBe(true)
    expect(visible.has('score')).toBe(true)
  })

  it('blocked (priority=2) hidden next when container is even narrower', () => {
    // Natural = 320 px; container = 200 px → drop 120 px.
    // events (70 px) first, then blocked (70 px) → total drops to 180 px → fits.
    const visible = computeVisibleColumns(THREAT_ACTOR_COLS, 200)
    expect(visible.has('events')).toBe(false)
    expect(visible.has('blocked')).toBe(false)
    expect(visible.has('ip')).toBe(true)
    expect(visible.has('score')).toBe(true)
  })

  it('never columns are NEVER hidden regardless of container width (width=1)', () => {
    const visible = computeVisibleColumns(THREAT_ACTOR_COLS, 1)
    expect(visible.has('ip')).toBe(true)
    expect(visible.has('score')).toBe(true)
  })

  it('non-never columns are hidden when container is very narrow', () => {
    const visible = computeVisibleColumns(THREAT_ACTOR_COLS, 1)
    expect(visible.has('events')).toBe(false)
    expect(visible.has('blocked')).toBe(false)
  })

  it('tie-break: rightmost column (highest index) hides first among equal-priority', () => {
    // Two columns with identical priority, no never flag — rightmost (idx 1) hides first.
    const cols: ColumnDef[] = [
      { key: 'a', priority: 2, minWidth: 80 }, // idx 0
      { key: 'b', priority: 2, minWidth: 80 }, // idx 1 — rightmost → hides first
    ]
    // Total = 160 px; container = 100 px → need to drop 60 px → hide b (80 px)
    const visible = computeVisibleColumns(cols, 100)
    expect(visible.has('b')).toBe(false)
    expect(visible.has('a')).toBe(true)
  })

  it('exact fit: container == natural width → all visible', () => {
    // Natural = 320 px; container = 320 px → exactly fits, no hiding
    const visible = computeVisibleColumns(THREAT_ACTOR_COLS, 320)
    expect(visible.size).toBe(4)
  })

  it('single never column alone — remains visible even at width=0', () => {
    const cols: ColumnDef[] = [
      { key: 'ip', priority: 1, never: true, minWidth: 120 },
    ]
    const visible = computeVisibleColumns(cols, 0)
    expect(visible.has('ip')).toBe(true)
  })

  it('uses defaultMinColWidth when no minWidth on column def', () => {
    // Without minWidth → uses default (80 px per column)
    const cols: ColumnDef[] = [
      { key: 'a', priority: 1, never: true },
      { key: 'b', priority: 2 },
    ]
    // Total = 80 + 80 = 160 px; container = 100 px → hide b
    const visible = computeVisibleColumns(cols, 100, 80)
    expect(visible.has('b')).toBe(false)
    expect(visible.has('a')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// useColumnPriority hook — integration (EARS-263-4)
// ---------------------------------------------------------------------------

describe('useColumnPriority hook — containerRef + ResizeObserver integration (EARS-263-4)', () => {
  it('returns containerRef (a RefObject) and visibleColumns (a Set)', () => {
    const { result } = renderHook(() => useColumnPriority(THREAT_ACTOR_COLS))
    expect(result.current.containerRef).toBeDefined()
    expect(result.current.containerRef).toHaveProperty('current')
    expect(result.current.visibleColumns).toBeInstanceOf(Set)
  })

  it('initial state before ResizeObserver fires includes all columns', () => {
    const { result } = renderHook(() => useColumnPriority(THREAT_ACTOR_COLS))
    // Without a real DOM element attached, ResizeObserver never fires; initial state = all visible.
    expect(result.current.visibleColumns.size).toBe(4)
  })

  it('updates visible columns when ResizeObserver fires a narrow width', () => {
    let capturedCallback:
      | ((entries: { contentRect: { width: number } }[]) => void)
      | null = null

    // Mock ResizeObserver: capture the callback only; no auto-fire on observe.
    // This lets us control exactly which widths the observer reports.
    const OriginalResizeObserver = globalThis.ResizeObserver

    class MockResizeObserver {
      constructor(cb: (entries: { contentRect: { width: number } }[]) => void) {
        capturedCallback = cb
      }
      observe(_element: Element) {
        // Do NOT fire automatically — we will fire manually below.
        void _element
      }
      disconnect() {}
    }

    globalThis.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver

    // Use a container object to capture the hook result (avoids TypeScript 'never' inference).
    const captured: { result: ReturnType<typeof useColumnPriority> | null } = { result: null }

    function TestComponent() {
      const result = useColumnPriority(THREAT_ACTOR_COLS)
      captured.result = result
      return <div ref={result.containerRef as React.RefObject<HTMLDivElement>} />
    }

    render(<TestComponent />)

    // Simulate the observer firing with 500 px (wide) — all columns should be visible.
    act(() => {
      capturedCallback?.([{ contentRect: { width: 500 } }])
    })
    expect(captured.result?.visibleColumns.has('events')).toBe(true)
    expect(captured.result?.visibleColumns.has('blocked')).toBe(true)

    // Simulate a narrow resize (200 px).
    act(() => {
      capturedCallback?.([{ contentRect: { width: 200 } }])
    })

    // events (priority 3) and blocked (priority 2) should now be hidden.
    expect(captured.result?.visibleColumns.has('events')).toBe(false)
    expect(captured.result?.visibleColumns.has('blocked')).toBe(false)
    // ip and score (never:true) still visible.
    expect(captured.result?.visibleColumns.has('ip')).toBe(true)
    expect(captured.result?.visibleColumns.has('score')).toBe(true)

    globalThis.ResizeObserver = OriginalResizeObserver
  })
})

// ---------------------------------------------------------------------------
// DS barrel exports (EARS-263-5)
// ---------------------------------------------------------------------------

describe('DS barrel — useColumnPriority and computeVisibleColumns exports (EARS-263-5)', () => {
  it('useColumnPriority is exported from the DS barrel as a function', () => {
    expect(typeof useColumnPriority).toBe('function')
  })

  it('computeVisibleColumns is exported from the DS barrel as a function', () => {
    expect(typeof computeVisibleColumns).toBe('function')
  })

  it('ColumnDef type is usable (runtime: can construct a conforming object)', () => {
    const col: ColumnDef = { key: 'ip', priority: 1, never: true, minWidth: 120 }
    expect(col.key).toBe('ip')
    expect(col.never).toBe(true)
  })
})
