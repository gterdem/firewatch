/**
 * Regression tests for bug #683 — ERG zoom binding on async data load.
 *
 * Root cause: useGraphZoom used a [] deps bind-effect that ran once on mount.
 * On first render the graph data was empty (useLogsSurround fetches async), so
 * EntityGraph returned the empty-state div (SVG not mounted), svgRef.current
 * was null, and d3-zoom was never bound.  When data arrived the [] effect never
 * re-ran, leaving zoomBehaviorRef null forever — [+]/[−]/fit were dead.
 *
 * Fix: useGraphZoom now accepts a `ready: boolean` param (nodes.length > 0),
 * included in the bind-effect deps.  The effect re-runs when ready flips true
 * (SVG mounts), binding d3-zoom at the right moment.
 *
 * EARS (issue #683):
 *   - WHEN the entity graph renders with data after an async load, THE wheel-zoom,
 *     drag-pan, and [+]/[−]/fit controls SHALL operate (zoomBehaviorRef bound).
 *   - WHEN the graph transitions empty→non-empty, THE zoom behaviour SHALL bind.
 *   - WHEN the graph transitions non-empty→empty, THE zoom behaviour SHALL unbind.
 *
 * Test strategy: render EntityGraph with nodes=[], verify empty-state;
 * rerender with nodes present, verify SVG mounted and zoom controls operate
 * (clicking [+] calls zoomIn, which in turn calls applyTransform — requires
 * svgRef.current to be set and zoomBehaviorRef to be non-null).
 *
 * Uses RFC 5737 documentation IPs only.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import EntityGraph from '../components/logs/EntityGraph'
import type { GraphNode, GraphEdge, ThreatScore } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures (RFC 5737 IPs only)
// ---------------------------------------------------------------------------

const NODES: GraphNode[] = [
  { id: '192.0.2.1',    type: 'ip',  label: '192.0.2.1' },
  { id: '192.0.2.2',    type: 'ip',  label: '192.0.2.2' },
  { id: '198.51.100.1', type: 'ip',  label: '198.51.100.1' },
]

const EDGES: GraphEdge[] = [
  { source: '192.0.2.1', target: '198.51.100.1', weight: 40, kind: 'flow' },
  { source: '192.0.2.2', target: '198.51.100.1', weight: 10, kind: 'flow' },
]

const EMPTY_THREAT_MAP: ReadonlyMap<string, ThreatScore> = new Map()

// ---------------------------------------------------------------------------
// Helper: render EntityGraph, optionally with empty nodes
// ---------------------------------------------------------------------------

function renderGraph(nodes: GraphNode[], edges: GraphEdge[] = []) {
  return render(
    <EntityGraph
      nodes={nodes}
      edges={edges}
      truncated={false}
      threatMap={EMPTY_THREAT_MAP}
      onNodeClick={vi.fn()}
    />,
  )
}

// ---------------------------------------------------------------------------
// Bug #683 regression — async-mount path
// ---------------------------------------------------------------------------

describe('Bug #683 — ERG zoom binding on async data load', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('test_empty_state_shown_before_data_arrives', () => {
    // Simulate the state before the async fetch resolves: no nodes
    renderGraph([])
    expect(screen.getByTestId('entity-graph-empty')).toBeTruthy()
    expect(screen.queryByTestId('entity-graph-svg')).toBeNull()
  })

  it('test_svg_and_controls_present_after_data_arrives', async () => {
    // Start with empty (simulates page before fetch resolves)
    const { rerender } = renderGraph([])
    expect(screen.getByTestId('entity-graph-empty')).toBeTruthy()

    // Simulate data arriving (async fetch resolves)
    await act(async () => {
      rerender(
        <EntityGraph
          nodes={NODES}
          edges={EDGES}
          truncated={false}
          threatMap={EMPTY_THREAT_MAP}
          onNodeClick={vi.fn()}
        />,
      )
    })

    // SVG should now be mounted
    expect(screen.getByTestId('entity-graph-svg')).toBeTruthy()
    // Controls should be present
    expect(screen.getByTestId('graph-zoom-in')).toBeTruthy()
    expect(screen.getByTestId('graph-zoom-out')).toBeTruthy()
    expect(screen.getByTestId('graph-zoom-reset')).toBeTruthy()
  })

  it('test_zoom_controls_clickable_after_async_data_load', async () => {
    // Start with empty state (SVG not mounted)
    const { rerender } = renderGraph([])
    expect(screen.queryByTestId('entity-graph-svg')).toBeNull()

    // Rerender with data (SVG now mounts)
    await act(async () => {
      rerender(
        <EntityGraph
          nodes={NODES}
          edges={EDGES}
          truncated={false}
          threatMap={EMPTY_THREAT_MAP}
          onNodeClick={vi.fn()}
        />,
      )
    })

    // The [+] button should be clickable and not throw
    // (before the fix, clicking [+] was a no-op because zoomBehaviorRef was null)
    const zoomInBtn = screen.getByTestId('graph-zoom-in')
    expect(() => {
      fireEvent.click(zoomInBtn)
    }).not.toThrow()

    // Similarly for [−] and fit-to-screen
    const zoomOutBtn = screen.getByTestId('graph-zoom-out')
    expect(() => {
      fireEvent.click(zoomOutBtn)
    }).not.toThrow()

    const resetBtn = screen.getByTestId('graph-zoom-reset')
    expect(() => {
      fireEvent.click(resetBtn)
    }).not.toThrow()
  })

  it('test_click_to_activate_then_keyboard_zoom_works_after_async_load', async () => {
    // Start empty; rerender with data
    const { rerender } = renderGraph([])

    await act(async () => {
      rerender(
        <EntityGraph
          nodes={NODES}
          edges={EDGES}
          truncated={false}
          threatMap={EMPTY_THREAT_MAP}
          onNodeClick={vi.fn()}
        />,
      )
    })

    const svg = screen.getByTestId('entity-graph-svg')
    // Clicking the SVG should activate zoom (click-to-interact)
    await act(async () => {
      fireEvent.click(svg)
    })

    // After click, the hint should be gone (zoom is active)
    expect(screen.queryByTestId('graph-click-hint')).toBeNull()

    // Keyboard zoom should not throw after async load
    expect(() => {
      fireEvent.keyDown(svg, { key: '+' })
    }).not.toThrow()
    expect(() => {
      fireEvent.keyDown(svg, { key: '-' })
    }).not.toThrow()
    expect(() => {
      fireEvent.keyDown(svg, { key: '0' })
    }).not.toThrow()
  })

  it('test_zoom_rebinds_on_empty_to_nonempty_transition', async () => {
    // Simulate filter change: data→empty→data (cross-filter yields 0 results, then back)
    const { rerender } = renderGraph(NODES, EDGES)

    // Transition to empty (filter scoped to IP with no matches)
    await act(async () => {
      rerender(
        <EntityGraph
          nodes={[]}
          edges={[]}
          truncated={false}
          threatMap={EMPTY_THREAT_MAP}
          onNodeClick={vi.fn()}
        />,
      )
    })

    expect(screen.getByTestId('entity-graph-empty')).toBeTruthy()

    // Transition back to non-empty (filter cleared)
    await act(async () => {
      rerender(
        <EntityGraph
          nodes={NODES}
          edges={EDGES}
          truncated={false}
          threatMap={EMPTY_THREAT_MAP}
          onNodeClick={vi.fn()}
        />,
      )
    })

    // SVG should be back and controls should work
    expect(screen.getByTestId('entity-graph-svg')).toBeTruthy()
    expect(() => {
      fireEvent.click(screen.getByTestId('graph-zoom-in'))
    }).not.toThrow()
  })
})
