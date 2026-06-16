/**
 * EntityGraphNewlyExposed.test.tsx — render tests for ADR-0061 D6.
 *
 * "Newly-exposed paths" pulse: when EntityGraph re-scopes (nodes/edges props
 * change due to a filter change), newly-surfaced entities receive:
 *   - a `data-newly-exposed` attribute on their node group / edge line
 *   - an accent ring <circle data-testid="newly-exposed-ring"> per node
 *   - a caption "N entities newly exposed by this filter"
 * Under prefers-reduced-motion, the ring has a static opacity style instead
 * of an animation property.
 *
 * EARS criteria covered:
 *   - EARS-D6-1: first render → no caption, no ring, no data-newly-exposed
 *   - EARS-D6-2: props change that adds a node → caption "N entities..." renders
 *   - EARS-D6-3: caption count is exactly the set-diff count
 *   - EARS-D6-4: newly-exposed node receives data-newly-exposed="true"
 *   - EARS-D6-5: newly-exposed node gets a newly-exposed-ring circle
 *   - EARS-D6-6: non-newly-exposed nodes do NOT get the ring
 *   - EARS-D6-7: prefers-reduced-motion → ring has static opacity, no animation
 *   - EARS-D6-8: without reduced-motion → ring has animation property set
 *
 * SECURITY (ADR-0029 D3): all node ids/labels are rendered as text nodes.
 * The newly-exposed caption uses only a plain integer (newlyExposedCount) —
 * not attacker-controlled text.
 *
 * NOTE: Tests use RFC 5737 doc IPs only (192.0.2.x, 198.51.100.x).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import EntityGraph from '../components/logs/EntityGraph'
import type { GraphNode, GraphEdge } from '../api/types'

// ---------------------------------------------------------------------------
// matchMedia mock — set before each test
// ---------------------------------------------------------------------------

let mqMatches = false

const mockMq: MediaQueryList = {
  get matches() { return mqMatches },
  media: '(prefers-reduced-motion: reduce)',
  onchange: null,
  addListener: () => {},
  removeListener: () => {},
  addEventListener: () => {},
  removeEventListener: () => {},
  dispatchEvent: () => true,
}

beforeEach(() => {
  mqMatches = false
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: () => mockMq,
  })
})

afterEach(() => {
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// Fixtures (RFC 5737 doc IPs only)
// ---------------------------------------------------------------------------

const NODE_A: GraphNode = { id: '192.0.2.1', type: 'ip', label: '192.0.2.1' }
const NODE_B: GraphNode = { id: '192.0.2.2', type: 'ip', label: '192.0.2.2' }
const NODE_C: GraphNode = { id: '192.0.2.3', type: 'ip', label: '192.0.2.3' }

const EDGE_AB: GraphEdge = { source: '192.0.2.1', target: '192.0.2.2', weight: 10, kind: 'flow' }
const EDGE_AC: GraphEdge = { source: '192.0.2.1', target: '192.0.2.3', weight: 5, kind: 'flow' }

const EMPTY_THREAT_MAP = new Map()

// ---------------------------------------------------------------------------
// Render helper — re-render with new props to simulate filter re-scope
// ---------------------------------------------------------------------------

function renderGraph(nodes: GraphNode[], edges: GraphEdge[]) {
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
// EARS-D6-1: first render — no caption, no ring
// ---------------------------------------------------------------------------

describe('EntityGraph newly-exposed D6 — first render', () => {
  it('test_first_render_no_newly_exposed_caption', () => {
    renderGraph([NODE_A, NODE_B], [EDGE_AB])
    expect(screen.queryByTestId('entity-graph-newly-exposed-caption')).toBeNull()
  })

  it('test_first_render_no_newly_exposed_ring', () => {
    renderGraph([NODE_A, NODE_B], [EDGE_AB])
    const svg = screen.getByTestId('entity-graph-svg')
    const rings = svg.querySelectorAll('[data-testid="newly-exposed-ring"]')
    expect(rings.length).toBe(0)
  })

  it('test_first_render_no_data_newly_exposed_attribute', () => {
    renderGraph([NODE_A, NODE_B], [EDGE_AB])
    const svg = screen.getByTestId('entity-graph-svg')
    const exposed = svg.querySelectorAll('[data-newly-exposed]')
    expect(exposed.length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// EARS-D6-2/3/4/5/6: re-scope adds NODE_C → caption + ring for NODE_C only
// ---------------------------------------------------------------------------

describe('EntityGraph newly-exposed D6 — filter re-scope adds nodes', () => {
  it('test_caption_appears_when_nodes_added_by_filter', () => {
    const { rerender } = renderGraph([NODE_A, NODE_B], [EDGE_AB])

    // Simulate filter re-scope that surfaces NODE_C
    act(() => {
      rerender(
        <EntityGraph
          nodes={[NODE_A, NODE_B, NODE_C]}
          edges={[EDGE_AB, EDGE_AC]}
          truncated={false}
          threatMap={EMPTY_THREAT_MAP}
          onNodeClick={vi.fn()}
        />,
      )
    })

    const caption = screen.getByTestId('entity-graph-newly-exposed-caption')
    expect(caption).toBeTruthy()
  })

  it('test_caption_count_reflects_newly_exposed_entities', () => {
    const { rerender } = renderGraph([NODE_A, NODE_B], [EDGE_AB])

    act(() => {
      rerender(
        <EntityGraph
          nodes={[NODE_A, NODE_B, NODE_C]}
          edges={[EDGE_AB, EDGE_AC]}
          truncated={false}
          threatMap={EMPTY_THREAT_MAP}
          onNodeClick={vi.fn()}
        />,
      )
    })

    const caption = screen.getByTestId('entity-graph-newly-exposed-caption')
    // 1 node (NODE_C) + 1 edge (EDGE_AC) = 2 entities newly exposed
    expect(caption.textContent).toContain('2')
    expect(caption.textContent).toContain('newly exposed by this filter')
  })

  it('test_newly_exposed_node_has_data_attribute', () => {
    const { rerender } = renderGraph([NODE_A, NODE_B], [EDGE_AB])

    act(() => {
      rerender(
        <EntityGraph
          nodes={[NODE_A, NODE_B, NODE_C]}
          edges={[EDGE_AB, EDGE_AC]}
          truncated={false}
          threatMap={EMPTY_THREAT_MAP}
          onNodeClick={vi.fn()}
        />,
      )
    })

    const svg = screen.getByTestId('entity-graph-svg')
    const newlyExposedNode = svg.querySelector('[data-node-id="192.0.2.3"][data-newly-exposed]')
    expect(newlyExposedNode).toBeTruthy()
  })

  it('test_newly_exposed_node_gets_accent_ring', () => {
    const { rerender } = renderGraph([NODE_A, NODE_B], [EDGE_AB])

    act(() => {
      rerender(
        <EntityGraph
          nodes={[NODE_A, NODE_B, NODE_C]}
          edges={[EDGE_AB, EDGE_AC]}
          truncated={false}
          threatMap={EMPTY_THREAT_MAP}
          onNodeClick={vi.fn()}
        />,
      )
    })

    const svg = screen.getByTestId('entity-graph-svg')
    // Exactly one newly-exposed ring should be present (for NODE_C only)
    const rings = svg.querySelectorAll('[data-testid="newly-exposed-ring"]')
    expect(rings.length).toBe(1)
  })

  it('test_pre_existing_nodes_do_not_get_ring', () => {
    const { rerender } = renderGraph([NODE_A, NODE_B], [EDGE_AB])

    act(() => {
      rerender(
        <EntityGraph
          nodes={[NODE_A, NODE_B, NODE_C]}
          edges={[EDGE_AB, EDGE_AC]}
          truncated={false}
          threatMap={EMPTY_THREAT_MAP}
          onNodeClick={vi.fn()}
        />,
      )
    })

    const svg = screen.getByTestId('entity-graph-svg')
    // NODE_A and NODE_B were present before — no ring, no data-newly-exposed
    const nodeA = svg.querySelector('[data-node-id="192.0.2.1"]')
    const nodeB = svg.querySelector('[data-node-id="192.0.2.2"]')
    expect(nodeA?.getAttribute('data-newly-exposed')).toBeNull()
    expect(nodeB?.getAttribute('data-newly-exposed')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// EARS-D6-7/8: prefers-reduced-motion
// ---------------------------------------------------------------------------

describe('EntityGraph newly-exposed D6 — prefers-reduced-motion', () => {
  it('test_reduced_motion_ring_has_static_opacity_not_animation', () => {
    // Enable reduced motion BEFORE render
    mqMatches = true

    const { rerender } = renderGraph([NODE_A, NODE_B], [EDGE_AB])

    act(() => {
      rerender(
        <EntityGraph
          nodes={[NODE_A, NODE_B, NODE_C]}
          edges={[EDGE_AB, EDGE_AC]}
          truncated={false}
          threatMap={EMPTY_THREAT_MAP}
          onNodeClick={vi.fn()}
        />,
      )
    })

    const svg = screen.getByTestId('entity-graph-svg')
    const ring = svg.querySelector('[data-testid="newly-exposed-ring"]') as HTMLElement | null
    expect(ring).toBeTruthy()

    // Under reduced-motion: ring should have inline opacity, NOT an animation
    const style = ring?.getAttribute('style') ?? ''
    expect(style).toContain('opacity')
    expect(style).not.toContain('animation')
  })

  it('test_normal_motion_ring_has_animation_not_static_opacity_style', () => {
    // Disable reduced motion (already false from beforeEach)
    mqMatches = false

    const { rerender } = renderGraph([NODE_A, NODE_B], [EDGE_AB])

    act(() => {
      rerender(
        <EntityGraph
          nodes={[NODE_A, NODE_B, NODE_C]}
          edges={[EDGE_AB, EDGE_AC]}
          truncated={false}
          threatMap={EMPTY_THREAT_MAP}
          onNodeClick={vi.fn()}
        />,
      )
    })

    const svg = screen.getByTestId('entity-graph-svg')
    const ring = svg.querySelector('[data-testid="newly-exposed-ring"]') as HTMLElement | null
    expect(ring).toBeTruthy()

    // Under normal motion: ring should have animation, not a static opacity style
    const style = ring?.getAttribute('style') ?? ''
    expect(style).toContain('animation')
  })
})
