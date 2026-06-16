/**
 * EntityGraphNodeRender.test.tsx — regression tests for bug #506.
 *
 * Root cause: EntityGraph.tsx wrapped each node <g> in CellTooltip, which
 * inserts an HTML <span> as the trigger element.  An HTML <span> inside SVG
 * is not a valid SVG element; the browser therefore skips rendering SVG
 * children (<circle>, <text>) inside it.  The edges rendered (they had no
 * tooltip wrapper) but zero node circles appeared.
 *
 * Fix: removed CellTooltip from the SVG tree; tooltip is now managed with
 * React state and rendered via a portal outside the SVG element.
 *
 * These tests assert that:
 *  1. Node <circle> elements ARE present in the SVG after the fix (the
 *     regression that was UT-08 High).
 *  2. The count of rendered node groups equals the node fixture length.
 *  3. Edge <line> elements are also present (unchanged behaviour).
 *  4. No HTML <span> appears inside the SVG tree (the broken pattern).
 *  5. Tooltip portal renders on hover / disappears on mouse-leave.
 *
 * Uses RFC 5737 documentation IPs (192.0.2.x, 198.51.100.x) only.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, within } from '@testing-library/react'
import EntityGraph from '../components/logs/EntityGraph'
import type { GraphNode, GraphEdge } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NODES: GraphNode[] = [
  { id: '192.0.2.1',    type: 'ip',       label: '192.0.2.1' },
  { id: '192.0.2.2',    type: 'ip',       label: '192.0.2.2' },
  { id: '198.51.100.1', type: 'ip',       label: '198.51.100.1' },
  { id: 'asn:64496',    type: 'asn',      label: 'TEST-NET (AS64496)' },
  { id: 'cat:sqli',     type: 'category', label: 'SQL Injection' },
]

const EDGES: GraphEdge[] = [
  { source: '192.0.2.1', target: '198.51.100.1', weight: 40, kind: 'flow' },
  { source: '192.0.2.2', target: '198.51.100.1', weight: 8,  kind: 'flow' },
  { source: '192.0.2.1', target: 'asn:64496',    weight: 1,  kind: 'asn' },
  { source: '192.0.2.1', target: 'cat:sqli',     weight: 20, kind: 'category' },
]

const EMPTY_THREAT_MAP = new Map()

function renderGraph(props: Partial<Parameters<typeof EntityGraph>[0]> = {}) {
  return render(
    <EntityGraph
      nodes={NODES}
      edges={EDGES}
      truncated={false}
      threatMap={EMPTY_THREAT_MAP}
      onNodeClick={vi.fn()}
      {...props}
    />,
  )
}

// ---------------------------------------------------------------------------
// Regression tests for UT-08 (#506)
// ---------------------------------------------------------------------------

describe('EntityGraph node circle rendering (regression #506)', () => {
  it('test_node_circles_present_in_svg_for_valid_payload', () => {
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')

    // The critical assertion that was failing before the fix:
    // circleCount === 0 in the browser repro (UT-08)
    // ADR-0061 D5: each node now has 2 circles — a transparent padded hit-area
    // (larger, for clickability) + the visible filled circle.
    const circles = svg.querySelectorAll('circle')
    expect(circles.length).toBe(NODES.length * 2)
  })

  it('test_ip_node_circles_equal_ip_node_count', () => {
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    const ipNodeGroups = svg.querySelectorAll('[data-testid="graph-node-ip"]')
    const circlesInIpGroups = Array.from(ipNodeGroups).reduce(
      (count, g) => count + g.querySelectorAll('circle').length,
      0,
    )
    const ipNodeCount = NODES.filter((n) => n.type === 'ip').length
    expect(ipNodeCount).toBe(3)
    // ADR-0061 D5: 2 circles per node (hit-area + visible)
    expect(circlesInIpGroups).toBe(6)
  })

  it('test_non_ip_node_circles_present', () => {
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    const otherGroups = svg.querySelectorAll('[data-testid="graph-node-other"]')
    const circlesInOtherGroups = Array.from(otherGroups).reduce(
      (count, g) => count + g.querySelectorAll('circle').length,
      0,
    )
    // asn + category = 2 other nodes; ADR-0061 D5: 2 circles each (hit-area + visible) = 4
    expect(circlesInOtherGroups).toBe(4)
  })

  it('test_total_node_group_count_matches_fixture', () => {
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    const ipGroups = svg.querySelectorAll('[data-testid="graph-node-ip"]')
    const otherGroups = svg.querySelectorAll('[data-testid="graph-node-other"]')
    expect(ipGroups.length + otherGroups.length).toBe(NODES.length)
  })

  it('test_edge_lines_still_render', () => {
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    const lines = svg.querySelectorAll('line')
    expect(lines.length).toBe(EDGES.length)
  })

  it('test_no_html_span_inside_svg_tree', () => {
    // Confirm the broken pattern (CellTooltip <span> inside SVG) is absent.
    // An HTML <span> inside SVG causes SVG children not to render (the #506 bug).
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    const spans = svg.querySelectorAll('span')
    expect(spans.length).toBe(0)
  })

  it('test_node_label_text_elements_render', () => {
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    // Each node group has a <text> label
    const texts = svg.querySelectorAll('text')
    // One <text> per node (the <title> element is not a text element)
    expect(texts.length).toBe(NODES.length)
  })

  it('test_node_circles_have_finite_position_via_transform', () => {
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    const nodeGroups = svg.querySelectorAll('[data-node-id]')
    expect(nodeGroups.length).toBe(NODES.length)
    // Every group has a transform attribute with finite coordinates
    for (const g of Array.from(nodeGroups)) {
      const transform = g.getAttribute('transform') ?? ''
      // Should match translate(X,Y) with finite numeric values
      const match = /translate\(([^,]+),([^)]+)\)/.exec(transform)
      expect(match).not.toBeNull()
      if (match) {
        const x = parseFloat(match[1])
        const y = parseFloat(match[2])
        expect(Number.isFinite(x)).toBe(true)
        expect(Number.isFinite(y)).toBe(true)
        expect(Number.isNaN(x)).toBe(false)
        expect(Number.isNaN(y)).toBe(false)
      }
    }
  })
})

// ---------------------------------------------------------------------------
// Tooltip portal tests
// ---------------------------------------------------------------------------

describe('EntityGraph tooltip portal (hover behaviour, #506)', () => {
  it('test_tooltip_not_present_before_hover', () => {
    renderGraph()
    // No tooltip visible before any hover
    expect(screen.queryByTestId('graph-node-tooltip')).toBeNull()
  })

  it('test_tooltip_appears_on_node_mouseenter', () => {
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    const firstIpNode = svg.querySelector('[data-testid="graph-node-ip"]')!
    fireEvent.mouseMove(svg, { clientX: 100, clientY: 100 })
    fireEvent.mouseEnter(firstIpNode)
    // Tooltip portal should now be in document (rendered to body)
    expect(screen.getByTestId('graph-node-tooltip')).toBeTruthy()
  })

  it('test_tooltip_disappears_on_node_mouseleave', () => {
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    const firstIpNode = svg.querySelector('[data-testid="graph-node-ip"]')!
    fireEvent.mouseMove(svg, { clientX: 100, clientY: 100 })
    fireEvent.mouseEnter(firstIpNode)
    expect(screen.getByTestId('graph-node-tooltip')).toBeTruthy()
    fireEvent.mouseLeave(firstIpNode)
    expect(screen.queryByTestId('graph-node-tooltip')).toBeNull()
  })

  it('test_tooltip_content_contains_node_label', () => {
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    const ipNode = svg.querySelector('[data-node-id="192.0.2.1"]')!
    fireEvent.mouseMove(svg, { clientX: 150, clientY: 150 })
    fireEvent.mouseEnter(ipNode)
    const tooltip = screen.getByTestId('graph-node-tooltip')
    expect(within(tooltip).getByText('192.0.2.1')).toBeTruthy()
  })

  it('test_tooltip_not_inside_svg_element', () => {
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    const firstIpNode = svg.querySelector('[data-testid="graph-node-ip"]')!
    fireEvent.mouseMove(svg, { clientX: 100, clientY: 100 })
    fireEvent.mouseEnter(firstIpNode)
    const tooltip = screen.getByTestId('graph-node-tooltip')
    // Tooltip portal renders to document.body, so it must NOT be inside the SVG
    expect(svg.contains(tooltip)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Responsive SVG (walkthrough fix — ERG must fill panel width)
// ---------------------------------------------------------------------------

describe('EntityGraph — responsive SVG layout', () => {
  it('svg has viewBox attribute with world dimensions instead of fixed width/height', () => {
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    // viewBox must be present so the SVG scales to its container
    const viewBox = svg.getAttribute('viewBox')
    expect(viewBox).toBeTruthy()
    // viewBox format: "0 0 W H" where W×H are the force-sim world coords (720×460)
    expect(viewBox).toMatch(/^0 0 \d+ \d+$/)
  })

  it('svg has width:100% style so it fills the panel', () => {
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    // width must be 100% (CSS) — not a fixed pixel attribute
    expect(svg.style.width).toBe('100%')
    // No fixed pixel width attribute that would prevent responsive scaling
    expect(svg.getAttribute('width')).toBeNull()
    // No fixed pixel height attribute
    expect(svg.getAttribute('height')).toBeNull()
  })

  it('svg has preserveAspectRatio attribute for correct scaling behaviour', () => {
    renderGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    const par = svg.getAttribute('preserveAspectRatio')
    expect(par).toBeTruthy()
    expect(par).toContain('meet')
  })
})

// ---------------------------------------------------------------------------
// Single-node edge case (zero edges)
// ---------------------------------------------------------------------------

describe('EntityGraph single-node graph', () => {
  it('test_single_node_renders_circle', () => {
    const singleNode: GraphNode[] = [
      { id: '192.0.2.99', type: 'ip', label: '192.0.2.99' },
    ]
    render(
      <EntityGraph
        nodes={singleNode}
        edges={[]}
        truncated={false}
        threatMap={EMPTY_THREAT_MAP}
        onNodeClick={vi.fn()}
      />,
    )
    const svg = screen.getByTestId('entity-graph-svg')
    const circles = svg.querySelectorAll('circle')
    // ADR-0061 D5: 2 circles per node (transparent hit-area + visible filled circle)
    expect(circles.length).toBe(2)
  })
})
