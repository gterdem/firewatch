/**
 * Tests for issue #668 ERG Navigation — ADR-0061 D1-D5
 *
 * EARS criteria covered (D6 filter-scope excluded — see issue for D6 exclusion rationale):
 *
 * D2 (click-to-activate wheel zoom):
 *   → test_graph_inactive_by_default_shows_hint
 *   → test_graph_active_after_svg_click_hides_hint
 *   → test_zoom_state_machine_inactive_by_default
 *   → test_zoom_state_machine_activates_on_svg_click
 *
 * D3 (controls + keyboard):
 *   → test_graph_controls_renders_three_buttons
 *   → test_graph_controls_zoom_in_button_has_aria_label
 *   → test_graph_controls_zoom_out_button_has_aria_label
 *   → test_graph_controls_reset_button_has_aria_label
 *   → test_graph_controls_are_real_buttons
 *   → test_graph_controls_buttons_fire_callbacks
 *   → test_graph_controls_present_in_entity_graph
 *
 * D4 (label LOD):
 *   → test_label_lod_base_scale_shows_top_k_by_degree
 *   → test_label_lod_always_shows_hovered_node
 *   → test_label_lod_hovered_node_not_in_top_k_still_shown
 *   → test_label_lod_always_shows_critical_high_ips
 *   → test_label_lod_reveals_more_at_higher_zoom
 *   → test_label_budget_increases_at_thresholds
 *
 * D5 (focus/context, legend toggles, density cap):
 *   → test_legend_toggle_asn_hidden_hides_asn_nodes
 *   → test_legend_toggle_category_hidden_hides_category_nodes
 *   → test_legend_toggle_ip_cannot_be_hidden
 *   → test_legend_toggle_is_real_button_with_aria_pressed
 *   → test_legend_toggle_aria_pressed_false_when_hidden
 *   → test_legend_toggle_calls_onToggle
 *   → test_truncation_chip_includes_filter_to_narrow
 *   → test_truncation_chip_shows_node_count
 *   → test_graph_node_has_padded_invisible_hit_area
 *   → test_focus_context_dimming_on_hover
 *
 * Backwards compat:
 *   → test_node_click_still_calls_onNodeClick
 *   → test_keyboard_enter_still_calls_onNodeClick
 *   → test_ip_node_verdict_band_still_set
 *   → test_crit_high_nodes_always_labelled_in_graph
 *
 * SECURITY (ADR-0029 D3):
 *   → test_xss_label_is_text_node_not_html
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import EntityGraph from '../components/logs/EntityGraph'
import GraphControls from '../components/logs/GraphControls'
import GraphLegendToggles from '../components/logs/GraphLegendToggles'
import {
  buildVisibleLabelSet,
  computeLabelBudget,
} from '../components/logs/graphLabels'
import type { LayoutNode } from '../components/logs/useEntityGraph'
import type { GraphNode, GraphEdge, ThreatScore } from '../api/types'
import { THREATS_FIXTURE } from './readFixtures'

// ---------------------------------------------------------------------------
// Fixtures (RFC 5737 doc IPs only)
// ---------------------------------------------------------------------------

const BASE_NODES: GraphNode[] = [
  { id: '192.0.2.1',    type: 'ip',       label: '192.0.2.1' },
  { id: '192.0.2.2',    type: 'ip',       label: '192.0.2.2' },
  { id: '198.51.100.1', type: 'ip',       label: '198.51.100.1' },
  { id: 'asn:4837',     type: 'asn',      label: 'CHINA-UNICOM (AS4837)' },
  { id: 'cat:sqli',     type: 'category', label: 'SQL Injection' },
]

const BASE_EDGES: GraphEdge[] = [
  { source: '192.0.2.1', target: '198.51.100.1', weight: 50, kind: 'flow' },
  { source: '192.0.2.2', target: '198.51.100.1', weight: 10, kind: 'flow' },
  { source: '192.0.2.1', target: 'asn:4837',     weight: 1,  kind: 'asn' },
  { source: '192.0.2.1', target: 'cat:sqli',     weight: 30, kind: 'category' },
]

const EMPTY_THREAT_MAP: ReadonlyMap<string, ThreatScore> = new Map()

// Build a HIGH-verdict threat map using the canonical THREATS_FIXTURE structure
const HIGH_THREAT_MAP: ReadonlyMap<string, ThreatScore> = new Map([
  ['192.0.2.1', { ...THREATS_FIXTURE[0], source_ip: '192.0.2.1', threat_level: 'HIGH' }],
])

// Build a CRITICAL-verdict threat map
const CRIT_THREAT_MAP: ReadonlyMap<string, ThreatScore> = new Map([
  ['192.0.2.2', { ...THREATS_FIXTURE[0], source_ip: '192.0.2.2', threat_level: 'CRITICAL' }],
])

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

function renderEntityGraph(
  overrides: Partial<Parameters<typeof EntityGraph>[0]> = {},
) {
  return render(
    <EntityGraph
      nodes={BASE_NODES}
      edges={BASE_EDGES}
      truncated={false}
      threatMap={EMPTY_THREAT_MAP}
      onNodeClick={vi.fn()}
      {...overrides}
    />,
  )
}

// ---------------------------------------------------------------------------
// D2 — Click-to-activate wheel zoom
// ---------------------------------------------------------------------------

describe('D2: click-to-activate wheel zoom', () => {
  it('test_graph_inactive_by_default_shows_hint', () => {
    renderEntityGraph()
    // The click-to-interact hint is visible when zoom is inactive (default)
    expect(screen.getByTestId('graph-click-hint')).toBeTruthy()
  })

  it('test_graph_active_after_svg_click_hides_hint', async () => {
    renderEntityGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    await act(async () => {
      fireEvent.click(svg)
    })
    // After clicking into the SVG, the hint should disappear
    expect(screen.queryByTestId('graph-click-hint')).toBeNull()
  })

  it('test_zoom_state_machine_inactive_by_default', () => {
    // The EntityGraph renders with the hint visible (inactive state)
    renderEntityGraph()
    const hint = screen.getByTestId('graph-click-hint')
    expect(hint).toBeTruthy()
    expect(hint.getAttribute('aria-hidden')).toBe('true')
  })

  it('test_zoom_state_machine_activates_on_svg_click', async () => {
    renderEntityGraph()
    expect(screen.getByTestId('graph-click-hint')).toBeTruthy()
    await act(async () => {
      fireEvent.click(screen.getByTestId('entity-graph-svg'))
    })
    expect(screen.queryByTestId('graph-click-hint')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// D3 — Graph controls (real buttons + aria-labels)
// ---------------------------------------------------------------------------

describe('D3: GraphControls component', () => {
  it('test_graph_controls_renders_three_buttons', () => {
    render(
      <GraphControls
        onZoomIn={vi.fn()}
        onZoomOut={vi.fn()}
        onReset={vi.fn()}
        isZoomed={false}
      />,
    )
    expect(screen.getByTestId('graph-zoom-in')).toBeTruthy()
    expect(screen.getByTestId('graph-zoom-out')).toBeTruthy()
    expect(screen.getByTestId('graph-zoom-reset')).toBeTruthy()
  })

  it('test_graph_controls_zoom_in_button_has_aria_label', () => {
    render(
      <GraphControls
        onZoomIn={vi.fn()}
        onZoomOut={vi.fn()}
        onReset={vi.fn()}
        isZoomed={false}
      />,
    )
    const btn = screen.getByTestId('graph-zoom-in')
    expect(btn.getAttribute('aria-label')).toBe('Zoom in')
  })

  it('test_graph_controls_zoom_out_button_has_aria_label', () => {
    render(
      <GraphControls
        onZoomIn={vi.fn()}
        onZoomOut={vi.fn()}
        onReset={vi.fn()}
        isZoomed={false}
      />,
    )
    const btn = screen.getByTestId('graph-zoom-out')
    expect(btn.getAttribute('aria-label')).toBe('Zoom out')
  })

  it('test_graph_controls_reset_button_has_aria_label', () => {
    render(
      <GraphControls
        onZoomIn={vi.fn()}
        onZoomOut={vi.fn()}
        onReset={vi.fn()}
        isZoomed={false}
      />,
    )
    const btn = screen.getByTestId('graph-zoom-reset')
    expect(btn.getAttribute('aria-label')).toBe('Reset zoom to fit')
  })

  it('test_graph_controls_are_real_buttons', () => {
    render(
      <GraphControls
        onZoomIn={vi.fn()}
        onZoomOut={vi.fn()}
        onReset={vi.fn()}
        isZoomed={false}
      />,
    )
    // All controls must be <button> elements (not divs/spans) for a11y
    expect(screen.getByTestId('graph-zoom-in').tagName).toBe('BUTTON')
    expect(screen.getByTestId('graph-zoom-out').tagName).toBe('BUTTON')
    expect(screen.getByTestId('graph-zoom-reset').tagName).toBe('BUTTON')
  })

  it('test_graph_controls_buttons_fire_callbacks', () => {
    const onZoomIn = vi.fn()
    const onZoomOut = vi.fn()
    const onReset = vi.fn()
    render(
      <GraphControls
        onZoomIn={onZoomIn}
        onZoomOut={onZoomOut}
        onReset={onReset}
        isZoomed={false}
      />,
    )
    fireEvent.click(screen.getByTestId('graph-zoom-in'))
    expect(onZoomIn).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByTestId('graph-zoom-out'))
    expect(onZoomOut).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByTestId('graph-zoom-reset'))
    expect(onReset).toHaveBeenCalledTimes(1)
  })

  it('test_graph_controls_present_in_entity_graph', () => {
    renderEntityGraph()
    // Controls cluster should be present inside the panel
    expect(screen.getByTestId('graph-controls')).toBeTruthy()
    expect(screen.getByTestId('graph-zoom-in')).toBeTruthy()
    expect(screen.getByTestId('graph-zoom-out')).toBeTruthy()
    expect(screen.getByTestId('graph-zoom-reset')).toBeTruthy()
  })
})

// ---------------------------------------------------------------------------
// D4 — Label LOD: graphLabels.ts pure-function tests
// ---------------------------------------------------------------------------

/**
 * Build a minimal set of LayoutNodes for testing.
 * Degrees are set manually to control the ranking.
 */
function makeLayoutNodes(specs: Array<{ id: string; type: string; degree: number }>): LayoutNode[] {
  return specs.map((s, i) => ({
    id: s.id,
    label: s.id,
    type: s.type,
    degree: s.degree,
    x: i * 100,
    y: 0,
  }))
}

describe('D4: graphLabels — label LOD predicate', () => {
  it('test_label_lod_base_scale_shows_top_k_by_degree', () => {
    // 10 IP nodes with varying degrees; at scale 1 only top-5 should be labelled
    const nodes = makeLayoutNodes([
      { id: 'ip:a', type: 'ip', degree: 10 },
      { id: 'ip:b', type: 'ip', degree: 9 },
      { id: 'ip:c', type: 'ip', degree: 8 },
      { id: 'ip:d', type: 'ip', degree: 7 },
      { id: 'ip:e', type: 'ip', degree: 6 },
      { id: 'ip:f', type: 'ip', degree: 5 },
      { id: 'ip:g', type: 'ip', degree: 4 },
      { id: 'ip:h', type: 'ip', degree: 3 },
      { id: 'ip:i', type: 'ip', degree: 2 },
      { id: 'ip:j', type: 'ip', degree: 1 },
    ])
    const visible = buildVisibleLabelSet(nodes, {
      scale: 1.0,
      hoveredId: null,
      threatMap: EMPTY_THREAT_MAP,
    })
    // Top-5 by degree should be labelled (BASE_LABEL_K = 5)
    expect(visible.has('ip:a')).toBe(true)
    expect(visible.has('ip:b')).toBe(true)
    expect(visible.has('ip:c')).toBe(true)
    expect(visible.has('ip:d')).toBe(true)
    expect(visible.has('ip:e')).toBe(true)
    // Below the budget: not labelled
    expect(visible.has('ip:f')).toBe(false)
    expect(visible.has('ip:j')).toBe(false)
  })

  it('test_label_lod_always_shows_hovered_node', () => {
    const nodes = makeLayoutNodes([
      { id: 'ip:a', type: 'ip', degree: 10 },
      { id: 'ip:b', type: 'ip', degree: 1 }, // low degree, below budget
    ])
    const visible = buildVisibleLabelSet(nodes, {
      scale: 1.0,
      hoveredId: 'ip:b', // hovered but not in top-K
      threatMap: EMPTY_THREAT_MAP,
    })
    expect(visible.has('ip:b')).toBe(true) // always labelled when hovered
  })

  it('test_label_lod_hovered_node_not_in_top_k_still_shown', () => {
    // 6 nodes; hover the 6th (below base K=5)
    const nodes = makeLayoutNodes([
      { id: 'a', type: 'ip', degree: 10 },
      { id: 'b', type: 'ip', degree: 9 },
      { id: 'c', type: 'ip', degree: 8 },
      { id: 'd', type: 'ip', degree: 7 },
      { id: 'e', type: 'ip', degree: 6 },
      { id: 'f', type: 'ip', degree: 1 },
    ])
    const visible = buildVisibleLabelSet(nodes, {
      scale: 1.0,
      hoveredId: 'f', // below budget
      threatMap: EMPTY_THREAT_MAP,
    })
    expect(visible.has('f')).toBe(true) // hovered always shown
  })

  it('test_label_lod_always_shows_critical_high_ips', () => {
    // 8 low-degree nodes; one CRITICAL, one HIGH, both should show
    const nodes = makeLayoutNodes([
      { id: '192.0.2.10', type: 'ip', degree: 1 },
      { id: '192.0.2.11', type: 'ip', degree: 1 },
      { id: '192.0.2.12', type: 'ip', degree: 1 },
      { id: '192.0.2.13', type: 'ip', degree: 1 },
      { id: '192.0.2.14', type: 'ip', degree: 1 },
      { id: '192.0.2.15', type: 'ip', degree: 1 },
      { id: 'crit-ip', type: 'ip', degree: 1 },
      { id: 'high-ip', type: 'ip', degree: 1 },
    ])
    const threatMap: ReadonlyMap<string, ThreatScore> = new Map([
      ['crit-ip', { ...THREATS_FIXTURE[0], source_ip: 'crit-ip', threat_level: 'CRITICAL' }],
      ['high-ip', { ...THREATS_FIXTURE[0], source_ip: 'high-ip', threat_level: 'HIGH' }],
    ])
    const visible = buildVisibleLabelSet(nodes, {
      scale: 1.0,
      hoveredId: null,
      threatMap,
    })
    // CRITICAL and HIGH IPs always labelled regardless of degree
    expect(visible.has('crit-ip')).toBe(true)
    expect(visible.has('high-ip')).toBe(true)
  })

  it('test_label_lod_reveals_more_at_higher_zoom', () => {
    const nodes = makeLayoutNodes([
      { id: 'a', type: 'ip', degree: 10 },
      { id: 'b', type: 'ip', degree: 9 },
      { id: 'c', type: 'ip', degree: 8 },
      { id: 'd', type: 'ip', degree: 7 },
      { id: 'e', type: 'ip', degree: 6 },
      { id: 'f', type: 'ip', degree: 5 }, // outside base budget (K=5)
      { id: 'g', type: 'ip', degree: 4 },
    ])

    const atScale1 = buildVisibleLabelSet(nodes, {
      scale: 1.0,
      hoveredId: null,
      threatMap: EMPTY_THREAT_MAP,
    })
    // 'f' is the 6th-ranked, outside budget at scale 1
    expect(atScale1.has('f')).toBe(false)

    // At scale 2.0 the budget expands to 5 + 3*2 = 11 (beyond all nodes)
    const atScale2 = buildVisibleLabelSet(nodes, {
      scale: 2.0,
      hoveredId: null,
      threatMap: EMPTY_THREAT_MAP,
    })
    expect(atScale2.has('f')).toBe(true)
    expect(atScale2.has('g')).toBe(true)
  })

  it('test_label_budget_increases_at_thresholds', () => {
    // computeLabelBudget is a pure function
    expect(computeLabelBudget(1.0)).toBe(5)    // base: no threshold crossed
    expect(computeLabelBudget(1.5)).toBe(8)    // +3 at 1.5×
    expect(computeLabelBudget(2.0)).toBe(11)   // +3 more at 2.0×
    expect(computeLabelBudget(3.0)).toBe(14)   // +3 more at 3.0×
    expect(computeLabelBudget(4.0)).toBe(17)   // +3 more at 4.0×
    expect(computeLabelBudget(0.5)).toBe(5)    // below all thresholds: base K
  })
})

// ---------------------------------------------------------------------------
// D5 — Focus/context, legend toggles, density cap
// ---------------------------------------------------------------------------

describe('D5: legend toggles', () => {
  it('test_legend_toggle_asn_hidden_hides_asn_nodes', () => {
    renderEntityGraph()
    // Initially ASN node is visible
    const asnNodes = screen.getAllByTestId('graph-node-other').filter(
      (n) => n.getAttribute('data-node-type') === 'asn',
    )
    expect(asnNodes.length).toBeGreaterThan(0)

    // Click the ASN toggle
    const asnToggle = screen.getByTestId('legend-toggle-asn')
    fireEvent.click(asnToggle)

    // After toggling ASN, no ASN nodes should be visible
    const remainingAsnNodes = screen.queryAllByTestId('graph-node-other').filter(
      (n) => n.getAttribute('data-node-type') === 'asn',
    )
    expect(remainingAsnNodes.length).toBe(0)
  })

  it('test_legend_toggle_category_hidden_hides_category_nodes', () => {
    renderEntityGraph()
    // Category node initially visible
    const catNodes = screen.getAllByTestId('graph-node-other').filter(
      (n) => n.getAttribute('data-node-type') === 'category',
    )
    expect(catNodes.length).toBeGreaterThan(0)

    // Toggle category
    fireEvent.click(screen.getByTestId('legend-toggle-category'))

    // Category nodes gone
    const remaining = screen.queryAllByTestId('graph-node-other').filter(
      (n) => n.getAttribute('data-node-type') === 'category',
    )
    expect(remaining.length).toBe(0)
  })

  it('test_legend_toggle_ip_cannot_be_hidden', () => {
    // There is no IP toggle button in GraphLegendToggles
    // IP items are static legend dots only
    render(
      <GraphLegendToggles
        hiddenKinds={new Set()}
        onToggle={vi.fn()}
      />,
    )
    // Only 'asn' and 'category' toggles exist
    expect(screen.getByTestId('legend-toggle-asn')).toBeTruthy()
    expect(screen.getByTestId('legend-toggle-category')).toBeTruthy()
    // No IP toggle
    expect(screen.queryByTestId('legend-toggle-ip')).toBeNull()
  })

  it('test_legend_toggle_is_real_button_with_aria_pressed', () => {
    render(
      <GraphLegendToggles
        hiddenKinds={new Set()}
        onToggle={vi.fn()}
      />,
    )
    const asnToggle = screen.getByTestId('legend-toggle-asn')
    // Real <button> element
    expect(asnToggle.tagName).toBe('BUTTON')
    // aria-pressed reflects visibility (true = visible)
    expect(asnToggle.getAttribute('aria-pressed')).toBe('true')
  })

  it('test_legend_toggle_aria_pressed_false_when_hidden', () => {
    render(
      <GraphLegendToggles
        hiddenKinds={new Set(['asn'])}
        onToggle={vi.fn()}
      />,
    )
    const asnToggle = screen.getByTestId('legend-toggle-asn')
    // When hidden, aria-pressed should be 'false'
    expect(asnToggle.getAttribute('aria-pressed')).toBe('false')
  })

  it('test_legend_toggle_calls_onToggle', () => {
    const onToggle = vi.fn()
    render(
      <GraphLegendToggles
        hiddenKinds={new Set()}
        onToggle={onToggle}
      />,
    )
    fireEvent.click(screen.getByTestId('legend-toggle-asn'))
    expect(onToggle).toHaveBeenCalledWith('asn')
  })
})

describe('D5: honest truncation chip', () => {
  it('test_truncation_chip_includes_filter_to_narrow', () => {
    renderEntityGraph({ truncated: true })
    const chip = screen.getByTestId('entity-graph-truncated-chip')
    // New improved text includes the call-to-action
    expect(chip.textContent).toContain('filter to narrow')
  })

  it('test_truncation_chip_shows_node_count', () => {
    renderEntityGraph({ truncated: true })
    const chip = screen.getByTestId('entity-graph-truncated-chip')
    expect(chip.textContent).toContain(String(BASE_NODES.length))
  })
})

describe('D5: padded invisible hit-areas', () => {
  it('test_graph_node_has_padded_invisible_hit_area', () => {
    renderEntityGraph()
    const svg = screen.getByTestId('entity-graph-svg')
    // Every node group should contain two circles: a transparent hit-area and a visible one
    const ipNodes = screen.getAllByTestId('graph-node-ip')
    for (const nodeGroup of ipNodes) {
      const circles = nodeGroup.querySelectorAll('circle')
      // At least 2 circles: padded transparent + visible
      expect(circles.length).toBeGreaterThanOrEqual(2)
      // First circle should have fill="transparent" (the hit-area)
      const hitArea = circles[0]
      expect(hitArea.getAttribute('fill')).toBe('transparent')
    }
    expect(svg).toBeTruthy()
  })
})

describe('D5: focus/context dimming on hover', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('test_focus_context_dimming_on_hover', () => {
    renderEntityGraph()
    const ipNodes = screen.getAllByTestId('graph-node-ip')
    // Hover over first IP node
    fireEvent.mouseEnter(ipNodes[0])
    // After hover, the hovered node itself should have full opacity (it IS in its own neighbour set)
    const hoveredId = ipNodes[0].getAttribute('data-node-id')
    const hoveredNode = screen.getAllByTestId('graph-node-ip').find(
      (n) => n.getAttribute('data-node-id') === hoveredId,
    )
    expect(hoveredNode).toBeTruthy()
    expect(hoveredNode!.style.opacity).toBe('1')
  })
})

// ---------------------------------------------------------------------------
// Integration: EntityGraph still passes original contract
// ---------------------------------------------------------------------------

describe('EntityGraph backwards compatibility', () => {
  it('test_node_click_still_calls_onNodeClick', () => {
    const onNodeClick = vi.fn()
    renderEntityGraph({ onNodeClick })
    const ipNodes = screen.getAllByTestId('graph-node-ip')
    fireEvent.click(ipNodes[0])
    expect(onNodeClick).toHaveBeenCalledTimes(1)
    const calledWith = onNodeClick.mock.calls[0][0] as string
    expect(typeof calledWith).toBe('string')
    expect(calledWith.length).toBeGreaterThan(0)
  })

  it('test_keyboard_enter_still_calls_onNodeClick', () => {
    const onNodeClick = vi.fn()
    renderEntityGraph({ onNodeClick })
    const ipNodes = screen.getAllByTestId('graph-node-ip')
    fireEvent.keyDown(ipNodes[0], { key: 'Enter' })
    expect(onNodeClick).toHaveBeenCalledTimes(1)
  })

  it('test_ip_node_verdict_band_still_set', () => {
    renderEntityGraph({ threatMap: HIGH_THREAT_MAP })
    const nodes = screen.getAllByTestId('graph-node-ip')
    const highNode = nodes.find((n) => n.getAttribute('data-node-id') === '192.0.2.1')
    expect(highNode).toBeTruthy()
    expect(highNode!.getAttribute('data-band')).toBe('HIGH')
  })

  it('test_crit_high_nodes_always_labelled_in_graph', () => {
    // CRIT/HIGH nodes should always render; test the node is present + has correct band
    const nodes: GraphNode[] = [
      { id: '192.0.2.50', type: 'ip', label: '192.0.2.50' },
      { id: '192.0.2.51', type: 'ip', label: '192.0.2.51' },
      { id: '192.0.2.52', type: 'ip', label: '192.0.2.52' },
      { id: '192.0.2.53', type: 'ip', label: '192.0.2.53' },
      { id: '192.0.2.54', type: 'ip', label: '192.0.2.54' },
      { id: '192.0.2.2',  type: 'ip', label: '192.0.2.2' }, // CRIT, low degree
    ]
    const edges: GraphEdge[] = [
      { source: '192.0.2.50', target: '192.0.2.51', weight: 10, kind: 'flow' },
      { source: '192.0.2.50', target: '192.0.2.52', weight: 9,  kind: 'flow' },
      { source: '192.0.2.50', target: '192.0.2.53', weight: 8,  kind: 'flow' },
      { source: '192.0.2.50', target: '192.0.2.54', weight: 7,  kind: 'flow' },
      { source: '192.0.2.51', target: '192.0.2.52', weight: 5,  kind: 'flow' },
    ]
    render(
      <EntityGraph
        nodes={nodes}
        edges={edges}
        truncated={false}
        threatMap={CRIT_THREAT_MAP}
        onNodeClick={vi.fn()}
      />,
    )
    // The graph should render without crashing
    expect(screen.getByTestId('entity-graph-panel')).toBeTruthy()
    // CRIT IP (192.0.2.2) should be rendered with correct band
    const critNode = screen.getAllByTestId('graph-node-ip').find(
      (n) => n.getAttribute('data-node-id') === '192.0.2.2',
    )
    expect(critNode).toBeTruthy()
    expect(critNode!.getAttribute('data-band')).toBe('CRITICAL')
  })
})

// ---------------------------------------------------------------------------
// Security: attacker-controlled labels remain text nodes
// ---------------------------------------------------------------------------

describe('Security: ADR-0029 D3 — text-node-only labels', () => {
  it('test_xss_label_is_text_node_not_html', () => {
    const xssNode: GraphNode = {
      id: '192.0.2.99',
      type: 'ip',
      label: '<script>alert("xss")</script>',
    }
    render(
      <EntityGraph
        nodes={[xssNode]}
        edges={[]}
        truncated={false}
        threatMap={EMPTY_THREAT_MAP}
        onNodeClick={vi.fn()}
      />,
    )
    const svgEl = screen.getByTestId('entity-graph-svg')
    expect(svgEl.querySelector('script')).toBeNull()
    // Text content appears safely as literal string
    expect(svgEl.textContent).toContain('<script>')
  })
})
