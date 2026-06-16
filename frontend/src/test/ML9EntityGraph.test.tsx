/**
 * Tests for ML-9 (#437) — Entity graph render (d3-force → SVG, AI-verdict-tinted nodes).
 *
 * EARS acceptance criteria covered:
 *
 * EARS-1: The page SHALL render the /logs/graph data as an interactive node-link view;
 *   clicking a node SHALL cross-filter the table.
 *   → test_renders_nodes_and_edges_from_graph_payload
 *   → test_node_size_reflects_degree
 *   → test_edge_weight_reflected_in_stroke_width
 *   → test_clicking_ip_node_calls_onNodeClick
 *   → test_keyboard_enter_on_ip_node_calls_onNodeClick
 *   → test_non_ip_node_click_does_not_call_onNodeClick
 *   → test_logs_route_graph_node_click_cross_filters_table
 *
 * EARS-2: The render SHALL handle the truncation flag honestly (show "showing top N").
 *   → test_truncation_chip_shown_when_truncated_true
 *   → test_truncation_chip_hidden_when_truncated_false
 *
 * IP nodes tinted by AI verdict band:
 *   → test_ip_node_with_high_verdict_has_band_data_attribute
 *   → test_ip_node_with_no_verdict_has_no_band
 *   → test_asn_node_does_not_use_verdict_band
 *
 * Empty state:
 *   → test_empty_state_shown_when_no_nodes
 *
 * Security (ADR-0029 D3):
 *   → test_ip_label_is_text_node_not_html
 *
 * Layout helpers:
 *   → test_nodeRadius_scales_with_degree
 *   → test_edgeStrokeWidth_normalises_correctly
 *
 * SECURITY (ADR-0029 D3): all attacker-controlled id/label values are rendered
 * as SVG text nodes only — never via dangerouslySetInnerHTML.
 *
 * NOTE: Tests use RFC 5737 doc IPs (192.0.2.x) only. No real IPs.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import EntityGraph from '../components/logs/EntityGraph'
import { nodeRadius, edgeStrokeWidth } from '../components/logs/useEntityGraph'
import LogsRoute from '../routes/LogsRoute'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import { RefreshProvider } from '../app/refresh/RefreshContext'
import { THREATS_FIXTURE } from './readFixtures'
import type { GraphNode, GraphEdge, ThreatScore } from '../api/types'

// ---------------------------------------------------------------------------
// Mock graph API used by LogsRoute
// ---------------------------------------------------------------------------

const { mockFetchEntityGraph } = vi.hoisted(() => ({
  mockFetchEntityGraph: vi.fn(),
}))

vi.mock('../api/logs', () => ({
  fetchPaginatedLogs: vi.fn().mockResolvedValue({
    logs: [], next_cursor: null, has_more: false, total_matching: 0,
  }),
  fetchTopPairs: vi.fn().mockResolvedValue([]),
  // #665: StripTiles (replaced TrafficShapeHeader) — default to zeros (non-fatal).
  fetchLogsStats: vi.fn().mockResolvedValue({ total_events: 0, blocked_events: 0, distinct_ips: 0, present_source_types: [] }),
  fetchTopTalkers: vi.fn().mockResolvedValue([]),
  fetchProtocolMix: vi.fn().mockResolvedValue([]),
  fetchEntityGraph: mockFetchEntityGraph,
}))

vi.mock('../api/client', () => ({
  fetchThreats: vi.fn().mockResolvedValue([]),
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'ok', ollama_connected: false, ollama_model: null, db_ok: true,
  }),
  fetchTimeline: vi.fn().mockResolvedValue([]),
  // #748: RefreshProvider (now required by LogsRoute) calls fetchStats.
  fetchStats: vi.fn().mockResolvedValue({
    total_logs: 0,
    total_ips: 0,
    blocked_percentage: 0,
    last_updated: new Date().toISOString(),
    freshness_minutes: 5,
    source_health: [],
  }),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: unknown) {
      super(String(message ?? status))
      this.status = status
    }
  },
}))

// ---------------------------------------------------------------------------
// Fixtures (RFC 5737 IPs only)
// ---------------------------------------------------------------------------

const GRAPH_NODES_FIXTURE: GraphNode[] = [
  { id: '192.0.2.1',    type: 'ip',       label: '192.0.2.1' },
  { id: '192.0.2.2',    type: 'ip',       label: '192.0.2.2' },
  { id: '198.51.100.1', type: 'ip',       label: '198.51.100.1' },
  { id: 'asn:4837',     type: 'asn',      label: 'CHINA-UNICOM (AS4837)' },
  { id: 'cat:sqli',     type: 'category', label: 'SQL Injection' },
]

const GRAPH_EDGES_FIXTURE: GraphEdge[] = [
  { source: '192.0.2.1', target: '198.51.100.1', weight: 50, kind: 'flow' },
  { source: '192.0.2.2', target: '198.51.100.1', weight: 10, kind: 'flow' },
  { source: '192.0.2.1', target: 'asn:4837',     weight: 1,  kind: 'asn' },
  { source: '192.0.2.1', target: 'cat:sqli',     weight: 30, kind: 'category' },
]

/** Threat map with HIGH verdict for 192.0.2.1 */
const THREAT_MAP_FIXTURE: ReadonlyMap<string, ThreatScore> = new Map([
  ['192.0.2.1', { ...THREATS_FIXTURE[0], source_ip: '192.0.2.1', threat_level: 'HIGH' }],
])

const EMPTY_THREAT_MAP: ReadonlyMap<string, ThreatScore> = new Map()

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderGraph(
  props: Partial<Parameters<typeof EntityGraph>[0]> = {},
) {
  return render(
    <svg>
      <EntityGraph
        nodes={GRAPH_NODES_FIXTURE}
        edges={GRAPH_EDGES_FIXTURE}
        truncated={false}
        threatMap={EMPTY_THREAT_MAP}
        onNodeClick={vi.fn()}
        {...props}
      />
    </svg>,
  )
}

function renderLogsRoute() {
  return render(
    <MemoryRouter initialEntries={['/logs']}>
      <RefreshProvider>
        <EntityPanelProvider>
        <LogsRoute />
        </EntityPanelProvider>
      </RefreshProvider>
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// Tests — EntityGraph component
// ---------------------------------------------------------------------------

describe('EntityGraph', () => {
  it('test_renders_nodes_and_edges_from_graph_payload', () => {
    renderGraph()
    // The SVG panel should be present
    expect(screen.getByTestId('entity-graph-panel')).toBeTruthy()
    expect(screen.getByTestId('entity-graph-svg')).toBeTruthy()
    // IP nodes present
    const ipNodes = screen.getAllByTestId('graph-node-ip')
    // 192.0.2.1, 192.0.2.2, 198.51.100.1 = 3 IP nodes
    expect(ipNodes.length).toBe(3)
    // Non-IP nodes (asn + category)
    const otherNodes = screen.getAllByTestId('graph-node-other')
    expect(otherNodes.length).toBe(2)
  })

  it('test_node_size_reflects_degree', () => {
    // Degree-0 node gets min radius (6); degree-4 node gets 8
    expect(nodeRadius(0)).toBe(6)
    expect(nodeRadius(2)).toBe(7)
    expect(nodeRadius(4)).toBe(8)
    // Capped at 18
    expect(nodeRadius(100)).toBe(18)
  })

  it('test_edge_weight_reflected_in_stroke_width', () => {
    // Min weight → minStroke
    expect(edgeStrokeWidth(10, 10, 50, 1, 5)).toBeCloseTo(1, 5)
    // Max weight → maxStroke
    expect(edgeStrokeWidth(50, 10, 50, 1, 5)).toBeCloseTo(5, 5)
    // Midpoint
    expect(edgeStrokeWidth(30, 10, 50, 1, 5)).toBeCloseTo(3, 0)
    // Same min/max → midpoint
    expect(edgeStrokeWidth(10, 10, 10, 1, 5)).toBeCloseTo(3, 5)
  })

  it('test_clicking_ip_node_calls_onNodeClick', () => {
    const onNodeClick = vi.fn()
    renderGraph({ onNodeClick })
    const ipNodes = screen.getAllByTestId('graph-node-ip')
    fireEvent.click(ipNodes[0])
    expect(onNodeClick).toHaveBeenCalledTimes(1)
    // Called with the node id (attacker-controlled string — must be the raw id)
    const calledWith = onNodeClick.mock.calls[0][0] as string
    expect(typeof calledWith).toBe('string')
    expect(calledWith.length).toBeGreaterThan(0)
  })

  it('test_keyboard_enter_on_ip_node_calls_onNodeClick', () => {
    const onNodeClick = vi.fn()
    renderGraph({ onNodeClick })
    const ipNodes = screen.getAllByTestId('graph-node-ip')
    fireEvent.keyDown(ipNodes[0], { key: 'Enter' })
    expect(onNodeClick).toHaveBeenCalledTimes(1)
  })

  it('test_non_ip_node_click_does_not_call_onNodeClick', () => {
    const onNodeClick = vi.fn()
    renderGraph({ onNodeClick })
    const otherNodes = screen.getAllByTestId('graph-node-other')
    fireEvent.click(otherNodes[0])
    expect(onNodeClick).not.toHaveBeenCalled()
  })

  it('test_truncation_chip_shown_when_truncated_true', () => {
    renderGraph({ truncated: true })
    expect(screen.getByTestId('entity-graph-truncated-chip')).toBeTruthy()
    const chip = screen.getByTestId('entity-graph-truncated-chip')
    expect(chip.textContent).toContain('showing top')
    // Shows the node count
    expect(chip.textContent).toContain(String(GRAPH_NODES_FIXTURE.length))
  })

  it('test_truncation_chip_hidden_when_truncated_false', () => {
    renderGraph({ truncated: false })
    expect(screen.queryByTestId('entity-graph-truncated-chip')).toBeNull()
  })

  it('test_ip_node_with_high_verdict_has_band_data_attribute', () => {
    renderGraph({ threatMap: THREAT_MAP_FIXTURE })
    // 192.0.2.1 should have data-band="HIGH"
    const nodes = screen.getAllByTestId('graph-node-ip')
    const highNode = nodes.find((n) => n.getAttribute('data-node-id') === '192.0.2.1')
    expect(highNode).toBeTruthy()
    expect(highNode!.getAttribute('data-band')).toBe('HIGH')
  })

  it('test_ip_node_with_no_verdict_has_no_band', () => {
    renderGraph({ threatMap: EMPTY_THREAT_MAP })
    const nodes = screen.getAllByTestId('graph-node-ip')
    const node = nodes.find((n) => n.getAttribute('data-node-id') === '192.0.2.1')
    expect(node).toBeTruthy()
    // No band = no data-band attribute (or undefined)
    expect(node!.getAttribute('data-band')).toBeNull()
  })

  it('test_asn_node_does_not_use_verdict_band', () => {
    renderGraph({ threatMap: THREAT_MAP_FIXTURE })
    const otherNodes = screen.getAllByTestId('graph-node-other')
    const asnNode = otherNodes.find((n) => n.getAttribute('data-node-type') === 'asn')
    expect(asnNode).toBeTruthy()
    expect(asnNode!.getAttribute('data-band')).toBeNull()
  })

  it('test_empty_state_shown_when_no_nodes', () => {
    render(
      <svg>
        <EntityGraph
          nodes={[]}
          edges={[]}
          truncated={false}
          threatMap={EMPTY_THREAT_MAP}
          onNodeClick={vi.fn()}
        />
      </svg>,
    )
    expect(screen.getByTestId('entity-graph-empty')).toBeTruthy()
    expect(screen.queryByTestId('entity-graph-panel')).toBeNull()
  })

  it('test_ip_label_is_text_node_not_html', () => {
    const xssNode: GraphNode = {
      id: '192.0.2.99',
      type: 'ip',
      label: '<script>alert("xss")</script>',
    }
    render(
      <svg>
        <EntityGraph
          nodes={[xssNode]}
          edges={[]}
          truncated={false}
          threatMap={EMPTY_THREAT_MAP}
          onNodeClick={vi.fn()}
        />
      </svg>,
    )
    // The SVG should NOT have a <script> element injected
    const svgEl = screen.getByTestId('entity-graph-svg')
    expect(svgEl.querySelector('script')).toBeNull()
    // The label text should appear as-is (as a text node)
    expect(svgEl.textContent).toContain('<script>')
  })
})

// ---------------------------------------------------------------------------
// Tests — Layout helpers (pure functions, no render)
// ---------------------------------------------------------------------------

describe('nodeRadius helper', () => {
  it('test_nodeRadius_scales_with_degree', () => {
    expect(nodeRadius(0)).toBe(6)   // 6 + 0
    expect(nodeRadius(1)).toBe(6)   // 6 + 0 (floor(1/2)=0)
    expect(nodeRadius(2)).toBe(7)   // 6 + 1
    expect(nodeRadius(6)).toBe(9)   // 6 + 3
    expect(nodeRadius(30)).toBe(18) // capped
  })
})

describe('edgeStrokeWidth helper', () => {
  it('test_edgeStrokeWidth_normalises_correctly', () => {
    expect(edgeStrokeWidth(0, 0, 100)).toBeCloseTo(1, 5)
    expect(edgeStrokeWidth(100, 0, 100)).toBeCloseTo(5, 5)
    expect(edgeStrokeWidth(50, 0, 100)).toBeCloseTo(3, 5)
    // Equal min/max → midpoint
    expect(edgeStrokeWidth(5, 5, 5)).toBeCloseTo(3, 5)
  })
})

// ---------------------------------------------------------------------------
// Tests — LogsRoute integration
// ---------------------------------------------------------------------------

describe('LogsRoute — ML-9 entity graph integration', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchEntityGraph.mockResolvedValue({
      nodes: GRAPH_NODES_FIXTURE,
      edges: GRAPH_EDGES_FIXTURE,
      truncated: false,
    })
  })

  it('test_logs_route_renders_entity_graph_panel', async () => {
    renderLogsRoute()
    await waitFor(() => {
      expect(screen.getByTestId('entity-graph-panel')).toBeTruthy()
    })
  })

  it('test_logs_route_graph_node_click_cross_filters_table', async () => {
    const { fetchPaginatedLogs } = await import('../api/logs')
    renderLogsRoute()
    await waitFor(() => {
      expect(screen.getByTestId('entity-graph-panel')).toBeTruthy()
    })
    const ipNodes = screen.getAllByTestId('graph-node-ip')
    const clickedNode = ipNodes[0]
    const clickedIp = clickedNode.getAttribute('data-node-id')!
    fireEvent.click(clickedNode)
    // fetchPaginatedLogs should have been called with an ip filter
    await waitFor(() => {
      const calls = (fetchPaginatedLogs as ReturnType<typeof vi.fn>).mock.calls
      const lastCall = calls[calls.length - 1][0] as { ip?: string }
      expect(lastCall.ip).toBe(clickedIp)
    })
  })

  it('test_logs_route_shows_truncation_chip_when_api_truncated', async () => {
    mockFetchEntityGraph.mockResolvedValue({
      nodes: GRAPH_NODES_FIXTURE,
      edges: GRAPH_EDGES_FIXTURE,
      truncated: true,
    })
    renderLogsRoute()
    await waitFor(() => {
      expect(screen.getByTestId('entity-graph-truncated-chip')).toBeTruthy()
    })
  })

  it('test_logs_route_degrades_gracefully_when_graph_fetch_fails', async () => {
    mockFetchEntityGraph.mockRejectedValue(new Error('503'))
    renderLogsRoute()
    // After failure, no graph panel shows, but the route does not crash
    await waitFor(() => {
      // The route itself should still render (no crash)
      expect(screen.getByTestId('logs-page-header')).toBeTruthy()
    })
    // With no data, the graph panel shows the empty state
    expect(screen.getByTestId('entity-graph-empty')).toBeTruthy()
  })
})
