/**
 * useNewlyExposed.test.ts — vitest tests for ADR-0061 D6.
 *
 * EARS acceptance criteria:
 *  EARS-1: First render SHALL expose nothing (mount = baseline, not "new").
 *  EARS-2: A props change that ADDS node ids SHALL mark exactly those ids as
 *          newly-exposed; ids that were already present SHALL NOT be marked.
 *  EARS-3: Ids that are REMOVED from the current set SHALL NOT be marked as
 *          newly-exposed.
 *  EARS-4: Edge keys follow the same set-diff logic.
 *  EARS-5: When the graph is cleared (nodes.length === 0), newly-exposed resets
 *          to empty and the NEXT render after re-population treats everything as
 *          fresh baseline (nothing newly-exposed again).
 *  EARS-6: `reducedMotion` reflects `window.matchMedia` at call time.
 *
 * Tests for the EntityGraph render side (pulse vs static ring) live in
 * EntityGraphNewlyExposed.test.tsx.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useNewlyExposed } from '../components/logs/useNewlyExposed'
import type { GraphNode, GraphEdge } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures (RFC 5737 doc IPs only)
// ---------------------------------------------------------------------------

function ip(id: string): GraphNode {
  return { id, type: 'ip', label: id }
}

function flowEdge(source: string, target: string, weight = 1): GraphEdge {
  return { source, target, weight, kind: 'flow' }
}

const NODE_A = ip('192.0.2.1')
const NODE_B = ip('192.0.2.2')
const NODE_C = ip('192.0.2.3')

const EDGE_AB = flowEdge('192.0.2.1', '192.0.2.2')
const EDGE_AC = flowEdge('192.0.2.1', '192.0.2.3')

// ---------------------------------------------------------------------------
// matchMedia mock — define once, update per test
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
// EARS-1: First render exposes nothing
// ---------------------------------------------------------------------------

describe('useNewlyExposed — EARS-1: first render exposes nothing', () => {
  it('test_first_render_newly_exposed_node_ids_is_empty', () => {
    const { result } = renderHook(() =>
      useNewlyExposed([NODE_A, NODE_B], [EDGE_AB]),
    )
    expect(result.current.newlyExposedNodeIds.size).toBe(0)
  })

  it('test_first_render_newly_exposed_edge_keys_is_empty', () => {
    const { result } = renderHook(() =>
      useNewlyExposed([NODE_A, NODE_B], [EDGE_AB]),
    )
    expect(result.current.newlyExposedEdgeKeys.size).toBe(0)
  })

  it('test_first_render_newly_exposed_count_is_zero', () => {
    const { result } = renderHook(() =>
      useNewlyExposed([NODE_A, NODE_B], [EDGE_AB]),
    )
    expect(result.current.newlyExposedCount).toBe(0)
  })

  it('test_first_render_with_empty_graph_exposes_nothing', () => {
    const { result } = renderHook(() =>
      useNewlyExposed([], []),
    )
    expect(result.current.newlyExposedNodeIds.size).toBe(0)
    expect(result.current.newlyExposedCount).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// EARS-2: Added ids are marked as newly-exposed
// ---------------------------------------------------------------------------

describe('useNewlyExposed — EARS-2: added ids are marked newly-exposed', () => {
  it('test_newly_added_node_is_in_exposed_set', () => {
    let nodes = [NODE_A, NODE_B]
    let edges = [EDGE_AB]

    const { result, rerender } = renderHook(() =>
      useNewlyExposed(nodes, edges),
    )

    // After first render, baseline is set — nothing newly exposed.
    expect(result.current.newlyExposedNodeIds.size).toBe(0)

    // Add NODE_C — simulates filter re-scope that surfaces a new entity.
    act(() => {
      nodes = [NODE_A, NODE_B, NODE_C]
      edges = [EDGE_AB, EDGE_AC]
    })
    rerender()

    expect(result.current.newlyExposedNodeIds.has('192.0.2.3')).toBe(true)
  })

  it('test_pre_existing_nodes_not_in_exposed_set', () => {
    let nodes = [NODE_A, NODE_B]
    const edges: GraphEdge[] = []

    const { result, rerender } = renderHook(() =>
      useNewlyExposed(nodes, edges),
    )

    act(() => {
      nodes = [NODE_A, NODE_B, NODE_C]
    })
    rerender()

    // NODE_A and NODE_B were present before — must NOT be newly-exposed.
    expect(result.current.newlyExposedNodeIds.has('192.0.2.1')).toBe(false)
    expect(result.current.newlyExposedNodeIds.has('192.0.2.2')).toBe(false)
    // Only NODE_C is newly-exposed.
    expect(result.current.newlyExposedNodeIds.has('192.0.2.3')).toBe(true)
  })

  it('test_count_reflects_only_newly_added_entities', () => {
    let nodes = [NODE_A]
    let edges: GraphEdge[] = []

    const { result, rerender } = renderHook(() =>
      useNewlyExposed(nodes, edges),
    )

    act(() => {
      nodes = [NODE_A, NODE_B, NODE_C]
      edges = [EDGE_AB, EDGE_AC]
    })
    rerender()

    // 2 new nodes + 2 new edges = 4
    expect(result.current.newlyExposedCount).toBe(4)
  })
})

// ---------------------------------------------------------------------------
// EARS-3: Removed ids are NOT marked as newly-exposed
// ---------------------------------------------------------------------------

describe('useNewlyExposed — EARS-3: removed ids are not marked', () => {
  it('test_removed_node_not_in_exposed_set', () => {
    let nodes = [NODE_A, NODE_B, NODE_C]
    let edges = [EDGE_AB, EDGE_AC]

    const { result, rerender } = renderHook(() =>
      useNewlyExposed(nodes, edges),
    )

    act(() => {
      // Remove NODE_C — simulates a filter that narrows, removing an entity.
      nodes = [NODE_A, NODE_B]
      edges = [EDGE_AB]
    })
    rerender()

    // NODE_C was present before and is now gone — not newly-exposed.
    expect(result.current.newlyExposedNodeIds.has('192.0.2.3')).toBe(false)
    // NODE_A and NODE_B were present before — not newly-exposed.
    expect(result.current.newlyExposedNodeIds.has('192.0.2.1')).toBe(false)
    expect(result.current.newlyExposedNodeIds.has('192.0.2.2')).toBe(false)
    expect(result.current.newlyExposedNodeIds.size).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// EARS-4: Edge keys follow the same diff logic
// ---------------------------------------------------------------------------

describe('useNewlyExposed — EARS-4: edge set-diff', () => {
  it('test_newly_added_edge_is_in_exposed_edge_keys', () => {
    let nodes = [NODE_A, NODE_B]
    let edges = [EDGE_AB]

    const { result, rerender } = renderHook(() =>
      useNewlyExposed(nodes, edges),
    )

    act(() => {
      nodes = [NODE_A, NODE_B, NODE_C]
      edges = [EDGE_AB, EDGE_AC]
    })
    rerender()

    // EDGE_AC is new — its canonical key should be in the set.
    const edgeKeys = result.current.newlyExposedEdgeKeys
    // At least one edge key should contain '192.0.2.3'
    const hasNewEdge = [...edgeKeys].some((k) => k.includes('192.0.2.3'))
    expect(hasNewEdge).toBe(true)
  })

  it('test_pre_existing_edge_not_in_exposed_edge_keys', () => {
    let nodes = [NODE_A, NODE_B]
    let edges = [EDGE_AB]

    const { result, rerender } = renderHook(() =>
      useNewlyExposed(nodes, edges),
    )

    act(() => {
      nodes = [NODE_A, NODE_B, NODE_C]
      edges = [EDGE_AB, EDGE_AC]
    })
    rerender()

    // EDGE_AB was present before — NOT in newly-exposed.
    const edgeKeys = result.current.newlyExposedEdgeKeys
    // EDGE_AB key = 'flow:192.0.2.1--192.0.2.2'
    expect(edgeKeys.has('flow:192.0.2.1--192.0.2.2')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// EARS-5: Graph clear resets state; re-population is a fresh baseline
// ---------------------------------------------------------------------------

describe('useNewlyExposed — EARS-5: clear + re-populate', () => {
  it('test_clear_resets_newly_exposed_to_empty', () => {
    let nodes = [NODE_A, NODE_B]
    let edges = [EDGE_AB]

    const { result, rerender } = renderHook(() =>
      useNewlyExposed(nodes, edges),
    )

    // First re-scope: add NODE_C.
    act(() => {
      nodes = [NODE_A, NODE_B, NODE_C]
      edges = [EDGE_AB, EDGE_AC]
    })
    rerender()
    expect(result.current.newlyExposedNodeIds.has('192.0.2.3')).toBe(true)

    // Clear (filter reset → no data).
    act(() => {
      nodes = []
      edges = []
    })
    rerender()
    expect(result.current.newlyExposedNodeIds.size).toBe(0)
    expect(result.current.newlyExposedEdgeKeys.size).toBe(0)
    expect(result.current.newlyExposedCount).toBe(0)
  })

  it('test_re_population_after_clear_is_fresh_baseline_nothing_newly_exposed', () => {
    let nodes: GraphNode[] = [NODE_A]
    let edges: GraphEdge[] = []

    const { result, rerender } = renderHook(() =>
      useNewlyExposed(nodes, edges),
    )

    // Clear.
    act(() => {
      nodes = []
      edges = []
    })
    rerender()

    // Re-populate — should be treated as a new baseline, nothing newly-exposed.
    act(() => {
      nodes = [NODE_A, NODE_B]
      edges = [EDGE_AB]
    })
    rerender()

    expect(result.current.newlyExposedNodeIds.size).toBe(0)
    expect(result.current.newlyExposedCount).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// EARS-6: reducedMotion reflects matchMedia
// ---------------------------------------------------------------------------

describe('useNewlyExposed — EARS-6: reducedMotion', () => {
  it('test_reduced_motion_false_when_media_query_not_matched', () => {
    mqMatches = false
    const { result } = renderHook(() =>
      useNewlyExposed([NODE_A], []),
    )
    expect(result.current.reducedMotion).toBe(false)
  })

  it('test_reduced_motion_true_when_media_query_matched', () => {
    mqMatches = true
    const { result } = renderHook(() =>
      useNewlyExposed([NODE_A], []),
    )
    expect(result.current.reducedMotion).toBe(true)
  })
})
