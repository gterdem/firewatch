/**
 * useEntityGraph — d3-force layout hook for the entity graph (ML-9, issue #437).
 *
 * Concern: purely layout math.  Runs a d3-force simulation on the graph data
 * and returns stable node positions (x, y), node degree map, and edge min/max
 * weight.  Renders nothing — SVG drawing is handled by EntityGraph.tsx.
 *
 * d3-force usage policy (approved approach):
 *   - Uses ONLY d3-force (layout math). No d3-selection, or any rendering
 *     helpers — those are hand-rolled SVG in EntityGraph.tsx.
 *   - d3-zoom is now also used for transform math + event handling (ADR-0061,
 *     which supersedes ADR-0050's deferred-zoom MVP clause).
 *   - `prefers-reduced-motion`: when the user has reduced motion enabled,
 *     ticks run synchronously to final positions (no animation).
 *   - Bounded: the simulation is run synchronously at call time and the
 *     final positions are returned; there is no ongoing animation.
 *
 * Outputs:
 *   layoutNodes — nodes with computed (x, y) position; degree (connection count).
 *   layoutEdges — edges with resolved source/target node references.
 *   minWeight / maxWeight — for edge stroke-width scaling.
 *
 * #751 — merge / warm-start path:
 *   When `isMerge` is true, the hook reuses prior (x, y) positions for nodes
 *   that persist (HARD-PIN — fx/fy fixed so they never drift) and seeds new
 *   nodes near a connected neighbour.  Only a short tick budget (MERGE_TICKS)
 *   is run for the additions; existing nodes are completely stationary.
 *   The cold-layout path (full SIMULATION_TICKS, fresh circle seed) is used
 *   for first load and filter re-scope (isMerge = false).
 *
 * SECURITY (ADR-0029 D3): id/label values are passed through without mutation;
 * callers must use them as text nodes only.
 */

import { useMemo, useRef, useEffect } from 'react'
import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
} from 'd3-force'
import type { SimulationNodeDatum, SimulationLinkDatum } from 'd3-force'
import type { GraphNode, GraphEdge } from '../../api/types'

// ---------------------------------------------------------------------------
// World size vs viewport size (ADR-0061 D4)
//
// WORLD_* constants define the d3-force layout coordinate space — a larger
// canvas that gives the force simulation room to breathe and avoids label
// overlap.  d3-zoom navigates this world (the SVG <g> transform pans/zooms
// it into the fixed SVG viewport).  GRAPH_WIDTH/HEIGHT are the visible
// viewport size exported for SVG element sizing.
// ---------------------------------------------------------------------------

/**
 * Layout world size — the coordinate space the force simulation uses.
 * Larger than the viewport so nodes have room to spread out.  d3-zoom
 * navigates it (ADR-0061 D1/D4 — "larger DECOUPLED world size").
 */
export const WORLD_WIDTH = 1200
export const WORLD_HEIGHT = 800

/**
 * SVG viewport dimensions — the fixed pixel area visible in the document.
 * d3-zoom applies a CSS transform on the inner <g> to pan/zoom the world
 * into this viewport.
 */
export const GRAPH_WIDTH = 720
export const GRAPH_HEIGHT = 460

// ---------------------------------------------------------------------------
// Types for the post-layout data structures
// ---------------------------------------------------------------------------

/** A GraphNode enriched with d3-force simulation position + degree. */
export interface LayoutNode extends SimulationNodeDatum {
  /** Stable identifier (from GraphNode.id). */
  id: string
  /** Display label (from GraphNode.label). */
  label: string
  /** Entity kind (from GraphNode.type). */
  type: 'ip' | 'asn' | 'category' | string
  /** Number of edges touching this node (for size scaling). */
  degree: number
  /** Computed x position (set by d3-force, guaranteed after simulation). */
  x: number
  /** Computed y position (set by d3-force, guaranteed after simulation). */
  y: number
}

/** A GraphEdge resolved to LayoutNode references (as required by d3-force). */
export interface LayoutEdge extends SimulationLinkDatum<LayoutNode> {
  source: LayoutNode
  target: LayoutNode
  weight: number
  kind: string
}

export interface EntityGraphLayout {
  layoutNodes: LayoutNode[]
  layoutEdges: LayoutEdge[]
  /** Minimum edge weight (for stroke normalization). */
  minWeight: number
  /** Maximum edge weight (for stroke normalization). */
  maxWeight: number
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** How many simulation ticks to run synchronously to final positions (cold layout). */
const SIMULATION_TICKS = 300

/**
 * Tick budget for the warm-start merge path (#751).
 * Only new nodes need to settle; existing nodes are hard-pinned (fx/fy fixed).
 * Short enough not to visibly jank; long enough for new nodes to avoid overlap.
 */
const MERGE_TICKS = 60

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Deterministic jitter for initial node position spread.
 * Uses a simple Mulberry32-style hash of the node index so positions are
 * stable across re-renders (Math.random() is impure — not allowed in useMemo).
 * Produces a value in [-0.5, 0.5].
 */
function deterministicJitter(index: number): number {
  // Mulberry32-style integer hash
  let t = (index ^ 0xdeadbeef) >>> 0
  t ^= t << 17
  t ^= t >>> 13
  t ^= t << 5
  return ((t >>> 0) / 0xffffffff) - 0.5
}

/**
 * Cold-layout path — full circle-seed + SIMULATION_TICKS.
 * Used for first load and filter re-scope (isMerge = false).
 */
function coldLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
  width: number,
  height: number,
): EntityGraphLayout {
  if (nodes.length === 0) {
    return { layoutNodes: [], layoutEdges: [], minWeight: 0, maxWeight: 0 }
  }

  // Build degree map from edges
  const degreeMap = new Map<string, number>()
  for (const e of edges) {
    degreeMap.set(e.source, (degreeMap.get(e.source) ?? 0) + 1)
    degreeMap.set(e.target, (degreeMap.get(e.target) ?? 0) + 1)
  }

  const nodeIndex = new Map<string, number>()
  nodes.forEach((n, i) => nodeIndex.set(n.id, i))

  // Initialise LayoutNode array with deterministic starting positions.
  const n = nodes.length
  const layoutNodes: LayoutNode[] = nodes.map((node, i) => {
    const angle = (2 * Math.PI * i) / n
    const radius = Math.min(width, height) * 0.35
    return {
      id: node.id,
      label: node.label,
      type: node.type,
      degree: degreeMap.get(node.id) ?? 0,
      x: width / 2 + radius * Math.cos(angle) + deterministicJitter(i) * 30,
      y: height / 2 + radius * Math.sin(angle) + deterministicJitter(i + 1000) * 30,
    }
  })

  return finishLayout(layoutNodes, edges, nodeIndex, width, height, SIMULATION_TICKS)
}

/**
 * Warm-start merge path — hard-pins existing nodes, seeds new nodes near a
 * neighbour, runs only MERGE_TICKS (#751 maintainer decision: HARD-PIN).
 *
 * Existing nodes: fx/fy set to current (x, y) → zero movement guaranteed.
 * New nodes: seeded near a connected existing neighbour (or layout center if none).
 * Removed nodes: simply absent from the output (they dropped out of the node list).
 */
function mergeLayoutFn(
  nodes: GraphNode[],
  edges: GraphEdge[],
  prevPositions: ReadonlyMap<string, { x: number; y: number }>,
  width: number,
  height: number,
): EntityGraphLayout {
  if (nodes.length === 0) {
    return { layoutNodes: [], layoutEdges: [], minWeight: 0, maxWeight: 0 }
  }

  // Build degree map
  const degreeMap = new Map<string, number>()
  for (const e of edges) {
    degreeMap.set(e.source, (degreeMap.get(e.source) ?? 0) + 1)
    degreeMap.set(e.target, (degreeMap.get(e.target) ?? 0) + 1)
  }

  const nodeIndex = new Map<string, number>()
  nodes.forEach((n, i) => nodeIndex.set(n.id, i))

  // Build adjacency map to find seed positions for new nodes
  const adjMap = new Map<string, string[]>()
  for (const e of edges) {
    if (!adjMap.has(e.source)) adjMap.set(e.source, [])
    if (!adjMap.has(e.target)) adjMap.set(e.target, [])
    adjMap.get(e.source)!.push(e.target)
    adjMap.get(e.target)!.push(e.source)
  }

  const layoutNodes: LayoutNode[] = nodes.map((node, i) => {
    const prev = prevPositions.get(node.id)
    if (prev !== undefined) {
      // HARD-PIN (#751): existing node keeps its exact (x, y).
      // fx/fy tells d3-force to lock the node in place — zero drift.
      return {
        id: node.id,
        label: node.label,
        type: node.type,
        degree: degreeMap.get(node.id) ?? 0,
        x: prev.x,
        y: prev.y,
        fx: prev.x,
        fy: prev.y,
      }
    }

    // New node: seed near a connected existing neighbour, or the layout center.
    const neighbours = adjMap.get(node.id) ?? []
    let seedX = width / 2
    let seedY = height / 2
    for (const nbrId of neighbours) {
      const nbrPos = prevPositions.get(nbrId)
      if (nbrPos) {
        seedX = nbrPos.x + deterministicJitter(i) * 60
        seedY = nbrPos.y + deterministicJitter(i + 500) * 60
        break
      }
    }

    return {
      id: node.id,
      label: node.label,
      type: node.type,
      degree: degreeMap.get(node.id) ?? 0,
      x: seedX,
      y: seedY,
    }
  })

  return finishLayout(layoutNodes, edges, nodeIndex, width, height, MERGE_TICKS)
}

/**
 * Shared tail: build resolved edges, run simulation ticks, clamp positions.
 * On merge path, existing nodes are already hard-pinned (fx/fy set); the
 * simulation only moves genuinely-new nodes.
 */
function finishLayout(
  layoutNodes: LayoutNode[],
  edges: GraphEdge[],
  nodeIndex: Map<string, number>,
  width: number,
  height: number,
  ticks: number,
): EntityGraphLayout {
  // Only include edges where both endpoints exist in the node set
  const resolvedEdges = edges.flatMap((e) => {
    const si = nodeIndex.get(e.source)
    const ti = nodeIndex.get(e.target)
    if (si === undefined || ti === undefined) return []
    return [{
      source: layoutNodes[si],
      target: layoutNodes[ti],
      weight: e.weight,
      kind: e.kind,
    }]
  })

  const weights = resolvedEdges.map((e) => e.weight)
  const minWeight = weights.length > 0 ? Math.min(...weights) : 0
  const maxWeight = weights.length > 0 ? Math.max(...weights) : 0

  const simulation = forceSimulation<LayoutNode>(layoutNodes)
    .force(
      'link',
      forceLink<LayoutNode, LayoutEdge>(resolvedEdges as LayoutEdge[])
        .id((d) => d.id)
        .distance(120)
        .strength(0.4),
    )
    .force('charge', forceManyBody<LayoutNode>().strength(-300))
    .force('center', forceCenter<LayoutNode>(width / 2, height / 2))
    .force(
      'collide',
      forceCollide<LayoutNode>().radius((d) => nodeRadius(d.degree) + 8),
    )
    .stop()

  // Run synchronously. On the merge path, pinned nodes don't move at all.
  simulation.tick(ticks)

  // Clamp positions within the world bounds and remove fx/fy locks so the
  // returned LayoutNode objects are clean (no d3-internal state leaking out).
  const PAD = 40
  for (const ln of layoutNodes) {
    ln.x = Math.max(PAD, Math.min(width - PAD, ln.x))
    ln.y = Math.max(PAD, Math.min(height - PAD, ln.y))
    // Clear the pin after layout is done — callers rely on x/y only.
    ln.fx = undefined
    ln.fy = undefined
  }

  return {
    layoutNodes,
    layoutEdges: resolvedEdges as LayoutEdge[],
    minWeight,
    maxWeight,
  }
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Compute the force-layout for the given graph data.
 * Returns stable positioned nodes and resolved edge references.
 *
 * @param nodes  - Graph node list from GET /logs/graph.
 * @param edges  - Graph edge list from GET /logs/graph.
 * @param width  - Layout world width (defaults to WORLD_WIDTH).
 * @param height - Layout world height (defaults to WORLD_HEIGHT).
 * @param isMerge - When true, applies the warm-start merge path (#751):
 *   existing nodes are HARD-PINNED at their prior (x, y); new nodes are
 *   seeded near a neighbour and settled with MERGE_TICKS only.
 *   When false (default), runs the full 300-tick cold layout from a fresh
 *   circular seed (used for first load and filter re-scope).
 */
export function useEntityGraph(
  nodes: GraphNode[],
  edges: GraphEdge[],
  width: number = WORLD_WIDTH,
  height: number = WORLD_HEIGHT,
  isMerge: boolean = false,
): EntityGraphLayout {
  // Compute stable dependency keys outside useMemo (plain string comparison).
  const nodeKey = nodes.map((n) => n.id).sort().join('|')
  const edgeKey = edges.map((e) => `${e.source}:${e.target}:${e.weight}`).sort().join('|')

  /**
   * prevPositionsRef tracks the (x, y) of the last-computed layout so the
   * merge path can hard-pin surviving nodes without a cold re-layout.
   * Lives in a ref to avoid triggering re-renders.
   *
   * Ref-access pattern: we snapshot `.current` OUTSIDE useMemo into a local
   * variable (`prevPositions`) to avoid the react-hooks/refs lint rule that
   * flags `.current` reads inside a useMemo body.  The write-back is done
   * in a useEffect that runs after each layout computation.
   */
  const prevPositionsRef = useRef<Map<string, { x: number; y: number }>>(new Map())

  // Snapshot the ref value at render time — outside useMemo so the lint rule
  // (react-hooks/refs) is satisfied.  This is safe: the ref is only written
  // in the useEffect below (after render), so the value is stable for this
  // render cycle.
  const prevPositionsSnapshot = prevPositionsRef.current

  const layout = useMemo(() => {
    if (isMerge && prevPositionsSnapshot.size > 0) { // eslint-disable-line react-hooks/refs
      // Warm-start: hard-pin existing nodes, settle only new additions.
      return mergeLayoutFn(nodes, edges, prevPositionsSnapshot, width, height) // eslint-disable-line react-hooks/refs
    }
    // Cold layout: first load or filter re-scope.
    return coldLayout(nodes, edges, width, height)
  // nodeKey/edgeKey/isMerge/width/height are all stable primitives.
  // prevPositionsSnapshot is NOT in the dep array — it is a stable Map reference
  // snapshotted from the ref; its identity only changes when we update the ref
  // in the effect below, which runs after a layout change, at which point
  // nodeKey or edgeKey will also have changed and useMemo will re-run.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeKey, edgeKey, isMerge, width, height])

  // Advance the position cache after each layout computation so the next
  // merge pass can read fresh positions.  useEffect runs after the render
  // cycle — safe to write to the ref here (satisfies react-hooks/refs).
  useEffect(() => {
    const nextPositions = new Map<string, { x: number; y: number }>()
    for (const ln of layout.layoutNodes) {
      nextPositions.set(ln.id, { x: ln.x, y: ln.y })
    }
    prevPositionsRef.current = nextPositions
  }, [layout])

  return layout
}

// ---------------------------------------------------------------------------
// Shared sizing helpers (also exported for use in EntityGraph.tsx)
// ---------------------------------------------------------------------------

/** Node circle radius based on degree (connection count). */
export function nodeRadius(degree: number): number {
  // Base 6px; +1px per 2 connections; capped at 18px.
  return Math.min(18, 6 + Math.floor(degree / 2))
}

/**
 * Normalise a weight value to a stroke width [minStroke, maxStroke].
 * When all edges have the same weight (or only one edge), returns midpoint.
 */
export function edgeStrokeWidth(
  weight: number,
  minWeight: number,
  maxWeight: number,
  minStroke: number = 1,
  maxStroke: number = 5,
): number {
  if (maxWeight === minWeight) return (minStroke + maxStroke) / 2
  const t = (weight - minWeight) / (maxWeight - minWeight)
  return minStroke + t * (maxStroke - minStroke)
}
