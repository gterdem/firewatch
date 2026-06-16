/**
 * useNewlyExposed — set-diff newly-surfaced entities on filter re-scope (ADR-0061 D6).
 *
 * When the graph re-scopes (nodes/edges props change because the analyst changed
 * the filter), this hook finds the entities **newly surfaced** — present in the
 * current id set but absent in the previous one.
 *
 * Design decisions:
 *  - First render (mount) is intentionally IGNORED: on mount there is no
 *    "previous" state, so every entity would be "newly exposed" — that is
 *    misleading.  The hook tracks whether it has seen at least one prior set
 *    before producing a diff.
 *  - Reset/clear: when nodes.length === 0 (filter cleared / unscoped view
 *    with no data), newly-exposed is emptied and the previous-set ref is reset.
 *    This prevents stale ids bleeding into the next filter session.
 *  - `prefers-reduced-motion`: the hook reads the media query and returns a
 *    `reducedMotion` boolean so the caller can swap animation for a static ring.
 *    The hook stays pure logic; the visual decision lives in EntityGraph.tsx.
 *
 * SECURITY (ADR-0029 D3): node id values are attacker-controlled telemetry.
 * They are stored as plain strings in a Set and compared with Set.has(); they
 * are never interpreted, executed, or injected into the DOM as HTML.
 */

import { useRef, useState, useEffect } from 'react'
import type { GraphNode, GraphEdge } from '../../api/types'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UseNewlyExposedReturn {
  /**
   * Set of node/edge ids (node.id and a canonical edge key) that are NEWLY
   * present in the current render vs the previous one.
   * Empty on the first render (mount) and when the graph is cleared.
   */
  newlyExposedNodeIds: ReadonlySet<string>
  newlyExposedEdgeKeys: ReadonlySet<string>
  /** Total count of newly-exposed entities (nodes + edges). */
  newlyExposedCount: number
  /**
   * Whether `prefers-reduced-motion: reduce` is active.
   * When true, callers SHOULD render a static accent ring instead of a pulse.
   */
  reducedMotion: boolean
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Canonical string key for an edge (direction-agnostic within a kind). */
function edgeKey(source: string, target: string, kind: string): string {
  return `${kind}:${source}--${target}`
}

function nodeIdSet(nodes: GraphNode[]): Set<string> {
  return new Set(nodes.map((n) => n.id))
}

function edgeKeySet(edges: GraphEdge[]): Set<string> {
  return new Set(edges.map((e) => edgeKey(e.source, e.target, e.kind)))
}

/** Set difference: items in `next` that are not in `prev`. */
function setDiff<T>(next: Set<T>, prev: Set<T>): Set<T> {
  const result = new Set<T>()
  for (const item of next) {
    if (!prev.has(item)) {
      result.add(item)
    }
  }
  return result
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Tracks previous node/edge id sets and returns the diff (newly-exposed) on
 * each prop change.  Ignores the first render (mount — no previous context).
 *
 * @param nodes - Current node list (from GET /logs/graph via props).
 * @param edges - Current edge list (from GET /logs/graph via props).
 */
export function useNewlyExposed(
  nodes: GraphNode[],
  edges: GraphEdge[],
): UseNewlyExposedReturn {
  // Track whether we have seen a previous render (skip the mount diff).
  const hasPrevRef = useRef(false)

  // Previous id sets — kept in refs so they don't trigger re-renders.
  const prevNodeIdsRef = useRef<Set<string>>(new Set())
  const prevEdgeKeysRef = useRef<Set<string>>(new Set())

  // Newly-exposed state — drives the visual highlight.
  const [newlyExposedNodeIds, setNewlyExposedNodeIds] = useState<ReadonlySet<string>>(new Set())
  const [newlyExposedEdgeKeys, setNewlyExposedEdgeKeys] = useState<ReadonlySet<string>>(new Set())

  // prefers-reduced-motion detection (initialised once; updated on change).
  // Guard: `window.matchMedia` may be undefined in jsdom / SSR environments.
  const [reducedMotion, setReducedMotion] = useState<boolean>(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches
  })

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    const handler = (e: MediaQueryListEvent) => setReducedMotion(e.matches)
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [])

  // Core diff effect — runs when nodes/edges reference changes.
  useEffect(() => {
    const currentNodeIds = nodeIdSet(nodes)
    const currentEdgeKeys = edgeKeySet(edges)

    if (!hasPrevRef.current) {
      // First render after mount (or after a clear) — record the baseline.
      // Nothing is "newly exposed" on the first view.
      // IMPORTANT: do NOT call setState here — state is already empty (new Set())
      // from the useState initialiser.  Calling setState would trigger a re-render
      // which changes the deps (new array literal in the caller) → infinite loop.
      hasPrevRef.current = true
      prevNodeIdsRef.current = currentNodeIds
      prevEdgeKeysRef.current = currentEdgeKeys
      return
    }

    // Clear path: when the graph is empty, reset refs and state.
    // Note: calling setState inside a conditional block within an effect is
    // intentional here — this is a "compare with previous value" pattern that
    // legitimately needs synchronous state updates to stay in sync with
    // ref-tracked prev sets.  The functional updater bails out (returns prev)
    // when already empty, preventing spurious re-renders / loops.
    if (nodes.length === 0) {
      hasPrevRef.current = false
      prevNodeIdsRef.current = new Set()
      prevEdgeKeysRef.current = new Set()
      // Only call setState if the exposed sets are not already empty.
      // This prevents spurious re-renders and potential loops when callers
      // pass a new empty-array literal on every render.
      setNewlyExposedNodeIds( // eslint-disable-line react-hooks/set-state-in-effect
        (prev) => (prev.size === 0 ? prev : new Set()),
      )
      setNewlyExposedEdgeKeys(
        (prev) => (prev.size === 0 ? prev : new Set()),
      )
      return
    }

    // Diff
    const newNodes = setDiff(currentNodeIds, prevNodeIdsRef.current)
    const newEdges = setDiff(currentEdgeKeys, prevEdgeKeysRef.current)

    // Advance the previous-set window
    prevNodeIdsRef.current = currentNodeIds
    prevEdgeKeysRef.current = currentEdgeKeys

    setNewlyExposedNodeIds(newNodes)
    setNewlyExposedEdgeKeys(newEdges)
  }, [nodes, edges])

  const newlyExposedCount = newlyExposedNodeIds.size + newlyExposedEdgeKeys.size

  return {
    newlyExposedNodeIds,
    newlyExposedEdgeKeys,
    newlyExposedCount,
    reducedMotion,
  }
}
