/**
 * useLogsSurround — filter-scoped surround data hook (#667 WS4a, #751).
 *
 * Collapses the three mount-only useEffect blocks in LogsRoute into a single
 * filter-keyed data layer, so top-pairs AND entity-graph re-query whenever the
 * active LogsFilter changes — the same key the table's existing effect uses.
 *
 * Fetches (all filter-scoped and non-fatal):
 *   - GET /logs/top-pairs  → topPairs
 *   - GET /logs/graph      → graph (nodes, edges, truncated)
 *
 * #751 — `refreshSurround()` seam:
 *   Exposes a stable `refreshSurround()` callback that LogsRoute's pill handler
 *   calls on click.  This refetches top-pairs + the graph for the CURRENT filter
 *   and routes the graph result through the MERGE path in useEntityGraph
 *   (via the `graphIsMerge` flag in the returned data).
 *
 *   Filter-change fetches still use the full cold-layout path (graphIsMerge = false).
 *   Only pill-driven refreshes set graphIsMerge = true.
 *
 * Note: StripTiles already self-manages its own filter-keyed fetches inside
 * the component (#665). This hook handles the panels that were still on
 * mount-only effects: TopPairsPanel and EntityGraph.
 *
 * Non-fatal posture (ADR-0015): each fetch degrades to its empty state on
 * failure — the logs table is unaffected. Errors are swallowed here because
 * the panels show their own empty states; there is no user-visible error UI
 * for surround panel failures.
 *
 * SECURITY (ADR-0029 D3): source_ip, destination_ip, and node id/label values
 * from the API are attacker-controlled telemetry. This hook returns them typed
 * normally; callers MUST render them as text nodes only.
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import { fetchTopPairs, fetchEntityGraph } from '../../api/logs'
import type { LogsFilter, TopPairsRow, GraphNode, GraphEdge } from '../../api/types'

// ---------------------------------------------------------------------------
// Return type
// ---------------------------------------------------------------------------

export interface LogsSurroundData {
  /** Top src→dst pairs from GET /logs/top-pairs (filter-scoped). */
  topPairs: TopPairsRow[]
  /** Whether topPairs are still loading. */
  topPairsLoading: boolean
  /** Node list from GET /logs/graph (filter-scoped). */
  graphNodes: GraphNode[]
  /** Edge list from GET /logs/graph (filter-scoped). */
  graphEdges: GraphEdge[]
  /** Whether the graph response was truncated to the highest-weight subgraph. */
  graphTruncated: boolean
  /**
   * Whether the latest graph data arrived via a pill-driven incremental merge
   * (#751).  True only after `refreshSurround()` is called; reverts to false
   * on the next filter-change fetch.  EntityGraph passes this to useEntityGraph
   * as `isMerge` to select the warm-start layout path.
   */
  graphIsMerge: boolean
  /**
   * Callback the pill handler calls on click (#748, #751).
   * Refetches top-pairs + graph for the CURRENT filter and routes the graph
   * result through the merge path (graphIsMerge = true).
   * Filter-change fetches are unaffected and always do a cold layout.
   */
  refreshSurround: () => void
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Fetch the analytical surround panels scoped to the current filter.
 *
 * Re-runs whenever the serialised filter changes (same key as the table effect).
 * Each fetch is independently non-fatal: a failure leaves that field at its
 * empty-state default without affecting other fetches or the logs table.
 *
 * @param filter - The current LogsFilter from LogsRoute (shared with the table).
 */
export function useLogsSurround(filter: LogsFilter): LogsSurroundData {
  const [topPairs, setTopPairs] = useState<TopPairsRow[]>([])
  const [topPairsLoading, setTopPairsLoading] = useState(true)
  const [graphNodes, setGraphNodes] = useState<GraphNode[]>([])
  const [graphEdges, setGraphEdges] = useState<GraphEdge[]>([])
  const [graphTruncated, setGraphTruncated] = useState(false)
  // #751: merge flag — true only for pill-driven refreshes
  const [graphIsMerge, setGraphIsMerge] = useState(false)

  // Stable serialised key — same approach as the table effect in LogsRoute.tsx.
  // Using JSON.stringify so we re-fetch on any field change without needing
  // the caller to memoize the filter object.
  const filterKey = JSON.stringify(filter)

  // Ref for the current filter so refreshSurround() can use the latest value
  // without being re-created on every filter change.
  const filterRef = useRef<LogsFilter>(filter)
  useEffect(() => {
    filterRef.current = filter
  })

  // ---------------------------------------------------------------------------
  // Filter-change effect — COLD LAYOUT.
  // Runs whenever the filter key changes.  Always produces graphIsMerge = false.
  // This is the existing behaviour, unchanged.
  // ---------------------------------------------------------------------------
  useEffect(() => {
    let cancelled = false

    // Reset merge flag on a filter change — the next render uses cold layout.
    setGraphIsMerge(false) // eslint-disable-line react-hooks/set-state-in-effect

    // Fetch top pairs and entity graph in parallel, both filter-scoped (#667 WS4).
    // top_n=10 so the panel can show top-5 with a "View all" for the rest.
    Promise.allSettled([
      fetchTopPairs(10, filter),
      fetchEntityGraph(40, 200, filter),
    ]).then(([pairsResult, graphResult]) => {
      if (cancelled) return

      if (pairsResult.status === 'fulfilled') {
        setTopPairs(pairsResult.value)
      } else {
        // Non-fatal: degrade to empty (ADR-0015)
        setTopPairs([])
      }
      // Loading ends once the fetch settles (success or failure).
      setTopPairsLoading(false)

      if (graphResult.status === 'fulfilled' && graphResult.value !== null) {
        setGraphNodes(graphResult.value.nodes)
        setGraphEdges(graphResult.value.edges)
        setGraphTruncated(graphResult.value.truncated)
      } else {
        // Non-fatal: graph degrades to empty state (ADR-0015)
        setGraphNodes([])
        setGraphEdges([])
        setGraphTruncated(false)
      }
    })

    return () => {
      cancelled = true
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterKey])

  // ---------------------------------------------------------------------------
  // refreshSurround — MERGE path (#748 / #751).
  // Called by the pill handler; refetches for the CURRENT filter and sets
  // graphIsMerge = true so EntityGraph uses the warm-start (hard-pin) layout path.
  // A stable callback: does not change when filter changes (reads filterRef).
  // ---------------------------------------------------------------------------
  const refreshSurround = useCallback(() => {
    const currentFilter = filterRef.current

    Promise.allSettled([
      fetchTopPairs(10, currentFilter),
      fetchEntityGraph(40, 200, currentFilter),
    ]).then(([pairsResult, graphResult]) => {
      if (pairsResult.status === 'fulfilled') {
        setTopPairs(pairsResult.value)
      }
      // topPairsLoading stays as-is — this is a background merge, not a full reload.

      if (graphResult.status === 'fulfilled' && graphResult.value !== null) {
        // Signal merge BEFORE updating nodes/edges so EntityGraph sees the flag
        // on the same render cycle that receives the new data.
        setGraphIsMerge(true)
        setGraphNodes(graphResult.value.nodes)
        setGraphEdges(graphResult.value.edges)
        setGraphTruncated(graphResult.value.truncated)
      }
      // Non-fatal: if the graph fetch fails, keep the existing graph (silent degrade).
    })
  }, [])

  return {
    topPairs,
    topPairsLoading,
    graphNodes,
    graphEdges,
    graphTruncated,
    graphIsMerge,
    refreshSurround,
  }
}
