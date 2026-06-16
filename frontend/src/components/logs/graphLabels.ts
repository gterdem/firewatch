/**
 * graphLabels — label level-of-detail (LOD) for the entity relationship graph.
 *
 * Implements ADR-0061 D4: label only top-K nodes by degree ∪ CRITICAL/HIGH-verdict
 * IPs ∪ the hovered/focused node, with more labels revealed as zoom scale rises.
 *
 * This is the primary readability fix (ADR-0061 context: "the unreadability is
 * LABELS + a cramped canvas, NOT node overlap").  forceCollide is already wired
 * in useEntityGraph.ts — this module handles the label budget.
 *
 * LOD pattern:
 *   - At scale 1.0 (default): show top-K by degree + CRITICAL/HIGH IPs
 *   - As scale increases: reveal more labels (descending degree)
 *   - Always show: hovered/focused node's label
 *   This mirrors the Sentinel / Maltego label-LOD pattern (ADR-0061 §References).
 *
 * SECURITY (ADR-0029 D3): this module decides WHICH labels to show, not HOW.
 *   The caller always renders labels as SVG text nodes only.
 */

import type { LayoutNode } from './useEntityGraph'
import type { ThreatScore } from '../../api/types'
import { normaliseThreatLevel } from '../../lib/provenance'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Base number of labels to show at scale 1.0 (top-K by degree).
 * CRITICAL/HIGH IPs are always labelled independently of this budget.
 */
const BASE_LABEL_K = 5

/**
 * Additional labels to reveal per zoom-level step.
 * At each integer zoom step above 1, reveal this many more labels.
 */
const LABELS_PER_ZOOM_STEP = 3

/**
 * Zoom scale thresholds at which more labels unlock.
 * (Labels unlock at 1.5×, 2×, 3×, etc.)
 */
const ZOOM_THRESHOLDS = [1.5, 2.0, 3.0, 4.0]

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface LabelLODConfig {
  /** Current zoom scale (from d3-zoom ZoomTransform.k). */
  scale: number
  /** Node id that is currently hovered/focused (always labelled). */
  hoveredId: string | null
  /**
   * Map of IP node id → ThreatScore for CRITICAL/HIGH detection.
   * Only IP-type nodes are checked.
   */
  threatMap: ReadonlyMap<string, ThreatScore>
}

// ---------------------------------------------------------------------------
// Core predicate
// ---------------------------------------------------------------------------

/**
 * Build a Set of node ids that SHOULD display labels at the current zoom/hover state.
 *
 * Inclusion rules (in order of priority):
 *  1. Hovered/focused node (always)
 *  2. CRITICAL/HIGH verdict IP nodes (always)
 *  3. Top-K by degree at base scale; more labels unlocked as scale increases
 *
 * @param nodes - All layout nodes, in any order
 * @param config - Current zoom scale, hovered id, threat map
 * @returns Set of node ids whose labels should be visible
 */
export function buildVisibleLabelSet(
  nodes: LayoutNode[],
  config: LabelLODConfig,
): Set<string> {
  const { scale, hoveredId, threatMap } = config
  const visible = new Set<string>()

  // Rule 1: Always label the hovered/focused node
  if (hoveredId !== null) {
    visible.add(hoveredId)
  }

  // Rule 2: CRITICAL/HIGH verdict IPs always labelled (importance signal from AI verdict)
  for (const node of nodes) {
    if (node.type === 'ip') {
      const threat = threatMap.get(node.id)
      if (threat) {
        const band = normaliseThreatLevel(threat.threat_level)
        if (band === 'CRITICAL' || band === 'HIGH') {
          visible.add(node.id)
        }
      }
    }
  }

  // Rule 3: Top-K by degree, with budget expanding as zoom increases
  const budget = computeLabelBudget(scale)
  if (budget > 0) {
    // Sort nodes by degree descending (stable: deterministic by id as tiebreaker)
    const byDegree = [...nodes].sort((a, b) => {
      if (b.degree !== a.degree) return b.degree - a.degree
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0
    })
    let count = 0
    for (const node of byDegree) {
      if (count >= budget) break
      visible.add(node.id)
      count++
    }
  }

  return visible
}

/**
 * Compute the number of degree-ranked labels to show at the given zoom scale.
 *
 * At scale < 1 (zoomed out): use only BASE_LABEL_K.
 * Each ZOOM_THRESHOLD crossed adds LABELS_PER_ZOOM_STEP more labels.
 */
export function computeLabelBudget(scale: number): number {
  let budget = BASE_LABEL_K
  for (const threshold of ZOOM_THRESHOLDS) {
    if (scale >= threshold) {
      budget += LABELS_PER_ZOOM_STEP
    }
  }
  return budget
}

/**
 * Predicate: should this specific node show its label?
 * Lightweight version for use in render loops — checks the precomputed Set.
 */
export function shouldShowLabel(nodeId: string, visibleLabels: Set<string>): boolean {
  return visibleLabels.has(nodeId)
}
