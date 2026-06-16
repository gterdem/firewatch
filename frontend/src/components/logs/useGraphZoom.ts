/**
 * useGraphZoom — d3-zoom transform layer for the Entity Relationship Graph.
 *
 * Implements ADR-0061 D1 (d3-zoom transform layer) and D2 (click-to-activate
 * wheel zoom). The zoom/pan is a CSS/SVG `transform` on a `<g>` layer —
 * NO inner scroll region (consistent with the no-nested-scrollbar constraint).
 *
 * Click-to-activate design (ADR-0061 D2):
 *   The ERG sits directly above the logs table.  Always-on wheel zoom would
 *   trap the page scroll.  Instead: wheel scrolls the page until the user
 *   clicks into the graph; a faint "click to interact" hint shows when inactive.
 *
 * Keyboard navigation (ADR-0061 D3):
 *   +/- keys: zoom in/out
 *   0 key: fit to content (true fit, not identity reset)
 *   Arrow keys: pan in steps
 *
 * Fit-to-content:
 *   computeFitTransform() computes a d3-zoom transform (translate + uniform scale)
 *   that centers and frames the node bounding-box within the viewport with 9% padding.
 *   fitToContent() applies this transform via the zoom behavior.
 *   zoomReset() is an alias for fitToContent() so [⤢] always fits the content.
 *   Auto-fit runs once when nodes first arrive (ready flips true) and re-fits
 *   when the node set changes (nodeKey dependency).
 *
 * #751 — auto-fit suppression on merge:
 *   A `suppressAutoFit` param gates the auto-fit effect.  When true (set by
 *   EntityGraph during a pill-driven incremental merge), the auto-fit RAF is
 *   skipped — the viewport (zoom/pan) is preserved.  Auto-fit still fires on
 *   first load and filter re-scope (suppressAutoFit = false).  The [⤢] button
 *   and `0` key remain user-initiated re-fit and are unaffected.
 *
 * SECURITY: no attacker-controlled values are processed here.
 */

import { useState, useRef, useCallback, useEffect } from 'react'
import { zoom as d3zoom, zoomIdentity } from 'd3-zoom'
import type { ZoomTransform } from 'd3-zoom'
import { select } from 'd3-selection'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MIN_SCALE = 0.2
const MAX_SCALE = 5
const ZOOM_STEP = 1.2     // multiplier per button press
const PAN_STEP = 40       // px per arrow key press

/**
 * Padding fraction for fit-to-content.  The bounding-box of the node cloud
 * is scaled to fill (1 − 2*FIT_PADDING) of the smaller viewport dimension.
 * 0.09 gives ~9% padding on each side.
 */
const FIT_PADDING = 0.09

// ---------------------------------------------------------------------------
// Fit-to-content helper (pure — no side effects)
// ---------------------------------------------------------------------------

/**
 * A minimal node shape required by computeFitTransform.
 * Only x/y world coordinates are needed.
 */
export interface FitNode {
  x: number
  y: number
}

/**
 * Compute a d3-zoom transform that centers and frames the bounding-box of
 * `nodes` within a `width × height` viewport with `FIT_PADDING` padding.
 *
 * Algorithm:
 *   1. Compute bounding-box of node positions.
 *   2. Scale uniformly so the bbox fits inside (1−2*pad) of the smaller dim.
 *   3. Translate to center the scaled bbox in the viewport.
 *
 * Returns `zoomIdentity` when there are no nodes (degenerate case).
 * The returned transform is clamped to [MIN_SCALE, MAX_SCALE].
 */
export function computeFitTransform(
  nodes: ReadonlyArray<FitNode>,
  width: number,
  height: number,
): ZoomTransform {
  if (nodes.length === 0) return zoomIdentity

  let minX = Infinity, maxX = -Infinity
  let minY = Infinity, maxY = -Infinity
  for (const n of nodes) {
    if (n.x < minX) minX = n.x
    if (n.x > maxX) maxX = n.x
    if (n.y < minY) minY = n.y
    if (n.y > maxY) maxY = n.y
  }

  const bboxW = maxX - minX
  const bboxH = maxY - minY

  // Available viewport dimensions after padding
  const padW = width * (1 - 2 * FIT_PADDING)
  const padH = height * (1 - 2 * FIT_PADDING)

  // Scale: fit the larger dimension; avoid division by zero for degenerate layouts
  let k: number
  if (bboxW <= 0 && bboxH <= 0) {
    k = 1
  } else if (bboxW <= 0) {
    k = padH / bboxH
  } else if (bboxH <= 0) {
    k = padW / bboxW
  } else {
    k = Math.min(padW / bboxW, padH / bboxH)
  }

  // Clamp to zoom extent
  k = Math.max(MIN_SCALE, Math.min(MAX_SCALE, k))

  // Center of bbox in world coords
  const cx = (minX + maxX) / 2
  const cy = (minY + maxY) / 2

  // Translate: map world center to viewport center
  const tx = width / 2 - k * cx
  const ty = height / 2 - k * cy

  return zoomIdentity.translate(tx, ty).scale(k)
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UseGraphZoomReturn {
  /** The current zoom transform, applied as an SVG attribute. */
  transform: ZoomTransform
  /** Whether wheel zoom is active. Apply the hint UI when false. */
  active: boolean
  /** Ref to attach to the outermost SVG element. */
  svgRef: React.RefObject<SVGSVGElement | null>
  /** Ref to attach to the inner <g> content group (unused; reserved for D6). */
  contentRef: React.RefObject<SVGGElement | null>
  /** Zoom in by one step. */
  zoomIn: () => void
  /** Zoom out by one step. */
  zoomOut: () => void
  /**
   * Fit the node cloud to fill the viewport (true fit-to-content, not identity reset).
   * Computes bbox from node positions, builds translate+scale transform, centers+frames
   * the cloud with FIT_PADDING.  Also triggered by the [⤢] button and the `0` key.
   */
  zoomReset: () => void
  /** Handle keyboard events on the SVG container. */
  handleKeyDown: (e: React.KeyboardEvent) => void
  /** Activate wheel zoom (call on SVG click). */
  activate: () => void
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Manages d3-zoom state for the entity graph SVG.
 *
 * Attaches d3-zoom to the SVG element via a ref.  The zoom transform is stored
 * in React state and applied as a `transform` attribute on the content <g>.
 * The wheel filter is toggled by the click-to-activate mechanism.
 *
 * NOTE: svgRef and contentRef are stable RefObject values — attaching them to
 * DOM elements via the `ref` prop is the intended React pattern and does not
 * constitute "accessing a ref during render" in the problematic sense.
 * The values passed to JSX here are the ref objects themselves, not `.current`.
 *
 * Bug #683 fix — `ready` param:
 *   On first render the graph data is empty (useLogsSurround fetches async), so
 *   EntityGraph takes its empty-state early-return and the <svg> is NOT mounted.
 *   The original [] deps effect ran once on mount with svgRef.current = null and
 *   never re-ran when data arrived and the SVG mounted, leaving zoomBehaviorRef
 *   null forever.  Passing `ready = nodes.length > 0` and including it in the
 *   bind-effect deps causes the effect to re-run when the SVG transitions from
 *   unmounted (empty state) to mounted (data present), binding d3-zoom at the
 *   right moment.  The cleanup already removes `.zoom` listeners, so unbind on
 *   ready→false and re-bind on ready→true work correctly.
 *
 * #751 — `suppressAutoFit` param:
 *   When true the auto-fit effect is suppressed — the viewport (zoom/pan) is
 *   preserved across the render.  Set to true for pill-driven incremental merges;
 *   false (the default) for first load and filter re-scope.
 *   The [⤢] button and `0` key always call fitToContent() regardless.
 *
 * Auto-fit-to-content:
 *   After d3-zoom binds (ready flips true), fitToContent() is called once to
 *   frame the node cloud in the viewport.  Re-fit also runs when `nodeKey`
 *   changes (node set changes on filter re-scope), keeping the graph centered.
 *   The `nodes` param is a readonly array of {x,y} positions from the layout.
 */
export function useGraphZoom(
  width: number,
  height: number,
  ready: boolean,
  nodes: ReadonlyArray<FitNode> = [],
  suppressAutoFit: boolean = false,
): UseGraphZoomReturn {
  const svgRef = useRef<SVGSVGElement | null>(null)
  const contentRef = useRef<SVGGElement | null>(null)

  // d3-zoom behavior — stored in a ref (never triggers re-renders)
  const zoomBehaviorRef = useRef<ReturnType<typeof d3zoom<SVGSVGElement, unknown>> | null>(null)

  // React state for the current transform (drives SVG attribute update)
  const [transform, setTransform] = useState<ZoomTransform>(zoomIdentity)

  // Whether wheel zoom is active (state, not a ref — drives UI changes)
  const [active, setActiveState] = useState(false)

  // Ref shadow of active for use inside d3 event handlers without closure stale state
  const activeRef = useRef(false)

  // Ref shadow of nodes — synced via effect so we never write to .current during render.
  // Used by fitToContent() (which is called from button/keyboard handlers) to
  // always access the latest node positions without stale closures.
  const nodesRef = useRef<ReadonlyArray<FitNode>>(nodes)
  useEffect(() => {
    nodesRef.current = nodes
  })

  // Stable key representing the current node set identity (for auto-fit dep).
  // Derived from the nodes array's x/y positions — changes when the layout
  // produces a new set of positions (new data or filter re-scope).
  const nodeKey = nodes.map((n) => `${n.x.toFixed(1)},${n.y.toFixed(1)}`).join('|')

  const setActive = useCallback((next: boolean) => {
    activeRef.current = next
    setActiveState(next)
    // Re-filter the zoom behavior when active flag changes
    if (zoomBehaviorRef.current) {
      zoomBehaviorRef.current.filter((event: Event) => {
        if (event.type === 'wheel') return activeRef.current
        return true
      })
    }
  }, [])

  // ---------------------------------------------------------------------------
  // Fit-to-content — core implementation (stable across renders)
  // ---------------------------------------------------------------------------

  const fitToContent = useCallback(() => {
    const svgEl = svgRef.current
    const behavior = zoomBehaviorRef.current
    if (!svgEl || !behavior) return
    const fitTransform = computeFitTransform(nodesRef.current, width, height)
    behavior.transform(select(svgEl), fitTransform)
  }, [width, height])

  // Bind d3-zoom when the SVG element is mounted (i.e. when `ready` is true).
  //
  // Bug #683: the original effect had [] deps and ran once on mount — at that
  // point svgRef.current was null (SVG not yet mounted; data still loading) so
  // the bind was skipped and zoomBehaviorRef stayed null forever.  Including
  // `ready` in deps causes the effect to re-run as soon as the graph transitions
  // from empty-state (SVG unmounted) to data-present (SVG mounted), binding
  // d3-zoom at the right moment.  The cleanup removes `.zoom` listeners so the
  // unbind/re-bind across empty↔non-empty transitions is correct.
  useEffect(() => {
    if (!ready) return            // SVG is not mounted yet — nothing to bind
    const svgEl = svgRef.current
    if (!svgEl) return

    const behavior = d3zoom<SVGSVGElement, unknown>()
      .scaleExtent([MIN_SCALE, MAX_SCALE])
      .extent([[0, 0], [width, height]])
      .filter((event: Event) => {
        if (event.type === 'wheel') return activeRef.current
        return true
      })
      .on('zoom', (event: { transform: ZoomTransform }) => {
        setTransform(event.transform)
      })

    zoomBehaviorRef.current = behavior

    const selection = select(svgEl)
    selection.call(behavior)
    // Disable dblclick zoom (avoid accidental double-zoom)
    selection.on('dblclick.zoom', null)

    return () => {
      selection.on('.zoom', null)
      zoomBehaviorRef.current = null
    }
  // `ready` is the key dep: re-bind whenever the SVG mounts/unmounts.
  // width/height intentionally excluded — zoom extent is set once; SVG clips naturally.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready])

  // ---------------------------------------------------------------------------
  // Auto-fit: run once after d3-zoom binds (ready=true), and re-fit whenever
  // the node set changes (nodeKey changes on filter re-scope / new data).
  //
  // #751: SUPPRESS auto-fit when `suppressAutoFit` is true — that signals an
  // incremental merge where the viewport MUST be preserved (ADR-0064 D5).
  // The [⤢] button and `0` key always call fitToContent() regardless.
  //
  // Split into a separate effect from the bind effect so the auto-fit dep
  // (nodeKey) doesn't re-trigger a full d3-zoom teardown/rebind.
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!ready) return
    if (suppressAutoFit) return   // #751: preserve viewport on merge
    // Defer one tick so the SVG layout has committed before we compute the fit.
    const id = requestAnimationFrame(() => {
      fitToContent()
    })
    return () => cancelAnimationFrame(id)
  }, [ready, nodeKey, fitToContent, suppressAutoFit])

  // ---------------------------------------------------------------------------
  // Programmatic zoom helpers — used by controls + keyboard (ADR-0061 D3)
  // ---------------------------------------------------------------------------

  const applyTransform = useCallback((fn: (t: ZoomTransform) => ZoomTransform) => {
    const svgEl = svgRef.current
    const behavior = zoomBehaviorRef.current
    if (!svgEl || !behavior) return
    // Read the current transform via the internal zoom state getter
    const currentTransform = (svgEl as SVGSVGElement & { __zoom?: ZoomTransform }).__zoom ?? zoomIdentity
    const next = fn(currentTransform)
    behavior.transform(select(svgEl), next)
  }, [])

  const zoomIn = useCallback(() => {
    applyTransform((t) => {
      const k2 = Math.min(MAX_SCALE, t.k * ZOOM_STEP)
      const cx = width / 2
      const cy = height / 2
      return zoomIdentity
        .translate(cx, cy)
        .scale(k2)
        .translate(-cx / k2, -cy / k2)
        .translate(t.x / k2, t.y / k2)
    })
  }, [applyTransform, width, height])

  const zoomOut = useCallback(() => {
    applyTransform((t) => {
      const k2 = Math.max(MIN_SCALE, t.k / ZOOM_STEP)
      const cx = width / 2
      const cy = height / 2
      return zoomIdentity
        .translate(cx, cy)
        .scale(k2)
        .translate(-cx / k2, -cy / k2)
        .translate(t.x / k2, t.y / k2)
    })
  }, [applyTransform, width, height])

  // zoomReset = true fit-to-content (not identity reset).
  // The [⤢] button and the `0` key both call this — always available.
  const zoomReset = fitToContent

  // ---------------------------------------------------------------------------
  // Keyboard handler (ADR-0061 D3): +/-/0/arrows
  // ---------------------------------------------------------------------------

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    switch (e.key) {
      case '+':
      case '=':
        e.preventDefault()
        zoomIn()
        break
      case '-':
        e.preventDefault()
        zoomOut()
        break
      case '0':
        e.preventDefault()
        zoomReset()
        break
      case 'ArrowLeft':
        e.preventDefault()
        applyTransform((t) => t.translate(PAN_STEP / t.k, 0))
        break
      case 'ArrowRight':
        e.preventDefault()
        applyTransform((t) => t.translate(-PAN_STEP / t.k, 0))
        break
      case 'ArrowUp':
        e.preventDefault()
        applyTransform((t) => t.translate(0, PAN_STEP / t.k))
        break
      case 'ArrowDown':
        e.preventDefault()
        applyTransform((t) => t.translate(0, -PAN_STEP / t.k))
        break
      default:
        break
    }
  }, [zoomIn, zoomOut, zoomReset, applyTransform])

  // ---------------------------------------------------------------------------
  // Click-to-activate (ADR-0061 D2)
  // ---------------------------------------------------------------------------

  // Deactivate when the user clicks outside the SVG
  useEffect(() => {
    const handleDocumentClick = (e: MouseEvent) => {
      if (!activeRef.current) return
      const svgEl = svgRef.current
      if (svgEl && !svgEl.contains(e.target as Node)) {
        setActive(false)
      }
    }
    document.addEventListener('click', handleDocumentClick, { capture: true })
    return () => {
      document.removeEventListener('click', handleDocumentClick, { capture: true })
    }
  }, [setActive])

  const activate = useCallback(() => {
    if (!activeRef.current) {
      setActive(true)
    }
  }, [setActive])

  return {
    transform,
    active,
    svgRef,
    contentRef,
    zoomIn,
    zoomOut,
    zoomReset,
    handleKeyDown,
    activate,
  }
}
