/**
 * EntityGraph — entity-relationship graph panel (ML-9, issue #437).
 *
 * Orchestrator component — composes the layout, zoom, label-LOD,
 * controls, legend-toggle, and newly-exposed-paths concerns.
 * Implements ADR-0061 D1-D6.
 *
 * Approach (ADR-0050 + ADR-0061):
 *   d3-force for layout math ONLY → drawn to hand-rolled SVG.
 *   d3-zoom for transform math + event handling ONLY (ADR-0061 amends
 *   ADR-0050's deferred-zoom clause; everything else in ADR-0050 stands).
 *   No graph-rendering framework. No canvas. Real DOM nodes throughout.
 *
 * Layout:
 *   - Nodes: <circle> sized by degree. An invisible padded <circle> larger
 *     than the visible dot handles hit-testing (ADR-0061 D5).
 *   - Edges: <line> with stroke-width by weight.
 *   - IP nodes: tinted by local-AI verdict band (LOW/MED/HIGH/CRIT).
 *   - Labels: <text> nodes rendered per label LOD logic (ADR-0061 D4);
 *     text nodes only (ADR-0029 D3).
 *
 * Interaction:
 *   - Click-to-activate wheel zoom (ADR-0061 D2): page scrolls until click.
 *   - Drag pan; +/-/0/arrow keys (ADR-0061 D3).
 *   - Focus/context: hover highlights neighbours, dims rest (ADR-0061 D5).
 *   - Legend toggles: ASN/Category kinds hidden client-side (ADR-0061 D5).
 *   - Click IP node → onNodeClick(ip) cross-filters the logs table.
 *
 * Newly-exposed paths (ADR-0061 D6):
 *   When nodes/edges props change (filter re-scope via useLogsSurround), the
 *   useNewlyExposed hook set-diffs the new vs previous id sets and returns
 *   the newly-surfaced ids.  These receive a brief accent pulse (600ms glow
 *   in --fw-accent).  Under prefers-reduced-motion, a static accent ring
 *   replaces the pulse.  A caption shows "N entities newly exposed by this
 *   filter" — glass-box, factual, never infers intent.  Node verdict-band
 *   tints are preserved (the pulse is an additive outline only).
 *
 * SECURITY (ADR-0029 D3): ALL node id/label values are attacker-controlled
 * telemetry. Rendered ONLY as SVG text nodes — never innerHTML.
 */

import { useId, useState, useRef, useCallback, useMemo, useEffect } from 'react'
import { createPortal } from 'react-dom'
import type { ThreatScore } from '../../api/types'
import type { GraphNode, GraphEdge } from '../../api/types'
import {
  useEntityGraph,
  nodeRadius,
  edgeStrokeWidth,
  GRAPH_WIDTH,
  GRAPH_HEIGHT,
  WORLD_WIDTH,
  WORLD_HEIGHT,
} from './useEntityGraph'
import {
  normaliseThreatLevel,
  severityFgToken,
  severityBgToken,
} from '../../lib/provenance'
import type { SeverityBand } from '../../lib/provenance'
import type { LayoutNode } from './useEntityGraph'
import { useGraphZoom } from './useGraphZoom'
import { buildVisibleLabelSet } from './graphLabels'
import GraphControls from './GraphControls'
import GraphLegendToggles from './GraphLegendToggles'
import type { ToggleableKind } from './GraphLegendToggles'
import { useNewlyExposed } from './useNewlyExposed'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EntityGraphProps {
  /** Node list from GET /logs/graph. */
  nodes: GraphNode[]
  /** Edge list from GET /logs/graph. */
  edges: GraphEdge[]
  /**
   * Whether the response was truncated (cardinality exceeded cap).
   * When true, renders an honest "showing top N — filter to narrow" chip.
   */
  truncated: boolean
  /**
   * Map of IP → ThreatScore from the threats endpoint.
   * Used to tint IP nodes by their AI verdict band.
   */
  threatMap: ReadonlyMap<string, ThreatScore>
  /**
   * Called when the user clicks (or activates via keyboard) an IP node.
   * Cross-filters the logs table.  The ip argument is the raw node.id string
   * — callers MUST treat it as attacker-controlled text.
   */
  onNodeClick: (ip: string) => void
  /**
   * #751 — when true, the graph uses the warm-start merge path (hard-pins
   * existing nodes, settles only new additions) and suppresses the auto-fit
   * viewport re-frame.  Set by LogsRoute when the pill triggers a surround
   * refresh.  False (default) for first load and filter re-scope.
   */
  isMerge?: boolean
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NEUTRAL_NODE_FG = 'var(--fw-t2)'
const NEUTRAL_NODE_BG = 'var(--fw-bg-raised)'
const ASN_NODE_FG = 'var(--fw-cyan)'
const ASN_NODE_BG = 'var(--fw-tint-blue)'
const CAT_NODE_FG = 'var(--fw-purple)'
const CAT_NODE_BG = 'var(--fw-tint-orange)'

const EDGE_COLOR_FLOW = 'var(--fw-border-l)'
const EDGE_COLOR_ASN = 'var(--fw-tint-blue-bd)'
const EDGE_COLOR_CAT = 'var(--fw-tint-orange-bd)'

/** Max characters shown in a node label before truncation with ellipsis. */
const LABEL_MAX_CHARS = 15

/**
 * Opacity for dimmed nodes/edges in focus+context mode (ADR-0061 D5).
 * Neighbours of hovered node remain at 1.0; all others at this value.
 */
const DIM_OPACITY = 0.15

/**
 * Newly-exposed paths pulse (ADR-0061 D6).
 * Radius offset for the accent ring/glow drawn around newly-exposed nodes.
 * The ring is additive — it sits outside the visible circle and does not
 * alter the verdict-band fill or stroke.
 */
const NEWLY_EXPOSED_RING_OFFSET = 4

/**
 * Duration of the pulse animation (ms).  After this the ring fades.
 * Under prefers-reduced-motion the animation is suppressed and a static
 * ring renders at reduced opacity instead.
 */
const PULSE_DURATION_MS = 600

/**
 * Edge highlighting for newly-exposed edges (ADR-0061 D6).
 * A brief accent glow on the stroke.
 */
const NEWLY_EXPOSED_EDGE_STROKE_OPACITY = 0.85

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Truncate a label to fit inside a node (text safety: still a text node). */
function truncateLabel(label: string): string {
  if (label.length <= LABEL_MAX_CHARS) return label
  return `${label.slice(0, LABEL_MAX_CHARS - 1)}…`
}

/** Pick fill/stroke colors for a node based on type + verdict band. */
function nodeColors(
  nodeType: string,
  id: string,
  threatMap: ReadonlyMap<string, ThreatScore>,
): { fg: string; bg: string; band: SeverityBand | null } {
  if (nodeType === 'ip') {
    const threat = threatMap.get(id)
    if (threat) {
      const band = normaliseThreatLevel(threat.threat_level)
      return { fg: severityFgToken(band), bg: severityBgToken(band), band }
    }
    return { fg: NEUTRAL_NODE_FG, bg: NEUTRAL_NODE_BG, band: null }
  }
  if (nodeType === 'asn') {
    return { fg: ASN_NODE_FG, bg: ASN_NODE_BG, band: null }
  }
  // category
  return { fg: CAT_NODE_FG, bg: CAT_NODE_BG, band: null }
}

/** Pick edge color by kind. */
function edgeColor(kind: string): string {
  if (kind === 'flow') return EDGE_COLOR_FLOW
  if (kind === 'asn') return EDGE_COLOR_ASN
  return EDGE_COLOR_CAT
}

/**
 * Canonical edge key matching the format in useNewlyExposed — used to look up
 * whether a layout edge is in the newly-exposed set (ADR-0061 D6).
 */
function layoutEdgeKey(sourceId: string, targetId: string, kind: string): string {
  return `${kind}:${sourceId}--${targetId}`
}

// ---------------------------------------------------------------------------
// Tooltip state type
// ---------------------------------------------------------------------------

interface TooltipState {
  node: LayoutNode
  band: SeverityBand | null
  screenX: number
  screenY: number
}

// ---------------------------------------------------------------------------
// Subcomponent: tooltip bubble (rendered via portal outside the SVG)
//
// We cannot use CellTooltip here because it wraps children in an HTML <span>,
// which is an invalid element inside SVG and causes the browser to skip
// rendering SVG children (<circle>, <text>).  This portal-based approach
// keeps the tooltip HTML completely outside the SVG DOM tree (fix for #506).
// ---------------------------------------------------------------------------

function NodeTooltipPortal({ tip }: { tip: TooltipState }) {
  const { node, band, screenX, screenY } = tip
  return createPortal(
    <div
      role="tooltip"
      data-testid="graph-node-tooltip"
      style={{
        position: 'fixed',
        top: screenY + 12,
        left: screenX + 12,
        zIndex: 120,
        maxWidth: 240,
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border-l)',
        borderRadius: 'var(--fw-r-md)',
        boxShadow: 'var(--fw-shadow-popup)',
        padding: '8px 10px',
        fontSize: 12,
        fontFamily: 'var(--fw-font-mono)',
        color: 'var(--fw-t1)',
        lineHeight: 1.5,
        pointerEvents: 'none',
        userSelect: 'none',
      }}
    >
      {/* SECURITY: all rendered as text nodes only — never innerHTML */}
      <div style={{ fontWeight: 600, color: 'var(--fw-t1)', marginBottom: 4 }}>
        {String(node.label)}
      </div>
      <div style={{ color: 'var(--fw-t3)', marginBottom: 2 }}>
        {String(node.type)} · {node.degree} connection{node.degree !== 1 ? 's' : ''}
      </div>
      {band && (
        <div style={{ color: 'var(--fw-t2)' }}>
          AI verdict: {String(band)}
        </div>
      )}
      {node.type === 'ip' && !band && (
        <div style={{ color: 'var(--fw-t3)' }}>
          No AI verdict yet
        </div>
      )}
      {node.type === 'ip' && (
        <div style={{ color: 'var(--fw-accent)', marginTop: 4, fontSize: 11 }}>
          Click to filter logs
        </div>
      )}
    </div>,
    document.body,
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function EntityGraph({
  nodes,
  edges,
  truncated,
  threatMap,
  onNodeClick,
  isMerge = false,
}: EntityGraphProps) {
  const titleId = useId()

  // Tooltip state: null = hidden; set on mouseenter/focus, cleared on mouseleave/blur
  const [tooltip, setTooltip] = useState<TooltipState | null>(null)
  // Track mouse position for tooltip placement
  const mousePosRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 })

  // Hovered node id for focus+context highlighting (ADR-0061 D5)
  const [hoveredId, setHoveredId] = useState<string | null>(null)

  // Legend toggle state — hidden kinds (ADR-0061 D5)
  const [hiddenKinds, setHiddenKinds] = useState<Set<string>>(new Set())

  const handleToggle = useCallback((kind: ToggleableKind) => {
    setHiddenKinds((prev) => {
      const next = new Set(prev)
      if (next.has(kind)) {
        next.delete(kind)
      } else {
        next.add(kind)
      }
      return next
    })
  }, [])

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    mousePosRef.current = { x: e.clientX, y: e.clientY }
  }, [])

  // d3-zoom state (ADR-0061 D1/D2/D3)
  // Destructured immediately so the linter can trace individual values
  // (svgRef/contentRef are RefObjects; transform/active are plain state).
  //
  // Bug #683 fix: pass `ready = nodes.length > 0` so useGraphZoom re-binds d3-zoom
  // when the SVG actually mounts (after async data arrives).  When nodes is empty
  // this component returns the empty-state div (SVG is not in the DOM), so ready=false
  // keeps zoomBehaviorRef null until the SVG is present.
  // Run force layout in world coordinate space (ADR-0061 D4).
  // #751: pass isMerge so useEntityGraph selects cold vs warm-start path.
  // NOTE: layout runs before useGraphZoom so we can pass layoutNodes for auto-fit.
  const { layoutNodes, layoutEdges, minWeight, maxWeight } = useEntityGraph(
    nodes,
    edges,
    WORLD_WIDTH,
    WORLD_HEIGHT,
    isMerge,
  )

  const {
    transform: zoomTransform,
    active: zoomActive,
    svgRef: zoomSvgRef,
    contentRef: zoomContentRef,
    zoomIn,
    zoomOut,
    zoomReset,
    handleKeyDown: handleZoomKeyDown,
    activate: activateZoom,
  // #751: suppressAutoFit = isMerge — preserve viewport on pill-driven merge;
  // keep auto-fit for first load and filter re-scope.
  } = useGraphZoom(GRAPH_WIDTH, GRAPH_HEIGHT, nodes.length > 0, layoutNodes, isMerge)

  // ---------------------------------------------------------------------------
  // Newly-exposed paths (ADR-0061 D6)
  // Set-diff the current vs previous node/edge id sets whenever props change
  // (i.e., whenever the filter re-scopes the graph via useLogsSurround).
  // Pure client-side — no backend.
  // ---------------------------------------------------------------------------
  const {
    newlyExposedNodeIds,
    newlyExposedEdgeKeys,
    newlyExposedCount,
    reducedMotion,
  } = useNewlyExposed(nodes, edges)

  // ---------------------------------------------------------------------------
  // #751 — Preserve focus/selection across merge (#751 EARS-3).
  // hoveredId and hiddenKinds are plain useState — they persist naturally across
  // re-renders (no key change, no remount on merge). We only need to clear
  // hoveredId if the focused node was removed from the graph in the merge.
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (hoveredId === null) return
    const nodeSet = new Set(nodes.map((n) => n.id))
    if (!nodeSet.has(hoveredId)) {
      // The hovered/focused node was removed — clear it to avoid a ghost state.
      setHoveredId(null) // eslint-disable-line react-hooks/set-state-in-effect
      setTooltip(null)
    }
  // Only run when nodes change (merge or filter change).
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes])

  // ---------------------------------------------------------------------------
  // Focus/context: neighbour set for hovered node (ADR-0061 D5)
  // No network fetch — pure client-side on already-fetched graph state.
  // ---------------------------------------------------------------------------
  const neighbourSet = useMemo((): Set<string> | null => {
    if (hoveredId === null) return null
    const nbrs = new Set<string>()
    nbrs.add(hoveredId)
    for (const e of layoutEdges) {
      if (e.source.id === hoveredId) nbrs.add(e.target.id)
      if (e.target.id === hoveredId) nbrs.add(e.source.id)
    }
    return nbrs
  }, [hoveredId, layoutEdges])

  // ---------------------------------------------------------------------------
  // Label LOD: which node ids show labels (ADR-0061 D4)
  // ---------------------------------------------------------------------------
  const visibleLabels = useMemo(() =>
    buildVisibleLabelSet(layoutNodes, {
      scale: zoomTransform.k,
      hoveredId,
      threatMap,
    }),
    [layoutNodes, zoomTransform.k, hoveredId, threatMap],
  )

  // Is the zoom transform non-identity?
  const isZoomed = zoomTransform.k !== 1 || zoomTransform.x !== 0 || zoomTransform.y !== 0

  // Filter nodes/edges by hidden kinds
  const visibleNodes = layoutNodes.filter((n) => !hiddenKinds.has(n.type))
  const visibleEdges = layoutEdges.filter(
    (e) => !hiddenKinds.has(e.kind) &&
      !hiddenKinds.has(e.source.type) &&
      !hiddenKinds.has(e.target.type),
  )

  // Empty state
  if (nodes.length === 0) {
    return (
      <div
        data-testid="entity-graph-empty"
        style={{
          background: 'var(--fw-bg-card)',
          border: '1px solid var(--fw-border)',
          borderRadius: 8,
          padding: '24px 16px',
          textAlign: 'center',
          fontFamily: 'var(--fw-font-ui)',
          fontSize: 'var(--fw-fs-sm)',
          color: 'var(--fw-t3)',
          marginBottom: 12,
        }}
      >
        No graph data — no destination IP relationships found yet.
      </div>
    )
  }

  return (
    <div
      data-testid="entity-graph-panel"
      style={{
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border)',
        borderRadius: 8,
        overflow: 'hidden',
        marginBottom: 12,
      }}
    >
      {/* Panel header */}
      <div
        style={{
          padding: '8px 12px',
          borderBottom: '1px solid var(--fw-border)',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          flexWrap: 'wrap',
        }}
      >
        <span
          style={{
            fontFamily: 'var(--fw-font-ui)',
            fontSize: 'var(--fw-fs-sm)',
            fontWeight: 'var(--fw-fw-semibold)',
            color: 'var(--fw-t1)',
          }}
        >
          Entity Relationship Graph
        </span>
        <span
          style={{
            fontFamily: 'var(--fw-font-mono)',
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
          }}
        >
          {nodes.length} nodes · {edges.length} edges · click IP to filter
        </span>

        {/* Honest truncation chip (ADR-0061 D5) */}
        {truncated && (
          <span
            data-testid="entity-graph-truncated-chip"
            style={{
              marginLeft: 'auto',
              background: 'var(--fw-tint-orange)',
              color: 'var(--fw-orange)',
              border: '1px solid var(--fw-tint-orange-bd)',
              borderRadius: 'var(--fw-r-md)',
              padding: '1px 8px',
              fontSize: 'var(--fw-fs-2xs)',
              fontFamily: 'var(--fw-font-mono)',
              fontWeight: 600,
              whiteSpace: 'nowrap',
            }}
            role="status"
            aria-live="polite"
          >
            showing top {nodes.length} — filter to narrow
          </span>
        )}
      </div>

      {/* Legend with toggles (ADR-0061 D5) */}
      <GraphLegendToggles hiddenKinds={hiddenKinds} onToggle={handleToggle} />

      {/* Newly-exposed paths caption (ADR-0061 D6) — glass-box, factual.
          Appears after the first filter re-scope that surfaces new entities.
          States what changed (new entities) and why (the filter) — never infers
          attacker intent.  Dismissed automatically when the filter changes again.
          SECURITY: the count is a plain integer — not attacker-controlled text. */}
      {newlyExposedCount > 0 && (
        <div
          data-testid="entity-graph-newly-exposed-caption"
          role="status"
          aria-live="polite"
          style={{
            padding: '4px 12px',
            fontSize: 'var(--fw-fs-2xs)',
            fontFamily: 'var(--fw-font-mono)',
            color: 'var(--fw-accent)',
            borderBottom: '1px solid var(--fw-border)',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          {/* Accent dot — visual indicator matching the pulse colour */}
          <span
            aria-hidden="true"
            style={{
              display: 'inline-block',
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: 'var(--fw-accent)',
              flexShrink: 0,
            }}
          />
          {/* SECURITY: newlyExposedCount is a plain integer, safe to render */}
          {newlyExposedCount} {newlyExposedCount === 1 ? 'entity' : 'entities'} newly exposed by this filter
        </div>
      )}

      {/* SVG graph canvas — relative container for absolute-positioned controls */}
      <div
        style={{
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        {/* Click-to-interact hint (ADR-0061 D2) — visible when zoom is inactive */}
        {!zoomActive && (
          <div
            data-testid="graph-click-hint"
            aria-hidden="true"
            style={{
              position: 'absolute',
              bottom: 42,
              left: '50%',
              transform: 'translateX(-50%)',
              background: 'rgba(0,0,0,0.45)',
              color: 'rgba(255,255,255,0.75)',
              borderRadius: 'var(--fw-r-md)',
              padding: '2px 10px',
              fontSize: 'var(--fw-fs-2xs)',
              fontFamily: 'var(--fw-font-ui)',
              pointerEvents: 'none',
              whiteSpace: 'nowrap',
              zIndex: 5,
            }}
          >
            Click to interact · scroll to pan page
          </div>
        )}

        <svg
          ref={zoomSvgRef}
          viewBox={`0 0 ${GRAPH_WIDTH} ${GRAPH_HEIGHT}`}
          preserveAspectRatio="xMidYMid meet"
          aria-labelledby={titleId}
          role="img"
          tabIndex={0}
          style={{
            display: 'block',
            width: '100%',
            height: 'auto',
            fontFamily: 'var(--fw-font-mono)',
            cursor: zoomActive ? 'grab' : 'default',
            outline: 'none',
          }}
          data-testid="entity-graph-svg"
          onMouseMove={handleMouseMove}
          onMouseLeave={() => {
            setTooltip(null)
            setHoveredId(null)
          }}
          onKeyDown={handleZoomKeyDown}
          onClick={activateZoom}
        >
          <title id={titleId}>
            {`Entity relationship graph: ${nodes.length} nodes, ${edges.length} edges${truncated ? ' (truncated)' : ''}`}
          </title>

          {/* CSS keyframe for newly-exposed pulse (ADR-0061 D6).
              Animation: accent glow pulsing from full opacity to zero over PULSE_DURATION_MS.
              Under prefers-reduced-motion the animation is suppressed at the caller;
              the <defs> is always present but the class is only applied when motion is ok. */}
          <defs>
            <style>{`
              @keyframes fw-newly-exposed-pulse {
                0%   { opacity: 1; }
                100% { opacity: 0; }
              }
              .fw-pulse-ring {
                animation: fw-newly-exposed-pulse ${PULSE_DURATION_MS}ms ease-out forwards;
              }
            `}</style>
          </defs>

          {/* Content group — d3-zoom transform applied here */}
          <g
            ref={zoomContentRef}
            transform={zoomTransform.toString()}
          >
            {/* Edges layer — drawn first so nodes appear above */}
            <g aria-hidden="true">
              {visibleEdges.map((e, i) => {
                const sw = edgeStrokeWidth(e.weight, minWeight, maxWeight)
                // Focus/context: dim edges not touching the hovered node (ADR-0061 D5)
                const isRelevant = neighbourSet === null ||
                  neighbourSet.has(e.source.id) ||
                  neighbourSet.has(e.target.id)
                // Newly-exposed edge highlight (ADR-0061 D6)
                const eKey = layoutEdgeKey(e.source.id, e.target.id, e.kind)
                const isNewlyExposed = newlyExposedEdgeKeys.has(eKey)
                return (
                  <g key={i} aria-hidden="true">
                    <line
                      x1={e.source.x}
                      y1={e.source.y}
                      x2={e.target.x}
                      y2={e.target.y}
                      stroke={edgeColor(e.kind)}
                      strokeWidth={sw}
                      strokeOpacity={isRelevant ? 0.7 : DIM_OPACITY}
                      strokeLinecap="round"
                      data-weight={e.weight}
                      data-kind={e.kind}
                      data-newly-exposed={isNewlyExposed || undefined}
                    />
                    {/* Newly-exposed accent line — additive, drawn on top (ADR-0061 D6) */}
                    {isNewlyExposed && (
                      <line
                        x1={e.source.x}
                        y1={e.source.y}
                        x2={e.target.x}
                        y2={e.target.y}
                        stroke="var(--fw-accent)"
                        strokeWidth={sw + 2}
                        strokeOpacity={NEWLY_EXPOSED_EDGE_STROKE_OPACITY}
                        strokeLinecap="round"
                        style={{
                          pointerEvents: 'none',
                          // Pulse animation unless reduced-motion is set
                          ...(!reducedMotion
                            ? { animation: `fw-newly-exposed-pulse ${PULSE_DURATION_MS}ms ease-out forwards` }
                            : { opacity: 0.4 }),
                        }}
                        aria-hidden="true"
                      />
                    )}
                  </g>
                )
              })}
            </g>

            {/* Nodes layer */}
            {visibleNodes.map((n) => {
              const r = nodeRadius(n.degree)
              const { fg, bg, band } = nodeColors(n.type, n.id, threatMap)
              const isIp = n.type === 'ip'
              const label = truncateLabel(n.label)
              // Focus/context: dim nodes not in the neighbour set (ADR-0061 D5)
              const isRelevant = neighbourSet === null || neighbourSet.has(n.id)
              const nodeOpacity = isRelevant ? 1 : DIM_OPACITY
              const showLabel = visibleLabels.has(n.id)
              // Newly-exposed highlight (ADR-0061 D6)
              const isNewlyExposed = newlyExposedNodeIds.has(n.id)

              return (
                <g
                  key={n.id}
                  transform={`translate(${n.x},${n.y})`}
                  tabIndex={0}
                  role={isIp ? 'button' : 'img'}
                  aria-label={
                    isIp
                      ? `IP node ${String(n.id)}${band ? `, verdict ${band}` : ''}, ${n.degree} connections — click to filter`
                      : `${n.type} node ${String(n.id)}, ${n.degree} connections`
                  }
                  style={{
                    cursor: isIp ? 'pointer' : 'default',
                    outline: 'none',
                    opacity: nodeOpacity,
                  }}
                  onClick={(ev) => {
                    if (isIp) {
                      ev.stopPropagation() // don't re-trigger SVG click-to-activate
                      onNodeClick(n.id)
                    }
                  }}
                  onKeyDown={(ev) => {
                    if (isIp && (ev.key === 'Enter' || ev.key === ' ')) {
                      ev.preventDefault()
                      onNodeClick(n.id)
                    }
                  }}
                  onMouseEnter={() => {
                    setHoveredId(n.id)
                    setTooltip({
                      node: n,
                      band,
                      screenX: mousePosRef.current.x,
                      screenY: mousePosRef.current.y,
                    })
                  }}
                  onMouseMove={() => {
                    // Keep tooltip anchor near cursor as it moves within the node
                    setTooltip((prev) =>
                      prev?.node.id === n.id
                        ? { ...prev, screenX: mousePosRef.current.x, screenY: mousePosRef.current.y }
                        : prev,
                    )
                  }}
                  onMouseLeave={() => {
                    setTooltip(null)
                    setHoveredId(null)
                  }}
                  onFocus={() => {
                    setHoveredId(n.id)
                    setTooltip({ node: n, band, screenX: 200, screenY: 200 })
                  }}
                  onBlur={() => {
                    setTooltip(null)
                    setHoveredId(null)
                  }}
                  data-testid={isIp ? `graph-node-ip` : `graph-node-other`}
                  data-node-id={n.id}
                  data-node-type={n.type}
                  data-band={band ?? undefined}
                  data-newly-exposed={isNewlyExposed || undefined}
                >
                  {/* Invisible padded hit-area — larger than visible circle (ADR-0061 D5).
                      Ensures small low-degree nodes remain clickable even when tiny. */}
                  <circle
                    r={Math.max(r + 8, 16)}
                    fill="transparent"
                    stroke="none"
                    style={{ pointerEvents: 'all' }}
                    aria-hidden="true"
                  />
                  {/* Visible circle — verdict-band tint preserved (ADR-0061 D6: pulse is additive) */}
                  <circle
                    r={r}
                    fill={bg}
                    stroke={fg}
                    strokeWidth={1.5}
                    style={{ pointerEvents: 'none' }}
                  />
                  {/* Newly-exposed accent ring/glow (ADR-0061 D6).
                      Additive outline — sits outside the visible circle; verdict-band fill
                      and stroke are untouched.  Under prefers-reduced-motion, a static ring
                      at reduced opacity replaces the pulse animation.
                      SECURITY: pure SVG attrs — no attacker-controlled values here. */}
                  {isNewlyExposed && (
                    <circle
                      r={r + NEWLY_EXPOSED_RING_OFFSET}
                      fill="none"
                      stroke="var(--fw-accent)"
                      strokeWidth={2}
                      aria-hidden="true"
                      data-testid="newly-exposed-ring"
                      style={{
                        pointerEvents: 'none',
                        ...(!reducedMotion
                          ? {
                              animation: `fw-newly-exposed-pulse ${PULSE_DURATION_MS}ms ease-out forwards`,
                            }
                          : {
                              // Static accent ring — no animation (prefers-reduced-motion)
                              opacity: 0.6,
                            }),
                      }}
                    />
                  )}
                  {/* Label — text node only (ADR-0029 D3); hidden when not in LOD budget */}
                  {showLabel && (
                    <text
                      y={r + 13}
                      textAnchor="middle"
                      fontSize={10}
                      fill={fg}
                      aria-hidden="true"
                      style={{ userSelect: 'none', pointerEvents: 'none' }}
                    >
                      {/* SECURITY: text node only — never innerHTML */}
                      {label}
                    </text>
                  )}
                </g>
              )
            })}
          </g>
        </svg>

        {/* Zoom/pan controls (ADR-0061 D3) */}
        <GraphControls
          onZoomIn={zoomIn}
          onZoomOut={zoomOut}
          onReset={zoomReset}
          isZoomed={isZoomed}
        />
      </div>

      {/* Tooltip portal — rendered outside the SVG so it is valid HTML (fix #506) */}
      {tooltip && <NodeTooltipPortal tip={tooltip} />}
    </div>
  )
}
