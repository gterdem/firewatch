/**
 * GraphControls — bottom-right zoom/pan control cluster for the Entity Relationship Graph.
 *
 * Implements ADR-0061 D3: real `<button>` elements with aria-labels.
 * Every navigation affordance is reachable without the wheel and without a mouse.
 *
 * Controls:
 *   [+]  — zoom in
 *   [−]  — zoom out
 *   [⤢]  — fit/reset to identity transform
 *
 * ACCESSIBILITY: all buttons have aria-labels; the cluster is positioned
 * absolute inside the graph container so it does not disturb document flow.
 *
 * No attacker-controlled values are rendered here.
 */

import React from 'react'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GraphControlsProps {
  onZoomIn: () => void
  onZoomOut: () => void
  onReset: () => void
  /** Whether the graph is currently zoomed (affects reset button appearance). */
  isZoomed: boolean
}

// ---------------------------------------------------------------------------
// Styles (inline — consistent with EntityGraph's style-prop approach)
// ---------------------------------------------------------------------------

const BUTTON_BASE_STYLE: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  width: 28,
  height: 28,
  padding: 0,
  background: 'var(--fw-bg-card)',
  border: '1px solid var(--fw-border)',
  borderRadius: 'var(--fw-r-sm)',
  color: 'var(--fw-t2)',
  cursor: 'pointer',
  fontSize: 14,
  lineHeight: 1,
  fontFamily: 'var(--fw-font-ui)',
  userSelect: 'none',
  outline: 'none',
  transition: 'background 0.1s, color 0.1s',
}

const CLUSTER_STYLE: React.CSSProperties = {
  position: 'absolute',
  bottom: 10,
  right: 10,
  display: 'flex',
  flexDirection: 'column',
  gap: 4,
  zIndex: 10,
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function GraphControls({
  onZoomIn,
  onZoomOut,
  onReset,
  isZoomed,
}: GraphControlsProps) {
  return (
    <div
      style={CLUSTER_STYLE}
      aria-label="Graph navigation controls"
      role="group"
      data-testid="graph-controls"
    >
      <button
        type="button"
        style={BUTTON_BASE_STYLE}
        onClick={onZoomIn}
        aria-label="Zoom in"
        data-testid="graph-zoom-in"
        title="Zoom in (+)"
      >
        +
      </button>
      <button
        type="button"
        style={BUTTON_BASE_STYLE}
        onClick={onZoomOut}
        aria-label="Zoom out"
        data-testid="graph-zoom-out"
        title="Zoom out (−)"
      >
        −
      </button>
      <button
        type="button"
        style={{
          ...BUTTON_BASE_STYLE,
          color: isZoomed ? 'var(--fw-accent)' : 'var(--fw-t3)',
          fontSize: 13,
        }}
        onClick={onReset}
        aria-label="Reset zoom to fit"
        data-testid="graph-zoom-reset"
        title="Reset zoom (0)"
      >
        ⤢
      </button>
    </div>
  )
}
