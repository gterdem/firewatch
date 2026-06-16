/**
 * Sparkline — UTC-bucketed inline trend chart (DS core, issue #245).
 *
 * A small, presentational SVG sparkline for time-bucketed numeric series.
 * Domain-agnostic: consumed by Risk Movers (P8), KPI strip (P10), and
 * spike-annotation context (P7). This component never fetches data.
 *
 * Design constraints:
 *   - Fixed small footprint (fits a KPI tile or a table row cell).
 *   - No inner scrollbar — ADR-0017 bounded-panes convention.
 *   - Colors use var(--fw-*) tokens only — no raw hex.
 *   - No stroke-icon library.
 *   - Optional hover detail MUST go through CellTooltip (sibling, #246) —
 *     the consumer wires it; this component just exposes the data.
 *
 * Accessibility:
 *   - role="img" + aria-label summarizing direction, never color-only.
 *   - Degenerate input (<2 points, empty) → quiet placeholder, no crash.
 *
 * Usage:
 *   import { Sparkline } from '@/components/ds'
 *
 *   <Sparkline series={buckets} label="Requests" width={80} height={24} />
 */

import type { CSSProperties } from 'react'
import type { SeriesPoint } from '../../../lib/series'
import {
  buildDenseSeries,
  minMaxNormalize,
  trendAriaLabel,
  trendDirection,
} from '../../../lib/series'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SparklineProps {
  /**
   * UTC-bucketed series. Each point is `{ t: string (ISO bucket key), value: number }`.
   * Tz-naive keys are interpreted as UTC per lib/time.ts.
   */
  series: SeriesPoint[]
  /**
   * Short human label for the series, used in the aria-label (e.g. "Requests").
   * Omit for anonymous sparklines embedded inside already-labelled containers.
   */
  label?: string
  /** SVG width in px (default 80). */
  width?: number
  /** SVG height in px (default 24). */
  height?: number
  /**
   * Optional CSS class forwarded to the outer <span> wrapper.
   * Use for sizing overrides at the call site.
   */
  className?: string
  /** Optional inline style forwarded to the outer <span> wrapper. */
  style?: CSSProperties
  /**
   * If true, render a filled area under the polyline in addition to the line.
   * Default: false (line-only is less visually heavy in dense tables).
   */
  filled?: boolean
  /**
   * Stroke color token (CSS var expression). Default: var(--fw-accent).
   * Consumers may pass var(--fw-blue), var(--fw-green), etc. to match
   * the surrounding hue context.
   */
  color?: string
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

const DEFAULT_WIDTH = 80
const DEFAULT_HEIGHT = 24
const DEFAULT_COLOR = 'var(--fw-accent)'

/** Vertical padding inside the SVG to give strokes room to breathe. */
const PAD_Y = 2
/** Horizontal padding to prevent clipping the first/last point's stroke. */
const PAD_X = 1

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Map a normalized [0..1] value to an SVG y coordinate.
 * SVG y-axis is inverted: 0 → bottom, 1 → top.
 */
function toY(norm: number, height: number): number {
  const drawH = height - PAD_Y * 2
  return PAD_Y + drawH * (1 - norm)
}

/**
 * Map an index [0..n-1] to an SVG x coordinate across the full width.
 */
function toX(index: number, total: number, width: number): number {
  if (total <= 1) return width / 2
  const drawW = width - PAD_X * 2
  return PAD_X + (index / (total - 1)) * drawW
}

/**
 * Build an SVG points attribute string from normalized points.
 */
function toPolylinePoints(
  normalized: ReturnType<typeof minMaxNormalize>,
  width: number,
  height: number,
): string {
  return normalized
    .map((p, i) => `${toX(i, normalized.length, width).toFixed(2)},${toY(p.norm, height).toFixed(2)}`)
    .join(' ')
}

/**
 * Build an SVG path `d` attribute for the filled area.
 * Closes the path at the bottom of the SVG.
 */
function toAreaPath(
  normalized: ReturnType<typeof minMaxNormalize>,
  width: number,
  height: number,
): string {
  if (normalized.length === 0) return ''

  const pts = normalized.map((p, i) => ({
    x: toX(i, normalized.length, width),
    y: toY(p.norm, height),
  }))

  const linePoints = pts.map((p) => `${p.x.toFixed(2)},${p.y.toFixed(2)}`).join(' L ')
  const firstX = pts[0].x.toFixed(2)
  const lastX = pts[pts.length - 1].x.toFixed(2)
  const bottom = (height - PAD_Y).toFixed(2)

  return `M ${firstX},${bottom} L ${linePoints} L ${lastX},${bottom} Z`
}

// ---------------------------------------------------------------------------
// Placeholder — renders when the series has < 2 valid points
// ---------------------------------------------------------------------------

function SparklinePlaceholder({
  width,
  height,
  ariaLabel,
  className,
  style,
}: {
  width: number
  height: number
  ariaLabel: string
  className?: string
  style?: CSSProperties
}) {
  return (
    <span
      role="img"
      aria-label={ariaLabel}
      className={className}
      style={{
        display: 'inline-block',
        width,
        height,
        overflow: 'hidden',
        flexShrink: 0,
        ...style,
      }}
    >
      <svg
        width={width}
        height={height}
        aria-hidden="true"
        style={{ display: 'block' }}
      >
        {/* Faint dash to indicate "no meaningful trend" */}
        <line
          x1={PAD_X}
          y1={height / 2}
          x2={width - PAD_X}
          y2={height / 2}
          stroke="var(--fw-border-l)"
          strokeWidth={1}
          strokeDasharray="3 3"
        />
      </svg>
    </span>
  )
}

// ---------------------------------------------------------------------------
// Sparkline component
// ---------------------------------------------------------------------------

export function Sparkline({
  series,
  label,
  width = DEFAULT_WIDTH,
  height = DEFAULT_HEIGHT,
  className,
  style,
  filled = false,
  color = DEFAULT_COLOR,
}: SparklineProps) {
  // Build dense (gap-filled), sorted series
  const dense = buildDenseSeries(series)
  const ariaLabel = trendAriaLabel(dense, label)

  // Degenerate: fewer than 2 points → quiet placeholder
  if (dense.length < 2) {
    return (
      <SparklinePlaceholder
        width={width}
        height={height}
        ariaLabel={ariaLabel}
        className={className}
        style={style}
      />
    )
  }

  const normalized = minMaxNormalize(dense)
  const pointsStr = toPolylinePoints(normalized, width, height)
  const allZero = normalized.every((p) => p.value === 0)

  // Signed-delta arrow for quick at-a-glance direction (supplementary to aria-label)
  // Direction is never conveyed by color alone: arrow glyph + text provide the channel.
  const dir = trendDirection(dense)
  const deltaArrow = dir === 'rising' ? '▲' : dir === 'falling' ? '▼' : '—'

  // Area fill uses 15% opacity for a subtle fill without overwhelming the line.
  const areaOpacity = 0.15

  return (
    <span
      role="img"
      aria-label={ariaLabel}
      className={className}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        overflow: 'hidden',
        flexShrink: 0,
        ...style,
      }}
    >
      <svg
        width={width}
        height={height}
        aria-hidden="true"
        style={{ display: 'block', overflow: 'hidden' }}
      >
        {/* Area fill (optional) */}
        {filled && !allZero && (
          <path
            d={toAreaPath(normalized, width, height)}
            fill={color}
            fillOpacity={areaOpacity}
            stroke="none"
          />
        )}

        {/* All-zero flat line uses muted color to indicate absence of events */}
        <polyline
          points={pointsStr}
          fill="none"
          stroke={allZero ? 'var(--fw-t3)' : color}
          strokeWidth={1.5}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>

      {/* Signed-delta arrow — supplementary direction signal (text, not color) */}
      <span
        aria-hidden="true"
        style={{
          fontSize: 'var(--fw-fs-2xs)',
          color: allZero
            ? 'var(--fw-t3)'
            : dir === 'rising'
              ? 'var(--fw-green)'
              : dir === 'falling'
                ? 'var(--fw-red)'
                : 'var(--fw-t3)',
          fontFamily: 'var(--fw-font-mono)',
          lineHeight: 1,
          userSelect: 'none',
        }}
      >
        {deltaArrow}
      </span>
    </span>
  )
}
