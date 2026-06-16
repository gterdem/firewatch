/**
 * TimelineChart — severity-stacked bars + disposition toggle + rich hover + spike
 * annotation (issues #247, #248).
 *
 * Data comes from GET /logs/timeline (ADR-0029 D1). Presentational only.
 *
 * Rendering modes:
 *   "severity"    — four stacked segments (critical/high/medium/low).  Default.
 *   "disposition" — two segments (blocked/allowed).  Free: derived from existing
 *                   total/blocked; no refetch required.
 *
 * Toggle: local state (no prop, no context — the mode decision lives here).
 *
 * Hover: each bar row is wrapped in CellTooltip (#246, WCAG 1.4.13) with
 *   TimelineBucketHover as the content (count, top category, top IP, severity mix).
 *
 * Spike annotation (issue #248):
 *   detectSpikes() (lib/spikes.ts) runs client-side over the bucket totals series
 *   using rolling median + k·MAD.  Flagged buckets get a TimelineSpikeMarker glyph
 *   in the count column.  Detection is purely statistical — no LLM calls.
 *   ADR-0035: no AI-attributed wording in the marker until #213 wires in.
 *
 * Time labels: via parseApiTimestamp + formatLocal/formatUtc from lib/time.ts (#244)
 *   so that tz-naive keys ("2026-06-11T04:00", no offset) are treated as UTC.
 *
 * Layout: kit `.tl-row` pattern — 64px label | flex:1 bar track | 110px count.
 *
 * SOC design-token classes (ADR-0028 D6 / issue #96):
 *   severity palette  → soc-{critical,high,medium,low}-fg (bg-* for bars)
 *   disposition       → soc-enforced-fg (blocked), soc-ok-fg (allowed)
 *
 * Backward-compat note:
 *   The old TimelineLegend export had no props.  The new signature adds an
 *   optional `mode` prop.  Existing callers that pass no props continue to work
 *   (mode defaults to 'severity', which shows Critical/High/Medium/Low swatches).
 *   TimelineChartLegend.test.tsx was testing for 'Blocked'/'Allowed' + specific
 *   swatch classes — those tests are updated alongside this file (issue #247).
 *
 * SECURITY (ADR-0029 D3):
 *   top_source_ip and top_category are attacker-controlled.  They are passed
 *   into TimelineBucketHover which renders them as text nodes only.
 *
 * No canvas/charting library — CSS-only bars (same approach as kit oracle).
 */

import { useMemo, useState } from 'react'
import type { TimelineBucket } from '../../api/types'
import { parseApiTimestamp, formatLocal, formatUtc } from '../../lib/time'
import {
  buildSeverityRows,
  buildDispositionRows,
  SEVERITY_LEGEND,
  DISPOSITION_LEGEND,
} from '../../lib/timelineSeries'
import { detectSpikes } from '../../lib/spikes'
import { CellTooltip } from '../ds'
import { TimelineBucketHover } from './TimelineBucketHover'
import { TimelineSpikeMarker } from './TimelineSpikeMarker'
import TimeText from './TimeText'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type TimelineMode = 'severity' | 'disposition'

interface TimelineChartProps {
  buckets: TimelineBucket[]
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Format a timeline bucket label via the lib/time.ts seam.
 * Tz-naive strings are treated as UTC (fixes the off-by-offset bug, #244).
 */
function formatBucketLabel(hour: string, granularity?: string): { local: string; utc: string; date: Date } {
  const d = parseApiTimestamp(hour)
  if (isNaN(d.getTime())) return { local: hour, utc: '', date: d }
  const style = granularity === 'daily' ? 'date' : 'time'
  return { local: formatLocal(d, style), utc: formatUtc(d), date: d }
}

// ---------------------------------------------------------------------------
// Legend — exported for optional use in Panel `actions` slot
// ---------------------------------------------------------------------------

/**
 * TimelineLegend — swatches adapt to the current rendering mode.
 *
 * The `mode` prop is optional for backward-compatibility with callers that
 * imported the component before issue #247 (e.g. DashboardRoute).  When
 * absent it defaults to 'severity'.
 *
 * TimelineChartLegend.test.tsx assertions:
 *   - In disposition mode: swatch testids "timeline-legend-blocked-swatch" and
 *     "timeline-legend-allowed-swatch" with classes bg-soc-enforced-fg /
 *     bg-soc-ok-fg remain valid (backward-compat path).
 *   - In severity mode: testids are "timeline-legend-critical-swatch" etc.
 */
export function TimelineLegend({ mode }: { mode?: TimelineMode }) {
  const items = mode === 'disposition' ? DISPOSITION_LEGEND : SEVERITY_LEGEND

  return (
    <div
      style={{ display: 'flex', gap: 12, fontSize: 11, alignItems: 'center', flexWrap: 'wrap' }}
      data-testid="timeline-legend"
    >
      {items.map((item) => (
        <span
          key={item.key}
          style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--fw-t2)' }}
        >
          <span
            aria-hidden="true"
            data-testid={`timeline-legend-${item.key}-swatch`}
            className={`inline-block rounded-sm shrink-0 ${item.colorClass}`}
            style={{ width: 10, height: 10, borderRadius: 2 }}
          />
          {item.label}
        </span>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function TimelineChart({ buckets }: TimelineChartProps) {
  const [mode, setMode] = useState<TimelineMode>('severity')

  // Spike detection — runs over the bucket totals series (issue #248).
  // Pure + deterministic; safe to compute on every render without memoisation,
  // but useMemo avoids re-running when only the mode toggle changes.
  const spikesIndex = useMemo(() => {
    const series = buckets.map((b) => b.total)
    const marks = detectSpikes(series)
    // Index by bucketIndex for O(1) lookup per row.
    return new Map(marks.map((m) => [m.bucketIndex, m]))
  }, [buckets])

  if (buckets.length === 0) {
    return (
      <p
        className="text-sm text-muted-foreground text-center py-4"
        data-testid="timeline-empty"
      >
        No data in selected range
      </p>
    )
  }

  const rows = mode === 'severity'
    ? buildSeverityRows(buckets)
    : buildDispositionRows(buckets)

  return (
    <div data-testid="timeline-chart">
      {/* Mode toggle */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 6 }}>
        <div
          role="group"
          aria-label="Timeline view mode"
          style={{
            display: 'flex',
            gap: 0,
            borderRadius: 5,
            overflow: 'hidden',
            border: '1px solid var(--fw-border-l)',
          }}
        >
          <button
            type="button"
            data-testid="timeline-toggle-severity"
            onClick={() => setMode('severity')}
            aria-pressed={mode === 'severity'}
            style={{
              padding: '3px 10px',
              fontSize: 11,
              fontFamily: 'var(--fw-font-ui)',
              background: mode === 'severity' ? 'var(--fw-bg-hover)' : 'transparent',
              color: mode === 'severity' ? 'var(--fw-t1)' : 'var(--fw-t3)',
              border: 'none',
              cursor: 'pointer',
              borderRight: '1px solid var(--fw-border-l)',
              fontWeight: mode === 'severity' ? 600 : 400,
            }}
          >
            Severity
          </button>
          <button
            type="button"
            data-testid="timeline-toggle-disposition"
            onClick={() => setMode('disposition')}
            aria-pressed={mode === 'disposition'}
            style={{
              padding: '3px 10px',
              fontSize: 11,
              fontFamily: 'var(--fw-font-ui)',
              background: mode === 'disposition' ? 'var(--fw-bg-hover)' : 'transparent',
              color: mode === 'disposition' ? 'var(--fw-t1)' : 'var(--fw-t3)',
              border: 'none',
              cursor: 'pointer',
              fontWeight: mode === 'disposition' ? 600 : 400,
            }}
          >
            Disposition
          </button>
        </div>
      </div>

      {/* Bar rows */}
      {rows.map((row, idx) => {
        const { date: bucketDate } = formatBucketLabel(row.hour, row.granularity)
        const style = row.granularity === 'daily' ? 'date' : 'time'

        return (
          <div
            key={idx}
            data-testid="timeline-row"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '3px 0',
            }}
          >
            {/* .tl-hr — time label via seam (UTC-safe, issue #244) */}
            <div
              style={{
                width: 64,
                fontFamily: 'var(--fw-font-mono)',
                fontSize: 10,
                color: 'var(--fw-t3)',
                flexShrink: 0,
              }}
            >
              <TimeText
                date={bucketDate}
                style={style}
                data-testid="timeline-bucket-label"
              />
            </div>

            {/* .tl-bar-w — stacked flex track, wrapped in CellTooltip for rich hover.
                triggerStyle makes the trigger span grow as a flex child (issue #355, P3a):
                CellTooltip defaults to display:inline + no flex-grow → collapses to 0px.
                flex:1 + minWidth:0 gives the span the same growth behaviour as the bar
                track div it previously had, so segment widths are percentages of a
                non-zero width. */}
            <CellTooltip
              data-testid={`timeline-bar-trigger-${idx}`}
              content={<TimelineBucketHover data={row.hover} />}
              triggerStyle={{ flex: 1, minWidth: 0 }}
            >
              <div
                style={{
                  flex: 1,
                  height: 16,
                  background: 'var(--fw-bg-input)',
                  borderRadius: 3,
                  overflow: 'hidden',
                  display: 'flex',
                }}
                data-testid="timeline-bar-track"
              >
                {!row.isEmpty &&
                  row.segments.map((seg) => {
                    if (seg.count === 0) return null
                    return (
                      <div
                        key={seg.key}
                        data-testid={`timeline-segment-${seg.key}`}
                        className={seg.colorClass}
                        style={{
                          width: `${seg.pct}%`,
                          height: '100%',
                        }}
                      />
                    )
                  })}
              </div>
            </CellTooltip>

            {/* .tl-cnt — count display + optional spike marker (issue #248) */}
            <div
              style={{
                width: 110,
                textAlign: 'right',
                fontFamily: 'var(--fw-font-mono)',
                fontSize: 10,
                color: 'var(--fw-t2)',
                flexShrink: 0,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'flex-end',
                gap: 4,
              }}
            >
              {/* Spike marker — appears inline before the count when flagged */}
              {spikesIndex.has(idx) && (
                <TimelineSpikeMarker
                  mark={spikesIndex.get(idx)!}
                />
              )}
              {mode === 'disposition' ? (
                <>
                  <span
                    data-testid="timeline-blocked-bar"
                    className="text-soc-enforced-fg"
                  >
                    {row.hover.blocked.toLocaleString()}
                  </span>
                  {' / '}
                  <span
                    data-testid="timeline-allowed-bar"
                    className="text-soc-ok-fg"
                  >
                    {row.hover.allowed.toLocaleString()}
                  </span>
                </>
              ) : (
                <span style={{ color: 'var(--fw-t2)' }}>{row.total.toLocaleString()}</span>
              )}
            </div>
          </div>
        )
      })}

      {/* Inline legend — adapts to current mode */}
      <TimelineLegend mode={mode} />
    </div>
  )
}
