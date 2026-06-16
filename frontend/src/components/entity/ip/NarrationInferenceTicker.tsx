/**
 * NarrationInferenceTicker — collapsed/expanded "watch it think" view for the
 * NarrationPanel loading state (CR3, issue #614).
 *
 * Default collapsed: one line showing `On-device inference · zero-egress [●] 2.4s`.
 * Expanded: the 6 real ADR-0046 stage facts with per-stage elapsed time —
 * proof of locality that no competitor surfaces.
 *
 * Design constraints:
 * - NO model-authored text rendered here (ADR-0029 D3 / ADR-0046 D3).
 *   All strings come from formatStageLabel() — closed enum + numeric facts.
 * - aria-live="polite" status region announces stage transitions (ADR-0046 §8).
 * - prefers-reduced-motion: animations disabled (ADR-0046 §8).
 * - Bounded height — no inner scrollbar (ADR-0046 §8).
 * - Honest degradation: caller passes `aiMode=false` → "Building rule summary…"
 *   is shown instead; stages are NEVER rendered (ADR-0035).
 *
 * Elapsed-time sourcing:
 * - Collapsed line: uses `generatingElapsedMs` (live heartbeat) when streaming,
 *   or the final `received` stage's `latency_ms` when done.
 * - Stage-level elapsed: derived from each stage fact's own fields:
 *   received → latency_ms, generating → elapsed_ms.
 *   Other stages have no inherent elapsed (they are near-instant events).
 */

import { useState, useEffect, useRef } from 'react'
import type { StageFact } from './ticker/stages'
import { formatStageLabel } from './ticker/stages'

// ---------------------------------------------------------------------------
// Detect reduced-motion preference
// ---------------------------------------------------------------------------

function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined') return false
  if (typeof window.matchMedia !== 'function') return false
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

// ---------------------------------------------------------------------------
// Helpers — per-stage elapsed extraction
// ---------------------------------------------------------------------------

/**
 * Extract a human-readable elapsed annotation from a stage fact, if applicable.
 * Only stages that carry timing data produce a non-null value.
 * SECURITY: values are numbers from the wire — never model-authored strings.
 */
function stageElapsed(fact: StageFact): string | null {
  if (fact.stage === 'received') {
    const sec = (fact.latency_ms / 1000).toFixed(1)
    return `${sec}s`
  }
  if (fact.stage === 'generating') {
    const sec = (fact.elapsed_ms / 1000).toFixed(1)
    return `${sec}s`
  }
  return null
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface NarrationInferenceTickerProps {
  /**
   * Accumulated stage facts from the ADR-0046 stream (excl. generating heartbeats
   * which are passed separately via `generatingElapsedMs`).
   */
  stages: StageFact[]
  /**
   * Live generating heartbeat elapsed_ms. Null when not generating.
   * Drives the collapsed-line live counter: `[●] 2.4s`.
   */
  generatingElapsedMs: number | null
  /** Whether the stream is still open (controls the pulsing indicator). */
  streaming: boolean
  /** Whether the pipeline completed successfully (enters static/done mode). */
  done: boolean
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/** One expanded stage line. */
function ExpandedStageLine({
  fact,
  isLive,
  reduceMotion,
}: {
  fact: StageFact
  isLive: boolean
  reduceMotion: boolean
}) {
  const elapsed = stageElapsed(fact)
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'baseline',
        fontSize: 11,
        fontFamily: 'var(--fw-font-mono)',
        color: isLive ? 'var(--fw-accent)' : 'var(--fw-t2)',
        lineHeight: 1.7,
        animation: !reduceMotion && isLive ? 'fw-narr-ticker-enter 0.18s ease-out' : undefined,
      }}
    >
      <span>
        {'→ '}
        {/* ADR-0029 D3: text node only — formatStageLabel returns a plain string */}
        {formatStageLabel(fact)}
      </span>
      {/* Per-stage elapsed — proof of locality (ADR-0047) */}
      {elapsed && (
        <span
          style={{
            fontSize: 10,
            color: 'var(--fw-t3)',
            marginLeft: 8,
            fontVariantNumeric: 'tabular-nums',
          }}
          aria-label={`${elapsed} elapsed`}
        >
          {elapsed}
        </span>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function NarrationInferenceTicker({
  stages,
  generatingElapsedMs,
  streaming,
  done,
}: NarrationInferenceTickerProps) {
  const reduceMotion = prefersReducedMotion()
  const [expanded, setExpanded] = useState(false)

  // Live region for screen-reader announcements (ADR-0046 §8).
  const liveRegionRef = useRef<HTMLDivElement>(null)
  const lastAnnouncedRef = useRef<string>('')

  // Announce the last terminal stage (not heartbeats — noise).
  const displayedStages = stages.filter((s) => s.stage !== 'generating')
  const lastStage = displayedStages[displayedStages.length - 1] ?? null
  const lastLabel = lastStage ? formatStageLabel(lastStage) : null

  useEffect(() => {
    if (!lastLabel || lastLabel === lastAnnouncedRef.current) return
    lastAnnouncedRef.current = lastLabel
    if (liveRegionRef.current) {
      liveRegionRef.current.textContent = lastLabel
    }
  }, [lastLabel])

  // Compute elapsed display for the collapsed line.
  // Priority: live generating heartbeat → final received latency → null.
  const receivedFact = stages.find((s) => s.stage === 'received') as
    | { stage: 'received'; latency_ms: number }
    | undefined
  const elapsedSec: string | null = (() => {
    if (generatingElapsedMs !== null && streaming) {
      return (generatingElapsedMs / 1000).toFixed(1) + 's'
    }
    if (receivedFact) {
      return (receivedFact.latency_ms / 1000).toFixed(1) + 's'
    }
    return null
  })()

  // Pulsing indicator: ● when streaming, ○ when done.
  const indicator = streaming ? '●' : '○'
  const indicatorColor = streaming ? 'var(--fw-accent)' : 'var(--fw-t3)'

  return (
    <div
      data-testid="narration-inference-ticker"
      data-done={done ? 'true' : undefined}
      style={{
        marginTop: 4,
        // Bounded height — no inner scrollbar (ADR-0046 §8).
        maxHeight: expanded ? 200 : 'none',
        overflowY: 'hidden',
      }}
    >
      {/* Hidden live region — announces stage transitions to screen readers. */}
      <div
        ref={liveRegionRef}
        role="status"
        aria-live="polite"
        aria-atomic="true"
        style={{
          position: 'absolute',
          width: 1,
          height: 1,
          overflow: 'hidden',
          clip: 'rect(0,0,0,0)',
          whiteSpace: 'nowrap',
        }}
      />

      {/* Collapsed / header row */}
      <button
        type="button"
        data-testid="narration-ticker-toggle"
        aria-expanded={expanded}
        aria-label={expanded ? 'Collapse inference stages' : 'Expand inference stages'}
        onClick={() => setExpanded((v) => !v)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          background: 'none',
          border: 'none',
          padding: 0,
          cursor: 'pointer',
          width: '100%',
          textAlign: 'left',
        }}
      >
        {/* Pulsing indicator */}
        <span
          aria-hidden="true"
          data-testid="narration-ticker-indicator"
          style={{
            fontSize: 10,
            color: indicatorColor,
            animation:
              !reduceMotion && streaming ? 'fw-narr-pulse 1s ease-in-out infinite' : undefined,
          }}
        >
          {indicator}
        </span>

        {/* Primary label */}
        <span
          data-testid="narration-ticker-label"
          style={{
            fontSize: 11,
            fontFamily: 'var(--fw-font-mono)',
            color: 'var(--fw-t2)',
            userSelect: 'none',
          }}
        >
          On-device inference&nbsp;·&nbsp;zero-egress
          {elapsedSec && (
            <span
              data-testid="narration-ticker-elapsed"
              style={{
                marginLeft: 6,
                color: 'var(--fw-t3)',
                fontVariantNumeric: 'tabular-nums',
              }}
              aria-label={`${elapsedSec} elapsed`}
            >
              {elapsedSec}
            </span>
          )}
        </span>

        {/* Expand/collapse chevron */}
        {displayedStages.length > 0 && (
          <span
            aria-hidden="true"
            style={{
              fontSize: 9,
              color: 'var(--fw-t3)',
              marginLeft: 'auto',
              transform: expanded ? 'rotate(180deg)' : undefined,
              transition: !reduceMotion ? 'transform 0.15s ease' : undefined,
            }}
          >
            ▾
          </span>
        )}
      </button>

      {/* Expanded: 6 real stages with per-stage elapsed (proof of locality) */}
      {expanded && displayedStages.length > 0 && (
        <div
          data-testid="narration-ticker-stages"
          style={{
            marginTop: 6,
            paddingLeft: 16,
            borderLeft: '2px solid var(--fw-border-l)',
            display: 'flex',
            flexDirection: 'column',
            gap: 0,
          }}
        >
          {displayedStages.map((fact, i) => (
            <ExpandedStageLine
              key={i}
              fact={fact}
              isLive={!done && i === displayedStages.length - 1}
              reduceMotion={reduceMotion || done}
            />
          ))}

          {/* Live generating counter — aria-hidden (not announced) */}
          {!done && streaming && generatingElapsedMs !== null && (
            <div
              aria-hidden="true"
              data-testid="narration-ticker-generating"
              style={{
                fontSize: 11,
                fontFamily: 'var(--fw-font-mono)',
                color: 'var(--fw-accent)',
                lineHeight: 1.7,
                display: 'flex',
                justifyContent: 'space-between',
              }}
            >
              <span>{'→ '}generating…</span>
              <span
                style={{
                  fontSize: 10,
                  color: 'var(--fw-t3)',
                  fontVariantNumeric: 'tabular-nums',
                }}
              >
                {(generatingElapsedMs / 1000).toFixed(1)}s
              </span>
            </div>
          )}
        </div>
      )}

      {/* Keyframes — injected once, no CSS module dependency */}
      {!reduceMotion && (
        <style>{`
          @keyframes fw-narr-pulse {
            0%, 100% { opacity: 1; }
            50%       { opacity: 0.3; }
          }
          @keyframes fw-narr-ticker-enter {
            from { opacity: 0; transform: translateY(3px); }
            to   { opacity: 1; transform: translateY(0); }
          }
        `}</style>
      )}
    </div>
  )
}
