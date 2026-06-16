/**
 * StageTicker — renders live pipeline stage facts as they arrive.
 *
 * ADR-0046 §8 accessibility requirements:
 *   - aria-live="polite" announces stage transitions (not heartbeats).
 *   - prefers-reduced-motion: animations disabled when the user prefers it.
 *   - Bounded-height block (no inner scrollbar).
 *
 * SECURITY (ADR-0029 D3 / ADR-0046 D3):
 *   - NO model-authored text is rendered here.
 *   - All strings come from formatStageLabel() — closed enum + numeric facts.
 *   - The terminal result is NOT rendered here; it goes through the existing
 *     RichDetailSection / analysis rendering path in IpPanel.
 */

import { useEffect, useRef } from 'react'
import type { StageFact } from './stages'
import { formatStageLabel } from './stages'

// ---------------------------------------------------------------------------
// Detect reduced-motion preference
// ---------------------------------------------------------------------------

function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined') return false
  if (typeof window.matchMedia !== 'function') return false
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export interface StageTickerProps {
  /**
   * The accumulated stage facts to display (heartbeats are NOT passed here —
   * the parent filters out 'generating' facts from the displayed list and
   * passes them separately via generatingElapsedMs).
   */
  stages: StageFact[]
  /**
   * Current generating heartbeat elapsed_ms. When non-null and streaming is
   * true, a "generating… (Ns)" line is shown at the bottom of the list.
   * Updated on each heartbeat but NOT announced to the live region (noise).
   */
  generatingElapsedMs: number | null
  /** Whether the stream is still open. Controls showing the generating line. */
  streaming: boolean
  /** Whether the `failed` stage was received (determines honest messaging). */
  hasFailed?: boolean
  /**
   * When true, the ticker renders in static/done mode: no live generating
   * counter, no enter animations, all terminal ✓ marks visible.
   * Use after the stream closes to show the completed pipeline summary.
   * Respects prefers-reduced-motion (animations are already off in that case).
   */
  done?: boolean
}

/** A single stage line with optional enter animation. */
function StageLine({
  label,
  isLive = false,
  reduceMotion = false,
}: {
  label: string
  isLive?: boolean
  reduceMotion?: boolean
}) {
  return (
    <div
      style={{
        fontSize: 11,
        fontFamily: 'var(--fw-font-mono)',
        color: isLive ? 'var(--fw-accent)' : 'var(--fw-t2)',
        lineHeight: 1.6,
        animation: !reduceMotion && isLive ? 'fw-ticker-enter 0.2s ease-out' : undefined,
        willChange: 'opacity, transform',
      }}
    >
      {/* ADR-0029 D3: text node only — formatStageLabel returns a plain string */}
      {'→ '}
      {label}
    </div>
  )
}

export default function StageTicker({
  stages,
  generatingElapsedMs,
  streaming,
  hasFailed = false,
  done = false,
}: StageTickerProps) {
  const reduceMotion = prefersReducedMotion()
  const liveRegionRef = useRef<HTMLDivElement>(null)

  // Live region: on each new TERMINAL stage (not heartbeat) update the
  // aria-live region text so screen readers announce it once.
  // We exclude 'generating' here — heartbeats are high-frequency noise.
  const lastAnnouncedRef = useRef<string>('')
  const lastStage = stages[stages.length - 1] ?? null
  const lastLabel = lastStage ? formatStageLabel(lastStage) : null

  useEffect(() => {
    if (!lastLabel || lastLabel === lastAnnouncedRef.current) return
    lastAnnouncedRef.current = lastLabel
    // The live region's text content drives the announcement.
    // Setting it here (outside render) avoids spurious re-renders.
    if (liveRegionRef.current) {
      liveRegionRef.current.textContent = lastLabel
    }
  }, [lastLabel])

  // The list of stages shown (all except raw generating heartbeats —
  // those are shown separately as the live counter line).
  const displayedStages = stages.filter((s) => s.stage !== 'generating')

  // In done/static mode: suppress the generating counter entirely.
  // In streaming mode: show the live counter when available.
  const generatingLabel =
    !done && streaming && generatingElapsedMs !== null
      ? `generating… (${(generatingElapsedMs / 1000).toFixed(1)}s)`
      : null

  return (
    <div
      data-testid="stage-ticker"
      data-done={done ? 'true' : undefined}
      style={{
        background: 'var(--fw-bg-input)',
        border: '1px solid var(--fw-border-l)',
        borderRadius: 8,
        padding: '10px 14px',
        marginBottom: 16,
        // Bounded height — no inner scrollbar (ADR-0046 §8).
        maxHeight: 180,
        overflowY: 'hidden',
      }}
    >
      {/* Hidden live region — announces stage transitions to screen readers. */}
      {/* aria-live="polite": not aggressive, does not interrupt ongoing speech. */}
      <div
        ref={liveRegionRef}
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

      {/* Header row */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 8,
        }}
      >
        <span aria-hidden="true" style={{ fontSize: 13 }}>
          🧠
        </span>
        <span
          style={{
            fontSize: 12,
            color: hasFailed ? 'var(--fw-red)' : 'var(--fw-accent)',
            fontWeight: 600,
          }}
          data-testid="stage-ticker-header"
        >
          {hasFailed ? 'Analysis gauntlet' : 'Analysis pipeline'}
        </span>
      </div>

      {/* Stage lines */}
      <div
        style={{ display: 'flex', flexDirection: 'column', gap: 1 }}
        data-testid="stage-ticker-lines"
      >
        {displayedStages.map((fact, i) => (
          <StageLine
            key={i}
            label={formatStageLabel(fact)}
            // In done/static mode all lines are non-live (no highlight, no animation).
            isLive={!done && i === displayedStages.length - 1 && !generatingLabel}
            reduceMotion={reduceMotion || done}
          />
        ))}

        {/* Live generating counter — updated on every heartbeat but NOT announced. */}
        {generatingLabel && (
          <div
            style={{
              fontSize: 11,
              fontFamily: 'var(--fw-font-mono)',
              color: 'var(--fw-accent)',
              lineHeight: 1.6,
            }}
            aria-hidden="true"
            data-testid="stage-ticker-generating"
          >
            {'→ '}
            {generatingLabel}
          </div>
        )}
      </div>

      {/* Keyframe: inject once via a style tag (no CSS module dependency). */}
      {!reduceMotion && !done && (
        <style>{`
          @keyframes fw-ticker-enter {
            from { opacity: 0; transform: translateY(4px); }
            to   { opacity: 1; transform: translateY(0); }
          }
        `}</style>
      )}
    </div>
  )
}
