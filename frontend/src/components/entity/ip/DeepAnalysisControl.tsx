/**
 * DeepAnalysisControl — the living control for the deep-analysis AI lifecycle (issue #268).
 *
 * MK-11 (ADR-0046): when phase='analyzing', renders the live stage ticker
 * (fetch-stream SSE via useStageTicker) instead of the blind AiSectionSkeleton.
 * On stream error, falls back gracefully to AiSectionSkeleton (the ticker is
 * presentation — analysis must still complete via the non-streaming path).
 *
 * Issue #416: stream is the PRIMARY (sole) analysis trigger. When the stream's
 * terminal `result` event arrives, `onStreamResult` is called so the parent
 * (IpPanel → useDeepAnalysis) can complete without a concurrent non-streaming fetch.
 * When the stream errors, `onStreamError` is called so the parent can fall back to
 * the non-streaming path. This eliminates the self-inflicted 409 that hid the ticker
 * on the first auto-triggered analysis.
 *
 * After completion (phase='complete'), the completed stage list is preserved as
 * a static summary so the user can read the full pipeline that ran (MK-11 fix).
 * useStageTicker is lifted to this component so its state (stages) persists
 * across the analyzing → complete phase transition — no re-fetch needed.
 *
 * Renders a single actionable element whose label and enabled-state reflect the
 * current phase from useDeepAnalysis:
 *
 *   ai_offline  → "AI offline — rules-only" badge + enabled "Run deep analysis" button
 *   analyzing   → StageTicker (live SSE) or AiSectionSkeleton (stream-error fallback)
 *               + disabled button "Analyzing…" only on stream-error fallback (spinner
 *                 redundant while ticker shows live progress — MK-11 fix)
 *   complete    → static stage summary (completed pipeline) + disabled "Deep analysis
 *               complete · Ns · model X" + [Re-run]
 *   failed      → ticker shows gauntlet stopping honestly ("validation FAILED → rules-only
 *               fallback"), then "AI analysis failed" badge + enabled "Retry" button.
 *               Panel renders the rules-only result — never "complete" theater (ADR-0046).
 *   idle        → nothing rendered (hook not yet started)
 *
 * SECURITY (ADR-0029 D3): modelName comes from /health (server-controlled, not
 * attacker-controlled); rendered as text node only.
 * NO model-authored text renders from stage events — only the terminal result
 * through the existing rendering path (ADR-0046 D3).
 */

import { useState, useEffect, useRef } from 'react'
import type { DeepAnalysisPhase } from './useDeepAnalysis'
import { Button, Spinner } from '../../ds'
import { capModelName } from '../../../lib/modelName'
import AiSectionSkeleton from './AiSectionSkeleton'
import StageTicker from './ticker/StageTicker'
import { useStageTicker } from './ticker/useStageTicker'

interface DeepAnalysisControlProps {
  phase: DeepAnalysisPhase
  elapsedSeconds: number
  modelName: string | null
  onRun: () => void
  /**
   * IP address — required when phase='analyzing' to open the SSE stream.
   * Used by useStageTicker to connect to GET /threats/{ip}/detailed/stream.
   * Optional for backward compatibility — defaults to null (no stream).
   */
  ip?: string | null
  /** True when the result was served from the session cache (issue #310). */
  fromCache?: boolean
  /**
   * Unix-ms timestamp of when the result was originally fetched (issue #310).
   * Used to render the "cached · X min ago" stamp.
   */
  fetchedAt?: number | null
  /**
   * Called when the SSE stream yields its terminal `result` payload.
   * The parent (IpPanel → useDeepAnalysis.receiveStreamResult) fast-paths to
   * COMPLETE without firing a concurrent non-streaming fetch (issue #416).
   */
  onStreamResult?: (payload: Record<string, unknown>) => void
  /**
   * Called when the SSE stream errors for a genuine (non-self-inflicted) reason.
   * The parent (IpPanel → useDeepAnalysis.triggerStreamFallback) falls back to
   * the non-streaming GET /threats/{ip}/detailed so the analysis still completes.
   *
   * Issue #416: a 409 from our own concurrent duplicate is eliminated upstream;
   * this callback only fires for genuine stream errors (network, parse, SSE error).
   */
  onStreamError?: () => void
}


/** Formats a Unix-ms timestamp as a human-readable age label, e.g. "2 min ago". */
function formatCacheAge(fetchedAt: number): string {
  const ageSeconds = Math.floor((Date.now() - fetchedAt) / 1000)
  if (ageSeconds < 60) return `${ageSeconds}s ago`
  const ageMinutes = Math.floor(ageSeconds / 60)
  if (ageMinutes < 60) return `${ageMinutes} min ago`
  const ageHours = Math.floor(ageMinutes / 60)
  return `${ageHours}h ago`
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function DeepAnalysisControl({
  phase,
  elapsedSeconds,
  modelName,
  onRun,
  ip = null,
  fromCache = false,
  fetchedAt = null,
  onStreamResult,
  onStreamError,
}: DeepAnalysisControlProps) {
  // -------------------------------------------------------------------------
  // Ticker lifecycle — hooks MUST be called unconditionally (Rules of Hooks).
  //
  // useStageTicker is lifted here (not in a sub-component) so its accumulated
  // stages persist when phase transitions from 'analyzing' → 'complete'.
  // The hook is enabled only while analyzing; it merely idles (no fetch) in
  // other phases, retaining the last stages in state for the static summary.
  // -------------------------------------------------------------------------
  const [resultDispatched, setResultDispatched] = useState(false)
  // useRef (not useState) avoids triggering a re-render when the flag flips;
  // the ref mutation is safe inside a useEffect without the set-state-in-effect lint rule.
  const errorDispatchedRef = useRef(false)

  // issue #525: reset per-render dispatch guards when the target IP changes.
  //
  // `resultDispatched` and `errorDispatchedRef` track whether we already notified
  // the parent for the CURRENT entity's stream. When a new entity (new IP) opens,
  // the component is NOT remounted (no key change), so these flags carry over.
  // Without the reset:
  //   - If IP-1 completed (resultDispatched=true), IP-2's result would never be
  //     forwarded to useDeepAnalysis(ip2) via onStreamResult.
  //   - If IP-1 had a stream error (errorDispatched=true), IP-2's stream error
  //     would not trigger the fallback fetch via onStreamError.
  // Both bugs would leave useDeepAnalysis stuck in 'analyzing' with no resolution.
  const prevIpRef = useRef<string | null | undefined>(undefined)
  useEffect(() => {
    if (prevIpRef.current !== undefined && prevIpRef.current !== ip) {
      // IP changed — reset dispatch guards for the new entity.
      setResultDispatched(false)
      errorDispatchedRef.current = false
    }
    prevIpRef.current = ip
  }, [ip])

  const { stages, generatingElapsedMs, result, streamError, persistentConflict, streaming } = useStageTicker({
    ip,
    enabled: phase === 'analyzing' && ip !== null,
  })

  // When the terminal result arrives, notify the parent once (via microtask to
  // avoid setState-during-render). The parent fast-paths to COMPLETE.
  if (result !== null && !resultDispatched && onStreamResult) {
    Promise.resolve().then(() => {
      setResultDispatched(true)
      onStreamResult(result)
    })
  }

  // When the stream errors (genuine non-409 failure), notify the parent once so
  // it can fall back to the non-streaming path. Uses useEffect to fire after the
  // render that shows the AiSectionSkeleton fallback — guarantees onStreamError
  // fires after the UI has already updated (issue #416 fallback contract).
  //
  // UT-02 (#502): persistentConflict (all 409 retries exhausted) is intentionally
  // excluded here — the caller must NOT fire the non-streaming fallback fetch
  // in that case because it would also receive a 409.
  // The persistentConflict UI branch below shows "please wait" instead.
  useEffect(() => {
    if (streamError && !persistentConflict && !errorDispatchedRef.current && onStreamError) {
      errorDispatchedRef.current = true
      onStreamError()
    }
  }, [streamError, persistentConflict, onStreamError])

  // -------------------------------------------------------------------------
  // Phase rendering
  // -------------------------------------------------------------------------

  if (phase === 'idle') return null

  // issue #525: concurrent analysis — stream AND non-streaming fallback both returned 409.
  // The fallback fetch receiving 409 means the backend single-flight lock is genuinely held.
  // Show "Analysis already running — please wait" (same message as useStageTicker's
  // persistentConflict path) rather than the generic "AI analysis failed" badge.
  if (phase === 'conflict') {
    return (
      <div
        data-testid="deep-analysis-control"
        style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}
      >
        <span
          data-testid="deep-analysis-conflict-badge"
          role="status"
          aria-live="polite"
          style={{
            fontSize: 11,
            color: 'var(--fw-amber)',
            background: 'var(--fw-bg-card)',
            border: '1px solid var(--fw-border)',
            borderRadius: 4,
            padding: '3px 8px',
            fontFamily: 'var(--fw-font-mono)',
          }}
        >
          Analysis already running — please wait
        </span>
      </div>
    )
  }

  const safeModelName = capModelName(modelName)
  const modelLabel = safeModelName ? ` · ${safeModelName}` : ''
  const elapsedLabel = elapsedSeconds > 0 ? ` · ${elapsedSeconds}s` : ''

  if (phase === 'ai_offline') {
    return (
      <div
        style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}
        data-testid="deep-analysis-control"
      >
        <span
          style={{
            fontSize: 11,
            color: 'var(--fw-t3)',
            background: 'var(--fw-bg-card)',
            border: '1px solid var(--fw-border)',
            borderRadius: 4,
            padding: '3px 8px',
            fontFamily: 'var(--fw-font-mono)',
          }}
          data-testid="deep-analysis-offline-badge"
          aria-label="AI offline — rules-only"
        >
          AI offline — rules-only
        </span>
        <Button
          variant="deep"
          size="sm"
          icon="🔬"
          onClick={onRun}
          data-testid="deep-analysis-run-btn"
          aria-label="Run deep analysis"
        >
          Run deep analysis
        </Button>
      </div>
    )
  }

  if (phase === 'analyzing') {
    const hasFailed = stages.some((s) => s.stage === 'failed')
    const displayStages = stages.filter((s) => s.stage !== 'generating')

    // UT-02 (#502): persistent 409 — another analysis is genuinely running for this IP.
    // Show a user-visible "please wait" message instead of an error.
    // Do NOT call onStreamError here — the non-streaming fallback would also 409.
    if (persistentConflict) {
      return (
        <div
          data-testid="deep-analysis-control"
          style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}
        >
          <span
            data-testid="deep-analysis-conflict-badge"
            role="status"
            aria-live="polite"
            style={{
              fontSize: 11,
              color: 'var(--fw-amber)',
              background: 'var(--fw-bg-card)',
              border: '1px solid var(--fw-border)',
              borderRadius: 4,
              padding: '3px 8px',
              fontFamily: 'var(--fw-font-mono)',
            }}
          >
            Analysis already running — please wait
          </span>
        </div>
      )
    }

    // Genuine stream error (non-409) → fall back to AiSectionSkeleton + spinner.
    if (streamError) {
      return (
        <div data-testid="deep-analysis-control">
          <AiSectionSkeleton
            elapsedSeconds={elapsedSeconds}
            modelName={modelName}
          />
          {/* Spinner only on stream-error fallback — ticker is not available here. */}
          <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 10 }}>
            <span data-testid="deep-analysis-spinner">
              <Spinner label="AI analyzing…" />
            </span>
            <Button variant="deep" size="sm" icon="🔬" disabled data-testid="deep-analysis-run-btn">
              {`Analyzing…${modelLabel}${elapsedLabel}`}
            </Button>
          </div>
        </div>
      )
    }

    // MK-11 fix: ticker IS the progress indicator — no redundant spinner.
    // The aria-busy attribute on the streaming region informs assistive
    // technology that live updates are in progress (WCAG 4.1.3 / ARIA 1.2).
    return (
      <div
        data-testid="deep-analysis-control"
        aria-busy={streaming ? 'true' : undefined}
      >
        {/* MK-11: StageTicker replaces the blind AiSectionSkeleton wait. */}
        <StageTicker
          stages={displayStages}
          generatingElapsedMs={generatingElapsedMs}
          streaming={streaming}
          hasFailed={hasFailed}
        />
        {/* Disabled button row — no spinner (ticker provides live progress). */}
        <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Button variant="deep" size="sm" icon="🔬" disabled data-testid="deep-analysis-run-btn">
            {`Analyzing…${modelLabel}${elapsedLabel}`}
          </Button>
        </div>
      </div>
    )
  }

  if (phase === 'failed') {
    return (
      <div
        style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}
        data-testid="deep-analysis-control"
      >
        <span
          style={{
            fontSize: 11,
            color: 'var(--fw-red)',
            background: 'var(--fw-bg-card)',
            border: '1px solid var(--fw-border)',
            borderRadius: 4,
            padding: '3px 8px',
            fontFamily: 'var(--fw-font-mono)',
          }}
          data-testid="deep-analysis-failed-badge"
          aria-label="AI analysis failed"
        >
          AI analysis failed
        </span>
        <Button
          variant="deep"
          size="sm"
          icon="🔬"
          onClick={onRun}
          data-testid="deep-analysis-run-btn"
          aria-label="Retry AI analysis"
        >
          Retry
        </Button>
      </div>
    )
  }

  if (phase === 'complete') {
    // Cache-hit path (issue #310): show "cached · age" stamp instead of elapsed time.
    const completeLabel = fromCache && fetchedAt !== null
      ? `cached · ${formatCacheAge(fetchedAt)}`
      : `Deep analysis complete${elapsedLabel}${modelLabel}`

    // MK-11 fix: render the completed pipeline as a static summary so the user
    // can read all stages that ran. Since useStageTicker is lifted to this
    // component, 'stages' persists across the analyzing → complete transition.
    // done=true suppresses animation and the live generating counter.
    const completedDisplayStages = stages.filter((s) => s.stage !== 'generating')
    const completedHasFailed = stages.some((s) => s.stage === 'failed')

    return (
      <div data-testid="deep-analysis-control">
        {completedDisplayStages.length > 0 && (
          <StageTicker
            stages={completedDisplayStages}
            generatingElapsedMs={null}
            streaming={false}
            hasFailed={completedHasFailed}
            done={true}
          />
        )}
        <div
          style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}
        >
          <Button
            variant="deep"
            size="sm"
            icon="🔬"
            disabled
            data-testid="deep-analysis-complete-btn"
            aria-label={fromCache ? 'Analysis served from session cache' : 'Deep analysis complete'}
          >
            {completeLabel}
          </Button>
          <button
            type="button"
            onClick={onRun}
            data-testid="deep-analysis-rerun-btn"
            aria-label="Re-run deep analysis"
            style={{
              fontSize: 11,
              color: 'var(--fw-t3)',
              background: 'none',
              border: '1px solid var(--fw-border)',
              borderRadius: 4,
              padding: '3px 8px',
              cursor: 'pointer',
              fontFamily: 'var(--fw-font-mono)',
            }}
          >
            Re-run
          </button>
        </div>
      </div>
    )
  }

  // health_check phase — silent wait (skeleton covers the AI section).
  return null
}
