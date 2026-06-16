/**
 * NarrationPanel — one-click local-LLM IP narration (ML-7, issue #435).
 *
 * Renders the "Explain" section inside the IpPanel slide-over.
 * Four states:
 *   idle       → Explain button visible (no narration yet)
 *   loading    → staged "watch it think" ticker (AI mode) or rule summary label
 *   done       → narrative text + provenance chips per claim (EARS-2)
 *   error      → error + Retry button
 *
 * CR3 (issue #614) — "watch it think" staged ticker:
 *   In AI mode, the loading state replaces the bare spinner with
 *   NarrationInferenceTicker: a collapsed/expanded ADR-0046 stage ticker that
 *   surfaces the REAL on-device model pipeline stages with per-stage elapsed
 *   times (proof of locality).  The ticker is driven by real SSE stage facts
 *   from the /threats/{ip}/detailed/stream endpoint via useNarrationStream.
 *   Honest degradation (ADR-0046 §7): if the stream itself fails, the ticker is
 *   hidden and the narration prose still arrives normally.
 *
 * Anti-fabrication (EARS-3):
 *   The ``collected_fields`` list from the API tells us which fields were
 *   actually used.  We surface this as a subtle "grounded in: …" label so
 *   the analyst can see exactly what the narration was derived from.
 *
 * AI-unavailable degrade (EARS-4 / ADR-0015):
 *   When ``ai_status`` is 'unavailable'/'skipped'/'disabled', the panel
 *   renders with ``provenance='rule'`` and a notice:
 *   "Rules-only mode · AI engine offline"
 *   In this mode, no inference stages are shown — only "Building rule summary…"
 *   (ADR-0035 honesty: never imply AI ran when it didn't).
 *
 * ADR-0035 provenance (EARS-2):
 *   The entire narrative block carries ONE ProvenanceChip derived from
 *   ``result.provenance``.  The chip is shown in the header, not inline,
 *   to avoid cluttering a flowing paragraph.
 *
 * SECURITY (ADR-0029 D3):
 *   ``narrative`` is LLM-authored text — rendered as a plain text node only
 *   (never via dangerouslySetInnerHTML).  collected_fields values are
 *   server-controlled metadata (safe for text rendering).
 *
 * Advisory-only (ADR-0015 §Tier-0 / Out-of-scope in issue #435):
 *   "What to check next" sentence is informational — no SOAR actions wired.
 */

import { useState, useCallback } from 'react'
import { ProvenanceChip, Spinner } from '../../ds'
import { fetchNarration } from '../../../api/logs'
import type { NarrationResult } from '../../../api/types'
import NarrationInferenceTicker from './NarrationInferenceTicker'
import { useNarrationStream } from './useNarrationStream'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface NarrationPanelProps {
  ip: string
  /**
   * Whether the AI engine is currently available.
   * When false, fetchNarration is called with includeAi=false (fast path);
   * the result will have provenance='rule' and ai_status='unavailable'/'skipped'.
   * Default: true.
   */
  aiAvailable?: boolean
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

type NarrationState =
  | { phase: 'idle' }
  | { phase: 'loading' }
  | { phase: 'done'; result: NarrationResult }
  | { phase: 'error'; message: string }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** True when the AI engine was not used to produce this narration. */
function isRuleOnly(result: NarrationResult): boolean {
  return (
    result.provenance === 'rule' ||
    result.ai_status === 'unavailable' ||
    result.ai_status === 'skipped' ||
    result.ai_status === 'disabled'
  )
}

// ---------------------------------------------------------------------------
// Sub-component: loading state — ticker (AI) vs rule summary (rule-only)
// CR3 (issue #614)
// ---------------------------------------------------------------------------

/**
 * NarrationLoadingState — the loading branch of NarrationPanel.
 *
 * AI mode: mounts `useNarrationStream` to open the /detailed/stream SSE and
 * renders the `NarrationInferenceTicker` (collapsed/expanded stage view).
 * If the stream errors, falls back to plain "Running local model…" text —
 * the narration prose still arrives via the parent's `fetchNarration` call.
 *
 * Rule-only mode: plain spinner + "Building rule summary…" — NO inference
 * stages are implied (ADR-0035 honest provenance / EARS-4).
 */
function NarrationLoadingState({ ip, aiAvailable }: { ip: string; aiAvailable: boolean }) {
  const stream = useNarrationStream({ ip, aiAvailable, enabled: true })

  // Show ticker only in AI mode AND when the stream has not errored.
  const showTicker = aiAvailable && !stream.streamError

  if (!aiAvailable) {
    // Rule-only degrade: no inference stages (ADR-0035 / EARS-4).
    return (
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 8 }}
        data-testid="narration-rule-only-loading"
      >
        <Spinner label="Building rule summary…" data-testid="narration-spinner" />
        <span style={{ fontSize: 'var(--fw-fs-xs)', color: 'var(--fw-t3)' }}>
          Building rule summary…
        </span>
      </div>
    )
  }

  if (showTicker) {
    // "Watch it think" — real ADR-0046 stage ticker (CR3).
    return (
      <NarrationInferenceTicker
        stages={stream.stages}
        generatingElapsedMs={stream.generatingElapsedMs}
        streaming={stream.streamStreaming}
        done={stream.streamDone}
      />
    )
  }

  // Fallback: stream errored → plain loading text (narration prose still arrives).
  return (
    <div
      style={{ display: 'flex', alignItems: 'center', gap: 8 }}
      data-testid="narration-stream-fallback"
    >
      <Spinner label="Running local model…" data-testid="narration-spinner" />
      <span style={{ fontSize: 'var(--fw-fs-xs)', color: 'var(--fw-t3)' }}>
        Running local model…
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function NarrationPanel({ ip, aiAvailable = true }: NarrationPanelProps) {
  const [state, setState] = useState<NarrationState>({ phase: 'idle' })

  const handleExplain = useCallback(async () => {
    setState({ phase: 'loading' })
    try {
      // EARS-4: pass includeAi=false when engine is offline so we get the
      // rule-only summary immediately without waiting for a timeout.
      const result = await fetchNarration(ip, aiAvailable)
      setState({ phase: 'done', result })
    } catch (err) {
      const msg =
        err instanceof Error ? err.message : 'Failed to fetch narration'
      setState({ phase: 'error', message: msg })
    }
  }, [ip, aiAvailable])

  const handleReset = useCallback(() => {
    setState({ phase: 'idle' })
  }, [])

  // ── Idle: just the Explain button ──────────────────────────────────────────
  if (state.phase === 'idle') {
    return (
      <div
        data-testid="narration-panel"
        data-narration-phase="idle"
        style={{ marginTop: 16 }}
      >
        <button
          type="button"
          data-testid="explain-btn"
          onClick={handleExplain}
          aria-label={`Explain IP ${ip} — generate a local-LLM narration`}
          style={{
            fontSize: 'var(--fw-fs-xs)',
            fontFamily: 'var(--fw-font-ui)',
            fontWeight: 'var(--fw-fw-semibold)',
            color: 'var(--fw-accent)',
            background: 'rgba(245,158,11,0.07)',
            border: '1px solid rgba(245,158,11,0.22)',
            borderRadius: 'var(--fw-r-sm)',
            padding: '5px 12px',
            cursor: 'pointer',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          <span aria-hidden="true">Explain</span>
        </button>
        <span
          style={{
            marginLeft: 8,
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
          }}
        >
          {aiAvailable
            ? 'Local AI · zero egress'
            : 'Rules-only · AI offline'}
        </span>
      </div>
    )
  }

  // ── Loading: "watch it think" ticker (AI) or rule summary (rule-only) ──────
  // CR3 (issue #614): replace bare spinner with NarrationInferenceTicker in AI mode.
  // Rule-only: keep "Building rule summary…" — NEVER imply AI ran (ADR-0035).
  if (state.phase === 'loading') {
    return (
      <div
        data-testid="narration-panel"
        data-narration-phase="loading"
        style={{ marginTop: 16 }}
      >
        <NarrationLoadingState ip={ip} aiAvailable={aiAvailable} />
      </div>
    )
  }

  // ── Error ──────────────────────────────────────────────────────────────────
  if (state.phase === 'error') {
    return (
      <div
        data-testid="narration-panel"
        data-narration-phase="error"
        style={{ marginTop: 16 }}
      >
        <span
          style={{ fontSize: 'var(--fw-fs-xs)', color: 'var(--fw-red)' }}
          data-testid="narration-error"
        >
          {state.message}
        </span>
        {' '}
        <button
          type="button"
          onClick={handleReset}
          data-testid="narration-retry-btn"
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t2)',
            background: 'none',
            border: '1px solid var(--fw-border)',
            borderRadius: 'var(--fw-r-xs)',
            padding: '2px 8px',
            cursor: 'pointer',
          }}
        >
          Retry
        </button>
      </div>
    )
  }

  // ── Done: narrative + provenance chip ──────────────────────────────────────
  const { result } = state
  const ruleOnly = isRuleOnly(result)

  return (
    <div
      data-testid="narration-panel"
      data-narration-phase="done"
      style={{ marginTop: 16 }}
    >
      {/* Header row: section label + provenance chip (EARS-2 / ADR-0035) */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 8,
        }}
        data-testid="narration-header"
      >
        <span
          style={{
            fontSize: 'var(--fw-fs-2xs)',
            fontWeight: 'var(--fw-fw-semibold)',
            color: 'var(--fw-t3)',
            textTransform: 'uppercase',
            letterSpacing: 'var(--fw-ls-label)',
          }}
        >
          Narration
        </span>
        {/* ADR-0035 provenance chip (EARS-2): one chip for the whole narrative */}
        <ProvenanceChip
          derivation={result.provenance}
          data-testid="narration-provenance-chip"
        />
        {/* ADR-0015 degrade notice: surfaced only when AI was not used */}
        {ruleOnly && (
          <span
            style={{ fontSize: 'var(--fw-fs-2xs)', color: 'var(--fw-t3)' }}
            data-testid="narration-rule-only-notice"
          >
            Rules-only mode · AI engine offline
          </span>
        )}
      </div>

      {/* Narrative text — SECURITY: text node only, never dangerouslySetInnerHTML */}
      <p
        data-testid="narration-text"
        style={{
          fontSize: 'var(--fw-fs-body)',
          color: 'var(--fw-t1)',
          lineHeight: 1.6,
          margin: '0 0 8px 0',
          whiteSpace: 'pre-wrap',
        }}
      >
        {result.narrative}
      </p>

      {/* Anti-fabrication disclosure (EARS-3): which fields the narration used */}
      {result.collected_fields.length > 0 && (
        <div
          data-testid="narration-collected-fields"
          style={{
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
            marginTop: 4,
          }}
        >
          Grounded in:{' '}
          <span data-testid="narration-fields-list">
            {result.collected_fields.join(', ')}
          </span>
        </div>
      )}

      {/* Re-explain button */}
      <button
        type="button"
        onClick={handleReset}
        data-testid="narration-reset-btn"
        style={{
          marginTop: 8,
          fontSize: 'var(--fw-fs-2xs)',
          color: 'var(--fw-t3)',
          background: 'none',
          border: '1px solid var(--fw-border)',
          borderRadius: 'var(--fw-r-xs)',
          padding: '2px 8px',
          cursor: 'pointer',
        }}
      >
        Re-explain
      </button>
    </div>
  )
}
