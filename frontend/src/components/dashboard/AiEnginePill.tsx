/**
 * AiEnginePill — global AI-engine status pill (issue #207, ADR-0035 §4).
 *
 * One always-on live engine pill that shows the AI engine state.
 * This is the SOLE always-on engine indicator in the application.
 * Panes surface engine state only when DEGRADED (via RULES_ONLY_DEGRADED_WORDING).
 *
 * Current placement: KPI strip right slot (scope amendment — this is the
 * physical home per part-2 P10 decision; #254 owns the strip layout and
 * will dock this component into the far-right slot natively once the strip
 * layout lands). This component is self-contained — it can be relocated by
 * #254 by moving the import, no internal changes needed.
 *
 * Content: `model · status`
 *   - Health available + health.ai='active':      "<model-name> · active" (green pulse)
 *   - Health available + health.ai='unreachable': "AI unreachable" (amber — attention,
 *     NOT critical/red; detection continues on the rules-only floor, ADR-0015)
 *   - Health available + health.ai='disabled':    "AI off" (muted — deliberate choice,
 *     non-alarming)
 *   - Health null (in-flight / failed): falls back to threat-derived aiStatus
 *     (boolean `ollama_connected` is NOT used directly — issue #93 / ADR-0066)
 *
 * Tri-state rework (issue #93, fast-follow to #41 / ADR-0066): branches on the
 * authoritative `health.ai` tri-state via `resolveHealthAiState` (aiStatusCopy.ts)
 * instead of the deprecated `ollama_connected` boolean, which collapsed "off by
 * choice" (disabled) and "unreachable" (fault) into one ambiguous value.
 *
 * Click disclosure (ADR-0035 §4): click/Enter/Space opens a small disclosure
 * showing model name + connection status. The inference endpoint host/URL is
 * NEVER rendered (PR #191 topology-leak posture).
 *
 * Disclosure behavior (#327): routes through useDismissableDisclosure —
 *   - Outside-click dismiss (pointerdown outside trigger + content).
 *   - Esc dismiss with focus return to the trigger (WCAG 1.4.13 dismissable).
 *   - Single-open invariant (module-level registry closes other open disclosures).
 *   - Hover-open: pointer entering the pill opens the disclosure (WCAG 1.4.13
 *     hoverable); pointer can travel to the disclosure content; 80 ms leave delay.
 *
 * Queue depth: not cheaply derivable from the current pipeline/supervisor
 * (no `last_scored_at` or queue bookkeeping in the store). Flagged to
 * the architect — ship `model · status` only per the scope amendment.
 *
 * ADR-0022: chip shows whatever model is configured (no hardcoded model name).
 * ADR-0015: AI is additive-only; pill is purely informational.
 * ADR-0028 D6: no raw hex — all colors via var(--fw-*) tokens.
 *
 * Note: last_scored_at and queue_depth are not available in the current /health
 * response. A contract-change issue should be raised if the architect wants
 * to expose these fields.
 */

import type { HealthResponse, AiStatus } from '../../api/types'
import { useDismissableDisclosure } from '../ds'
import { capModelName } from '../../lib/modelName'
import { resolveHealthAiState } from '../aiStatusCopy'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface AiEnginePillProps {
  /**
   * Health from GET /health — authoritative AI engine state.
   * null = still in-flight or fetch failed; falls back to threat-derived aiStatus.
   */
  health?: HealthResponse | null
  /**
   * Threat-derived AI status — fallback while health is in flight (ADR-0015).
   * Ignored once health arrives.
   */
  aiStatus?: AiStatus | null
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** The tri-state `/health.ai` value (ADR-0066), plus the model name. */
interface ResolvedState {
  state: 'active' | 'disabled' | 'unreachable'
  model: string | null
}

/** Per-tone visual treatment for the pill (issue #93 — amber ≠ neutral, never collapsed). */
interface ToneStyle {
  border: string
  background: string
  color: string
  dotColor: string
  animate: boolean
}

const TONE_STYLES: Record<ResolvedState['state'], ToneStyle> = {
  active: {
    border: '1px solid rgba(34, 197, 94, 0.3)',
    background: 'rgba(34, 197, 94, 0.06)',
    color: 'var(--fw-green)',
    dotColor: 'var(--fw-green)',
    animate: true,
  },
  // Attention-worthy amber (soc-watch tokens) — a real fault, but NOT critical/red:
  // detection continues on the rules-only floor (ADR-0015).
  unreachable: {
    border: '1px solid var(--soc-watch-border)',
    background: 'var(--soc-watch-bg)',
    color: 'var(--soc-watch-fg)',
    dotColor: 'var(--fw-accent)',
    animate: false,
  },
  // Deliberate choice — neutral, non-alarming (ADR-0066).
  disabled: {
    border: '1px solid var(--fw-border)',
    background: 'var(--fw-bg-input)',
    color: 'var(--fw-t3)',
    dotColor: 'var(--fw-t3)',
    animate: false,
  },
}

/**
 * Resolve the tri-state engine status.
 *
 * health is authoritative (ADR-0066 `health.ai`, via `resolveHealthAiState`).
 * When health is still in-flight/failed (null), falls back to the threat-derived
 * `aiStatus` (issue #41 pattern) — the deprecated `ollama_connected` boolean is
 * NOT read directly, since it collapses "off by choice" and "unreachable" into
 * one ambiguous value. The fallback mirrors AiPanel.tsx: any non-'active'
 * threat-derived status degrades to 'disabled' (conservative — we cannot assert
 * a fault from threat data alone).
 */
function resolveState(
  health: HealthResponse | null | undefined,
  aiStatus: AiStatus | null | undefined,
): ResolvedState {
  if (health != null) {
    return { state: resolveHealthAiState(health), model: health.ollama_model }
  }
  return { state: aiStatus === 'active' ? 'active' : 'disabled', model: null }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function AiEnginePill({ health, aiStatus }: AiEnginePillProps) {
  const { open, triggerRef, contentRef, triggerProps, contentProps } =
    useDismissableDisclosure({ allowHover: true })

  // Hide during initial load (health=null + no aiStatus)
  if (health == null && !aiStatus) return null

  const { state, model: rawModel } = resolveState(health, aiStatus)
  // NB-2 (issue #306): cap model name to 64 chars to guard against layout breaks.
  const model = capModelName(rawModel)
  const tone = TONE_STYLES[state]

  const pillLabel =
    state === 'active'
      ? model
        ? `${model} · active`
        : 'AI · active'
      : state === 'unreachable'
        ? 'AI unreachable'
        : 'AI off'

  const ariaLabel =
    state === 'active'
      ? `AI engine active${model ? `: ${model}` : ''}`
      : state === 'unreachable'
        ? 'AI engine unreachable'
        : 'AI engine off'

  const statusLabel = state === 'active' ? 'connected' : state === 'unreachable' ? 'unreachable' : 'off'

  return (
    <div
      style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}
      data-testid="ai-engine-pill-wrapper"
    >
      <button
        ref={triggerRef as React.RefObject<HTMLButtonElement>}
        type="button"
        data-testid="ai-engine-pill"
        aria-expanded={open}
        aria-label={ariaLabel}
        {...triggerProps}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          padding: '2px 10px',
          borderRadius: 100,
          fontSize: 11,
          fontFamily: 'var(--fw-font-ui)',
          fontWeight: 500,
          cursor: 'pointer',
          border: tone.border,
          background: tone.background,
          color: tone.color,
          /* #578: maxWidth raised from 180→220 to avoid premature clip @1280px.
             overflow+textOverflow removed from the button (inline-flex does not
             apply textOverflow to its block box) — ellipsis is on the text span. */
          maxWidth: 220,
          minWidth: 0,
        }}
      >
        {/* Status dot */}
        <span
          aria-hidden="true"
          style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: tone.dotColor,
            display: 'inline-block',
            flexShrink: 0,
            animation: tone.animate ? 'fw-pulse var(--fw-dur-pulse) infinite' : 'none',
          }}
        />
        {/* #578: flex:1 + minWidth:0 lets the span shrink inside the inline-flex
            button; overflow+textOverflow applied here (block-level) so the
            ellipsis fires correctly rather than on the container button. */}
        <span style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {pillLabel}
        </span>
      </button>

      {/* Click disclosure — model name + status (NO endpoint URL per ADR topology-leak posture) */}
      {open && (
        <div
          ref={contentRef as React.RefObject<HTMLDivElement>}
          data-testid="ai-engine-pill-disclosure"
          role="tooltip"
          {...contentProps}
          style={{
            position: 'absolute',
            top: 'calc(100% + 6px)',
            right: 0,
            zIndex: 100,
            background: 'var(--fw-bg-card)',
            border: '1px solid var(--fw-border-l)',
            borderRadius: 6,
            padding: '10px 14px',
            minWidth: 200,
            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
          }}
        >
          <div
            style={{
              fontSize: 11,
              color: 'var(--fw-t3)',
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
              marginBottom: 6,
            }}
          >
            AI Engine
          </div>

          {/* Model name — shown when known (ADR-0022: whatever is configured) */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              fontSize: 12,
              color: 'var(--fw-t1)',
              marginBottom: 4,
            }}
            data-testid="ai-engine-pill-model"
          >
            <span style={{ color: 'var(--fw-t3)' }}>Model</span>
            <span style={{ fontFamily: 'var(--fw-font-mono)' }}>
              {model ?? 'unknown'}
            </span>
          </div>

          {/* Connection status */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              fontSize: 12,
              color: 'var(--fw-t1)',
            }}
            data-testid="ai-engine-pill-status"
          >
            <span style={{ color: 'var(--fw-t3)' }}>Status</span>
            <span style={{ color: tone.color }}>
              {statusLabel}
            </span>
          </div>

          {/* NOTE: inference endpoint host is intentionally NOT rendered (PR #191 topology-leak posture) */}
          {/* NOTE: last_scored_at and queue_depth not available — flagged to architect */}
        </div>
      )}
    </div>
  )
}
