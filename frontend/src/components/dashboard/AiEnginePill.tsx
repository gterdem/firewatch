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
 *   - Health available + engine connected: "<model-name> · active" (green pulse)
 *   - Health available + engine offline: "AI offline" (muted)
 *   - Health null (in-flight / failed): falls back to threat-derived aiStatus
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

interface ResolvedState {
  connected: boolean
  model: string | null
}

function resolveState(
  health: HealthResponse | null | undefined,
  aiStatus: AiStatus | null | undefined,
): ResolvedState {
  if (health != null) {
    return { connected: health.ollama_connected, model: health.ollama_model }
  }
  // Fallback: threat-derived status
  const connected = aiStatus === 'active'
  return { connected, model: null }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function AiEnginePill({ health, aiStatus }: AiEnginePillProps) {
  const { open, triggerRef, contentRef, triggerProps, contentProps } =
    useDismissableDisclosure({ allowHover: true })

  // Hide during initial load (health=null + no aiStatus)
  if (health == null && !aiStatus) return null

  const { connected, model: rawModel } = resolveState(health, aiStatus)
  // NB-2 (issue #306): cap model name to 64 chars to guard against layout breaks.
  const model = capModelName(rawModel)

  const pillLabel = connected
    ? model
      ? `${model} · active`
      : 'AI · active'
    : 'AI offline'

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
        aria-label={connected ? `AI engine active${model ? `: ${model}` : ''}` : 'AI engine offline'}
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
          border: connected
            ? '1px solid rgba(34, 197, 94, 0.3)'
            : '1px solid var(--fw-border)',
          background: connected
            ? 'rgba(34, 197, 94, 0.06)'
            : 'var(--fw-bg-input)',
          color: connected ? 'var(--fw-green)' : 'var(--fw-t3)',
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
            background: connected ? 'var(--fw-green)' : 'var(--fw-t3)',
            display: 'inline-block',
            flexShrink: 0,
            animation: connected ? 'fw-pulse var(--fw-dur-pulse) infinite' : 'none',
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
            <span style={{ color: connected ? 'var(--fw-green)' : 'var(--fw-t3)' }}>
              {connected ? 'connected' : 'offline'}
            </span>
          </div>

          {/* NOTE: inference endpoint host is intentionally NOT rendered (PR #191 topology-leak posture) */}
          {/* NOTE: last_scored_at and queue_depth not available — flagged to architect */}
        </div>
      )}
    </div>
  )
}
