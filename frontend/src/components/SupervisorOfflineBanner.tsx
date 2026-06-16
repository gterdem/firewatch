/**
 * SupervisorOfflineBanner — page-level banner shown when the supervisor process
 * is unreachable (GET /sources returns 503).
 *
 * Issue #315: one honest banner replaces the 12× silent 503 console flood.
 * Issue #491 (UT-15): banner adds plain-language "what it means / how to recover"
 * copy so the operator has a guided recovery path, not a dead-end statement.
 *
 * Contract:
 *   - Rendered ONCE at the top of the Settings page when supervisorStatus="offline".
 *   - Shows a countdown to the next automatic retry.
 *   - "Retry now" button fires an immediate probe and resets the backoff timer.
 *   - Disappears automatically when the probe succeeds (no page reload needed).
 *   - Explains what "supervisor offline" means and how to recover (ADR-0035 honesty).
 *
 * This banner represents the SUPERVISOR-ABSENT state, completely separate from
 * the ADR-0032 per-source health vocabulary (ok|amber|red|not_configured).
 * Do NOT overload the two concerns — this is a process-level gate, not a
 * per-source health indicator.
 *
 * DS tokens used throughout (ADR-0028 D6 — no raw hex).
 */

import type { SupervisorStatus } from '../hooks/useSupervisorGate'

interface SupervisorOfflineBannerProps {
  /** Current supervisor status from useSupervisorGate. */
  supervisorStatus: SupervisorStatus
  /** Seconds until the next automatic retry. */
  retryCountdown: number
  /** Callback to fire an immediate probe. */
  onRetryNow: () => void
}

export default function SupervisorOfflineBanner({
  supervisorStatus,
  retryCountdown,
  onRetryNow,
}: SupervisorOfflineBannerProps) {
  if (supervisorStatus !== 'offline') return null

  return (
    <div
      role="alert"
      aria-live="assertive"
      data-testid="supervisor-offline-banner"
      style={{
        padding: '12px 16px',
        marginBottom: 16,
        borderRadius: 'var(--fw-r-md)',
        border: '1px solid var(--fw-border-l)',
        borderLeft: '3px solid var(--fw-amber)',
        background: 'var(--fw-bg-card)',
        fontFamily: 'var(--fw-font-ui)',
        fontSize: 'var(--fw-fs-sm)',
        color: 'var(--fw-t1)',
      }}
    >
      {/* Header row: icon + title + retry button */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        {/* Status icon */}
        <span aria-hidden="true" style={{ fontSize: 14, flexShrink: 0 }}>
          ⚠️
        </span>

        {/* Title + countdown */}
        <span style={{ flex: 1 }}>
          <span style={{ fontWeight: 'var(--fw-fw-bold)' }}>
            Supervisor offline
          </span>{' '}
          — source management unavailable.
          {retryCountdown > 0 && (
            <>
              {' '}
              Retrying in{' '}
              <span
                data-testid="supervisor-retry-countdown"
                style={{ fontFamily: 'var(--fw-font-mono)' }}
              >
                {retryCountdown}s
              </span>
            </>
          )}
        </span>

        {/* Retry now button */}
        <button
          type="button"
          onClick={onRetryNow}
          data-testid="supervisor-retry-now"
          style={{
            background: 'none',
            border: '1px solid var(--fw-border-l)',
            borderRadius: 'var(--fw-r-sm)',
            padding: '3px 10px',
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t2)',
            cursor: 'pointer',
            fontFamily: 'var(--fw-font-ui)',
            whiteSpace: 'nowrap',
            transition: 'border-color 0.15s, color 0.15s',
            flexShrink: 0,
          }}
          onMouseEnter={(e) => {
            ;(e.target as HTMLButtonElement).style.color = 'var(--fw-t1)'
            ;(e.target as HTMLButtonElement).style.borderColor = 'var(--fw-amber)'
          }}
          onMouseLeave={(e) => {
            ;(e.target as HTMLButtonElement).style.color = 'var(--fw-t2)'
            ;(e.target as HTMLButtonElement).style.borderColor = 'var(--fw-border-l)'
          }}
        >
          Retry now
        </button>
      </div>

      {/*
       * Issue #491 (UT-15): plain-language recovery guidance so the banner is a
       * recovery path, not a dead-end statement (ADR-0035 honesty).
       *
       * What it explains:
       *   - what "supervisor offline" means in practical terms
       *   - what the operator can still do (edit config — form is always accessible)
       *   - how to recover (Retry now or restart the supervisor process)
       */}
      <p
        data-testid="supervisor-offline-recovery-hint"
        style={{
          marginTop: 6,
          marginBottom: 0,
          paddingLeft: 26,
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          lineHeight: 1.5,
        }}
      >
        The FireWatch supervisor process is not running — source collection and
        sync controls are unavailable. You can still edit and save source
        configuration. Click{' '}
        <strong style={{ color: 'var(--fw-t2)' }}>Retry now</strong> to check
        again, or restart the supervisor with{' '}
        <code
          style={{
            fontFamily: 'var(--fw-font-mono)',
            fontSize: 'var(--fw-fs-xs)',
            background: 'var(--fw-bg-input)',
            padding: '0 4px',
            borderRadius: 'var(--fw-r-sm)',
          }}
        >
          firewatch supervisor start
        </code>
        .
      </p>
    </div>
  )
}
