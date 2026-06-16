/**
 * useSupervisorGate — single probe for supervisor availability.
 *
 * Issue #315: When the supervisor process is not running, GET /sources returns
 * 503. This hook polls that probe with exponential backoff, surfaces a
 * supervisor-offline gate status, and exposes a retryNow() affordance.
 *
 * Contract (issue #315):
 *   - GET /sources is the canonical supervisor probe.
 *   - On 503: status transitions to "offline"; per-source fan-out is suppressed
 *     by the caller testing supervisorOffline before mounting sub-requests.
 *   - Backoff: 5 s base, doubles each tick, capped at 60 s (RFC 9110 §10.2.3).
 *   - If the probe response carries a Retry-After header, its value (seconds)
 *     overrides the computed backoff for that tick (graceful honour, not required).
 *   - retryNow(): fires the probe immediately and resets the backoff counter.
 *   - On recovery (probe succeeds): status → "online"; caller resumes fan-out.
 *
 * This is a PAGE-LEVEL supervisor-absent signal — completely separate from the
 * ADR-0032 per-source health vocabulary (ok|amber|red|not_configured).
 *
 * Security: this hook never logs form values. The probe carries no secrets.
 *
 * ADR-0026: loopback-only API; no auth in MB.
 *
 * Implementation note: the probe stores itself in a ref (probeRef) to allow
 * self-scheduling without a forward-reference lint violation. The probe reads
 * all mutable state through refs (attemptRef, mountedRef, retryAfterRef) and
 * updates React state via setters.
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import { fetchSources } from '../api/sources'
import { ApiError } from '../api/client'

/** Supervisor availability states — distinct from ADR-0032 per-source health vocab. */
export type SupervisorStatus = 'unknown' | 'online' | 'offline'

/** Backoff parameters (RFC 9110 §10.2.3 spirit: back off on server signals). */
const BACKOFF_BASE_MS = 5_000
const BACKOFF_CAP_MS = 60_000

/**
 * Compute the next backoff delay, respecting a Retry-After value if present,
 * and capping at BACKOFF_CAP_MS.
 */
function nextDelay(attempt: number, retryAfterSeconds: number | null): number {
  if (retryAfterSeconds !== null && retryAfterSeconds > 0) {
    return Math.min(retryAfterSeconds * 1000, BACKOFF_CAP_MS)
  }
  // Exponential: base * 2^attempt, capped
  return Math.min(BACKOFF_BASE_MS * Math.pow(2, attempt), BACKOFF_CAP_MS)
}

export interface UseSupervisorGateResult {
  /** Current supervisor availability. "unknown" while the first probe is in flight. */
  supervisorStatus: SupervisorStatus
  /**
   * Seconds until the next automatic retry. Only meaningful when offline.
   * Updated every second for the banner countdown.
   */
  retryCountdown: number
  /** Fire a probe immediately and reset the backoff counter. */
  retryNow: () => void
}

export function useSupervisorGate(): UseSupervisorGateResult {
  const [supervisorStatus, setSupervisorStatus] = useState<SupervisorStatus>('unknown')
  const [retryCountdown, setRetryCountdown] = useState(0)

  // All mutable bookkeeping lives in refs so the probe function doesn't need
  // to be recreated on every state change (stable identity is required for
  // the effect dependency and the retryNow callback).
  const attemptRef = useRef(0)
  const retryAfterRef = useRef<number | null>(null)
  const probeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const countdownIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const mountedRef = useRef(true)

  // probeRef holds the current probe implementation so the self-scheduling
  // callback can call it without a forward-reference lint violation.
  const probeRef = useRef<() => Promise<void>>(async () => undefined)

  // Trigger token: retryNow() increments this to re-fire the effect.
  const [triggerCount, setTriggerCount] = useState(0)

  /** Cancel both the backoff timer and the countdown interval. */
  const clearTimers = useCallback(() => {
    if (probeTimerRef.current !== null) {
      clearTimeout(probeTimerRef.current)
      probeTimerRef.current = null
    }
    if (countdownIntervalRef.current !== null) {
      clearInterval(countdownIntervalRef.current)
      countdownIntervalRef.current = null
    }
  }, [])

  /**
   * Schedule the probe to fire after `delayMs`, running a 1-second countdown
   * display while waiting.
   */
  const scheduleNext = useCallback(
    (delayMs: number) => {
      clearTimers()

      const delaySeconds = Math.ceil(delayMs / 1000)
      setRetryCountdown(delaySeconds)

      countdownIntervalRef.current = setInterval(() => {
        setRetryCountdown((prev) => Math.max(0, prev - 1))
      }, 1000)

      probeTimerRef.current = setTimeout(() => {
        if (countdownIntervalRef.current !== null) {
          clearInterval(countdownIntervalRef.current)
          countdownIntervalRef.current = null
        }
        setRetryCountdown(0)
        if (mountedRef.current) {
          // Self-schedule through the ref — no forward-reference lint issue.
          probeRef.current().catch(() => undefined)
        }
      }, delayMs)
    },
    [clearTimers],
  )

  // Build the probe function and keep it current in the ref.
  // Using useEffect (not useCallback) avoids the forward-reference issue entirely:
  // the effect runs after every render, keeping probeRef.current up-to-date.
  useEffect(() => {
    probeRef.current = async () => {
      if (!mountedRef.current) return

      try {
        await fetchSources()

        if (!mountedRef.current) return

        attemptRef.current = 0
        retryAfterRef.current = null
        setSupervisorStatus('online')
        setRetryCountdown(0)
        clearTimers()
      } catch (err: unknown) {
        if (!mountedRef.current) return

        if (err instanceof ApiError && err.status === 503) {
          // Honour an optional Retry-After from the error detail if the backend
          // includes it (issue #315 backend touch). Falls back to computed backoff.
          const retryAfterHeader =
            typeof err.detail === 'object' &&
            err.detail !== null &&
            'retry_after' in err.detail
              ? (err.detail as Record<string, unknown>)['retry_after']
              : null
          retryAfterRef.current =
            typeof retryAfterHeader === 'number' ? retryAfterHeader : null

          setSupervisorStatus('offline')

          const delay = nextDelay(attemptRef.current, retryAfterRef.current)
          attemptRef.current += 1
          scheduleNext(delay)
        } else {
          // Non-503 transient error: schedule a retry without changing status.
          const delay = nextDelay(attemptRef.current, null)
          attemptRef.current += 1
          scheduleNext(delay)
        }
      }
    }
  })

  // Fire the initial probe on mount; re-fire when retryNow() bumps triggerCount.
  useEffect(() => {
    mountedRef.current = true
    probeRef.current().catch(() => undefined)

    return () => {
      mountedRef.current = false
      clearTimers()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [triggerCount])

  const retryNow = useCallback(() => {
    clearTimers()
    attemptRef.current = 0
    retryAfterRef.current = null
    setRetryCountdown(0)
    setTriggerCount((n) => n + 1)
  }, [clearTimers])

  return { supervisorStatus, retryCountdown, retryNow }
}
