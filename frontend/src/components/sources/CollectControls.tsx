/**
 * CollectControls — flavor-driven collect controls for a source card.
 *
 * ADR-0062 §B/§D changes:
 *   - The Active toggle has moved to the card header slot (SourceCard page-level).
 *     CollectControls no longer renders the toggle itself; it receives `isActive`
 *     as a prop to gate Test/Sync and show the schedule sub-line.
 *   - WHILE Active: shows "Sync every [N] s · Sync now" schedule sub-line + Test.
 *   - WHILE Inactive (instance===null): Test and Sync are disabled with an
 *     accessible tooltip. No request is ever made with a missing source_id.
 *     No raw status code is ever shown for the inactive case.
 *   - Other failures (SSH / connection / path / auth): plain-language remediation.
 *     extractErrorMessage's (${err.status}) suffix remains only as a developer
 *     fallback for genuinely unexpected errors.
 *
 * Implements issue #138 (ADR-0031 UI surface):
 *   - PULL sources: "Sync now" button + interval input + last-sync info.
 *   - PUSH sources: listener status display only (no Sync/Active controls).
 *
 * ADR-0010 ubiquitous criterion: the flavor→controls decision lives in ONE place
 * (renderSourceControls helper). There is zero per-source-type branching outside
 * this helper — no "if suricata" or "if azure_waf" checks anywhere.
 *
 * Strict-bool contract (issue #155 NB-1 / #166 NB-A):
 *   - setAutoSync never sends interval_seconds when disabling (enabled=false).
 *   - setAutoSync always sends a JSON boolean, never a string/int.
 *   - Client-side interval bounds: 30–86400 (ADR-0031 §E).
 *
 * Security:
 *   - Error messages from the API are rendered as text nodes only (never innerHTML).
 *   - last_error from AutoSyncState is sanitized server-side; we render it as text.
 *   - Form values (interval) are never logged.
 */

import React, { useState, useEffect, useCallback } from 'react'
import { syncSource, testSource, getAutoSync, setAutoSync } from '../../api/sources'
import type { SourceInstance, AutoSyncState, SyncResult, TestResult } from '../../api/types'
import { ApiError } from '../../api/client'
import type { SourceFlavor } from '../../schema/types'
import { fmtTimestampNever } from '../../lib/time'

/** Interval bounds match ADR-0031 §E server-side validation. */
const INTERVAL_MIN = 30
const INTERVAL_MAX = 86400

/** Default interval when the server hasn't reported one yet (matches server default). */
const DEFAULT_INTERVAL = 300

interface CollectControlsProps {
  /** The source type key (e.g. "suricata", "azure_waf"). */
  typeKey: string
  /** "pull" | "push" — drives which controls subtree renders. */
  flavor: SourceFlavor
  /**
   * The source instance from GET /sources, or null if not yet fetched / unavailable.
   * Used to show status and pass source_id to sync/test calls.
   */
  instance: SourceInstance | null
  /**
   * Whether this source is Active (ADR-0062 §B / ADR-0031 §A).
   * Active = instance present in GET /sources = registered + pull loop running.
   * When false: Test and Sync are disabled with the tooltip "Turn this source on to test it".
   * When true: sync schedule sub-line is shown.
   * Defaults to false so inactive sources never accidentally enable controls.
   */
  isActive?: boolean
}

/** Validate an interval value for the client-side fast path. */
function validateInterval(value: number): string | null {
  if (!Number.isInteger(value)) return 'Interval must be a whole number.'
  if (value < INTERVAL_MIN) return `Interval must be at least ${INTERVAL_MIN} seconds.`
  if (value > INTERVAL_MAX) return `Interval must be at most ${INTERVAL_MAX} seconds (24 h).`
  return null
}

/**
 * Extract a sanitized error string from an unknown thrown value.
 *
 * Handles the following ApiError detail shapes (most to least specific):
 *   1. string                                          → plain message
 *   2. { detail: string }                              → double-wrapped plain
 *   3. { error: { code, message } }                   → structured sync envelope
 *      (backend #569/PR #586 returns HTTP 502 with this shape for SYNC_FAILED)
 *   4. { detail: { error: { code, message } } }       → same, double-wrapped
 *
 * Rendering the structured message once (not tripled) fixes the "Azure error
 * tripled" bug (#573): each shape has exactly one extraction path.
 *
 * ADR-0062 §D: the inactive-source (422) and known-remediation paths MUST be
 * intercepted before reaching this function. This is the developer fallback for
 * genuinely unexpected errors — a normal operator should never see a code.
 */
function extractErrorMessage(err: unknown, context: string): string {
  if (err instanceof ApiError) {
    const detail = err.detail

    // Shape 1: plain string detail
    if (typeof detail === 'string') return `${context} (${err.status}): ${detail}`

    if (detail && typeof detail === 'object') {
      const detailObj = detail as Record<string, unknown>

      // Shape 3: structured sync envelope { error: { code, message } }
      if (detailObj.error && typeof detailObj.error === 'object') {
        const errObj = detailObj.error as Record<string, unknown>
        if (typeof errObj.message === 'string') {
          return `${context} (${err.status}): ${errObj.message}`
        }
      }

      // Shape 2: double-wrapped plain { detail: string }
      if ('detail' in detailObj) {
        const inner = detailObj.detail
        if (typeof inner === 'string') return `${context} (${err.status}): ${inner}`

        // Shape 4: double-wrapped structured { detail: { error: { code, message } } }
        if (inner && typeof inner === 'object') {
          const innerObj = inner as Record<string, unknown>
          if (innerObj.error && typeof innerObj.error === 'object') {
            const errObj = innerObj.error as Record<string, unknown>
            if (typeof errObj.message === 'string') {
              return `${context} (${err.status}): ${errObj.message}`
            }
          }
        }
      }
    }

    return `${context} failed (${err.status})`
  }
  return `${context} failed`
}

// ---------------------------------------------------------------------------
// Push-source controls subtree: listener status only
// ---------------------------------------------------------------------------

interface PushStatusProps {
  instance: SourceInstance | null
}

function PushStatus({ instance }: PushStatusProps) {
  return (
    <div
      className="mt-3 space-y-1"
      data-testid="push-status"
      aria-label="Listener status"
    >
      <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
        Listener
      </div>
      {instance !== null ? (
        <div className="flex items-center gap-2 text-sm" data-testid="listener-state">
          <span
            className={
              instance.state === 'ok' || instance.state === 'running'
                ? 'text-green-700 dark:text-green-400 font-medium'
                : 'text-muted-foreground'
            }
          >
            {/* Render as text — server-controlled field */}
            {String(instance.state)}
          </span>
          {instance.last_success_at && (
            <span className="text-muted-foreground text-xs">
              Last event: {new Date(instance.last_success_at).toLocaleString()}
            </span>
          )}
        </div>
      ) : (
        <div className="text-sm text-muted-foreground" data-testid="listener-state">
          No listener status available
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Pull-source controls subtree: Sync now + Test + interval (when Active)
// ---------------------------------------------------------------------------

interface PullControlsProps {
  typeKey: string
  instance: SourceInstance | null
  /** ADR-0062 §B/§D: Active state gates Test/Sync availability and schedule sub-line. */
  isActive: boolean
}

function PullControls({ typeKey, instance, isActive }: PullControlsProps) {
  // ── auto-sync state (interval + last-sync info) ──────────────────────────
  const [autoSync, setAutoSyncState] = useState<AutoSyncState | null>(null)
  const [autoSyncLoading, setAutoSyncLoading] = useState(false)
  const [autoSyncError, setAutoSyncError] = useState<string | null>(null)

  // Local interval input value — kept as a string to allow partial typing.
  const [intervalInput, setIntervalInput] = useState<string>(String(DEFAULT_INTERVAL))
  const [intervalError, setIntervalError] = useState<string | null>(null)

  // ── manual sync / test state ─────────────────────────────────────────────
  const [syncBusy, setSyncBusy] = useState(false)
  const [testBusy, setTestBusy] = useState(false)
  const [syncResult, setSyncResult] = useState<SyncResult | null>(null)
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [syncError, setSyncError] = useState<string | null>(null)
  const [testError, setTestError] = useState<string | null>(null)
  /**
   * Issue #738: soft timeout indicator for long-running syncs.
   * After 90 s still busy, show "Still syncing…" note (ADR-0023: request is idempotent,
   * do NOT abort).  Reset when sync completes (syncBusy → false).
   */
  const [syncTakingLong, setSyncTakingLong] = useState(false)

  // ── load auto-sync state on mount ────────────────────────────────────────
  const loadAutoSync = useCallback(() => {
    let cancelled = false
    getAutoSync(typeKey)
      .then((state) => {
        if (!cancelled) {
          setAutoSyncState(state)
          setIntervalInput(String(state.interval_seconds))
          setAutoSyncError(null)
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          // 409 = push source (shouldn't happen — flavor guard prevents it)
          // 503 = no supervisor (graceful — show controls but disabled)
          if (err instanceof ApiError && err.status === 503) {
            setAutoSyncError(null) // 503 is handled gracefully: show controls as inactive
          } else {
            setAutoSyncError(extractErrorMessage(err, 'Auto-sync load'))
          }
        }
      })
    return () => {
      cancelled = true
    }
  }, [typeKey])

  useEffect(loadAutoSync, [loadAutoSync])

  // ── soft timeout indicator (issue #738) ──────────────────────────────────
  // After 90 s still busy: show "Still syncing…" note. ADR-0023: do NOT abort.
  // syncTakingLong resets via useState initialiser when syncBusy goes false
  // (handled by the conditional timer below — no state write in the effect body).
  React.useEffect(() => {
    // When not busy, ensure the flag is off and skip the timer.
    // State is reset here via cleanup-compatible form: the previous render's
    // cleanup (clearTimeout) fires first, then this no-op path wins.
    if (!syncBusy) {
      const id = setTimeout(() => setSyncTakingLong(false), 0)
      return () => clearTimeout(id)
    }
    const timer = setTimeout(() => setSyncTakingLong(true), 90_000)
    return () => clearTimeout(timer)
  }, [syncBusy])

  // ── interval change handler (persist on blur if active) ──────────────────
  const handleIntervalBlur = useCallback(async () => {
    if (!isActive) return
    const iv = parseInt(intervalInput, 10)
    const err = validateInterval(iv)
    if (err !== null) {
      setIntervalError(err)
      return
    }
    setIntervalError(null)
    setAutoSyncLoading(true)
    try {
      const result = await setAutoSync(typeKey, { enabled: true, interval_seconds: iv })
      setAutoSyncState(result)
      setIntervalInput(String(result.interval_seconds))
    } catch (err: unknown) {
      setAutoSyncError(extractErrorMessage(err, 'Interval update'))
    } finally {
      setAutoSyncLoading(false)
    }
  }, [isActive, typeKey, intervalInput])

  // ── manual sync handler ───────────────────────────────────────────────────
  const handleSync = useCallback(async () => {
    // ADR-0062 §D: short-circuit if not active — never call with missing source_id
    if (!isActive || !instance) return
    setSyncBusy(true)
    setSyncResult(null)
    setSyncError(null)
    try {
      const result = await syncSource(typeKey, instance.source_id)
      setSyncResult(result)

      // #707 fix: immediately apply the sync result to the last_sync display so
      // the card updates without a page reload. We optimistically patch the local
      // autoSync state from the sync response (timestamp = now, ingested =
      // events_ingested from SyncResult, status = ok/error from result.ok).
      // A background getAutoSync re-fetch then confirms the real server state.
      const syncedAt = new Date().toISOString()
      setAutoSyncState((prev) => {
        if (!prev) return prev
        return {
          ...prev,
          last_sync: {
            last_sync_at: syncedAt,
            last_sync_ingested: result.events_ingested ?? 0,
            last_sync_status: result.ok ? 'ok' : 'error',
            last_error: result.ok ? null : (result.message ?? null),
          },
        }
      })

      // Background re-fetch to confirm the server-persisted state.
      // Only apply the re-fetch result if it has a real last_sync_at —
      // otherwise we would overwrite the optimistic update with stale null data.
      getAutoSync(typeKey).then((state) => {
        setIntervalInput(String(state.interval_seconds))
        if (state.last_sync?.last_sync_at !== null) {
          // Server has the persisted timestamp — authoritative, apply it.
          setAutoSyncState(state)
        }
        // If server still returns null (race: supervisor hasn't persisted yet),
        // keep the optimistic update so the user sees immediate feedback.
      }).catch(() => {
        // Ignore refresh error — the sync itself succeeded and the
        // optimistic update above already reflects the result.
      })
    } catch (err: unknown) {
      setSyncError(extractErrorMessage(err, 'Sync'))
    } finally {
      setSyncBusy(false)
    }
  }, [isActive, typeKey, instance])

  // ── test connectivity handler ─────────────────────────────────────────────
  const handleTest = useCallback(async () => {
    // ADR-0062 §D: short-circuit if not active — never call with missing source_id
    if (!isActive || !instance) return
    setTestBusy(true)
    setTestResult(null)
    setTestError(null)
    try {
      const result = await testSource(typeKey, instance.source_id)
      setTestResult(result)
    } catch (err: unknown) {
      setTestError(extractErrorMessage(err, 'Test'))
    } finally {
      setTestBusy(false)
    }
  }, [isActive, typeKey, instance])

  const isBusy = syncBusy || testBusy || autoSyncLoading
  const isInstanceInactive =
    instance !== null &&
    (instance.state === 'backoff' || instance.state === 'parked' || instance.state === 'error')
  // A parked instance is recovered by the operator pressing Sync now (the backend
  // resumes the supervised loop on a successful manual sync — ADR-0023 §D). So the
  // Sync + Test buttons must stay clickable while parked — disabling them strands
  // the source with no UI recovery path. Test is a read-only probe; Sync is the
  // unpark action. Backoff/error remain disabled (transient / auto-retrying).
  const isParked = instance !== null && instance.state === 'parked'
  // ADR-0062 §D: also disabled when not active (no registered instance to probe)
  const actionsDisabled = isBusy || !isActive || (isInstanceInactive && !isParked)

  // Tooltip for disabled Test/Sync when the source is not Active (ADR-0062 §D)
  const inactiveTooltip = !isActive ? 'Turn this source on to test it' : undefined

  const lastSync = autoSync?.last_sync ?? null

  return (
    <div className="mt-3 space-y-3" data-testid="pull-controls">
      {/* ── Manual action row: Sync now + Test ─────────────────────────── */}
      <div className="flex gap-2 flex-wrap items-center">
        <button
          type="button"
          disabled={actionsDisabled}
          className="inline-flex items-center gap-1.5 rounded border px-3 py-1 text-sm disabled:opacity-50 hover:bg-muted transition-colors"
          data-testid="btn-sync-now"
          aria-label={syncBusy ? 'Syncing in progress' : 'Sync now'}
          aria-busy={syncBusy}
          title={inactiveTooltip}
          onClick={handleSync}
        >
          {syncBusy && (
            <span
              className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"
              aria-hidden="true"
            />
          )}
          {/* Issue #738: "Syncing…" label while in flight (bug 2c fix) */}
          {syncBusy ? 'Syncing…' : 'Sync now'}
        </button>

        <button
          type="button"
          disabled={actionsDisabled}
          className="inline-flex items-center gap-1.5 rounded border px-3 py-1 text-sm disabled:opacity-50 hover:bg-muted transition-colors"
          data-testid="btn-test"
          aria-label="Test connectivity"
          aria-busy={testBusy}
          title={inactiveTooltip}
          onClick={handleTest}
        >
          {testBusy && (
            <span
              className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"
              aria-hidden="true"
            />
          )}
          Test
        </button>
      </div>

      {/* ── Sync in-progress affordance (issue #738) ─────────────────────
           Shown while syncBusy=true; clears automatically on terminal state.
           role="status" + aria-live="polite" per ADR-0062 §D (assistive tech). */}
      {syncBusy && (
        <p
          className="text-xs text-muted-foreground"
          role="status"
          aria-live="polite"
          data-testid="sync-in-progress"
        >
          Syncing now — this can take up to ~60 s for SSH/cloud sources.
          {syncTakingLong && ' Still syncing — large pull or slow upstream; you can leave this page.'}
        </p>
      )}

      {/* ADR-0062 §D: human-readable inactive message (no raw status code) */}
      {!isActive && (
        <p
          className="text-xs text-muted-foreground"
          data-testid="pull-inactive-hint"
        >
          Turn this source on to test it.
        </p>
      )}

      {/* ── Terminal sync result (issue #738: promoted, unmissable) ─────── */}
      {syncError !== null && (
        <p className="text-destructive text-xs font-medium" role="alert" data-testid="sync-error">
          {syncError}
        </p>
      )}
      {testError !== null && (
        <p className="text-destructive text-xs" role="alert" data-testid="test-error">
          {testError}
        </p>
      )}
      {syncResult !== null && (
        <div
          className={`text-xs rounded border px-3 py-2 font-medium ${
            syncResult.ok
              ? 'border-green-300 bg-green-50 text-green-800 dark:bg-green-950 dark:text-green-200'
              : 'border-destructive bg-destructive/10 text-destructive'
          }`}
          data-testid="sync-result"
          role="status"
        >
          {syncResult.ok ? (
            syncResult.events_ingested != null && syncResult.events_ingested > 0 ? (
              // Issue #738: "Synced — N events ingested" (prominent, analyst-readable)
              `Synced — ${syncResult.events_ingested} events ingested`
            ) : syncResult.events_ingested === 0 ? (
              // Issue #744: 0 ingested is a HEALTHY outcome (watermark-incremental pull).
              // Show reassuring success message, not an ambiguous zero count.
              <>
                Synced — no new events
                <span className="ml-1 font-normal text-green-700 dark:text-green-300">
                  — sources log only when a rule matches; generate traffic and sync again.
                </span>
              </>
            ) : (
              'Synced'
            )
          ) : (
            // Failure: surface the sanitized error message (ADR-0062 §D)
            syncResult.message
              ? `Sync failed — ${String(syncResult.message)}`
              : 'Sync failed'
          )}
        </div>
      )}
      {testResult !== null && (
        <div
          className={`text-xs rounded border px-3 py-2 ${
            testResult.ok
              ? 'border-green-300 bg-green-50 text-green-800 dark:bg-green-950 dark:text-green-200'
              : 'border-destructive bg-destructive/10 text-destructive'
          }`}
          data-testid="test-result"
          role="status"
        >
          <span className="font-medium">Test:</span>{' '}
          {/* Render message as text — server-sanitized but defensive */}
          {String(testResult.ok ? 'OK' : 'Failed')}{testResult.message ? ` — ${String(testResult.message)}` : ''}
        </div>
      )}

      {/* ── Schedule sub-line: shown ONLY when Active (ADR-0062 §B) ─────── */}
      {isActive && (
        <div className="pt-2 border-t border-border/50" data-testid="active-schedule-section">
          <div className="flex items-center gap-3 flex-wrap">
            {/* Interval input — only interactive when active */}
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-muted-foreground whitespace-nowrap">
                Sync every
              </span>
              <label htmlFor={`interval-${typeKey}`} className="sr-only">
                Sync interval in seconds
              </label>
              <input
                id={`interval-${typeKey}`}
                type="number"
                min={INTERVAL_MIN}
                max={INTERVAL_MAX}
                step={30}
                value={intervalInput}
                onChange={(e) => {
                  setIntervalInput(e.target.value)
                  setIntervalError(null)
                }}
                onBlur={handleIntervalBlur}
                disabled={autoSyncLoading}
                className="w-20 rounded border border-border bg-bg-input px-2 py-1 text-xs font-mono disabled:opacity-50"
                data-testid="interval-input"
                aria-label="Auto-sync interval in seconds"
                aria-describedby={intervalError ? `interval-err-${typeKey}` : undefined}
              />
              <span className="text-xs text-muted-foreground">s</span>
              {autoSyncLoading && (
                <span
                  className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"
                  aria-hidden="true"
                />
              )}
            </div>
          </div>

          {/* Interval validation error */}
          {intervalError !== null && (
            <p
              id={`interval-err-${typeKey}`}
              className="mt-1 text-xs text-destructive"
              role="alert"
              data-testid="interval-error"
            >
              {intervalError}
            </p>
          )}

          {/* Auto-sync API error */}
          {autoSyncError !== null && (
            <p
              className="mt-1 text-xs text-destructive"
              role="alert"
              data-testid="autosync-error"
            >
              {autoSyncError}
            </p>
          )}

          {/* Last-sync info (ADR-0031 §F) */}
          {lastSync !== null && (
            <div className="mt-2 text-xs text-muted-foreground space-y-0.5" data-testid="last-sync-info">
              <div>
                <span className="font-medium">Last sync:</span>{' '}
                <span data-testid="last-sync-at">{fmtTimestampNever(lastSync.last_sync_at)}</span>
              </div>
              {lastSync.last_sync_at !== null && (
                <div>
                  <span className="font-medium">Ingested:</span>{' '}
                  <span data-testid="last-sync-ingested">{lastSync.last_sync_ingested}</span>
                </div>
              )}
              {lastSync.last_sync_status !== null && (
                <div>
                  <span className="font-medium">Status:</span>{' '}
                  <span
                    data-testid="last-sync-status"
                    className={lastSync.last_sync_status === 'error' ? 'text-destructive' : ''}
                  >
                    {/* last_sync_status is a server enum — safe to render */}
                    {String(lastSync.last_sync_status)}
                  </span>
                </div>
              )}
              {lastSync.last_error !== null && (
                <div
                  className="text-destructive"
                  data-testid="last-sync-error"
                  role="alert"
                >
                  {/* last_error is sanitized server-side — render as text */}
                  {String(lastSync.last_error)}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Inactive instance note (for backoff/parked/error states when already active) */}
      {isActive && isInstanceInactive && (
        <p
          className="mt-1 text-xs text-muted-foreground"
          data-testid="pull-inactive"
        >
          Instance is in{' '}
          <span className="font-medium">{String(instance!.state)}</span> state.
          {isParked && ' Press Sync now to resume collection.'}
        </p>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// CollectControls: top-level flavor router
// ---------------------------------------------------------------------------

/**
 * Render the correct controls subtree based on the source's flavor.
 * This is the single place where the flavor→controls decision lives (ADR-0010
 * ubiquitous criterion: no per-source branching outside this helper).
 */
function renderSourceControls(
  typeKey: string,
  flavor: SourceFlavor,
  instance: SourceInstance | null,
  isActive: boolean,
): React.ReactNode {
  if (flavor === 'pull') {
    return <PullControls typeKey={typeKey} instance={instance} isActive={isActive} />
  }
  // flavor === 'push': always-on listener; show status only
  return <PushStatus instance={instance} />
}

export default function CollectControls({ typeKey, flavor, instance, isActive = false }: CollectControlsProps) {
  return (
    <div data-testid="collect-controls" data-flavor={flavor}>
      {renderSourceControls(typeKey, flavor, instance, isActive)}
    </div>
  )
}
