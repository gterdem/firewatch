/**
 * SuricataControls — Test and Sync control panel for a Suricata source instance.
 *
 * Displayed on the Suricata source card/row in the Settings view.
 * Calls MB.4 routes:
 *   POST /sources/suricata/test?source_id=...  — connectivity / file-stat check.
 *   POST /sync/suricata?source_id=...          — manual sync trigger.
 *
 * Reflects per-instance status from GET /sources:
 *   ok → normal; backoff/parked/error → visual indication + disabled controls.
 *
 * Buttons are disabled and show a spinner during in-flight requests.
 *
 * ADR-0010: schema-driven component — no source-specific business logic here;
 * this is the generic control panel seam for MB. It is wired to the Suricata
 * type_key but the call shape is type-agnostic so MC can lift it.
 */

import { useState } from 'react'
import { testSource, syncSource } from '../../api/sources'
import type { SourceInstance, TestResult, SyncResult } from '../../api/types'
import { ApiError } from '../../api/client'

interface SuricataControlsProps {
  /** The source instance shown by GET /sources, or null if not yet fetched. */
  instance: SourceInstance | null
}

type CallResult = { kind: 'test'; result: TestResult } | { kind: 'sync'; result: SyncResult }

const TYPE_KEY = 'suricata'

export default function SuricataControls({ instance }: SuricataControlsProps) {
  const [busy, setBusy] = useState<'test' | 'sync' | null>(null)
  const [lastResult, setLastResult] = useState<CallResult | null>(null)
  const [callError, setCallError] = useState<string | null>(null)

  const isInactive =
    instance !== null &&
    (instance.state === 'backoff' ||
      instance.state === 'parked' ||
      instance.state === 'error')

  async function handleTest() {
    setBusy('test')
    setLastResult(null)
    setCallError(null)
    try {
      const result = await testSource(TYPE_KEY, instance?.source_id)
      setLastResult({ kind: 'test', result })
    } catch (err) {
      setCallError(
        err instanceof ApiError
          ? `Test failed (${err.status}): ${typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail)}`
          : 'Test request failed',
      )
    } finally {
      setBusy(null)
    }
  }

  async function handleSync() {
    setBusy('sync')
    setLastResult(null)
    setCallError(null)
    try {
      const result = await syncSource(TYPE_KEY, instance?.source_id)
      setLastResult({ kind: 'sync', result })
    } catch (err) {
      setCallError(
        err instanceof ApiError
          ? `Sync failed (${err.status}): ${typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail)}`
          : 'Sync request failed',
      )
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="mt-3 space-y-2" data-testid="suricata-controls">
      {/* Status badge */}
      {instance !== null && (
        <div className="flex items-center gap-2 text-xs" data-testid="source-status">
          <span className="text-muted-foreground">Status:</span>
          <span
            className={
              instance.state === 'ok'
                ? 'text-green-700 dark:text-green-400 font-medium'
                : 'text-destructive font-medium'
            }
          >
            {String(instance.state)}
          </span>
          {instance.last_success_at && (
            <span className="text-muted-foreground">
              Last event: {new Date(instance.last_success_at).toLocaleString()}
            </span>
          )}
        </div>
      )}

      {/* Controls row */}
      <div className="flex gap-2 flex-wrap">
        {/* Test button */}
        <button
          type="button"
          disabled={busy !== null || isInactive}
          className="inline-flex items-center gap-1.5 rounded border px-3 py-1 text-sm disabled:opacity-50 hover:bg-muted transition-colors"
          data-testid="btn-test"
          aria-label="Test Suricata source connectivity"
          aria-busy={busy === 'test'}
          onClick={handleTest}
        >
          {busy === 'test' && (
            <span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" />
          )}
          Test
        </button>

        {/* Sync button */}
        <button
          type="button"
          disabled={busy !== null || isInactive}
          className="inline-flex items-center gap-1.5 rounded border px-3 py-1 text-sm disabled:opacity-50 hover:bg-muted transition-colors"
          data-testid="btn-sync"
          aria-label="Sync Suricata source"
          aria-busy={busy === 'sync'}
          onClick={handleSync}
        >
          {busy === 'sync' && (
            <span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" />
          )}
          Sync
        </button>
      </div>

      {/* Result / error feedback */}
      {callError !== null && (
        <p className="text-destructive text-xs" role="alert" data-testid="controls-error">
          {callError}
        </p>
      )}

      {lastResult !== null && (
        <div
          className={`text-xs rounded border px-3 py-2 ${
            lastResult.result.ok
              ? 'border-green-300 bg-green-50 text-green-800 dark:bg-green-950 dark:text-green-200'
              : 'border-destructive bg-destructive/10 text-destructive'
          }`}
          data-testid="controls-result"
          role="status"
        >
          {/* Result message rendered as text — safe */}
          <span className="font-medium">
            {lastResult.kind === 'test' ? 'Test' : 'Sync'}:
          </span>{' '}
          {String(lastResult.result.message)}
          {lastResult.kind === 'sync' &&
            lastResult.result.events_ingested !== null &&
            lastResult.result.events_ingested !== undefined && (
              <span className="ml-1 text-muted-foreground">
                ({lastResult.result.events_ingested} events ingested)
              </span>
            )}
        </div>
      )}

      {/* Inactive state note */}
      {isInactive && (
        <p className="text-xs text-muted-foreground" data-testid="controls-inactive">
          Controls disabled: instance is in{' '}
          <span className="font-medium">{String(instance!.state)}</span> state.
        </p>
      )}
    </div>
  )
}
