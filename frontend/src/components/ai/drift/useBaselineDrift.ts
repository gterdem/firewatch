/**
 * useBaselineDrift — fetch hook for Model Trust panel (MK-9, issue #414).
 *
 * Fetch strategy (issue #505 — suppress spurious 404 console noise):
 *   1. Fetch GET /ai/baseline and GET /health in parallel.
 *   2. If no baseline exists, resolve immediately to 'no-baseline'.
 *      This avoids firing GET /ai/baseline/drift when no baseline is saved —
 *      the endpoint would 404, which browsers log as a console error even though
 *      the JS path handles it correctly (fetchDriftReport returns null on 404).
 *      Skipping the request entirely silences CE-01/CE-02 console noise (UT-06).
 *   3. Only when baseline.exists=true, fetch GET /ai/baseline/drift.
 *
 * Exposes the states the DriftPanel needs:
 *   - loading
 *   - no baseline (exists=false)
 *   - baseline exists but no drift comparison yet (drift=null, baseline.exists=true)
 *   - full drift report available
 *   - error (report corrupt/422 or network failure)
 *
 * MM #476: `configuredModel` is included in the baseline-only and drift-report
 * states so DriftPanel can detect a model swap (baseline.model ≠ configuredModel)
 * and surface a re-baseline banner. The field is null when /health is unavailable
 * or ollama_model is unset — in those cases no banner is shown.
 *
 * Does NOT trigger any AI inference — reads persisted CLI output only
 * (ADR-0043: page renders retrospective artifacts; ai-engine-invariants boundary).
 * ADR-0026: loopback-only — calls go through the existing fetch helpers.
 */
import { useState, useEffect } from 'react'
import { fetchBaselineStatus, fetchDriftReport, fetchHealth, ApiError } from '../../../api/client'
import type { BaselineStatus, DriftReport } from '../../../api/types'

export type BaselineDriftState =
  | { status: 'loading' }
  | { status: 'no-baseline' }
  | {
      status: 'baseline-only'
      baseline: Extract<BaselineStatus, { exists: true }>
      /** Model currently configured on the engine; null if /health unavailable. */
      configuredModel: string | null
    }
  | {
      status: 'drift-report'
      baseline: Extract<BaselineStatus, { exists: true }>
      drift: DriftReport
      /** Model currently configured on the engine; null if /health unavailable. */
      configuredModel: string | null
    }
  | { status: 'error'; message: string }

/**
 * Two-phase fetch: /ai/baseline + /health in parallel first; drift only if baseline exists.
 *
 * Phase 1 (parallel): fetchBaselineStatus() + fetchHealth() — both fire immediately.
 * Phase 2 (conditional): fetchDriftReport() — only fired when baseline.exists=true,
 *   preventing a guaranteed-404 request that browsers surface as a console error.
 *
 * /health is fetched non-fatally: a failure to reach it only yields
 * configuredModel=null (banner suppressed) rather than an error state.
 *
 * Stable: the hook never triggers writes or side-effectful mutations.
 * The result is memoised by mount; re-mount or external trigger needed for
 * refresh (no polling — this is batch/retrospective data).
 */
export function useBaselineDrift(): BaselineDriftState {
  const [state, setState] = useState<BaselineDriftState>({ status: 'loading' })

  useEffect(() => {
    let cancelled = false

    // Phase 1: fetch baseline status + health in parallel.
    // /health is non-fatal: failure → configuredModel=null (banner hidden, MM #476).
    const healthPromise = fetchHealth()
      .then((h) => h.ollama_model ?? null)
      .catch(() => null)

    Promise.all([fetchBaselineStatus(), healthPromise])
      .then(async ([baseline, configuredModel]) => {
        if (cancelled) return

        // No baseline saved — resolve immediately without firing the drift endpoint.
        // Skipping the request avoids a guaranteed 404 that browsers log as an error
        // even when the JS handler returns null (UT-06 / issue #505).
        if (!baseline.exists) {
          setState({ status: 'no-baseline' })
          return
        }

        const existingBaseline = baseline as Extract<BaselineStatus, { exists: true }>

        // Phase 2: baseline exists — now it makes sense to check for a drift report.
        // fetchDriftReport returns null on 404 (no comparison run yet); throws on 422.
        const drift = await fetchDriftReport()

        if (cancelled) return

        if (drift === null) {
          setState({ status: 'baseline-only', baseline: existingBaseline, configuredModel })
          return
        }

        setState({ status: 'drift-report', baseline: existingBaseline, drift, configuredModel })
      })
      .catch((err: unknown) => {
        if (cancelled) return

        if (err instanceof ApiError) {
          if (err.status === 422) {
            setState({
              status: 'error',
              message:
                'Drift report is unreadable (corrupt or oversized). ' +
                'Re-run: firewatch ai-baseline --compare',
            })
            return
          }
          setState({ status: 'error', message: `Could not load model trust data (${err.status})` })
          return
        }

        setState({ status: 'error', message: 'Could not load model trust data' })
      })

    return () => {
      cancelled = true
    }
  }, [])

  return state
}
