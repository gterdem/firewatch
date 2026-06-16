/**
 * Source maintenance action API client (ADR-0034 / issue #169).
 *
 * GET  /sources/{type_key}/actions?source_id=
 *   Returns each declared action merged with its live ActionStatus.
 *   Resilient: plugin errors degrade to null-status entries, never 500.
 *
 * POST /sources/{type_key}/actions/{action_id}?source_id=
 *   Invokes a declared maintenance action.
 *   Returns HTTP 200 + ActionResult for both ok=true and ok=false outcomes.
 *   HTTP 409 → action already in flight.
 *   HTTP 422 → source_id fails pattern/length constraint.
 *   HTTP 404 → unknown type_key, unconfigured source_id, or undeclared action_id.
 *   HTTP 503 → no supervisor available.
 *
 * Security:
 *   - All URLs are built via URL() + encodeURIComponent — no string interpolation
 *     into path components.
 *   - source_id and action_id are echoed in ActionResult — the caller MUST render
 *     them as text nodes, never via dangerouslySetInnerHTML.
 *   - The loopback guard from client.ts is re-used for BASE_URL resolution.
 *
 * ADR-0026: loopback-only; no auth header in MA.
 */

import { ApiError, buildHeaders, resolveBaseUrl, assertLoopbackBase } from './client'
import type { ActionEntry, ActionResult } from './types'

const BASE_URL = resolveBaseUrl(
  (import.meta as { env?: { VITE_API_BASE_URL?: string; DEV?: boolean; PROD?: boolean } }).env ??
    {},
)

// ADR-0026 loopback guard — fail-closed in prod, identical to client.ts (#81).
if (
  (import.meta as { env?: { PROD?: boolean } }).env?.PROD === true &&
  BASE_URL !== ''
) {
  assertLoopbackBase(BASE_URL)
}

async function parseError(res: Response): Promise<ApiError> {
  const detail = await res.json().catch(() => res.text().catch(() => null))
  return new ApiError(res.status, detail, `API ${res.status}: ${res.url}`)
}

/**
 * Fetch declared actions with their live status for a source instance.
 * GET /sources/{type_key}/actions?source_id=
 *
 * Returns an empty array when the plugin declares no actions.
 * Throws ApiError on 404 / 503 / 422.
 *
 * Long-running actions (long_running=true) should use an extended
 * timeout at the fetch layer — callers use AbortController for that.
 *
 * @param typeKey  Plugin type key (^[a-z][a-z0-9_]*$).
 * @param sourceId Instance name (constrained, ADR-0016 / NB-4).
 */
export async function fetchSourceActions(
  typeKey: string,
  sourceId: string,
): Promise<ActionEntry[]> {
  const url = new URL(
    `${BASE_URL}/sources/${encodeURIComponent(typeKey)}/actions`,
    window.location.origin,
  )
  url.searchParams.set('source_id', sourceId)
  const res = await fetch(url.toString(), { method: 'GET', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<ActionEntry[]>
}

/**
 * Invoke a declared maintenance action for a source instance.
 * POST /sources/{type_key}/actions/{action_id}?source_id=
 *
 * Returns ActionResult (ok=true or ok=false) on HTTP 200.
 * Throws ApiError on 404 / 409 / 422 / 503.
 *
 * When the action is long_running, the caller should use a longer
 * AbortController timeout (e.g. 120 s) to avoid premature cancellation.
 *
 * @param typeKey   Plugin type key.
 * @param sourceId  Instance name.
 * @param actionId  Declared action identifier.
 * @param signal    Optional AbortSignal for timeout / cancellation.
 */
export async function runSourceAction(
  typeKey: string,
  sourceId: string,
  actionId: string,
  signal?: AbortSignal,
): Promise<ActionResult> {
  const url = new URL(
    `${BASE_URL}/sources/${encodeURIComponent(typeKey)}/actions/${encodeURIComponent(actionId)}`,
    window.location.origin,
  )
  url.searchParams.set('source_id', sourceId)
  const res = await fetch(url.toString(), {
    method: 'POST',
    headers: buildHeaders(),
    signal,
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<ActionResult>
}
