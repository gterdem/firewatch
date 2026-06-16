/**
 * Sources control API client — MB.4 control routes + ADR-0031 auto-sync.
 *
 * GET  /sources                              — list source instances + status.
 * POST /sources/{type_key}/test             — connectivity / file-stat test.
 * POST /sync/{type_key}?source_id=...       — manual sync trigger.
 * GET  /sources/{type_key}/auto-sync        — read auto-sync state (ADR-0031 §E).
 * PUT  /sources/{type_key}/auto-sync        — enable/disable/update auto-sync (ADR-0031 §E).
 *
 * These are the control routes defined by MB.4 (#56) and issue #138.
 * The discovery route (GET /sources/types) remains in client.ts.
 *
 * ADR-0026: loopback-only; no auth header in MB.
 *
 * Fix #81: base-URL resolution is routed through the shared resolveBaseUrl helper
 * from client.ts, and assertLoopbackBase is called in prod — identical fail-closed
 * posture to client.ts. A mis-set VITE_API_BASE_URL in a prod build is rejected here
 * just as it is in client.ts.
 *
 * ADR-0031 strict-bool contract: the PUT body sends enabled as a JSON boolean.
 * interval_seconds is sent ONLY when enabling — never sent on disable (issue #155 NB-1).
 */

import { ApiError, buildHeaders, resolveBaseUrl, assertLoopbackBase } from './client'
import type { SourceInstance, TestResult, SyncResult, AutoSyncState, AutoSyncRequest } from './types'

const BASE_URL = resolveBaseUrl(
  (import.meta as { env?: { VITE_API_BASE_URL?: string; DEV?: boolean; PROD?: boolean } }).env ??
    {},
)

// ADR-0026 loopback guard — fail-closed in prod, same as client.ts (#81).
// An empty/relative base (dev proxy mode) is a non-URL and must not be validated.
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
 * List all source instances with their current status.
 * GET /sources
 * Returns status: 'ok' | 'backoff' | 'parked' | 'error' per instance.
 */
export async function fetchSources(): Promise<SourceInstance[]> {
  const res = await fetch(`${BASE_URL}/sources`, { method: 'GET', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<SourceInstance[]>
}

/**
 * Test connectivity for a source instance.
 * POST /sources/{type_key}/test?source_id=...
 * Calls are idempotent from the UI's perspective (read-only side-effect — checks file/SSH).
 * source_id: the instance to test; if omitted, the server picks the default/only instance.
 */
export async function testSource(typeKey: string, sourceId?: string): Promise<TestResult> {
  const url = new URL(
    `${BASE_URL}/sources/${encodeURIComponent(typeKey)}/test`,
    window.location.origin,
  )
  if (sourceId) url.searchParams.set('source_id', sourceId)
  const res = await fetch(url.toString(), { method: 'POST', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<TestResult>
}

/**
 * Trigger a manual sync for a source instance.
 * POST /sync/{type_key}?source_id=...
 * source_id: the instance to sync; if omitted, the server picks the default/only instance.
 */
export async function syncSource(typeKey: string, sourceId?: string): Promise<SyncResult> {
  const url = new URL(
    `${BASE_URL}/sync/${encodeURIComponent(typeKey)}`,
    window.location.origin,
  )
  if (sourceId) url.searchParams.set('source_id', sourceId)
  const res = await fetch(url.toString(), { method: 'POST', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<SyncResult>
}

/**
 * Read the current auto-sync state for a pull source.
 * GET /sources/{type_key}/auto-sync
 *
 * Returns enabled, interval_seconds, source_id (= type_key), and last_sync info.
 * 404 for unknown type_key; 409 for push sources (no auto-sync concept).
 *
 * ADR-0031 §E/§F: enabled is derived from _instances file entry presence
 * (restart-stable, not from volatile live supervisor state).
 */
export async function getAutoSync(typeKey: string): Promise<AutoSyncState> {
  const res = await fetch(
    `${BASE_URL}/sources/${encodeURIComponent(typeKey)}/auto-sync`,
    { method: 'GET', headers: buildHeaders() },
  )
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<AutoSyncState>
}

/**
 * Enable, disable, or update the auto-sync schedule for a pull source.
 * PUT /sources/{type_key}/auto-sync
 *
 * STRICT CONTRACT (ADR-0031 §E, issue #155 NB-1, #166 NB-A):
 * - enabled MUST be a real JSON boolean — the server returns 422 for strings/ints.
 * - interval_seconds is required only when enabling (enabled=true).
 *   When disabling (enabled=false), interval_seconds is NOT sent in the body —
 *   sending 0 or any invalid value would trigger a 422 on older server versions
 *   and is semantically wrong (interval is meaningless when disabling).
 * - Interval must be 30–86400 seconds (ADR-0031 §E floor/ceiling).
 *
 * Returns the resulting AutoSyncState (enabled, interval_seconds, source_id).
 * On disable, the response returns the last-known persisted interval (not 0).
 *
 * The caller (CollectControls) handles the enable/disable branching;
 * this function enforces the wire shape.
 */
export async function setAutoSync(
  typeKey: string,
  request: AutoSyncRequest,
): Promise<AutoSyncState> {
  // Build the body according to the strict contract:
  // - enabled: always a boolean literal (never a string, never an int)
  // - interval_seconds: included ONLY when enabling
  const body: Record<string, unknown> = { enabled: request.enabled }
  if (request.enabled && request.interval_seconds !== undefined) {
    body['interval_seconds'] = request.interval_seconds
  }

  const res = await fetch(
    `${BASE_URL}/sources/${encodeURIComponent(typeKey)}/auto-sync`,
    { method: 'PUT', headers: buildHeaders(), body: JSON.stringify(body) },
  )
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<AutoSyncState>
}
