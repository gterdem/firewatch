/**
 * Triage-decisions API client — ADR-0072 D3, issue #47 Part 2/frontend.
 *
 * Mirrors the 3 /decisions endpoints from
 * packages/firewatch-api/src/firewatch_api/routes/decisions.py:
 *
 *   POST   /decisions            — record a decision (server computes the snapshot)
 *   GET    /decisions            — cursor-paginated history (ADR-0029 D2)
 *   DELETE /decisions/{id}       — soft-revoke (undo; audit row survives)
 *
 * SECURITY:
 *   - actor_ip / rule_name / note are bounded and pattern-validated server-side;
 *     a malformed body is a clean 422, never a 500.
 *   - Zero egress: only the loopback API is called (ADR-0026).
 *   - The client NEVER sends decided_tier/decided_score — the server is the
 *     sole snapshot authority (ADR-0072 D2; a stale tab must not write a
 *     stale re-entry baseline).
 *
 * Lazy `getBaseUrl()` (mirrors api/cases.ts): triageActions.ts /
 * triageDecisions.ts are transitively imported by most triage-surface
 * components and tests (TriageBanner, RecommendationCards, DashboardRoute,
 * triageBand). Resolving the base URL at call time — rather than at module
 * import time — means those tests do not all need to mock `resolveBaseUrl`/
 * `assertLoopbackBase` out of '../api/client'.
 */
import { ApiError, buildHeaders } from './client'
import type { CreateDecisionRequest, DecisionRecord, ListDecisionsResponse } from './types'

let _resolvedBase: string | null = null

function getBaseUrl(): string {
  if (_resolvedBase !== null) return _resolvedBase

  const env =
    (import.meta as { env?: { VITE_API_BASE_URL?: string; DEV?: boolean; PROD?: boolean } })
      .env ?? {}

  if (env.VITE_API_BASE_URL !== undefined) {
    _resolvedBase = env.VITE_API_BASE_URL
  } else if (env.DEV) {
    _resolvedBase = ''
  } else {
    _resolvedBase = 'http://127.0.0.1:8000'
  }

  return _resolvedBase
}

async function parseError(res: Response): Promise<ApiError> {
  const detail = await res.json().catch(() => res.text().catch(() => null))
  return new ApiError(res.status, detail, `API ${res.status}: ${res.url}`)
}

// ---------------------------------------------------------------------------
// POST /decisions — record a decision
// ---------------------------------------------------------------------------

/**
 * Record a triage decision (`expected` / `dismissed` / `false_positive`).
 *
 * The server computes `decided_tier`/`decided_score` by running the actor
 * through the pipeline (ADR-0072 D2) — never send them here.
 *
 * Returns the full record (incl. server snapshot) on 201.
 * Throws ApiError on 422 (verb/rule_name XOR mismatch) or 503 (store/pipeline
 * not wired).
 */
export async function createDecision(body: CreateDecisionRequest): Promise<DecisionRecord> {
  const res = await fetch(`${getBaseUrl()}/decisions`, {
    method: 'POST',
    headers: buildHeaders(),
    body: JSON.stringify(body),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<DecisionRecord>
}

// ---------------------------------------------------------------------------
// GET /decisions — cursor-paginated history
// ---------------------------------------------------------------------------

/**
 * Fetch the decision history (ADR-0029 D2 cursor envelope), newest-first.
 * Returns the FULL history (active + revoked) — the audit trail feeds the
 * case inbox (#16).
 *
 * `actor` scopes to one actor's full history (active + revoked).
 * Returns null on 503 (store not yet wired — honest degrade).
 */
export async function listDecisions(params?: {
  actor?: string
  cursor?: string
  limit?: number
}): Promise<ListDecisionsResponse | null> {
  const url = new URL(`${getBaseUrl()}/decisions`, globalThis.location?.origin ?? 'http://localhost')
  if (params?.actor !== undefined) url.searchParams.set('actor', params.actor)
  if (params?.cursor) url.searchParams.set('cursor', params.cursor)
  if (params?.limit !== undefined) url.searchParams.set('limit', String(params.limit))

  const res = await fetch(url.toString(), { method: 'GET', headers: buildHeaders() })
  if (res.status === 503) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<ListDecisionsResponse>
}

// ---------------------------------------------------------------------------
// DELETE /decisions/{id} — soft-revoke (undo)
// ---------------------------------------------------------------------------

/**
 * Soft-revoke a decision (sets `revoked_at`) — the audit row survives
 * (append-only, ADR-0072 D2).
 *
 * Throws ApiError on 404 (unknown id) or 503 (store not wired).
 */
export async function revokeDecision(decisionId: number): Promise<void> {
  const res = await fetch(`${getBaseUrl()}/decisions/${encodeURIComponent(decisionId)}`, {
    method: 'DELETE',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
}
