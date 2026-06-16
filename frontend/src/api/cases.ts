/**
 * Case File API client — ADR-0053 / issue #534.
 *
 * Mirrors the 8 /cases endpoints from
 * packages/firewatch-api/src/firewatch_api/routes/cases.py
 *
 * Endpoints consumed:
 *   POST   /cases                           — create case (EARS-1)
 *   GET    /cases                           — list cases (paginated)
 *   GET    /cases/{id}                      — get one case
 *   PATCH  /cases/{id}/disposition          — set disposition (EARS-5)
 *   POST   /cases/{id}/notes               — add note (EARS-3)
 *   GET    /cases/{id}/notes               — list notes (EARS-3)
 *   POST   /cases/{id}/events              — link event ref (EARS-2)
 *   GET    /cases/{id}/timeline            — assembled timeline (EARS-2)
 *
 * SECURITY:
 *   - body_md may embed attacker-controlled content (OWASP LLM01).
 *     The UI MUST render it as sanitized text/markdown — never raw HTML (ADR-0029 D3).
 *   - All reads degrade gracefully on 503 (case store not yet wired).
 *   - Zero egress: only the loopback API is called (ADR-0026).
 */

import { ApiError, buildHeaders } from './client'

/**
 * Resolve the API base URL lazily on first call.
 *
 * Lazy evaluation avoids calling resolveBaseUrl at module import time, which
 * would break tests that mock '../api/client' without providing resolveBaseUrl.
 * The loopback guard (assertLoopbackBase) is applied once per process on the
 * first real request in production builds.
 *
 * This pattern diverges from client.ts's module-init approach intentionally:
 * cases.ts is transitively imported by EntityPanelProvider (via CasePanel),
 * which means every test that mounts EntityPanelProvider would need to export
 * resolveBaseUrl in its '../api/client' mock — that's 30+ files. Lazy eval
 * avoids that blast radius while keeping the same security posture.
 */
let _resolvedBase: string | null = null

function getBaseUrl(): string {
  if (_resolvedBase !== null) return _resolvedBase

  // Dynamic import of resolveBaseUrl + assertLoopbackBase at call time
  // so tests that mock '../api/client' without these exports still work.
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
// Types
// ---------------------------------------------------------------------------

/** Valid disposition values (mirrors backend _DispositionLiteral). */
export type CaseDisposition = 'true-positive' | 'false-positive' | 'benign' | 'open'

/** One case_file row returned by GET /cases/{id}. */
export interface CaseFile {
  id: number
  title: string
  subject: string
  status: string
  disposition: CaseDisposition
  created_at: string
  updated_at: string
}

/** Cursor-paginated list of cases from GET /cases. */
export interface CaseListPage {
  items: CaseFile[]
  next_cursor: string | null
  has_more: boolean
}

/**
 * One case_note row from GET /cases/{id}/notes.
 *
 * SECURITY (ADR-0029 D3): body_md is operator text that may embed
 * attacker-controlled event data. Render as sanitized markdown only.
 */
export interface CaseNote {
  id: number
  case_id: number
  author: string
  body_md: string
  ai_drafted: boolean
  created_at: string
  updated_at: string
}

/** Notes envelope from GET /cases/{id}/notes. */
export interface CaseNotesResponse {
  case_id: number
  notes: CaseNote[]
}

/**
 * One timeline entry from GET /cases/{id}/timeline.
 * ref_kind is "security_event" or "ai_analysis".
 */
export interface TimelineEntry {
  id: number
  case_id: number
  ref_kind: string
  ref_id: string
  created_at: string
}

/** Timeline envelope from GET /cases/{id}/timeline. */
export interface CaseTimelineResponse {
  case_id: number
  entries: TimelineEntry[]
}

// ---------------------------------------------------------------------------
// POST /cases — create a new case
// ---------------------------------------------------------------------------

export interface CreateCaseBody {
  title: string
  subject: string
  disposition?: CaseDisposition
}

/**
 * Create a new case file (EARS-1).
 * Returns the new case id.
 * Throws ApiError on failure.
 */
export async function createCase(body: CreateCaseBody): Promise<number> {
  const res = await fetch(`${getBaseUrl()}/cases`, {
    method: 'POST',
    headers: buildHeaders(),
    body: JSON.stringify(body),
  })
  if (!res.ok) throw await parseError(res)
  const data = await res.json() as { id: number }
  return data.id
}

// ---------------------------------------------------------------------------
// GET /cases — paginated list
// ---------------------------------------------------------------------------

/**
 * Fetch a cursor-paginated list of cases (newest first).
 * Returns null on 503 (store not yet wired — honest degrade).
 *
 * `subject` filters to cases matching that subject string exactly (issue #757).
 * The backend returns matching cases newest-first; the caller picks the first open one.
 */
export async function listCases(params?: {
  limit?: number
  cursor?: string
  subject?: string
}): Promise<CaseListPage | null> {
  const url = new URL(`${getBaseUrl()}/cases`, globalThis.location?.origin ?? 'http://localhost')
  if (params?.limit !== undefined) url.searchParams.set('limit', String(params.limit))
  if (params?.cursor) url.searchParams.set('cursor', params.cursor)
  if (params?.subject !== undefined) url.searchParams.set('subject', params.subject)

  const res = await fetch(url.toString(), { method: 'GET', headers: buildHeaders() })
  if (res.status === 503) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<CaseListPage>
}

// ---------------------------------------------------------------------------
// GET /cases/{id}
// ---------------------------------------------------------------------------

/**
 * Fetch a single case file.
 * Returns null on 404 or 503 (honest degrade).
 */
export async function getCase(caseId: number): Promise<CaseFile | null> {
  const res = await fetch(`${getBaseUrl()}/cases/${encodeURIComponent(caseId)}`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (res.status === 404 || res.status === 503) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<CaseFile>
}

// ---------------------------------------------------------------------------
// PATCH /cases/{id}/disposition
// ---------------------------------------------------------------------------

/**
 * Set the disposition of a case (EARS-5).
 * Returns true on success.
 * Throws ApiError on 404 / 422 / 503.
 */
export async function setDisposition(
  caseId: number,
  disposition: CaseDisposition,
): Promise<void> {
  const res = await fetch(`${getBaseUrl()}/cases/${encodeURIComponent(caseId)}/disposition`, {
    method: 'PATCH',
    headers: buildHeaders(),
    body: JSON.stringify({ disposition }),
  })
  if (!res.ok) throw await parseError(res)
}

// ---------------------------------------------------------------------------
// POST /cases/{id}/notes
// ---------------------------------------------------------------------------

/**
 * Add a markdown note to a case (EARS-3).
 * author defaults to "local operator" (ADR-0053 D3 auth-aware seam).
 * Returns the new note id.
 * Throws ApiError on 404 / 422 / 503.
 *
 * SECURITY (ADR-0029 D3): body_md will be stored and later rendered
 * as sanitized markdown — never echoed as raw HTML.
 */
export async function addNote(
  caseId: number,
  body: { body_md: string; author?: string; ai_drafted?: boolean },
): Promise<number> {
  const res = await fetch(`${getBaseUrl()}/cases/${encodeURIComponent(caseId)}/notes`, {
    method: 'POST',
    headers: buildHeaders(),
    body: JSON.stringify(body),
  })
  if (!res.ok) throw await parseError(res)
  const data = await res.json() as { id: number }
  return data.id
}

// ---------------------------------------------------------------------------
// GET /cases/{id}/notes
// ---------------------------------------------------------------------------

/**
 * Fetch all notes for a case in chronological order (EARS-3).
 * Returns null on 503 (honest degrade).
 */
export async function listNotes(caseId: number): Promise<CaseNotesResponse | null> {
  const res = await fetch(`${getBaseUrl()}/cases/${encodeURIComponent(caseId)}/notes`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (res.status === 503) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<CaseNotesResponse>
}

// ---------------------------------------------------------------------------
// POST /cases/{id}/events — link a reference
// ---------------------------------------------------------------------------

/**
 * Link a security_event or ai_analysis reference to a case (EARS-2 / ADR-0041).
 * Stores a reference only — no denormalized copy.
 * Returns the new case_event id.
 * Throws ApiError on 404 / 422 / 503.
 */
export async function linkEvent(
  caseId: number,
  body: { ref_kind: string; ref_id: string },
): Promise<number> {
  const res = await fetch(`${getBaseUrl()}/cases/${encodeURIComponent(caseId)}/events`, {
    method: 'POST',
    headers: buildHeaders(),
    body: JSON.stringify(body),
  })
  if (!res.ok) throw await parseError(res)
  const data = await res.json() as { id: number }
  return data.id
}

// ---------------------------------------------------------------------------
// POST /cases/{id}/summary — draft an AI summary (B1-polish, issue #535)
// ---------------------------------------------------------------------------

/**
 * Response from POST /cases/{id}/summary.
 *
 * provenance mirrors ADR-0035: "rule" | "ai" | "ai+rule".
 * "rule" means the LLM was unavailable — deterministic rule-only fallback (EARS-5).
 */
export interface CaseSummaryResponse {
  note_id: number
  narrative: string
  /** ADR-0035 derivation tag: "rule" | "ai" | "ai+rule" */
  provenance: string
  collected_fields: string[]
  ai_status: string
}

/**
 * POST /cases/{id}/summary — request a local-LLM draft summary (EARS-1).
 *
 * Reuses the ML-7 narration path (ADR-0043). On-box / zero-egress (ADR-0022/0047).
 * Degrades to rule-only when the LLM is unavailable (EARS-5).
 * The draft is stored as a case_note with ai_drafted=1 (EARS-2 / ADR-0035).
 *
 * Suggest-only: does NOT auto-close or auto-set disposition (EARS-6 / ADR-0015).
 *
 * SECURITY (ADR-0029 D3): narrative may embed attacker-controlled content.
 * Render as text node only — never as raw HTML.
 *
 * Returns CaseSummaryResponse on success (201).
 * Throws ApiError on failure.
 */
export async function draftCaseSummary(caseId: number): Promise<CaseSummaryResponse> {
  const res = await fetch(
    `${getBaseUrl()}/cases/${encodeURIComponent(caseId)}/summary`,
    {
      method: 'POST',
      headers: buildHeaders(),
    },
  )
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<CaseSummaryResponse>
}

// ---------------------------------------------------------------------------
// GET /cases/{id}/timeline — assembled at read time
// ---------------------------------------------------------------------------

/**
 * Fetch the assembled timeline for a case (EARS-2 / ADR-0041 / ADR-0053 D2).
 * References are assembled at read time from case_events — no denormalized copies.
 * Returns null on 404 or 503 (honest degrade).
 */
export async function getCaseTimeline(caseId: number): Promise<CaseTimelineResponse | null> {
  const res = await fetch(`${getBaseUrl()}/cases/${encodeURIComponent(caseId)}/timeline`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (res.status === 404 || res.status === 503) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<CaseTimelineResponse>
}
