/**
 * Typed HTTP client for the FireWatch loopback API.
 *
 * ADR-0026: In MA the API is loopback-only with no auth header.
 * A seam is left here for future auth (MB+): provide a getAuthHeader
 * factory to attach the bearer token when the API is exposed beyond loopback.
 *
 * Endpoints:
 *   GET  /sources/types              — discovery (MA.3 / #32)
 *   GET  /config/sources/{type_key}  — read source config (MA.3b / #45)
 *   PUT  /config/sources/{type_key}  — write source config (MA.3b / #45)
 *
 * Read/query endpoints (ADR-0029 D1 — MB.5):
 *   GET  /stats                      — global stats + source health
 *   GET  /health                     — liveness + component status
 *   GET  /threats                    — list of ThreatScore
 *   GET  /logs/timeline              — timeline buckets
 *   GET  /logs/categories            — category counts
 */

import type { SourceTypeEntry } from '../schema/types'
import { getApiKey } from '../app/apiKeyStore'
import type {
  StatsResponse,
  HealthResponse,
  ThreatScore,
  TimelineBucket,
  CategoryCount,
  AiModelsResponse,
  RuntimeConfigResponse,
  ScoreHistoryPoint,
  EvidenceChainResponse,
  AnalysisListPage,
  AnalysisDetail,
  BaselineStatus,
  DriftReport,
  FeedbackRequest,
  FeedbackRow,
  FeedbackSummary,
  EscalationPolicyResponse,
  BannerAttemptSummary,
} from './types'

/**
 * Assert that a base URL resolves to a loopback address.
 * Exported so it can be unit-tested without touching import.meta.env.
 *
 * Throws if the host is not 127.0.0.1, localhost, or ::1 (IPv6 loopback).
 * ADR-0026: the MA UI must only talk to the loopback API.
 */
export function assertLoopbackBase(url: string): void {
  let hostname: string
  try {
    hostname = new URL(url).hostname
  } catch {
    throw new Error(
      `FireWatch: VITE_API_BASE_URL "${url}" is not a valid URL. ` +
        'In production it must resolve to loopback (ADR-0026).',
    )
  }
  const loopbackHosts = ['127.0.0.1', 'localhost', '::1', '[::1]']
  if (!loopbackHosts.includes(hostname)) {
    throw new Error(
      `FireWatch: production build refuses non-loopback API base "${url}" ` +
        '(host: ' +
        hostname +
        '). ' +
        'ADR-0026 restricts MA config PUTs (which carry secrets) to loopback only. ' +
        'Set VITE_API_BASE_URL to http://127.0.0.1:8000 or leave it unset.',
    )
  }
}

/**
 * Resolve the API base URL from the environment.
 * Exported as a pure helper so it can be unit-tested without side effects.
 *
 * Resolution order (same in dev and prod — explicit override always wins):
 *   1. VITE_API_BASE_URL — explicit override, wins in both dev and prod.
 *   2. DEV=true          — empty string so requests are relative and route
 *                          through the Vite dev proxy (no CORS, no .env.local
 *                          needed). The proxy in vite.config.ts forwards
 *                          /sources and /config to http://127.0.0.1:8000.
 *   3. PROD default      — absolute loopback URL; assertLoopbackBase guard
 *                          then validates any explicit override.
 *
 * ADR-0026: loopback-only posture is preserved in production.
 */
export function resolveBaseUrl(env: {
  VITE_API_BASE_URL?: string
  DEV?: boolean
}): string {
  if (env.VITE_API_BASE_URL !== undefined) {
    return env.VITE_API_BASE_URL
  }
  // In dev: use a relative base so the Vite proxy handles origin forwarding.
  if (env.DEV) {
    return ''
  }
  return 'http://127.0.0.1:8000'
}

/** Base URL for the loopback API. Override via VITE_API_BASE_URL. */
const BASE_URL = resolveBaseUrl(
  (import.meta as { env?: { VITE_API_BASE_URL?: string; DEV?: boolean; PROD?: boolean } }).env ??
    {},
)

/**
 * In production builds, reject any non-loopback base URL so config PUTs
 * (which carry secrets) can never accidentally reach an off-host endpoint.
 * ADR-0026: MA API is loopback-only.
 *
 * We throw rather than console.warn so the failure is hard and explicit —
 * matching the fail-closed security posture demanded by ADR-0026.
 * Dev/test builds skip this guard to allow local proxy setups.
 * An empty/relative base (dev proxy mode) is not a URL and must not be
 * passed to assertLoopbackBase.
 */
if (
  (import.meta as { env?: { PROD?: boolean } }).env?.PROD === true &&
  BASE_URL !== ''
) {
  assertLoopbackBase(BASE_URL)
}

/**
 * Build common request headers.
 *
 * ADR-0026 Amendment 1 (enforce-when-set): when an API key is configured, attach
 * `Authorization: Bearer <key>` on every outbound request (RFC 6750 §2.1).
 * When no key is set, the header is omitted entirely — the loopback boundary is the
 * sole access control (ADR-0026 D2, no-key path).
 *
 * The key is sourced from apiKeyStore (the single client-side location). It is never
 * logged, URL-embedded, or echoed to the DOM in plaintext (ADR-0006 / ADR-0026 D6).
 */
export function buildHeaders(extra?: Record<string, string>): Record<string, string> {
  const key = getApiKey()
  const authHeader: Record<string, string> =
    key !== null ? { Authorization: `Bearer ${key}` } : {}
  return {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...authHeader,
    ...extra,
  }
}

/** Typed API error — carries HTTP status and structured detail from the server. */
export class ApiError extends Error {
  readonly status: number
  readonly detail: unknown

  constructor(status: number, detail: unknown, message?: string) {
    super(message ?? `API error ${status}`)
    this.status = status
    this.detail = detail
  }
}

/**
 * Parse a non-ok response into an ApiError.
 *
 * 401 responses produce a clear "API key required or invalid" message so callers
 * can surface it directly (ADR-0026 Amendment 1: the SPA must communicate auth failures
 * without retrying in a loop — EARS event-driven criterion).
 */
async function parseError(res: Response): Promise<ApiError> {
  const parsedDetail = await res.json().catch(() => res.text().catch(() => null))
  const message =
    res.status === 401
      ? 'API key required or invalid — set a valid key in Settings'
      : `API ${res.status}: ${res.url}`
  return new ApiError(res.status, parsedDetail, message)
}

// ---------------------------------------------------------------------------
// Discovery endpoint — GET /sources/types
// ---------------------------------------------------------------------------

/**
 * Fetch the list of installed source plugins.
 * Each entry carries type_key, display_name, version, flavor, and config_schema
 * (the JSON Schema that drives the rjsf Settings card, ADR-0010 / ADR-0028 D4).
 */
export async function fetchSourceTypes(): Promise<SourceTypeEntry[]> {
  const res = await fetch(`${BASE_URL}/sources/types`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<SourceTypeEntry[]>
}

// ---------------------------------------------------------------------------
// Config endpoints — GET/PUT /config/sources/{type_key}
// ---------------------------------------------------------------------------

/**
 * Load current config for a source type.
 * SecretStr fields are returned as null (masked by the server, ADR-0006).
 * The PasswordWidget must handle null gracefully — show "•••• set", never prefill.
 */
export async function fetchSourceConfig(
  typeKey: string,
): Promise<Record<string, unknown>> {
  const res = await fetch(`${BASE_URL}/config/sources/${encodeURIComponent(typeKey)}`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<Record<string, unknown>>
}

/**
 * Save config for a source type.
 * The server validates against the plugin schema and returns 422 on failure.
 * The 422 body has "input" stripped by the server to prevent secret-echo (ADR-0006).
 * Throws ApiError on non-ok responses.
 *
 * Body shape: {"updates": <config>} — the API reads body.get("updates", {}).
 * Sending a raw config object resolves updates={} and nothing is persisted (#63).
 */
export async function putSourceConfig(
  typeKey: string,
  config: Record<string, unknown>,
): Promise<void> {
  const res = await fetch(`${BASE_URL}/config/sources/${encodeURIComponent(typeKey)}`, {
    method: 'PUT',
    headers: buildHeaders(),
    body: JSON.stringify({ updates: config }),
  })
  if (!res.ok) throw await parseError(res)
}

// ---------------------------------------------------------------------------
// Read/query endpoints — ADR-0029 D1 (MB.5)
// All requests are safe GET (RFC 9110 §9.2.1 — no side effects).
// ---------------------------------------------------------------------------

/**
 * Global stats + source health.
 * GET /stats
 */
export async function fetchStats(): Promise<StatsResponse> {
  const res = await fetch(`${BASE_URL}/stats`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<StatsResponse>
}

/**
 * Liveness + component status (AI / DB).
 * GET /health
 */
export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${BASE_URL}/health`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<HealthResponse>
}

/**
 * All threat scores for known IPs.
 * GET /threats
 * ai_* fields are additive-only; consumers must degrade gracefully when
 * ai_status is "unavailable" or "disabled" (ADR-0015).
 */
export async function fetchThreats(): Promise<ThreatScore[]> {
  const res = await fetch(`${BASE_URL}/threats`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<ThreatScore[]>
}

/**
 * Attempt/actor/succeeded/queue counts + bounded top-N pressure strip for the
 * triage banner's attempts headline (issue #55).
 * GET /banner/summary
 *
 * Every integer is computed server-side from the shared attempts module and
 * the existing decide()/detect() verdicts — the banner must never count
 * differently than the engine. Callers MUST render these fields verbatim
 * (never recompute attempt/actor/succeeded/queue counts client-side).
 */
export async function fetchBannerSummary(): Promise<BannerAttemptSummary> {
  const res = await fetch(`${BASE_URL}/banner/summary`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<BannerAttemptSummary>
}

/**
 * Per-IP score history series for the trajectory sparkline.
 * GET /threats/{ip}/score-history?window=<hours>
 *
 * `historyWindow` is a numeric duration in **hours** (float) — the backend
 * FastAPI/Pydantic route parameter is typed as `float`, so passing a string
 * like "1h" causes a 422 float_parsing error (issue #309 regression).
 *
 * Returns a UTC-bucketed series of score snapshots for the given IP.
 * An unknown/unsampled IP returns an empty array (not 404).
 * Callers SHOULD handle 404 gracefully: the backend route may not be
 * registered (issue #250 wiring gap — known at time of writing).
 *
 * issue #251: used by RiskMovers.tsx to feed Sparkline trajectories.
 */
export async function fetchScoreHistory(
  ip: string,
  historyWindow: number = 1,
): Promise<ScoreHistoryPoint[]> {
  const url = new URL(`${BASE_URL}/threats/${encodeURIComponent(ip)}/score-history`, globalThis.location.origin)
  url.searchParams.set('window', String(historyWindow))
  const res = await fetch(url.toString(), {
    method: 'GET',
    headers: buildHeaders(),
  })
  // Graceful degradation: 404 = endpoint not registered or unknown IP; return empty series.
  if (res.status === 404) return []
  if (!res.ok) throw await parseError(res)
  // Field-name reshape: the backend emits `{ ip, score, ts }` (threats.py
  // GET /score-history → store.get_score_history), but the frontend series
  // seam (lib/series.ts) reads `{ t, value }`. Without this map, `t`/`value`
  // are undefined → every point is dropped → the sparkline renders its empty
  // "no-data" baseline and history-bearing rows can never collapse. Map at the
  // single client seam so types.ts / series.ts / consumers stay unchanged.
  const raw = (await res.json()) as Array<{ score: number; ts: string }>
  return raw.map((p) => ({ t: p.ts, value: p.score }))
}

/**
 * Activity timeline buckets.
 * GET /logs/timeline?start=<iso>&end=<iso>
 * Both parameters are optional — omit for the default range.
 */
export async function fetchTimeline(params?: {
  start?: string
  end?: string
}): Promise<TimelineBucket[]> {
  const url = new URL(`${BASE_URL}/logs/timeline`, window.location.origin)
  if (params?.start) url.searchParams.set('start', params.start)
  if (params?.end) url.searchParams.set('end', params.end)
  const res = await fetch(url.toString(), {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<TimelineBucket[]>
}

/**
 * Category event counts.
 * GET /logs/categories
 */
export async function fetchCategories(): Promise<CategoryCount[]> {
  const res = await fetch(`${BASE_URL}/logs/categories`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<CategoryCount[]>
}

// ---------------------------------------------------------------------------
// Local AI endpoints — #135 (ADR-0022)
// ---------------------------------------------------------------------------

/**
 * Fetch the list of models available at the configured local AI endpoint.
 * GET /ai/models → { models: string[], current: string | null }
 *
 * If the endpoint is unreachable the server returns an empty list (never 500).
 * ADR-0022: only contacts a loopback/RFC-1918 base_url.
 */
export async function fetchAiModels(): Promise<AiModelsResponse> {
  const res = await fetch(`${BASE_URL}/ai/models`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<AiModelsResponse>
}

/**
 * Read the current runtime configuration.
 * GET /config/runtime → RuntimeConfigResponse
 *
 * SecretStr fields (webhook_url, api_key) are returned as null (masked,
 * ADR-0006 / config.py _mask_secrets). The UI shows a "•••• set" placeholder;
 * it never prefills a secret field.
 */
export async function getRuntimeConfig(): Promise<RuntimeConfigResponse> {
  const res = await fetch(`${BASE_URL}/config/runtime`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<RuntimeConfigResponse>
}

/**
 * Persist a runtime configuration update.
 * PUT /config/runtime  body: { updates: { ollama_model: "..." } }
 *
 * Field name `ollama_model` is the backend SDK name (rename DEFERRED per #135).
 * Used by LocalAiPanel to persist the selected model.
 * Throws ApiError on non-ok responses — callers should surface 422 (SSRF / validation)
 * as sanitized text (anti-SSRF guard in RuntimeConfig._validate_webhook_url_ssrf).
 */
export async function putRuntimeConfig(updates: Record<string, unknown>): Promise<void> {
  const res = await fetch(`${BASE_URL}/config/runtime`, {
    method: 'PUT',
    headers: buildHeaders(),
    body: JSON.stringify({ updates }),
  })
  if (!res.ok) throw await parseError(res)
}

// ---------------------------------------------------------------------------
// Evidence chain endpoint — ADR-0041 / MI-6 (issue #387)
// GET /threats/{ip}/evidence
// ---------------------------------------------------------------------------

/**
 * Fetch the evidence chain for one IP.
 * GET /threats/{ip}/evidence → EvidenceChainResponse
 *
 * Returns the factor → log_row_ids mapping recomputed at read time from stored
 * rows. The ``ai_boost`` factor returns a stored-artifact reference — no LLM
 * call is triggered (ai-engine-invariants / ADR-0041 hard boundary).
 *
 * Returns null on 404 (IP has no stored events).
 * Throws ApiError on other non-ok responses (503 = store/pipeline unavailable).
 */
export async function fetchEvidenceChain(ip: string): Promise<EvidenceChainResponse | null> {
  const res = await fetch(
    `${BASE_URL}/threats/${encodeURIComponent(ip)}/evidence`,
    { method: 'GET', headers: buildHeaders() },
  )
  if (res.status === 404) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<EvidenceChainResponse>
}

// ---------------------------------------------------------------------------
// AI verdict ledger endpoints — ADR-0044 / MK-2 (issue #407)
// GET /ai/analyses   — cursor-paginated summary list (no prompt/response text)
// GET /ai/analyses/{id} — full record (MK-7 prompt drawer)
// ---------------------------------------------------------------------------

/**
 * Fetch the full analysis record including prompt/response text.
 * GET /ai/analyses/{id} → AnalysisDetail
 *
 * Returns the full record including prompt_text, response_text, validated_json,
 * and truncation flags — fields intentionally absent from the list endpoint
 * (ADR-0044 §Security / OWASP LLM05).
 *
 * Returns null on 404 (analysis record not found — honest degrade).
 * Returns null on 503 (ledger not wired — honest degrade).
 * Throws ApiError on other non-ok responses.
 *
 * SECURITY (ADR-0029 D3): prompt_text and response_text are the most
 * attacker-controlled strings in the product. Callers MUST render them as
 * text nodes only — never via dangerouslySetInnerHTML.
 */
export async function fetchAnalysisDetail(id: number): Promise<AnalysisDetail | null> {
  const res = await fetch(
    `${BASE_URL}/ai/analyses/${encodeURIComponent(id)}`,
    { method: 'GET', headers: buildHeaders() },
  )
  if (res.status === 404 || res.status === 503) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<AnalysisDetail>
}

// ---------------------------------------------------------------------------
// AI baseline + drift endpoints — MK-8 / MK-9 (issue #413 / #414)
// GET /ai/baseline          → BaselineStatus
// GET /ai/baseline/drift    → DriftReport | null (404 = no comparison run)
// ---------------------------------------------------------------------------

/**
 * Fetch the AI verdict baseline status.
 * GET /ai/baseline → BaselineStatus
 *
 * Returns {exists: false} when no baseline has been saved.
 * When a baseline exists, returns metadata (model, saved_at, scenario_count).
 * Note: model and saved_at may be null in the current backend implementation.
 *
 * Throws ApiError on non-ok responses other than 404.
 */
export async function fetchBaselineStatus(): Promise<BaselineStatus> {
  const res = await fetch(`${BASE_URL}/ai/baseline`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<BaselineStatus>
}

/**
 * Fetch the latest AI verdict drift report.
 * GET /ai/baseline/drift → DriftReport | null
 *
 * Returns null on 404 (no comparison has been run yet — honest empty state).
 * Throws ApiError on 422 (corrupt/oversized report — caller should prompt re-run)
 * or other non-ok responses.
 */
export async function fetchDriftReport(): Promise<DriftReport | null> {
  const res = await fetch(`${BASE_URL}/ai/baseline/drift`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (res.status === 404) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<DriftReport>
}

/**
 * Fetch a page of AI analysis summary records.
 * GET /ai/analyses?ip=&limit=&cursor=
 *
 * The response excludes ``prompt_text`` and ``response_text`` (ADR-0044 §Security /
 * OWASP LLM05 — those are returned only by the detail endpoint).
 *
 * Returns null on 503 (ledger not yet wired / service starting up — honest degrade).
 * Throws ApiError on other non-ok responses.
 *
 * ``limit`` must be 1–200 (server clamps at 200, ADR-0044 §Security).
 */
export async function fetchAnalyses(params?: {
  ip?: string
  limit?: number
  cursor?: string
}): Promise<AnalysisListPage | null> {
  const url = new URL(`${BASE_URL}/ai/analyses`, globalThis.location.origin)
  if (params?.ip) url.searchParams.set('ip', params.ip)
  if (params?.limit !== undefined) url.searchParams.set('limit', String(params.limit))
  if (params?.cursor) url.searchParams.set('cursor', params.cursor)

  const res = await fetch(url.toString(), { method: 'GET', headers: buildHeaders() })
  // 503 = ledger not wired yet — degrade gracefully (no analyses = honest empty state)
  if (res.status === 503) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<AnalysisListPage>
}

// ---------------------------------------------------------------------------
// Verdict feedback endpoints — ADR-0045 / MK-5+MK-6 (issue #410 / #411)
// POST /ai/analyses/{id}/feedback — upsert analyst judgment
// GET  /ai/feedback/summary       — agreement rollup
// ---------------------------------------------------------------------------

/**
 * Upsert analyst feedback (agree/disagree) for an analysis record.
 * POST /ai/analyses/{id}/feedback
 *
 * Re-submitting replaces the previous judgment for the same analysis_id
 * (latest wins — ADR-0045 D1 unique-constraint upsert).
 *
 * ``reason`` is capped at 1 000 chars client-side (mirrored from server cap).
 * The server also enforces the cap independently (defence-in-depth).
 *
 * Status codes handled:
 *   200 — success; returns the stored FeedbackRow.
 *   404 — unknown analysis_id; throws ApiError(404).
 *   422 — invalid verdict or oversized reason; throws ApiError(422).
 *   503 — ledger not wired; throws ApiError(503).
 *
 * SECURITY (ADR-0026): write route — loopback-only by design.
 * Never logs reason values (operator text, potentially sensitive).
 */
export async function postFeedback(
  analysisId: number,
  body: FeedbackRequest,
): Promise<FeedbackRow> {
  const res = await fetch(
    `${BASE_URL}/ai/analyses/${encodeURIComponent(analysisId)}/feedback`,
    {
      method: 'POST',
      headers: buildHeaders(),
      body: JSON.stringify(body),
    },
  )
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<FeedbackRow>
}

/**
 * Fetch the analyst agreement rollup.
 * GET /ai/feedback/summary → FeedbackSummary
 *
 * Returns {graded, agreed, agreement_pct} computed at read time (ADR-0045 D2).
 * Returns null on 503 (ledger not wired — honest degrade; no fabricated counts).
 * Throws ApiError on other non-ok responses.
 *
 * Honest denominator rule (ADR-0045 D4): ``graded`` is always present in the
 * response; the UI must display it — never a bare percentage.
 */
export async function fetchFeedbackSummary(): Promise<FeedbackSummary | null> {
  const res = await fetch(`${BASE_URL}/ai/feedback/summary`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (res.status === 503) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<FeedbackSummary>
}

// ---------------------------------------------------------------------------
// Escalation policy endpoint — GET /escalation/policy (issue #650, ADR-0058 D1/D6)
// ---------------------------------------------------------------------------

/**
 * Fetch the escalation policy registry with rolling 24h detection hit-counts.
 * GET /escalation/policy → EscalationPolicyResponse
 *
 * Returns the ESCALATION_POLICY registry (per-detection severity + auto_escalate
 * flag) together with 24h hit-counts derived from stored events.
 * Every registered detection appears even when its hit_count_24h is 0.
 *
 * The registry is read-only — finalized at import time in the backend
 * (escalation/policy.py). No write path exists.
 *
 * Returns null on 503 (store not available — honest degrade).
 * Throws ApiError on other non-ok responses.
 */
export async function fetchEscalationPolicy(): Promise<EscalationPolicyResponse | null> {
  const res = await fetch(`${BASE_URL}/escalation/policy`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (res.status === 503) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<EscalationPolicyResponse>
}
