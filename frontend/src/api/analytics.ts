/**
 * Analytics API client — MB.6 analytics endpoints.
 *
 * GET /analytics/geo               — server-side geo points for the Leaflet map (#20).
 *   SECURITY: never call external ip-api.com or similar CDN geo services.
 *   The server resolves coordinates; the UI just renders them on a Leaflet map.
 *   Air-gap-safe by design (ADR-0029 D1, issue #20).
 *
 * GET /analytics/summary           — aggregate stats for the charts panel.
 * GET /analytics/categories-timeline — category-over-time buckets.
 * GET /analytics/asn               — ranked ASN aggregation (issue #533, A2).
 * GET /analytics/asn/{asn}/narration — local-LLM ASN narrative (issue #533, A2 EARS-5).
 */

import { ApiError, buildHeaders, resolveBaseUrl, assertLoopbackBase } from './client'
import type {
  GeoPoint,
  AnalyticsSummary,
  CategoryTimelineBucket,
  AttackDispositionRow,
  AsnRow,
  AsnNarrationResult,
} from './types'

/**
 * Resolve BASE_URL from environment via the shared helper (fix #81).
 * Routes through client.ts resolveBaseUrl so the loopback guard is applied
 * in prod — identical fail-closed posture to client.ts (ADR-0026).
 */
const BASE_URL = resolveBaseUrl(
  (import.meta as { env?: { VITE_API_BASE_URL?: string; DEV?: boolean; PROD?: boolean } }).env ??
    {},
)

// ADR-0026 loopback guard — fail-closed in prod, same as client.ts (#81).
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
 * Fetch server-side geo points for the Leaflet map.
 * GET /analytics/geo
 *
 * All coordinates are resolved server-side (#20). The UI MUST NOT make any
 * client-side calls to ip-api.com or any external geo service — air-gap-safe.
 */
export async function fetchGeo(): Promise<GeoPoint[]> {
  const res = await fetch(`${BASE_URL}/analytics/geo`, { method: 'GET', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<GeoPoint[]>
}

/**
 * Fetch aggregate analytics summary.
 * GET /analytics/summary
 */
export async function fetchAnalyticsSummary(): Promise<AnalyticsSummary> {
  const res = await fetch(`${BASE_URL}/analytics/summary`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<AnalyticsSummary>
}

/**
 * Fetch category-over-time timeline.
 * GET /analytics/categories-timeline
 */
export async function fetchCategoriesTimeline(): Promise<CategoryTimelineBucket[]> {
  const res = await fetch(`${BASE_URL}/analytics/categories-timeline`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<CategoryTimelineBucket[]>
}

/**
 * Fetch attack-category × disposition cross-tab.
 * GET /analytics/attack-dispositions
 *
 * Returns [{attack_type, action, count}] for top-5 attack categories + Other.
 * Empty array when no categorized events exist (degrade-to-hidden semantics).
 *
 * Issue #214 — additive endpoint (ADR-0029 D1).
 */
export async function fetchAttackDispositions(): Promise<AttackDispositionRow[]> {
  const res = await fetch(`${BASE_URL}/analytics/attack-dispositions`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<AttackDispositionRow[]>
}

/**
 * Fetch ranked ASN aggregation for the infrastructure lens.
 * GET /analytics/asn
 *
 * Returns [{asn, as_name, total_events, distinct_ips, blocked, blocked_pct}]
 * ordered by total_events descending.
 *
 * Issue #533 A2 — EARS-2.  Zero-egress (ADR-0022/0047).
 */
export async function fetchAsnStats(topN = 15): Promise<AsnRow[]> {
  const res = await fetch(`${BASE_URL}/analytics/asn?top_n=${topN}`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<AsnRow[]>
}

/**
 * Fetch a local-LLM narrative for the given ASN.
 * GET /analytics/asn/{asn}/narration[?ai=false]
 *
 * Reuses the ML-7 narration path (ADR-0043).  Pass includeAi=false to
 * get a deterministic rule-only summary without calling the LLM.
 *
 * Issue #533 A2 — EARS-5.  Zero-egress (ADR-0022/0047).
 */
export async function fetchAsnNarration(
  asn: number,
  includeAi = true,
): Promise<AsnNarrationResult> {
  const url = `${BASE_URL}/analytics/asn/${asn}/narration${includeAi ? '' : '?ai=false'}`
  const res = await fetch(url, { method: 'GET', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<AsnNarrationResult>
}
