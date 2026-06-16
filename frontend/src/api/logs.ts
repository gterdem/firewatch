/**
 * Logs API client — MB.6 read endpoints.
 *
 * GET /logs/paginated — cursor-paginated log explorer (ADR-0029 D2).
 *   Consumes the verbatim store envelope: {logs, next_cursor, has_more, total_matching}.
 *   Clients MUST echo next_cursor back as `cursor` — never compute offsets client-side.
 *
 * GET /threats/{ip}         — concise ThreatScore for the drill-down header.
 * GET /threats/{ip}/detailed — full deep analysis (#19).
 * GET /rules                 — rule descriptions for the drill-down sidebar.
 *
 * SECURITY (ADR-0029 D3): raw_log / native fields in LogEntry are attacker-controlled.
 * This module returns them typed as `unknown`; the render layer MUST use text nodes only.
 */

import { ApiError, buildHeaders, resolveBaseUrl, assertLoopbackBase } from './client'
import type { LogsFilter, LogsStats, NlQueryResponse, PaginatedLogs, ThreatScore, DetailedAnalysis, RuleDescription, IpEventTimelineResponse, TopPairsRow, TopTalkerRow, ProtocolMixRow, DgaSuspectRow, EntityGraphResponse, Ja4FingerprintRow, NarrationResult } from './types'

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
 * Fetch a cursor-paginated page of log entries.
 * GET /logs/paginated?cursor=…&limit=…&source_type=…&…
 *
 * Filter parameters bind 1:1 to the store signature (ADR-0029 D2).
 * Pass `filter.cursor` from the previous envelope's `next_cursor` to advance;
 * omit or pass undefined to start from the first page.
 */
export async function fetchPaginatedLogs(filter: LogsFilter = {}): Promise<PaginatedLogs> {
  const url = new URL(`${BASE_URL}/logs/paginated`, window.location.origin)
  const params: Record<string, string | number> = {}
  if (filter.cursor) params.cursor = filter.cursor
  if (filter.limit !== undefined) params.limit = filter.limit
  if (filter.source_type) params.source_type = filter.source_type
  if (filter.source_id) params.source_id = filter.source_id
  if (filter.category) params.category = filter.category
  if (filter.severity) params.severity = filter.severity
  if (filter.ip) params.ip = filter.ip
  if (filter.start) params.start = filter.start
  if (filter.end) params.end = filter.end
  if (filter.q) params.q = filter.q
  if (filter.action) params.action = filter.action
  // ML-3 (issue #431) — destination dimension filters
  if (filter.destination_ip) params.destination_ip = filter.destination_ip
  if (filter.protocol) params.protocol = filter.protocol
  // ML-13 (issue #441) — JA4 fingerprint facet filter
  if (filter.tls_ja4) params.tls_ja4 = filter.tls_ja4
  Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, String(v)))

  const res = await fetch(url.toString(), { method: 'GET', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<PaginatedLogs>
}

/**
 * Fetch concise ThreatScore for one IP.
 * GET /threats/{ip}
 * Returns null on 404 (IP has no events — ADR-0029 D3 "404 not empty-200").
 */
export async function fetchThreatScore(ip: string): Promise<ThreatScore | null> {
  const res = await fetch(`${BASE_URL}/threats/${encodeURIComponent(ip)}`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (res.status === 404) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<ThreatScore>
}

/**
 * Fetch detailed analysis for one IP.
 * GET /threats/{ip}/detailed[?ai=false]
 * Fetched once on drill-down open (#19). Returns null on 404.
 *
 * @param ip - The IP address to analyze.
 * @param includeAi - When false, passes `?ai=false` to skip the LLM and return
 *   rule-only analysis instantly (ai_status='skipped'). Used by useRuleAnalysis
 *   when GET /health reports the AI engine is offline (issue #268 fast path).
 *   Default: true (full deep-analysis path, may take ~15s).
 */
export async function fetchDetailedAnalysis(
  ip: string,
  includeAi: boolean = true,
): Promise<DetailedAnalysis | null> {
  const url = new URL(
    `${BASE_URL}/threats/${encodeURIComponent(ip)}/detailed`,
    window.location.origin,
  )
  if (!includeAi) {
    url.searchParams.set('ai', 'false')
  }
  const res = await fetch(url.toString(), {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (res.status === 404) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<DetailedAnalysis>
}

/**
 * Fetch rule descriptions.
 * GET /rules
 * Used in the IP drill-down modal to annotate detections.
 */
export async function fetchRules(): Promise<RuleDescription[]> {
  const res = await fetch(`${BASE_URL}/rules`, { method: 'GET', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<RuleDescription[]>
}

/**
 * Fetch top (source_ip → destination_ip) pairs by event count (ML-3, issue #431).
 * GET /logs/top-pairs?top_n=N[&filter params]
 *
 * Returns pairs ordered by count descending, bounded by top_n (default 10).
 * Pairs where destination_ip is NULL on the server are excluded.
 *
 * @param topN    - Upper bound on results (default 10).
 * @param filter  - Optional LogsFilter facets so the pairs are scoped to the
 *   active filter (#667 WS4). The backend already accepts these facet params
 *   on GET /logs/top-pairs (#662). Omit to get the unfiltered top list.
 *
 * SECURITY (ADR-0029 D3): source_ip and destination_ip are attacker-controlled.
 * Callers MUST render them as text nodes only — never via dangerouslySetInnerHTML.
 */
export async function fetchTopPairs(
  topN: number = 10,
  filter: Partial<LogsFilter> = {},
): Promise<TopPairsRow[]> {
  const url = new URL(`${BASE_URL}/logs/top-pairs`, window.location.origin)
  url.searchParams.set('top_n', String(topN))
  // Filter facets — mirror the same params as fetchPaginatedLogs (#667 WS4).
  if (filter.source_type) url.searchParams.set('source_type', filter.source_type)
  if (filter.source_id) url.searchParams.set('source_id', filter.source_id)
  if (filter.category) url.searchParams.set('category', filter.category)
  if (filter.severity) url.searchParams.set('severity', filter.severity)
  if (filter.ip) url.searchParams.set('ip', filter.ip)
  if (filter.start) url.searchParams.set('start', filter.start)
  if (filter.end) url.searchParams.set('end', filter.end)
  if (filter.q) url.searchParams.set('q', filter.q)
  if (filter.action) url.searchParams.set('action', filter.action)
  if (filter.protocol) url.searchParams.set('protocol', filter.protocol)
  const res = await fetch(url.toString(), { method: 'GET', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<TopPairsRow[]>
}

/**
 * Fetch per-event cross-source timeline for one IP (DEF-1 / issue #118).
 * GET /threats/{ip}/events
 *
 * Returns null on 404 — the IP has no events.  The caller falls back to the
 * coarse score-derived timeline (OD-3 approved).
 *
 * SECURITY: label/payload are attacker-controlled — render as text nodes only.
 */
export async function fetchIpEvents(ip: string): Promise<IpEventTimelineResponse | null> {
  const res = await fetch(`${BASE_URL}/threats/${encodeURIComponent(ip)}/events`, {
    method: 'GET',
    headers: buildHeaders(),
  })
  if (res.status === 404) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<IpEventTimelineResponse>
}

/**
 * Fetch top source IPs by event count (ML-4, issue #432).
 * GET /logs/top-talkers?top_n=N
 *
 * Returns IPs ordered by count descending, bounded by top_n (default 10).
 *
 * SECURITY (ADR-0029 D3): source_ip is attacker-controlled.
 * Callers MUST render it as text nodes only — never via dangerouslySetInnerHTML.
 */
export async function fetchTopTalkers(topN: number = 10): Promise<TopTalkerRow[]> {
  const url = new URL(`${BASE_URL}/logs/top-talkers`, window.location.origin)
  url.searchParams.set('top_n', String(topN))
  const res = await fetch(url.toString(), { method: 'GET', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<TopTalkerRow[]>
}

/**
 * Fetch protocol mix (ML-4, issue #432).
 * GET /logs/protocol-mix?top_n=N
 *
 * Returns per-protocol event counts ordered by count descending.
 * NULL protocol rows (e.g. Azure WAF) appear as "(unknown)".
 *
 * SECURITY (ADR-0029 D3): protocol values are attacker-controlled telemetry.
 * Callers MUST render as text nodes only.
 */
export async function fetchProtocolMix(topN: number = 10): Promise<ProtocolMixRow[]> {
  const url = new URL(`${BASE_URL}/logs/protocol-mix`, window.location.origin)
  url.searchParams.set('top_n', String(topN))
  const res = await fetch(url.toString(), { method: 'GET', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<ProtocolMixRow[]>
}

/**
 * Fetch real filter-scoped totals for the Network Logs header strip (issue #663).
 * GET /logs/stats
 *
 * Returns total_events, blocked_events, distinct_ips, and present_source_types
 * computed from a full scope scan — NOT from any top-N list (fixes the
 * TrafficShapeHeader bug where totals were summed from the top-10 talkers only).
 *
 * Accepts optional filter params that mirror LogsFilter so the strip tiles
 * re-query with the active filter (WS4 — #667).
 *
 * Returns LogsStats. Throws ApiError on non-2xx.
 */
export async function fetchLogsStats(filter: Partial<LogsFilter> = {}): Promise<LogsStats> {
  const url = new URL(`${BASE_URL}/logs/stats`, window.location.origin)
  if (filter.source_type) url.searchParams.set('source_type', filter.source_type)
  if (filter.source_id) url.searchParams.set('source_id', filter.source_id)
  if (filter.category) url.searchParams.set('category', filter.category)
  if (filter.severity) url.searchParams.set('severity', filter.severity)
  if (filter.ip) url.searchParams.set('ip', filter.ip)
  if (filter.start) url.searchParams.set('start', filter.start)
  if (filter.end) url.searchParams.set('end', filter.end)
  if (filter.q) url.searchParams.set('q', filter.q)
  if (filter.action) url.searchParams.set('action', filter.action)
  if (filter.protocol) url.searchParams.set('protocol', filter.protocol)
  const res = await fetch(url.toString(), { method: 'GET', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<LogsStats>
}

/**
 * Fetch DGA-suspected DNS rows (ML-12, issue #440).
 * GET /logs/dga-suspects?top_n=N
 *
 * Returns DNS log rows whose dns_query scored above the local DGA heuristic
 * threshold (Shannon entropy + consonant ratio + digit ratio + label length +
 * unique-char ratio + no-vowel bonus).  Zero-egress: no DNS lookups or
 * external reputation calls.  Provenance: RULE (deterministic), not AI.
 *
 * Rows are ordered by dga_score descending.  Bounded by top_n (default 50).
 *
 * SECURITY (ADR-0029 D3): dns_query and source_ip are attacker-controlled.
 * Callers MUST render them as text nodes only — never via dangerouslySetInnerHTML.
 */
export async function fetchDgaSuspects(topN: number = 50): Promise<DgaSuspectRow[]> {
  const url = new URL(`${BASE_URL}/logs/dga-suspects`, window.location.origin)
  url.searchParams.set('top_n', String(topN))
  const res = await fetch(url.toString(), { method: 'GET', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<DgaSuspectRow[]>
}

/**
 * Fetch the entity graph (ML-8 / ML-9, issue #436/#437).
 * GET /logs/graph?max_nodes=N&max_edges=N[&filter params]
 *
 * Returns a bounded node+edge graph connecting source IPs, destination IPs,
 * ASNs, and attack categories.  The ``truncated`` flag indicates the response
 * was capped to the highest-weight subgraph.
 *
 * Returns null on 503 (event store unavailable — non-fatal).
 *
 * @param maxNodes - Maximum nodes in response (default 40, ADR-0061 D5).
 * @param maxEdges - Maximum edges in response (default 200).
 * @param filter   - Optional LogsFilter facets so the graph is scoped to the
 *   active filter (#667 WS4). The backend already accepts these facet params
 *   on GET /logs/graph (#662). Omit to get the unfiltered graph.
 *
 * SECURITY (ADR-0029 D3): node ids/labels from telemetry are attacker-controlled.
 * Callers MUST render them as text nodes only — never via dangerouslySetInnerHTML.
 */
export async function fetchEntityGraph(
  maxNodes: number = 40,   // ADR-0061 D5: tighter default cap for unfiltered view (was 200)
  maxEdges: number = 200,
  filter: Partial<LogsFilter> = {},
): Promise<EntityGraphResponse | null> {
  const url = new URL(`${BASE_URL}/logs/graph`, window.location.origin)
  url.searchParams.set('max_nodes', String(maxNodes))
  url.searchParams.set('max_edges', String(maxEdges))
  // Filter facets — mirror the same params as fetchPaginatedLogs (#667 WS4).
  if (filter.source_type) url.searchParams.set('source_type', filter.source_type)
  if (filter.source_id) url.searchParams.set('source_id', filter.source_id)
  if (filter.category) url.searchParams.set('category', filter.category)
  if (filter.severity) url.searchParams.set('severity', filter.severity)
  if (filter.ip) url.searchParams.set('ip', filter.ip)
  if (filter.start) url.searchParams.set('start', filter.start)
  if (filter.end) url.searchParams.set('end', filter.end)
  if (filter.q) url.searchParams.set('q', filter.q)
  if (filter.action) url.searchParams.set('action', filter.action)
  if (filter.protocol) url.searchParams.set('protocol', filter.protocol)
  const res = await fetch(url.toString(), { method: 'GET', headers: buildHeaders() })
  if (res.status === 503) return null
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<EntityGraphResponse>
}

/**
 * Fetch top JA4 TLS fingerprints by event count (ML-13, issue #441).
 * GET /logs/top-ja4?top_n=N
 *
 * Consume-only: only rows where the sensor populated tls_ja4 appear.
 * An empty list means all rows have NULL tls_ja4 (sensor did not emit JA4) —
 * honest absence, not an error. The facet should degrade gracefully to hidden.
 *
 * Returns fingerprints ordered by count descending, bounded by top_n (default 10).
 *
 * SECURITY (ADR-0029 D3): tls_ja4 is sensor-normalised from attacker-controlled
 * TLS traffic. Callers MUST render as text nodes only.
 */
export async function fetchTopJa4(topN: number = 10): Promise<Ja4FingerprintRow[]> {
  const url = new URL(`${BASE_URL}/logs/top-ja4`, window.location.origin)
  url.searchParams.set('top_n', String(topN))
  const res = await fetch(url.toString(), { method: 'GET', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<Ja4FingerprintRow[]>
}

/**
 * POST /logs/nl-query — parse a natural-language query into a FilterSpec (ML-6 / ADR-0049).
 *
 * Sends the analyst's NL query to the local LLM (zero-egress, EARS-5).
 * The response carries:
 *   - ``filter_spec``  — the validated FilterSpec (only non-null fields).
 *   - ``degraded``     — true when the parse fell back to q= free-text (EARS-2).
 *   - ``provenance``   — "ai" on success, "ai_degraded" on fallback (EARS-3).
 *   - ``error``        — optional diagnostic string; null on success.
 *
 * Always returns a NlQueryResponse (HTTP 200) — degradation is a data-level
 * concern, not an HTTP error.  Throws ApiError on 503 (config store absent)
 * or 422 (malformed request).
 *
 * SECURITY (ADR-0049 / OWASP LLM01): the returned filter_spec has already been
 * validated server-side against the strict allowlist.  The caller applies it
 * directly as filter chips — safe because OOV/hallucinated fields were rejected.
 *
 * @param query - The analyst's natural-language query string.
 * @param model - Optional model name override (uses server config default when omitted).
 */
export async function fetchNlQuery(
  query: string,
  model?: string,
): Promise<NlQueryResponse> {
  const res = await fetch(`${BASE_URL}/logs/nl-query`, {
    method: 'POST',
    headers: buildHeaders(),
    body: JSON.stringify({ query, ...(model ? { model } : {}) }),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<NlQueryResponse>
}

/**
 * Fetch a short local-LLM narration for one IP (ML-7, issue #435).
 * GET /threats/{ip}/narration[?ai=false]
 *
 * Returns a NarrationResult grounded ONLY in the IP's real collected fields.
 * Anti-fabrication (EARS-3): absent/null dimensions are never asserted.
 *
 * @param ip - The IP address to narrate.
 * @param includeAi - When false, skips the LLM entirely and returns a rule-only
 *   summary (ai_status='skipped' | 'unavailable', provenance='rule').
 *   Default: true (calls the local model when online).
 *
 * SECURITY (ADR-0029 D3): narrative is LLM-authored text.
 * Callers MUST render it as a text node ONLY — never dangerouslySetInnerHTML.
 */
export async function fetchNarration(
  ip: string,
  includeAi: boolean = true,
): Promise<NarrationResult> {
  const url = new URL(
    `${BASE_URL}/threats/${encodeURIComponent(ip)}/narration`,
    window.location.origin,
  )
  if (!includeAi) {
    url.searchParams.set('ai', 'false')
  }
  const res = await fetch(url.toString(), { method: 'GET', headers: buildHeaders() })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<NarrationResult>
}
