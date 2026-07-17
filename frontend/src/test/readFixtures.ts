/**
 * Test fixtures for the read/query API (ADR-0029).
 *
 * All IP addresses use RFC 5737 documentation ranges (192.0.2.0/24).
 * No real or production IPs in test fixtures.
 */

import type {
  StatsResponse,
  HealthResponse,
  ThreatScore,
  TimelineBucket,
  CategoryCount,
  LogEntry,
  PaginatedLogs,
  DetailedAnalysis,
  RuleDescription,
  GeoPoint,
  AnalyticsSummary,
  CategoryTimelineBucket,
  SourceInstance,
  TestResult,
  SyncResult,
  IpEventTimelineResponse,
  AutoSyncState,
} from '../api/types'

/** GET /stats fixture — typical operational state. */
export const STATS_FIXTURE: StatsResponse = {
  total_logs: 4815,
  total_ips: 23,
  blocked_percentage: 62.3,
  source_health: [
    {
      source_id: 'suricata-1',
      source_type: 'suricata',
      display_name: 'Suricata',
      flavor: 'pull',
      health: 'ok',
      supervisor_state: null,
      last_event_at: '2026-06-04T10:00:00Z',
      event_count: 4815,
      last_error: null,
    },
  ],
  last_updated: '2026-06-04T10:00:00Z',
}

/** GET /stats fixture — zero events (empty state). */
export const STATS_EMPTY_FIXTURE: StatsResponse = {
  total_logs: 0,
  total_ips: 0,
  blocked_percentage: 0,
  source_health: [],
  last_updated: null,
}

/** GET /health fixture — AI online (ADR-0066 tri-state: ai='active'). */
export const HEALTH_AI_ONLINE: HealthResponse = {
  status: 'ok',
  ollama_connected: true,
  ollama_model: 'llama3.2',
  db_ok: true,
  ai: 'active',
}

/**
 * GET /health fixture — AI unreachable (ADR-0066 tri-state: ai='unreachable', the
 * FAULT state — attention-worthy, not the neutral "off by choice" state). Named
 * "OFFLINE" for historical continuity with pre-#41 tests that used it to mean
 * "not connected"; semantically this is the fault/unreachable bucket. Use
 * HEALTH_AI_DISABLED below for the deliberate-choice ("off") state.
 */
export const HEALTH_AI_OFFLINE: HealthResponse = {
  status: 'ok',
  ollama_connected: false,
  ollama_model: null,
  db_ok: true,
  ai: 'unreachable',
}

/**
 * GET /health fixture — AI off BY CHOICE (ADR-0066 tri-state: ai='disabled').
 * The operator turned AI off; nothing is wrong — neutral, non-alarming presentation.
 */
export const HEALTH_AI_DISABLED: HealthResponse = {
  status: 'ok',
  ollama_connected: false,
  ollama_model: null,
  db_ok: true,
  ai: 'disabled',
}

/** GET /threats fixture — two IPs, one with AI active, one degraded. */
export const THREATS_FIXTURE: ThreatScore[] = [
  {
    source_ip: '192.0.2.1',
    threat_level: 'HIGH',
    score: 78,
    total_events: 120,
    blocked_events: 95,
    attack_types: ['SQL Injection', 'Scanner'],
    first_seen: '2026-06-01T08:00:00Z',
    last_seen: '2026-06-04T09:55:00Z',
    source_types: ['suricata'],
    detections: [],
    ai_insights: ['Intent: reconnaissance scanning', 'Risk: lateral movement attempt'],
    ai_confidence: 0.87,
    ai_status: 'active',
    location: 'Chicago, United States',
    score_breakdown: [],
    asn: null,
    as_name: null,
    score_delta: 22,
  },
  {
    source_ip: '192.0.2.2',
    threat_level: 'MEDIUM',
    score: 44,
    total_events: 30,
    blocked_events: 12,
    attack_types: ['Brute Force'],
    first_seen: '2026-06-03T14:00:00Z',
    last_seen: '2026-06-04T09:50:00Z',
    source_types: ['suricata'],
    detections: [],
    ai_insights: null,
    ai_confidence: null,
    ai_status: 'unavailable',
    location: null,
    score_breakdown: [],
    asn: null,
    as_name: null,
    score_delta: null,
  },
]

/**
 * GET /threats fixture — correlated IP seen by BOTH Suricata and Azure WAF.
 * This is the MC.3 correlation proof: source_types: ["azure_waf","suricata"].
 * RFC 5737 doc IP only.
 */
export const THREATS_CORRELATED_FIXTURE: ThreatScore[] = [
  {
    source_ip: '192.0.2.50',
    threat_level: 'CRITICAL',
    score: 92,
    total_events: 240,
    blocked_events: 210,
    attack_types: ['SQL Injection', 'Scanner'],
    first_seen: '2026-06-04T06:00:00Z',
    last_seen: '2026-06-04T10:00:00Z',
    source_types: ['azure_waf', 'suricata'],
    detections: [],
    ai_insights: ['Intent: exfiltration', 'Risk: confirmed attacker'],
    ai_confidence: 0.95,
    ai_status: 'active',
    location: 'London, United Kingdom',
    score_breakdown: [],
    asn: null,
    as_name: null,
    score_delta: 38,
  },
]

/** GET /threats fixture — all IPs with AI unavailable (rule-only). */
export const THREATS_AI_UNAVAILABLE_FIXTURE: ThreatScore[] = [
  {
    source_ip: '192.0.2.10',
    threat_level: 'LOW',
    score: 15,
    total_events: 8,
    blocked_events: 2,
    attack_types: ['Port Scan'],
    first_seen: '2026-06-04T06:00:00Z',
    last_seen: '2026-06-04T07:00:00Z',
    source_types: ['suricata'],
    detections: [],
    ai_insights: null,
    ai_confidence: null,
    ai_status: 'unavailable',
    location: null,
    score_breakdown: [],
    asn: null,
    as_name: null,
    score_delta: null,
  },
]

/** GET /logs/timeline fixture — 4 hourly buckets. */
export const TIMELINE_FIXTURE: TimelineBucket[] = [
  { hour: '2026-06-04T06:00:00Z', total: 120, blocked: 80, granularity: 'hourly' },
  { hour: '2026-06-04T07:00:00Z', total: 200, blocked: 140, granularity: 'hourly' },
  { hour: '2026-06-04T08:00:00Z', total: 95, blocked: 60, granularity: 'hourly' },
  { hour: '2026-06-04T09:00:00Z', total: 310, blocked: 200, granularity: 'hourly' },
]

/** GET /logs/categories fixture — multiple categories. */
export const CATEGORIES_FIXTURE: CategoryCount[] = [
  { category: 'SQL Injection', count: 980, source_type: 'suricata' },
  { category: 'Port Scan', count: 1240, source_type: 'suricata' },
  { category: 'Brute Force', count: 620, source_type: 'suricata' },
  { category: 'Malware', count: 310, source_type: 'suricata' },
]

// ---------------------------------------------------------------------------
// MB.6 fixtures
// ---------------------------------------------------------------------------

/**
 * RFC 5737 doc IPs only — 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
 * No real production IPs in test data.
 */
export const LOG_ENTRY_FIXTURE: LogEntry = {
  id: 1,
  timestamp: '2026-06-04T10:00:00Z',
  source_type: 'suricata',
  source_id: 'suricata-1',
  source_ip: '192.0.2.1',
  destination_ip: '198.51.100.1',
  category: 'SQL Injection',
  severity: 'high',
  action: 'blocked',
  raw_log: '{"event_type":"alert","src_ip":"192.0.2.1"}',
}

/**
 * XSS test fixture — raw_log contains HTML/script markup.
 * The render layer MUST display it as literal text, NOT as DOM/script.
 * This is the attacker-controlled boundary documented in ADR-0029 D3.
 */
export const LOG_ENTRY_XSS_FIXTURE: LogEntry = {
  id: 2,
  timestamp: '2026-06-04T10:01:00Z',
  source_type: 'suricata',
  source_id: 'suricata-1',
  source_ip: '192.0.2.2',
  destination_ip: null,
  category: '<script>alert("xss")</script>',
  severity: '<img src=x onerror=alert(1)>',
  action: null,
  raw_log: '<script>alert("xss-in-raw-log")</script>',
}

/** GET /logs/paginated fixture — first page with two rows and a next_cursor. */
export const PAGINATED_LOGS_PAGE1: PaginatedLogs = {
  logs: [LOG_ENTRY_FIXTURE, LOG_ENTRY_XSS_FIXTURE],
  next_cursor: '2026-06-04T10:01:00|2',
  has_more: true,
  total_matching: 1287,
}

/** GET /logs/paginated fixture — last page (has_more=false, no next_cursor). */
export const PAGINATED_LOGS_LAST_PAGE: PaginatedLogs = {
  logs: [
    {
      id: 100,
      timestamp: '2026-06-04T09:00:00Z',
      source_type: 'suricata',
      source_id: 'suricata-1',
      source_ip: '203.0.113.5',
      destination_ip: null,
      category: 'Port Scan',
      severity: 'low',
      action: 'allowed',
      raw_log: '{"event_type":"alert","src_ip":"203.0.113.5"}',
    },
  ],
  next_cursor: null,
  has_more: false,
  total_matching: 1287,
}

/** GET /logs/paginated fixture — empty result (no matching events). */
export const PAGINATED_LOGS_EMPTY: PaginatedLogs = {
  logs: [],
  next_cursor: null,
  has_more: false,
  total_matching: 0,
}

/**
 * GET /threats/{ip}/detailed fixture — AI-active path (analysis + ai_insights present).
 * Mirrors the shape the AI path populates.
 */
export const DETAILED_ANALYSIS_FIXTURE: DetailedAnalysis = {
  source_ip: '192.0.2.1',
  threat_level: 'HIGH',
  score: 78,
  total_events: 120,
  blocked_events: 95,
  attack_types: ['SQL Injection', 'Scanner'],
  first_seen: '2026-06-01T08:00:00Z',
  last_seen: '2026-06-04T09:55:00Z',
  source_types: ['suricata'],
  detections: [],
  ai_insights: ['Intent: reconnaissance', 'Risk: lateral movement'],
  ai_confidence: 0.87,
  ai_status: 'active',
  analysis: 'This IP shows aggressive SQL injection probing across multiple endpoints.',
  mitre_techniques: ['T1190', 'T1595'],
  executive_summary: 'The threat actor initiated SQL injection attacks targeting the /api/users endpoint.',
  attack_progression: [
    'Step 1: Probed /api/users with SQL injection payload.',
    'Step 2: Reiterated the attack confirming the exploit path.',
  ],
  recommended_action: 'block',
  intent: 'Likely aims to exfiltrate user data via SQL injection.',
  ioc_indicators: ['IP: 192.0.2.1', 'Payload: id=1 OR 1=1', 'Rule: 942100'],
  insights: {
    patterns: ['Classic OR 1=1 injection technique.'],
    risks: ['Potential user data compromise.'],
    mitigations: ['Block payloads with SQL injection patterns.'],
  },
  attack_stage: 'exploitation',
  confidence: 0.87,
  false_positive_likelihood: 0.1,
}

/**
 * GET /threats/{ip}/detailed fixture — rules-only path (AI disabled).
 * Shape verified against live endpoint: curl http://127.0.0.1:8000/threats/198.51.100.50/detailed
 * When ai_status="disabled", the AI fields (analysis, ai_insights, mitre_techniques) are absent,
 * but structured fields (executive_summary, attack_progression, etc.) come from the scoring layer.
 */
export const DETAILED_ANALYSIS_RULES_ONLY_FIXTURE: DetailedAnalysis = {
  source_ip: '192.0.2.10',
  threat_level: 'HIGH',
  score: 52,
  total_events: 4,
  blocked_events: 2,
  attack_types: ['sql_injection'],
  first_seen: '2026-06-05T13:00:00Z',
  last_seen: '2026-06-05T18:00:00Z',
  source_types: ['azure_waf'],
  detections: [],
  ai_insights: null,
  ai_confidence: null,
  ai_status: 'disabled',
  analysis: null,
  mitre_techniques: null,
  executive_summary:
    'The threat actor initiated two SQL injection attacks targeting the /api/users endpoint.',
  attack_progression: [
    'Step 1: Probed the /api/users endpoint with SQL injection payload.',
    'Step 2: Reiterated the attack with identical payload structure.',
    'Step 3: No further escalation observed.',
  ],
  recommended_action: 'block',
  intent: 'Likely aims to compromise application security via SQL injection.',
  ioc_indicators: ['IP Address: 192.0.2.10', 'Payload: id=1%20OR%201%3D1', 'Rule Triggered: 942100'],
  insights: {
    patterns: ['Use of classic SQL injection technique (OR 1=1).'],
    risks: ['Potential compromise of user data.'],
    mitigations: ['Implement WAF rules to block SQL injection patterns.'],
  },
  attack_stage: 'exploitation',
  confidence: 0.85,
  false_positive_likelihood: 0.2,
}

/**
 * GET /threats/{ip}/detailed fixture — correlated IP (both sources).
 * Used by MC.3 correlation-UI tests (IpDrilldownModal provenance badges).
 */
export const DETAILED_ANALYSIS_CORRELATED_FIXTURE: DetailedAnalysis = {
  source_ip: '192.0.2.50',
  threat_level: 'CRITICAL',
  score: 92,
  total_events: 240,
  blocked_events: 210,
  attack_types: ['SQL Injection', 'Scanner'],
  first_seen: '2026-06-04T06:00:00Z',
  last_seen: '2026-06-04T10:00:00Z',
  source_types: ['azure_waf', 'suricata'],
  detections: [],
  ai_insights: ['Intent: exfiltration', 'Risk: confirmed attacker'],
  ai_confidence: 0.95,
  ai_status: 'active',
  analysis: 'This IP was observed by both Azure WAF and Suricata with overlapping attack patterns.',
  mitre_techniques: ['T1190', 'T1595'],
}

/** GET /rules fixture. */
export const RULES_FIXTURE: RuleDescription[] = [
  {
    rule_id: 2001219,
    name: 'ET SCAN Potential VNC Scan',
    description: 'Detects potential VNC scanning activity.',
    severity: 'medium',
    category: 'Port Scan',
    source_type: 'suricata',
  },
  {
    rule_id: 2006546,
    name: 'ET EXPLOIT MS-SQL xp_cmdshell Exec',
    description: 'Detects SQL Server xp_cmdshell execution.',
    severity: 'high',
    category: 'SQL Injection',
    source_type: 'suricata',
  },
]

/**
 * GET /analytics/geo fixture — RFC 5737 IPs only.
 *
 * Shape matches the REAL API response from store.get_analytics_geo() (fix #178):
 *   ip, country, city, lat, lon, total_events, blocked, rules_triggered.
 * `count` was the wrong field name — it does not exist in the API response.
 *
 * Issue #532 additive fields: asn, as_name, ip_class — now part of the response.
 * Older API responses without these fields are still valid (all optional).
 */
export const GEO_FIXTURE: GeoPoint[] = [
  {
    lat: 40.7128,
    lon: -74.006,
    total_events: 450,
    blocked: 320,
    rules_triggered: 5,
    ip: '192.0.2.1',
    city: 'New York',
    country: 'US',
    asn: 16509,
    as_name: 'Amazon',
    ip_class: 'datacenter',
  },
  {
    lat: 51.5074,
    lon: -0.1278,
    total_events: 120,
    blocked: 85,
    rules_triggered: 3,
    ip: '198.51.100.1',
    city: 'London',
    country: 'GB',
    asn: 7922,
    as_name: 'Comcast Cable',
    ip_class: 'residential',
  },
]

/**
 * GET /analytics/summary fixture.
 *
 * Matches the REAL store.get_analytics_summary() output shape
 * (ADR-0029 D1 / sqlite_store.py::get_analytics_summary):
 *   total_ips, total_events, total_blocked, block_rate,
 *   top_country, unique_countries, top_rule.
 *
 * RFC 5737 IPs used throughout; no real production IPs.
 */
export const ANALYTICS_SUMMARY_FIXTURE: AnalyticsSummary = {
  total_ips: 23,
  total_events: 4815,
  total_blocked: 3000,
  block_rate: 62.3,
  top_country: 'US',
  unique_countries: 12,
  // String per verified contract (rule_id TEXT in SQLite, fix #82).
  top_rule: '2001219',
}

/** GET /analytics/summary fixture — empty state (no data in store). */
export const ANALYTICS_SUMMARY_EMPTY_FIXTURE: AnalyticsSummary = {
  total_ips: 0,
  total_events: 0,
  total_blocked: 0,
  block_rate: 0,
  top_country: 'Unknown',
  unique_countries: 0,
  top_rule: '',
}

/**
 * GET /analytics/categories-timeline fixture.
 *
 * Shape verified against the REAL API response (fix #93):
 * the server returns wide/pivoted rows — one row per time period, with each
 * attack category as a named numeric column.
 *
 * Real response sample (curl http://127.0.0.1:8000/analytics/categories-timeline):
 *   [{"period":"2026-06-05","sqli":3,"xss":0,"bot":0,"ratelimit":0,"geo":0,
 *     "lfi":0,"ids_alert":2,"total":7,"granularity":"daily"}]
 */
export const CATEGORIES_TIMELINE_FIXTURE: CategoryTimelineBucket[] = [
  {
    period: '2026-06-04',
    sqli: 3,
    xss: 1,
    bot: 0,
    ratelimit: 0,
    geo: 0,
    lfi: 0,
    ids_alert: 2,
    total: 6,
    granularity: 'daily',
  },
  {
    period: '2026-06-05',
    sqli: 5,
    xss: 0,
    bot: 2,
    ratelimit: 1,
    geo: 0,
    lfi: 0,
    ids_alert: 4,
    total: 12,
    granularity: 'daily',
  },
]

/**
 * GET /sources fixture — one Suricata instance in 'running' state.
 *
 * D1 fix (issue #195): uses the REAL GET /sources DTO field names:
 *   source_type (not type_key), state (not status), last_success_at (not last_event_at).
 * The old fields (type_key, status, last_event_at, error_message) do NOT exist in the
 * real API response and MUST NOT be used here.
 */
export const SOURCES_FIXTURE: SourceInstance[] = [
  {
    source_type: 'suricata',          // real field (was type_key)
    source_id: 'suricata-1',
    flavor: 'pull',
    state: 'running',                  // real field (was status)
    attempt: 0,
    total_crashes: 0,
    total_dlq: 0,
    dropped_count: 0,
    last_success_at: '2026-06-04T10:00:00Z',  // real field (was last_event_at)
    event_count: 4815,
    // NO type_key, NO status, NO last_event_at, NO error_message
  },
]

/**
 * GET /sources fixture — instance in 'backoff' state.
 * Uses real DTO fields — no error_message in the real DTO.
 */
export const SOURCES_BACKOFF_FIXTURE: SourceInstance[] = [
  {
    source_type: 'suricata',
    source_id: 'suricata-1',
    flavor: 'pull',
    state: 'backoff',
    attempt: 3,
    total_crashes: 2,
    total_dlq: 0,
    dropped_count: 0,
    last_success_at: '2026-06-04T09:00:00Z',
    event_count: 4800,
  },
]

/** POST /sources/suricata/test success fixture. */
export const TEST_RESULT_OK: TestResult = {
  ok: true,
  message: 'Connection OK. eve.json size: 24 MB, last modified 5 min ago.',
  detail: { file_size_bytes: 25165824, last_modified: '2026-06-04T09:55:00Z' },
}

/** POST /sources/suricata/test failure fixture. */
export const TEST_RESULT_FAIL: TestResult = {
  ok: false,
  message: 'SSH connection refused: port 22 not reachable.',
  detail: null,
}

/** POST /sync/suricata success fixture. */
export const SYNC_RESULT_OK: SyncResult = {
  ok: true,
  message: 'Sync complete.',
  events_ingested: 127,
}

/**
 * POST /sync/suricata success fixture — 0 events ingested.
 *
 * This is the expected healthy result when the watermark-incremental pull
 * finds no new alert records (Suricata only writes event_type:alert on rule
 * matches; Azure WAF similarly only logs on detection-mode hits).
 * Used by EARS-1 (issue #744): the UI must show a reassuring message, not
 * an ambiguous "0 events ingested".
 */
export const SYNC_RESULT_ZERO: SyncResult = {
  ok: true,
  message: 'Sync complete.',
  events_ingested: 0,
}

// ---------------------------------------------------------------------------
// ADR-0031 — Auto-sync fixtures (GET/PUT /sources/{type_key}/auto-sync)
// ---------------------------------------------------------------------------

/** GET /sources/suricata/auto-sync — auto-sync disabled (no _instances entry). */
export const AUTOSYNC_DISABLED: AutoSyncState = {
  enabled: false,
  interval_seconds: 300,
  source_id: 'suricata',
  last_sync: {
    last_sync_at: null,
    last_sync_ingested: 0,
    last_sync_status: null,
    last_error: null,
  },
}

/** GET /sources/suricata/auto-sync — auto-sync enabled at 5-minute interval. */
export const AUTOSYNC_ENABLED: AutoSyncState = {
  enabled: true,
  interval_seconds: 300,
  source_id: 'suricata',
  last_sync: {
    last_sync_at: '2026-06-04T10:00:00Z',
    last_sync_ingested: 127,
    last_sync_status: 'ok',
    last_error: null,
  },
}

/** GET /sources/suricata/auto-sync — auto-sync on, last cycle errored. */
export const AUTOSYNC_ERROR: AutoSyncState = {
  enabled: true,
  interval_seconds: 300,
  source_id: 'suricata',
  last_sync: {
    last_sync_at: '2026-06-04T09:50:00Z',
    last_sync_ingested: 0,
    last_sync_status: 'error',
    last_error: 'SSH connection timed out',
  },
}

/** PUT /sources/suricata/auto-sync response — enabled with 600s interval. */
export const AUTOSYNC_ENABLE_RESPONSE: AutoSyncState = {
  enabled: true,
  interval_seconds: 600,
  source_id: 'suricata',
  last_sync: {
    last_sync_at: null,
    last_sync_ingested: 0,
    last_sync_status: null,
    last_error: null,
  },
}

/** PUT /sources/suricata/auto-sync response — disabled (returns persisted interval). */
export const AUTOSYNC_DISABLE_RESPONSE: AutoSyncState = {
  enabled: false,
  interval_seconds: 300,
  source_id: 'suricata',
  last_sync: {
    last_sync_at: '2026-06-04T10:00:00Z',
    last_sync_ingested: 127,
    last_sync_status: 'ok',
    last_error: null,
  },
}

// ---------------------------------------------------------------------------
// DEF-1 — Per-IP event timeline fixtures (GET /threats/{ip}/events)
// Mirrors IPEventTimelineResponse from packages/firewatch-api/src/firewatch_api/schemas.py
// ---------------------------------------------------------------------------

/**
 * GET /threats/{ip}/events fixture — single source, not correlated.
 * Represents a Suricata-only IP with 2 timeline events.
 */
export const IP_EVENTS_SINGLE_SOURCE_FIXTURE: IpEventTimelineResponse = {
  events: [
    {
      source: 'suricata',
      time: '2026-06-04T08:00:00Z',
      label: '2001219',
      payload: 'GET /api/users?id=1 OR 1=1',
      correlated: false,
      action: 'BLOCK',
      severity: 'high',
      category: 'SQL Injection',
    },
    {
      source: 'suricata',
      time: '2026-06-04T09:00:00Z',
      label: '2006546',
      payload: null,
      correlated: false,
      action: 'ALERT',
      severity: 'medium',
      category: 'Port Scan',
    },
  ],
  total: 2,
  correlated: false,
  source_types: ['suricata'],
  capped: false,
}

/**
 * GET /threats/{ip}/events fixture — multi-source correlated.
 * Represents an IP seen by both Azure WAF and Suricata.
 * All entries have correlated=true, triggering the orange stripe.
 */
export const IP_EVENTS_CORRELATED_FIXTURE: IpEventTimelineResponse = {
  events: [
    {
      source: 'azure_waf',
      time: '2026-06-04T06:00:00Z',
      label: '942100',
      payload: 'id=1%20OR%201%3D1',
      correlated: true,
      action: 'BLOCK',
      severity: 'high',
      category: 'sql_injection',
    },
    {
      source: 'suricata',
      time: '2026-06-04T07:00:00Z',
      label: '2001219',
      payload: null,
      correlated: true,
      action: 'ALERT',
      severity: 'medium',
      category: 'Port Scan',
    },
  ],
  total: 2,
  correlated: true,
  source_types: ['azure_waf', 'suricata'],
  capped: false,
}

/**
 * GET /threats/{ip}/events fixture — result capped at limit.
 * Simulates a high-volume IP where the backend returned capped=true.
 */
export const IP_EVENTS_CAPPED_FIXTURE: IpEventTimelineResponse = {
  events: [
    {
      source: 'suricata',
      time: '2026-06-04T08:00:00Z',
      label: '2001219',
      payload: null,
      correlated: false,
      action: 'BLOCK',
      severity: 'high',
      category: 'SQL Injection',
    },
  ],
  total: 1,
  correlated: false,
  source_types: ['suricata'],
  capped: true,
}
