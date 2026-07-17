/**
 * TypeScript types for the FireWatch read/query API.
 *
 * Mirrors the response shapes defined in ADR-0029:
 *   - ThreatScore    (D3) — returned by GET /threats and GET /threats/{ip}
 *   - StatsResponse  (D1) — returned by GET /stats
 *   - HealthResponse (D1) — returned by GET /health
 *   - TimelineBucket (D1) — one element in GET /logs/timeline
 *   - CategoryCount  (D1) — one element in GET /logs/categories
 *   - LogEntry       (D2) — one row in the paginated logs envelope
 *   - PaginatedLogs  (D2) — cursor-pagination envelope from GET /logs/paginated
 *   - DetailedAnalysis (D3) — from GET /threats/{ip}/detailed
 *   - RuleDescription  (D1) — one entry from GET /rules
 *   - GeoPoint       (D1) — one entry from GET /analytics/geo
 *   - AnalyticsSummary (D1) — from GET /analytics/summary
 *   - CategoryTimelineBucket (D1) — from GET /analytics/categories-timeline
 *   - SourceInstance (MB.4) — from GET /sources
 *   - TestResult     (MB.4) — from POST /sources/{type_key}/test
 *   - SyncResult     (MB.4) — from POST /sync/{type_key}
 *
 * SECURITY (ADR-0029 D3): raw_log / native event fields are attacker-controlled.
 * They are typed as `unknown` to force explicit handling at the render layer.
 * Consumers MUST render them as text nodes — never via dangerouslySetInnerHTML.
 */

/**
 * One additive factor in a threat score breakdown (ADR-0036 D4, issue #209).
 *
 * ``factor`` is a machine-readable key (e.g. "brute_force", "ai_boost", "cap").
 * ``label``  is a human-readable string safe to render as a text node.
 * ``points`` is the integer contribution; may be negative for the "cap" item
 *            which records the reduction when the raw sum exceeded 100.
 *
 * The ``points`` values across all items sum to the final ``score``.
 */
export interface ScoreBreakdownItem {
  factor: string
  label: string
  points: number
}

/**
 * Per-analysis ai_status values (ADR-0066 Layer 2 — the analog of ECS `event.outcome`,
 * extended with *why-not-attempted*). ONE closed vocabulary across both pipeline paths:
 *   "active"      — the AI engine analyzed this and produced a verdict (success).
 *   "disabled"    — AI is turned off in config; rules scored this (choice, operator).
 *   "skipped"     — this request asked for rules-only, ?ai=false (choice, caller).
 *   "no_input"    — there was nothing to send to the AI; rules scored this (non-event).
 *   "unavailable" — AI was wanted but the engine failed/was unreachable
 *                   (fault — the only state that means "go fix something").
 * The server MUST NOT claim success when the engine was not called (ADR-0035).
 * Open union (| string): unrecognized future values degrade to the neutral
 * "did not run" treatment at every render site — never assumed to be a fault.
 *
 * NOTE: this is a DIFFERENT vocabulary from the `/health` `ai` field
 * (see `HealthAiStatus` below) — that layer's fault word is "unreachable", not
 * "unavailable". Do not conflate the two when reading `HealthResponse.ai`.
 */
export type AiStatus =
  | 'active'
  | 'unavailable'
  | 'disabled'
  | 'error'
  | 'skipped'
  | 'no_input'
  | string

/**
 * `/health` `ai` field — ADR-0066 Layer 1 engine (administrative vs operational) state,
 * mirroring RFC 2863's `ifAdminStatus`/`ifOperStatus` split:
 *   "active"      — AI is on and the engine answered the probe.
 *   "disabled"    — AI is off because the operator turned it off — nothing is wrong.
 *   "unreachable" — AI is on but the engine cannot be reached — go fix something.
 * This is the ONLY vocabulary the global AI-status chip should key off of; the
 * per-analysis `AiStatus` (Layer 2, above) drives per-row/per-analysis labels only.
 * Open union (| string): unrecognized future values degrade to the neutral "did not
 * run" treatment (never assumed to be a fault) — see `resolveHealthAiState`.
 */
export type HealthAiStatus = 'active' | 'disabled' | 'unreachable' | string

/**
 * Threat level vocabulary (ADR-0024 canonical values).
 */
export type ThreatLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string

/**
 * Escalation verdict sub-object on ThreatScore (ADR-0058 D2/D3; ADR-0067 D1/D2).
 *
 * Produced by the deterministic escalation decider (no LLM) and attached to
 * ThreatScore.escalation by pipeline.analyze_ip.  All fields are required when
 * the sub-object is present; the sub-object itself is optional/null (additive
 * field — absent when the decider has not run or returned no verdict).
 *
 * ``tier``               — 1-4 per the ADR-0058 §4a table (lower = louder/more urgent),
 *                          or ``null`` for the ADR-0067 D2 **observed** stratum — "on
 *                          the record, no escalation claim." Deliberately NOT a fifth
 *                          tier (a numeric 5 would force a false ordering against Tier
 *                          4). Every consumer that compares ``tier`` MUST null-guard
 *                          first — in JavaScript ``null <= 2`` is ``true`` (null
 *                          coerces to 0), so an unguarded comparison silently re-admits
 *                          every observed actor (see ``triageBand.ts``).
 * ``disposition``        — machine-readable action label:
 *                          "allowed_through" | "block_status_unknown" |
 *                          "blocked_persistent" | "blocked_one_off" | "observed".
 *                          "observed" (ADR-0067 D2, additive) always pairs with
 *                          ``tier: null`` — anchors OCSF ``action_id=3 Observed``.
 * ``justification``      — RULE-tagged (ADR-0035) human-readable sentence safe to render
 *                          as a text node (e.g. "[RULE] sqli_rule matched, and the request
 *                          got through — this may have reached your system").
 *                          SECURITY (ADR-0029 D3): may contain operator-rule-derived
 *                          attacker field references — MUST be rendered as a text node,
 *                          never via dangerouslySetInnerHTML.
 * ``block_status``       — explicit, non-fabricated state:
 *                          "blocked" | "allowed" | "unknown" | "partial".
 *                          "partial" = actor has events in more than one terminal
 *                          disposition (ADR-0058 Amendment 1 A1). Meaning is unchanged
 *                          by ADR-0067 — an observed verdict still carries its truthful
 *                          ``block_status``.
 * ``disposition_counts`` — structured per-class event counts when block_status is
 *                          "partial" (ADR-0058 Amendment 1 A2). Absent on older
 *                          API responses; default to zeros when missing. Integer
 *                          counts — the frontend formats the label (glass-box, i18n-safe).
 */
export interface EscalationVerdict {
  /**
   * 1-4; Tier 1 = loudest (allowed-through + detection). ``null`` = the
   * observed stratum (ADR-0067 D2) — no escalation claim was made. Null-guard
   * before any numeric comparison (``tier != null && tier <= 2``, never bare
   * ``tier <= 2`` — see the module doc above).
   */
  tier: number | null
  /** Machine-readable disposition key. */
  disposition:
    | 'allowed_through'
    | 'block_status_unknown'
    | 'blocked_persistent'
    | 'blocked_one_off'
    | 'observed'
    | string
  /**
   * RULE-tagged justification string (ADR-0035).
   * SECURITY (ADR-0029 D3): render as a text node only — never via dangerouslySetInnerHTML.
   */
  justification: string
  /**
   * Explicit block state: "blocked" | "allowed" | "unknown" | "partial".
   * "partial" means the actor's events span more than one terminal disposition
   * (ADR-0058 Amendment 1 A1). Widened from the original 3-value set.
   */
  block_status: 'blocked' | 'allowed' | 'unknown' | 'partial' | string
  /**
   * Per-class event counts; present when block_status === "partial"
   * (ADR-0058 Amendment 1 A2). Additive — absent on older API responses;
   * gracefully absent when block_status is not "partial".
   *
   * ``blocked``       — events with a confirmed BLOCK/DROP action.
   * ``alert_unknown`` — events from IDS ALERT or WAF detection-mode (disposition unknown).
   * ``allowed``       — events with a confirmed ALLOW action.
   */
  disposition_counts?: {
    blocked: number
    alert_unknown: number
    allowed: number
  }
}

/**
 * Re-entry payload (ADR-0072 D4, issue #56). Mirrors the API schema
 * `ReentryAnnotation` (packages/firewatch-api/src/firewatch_api/schemas.py).
 *
 * Populated when the actor's CURRENT verdict tier is newly present
 * (`decided_tier` was `null`) or numerically lower (louder) than
 * `decided_tier` was at decision time — i.e. the actor has re-entered the
 * queue since the operator decided it. `decided_score`/`current_score` are
 * carried as a #49 (novelty memory) input; a score increase ALONE is never
 * itself a re-entry trigger (ADR-0072 D4 boundary 2) — the UI must never
 * recompute re-entry from these, only render the engine integers it is
 * handed. Engine integers only, never a raw float; RULE-tagged provenance
 * (ADR-0035).
 */
export interface ReentryAnnotation {
  /** Verdict tier recorded at decision time; null = observed stratum. */
  decided_tier: number | null
  /** Engine score recorded at decision time. */
  decided_score: number
  /** The actor's CURRENT verdict tier; null = observed stratum. */
  current_tier: number | null
  /** The actor's CURRENT engine score. */
  current_score: number
  /** UTC ISO-8601 — when the baseline decision was made. */
  decided_at: string
}

/**
 * The additive `triage_decision` annotation on `ThreatScore` (ADR-0072 D3/D8,
 * issue #47). Mirrors the API schema `TriageDecisionAnnotation`
 * (packages/firewatch-api/src/firewatch_api/schemas.py).
 *
 * `null` (the default) when the actor carries no active actor-identity
 * decision — `false_positive` rows are rule-scoped and never rendered in this
 * slot; they only affect `suppressed` via the server-side evaluator. Decided
 * actors are NEVER removed from `GET /threats` — this field only ANNOTATES
 * (ADR-0072 finding 1, the observed-stratum "never hide lifetime facts" rule).
 *
 * **Client contract (ADR-0072 D3):** queue membership is
 * `escalated && !(triage_decision?.suppressed)`. No lifecycle logic runs
 * client-side — the client renders what the server computed. See
 * `lib/triageDecisions.ts`'s `isSuppressed` for the canonical predicate.
 */
export interface TriageDecisionAnnotation {
  /** `false_positive` decisions are rule-scoped and never surface here. */
  verb: 'expected' | 'dismissed'
  /** UTC ISO-8601 timestamp the decision was recorded. */
  decided_at: string
  /** Verdict tier at decision time; null = observed stratum (ADR-0067 D2). */
  decided_tier: number | null
  /** Score at decision time (#49/#56 re-entry input; not consumed in M1). */
  decided_score: number
  /**
   * OR of actor-identity and false-positive suppression (ADR-0072 D4) — the
   * ONLY field queue-membership logic may read.
   */
  suppressed: boolean
  /**
   * Non-null when the actor was decided (`expected`/`dismissed`) and has
   * since re-entered the queue (issue #56, ADR-0072 D4) — a tier appeared or
   * loudened since the decision. `null` when no re-entry has occurred
   * (including when the actor is still suppressed, or was never decided).
   */
  reentry: ReentryAnnotation | null
}

/**
 * Mirrors the SDK ThreatScore model as returned by GET /threats and GET /threats/{ip}.
 * ai_* fields are additive-only — absent or unavailable when AI is offline (ADR-0015).
 */
export interface ThreatScore {
  source_ip: string
  threat_level: ThreatLevel
  score: number
  total_events: number
  blocked_events: number
  attack_types: string[]
  first_seen: string | null
  last_seen: string | null
  source_types: string[]
  detections: unknown[]
  ai_insights: string[] | null
  ai_confidence: number | null
  ai_status: AiStatus
  /**
   * Human-readable geo string for the source IP, e.g. "Chicago, United States".
   * Resolved from the ip_geo cache; null when no geo data exists or the IP is
   * non-public (RFC 1918 / loopback). Issue #132.
   */
  location: string | null
  /**
   * Additive contributing factors that sum to ``score`` (ADR-0036 D4, issue #209).
   * Each item carries a machine-readable ``factor`` key, a human-readable ``label``,
   * and an integer ``points`` value. Defaults to [] when not computed.
   */
  score_breakdown: ScoreBreakdownItem[]
  /**
   * Autonomous System Number for the source IP (issue #211).
   * Parsed from the ip-api.com ``as`` field (e.g. "AS4837 …" → 4837).
   * Follows ECS as.number. Null when no geo data, non-public IP, or provider
   * did not return AS data.
   */
  asn: number | null
  /**
   * AS operator name for the source IP (issue #211).
   * From the ip-api.com ``asname`` field (e.g. "CHINA-UNICOM").
   * Follows ECS as.organization.name. Null when no geo data or absent from provider.
   */
  as_name: string | null
  /**
   * Signed score change over the 1-hour look-back window (issue #250).
   * current_score − earliest_score_in_window.
   * null = new actor (no prior snapshot in the window); the UI renders a NEW badge
   * rather than a numeric delta. Never used as an input to scoring.
   */
  score_delta: number | null
  /**
   * Deterministic escalation verdict (ADR-0058 D2).
   * Computed by the escalation decider (no LLM) and additive — null/absent
   * when the backend has not yet computed a verdict for this actor.
   * The banner reads this alongside threat_level to decide banner-worthiness:
   * tier 1 or tier 2 = banner-worthy even when threat_level is MEDIUM or LOW.
   */
  escalation?: EscalationVerdict | null
  /**
   * Server-computed triage-decision annotation (ADR-0072 D3, issue #47).
   * Additive — null/absent when the actor carries no active decision, or on
   * older API responses that predate this field. See `TriageDecisionAnnotation`.
   */
  triage_decision?: TriageDecisionAnnotation | null
}

/**
 * One bucket in a GET /threats/{ip}/score-history response (issue #250).
 * ``t`` is a UTC ISO bucket key (hourly: "YYYY-MM-DDTHH:00"), tz-naive = UTC.
 * ``value`` is the score value recorded in that bucket.
 */
export interface ScoreHistoryPoint {
  t: string
  value: number
}

/**
 * Source health entry inside StatsResponse (ADR-0032 §B shape, issue #134).
 *
 * Shape emitted by the health_assembler (packages/firewatch-api/health_assembler.py)
 * and returned via GET /stats source_health[].
 *
 * `health` is SERVER-COMPUTED (ADR-0032 Decision C):
 *   "not_configured" → grey  (installed, not yet configured)
 *   "amber"          → amber (configured, no/stale events)
 *   "ok"             → green (configured, recent events)
 *   "red"            → red   (supervisor error/parked, or last_error set)
 *
 * The frontend RENDERS this value; it does NOT re-derive policy from
 * last_event_at recency (that logic moved server-side per ADR-0032 D).
 *
 * ADR-0032 Amendment 1 R2 (issue #378): three additive sync-evidence fields
 * so the tooltip can split the single amber state into honest sub-states.
 */
export interface SourceHealth {
  source_type: string
  source_id: string
  /** Human-readable label from plugin metadata().display_name. */
  display_name: string
  /** "pull" | "push" — from plugin metadata().flavor. */
  flavor: string
  /** Server-computed 4-state health: "not_configured" | "amber" | "ok" | "red". */
  health: string
  /** Supervisor instance state, or null when no supervisor is available. */
  supervisor_state: string | null
  /** ISO8601 timestamp of the most recent event, or null if no data. */
  last_event_at: string | null
  /** Total events for this (source_type, source_id). */
  event_count: number
  /** Sanitized supervisor last_error string (secrets stripped server-side), or null. */
  last_error: string | null
  /**
   * ISO8601 timestamp of the last completed pull cycle, or null (push/pre-first-cycle).
   * ADR-0032 Amendment 1 R2: epoch float from supervisor DTO converted to ISO8601
   * server-side for consistency with last_event_at.
   */
  last_sync_at?: string | null
  /**
   * Outcome of the last completed pull cycle: "ok" | "no_data" | "error", or null.
   * ADR-0032 Amendment 1 R2 — distinguishes verified-quiet (no_data) from
   * never-connected (null) and errored (error) for honest tooltip text.
   */
  last_sync_status?: 'ok' | 'no_data' | 'error' | null
  /**
   * Events ingested on the last completed pull cycle; 0 when no cycle has run.
   * ADR-0032 Amendment 1 R2.
   */
  last_sync_ingested?: number
}

/**
 * Response from GET /stats (ADR-0029 D1).
 *
 * ADR-0032 Amendment 1 R1 (issue #377): adds `freshness_minutes` carrying the
 * live FRESHNESS_MINUTES constant from health_assembler.py so the legend never
 * hardcodes a second copy of that server constant.
 */
export interface StatsResponse {
  total_logs: number
  total_ips: number
  blocked_percentage: number
  source_health: SourceHealth[]
  /** ISO timestamp of the most recent event, or null if no data. */
  last_updated: string | null
  /**
   * Server freshness window in minutes (ADR-0032 Amendment 1 R1).
   * green/amber boundary: events within this many minutes → green (ok).
   * The legend renders this value — never a hardcoded constant.
   */
  freshness_minutes?: number
}

/**
 * Response from GET /health (ADR-0029 D1; tri-state `ai` field per ADR-0066).
 * ollama_connected / ollama_model: backend field names are unchanged (rename DEFERRED per #135).
 * User-facing label is "Local AI" (ADR-0022).
 */
export interface HealthResponse {
  status: string
  /**
   * @deprecated Retained for compatibility only — `true` iff `ai === "active"`.
   * Branch on `ai` (below) instead; this boolean collapses "off by choice" and
   * "unreachable" into one value, which is exactly the honesty bug ADR-0066 fixes.
   * It remains valid to use ONLY as a loading-time fallback while `health` itself
   * has not yet arrived (i.e. before a HealthResponse exists at all).
   */
  ollama_connected: boolean
  ollama_model: string | null
  db_ok: boolean
  /**
   * ISO-8601 timestamp of the last AI scoring run (issue #207 scope amendment).
   * Additive field (ADR-0029 additive posture); absent from the current /health
   * response until the backend exposes it. The AiEnginePill renders it when
   * present; the field is optional here so existing responses remain valid.
   *
   * NOTE: `queue_depth` was also requested in the scope amendment but is not
   * cheaply derivable from the current pipeline/supervisor (no queue bookkeeping
   * in the store). Both fields are flagged to the architect for a contract-change
   * issue before implementing backend exposure.
   */
  last_scored_at?: string | null
  /**
   * Tri-state AI engine status (ADR-0066 Layer 1) — the authoritative source for
   * all AI-status presentation. See `HealthAiStatus` for the vocabulary. Always
   * present on live `/health` responses (packages/firewatch-api routes/meta.py).
   */
  ai: HealthAiStatus
}

/**
 * One row of the bounded top-N `top_pressure` strip (issue #55).
 *
 * `attempt_count` and `span_minutes` are plain engine integers (ADR-0035) —
 * never the underlying decayed-intensity float used to rank the strip
 * server-side. Rows arrive already ordered highest-pressure first; the
 * frontend never re-sorts or re-derives the ranking.
 */
export interface PressureEntry {
  /** The actor's IP (attacker-influenced value — render as a text node only, ADR-0029 D3). */
  source_ip: string
  /** Count of ADR-0070 D1-qualifying attempt events for this actor, state window (24h). */
  attempt_count: number
  /** Minutes between this actor's first and last qualifying attempt. 0 when fewer than two exist. */
  span_minutes: number
}

/**
 * Response from GET /banner/summary (issue #55).
 *
 * Additive fields for the dashboard triage banner's attempts headline + pressure
 * strip — extends #43's aggregate record line with the ADR-0070 attempt
 * vocabulary. Every count is computed server-side from the same
 * `firewatch_core.attempts` module and `decide()`/`detect()` verdicts the
 * per-actor `ThreatScore` escalation already uses — the frontend NEVER
 * recomputes any of these integers; it only renders what the server sends.
 *
 * `succeeded_count` is THE correctness crux (ADR-0070 D3 tier-attribution
 * correction): the success set is Tier-1 verdicts UNION actors carrying a
 * critical-severity qualifying detection — never Tier-1 alone. Render this
 * field verbatim; do not re-derive "succeeded" from tier client-side.
 */
export interface BannerAttemptSummary {
  /** Total D1-qualifying attempt events across all actors, state window (24h). */
  attempt_count: number
  /** Distinct actors with >=1 qualifying attempt in the state window. */
  actor_count: number
  /**
   * Actors with a Tier-1 verdict OR a critical-severity qualifying detection
   * (ADR-0070 D3 tier-attribution correction) — the union, never Tier-1 alone.
   */
  succeeded_count: number
  /** K = actors carrying a Tier-1 or Tier-2 escalation verdict ("need review"). */
  queue_size: number
  /** Bounded (<= 5) highest-pressure actors, ranked server-side by peak decayed intensity. */
  top_pressure: PressureEntry[]
  /** ISO-8601 UTC timestamp when this summary was generated. */
  generated_at: string
}

/**
 * Response from GET /ai/models (#135).
 * models: flat list of model IDs available at the configured local endpoint.
 * current: the currently persisted model ID, or null if none is set.
 * Empty `models` means the endpoint is unreachable — show a status message.
 */
export interface AiModelsResponse {
  models: string[]
  current: string | null
}

/**
 * Subset of RuntimeConfig returned by GET /config/runtime (#131).
 *
 * Only the fields consumed by LocalAiPanel are listed.
 * SecretStr fields (webhook_url, api_key) are returned as null by the server
 * when set (ADR-0006 / masked); the UI shows "•••• set" and never prefills them.
 *
 * Backend field names mirror firewatch-sdk/config.py RuntimeConfig exactly.
 * Rename (ollama_* → local_ai_*) is DEFERRED per #135.
 */
export interface RuntimeConfigResponse {
  /** Minimum threat level that triggers an alert. */
  alert_threshold: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  /** Send a digest alert after every sync run. */
  alert_on_sync: boolean
  /**
   * Outbound webhook URL — SecretStr on the server.
   * Returned as null when set (masked, ADR-0006).
   * The UI must NOT prefill with null; show placeholder text instead.
   */
  webhook_url: null
  /**
   * Non-secret boolean: true when a webhook URL is configured on the server.
   * Derived server-side from webhook_url being set (ADR-0006 / issue #494).
   * The UI uses this to show "•••• set — type to replace" across sessions
   * without echoing the secret value. The session-local heuristic is REPLACED
   * by this honest signal.
   */
  webhook_url_set: boolean
  /**
   * Non-secret boolean: true when an API key is configured on the server.
   * The api_key field is SecretStr — GET returns it as null (masked, ADR-0006).
   * This honest signal distinguishes "key set (masked)" from "never set".
   * The UI uses it to show the honest empty state and prompt the operator to
   * re-enter the key in this session (issue #550 / ADR-0026 Amendment 1).
   */
  api_key_set: boolean
  /** Currently selected model. */
  ollama_model: string
  /** Whether AI analysis is enabled. */
  ai_enabled: boolean
  /**
   * Base URL of the local OpenAI-compatible inference endpoint (ADR-0022).
   * Must resolve to loopback, RFC 1918, or link-local — validated server-side.
   * Not a secret; returned plaintext by GET /config/runtime.
   * Issue #492.
   */
  ollama_base_url: string
  /**
   * Geo-enrichment provider (ADR-0039).
   * "offline" (default): MMDB files, zero network egress after first run.
   * "online": ip-api.com (explicit opt-in).
   * Issue #492.
   */
  geo_provider: 'offline' | 'online'
  /**
   * Escalation-aware notifications, ON by default (ADR-0059 D3 mechanism /
   * ADR-0059 Amendment 1 default / issue #74).
   * When true (default since Amendment 1), notifier uses is_alert_worthy(threat,
   * threshold) — band OR escalation tier <= 2 — so a HIGH ALERT / escalation-tier
   * actor also triggers a notification. When false, notifier gates on the
   * Notification threshold band only.
   * Additive SDK field; backward-compatible. Firing cadence is transition-gated
   * (fires on a state change, not on every re-evaluation of an unchanged state).
   */
  notify_on_auto_escalate: boolean
  /**
   * Triage threshold — minimum severity band for an actor to enter the triage banner
   * by severity (ADR-0059 D1 / issue #650).
   *
   * Default HIGH preserves the existing hard-coded {CRITICAL, HIGH} banner band.
   * The action-aware escalation tier (tier ≤ 2) ALWAYS surfaces in the banner
   * regardless of this threshold (ADR-0058 D2).
   *
   * Additive SDK field; absent on older API responses → fallback to "HIGH".
   */
  triage_threshold?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
}

/**
 * One entry in the escalation policy registry view.
 * Returned as part of GET /escalation/policy (issue #650, ADR-0058 D1/D6).
 *
 * SECURITY (ADR-0029 D3): rule_name may be operator-authored; render as text node only.
 */
export interface PolicyRow {
  /** Correlation rule identifier. */
  rule_name: string
  /**
   * Sigma-anchored severity declared by the rule.
   * Null when the rule did not declare a severity level.
   */
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null
  /**
   * True when the rule jumps the triage queue without volume/AI confirmation
   * (ADR-0058 D1 — auto_escalate tier ≤ 2 by convention).
   */
  auto_escalate: boolean
  /** Number of times this rule fired across all IPs in the last 24 hours. */
  hit_count_24h: number
}

/**
 * Response for GET /escalation/policy (issue #650, ADR-0058 D1/D6).
 *
 * The policy list is read-only — the registry is finalized at import time.
 * Every registered detection appears even when its hit_count_24h is 0.
 */
export interface EscalationPolicyResponse {
  /** One row per registered detection rule. */
  policy: PolicyRow[]
  /** ISO-8601 UTC timestamp when this response was generated. */
  generated_at: string
}

/**
 * Per-severity event counts within a timeline bucket (issue #247).
 * All four canonical severity levels are always present; value is 0 when absent.
 */
export interface BucketSeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
}

/**
 * One bucket from GET /logs/timeline (ADR-0029 D1).
 * hour: ISO timestamp of the bucket start.
 * granularity: "hourly" | "daily" | etc.
 *
 * Additive fields (issue #247 — backend may omit them on older API responses):
 *   severity:      per-severity counts for stacked-bar rendering.
 *   top_category:  most-frequent attack category in the bucket; null when none.
 *   top_source_ip: most-frequent source IP in the bucket; null when none.
 *                  SECURITY: attacker-controlled — render as text node only (ADR-0029 D3).
 */
export interface TimelineBucket {
  hour: string
  total: number
  blocked: number
  granularity?: string
  /** Additive (issue #247) — absent on older API responses; default to zeros. */
  severity?: BucketSeverityCounts
  /** Additive (issue #247) — null when no categorised events in the bucket. */
  top_category?: string | null
  /**
   * Additive (issue #247) — null when no events in the bucket.
   * SECURITY (ADR-0029 D3): attacker-controlled field from logs.source_ip.
   * Render as text node only — never via dangerouslySetInnerHTML.
   */
  top_source_ip?: string | null
}

/**
 * One entry from GET /logs/categories (ADR-0029 D1).
 * category: canonical category string.
 * count: number of events in that category.
 * source_type: which source contributed (may be absent in aggregate views).
 */
export interface CategoryCount {
  category: string
  count: number
  source_type?: string
}

// ---------------------------------------------------------------------------
// MB.6 — Logs explorer types (ADR-0029 D2, D3)
// ---------------------------------------------------------------------------

/**
 * Facet filter parameters for GET /logs/paginated (ADR-0029 D2).
 * All fields are optional — omitted means "no filter".
 * cursor: opaque continuation token; never compute offset client-side.
 *
 * Free-text search maps to `?q=` — the backend matches against source_ip,
 * rule_id, payload_snippet and rule descriptions (sqlite_store.py line 638).
 * There is no separate `?search=` or `?ip=` split in the UX: one search box,
 * one `q=` param, keeping the surface simple (issue #177).
 */
export interface LogsFilter {
  cursor?: string
  limit?: number
  source_type?: string
  source_id?: string
  category?: string
  severity?: string
  ip?: string
  start?: string
  end?: string
  /** Free-text search — maps to `?q=` on GET /logs/paginated. */
  q?: string
  /**
   * Action filter — maps to `?action=` on GET /logs/paginated (issue #252).
   * Exact values: ALLOW / BLOCK / DROP / ALERT.
   * Shorthand: "blocked" (case-insensitive) → BLOCK + DROP server-side.
   */
  action?: string
  /**
   * Destination IP substring filter (ML-3, issue #431).
   * Maps to `?destination_ip=` on GET /logs/paginated.
   * SECURITY (ADR-0029 D3): attacker-controlled field — render as text only.
   */
  destination_ip?: string
  /**
   * Protocol exact-match filter (ML-3, issue #431).
   * Maps to `?protocol=` on GET /logs/paginated.
   * Accepted values: TCP / UDP / ICMP / etc. (exact, case-sensitive).
   * Sources that do not populate protocol (e.g. Azure WAF) will not match.
   */
  protocol?: string
  /**
   * JA4 TLS fingerprint exact-match filter (ML-13, issue #441).
   * Maps to `?tls_ja4=` on GET /logs/paginated.
   * Consume-only: only rows where the sensor populated tls_ja4 participate.
   * Sources that do not emit JA4 (e.g. older Suricata builds) will not match.
   * SECURITY (ADR-0029 D3): fingerprint is sensor-normalised — render as text only.
   */
  tls_ja4?: string
}

/**
 * Response from POST /logs/nl-query (ML-6 / ADR-0049 / issue #434).
 *
 * ``filter_spec`` — the validated FilterSpec fields (only non-null values).
 *   When ``degraded=true`` this will contain only ``{q: "<nl_text>"}`` —
 *   a plain free-text fallback identical to the analyst typing it manually.
 * ``degraded``    — true when the LLM parse was rejected (OOV field, low
 *   confidence, or endpoint error) and the result fell back to q=.
 * ``provenance``  — "ai" on success; "ai_degraded" on fallback.
 *   Drives the AI provenance chip rendering (EARS-3).
 * ``error``       — optional short error message for debugging; null on success.
 *
 * SECURITY (ADR-0049 / OWASP LLM01): filter_spec values come from the strict
 * allowlist validator; they are safe to apply as filter chips.
 */
export interface NlQueryResponse {
  filter_spec: Partial<LogsFilter>
  degraded: boolean
  provenance: 'ai' | 'ai_degraded'
  error: string | null
}

/**
 * One canonical log row from the paginated envelope (ADR-0029 D2, D3).
 *
 * SECURITY: raw_log and native fields are attacker-controlled (ingested
 * telemetry). They MUST be rendered as text nodes only — never via
 * dangerouslySetInnerHTML. typed as `unknown` to force explicit handling.
 */
export interface LogEntry {
  id: number | string
  timestamp: string
  source_type: string
  source_id?: string
  source_ip: string
  /**
   * Destination IP address (ML-3, issue #431).
   * SECURITY (ADR-0029 D3): attacker-controlled — render as text node only.
   * Null for L7-only sources (e.g. Azure WAF) that do not populate this field.
   */
  destination_ip?: string | null
  /**
   * Network protocol string, e.g. "TCP", "UDP", "ICMP" (ML-3, issue #431).
   * SECURITY (ADR-0029 D3): attacker-controlled — render as text node only.
   * Null for sources that do not populate this field (e.g. Azure WAF).
   */
  protocol?: string | null
  /**
   * JA4 TLS client fingerprint (ML-13, issue #441).
   * SECURITY (ADR-0029 D3): sensor-normalised from attacker-controlled TLS traffic.
   * Null when the sensor did not emit JA4 (consume-only — never fabricated).
   * Render as a text node only — never via dangerouslySetInnerHTML.
   */
  tls_ja4?: string | null
  /**
   * JA4S TLS server fingerprint (ML-13, issue #441).
   * SECURITY (ADR-0029 D3): sensor-normalised — render as text node only.
   * Null when not emitted by the sensor.
   */
  tls_ja4s?: string | null
  /**
   * TLS SNI server name (ML-13, issue #441).
   * SECURITY (ADR-0029 D3): attacker-controlled — render as text node only.
   */
  tls_sni?: string | null
  /**
   * Negotiated TLS version, e.g. "TLSv1.3" (ML-13, issue #441).
   * SECURITY (ADR-0029 D3): sensor-normalised — render as text node only.
   */
  tls_version?: string | null
  category: string
  severity: string
  action?: string | null
  /** Attacker-controlled — render as text only, never as HTML. */
  raw_log: unknown
  /**
   * Geo city from the local ip_geo cache (issue #334).
   * Null when the IP is not yet in the cache or is non-public.
   * Populated by the server-side LEFT JOIN in get_paginated — no per-cell network call.
   * SECURITY (ADR-0029 D3): GeoIP-resolved from attacker-controlled source_ip;
   * render as text nodes only.
   */
  geo_city?: string | null
  /**
   * Geo country (full name) from the local ip_geo cache (issue #334).
   * Null when the IP is not yet in the cache or is non-public.
   * SECURITY (ADR-0029 D3): GeoIP-resolved from attacker-controlled source_ip;
   * render as text nodes only.
   */
  geo_country?: string | null
  /**
   * DNS queried domain (ML-1 / ADR-0048).
   * Null for sources that do not populate dns_query (e.g. Azure WAF).
   * SECURITY (ADR-0029 D3): attacker-controlled — render as text node only.
   */
  dns_query?: string | null
  /**
   * DGA likelihood score [FLAG_THRESHOLD, 1.0] if this row's dns_query was
   * flagged by the local heuristic (ML-12, issue #440).
   * Null / absent when dns_query is null or scored below threshold.
   * Provenance: RULE (deterministic, zero-egress).
   */
  dga_score?: number | null
  /** Optional additional native fields — attacker-controlled. */
  [key: string]: unknown
}

// ---------------------------------------------------------------------------
// ML-3 (issue #431) — Top src→dst pairs type (GET /logs/top-pairs)
// ---------------------------------------------------------------------------

/**
 * One entry from GET /logs/top-pairs (ML-3, issue #431).
 *
 * ``source_ip``      — source IP address (attacker-controlled — text node only).
 * ``destination_ip`` — destination IP address (attacker-controlled — text node only).
 * ``count``          — number of events for this pair.
 *
 * Pairs are ordered by count descending; bounded by ``?top_n=`` (default 10).
 * Pairs where destination_ip is NULL on the server are excluded.
 *
 * SECURITY (ADR-0029 D3): both IP fields are attacker-controlled.
 * Render as text nodes only — never via dangerouslySetInnerHTML.
 */
export interface TopPairsRow {
  /** Source IP — attacker-controlled, text node only. */
  source_ip: string
  /** Destination IP — attacker-controlled, text node only. */
  destination_ip: string
  /** Event count for this pair. */
  count: number
}

// ---------------------------------------------------------------------------
// ML-4 (issue #432) — Traffic-shape header types
// ---------------------------------------------------------------------------

/**
 * One entry from GET /logs/top-talkers (ML-4, issue #432).
 *
 * ``source_ip`` — most-active source IP (attacker-controlled — text node only).
 * ``count``     — total event count for this IP.
 * ``blocked``   — number of BLOCK/DROP events for this IP.
 *
 * SECURITY (ADR-0029 D3): ``source_ip`` is attacker-controlled telemetry.
 * Render as text nodes only — never via dangerouslySetInnerHTML.
 */
export interface TopTalkerRow {
  /** Source IP — attacker-controlled, text node only. */
  source_ip: string
  /** Total event count. */
  count: number
  /** Blocked event count (action IN ('BLOCK','DROP')). */
  blocked: number
}

/**
 * One entry from GET /logs/protocol-mix (ML-4, issue #432).
 *
 * ``protocol`` — protocol string (e.g. "TCP", "UDP") or ``"(unknown)"`` for
 *               NULL rows from L7-only sources (e.g. Azure WAF).
 * ``count``    — number of events with this protocol value.
 *
 * SECURITY (ADR-0029 D3): ``protocol`` is normalised from attacker-controlled
 * telemetry. Render as text nodes only — never via dangerouslySetInnerHTML.
 */
export interface ProtocolMixRow {
  /** Protocol string or "(unknown)" sentinel. */
  protocol: string
  /** Event count for this protocol. */
  count: number
}

// ---------------------------------------------------------------------------
// Issue #663 — /logs/stats totals
// ---------------------------------------------------------------------------

/**
 * Response from GET /logs/stats (issue #663).
 *
 * Real filter-scoped counts — NOT derived from any top-N list.
 * Used by StripTiles to populate the Events / Blocked / Distinct IPs tiles.
 *
 * ``present_source_types`` — sorted DISTINCT source_type values within the
 * filtered scope; used by the source-type facet strip (#664).
 *
 * SECURITY (ADR-0029 D3): present_source_types strings are normalised backend
 * values but still text-node only — never via dangerouslySetInnerHTML.
 */
export interface LogsStats {
  /** Total event count within the current filter scope. */
  total_events: number
  /** Blocked/dropped event count within the current filter scope. */
  blocked_events: number
  /** Distinct source IPs within the current filter scope. */
  distinct_ips: number
  /** Sorted list of distinct source_type values within the filter scope. */
  present_source_types: string[]
}

// ---------------------------------------------------------------------------
// ML-12 (issue #440) — DGA suspect types
// ---------------------------------------------------------------------------

/**
 * One entry from GET /logs/dga-suspects (ML-12, issue #440).
 *
 * Produced by local heuristic analysis (Shannon entropy, consonant ratio,
 * digit ratio, label length, unique-char ratio) — zero-egress, no DNS lookups.
 * Provenance: RULE (deterministic), not AI.
 *
 * SECURITY (ADR-0029 D3): ``dns_query`` and ``source_ip`` are attacker-controlled
 * telemetry.  Render as text nodes only — never via dangerouslySetInnerHTML.
 */
export interface DgaSuspectRow {
  /** Queried FQDN flagged as possible DGA — attacker-controlled, text node only. */
  dns_query: string
  /** Source IP of the event that made the query — attacker-controlled, text node only. */
  source_ip: string
  /** ISO-8601 timestamp of the event. */
  timestamp: string
  /** Composite DGA likelihood score in [FLAG_THRESHOLD, 1.0]. Glass-box honest. */
  dga_score: number
  /** Normalized Shannon entropy of the leftmost label [0.0, 1.0]. */
  entropy: number
  /** Ratio of consonant chars to total alpha chars in the scored label. */
  consonant_ratio: number
  /** Ratio of digit chars to total chars in the scored label. */
  digit_ratio: number
  /** Character count of the scored (leftmost) label. */
  label_length: number
}

// ---------------------------------------------------------------------------
// ML-13 (issue #441) — JA4+ fingerprint facet type (GET /logs/top-ja4)
// ---------------------------------------------------------------------------

/**
 * One entry from GET /logs/top-ja4 (ML-13, issue #441).
 *
 * ``tls_ja4`` — JA4 TLS fingerprint string from the sensor.
 * ``count``   — number of events with this fingerprint value.
 *
 * Consume-only: only rows where the sensor populated tls_ja4 appear here.
 * An empty list means all rows have NULL tls_ja4 (sensor did not emit JA4).
 * This is honest absence, not an error.
 *
 * SECURITY (ADR-0029 D3): ``tls_ja4`` is sensor-normalised from
 * attacker-controlled TLS traffic. Render as text nodes only — never via
 * dangerouslySetInnerHTML.
 */
export interface Ja4FingerprintRow {
  /** JA4 fingerprint string — attacker-controlled, text node only. */
  tls_ja4: string
  /** Event count for this fingerprint. */
  count: number
}

/**
 * Cursor-pagination envelope from GET /logs/paginated (ADR-0029 D2).
 * The server exposes the store's envelope verbatim — no re-wrapping.
 */
export interface PaginatedLogs {
  logs: LogEntry[]
  /** Opaque continuation token — echo back as `cursor` on the next request. */
  next_cursor: string | null
  has_more: boolean
  total_matching: number
}

// ---------------------------------------------------------------------------
// MB.6 — Threat drill-down types (ADR-0029 D3)
// ---------------------------------------------------------------------------

/**
 * Structured insights block within DetailedAnalysis.
 * Returned by both the rules-only and AI paths.
 * SECURITY: all fields are attacker-controlled — render as text only.
 */
export interface DetailedInsights {
  patterns?: string[] | null
  risks?: string[] | null
  mitigations?: string[] | null
}

/**
 * Response from GET /threats/{ip}/detailed (#19).
 *
 * Fields verified against the live endpoint (2026-06-05):
 *   curl http://127.0.0.1:8000/threats/198.51.100.50/detailed
 *
 * ai_* fields follow additive-only semantics (ADR-0015).
 * Rich structured fields (executive_summary, attack_progression, etc.) are
 * returned by the rules-only path too — they come from the AI result when AI
 * is active, or may be absent when AI is disabled (#94).
 *
 * SECURITY (ADR-0029 D3): all string fields are attacker-controlled.
 * Render as text nodes only — never via dangerouslySetInnerHTML.
 */
export interface DetailedAnalysis {
  source_ip: string
  threat_level: ThreatLevel
  score: number
  total_events: number
  blocked_events: number
  attack_types: string[]
  first_seen: string | null
  last_seen: string | null
  source_types: string[]
  detections: unknown[]
  ai_insights: string[] | null
  ai_confidence: number | null
  ai_status: AiStatus
  /** Full AI analysis narrative (absent when AI unavailable). */
  analysis?: string | null
  /** MITRE ATT&CK technique IDs if detected. */
  mitre_techniques?: string[] | null

  // --- Rich structured fields present in both rules-only and AI paths ---

  /** High-level summary of the threat (attacker-controlled — text only). */
  executive_summary?: string | null
  /** Ordered list of attack steps observed (attacker-controlled — text only). */
  attack_progression?: string[] | null
  /** Recommended action: "block" | "monitor" | "allow" | string. */
  recommended_action?: string | null
  /** Attacker intent narrative (attacker-controlled — text only). */
  intent?: string | null
  /** Indicators of compromise (attacker-controlled — text only). */
  ioc_indicators?: string[] | null
  /** Structured insights block with patterns, risks, mitigations. */
  insights?: DetailedInsights | null
  /** Attack lifecycle stage, e.g. "exploitation" | "reconnaissance". */
  attack_stage?: string | null
  /** Overall confidence in this assessment (0–1). */
  confidence?: number | null
  /** Estimated false-positive likelihood (0–1). */
  false_positive_likelihood?: number | null
  /**
   * Human-readable geo string for the source IP, e.g. "Toronto, Canada".
   * Resolved from the ip_geo cache; null when no geo data or non-public IP.
   * Issue #132 DC-2.
   */
  location?: string | null
  /**
   * Additive contributing factors that sum to ``score`` (ADR-0036 D4, issue #209).
   * Same shape as ThreatScore.score_breakdown. Defaults to [] when not computed.
   */
  score_breakdown?: ScoreBreakdownItem[]
  /**
   * Autonomous System Number for the source IP (issue #211).
   * Null when no geo data, non-public IP, or provider omitted AS data.
   */
  asn?: number | null
  /**
   * AS operator name for the source IP (issue #211).
   * Null when no geo data or absent from provider response.
   */
  as_name?: string | null
}

/**
 * One rule description from GET /rules.
 */
export interface RuleDescription {
  rule_id: string | number
  name: string
  description?: string | null
  severity?: string | null
  category?: string | null
  source_type?: string | null
}

// ---------------------------------------------------------------------------
// MB.6 — Analytics types (ADR-0029 D1)
// ---------------------------------------------------------------------------

/**
 * IP provenance class derived from ASN data (issue #532 / EARS-1).
 *
 * Classified server-side by ip_classifier.py — zero external calls (ADR-0047).
 * Values:
 *   "datacenter"  — ASN belongs to a known cloud/hosting provider.
 *                   Country is the *hosting location*, not the actor origin.
 *   "vpn-likely"  — ASN belongs to a known VPN/anonymiser provider.
 *   "residential" — Has an ASN, not in the cloud/VPN sets; ISP/residential origin.
 *   "private"     — IP is in a non-routable range (RFC 1918, loopback, …).
 *   "unresolved"  — No ASN data for a routable IP (not yet enriched or absent).
 */
export type IpClass = 'datacenter' | 'vpn-likely' | 'residential' | 'private' | 'unresolved'

/**
 * One geo point from GET /analytics/geo (#20).
 *
 * Field names match the real API response from store.get_analytics_geo() verbatim
 * (sqlite_store.py::get_analytics_geo — verified against live endpoint, fix #178):
 *   ip, country, city, lat, lon, total_events, blocked, rules_triggered
 *
 * Issue #532 additive fields: asn, as_name, ip_class.
 *
 * lat/lon: WGS-84 coordinates.
 * total_events: total event count from that IP (was incorrectly named `count` — #178).
 * blocked: number of BLOCK/DROP actions for that IP.
 * rules_triggered: count of distinct rules that fired for that IP.
 *
 * SECURITY: ip/city/country/as_name are GeoIP-resolved from attacker-controlled src_ip.
 * Render as text nodes only — never via innerHTML (#74 / ADR-0029 D3).
 */
export interface GeoPoint {
  lat: number
  lon: number
  /** Total events from this IP. Field was incorrectly `count` before fix #178. */
  total_events: number
  /** Number of BLOCK/DROP actions for this IP. */
  blocked: number
  /** Count of distinct rules triggered by this IP. */
  rules_triggered: number
  ip?: string | null
  city?: string | null
  country?: string | null
  /**
   * Autonomous System Number (issue #532 / ECS as.number).
   * Null when not yet enriched or non-public IP.
   */
  asn?: number | null
  /**
   * AS organisation name (issue #532 / ECS as.organization.name).
   * Null when not yet enriched or non-public IP.
   * SECURITY: GeoIP-resolved — render as text node only (ADR-0029 D3).
   */
  as_name?: string | null
  /**
   * IP provenance class (issue #532 / EARS-1).
   * Classified server-side from asn/as_name/IP-range — never fabricated.
   * Absent on older API responses; defaults to "unresolved" when missing.
   */
  ip_class?: IpClass
}

/**
 * Response from GET /analytics/summary (ADR-0029 D1).
 *
 * Shape mirrors store.get_analytics_summary() verbatim:
 *   total_ips, total_events, total_blocked, block_rate,
 *   top_country, unique_countries, top_rule.
 *
 * Issue #532 additive field: unresolved_private_count.
 *
 * NOTE: this endpoint does NOT return top_categories, top_ips, or
 * severity_distribution. Use GET /logs/categories for category counts
 * and GET /analytics/categories-timeline for category-over-time data.
 */
export interface AnalyticsSummary {
  total_ips: number
  total_events: number
  total_blocked: number
  /** Percentage of events that were blocked, e.g. 62.3 means 62.3%. */
  block_rate: number
  /** Country with the most blocked events, or "Unknown" if no geo data. */
  top_country: string
  unique_countries: number
  /**
   * rule_id of the most-triggered block rule, or "" when no data.
   *
   * Fix #82: narrowed to string (was string | number).
   * The backend stores rule_id as TEXT (sqlite_store.py line 231:
   * "rule_id TEXT") and the sentinel is "" — the server always sends a
   * string. The `!== ''` hide-guard in AnalyticsCharts is therefore
   * sound at compile time: numeric 0 cannot arrive as a number.
   * Verified in packages/firewatch-core/src/firewatch_core/adapters/
   * sqlite_store.py::get_analytics_summary (line 914):
   *   "top_rule": top_rule_row["rule_id"] if top_rule_row else ""
   */
  top_rule: string
  /**
   * Count of distinct source IPs not shown on the map — either RFC-1918/private
   * or not yet geo-enriched (issue #532 / EARS-4/EARS-5).
   *
   * Additive (ADR-0029 additive posture): absent on older API responses.
   * When absent (undefined) the UI renders nothing; when present and > 0 the
   * UI shows an honest "Unresolved / private (N)" chip.
   *
   * Making "Unknown" traffic visible (not silently dropped) converts what looked
   * like a bug into an honest, labeled answer.
   */
  unresolved_private_count?: number
}

/**
 * One row from GET /analytics/attack-dispositions (issue #214).
 *
 * Cross-tab of attack category × disposition action.
 * attack_type: canonical category label (e.g. "SQL Injection", "Other").
 * action:      canonical disposition string (BLOCK, DROP, ALERT, ALLOW, LOG, …).
 * count:       number of events with that (attack_type, action) combination.
 *
 * Bounded: top-5 attack categories + "Other" tail.
 * Empty list when no categorized events exist (degrade-to-hidden semantics).
 *
 * ADR-0029 D1 (additive read endpoint, no existing shape changed).
 * SECURITY (ADR-0029 D3): attack_type is derived from the logs.category column
 * (rule-engine output) — render as text nodes only.
 */
export interface AttackDispositionRow {
  attack_type: string
  action: string
  count: number
}

/**
 * One row from GET /analytics/asn (issue #533, A2).
 *
 * Aggregated per-ASN metrics from ip_geo JOIN logs.
 * Shape mirrors store.get_analytics_asn() verbatim.
 *
 * ``asn``         — integer AS number; null when enrichment is absent.
 * ``as_name``     — AS organization name; null when absent.
 *                   SECURITY: attacker-influenced (GeoIP of ingested src_ip) —
 *                   render as text node only (ADR-0029 D3).
 * ``total_events`` — total log events from all IPs in this ASN.
 * ``distinct_ips`` — number of distinct source IPs in this ASN.
 * ``blocked``     — events with action BLOCK or DROP.
 * ``blocked_pct`` — blocked / total_events * 100, rounded to 1 dp.
 */
export interface AsnRow {
  asn: number | null
  as_name: string | null
  total_events: number
  distinct_ips: number
  blocked: number
  blocked_pct: number
}

/**
 * Response from GET /analytics/asn/{asn}/narration (issue #533, A2 EARS-5).
 *
 * Same shape as NarrationResult but keyed by asn (integer) instead of source_ip.
 * SECURITY: narrative is LLM-authored — render as text node only.
 */
export interface AsnNarrationResult {
  asn: number
  /** Short narrative (≤ 120 words). Render as text node only. */
  narrative: string
  /** ADR-0035 provenance: 'rule' | 'ai'. */
  provenance: string
  /** Field names used to ground the narration (anti-fabrication). */
  collected_fields: string[]
  /** 'ok' | 'unavailable' | 'skipped'. */
  ai_status: string
}

/**
 * One bucket from GET /analytics/categories-timeline.
 *
 * The server returns wide/pivoted rows — one row per time period, with each
 * attack category as a named numeric column.  Fields verified against
 * sqlite_store.py::get_categories_timeline (issue #93):
 *
 *   period      — ISO date (daily: "YYYY-MM-DD") or "YYYY-MM-DDThh:00" (hourly)
 *   sqli        — WAF rule prefix 942*
 *   xss         — WAF rule prefix 941*
 *   bot         — WAF rule prefix 300*
 *   ratelimit   — WAF rule containing "RateLimit"
 *   geo         — WAF rule containing "GeoBlock"
 *   lfi         — WAF rule prefix 930*
 *   ids_alert   — Suricata events
 *   total       — total blocked events in the period
 *   granularity — "daily" | "hourly"
 */
export interface CategoryTimelineBucket {
  period: string
  sqli: number
  xss: number
  bot: number
  ratelimit: number
  geo: number
  lfi: number
  ids_alert: number
  total: number
  granularity: string
}

// ---------------------------------------------------------------------------
// MB.6 — Source control types (MB.4 routes)
// ---------------------------------------------------------------------------

/**
 * One source instance from GET /sources (MB.4).
 *
 * Fields mirror the backend InstanceStatus DTO verbatim
 * (packages/firewatch-api/src/firewatch_api/routes/sources.py list_instances):
 *
 *   source_type    — matches plugin type_key (e.g. "suricata")
 *   source_id      — configured instance name (e.g. "vm-target")
 *   flavor         — "pull" | "push" from plugin metadata
 *   state          — supervisor lifecycle state string (e.g. "running", "parked",
 *                    "backoff", "error")
 *   attempt        — current retry attempt number (0 = first attempt)
 *   total_crashes  — crash count for this lifecycle
 *   total_dlq      — events sent to the dead-letter queue
 *   dropped_count  — events dropped (DLQ full)
 *   last_success_at — ISO-8601 timestamp of the last successful collect cycle, or null
 *   event_count    — total events ingested from this instance (from the store)
 *
 * IMPORTANT: The old interface used `type_key` and `status` — these are WRONG.
 * The real API always uses `source_type` and `state`. Any match on `type_key`
 * or read of `.status` from this type is a shape-mismatch bug.
 */
export interface SourceInstance {
  /** Plugin type key (e.g. "suricata"). NOT "type_key" — the API field is "source_type". */
  source_type: string
  /** Configured instance name (e.g. "vm-target"). Used as source_id in action/sync calls. */
  source_id: string
  /** "pull" | "push" from the plugin metadata. */
  flavor: string
  /** Supervisor lifecycle state. Use this where `.status` was used before. */
  state: string
  /** Current retry attempt number. */
  attempt: number
  /** Crash count for this lifecycle. */
  total_crashes: number
  /** Events sent to dead-letter queue. */
  total_dlq: number
  /** Events dropped (DLQ full). */
  dropped_count: number
  /** ISO-8601 timestamp of last successful collect cycle, or null. */
  last_success_at: string | null
  /** Total events ingested from this instance (from the store). */
  event_count: number
  /**
   * ADR-0031 §F diagnostics fields (issue #139).
   * Exposed on GET /sources so the Settings diagnostics panel can render them
   * without a separate endpoint.  All are optional (undefined in old API shapes).
   *
   * SECURITY: last_error is sanitized server-side (secrets stripped). Render as
   * text nodes only — never via dangerouslySetInnerHTML.
   */
  /** Wall-clock Unix timestamp of the last completed pull cycle, or null. */
  last_sync_at?: number | null
  /** Number of events ingested on the last completed cycle. */
  last_sync_ingested?: number
  /** Outcome of the last completed cycle: "ok" | "no_data" | "error" | null. */
  last_sync_status?: 'ok' | 'no_data' | 'error' | null
  /** Error message when last_sync_status === "error", else null. Server-sanitized. */
  last_error?: string | null
  /**
   * ADR-0062 Amendment 1 §1: server-derived Active flag (issue #737).
   * True when the pull loop is enabled and scheduled; false when idle/never-enabled.
   * This is THE truth source for the Active toggle — never derive Active from
   * instance-presence or `state`.  Missing field (older backend) ⇒ treat as false
   * (safe degrade — `?? false` at read sites).
   */
  auto_sync_enabled?: boolean
}

/**
 * Response from POST /sources/{type_key}/test (MB.4).
 */
export interface TestResult {
  ok: boolean
  message: string
  detail?: Record<string, unknown> | null
}

/**
 * Response from POST /sync/{type_key} (MB.4).
 */
export interface SyncResult {
  ok: boolean
  message: string
  events_ingested?: number | null
}

// ---------------------------------------------------------------------------
// ADR-0031 — Auto-sync state (issue #138)
// Mirrors GET/PUT /sources/{type_key}/auto-sync routes in
// packages/firewatch-api/src/firewatch_api/routes/sources.py
// ---------------------------------------------------------------------------

/**
 * Last-sync details nested inside AutoSyncState.
 * All fields are null / 0 before the first cycle.
 * Fields are populated from Supervisor.status() (ADR-0031 §F).
 *
 * SECURITY: last_error is sanitized server-side (secrets stripped).
 * Render as text only — never via dangerouslySetInnerHTML.
 */
export interface LastSyncInfo {
  last_sync_at: string | null
  last_sync_ingested: number
  last_sync_status: 'ok' | 'no_data' | 'error' | null
  last_error: string | null
}

/**
 * Response from GET /sources/{type_key}/auto-sync (ADR-0031 §E/§F).
 *
 * enabled: derived from _instances file entry presence (restart-stable).
 * interval_seconds: from the _instances entry; defaults to 60 if absent.
 * source_id: type_key (ADR-0031 §B single-instance-per-type default).
 * last_sync: populated from Supervisor.status(); null fields before first cycle.
 */
export interface AutoSyncState {
  enabled: boolean
  interval_seconds: number
  source_id: string
  last_sync: LastSyncInfo
}

/**
 * Request body for PUT /sources/{type_key}/auto-sync (ADR-0031 §E).
 *
 * STRICT CONTRACT (issue #155 NB-1 / #166 NB-A):
 * - enabled MUST be a JSON boolean (true/false) — server returns 422 for strings/ints.
 * - interval_seconds is required ONLY when enabling (enabled=true).
 *   When disabling (enabled=false), interval_seconds MUST be omitted (not sent as 0).
 * - Interval bounds: 30–86400 seconds (ADR-0031 §E floor/ceiling).
 */
export interface AutoSyncRequest {
  enabled: boolean
  /** Only required when enabled=true. Must be 30–86400. */
  interval_seconds?: number
}

// ---------------------------------------------------------------------------
// DEF-1 — Per-IP cross-source event timeline (issue #118 / OD-3)
// Mirrors IPEventTimelineResponse / TimelineEventItem in
// packages/firewatch-api/src/firewatch_api/schemas.py
// ---------------------------------------------------------------------------

/**
 * One entry in the per-IP cross-source event timeline.
 *
 * Field names match the backend ``TimelineEventItem`` exactly so the
 * response array can be bound to the DS ``EventTimeline`` component
 * without a mapping step.
 *
 * SECURITY (ADR-0029 D3): ``label`` and ``payload`` are attacker-controlled.
 * Render as text nodes only — never via dangerouslySetInnerHTML.
 */
export interface IpTimelineEventItem {
  /** Plugin source_type — drives the dot colour in EventTimeline. */
  source: string
  /** ISO-8601 UTC timestamp string. */
  time: string
  /** Rule id or category (rule_name not persisted). Attacker-controlled. */
  label: string | null
  /** Payload snippet. Attacker-controlled — text only. */
  payload: string | null
  /** True when the IP appears in more than one source_type. */
  correlated: boolean
  /** Canonical action (ALERT/BLOCK/DROP/ALLOW/LOG). */
  action: string
  /** Event severity level, optional. */
  severity: string | null
  /** Attack category label, optional. */
  category: string | null
}

// ---------------------------------------------------------------------------
// ADR-0034 — Source maintenance action types (issue #169)
// Mirrors the response shapes from
// packages/firewatch-api/src/firewatch_api/routes/source_actions.py
// ---------------------------------------------------------------------------

/**
 * One entry from GET /sources/{type_key}/actions?source_id=
 *
 * Combines:
 *   - Action declaration fields (id, label, description, long_running,
 *     confirm, provides) from plugin.metadata().actions
 *   - Live ActionStatus fields (last_run_at, stale, status_message,
 *     status_detail) from supervisor.action_status_for
 *
 * Live status fields degrade to null when the plugin raises — the server
 * returns null-status entries rather than 500 (ADR-0034 §resilience).
 *
 * SECURITY: status_message is server-sanitized (never raw exception text).
 * Render as text nodes only — never via dangerouslySetInnerHTML.
 *
 * NOTE: source_host was explicitly REMOVED from the meta for security.
 * Never render or expect a source_host field.
 */
export interface ActionEntry {
  // --- Declaration fields ---
  id: string
  label: string
  description: string
  long_running: boolean
  confirm: string | null
  provides: string[]
  // --- Live status fields (null when degraded) ---
  /**
   * Timestamp of the last action run.
   *
   * R2 fix: the API returns this as a Unix epoch float (seconds, e.g. 1781162501.16),
   * NOT as an ISO-8601 string.  The type is widened to `string | number | null` so that
   * consumers (fmtDate in SourceActions) can handle both forms correctly.  fmtDate
   * multiplies numeric values by 1000 before constructing the JS Date.
   */
  last_run_at: string | number | null
  stale: boolean | null
  status_message: string | null
  status_detail: Record<string, unknown>
}

/**
 * Response from POST /sources/{type_key}/actions/{action_id}?source_id=
 *
 * ok=true  → action succeeded; message is human-readable success text.
 * ok=false → action encountered a plugin-level error; message is the
 *            sanitized error text (never raw stack traces).
 *
 * HTTP 200 for both outcomes — 4xx/5xx are reserved for API-level errors
 * (404 unknown type/action, 409 in-flight, 422 bad source_id, 503 no sup).
 *
 * SECURITY: message is sanitized server-side. Render as text; never as HTML.
 * source_id, action_id are echoed from the request — render as text only.
 */
export interface ActionResult {
  ok: boolean
  message: string
  detail: Record<string, unknown>
  source_type: string
  source_id: string
  action_id: string
}

/**
 * Response envelope for GET /threats/{ip}/events.
 *
 * 404 when the IP has no events — the client falls back to the coarse
 * score-derived timeline (OD-3).
 */
export interface IpEventTimelineResponse {
  /** Time-ordered list of cross-source events (ascending). */
  events: IpTimelineEventItem[]
  /** Number of events in this response (after cap). */
  total: number
  /** True when events span more than one source_type. */
  correlated: boolean
  /** Distinct source types seen for this IP. */
  source_types: string[]
  /** True when the store had more events than the cap; result is truncated. */
  capped: boolean
}

// ---------------------------------------------------------------------------
// ADR-0044 / MK-2 — AI verdict ledger types (GET /ai/analyses, GET /ai/analyses/{id})
// Mirrors AnalysisRecord fields from
// packages/firewatch-core/src/firewatch_core/ports/analysis_ledger.py
// ---------------------------------------------------------------------------

/**
 * Summary row from GET /ai/analyses — the list projection.
 *
 * ``prompt_text`` and ``response_text`` are intentionally absent (ADR-0044 §Security /
 * OWASP LLM05 — those fields are attacker-influenced and returned only by the detail
 * endpoint GET /ai/analyses/{id}).
 *
 * SECURITY (ADR-0029 D3): all string fields are model-authored or attacker-influenced.
 * Render as text nodes only — never via dangerouslySetInnerHTML.
 *
 * ``confidence`` is a 0–1 float (null when not recorded in older rows).
 * ``created_at`` is a UTC ISO-8601 string from the ledger (SQLite TEXT column).
 */
export interface AnalysisSummary {
  /** Ledger primary key — used to fetch the full record (MK-7). */
  id: number
  /** Source IP address (attacker-controlled — render as text). */
  ip: string
  /** Analysis kind: "concise" | "detailed". */
  kind: 'concise' | 'detailed' | string
  /** Model ID string (e.g. "qwen3:8b") — from the engine at analysis time. */
  model: string
  /** host:port of the local AI endpoint — no credentials (ADR-0044 §Security). */
  endpoint_host: string
  /** AI pipeline status at analysis time: "active" | "unavailable" | string. */
  ai_status: AiStatus
  /** AI-assessed threat level (validated closed-schema output). */
  threat_level: ThreatLevel
  /**
   * AI confidence score (0–1) at analysis time.
   * null when not recorded (older rows before the field was added).
   */
  confidence: number | null
  /** Merged score at analysis time (ADR-0035/0036). */
  score: number
  /** Score derivation tag: "ai" | "rule" | "ai+rule" (ADR-0035). */
  score_derivation: string
  /** End-to-end latency in milliseconds. */
  latency_ms: number
  /** Prompt token count from the endpoint's usage block; null when absent. */
  prompt_tokens: number | null
  /** Completion token count from the endpoint's usage block; null when absent. */
  completion_tokens: number | null
  /** Closed output-schema version (integer). */
  schema_version: number
  /** UTC ISO-8601 timestamp of when the analysis completed. */
  created_at: string
  /**
   * Additive feedback field (ADR-0045 MK-5 list-row join).
   * Null when no feedback has been submitted for this analysis.
   * Contains only {verdict, created_at} from the server projection;
   * the full row (with id, reason) is returned by POST feedback.
   * Optional (absent in pre-MK-5 server responses).
   */
  feedback?: {
    verdict: 'agree' | 'disagree'
    created_at: string
  } | null
}

/**
 * Cursor-paginated response envelope from GET /ai/analyses (ADR-0029).
 *
 * ``items`` contains AnalysisSummary rows (summary projection).
 * ``next_cursor`` is an opaque token — echo back as ``cursor`` on the next request.
 * ``has_more`` is true when additional pages exist.
 */
export interface AnalysisListPage {
  items: AnalysisSummary[]
  next_cursor: string | null
  has_more: boolean
}

// ---------------------------------------------------------------------------
// ADR-0045 / MK-5+MK-6 — Verdict feedback types
// Mirrors the feedback table schema and API shapes from
// packages/firewatch-api/src/firewatch_api/routes/ai_ledger.py
// ---------------------------------------------------------------------------

/**
 * The analyst verdict on an AI analysis: either agreement or disagreement.
 * Mirrors the CHECK constraint in the ``ai_feedback`` table.
 */
export type FeedbackVerdict = 'agree' | 'disagree'

/**
 * Request body for POST /ai/analyses/{id}/feedback (ADR-0045 D2).
 *
 * ``verdict``  — required; must be "agree" or "disagree" (server validates).
 * ``reason``   — optional operator note; capped at 1 000 chars server-side and
 *                mirrored client-side in the UI (both layers enforce the cap).
 */
export interface FeedbackRequest {
  verdict: FeedbackVerdict
  reason?: string
}

/**
 * Row returned by POST /ai/analyses/{id}/feedback and embedded in
 * AnalysisSummary.feedback (ADR-0045 D2 — upsert returns the stored row).
 *
 * ``id``          — feedback table primary key.
 * ``analysis_id`` — FK → ai_analyses.id.
 * ``verdict``     — "agree" | "disagree".
 * ``reason``      — operator note (null when not provided).
 * ``created_at``  — UTC ISO-8601 timestamp of the upsert.
 *
 * SECURITY (ADR-0029 D3): ``reason`` is operator text (attacker-influenced
 * via the threat model). Render as a text node only — never via innerHTML
 * and never interpolated into prompts (ADR-0045 D3 / OWASP LLM01).
 */
export interface FeedbackRow {
  id: number
  analysis_id: number
  verdict: FeedbackVerdict
  /** Operator note — null when not provided. Render as text node only. */
  reason: string | null
  /** UTC ISO-8601 upsert timestamp. */
  created_at: string
}

/**
 * Agreement rollup from GET /ai/feedback/summary (ADR-0045 D2 / D4).
 *
 * ``graded``        — total analyses graded (denominator; always shown per D4).
 * ``agreed``        — count of graded analyses where verdict = "agree".
 * ``agreement_pct`` — agreed / graded * 100; 0.0 when graded === 0.
 *
 * Honest denominator rule (ADR-0045 D4): the caller MUST display both
 * ``agreed``/``graded`` (or the percentage WITH ``graded``) — never a
 * bare percentage.
 *
 * Small-n rule (issue #411): when graded < 10, show counts only
 * ("7 of 9 graded verdicts agreed"); no percentage (not statistically
 * meaningful on small samples).
 */
export interface FeedbackSummary {
  graded: number
  agreed: number
  agreement_pct: number
}

// ---------------------------------------------------------------------------
// ADR-0041 / MI-6 — Evidence-chain types (GET /threats/{ip}/evidence)
// Mirrors FactorEvidence / AiBoostEvidence / EventSummary in
// packages/firewatch-sdk/src/firewatch_sdk/models.py
// and EvidenceChainResponse in
// packages/firewatch-api/src/firewatch_api/schemas.py
// ---------------------------------------------------------------------------

/**
 * Minimal descriptor for a contributing ``logs`` row (ADR-0041 evidence chain).
 *
 * ``log_row_id``      — integer primary key from the ``logs`` table.
 * ``timestamp``       — ISO-8601 UTC string for display.
 * ``action``          — canonical action (BLOCK/DROP/ALERT/ALLOW/LOG).
 * ``rule_id``         — rule identifier, if any.
 * ``payload_snippet`` — up to 200 chars of the matched payload, if any.
 *
 * SECURITY (ADR-0029 D3): payload_snippet and rule_id are attacker-controlled.
 * Render as text nodes only — never via dangerouslySetInnerHTML.
 */
export interface EventSummary {
  log_row_id: number
  timestamp: string
  action: string
  rule_id: string | null
  payload_snippet: string | null
}

/**
 * Evidence for one rule-based score factor (ADR-0041).
 *
 * ``factor``      — machine key matching ScoreBreakdownItem.factor.
 * ``label``       — human-readable label (same as ScoreBreakdownItem.label).
 * ``points``      — points contribution (same as ScoreBreakdownItem.points).
 * ``log_row_ids`` — primary-key ids of the contributing ``logs`` rows.
 * ``count``       — convenience length of ``log_row_ids``.
 * ``summaries``   — minimal per-row descriptors.
 *
 * SECURITY (ADR-0029 D3): summaries fields are attacker-controlled.
 * Render as text nodes only.
 */
export interface FactorEvidence {
  factor: string
  label: string
  points: number
  log_row_ids: number[]
  count: number
  summaries: EventSummary[]
}

/**
 * Evidence for the ``ai_boost`` factor — a reference to the stored AI artifact.
 *
 * The AI boost evidence is NOT a re-run of sample building or any LLM call
 * (ai-engine-invariants / ADR-0041 hard boundary). It carries a reference to
 * the stored AI analysis artifact with its ADR-0035 provenance tag.
 *
 * ``factor``       — always ``"ai_boost"``.
 * ``label``        — human-readable label.
 * ``points``       — factor contribution.
 * ``provenance``   — ADR-0035 derivation tag: ``"ai"`` or ``"ai+rule"``.
 * ``threat_level`` — AI-assessed threat level from the stored artifact.
 * ``confidence``   — AI confidence from the stored artifact (0–1).
 * ``note``         — explanation of read-time semantics.
 *
 * Discriminated from FactorEvidence by ``factor === "ai_boost"``.
 */
export interface AiBoostEvidence {
  factor: 'ai_boost'
  label: string
  points: number
  provenance: string
  threat_level: string | null
  confidence: number | null
  note?: string
}

/**
 * Union of all evidence item shapes.
 * Discriminated by ``factor``: ``"ai_boost"`` → AiBoostEvidence; others → FactorEvidence.
 */
export type EvidenceItem = FactorEvidence | AiBoostEvidence

/**
 * Response from GET /threats/{ip}/evidence (ADR-0041 / MI-6).
 *
 * ``source_ip``  — the queried IP.
 * ``factors``    — per-factor evidence items (one per breakdown factor).
 * ``recomputed`` — always true; events arriving after scoring may shift sets.
 *
 * Rendering MUST NOT trigger any LLM call (ai-engine-invariants boundary).
 */
export interface EvidenceChainResponse {
  source_ip: string
  factors: EvidenceItem[]
  recomputed: boolean
}

// ---------------------------------------------------------------------------
// ADR-0044 / MK-7 — AI analysis detail type (GET /ai/analyses/{id})
// ---------------------------------------------------------------------------

/**
 * Full analysis record from GET /ai/analyses/{id} (MK-7 prompt drawer).
 *
 * Extends AnalysisSummary with the prompt/response text and truncation flags.
 * These fields are intentionally absent from the list endpoint (ADR-0044 §Security /
 * OWASP LLM05 — they are attacker-influenced and returned only here).
 *
 * SECURITY (ADR-0029 D3 / OWASP LLM05):
 *   prompt_text and response_text are the most attacker-controlled strings in
 *   the product (they contain sentinel-wrapped attacker payloads). Callers MUST
 *   render them as text nodes ONLY — never via dangerouslySetInnerHTML. No markdown
 *   rendering, no HTML interpretation, no ANSI escape processing.
 */
export interface AnalysisDetail extends AnalysisSummary {
  /**
   * The exact prompt sent to the local model, including sentinel-delimited
   * attacker-payload samples (<untrusted_data>…</untrusted_data>).
   * SECURITY: attacker-controlled — text node only.
   */
  prompt_text: string | null
  /**
   * The raw text response from the model before JSON validation.
   * SECURITY: model-authored, may contain attacker-influenced values —
   * text node only.
   */
  response_text: string | null
  /**
   * The validated JSON object the product consumed (closed output schema).
   * Fields: threat_level, confidence, intent, attack_stage, insights,
   * recommended_action, and (detailed) executive_summary, attack_progression, etc.
   * Null when the response failed JSON validation.
   */
  validated_json: Record<string, unknown> | null
  /**
   * True when prompt_text was truncated at 64 KiB during persistence.
   * Show a "truncated at 64 KiB" notice when true.
   */
  prompt_truncated: boolean
  /**
   * True when response_text was truncated at 64 KiB during persistence.
   * Show a "truncated at 64 KiB" notice when true.
   */
  response_truncated: boolean
}

// ---------------------------------------------------------------------------
// ML-7 — Narration response (GET /threats/{ip}/narration, issue #435)
// ---------------------------------------------------------------------------

/**
 * Response from GET /threats/{ip}/narration (ML-7, issue #435).
 *
 * A SHORT (≤ 120 words) narrative grounded ONLY in fields actually collected
 * for this IP.  Every claim is tied to a real field — NULL/absent dimensions
 * are never asserted (anti-fabrication, EARS-3).
 *
 * ``provenance``       — ADR-0035 derivation tag: 'rule' | 'ai' | 'ai+rule'.
 *                        'rule' when the LLM was not called (offline / ai=false).
 * ``collected_fields`` — list of field names actually used; absent fields are
 *                        NOT listed (anti-fabrication).
 * ``ai_status``        — pipeline ai_status at the time of this call.
 *
 * SECURITY (ADR-0029 D3): ``narrative`` is LLM-authored text (model output).
 * Callers MUST render it as a text node ONLY — never via dangerouslySetInnerHTML.
 */
export interface NarrationResult {
  /** The queried IP address. */
  source_ip: string
  /**
   * Short narrative (≤ 120 words).  LLM-authored when provenance includes 'ai',
   * deterministic rule-based text when provenance='rule'.
   * SECURITY: render as text node only.
   */
  narrative: string
  /**
   * ADR-0035 provenance tag: 'rule' | 'ai' | 'ai+rule'.
   * Determines which ProvenanceChip to show (EARS-2).
   */
  provenance: string
  /**
   * Field names actually used to build the narration.
   * Fields that were NULL/absent are NOT listed (anti-fabrication, EARS-3).
   */
  collected_fields: string[]
  /**
   * Pipeline ai_status at narration time.
   * 'unavailable' | 'skipped' | 'disabled' → rule-only path was used.
   */
  ai_status: AiStatus
}

// ---------------------------------------------------------------------------
// MK-8 / MK-9 — AI baseline and drift-report types
// GET /ai/baseline → BaselineStatus
// GET /ai/baseline/drift → DriftReport
// Mirrors firewatch_core.ai.baseline.drift_report shape (build_drift_report).
// ---------------------------------------------------------------------------

/**
 * Response from GET /ai/baseline.
 *
 * Returned as {"exists": false} when no baseline has been saved.
 * When a baseline exists, "exists" is true plus optional metadata.
 * `model` and `saved_at` are null in the current implementation (not stored
 * in the baseline file format — see routes/ai_baseline.py).
 */
export type BaselineStatus =
  | { exists: false }
  | {
      exists: true
      model: string | null
      saved_at: string | null
      scenario_count: number
    }

/**
 * One changed scenario in a drift report diff list.
 * Mirrors the `diffs[]` element from build_drift_report in drift_report.py.
 *
 * SECURITY (ADR-0029 D3): scenario, baseline_summary, candidate_summary are
 * model-authored / synthetic fixture names — render as text nodes only.
 */
export interface DriftDiff {
  /** Scenario identifier (synthetic fixture name — text node). */
  scenario: string
  /** Baseline model threat_level verdict. */
  baseline_verdict: string
  /** Candidate model threat_level verdict. */
  candidate_verdict: string
  /** Baseline model confidence (0–1). */
  baseline_confidence: number
  /** Candidate model confidence (0–1). */
  candidate_confidence: number
  /**
   * Baseline model recommended_action string (e.g. "block", "monitor").
   * SECURITY: model-authored — text node only.
   */
  baseline_summary: string
  /**
   * Candidate model recommended_action string.
   * SECURITY: model-authored — text node only.
   */
  candidate_summary: string
}

/**
 * Response from GET /ai/baseline/drift.
 *
 * 404 when no comparison has been run yet (caller should show honest empty state).
 * 422 when the report file is corrupt/oversized (caller should prompt re-run).
 *
 * Mirrors the full report dict from build_drift_report in drift_report.py.
 *
 * `diffs` contains one entry per scenario where any drift field differed.
 * An empty `diffs` list means scenarios were evaluated but no changes found.
 *
 * SECURITY (ADR-0029 D3): baseline_model and candidate_model are server-validated
 * model IDs — render as text nodes only.
 */
export interface DriftReport {
  /** Model ID used to produce the baseline (text node). */
  baseline_model: string
  /** Model ID used for the candidate comparison run (text node). */
  candidate_model: string
  /** ISO-8601 UTC timestamp of this comparison run. */
  run_at: string
  /** Total number of scenarios evaluated. */
  scenarios: number
  /** Count of scenarios where any drift field differed. */
  changed: number
  /** Changed scenarios where threat_level moved to a higher severity. */
  escalations: number
  /** Changed scenarios where threat_level moved to a lower severity. */
  deescalations: number
  /** Per-changed-scenario diff entries. Empty list when no drift found. */
  diffs: DriftDiff[]
}

// ---------------------------------------------------------------------------
// ML-8 / ML-9 — Entity graph types (GET /logs/graph, issue #436/#437)
// Mirrors GraphNode / GraphEdge / EntityGraphResponse in
// packages/firewatch-api/src/firewatch_api/schemas.py
// ---------------------------------------------------------------------------

/**
 * One node in the entity graph (ML-8 / ML-9).
 *
 * ``type``  — entity kind: ``"ip"`` | ``"asn"`` | ``"category"``.
 * ``id``    — stable identifier (IP string, ``"asn:<N>"``, or ``"cat:<value>"``).
 * ``label`` — human-readable display string.
 *
 * SECURITY (ADR-0029 D3): ``id`` and ``label`` for IP/category nodes originate
 * from attacker-controlled telemetry.  Render as text nodes only.
 */
export interface GraphNode {
  /** Entity kind: "ip" | "asn" | "category". */
  type: 'ip' | 'asn' | 'category' | string
  /** Stable identifier — attacker-controlled for IP/category nodes (text node only). */
  id: string
  /** Human-readable display string — attacker-controlled (text node only). */
  label: string
}

/**
 * One directed edge in the entity graph.
 *
 * ``source`` — id of the source node.
 * ``target`` — id of the target node.
 * ``weight`` — event count for this relationship (positive integer).
 * ``kind``   — edge type: ``"flow"`` | ``"asn"`` | ``"category"``.
 */
export interface GraphEdge {
  /** Source node id. */
  source: string
  /** Target node id. */
  target: string
  /** Event count for this relationship. */
  weight: number
  /** Edge type: "flow" | "asn" | "category". */
  kind: 'flow' | 'asn' | 'category' | string
}

/**
 * Response envelope from GET /logs/graph (ML-8 / ML-9, issue #436).
 *
 * ``nodes``     — deduplicated list of entity nodes.
 * ``edges``     — directed weighted edges, ranked by weight descending.
 * ``truncated`` — true when raw cardinality exceeded the cap; the returned
 *                 subgraph is the highest-weight subset (EARS-3).
 *
 * SECURITY (ADR-0029 D3): node ids/labels from telemetry are attacker-controlled.
 * Render as plain text only.
 */
export interface EntityGraphResponse {
  /** Deduplicated entity nodes. */
  nodes: GraphNode[]
  /** Directed weighted edges. */
  edges: GraphEdge[]
  /**
   * True when raw cardinality exceeded the cap; the returned subgraph is the
   * highest-weight subset (EARS-3).  Render an honest "showing top N" chip when true.
   */
  truncated: boolean
}

// ---------------------------------------------------------------------------
// Triage decisions — ADR-0072 D2/D3, issue #47 (server-side triage persistence)
//
// Mirrors packages/firewatch-api/src/firewatch_api/schemas.py's
// CreateDecisionRequest / DecisionRecord / ListDecisionsResponse.
// Consumed by api/decisions.ts. `acknowledge` is retired (ADR-0072 D6) — the
// verb vocabulary here is the closed 3-value set the store accepts.
// ---------------------------------------------------------------------------

/**
 * The three verbs an operator may record against an actor (or actor+rule)
 * via `POST /decisions` (ADR-0072 D2/D6). NOT the SIEM `ThreatActionVerb`
 * (lib/triageActions.ts) — that is the UI-facing action-seam vocabulary;
 * this is the server-store vocabulary the seam's `dismiss`/`block` verbs
 * translate into.
 */
export type TriageDecisionVerb = 'expected' | 'dismissed' | 'false_positive'

/**
 * Request body for `POST /decisions` (ADR-0072 D3).
 *
 * `decided_tier`/`decided_score` are NEVER sent by the client — the server
 * computes them by running the actor through the pipeline at decision time
 * (ADR-0072 D2 "snapshot authority is the server"; a stale tab must not write
 * a stale re-entry baseline).
 *
 * `rule_name` is required iff `verb === 'false_positive'` — the server
 * returns 422 on a mismatch.
 */
export interface CreateDecisionRequest {
  actor_ip: string
  verb: TriageDecisionVerb
  rule_name?: string | null
  note?: string | null
}

/**
 * One `triage_decisions` row on the wire (ADR-0072 D2) — full history shape.
 * Returned by `POST /decisions` (the new row incl. server snapshot) and as
 * each item of `GET /decisions`' cursor envelope.
 */
export interface DecisionRecord {
  id: number
  actor_ip: string
  verb: TriageDecisionVerb
  rule_name: string | null
  /** Verdict tier at decision time; null = observed stratum. */
  decided_tier: number | null
  decided_score: number
  /** UTC ISO-8601 — server-stamped. */
  decided_at: string
  /** Null = active; set by `DELETE /decisions/{id}` (soft-revoke). */
  revoked_at: string | null
  /** Defaults to 'local operator' (ADR-0053 D3 seam). */
  author: string
  note: string | null
}

/** `GET /decisions` — ADR-0029 D2 cursor envelope, newest-first. */
export interface ListDecisionsResponse {
  items: DecisionRecord[]
  next_cursor: string | null
  has_more: boolean
}
