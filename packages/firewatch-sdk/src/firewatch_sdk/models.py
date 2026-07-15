"""Canonical domain models for FireWatch — the lingua franca of the pipeline.

Pure Pydantic v2; depends only on stdlib + pydantic. Every plugin and core consume or
produce these types. Ported from ``legacy/core/models.py`` and reconciled with the
accepted ADRs:
- ADR-0016 / Flag B — two-axis ECS source identity: ``source_type`` (constant the plugin
  declares) + ``source_id`` (the user's named instance). Replaces legacy ``source_module``.
- ADR-0014 — MITRE ATT&CK / CAPEC fields populated at normalize-time.
- ADR-0020 — lightweight OCSF alignment (``ocsf_class``/``ocsf_category`` formalized).
- Flag A — ``action`` retains the non-blocking ``LOG`` disposition.
"""
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# IDS detections → ALERT, WAF/IPS blocks → BLOCK (ADR-0012); LOG is non-blocking
# informational (e.g. Syslog SSH-Login), kept per Flag A.
ActionLiteral = Literal["ALLOW", "BLOCK", "DROP", "ALERT", "LOG"]
# `info` retained — maps cleanly to OCSF severity_id=1 Informational (ADR-0020).
SeverityLiteral = Literal["info", "low", "medium", "high", "critical"]
ThreatLevelLiteral = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
AIStatusLiteral = Literal["active", "degraded", "unavailable", "disabled"]


class RawEvent(BaseModel):
    """Source-shaped payload before normalization.

    Collectors emit these; the owning plugin's ``normalize()`` turns them into a
    ``SecurityEvent``. ``data`` is opaque to core — only the plugin knows its shape, and
    unmapped vendor fields stay here (PLUGIN_CONTRACT.md). ``source_type`` lets the
    pipeline route a raw event to the right normalizer; ``source_id`` is supplied to
    ``normalize(raw, source_id)`` separately.
    """

    source_type: str
    received_at: datetime
    data: dict[str, Any]


class SecurityEvent(BaseModel):
    """Normalized event flowing through the pipeline (the canonical model)."""

    event_id: str | None = None

    # Source identity — two ECS-aligned axes (ADR-0016 / Flag B).
    source_type: str          # constant the plugin declares  (≈ ECS event.module)
    source_id: str            # user's named instance         (≈ ECS observer.name)
    source_event_id: str | None = None

    timestamp: datetime

    source_ip: str
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_ip: str | None = None
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None

    action: ActionLiteral
    category: str | None = None
    severity: SeverityLiteral | None = None
    rule_id: str | None = None
    rule_name: str | None = None

    payload_snippet: str | None = None

    geo_country: str | None = None
    geo_city: str | None = None
    geo_lat: float | None = None
    geo_lon: float | None = None

    # MITRE ATT&CK / CAPEC — populated at normalize-time where derivable (ADR-0014).
    attack_technique: str | None = None   # e.g. T1190
    attack_tactic: str | None = None      # e.g. TA0001
    kill_chain_phase: str | None = None   # derived from tactic
    capec_id: str | None = None           # e.g. CAPEC-66

    # Lightweight OCSF alignment (ADR-0020). class_uid / category_uid, set per source at normalize-time.
    ocsf_class: int | None = None         # e.g. 4002 = HTTP Activity (WAF/web); see docs/research/azure-waf-log-standard.md
    ocsf_category: int | None = None      # e.g. 4 = Network Activity

    # ---------------------------------------------------------------------------
    # ADR-0048 — OCSF network-depth fields (ML-1, all optional/nullable).
    # Every field defaults to None; no source is forced to populate any of them.
    # ---------------------------------------------------------------------------

    # Group A — flow volume & duration → OCSF Network Activity (class_uid 4001,
    # category_uid 4), Network Traffic object.
    # ECS anchor for duration: event.duration (ns) → we store ms for readability
    # (documented deviation; OCSF has no first-class duration scalar on Network Activity).
    bytes_in: int | None = None
    """Bytes from responder→originator. OCSF Network Traffic bytes_in. (ECS destination.bytes.)"""
    bytes_out: int | None = None
    """Bytes originator→responder. OCSF Network Traffic bytes_out. (ECS source.bytes.)"""
    packets_in: int | None = None
    """Packets responder→originator. OCSF Network Traffic packets_in. (ECS destination.packets.)"""
    packets_out: int | None = None
    """Packets originator→responder. OCSF Network Traffic packets_out. (ECS source.packets.)"""
    flow_duration_ms: int | None = None
    """Connection duration in milliseconds. ECS event.duration (ns) stored as ms. (ADR-0048 deviation.)"""

    # Group B — DNS → OCSF DNS Activity (class_uid 4003, category_uid 4),
    # DNS Query object.
    dns_query: str | None = None
    """Queried FQDN. OCSF DNS Query hostname. (ECS dns.question.name.) Feeds R8 DGA detection."""
    dns_rcode: str | None = None
    """DNS response code (e.g. NXDOMAIN). OCSF rcode. (ECS dns.response_code.)"""

    # Group C — TLS / fingerprint → OCSF TLS object (on Network Activity 4001).
    # JA4/JA4S are an emerging fingerprint standard (FoxIO) added to ECS tls.* in 8.x.
    tls_ja4: str | None = None
    """JA4 client fingerprint. (ECS tls.client.ja4.) Feeds R8 JA4+ detection."""
    tls_ja4s: str | None = None
    """JA4S server fingerprint. (ECS tls.server.ja4s.)"""
    tls_sni: str | None = None
    """TLS SNI server name. OCSF TLS sni. (ECS tls.client.server_name.)"""
    tls_version: str | None = None
    """Negotiated TLS version (e.g. TLSv1.3). OCSF TLS version. (ECS tls.version.)"""

    # Group D — HTTP → OCSF HTTP Activity (class_uid 4002, category_uid 4),
    # HTTP Request object.
    http_method: str | None = None
    """HTTP request method. OCSF HTTP Request http_method. (ECS http.request.method.)"""
    http_host: str | None = None
    """HTTP Host header / URL domain. OCSF/ECS url.domain."""
    http_url: str | None = None
    """Full request URL. OCSF HTTP Request url. (ECS url.full.)"""
    http_user_agent: str | None = None
    """HTTP User-Agent header. OCSF HTTP Request user_agent. (ECS user_agent.original.)"""

    # ---------------------------------------------------------------------------
    # ADR-0055 — file-IOC, DNS-answer, JA3 fields (issue #602, all optional/nullable).
    # Every field defaults to None; no source is forced to populate any of them.
    # Zeek populates from files.log / dns.log / ssl.log; Suricata may populate file_*
    # from fileinfo events; Azure WAF / syslog leave them null (no fabrication).
    # ---------------------------------------------------------------------------

    # Group E — File IOC → OCSF File object + Fingerprint (Detection Finding 2004 /
    # File System Activity).  Flat scalars per ADR-0020 lightweight-alignment stance;
    # the ADR-0040 OCSF serializer reassembles File.hashes[] at the export boundary
    # (same pattern as ADR-0048 flat network-depth fields — deviation documented in
    # ADR-0055 §Standard alignment).
    # Ref: OCSF 1.8.0 File object https://schema.ocsf.io/ (File.hashes, Fingerprint)
    # Ref: ECS file fields https://www.elastic.co/guide/en/ecs/current/ecs-file.html
    file_sha256: str | None = None
    """SHA-256 file hash. OCSF File.hashes[].value (algorithm_id=3). ECS file.hash.sha256.
    Primary threat-intel join key (VirusTotal/MISP pivot). Queryable via FilterSpec."""
    file_md5: str | None = None
    """MD5 file hash. OCSF File.hashes[].value (algorithm_id=1). ECS file.hash.md5."""
    file_sha1: str | None = None
    """SHA-1 file hash. OCSF File.hashes[].value (algorithm_id=2). ECS file.hash.sha1."""
    file_name: str | None = None
    """File name (e.g. malware.exe). OCSF File.name. ECS file.name."""
    file_mime_type: str | None = None
    """MIME type (e.g. application/x-dosexec). OCSF File.mime_type. ECS file.mime_type."""

    # Group F — DNS answers → OCSF DNS Activity (class_uid 4003), DNS Answer object.
    # Stored as a comma-joined flat scalar (ADR-0055 deviation: avoids nested JSON
    # column in SQLite; export serializer splits to OCSF answers[].rdata at boundary).
    # Ref: OCSF DNS Activity https://schema.ocsf.io/ (class_uid 4003, Answer object)
    # Ref: ECS DNS https://www.elastic.co/guide/en/ecs/current/ecs-dns.html
    dns_answer: str | None = None
    """Resolved DNS answer values, comma-joined (A/AAAA/CNAME).
    OCSF DNS Activity answers[].rdata. ECS dns.answers[].data / dns.resolved_ip.
    Queryable via FilterSpec for passive-DNS pivoting."""

    # Group G — JA3 client fingerprint → OCSF TLS object (on Network Activity 4001).
    # JA4 (tls_ja4, ADR-0048/ML-13) remains the strategic fingerprint; tls_ja3 is
    # carried ALONGSIDE it for compatibility with stock Zeek and widely-deployed sensors
    # that still emit only JA3.  tls_ja3s (server) is deliberately skipped — analysts
    # pivot on the client fingerprint, and JA4S covers the server side strategically.
    # Ref: ECS TLS https://www.elastic.co/guide/en/ecs/current/ecs-tls.html (tls.client.ja3)
    tls_ja3: str | None = None
    """JA3 client fingerprint. ECS tls.client.ja3. Stock-Zeek default fingerprint.
    Coexists with tls_ja4 (ADR-0048/ML-13); JA3 for sensor compatibility, JA4 forward."""

    # Source's original payload when available (retained for raw-log drill-down).
    raw_log: dict[str, Any] | None = None


class Sample(BaseModel):
    """Per-IP sample handed to the AI engine (one LLM call per IP, ADR-0003)."""

    source_ip: str
    total_events: int
    blocked_events: int
    first_seen: datetime
    last_seen: datetime
    categories: list[str]
    events: list[SecurityEvent]


class Detection(BaseModel):
    """Output of a rule or correlation match.

    ADR-0058 §D3 (issue #647) adds two **additive, defaulted** fields:

    ``severity``      — Sigma-anchored level (``SeverityLiteral | None``).
                        Populated by ``detector.py`` rules that have registered a
                        declared severity in ``escalation.policy.ESCALATION_POLICY``.
                        ``None`` when the producing rule has not declared a level —
                        a safe default that changes no existing behaviour.

    ``auto_escalate`` — ``True`` when the rule is loud enough to jump the triage
                        queue without waiting for volume or AI confirmation.
                        Consumed by the D2 decider (issue #648).
                        Defaults to ``False`` — non-escalating — so all existing
                        plugins remain conformant with no changes required.

    Standard anchor:
    - Sigma ``level`` vocabulary — https://sigmahq.io/docs/basics/rules.html
    - Elastic Detection Rules ``risk_score`` (0-100 ordinal) —
      https://www.elastic.co/guide/en/security/current/rules-ui-create.html
    """

    source_ip: str
    rule_name: str
    score_delta: int
    reason: str
    matched_event_ids: list[str] = []
    # ADR-0058 §D3 (issue #647) — additive, defaulted, non-breaking.
    # Existing plugins that construct Detection(...) without these fields continue to work
    # (defaults: severity=None, auto_escalate=False) — the ADR-0048/0055 additive pattern.
    severity: SeverityLiteral | None = None
    auto_escalate: bool = False


class FilterSpec(BaseModel):
    """Typed filter set for paginated event queries (ADR-0007/0011).

    All fields optional. Empty ``FilterSpec`` returns unfiltered results. Source identity
    is filterable on both axes (ADR-0016): ``source_type`` (telemetry type) and
    ``source_id`` (a specific named instance).
    """

    cursor: str | None = None         # "<iso_timestamp>|<id>"
    category: str | None = None       # canonical stored value (exact match); legacy shorthands sqli/xss/lfi/cmdi/proto/anomaly/bot/ratelimit/geo accepted as aliases; "all" = no filter (issue #325)
    category_name: str | None = None  # DEPRECATED synonym for category exact-match; use category= instead
    ip: str | None = None             # substring match on source_ip
    action: str | None = None         # ALLOW/BLOCK/DROP/ALERT (exact); "blocked" = BLOCK+DROP shorthand (issue #252)
    rule: str | None = None           # substring match on rule_id
    source_type: str | None = None    # exact match on source telemetry type
    source_id: str | None = None      # exact match on named instance
    severity: str | None = None       # critical/high/medium/low
    q: str | None = None              # free-text: IP, rule, payload, signature
    # ML-3 (issue #431) — destination dimension filters
    destination_ip: str | None = None  # substring match on destination_ip (EARS-1)
    protocol: str | None = None        # exact match on protocol, e.g. TCP/UDP/ICMP (EARS-1)
    # ML-13 (issue #441) — JA4+ TLS fingerprint facet (consume-only, ADR-0048)
    tls_ja4: str | None = None         # exact match on tls_ja4 fingerprint (EARS-1)
    # ML-10 (issue #438) — behavioral anomaly lane facet (EARS-2).
    # Open string (not enum) so ML-11 and future detectors extend the lane with
    # zero schema/contract changes: write a new anomaly_type to anomaly_verdicts,
    # pass the same string here, and the filter surfaces those rows automatically.
    # Known values: "beaconing" (ML-10), "rare_flow" (ML-10).
    anomaly_type: str | None = None    # exact match on anomaly_verdicts.anomaly_type; None = no filter
    # ADR-0055 (issue #602) — file-IOC and DNS-answer queryable facets (EARS-3).
    # file_sha256: exact match on the file_sha256 column (threat-intel IOC pivot).
    # dns_answer:  exact match on the dns_answer column (passive-DNS pivoting).
    # Both use ? parameterized placeholders in the store WHERE-builder (B1 invariant).
    file_sha256: str | None = None     # exact match on file_sha256 (EARS-3)
    dns_answer: str | None = None      # exact match on dns_answer (EARS-3)


ScoreDerivationLiteral = Literal["rule", "ai+rule"]

# Escalation disposition literals — ADR-0058 §D2 / §D3.
# Four deterministic labels derived from the action axis (ActionLiteral).
EscalationDispositionLiteral = Literal[
    "allowed_through",       # ALLOW  — request passed; possible success (Tier 1)
    "block_status_unknown",  # ALERT/LOG — neither blocked nor allowed asserted (Tier 2)
    "blocked_persistent",    # BLOCK/DROP, persistent / high-volume (Tier 3)
    "blocked_one_off",       # BLOCK/DROP, one-off (Tier 4)
]
# ADR-0058 Amendment 1 (A1): adds ``"partial"`` for actors whose events span more than
# one terminal disposition class (e.g. some ALERT/LOG AND some BLOCK/DROP).
# OCSF deviation note: OCSF 1.8.0 disposition_id has no mixed/partial concept; the
# "partial" label is a FireWatch extension for honest provenance (ADR-0058 §Standard
# alignment). The four single-class values remain unchanged.
EscalationBlockStatusLiteral = Literal["blocked", "allowed", "unknown", "partial"]


class DispositionCounts(BaseModel):
    """Integer breakdown of events across terminal disposition classes (ADR-0058 A2).

    Structured integer counts, NOT a baked English string — glass-box, testable,
    and i18n-safe.  The frontend formats the human-readable label from these integers.

    ``blocked``       — count of BLOCK/DROP events for this actor.
    ``alert_unknown`` — count of ALERT/LOG events for this actor (block status unknown).
    ``allowed``       — count of ALLOW events for this actor.

    All default to 0 so that single-class actors and callers that omit counts are
    valid without requiring all three fields (ADR-0048/0055 additive pattern).
    """

    blocked: int = 0
    alert_unknown: int = 0
    allowed: int = 0


class EscalationVerdict(BaseModel):
    """Deterministic escalation verdict attached to ``ThreatScore`` (ADR-0058 D2/D3).

    Produced by the pure ``decide(events, detections) -> EscalationVerdict``
    function in ``firewatch_core.escalation.decider``.  **No LLM, no I/O** — free at
    ingest.  Serialises to JSON for dashboard consumption (issue #649).

    Fields (ADR-0058 §D3 / Amendment 1):
    ``tier``               — 1-4 per the 4-tier action model (lower = louder / more urgent).
                             1 = allowed-through (highest); 4 = one-off block (informational).
    ``disposition``        — machine-readable action label (one of four ``EscalationDispositionLiteral``
                             values). Safe for programmatic routing (e.g. banner logic).
    ``justification``      — human-readable, ``RULE``-tagged sentence (ADR-0035) safe to render
                             as a plain text node (e.g.
                             "sqli_rule matched, and the request got through — this may have
                             reached your system"). Wording owned by the decider's justification
                             builders (issue #6); produced by the decider, never by an LLM.
    ``block_status``       — honest, non-fabricated disposition state: ``"blocked"`` /
                             ``"allowed"`` / ``"unknown"`` / ``"partial"`` (A1).
                             ALERT/LOG → ``"unknown"`` (OCSF non-terminating disposition).
                             Mixed (ALERT/LOG + BLOCK/DROP) → ``"partial"`` (ADR-0058 A1).
    ``disposition_counts`` — optional integer breakdown by terminal class (A2).
                             Present on every verdict produced by the decider; ``None``
                             only for legacy/external verdicts that predate the amendment.
                             Defaults to ``None`` so existing serialised shapes remain valid
                             (ADR-0048/0055 additive pattern — no required-field break).

    Standard alignment:
    - Disposition semantics anchored to OCSF ``disposition_id`` (1.8.0):
      Allowed ≈ ALLOW, Blocked ≈ BLOCK/DROP, non-terminating ≈ ALERT/LOG
      (see ADR-0058 §Standard alignment).
    - ``"partial"`` is a FireWatch extension — no OCSF equivalent; see ADR-0058 A1.
    - Provenance: ``justification`` is a ``RULE``-tagged artifact (ADR-0035).
    """

    tier: int = Field(ge=1, le=4)
    disposition: EscalationDispositionLiteral
    justification: str
    block_status: EscalationBlockStatusLiteral
    # ADR-0058 Amendment 1 (A2) — additive, optional (non-breaking).
    # Populated by the decider on every verdict; None for pre-amendment external shapes.
    disposition_counts: DispositionCounts | None = None


class ScoreBreakdownItem(BaseModel):
    """One additive contributing factor in a threat score breakdown (ADR-0036 D4).

    Each item represents a single factor that contributed points to the final
    score.  The ``points`` values across all items sum to the final ``score``
    (after the 100-cap is applied and any cap item accounts for the reduction).

    ``factor`` is a machine-readable key (e.g. ``"brute_force"``, ``"ai_boost"``).
    ``label``  is a human-readable string safe to render as a text node
               (e.g. ``"Brute force — 12 blocked events"``).
    ``points`` is the non-negative integer contribution of this factor
               (for the cap item this is the negative reduction, stored as 0
               with the cap noted in the label).
    """

    factor: str
    label: str
    points: int = 0


class EventSummary(BaseModel):
    """Minimal descriptor for a contributing ``logs`` row (ADR-0041 evidence chain).

    Carries just enough information to let an analyst orient to the event without
    fetching the full row.  The ``log_row_id`` is the stable reference key
    (``logs.id`` integer primary key — the only persistent event identifier in
    production; ``SecurityEvent.event_id`` / ``Detection.matched_event_ids`` are
    empty in production, per ADR-0041).

    ``log_row_id``      — integer primary key from the ``logs`` table.
    ``timestamp``       — ISO-8601 UTC string for display.
    ``action``          — canonical action (BLOCK/DROP/ALERT/ALLOW/LOG).
    ``rule_id``         — rule identifier, if any.
    ``payload_snippet`` — up to 200 chars of the matched payload, if any.
    """

    log_row_id: int
    timestamp: str
    action: str
    rule_id: str | None = None
    payload_snippet: str | None = None


class FactorEvidence(BaseModel):
    """Evidence for one score-breakdown factor, keyed to ``logs`` row ids (ADR-0041).

    ``factor``       — machine-readable factor key (mirrors ``ScoreBreakdownItem.factor``).
    ``label``        — human-readable label (mirrors ``ScoreBreakdownItem.label``).
    ``points``       — factor contribution (mirrors ``ScoreBreakdownItem.points``).
    ``log_row_ids``  — ``logs`` primary-key ids of the contributing rows.
    ``count``        — convenience length of ``log_row_ids``.
    ``summaries``    — minimal per-row descriptors (same order as ``log_row_ids``).

    Recomputed at read time from stored rows — NOT a persisted chain.  Events
    arriving after scoring may shift the set (read-time semantics, ADR-0041).
    """

    factor: str
    label: str
    points: int = 0
    log_row_ids: list[int] = Field(default_factory=list)
    count: int = 0
    summaries: list["EventSummary"] = Field(default_factory=list)


class AiBoostEvidence(BaseModel):
    """Evidence for the ``ai_boost`` factor — a reference to the stored AI artifact.

    The AI boost evidence is NOT a re-run of sample building or any LLM call
    (ai-engine-invariants / ADR-0041 hard boundary).  Instead it carries a
    reference to the stored AI analysis artifact with its ADR-0035 provenance tag.

    ``factor``          — always ``"ai_boost"``.
    ``label``           — human-readable label (mirrors ``ScoreBreakdownItem.label``).
    ``points``          — factor contribution (mirrors ``ScoreBreakdownItem.points``).
    ``provenance``      — ADR-0035 derivation tag (``"ai"`` or ``"ai+rule"``).
    ``threat_level``    — AI-assessed threat level from the stored artifact.
    ``confidence``      — AI confidence from the stored artifact.
    ``note``            — explanation of read-time semantics for API consumers.
    """

    factor: str = "ai_boost"
    label: str
    points: int = 0
    provenance: str = "ai+rule"
    threat_level: str | None = None
    confidence: float | None = None
    note: str = (
        "Evidence is a reference to the stored AI analysis artifact (ADR-0035). "
        "No LLM call or sample rebuild is performed at read time (ADR-0041)."
    )


class ThreatScore(BaseModel):
    """Final per-IP threat verdict.

    ``ai_*`` fields carry the additive AI contribution (additive-only, never
    de-escalating — ARCHITECTURE invariant 3). ``source_types`` records the telemetry
    types that contributed (cross-source provenance, ADR-0016).

    ``location`` is the human-readable geo string for the source IP
    (e.g. "Toronto, Canada") resolved from the ip_geo cache — ``None`` when no
    geo data exists or the IP is non-public (RFC 1918 / loopback). Issue #132.

    ``score_derivation`` records whether the final score was the result of
    deterministic rules alone (``"rule"``) or rules plus an applied AI boost
    (``"ai+rule"``).  Computed at the point of authorship in ``merge_score``
    (ADR-0035 contract point 1 / issue #201).  Additive field — does not affect
    any existing field value.

    ``score_breakdown`` lists every factor that contributed to the final score.
    Points sum to the returned ``score`` value.  When the raw sum exceeded 100
    a ``"cap"`` item records the reduction so the breakdown remains honest
    (ADR-0036 D4 / issue #209).  Additive field; defaults to ``[]``.
    """

    source_ip: str
    threat_level: ThreatLevelLiteral
    score: int = Field(ge=0, le=100)
    total_events: int
    blocked_events: int
    attack_types: list[str]
    first_seen: datetime
    last_seen: datetime
    source_types: list[str] = []
    detections: list[Detection] = []
    ai_insights: list[str] = []
    ai_confidence: float = 0.0
    ai_status: AIStatusLiteral = "disabled"
    location: str | None = None
    score_derivation: ScoreDerivationLiteral = "rule"
    score_breakdown: list[ScoreBreakdownItem] = []
    # ASN enrichment — additive fields populated from the ip_geo cache (issue #211).
    # asn: integer AS number parsed from the ip-api.com "as" field (e.g. 4837).
    # as_name: operator name from the ip-api.com "asname" field (e.g. "CHINA-UNICOM").
    # Both are None when no geo data exists, the IP is non-public, or the provider
    # did not return AS data (free-tier rate-limited response).
    # Field naming follows ECS: asn ~ as.number, as_name ~ as.organization.name.
    # Ref: Elastic Common Schema §as
    # https://www.elastic.co/guide/en/ecs/current/ecs-as.html
    asn: int | None = None
    as_name: str | None = None
    # Score history delta — additive field (issue #250).
    # Signed integer: current score minus earliest score within the look-back
    # window (default 1h, documented in SCORE_HISTORY_DELTA_WINDOW_HOURS in
    # firewatch_core.adapters.sqlite_store).
    # None means the IP has no prior snapshot in the window ("new actor");
    # the UI renders a NEW badge rather than a numeric delta.
    # This field does NOT change scoring behaviour — it is an observation of
    # the already-computed score, read from the score_history store table.
    score_delta: int | None = None
    # ADR-0058 D2/D3 — additive escalation axis (issue #648).
    # ``None`` when no events were present (empty IP) or the decider was not invoked.
    # Must NOT change ``score`` or ``threat_level`` — purely additive observation.
    escalation: "EscalationVerdict | None" = None
