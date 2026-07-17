"""Suricata EVE JSON → SecurityEvent normalization.

Ported from ``legacy/core/normalizer.py::suricata_raw_to_security_event`` (reference
only — never imported). Reconciled with the v2 SecurityEvent schema:
  - ``source_type`` / ``source_id`` (ADR-0016 / Flag B)
  - ``action``: alert.action="blocked" → BLOCK, anything else → ALERT (ADR-0012)
  - ``attack_technique`` / ``attack_tactic`` from ET Open ``mitre_*`` metadata (ADR-0014)
  - ADR-0048 network-depth fields: flow/dns/tls/http sub-objects → nullable fields (ML-2)

``source_type`` is ALWAYS the constant ``"suricata"`` — this plugin owns that mapping.
``source_id`` is the caller-supplied instance name; this function never branches on it.
(PLUGIN_CONTRACT.md "source_type vs source_id" section.)
"""
from datetime import datetime, timezone
from typing import Any

from firewatch_sdk import RawEvent, SecurityEvent

# ── Category map ─────────────────────────────────────────────────────────────
# Ported from legacy/core/normalizer.py::SURICATA_CATEGORY_MAP.
# Suricata alert.category → FireWatch category. Suffixed "(IDS)" so categories
# don't visually collide with OWASP CRS categories on the dashboard.
# Unknown categories fall through to "IDS Alert".
SURICATA_CATEGORY_MAP: dict[str, str] = {
    "Web Application Attack":                  "Web Attack (IDS)",
    "Attempted Information Leak":              "Recon (IDS)",
    "Information Leak":                        "Recon (IDS)",
    "Misc Attack":                             "Misc Attack (IDS)",
    "A Network Trojan was detected":           "Trojan (IDS)",
    "Trojan Activity":                         "Trojan (IDS)",
    "Detection of a Network Scan":             "Port Scan (IDS)",
    "A suspicious string was detected":        "Suspicious (IDS)",
    "Generic Protocol Command Decode":         "Protocol Anomaly (IDS)",
    "Potentially Bad Traffic":                 "Suspicious (IDS)",
    "Attempted Administrator Privilege Gain":  "Privilege Escalation (IDS)",
    "Successful Administrator Privilege Gain": "Privilege Escalation (IDS)",
    "Attempted User Privilege Gain":           "Privilege Escalation (IDS)",
    "Web Application User":                    "Web Attack (IDS)",
    "Misc activity":                           "IDS Alert",
}

# ADR-0069 D4(a) — recalibrated against Sigma's behavioral `level` vocabulary
# (SigmaHQ/sigma-specification, `specification/sigma-rules-specification.md`) and
# Suricata's shipped `classification.config`
# (https://raw.githubusercontent.com/OISF/suricata/master/etc/classification.config,
# quoted in ADR-0068/ADR-0069): priority 1 = trojan-activity/web-application-attack/
# successful-admin, priority 2 = attempted-recon/misc-attack (the ET SCAN / ET
# DROP-reputation ambient mass), priority 3 = misc-activity (ET INFO).
# Suricata integer severity (1=highest priority) → FireWatch severity string.
_SEVERITY_MAP: dict[int, str] = {
    # "should trigger an internal alert and requires a prompt review" (Sigma high) —
    # not `critical`: Sigma reserves that for "probability borders certainty," and a
    # single ET signature match is well-documented as FP-prone.
    1: "high",
    # "Relevant event that should be reviewed manually on a more frequent basis"
    # (Sigma medium) — this class (attempted-recon/misc-attack) is ambient at volume
    # on every internet-exposed sensor (ADR-0068 fact 1); the D1 distribution
    # corollary makes anything higher than `medium` definitionally wrong here.
    2: "medium",
    # "Notable event but rarely an incident... relevant in high numbers or
    # combination with others" (Sigma low) — ET INFO (misc-activity) verbatim.
    3: "low",
    # "expected that a huge amount of events will match" (Sigma informational) —
    # the below-low ordinal floor; unused by the shipped classification.config
    # (reachable via custom classifications only).
    4: "info",
}

# ADR-0069 D3 rule 4 (fail quiet): missing/unparseable/unrecognized severity maps
# to "low" (telemetry-grade) — never fabricated upward to a level that would
# qualify the actor for Tier-2 triage on its own (ADR-0067 D1(b)).
_FAIL_QUIET_SEVERITY = "low"


def _map_severity(raw_severity: Any) -> str:
    """Translate Suricata's integer priority into a FireWatch severity level.

    ADR-0069 D4(a): see ``_SEVERITY_MAP`` for the per-value Sigma justification.
    Missing (``None``) or unparseable (non-integer) values fail quiet to "low"
    (D3 rule 4) rather than defaulting to a mid-scale value that could still
    qualify for triage.
    """
    if raw_severity is None:
        return _FAIL_QUIET_SEVERITY
    try:
        sev_int = int(raw_severity)
    except (ValueError, TypeError):
        return _FAIL_QUIET_SEVERITY
    return _SEVERITY_MAP.get(sev_int, _FAIL_QUIET_SEVERITY)


# Lightweight OCSF class alignment (ADR-0020).
# Sources: https://schema.ocsf.io/classes/detection_finding (class_uid=2004, category_uid=2)
#          https://schema.ocsf.io/classes/network_activity  (class_uid=4001, category_uid=4)
#
# Security-detection categories (IDS/IPS alerts generated by Suricata rule engine):
#   → class_uid=2004 Detection Finding / category_uid=2 Findings
#   OCSF 2004: "detections or alerts generated by security products such as
#               antivirus, EDR, network security monitoring…" — exactly what Suricata is.
#
# Connection-level observation categories (Port Scan, Trojan, Recon):
#   → class_uid=4001 Network Activity / category_uid=4 Network Activity
#   These describe observed network connections, not security-product detections per se.
#   ADR-0020 lightweight alignment: defensible as connection-level events (architect's call).
#
# Maps FireWatch category → (class_uid, category_uid).
_OCSF_CLASS_MAP: dict[str, tuple[int, int]] = {
    "Web Attack (IDS)":           (2004, 2),
    "Recon (IDS)":                (4001, 4),
    "Misc Attack (IDS)":          (2004, 2),
    "Trojan (IDS)":               (4001, 4),
    "Port Scan (IDS)":            (4001, 4),
    "Suspicious (IDS)":           (2004, 2),
    "Protocol Anomaly (IDS)":     (2004, 2),
    "Privilege Escalation (IDS)": (2004, 2),
    "IDS Alert":                  (2004, 2),
}

# Constant source_type — this plugin declares "suricata" as its type key and
# every SecurityEvent it emits carries this constant (PLUGIN_CONTRACT.md / Flag B).
SOURCE_TYPE: str = "suricata"


def _flow_duration_ms(flow: dict) -> int | None:
    """Compute flow duration in milliseconds from EVE flow.start / flow.end.

    EVE encodes start/end as ISO-8601 strings (e.g. "2026-01-15T10:24:58.000000+0000").
    Returns None if either key is absent or unparseable — honest over approximate.

    ADR-0048 deviation: stored as ms; OCSF has no first-class duration scalar on
    Network Activity (ECS anchor: event.duration in ns → we store ms for readability).
    """
    start_str: str | None = flow.get("start")
    end_str: str | None = flow.get("end")
    if not start_str or not end_str:
        return None
    try:
        start_dt = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
        # Ensure both are timezone-aware for subtraction
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=timezone.utc)
        if end_dt.tzinfo is None:
            end_dt = end_dt.replace(tzinfo=timezone.utc)
        delta_ms = int((end_dt - start_dt).total_seconds() * 1000)
        return delta_ms if delta_ms >= 0 else None
    except (ValueError, AttributeError, OverflowError):
        return None


def normalize(raw: RawEvent, source_id: str) -> SecurityEvent:
    """Map a Suricata EVE JSON alert (wrapped in a RawEvent) to a SecurityEvent.

    Implements the PLUGIN_CONTRACT.md ``normalize()`` responsibility for the Suricata
    source. Must set ``source_type="suricata"`` (constant) and pass ``source_id``
    through without branching on it (Flag B).

    Action mapping (ADR-0012):
      - ``alert.action == "blocked"`` → ``BLOCK``  (IPS mode dropped the packet)
      - anything else                → ``ALERT``  (IDS detected, not blocked)

    MITRE ATT&CK (ADR-0014):
      - ET Open ``alert.metadata.mitre_technique_id[0]`` → ``attack_technique``
      - ET Open ``alert.metadata.mitre_tactic_id[0]``    → ``attack_tactic``

    ADR-0048 network-depth fields (ML-2):
      - flow  → bytes_in/out, packets_in/out, flow_duration_ms
      - dns   → dns_query (rrname), dns_rcode
      - tls   → tls_ja4/ja4s (Suricata 7.x+ only; null when absent), tls_sni, tls_version
               NOTE: tls.ja3 is intentionally NOT mapped to tls_ja4 — they are
               different fingerprint algorithms; copying ja3→ja4 would poison detections.
      - http  → http_method, http_host (hostname), http_url (url), http_user_agent

    All ADR-0048 fields are optional and default to None when the sub-object is absent.
    """
    d = raw.data
    alert = d.get("alert") or {}
    metadata_tags: dict = alert.get("metadata") or {}

    # ── Timestamp ─────────────────────────────────────────────────────────────
    ts_str = d.get("timestamp", "")
    try:
        timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        timestamp = raw.received_at

    # ── Category / OCSF ──────────────────────────────────────────────────────
    category = SURICATA_CATEGORY_MAP.get(
        str(alert.get("category") or ""), "IDS Alert"
    )
    ocsf_class, ocsf_category = _OCSF_CLASS_MAP.get(category, (None, None))

    # ── Action (ADR-0012) ─────────────────────────────────────────────────────
    raw_action = str(alert.get("action") or "").lower()
    action = "BLOCK" if raw_action == "blocked" else "ALERT"

    # ── Severity (ADR-0069 D4a) ───────────────────────────────────────────────
    # NB-4 — guard against non-integer severity values (e.g. "critical" string).
    # Suricata always sends an integer, but defensive parsing prevents a ValueError
    # from crashing the pipeline if a malformed event slips through.
    severity = _map_severity(alert.get("severity"))

    # ── Rule ─────────────────────────────────────────────────────────────────
    sig_id = alert.get("signature_id")
    rule_id = str(sig_id) if sig_id is not None else None
    rule_name: str | None = alert.get("signature") or None

    # ── Source event ID (flow-level dedup) ────────────────────────────────────
    flow_id = d.get("flow_id")
    source_event_id = str(flow_id) if flow_id is not None else None

    # ── HTTP payload snippet ──────────────────────────────────────────────────
    http = d.get("http") or {}
    http_url: str | None = http.get("url") or None
    http_host: str | None = http.get("hostname") or None
    payload_snippet: str | None
    if http_url:
        raw_snippet: str = (http_host + http_url) if http_host else http_url
        payload_snippet = raw_snippet[:500]
    else:
        payload_snippet = None

    # ── MITRE ATT&CK from ET Open metadata (ADR-0014) ─────────────────────────
    # ET Open embeds technique/tactic lists in alert.metadata:
    #   mitre_technique_id: ["T1190"]
    #   mitre_tactic_id:    ["TA0001"]
    technique_ids: list[str] = metadata_tags.get("mitre_technique_id") or []
    attack_technique: str | None = technique_ids[0] if technique_ids else None

    tactic_ids: list[str] = metadata_tags.get("mitre_tactic_id") or []
    attack_tactic: str | None = tactic_ids[0] if tactic_ids else None

    # ── ADR-0048 Group A: flow volume & duration ──────────────────────────────
    # Suricata EVE flow keys: bytes_toserver (originator→responder = bytes_out),
    # bytes_toclient (responder→originator = bytes_in), pkts_toserver/pkts_toclient.
    # Direction follows ADR-0048: bytes_in = responder→originator (toclient).
    flow_obj: dict = d.get("flow") or {}
    bytes_in: int | None = flow_obj.get("bytes_toclient")
    bytes_out: int | None = flow_obj.get("bytes_toserver")
    packets_in: int | None = flow_obj.get("pkts_toclient")
    packets_out: int | None = flow_obj.get("pkts_toserver")
    flow_duration_ms: int | None = _flow_duration_ms(flow_obj) if flow_obj else None

    # ── ADR-0048 Group B: DNS ─────────────────────────────────────────────────
    # Suricata EVE dns keys: rrname (queried FQDN), rcode (response code).
    dns_obj: dict = d.get("dns") or {}
    dns_query: str | None = dns_obj.get("rrname") or None
    dns_rcode: str | None = dns_obj.get("rcode") or None

    # ── ADR-0048 Group C: TLS / JA4 ──────────────────────────────────────────
    # Suricata EVE tls keys: sni, version, ja4 (7.x+ only), ja4s (7.x+ only).
    # IMPORTANT: ja3/ja3s are a different fingerprint algorithm from ja4/ja4s.
    # Do NOT copy tls.ja3 into tls_ja4 — that would silently corrupt the JA4 data.
    # ADR-0048 sub-decision: consume tls.ja4 when the sensor emits it, null otherwise.
    tls_obj: dict = d.get("tls") or {}
    tls_sni: str | None = tls_obj.get("sni") or None
    tls_version: str | None = tls_obj.get("version") or None
    tls_ja4: str | None = tls_obj.get("ja4") or None      # 7.x+ only; None on older builds
    tls_ja4s: str | None = tls_obj.get("ja4s") or None    # 7.x+ only; None on older builds

    # ── ADR-0048 Group D: HTTP ────────────────────────────────────────────────
    # Suricata EVE http keys: http_method, hostname (http_host), url (http_url),
    # http_user_agent. All are optional; absent when no HTTP decoding occurred.
    http_method: str | None = http.get("http_method") or None
    http_user_agent: str | None = http.get("http_user_agent") or None

    return SecurityEvent(
        source_type=SOURCE_TYPE,   # constant — never branches on source_id (Flag B)
        source_id=source_id,       # caller's instance name, passed through as-is
        source_event_id=source_event_id,
        timestamp=timestamp,
        source_ip=d.get("src_ip") or "",
        source_port=d.get("src_port"),
        destination_ip=d.get("dest_ip"),
        destination_port=d.get("dest_port"),
        protocol=d.get("proto"),
        action=action,  # type: ignore[arg-type]
        category=category,
        severity=severity,  # type: ignore[arg-type]
        ocsf_class=ocsf_class,
        ocsf_category=ocsf_category,
        rule_id=rule_id,
        rule_name=rule_name,
        payload_snippet=payload_snippet,
        attack_technique=attack_technique,
        attack_tactic=attack_tactic,
        # ADR-0048 network-depth fields (ML-2)
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        packets_in=packets_in,
        packets_out=packets_out,
        flow_duration_ms=flow_duration_ms,
        dns_query=dns_query,
        dns_rcode=dns_rcode,
        tls_ja4=tls_ja4,
        tls_ja4s=tls_ja4s,
        tls_sni=tls_sni,
        tls_version=tls_version,
        http_method=http_method,
        http_host=http_host,
        http_url=http_url,
        http_user_agent=http_user_agent,
        raw_log=d,
    )
