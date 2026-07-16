"""OCSF 1.8.0 serializer — pure functions, no I/O (ADR-0040 / MI-5 #386).

Two public functions:
  event_to_ocsf(event)                                      → dict
  threat_to_detection_finding(threat, events, mitre_refs)   → dict

Both map FireWatch internal models to OCSF 1.8.0 dicts at the API boundary.
Neither modifies any internal model (ADR-0020 hard constraint).

All numeric values cite their source constant in mapping.py which in turn
traces to scratch/ocsf-1.8.0-reference.md / schema.ocsf.io/1.8.0.
"""
from __future__ import annotations

from typing import Any

from firewatch_sdk.models import SecurityEvent, ThreatScore

from firewatch_api.ocsf import mapping


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _metadata(
    *,
    use_security_control_profile: bool = False,
    original_time: str | None = None,
) -> dict[str, Any]:
    """Build the OCSF metadata object.

    Source: scratch/ocsf-1.8.0-reference.md §5 / schema.ocsf.io/1.8.0/objects/metadata
    Required: version, product.
    Recommended: profiles when Security Control dispositions are emitted.
    """
    meta: dict[str, Any] = {
        "version": mapping.OCSF_VERSION,
        "product": mapping.FIREWATCH_PRODUCT,
    }
    if use_security_control_profile:
        # Per scratch/ocsf-1.8.0-reference.md caveat: include profiles when emitting
        # Security-Control-profile disposition_id extensions (6, 15, 17, 19, 20, 21).
        meta["profiles"] = ["security_control"]
    if original_time:
        meta["original_time"] = original_time
    return meta


def _resolve_class_uid(event: SecurityEvent) -> tuple[int, int]:
    """Return (class_uid, category_uid) from the event's ocsf_class/ocsf_category.

    Falls back to OCSF Network Activity (4001/4) only when the fields are UNSET
    (``None``). Source: ADR-0020 — ocsf_class/ocsf_category are set at normalize
    time by each plugin.

    Deliberate ``is not None`` check (issue #76 — falsy-zero fix): OCSF class_uid
    ``0`` (Base Event, https://schema.ocsf.io/api/1.8.0/categories — category_uid 0
    "Uncategorized") is a legitimate, honestly-emitted value (e.g. syslog's and
    syslog_cef's unclassified-line fallback, linux_auth's unclassified row). Python
    truthiness treats ``0`` as falsy, so the previous ``event.ocsf_class or
    mapping.SURICATA_NET_CLASS_UID`` silently rewrote every such event to 4001/4
    (Network Activity) on export — live-firing today for linux_auth's merged 0/0
    rows. ``is not None`` fixes this without changing the None-fallback behavior.
    """
    class_uid = (
        event.ocsf_class if event.ocsf_class is not None else mapping.SURICATA_NET_CLASS_UID
    )
    category_uid = (
        event.ocsf_category
        if event.ocsf_category is not None
        else mapping.SURICATA_NET_CATEGORY_UID
    )
    return class_uid, category_uid


def _resolve_activity_id(event: SecurityEvent, class_uid: int) -> int:
    """Return the activity_id appropriate for the event's OCSF class.

    activity_id enums are PER-CLASS in OCSF (issue #80) — a value valid for
    one class (e.g. Network Activity's 6 "Traffic") is a different, often
    false, meaning for another (Authentication's 6 "Preauth"). Each branch
    below resolves the value from that class's own OCSF 1.8.0 enum, cited
    inline; there is no cross-class fallback.

    - HTTP Activity (4002): resolve from HTTP method in payload/raw_log.
      No resolvable method → 0 (Unknown).
      Source: scratch/ocsf-1.8.0-reference.md §3
    - Detection Finding (2004): 1 (Create) — each export is a point-in-time snapshot.
      Source: scratch/ocsf-1.8.0-reference.md §2
    - Authentication (3002): 1 (Logon) — every shipped emitter is a logon
      attempt; success/failure is status_id, not activity_id (ADR-0071 D2).
      Source: mapping.AUTHENTICATION_ACTIVITY_ID citation.
    - Account Change (3001): 1 (Create) — the only shipped emitter
      (useradd_new_user) is an account creation.
      Source: mapping.ACCOUNT_CHANGE_ACTIVITY_ID citation.
    - Network Activity (4001): 6 (Traffic) — explicit branch, no longer the
      fallthrough. Source: scratch/ocsf-1.8.0-reference.md §4
    - Base Event (0) and any class with no explicit branch above: 0 (Unknown)
      — valid in every OCSF class's activity_id enum, unlike a value borrowed
      from another class (e.g. the old 6 "Traffic" fallthrough).
      Source: mapping.BASE_EVENT_ACTIVITY_ID / mapping.ACTIVITY_UNKNOWN citation.
    """
    if class_uid == mapping.AZURE_WAF_CLASS_UID:  # 4002 HTTP Activity
        return _http_activity_id(event)
    if class_uid == mapping.SURICATA_IDS_CLASS_UID:  # 2004 Detection Finding
        return mapping.DETECTION_FINDING_ACTIVITY_ID  # 1 Create
    if class_uid == mapping.AUTHENTICATION_CLASS_UID:  # 3002 Authentication
        return mapping.AUTHENTICATION_ACTIVITY_ID  # 1 Logon
    if class_uid == mapping.ACCOUNT_CHANGE_CLASS_UID:  # 3001 Account Change
        return mapping.ACCOUNT_CHANGE_ACTIVITY_ID  # 1 Create
    if class_uid == mapping.SURICATA_NET_CLASS_UID:  # 4001 Network Activity
        return mapping.NETWORK_ACTIVITY_TRAFFIC  # 6 Traffic
    # Base Event (0) and any ocsf_class with no explicit branch above.
    return mapping.ACTIVITY_UNKNOWN  # 0 Unknown


def _http_activity_id(event: SecurityEvent) -> int:
    """Extract the HTTP method from raw_log and resolve to an activity_id.

    Azure WAF logs carry the HTTP method in raw_log.properties.httpMethod
    (App Gateway) or raw_log.properties.requestMethod (Front Door).
    If no resolvable method is found → 0 (Unknown).
    Source: scratch/ocsf-1.8.0-reference.md §3
    """
    raw = event.raw_log or {}
    props: dict[str, Any] = raw.get("properties") or raw
    method: str | None = (
        props.get("httpMethod")
        or props.get("requestMethod")
        or props.get("method")
        or None
    )
    if method:
        return mapping.HTTP_METHOD_ACTIVITY_ID.get(str(method).upper(), mapping.HTTP_ACTIVITY_UNKNOWN)
    return mapping.HTTP_ACTIVITY_UNKNOWN


def _needs_security_control_profile(disposition_id: int | None) -> bool:
    """Return True when the disposition_id is a Security-Control-profile extension.

    Source: scratch/ocsf-1.8.0-reference.md §2 caveat.
    """
    return disposition_id in mapping.SECURITY_CONTROL_DISPOSITION_IDS


def _event_evidence_object(event: SecurityEvent) -> dict[str, Any]:
    """Map a SecurityEvent to one OCSF Evidence Artifacts object.

    Each evidence object carries at minimum one of actor/src_endpoint/dst_endpoint/data.
    Source: scratch/ocsf-1.8.0-reference.md §2 "evidences"
    """
    evidence: dict[str, Any] = {}

    if event.source_ip:
        src: dict[str, Any] = {"ip": event.source_ip}
        if event.source_port is not None:
            src["port"] = event.source_port
        evidence["src_endpoint"] = src

    if event.destination_ip or event.destination_port is not None:
        dst: dict[str, Any] = {}
        if event.destination_ip:
            dst["ip"] = event.destination_ip
        if event.destination_port is not None:
            dst["port"] = event.destination_port
        if dst:
            evidence["dst_endpoint"] = dst

    data: dict[str, Any] = {}
    if event.rule_id:
        data["rule_id"] = event.rule_id
    if event.payload_snippet:
        # Truncate to 200 chars at the serializer boundary (BLOCKING-1 NB-1).
        # SecurityEvent.payload_snippet is uncapped; we cap here, not in the model.
        data["payload_snippet"] = event.payload_snippet[:200]
    if data:
        evidence["data"] = data

    return evidence


def _build_ocsf_file_object(event: SecurityEvent) -> dict[str, Any] | None:
    """Assemble the OCSF File object from ADR-0055 flat file-IOC scalars.

    Returns None when no file fields are set (prevents fabricating an empty object).

    OCSF 1.8.0 File object: name, mime_type, hashes[] (Fingerprint array).
    Fingerprint algorithm_id values (OCSF 1.8.0):
      1 = MD5   (ECS file.hash.md5)
      2 = SHA-1 (ECS file.hash.sha1)
      3 = SHA-256 (ECS file.hash.sha256)
    Source: schema.ocsf.io/1.8.0 File object + hashes array (ADR-0055 §Standard alignment)
    ECS: https://www.elastic.co/guide/en/ecs/current/ecs-file.html

    Security boundary caps (issue #643 — matching the payload_snippet[:200] pattern):
    - Hash values are capped at their natural hex-digest lengths so an adversarial
      source cannot emit unbounded strings into the authenticated OCSF export:
        SHA-256 → 64 hex chars (256 bits / 4 bits-per-hex-char)
        MD5     → 32 hex chars (128 bits / 4 bits-per-hex-char)
        SHA-1   → 40 hex chars (160 bits / 4 bits-per-hex-char)
    - file_name and file_mime_type are capped at 255 chars (POSIX NAME_MAX /
      IANA media-type practical maximum), consistent with payload_snippet[:200].
    """
    has_any = (
        event.file_sha256
        or event.file_md5
        or event.file_sha1
        or event.file_name
        or event.file_mime_type
    )
    if not has_any:
        return None

    file_obj: dict[str, Any] = {}

    if event.file_name:
        # Cap at 255 chars (POSIX NAME_MAX / IANA media-type practical max).
        # Matching the payload_snippet[:200] boundary-cap pattern (issue #643).
        file_obj["name"] = event.file_name[:255]

    if event.file_mime_type:
        # Cap at 255 chars (same boundary pattern as file_name above).
        file_obj["mime_type"] = event.file_mime_type[:255]

    # Reconstruct OCSF hashes[] from flat scalars.
    # algorithm_id values: 1=MD5, 2=SHA-1, 3=SHA-256 (OCSF 1.8.0 Fingerprint enum).
    # Hash values are capped at their natural digest length (issue #643): an adversarial
    # plugin cannot inject unbounded strings into the authenticated OCSF export via these
    # fields. A valid hash is exactly N chars; truncating to N is safe and always correct.
    hashes: list[dict[str, Any]] = []
    if event.file_md5:
        hashes.append({"algorithm_id": 1, "algorithm": "MD5", "value": event.file_md5[:32]})
    if event.file_sha1:
        hashes.append({"algorithm_id": 2, "algorithm": "SHA-1", "value": event.file_sha1[:40]})
    if event.file_sha256:
        hashes.append({"algorithm_id": 3, "algorithm": "SHA-256", "value": event.file_sha256[:64]})
    if hashes:
        file_obj["hashes"] = hashes

    return file_obj


def _mitre_attacks(
    event: SecurityEvent | None = None,
    mitre_refs: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]] | None:
    """Build the OCSF attacks list (MITRE ATT&CK).

    Reads attack_technique / attack_tactic from the SecurityEvent (set at
    normalize-time by each plugin per ADR-0014), or accepts pre-built mitre_refs.
    Returns None (omit field) when no MITRE data is available.
    """
    attacks: list[dict[str, Any]] = []

    if mitre_refs:
        attacks.extend(mitre_refs)
    elif event and (event.attack_technique or event.attack_tactic):
        entry: dict[str, Any] = {}
        if event.attack_technique:
            entry["technique"] = {
                "uid": event.attack_technique,
                "name": event.attack_technique,  # technique name not stored; use id
            }
        if event.attack_tactic:
            entry["tactic"] = {
                "uid": event.attack_tactic,
                "name": event.attack_tactic,  # tactic name not stored; use id
            }
        if entry:
            attacks.append(entry)

    return attacks if attacks else None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def event_to_ocsf(event: SecurityEvent) -> dict[str, Any]:
    """Map a SecurityEvent to its OCSF 1.8.0 activity class dict.

    Reads the event's own ocsf_class/ocsf_category to determine class_uid /
    category_uid (ADR-0020 — set at normalize-time by each plugin):
      Azure WAF events   → HTTP Activity (class_uid=4002, category_uid=4)
      Suricata IDS       → Detection Finding (class_uid=2004, category_uid=2)
      Suricata network   → Network Activity (class_uid=4001, category_uid=4)
      linux_auth/syslog  → Authentication (3002), Account Change (3001),
                           Base Event (0) — see _resolve_activity_id (#80)

    Fills activity_id, disposition_id, severity_id, type_uid, metadata, time
    per the reference.  Does NOT modify the SecurityEvent.

    Source: ADR-0040, ADR-0020, scratch/ocsf-1.8.0-reference.md
    """
    class_uid, category_uid = _resolve_class_uid(event)
    activity_id = _resolve_activity_id(event, class_uid)

    action: str = event.action
    disposition_id: int = mapping.DISPOSITION_ID.get(action, 0)
    disposition: str = mapping.DISPOSITION_LABEL.get(action, "Unknown")

    severity_id: int = mapping.SEVERITY_ID.get(event.severity, 0)
    severity_label: str = mapping.SEVERITY_LABEL.get(event.severity, "Unknown")

    # type_uid = class_uid * 100 + activity_id
    # Source: OCSF spec (standard formula across all event classes)
    type_uid: int = class_uid * 100 + activity_id

    use_sc_profile = _needs_security_control_profile(disposition_id)
    ts_str = event.timestamp.isoformat() if event.timestamp else None

    result: dict[str, Any] = {
        "class_uid": class_uid,
        "category_uid": category_uid,
        "activity_id": activity_id,
        "type_uid": type_uid,
        "severity_id": severity_id,
        "severity": severity_label,
        "disposition_id": disposition_id,
        "disposition": disposition,
        "time": ts_str,
        "metadata": _metadata(
            use_security_control_profile=use_sc_profile,
            original_time=ts_str,
        ),
    }

    # Source endpoint (always present when source_ip is set)
    if event.source_ip:
        src: dict[str, Any] = {"ip": event.source_ip}
        if event.source_port is not None:
            src["port"] = event.source_port
        result["src_endpoint"] = src

    # Destination endpoint
    if event.destination_ip or event.destination_port is not None:
        dst: dict[str, Any] = {}
        if event.destination_ip:
            dst["ip"] = event.destination_ip
        if event.destination_port is not None:
            dst["port"] = event.destination_port
        if dst:
            result["dst_endpoint"] = dst

    # HTTP request block (HTTP Activity class only)
    if class_uid == mapping.AZURE_WAF_CLASS_UID:
        raw = event.raw_log or {}
        props: dict[str, Any] = raw.get("properties") or raw
        uri = props.get("requestUri")
        method_raw = (
            props.get("httpMethod")
            or props.get("requestMethod")
            or props.get("method")
        )
        if uri or method_raw or event.payload_snippet:
            http_req: dict[str, Any] = {}
            if method_raw:
                http_req["method"] = str(method_raw)
            if uri:
                http_req["url"] = {"path": str(uri)}
            if event.payload_snippet:
                # Truncate to 200 chars at the serializer boundary (BLOCKING-1 NB-1).
                http_req["body"] = {"data": event.payload_snippet[:200]}
            if http_req:
                result["http_request"] = http_req

    # Rule / category info
    if event.rule_id:
        result["rule"] = {"uid": event.rule_id, "name": event.rule_name or event.rule_id}
    if event.category:
        result["category_name"] = event.category

    # MITRE ATT&CK (ADR-0014)
    attacks = _mitre_attacks(event=event)
    if attacks:
        result["attacks"] = attacks

    # ADR-0055 — flat→nested assembly for file IOC and DNS answers at the export boundary.
    # Internal model uses flat nullable scalars (ADR-0020 / ADR-0055 deviation); the OCSF
    # export serializer reassembles the standard nested shapes here — same boundary as ADR-0048.

    # Group E — OCSF File object + hashes[] (Fingerprint array).
    # Source: OCSF 1.8.0 File object, hashes array with Fingerprint object.
    # https://schema.ocsf.io/ (File object; Fingerprint: algorithm_id 1=MD5, 2=SHA-1, 3=SHA-256)
    # ECS: file.hash.* (https://www.elastic.co/guide/en/ecs/current/ecs-file.html)
    file_obj = _build_ocsf_file_object(event)
    if file_obj:
        result["file"] = file_obj

    # Group F — OCSF DNS Activity answers[] (DNS Answer object, rdata field).
    # dns_answer is a comma-joined flat scalar; we split at the boundary to reconstruct
    # the OCSF standard array form.
    # Source: OCSF 1.8.0 DNS Activity class_uid 4003, answers[] DNS Answer object, rdata.
    # https://schema.ocsf.io/ (class_uid 4003, DNS Answer)
    # ECS: dns.answers[].data (https://www.elastic.co/guide/en/ecs/current/ecs-dns.html)
    #
    # Security boundary caps (issue #643 — defence-in-depth, adversarial source hardening):
    # - Entry count capped at 50: an adversarial source cannot inflate the export response
    #   by emitting thousands of comma-joined DNS answers.
    # - Per-rdata length capped at 253 chars: RFC 1035 §3.1 specifies that a full domain
    #   name in presentation format must not exceed 253 characters (255 wire-format octets
    #   minus two length bytes for the root label). Values beyond 253 are not valid domain
    #   names or rdata; capping prevents unbounded strings in the OCSF export.
    #   Source: RFC 1035 §3.1, §3.3.
    if event.dns_answer:
        result["answers"] = [
            {"rdata": v.strip()[:253]}          # cap per-rdata to RFC 1035 §3.1 limit
            for v in event.dns_answer.split(",")[:50]  # cap entry count at 50
            if v.strip()
        ]

    return result


def threat_to_detection_finding(
    threat: ThreatScore,
    contributing_events: list[SecurityEvent],
    mitre_refs: list[dict[str, Any]] | None = None,
    total_evidence_count: int | None = None,
) -> dict[str, Any]:
    """Map a ThreatScore + its contributing events to an OCSF 1.8.0 Detection Finding.

    ALWAYS class_uid=2004, category_uid=2, type_uid=200401, activity_id=1 (Create).
    Source: scratch/ocsf-1.8.0-reference.md §2

    Required fields (per reference):
      metadata, time, severity_id, activity_id, finding_info, class_uid,
      category_uid, type_uid.
    Recommended fields:
      disposition_id (from dominant action), evidences (contributing events),
      attacks (MITRE ATT&CK from events).

    total_evidence_count: when the caller capped contributing_events for response-size
      reasons (BLOCKING-1), pass the true row count so finding_info.total_evidence_count
      signals truncation to consumers.  Defaults to len(contributing_events) when omitted.

    Does NOT modify any internal model (ADR-0020 hard constraint).
    """
    # severity_id from threat level (map threat_level → implied severity)
    # threat_level is CRITICAL/HIGH/MEDIUM/LOW → map to OCSF severity_id.
    # Source: scratch/ocsf-1.8.0-reference.md §1 / OCSF severity_id mapping.
    _THREAT_LEVEL_TO_SEVERITY_ID: dict[str, int] = {
        "CRITICAL": 5,  # Critical
        "HIGH":     4,  # High
        "MEDIUM":   3,  # Medium
        "LOW":      2,  # Low
    }
    _THREAT_LEVEL_TO_SEVERITY_LABEL: dict[str, str] = {
        "CRITICAL": "Critical",
        "HIGH":     "High",
        "MEDIUM":   "Medium",
        "LOW":      "Low",
    }
    threat_level = str(threat.threat_level)
    severity_id = _THREAT_LEVEL_TO_SEVERITY_ID.get(threat_level, 0)
    severity_label = _THREAT_LEVEL_TO_SEVERITY_LABEL.get(threat_level, "Unknown")

    # disposition_id from dominant action (most severe action in contributing events).
    # Priority: BLOCK > DROP > ALERT > LOG > ALLOW (most restrictive first).
    # Source: scratch/ocsf-1.8.0-reference.md §2 "disposition_id"
    _ACTION_PRIORITY = {"BLOCK": 5, "DROP": 4, "ALERT": 3, "LOG": 2, "ALLOW": 1}
    dominant_action = "ALERT"  # default when no contributing events
    best_priority = 0
    for ev in contributing_events:
        p = _ACTION_PRIORITY.get(ev.action, 0)
        if p > best_priority:
            best_priority = p
            dominant_action = ev.action

    disposition_id: int = mapping.DISPOSITION_ID.get(dominant_action, 0)
    disposition: str = mapping.DISPOSITION_LABEL.get(dominant_action, "Unknown")

    use_sc_profile = _needs_security_control_profile(disposition_id)
    ts_str = threat.last_seen.isoformat() if threat.last_seen else None

    # evidences — one OCSF Evidence Artifacts object per contributing event.
    # Source: scratch/ocsf-1.8.0-reference.md §2 "evidences"
    evidences: list[dict[str, Any]] = [
        _event_evidence_object(ev) for ev in contributing_events
        if _event_evidence_object(ev)  # skip empty evidence objects
    ]

    # MITRE ATT&CK — prefer explicit mitre_refs, otherwise gather from events.
    # Source: ADR-0014 — attack_technique/attack_tactic set at normalize-time.
    if mitre_refs:
        attacks = mitre_refs
    else:
        # Deduplicate by technique uid
        seen_techniques: set[str] = set()
        attacks = []
        for ev in contributing_events:
            if ev.attack_technique and ev.attack_technique not in seen_techniques:
                seen_techniques.add(ev.attack_technique)
                entry: dict[str, Any] = {
                    "technique": {
                        "uid": ev.attack_technique,
                        "name": ev.attack_technique,
                    }
                }
                if ev.attack_tactic:
                    entry["tactic"] = {
                        "uid": ev.attack_tactic,
                        "name": ev.attack_tactic,
                    }
                attacks.append(entry)

    result: dict[str, Any] = {
        # Required attrs (scratch/ocsf-1.8.0-reference.md §2 "required vs recommended")
        "class_uid": mapping.DETECTION_FINDING_CLASS_UID,        # 2004
        "category_uid": mapping.DETECTION_FINDING_CATEGORY_UID,  # 2
        "activity_id": mapping.DETECTION_FINDING_ACTIVITY_ID,    # 1 Create
        "type_uid": mapping.DETECTION_FINDING_TYPE_UID,          # 200401
        "severity_id": severity_id,
        "severity": severity_label,
        "time": ts_str,
        "metadata": _metadata(use_security_control_profile=use_sc_profile),
        # finding_info required: title + uid (source_ip is the unique identifier here).
        # total_evidence_count: true row count from the store (may exceed len(evidences)
        # when the route capped contributing_events — BLOCKING-1 truncation signal).
        "finding_info": {
            "title": f"Threat detected from {threat.source_ip}",
            "uid": threat.source_ip,
            "total_evidence_count": (
                total_evidence_count
                if total_evidence_count is not None
                else len(contributing_events)
            ),
        },
        # Recommended
        "disposition_id": disposition_id,
        "disposition": disposition,
    }

    if evidences:
        result["evidences"] = evidences

    if attacks:
        result["attacks"] = attacks

    # score from ThreatScore
    result["confidence_score"] = threat.score

    return result
