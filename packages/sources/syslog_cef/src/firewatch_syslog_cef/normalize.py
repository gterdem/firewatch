"""CEF/Syslog -> SecurityEvent normalization.

Maps a RawEvent produced by the syslog_cef listener to a SecurityEvent.

Pipeline (in priority order):
  1. Try CEF parser -- if the line contains "CEF:", extract header + Extension.
     Map CEF fields to SecurityEvent using the vendor registry for 'act' mapping.
  2. Fallback: try RFC 5424, then RFC 3164 syslog framing.
     Delegate to the syslog fallback classifier (SSH brute-force pattern etc.)
     for action/severity/MITRE derivation -- same logic as firewatch_syslog.

Flag B (PLUGIN_CONTRACT.md):
  source_type is ALWAYS the constant "syslog_cef".
  This function MUST NOT branch on source_id for detection.
  source_id is passed through to SecurityEvent as-is (labelling only).

CEF field -> SecurityEvent mapping (ArcSight CEF standard dictionary):
  src            -> source_ip
  dst            -> destination_ip
  spt            -> source_port (int)
  dpt            -> destination_port (int)
  proto          -> protocol
  act            -> action (via vendor registry)
  SignatureID    -> rule_id
  Name           -> rule_name
  Severity (0-10)-> severity (banded per CEF spec)
  request        -> http_url (ADR-0048)
  requestMethod  -> http_method (ADR-0048)
  requestClientApp -> http_user_agent (ADR-0048)
  dhost / deviceDnsName -> http_host (ADR-0048)

OCSF alignment (ADR-0020):
  CEF network events -> class_uid=4001 (Network Activity), category_uid=4
  CEF with HTTP fields -> class_uid=4002 (HTTP Activity), category_uid=4
  Syslog fallback auth events -> class_uid=4001, category_uid=4

CEF severity banding (ArcSight CEF Implementation Standard, Severity field):
  0-3  -> low
  4-6  -> medium
  7-8  -> high
  9-10 -> critical
  (strings "Low"/"Medium"/"High"/"VeryHigh"/"Unknown" also normalized)

Source:
  ArcSight CEF Implementation Standard
  https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/
"""
from __future__ import annotations

import logging
import re

from firewatch_sdk import RawEvent, SecurityEvent
from firewatch_sdk.models import ActionLiteral, SeverityLiteral

from firewatch_syslog_cef.parsers.cef import parse_cef
from firewatch_syslog_cef.parsers.rfc3164 import parse_rfc3164
from firewatch_syslog_cef.parsers.rfc5424 import parse_rfc5424
from firewatch_syslog_cef.registry import resolve_action

logger = logging.getLogger("firewatch.syslog_cef.normalize")

# Constant source_type for this plugin (Flag B, PLUGIN_CONTRACT.md).
SOURCE_TYPE: str = "syslog_cef"

# OCSF class/category for network flow events (class_uid 4001 = Network Activity).
# Source: https://schema.ocsf.io/1.0.0/classes/network_activity
_OCSF_CLASS_NETWORK = 4001
_OCSF_CLASS_HTTP = 4002      # HTTP Activity
_OCSF_CATEGORY_NETWORK = 4  # Network Activity category

# Syslog fallback: SSH brute-force pattern (reuses logic from firewatch_syslog).
# MITRE ATT&CK T1110 / TA0006 (Credential Access / Brute Force).
_SSH_BRUTEFORCE_RE = re.compile(
    r"Failed (?:password|publickey) for\b.*?\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
_SSH_LOGIN_RE = re.compile(
    r"Accepted (?:password|publickey) for\b.*?\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
_SUDO_FAIL_RE = re.compile(
    r"pam_unix\(sudo:auth\).*?authentication failure|sudo.*?authentication failure",
    re.IGNORECASE,
)
_FROM_IP_RE = re.compile(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)


# ---------------------------------------------------------------------------
# CEF severity banding
# ---------------------------------------------------------------------------


def cef_severity_to_canonical(severity_str: str) -> SeverityLiteral:
    """Band a CEF Severity field value to a canonical SeverityLiteral.

    CEF Severity (ArcSight CEF Implementation Standard):
      0-3  -> low
      4-6  -> medium
      7-8  -> high
      9-10 -> critical
    String synonyms (Low/Medium/High/VeryHigh) are also handled.

    Unknown or out-of-range values default to "medium".
    """
    s = severity_str.strip().lower()

    # Handle string synonyms from some vendor implementations.
    _STRING_MAP: dict[str, SeverityLiteral] = {
        "low": "low",
        "unknown": "low",
        "medium": "medium",
        "high": "high",
        "veryhigh": "high",
        "very-high": "high",
        "critical": "critical",
    }
    if s in _STRING_MAP:
        return _STRING_MAP[s]

    try:
        n = int(s)
    except ValueError:
        return "medium"

    if n <= 3:  # noqa: PLR2004
        return "low"
    if n <= 6:  # noqa: PLR2004
        return "medium"
    if n <= 8:  # noqa: PLR2004
        return "high"
    return "critical"


# ---------------------------------------------------------------------------
# CEF normalize path
# ---------------------------------------------------------------------------


def _normalize_cef(
    cef: dict[str, object],
    client_ip: str,
    line: str,
    source_id: str,
    received_at: object,
    raw_data: dict[str, object],
) -> SecurityEvent:
    """Map a parsed CEF dict to a SecurityEvent.

    Uses the vendor registry to resolve the 'act' token. Routes on
    DeviceVendor/DeviceProduct from the *payload* (not on source_id — Flag B).
    """
    ext: dict[str, str] = cef.get("ext", {})  # type: ignore[assignment]

    vendor: str = str(cef.get("device_vendor", ""))
    product: str = str(cef.get("device_product", ""))
    act_token: str = ext.get("act", "")
    action: ActionLiteral = resolve_action(vendor, product, act_token) if act_token else "ALERT"

    source_ip: str = ext.get("src", client_ip) or client_ip
    destination_ip: str | None = ext.get("dst") or None

    source_port: int | None = _safe_int(ext.get("spt"))
    destination_port: int | None = _safe_int(ext.get("dpt"))
    protocol: str | None = ext.get("proto") or None

    # Sanitized: SignatureID is attacker-controlled and reaches the LLM prompt (B-1).
    rule_id: str | None = _sanitize_rule_id(str(cef.get("signature_id", "")))
    rule_name: str | None = str(cef.get("name", "")) or None
    severity = cef_severity_to_canonical(str(cef.get("cef_severity", "5")))

    # HTTP fields (ADR-0048).
    http_url: str | None = ext.get("request") or None
    http_method: str | None = ext.get("requestMethod") or None
    http_user_agent: str | None = ext.get("requestClientApplication") or ext.get("requestClientApp") or None
    http_host: str | None = ext.get("dhost") or ext.get("deviceDnsName") or None

    # OCSF class: HTTP Activity if HTTP fields present, else Network Activity.
    ocsf_class = _OCSF_CLASS_HTTP if (http_url or http_method) else _OCSF_CLASS_NETWORK

    # Category from vendor+product (human-readable).
    category = f"CEF:{vendor}/{product}" if vendor else "CEF Network Event"

    payload_snippet = line[:500] if line else None

    from datetime import datetime
    ts = received_at if isinstance(received_at, datetime) else None

    return SecurityEvent(
        source_type=SOURCE_TYPE,   # constant -- never branches on source_id (Flag B)
        source_id=source_id,       # caller's instance name, passed through as-is
        timestamp=ts,              # type: ignore[arg-type]
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        action=action,
        category=category,
        severity=severity,
        rule_id=rule_id,
        rule_name=rule_name,
        http_url=http_url,
        http_method=http_method,
        http_user_agent=http_user_agent,
        http_host=http_host,
        ocsf_class=ocsf_class,
        ocsf_category=_OCSF_CATEGORY_NETWORK,
        payload_snippet=payload_snippet,
        raw_log=raw_data,
    )


# ---------------------------------------------------------------------------
# Syslog fallback path
# ---------------------------------------------------------------------------


def _normalize_syslog_fallback(
    msg: str,
    client_ip: str,
    line: str,
    source_id: str,
    received_at: object,
    raw_data: dict[str, object],
) -> SecurityEvent:
    """Fallback normalization for non-CEF RFC 5424 / RFC 3164 syslog messages.

    Applies the same SSH brute-force / login / sudo classifier used by
    firewatch_syslog -- ported here rather than imported from that package
    to keep the syslog-specific logic self-contained and testable independently.

    MITRE ATT&CK references (ATT&CK v15):
      T1110 / TA0006: Brute Force / Credential Access
        https://attack.mitre.org/techniques/T1110/
      T1078 / TA0004: Valid Accounts / Privilege Escalation
        https://attack.mitre.org/techniques/T1078/
    """
    action: ActionLiteral
    severity: SeverityLiteral
    attack_technique: str | None = None
    attack_tactic: str | None = None
    kill_chain_phase: str | None = None
    source_ip: str

    m = _SSH_BRUTEFORCE_RE.search(msg)
    if m:
        source_ip = m.group(1)
        action = "ALERT"
        severity = "high"
        category = "SSH Brute Force"
        attack_technique = "T1110"
        attack_tactic = "TA0006"
        kill_chain_phase = "credential-access"
        ocsf_class = 4001
    else:
        m2 = _SSH_LOGIN_RE.search(msg)
        if m2:
            source_ip = m2.group(1)
            action = "LOG"
            severity = "info"
            category = "SSH Login"
            ocsf_class = 4001
        elif _SUDO_FAIL_RE.search(msg):
            m3 = _FROM_IP_RE.search(msg)
            source_ip = m3.group(1) if m3 else client_ip
            action = "ALERT"
            severity = "medium"
            category = "Sudo Failure"
            attack_technique = "T1078"
            attack_tactic = "TA0004"
            kill_chain_phase = "privilege-escalation"
            ocsf_class = 4001
        else:
            m4 = _FROM_IP_RE.search(msg)
            source_ip = m4.group(1) if m4 else client_ip
            action = "LOG"
            severity = "info"
            category = "Syslog Event"
            ocsf_class = 6002

    from datetime import datetime
    ts = received_at if isinstance(received_at, datetime) else None

    return SecurityEvent(
        source_type=SOURCE_TYPE,
        source_id=source_id,
        timestamp=ts,  # type: ignore[arg-type]
        source_ip=source_ip,
        action=action,
        category=category,
        severity=severity,
        attack_technique=attack_technique,
        attack_tactic=attack_tactic,
        kill_chain_phase=kill_chain_phase,
        ocsf_class=ocsf_class,
        ocsf_category=4,
        payload_snippet=line[:500] if line else None,
        raw_log=raw_data,
    )


# ---------------------------------------------------------------------------
# Public normalize() entry point
# ---------------------------------------------------------------------------


def normalize(raw: RawEvent, source_id: str) -> SecurityEvent:
    """Map a syslog_cef RawEvent to a SecurityEvent.

    Parse priority order:
    1. CEF (ArcSight Common Event Format) -- sniffed by "CEF:" prefix.
    2. RFC 5424 syslog framing fallback.
    3. RFC 3164 syslog framing fallback.
    4. Raw line fallback (classification on the bare line text).

    source_type is ALWAYS "syslog_cef" (Flag B: never branches on source_id).
    source_id is passed through as-is for labelling only.
    """
    d = raw.data
    line: str = str(d.get("line") or "")
    client_ip: str = str(d.get("client_ip") or "")

    # --- CEF path ---
    cef = parse_cef(line)
    if cef is not None:
        return _normalize_cef(cef, client_ip, line, source_id, raw.received_at, d)

    # --- RFC 5424 fallback ---
    r5 = parse_rfc5424(line)
    if r5 is not None:
        msg = r5.get("msg") or ""
        return _normalize_syslog_fallback(
            str(msg), client_ip, line, source_id, raw.received_at, d
        )

    # --- RFC 3164 fallback ---
    r3 = parse_rfc3164(line)
    if r3 is not None:
        msg = r3.get("msg") or ""
        return _normalize_syslog_fallback(
            str(msg), client_ip, line, source_id, raw.received_at, d
        )

    # --- Bare line fallback ---
    return _normalize_syslog_fallback(line, client_ip, line, source_id, raw.received_at, d)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_int(value: str | None) -> int | None:
    """Convert a string to int; return None on failure (never raises)."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


# CEF SignatureID is fully attacker-controlled (any host that can reach the
# listener can write it) and flows into rule_id, which the core prompt layer
# currently interpolates OUTSIDE the <untrusted_data> sentinel (PR #638 security
# review B-1; architectural fix tracked in #590). Strip to identifier-safe chars
# and cap length so it cannot carry sentinel-breaking tokens or prompt
# instructions. The raw, unmodified SignatureID is still retained in raw_log.
_RULE_ID_SAFE_RE = re.compile(r"[^A-Za-z0-9._:\-]")
_RULE_ID_MAX = 64


def _sanitize_rule_id(value: str) -> str | None:
    """Return an injection-safe rule_id (identifier chars only, <=64), or None."""
    cleaned = _RULE_ID_SAFE_RE.sub("", value)[:_RULE_ID_MAX]
    return cleaned or None
