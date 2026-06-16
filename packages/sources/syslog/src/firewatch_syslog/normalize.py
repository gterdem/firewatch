"""Syslog → SecurityEvent normalization.

Ported from ``legacy/adapters/collectors/syslog.py`` (reference only — never imported).
Reconciled with the v2 SecurityEvent schema:
  - ``source_type`` / ``source_id`` (ADR-0016 / Flag B)
  - ``action``: SSH brute-force / sudo failure → ALERT; SSH login → LOG (ADR-0012 Flag A)
  - ``attack_technique`` / ``attack_tactic`` / ``kill_chain_phase`` from pattern matching
    (ADR-0014): SSH brute-force → T1110 / TA0006 (Credential Access)
  - ``ocsf_class`` / ``ocsf_category`` (ADR-0020)

``source_type`` is ALWAYS the constant ``"syslog"`` — this plugin owns that mapping.
``source_id`` is the caller-supplied instance name; this function never branches on it.
(PLUGIN_CONTRACT.md "source_type vs source_id" section.)

RFC references:
  - RFC 3164: BSD syslog format (legacy; widely deployed)
  - RFC 5424: IETF syslog format (structured data; modern)

MITRE ATT&CK references (ATT&CK v15):
  - T1110 / TA0006: Brute Force / Credential Access
    https://attack.mitre.org/techniques/T1110/
  - TA0006 kill-chain phase: credential-access
    https://attack.mitre.org/tactics/TA0006/

OCSF references (https://schema.ocsf.io):
  - class_uid 4001 = Authentication Activity (category_uid 4 = Identity & Access Mgmt)
  - class_uid 6002 = File System Activity (category_uid 6 = Application Activity)
    used as a general-purpose fallback for system-level syslog events.
"""
import re

from firewatch_sdk import RawEvent, SecurityEvent

# Constant source_type — this plugin declares "syslog" as its type key.
SOURCE_TYPE: str = "syslog"

# ---------------------------------------------------------------------------
# Pattern classification
# ---------------------------------------------------------------------------
# These regexes identify the event type from the syslog message body.
# Order matters: more specific patterns come first.

# SSH brute-force / failed auth: "Failed password for <user> from <ip> port ..."
_SSH_BRUTEFORCE_RE = re.compile(
    r"Failed (?:password|publickey) for\b.*?\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)

# SSH accepted login: "Accepted password/publickey for <user> from <ip> port ..."
_SSH_LOGIN_RE = re.compile(
    r"Accepted (?:password|publickey) for\b.*?\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)

# Sudo authentication failure
_SUDO_FAIL_RE = re.compile(
    r"pam_unix\(sudo:auth\).*?authentication failure|"
    r"sudo.*?authentication failure",
    re.IGNORECASE,
)

# Generic "from <ip>" extractor (best-effort for unclassified lines)
_FROM_IP_RE = re.compile(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Category / action / severity / MITRE / OCSF maps
# ---------------------------------------------------------------------------

# Maps category name → (action, severity, attack_technique, attack_tactic,
#                        kill_chain_phase, capec_id, ocsf_class, ocsf_category)
# OCSF class_uid 4001 = Authentication Activity, category_uid 4 = Identity & Access Mgmt.
# OCSF class_uid 6002 = File System Activity (used as fallback for general system events).
#   Source: https://schema.ocsf.io/categories
_CATEGORY_MAP: dict[
    str,
    tuple[str, str, str | None, str | None, str | None, str | None, int, int],
] = {
    # category        action   severity  technique  tactic    kc-phase              capec  ocsf_cls  ocsf_cat
    "SSH Brute Force": (
        "ALERT", "high",   "T1110",   "TA0006", "credential-access", None,  4001,    4,
    ),
    "SSH Login": (
        "LOG",   "info",   None,      None,     None,                None,  4001,    4,
    ),
    "Sudo Failure": (
        "ALERT", "medium", "T1078",   "TA0004", "privilege-escalation", None, 4001,  4,
    ),
    "Syslog Event": (
        "LOG",   "info",   None,      None,     None,                None,  6002,    6,
    ),
}


def _classify(line: str) -> tuple[str, str | None]:
    """Classify a syslog line and return (category, extracted_ip | None).

    Returns one of the known categories, plus the best-effort source IP from the
    line text (``None`` if not extractable — caller falls back to client_ip).
    """
    m = _SSH_BRUTEFORCE_RE.search(line)
    if m:
        return "SSH Brute Force", m.group(1)

    m = _SSH_LOGIN_RE.search(line)
    if m:
        return "SSH Login", m.group(1)

    if _SUDO_FAIL_RE.search(line):
        return "Sudo Failure", None

    m = _FROM_IP_RE.search(line)
    ip = m.group(1) if m else None
    return "Syslog Event", ip


def normalize(raw: RawEvent, source_id: str) -> SecurityEvent:
    """Map a syslog RawEvent to a SecurityEvent.

    Implements the PLUGIN_CONTRACT.md ``normalize()`` responsibility for the Syslog
    source. Must set ``source_type="syslog"`` (constant) and pass ``source_id``
    through without branching on it (Flag B).

    Action mapping (ADR-0012):
      - SSH brute-force / sudo failure → ``ALERT``  (threat indicator, IDS semantics)
      - SSH login accepted             → ``LOG``    (informational; non-blocking, Flag A)
      - generic syslog event           → ``LOG``    (informational)

    MITRE ATT&CK (ADR-0014):
      - SSH brute-force → T1110 / TA0006 / credential-access
      - Sudo failure    → T1078 / TA0004 / privilege-escalation

    OCSF (ADR-0020):
      - Auth events → class_uid=4001 (Authentication Activity), category_uid=4
      - Generic     → class_uid=6002 (File System/System Activity), category_uid=6
    """
    d = raw.data
    line: str = d.get("line") or ""
    client_ip: str = d.get("client_ip") or ""

    category, extracted_ip = _classify(line)
    source_ip = extracted_ip or client_ip

    row = _CATEGORY_MAP[category]
    (
        action,
        severity,
        attack_technique,
        attack_tactic,
        kill_chain_phase,
        capec_id,
        ocsf_class,
        ocsf_category,
    ) = row

    # payload_snippet: the raw syslog line, capped at 500 chars.
    payload_snippet: str | None = line[:500] if line else None

    return SecurityEvent(
        source_type=SOURCE_TYPE,   # constant — never branches on source_id (Flag B)
        source_id=source_id,       # caller's instance name, passed through as-is
        timestamp=raw.received_at,
        source_ip=source_ip,
        action=action,             # type: ignore[arg-type]
        category=category,
        severity=severity,         # type: ignore[arg-type]
        attack_technique=attack_technique,
        attack_tactic=attack_tactic,
        kill_chain_phase=kill_chain_phase,
        capec_id=capec_id,
        ocsf_class=ocsf_class,
        ocsf_category=ocsf_category,
        payload_snippet=payload_snippet,
        raw_log=d,
    )
