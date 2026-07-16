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

OCSF references (OCSF 1.8.0, https://schema.ocsf.io/api/1.8.0/classes, verified live
2026-07-16 — issue #76 conformance correction; corrects an earlier version of this
docstring which mislabeled both classes below):
  - class_uid 3002 = Authentication (category_uid 3 = Identity & Access Management).
    https://schema.ocsf.io/api/1.8.0/classes/authentication: "Authentication events
    report authentication session activities, including user attempts to log on or
    log off, regardless of success". Applies to every auth-shaped category this
    module emits (SSH Brute Force, SSH Login, Sudo Failure) — 4001 is Network
    Activity, not Authentication, and does not apply here.
  - class_uid 0 = Base Event (category_uid 0 = Uncategorized), used as the honest
    fallback for a syslog line this module could not classify.
    https://schema.ocsf.io/api/1.8.0/categories: category_uid 0 "Uncategorized" —
    "a generic event that does not belong to any event category". 6002 is
    Application Lifecycle (category 6) and 1001 is File System Activity (category
    1); neither describes an unclassified line, and the earlier docstring's claim
    that 6002 means "File System Activity" was also wrong on its own terms.
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
#
# OCSF 1.8.0 (https://schema.ocsf.io/api/1.8.0/classes, verified live 2026-07-16,
# issue #76 conformance correction):
#   class_uid 3002 = Authentication, category_uid 3 = Identity & Access Management
#     — https://schema.ocsf.io/api/1.8.0/classes/authentication: "regardless of
#     success" — every auth-shaped row below (brute force, login, sudo failure).
#   class_uid 0 = Base Event, category_uid 0 = Uncategorized
#     — https://schema.ocsf.io/api/1.8.0/categories: "a generic event that does
#     not belong to any event category" — the unclassified fallback row.
# (Previously this table used 4001/4, which is OCSF Network Activity, and 6002/6,
# which is OCSF Application Lifecycle — both wrong; neither pair describes a
# syslog auth line or an unclassified line. See ADR-0071 D5.)
_CATEGORY_MAP: dict[
    str,
    tuple[str, str, str | None, str | None, str | None, str | None, int, int],
] = {
    # category        action   severity  technique  tactic    kc-phase              capec  ocsf_cls  ocsf_cat
    "SSH Brute Force": (
        "ALERT", "high",   "T1110",   "TA0006", "credential-access", None,  3002,    3,
    ),
    "SSH Login": (
        "LOG",   "info",   None,      None,     None,                None,  3002,    3,
    ),
    "Sudo Failure": (
        "ALERT", "medium", "T1078",   "TA0004", "privilege-escalation", None, 3002,  3,
    ),
    "Syslog Event": (
        "LOG",   "info",   None,      None,     None,                None,  0,       0,
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

    OCSF (1.8.0, ADR-0040 pin; see module docstring for citations — issue #76):
      - Auth events (SSH Brute Force / SSH Login / Sudo Failure) →
        class_uid=3002 (Authentication), category_uid=3
      - Generic ("Syslog Event", unclassified) →
        class_uid=0 (Base Event), category_uid=0
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
