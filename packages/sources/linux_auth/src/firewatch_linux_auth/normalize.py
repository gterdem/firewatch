"""Linux auth & intrusion signals → SecurityEvent normalization.

Reconciled with the canonical schema (canonical-schema skill) and the accepted ADRs:
  - ``source_type`` / ``source_id`` (ADR-0016 / Flag B)
  - ``action`` (ADR-0012 / ADR-0070 D1): a FAILED authentication attempt
    (sshd, sudo/su, generic PAM) is ``ALERT`` — ADR-0070 D1's "hostile attempt"
    predicate is ``action ∈ {BLOCK, DROP, ALERT}``, and only ALERT applies to a
    passive host-log source; ``LOG``-ing it would make every SSH brute force
    this plugin observes structurally invisible to the attempt-pressure/
    campaign rules (issue #53/#54) at any volume. A NEUTRAL/successful event
    (accepted login, new account created) is ``LOG`` — it asserts nothing
    hostile. **This corrects an earlier version of issue #3 that specified
    ``action=LOG`` for failed logins** (spec correction, 2026-07-15; see the
    issue's history) — that would have diverged from
    ``firewatch_syslog.normalize`` (which already maps the same ``Failed
    password`` line to ALERT) and silently broken ADR-0070's predicate.
  - ``severity`` (ADR-0069 D1/D3/D4(e)): Sigma ``level`` is the normative
    semantics of this field (ADR-0069 D1) — behavioral, not vibes. Every
    mapping below is justified against the Sigma definitions verbatim
    (SigmaHQ/sigma-specification) in the severity table, and the ambient-mass
    corollary (an event class that is ambient at volume on a healthy
    deployment maps to at most `medium`) is checked per category. **No
    category here ever qualifies the ADR-0067 D1(a)/D1(b) severity gate on
    its own** — escalation, if any, is a decision for a core correlation rule
    (``firewatch_core.detector``), never a per-event severity bump. This is
    what keeps a lone failed SSH login (or any ambient volume of them) from
    self-qualifying at any volume.
  - ``attack_technique`` / ``attack_tactic`` / ``kill_chain_phase`` (ADR-0014):
    MITRE ATT&CK v15 techniques, cited per-category below.
  - ``ocsf_class`` / ``ocsf_category`` (ADR-0020) — lightweight alignment only.

``source_type`` is ALWAYS the constant ``"linux_auth"`` — this plugin owns that
mapping. ``source_id`` is the caller-supplied instance name; this function never
branches on it (PLUGIN_CONTRACT.md "source_type vs source_id" section).

Severity/action table (ADR-0069 D4(e); Sigma levels quoted verbatim from
SigmaHQ/sigma-specification, ``specification/sigma-rules-specification.md``):

| Category                     | action | severity | Sigma justification |
|-------------------------------|--------|----------|----------------------|
| SSH Login Failure             | ALERT  | low      | Sigma `low`: "Notable event but rarely an incident. Low rated events can be relevant in high numbers or combination with others" — a lone failed SSH attempt, letter for letter. Ambient mass: an internet-exposed sshd sees many distinct scanner IPs a night, each a `low` ALERT — never queues alone (ADR-0067 D1(b) requires high/critical). Any "high numbers... combination" handling is a core correlation-rule decision (`firewatch_core.detector`), not this mapping. |
| SSH Login Success             | LOG    | info     | Sigma `informational`: "intended for enrichment... no case or alerting... expected that a huge amount of events will match" — every legitimate login, the ambient case by definition. Not an assertion of anything hostile (ECS `event.kind:event`). |
| Sudo Authentication Failure   | ALERT  | medium   | Sigma `medium`: "Relevant event that should be reviewed manually on a more frequent basis." Unlike SSH (internet-exposed), a sudo prompt is local-only and near-zero ambient on a healthy box (ADR-0069 D4(b) states this explicitly for the same event) — escalating above `low` does not breach the D1 ambient-mass corollary. |
| PAM Authentication Failure    | ALERT  | medium   | Same `pam_unix` mechanism as sudo (this plugin's `_parse_pam_generic` classifies every OTHER PAM-aware caller — `su`, `login`, …), same local-only/near-zero-ambient profile — the sudo justification above extends by analogy (ADR-0069 D3 rule 2: justify against the D1 definitions). |
| User Account Created          | LOG    | medium   | A SUCCESSFUL administrative action (ECS `event.outcome:success`), not a hostility assertion — `LOG`, mirroring "Accepted login". Severity sits above `info`: account creation is rare/noteworthy on a healthy box (not ambient telemetry, unlike a routine login) and carries T1136 Persistence relevance — Sigma `medium`: "reviewed manually on a more frequent basis." |
| Auth Activity (unclassified)  | LOG    | low      | ADR-0069 D3 rule 4 (fail quiet): a line that matched no known pattern is missing/unparseable classification — maps to `low` (telemetry-grade), never a gate-qualifying level, never fabricated upward. |

**Distribution statement (ADR-0069 D3 rule 3):** on a healthy Solo install,
the ambient mass is SSH Login Failure (low, from internet-wide scanner noise)
and SSH Login Success (info, the owner's own logins) — both non-queuing at
any volume. Sudo/PAM failures and new-user creation are near-zero-ambient
local events; `medium` for them does not flood (there is essentially nothing
there to flood with). Whether and how a burst of failures ever reaches Tier-2
is entirely a core correlation-rule decision (``firewatch_core.detector`` —
see that module for the current, still-evolving answer); it is never decided
by this per-event severity mapping.

Local-host IP fallback: ``sudo``/PAM/``useradd`` events usually have no network
origin (a local terminal session) — ``SecurityEvent.source_ip`` is a required
field, so ``_LOCAL_HOST_IP`` ("127.0.0.1") is used as the documented "this host"
sentinel when no remote IP is present in the log line (mirrors how the
loopback address already denotes "the local machine itself" in RFC 5735 §3 /
common security-tool convention). PAM's optional ``rhost=`` field is consulted
first (``parsers._extract_rhost``) — when a PAM-aware service is actually
triggered from a network session (e.g. sshd's PAM stack) and records the
originating host, that address is used instead of the loopback sentinel.

MITRE ATT&CK references (ATT&CK v15, https://attack.mitre.org/):
  - T1110 / TA0006 (Credential Access — Brute Force): a failed authentication
    attempt (SSH or generic PAM) — the technique describes the *method*
    (password/credential guessing), valid even for a single observed attempt,
    matching the in-tree precedent set by ``firewatch_syslog.normalize``.
  - T1548.003 / TA0004 (Privilege Escalation — Abuse Elevation Control
    Mechanism: Sudo and Sudo Caching): a failed sudo authentication is an
    attempted privilege-escalation action, distinct from ``firewatch_syslog``'s
    T1078 (Valid Accounts) choice for the same concept — deliberately more
    specific here since this plugin owns its own mapping (PLUGIN_CONTRACT.md).
  - T1136 / TA0003 (Persistence — Create Account): new local user account
    creation — named explicitly in issue #3's own acceptance criteria.

OCSF references (https://schema.ocsf.io, v1.8.0, verified live — lightweight
ADR-0020 alignment; corrected 2026-07-16, PR #73 held batch — the previous
text claimed class_uid 4001 for authentication AND put it under category_uid
4, self-contradicting the account-change row's own category_uid 3 for the
same "Identity & Access Management" name):
  - category_uid 3 = Identity & Access Management; category_uid 4 = Network
    Activity — two different categories, not interchangeable names.
  - class_uid 3002 = Authentication (category_uid 3, IAM) — SSH/sudo/PAM
    authentication outcomes (all four classified auth categories below).
  - class_uid 3001 = Account Change (category_uid 3, IAM) — new user account
    creation.
  - class_uid 0 = Base Event (category_uid 0) — the fallback row for a line
    this plugin could not classify; OCSF's own "uncategorized" class, not a
    borrowed Network Activity identity.
  - class_uid 4001 (Network Activity, category_uid 4) does NOT apply to any
    event this plugin emits — that class belongs to Suricata's network-layer
    telemetry (`firewatch_suricata.normalize`), which correctly keeps it.
"""
from __future__ import annotations

from datetime import datetime

from firewatch_sdk import RawEvent, SecurityEvent

from firewatch_linux_auth import parsers

# Constant source_type — this plugin declares "linux_auth" as its type key.
SOURCE_TYPE: str = "linux_auth"

# Sentinel for host-local events with no remote IP (sudo/PAM/useradd) — see
# module docstring "Local-host IP fallback".
_LOCAL_HOST_IP = "127.0.0.1"

# Fallback category for auth-relevant lines that matched none of the known
# parsers (e.g. a PAM session-opened/closed line, an sshd disconnect message).
# Deliberately distinct from every named category above — NOT the "one generic
# auth event" bucket the acceptance criteria rule out; those five signal types
# above always get their own distinct identity. This is only the "we saw
# something auth-adjacent but don't know what" residual.
_CAT_UNCLASSIFIED = "Auth Activity"

# category → (rule_id, action, severity, attack_technique, attack_tactic,
#             kill_chain_phase, ocsf_class, ocsf_category).
# See the module docstring's severity table (ADR-0069 D4(e)) for the Sigma
# justification behind every action/severity pair below, and the module
# docstring's "OCSF references" section (schema.ocsf.io v1.8.0) for the
# ocsf_class/ocsf_category pair on each row.
_CATEGORY_META: dict[
    str,
    tuple[str | None, str, str | None, str | None, str | None, str | None, int, int],
] = {
    parsers.CAT_SSH_LOGIN_FAILURE: (
        "sshd_login_failure", "ALERT", "low", "T1110", "TA0006", "credential-access", 3002, 3,
    ),
    parsers.CAT_SSH_LOGIN_SUCCESS: (
        "sshd_login_success", "LOG", "info", None, None, None, 3002, 3,
    ),
    parsers.CAT_SUDO_AUTH_FAILURE: (
        "sudo_auth_failure", "ALERT", "medium", "T1548.003", "TA0004", "privilege-escalation", 3002, 3,
    ),
    parsers.CAT_PAM_AUTH_FAILURE: (
        "pam_auth_failure", "ALERT", "medium", "T1110", "TA0006", "credential-access", 3002, 3,
    ),
    parsers.CAT_USER_ACCOUNT_CREATED: (
        "useradd_new_user", "LOG", "medium", "T1136", "TA0003", "persistence", 3001, 3,
    ),
    # Base Event (0, 0) — not 4001/4 (Network Activity): a line we could not
    # classify carries no honest claim to any specific OCSF class, and
    # Network Activity in particular would be actively wrong (this plugin
    # never observes network-layer telemetry). See the serializer note below
    # before touching this row.
    _CAT_UNCLASSIFIED: (
        None, "LOG", "low", None, None, None, 0, 0,
    ),
}

# RESOLVED (issue #76): firewatch_api's OCSF serializer used to do
# `event.ocsf_class or mapping.SURICATA_NET_CLASS_UID` — a falsy-zero bug.
# Because `0` is falsy in Python, the Base Event `(0, 0)` row above was
# silently REWRITTEN to `4001/4` on OCSF *export*, even though normalize()
# always emitted the honest `(0, 0)` pair. Fixed in
# `firewatch_api/ocsf/serializer.py::_resolve_class_uid` (`is not None` checks,
# issue #76) — class `0` now survives to the wire. Tests in this package still
# pin the *normalize-level* value (what this module actually emits), not the
# serialized output; that boundary stands regardless of the export-side fix.

_PAYLOAD_MAX_LEN = 500


def normalize(raw: RawEvent, source_id: str) -> SecurityEvent:
    """Map a Linux auth RawEvent to a SecurityEvent.

    Implements the PLUGIN_CONTRACT.md ``normalize()`` responsibility. Must set
    ``source_type="linux_auth"`` (constant) and pass ``source_id`` through
    without branching on it (Flag B).

    ``raw.data`` (constructed by ``collector.py``) carries ``"message"`` (the
    auth log text — a bare journald ``MESSAGE`` value or a full classic
    syslog line) and an optional ``"timestamp"`` (ISO-8601, when the reader
    could derive one; falls back to ``raw.received_at`` otherwise, mirroring
    ``firewatch_suricata.normalize``'s own fallback).
    """
    data = raw.data
    message: str = data.get("message") or ""
    parsed = parsers.parse_line(message)

    category = parsed.category if parsed is not None else _CAT_UNCLASSIFIED
    (
        rule_id, action, severity, technique, tactic, kill_chain_phase,
        ocsf_class, ocsf_category,
    ) = _CATEGORY_META[category]
    source_ip = (parsed.source_ip if parsed is not None else None) or _LOCAL_HOST_IP

    timestamp = _resolve_timestamp(data.get("timestamp"), raw.received_at)
    payload_snippet = message[:_PAYLOAD_MAX_LEN] if message else None

    return SecurityEvent(
        source_type=SOURCE_TYPE,   # constant — never branches on source_id (Flag B)
        source_id=source_id,       # caller's instance name, passed through as-is
        timestamp=timestamp,
        source_ip=source_ip,
        action=action,              # type: ignore[arg-type]
        category=category,
        severity=severity,         # type: ignore[arg-type]
        rule_id=rule_id,
        attack_technique=technique,
        attack_tactic=tactic,
        kill_chain_phase=kill_chain_phase,
        ocsf_class=ocsf_class,
        ocsf_category=ocsf_category,
        payload_snippet=payload_snippet,
        raw_log=data,
    )


def _resolve_timestamp(ts_str: object, received_at: datetime) -> datetime:
    """Parse the reader-supplied ISO-8601 timestamp, falling back to received_at.

    Mirrors ``firewatch_suricata.normalize``'s own received_at fallback for a
    missing/unparseable per-event timestamp.
    """
    if isinstance(ts_str, str) and ts_str:
        try:
            return datetime.fromisoformat(ts_str)
        except ValueError:
            pass
    return received_at
