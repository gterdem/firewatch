"""Azure WAF RawEvent → SecurityEvent normalization.

Clean-room implementation (ADR-0024): the v1 normalization wiring is DISCARDED.
Only the pull *technique* (SDK + watermark pattern) is reused.

This module handles BOTH Azure WAF product shapes:
  - Application Gateway WAF (azure-waf-log-standard.md §1a):
    discrete ``ruleId`` / ``ruleGroup`` / ``details.{message,data,file,line}``.
  - Front Door WAF (§1b):
    dotted ``ruleName`` (``{ruleset}-{version}-{group}-{ruleId}``) +
    ``details.matches[]``.  Rule ID is parsed from the trailing segment of ``ruleName``.

Action mapping (ADR-0012, azure-waf-log-standard.md §2b):
  Block / Blocked / JSChallengeBlock       → BLOCK  (OCSF disposition_id=2)
  Detected / Matched / AnomalyScoring /
    logandscore                             → ALERT  (OCSF disposition_id=15)
  Allowed / Allow                          → ALLOW  (OCSF disposition_id=1)
  Log / JSChallengeIssued / JSChallengePass
    / JSChallengeValid                     → LOG    (OCSF disposition_id=17)

No transport fields are fabricated: Azure WAF logs do not carry ``destination_port``,
``protocol``, or a reliable ``source_port``; leaving them unset (``None``) is correct
per PLUGIN_CONTRACT.md and §3 critique #5.

OCSF alignment (ADR-0020, azure-waf-log-standard.md §2a):
  ocsf_class    = 4002  (HTTP Activity — not the stale 6004)
  ocsf_category = 4     (Network Activity)
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from firewatch_sdk import RawEvent, SecurityEvent

from firewatch_azure_waf import crs as _crs
from firewatch_azure_waf import severity as _severity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SOURCE_TYPE: str = "azure_waf"

# OCSF HTTP Activity — azure-waf-log-standard.md §2a
OCSF_CLASS: int = 4002
OCSF_CATEGORY: int = 4

# ---------------------------------------------------------------------------
# Action mapping (§1c / §2b)
# Normalize to uppercase before lookup; covers casing variations across products.
# ---------------------------------------------------------------------------

_ACTION_MAP: dict[str, str] = {
    # Terminating blocks
    "block":              "BLOCK",
    "blocked":            "BLOCK",
    "jschallengeblock":   "BLOCK",
    # Detection / non-terminating / anomaly scoring — NOT blocks (corrects legacy bug)
    "detected":           "ALERT",
    "matched":            "ALERT",
    "anomalyscoring":     "ALERT",
    "logandscore":        "ALERT",
    # Passed
    "allowed":            "ALLOW",
    "allow":              "ALLOW",
    # Informational / JS-challenge lifecycle
    "log":                "LOG",
    "jslog":              "LOG",
    "jschallengelog":     "LOG",
    "jschallengeissued":  "LOG",
    "jschallengepass":    "LOG",
    "jschallengevalid":   "LOG",
}

# Default when action is unrecognized (conservative: treat as ALERT, not BLOCK)
_DEFAULT_ACTION = "ALERT"

# ---------------------------------------------------------------------------
# Front Door ruleName parser
# ---------------------------------------------------------------------------

# Pattern: {ruleset}-{version}-{group}-{ruleId}
# Example: "Microsoft_DefaultRuleSet-1.1-SQLI-942100"
# The trailing segment after the last dash that is all-digit is the rule ID.
_RULE_ID_TAIL_RE = re.compile(r"-(\d+)$")


def _parse_rule_id_from_rule_name(rule_name: str) -> str | None:
    """Extract the numeric rule ID from a Front Door dotted ruleName string.

    Front Door packs CRS metadata into a single string:
      ``{ruleset}-{version}-{group}-{ruleId}``
    e.g. ``Microsoft_DefaultRuleSet-1.1-SQLI-942100`` → ``"942100"``

    Returns the trailing numeric segment, or ``None`` if no digit tail found.
    (azure-waf-log-standard.md §1b)
    """
    m = _RULE_ID_TAIL_RE.search(rule_name)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Product shape detection
# ---------------------------------------------------------------------------

def _is_front_door(props: dict[str, Any]) -> bool:
    """Return True if this event looks like a Front Door WAF record.

    Front Door records use ``ruleName`` (a dotted string) instead of separate
    ``ruleId`` / ``ruleGroup`` fields.  Application Gateway records always have
    ``ruleId`` as a discrete field.
    """
    return "ruleName" in props and "ruleId" not in props


# ---------------------------------------------------------------------------
# Field extractors per product shape
# ---------------------------------------------------------------------------

def _extract_app_gateway(props: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """Extract (rule_id, rule_name, message) from Application Gateway properties.

    Returns:
        rule_id:   numeric CRS rule ID string (e.g. "942100"), or None.
        rule_name: human description from ``message`` field, or None.
        message:   same as rule_name (App Gateway puts the description in ``message``).
    """
    rule_id: str | None = str(props["ruleId"]) if props.get("ruleId") else None
    message: str | None = props.get("message") or None
    return rule_id, message, message


def _extract_front_door(props: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """Extract (rule_id, rule_name, message) from Front Door properties.

    Front Door packs CRS metadata into ``ruleName``; the human message is not always
    present as a separate field.  Parse the trailing rule ID from ``ruleName``.

    Returns:
        rule_id:   parsed trailing numeric ID, or None.
        rule_name: the full ``ruleName`` string (keeps provenance for drill-down).
        message:   None (Front Door does not carry a separate message field).
    """
    full_rule_name: str | None = props.get("ruleName") or None
    rule_id: str | None = None
    if full_rule_name:
        rule_id = _parse_rule_id_from_rule_name(full_rule_name)
    return rule_id, full_rule_name, None


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

def _parse_timestamp(raw_time: Any, fallback: datetime) -> datetime:
    """Parse an Azure log timestamp string into a timezone-aware datetime.

    Azure resource logs use ``time`` (ISO 8601) in the envelope.
    Falls back to ``fallback`` on any parse error.
    """
    if not raw_time:
        return fallback
    ts_str = str(raw_time)
    # Azure uses "Z" suffix; replace for fromisoformat compat
    ts_str = ts_str.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return fallback


# ---------------------------------------------------------------------------
# Payload snippet builder
# ---------------------------------------------------------------------------

_MAX_SNIPPET = 500


def _build_payload_snippet(props: dict[str, Any]) -> str | None:
    """Build a payload snippet from the most informative available fields.

    App Gateway: ``details.data`` (matched payload) + ``details.message``.
    Front Door:  ``details.matches[].matchVariableValue`` (truncated to 100 per MS).
    Falls back to ``requestUri`` if no detail fields are present.
    """
    details: dict[str, Any] = props.get("details") or {}
    parts: list[str] = []

    # App Gateway detail fields
    data_field: str | None = details.get("data") or None
    if data_field:
        parts.append(data_field)
    detail_msg: str | None = details.get("message") or None
    if detail_msg:
        parts.append(detail_msg)

    # Front Door matches array
    matches: list[Any] = details.get("matches") or []
    for match in matches:
        if isinstance(match, dict):
            val: str | None = match.get("matchVariableValue") or None
            if val:
                parts.append(val)
            var_name: str | None = match.get("matchVariableName") or None
            if var_name:
                parts.append(f"[{var_name}]")

    # Fallback to requestUri
    if not parts:
        uri: str | None = props.get("requestUri") or None
        if uri:
            parts.append(uri)

    if not parts:
        return None
    snippet = " | ".join(parts)
    return snippet[:_MAX_SNIPPET]


# ---------------------------------------------------------------------------
# Public normalize function
# ---------------------------------------------------------------------------

def normalize(raw: RawEvent, source_id: str) -> SecurityEvent:
    """Map an Azure WAF ``RawEvent`` to a ``SecurityEvent``.

    Implements PLUGIN_CONTRACT.md ``normalize()`` for the Azure WAF source.
    ``source_type`` is always the constant ``"azure_waf"`` (Flag B).
    ``source_id`` is the caller's instance name; never branched on.

    Handles both product shapes:
      - Application Gateway: discrete ``ruleId``/``ruleGroup`` fields.
      - Front Door: dotted ``ruleName`` parsed for rule ID (§1b).

    Never fabricates transport fields (destination_port, protocol, source_port)
    that Azure WAF logs do not carry (§3 critique #5).
    """
    d = raw.data
    # Azure resource log envelope wraps properties
    props: dict[str, Any] = d.get("properties") or d

    # ── Timestamp ─────────────────────────────────────────────────────────────
    raw_time = d.get("time") or d.get("timeStamp") or props.get("time")
    timestamp = _parse_timestamp(raw_time, fallback=raw.received_at)

    # ── Action ────────────────────────────────────────────────────────────────
    raw_action: str = str(props.get("action") or "").strip()
    normalized_action = raw_action.lower().replace("-", "").replace("_", "")
    action: str = _ACTION_MAP.get(normalized_action, _DEFAULT_ACTION)

    # ── Product shape & field extraction ─────────────────────────────────────
    if _is_front_door(props):
        rule_id, rule_name, message = _extract_front_door(props)
    else:
        rule_id, rule_name, message = _extract_app_gateway(props)

    # ── CRS lookup ────────────────────────────────────────────────────────────
    crs_entry = _crs.lookup(rule_id, rule_name)

    # Derive category: prefer CRS entry, fall back to ruleGroup/ruleName hint
    if crs_entry is not None:
        category: str | None = crs_entry.category
        attack_technique: str | None = crs_entry.attack_technique
        attack_tactic: str | None = crs_entry.attack_tactic
        kill_chain_phase: str | None = crs_entry.kill_chain_phase
        capec_id: str | None = crs_entry.capec_id
    else:
        # No recognized CRS mapping — use the ruleGroup or ruleName as category hint
        category = (
            props.get("ruleGroup")
            or (rule_name.split("-")[2] if rule_name and rule_name.count("-") >= 2 else None)
            or "WAF Rule"
        )
        attack_technique = None
        attack_tactic = None
        kill_chain_phase = None
        capec_id = None

    # ── Severity ──────────────────────────────────────────────────────────────
    # Always set — primary from CRS category, refined by anomaly score (§2d).
    severity = _severity.severity_from_category(category, message)

    # ── Source IP ─────────────────────────────────────────────────────────────
    # App Gateway: clientIp; Front Door: clientIP (note casing).
    # Azure logs do not carry destination_port, protocol, or source_port.
    source_ip: str = str(
        props.get("clientIp") or props.get("clientIP") or ""
    )
    # client_port is present on Front Door but not App Gateway; do not invent it
    # for App Gateway rows (no fabrication rule, §3 critique #5).
    raw_client_port = props.get("clientPort")
    source_port: int | None = None
    if raw_client_port is not None:
        try:
            source_port = int(raw_client_port)
        except (ValueError, TypeError):
            source_port = None

    # ── Payload snippet ───────────────────────────────────────────────────────
    payload_snippet = _build_payload_snippet(props)

    # ── Source event ID (transactionId for App Gateway, trackingReference for FD)
    source_event_id: str | None = (
        str(props["transactionId"]) if props.get("transactionId")
        else (str(props["trackingReference"]) if props.get("trackingReference") else None)
    )

    # ── ADR-0048 Group D: HTTP fields (ML-2) ─────────────────────────────────
    # Azure WAF diagnostic logs DO carry requestUri and hostname/host — these are
    # the HTTP layer fields we can honestly populate.
    #
    # Field mapping (verified against MS Learn log shapes in azure-waf-log-standard.md):
    #   http_url  <- properties.requestUri  (request URI / full URL)
    #   http_host <- properties.hostname    (App Gateway) or properties.host (Front Door)
    #
    # Azure WAF does NOT provide http_method or http_user_agent in diagnostic logs.
    # Leaving those None is correct; fabricating values is the explicit anti-pattern
    # (PLUGIN_CONTRACT.md + azure-waf-log-standard.md §3 critique #5).
    #
    # Flow/DNS/TLS fields remain None: Azure WAF is an L7 HTTP gateway with no access
    # to transport-layer flow stats, DNS queries, or TLS handshake fingerprints.
    http_url: str | None = props.get("requestUri") or None
    # App Gateway uses "hostname"; Front Door uses "host" — check both, prefer hostname
    http_host: str | None = props.get("hostname") or props.get("host") or None

    return SecurityEvent(
        source_type=SOURCE_TYPE,  # constant — never branches on source_id (Flag B)
        source_id=source_id,
        source_event_id=source_event_id,
        timestamp=timestamp,
        source_ip=source_ip,
        source_port=source_port,
        # destination_ip, destination_port, protocol: NOT set — Azure WAF does not
        # carry these fields; fabricating them is explicitly forbidden (§3 critique #5).
        action=action,  # type: ignore[arg-type]
        category=category,
        severity=severity,  # type: ignore[arg-type]
        ocsf_class=OCSF_CLASS,
        ocsf_category=OCSF_CATEGORY,
        rule_id=rule_id,
        rule_name=rule_name,
        payload_snippet=payload_snippet,
        attack_technique=attack_technique,
        attack_tactic=attack_tactic,
        kill_chain_phase=kill_chain_phase,
        capec_id=capec_id,
        # ADR-0048 Group D HTTP fields (ML-2): only the subset Azure WAF genuinely has.
        # http_method and http_user_agent are not available in WAF diagnostic logs.
        # Flow/DNS/TLS fields are intentionally left None (L7 HTTP gateway — honest).
        http_url=http_url,
        http_host=http_host,
        raw_log=d,
    )
