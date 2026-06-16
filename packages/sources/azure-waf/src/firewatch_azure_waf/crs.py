"""Static CRS rule-ID range table for the Azure WAF plugin.

Maps CRS rule-ID ranges (and Azure custom-rule prefixes) to:
  (category, attack_technique, attack_tactic, kill_chain_phase, capec_id)

Sources:
  - OWASP CRS rule-ID ranges: https://coreruleset.org/docs/3-about-rules/ruleid/
  - Azure CRS rule groups: https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-crs-rulegroups-rules
  - MITRE ATT&CK: https://attack.mitre.org/
  - CAPEC: https://capec.mitre.org/

Design: no runtime dependency on the CRS corpus (ADR-0014 — "extract at normalize-time,
no new deps").  A simple range-based lookup replaces the legacy 7-entry dict that caused
the ~68% "Other" rate (azure-waf-log-standard.md §3).

Azure custom rule names (RateLimit / GeoBlock / IPReputation / bot) are handled via a
separate prefix map to avoid dropping them to "Other".
"""
from __future__ import annotations

from typing import NamedTuple


class CRSEntry(NamedTuple):
    """One row in the CRS mapping table."""

    category: str
    attack_technique: str | None  # MITRE ATT&CK technique ID, e.g. "T1190"
    attack_tactic: str | None     # MITRE ATT&CK tactic ID, e.g. "TA0043"
    kill_chain_phase: str | None  # human tactic label, e.g. "reconnaissance"
    capec_id: str | None          # CAPEC ID, e.g. "CAPEC-66"


# ---------------------------------------------------------------------------
# CRS numeric range table
# Each entry covers rules from range_start (inclusive) to range_end (inclusive).
# Sources: CRS docs §rule-IDs; azure-waf-log-standard.md §2c.
# ---------------------------------------------------------------------------

# (range_start, range_end, CRSEntry)
_RANGE_TABLE: list[tuple[int, int, CRSEntry]] = [
    # 913xxx — scanner/recon detection (paranoia-level tags from CRS)
    (
        913000, 913999,
        CRSEntry(
            category="Scanner / Recon Detection",
            attack_technique="T1595",
            attack_tactic="TA0043",
            kill_chain_phase="reconnaissance",
            capec_id="CAPEC-169",
        ),
    ),
    # 920xxx — protocol enforcement / violation
    (
        920000, 920999,
        CRSEntry(
            category="Protocol Enforcement",
            attack_technique="T1190",
            attack_tactic="TA0001",
            kill_chain_phase="initial-access",
            capec_id="CAPEC-272",
        ),
    ),
    # 921xxx — HTTP request smuggling / protocol attack
    (
        921000, 921999,
        CRSEntry(
            category="Protocol Attack",
            attack_technique="T1190",
            attack_tactic="TA0001",
            kill_chain_phase="initial-access",
            capec_id="CAPEC-105",
        ),
    ),
    # 930xxx — local file inclusion (LFI) / path traversal
    (
        930000, 930999,
        CRSEntry(
            category="Local File Inclusion",
            attack_technique="T1190",
            attack_tactic="TA0001",
            kill_chain_phase="initial-access",
            capec_id="CAPEC-126",
        ),
    ),
    # 931xxx — remote file inclusion (RFI)
    (
        931000, 931999,
        CRSEntry(
            category="Remote File Inclusion",
            attack_technique="T1190",
            attack_tactic="TA0001",
            kill_chain_phase="initial-access",
            capec_id="CAPEC-193",
        ),
    ),
    # 932xxx — remote code execution / command injection
    (
        932000, 932999,
        CRSEntry(
            category="Remote Code Execution",
            attack_technique="T1190",
            attack_tactic="TA0001",
            kill_chain_phase="initial-access",
            capec_id="CAPEC-248",
        ),
    ),
    # 933xxx — PHP injection
    (
        933000, 933999,
        CRSEntry(
            category="PHP Injection",
            attack_technique="T1190",
            attack_tactic="TA0001",
            kill_chain_phase="initial-access",
            capec_id="CAPEC-242",
        ),
    ),
    # 941xxx — cross-site scripting (XSS)
    (
        941000, 941999,
        CRSEntry(
            category="Cross-Site Scripting (XSS)",
            attack_technique="T1059",
            attack_tactic="TA0002",
            kill_chain_phase="execution",
            capec_id="CAPEC-63",
        ),
    ),
    # 942xxx — SQL injection (SQLi)
    (
        942000, 942999,
        CRSEntry(
            category="SQL Injection",
            attack_technique="T1190",
            attack_tactic="TA0001",
            kill_chain_phase="initial-access",
            capec_id="CAPEC-66",
        ),
    ),
    # 943xxx — session fixation
    (
        943000, 943999,
        CRSEntry(
            category="Session Fixation",
            attack_technique="T1190",
            attack_tactic="TA0001",
            kill_chain_phase="initial-access",
            capec_id="CAPEC-61",
        ),
    ),
    # 944xxx — Java attacks (includes Log4Shell — CVE-2021-44228)
    (
        944000, 944999,
        CRSEntry(
            category="Java / Log4j Exploit",
            attack_technique="T1190",
            attack_tactic="TA0001",
            kill_chain_phase="initial-access",
            capec_id="CAPEC-242",
        ),
    ),
    # 949xxx — anomaly-score blocking / inbound anomaly evaluation
    (
        949000, 949999,
        CRSEntry(
            category="Anomaly Score Threshold",
            attack_technique="T1190",
            attack_tactic="TA0001",
            kill_chain_phase="initial-access",
            capec_id=None,
        ),
    ),
    # 959xxx — anomaly-score outbound evaluation
    (
        959000, 959999,
        CRSEntry(
            category="Anomaly Score Threshold",
            attack_technique="T1190",
            attack_tactic="TA0001",
            kill_chain_phase="initial-access",
            capec_id=None,
        ),
    ),
    # 980xxx — anomaly-score outbound blocking
    (
        980000, 980999,
        CRSEntry(
            category="Anomaly Score Threshold",
            attack_technique="T1190",
            attack_tactic="TA0001",
            kill_chain_phase="initial-access",
            capec_id=None,
        ),
    ),
]

# ---------------------------------------------------------------------------
# Azure custom-rule keyword table
# Azure WAF lets operators create custom rules; their rule names (not numeric IDs)
# carry semantic keywords.  Map known prefixes/substrings to CRSEntry.
# Source: Azure WAF custom rule naming conventions + azure-waf-log-standard.md §2c.
# ---------------------------------------------------------------------------

_CUSTOM_RULE_TABLE: list[tuple[str, CRSEntry]] = [
    (
        "ratelimit",
        CRSEntry(
            category="Rate Limit",
            attack_technique="T1595",
            attack_tactic="TA0043",
            kill_chain_phase="reconnaissance",
            capec_id=None,
        ),
    ),
    (
        "geoblock",
        CRSEntry(
            category="Geo Block",
            attack_technique=None,
            attack_tactic=None,
            kill_chain_phase=None,
            capec_id=None,
        ),
    ),
    (
        "ipreput",
        CRSEntry(
            category="IP Reputation",
            attack_technique="T1595",
            attack_tactic="TA0043",
            kill_chain_phase="reconnaissance",
            capec_id=None,
        ),
    ),
    (
        "bot",
        CRSEntry(
            category="Bot Detection",
            attack_technique="T1595",
            attack_tactic="TA0043",
            kill_chain_phase="reconnaissance",
            capec_id=None,
        ),
    ),
]

# ---------------------------------------------------------------------------
# Public lookup functions
# ---------------------------------------------------------------------------


def lookup_by_rule_id(rule_id: str | None) -> CRSEntry | None:
    """Return a ``CRSEntry`` for a numeric CRS rule ID string, or ``None``.

    Converts the string to int and scans the range table.  Returns ``None`` if
    rule_id is absent, non-numeric, or outside all documented ranges.  The caller
    can then fall back to ``lookup_by_custom_name`` or a default category.
    """
    if not rule_id:
        return None
    try:
        rid = int(rule_id)
    except (ValueError, TypeError):
        return None
    for start, end, entry in _RANGE_TABLE:
        if start <= rid <= end:
            return entry
    return None


def lookup_by_custom_name(rule_name: str | None) -> CRSEntry | None:
    """Return a ``CRSEntry`` for an Azure custom rule name, or ``None``.

    Lowercases the name and checks for known keyword substrings.  Returns the
    first match, or ``None`` if unrecognized.  Never returns an "Other" sentinel —
    callers decide how to handle ``None``.
    """
    if not rule_name:
        return None
    lower = rule_name.lower()
    for keyword, entry in _CUSTOM_RULE_TABLE:
        if keyword in lower:
            return entry
    return None


def lookup(rule_id: str | None, rule_name: str | None) -> CRSEntry | None:
    """Try numeric lookup first, then custom-name lookup.

    Returns the first matching ``CRSEntry``, or ``None`` if neither matches.
    Callers that need a guaranteed non-None result should supply a fallback.
    """
    entry = lookup_by_rule_id(rule_id)
    if entry is not None:
        return entry
    return lookup_by_custom_name(rule_name)
