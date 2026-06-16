"""Shared, source-agnostic normalize helpers.

Ported verbatim from the source-agnostic part of ``legacy/core/normalizer.py``:
rule-id → category mapping and the lightweight OCSF class map (ADR-0014/0020). The
per-source raw → SecurityEvent mappers (Suricata/Syslog/v1) deliberately do NOT live
here — each plugin owns its own mapping (PLUGIN_CONTRACT.md).
"""

RULE_CATEGORIES = {
    "942": "SQL Injection",
    "941": "XSS",
    "930": "Local File Inclusion",
    "932": "Command Injection",
    "920": "Protocol Violation",
    "949": "Anomaly Score Exceeded",
    "300": "Bot Activity",
}

# Lightweight OCSF v1.x class alignment (ADR-0020). Not full compliance.
# Reference: https://schema.ocsf.io/categories
# Maps category name -> (class_uid, category_uid).
OCSF_CLASS_MAP: dict[str, tuple[int, int]] = {
    "SQL Injection":          (6004, 6),  # Web Resources Activity / Application Activity
    "XSS":                    (6004, 6),
    "Local File Inclusion":   (6004, 6),
    "Command Injection":      (6004, 6),
    "Protocol Violation":     (6004, 6),
    "Anomaly Score Exceeded": (6004, 6),
    "Bot Activity":           (4001, 4),  # Network Activity / Network Activity
    "Rate Limited":           (6004, 6),
    "Geo-Blocked":            (6004, 6),
    "IP Reputation":          (4001, 4),
    "Other":                  (6004, 6),
}


def ocsf_for_category(category: str) -> tuple[int | None, int | None]:
    """Return (class_uid, category_uid) for an OCSF-mapped category, or (None, None)."""
    return OCSF_CLASS_MAP.get(category, (None, None))


def categorize_rule(rule_id: str | None) -> str:
    """Map a rule ID to a human-readable category."""
    r = str(rule_id or "")
    for prefix, cat in RULE_CATEGORIES.items():
        if r.startswith(prefix):
            return cat
    if "RateLimit" in r:
        return "Rate Limited"
    if "GeoBlock" in r:
        return "Geo-Blocked"
    if "IPReputation" in r:
        return "IP Reputation"
    return "Other"
