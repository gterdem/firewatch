"""OCSF 1.8.0 field-mapping tables and constants (ADR-0040 / MI-5 #386).

Pure constants and lookup tables — NO I/O, no imports beyond stdlib.

Every numeric mapping traces to one of:
  - scratch/ocsf-1.8.0-reference.md (compiled from schema.ocsf.io/1.8.0, 2026-06-12)
  - schema.ocsf.io/1.8.0/dictionary
  - schema.ocsf.io/1.8.0/classes/detection_finding
  - schema.ocsf.io/1.8.0/classes/http_activity
  - schema.ocsf.io/1.8.0/classes/network_activity

The string sibling is the OCSF enum label (PascalCase as per schema).
"""

# ---------------------------------------------------------------------------
# Schema version (pinned — ADR-0040)
# ---------------------------------------------------------------------------

#: OCSF schema version pinned by ADR-0040.  Bump deliberately + update ADR + fix goldens.
OCSF_VERSION: str = "1.8.0"

# ---------------------------------------------------------------------------
# FireWatch product metadata (emitted in every ``metadata`` block)
# ---------------------------------------------------------------------------

FIREWATCH_PRODUCT: dict = {
    "name": "FireWatch",
    "vendor_name": "FireWatch",
}

# ---------------------------------------------------------------------------
# severity_id (base event enum)
# Source: schema.ocsf.io/1.8.0/dictionary  (scratch/ocsf-1.8.0-reference.md §1)
# ---------------------------------------------------------------------------

# FireWatch SeverityLiteral → OCSF severity_id + severity string.
# SeverityLiteral values: "info", "low", "medium", "high", "critical"
# (no "fatal" in FireWatch — ADR-0020; OCSF 6=Fatal is therefore unreachable here).
SEVERITY_ID: dict[str | None, int] = {
    # Source: scratch/ocsf-1.8.0-reference.md §1 / schema.ocsf.io/1.8.0/dictionary
    "info":     1,   # Informational
    "low":      2,   # Low
    "medium":   3,   # Medium
    "high":     4,   # High
    "critical": 5,   # Critical
    None:       0,   # Unknown (no severity set)
}

SEVERITY_LABEL: dict[str | None, str] = {
    "info":     "Informational",
    "low":      "Low",
    "medium":   "Medium",
    "high":     "High",
    "critical": "Critical",
    None:       "Unknown",
}

# ---------------------------------------------------------------------------
# disposition_id (Security Control profile extension)
# Source: scratch/ocsf-1.8.0-reference.md §2 / schema.ocsf.io/1.8.0/classes/detection_finding
#
# Core: 0 Unknown · 1 Allowed · 2 Blocked · 3 Quarantined · 4 Isolated · 5 Deleted
# Extended (Security Control profile): 6 Dropped · 15 Detected · 17 Logged
#   · 19 Alert · 20 Count · 21 Reset
#
# NOTE: extended values (6, 15, 17, 19, 20, 21) are Security-Control-profile
# extensions.  Per scratch/ocsf-1.8.0-reference.md caveat, include
# profiles:["security_control"] in metadata when emitting them.
# ---------------------------------------------------------------------------

# FireWatch ActionLiteral → OCSF disposition_id + disposition string sibling.
# ActionLiteral values: "ALLOW", "BLOCK", "DROP", "ALERT", "LOG"
DISPOSITION_ID: dict[str, int] = {
    # Source: scratch/ocsf-1.8.0-reference.md §2 "disposition_id"
    "ALLOW":  1,   # Allowed  (core)
    "BLOCK":  2,   # Blocked  (core)
    "DROP":   6,   # Dropped  (Security Control profile ext)
    "ALERT":  19,  # Alert    (Security Control profile ext)
    "LOG":    17,  # Logged   (Security Control profile ext)
}

DISPOSITION_LABEL: dict[str, str] = {
    "ALLOW":  "Allowed",
    "BLOCK":  "Blocked",
    "DROP":   "Dropped",
    "ALERT":  "Alert",
    "LOG":    "Logged",
}

#: disposition_id values that are Security-Control-profile extensions;
#: metadata.profiles must include "security_control" when these are emitted.
#: Source: scratch/ocsf-1.8.0-reference.md §2 caveat.
SECURITY_CONTROL_DISPOSITION_IDS: frozenset[int] = frozenset({6, 15, 17, 19, 20, 21})

# ---------------------------------------------------------------------------
# HTTP Activity (class_uid 4002) — activity_id (HTTP method)
# Source: scratch/ocsf-1.8.0-reference.md §3 / schema.ocsf.io/1.8.0/classes/http_activity
# ---------------------------------------------------------------------------

# OCSF HTTP Activity activity_id values (OCSF 1.8.0):
#   0 Unknown · 1 Connect · 2 Delete · 3 Get · 4 Head · 5 Options
#   6 Post · 7 Put · 8 Trace · 9 Patch · 99 Other
HTTP_METHOD_ACTIVITY_ID: dict[str, int] = {
    # Source: scratch/ocsf-1.8.0-reference.md §3
    "CONNECT": 1,
    "DELETE":  2,
    "GET":     3,
    "HEAD":    4,
    "OPTIONS": 5,
    "POST":    6,
    "PUT":     7,
    "TRACE":   8,
    "PATCH":   9,
}

HTTP_ACTIVITY_UNKNOWN: int = 0   # No resolvable HTTP method → Unknown

# ---------------------------------------------------------------------------
# Network Activity (class_uid 4001) — activity_id
# Source: scratch/ocsf-1.8.0-reference.md §4 / schema.ocsf.io/1.8.0/classes/network_activity
# ---------------------------------------------------------------------------

# Default for network events without a lifecycle signal (use Traffic).
# Source: scratch/ocsf-1.8.0-reference.md §4
NETWORK_ACTIVITY_TRAFFIC: int = 6   # Traffic

# ---------------------------------------------------------------------------
# Detection Finding (class_uid 2004) — activity_id
# Source: scratch/ocsf-1.8.0-reference.md §2 / schema.ocsf.io/1.8.0/classes/detection_finding
# ---------------------------------------------------------------------------

# Each export is a point-in-time snapshot → activity_id 1 (Create).
# type_uid = class_uid * 100 + activity_id = 2004 * 100 + 1 = 200401.
DETECTION_FINDING_ACTIVITY_ID: int = 1      # Create
DETECTION_FINDING_CLASS_UID: int = 2004
DETECTION_FINDING_CATEGORY_UID: int = 2
DETECTION_FINDING_TYPE_UID: int = 200401    # 2004 * 100 + 1

# ---------------------------------------------------------------------------
# Class / category passthrough (per-event — read from SecurityEvent)
# ---------------------------------------------------------------------------

# Azure WAF events → HTTP Activity (as set by normalize.py, ADR-0020).
# Source: firewatch_azure_waf.normalize  (OCSF_CLASS=4002, OCSF_CATEGORY=4)
AZURE_WAF_CLASS_UID: int = 4002
AZURE_WAF_CATEGORY_UID: int = 4

# Suricata detection events → Detection Finding.
# Source: firewatch_suricata.normalize  (2004, 2 for IDS alert categories)
SURICATA_IDS_CLASS_UID: int = 2004
SURICATA_IDS_CATEGORY_UID: int = 2

# Suricata network-observation events → Network Activity.
# Source: firewatch_suricata.normalize  (4001, 4 for connection-level events)
SURICATA_NET_CLASS_UID: int = 4001
SURICATA_NET_CATEGORY_UID: int = 4
