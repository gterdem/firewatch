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
# Authentication (class_uid 3002) — activity_id (issue #80)
# Source: live OCSF 1.8.0 schema, fetched 2026-07-16 via
#   https://schema.ocsf.io/api/1.8.0/classes/authentication
# Full activity_id enum: 0 Unknown, 1 Logon, 2 Logoff, 3 Authentication Ticket,
#   4 Service Ticket Request, 5 Service Ticket Renew, 6 Preauth, 7 Account
#   Switch, 99 Other.
#
# Every shipped 3002 emitter (linux_auth sshd/PAM/sudo, syslog, syslog_cef) is
# an authentication attempt for a logon session — success/failure is encoded
# in status_id (ADR-0071 D2 / issue #77), not activity_id. So the correct
# activity_id is 1 "Logon" for all of them, not 6 "Preauth" (Preauth is a
# Kerberos preauthentication stage — no shipped source emits that).
# type_uid = 3002 * 100 + 1 = 300201.
AUTHENTICATION_CLASS_UID: int = 3002
AUTHENTICATION_ACTIVITY_ID: int = 1         # Logon
AUTHENTICATION_TYPE_UID: int = 300201       # 3002 * 100 + 1

# ---------------------------------------------------------------------------
# Account Change (class_uid 3001) — activity_id (issue #80)
# Source: live OCSF 1.8.0 schema, fetched 2026-07-16 via
#   https://schema.ocsf.io/api/1.8.0/classes/account_change
# Full activity_id enum: 0 Unknown, 1 Create, 2 Enable, 3 Password Change,
#   4 Password Reset, 5 Disable, 6 Delete, 7 Attach Policy, 8 Detach Policy,
#   9 Lock, 10 MFA Factor Enable, 11 MFA Factor Disable, 12 Unlock.
#
# The only shipped 3001 emitter (linux_auth's useradd_new_user) is an account
# *creation* → activity_id 1 "Create" (not 6 "Delete").
# type_uid = 3001 * 100 + 1 = 300101.
ACCOUNT_CHANGE_CLASS_UID: int = 3001
ACCOUNT_CHANGE_ACTIVITY_ID: int = 1         # Create
ACCOUNT_CHANGE_TYPE_UID: int = 300101       # 3001 * 100 + 1

# ---------------------------------------------------------------------------
# Base Event (class_uid 0) and any class with no explicit branch — activity_id
# Source: live OCSF 1.8.0 schema, fetched 2026-07-16 via
#   https://schema.ocsf.io/api/1.8.0/classes/base_event
# Full activity_id enum (Base Event only defines the two universal members):
#   0 Unknown, 99 Other.
#
# 0 "Unknown" is valid in EVERY OCSF class's activity_id enum (all classes
# derive it from Base Event), so it is also the correct fallback for any
# ocsf_class the serializer has no explicit branch for — never a value
# borrowed from another class's enum (e.g. Network Activity's 6 "Traffic").
# type_uid for Base Event = 0 (not class_uid*100 + activity_id — 0*100+0 = 0
# coincides, but Base Event's type_uid is defined as 0 "Base Event: Unknown").
BASE_EVENT_CLASS_UID: int = 0
BASE_EVENT_ACTIVITY_ID: int = 0             # Unknown
BASE_EVENT_TYPE_UID: int = 0                # Base Event: Unknown

# Generic "Unknown" fallback activity_id, valid in every OCSF class's enum.
ACTIVITY_UNKNOWN: int = 0

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
