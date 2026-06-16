"""Vendor action registry — (DeviceVendor, DeviceProduct) -> ActionValueTable.

Maps CEF Extension 'act' tokens to FireWatch canonical action literals
(BLOCK / DROP / ALLOW / ALERT / LOG) per the ArcSight CEF standard dictionary.

Design (PLUGIN_CONTRACT.md Flag B):
  - normalize() routes on the *payload's* DeviceVendor/DeviceProduct, NEVER on source_id.
  - source_type stays the constant "syslog_cef"; this registry is plugin-internal.
  - Core never learns vendor names.

Registry structure:
  _VENDOR_REGISTRY: dict[(vendor_lower, product_lower), dict[act_lower, ActionLiteral]]
    Per-vendor override tables. Lookup is case-insensitive on all keys.

  _GENERIC_TABLE: dict[act_lower, ActionLiteral]
    Generic default — used when (vendor, product) has no registered table.
    Covers the common CEF dictionary tokens defined in the ArcSight CEF spec.

Generic table token sources (ArcSight CEF Implementation Standard, Extension field 'act'):
  Block/deny tokens: block, deny, reject, drop, blocked, denied, dropped, rejected
  Allow tokens:      allow, permit, allowed, permitted, pass, passed, accept, accepted
  Alert tokens:      alert, detect, detected, detection, ids-alert, warn, warning
  Log tokens:        log, logged, monitor, monitored, audit

Action mapping rationale (ADR-0012):
  WAF/firewall block actions -> BLOCK or DROP (per CEF spec: act=deny/block/drop)
  IDS detections             -> ALERT         (per CEF spec: act=alert/detect)
  Permit/allow               -> ALLOW
  Log-only/audit             -> LOG
  Unknown token              -> ALERT (safe IDS-semantics default; not a silent no-op)
"""
from __future__ import annotations

from firewatch_sdk.models import ActionLiteral

# ---------------------------------------------------------------------------
# Generic default table (unknown vendor or no per-vendor override found).
# Keys are lowercase CEF 'act' tokens; values are canonical ActionLiterals.
# ---------------------------------------------------------------------------

_GENERIC_TABLE: dict[str, ActionLiteral] = {
    # Block / deny family
    "block": "BLOCK",
    "blocked": "BLOCK",
    "deny": "BLOCK",
    "denied": "BLOCK",
    "reject": "BLOCK",
    "rejected": "BLOCK",
    # Drop family (stateful firewall 'silently discard')
    "drop": "DROP",
    "dropped": "DROP",
    "discard": "DROP",
    "discarded": "DROP",
    # Allow / permit family
    "allow": "ALLOW",
    "allowed": "ALLOW",
    "permit": "ALLOW",
    "permitted": "ALLOW",
    "pass": "ALLOW",
    "passed": "ALLOW",
    "accept": "ALLOW",
    "accepted": "ALLOW",
    # IDS alert / detect family
    "alert": "ALERT",
    "detect": "ALERT",
    "detected": "ALERT",
    "detection": "ALERT",
    "ids-alert": "ALERT",
    "warn": "ALERT",
    "warning": "ALERT",
    "threat": "ALERT",
    # Log / audit / monitor (informational, non-blocking)
    "log": "LOG",
    "logged": "LOG",
    "monitor": "LOG",
    "monitored": "LOG",
    "audit": "LOG",
}

# ---------------------------------------------------------------------------
# Per-vendor override tables.
# Key: (vendor_lower, product_lower)  -- or use "" for product to match any product.
# Value: dict[act_lower, ActionLiteral]
#
# Only tokens that DIFFER from the generic table need to be listed here.
# Vendor-specific tokens not in the override fall through to the generic table.
# ---------------------------------------------------------------------------

# Fortinet FortiGate CEF mappings.
# Source: Fortinet FortiGate CEF Log Reference
#   https://docs.fortinet.com/document/fortigate/7.0.0/log-message-reference/
# FortiGate uses "deny" for blocked traffic and "accept" for allowed traffic.
# These match the generic table, so only non-standard tokens are added.
_FORTINET_FORTIGATE: dict[str, ActionLiteral] = {
    **_GENERIC_TABLE,
    # FortiGate-specific: "deny" is the primary block token (matches generic)
    # "close" occurs in session-end events -- informational
    "close": "LOG",
    "server-rst": "LOG",
    "client-rst": "LOG",
    "timeout": "LOG",
}

# Palo Alto Networks PAN-OS CEF mappings.
# Source: Palo Alto Networks CEF Configuration Guide
#   https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/monitoring/
# PAN-OS uses "drop" and "deny" for blocked traffic, "allow" for permitted.
_PALOALTO_PANOS: dict[str, ActionLiteral] = {
    **_GENERIC_TABLE,
    # PAN-OS-specific tokens
    "drop-icmp": "DROP",
    "sinkhole": "BLOCK",
    "reset-client": "BLOCK",
    "reset-server": "BLOCK",
    "reset-both": "BLOCK",
    "drop-all": "DROP",
}

# Cisco ASA CEF mappings.
# Source: Cisco ASA Series Syslog Guide
#   https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/
# ASA uses "Built"/"Teardown" for flow events, "Deny" for blocks.
_CISCO_ASA: dict[str, ActionLiteral] = {
    **_GENERIC_TABLE,
    "built": "LOG",
    "teardown": "LOG",
    "no-user": "ALERT",
    "denied": "BLOCK",
}

# Registry: (vendor_lower, product_lower) -> action table
# Use "" for product_lower to match ANY product from that vendor.
_VENDOR_REGISTRY: dict[tuple[str, str], dict[str, ActionLiteral]] = {
    ("fortinet", "fortigate"): _FORTINET_FORTIGATE,
    ("palo alto networks", "pan-os"): _PALOALTO_PANOS,
    ("cisco", "asa"): _CISCO_ASA,
    # Wildcard product entries for vendors with consistent act tokens across products
    ("fortinet", ""): _FORTINET_FORTIGATE,
    ("palo alto networks", ""): _PALOALTO_PANOS,
    ("cisco", ""): _CISCO_ASA,
}

# Safe default for completely unrecognized act tokens (IDS semantics — not a no-op).
_DEFAULT_UNKNOWN_ACTION: ActionLiteral = "ALERT"


def resolve_action(vendor: str, product: str, act_token: str) -> ActionLiteral:
    """Resolve a CEF 'act' token to a canonical ActionLiteral.

    Lookup order (all comparisons are case-insensitive):
    1. Per-vendor per-product table: (vendor, product)
    2. Per-vendor wildcard table:    (vendor, "")
    3. Generic default table
    4. _DEFAULT_UNKNOWN_ACTION ("ALERT") for completely unrecognized tokens

    Args:
        vendor:    CEF DeviceVendor header field.
        product:   CEF DeviceProduct header field.
        act_token: CEF Extension 'act' field value (raw, any case).

    Returns:
        A canonical ActionLiteral (BLOCK/DROP/ALLOW/ALERT/LOG).
    """
    vendor_l = vendor.lower()
    product_l = product.lower()
    token_l = act_token.lower()

    # Try exact (vendor, product) match.
    table = _VENDOR_REGISTRY.get((vendor_l, product_l))

    # Try (vendor, "") wildcard if no exact product match.
    if table is None:
        table = _VENDOR_REGISTRY.get((vendor_l, ""))

    # Fall through to generic table.
    if table is None:
        table = _GENERIC_TABLE

    return table.get(token_l, _DEFAULT_UNKNOWN_ACTION)
