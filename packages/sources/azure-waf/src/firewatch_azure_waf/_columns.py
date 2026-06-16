"""Column-name canonicalization for the Azure WAF plugin.

Azure WAF Log Analytics tables use three distinct column-name regimes, none of
which matches the camelCase ``properties`` shape that ``normalize.py`` reads:

  resource_specific / App Gateway  — PascalCase flat columns
    (``ClientIp``, ``RuleId``, ``Action``, ``Details_Message``, …)
  resource_specific / Front Door   — PascalCase flat columns
    (``ClientIP``, ``RuleName``, ``Details_Matches``, …)
  azure_diagnostics                — ``_s``/``_d`` suffixed columns
    (``clientIp_s``, ``ruleId_s``, ``action_s``, ``details_matches_s``, …)

This module provides a single ``canonicalize_row`` function that maps ANY of
those regimes into the ONE canonical camelCase ``properties``-object shape that
``normalize.py`` consumes (matching the Azure resource-log ``properties`` envelope
documented at azure-waf-log-standard.md §1a and §1b).

After canonicalization every row dict carries a ``"properties"`` key whose
sub-dict contains only camelCase field names, with nested ``details`` sub-dict
reconstructed from the flattened columns.

Placement: called by ``client._row_to_raw_event`` immediately after
``_row_to_dict``, before the ``RawEvent`` is constructed.  ``normalize.py`` is
completely regime-agnostic — it only sees the canonical shape.

Design rationale (mapping-layer vs. KQL project-rename):
  KQL ``project-rename`` can flatten names but cannot reconstruct the nested
  ``details``/``details.matches[]`` objects (KQL has no JSON-build primitives for
  that at result-set level).  A Python mapping layer cleanly handles both
  name remapping and nested-object reconstruction in one place, keeping the KQL
  templates readable and the normalizer regime-agnostic.  Column names are
  sourced from azure-waf-log-standard.md §1 (the ``properties`` field tables) —
  no invented names.
"""
from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger("firewatch.azure_waf.columns")

# ---------------------------------------------------------------------------
# Envelope columns — stay at the top level of the raw-event dict, not inside
# ``properties``.  These are the same across all three regimes.
# ---------------------------------------------------------------------------

_ENVELOPE_COLS: frozenset[str] = frozenset({
    "TimeGenerated",
    "ResourceId",
    "OperationName",
    "Category",
    "time",  # synthetic key added by _row_to_raw_event after TimeGenerated parse
})

# ---------------------------------------------------------------------------
# resource_specific App Gateway (AGWFirewallLogs) — PascalCase → camelCase
#
# Source: _kql.py _KQL_AGW_RESOURCE project clause +
#         azure-waf-log-standard.md §1a field table.
# ---------------------------------------------------------------------------

_AGW_RESOURCE_MAP: dict[str, str] = {
    "InstanceId":       "instanceId",
    "ClientIp":         "clientIp",
    "RequestUri":       "requestUri",
    "RuleSetType":      "ruleSetType",
    "RuleSetVersion":   "ruleSetVersion",
    "RuleId":           "ruleId",
    "RuleGroup":        "ruleGroup",
    "Message":          "message",
    "Action":           "action",
    "Site":             "site",
    "Hostname":         "hostname",
    "TransactionId":    "transactionId",
    "PolicyId":         "policyId",
    "PolicyScope":      "policyScope",
    "PolicyScopeName":  "policyScopeName",
    # Details_* are handled separately — they fold into a nested details dict.
    "Details_Message":  "_details_message",
    "Details_Data":     "_details_data",
    "Details_File":     "_details_file",
    "Details_Line":     "_details_line",
}

# ---------------------------------------------------------------------------
# resource_specific Front Door (AzureFrontDoorWebApplicationFirewallLog)
# — PascalCase → camelCase
#
# Source: _kql.py _KQL_FD_RESOURCE project clause +
#         azure-waf-log-standard.md §1b field table.
# ---------------------------------------------------------------------------

_FD_RESOURCE_MAP: dict[str, str] = {
    "ClientIP":          "clientIP",
    "ClientPort":        "clientPort",
    "SocketIP":          "socketIP",
    "RequestUri":        "requestUri",
    "RuleName":          "ruleName",
    "Policy":            "policy",
    "PolicyMode":        "policyMode",
    "Host":              "host",
    "TrackingReference": "trackingReference",
    # Details_Matches is a JSON string from KQL — folded into details.matches[].
    "Details_Matches":   "_details_matches",
    "Action":            "action",
}

# ---------------------------------------------------------------------------
# azure_diagnostics — _s/_d suffix stripping
#
# Source: _kql.py _KQL_AZURE_DIAG_* project clauses.
# Both App Gateway and Front Door columns are listed; only present columns are
# remapped (absent ones are silently skipped).
# ---------------------------------------------------------------------------

_DIAG_SUFFIX_MAP: dict[str, str] = {
    # App Gateway
    "instanceId_s":       "instanceId",
    "clientIp_s":         "clientIp",
    "requestUri_s":       "requestUri",
    "ruleSetType_s":      "ruleSetType",
    "ruleSetVersion_s":   "ruleSetVersion",
    "ruleId_s":           "ruleId",
    "ruleGroup_s":        "ruleGroup",
    "message_s":          "message",
    "action_s":           "action",
    "site_s":             "site",
    "hostname_s":         "hostname",
    "transactionId_s":    "transactionId",
    "policyId_s":         "policyId",
    "policyScope_s":      "policyScope",
    "policyScopeName_s":  "policyScopeName",
    # App Gateway details — folded into nested details dict
    "details_message_s":  "_details_message",
    "details_data_s":     "_details_data",
    "details_file_s":     "_details_file",
    "details_line_s":     "_details_line",
    # Front Door
    "clientIP_s":         "clientIP",
    "clientPort_d":       "clientPort",
    "socketIP_s":         "socketIP",
    "ruleName_s":         "ruleName",
    "policy_s":           "policy",
    "policyMode_s":       "policyMode",
    "host_s":             "host",
    "trackingReference_s":"trackingReference",
    # Front Door details_matches — folded into details.matches[]
    "details_matches_s":  "_details_matches",
}


# ---------------------------------------------------------------------------
# Regime detection
# ---------------------------------------------------------------------------

def _detect_regime(row: dict[str, Any]) -> str:
    """Infer the column regime from the keys present in a row dict.

    Returns one of ``"resource_agw"``, ``"resource_fd"``, or ``"diagnostics"``.

    Detection heuristic (deterministic, no guessing):
    - If any ``_s``/``_d`` suffixed key is present → ``"diagnostics"``.
    - Else if ``RuleName`` present (Front Door PascalCase marker) → ``"resource_fd"``.
    - Else → ``"resource_agw"`` (default for resource-specific App Gateway).

    The caller (``_row_to_raw_event``) passes the full row dict from the real
    LogsTableRow extraction, so the keys are always the actual projected column names.
    """
    # Any _s or _d suffix → AzureDiagnostics
    for key in row:
        if key.endswith("_s") or key.endswith("_d"):
            return "diagnostics"
    # Front Door resource-specific marker
    if "RuleName" in row or "TrackingReference" in row or "ClientIP" in row:
        return "resource_fd"
    return "resource_agw"


# ---------------------------------------------------------------------------
# Details reconstruction helpers
# ---------------------------------------------------------------------------

def _build_details_from_flat(props: dict[str, Any]) -> None:
    """Reconstruct nested ``details`` dict from ``_details_*`` staging keys.

    After prefix-mapping, App Gateway detail columns land as:
      ``_details_message``, ``_details_data``, ``_details_file``, ``_details_line``

    These are folded into ``props["details"]`` = ``{message, data, file, line}``
    and removed from the top-level props dict.

    Mutates ``props`` in-place.
    """
    staging_keys = ("_details_message", "_details_data", "_details_file", "_details_line")
    detail_names = ("message", "data", "file", "line")
    details: dict[str, Any] = {}
    for staging, name in zip(staging_keys, detail_names):
        val = props.pop(staging, None)
        if val is not None:
            details[name] = val
    if details:
        props["details"] = details


def _build_details_matches_from_flat(props: dict[str, Any]) -> None:
    """Reconstruct ``details.matches[]`` from the ``_details_matches`` staging key.

    Front Door stores the matches as a JSON string in Log Analytics.
    After suffix/PascalCase mapping the value lands at ``props["_details_matches"]``.
    This function parses the JSON and nests it as ``props["details"]["matches"]``.

    If the value is already a list (e.g. the SDK already parsed it), it is used
    directly.  Falls back gracefully if the JSON is malformed — logs a warning
    and omits the field rather than crashing.

    Mutates ``props`` in-place.
    """
    raw_matches = props.pop("_details_matches", None)
    if raw_matches is None:
        return

    matches: list[Any] | None = None
    if isinstance(raw_matches, list):
        matches = raw_matches
    elif isinstance(raw_matches, str):
        try:
            parsed = json.loads(raw_matches)
            if isinstance(parsed, list):
                matches = parsed
            else:
                logger.warning(
                    "_build_details_matches_from_flat: parsed JSON is not a list "
                    "(type=%s); dropping matches", type(parsed).__name__
                )
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning(
                "_build_details_matches_from_flat: JSON parse error for matches: %s; "
                "raw value truncated to 200 chars: %.200r",
                exc, raw_matches,
            )

    if matches is not None:
        existing_details: dict[str, Any] = props.get("details") or {}
        existing_details["matches"] = matches
        props["details"] = existing_details


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def canonicalize_row(row: dict[str, Any]) -> dict[str, Any]:
    """Remap a flat Log Analytics row dict into the canonical ``properties`` shape.

    Takes a row dict produced by ``_row_to_dict`` (flat column-name → value) and
    returns a new dict with:
      - Top-level envelope keys (``TimeGenerated``, ``ResourceId``, ``OperationName``,
        ``Category``, ``time``) preserved at the top level.
      - All WAF-specific fields mapped to camelCase and placed under a
        ``"properties"`` sub-dict matching the Azure resource-log envelope shape
        (azure-waf-log-standard.md §1a / §1b).
      - Nested ``details`` sub-dict reconstructed from flat ``Details_*`` /
        ``details_*_s`` columns (App Gateway) and ``Details_Matches`` /
        ``details_matches_s`` parsed from JSON (Front Door).
      - Unmapped columns preserved as-is inside ``properties`` (no forensic data
        is dropped — the full raw row is stored in ``raw_log``).

    This function is idempotent for rows that already carry a ``"properties"``
    key (e.g. a pre-formed JSON envelope) — those are returned unchanged.

    Args:
        row: Flat dict from ``_row_to_dict`` — column names as delivered by
             the SDK (PascalCase or ``_s``/``_d`` suffixed).

    Returns:
        Dict in ``{envelope_key: value, ..., "properties": {camelCase: value, ...}}``
        shape ready for ``normalize.py``.
    """
    # Already in canonical envelope shape — pass through unchanged.
    if "properties" in row:
        return row

    regime = _detect_regime(row)
    col_map = _DIAG_SUFFIX_MAP if regime == "diagnostics" else (
        _FD_RESOURCE_MAP if regime == "resource_fd" else _AGW_RESOURCE_MAP
    )

    envelope: dict[str, Any] = {}
    props: dict[str, Any] = {}

    for col, val in row.items():
        if col in _ENVELOPE_COLS:
            envelope[col] = val
            continue
        canonical = col_map.get(col, col)
        props[canonical] = val

    # Reconstruct nested details sub-dicts from staging keys
    _build_details_from_flat(props)
    _build_details_matches_from_flat(props)

    result: dict[str, Any] = {**envelope, "properties": props}
    return result
