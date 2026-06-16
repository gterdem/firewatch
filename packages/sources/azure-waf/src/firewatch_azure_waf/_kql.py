"""KQL query templates and builder for the Azure WAF plugin.

Separated from ``client.py`` by concern: this module is purely
data (KQL string templates) + a single pure function that
selects and formats them given product/table-regime/time-window inputs.
It has no SDK dependencies (only the stdlib ``datetime``).

Table regimes (azure-waf-log-standard.md §1d):
  resource_specific:
    App Gateway → ``AGWFirewallLogs``
    Front Door  → ``AzureFrontDoorWebApplicationFirewallLog``
  azure_diagnostics:
    Both products → ``AzureDiagnostics``
    Column names carry _s / _d suffixes (e.g. ``clientIp_s``, ``ruleId_s``).

AzureDiagnostics column-name notes (verified against a live App Gateway WAF workspace,
issue #142):
  - ``Message`` (capital, no _s suffix) carries the rule message — NOT ``message_s``.
  - ``transactionId_g`` (note ``_g``, not ``_s``) is the transaction GUID.
  - ``site_s`` is NOT emitted by App Gateway WAF; it is absent from real workspaces.
  - AzureDiagnostics only materialises a column after the first row populates it.
    Any bare ``project column_name`` fails with SEM0100 on a sparse table.
    The fix: every optional/suffixed column uses ``column_ifexists("name", "")``
    so an absent column yields an empty string instead of a query failure.
    Envelope columns (TimeGenerated, ResourceId, OperationName, Category) are
    always present and do NOT need column_ifexists.
"""
from __future__ import annotations

from datetime import datetime

# ---------------------------------------------------------------------------
# KQL templates
# ---------------------------------------------------------------------------

# Full field set for resource-specific App Gateway table.
# We select all WAF-relevant columns (no lossy projection — §3 critique #1).
_KQL_AGW_RESOURCE = """\
AGWFirewallLogs
| where TimeGenerated > datetime({since}) and TimeGenerated <= datetime({until})
| project TimeGenerated, ResourceId=_ResourceId, OperationName,
          InstanceId, ClientIp, RequestUri, RuleSetType, RuleSetVersion,
          RuleId, RuleGroup, Message, Action, Site,
          Details_Message=Details.Message, Details_Data=Details.Data,
          Details_File=Details.File, Details_Line=Details.Line,
          Hostname, TransactionId, PolicyId, PolicyScope, PolicyScopeName
| order by TimeGenerated asc
"""

# Full field set for resource-specific Front Door table.
_KQL_FD_RESOURCE = """\
AzureFrontDoorWebApplicationFirewallLog
| where TimeGenerated > datetime({since}) and TimeGenerated <= datetime({until})
| project TimeGenerated, ResourceId=_ResourceId, OperationName,
          ClientIP, ClientPort, SocketIP, RequestUri, RuleName,
          Policy, PolicyMode, Host, TrackingReference,
          Details_Matches=Details.Matches, Action
| order by TimeGenerated asc
"""

# AzureDiagnostics regime — suffixed column names with column_ifexists guards.
#
# Every optional/suffixed column uses column_ifexists("real_name", "") so that a
# sparse AzureDiagnostics table (where a column has never been populated) yields an
# empty string instead of a SEM0100 "Failed to resolve scalar expression" error.
# Envelope columns (TimeGenerated, ResourceId, OperationName, Category) are always
# present and do not need column_ifexists guards.
#
# Real column names verified against a live App Gateway WAF workspace (issue #142):
#   "Message"        — the rule message (capital, no _s suffix; NOT message_s).
#   "transactionId_g" — transaction GUID (_g suffix, NOT _s).
#   "site_s"         — NOT emitted by real App Gateway WAF workspaces; omitted.
#
# The aliased output names (right-hand side of "alias = column_ifexists(...)") match
# the keys expected by _DIAG_SUFFIX_MAP in _columns.py.
_KQL_AZURE_DIAG_APP_GW = """\
AzureDiagnostics
| where TimeGenerated > datetime({since}) and TimeGenerated <= datetime({until})
| where Category == "ApplicationGatewayFirewallLog"
| project TimeGenerated, ResourceId, OperationName,
          instanceId_s = column_ifexists("instanceId_s", ""),
          clientIp_s = column_ifexists("clientIp_s", ""),
          requestUri_s = column_ifexists("requestUri_s", ""),
          ruleSetType_s = column_ifexists("ruleSetType_s", ""),
          ruleSetVersion_s = column_ifexists("ruleSetVersion_s", ""),
          ruleId_s = column_ifexists("ruleId_s", ""),
          ruleGroup_s = column_ifexists("ruleGroup_s", ""),
          message_s = column_ifexists("Message", ""),
          action_s = column_ifexists("action_s", ""),
          details_message_s = column_ifexists("details_message_s", ""),
          details_data_s = column_ifexists("details_data_s", ""),
          details_file_s = column_ifexists("details_file_s", ""),
          details_line_s = column_ifexists("details_line_s", ""),
          hostname_s = column_ifexists("hostname_s", ""),
          transactionId_s = column_ifexists("transactionId_g", ""),
          policyId_s = column_ifexists("policyId_s", ""),
          policyScope_s = column_ifexists("policyScope_s", ""),
          policyScopeName_s = column_ifexists("policyScopeName_s", "")
| order by TimeGenerated asc
"""

_KQL_AZURE_DIAG_FRONT_DOOR = """\
AzureDiagnostics
| where TimeGenerated > datetime({since}) and TimeGenerated <= datetime({until})
| where Category has "WebApplicationFirewallLog"
| project TimeGenerated, ResourceId, OperationName,
          clientIP_s = column_ifexists("clientIP_s", ""),
          clientPort_d = column_ifexists("clientPort_d", ""),
          socketIP_s = column_ifexists("socketIP_s", ""),
          requestUri_s = column_ifexists("requestUri_s", ""),
          ruleName_s = column_ifexists("ruleName_s", ""),
          policy_s = column_ifexists("policy_s", ""),
          policyMode_s = column_ifexists("policyMode_s", ""),
          host_s = column_ifexists("host_s", ""),
          trackingReference_s = column_ifexists("trackingReference_s", ""),
          action_s = column_ifexists("action_s", ""),
          details_matches_s = column_ifexists("details_matches_s", "")
| order by TimeGenerated asc
"""

_KQL_AZURE_DIAG_BOTH = """\
AzureDiagnostics
| where TimeGenerated > datetime({since}) and TimeGenerated <= datetime({until})
| where Category has "FirewallLog"
| project TimeGenerated, ResourceId, OperationName, Category,
          instanceId_s = column_ifexists("instanceId_s", ""),
          clientIp_s = column_ifexists("clientIp_s", ""),
          clientIP_s = column_ifexists("clientIP_s", ""),
          clientPort_d = column_ifexists("clientPort_d", ""),
          socketIP_s = column_ifexists("socketIP_s", ""),
          requestUri_s = column_ifexists("requestUri_s", ""),
          ruleSetType_s = column_ifexists("ruleSetType_s", ""),
          ruleSetVersion_s = column_ifexists("ruleSetVersion_s", ""),
          ruleId_s = column_ifexists("ruleId_s", ""),
          ruleGroup_s = column_ifexists("ruleGroup_s", ""),
          ruleName_s = column_ifexists("ruleName_s", ""),
          message_s = column_ifexists("Message", ""),
          action_s = column_ifexists("action_s", ""),
          details_message_s = column_ifexists("details_message_s", ""),
          details_data_s = column_ifexists("details_data_s", ""),
          details_file_s = column_ifexists("details_file_s", ""),
          details_line_s = column_ifexists("details_line_s", ""),
          hostname_s = column_ifexists("hostname_s", ""),
          transactionId_s = column_ifexists("transactionId_g", ""),
          policyId_s = column_ifexists("policyId_s", ""),
          policyScope_s = column_ifexists("policyScope_s", ""),
          policyScopeName_s = column_ifexists("policyScopeName_s", ""),
          policy_s = column_ifexists("policy_s", ""),
          policyMode_s = column_ifexists("policyMode_s", ""),
          host_s = column_ifexists("host_s", ""),
          trackingReference_s = column_ifexists("trackingReference_s", ""),
          details_matches_s = column_ifexists("details_matches_s", "")
| order by TimeGenerated asc
"""


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_kql(
    product: str,
    table_regime: str,
    since_dt: datetime,
    until_dt: datetime,
) -> list[str]:
    """Return a list of KQL query strings for the given product and table regime.

    Returns multiple queries when ``product == "both"`` and
    ``table_regime == "resource_specific"`` (one query per table).
    Returns a single query otherwise.

    Time placeholders are rendered in ISO format; KQL ``datetime()`` accepts
    ISO 8601 strings.
    """
    since_s = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    until_s = until_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    params = {"since": since_s, "until": until_s}

    if table_regime == "resource_specific":
        if product == "app_gateway":
            return [_KQL_AGW_RESOURCE.format(**params)]
        if product == "front_door":
            return [_KQL_FD_RESOURCE.format(**params)]
        # both
        return [
            _KQL_AGW_RESOURCE.format(**params),
            _KQL_FD_RESOURCE.format(**params),
        ]
    else:  # azure_diagnostics
        if product == "app_gateway":
            return [_KQL_AZURE_DIAG_APP_GW.format(**params)]
        if product == "front_door":
            return [_KQL_AZURE_DIAG_FRONT_DOOR.format(**params)]
        # both
        return [_KQL_AZURE_DIAG_BOTH.format(**params)]
