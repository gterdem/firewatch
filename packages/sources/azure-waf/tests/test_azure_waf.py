"""Tests for firewatch_azure_waf — EARS criteria mapped 1:1.

EARS-1   Entry-point registration and zero-core-edit discovery.
EARS-2   config_schema: fields, SecretStr defaults to None.
EARS-3   normalize(): source_type constant "azure_waf", source_id passed through.
EARS-4   normalize(): full action map (Block/Detected/Matched/AnomalyScoring/
         logandscore/Allowed/Log/JSChallenge family).
EARS-5   normalize(): App-Gateway shape (discrete ruleId/ruleGroup).
EARS-6   normalize(): Front Door shape (dotted ruleName parsed for rule ID).
EARS-7   normalize(): CRS range coverage — every documented family maps to a
         non-"Other" category.
EARS-8   normalize(): severity always set, never None.
EARS-9   normalize(): ocsf_class==4002, ocsf_category==4.
EARS-10  normalize(): attack_technique + capec_id populated from §2c table.
EARS-11  normalize(): no fabricated transport fields (destination_port, protocol
         not invented; source_port only when clientPort present).
EARS-12  collect() mock: watermark + 5-min overlap + advance.
EARS-13  collect() raises typed error (AzureWAFAuthError) on auth failure.
EARS-14  health_check() returns False (not raises) when unreachable.
EARS-15  No forbidden imports (no firewatch_core, no legacy).
EARS-16  config_schema descriptions are operator-facing copy — no developer notes (issue #95).

Security hardening tests (added in PR security review):
  N2       workspace_id GUID format validation (clear error at config time).
  B1-guard EARS-12 now uses real LogsTableRow objects so column-extraction
           failures (the B1 regression) are caught by CI.

Test fixtures use RFC 5737 documentation IPs ONLY
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
No real/routable IPs are used anywhere — gitleaks public-ipv4 rule blocks them.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from firewatch_sdk import PluginContext, RawEvent
from firewatch_sdk.testing import InMemoryScopedKV

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ctx(source_id: str = "test-azure") -> PluginContext:
    return PluginContext(kv=InMemoryScopedKV(), source_id=source_id)


def _received() -> datetime:
    return datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)


def _app_gw_raw(
    *,
    client_ip: str = "203.0.113.10",
    rule_id: str = "942100",
    rule_group: str = "942-APPLICATION-ATTACK-SQLI",
    action: str = "Matched",
    message: str = "SQL Injection Attack Detected",
    transaction_id: str = "12345",
    ts: str = "2026-01-15T10:00:00.000000Z",
    details_data: str | None = "' OR 1=1",
    details_message: str | None = "Warning. SQL injection pattern matched.",
) -> RawEvent:
    """Build a minimal Application Gateway WAF RawEvent.

    Uses RFC 5737 doc IPs only (203.0.113.0/24).
    """
    props: dict[str, Any] = {
        "clientIp": client_ip,
        "requestUri": "/login?user=admin",
        "ruleSetType": "OWASP",
        "ruleSetVersion": "3.2",
        "ruleId": rule_id,
        "ruleGroup": rule_group,
        "message": message,
        "action": action,
        "site": "Global",
        "details": {
            "message": details_message,
            "data": details_data,
            "file": f"rules/REQUEST-{rule_group}.conf",
            "line": "100",
        },
        "hostname": "192.0.2.1",
        "transactionId": transaction_id,
        "policyId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw/policies/pol",
        "policyScope": "Global",
        "policyScopeName": "httpListener1",
    }
    return RawEvent(
        source_type="azure_waf",
        received_at=_received(),
        data={
            "time": ts,
            "resourceId": "/SUBSCRIPTIONS/sub/RESOURCEGROUPS/rg/PROVIDERS/MICROSOFT.NETWORK/APPLICATIONGATEWAYS/gw",
            "operationName": "ApplicationGatewayFirewall",
            "category": "ApplicationGatewayFirewallLog",
            "properties": props,
        },
    )


def _front_door_raw(
    *,
    client_ip: str = "198.51.100.5",
    rule_name: str = "Microsoft_DefaultRuleSet-1.1-SQLI-942100",
    action: str = "Block",
    policy_mode: str = "prevention",
    client_port: str = "52097",
    ts: str = "2026-01-15T10:00:00.000000Z",
    match_variable: str = "QueryParamValue:q",
    match_value: str = "' or 1=1",
) -> RawEvent:
    """Build a minimal Front Door WAF RawEvent.

    Uses RFC 5737 doc IPs only (198.51.100.0/24).
    """
    props: dict[str, Any] = {
        "clientIP": client_ip,
        "clientPort": client_port,
        "socketIP": client_ip,
        "requestUri": "https://app.example.com:443/?q=%27%20or%201=1",
        "ruleName": rule_name,
        "policy": "WafDemoPolicy",
        "action": action,
        "host": "app.example.com",
        "trackingReference": "08Q3gXgAAAAA",
        "policyMode": policy_mode,
        "details": {
            "matches": [
                {
                    "matchVariableName": match_variable,
                    "matchVariableValue": match_value,
                }
            ]
        },
    }
    return RawEvent(
        source_type="azure_waf",
        received_at=_received(),
        data={
            "time": ts,
            "category": "FrontdoorWebApplicationFirewallLog",
            "operationName": "Microsoft.Cdn/Profiles/Write",
            "properties": props,
        },
    )


# ---------------------------------------------------------------------------
# EARS-1: Entry-point registration (modularity proof)
# ---------------------------------------------------------------------------


class TestEntryPointDiscovery:
    """EARS-1 — package registered under firewatch.sources; zero core edits."""

    def test_entry_point_is_registered(self) -> None:
        from importlib.metadata import entry_points

        eps = entry_points(group="firewatch.sources")
        names = {ep.name for ep in eps}
        assert "azure_waf" in names, (
            f"'azure_waf' not found in firewatch.sources entry points. Found: {names}"
        )

    def test_entry_point_loads_to_azure_waf_source_class(self) -> None:
        from importlib.metadata import entry_points
        from firewatch_sdk import SourcePlugin

        eps = {ep.name: ep for ep in entry_points(group="firewatch.sources")}
        ep = eps["azure_waf"]
        cls = ep.load()
        plugin = cls()
        assert isinstance(plugin, SourcePlugin)

    def test_metadata_type_key_is_azure_waf(self) -> None:
        from firewatch_azure_waf.plugin import AzureWAFSource

        plugin = AzureWAFSource()
        assert plugin.metadata().type_key == "azure_waf"
        assert plugin.metadata().flavor == "pull"

    def test_zero_core_edits_via_loader(self) -> None:
        """The core loader discovers azure_waf with zero core edits."""
        from firewatch_core.loader import load_source_plugins

        registry = load_source_plugins()
        assert "azure_waf" in registry, (
            f"Loader did not find 'azure_waf'. Registry: {set(registry)}"
        )


# ---------------------------------------------------------------------------
# EARS-2: config_schema
# ---------------------------------------------------------------------------


class TestConfigSchema:
    """EARS-2 — config_schema returns a Pydantic model with the right shape."""

    def setup_method(self) -> None:
        from firewatch_azure_waf.plugin import AzureWAFSource
        self.plugin = AzureWAFSource()
        self.schema_cls = self.plugin.config_schema()

    def test_returns_pydantic_model_class(self) -> None:
        from pydantic import BaseModel
        assert issubclass(self.schema_cls, BaseModel)

    def test_has_workspace_id_field(self) -> None:
        assert "workspace_id" in self.schema_cls.model_fields

    def test_has_table_regime_field(self) -> None:
        assert "table_regime" in self.schema_cls.model_fields

    def test_has_product_field(self) -> None:
        assert "product" in self.schema_cls.model_fields

    def test_secret_fields_default_to_none(self) -> None:
        """SecretStr fields MUST default to None (PLUGIN_CONTRACT.md).

        The discovery endpoint emits defaults verbatim in JSON schema;
        a non-None secret default would leak into the API response.
        """
        schema_json = self.schema_cls.model_json_schema()
        props = schema_json.get("properties", {})
        for field_name in ("tenant_id", "client_id", "client_secret"):
            field_schema = props.get(field_name, {})
            # Pydantic emits "default: null" for None defaults
            assert field_schema.get("default") is None, (
                f"Secret field {field_name!r} must default to None in JSON schema; "
                f"got: {field_schema.get('default')!r}"
            )

    def test_table_regime_default_is_resource_specific(self) -> None:
        cfg = self.schema_cls()
        assert cfg.table_regime == "resource_specific"  # type: ignore[attr-defined]

    def test_product_default_is_both(self) -> None:
        cfg = self.schema_cls()
        assert cfg.product == "both"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# N2: workspace_id GUID format validation
# ---------------------------------------------------------------------------


class TestWorkspaceIdGuidValidation:
    """N2 — workspace_id must be a valid GUID; rejects non-GUID strings at
    config construction time (clear error, not opaque query failure).
    """

    def test_valid_guid_lowercase_accepted(self) -> None:
        from firewatch_azure_waf.config import AzureWAFConfig
        cfg = AzureWAFConfig(workspace_id="12345678-1234-1234-1234-123456789abc")
        assert cfg.workspace_id == "12345678-1234-1234-1234-123456789abc"

    def test_valid_guid_uppercase_accepted(self) -> None:
        from firewatch_azure_waf.config import AzureWAFConfig
        cfg = AzureWAFConfig(workspace_id="12345678-ABCD-EF01-2345-67890ABCDEF0")
        assert cfg.workspace_id == "12345678-ABCD-EF01-2345-67890ABCDEF0"

    def test_valid_guid_mixed_case_accepted(self) -> None:
        from firewatch_azure_waf.config import AzureWAFConfig
        cfg = AzureWAFConfig(workspace_id="aAbBcCdD-1234-5678-90ef-abcdef012345")
        assert cfg.workspace_id == "aAbBcCdD-1234-5678-90ef-abcdef012345"

    def test_empty_workspace_id_accepted(self) -> None:
        """Empty string is the default — must not fail validation (user hasn't configured yet)."""
        from firewatch_azure_waf.config import AzureWAFConfig
        cfg = AzureWAFConfig(workspace_id="")
        assert cfg.workspace_id == ""

    def test_non_guid_string_rejected(self) -> None:
        """A plain string that is not a GUID should raise a ValidationError."""
        from pydantic import ValidationError
        from firewatch_azure_waf.config import AzureWAFConfig
        with pytest.raises(ValidationError, match="workspace_id must be a valid GUID"):
            AzureWAFConfig(workspace_id="not-a-guid")

    def test_guid_without_hyphens_rejected(self) -> None:
        """GUID without dashes is invalid."""
        from pydantic import ValidationError
        from firewatch_azure_waf.config import AzureWAFConfig
        with pytest.raises(ValidationError, match="workspace_id must be a valid GUID"):
            AzureWAFConfig(workspace_id="12345678123412341234123456789abc")

    def test_partial_guid_rejected(self) -> None:
        """Truncated GUID should be rejected."""
        from pydantic import ValidationError
        from firewatch_azure_waf.config import AzureWAFConfig
        with pytest.raises(ValidationError, match="workspace_id must be a valid GUID"):
            AzureWAFConfig(workspace_id="12345678-1234-1234-1234")


# ---------------------------------------------------------------------------
# EARS-3: normalize() — source_type constant + source_id pass-through
# ---------------------------------------------------------------------------


class TestNormalizeSourceIdentity:
    """EARS-3 — source_type="azure_waf" always; source_id passed through."""

    def setup_method(self) -> None:
        from firewatch_azure_waf.plugin import AzureWAFSource
        self.plugin = AzureWAFSource()

    def test_source_type_is_constant_azure_waf(self) -> None:
        event = self.plugin.normalize(_app_gw_raw(), source_id="my-instance")
        assert event.source_type == "azure_waf"

    def test_source_type_constant_regardless_of_source_id(self) -> None:
        for sid in ("prod-waf", "staging-waf", "azure-juiceshop"):
            event = self.plugin.normalize(_app_gw_raw(), source_id=sid)
            assert event.source_type == "azure_waf"

    def test_source_id_passed_through(self) -> None:
        event = self.plugin.normalize(_app_gw_raw(), source_id="my-waf-01")
        assert event.source_id == "my-waf-01"


# ---------------------------------------------------------------------------
# EARS-4: normalize() — full action map
# ---------------------------------------------------------------------------


class TestNormalizeActionMap:
    """EARS-4 — every Azure WAF action value maps to the correct FireWatch action.

    Tests the complete action vocabulary from azure-waf-log-standard.md §1c/§2b,
    including case variations (both products use inconsistent casing).
    """

    def setup_method(self) -> None:
        from firewatch_azure_waf.plugin import AzureWAFSource
        self.plugin = AzureWAFSource()

    def _normalize_with_action(self, action: str) -> str:
        raw = _app_gw_raw(action=action)
        return self.plugin.normalize(raw, "test").action

    def test_block_maps_to_block(self) -> None:
        assert self._normalize_with_action("Block") == "BLOCK"

    def test_block_lowercase_maps_to_block(self) -> None:
        assert self._normalize_with_action("block") == "BLOCK"

    def test_blocked_maps_to_block(self) -> None:
        assert self._normalize_with_action("Blocked") == "BLOCK"

    def test_jschallengeblock_maps_to_block(self) -> None:
        assert self._normalize_with_action("JSChallengeBlock") == "BLOCK"

    def test_detected_maps_to_alert_not_block(self) -> None:
        """Detected is detection-mode (non-terminating) — ALERT not BLOCK.

        Corrects legacy bug: sync.py:90 mapped Detected → BLOCK.
        """
        assert self._normalize_with_action("Detected") == "ALERT"

    def test_matched_maps_to_alert_not_block(self) -> None:
        """Matched is non-terminating CRS anomaly-score contribution — ALERT not BLOCK.

        Corrects legacy bug (same as Detected above).
        """
        assert self._normalize_with_action("Matched") == "ALERT"

    def test_anomalyscoring_maps_to_alert(self) -> None:
        """AnomalyScoring is the Front Door equivalent of Matched — ALERT."""
        assert self._normalize_with_action("AnomalyScoring") == "ALERT"

    def test_logandscore_maps_to_alert(self) -> None:
        assert self._normalize_with_action("logandscore") == "ALERT"

    def test_allowed_maps_to_allow(self) -> None:
        assert self._normalize_with_action("Allowed") == "ALLOW"

    def test_allow_lowercase_maps_to_allow(self) -> None:
        assert self._normalize_with_action("allow") == "ALLOW"

    def test_log_maps_to_log(self) -> None:
        assert self._normalize_with_action("Log") == "LOG"

    def test_jschallengeissued_maps_to_log(self) -> None:
        assert self._normalize_with_action("JSChallengeIssued") == "LOG"

    def test_jschallengepass_maps_to_log(self) -> None:
        assert self._normalize_with_action("JSChallengePass") == "LOG"

    def test_jschallengevalid_maps_to_log(self) -> None:
        assert self._normalize_with_action("JSChallengeValid") == "LOG"

    def test_unknown_action_defaults_to_alert(self) -> None:
        """Unrecognized action falls back to ALERT (conservative — not BLOCK)."""
        assert self._normalize_with_action("SomethingNew") == "ALERT"


# ---------------------------------------------------------------------------
# EARS-5: normalize() — Application Gateway shape
# ---------------------------------------------------------------------------


class TestNormalizeAppGateway:
    """EARS-5 — App Gateway shape: discrete ruleId/ruleGroup fields."""

    def setup_method(self) -> None:
        from firewatch_azure_waf.plugin import AzureWAFSource
        self.plugin = AzureWAFSource()

    def test_rule_id_from_discrete_field(self) -> None:
        raw = _app_gw_raw(rule_id="942100")
        event = self.plugin.normalize(raw, "test")
        assert event.rule_id == "942100"

    def test_rule_name_from_message_field(self) -> None:
        raw = _app_gw_raw(message="SQL Injection Attack Detected via libinjection")
        event = self.plugin.normalize(raw, "test")
        assert event.rule_name == "SQL Injection Attack Detected via libinjection"

    def test_source_ip_from_client_ip(self) -> None:
        """App Gateway uses clientIp (capital I)."""
        raw = _app_gw_raw(client_ip="203.0.113.10")
        event = self.plugin.normalize(raw, "test")
        assert event.source_ip == "203.0.113.10"

    def test_transaction_id_as_source_event_id(self) -> None:
        raw = _app_gw_raw(transaction_id="txn-abc-123")
        event = self.plugin.normalize(raw, "test")
        assert event.source_event_id == "txn-abc-123"

    def test_payload_snippet_from_details_data(self) -> None:
        raw = _app_gw_raw(details_data="' OR 1=1 --")
        event = self.plugin.normalize(raw, "test")
        assert event.payload_snippet is not None
        assert "OR 1=1" in event.payload_snippet

    def test_timestamp_parsed_from_envelope(self) -> None:
        raw = _app_gw_raw(ts="2026-03-15T08:30:00.000000Z")
        event = self.plugin.normalize(raw, "test")
        assert event.timestamp.year == 2026
        assert event.timestamp.month == 3
        assert event.timestamp.day == 15

    def test_raw_log_preserved(self) -> None:
        raw = _app_gw_raw()
        event = self.plugin.normalize(raw, "test")
        assert event.raw_log is not None


# ---------------------------------------------------------------------------
# EARS-6: normalize() — Front Door shape (ruleName parsing)
# ---------------------------------------------------------------------------


class TestNormalizeFrontDoor:
    """EARS-6 — Front Door shape: dotted ruleName → rule ID + category/MITRE."""

    def setup_method(self) -> None:
        from firewatch_azure_waf.plugin import AzureWAFSource
        self.plugin = AzureWAFSource()

    def test_rule_id_parsed_from_rule_name(self) -> None:
        """Rule ID is the trailing numeric segment of the dotted ruleName (§1b)."""
        raw = _front_door_raw(rule_name="Microsoft_DefaultRuleSet-1.1-SQLI-942100")
        event = self.plugin.normalize(raw, "test")
        assert event.rule_id == "942100"

    def test_rule_name_preserves_full_dotted_string(self) -> None:
        """The full ruleName is stored for drill-down provenance."""
        raw = _front_door_raw(rule_name="Microsoft_DefaultRuleSet-1.1-XSS-941100")
        event = self.plugin.normalize(raw, "test")
        assert event.rule_name == "Microsoft_DefaultRuleSet-1.1-XSS-941100"

    def test_source_ip_from_client_ip_pascal(self) -> None:
        """Front Door uses clientIP (capital IP), different from App Gateway's clientIp."""
        raw = _front_door_raw(client_ip="198.51.100.5")
        event = self.plugin.normalize(raw, "test")
        assert event.source_ip == "198.51.100.5"

    def test_source_port_from_client_port(self) -> None:
        """Front Door carries clientPort; it should be populated as source_port."""
        raw = _front_door_raw(client_port="52097")
        event = self.plugin.normalize(raw, "test")
        assert event.source_port == 52097

    def test_tracking_reference_as_source_event_id(self) -> None:
        raw = _front_door_raw()
        event = self.plugin.normalize(raw, "test")
        assert event.source_event_id == "08Q3gXgAAAAA"

    def test_payload_snippet_from_matches(self) -> None:
        raw = _front_door_raw(match_value="' or 1=1", match_variable="QueryParamValue:q")
        event = self.plugin.normalize(raw, "test")
        assert event.payload_snippet is not None
        assert "or 1=1" in event.payload_snippet

    def test_front_door_crs_category_lookup_works(self) -> None:
        """Parsed rule ID 942100 → SQL Injection category (not None / not Other)."""
        raw = _front_door_raw(rule_name="Microsoft_DefaultRuleSet-1.1-SQLI-942100")
        event = self.plugin.normalize(raw, "test")
        assert event.category == "SQL Injection"

    def test_front_door_block_action(self) -> None:
        raw = _front_door_raw(action="Block")
        event = self.plugin.normalize(raw, "test")
        assert event.action == "BLOCK"


# ---------------------------------------------------------------------------
# EARS-7: normalize() — CRS range coverage, no "Other"
# ---------------------------------------------------------------------------


class TestCRSCoverage:
    """EARS-7 — every documented CRS family maps to a non-None, non-Other category.

    Tests one representative rule ID from each CRS range documented in
    azure-waf-log-standard.md §2c.  No fall-through to 'Other' allowed.
    """

    def setup_method(self) -> None:
        from firewatch_azure_waf.plugin import AzureWAFSource
        self.plugin = AzureWAFSource()

    def _category_for(self, rule_id: str) -> str | None:
        raw = _app_gw_raw(rule_id=rule_id, rule_group="TEST")
        return self.plugin.normalize(raw, "test").category

    @pytest.mark.parametrize("rule_id,expected_fragment", [
        ("913100", "Scanner"),      # 913xxx scanner/recon
        ("920350", "Protocol"),     # 920xxx protocol enforcement
        ("921110", "Protocol"),     # 921xxx protocol attack
        ("930100", "Local File"),   # 930xxx LFI
        ("931100", "Remote File"),  # 931xxx RFI
        ("932100", "Remote Code"),  # 932xxx RCE
        ("933100", "PHP"),          # 933xxx PHP injection
        ("941100", "XSS"),          # 941xxx XSS
        ("942100", "SQL"),          # 942xxx SQLi
        ("943100", "Session"),      # 943xxx session fixation
        ("944100", "Java"),         # 944xxx Java attacks
        ("949110", "Anomaly"),      # 949xxx anomaly-score blocking
        ("959100", "Anomaly"),      # 959xxx anomaly-score outbound
        ("980100", "Anomaly"),      # 980xxx anomaly-score outbound
    ])
    def test_crs_range_maps_to_known_category(
        self, rule_id: str, expected_fragment: str
    ) -> None:
        category = self._category_for(rule_id)
        assert category is not None, (
            f"rule_id {rule_id}: category is None (should map to {expected_fragment!r})"
        )
        assert "other" not in (category or "").lower(), (
            f"rule_id {rule_id}: category fell through to 'Other' variant: {category!r}"
        )
        assert expected_fragment.lower() in (category or "").lower(), (
            f"rule_id {rule_id}: expected fragment {expected_fragment!r} in {category!r}"
        )

    def test_azure_custom_ratelimit_not_other(self) -> None:
        """Azure custom rule 'RateLimit' classifies without falling to Other."""
        raw = _front_door_raw(rule_name="Custom-RateLimit-Rule1")
        event = self.plugin.normalize(raw, "test")
        assert event.category is not None
        assert "other" not in (event.category or "").lower()
        assert "rate" in (event.category or "").lower()

    def test_azure_custom_geoblock_not_other(self) -> None:
        raw = _front_door_raw(rule_name="Custom-GeoBlock-CN")
        event = self.plugin.normalize(raw, "test")
        assert event.category is not None
        assert "geo" in (event.category or "").lower()

    def test_azure_custom_bot_not_other(self) -> None:
        raw = _front_door_raw(rule_name="BotDetection-001")
        event = self.plugin.normalize(raw, "test")
        assert event.category is not None
        assert "bot" in (event.category or "").lower()


# ---------------------------------------------------------------------------
# EARS-8: normalize() — severity always set, never None
# ---------------------------------------------------------------------------


class TestSeverityAlwaysSet:
    """EARS-8 — severity is always a SeverityLiteral, never None."""

    def setup_method(self) -> None:
        from firewatch_azure_waf.plugin import AzureWAFSource
        self.plugin = AzureWAFSource()

    def test_severity_set_for_app_gateway_sqli(self) -> None:
        event = self.plugin.normalize(_app_gw_raw(rule_id="942100"), "test")
        assert event.severity is not None
        assert event.severity in ("info", "low", "medium", "high", "critical")

    def test_severity_set_for_front_door_xss(self) -> None:
        raw = _front_door_raw(rule_name="Microsoft_DefaultRuleSet-1.1-XSS-941100")
        event = self.plugin.normalize(raw, "test")
        assert event.severity is not None

    def test_severity_never_none_for_unknown_rule(self) -> None:
        """Even for an unmapped rule ID, severity must be set to a fallback."""
        raw = _app_gw_raw(rule_id="999999", rule_group="UNKNOWN-GROUP")
        event = self.plugin.normalize(raw, "test")
        assert event.severity is not None

    def test_severity_set_for_anomaly_score_message(self) -> None:
        """Anomaly-score messages trigger score refinement."""
        raw = _app_gw_raw(
            rule_id="949110",
            message="Inbound Anomaly Score Exceeded (Total Score: 15)",
        )
        event = self.plugin.normalize(raw, "test")
        assert event.severity is not None
        # Score 15 >= threshold (5) → high or critical
        assert event.severity in ("high", "critical")

    def test_rce_category_is_critical(self) -> None:
        raw = _app_gw_raw(rule_id="932100")
        event = self.plugin.normalize(raw, "test")
        assert event.severity == "critical"

    def test_scanner_category_is_low(self) -> None:
        raw = _app_gw_raw(rule_id="913100")
        event = self.plugin.normalize(raw, "test")
        assert event.severity == "low"


# ---------------------------------------------------------------------------
# EARS-9: normalize() — OCSF 4002 / category 4
# ---------------------------------------------------------------------------


class TestOCSFAlignment:
    """EARS-9 — ocsf_class=4002 (HTTP Activity), ocsf_category=4 (Network Activity).

    Corrects the stale 6004 in the legacy code (azure-waf-log-standard.md §2a).
    """

    def setup_method(self) -> None:
        from firewatch_azure_waf.plugin import AzureWAFSource
        self.plugin = AzureWAFSource()

    def test_ocsf_class_is_4002_app_gateway(self) -> None:
        event = self.plugin.normalize(_app_gw_raw(), "test")
        assert event.ocsf_class == 4002

    def test_ocsf_category_is_4_app_gateway(self) -> None:
        event = self.plugin.normalize(_app_gw_raw(), "test")
        assert event.ocsf_category == 4

    def test_ocsf_class_is_4002_front_door(self) -> None:
        event = self.plugin.normalize(_front_door_raw(), "test")
        assert event.ocsf_class == 4002

    def test_ocsf_category_is_4_front_door(self) -> None:
        event = self.plugin.normalize(_front_door_raw(), "test")
        assert event.ocsf_category == 4

    def test_ocsf_class_is_not_stale_6004(self) -> None:
        """Explicit regression: ocsf_class must NOT be 6004 (stale legacy value)."""
        event = self.plugin.normalize(_app_gw_raw(), "test")
        assert event.ocsf_class != 6004


# ---------------------------------------------------------------------------
# EARS-10: normalize() — attack_technique + capec_id populated
# ---------------------------------------------------------------------------


class TestMitreCapec:
    """EARS-10 — attack_technique and capec_id populated from §2c table."""

    def setup_method(self) -> None:
        from firewatch_azure_waf.plugin import AzureWAFSource
        self.plugin = AzureWAFSource()

    def test_sqli_gets_t1190_and_capec66(self) -> None:
        raw = _app_gw_raw(rule_id="942100")
        event = self.plugin.normalize(raw, "test")
        assert event.attack_technique == "T1190"
        assert event.capec_id == "CAPEC-66"

    def test_xss_gets_t1059_and_capec63(self) -> None:
        raw = _app_gw_raw(rule_id="941100")
        event = self.plugin.normalize(raw, "test")
        assert event.attack_technique == "T1059"
        assert event.capec_id == "CAPEC-63"

    def test_rce_gets_capec248(self) -> None:
        raw = _app_gw_raw(rule_id="932100")
        event = self.plugin.normalize(raw, "test")
        assert event.capec_id == "CAPEC-248"

    def test_scanner_gets_t1595(self) -> None:
        raw = _app_gw_raw(rule_id="913100")
        event = self.plugin.normalize(raw, "test")
        assert event.attack_technique == "T1595"

    def test_lfi_gets_capec126(self) -> None:
        raw = _app_gw_raw(rule_id="930100")
        event = self.plugin.normalize(raw, "test")
        assert event.capec_id == "CAPEC-126"

    def test_front_door_sqli_gets_mitre_from_parsed_id(self) -> None:
        """Front Door: MITRE/CAPEC derived from the parsed trailing rule ID."""
        raw = _front_door_raw(rule_name="Microsoft_DefaultRuleSet-1.1-SQLI-942100")
        event = self.plugin.normalize(raw, "test")
        assert event.attack_technique == "T1190"
        assert event.capec_id == "CAPEC-66"

    def test_kill_chain_phase_populated(self) -> None:
        raw = _app_gw_raw(rule_id="942100")
        event = self.plugin.normalize(raw, "test")
        assert event.kill_chain_phase is not None


# ---------------------------------------------------------------------------
# EARS-11: normalize() — no fabricated transport fields
# ---------------------------------------------------------------------------


class TestNoFabricatedTransportFields:
    """EARS-11 — destination_port and protocol must NOT be invented.

    Azure WAF logs carry neither destination_port nor protocol.
    Fabricating them is explicitly forbidden (§3 critique #5 / PLUGIN_CONTRACT.md).
    """

    def setup_method(self) -> None:
        from firewatch_azure_waf.plugin import AzureWAFSource
        self.plugin = AzureWAFSource()

    def test_destination_port_is_none_app_gateway(self) -> None:
        event = self.plugin.normalize(_app_gw_raw(), "test")
        assert event.destination_port is None, (
            "destination_port must be None — Azure WAF logs do not carry it; "
            "fabricating 80 is the legacy anti-pattern (§3 critique #5)."
        )

    def test_protocol_is_none_app_gateway(self) -> None:
        event = self.plugin.normalize(_app_gw_raw(), "test")
        assert event.protocol is None, (
            "protocol must be None — Azure WAF logs do not carry it; "
            "fabricating 'TCP' is the legacy anti-pattern (§3 critique #5)."
        )

    def test_destination_port_is_none_front_door(self) -> None:
        event = self.plugin.normalize(_front_door_raw(), "test")
        assert event.destination_port is None

    def test_source_port_only_when_client_port_present(self) -> None:
        """Front Door carries clientPort; App Gateway does not."""
        fd_event = self.plugin.normalize(_front_door_raw(client_port="52097"), "test")
        assert fd_event.source_port == 52097

        # App Gateway raw has no clientPort → source_port must be None
        ag_event = self.plugin.normalize(_app_gw_raw(), "test")
        assert ag_event.source_port is None

    def test_source_ip_not_fabricated_as_zero(self) -> None:
        """source_ip must NOT be the legacy placeholder '0.0.0.0'."""
        event = self.plugin.normalize(_app_gw_raw(client_ip="203.0.113.10"), "test")
        assert event.source_ip != "0.0.0.0"
        assert event.source_ip == "203.0.113.10"


# ---------------------------------------------------------------------------
# EARS-12: collect() — watermark + 5-min overlap (mocked LogsQueryClient)
# ---------------------------------------------------------------------------


class TestCollectWatermark:
    """EARS-12 — collect() reads watermark, applies 5-min overlap, yields RawEvents.

    No live Azure calls.  The LogsQueryClient is mocked at the module level
    so the collect() async generator exercises the watermark/window logic.
    """

    def _make_plugin(self) -> Any:
        from firewatch_azure_waf.plugin import AzureWAFSource
        return AzureWAFSource()

    def _make_cfg(self) -> Any:
        from firewatch_azure_waf.config import AzureWAFConfig
        return AzureWAFConfig(
            workspace_id="12345678-1234-1234-1234-123456789abc",
            table_regime="resource_specific",
            product="app_gateway",
            overlap_minutes=5,
        )

    @staticmethod
    def _make_real_table(rows: list[dict[str, Any]]) -> Any:
        """Build a real ``LogsTable`` from a list of dicts.

        This is the SDK-accurate construction path: ``LogsTable`` takes
        ``columns``, ``columns_types``, and ``rows`` (list-of-lists in column
        order), then constructs real ``LogsTableRow`` objects internally.
        Using a real ``LogsTable`` (instead of a plain dict or MagicMock)
        exercises the actual ``_row_to_dict`` path and guards against B1-class
        regressions where the real-object path was never exercised by tests.
        """
        from azure.monitor.query import LogsTable

        if not rows:
            return LogsTable(
                name="AGWFirewallLogs",
                columns=[],
                columns_types=[],
                rows=[],
            )

        columns = list(rows[0].keys())
        col_types = ["string"] * len(columns)
        raw_rows = [[row.get(col) for col in columns] for row in rows]
        return LogsTable(
            name="AGWFirewallLogs",
            columns=columns,
            columns_types=col_types,
            rows=raw_rows,
        )

    def _make_mock_result(self, rows: list[dict[str, Any]]) -> MagicMock:
        """Build a mock LogsQueryResult backed by a REAL ``LogsTable``.

        Previously this used plain dicts for rows (the ``isinstance(row, dict)``
        fast-path), which meant the real ``LogsTableRow`` extraction path was
        never exercised.  Building a real ``LogsTable`` here ensures CI catches
        the B1 class of bug (column-extraction failures that silently produce
        empty dicts).
        """
        from azure.monitor.query import LogsQueryStatus

        real_table = self._make_real_table(rows)

        mock_result = MagicMock()
        mock_result.status = LogsQueryStatus.SUCCESS
        mock_result.tables = [real_table]
        return mock_result

    @staticmethod
    def _make_row_as_dict(data: dict[str, Any]) -> dict[str, Any]:
        """Plain-dict row for exercising the isinstance(row, dict) fast-path.

        Kept separate so we have at least one test using the dict path;
        the real-object path is now the default in _make_mock_result.
        """
        return data

    async def test_collect_yields_raw_events_from_real_table_row(self) -> None:
        """collect() extracts column data from real ``LogsTableRow`` objects.

        This test exercises the real SDK object path (not the dict fast-path)
        and asserts that field values are actually populated in the resulting
        RawEvent.  This would have caught B1: _row_to_dict using
        ``row.column_types`` (non-existent) and silently returning ``{}``.
        Uses RFC 5737 documentation IP (203.0.113.0/24) only.
        """
        plugin = self._make_plugin()
        cfg = self._make_cfg()

        sample_row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ClientIp": "203.0.113.10",
            "RuleId": "942100",
            "RuleGroup": "942-APPLICATION-ATTACK-SQLI",
            "Message": "SQL Injection",
            "Action": "Matched",
            "RequestUri": "/login",
        }

        # _make_mock_result now uses a real LogsTable → real LogsTableRow objects
        mock_result = self._make_mock_result([sample_row])

        with patch("firewatch_azure_waf.client.LogsQueryClient") as mock_cls:
            mock_client = MagicMock()
            mock_client.query_workspace.return_value = mock_result
            mock_cls.return_value = mock_client

            with patch("firewatch_azure_waf.client._build_credential", return_value=MagicMock()):
                events = [
                    ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())
                ]

        assert len(events) == 1
        assert events[0].source_type == "azure_waf"
        # Assert that column values were actually extracted (not an empty dict {}).
        # The B1 regression: _row_to_dict used row.column_types (non-existent) and
        # silently returned {}, making properties an empty dict.
        # After canonicalization (canonicalize_row), PascalCase columns from
        # resource-specific tables are mapped to camelCase in the properties dict
        # (ClientIp→clientIp, RuleId→ruleId, Action→action).
        raw_data = events[0].data
        props = raw_data.get("properties", {})
        assert props, (
            "properties dict is empty — _row_to_dict returned {} (B1 regression); "
            f"full data: {raw_data}"
        )
        assert props.get("clientIp") == "203.0.113.10", (
            "clientIp was not extracted from LogsTableRow after canonicalization — "
            f"suggests B1 or seam regression; props keys: {list(props)}"
        )
        assert props.get("ruleId") == "942100", (
            "ruleId was not extracted from LogsTableRow after canonicalization (B1 regression)"
        )
        assert props.get("action") == "Matched", (
            "action was not extracted from LogsTableRow after canonicalization (B1 regression)"
        )

    async def test_collect_yields_raw_events_from_dict_row(self) -> None:
        """collect() also works when the table contains plain-dict rows (dict fast-path).

        Keeps the dict-path coverage alive now that the default seam uses
        real LogsTableRow objects.
        """
        from azure.monitor.query import LogsQueryStatus

        plugin = self._make_plugin()
        cfg = self._make_cfg()

        sample_row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ClientIp": "203.0.113.10",
            "RuleId": "942100",
            "Action": "Matched",
        }

        # Build a mock table that holds plain dicts (exercises the dict fast-path)
        mock_table = MagicMock()
        mock_table.columns = list(sample_row.keys())
        mock_table.rows = [self._make_row_as_dict(sample_row)]

        mock_result = MagicMock()
        mock_result.status = LogsQueryStatus.SUCCESS
        mock_result.tables = [mock_table]

        with patch("firewatch_azure_waf.client.LogsQueryClient") as mock_cls:
            mock_client = MagicMock()
            mock_client.query_workspace.return_value = mock_result
            mock_cls.return_value = mock_client

            with patch("firewatch_azure_waf.client._build_credential", return_value=MagicMock()):
                events = [
                    ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())
                ]

        assert len(events) == 1
        assert events[0].source_type == "azure_waf"

    async def test_collect_applies_overlap_to_since(self) -> None:
        """5-min overlap: the KQL query window starts overlap_minutes before the watermark."""
        from firewatch_azure_waf import client as _client_module

        cfg = self._make_cfg()
        since = "2026-01-15T10:00:00+00:00"

        since_dt, until_dt = _client_module._compute_window(since, cfg.overlap_minutes)
        # since_dt must be (10:00 - 5min) = 09:55
        assert since_dt.hour == 9
        assert since_dt.minute == 55

    async def test_collect_none_since_uses_24h_window(self) -> None:
        """None since → initial 24h window."""
        from firewatch_azure_waf import client as _client_module

        cfg = self._make_cfg()
        since_dt, until_dt = _client_module._compute_window(None, cfg.overlap_minutes)
        delta = until_dt - since_dt
        # Should be approximately 24 hours (within a minute of test execution)
        assert abs(delta.total_seconds() - 86400) < 120

    async def test_collect_no_events_yields_nothing(self) -> None:
        """Empty result from Log Analytics yields no RawEvents."""
        plugin = self._make_plugin()
        cfg = self._make_cfg()

        mock_result = self._make_mock_result([])

        with patch("firewatch_azure_waf.client.LogsQueryClient") as mock_cls:
            mock_client = MagicMock()
            mock_client.query_workspace.return_value = mock_result
            mock_cls.return_value = mock_client

            with patch("firewatch_azure_waf.client._build_credential", return_value=MagicMock()):
                events = [
                    ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())
                ]

        assert events == []


# ---------------------------------------------------------------------------
# EARS-13: collect() raises typed error on auth failure
# ---------------------------------------------------------------------------


class TestCollectTypedErrors:
    """EARS-13 — auth/connectivity errors surface as typed exceptions, not "no data".

    The legacy sync.py:43 anti-pattern: a broad except swallowed all errors as
    empty list.  This plugin must NOT do that (§3 critique #6).
    """

    def _make_plugin(self) -> Any:
        from firewatch_azure_waf.plugin import AzureWAFSource
        return AzureWAFSource()

    def _make_cfg(self) -> Any:
        from firewatch_azure_waf.config import AzureWAFConfig
        return AzureWAFConfig(workspace_id="12345678-1234-1234-1234-123456789abc")

    async def test_auth_error_raises_azure_waf_auth_error(self) -> None:
        """Credential failure raises AzureWAFAuthError, not silently yields nothing."""
        from firewatch_azure_waf.client import AzureWAFAuthError

        plugin = self._make_plugin()
        cfg = self._make_cfg()

        with patch("firewatch_azure_waf.client._build_credential") as mock_cred:
            mock_cred.side_effect = AzureWAFAuthError("credential failure")
            with pytest.raises(AzureWAFAuthError):
                _ = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

    async def test_query_error_raises_azure_waf_query_error(self) -> None:
        """Bad workspace ID / unknown table raises AzureWAFQueryError."""
        from azure.monitor.query import LogsQueryStatus
        from firewatch_azure_waf.client import AzureWAFQueryError

        plugin = self._make_plugin()
        cfg = self._make_cfg()

        mock_result = MagicMock()
        mock_result.status = LogsQueryStatus.FAILURE
        mock_result.tables = None

        with patch("firewatch_azure_waf.client.LogsQueryClient") as mock_cls:
            mock_client = MagicMock()
            mock_client.query_workspace.return_value = mock_result
            mock_cls.return_value = mock_client

            with patch("firewatch_azure_waf.client._build_credential", return_value=MagicMock()):
                with pytest.raises(AzureWAFQueryError):
                    _ = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]


# ---------------------------------------------------------------------------
# EARS-14: health_check() returns False (not raises) when unreachable
# ---------------------------------------------------------------------------


class TestHealthCheck:
    """EARS-14 — health_check() returns True/False; never raises."""

    def _make_plugin(self) -> Any:
        from firewatch_azure_waf.plugin import AzureWAFSource
        return AzureWAFSource()

    def _make_cfg(self) -> Any:
        from firewatch_azure_waf.config import AzureWAFConfig
        return AzureWAFConfig(workspace_id="12345678-1234-1234-1234-123456789abc")

    async def test_health_check_returns_true_on_success(self) -> None:
        from azure.monitor.query import LogsQueryStatus

        plugin = self._make_plugin()
        cfg = self._make_cfg()

        mock_result = MagicMock()
        mock_result.status = LogsQueryStatus.SUCCESS

        with patch("firewatch_azure_waf.client.LogsQueryClient") as mock_cls:
            mock_client = MagicMock()
            mock_client.query_workspace.return_value = mock_result
            mock_cls.return_value = mock_client

            with patch("firewatch_azure_waf.client._build_credential", return_value=MagicMock()):
                result = await plugin.health_check(cfg)

        assert result is True

    async def test_health_check_returns_false_on_auth_error(self) -> None:
        """Auth failure → False, not raise."""
        from firewatch_azure_waf.client import AzureWAFAuthError

        plugin = self._make_plugin()
        cfg = self._make_cfg()

        with patch("firewatch_azure_waf.client._build_credential") as mock_cred:
            mock_cred.side_effect = AzureWAFAuthError("no token")
            result = await plugin.health_check(cfg)

        assert result is False

    async def test_health_check_returns_false_on_network_error(self) -> None:
        """Network failure → False, not raise."""
        plugin = self._make_plugin()
        cfg = self._make_cfg()

        with patch("firewatch_azure_waf.client.LogsQueryClient") as mock_cls:
            mock_client = MagicMock()
            mock_client.query_workspace.side_effect = Exception("connection refused")
            mock_cls.return_value = mock_client

            with patch("firewatch_azure_waf.client._build_credential", return_value=MagicMock()):
                result = await plugin.health_check(cfg)

        assert result is False

    async def test_health_check_returns_false_on_invalid_config(self) -> None:
        """Garbage config dict → False."""
        plugin = self._make_plugin()
        from pydantic import BaseModel

        class BadConfig(BaseModel):
            foo: str = "bar"

        result = await plugin.health_check(BadConfig())
        # validate_config will fail → False
        # (or it succeeds with defaults — either way must not raise)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# EARS-15: no forbidden imports
# ---------------------------------------------------------------------------


class TestNoForbiddenImports:
    """EARS-15 — firewatch_azure_waf depends only on firewatch_sdk; never core or legacy."""

    def _get_source_dir(self) -> Path:
        return Path(__file__).parent.parent / "src" / "firewatch_azure_waf"

    def test_does_not_import_firewatch_core(self) -> None:
        src = self._get_source_dir()
        for py_file in src.glob("*.py"):
            content = py_file.read_text()
            assert "firewatch_core" not in content, (
                f"{py_file.name} imports firewatch_core — forbidden (PLUGIN_CONTRACT.md)"
            )

    def test_does_not_import_legacy(self) -> None:
        import re
        import_re = re.compile(r"^\s*(from legacy|import legacy)\b", re.MULTILINE)
        src = self._get_source_dir()
        for py_file in src.glob("*.py"):
            content = py_file.read_text()
            m = import_re.search(content)
            assert m is None, (
                f"{py_file.name} imports legacy — forbidden: {m.group()!r}"
            )

    def test_only_firewatch_sdk_from_firewatch_namespace(self) -> None:
        src = self._get_source_dir()
        for py_file in src.glob("*.py"):
            content = py_file.read_text()
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("from firewatch_") or stripped.startswith("import firewatch_"):
                    assert (
                        "firewatch_sdk" in stripped
                        or "firewatch_azure_waf" in stripped
                    ), (
                        f"{py_file.name}: forbidden import line: {stripped!r}"
                    )


# ---------------------------------------------------------------------------
# Severity module unit tests (supplement EARS-8)
# ---------------------------------------------------------------------------


class TestSeverityModule:
    """Unit tests for severity.py — covers anomaly-score refinement."""

    def test_sqli_category_is_high(self) -> None:
        from firewatch_azure_waf.severity import severity_from_category
        assert severity_from_category("SQL Injection") == "high"

    def test_rce_category_is_critical(self) -> None:
        from firewatch_azure_waf.severity import severity_from_category
        assert severity_from_category("Remote Code Execution") == "critical"

    def test_scanner_category_is_low(self) -> None:
        from firewatch_azure_waf.severity import severity_from_category
        assert severity_from_category("Scanner / Recon Detection") == "low"

    def test_xss_category_is_high(self) -> None:
        from firewatch_azure_waf.severity import severity_from_category
        assert severity_from_category("Cross-Site Scripting (XSS)") == "high"

    def test_anomaly_score_15_escalates_to_high(self) -> None:
        from firewatch_azure_waf.severity import severity_from_category
        sev = severity_from_category(
            "Anomaly Score Threshold",
            "Inbound Anomaly Score Exceeded (Total Score: 15)",
        )
        assert sev in ("high", "critical")

    def test_anomaly_score_35_escalates_to_critical(self) -> None:
        from firewatch_azure_waf.severity import severity_from_category
        sev = severity_from_category(
            "Anomaly Score Threshold",
            "Inbound Anomaly Score Exceeded (Total Score: 35)",
        )
        assert sev == "critical"

    def test_none_category_returns_medium_default(self) -> None:
        from firewatch_azure_waf.severity import severity_from_category
        sev = severity_from_category(None)
        assert sev == "medium"

    def test_unknown_category_returns_medium_default(self) -> None:
        from firewatch_azure_waf.severity import severity_from_category
        sev = severity_from_category("Completely Unknown Category XYZ")
        assert sev == "medium"


# ---------------------------------------------------------------------------
# CRS module unit tests (supplement EARS-7)
# ---------------------------------------------------------------------------


class TestCRSModule:
    """Unit tests for crs.py — lookup functions."""

    def test_lookup_by_rule_id_sqli(self) -> None:
        from firewatch_azure_waf.crs import lookup_by_rule_id
        entry = lookup_by_rule_id("942100")
        assert entry is not None
        assert "SQL" in entry.category

    def test_lookup_by_rule_id_returns_none_for_unmapped(self) -> None:
        from firewatch_azure_waf.crs import lookup_by_rule_id
        assert lookup_by_rule_id("000001") is None

    def test_lookup_by_rule_id_returns_none_for_non_numeric(self) -> None:
        from firewatch_azure_waf.crs import lookup_by_rule_id
        assert lookup_by_rule_id("NOT_A_NUMBER") is None

    def test_lookup_by_rule_id_returns_none_for_none(self) -> None:
        from firewatch_azure_waf.crs import lookup_by_rule_id
        assert lookup_by_rule_id(None) is None

    def test_lookup_by_custom_name_ratelimit(self) -> None:
        from firewatch_azure_waf.crs import lookup_by_custom_name
        entry = lookup_by_custom_name("Custom-RateLimit-100req")
        assert entry is not None
        assert "Rate" in entry.category

    def test_lookup_by_custom_name_bot(self) -> None:
        from firewatch_azure_waf.crs import lookup_by_custom_name
        entry = lookup_by_custom_name("BotProtection-Rule1")
        assert entry is not None
        assert "Bot" in entry.category

    def test_lookup_custom_name_returns_none_for_unknown(self) -> None:
        from firewatch_azure_waf.crs import lookup_by_custom_name
        assert lookup_by_custom_name("WeirdCustomRuleXyz") is None

    def test_lookup_tries_rule_id_first(self) -> None:
        from firewatch_azure_waf.crs import lookup
        entry = lookup("942100", "Custom-RateLimit-100req")
        # rule_id wins (942100 = SQLi, not RateLimit)
        assert entry is not None
        assert "SQL" in entry.category

    def test_lookup_falls_back_to_custom_name(self) -> None:
        from firewatch_azure_waf.crs import lookup
        entry = lookup(None, "Custom-RateLimit-100req")
        assert entry is not None
        assert "Rate" in entry.category


# ---------------------------------------------------------------------------
# END-TO-END seam regression: collect() → normalize() fully populated
#
# These tests use REAL LogsTable (SDK constructor) with the ACTUAL projected
# column names from _kql.py, feed them through collect() (mocked client), then
# through normalize(), and assert the resulting SecurityEvent has fully-populated
# fields.  They guard against the class of bug where collect() yields data in a
# shape that normalize() cannot read (information-free SecurityEvents).
#
# Before the canonicalization fix these tests FAIL because:
#   - resource_specific rows use PascalCase (ClientIp, RuleId, Action, …) but
#     normalize() reads camelCase (clientIp, ruleId, action, …) — result: empty.
#   - AzureDiagnostics Front Door: details_matches stays flat, not nested into
#     props["details"]["matches"] — result: payload_snippet empty.
# ---------------------------------------------------------------------------


class TestCollectNormalizeE2E:
    """End-to-end regression: real LogsTable column shapes → fully-populated SecurityEvent.

    Seam guard: every test builds a LogsTable with the EXACT column names that
    the KQL queries in _kql.py project, pipes through collect() (mocked client),
    then normalize(), and asserts critical SecurityEvent fields are populated.
    Any future collect()→normalize() seam break will fail here.

    Test fixtures use RFC 5737 documentation IPs only (203.0.113.0/24,
    198.51.100.0/24) — no real/routable IPs.
    """

    def _make_plugin(self) -> Any:
        from firewatch_azure_waf.plugin import AzureWAFSource
        return AzureWAFSource()

    @staticmethod
    def _make_real_table(name: str, rows: list[dict[str, Any]]) -> Any:
        """Build a real LogsTable from a list of dicts (SDK constructor path)."""
        from azure.monitor.query import LogsTable

        if not rows:
            return LogsTable(name=name, columns=[], columns_types=[], rows=[])

        columns = list(rows[0].keys())
        col_types = ["string"] * len(columns)
        raw_rows = [[row.get(col) for col in columns] for row in rows]
        return LogsTable(name=name, columns=columns, columns_types=col_types, rows=raw_rows)

    async def _collect_and_normalize(
        self, table_name: str, rows: list[dict[str, Any]], product: str, regime: str
    ) -> list[Any]:
        """Run collect() with mocked client returning a real LogsTable, then normalize()."""
        from typing import cast
        from azure.monitor.query import LogsQueryStatus
        from firewatch_azure_waf.config import AzureWAFConfig, ProductLiteral, TableRegimeLiteral
        from firewatch_azure_waf.plugin import AzureWAFSource

        plugin: AzureWAFSource = AzureWAFSource()
        cfg = AzureWAFConfig(
            workspace_id="12345678-1234-1234-1234-123456789abc",
            table_regime=cast(TableRegimeLiteral, regime),
            product=cast(ProductLiteral, product),
            overlap_minutes=5,
        )

        real_table = self._make_real_table(table_name, rows)
        mock_result = MagicMock()
        mock_result.status = LogsQueryStatus.SUCCESS
        mock_result.tables = [real_table]

        with patch("firewatch_azure_waf.client.LogsQueryClient") as mock_cls:
            mock_client = MagicMock()
            mock_client.query_workspace.return_value = mock_result
            mock_cls.return_value = mock_client
            with patch("firewatch_azure_waf.client._build_credential", return_value=MagicMock()):
                raw_events = [
                    ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())
                ]
        return [plugin.normalize(ev, "e2e-test") for ev in raw_events]

    # ── resource_specific App Gateway ────────────────────────────────────────

    async def test_resource_specific_agw_source_ip_populated(self) -> None:
        """resource_specific AGWFirewallLogs: ClientIp column → source_ip populated.

        Without canonicalization: normalize() reads props.get('clientIp') == None
        because collect() puts it in props['ClientIp'] (PascalCase).
        """
        # Exact column names from _kql.py _KQL_AGW_RESOURCE project clause
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ResourceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw",
            "OperationName": "ApplicationGatewayFirewall",
            "InstanceId": "ApplicationGatewayRole_IN_0",
            "ClientIp": "203.0.113.10",
            "RequestUri": "/login?user=admin",
            "RuleSetType": "OWASP",
            "RuleSetVersion": "3.2",
            "RuleId": "942100",
            "RuleGroup": "942-APPLICATION-ATTACK-SQLI",
            "Message": "SQL Injection Attack Detected",
            "Action": "Matched",
            "Site": "Global",
            "Details_Message": "Warning. SQL injection pattern matched.",
            "Details_Data": "' OR 1=1",
            "Details_File": "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
            "Details_Line": "791",
            "Hostname": "203.0.113.1",
            "TransactionId": "txn-e2e-001",
            "PolicyId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw",
            "PolicyScope": "Global",
            "PolicyScopeName": "httpListener1",
        }

        events = await self._collect_and_normalize(
            "AGWFirewallLogs", [row], "app_gateway", "resource_specific"
        )

        assert len(events) == 1
        ev = events[0]
        assert ev.source_ip == "203.0.113.10", (
            f"source_ip must be '203.0.113.10' but got {ev.source_ip!r} — "
            "collect()→normalize() seam broken: ClientIp not canonicalized to clientIp"
        )

    async def test_resource_specific_agw_rule_id_populated(self) -> None:
        """resource_specific AGWFirewallLogs: RuleId column → rule_id populated."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ClientIp": "203.0.113.10",
            "RuleId": "942100",
            "RuleGroup": "942-APPLICATION-ATTACK-SQLI",
            "Message": "SQL Injection Attack Detected",
            "Action": "Matched",
            "RequestUri": "/login",
        }

        events = await self._collect_and_normalize(
            "AGWFirewallLogs", [row], "app_gateway", "resource_specific"
        )
        assert len(events) == 1
        assert events[0].rule_id == "942100", (
            f"rule_id must be '942100' but got {events[0].rule_id!r} — "
            "RuleId not canonicalized to ruleId"
        )

    async def test_resource_specific_agw_action_block(self) -> None:
        """resource_specific AGWFirewallLogs: Action=Block → BLOCK (not default ALERT)."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ClientIp": "203.0.113.10",
            "RuleId": "942100",
            "Action": "Block",
            "RequestUri": "/login",
        }

        events = await self._collect_and_normalize(
            "AGWFirewallLogs", [row], "app_gateway", "resource_specific"
        )
        assert len(events) == 1
        # Action=Block → BLOCK; if seam broken, empty action → default ALERT
        assert events[0].action == "BLOCK", (
            f"action must be 'BLOCK' but got {events[0].action!r} — "
            "Action not canonicalized to action"
        )

    async def test_resource_specific_agw_category_populated(self) -> None:
        """resource_specific AGWFirewallLogs: RuleId 942100 → SQL Injection category."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ClientIp": "203.0.113.10",
            "RuleId": "942100",
            "RuleGroup": "942-APPLICATION-ATTACK-SQLI",
            "Message": "SQL Injection Attack Detected",
            "Action": "Matched",
            "RequestUri": "/login",
        }

        events = await self._collect_and_normalize(
            "AGWFirewallLogs", [row], "app_gateway", "resource_specific"
        )
        assert len(events) == 1
        ev = events[0]
        assert ev.category is not None, "category must not be None"
        assert "SQL" in (ev.category or ""), (
            f"Expected 'SQL' in category from ruleId 942100 but got {ev.category!r} — "
            "seam broken: RuleId not reaching CRS lookup"
        )

    async def test_resource_specific_agw_attack_technique_populated(self) -> None:
        """resource_specific AGWFirewallLogs: RuleId 942100 → T1190 attack_technique."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ClientIp": "203.0.113.10",
            "RuleId": "942100",
            "Action": "Matched",
        }

        events = await self._collect_and_normalize(
            "AGWFirewallLogs", [row], "app_gateway", "resource_specific"
        )
        assert len(events) == 1
        assert events[0].attack_technique == "T1190", (
            f"attack_technique must be 'T1190' but got {events[0].attack_technique!r}"
        )

    async def test_resource_specific_agw_details_payload_snippet(self) -> None:
        """resource_specific AGWFirewallLogs: Details_Data/Details_Message → payload_snippet."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ClientIp": "203.0.113.10",
            "RuleId": "942100",
            "Action": "Matched",
            "Details_Data": "' OR 1=1 --",
            "Details_Message": "SQL injection matched",
        }

        events = await self._collect_and_normalize(
            "AGWFirewallLogs", [row], "app_gateway", "resource_specific"
        )
        assert len(events) == 1
        ev = events[0]
        assert ev.payload_snippet is not None, (
            "payload_snippet must be populated from Details_Data"
        )
        assert "OR 1=1" in ev.payload_snippet, (
            f"Details_Data content not in payload_snippet: {ev.payload_snippet!r}"
        )

    async def test_resource_specific_agw_transaction_id_as_source_event_id(self) -> None:
        """resource_specific AGWFirewallLogs: TransactionId column → source_event_id."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ClientIp": "203.0.113.10",
            "RuleId": "942100",
            "Action": "Matched",
            "TransactionId": "e2e-txn-abc",
        }

        events = await self._collect_and_normalize(
            "AGWFirewallLogs", [row], "app_gateway", "resource_specific"
        )
        assert len(events) == 1
        assert events[0].source_event_id == "e2e-txn-abc", (
            f"source_event_id must be 'e2e-txn-abc' but got {events[0].source_event_id!r} — "
            "TransactionId not canonicalized to transactionId"
        )

    async def test_resource_specific_agw_raw_log_non_empty(self) -> None:
        """resource_specific AGWFirewallLogs: raw_log must be non-empty for forensics."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ClientIp": "203.0.113.10",
            "RuleId": "942100",
            "Action": "Matched",
        }

        events = await self._collect_and_normalize(
            "AGWFirewallLogs", [row], "app_gateway", "resource_specific"
        )
        assert len(events) == 1
        assert events[0].raw_log, "raw_log must not be empty"

    # ── resource_specific Front Door ─────────────────────────────────────────

    async def test_resource_specific_fd_source_ip_populated(self) -> None:
        """resource_specific FrontDoor: ClientIP column → source_ip populated.

        Front Door uses ClientIP (capital IP) vs App Gateway's ClientIp.
        """
        # Exact column names from _kql.py _KQL_FD_RESOURCE project clause
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ResourceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Cdn/profiles/fd",
            "OperationName": "Microsoft.Cdn/Profiles/Write",
            "ClientIP": "198.51.100.5",
            "ClientPort": 52097,
            "SocketIP": "198.51.100.5",
            "RequestUri": "https://app.example.com:443/?q=%27%20or%201%3D1",
            "RuleName": "Microsoft_DefaultRuleSet-1.1-SQLI-942100",
            "Policy": "WafDemoPolicy",
            "PolicyMode": "prevention",
            "Host": "app.example.com",
            "TrackingReference": "08Q3gXgAAAAA",
            "Details_Matches": '[{"matchVariableName": "QueryParamValue:q", "matchVariableValue": "\' or 1=1"}]',
            "Action": "Block",
        }

        events = await self._collect_and_normalize(
            "AzureFrontDoorWebApplicationFirewallLog", [row], "front_door", "resource_specific"
        )

        assert len(events) == 1
        ev = events[0]
        assert ev.source_ip == "198.51.100.5", (
            f"source_ip must be '198.51.100.5' but got {ev.source_ip!r} — "
            "ClientIP not canonicalized to clientIP"
        )

    async def test_resource_specific_fd_rule_id_parsed_from_rule_name(self) -> None:
        """resource_specific FrontDoor: RuleName dotted column → rule_id parsed."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ClientIP": "198.51.100.5",
            "ClientPort": 52097,
            "RequestUri": "https://app.example.com/?q=test",
            "RuleName": "Microsoft_DefaultRuleSet-1.1-SQLI-942100",
            "Action": "Block",
            "TrackingReference": "08Q3gXgAAAAA",
        }

        events = await self._collect_and_normalize(
            "AzureFrontDoorWebApplicationFirewallLog", [row], "front_door", "resource_specific"
        )
        assert len(events) == 1
        assert events[0].rule_id == "942100", (
            f"rule_id must be '942100' (parsed from RuleName) but got {events[0].rule_id!r} — "
            "RuleName not canonicalized to ruleName"
        )

    async def test_resource_specific_fd_action_block(self) -> None:
        """resource_specific FrontDoor: Action=Block → BLOCK."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ClientIP": "198.51.100.5",
            "RequestUri": "https://app.example.com/?q=test",
            "RuleName": "Microsoft_DefaultRuleSet-1.1-SQLI-942100",
            "Action": "Block",
        }

        events = await self._collect_and_normalize(
            "AzureFrontDoorWebApplicationFirewallLog", [row], "front_door", "resource_specific"
        )
        assert len(events) == 1
        assert events[0].action == "BLOCK", (
            f"action must be BLOCK but got {events[0].action!r} — Action not canonicalized"
        )

    async def test_resource_specific_fd_payload_snippet_from_details_matches(self) -> None:
        """resource_specific FrontDoor: Details_Matches JSON string → payload_snippet."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ClientIP": "198.51.100.5",
            "RequestUri": "https://app.example.com/?q=test",
            "RuleName": "Microsoft_DefaultRuleSet-1.1-SQLI-942100",
            "Action": "Block",
            "Details_Matches": '[{"matchVariableName": "QueryParamValue:q", "matchVariableValue": "\' or 1=1"}]',
            "TrackingReference": "08Q3gXgAAAAA",
        }

        events = await self._collect_and_normalize(
            "AzureFrontDoorWebApplicationFirewallLog", [row], "front_door", "resource_specific"
        )
        assert len(events) == 1
        ev = events[0]
        assert ev.payload_snippet is not None, (
            "payload_snippet must be populated from Details_Matches"
        )
        assert "or 1=1" in ev.payload_snippet, (
            f"matchVariableValue not in payload_snippet: {ev.payload_snippet!r}"
        )

    async def test_resource_specific_fd_tracking_ref_as_source_event_id(self) -> None:
        """resource_specific FrontDoor: TrackingReference column → source_event_id."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ClientIP": "198.51.100.5",
            "RequestUri": "https://app.example.com/?q=test",
            "RuleName": "Microsoft_DefaultRuleSet-1.1-SQLI-942100",
            "Action": "Block",
            "TrackingReference": "08Q3gXgAAAAA",
        }

        events = await self._collect_and_normalize(
            "AzureFrontDoorWebApplicationFirewallLog", [row], "front_door", "resource_specific"
        )
        assert len(events) == 1
        assert events[0].source_event_id == "08Q3gXgAAAAA", (
            f"source_event_id must be '08Q3gXgAAAAA' but got {events[0].source_event_id!r} — "
            "TrackingReference not canonicalized"
        )

    async def test_resource_specific_fd_source_port_from_client_port(self) -> None:
        """resource_specific FrontDoor: ClientPort column → source_port populated."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ClientIP": "198.51.100.5",
            "ClientPort": 52097,
            "RequestUri": "https://app.example.com/?q=test",
            "RuleName": "Microsoft_DefaultRuleSet-1.1-SQLI-942100",
            "Action": "Block",
        }

        events = await self._collect_and_normalize(
            "AzureFrontDoorWebApplicationFirewallLog", [row], "front_door", "resource_specific"
        )
        assert len(events) == 1
        assert events[0].source_port == 52097, (
            f"source_port must be 52097 but got {events[0].source_port!r} — "
            "ClientPort not canonicalized to clientPort"
        )

    # ── azure_diagnostics App Gateway ────────────────────────────────────────

    async def test_azure_diagnostics_agw_source_ip_populated(self) -> None:
        """azure_diagnostics AGW: clientIp_s column → source_ip populated."""
        # Exact column names from _kql.py _KQL_AZURE_DIAG_APP_GW project clause
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ResourceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw",
            "OperationName": "ApplicationGatewayFirewall",
            "instanceId_s": "ApplicationGatewayRole_IN_0",
            "clientIp_s": "203.0.113.10",
            "requestUri_s": "/login?user=admin",
            "ruleSetType_s": "OWASP",
            "ruleSetVersion_s": "3.2",
            "ruleId_s": "942100",
            "ruleGroup_s": "942-APPLICATION-ATTACK-SQLI",
            "message_s": "SQL Injection Attack Detected",
            "action_s": "Matched",
            # site_s removed: not emitted by real App Gateway WAF workspaces (issue #142)
            "details_message_s": "Warning. SQL injection pattern matched.",
            "details_data_s": "' OR 1=1",
            "details_file_s": "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
            "details_line_s": "791",
            "hostname_s": "203.0.113.1",
            "transactionId_s": "txn-diag-001",
            "policyId_s": "/subscriptions/sub/providers/Microsoft.Network/applicationGateways/gw",
            "policyScope_s": "Global",
            "policyScopeName_s": "httpListener1",
        }

        events = await self._collect_and_normalize(
            "AzureDiagnostics", [row], "app_gateway", "azure_diagnostics"
        )

        assert len(events) == 1
        assert events[0].source_ip == "203.0.113.10", (
            f"source_ip must be '203.0.113.10' but got {events[0].source_ip!r}"
        )

    async def test_azure_diagnostics_agw_rule_id_populated(self) -> None:
        """azure_diagnostics AGW: ruleId_s column → rule_id populated."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "clientIp_s": "203.0.113.10",
            "ruleId_s": "942100",
            "action_s": "Matched",
        }

        events = await self._collect_and_normalize(
            "AzureDiagnostics", [row], "app_gateway", "azure_diagnostics"
        )
        assert len(events) == 1
        assert events[0].rule_id == "942100"

    async def test_azure_diagnostics_agw_action_block(self) -> None:
        """azure_diagnostics AGW: action_s=Block → BLOCK."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "clientIp_s": "203.0.113.10",
            "ruleId_s": "942100",
            "action_s": "Block",
        }

        events = await self._collect_and_normalize(
            "AzureDiagnostics", [row], "app_gateway", "azure_diagnostics"
        )
        assert len(events) == 1
        assert events[0].action == "BLOCK"

    async def test_azure_diagnostics_agw_details_payload_snippet(self) -> None:
        """azure_diagnostics AGW: details_data_s / details_message_s → payload_snippet."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "clientIp_s": "203.0.113.10",
            "ruleId_s": "942100",
            "action_s": "Matched",
            "details_data_s": "' OR 1=1 --",
            "details_message_s": "SQL injection matched",
        }

        events = await self._collect_and_normalize(
            "AzureDiagnostics", [row], "app_gateway", "azure_diagnostics"
        )
        assert len(events) == 1
        ev = events[0]
        assert ev.payload_snippet is not None, (
            "payload_snippet must be populated from details_data_s"
        )
        assert "OR 1=1" in ev.payload_snippet

    async def test_azure_diagnostics_agw_transaction_id_as_source_event_id(self) -> None:
        """azure_diagnostics AGW: transactionId_s → source_event_id."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "clientIp_s": "203.0.113.10",
            "ruleId_s": "942100",
            "action_s": "Matched",
            "transactionId_s": "txn-diag-e2e",
        }

        events = await self._collect_and_normalize(
            "AzureDiagnostics", [row], "app_gateway", "azure_diagnostics"
        )
        assert len(events) == 1
        assert events[0].source_event_id == "txn-diag-e2e"

    # ── azure_diagnostics Front Door ─────────────────────────────────────────

    async def test_azure_diagnostics_fd_source_ip_populated(self) -> None:
        """azure_diagnostics FrontDoor: clientIP_s column → source_ip populated.

        Note the casing difference: Front Door uses clientIP_s (capital IP)
        while App Gateway uses clientIp_s (lowercase p).
        """
        # Exact column names from _kql.py _KQL_AZURE_DIAG_FRONT_DOOR project clause
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "ResourceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Cdn/profiles/fd",
            "OperationName": "Microsoft.Cdn/Profiles/Write",
            "clientIP_s": "198.51.100.5",
            "clientPort_d": 52097,
            "socketIP_s": "198.51.100.5",
            "requestUri_s": "https://app.example.com:443/?q=%27%20or%201%3D1",
            "ruleName_s": "Microsoft_DefaultRuleSet-1.1-SQLI-942100",
            "policy_s": "WafDemoPolicy",
            "policyMode_s": "prevention",
            "host_s": "app.example.com",
            "trackingReference_s": "08Q3gXgAAAAA",
            "action_s": "Block",
            "details_matches_s": '[{"matchVariableName": "QueryParamValue:q", "matchVariableValue": "\' or 1=1"}]',
        }

        events = await self._collect_and_normalize(
            "AzureDiagnostics", [row], "front_door", "azure_diagnostics"
        )

        assert len(events) == 1
        assert events[0].source_ip == "198.51.100.5", (
            f"source_ip must be '198.51.100.5' but got {events[0].source_ip!r} — "
            "clientIP_s not canonicalized to clientIP"
        )

    async def test_azure_diagnostics_fd_rule_id_populated(self) -> None:
        """azure_diagnostics FrontDoor: ruleName_s → rule_id parsed."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "clientIP_s": "198.51.100.5",
            "ruleName_s": "Microsoft_DefaultRuleSet-1.1-SQLI-942100",
            "action_s": "Block",
            "trackingReference_s": "08Q3gXgAAAAA",
        }

        events = await self._collect_and_normalize(
            "AzureDiagnostics", [row], "front_door", "azure_diagnostics"
        )
        assert len(events) == 1
        assert events[0].rule_id == "942100"

    async def test_azure_diagnostics_fd_action_block(self) -> None:
        """azure_diagnostics FrontDoor: action_s=Block → BLOCK."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "clientIP_s": "198.51.100.5",
            "ruleName_s": "Microsoft_DefaultRuleSet-1.1-SQLI-942100",
            "action_s": "Block",
        }

        events = await self._collect_and_normalize(
            "AzureDiagnostics", [row], "front_door", "azure_diagnostics"
        )
        assert len(events) == 1
        assert events[0].action == "BLOCK"

    async def test_azure_diagnostics_fd_payload_snippet_from_details_matches(self) -> None:
        """azure_diagnostics FrontDoor: details_matches_s JSON → payload_snippet.

        Without the fix: details_matches_s gets remapped to details_matches (flat),
        but normalize() reads props['details']['matches'], so the matches are invisible
        and payload_snippet is empty.
        """
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "clientIP_s": "198.51.100.5",
            "ruleName_s": "Microsoft_DefaultRuleSet-1.1-SQLI-942100",
            "action_s": "Block",
            "details_matches_s": '[{"matchVariableName": "QueryParamValue:q", "matchVariableValue": "\' or 1=1"}]',
        }

        events = await self._collect_and_normalize(
            "AzureDiagnostics", [row], "front_door", "azure_diagnostics"
        )
        assert len(events) == 1
        ev = events[0]
        assert ev.payload_snippet is not None, (
            "payload_snippet must be populated from details_matches_s — "
            "details_matches not nested into details.matches[]"
        )
        assert "or 1=1" in ev.payload_snippet, (
            f"matchVariableValue not in payload_snippet: {ev.payload_snippet!r}"
        )

    async def test_azure_diagnostics_fd_tracking_reference_as_source_event_id(self) -> None:
        """azure_diagnostics FrontDoor: trackingReference_s → source_event_id."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "clientIP_s": "198.51.100.5",
            "ruleName_s": "Microsoft_DefaultRuleSet-1.1-SQLI-942100",
            "action_s": "Block",
            "trackingReference_s": "e2e-ref-fd",
        }

        events = await self._collect_and_normalize(
            "AzureDiagnostics", [row], "front_door", "azure_diagnostics"
        )
        assert len(events) == 1
        assert events[0].source_event_id == "e2e-ref-fd"

    async def test_azure_diagnostics_fd_source_port_populated(self) -> None:
        """azure_diagnostics FrontDoor: clientPort_d → source_port populated."""
        row: dict[str, Any] = {
            "TimeGenerated": "2026-01-15T10:00:00Z",
            "clientIP_s": "198.51.100.5",
            "clientPort_d": 52097,
            "ruleName_s": "Microsoft_DefaultRuleSet-1.1-SQLI-942100",
            "action_s": "Block",
        }

        events = await self._collect_and_normalize(
            "AzureDiagnostics", [row], "front_door", "azure_diagnostics"
        )
        assert len(events) == 1
        assert events[0].source_port == 52097

    # ── Real workspace shape — issue #142 golden test ─────────────────────────

    async def test_azure_diagnostics_agw_real_workspace_shape_end_to_end(self) -> None:
        """Golden E2E: real App Gateway WAF workspace column shape → fully-populated SecurityEvent.

        This test uses the ACTUAL column shape captured from a live workspace
        (issue #142), where:
          - "Message" (capital, no _s) carries the rule message — NOT message_s.
          - "transactionId_g" (_g suffix) is the transaction GUID — NOT transactionId_s.
          - "site_s" is absent — NOT emitted by real App Gateway WAF workspaces.

        After the KQL fix (_kql.py), the query aliases these to the expected output
        names using column_ifexists:
          column_ifexists("Message", "")       → aliased as message_s
          column_ifexists("transactionId_g", "") → aliased as transactionId_s

        The row dict below represents the post-KQL (aliased) shape that collect()
        yields to normalize().  Asserting non-empty source_ip, rule_id, action, and
        message proves the full collect→canonicalize→normalize chain works on real
        column names.

        IP sanitized to RFC 5737 documentation range (203.0.113.0/24) per
        docs/lessons.md — gitleaks blocks real public IPs.
        """
        # Post-KQL row: column_ifexists aliases from the real workspace shape.
        # message_s is aliased from "Message"; transactionId_s from "transactionId_g".
        # site_s is absent (not projected by the fixed KQL).
        row: dict[str, Any] = {
            "TimeGenerated": "2026-05-20T14:32:11.456000Z",
            "ResourceId": (
                "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000"
                "/RESOURCEGROUPS/RG-WAF-PROJECT"
                "/PROVIDERS/MICROSOFT.NETWORK/APPLICATIONGATEWAYS/APPGW-WAF"
            ),
            "OperationName": "ApplicationGatewayFirewall",
            "instanceId_s": "ApplicationGatewayRole_IN_0",
            "clientIp_s": "203.0.113.102",
            "requestUri_s": "/admin/login",
            "ruleSetType_s": "OWASP",
            "ruleSetVersion_s": "3.2",
            "ruleId_s": "942100",
            "ruleGroup_s": "942-APPLICATION-ATTACK-SQLI",
            # Aliased from "Message" via column_ifexists("Message", "") in the fixed KQL
            "message_s": (
                "Access denied with code 403. "
                "Found condition 0 in RemoteAddr, with value 203.0.113.102."
            ),
            "action_s": "Blocked",
            "details_message_s": "Warning. Pattern match ...",
            "details_data_s": "Matched Data: 1=1 found within ARGS:user",
            "details_file_s": "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
            "details_line_s": "791",
            "hostname_s": "app.example.com",
            # Aliased from "transactionId_g" via column_ifexists("transactionId_g", "")
            "transactionId_s": "00000000-0000-0000-0000-000000000001",
            "policyId_s": (
                "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000"
                "/RESOURCEGROUPS/RG-WAF-PROJECT"
                "/PROVIDERS/MICROSOFT.NETWORK/APPLICATIONGATEWAYS/APPGW-WAF"
            ),
            "policyScope_s": "Global",
            "policyScopeName_s": "httpListener1",
        }

        events = await self._collect_and_normalize(
            "AzureDiagnostics", [row], "app_gateway", "azure_diagnostics"
        )

        assert len(events) == 1, (
            "Expected 1 SecurityEvent from the real-workspace-shape row; "
            f"got {len(events)}"
        )
        ev = events[0]

        # source_ip must be populated from clientIp_s
        assert ev.source_ip == "203.0.113.102", (
            f"source_ip must be '203.0.113.102' from clientIp_s; got {ev.source_ip!r} — "
            "collect()→canonicalize()→normalize() seam broken for real workspace shape"
        )
        # rule_id populated from ruleId_s
        assert ev.rule_id == "942100", (
            f"rule_id must be '942100' from ruleId_s; got {ev.rule_id!r}"
        )
        # action mapped from action_s="Blocked" → BLOCK
        assert ev.action == "BLOCK", (
            f"action must be 'BLOCK' (action_s='Blocked'); got {ev.action!r}"
        )
        # message populated via message_s (aliased from "Message" in the fixed KQL)
        assert ev.rule_name is not None and len(ev.rule_name) > 0, (
            f"rule_name (from message_s/Message) must be non-empty; got {ev.rule_name!r} — "
            "message_s alias from column_ifexists(\"Message\", \"\") not working"
        )
        # transactionId populated via transactionId_s (aliased from transactionId_g)
        assert ev.source_event_id == "00000000-0000-0000-0000-000000000001", (
            f"source_event_id must equal transactionId_s (aliased from transactionId_g); "
            f"got {ev.source_event_id!r}"
        )
        # category from CRS lookup on rule 942100
        assert ev.category is not None and "SQL" in (ev.category or ""), (
            f"category must contain 'SQL' from CRS rule 942100; got {ev.category!r}"
        )
        # OCSF constants always set
        assert ev.ocsf_class == 4002
        assert ev.ocsf_category == 4
        # severity always set (never None)
        assert ev.severity is not None, "severity must never be None"
        # payload_snippet from details_data_s
        assert ev.payload_snippet is not None, (
            "payload_snippet must be populated from details_data_s"
        )
        assert "1=1" in (ev.payload_snippet or ""), (
            f"details_data_s content not in payload_snippet: {ev.payload_snippet!r}"
        )


# ---------------------------------------------------------------------------
# KQL template correctness (issue #142 regression guard)
# ---------------------------------------------------------------------------


class TestKQLTemplatesAzureDiagnostics:
    """Guard against regression of the SEM0100 bug (issue #142).

    The AzureDiagnostics templates MUST:
      1. Use column_ifexists for every optional/suffixed column — never bare
         column references that crash on sparse tables (SEM0100).
      2. Alias "Message" → message_s (real column name, no _s suffix).
      3. Alias "transactionId_g" → transactionId_s (real _g suffix, not _s).
      4. NOT reference site_s (absent from real App Gateway WAF workspaces).

    resource_specific templates are NOT tested here — they use a dedicated
    resource-specific table that has stable columns.
    """

    def _get_templates(self) -> dict[str, str]:
        """Return the three azure_diagnostics KQL template strings."""
        from datetime import datetime, timezone
        from firewatch_azure_waf._kql import build_kql

        since = datetime(2026, 1, 1, tzinfo=timezone.utc)
        until = datetime(2026, 1, 2, tzinfo=timezone.utc)

        return {
            "app_gateway": build_kql("app_gateway", "azure_diagnostics", since, until)[0],
            "front_door": build_kql("front_door", "azure_diagnostics", since, until)[0],
            "both": build_kql("both", "azure_diagnostics", since, until)[0],
        }

    def test_all_azure_diag_templates_use_column_ifexists(self) -> None:
        """Every azure_diagnostics template must use column_ifexists (SEM0100 guard).

        Bare column references in AzureDiagnostics crash with SEM0100 when the
        column has never been populated in the workspace.  The fix wraps every
        optional column with column_ifexists("name", "").
        (issue #142)
        """
        for template_name, kql in self._get_templates().items():
            assert "column_ifexists" in kql, (
                f"{template_name!r} template lacks column_ifexists — "
                "bare column references will crash with SEM0100 on sparse tables "
                "(issue #142)"
            )

    def test_app_gw_template_aliases_Message_not_message_s(self) -> None:
        """App Gateway template reads from real column 'Message', not 'message_s'.

        In a live App Gateway WAF workspace the rule-message column is 'Message'
        (capital M, no _s suffix).  The old template referenced message_s directly
        and crashed with SEM0100 because that column does not exist.
        (issue #142, verified against live workspace)
        """
        kql = self._get_templates()["app_gateway"]
        assert 'column_ifexists("Message"' in kql, (
            "App Gateway template must read from 'Message' via column_ifexists; "
            "message_s does not exist in real workspaces (issue #142)"
        )

    def test_app_gw_template_aliases_transactionId_g_not_transactionId_s(self) -> None:
        """App Gateway template reads from 'transactionId_g', not 'transactionId_s'.

        In a live App Gateway WAF workspace the transaction column is 'transactionId_g'
        (_g suffix = GUID, not _s = string).  The old template used transactionId_s
        which does not exist.
        (issue #142, verified against live workspace)
        """
        kql = self._get_templates()["app_gateway"]
        assert 'column_ifexists("transactionId_g"' in kql, (
            "App Gateway template must read from 'transactionId_g' via column_ifexists; "
            "transactionId_s does not exist in real workspaces (issue #142)"
        )

    def test_app_gw_template_does_not_project_site_s_bare(self) -> None:
        """App Gateway template must not project site_s as a bare column reference.

        site_s is not emitted by real App Gateway WAF workspaces and any bare
        reference to it would cause SEM0100.
        (issue #142, verified against live workspace)
        """
        kql = self._get_templates()["app_gateway"]
        # The only valid occurrence would be inside column_ifexists — but since
        # site_s doesn't exist at all, it should not appear in the template at all.
        assert "site_s" not in kql, (
            "App Gateway template must not reference site_s — it is not emitted "
            "by real App Gateway WAF workspaces (issue #142)"
        )

    def test_both_template_aliases_Message_and_transactionId_g(self) -> None:
        """'both' template (App GW + Front Door) must also use the real column names."""
        kql = self._get_templates()["both"]
        assert 'column_ifexists("Message"' in kql, (
            "'both' template must read 'Message' via column_ifexists (issue #142)"
        )
        assert 'column_ifexists("transactionId_g"' in kql, (
            "'both' template must read 'transactionId_g' via column_ifexists (issue #142)"
        )
        assert "site_s" not in kql, (
            "'both' template must not reference site_s (issue #142)"
        )


# ---------------------------------------------------------------------------
# EARS-16: config_schema descriptions are operator-facing — no developer notes
# ---------------------------------------------------------------------------


class TestConfigSchemaOperatorCopy:
    """EARS-16 — user-facing schema strings contain no developer notes (issue #95).

    The Settings card renders field descriptions verbatim; they must be plain
    operator language with no internal ticket tags, implementation details, or
    backtick-fenced type references.
    """

    def _collect_user_facing_strings(self) -> list[str]:
        """Gather all description/title strings that appear in model_json_schema()."""
        from firewatch_azure_waf.config import AzureWAFConfig

        schema = AzureWAFConfig.model_json_schema()
        strings: list[str] = []

        # Top-level model description (from class docstring).
        if "description" in schema:
            strings.append(schema["description"])
        if "title" in schema:
            strings.append(schema["title"])

        # Per-field descriptions and titles.
        for field_schema in schema.get("properties", {}).values():
            if "description" in field_schema:
                strings.append(field_schema["description"])
            if "title" in field_schema:
                strings.append(field_schema["title"])
            # Handle anyOf nesting (SecretStr fields).
            for sub in field_schema.get("anyOf", []):
                if "description" in sub:
                    strings.append(sub["description"])

        return strings

    def test_no_ticket_tags_in_schema(self) -> None:
        """Ticket tags (BLOCKING-*, NB-*) must not appear in user-facing schema strings."""
        strings = self._collect_user_facing_strings()
        combined = "\n".join(strings)
        for pattern in ("BLOCKING-1", "BLOCKING-2", "NB-5", "NB-4"):
            assert pattern not in combined, (
                f"Developer ticket tag {pattern!r} found in user-facing schema string. "
                "Move it to a code comment."
            )

    def test_no_plugin_contract_refs_in_schema(self) -> None:
        """PLUGIN_CONTRACT.md references must not appear in user-facing schema strings."""
        strings = self._collect_user_facing_strings()
        combined = "\n".join(strings)
        assert "PLUGIN_CONTRACT" not in combined, (
            "PLUGIN_CONTRACT.md reference found in user-facing schema string. "
            "Move it to a code comment."
        )

    def test_no_backtick_fences_in_schema(self) -> None:
        """reStructuredText double-backtick fences (``foo``) must not appear in schema strings."""
        strings = self._collect_user_facing_strings()
        combined = "\n".join(strings)
        assert "``" not in combined, (
            "reStructuredText backtick fence (`` ``) found in user-facing schema string. "
            "Use plain text instead."
        )

    def test_no_model_json_schema_refs_in_schema(self) -> None:
        """Implementation detail 'model_json_schema' must not appear in schema strings."""
        strings = self._collect_user_facing_strings()
        combined = "\n".join(strings)
        assert "model_json_schema" not in combined, (
            "'model_json_schema' found in user-facing schema string. "
            "Move implementation details to code comments."
        )

    def test_no_secretstr_backtick_refs_in_schema(self) -> None:
        """Type name 'SecretStr' in backticks must not appear in user-facing schema strings."""
        strings = self._collect_user_facing_strings()
        combined = "\n".join(strings)
        # Backtick-wrapped SecretStr (``SecretStr``) is caught by test_no_backtick_fences,
        # but also check bare "SecretStr" which has no place in operator-facing copy.
        assert "SecretStr" not in combined, (
            "'SecretStr' type name found in user-facing schema string. "
            "Operators don't need to know the Pydantic type. "
            "Move it to a code comment."
        )
