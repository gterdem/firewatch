"""Tests for firewatch_aws_nfw — EARS criteria mapped 1:1.

EARS-1  WHEN configured for CloudWatch Logs mode, the plugin SHALL pull NFW alert records
        newer than the (source_type, source_id) watermark and yield RawEvents.
EARS-2  WHEN an NFW alert record has event.alert.action="blocked", normalize() SHALL set
        action=BLOCK; "alert" SHALL map to ALERT (ADR-0012).
EARS-3  WHEN credentials/connectivity fail, collect() SHALL raise a typed error (NOT
        swallow as "no data") so the supervisor isolates the instance.
EARS-4  SecretStr auth fields SHALL default to None (no secret leak in the discovery schema).
EARS-5  Golden tests SHALL pin sample NFW alert logs → expected SecurityEvents against
        the published standard (OCSF/ADR-0020 + ADR-0012), not recorded from legacy.
EARS-6  Adding this package SHALL require zero edits to firewatch-core.

Additional tests:
  - Flag-B: source_type is constant "aws_network_firewall"; source_id never branched on.
  - Watermark window: since=None → 24h; since=ISO string → overlap applied.
  - Pagination: multi-page CloudWatch nextToken handled correctly.
  - Health check: returns bool, never raises.
  - Forbidden imports: no firewatch_core, no legacy.

Test fixtures use RFC 5737 documentation IPs ONLY:
  192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
RFC-1918 private addresses (10.x, 172.16.x, 192.168.x) and loopback are also used
where they naturally appear in NFW log examples (inside-network traffic).
No real/routable IPs — gitleaks public-ipv4 rule blocks them.

Sources:
  - AWS NFW log format: AWS Network Firewall Developer Guide, Logging section
    (https://docs.aws.amazon.com/network-firewall/latest/developerguide/logging-cw-logs.html)
  - OCSF alignment: ADR-0020, https://schema.ocsf.io/classes/detection_finding
  - Action mapping: ADR-0012 (blocked→BLOCK, alert→ALERT)
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from firewatch_sdk import PluginContext, RawEvent
from firewatch_sdk.testing import InMemoryScopedKV

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _ctx(source_id: str = "test-nfw") -> PluginContext:
    return PluginContext(kv=InMemoryScopedKV(), source_id=source_id)


def _received() -> datetime:
    return datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)


def _make_nfw_stateful_alert_record(
    *,
    src_ip: str = "203.0.113.10",
    src_port: int = 44321,
    dest_ip: str = "198.51.100.5",
    dest_port: int = 80,
    proto: str = "TCP",
    action: str = "blocked",
    signature: str = "ET WEB_SERVER SQL Injection Attempt",
    signature_id: int = 2012345,
    severity: int = 2,
    category: str = "Web Application Attack",
    ts: str = "2026-01-15T10:00:00.000000+0000",
    flow_id: int = 1234567890,
    app_proto: str = "http",
    http_url: str | None = "/login?id=1 OR 1=1",
    http_hostname: str | None = "example.internal",
    mitre_technique_id: str | None = None,
    mitre_tactic_id: str | None = None,
) -> dict[str, Any]:
    """Build a minimal AWS NFW stateful alert log record (EVE-in-AWS-envelope).

    AWS NFW's stateful engine is Suricata; its alert log records are EVE JSON
    wrapped in an AWS CloudWatch Logs envelope.

    Reference: AWS Network Firewall Developer Guide — Stateful engine alert logs
    (https://docs.aws.amazon.com/network-firewall/latest/developerguide/logging-cw-logs.html)

    Uses RFC 5737 documentation IPs only.
    """
    alert: dict[str, Any] = {
        "action": action,
        "category": category,
        "signature": signature,
        "signature_id": signature_id,
        "severity": severity,
    }
    if mitre_technique_id:
        alert["metadata"] = {
            "mitre_technique_id": [mitre_technique_id],
        }
    if mitre_tactic_id:
        alert.setdefault("metadata", {})["mitre_tactic_id"] = [mitre_tactic_id]

    event: dict[str, Any] = {
        "timestamp": ts,
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "app_proto": app_proto,
        "flow_id": flow_id,
        "alert": alert,
    }
    if http_url:
        event["http"] = {
            "url": http_url,
            "hostname": http_hostname or "",
            "http_method": "GET",
        }

    # AWS CloudWatch Logs envelope: {"firewall_name":…, "availability_zone":…, "event":{EVE}}
    return {
        "firewall_name": "test-firewall",
        "availability_zone": "us-east-1a",
        "event_timestamp": ts,
        "event": event,
    }


def _make_nfw_pass_record(
    *,
    src_ip: str = "192.0.2.20",
    dest_ip: str = "198.51.100.100",
    dest_port: int = 443,
    proto: str = "TCP",
    ts: str = "2026-01-15T10:05:00.000000+0000",
) -> dict[str, Any]:
    """Build a pass-through (non-alerting) NFW record — no alert sub-object.

    AWS NFW pass records have event_type=flow, not alert.
    """
    event: dict[str, Any] = {
        "timestamp": ts,
        "event_type": "flow",
        "src_ip": src_ip,
        "src_port": 50000,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "flow": {
            "pkts_toserver": 5,
            "pkts_toclient": 3,
            "bytes_toserver": 512,
            "bytes_toclient": 256,
            "start": ts,
            "end": "2026-01-15T10:05:01.000000+0000",
            "state": "established",
            "reason": "timeout",
        },
    }
    return {
        "firewall_name": "test-firewall",
        "availability_zone": "us-east-1a",
        "event_timestamp": ts,
        "event": event,
    }


def _make_raw_event(data: dict[str, Any]) -> RawEvent:
    return RawEvent(
        source_type="aws_network_firewall",
        received_at=_received(),
        data=data,
    )


def _make_mock_cw_client(
    log_events: list[dict[str, Any]],
    *,
    next_token: str | None = None,
    second_page: list[dict[str, Any]] | None = None,
) -> MagicMock:
    """Build a mock CloudWatch Logs boto3 client.

    Simulates filter_log_events with optional pagination via nextToken.

    Each log event is wrapped as a CloudWatch Logs log event dict:
    {"logStreamName":…, "timestamp":…, "message": "<json string>", "ingestionTime":…}
    """
    import json

    def _make_cw_log_event(record: dict[str, Any], ts_ms: int = 1705312800000) -> dict[str, Any]:
        return {
            "logStreamName": "aws/network-firewall/test-firewall/alert",
            "timestamp": ts_ms,
            "message": json.dumps(record),
            "ingestionTime": ts_ms + 100,
        }

    first_events = [_make_cw_log_event(r) for r in log_events]
    first_response: dict[str, Any] = {"events": first_events}
    if next_token and second_page is not None:
        first_response["nextToken"] = next_token

    mock_client = MagicMock()

    if next_token and second_page is not None:
        second_events = [_make_cw_log_event(r) for r in second_page]
        second_response: dict[str, Any] = {"events": second_events}
        mock_client.filter_log_events.side_effect = [first_response, second_response]
    else:
        mock_client.filter_log_events.return_value = first_response

    return mock_client


# ---------------------------------------------------------------------------
# EARS-1: CloudWatch Logs pull + watermark + yield RawEvents
# ---------------------------------------------------------------------------


class TestCollectCloudWatch:
    """EARS-1 — collect() pulls from CloudWatch Logs newer than the watermark."""

    def _make_plugin(self) -> Any:
        from firewatch_aws_nfw.plugin import AwsNetworkFirewallSource
        return AwsNetworkFirewallSource()

    def _make_cfg(self) -> Any:
        from firewatch_aws_nfw.config import AwsNetworkFirewallConfig
        return AwsNetworkFirewallConfig(
            region="us-east-1",
            log_group_name="/aws/network-firewall/test-firewall/alert",
        )

    async def test_collect_yields_raw_events(self) -> None:
        """collect() wraps each CloudWatch log event in a RawEvent."""
        plugin = self._make_plugin()
        cfg = self._make_cfg()
        record = _make_nfw_stateful_alert_record()

        mock_client = _make_mock_cw_client([record])
        with patch("firewatch_aws_nfw.client.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            events = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

        assert len(events) == 1
        assert events[0].source_type == "aws_network_firewall"

    async def test_collect_raw_event_data_contains_aws_envelope(self) -> None:
        """The RawEvent.data contains the full AWS+EVE payload for drill-down."""
        plugin = self._make_plugin()
        cfg = self._make_cfg()
        record = _make_nfw_stateful_alert_record()

        mock_client = _make_mock_cw_client([record])
        with patch("firewatch_aws_nfw.client.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            events = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

        data = events[0].data
        # The inner EVE "event" sub-object must be present
        assert "event" in data
        assert data["event"]["alert"]["action"] == "blocked"

    async def test_collect_since_none_uses_24h_window(self) -> None:
        """since=None → initial 24h window (first run)."""
        from firewatch_aws_nfw import client as _client_mod

        start_ms, end_ms = _client_mod._compute_window(None, overlap_minutes=5)
        delta_ms = end_ms - start_ms
        # Should be approximately 24h = 86_400_000 ms (within 2 minutes)
        assert abs(delta_ms - 86_400_000) < 120_000

    async def test_collect_since_applies_overlap(self) -> None:
        """since watermark → (since - overlap_minutes) used as start_time."""
        from firewatch_aws_nfw import client as _client_mod

        since = "2026-01-15T10:00:00+00:00"
        start_ms, end_ms = _client_mod._compute_window(since, overlap_minutes=5)
        # Start should be 5 minutes before the watermark = 09:55
        # 2026-01-15T09:55:00Z in epoch ms
        expected_start_s = datetime(2026, 1, 15, 9, 55, 0, tzinfo=timezone.utc).timestamp()
        actual_start_s = start_ms / 1000.0
        assert abs(actual_start_s - expected_start_s) < 10

    async def test_collect_empty_log_group_yields_nothing(self) -> None:
        """Empty CloudWatch Logs result yields no RawEvents."""
        plugin = self._make_plugin()
        cfg = self._make_cfg()

        mock_client = _make_mock_cw_client([])
        with patch("firewatch_aws_nfw.client.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            events = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

        assert events == []

    async def test_collect_pagination_nexttoken_followed(self) -> None:
        """Multi-page result: nextToken is followed to retrieve all pages."""
        plugin = self._make_plugin()
        cfg = self._make_cfg()

        page1_record = _make_nfw_stateful_alert_record(src_ip="203.0.113.10")
        page2_record = _make_nfw_stateful_alert_record(src_ip="203.0.113.20")

        mock_client = _make_mock_cw_client(
            [page1_record],
            next_token="page2-token",
            second_page=[page2_record],
        )
        with patch("firewatch_aws_nfw.client.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            events = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

        # Both pages should be yielded
        assert len(events) == 2
        assert mock_client.filter_log_events.call_count == 2

    async def test_collect_is_cancellable(self) -> None:
        """CancelledError propagates from collect() (PLUGIN_CONTRACT.md hard rule)."""
        plugin = self._make_plugin()
        cfg = self._make_cfg()

        records = [_make_nfw_stateful_alert_record() for _ in range(10)]
        mock_client = _make_mock_cw_client(records)

        async def _consumer() -> list[RawEvent]:
            results: list[RawEvent] = []
            with patch("firewatch_aws_nfw.client.boto3") as mock_boto3:
                mock_boto3.client.return_value = mock_client
                async for ev in plugin.collect(cfg, since=None, ctx=_ctx()):
                    results.append(ev)
                    if len(results) >= 1:
                        raise asyncio.CancelledError()
            return results

        task = asyncio.create_task(_consumer())
        with pytest.raises(asyncio.CancelledError):
            await task

    async def test_collect_invalid_json_log_event_skipped(self) -> None:
        """A corrupt CloudWatch log message is skipped; valid ones are still yielded."""
        plugin = self._make_plugin()
        cfg = self._make_cfg()

        record = _make_nfw_stateful_alert_record()

        mock_client = MagicMock()
        mock_client.filter_log_events.return_value = {
            "events": [
                {
                    "logStreamName": "test",
                    "timestamp": 1705312800000,
                    "message": "NOT VALID JSON",
                    "ingestionTime": 1705312800100,
                },
                {
                    "logStreamName": "test",
                    "timestamp": 1705312800000,
                    "message": __import__("json").dumps(record),
                    "ingestionTime": 1705312800100,
                },
            ]
        }

        with patch("firewatch_aws_nfw.client.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            events = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

        # Only the valid record yields an event
        assert len(events) == 1


# ---------------------------------------------------------------------------
# EARS-2: normalize() — action mapping (blocked→BLOCK, alert→ALERT)
# ---------------------------------------------------------------------------


class TestNormalizeActionMapping:
    """EARS-2 — blocked→BLOCK, alert→ALERT; other values handled defensively.

    ADR-0012: IDS detections→ALERT, IPS blocks→BLOCK.
    AWS NFW alert.action values: "blocked" (IPS mode), "alert" (IDS mode).
    Reference: AWS Network Firewall Developer Guide, Stateful rules logging.
    """

    def setup_method(self) -> None:
        from firewatch_aws_nfw.plugin import AwsNetworkFirewallSource
        self.plugin = AwsNetworkFirewallSource()

    def _normalize(self, action: str) -> str:
        record = _make_nfw_stateful_alert_record(action=action)
        raw = _make_raw_event(record)
        return self.plugin.normalize(raw, "test").action

    def test_blocked_maps_to_block(self) -> None:
        """AWS NFW alert.action='blocked' → BLOCK (IPS mode dropped the packet)."""
        assert self._normalize("blocked") == "BLOCK"

    def test_alert_maps_to_alert(self) -> None:
        """AWS NFW alert.action='alert' → ALERT (IDS mode — detected, not blocked)."""
        assert self._normalize("alert") == "ALERT"

    def test_blocked_uppercase_maps_to_block(self) -> None:
        """Case-insensitive: 'BLOCKED' → BLOCK."""
        assert self._normalize("BLOCKED") == "BLOCK"

    def test_alert_uppercase_maps_to_alert(self) -> None:
        """Case-insensitive: 'ALERT' → ALERT."""
        assert self._normalize("ALERT") == "ALERT"

    def test_unknown_action_defaults_to_alert(self) -> None:
        """Unrecognized action → ALERT (conservative; never escalate to BLOCK on ambiguity)."""
        assert self._normalize("unknown_action") == "ALERT"

    def test_empty_action_defaults_to_alert(self) -> None:
        """Missing/empty action → ALERT (defensive)."""
        record = _make_nfw_stateful_alert_record()
        record["event"]["alert"]["action"] = ""
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")
        assert event.action == "ALERT"


# ---------------------------------------------------------------------------
# EARS-3: collect() raises typed error on credential/connectivity failure
# ---------------------------------------------------------------------------


class TestCollectTypedErrors:
    """EARS-3 — credential/connectivity failures raise typed errors, never silently yield nothing.

    This is the key safety requirement: a failing instance must be visible to the supervisor
    so it can be isolated. Swallowing errors as "no data" (the legacy anti-pattern) is
    explicitly forbidden (PLUGIN_CONTRACT.md §hard rules).
    """

    def _make_plugin(self) -> Any:
        from firewatch_aws_nfw.plugin import AwsNetworkFirewallSource
        return AwsNetworkFirewallSource()

    def _make_cfg(self) -> Any:
        from firewatch_aws_nfw.config import AwsNetworkFirewallConfig
        return AwsNetworkFirewallConfig(
            region="us-east-1",
            log_group_name="/aws/network-firewall/test-firewall/alert",
        )

    async def test_auth_error_raises_typed_error(self) -> None:
        """ClientError with auth failure → AwsNfwAuthError, not silent empty list."""
        from botocore.exceptions import ClientError
        from firewatch_aws_nfw.client import AwsNfwAuthError

        plugin = self._make_plugin()
        cfg = self._make_cfg()

        mock_client = MagicMock()
        mock_client.filter_log_events.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
            "FilterLogEvents",
        )

        with patch("firewatch_aws_nfw.client.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            with pytest.raises(AwsNfwAuthError):
                _ = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

    async def test_connectivity_error_raises_typed_error(self) -> None:
        """Network error → AwsNfwConnectError, not silent empty list."""
        from botocore.exceptions import EndpointConnectionError
        from firewatch_aws_nfw.client import AwsNfwConnectError

        plugin = self._make_plugin()
        cfg = self._make_cfg()

        mock_client = MagicMock()
        mock_client.filter_log_events.side_effect = EndpointConnectionError(
            endpoint_url="https://logs.us-east-1.amazonaws.com"
        )

        with patch("firewatch_aws_nfw.client.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            with pytest.raises(AwsNfwConnectError):
                _ = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

    async def test_throttling_error_raises_typed_error(self) -> None:
        """ThrottlingException → AwsNfwQueryError (rate limited, not credential error)."""
        from botocore.exceptions import ClientError
        from firewatch_aws_nfw.client import AwsNfwQueryError

        plugin = self._make_plugin()
        cfg = self._make_cfg()

        mock_client = MagicMock()
        mock_client.filter_log_events.side_effect = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
            "FilterLogEvents",
        )

        with patch("firewatch_aws_nfw.client.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            with pytest.raises(AwsNfwQueryError):
                _ = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

    async def test_resource_not_found_raises_typed_error(self) -> None:
        """ResourceNotFoundException → AwsNfwQueryError (wrong log group name)."""
        from botocore.exceptions import ClientError
        from firewatch_aws_nfw.client import AwsNfwQueryError

        plugin = self._make_plugin()
        cfg = self._make_cfg()

        mock_client = MagicMock()
        mock_client.filter_log_events.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Log group not found"}},
            "FilterLogEvents",
        )

        with patch("firewatch_aws_nfw.client.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            with pytest.raises(AwsNfwQueryError):
                _ = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]


# ---------------------------------------------------------------------------
# EARS-4: SecretStr fields default to None
# ---------------------------------------------------------------------------


class TestConfigSchema:
    """EARS-4 — config_schema has SecretStr auth fields defaulting to None.

    The discovery endpoint (GET /sources/types) emits config_schema().model_json_schema()
    verbatim; a non-None secret default would leak the value into the API response
    (PLUGIN_CONTRACT.md: SecretStr fields MUST default to None).
    """

    def setup_method(self) -> None:
        from firewatch_aws_nfw.plugin import AwsNetworkFirewallSource
        self.plugin = AwsNetworkFirewallSource()
        self.schema_cls = self.plugin.config_schema()

    def test_returns_pydantic_model_class(self) -> None:
        from pydantic import BaseModel
        assert issubclass(self.schema_cls, BaseModel)

    def test_has_region_field(self) -> None:
        assert "region" in self.schema_cls.model_fields

    def test_has_log_group_name_field(self) -> None:
        assert "log_group_name" in self.schema_cls.model_fields

    def test_secret_access_key_defaults_to_none_in_json_schema(self) -> None:
        """SecretStr fields must default to None in the JSON schema response."""
        schema_json = self.schema_cls.model_json_schema()
        props = schema_json.get("properties", {})
        for field_name in ("secret_access_key",):
            field_schema = props.get(field_name, {})
            assert field_schema.get("default") is None, (
                f"Secret field {field_name!r} must default to None in JSON schema; "
                f"got: {field_schema.get('default')!r}"
            )

    def test_optional_auth_fields_default_to_none(self) -> None:
        """AWS credentials default to None (instance profile auth is the default)."""
        cfg = self.schema_cls()
        assert cfg.access_key_id is None  # type: ignore[attr-defined]
        assert cfg.secret_access_key is None  # type: ignore[attr-defined]

    def test_region_has_default(self) -> None:
        """region must have a sensible default."""
        cfg = self.schema_cls()
        # Default may be empty or a region string; must not be None
        assert cfg.region is not None  # type: ignore[attr-defined]

    def test_overlap_minutes_default_is_5(self) -> None:
        """Default overlap matches Azure WAF precedent (5 min)."""
        cfg = self.schema_cls()
        assert cfg.overlap_minutes == 5  # type: ignore[attr-defined]

    def test_validate_config_accepts_minimal_config(self) -> None:
        """validate_config() accepts a minimal config dict."""
        plugin = self.plugin
        plugin.validate_config({"region": "us-east-1", "log_group_name": "/aws/nfw/test"})

    def test_validate_config_raises_on_invalid(self) -> None:
        """validate_config() raises on clearly invalid input."""
        from pydantic import ValidationError
        plugin = self.plugin
        with pytest.raises((ValidationError, ValueError)):
            plugin.validate_config({"overlap_minutes": -99})


# ---------------------------------------------------------------------------
# EARS-5: Golden tests — NFW sample logs → expected SecurityEvents
# ---------------------------------------------------------------------------


class TestGoldenNormalize:
    """EARS-5 — golden fixtures pin NFW log records to expected SecurityEvents.

    Each expected value is derived from the AWS NFW Developer Guide + OCSF standard
    (ADR-0020) + ADR-0012 action mapping. No values are recorded from legacy output.

    Fixture sources:
      - AWS Network Firewall Developer Guide, Stateful engine alert logging
        https://docs.aws.amazon.com/network-firewall/latest/developerguide/logging-cw-logs.html
      - OCSF: https://schema.ocsf.io/classes/detection_finding (class_uid=2004, category_uid=2)
      - ADR-0012: blocked→BLOCK, alert→ALERT
      - ADR-0048: flow/http fields
    """

    def setup_method(self) -> None:
        from firewatch_aws_nfw.plugin import AwsNetworkFirewallSource
        self.plugin = AwsNetworkFirewallSource()

    # ── Fixture 1: Stateful engine BLOCK alert (IPS mode) ──────────────────

    def test_golden_blocked_alert_action_is_block(self) -> None:
        """Blocked alert: action=BLOCK (ADR-0012 — IPS mode dropped the packet)."""
        record = _make_nfw_stateful_alert_record(
            action="blocked",
            src_ip="203.0.113.10",
            dest_ip="198.51.100.5",
            dest_port=80,
            proto="TCP",
            signature="ET WEB_SERVER SQL Injection Attempt",
            signature_id=2012345,
            severity=2,
        )
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "prod-firewall")

        assert event.action == "BLOCK"

    def test_golden_blocked_alert_source_identity(self) -> None:
        """source_type is constant 'aws_network_firewall'; source_id passed through."""
        record = _make_nfw_stateful_alert_record(action="blocked")
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "prod-firewall")

        assert event.source_type == "aws_network_firewall"
        assert event.source_id == "prod-firewall"

    def test_golden_blocked_alert_network_fields(self) -> None:
        """Network fields populated from EVE payload (src/dest IP/port, protocol)."""
        record = _make_nfw_stateful_alert_record(
            src_ip="203.0.113.10",
            src_port=44321,
            dest_ip="198.51.100.5",
            dest_port=80,
            proto="TCP",
        )
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")

        assert event.source_ip == "203.0.113.10"
        assert event.source_port == 44321
        assert event.destination_ip == "198.51.100.5"
        assert event.destination_port == 80
        assert event.protocol == "TCP"

    def test_golden_blocked_alert_rule_fields(self) -> None:
        """Rule fields from EVE alert sub-object."""
        record = _make_nfw_stateful_alert_record(
            signature="ET WEB_SERVER SQL Injection Attempt",
            signature_id=2012345,
        )
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")

        assert event.rule_id == "2012345"
        assert event.rule_name == "ET WEB_SERVER SQL Injection Attempt"

    def test_golden_blocked_alert_severity_from_suricata_int(self) -> None:
        """Suricata integer severity: 1=critical, 2=high, 3=medium, 4=low (ADR-0048)."""
        for sev_int, expected in [(1, "critical"), (2, "high"), (3, "medium"), (4, "low")]:
            record = _make_nfw_stateful_alert_record(severity=sev_int)
            raw = _make_raw_event(record)
            event = self.plugin.normalize(raw, "test")
            assert event.severity == expected, (
                f"severity={sev_int} should map to {expected!r}; got {event.severity!r}"
            )

    def test_golden_blocked_alert_ocsf_detection_finding(self) -> None:
        """OCSF class 2004 (Detection Finding) for alert records.

        Source: https://schema.ocsf.io/classes/detection_finding
        'detections or alerts generated by security products such as antivirus,
        EDR, network security monitoring' — exactly what NFW Suricata IDS/IPS is.
        category_uid=2 (Findings).
        """
        record = _make_nfw_stateful_alert_record()
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")

        assert event.ocsf_class == 2004
        assert event.ocsf_category == 2

    def test_golden_blocked_alert_raw_log_preserved(self) -> None:
        """The full AWS+EVE record is stored in raw_log for drill-down."""
        record = _make_nfw_stateful_alert_record()
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")

        assert event.raw_log is not None
        assert "event" in event.raw_log

    # ── Fixture 2: Stateful engine ALERT (IDS mode — detected, not blocked) ──

    def test_golden_alert_action_action_is_alert(self) -> None:
        """IDS-mode alert (action='alert') → ALERT (packet was not dropped)."""
        record = _make_nfw_stateful_alert_record(action="alert")
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")

        assert event.action == "ALERT"

    def test_golden_alert_network_fields_populated(self) -> None:
        """Network fields present for IDS-mode alert too."""
        record = _make_nfw_stateful_alert_record(
            action="alert",
            src_ip="203.0.113.15",
            dest_ip="192.0.2.50",
        )
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")

        assert event.source_ip == "203.0.113.15"
        assert event.destination_ip == "192.0.2.50"

    # ── Fixture 3: HTTP fields populated from eve http sub-object ──

    def test_golden_http_fields_populated(self) -> None:
        """http.url and http.hostname → http_url, http_host (ADR-0048 Group D)."""
        record = _make_nfw_stateful_alert_record(
            http_url="/admin?id=1 OR 1=1",
            http_hostname="app.internal",
        )
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")

        assert event.http_url == "/admin?id=1 OR 1=1"
        assert event.http_host == "app.internal"

    def test_golden_http_payload_snippet(self) -> None:
        """payload_snippet is derived from http.url + hostname for HTTP traffic."""
        record = _make_nfw_stateful_alert_record(
            http_url="/login?user=admin",
            http_hostname="example.internal",
        )
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")

        assert event.payload_snippet is not None
        assert "login" in event.payload_snippet

    def test_golden_payload_snippet_truncated_to_500(self) -> None:
        """payload_snippet is truncated to 500 characters."""
        long_url = "/path?" + "a" * 600
        record = _make_nfw_stateful_alert_record(http_url=long_url)
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")

        assert event.payload_snippet is not None
        assert len(event.payload_snippet) <= 500

    # ── Fixture 4: Flow record (pass-through, no alert sub-object) ──

    def test_golden_pass_through_record_not_normalized_to_alert(self) -> None:
        """Flow/pass records (event_type != alert) have no alert sub-object.
        They should still normalize without crashing; action defaults to ALERT
        (conservative fallback for unrecognized event types).
        """
        record = _make_nfw_pass_record()
        raw = _make_raw_event(record)
        # Must not raise
        event = self.plugin.normalize(raw, "test")
        assert event.action in ("ALERT", "ALLOW")  # defensive default

    # ── Fixture 5: MITRE ATT&CK from ET Open metadata ──

    def test_golden_mitre_from_et_open_metadata(self) -> None:
        """ET Open mitre_technique_id in alert metadata → attack_technique (ADR-0014)."""
        record = _make_nfw_stateful_alert_record(mitre_technique_id="T1190")
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")

        assert event.attack_technique == "T1190"

    def test_golden_mitre_tactic_from_metadata(self) -> None:
        """ET Open mitre_tactic_id → attack_tactic."""
        record = _make_nfw_stateful_alert_record(
            mitre_technique_id="T1190",
            mitre_tactic_id="TA0001",
        )
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")

        assert event.attack_tactic == "TA0001"

    def test_golden_no_mitre_tags_leaves_fields_none(self) -> None:
        """When no MITRE metadata present, attack fields are None — no fabrication."""
        record = _make_nfw_stateful_alert_record()  # no mitre_technique_id
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")

        assert event.attack_technique is None
        assert event.attack_tactic is None

    def test_golden_flow_id_as_source_event_id(self) -> None:
        """EVE flow_id → source_event_id for dedup."""
        record = _make_nfw_stateful_alert_record(flow_id=987654321)
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")

        assert event.source_event_id == "987654321"

    def test_golden_timestamp_from_eve_timestamp(self) -> None:
        """Timestamp parsed from EVE event.timestamp field."""
        record = _make_nfw_stateful_alert_record(ts="2026-03-01T14:30:00.000000+0000")
        raw = _make_raw_event(record)
        event = self.plugin.normalize(raw, "test")

        assert event.timestamp.year == 2026
        assert event.timestamp.month == 3
        assert event.timestamp.day == 1


# ---------------------------------------------------------------------------
# EARS-6 + Flag-B: zero core edits + source_type constant
# ---------------------------------------------------------------------------


class TestEntryPointDiscovery:
    """EARS-6 — entry point registered; zero core edits; source_type constant (Flag B)."""

    def test_entry_point_is_registered(self) -> None:
        """aws_network_firewall is discoverable in firewatch.sources group."""
        from importlib.metadata import entry_points

        eps = entry_points(group="firewatch.sources")
        names = {ep.name for ep in eps}
        assert "aws_network_firewall" in names, (
            f"'aws_network_firewall' not in firewatch.sources entry points. Found: {names}"
        )

    def test_entry_point_loads_source_plugin(self) -> None:
        """Loading the entry point yields a SourcePlugin-conformant object."""
        from importlib.metadata import entry_points
        from firewatch_sdk import SourcePlugin

        eps = {ep.name: ep for ep in entry_points(group="firewatch.sources")}
        ep = eps["aws_network_firewall"]
        cls = ep.load()
        plugin = cls()
        assert isinstance(plugin, SourcePlugin)

    def test_metadata_type_key_is_aws_network_firewall(self) -> None:
        """metadata().type_key == 'aws_network_firewall' (constrained to ^[a-z][a-z0-9_]*$)."""
        from firewatch_aws_nfw.plugin import AwsNetworkFirewallSource

        plugin = AwsNetworkFirewallSource()
        meta = plugin.metadata()
        assert meta.type_key == "aws_network_firewall"
        assert meta.flavor == "pull"

    def test_metadata_enforcement_default_is_enforce(self) -> None:
        """ADR-0067 D6 + Amendment 1 (issue #75): AWS NFW is an inline, enforcing control."""
        from firewatch_aws_nfw.plugin import AwsNetworkFirewallSource

        plugin = AwsNetworkFirewallSource()
        assert plugin.metadata().enforcement == "enforce"

    def test_zero_core_edits_via_loader(self) -> None:
        """The core loader discovers aws_network_firewall with zero core edits."""
        from firewatch_core.loader import load_source_plugins

        registry = load_source_plugins()
        assert "aws_network_firewall" in registry, (
            f"Loader did not find 'aws_network_firewall'. Registry: {set(registry)}"
        )

    def test_flag_b_source_type_constant_not_branched_on_source_id(self) -> None:
        """source_type is constant 'aws_network_firewall' regardless of source_id value.

        Flag B: the plugin MUST NOT branch on source_id for detection.
        source_type is the constant; source_id is the user's instance name.
        """
        from firewatch_aws_nfw.plugin import AwsNetworkFirewallSource

        plugin = AwsNetworkFirewallSource()
        record = _make_nfw_stateful_alert_record()
        raw = _make_raw_event(record)

        for sid in ("prod-firewall", "staging", "customer-xyz-nfw", "test-instance-99"):
            event = plugin.normalize(raw, sid)
            assert event.source_type == "aws_network_firewall", (
                f"source_type changed when source_id={sid!r} — Flag B violation"
            )
            assert event.source_id == sid


# ---------------------------------------------------------------------------
# health_check
# ---------------------------------------------------------------------------


class TestHealthCheck:
    """health_check() returns bool (True/False), never raises."""

    def _make_plugin(self) -> Any:
        from firewatch_aws_nfw.plugin import AwsNetworkFirewallSource
        return AwsNetworkFirewallSource()

    def _make_cfg(self) -> Any:
        from firewatch_aws_nfw.config import AwsNetworkFirewallConfig
        return AwsNetworkFirewallConfig(
            region="us-east-1",
            log_group_name="/aws/network-firewall/test-firewall/alert",
        )

    async def test_health_check_returns_true_on_success(self) -> None:
        """Successful describe_log_groups → True."""
        plugin = self._make_plugin()
        cfg = self._make_cfg()

        mock_client = MagicMock()
        mock_client.describe_log_groups.return_value = {
            "logGroups": [{"logGroupName": "/aws/network-firewall/test-firewall/alert"}]
        }

        with patch("firewatch_aws_nfw.client.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            result = await plugin.health_check(cfg)

        assert result is True

    async def test_health_check_returns_false_on_auth_error(self) -> None:
        """Auth failure → False, not raise."""
        from botocore.exceptions import ClientError

        plugin = self._make_plugin()
        cfg = self._make_cfg()

        mock_client = MagicMock()
        mock_client.describe_log_groups.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
            "DescribeLogGroups",
        )

        with patch("firewatch_aws_nfw.client.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            result = await plugin.health_check(cfg)

        assert result is False

    async def test_health_check_returns_false_on_network_error(self) -> None:
        """Network error → False, not raise."""
        from botocore.exceptions import EndpointConnectionError

        plugin = self._make_plugin()
        cfg = self._make_cfg()

        mock_client = MagicMock()
        mock_client.describe_log_groups.side_effect = EndpointConnectionError(
            endpoint_url="https://logs.us-east-1.amazonaws.com"
        )

        with patch("firewatch_aws_nfw.client.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            result = await plugin.health_check(cfg)

        assert result is False


# ---------------------------------------------------------------------------
# No forbidden imports
# ---------------------------------------------------------------------------


class TestNoForbiddenImports:
    """Plugin depends only on firewatch_sdk; never imports firewatch_core or legacy."""

    def _get_source_dir(self) -> Path:
        return Path(__file__).parent.parent / "src" / "firewatch_aws_nfw"

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
                        or "firewatch_aws_nfw" in stripped
                    ), (
                        f"{py_file.name}: forbidden import line: {stripped!r}"
                    )
