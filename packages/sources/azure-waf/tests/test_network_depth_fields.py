"""Tests — Azure WAF ADR-0048 network-depth field extraction (ML-2, #430).

EARS criteria covered:
  EARS-2  Azure WAF normalize() populates only the HTTP subset it actually carries
          and leaves flow/DNS/TLS/transport fields NULL (honest — documented).

Azure WAF HTTP field mapping (verified against MS Learn log shapes in fixtures/):
  http_url   <- properties.requestUri  (full request URI / URL)
  http_host  <- properties.hostname    (App Gateway) or properties.host (Front Door)

Azure WAF does NOT provide http_method or http_user_agent in WAF diagnostic logs.
Leaving those None is correct; fabricating them is the explicit anti-pattern
(PLUGIN_CONTRACT.md + azure-waf-log-standard.md §3 critique #5).

Flow/DNS/TLS fields are always None — Azure WAF is an L7 HTTP gateway; it has no
access to transport-layer flow statistics, DNS queries, or TLS handshake details.

IP addresses use RFC 5737 documentation ranges only (gitleaks public-ipv4 rule).
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
from typing import Any

import pytest

from firewatch_sdk import RawEvent
from firewatch_azure_waf.normalize import normalize

_FIXTURES_DIR = Path(__file__).parent / "fixtures"
_RECEIVED_AT = datetime(2026, 1, 15, 0, 0, 0, tzinfo=timezone.utc)


def _raw(filename: str) -> RawEvent:
    data = json.loads((_FIXTURES_DIR / filename).read_text())
    return RawEvent(source_type="azure_waf", received_at=_RECEIVED_AT, data=data)


def _norm(filename: str) -> Any:
    return normalize(_raw(filename), source_id="test-waf")


# ── EARS-2: HTTP fields populated ─────────────────────────────────────────────


class TestAppGatewayHttpFields:
    """App Gateway: http_url from requestUri, http_host from hostname (ADR-0048 Group D)."""

    def test_http_url_from_request_uri(self) -> None:
        """http_url <- properties.requestUri (App Gateway, ADR-0048 Group D)."""
        event = _norm("app_gateway_942100_sqli_log.json")
        assert event.http_url == "/api/users?id=1%20OR%201%3D1", (
            f"http_url must be properties.requestUri; got {event.http_url!r}"
        )

    def test_http_host_from_hostname_field(self) -> None:
        """http_host <- properties.hostname (App Gateway, ADR-0048 Group D, ECS url.domain)."""
        event = _norm("app_gateway_942100_sqli_log.json")
        assert event.http_host == "192.0.2.2", (
            f"http_host must be properties.hostname; got {event.http_host!r}"
        )

    def test_http_url_populated_for_rce_block(self) -> None:
        """http_url from requestUri on a BLOCK event (not just LOG)."""
        event = _norm("app_gateway_932100_rce_block.json")
        assert event.http_url == "/api/exec?cmd=ls+-la", (
            f"http_url must be properties.requestUri on block; got {event.http_url!r}"
        )

    def test_http_host_from_hostname_rce(self) -> None:
        """http_host from properties.hostname on the RCE fixture."""
        event = _norm("app_gateway_932100_rce_block.json")
        assert event.http_host == "192.0.2.1", (
            f"http_host must be properties.hostname; got {event.http_host!r}"
        )

    def test_http_url_for_xss_detected(self) -> None:
        """http_url from requestUri on XSS detected fixture."""
        event = _norm("app_gateway_941100_xss_detected.json")
        assert event.http_url == "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", (
            f"http_url must be properties.requestUri; got {event.http_url!r}"
        )

    def test_http_host_xss_detected(self) -> None:
        """http_host from properties.hostname on XSS fixture."""
        event = _norm("app_gateway_941100_xss_detected.json")
        assert event.http_host == "192.0.2.10", (
            f"http_host must be properties.hostname; got {event.http_host!r}"
        )


class TestFrontDoorHttpFields:
    """Front Door: http_url from requestUri, http_host from host (ADR-0048 Group D).

    Front Door uses 'host' (lowercase) not 'hostname'. The requestUri on Front Door
    is the full URL including scheme and host (different from App Gateway).
    """

    def test_http_url_from_request_uri_front_door(self) -> None:
        """http_url <- properties.requestUri (Front Door, full URL)."""
        event = _norm("front_door_942100_sqli_block.json")
        assert event.http_url == "https://app.example.azurefd.net:443/?q=%27%20or%201%3D1", (
            f"http_url must be properties.requestUri (full URL on FD); got {event.http_url!r}"
        )

    def test_http_host_from_host_field_front_door(self) -> None:
        """http_host <- properties.host (Front Door uses 'host', not 'hostname').

        Front Door WAF logs carry the Host header in the 'host' field (lowercase),
        while App Gateway uses 'hostname'. Normalize() must handle both.
        """
        event = _norm("front_door_942100_sqli_block.json")
        assert event.http_host == "app.example.azurefd.net", (
            f"http_host must be properties.host on Front Door; got {event.http_host!r}"
        )

    def test_http_url_scanner_log(self) -> None:
        """http_url from requestUri on Front Door scanner log fixture."""
        event = _norm("front_door_913110_scanner_log.json")
        assert event.http_url == "https://app.example.azurefd.net/admin/.env", (
            f"http_url must be properties.requestUri; got {event.http_url!r}"
        )

    def test_http_host_scanner_log(self) -> None:
        """http_host from properties.host on Front Door scanner log."""
        event = _norm("front_door_913110_scanner_log.json")
        assert event.http_host == "app.example.azurefd.net", (
            f"http_host must be properties.host; got {event.http_host!r}"
        )


# ── EARS-2: no fabricated fields — method/UA/flow/DNS/TLS are always None ─────


class TestAzureWafNoFabricatedDepthFields:
    """EARS-2: Azure WAF must leave http_method, http_user_agent, and all
    flow/DNS/TLS fields as None (honest — WAF logs don't carry these).

    This is the no-fabrication invariant: setting these from WAF logs would be
    incorrect because they are not available in Azure WAF diagnostic data.
    """

    @pytest.mark.parametrize("fixture_file", [
        "app_gateway_920350_matched.json",
        "app_gateway_941100_xss_detected.json",
        "app_gateway_932100_rce_block.json",
        "app_gateway_913100_scanner_allowed.json",
        "app_gateway_942100_sqli_log.json",
        "front_door_942100_sqli_block.json",
        "front_door_941100_xss_anomalyscoring.json",
        "front_door_913110_scanner_log.json",
    ])
    def test_http_method_always_none(self, fixture_file: str) -> None:
        """http_method is always None — Azure WAF logs don't carry the HTTP method.

        EARS-2: Azure WAF populates ONLY the HTTP subset it genuinely has.
        http_method is not present in WAF diagnostic logs; fabricating 'GET' or 'POST'
        would be incorrect (no-fabrication rule, PLUGIN_CONTRACT.md).
        """
        event = _norm(fixture_file)
        assert event.http_method is None, (
            f"{fixture_file}: http_method must be None — not available in Azure WAF logs; "
            f"got {event.http_method!r}. Do not fabricate."
        )

    @pytest.mark.parametrize("fixture_file", [
        "app_gateway_920350_matched.json",
        "app_gateway_941100_xss_detected.json",
        "app_gateway_932100_rce_block.json",
        "app_gateway_913100_scanner_allowed.json",
        "app_gateway_942100_sqli_log.json",
        "front_door_942100_sqli_block.json",
        "front_door_941100_xss_anomalyscoring.json",
        "front_door_913110_scanner_log.json",
    ])
    def test_http_user_agent_always_none(self, fixture_file: str) -> None:
        """http_user_agent is always None — not in Azure WAF diagnostic logs."""
        event = _norm(fixture_file)
        assert event.http_user_agent is None, (
            f"{fixture_file}: http_user_agent must be None — not in WAF logs; "
            f"got {event.http_user_agent!r}. Do not fabricate."
        )

    @pytest.mark.parametrize("fixture_file", [
        "app_gateway_942100_sqli_log.json",
        "front_door_942100_sqli_block.json",
    ])
    def test_flow_dns_tls_always_none(self, fixture_file: str) -> None:
        """All flow/DNS/TLS fields are always None for Azure WAF (L7 HTTP gateway).

        EARS-2: Azure WAF is a Layer 7 HTTP gateway; it has no access to transport
        flow statistics, DNS queries, or TLS fingerprint data. These must be None.
        """
        event = _norm(fixture_file)
        transport_depth_fields = [
            "bytes_in", "bytes_out", "packets_in", "packets_out", "flow_duration_ms",
            "dns_query", "dns_rcode",
            "tls_ja4", "tls_ja4s", "tls_sni", "tls_version",
        ]
        for field in transport_depth_fields:
            val = getattr(event, field)
            assert val is None, (
                f"{fixture_file}: {field!r} must be None — Azure WAF (L7 HTTP gateway) "
                f"has no transport-layer data; got {val!r}. Do not fabricate."
            )


# ── EARS-2: http_url/http_host null when absent from record ───────────────────


class TestAzureWafHttpUrlHostNull:
    """EARS-2 + EARS-5 analog: if a fixture lacks requestUri/hostname, fields are None.

    Tests with a minimal record that omits those fields — normalize() must not crash.
    """

    def test_minimal_record_no_request_uri(self) -> None:
        """normalize() with no requestUri -> http_url is None (no crash)."""
        minimal = {
            "time": "2026-01-15T10:00:00Z",
            "properties": {
                "clientIp": "198.51.100.5",
                "ruleId": "942100",
                "action": "Block",
            },
        }
        raw = RawEvent(source_type="azure_waf", received_at=_RECEIVED_AT, data=minimal)
        event = normalize(raw, source_id="test-waf")
        assert event.http_url is None, f"http_url must be None when requestUri absent; got {event.http_url!r}"
        assert event.http_host is None, f"http_host must be None when hostname/host absent; got {event.http_host!r}"
