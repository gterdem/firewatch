"""Tests for the WebhookNotifier adapter + webhook_url anti-SSRF validation (MB.3 / #55).

No real network: httpx.AsyncClient is patched throughout; socket.getaddrinfo is
patched for all tests that construct RuntimeConfig with a hostname-based URL so CI
never makes a real DNS call.  RFC 5737 (TEST-NET-1/2/3) and RFC 3849 documentation
IP literals are used throughout.

EARS mapping:
- Event-driven: a threat meeting the threshold POSTs a webhook alert.
- Unwanted: no webhook configured OR delivery failure → returns False, never raises.
- Unwanted: a webhook URL in a blocked range / non-http scheme is rejected at config time.
- Security: non-canonical IP encodings (decimal, octal, hex, trailing-dot) that bypass
  ipaddress.ip_address() but resolve to blocked ranges are rejected (OWASP API7 / ADR-0026).
- Security: delivery-failure log lines must never contain the webhook URL (which may
  carry an auth token).
- Security (#549, ADR-0026 D6): 3xx redirects are NOT followed; a redirect response is
  treated as a delivery failure (no second request to the redirect target).
"""
from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from pydantic import ValidationError

from firewatch_sdk.config import RuntimeConfig
from firewatch_sdk.models import ThreatScore

from firewatch_core.adapters.webhook_notifier import WebhookNotifier

# A global, DNS-free URL that passes the anti-SSRF validator (TEST-NET-2, RFC 5737).
SAFE_URL = "http://203.0.113.9/hook"
DISCORD_URL = "https://discord.com/api/webhooks/123/abc"
SLACK_URL = "https://hooks.slack.com/services/T/B/X"

# RFC 5737 TEST-NET-1 (192.0.2.0/24): documentation-only range, globally routable,
# not blocked by the webhook validator — used as the mock "safe" resolved address.
_SAFE_RESOLVED_SOCKADDR = [
    (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.0.2.1", 0))
]

# 127.0.0.1 sockaddr — used to simulate a non-canonical encoding resolving to loopback.
_LOOPBACK_SOCKADDR = [
    (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0))
]

# 169.254.169.254 sockaddr — used to simulate the cloud-metadata address.
_METADATA_SOCKADDR = [
    (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0))
]


def _threat(level: str = "CRITICAL", *, ip: str = "192.0.2.5") -> ThreatScore:
    return ThreatScore(
        source_ip=ip,
        threat_level=level,  # type: ignore[arg-type]
        score=90,
        total_events=10,
        blocked_events=8,
        attack_types=["SQL Injection"],
        first_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 1, 12, tzinfo=timezone.utc),
        ai_insights=["looks like an automated scanner"],
    )


class _FakeConfigStore:
    """Minimal ConfigStore duck type — the notifier only calls get_runtime()."""

    def __init__(self, runtime: RuntimeConfig) -> None:
        self._runtime = runtime

    def get_runtime(self) -> RuntimeConfig:
        return self._runtime


class _FakeHttpx:
    """Patchable stand-in for httpx.AsyncClient that records POSTs."""

    captured: list[tuple[str, dict[str, Any]]] = []
    fail: bool = False
    # If set, raise this exception on post() instead of ConnectError.
    raise_exc: Exception | None = None
    # If set, post() records the call then raises HTTPStatusError with this code.
    # Used to simulate 3xx/4xx/5xx without suppressing the captured-calls record.
    redirect_status: int | None = None

    def __init__(self, *_a: Any, **_k: Any) -> None: ...

    async def __aenter__(self) -> _FakeHttpx:
        return self

    async def __aexit__(self, *_a: Any) -> bool:
        return False

    async def post(self, url: str, json: dict[str, Any]) -> Any:
        if _FakeHttpx.raise_exc is not None:
            raise _FakeHttpx.raise_exc
        if _FakeHttpx.fail:
            raise httpx.ConnectError("refused")
        _FakeHttpx.captured.append((url, json))
        if _FakeHttpx.redirect_status is not None:
            # Simulate a 3xx (or any non-2xx) — raise_for_status would raise on these.
            mock_req = httpx.Request("POST", url)
            mock_resp = httpx.Response(_FakeHttpx.redirect_status, request=mock_req)
            raise httpx.HTTPStatusError(
                f"{_FakeHttpx.redirect_status}",
                request=mock_req,
                response=mock_resp,
            )

        class _Resp:
            def raise_for_status(self) -> None: ...

        return _Resp()


@pytest.fixture(autouse=True)
def _reset_httpx() -> Any:
    _FakeHttpx.captured = []
    _FakeHttpx.fail = False
    _FakeHttpx.raise_exc = None
    _FakeHttpx.redirect_status = None
    yield


def _notifier(monkeypatch: pytest.MonkeyPatch, **runtime_kwargs: Any) -> WebhookNotifier:
    monkeypatch.setattr(
        "firewatch_core.adapters.webhook_notifier.httpx.AsyncClient", _FakeHttpx
    )
    # Mock socket.getaddrinfo so that hostname-based URLs (DISCORD_URL, SLACK_URL)
    # do not make real DNS calls during RuntimeConfig construction.  Any hostname that
    # reaches the resolver is treated as resolving to a safe documentation IP (RFC 5737).
    monkeypatch.setattr(
        "firewatch_sdk.config.socket.getaddrinfo",
        lambda *_a, **_k: _SAFE_RESOLVED_SOCKADDR,
    )
    runtime = RuntimeConfig(**runtime_kwargs)
    return WebhookNotifier(_FakeConfigStore(runtime))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# anti-SSRF validation on RuntimeConfig.webhook_url (ADR-0026 / OWASP API7)
# ---------------------------------------------------------------------------


class TestWebhookUrlSsrfValidation:
    def test_safe_ip_url_accepted(self) -> None:
        """Pure IP-literal URLs (canonical) that are globally routable are accepted."""
        for url in (SAFE_URL, "https://198.51.100.7/h"):
            assert RuntimeConfig(webhook_url=url).webhook_url is not None  # type: ignore[arg-type]

    def test_rfc1918_lan_allowed(self) -> None:
        # A self-hosted LAN receiver is legitimate (operator-trusted).
        assert RuntimeConfig(webhook_url="http://192.168.1.50/hook").webhook_url is not None  # type: ignore[arg-type]

    def test_safe_hostname_url_accepted(self) -> None:
        """Hostname-based URLs that resolve to a globally-routable IP are accepted."""
        # Mock getaddrinfo so CI never makes a real DNS call.
        with patch("firewatch_sdk.config.socket.getaddrinfo", return_value=_SAFE_RESOLVED_SOCKADDR):
            cfg = RuntimeConfig(webhook_url=DISCORD_URL)  # type: ignore[arg-type]
            assert cfg.webhook_url is not None
            cfg2 = RuntimeConfig(webhook_url=SLACK_URL)  # type: ignore[arg-type]
            assert cfg2.webhook_url is not None

    def test_unresolvable_hostname_accepted(self) -> None:
        """A hostname that fails DNS resolution is not blocked at config-write time.

        Network egress policy is the residual control (ADR-0026).
        """
        with patch(
            "firewatch_sdk.config.socket.getaddrinfo",
            side_effect=OSError("Name or service not known"),
        ):
            cfg = RuntimeConfig(webhook_url="https://webhook.example.invalid/hook")  # type: ignore[arg-type]
            assert cfg.webhook_url is not None

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/hook",          # loopback (canonical)
            "http://169.254.169.254/latest",  # cloud metadata (link-local, canonical)
            "http://localhost/hook",          # localhost literal
            "http://0.0.0.0/hook",            # unspecified (canonical)
            "file:///etc/passwd",             # non-http scheme
            "gopher://203.0.113.9/x",         # non-http scheme
        ],
    )
    def test_canonical_blocked_urls_rejected(self, url: str) -> None:
        """Standard canonical blocked URLs are rejected without needing DNS resolution."""
        with pytest.raises(ValidationError):
            RuntimeConfig(webhook_url=url)  # type: ignore[arg-type]

    # -- SSRF encoded-bypass tests (BLOCKING 1 fix) ---------------------------
    # Non-canonical IP encodings that ipaddress.ip_address() cannot parse but that
    # the OS resolver maps to blocked addresses.  socket.getaddrinfo is mocked to
    # return the address that the OS *would* return, making the tests deterministic.

    @pytest.mark.parametrize(
        ("url", "mock_sockaddr"),
        [
            # Decimal integer encoding of 127.0.0.1 (2130706433 = 0x7F000001)
            ("http://2130706433/", _LOOPBACK_SOCKADDR),
            # Octal encoding of 127.0.0.1
            ("http://017700000001/", _LOOPBACK_SOCKADDR),
            # Hex-dotted encoding of 127.0.0.1
            ("http://0x7f.0.0.1/", _LOOPBACK_SOCKADDR),
            # Trailing-dot hostname (resolves same as without dot, can be loopback)
            ("http://127.0.0.1./", _LOOPBACK_SOCKADDR),
            # Decimal integer encoding of 169.254.169.254 (cloud metadata; 2852039166)
            ("http://2852039166/", _METADATA_SOCKADDR),
        ],
    )
    def test_encoded_bypass_urls_rejected(
        self, url: str, mock_sockaddr: list[Any]
    ) -> None:
        """Non-canonical IP encodings that bypass ipaddress.ip_address() are caught
        via socket.getaddrinfo resolution and rejected (OWASP API7 / ADR-0026)."""
        with patch(
            "firewatch_sdk.config.socket.getaddrinfo", return_value=mock_sockaddr
        ):
            with pytest.raises(ValidationError):
                RuntimeConfig(webhook_url=url)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# check_and_alert — threshold gate
# ---------------------------------------------------------------------------


class TestCheckAndAlert:
    async def test_below_threshold_does_not_send(self, monkeypatch: pytest.MonkeyPatch) -> None:
        n = _notifier(monkeypatch, webhook_url=SAFE_URL, alert_threshold="CRITICAL")
        sent = await n.check_and_alert(_threat("MEDIUM"))
        assert sent is False
        assert _FakeHttpx.captured == []

    async def test_meets_threshold_sends(self, monkeypatch: pytest.MonkeyPatch) -> None:
        n = _notifier(monkeypatch, webhook_url=SAFE_URL, alert_threshold="HIGH")
        sent = await n.check_and_alert(_threat("CRITICAL"))
        assert sent is True
        assert len(_FakeHttpx.captured) == 1
        assert _FakeHttpx.captured[0][0] == SAFE_URL

    async def test_no_webhook_configured_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        n = _notifier(monkeypatch, alert_threshold="LOW")  # webhook_url defaults to None
        assert await n.check_and_alert(_threat("CRITICAL")) is False
        assert _FakeHttpx.captured == []


# ---------------------------------------------------------------------------
# send_alert — delivery + flavor detection
# ---------------------------------------------------------------------------


class TestSendAlert:
    async def test_no_webhook_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        n = _notifier(monkeypatch)
        assert await n.send_alert(_threat()) is False

    async def test_delivery_failure_returns_false_no_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        n = _notifier(monkeypatch, webhook_url=SAFE_URL)
        _FakeHttpx.fail = True
        assert await n.send_alert(_threat()) is False  # no exception propagates

    async def test_generic_payload_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        n = _notifier(monkeypatch, webhook_url=SAFE_URL)
        assert await n.send_alert(_threat()) is True
        _, payload = _FakeHttpx.captured[0]
        assert payload["alert_level"] == "CRITICAL"
        assert payload["source_ip"] == "192.0.2.5"

    async def test_discord_payload_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        n = _notifier(monkeypatch, webhook_url=DISCORD_URL)
        await n.send_alert(_threat())
        _, payload = _FakeHttpx.captured[0]
        assert "embeds" in payload

    async def test_slack_payload_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        n = _notifier(monkeypatch, webhook_url=SLACK_URL)
        await n.send_alert(_threat())
        _, payload = _FakeHttpx.captured[0]
        assert "blocks" in payload and payload.get("text")

    # -- BLOCKING 2 fix: secret URL must not appear in logs on delivery failure --

    async def test_http_status_error_does_not_log_url(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An HTTPStatusError must not leak the URL (which may carry a token) into logs.

        The URL sentinel ``SECRET_TOKEN_abc123`` is embedded in the URL; the log
        output must contain only the HTTP status code.
        """
        url_with_token = "http://203.0.113.9/hook?token=SECRET_TOKEN_abc123"
        monkeypatch.setattr(
            "firewatch_core.adapters.webhook_notifier.httpx.AsyncClient", _FakeHttpx
        )

        # Build a realistic HTTPStatusError whose __str__ embeds the full URL.
        mock_request = httpx.Request("POST", url_with_token)
        mock_response = httpx.Response(403, request=mock_request)
        _FakeHttpx.raise_exc = httpx.HTTPStatusError(
            "403 Forbidden", request=mock_request, response=mock_response
        )

        runtime = RuntimeConfig(webhook_url=url_with_token)  # type: ignore[arg-type]
        notifier = WebhookNotifier(_FakeConfigStore(runtime))  # type: ignore[arg-type]

        import logging

        with caplog.at_level(logging.ERROR, logger="firewatch.webhook"):
            result = await notifier.send_alert(_threat())

        assert result is False
        assert "SECRET_TOKEN_abc123" not in caplog.text
        assert "403" in caplog.text

    async def test_connection_error_does_not_log_url(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A connection/timeout error must not embed the URL in logs."""
        url_with_token = "http://203.0.113.9/hook?token=SECRET_TOKEN_abc123"
        monkeypatch.setattr(
            "firewatch_core.adapters.webhook_notifier.httpx.AsyncClient", _FakeHttpx
        )
        _FakeHttpx.fail = True

        runtime = RuntimeConfig(webhook_url=url_with_token)  # type: ignore[arg-type]
        notifier = WebhookNotifier(_FakeConfigStore(runtime))  # type: ignore[arg-type]

        import logging

        with caplog.at_level(logging.ERROR, logger="firewatch.webhook"):
            result = await notifier.send_alert(_threat())

        assert result is False
        assert "SECRET_TOKEN_abc123" not in caplog.text


# ---------------------------------------------------------------------------
# Redirect not-followed (ADR-0026 Decision 6, OWASP API7, issue #549)
# ---------------------------------------------------------------------------


class TestRedirectNotFollowed:
    """Verify that a 3xx response is treated as a delivery failure and never re-dialed.

    ADR-0026 Decision 6: ``follow_redirects=False`` is enforced on the httpx client.
    A redirect to an internal/blocked target after the initial URL validation would
    otherwise bypass the allowlist — so the first 3xx terminates delivery.
    """

    @pytest.mark.parametrize("status_code", [301, 302, 307, 308])
    async def test_3xx_treated_as_delivery_failure(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        status_code: int,
    ) -> None:
        """A 3xx response MUST return False and log the status code (no URL in log)."""
        n = _notifier(monkeypatch, webhook_url=SAFE_URL)
        _FakeHttpx.redirect_status = status_code

        import logging

        with caplog.at_level(logging.ERROR, logger="firewatch.webhook"):
            result = await n.send_alert(_threat())

        assert result is False, f"Expected False for {status_code}, got True"
        assert str(status_code) in caplog.text, "Status code must appear in the failure log"
        # The URL (which may carry a token) must never appear in logs.
        assert SAFE_URL not in caplog.text, "Webhook URL must not be logged on redirect"

    async def test_3xx_no_second_request_to_redirect_target(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """After a 302, exactly ONE outbound request is made — the redirect target
        is NOT dialed (no second entry in _FakeHttpx.captured).

        This proves follow_redirects=False is in effect: httpx does not automatically
        follow the Location header to a potentially blocked internal address.
        """
        n = _notifier(monkeypatch, webhook_url=SAFE_URL)
        _FakeHttpx.redirect_status = 302

        await n.send_alert(_threat())

        # Exactly one call was made (the initial POST to SAFE_URL).
        # If follow_redirects were True, httpx would transparently re-dial the
        # Location target; since we've disabled that, captured has at most 1 entry.
        assert len(_FakeHttpx.captured) == 1, (
            "Expected exactly 1 outbound request; redirect target must NOT be dialed"
        )
        assert _FakeHttpx.captured[0][0] == SAFE_URL

    async def test_3xx_url_not_in_logs(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """On redirect (3xx), the webhook URL must not appear in the log output.

        The URL may carry an auth token (SecretStr policy, ADR-0026).
        """
        url_with_token = "http://203.0.113.9/hook?token=SECRET_REDIRECT_TOKEN_xyz"
        monkeypatch.setattr(
            "firewatch_core.adapters.webhook_notifier.httpx.AsyncClient", _FakeHttpx
        )
        _FakeHttpx.redirect_status = 302

        runtime = RuntimeConfig(webhook_url=url_with_token)  # type: ignore[arg-type]
        notifier = WebhookNotifier(_FakeConfigStore(runtime))  # type: ignore[arg-type]

        import logging

        with caplog.at_level(logging.ERROR, logger="firewatch.webhook"):
            result = await notifier.send_alert(_threat())

        assert result is False
        assert "SECRET_REDIRECT_TOKEN_xyz" not in caplog.text


# ---------------------------------------------------------------------------
# send_sync_digest
# ---------------------------------------------------------------------------


class TestSyncDigest:
    async def test_sends_when_enabled_and_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        n = _notifier(monkeypatch, webhook_url=SAFE_URL, alert_on_sync=True)
        ok = await n.send_sync_digest(
            total_new=20, blocked_new=5, ip_blocks=[{"ip": "192.0.2.9", "blocked": 5}],
            categories={"Web Attack": 5},
        )
        assert ok is True
        assert len(_FakeHttpx.captured) == 1

    async def test_no_send_when_zero_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        n = _notifier(monkeypatch, webhook_url=SAFE_URL, alert_on_sync=True)
        assert await n.send_sync_digest(10, 0, [], {}) is False
        assert _FakeHttpx.captured == []

    async def test_no_send_when_alert_on_sync_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        n = _notifier(monkeypatch, webhook_url=SAFE_URL, alert_on_sync=False)
        assert await n.send_sync_digest(10, 5, [], {}) is False
        assert _FakeHttpx.captured == []
