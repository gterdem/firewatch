"""Tests for issue #385 (MI-4) — zero-egress assertion for the air-gapped config.

EARS criteria covered:

  Z1  WHEN geo_provider=offline and both MMDB files are present, the offline geo
      enricher SHALL make NO HTTP or socket connects during a representative
      enrich cycle. Validated by monkeypatching socket.socket.connect and
      httpx.AsyncClient to raise on any attempt.

  Z2  WHEN the offline pipeline path is configured (offline geo + no webhook),
      a full enrich cycle completes successfully with NO unexpected outbound
      socket connections.

  Z3  WHEN geo_provider=offline and both MMDB files are present, the enricher
      SHALL NOT call httpx.AsyncClient at all (no HTTP client instantiated).

  Z4  WHEN geo_provider=offline and both MMDB files are present, the enricher
      SHALL NOT call socket.socket.connect to any external address.

  Z5  WHEN webhook_url is None (the default), the WebhookNotifier SHALL make
      no outbound HTTP calls during send_alert() or check_and_alert().

  Z6  WHEN geo_provider=offline and DBs are present, the first-run fetch
      code path (ensure_dbs) is NOT entered at all — confirming the
      download guard works correctly.

Design: all assertions are component-level (no full pipeline spin-up), fast,
and deterministic. No real network calls are made.

RFC 5737 IPs only: 192.0.2.x, 198.51.100.x, 203.0.113.x.
The is_non_public guard treats these as non-global; tests that exercise the
"public IP gets resolved" path patch is_non_public to return False for them.
"""
from __future__ import annotations

import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from firewatch_sdk.models import SecurityEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _evt(
    source_ip: str = "192.0.2.1",
    source_type: str = "suricata",
) -> SecurityEvent:
    return SecurityEvent(
        source_type=source_type,
        source_id="sensor-01",
        source_ip=source_ip,
        action="ALERT",
        timestamp=datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
    )


def _make_store(ips_without_geo: list[str] | None = None) -> AsyncMock:
    """Return an AsyncMock EventStore pre-loaded with the given IPs needing geo."""
    store = AsyncMock()
    store.get_ips_without_geo = AsyncMock(return_value=ips_without_geo or [])
    store.upsert_ip_geo = AsyncMock()
    return store


def _make_city_record(
    country: str = "Canada",
    city: str = "Toronto",
    lat: float = 43.7,
    lon: float = -79.4,
) -> dict[str, Any]:
    return {
        "country": {"names": {"en": country}},
        "city": {"names": {"en": city}},
        "location": {"latitude": lat, "longitude": lon},
    }


def _make_asn_record(asn: int = 7018, as_name: str = "AS-TEST") -> dict[str, Any]:
    return {
        "autonomous_system_number": asn,
        "autonomous_system_organization": as_name,
    }


def _make_mock_reader(record: dict[str, Any] | None) -> MagicMock:
    reader = MagicMock()
    reader.get.return_value = record
    return reader


def _make_threat_score(source_ip: str = "192.0.2.1") -> Any:
    """Return a valid ThreatScore for notifier tests."""
    from firewatch_sdk.models import ThreatScore

    return ThreatScore(
        source_ip=source_ip,
        score=85,
        threat_level="HIGH",
        total_events=20,
        blocked_events=15,
        attack_types=["reconnaissance"],
        ai_status="active",
        ai_insights=["Port scan pattern"],
        first_seen=datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 6, 1, 12, 5, tzinfo=timezone.utc),
    )


# ---------------------------------------------------------------------------
# Z3 — MmdbGeoEnricher does NOT call httpx.AsyncClient when DBs are present
# ---------------------------------------------------------------------------


class TestNoHttpClientInstantiated:
    """Z3 — no httpx.AsyncClient is instantiated during offline enrich."""

    async def test_no_httpx_async_client_created(self, tmp_path: Path) -> None:
        """httpx.AsyncClient must never be called when geo_provider=offline + DBs present."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake_city")
        asn_path.write_bytes(b"fake_asn")

        city_reader = _make_mock_reader(_make_city_record())
        asn_reader = _make_mock_reader(_make_asn_record())
        store = _make_store(["192.0.2.1"])

        enricher = MmdbGeoEnricher(
            store=store, city_db_path=city_path, asn_db_path=asn_path
        )

        with (
            patch(
                "firewatch_core.adapters.geo_mmdb.maxminddb.open_database",
                side_effect=[city_reader, asn_reader],
            ),
            patch(
                "firewatch_core.adapters.geo_mmdb.is_non_public", return_value=False
            ),
            patch("httpx.AsyncClient") as mock_async_client,
        ):
            await enricher.enrich([_evt("192.0.2.1")])

        assert mock_async_client.call_count == 0, (
            "httpx.AsyncClient must not be instantiated during offline geo enrich"
        )

    async def test_no_httpx_client_created(self, tmp_path: Path) -> None:
        """httpx.Client (sync) must not be instantiated during offline enrich."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake_city")
        asn_path.write_bytes(b"fake_asn")

        city_reader = _make_mock_reader(_make_city_record())
        asn_reader = _make_mock_reader(_make_asn_record())
        store = _make_store(["192.0.2.1"])

        enricher = MmdbGeoEnricher(
            store=store, city_db_path=city_path, asn_db_path=asn_path
        )

        with (
            patch(
                "firewatch_core.adapters.geo_mmdb.maxminddb.open_database",
                side_effect=[city_reader, asn_reader],
            ),
            patch(
                "firewatch_core.adapters.geo_mmdb.is_non_public", return_value=False
            ),
            patch("httpx.Client") as mock_sync_client,
        ):
            await enricher.enrich([_evt("192.0.2.1")])

        assert mock_sync_client.call_count == 0, (
            "httpx.Client must not be instantiated during offline geo enrich"
        )


# ---------------------------------------------------------------------------
# Z4 — No socket.connect called during offline enrich
# ---------------------------------------------------------------------------


class TestNoSocketConnect:
    """Z4 — socket.socket.connect is never called during the offline enrich cycle."""

    async def test_no_socket_connect_during_offline_enrich(
        self, tmp_path: Path
    ) -> None:
        """socket.socket.connect must not be called at all during offline enrich.

        We monkeypatch socket.socket.connect to raise on any call. The test
        asserts the enricher completes successfully AND the mock was never called.
        This is the strongest possible assertion: if any code in the enrich path
        tried to open a socket connection, the test would fail immediately.
        """
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake_city")
        asn_path.write_bytes(b"fake_asn")

        city_reader = _make_mock_reader(_make_city_record())
        asn_reader = _make_mock_reader(_make_asn_record())
        store = _make_store(["192.0.2.1"])

        enricher = MmdbGeoEnricher(
            store=store, city_db_path=city_path, asn_db_path=asn_path
        )

        connect_calls: list[Any] = []

        def _fail_on_connect(self_sock: Any, address: Any) -> None:
            connect_calls.append(address)
            raise ConnectionRefusedError(
                f"Zero-egress assertion: unexpected socket.connect({address!r}) "
                "during offline geo enrich cycle"
            )

        with (
            patch(
                "firewatch_core.adapters.geo_mmdb.maxminddb.open_database",
                side_effect=[city_reader, asn_reader],
            ),
            patch(
                "firewatch_core.adapters.geo_mmdb.is_non_public", return_value=False
            ),
            patch.object(socket.socket, "connect", _fail_on_connect),
        ):
            result = await enricher.enrich([_evt("192.0.2.1")])

        assert connect_calls == [], (
            f"Expected zero socket.connect calls during offline enrich; "
            f"got: {connect_calls}"
        )
        assert result == [_evt("192.0.2.1")]


# ---------------------------------------------------------------------------
# Z6 — First-run fetch is NOT entered when DBs are already present
# ---------------------------------------------------------------------------


class TestFirstRunFetchNotCalled:
    """Z6 — ensure_dbs (the download function) is never called when DBs are present."""

    async def test_ensure_dbs_not_called_when_files_present(
        self, tmp_path: Path
    ) -> None:
        """When both DB files exist, _try_first_run_fetch is never called."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake_city")
        asn_path.write_bytes(b"fake_asn")

        city_reader = _make_mock_reader(_make_city_record())
        asn_reader = _make_mock_reader(_make_asn_record())
        store = _make_store(["192.0.2.1"])

        enricher = MmdbGeoEnricher(
            store=store, city_db_path=city_path, asn_db_path=asn_path
        )

        with (
            patch(
                "firewatch_core.adapters.geo_mmdb.maxminddb.open_database",
                side_effect=[city_reader, asn_reader],
            ),
            patch(
                "firewatch_core.adapters.geo_mmdb.is_non_public", return_value=False
            ),
            patch.object(
                MmdbGeoEnricher,
                "_try_first_run_fetch",
                wraps=enricher._try_first_run_fetch,
            ) as mock_fetch,
        ):
            await enricher.enrich([_evt("192.0.2.1")])

        assert mock_fetch.call_count == 0, (
            "_try_first_run_fetch must not be called when both DB files are present"
        )

    async def test_ensure_dbs_not_called_second_enrich(
        self, tmp_path: Path
    ) -> None:
        """_try_first_run_fetch is also not called on a second enrich() call."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake_city")
        asn_path.write_bytes(b"fake_asn")

        city_reader = _make_mock_reader(_make_city_record())
        asn_reader = _make_mock_reader(_make_asn_record())
        store = _make_store(["192.0.2.1"])

        enricher = MmdbGeoEnricher(
            store=store, city_db_path=city_path, asn_db_path=asn_path
        )

        fetch_call_count = [0]

        def _track_fetch() -> None:
            fetch_call_count[0] += 1

        with (
            patch(
                "firewatch_core.adapters.geo_mmdb.maxminddb.open_database",
                side_effect=[city_reader, asn_reader],
            ),
            patch(
                "firewatch_core.adapters.geo_mmdb.is_non_public", return_value=False
            ),
            patch.object(MmdbGeoEnricher, "_try_first_run_fetch", _track_fetch),
        ):
            await enricher.enrich([_evt("192.0.2.1")])
            await enricher.enrich([_evt("198.51.100.1")])

        assert fetch_call_count[0] == 0, (
            f"Expected zero _try_first_run_fetch calls across two enrich cycles; "
            f"got: {fetch_call_count[0]}"
        )


# ---------------------------------------------------------------------------
# Z1 — Full zero-egress assertion: connect-fail trap + successful completion
# ---------------------------------------------------------------------------


class TestZeroEgressAssertionFull:
    """Z1/Z2 — Full zero-egress: socket.connect trap + httpx trap, full cycle completes.

    This is the primary integration assertion for the air-gapped config:
    install a trap that RAISES on any socket connect or httpx instantiation,
    run the offline enrich cycle, and assert:
      (a) the trap was never triggered (zero egress attempted), AND
      (b) the enricher returned events unchanged (pipeline not disrupted).
    """

    async def test_offline_enrich_zero_egress_full_assertion(
        self, tmp_path: Path
    ) -> None:
        """Offline enrich with DBs present: no socket or HTTP call is attempted."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake_city_data")
        asn_path.write_bytes(b"fake_asn_data")

        city_reader = _make_mock_reader(_make_city_record("Germany", "Berlin", 52.5, 13.4))
        asn_reader = _make_mock_reader(_make_asn_record(3320, "Deutsche Telekom"))
        store = _make_store(["203.0.113.50"])

        enricher = MmdbGeoEnricher(
            store=store, city_db_path=city_path, asn_db_path=asn_path
        )

        egress_violations: list[str] = []

        def _trap_socket_connect(self_sock: Any, address: Any) -> None:
            msg = (
                f"EGRESS VIOLATION: socket.connect({address!r}) called during "
                "air-gapped offline enrich cycle"
            )
            egress_violations.append(msg)
            raise ConnectionRefusedError(msg)

        def _trap_httpx_async_client(*args: Any, **kwargs: Any) -> None:
            msg = (
                f"EGRESS VIOLATION: httpx.AsyncClient instantiated with "
                f"args={args!r} kwargs={kwargs!r} during air-gapped enrich"
            )
            egress_violations.append(msg)
            raise ConnectionRefusedError(msg)

        with (
            patch(
                "firewatch_core.adapters.geo_mmdb.maxminddb.open_database",
                side_effect=[city_reader, asn_reader],
            ),
            patch(
                "firewatch_core.adapters.geo_mmdb.is_non_public", return_value=False
            ),
            patch.object(socket.socket, "connect", _trap_socket_connect),
            patch("httpx.AsyncClient", side_effect=_trap_httpx_async_client),
        ):
            result = await enricher.enrich([_evt("203.0.113.50")])

        assert egress_violations == [], (
            "Zero-egress violations detected during offline enrich:\n"
            + "\n".join(egress_violations)
        )
        assert result == [_evt("203.0.113.50")], (
            "Offline enrich must return events unchanged"
        )

    async def test_offline_enrich_multiple_ips_zero_egress(
        self, tmp_path: Path
    ) -> None:
        """Multiple IPs enriched offline in one cycle: no egress violations."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake_city_data")
        asn_path.write_bytes(b"fake_asn_data")

        city_reader = _make_mock_reader(_make_city_record("Japan", "Tokyo", 35.7, 139.7))
        asn_reader = _make_mock_reader(_make_asn_record(7545, "TPG"))

        store = _make_store(["192.0.2.10", "198.51.100.20", "203.0.113.30"])

        enricher = MmdbGeoEnricher(
            store=store, city_db_path=city_path, asn_db_path=asn_path
        )

        egress_violations: list[str] = []

        def _trap_socket(self_sock: Any, address: Any) -> None:
            egress_violations.append(f"socket.connect({address!r})")
            raise ConnectionRefusedError

        with (
            patch(
                "firewatch_core.adapters.geo_mmdb.maxminddb.open_database",
                side_effect=[city_reader, asn_reader],
            ),
            patch(
                "firewatch_core.adapters.geo_mmdb.is_non_public", return_value=False
            ),
            patch.object(socket.socket, "connect", _trap_socket),
            patch("httpx.AsyncClient") as mock_http,
        ):
            events = [_evt(ip) for ip in ["192.0.2.10", "198.51.100.20", "203.0.113.30"]]
            await enricher.enrich(events)

        assert egress_violations == [], (
            f"Egress violations during multi-IP offline enrich: {egress_violations}"
        )
        assert mock_http.call_count == 0, (
            "httpx.AsyncClient must not be instantiated during offline multi-IP enrich"
        )


# ---------------------------------------------------------------------------
# Z5 — WebhookNotifier makes no outbound call when webhook_url is None
# ---------------------------------------------------------------------------


class TestWebhookNotifierNoEgress:
    """Z5 — WebhookNotifier makes no HTTP call when webhook_url is None."""

    async def test_no_http_call_when_webhook_url_is_none(self) -> None:
        """send_alert() must not call httpx when webhook_url is not configured."""
        from firewatch_core.adapters.webhook_notifier import WebhookNotifier
        from firewatch_sdk.config import ConfigStore, RuntimeConfig

        config_store = MagicMock(spec=ConfigStore)
        config_store.get_runtime.return_value = RuntimeConfig(webhook_url=None)

        notifier = WebhookNotifier(config_store=config_store)
        threat = _make_threat_score("192.0.2.1")

        with patch("httpx.AsyncClient") as mock_http:
            result = await notifier.send_alert(threat)

        assert result is False, "send_alert must return False when webhook_url is None"
        assert mock_http.call_count == 0, (
            "httpx.AsyncClient must not be instantiated when webhook_url is None"
        )

    async def test_no_http_call_check_and_alert_webhook_none(self) -> None:
        """check_and_alert() must not call httpx when webhook_url is not configured."""
        from firewatch_core.adapters.webhook_notifier import WebhookNotifier
        from firewatch_sdk.config import ConfigStore, RuntimeConfig

        config_store = MagicMock(spec=ConfigStore)
        config_store.get_runtime.return_value = RuntimeConfig(
            webhook_url=None,
            alert_threshold="HIGH",
        )

        notifier = WebhookNotifier(config_store=config_store)
        threat = _make_threat_score("198.51.100.5")

        with patch("httpx.AsyncClient") as mock_http:
            result = await notifier.check_and_alert(threat)

        assert result is False
        assert mock_http.call_count == 0, (
            "httpx.AsyncClient must not be called in check_and_alert with no webhook_url"
        )

    async def test_no_socket_connect_webhook_none(self) -> None:
        """socket.connect is never called when webhook_url is None."""
        from firewatch_core.adapters.webhook_notifier import WebhookNotifier
        from firewatch_sdk.config import ConfigStore, RuntimeConfig

        config_store = MagicMock(spec=ConfigStore)
        config_store.get_runtime.return_value = RuntimeConfig(webhook_url=None)

        notifier = WebhookNotifier(config_store=config_store)
        threat = _make_threat_score("203.0.113.10")

        connect_calls: list[Any] = []

        def _trap_connect(self_sock: Any, address: Any) -> None:
            connect_calls.append(address)
            raise ConnectionRefusedError(
                f"Zero-egress assertion: unexpected connect({address!r})"
            )

        with patch.object(socket.socket, "connect", _trap_connect):
            await notifier.send_alert(threat)

        assert connect_calls == [], (
            f"Unexpected socket.connect calls with webhook_url=None: {connect_calls}"
        )
