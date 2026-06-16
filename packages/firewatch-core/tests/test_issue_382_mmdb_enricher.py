"""Tests for issue #382 (MI-1) — MmdbGeoEnricher (offline geo default).

EARS criteria covered (mapped 1:1 from issue #382):

  M1  WHEN geo_provider=offline and both MMDB files are present, the enricher
      SHALL resolve public IPs with zero network egress and persist results via
      upsert_ip_geo() filling country/city/lat/lon + asn/as_name; fields a DB
      lacks SHALL be stored as None, never fabricated.

  M2  WHEN the MMDB files are absent and cannot be fetched (air-gapped), the
      enricher SHALL log a WARNING containing the copy-in instruction and return
      events unchanged (fail-safe; never raises).

  M3  WHEN a present MMDB file is unreadable or corrupt, the enricher SHALL log
      a WARNING and return events unchanged.

  M4  Ubiquitous: private/reserved/multicast IPs SHALL be skipped before lookup
      (same guard as the online path).

  M5  MmdbGeoEnricher implements the firewatch_sdk.Enricher protocol (name + enrich).

  M6  Provider selection: geo_provider=offline builds MmdbGeoEnricher;
      geo_provider=online builds GeoEnricher.

  M7  WHEN enrich() is called with an empty event list, the enricher returns []
      without touching the readers.

NOTE on IP fixtures: RFC 5737 documentation IPs (192.0.2.x, 198.51.100.x,
203.0.113.x) are used throughout. The _is_non_public guard in geo_ip_utils
treats them as non-global (correct — they are NOT real public IPs). Tests that
exercise the positive "public IP gets resolved" path patch is_non_public to
return False for these doc IPs, isolating the lookup logic from the guard.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from firewatch_sdk import Enricher, SecurityEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _evt(
    source_ip: str = "192.0.2.1",
    source_type: str = "suricata",
) -> SecurityEvent:
    from datetime import datetime, timezone

    return SecurityEvent(
        source_type=source_type,
        source_id="pi-home",
        source_ip=source_ip,
        action="ALERT",
        timestamp=datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
    )


def _make_city_record(
    country: str = "Canada",
    city: str = "Toronto",
    lat: float = 43.7001,
    lon: float = -79.4163,
) -> dict[str, Any]:
    """Return a dict matching DB-IP City Lite MMDB record shape."""
    return {
        "country": {"names": {"en": country}},
        "city": {"names": {"en": city}},
        "location": {"latitude": lat, "longitude": lon},
    }


def _make_asn_record(asn: int = 7018, as_name: str = "AT&T") -> dict[str, Any]:
    """Return a dict matching DB-IP ASN Lite MMDB record shape."""
    return {
        "autonomous_system_number": asn,
        "autonomous_system_organization": as_name,
    }


def _make_mock_reader(record: dict[str, Any] | None) -> MagicMock:
    """Return a mock maxminddb.Reader whose .get() returns *record*."""
    reader = MagicMock()
    reader.get.return_value = record
    return reader


def _make_store(ips_without_geo: list[str] | None = None) -> AsyncMock:
    store = AsyncMock()
    store.get_ips_without_geo = AsyncMock(return_value=ips_without_geo or [])
    store.upsert_ip_geo = AsyncMock()
    return store


# ---------------------------------------------------------------------------
# M5 — Enricher protocol conformance
# ---------------------------------------------------------------------------


class TestEnricherProtocol:
    """M5 — MmdbGeoEnricher implements the SDK Enricher protocol."""

    def test_implements_enricher_protocol(self, tmp_path: Path) -> None:
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        store = _make_store()
        enricher = MmdbGeoEnricher(
            store=store,
            city_db_path=tmp_path / "city.mmdb",
            asn_db_path=tmp_path / "asn.mmdb",
        )
        assert isinstance(enricher, Enricher)

    def test_name_is_geo(self, tmp_path: Path) -> None:
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        store = _make_store()
        enricher = MmdbGeoEnricher(
            store=store,
            city_db_path=tmp_path / "city.mmdb",
            asn_db_path=tmp_path / "asn.mmdb",
        )
        assert enricher.name == "geo"


# ---------------------------------------------------------------------------
# M7 — Empty events fast-path
# ---------------------------------------------------------------------------


class TestEmptyEventsFastPath:
    """M7 — empty event list returns immediately without reader access."""

    async def test_empty_events_returns_empty(self, tmp_path: Path) -> None:
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        store = _make_store()
        enricher = MmdbGeoEnricher(
            store=store,
            city_db_path=tmp_path / "city.mmdb",
            asn_db_path=tmp_path / "asn.mmdb",
        )
        # Patch open_database to confirm it is never called
        with patch("firewatch_core.adapters.geo_mmdb.maxminddb") as mock_mmdb:
            result = await enricher.enrich([])

        assert result == []
        mock_mmdb.open_database.assert_not_called()
        store.get_ips_without_geo.assert_not_called()


# ---------------------------------------------------------------------------
# M1 — Successful offline lookup: country/city/lat/lon + asn/as_name
# ---------------------------------------------------------------------------


class TestSuccessfulOfflineLookup:
    """M1 — MMDB present → enricher resolves IPs and persists all six fields."""

    async def test_resolves_country_city_lat_lon_asn_as_name(
        self, tmp_path: Path
    ) -> None:
        """When both DBs are present and return data, all six geo fields are populated."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake")
        asn_path.write_bytes(b"fake")

        city_reader = _make_mock_reader(
            _make_city_record("Canada", "Toronto", 43.7001, -79.4163)
        )
        asn_reader = _make_mock_reader(_make_asn_record(7018, "AT&T"))

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
        ):
            result = await enricher.enrich([_evt("192.0.2.1")])

        store.upsert_ip_geo.assert_called_once()
        rows: list[dict[str, Any]] = store.upsert_ip_geo.call_args[0][0]
        assert len(rows) == 1
        row = rows[0]
        assert row["ip"] == "192.0.2.1"
        assert row["country"] == "Canada"
        assert row["city"] == "Toronto"
        assert abs(row["lat"] - 43.7001) < 0.001
        assert abs(row["lon"] - (-79.4163)) < 0.001
        assert row["asn"] == 7018
        assert row["as_name"] == "AT&T"
        assert result == [_evt("192.0.2.1")]

    async def test_missing_city_subkeys_stored_as_none(self, tmp_path: Path) -> None:
        """Fields absent in the City record are stored as None, never fabricated."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake")
        asn_path.write_bytes(b"fake")

        # City record with no city node and no location
        sparse_city_record: dict[str, Any] = {
            "country": {"names": {"en": "Canada"}},
            # no "city" key
            # no "location" key
        }
        city_reader = _make_mock_reader(sparse_city_record)
        asn_reader = _make_mock_reader(_make_asn_record(7018, "AT&T"))

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
        ):
            await enricher.enrich([_evt("192.0.2.1")])

        rows = store.upsert_ip_geo.call_args[0][0]
        row = rows[0]
        assert row["country"] == "Canada"
        assert row["city"] is None
        assert row["lat"] is None
        assert row["lon"] is None

    async def test_missing_asn_subkeys_stored_as_none(self, tmp_path: Path) -> None:
        """Fields absent in the ASN record are stored as None."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake")
        asn_path.write_bytes(b"fake")

        city_reader = _make_mock_reader(
            _make_city_record("Canada", "Toronto", 43.7001, -79.4163)
        )
        # ASN record with no autonomous_system fields
        asn_reader = _make_mock_reader({})

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
        ):
            await enricher.enrich([_evt("192.0.2.1")])

        rows = store.upsert_ip_geo.call_args[0][0]
        row = rows[0]
        assert row["asn"] is None
        assert row["as_name"] is None

    async def test_ip_not_in_db_returns_none_fields(self, tmp_path: Path) -> None:
        """When an IP is not found in either DB, all geo fields are None."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake")
        asn_path.write_bytes(b"fake")

        # Both readers return None for the IP (not in DB)
        city_reader = _make_mock_reader(None)
        asn_reader = _make_mock_reader(None)

        store = _make_store(["198.51.100.1"])
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
        ):
            await enricher.enrich([_evt("198.51.100.1")])

        # upsert_ip_geo is still called with the row (all None fields)
        store.upsert_ip_geo.assert_called_once()
        row = store.upsert_ip_geo.call_args[0][0][0]
        assert row["ip"] == "198.51.100.1"
        assert row["country"] is None
        assert row["city"] is None
        assert row["lat"] is None
        assert row["lon"] is None
        assert row["asn"] is None
        assert row["as_name"] is None

    async def test_no_network_egress_during_lookup(self, tmp_path: Path) -> None:
        """Lookup makes no HTTP calls — zero network egress (EARS M1)."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake")
        asn_path.write_bytes(b"fake")

        city_reader = _make_mock_reader(
            _make_city_record("Canada", "Toronto", 43.7, -79.4)
        )
        asn_reader = _make_mock_reader(_make_asn_record(7018, "AT&T"))

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
            patch("httpx.AsyncClient") as mock_http,
        ):
            await enricher.enrich([_evt("192.0.2.1")])

        mock_http.assert_not_called()


# ---------------------------------------------------------------------------
# M4 — Private/reserved IP guard
# ---------------------------------------------------------------------------


class TestPrivateIpGuard:
    """M4 — private/reserved/multicast IPs are skipped before lookup."""

    @pytest.mark.parametrize(
        "private_ip",
        [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "169.254.0.1",
            "224.0.0.251",
        ],
    )
    async def test_private_ip_not_looked_up(
        self, tmp_path: Path, private_ip: str
    ) -> None:
        """Private/reserved/multicast IPs are skipped — readers not called."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake")
        asn_path.write_bytes(b"fake")

        city_reader = _make_mock_reader(None)
        asn_reader = _make_mock_reader(None)

        store = _make_store([private_ip])
        enricher = MmdbGeoEnricher(
            store=store, city_db_path=city_path, asn_db_path=asn_path
        )

        with patch(
            "firewatch_core.adapters.geo_mmdb.maxminddb.open_database",
            side_effect=[city_reader, asn_reader],
        ):
            result = await enricher.enrich([_evt(private_ip)])

        # Readers opened but .get() never called (no public IPs)
        city_reader.get.assert_not_called()
        asn_reader.get.assert_not_called()
        store.upsert_ip_geo.assert_not_called()
        assert result == [_evt(private_ip)]


# ---------------------------------------------------------------------------
# M2 — Fail-safe: missing DB + download failure
# ---------------------------------------------------------------------------


class TestFailSafeMissingDb:
    """M2 — DB absent and download fails → events pass through unchanged, WARNING logged."""

    async def test_missing_db_download_fails_returns_events_unchanged(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """When files are absent and the download fails, events are returned unchanged."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        store = _make_store(["192.0.2.1"])
        enricher = MmdbGeoEnricher(
            store=store,
            city_db_path=tmp_path / "city.mmdb",
            asn_db_path=tmp_path / "asn.mmdb",
        )

        events = [_evt("192.0.2.1")]

        with (
            patch(
                "firewatch_core.adapters.geo_mmdb.MmdbGeoEnricher._try_first_run_fetch"
            ) as mock_fetch,
            caplog.at_level(logging.WARNING, logger="firewatch.geo_mmdb"),
        ):
            # Fetch does nothing (files still absent); open_readers will fail
            mock_fetch.return_value = None
            result = await enricher.enrich(events)

        assert result == events
        store.upsert_ip_geo.assert_not_called()

    async def test_missing_db_no_exception_raised(
        self, tmp_path: Path
    ) -> None:
        """Missing DB never raises — fail-safe posture (ADR-0003)."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        store = _make_store(["192.0.2.1"])
        enricher = MmdbGeoEnricher(
            store=store,
            city_db_path=tmp_path / "city.mmdb",
            asn_db_path=tmp_path / "asn.mmdb",
        )

        # Patch fetch to simulate a network failure
        with patch(
            "firewatch_core.adapters.geo_mmdb.MmdbGeoEnricher._try_first_run_fetch"
        ):
            # Must not raise
            result = await enricher.enrich([_evt("192.0.2.1")])

        assert isinstance(result, list)

    async def test_warning_contains_copy_in_hint(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The warning logged when download fails includes the copy-in hint text."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher, _COPY_IN_HINT

        store = _make_store(["192.0.2.1"])
        enricher = MmdbGeoEnricher(
            store=store,
            city_db_path=tmp_path / "city.mmdb",
            asn_db_path=tmp_path / "asn.mmdb",
        )

        with (
            patch(
                "firewatch_core.adapters.geo_mmdb.MmdbGeoEnricher._try_first_run_fetch",
                side_effect=lambda: None,  # fetch attempted but city file still absent
            ),
            caplog.at_level(logging.WARNING, logger="firewatch.geo_mmdb"),
        ):
            await enricher.enrich([_evt("192.0.2.1")])

        # The warning emitted by _try_open_readers should mention the copy-in hint
        all_messages = " ".join(caplog.messages)
        assert "db-ip.com" in all_messages.lower() or _COPY_IN_HINT[:30] in all_messages


# ---------------------------------------------------------------------------
# M3 — Fail-safe: corrupt / unreadable DB
# ---------------------------------------------------------------------------


class TestFailSafeCorruptDb:
    """M3 — corrupt/unreadable DB → WARNING logged, events returned unchanged."""

    async def test_corrupt_city_db_returns_events_unchanged(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """InvalidDatabaseError on open → events returned unchanged, no crash."""
        from maxminddb.errors import InvalidDatabaseError

        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"corrupt bytes")
        asn_path.write_bytes(b"fake")

        store = _make_store(["192.0.2.1"])
        enricher = MmdbGeoEnricher(
            store=store, city_db_path=city_path, asn_db_path=asn_path
        )

        def _raise_corrupt(path: str) -> None:
            raise InvalidDatabaseError("corrupt")

        events = [_evt("192.0.2.1")]

        with (
            patch(
                "firewatch_core.adapters.geo_mmdb.maxminddb.open_database",
                side_effect=_raise_corrupt,
            ),
            caplog.at_level(logging.WARNING, logger="firewatch.geo_mmdb"),
        ):
            result = await enricher.enrich(events)

        assert result == events
        store.upsert_ip_geo.assert_not_called()
        assert any("cannot open" in m.lower() or "city" in m.lower() for m in caplog.messages)

    async def test_corrupt_asn_db_returns_events_unchanged(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """InvalidDatabaseError on ASN open → events returned unchanged."""
        from maxminddb.errors import InvalidDatabaseError

        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake")
        asn_path.write_bytes(b"corrupt bytes")

        store = _make_store(["192.0.2.1"])
        enricher = MmdbGeoEnricher(
            store=store, city_db_path=city_path, asn_db_path=asn_path
        )

        city_reader = _make_mock_reader(None)

        def _open_side_effect(path: str) -> MagicMock:
            if "city" in path:
                return city_reader
            raise InvalidDatabaseError("asn corrupt")

        events = [_evt("192.0.2.1")]

        with (
            patch(
                "firewatch_core.adapters.geo_mmdb.maxminddb.open_database",
                side_effect=_open_side_effect,
            ),
            caplog.at_level(logging.WARNING, logger="firewatch.geo_mmdb"),
        ):
            result = await enricher.enrich(events)

        assert result == events
        store.upsert_ip_geo.assert_not_called()

    async def test_no_exception_raised_on_corrupt_db(self, tmp_path: Path) -> None:
        """Corrupt DB must never raise out of enrich() (ADR-0003 fail-safe)."""
        from maxminddb.errors import InvalidDatabaseError

        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"corrupt")
        asn_path.write_bytes(b"corrupt")

        store = _make_store(["192.0.2.1"])
        enricher = MmdbGeoEnricher(
            store=store, city_db_path=city_path, asn_db_path=asn_path
        )

        with patch(
            "firewatch_core.adapters.geo_mmdb.maxminddb.open_database",
            side_effect=InvalidDatabaseError("totally broken"),
        ):
            # Must not raise
            result = await enricher.enrich([_evt("192.0.2.1")])

        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# M6 — Provider selection via _build_pipeline
# ---------------------------------------------------------------------------


class TestProviderSelection:
    """M6 — geo_provider=offline builds MmdbGeoEnricher; online builds GeoEnricher."""

    def test_offline_provider_builds_mmdb_enricher(self) -> None:
        """geo_provider='offline' → pipeline enrichers contain MmdbGeoEnricher."""
        from firewatch_cli.commands._pipeline_factory import _build_pipeline

        pipeline = _build_pipeline(config_file=None)
        enricher_types = [type(e).__name__ for e in pipeline.enrichers]  # type: ignore[attr-defined]
        assert "MmdbGeoEnricher" in enricher_types, (
            f"Expected MmdbGeoEnricher in pipeline.enrichers (geo_provider=offline default); "
            f"got: {enricher_types}"
        )

    def test_online_provider_builds_geo_enricher(self, tmp_path: Path) -> None:
        """geo_provider='online' → pipeline enrichers contain GeoEnricher."""
        import os

        from firewatch_cli.commands._pipeline_factory import _build_pipeline

        with patch.dict(os.environ, {"FIREWATCH_GEO_PROVIDER": "online"}):
            pipeline = _build_pipeline(config_file=None)

        enricher_types = [type(e).__name__ for e in pipeline.enrichers]  # type: ignore[attr-defined]
        assert "GeoEnricher" in enricher_types, (
            f"Expected GeoEnricher in pipeline.enrichers (geo_provider=online); "
            f"got: {enricher_types}"
        )

    def test_default_provider_is_offline(self, tmp_path: Path) -> None:
        """Without any config, geo_provider defaults to 'offline' (ADR-0039)."""
        from firewatch_sdk.config import RuntimeConfig

        cfg = RuntimeConfig()
        assert cfg.geo_provider == "offline"
