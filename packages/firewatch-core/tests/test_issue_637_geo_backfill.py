"""Tests for issue #637 — geo backfill for historical IPs.

Root cause: MmdbGeoEnricher.enrich() and GeoEnricher.enrich() both open with
``if not events: return events``, so IPs already in the DB (ingested before
geo was working) sit in get_ips_without_geo() forever, never re-enriched.

Fix: add backfill_geo() method on both enrichers + Pipeline.startup_backfill()
that invokes it once on startup (decoupled from the hot pull cycle).

EARS criteria mapped 1:1 from issue #637:

  BF-1  WHEN backfill_geo() is called on MmdbGeoEnricher AND the MMDB readers
        open successfully, the enricher SHALL resolve all IPs from
        get_ips_without_geo() via _lookup_ip + upsert_ip_geo — even with
        zero new events.

  BF-2  WHEN backfill_geo() is called on GeoEnricher, the enricher SHALL
        resolve all IPs from get_ips_without_geo() via the HTTP API + upsert_ip_geo
        — even with zero new events.

  BF-3  WHEN backfill_geo() is called on MmdbGeoEnricher AND the MMDB readers
        cannot open (missing files / corrupt), backfill_geo() SHALL log a WARNING
        and return without calling upsert_ip_geo (fail-safe; ADR-0003).

  BF-4  WHEN backfill_geo() is called on either enricher AND get_ips_without_geo()
        returns an empty list, upsert_ip_geo() SHALL NOT be called (no-op path).

  BF-5  WHEN Pipeline.startup_backfill() is called, it SHALL invoke
        backfill_geo() on each enricher that exposes it, and it SHALL succeed
        (not raise) when enrichers lack backfill_geo (backward compatible).

  BF-6  WHEN backfill_geo() is called on MmdbGeoEnricher, private/reserved/
        multicast IPs from get_ips_without_geo() SHALL be skipped (same SSRF
        guard as enrich()).

  BF-7  WHEN backfill_geo() is called on GeoEnricher AND the HTTP provider is
        unreachable, backfill_geo() SHALL not raise (fail-safe; ADR-0003).

  BF-8  The fast-path ``if not events: return events`` in enrich() SHALL remain
        intact — an empty cycle MUST NOT trigger backfill work.

NOTE on IPs: RFC 5737 documentation IPs (192.0.2.x, 198.51.100.x, 203.0.113.x)
are used throughout. The is_non_public guard treats them as non-global; tests
that verify the "public IP gets resolved" path patch is_non_public to return
False for these doc IPs.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from firewatch_sdk import SecurityEvent


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _evt(source_ip: str = "192.0.2.1") -> SecurityEvent:
    from datetime import datetime, timezone

    return SecurityEvent(
        source_type="suricata",
        source_id="pi-home",
        source_ip=source_ip,
        action="ALERT",
        timestamp=datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
    )


def _make_store(ips_without_geo: list[str] | None = None) -> AsyncMock:
    store = AsyncMock()
    store.get_ips_without_geo = AsyncMock(return_value=ips_without_geo or [])
    store.upsert_ip_geo = AsyncMock()
    return store


def _make_city_record(
    country: str = "Canada",
    city: str = "Toronto",
    lat: float = 43.7001,
    lon: float = -79.4163,
) -> dict[str, Any]:
    return {
        "country": {"names": {"en": country}},
        "city": {"names": {"en": city}},
        "location": {"latitude": lat, "longitude": lon},
    }


def _make_asn_record(asn: int = 7018, as_name: str = "AT&T") -> dict[str, Any]:
    return {
        "autonomous_system_number": asn,
        "autonomous_system_organization": as_name,
    }


def _make_mock_reader(record: dict[str, Any] | None) -> MagicMock:
    reader = MagicMock()
    reader.get.return_value = record
    return reader


def _geo_response(ip: str) -> dict[str, Any]:
    return {
        "status": "success",
        "query": ip,
        "country": "Germany",
        "city": "Berlin",
        "lat": 52.52,
        "lon": 13.405,
        "as": "AS1234 Example ISP",
        "asname": "Example ISP",
    }


# ---------------------------------------------------------------------------
# BF-1 — MmdbGeoEnricher.backfill_geo() resolves historical IPs (MMDB path)
# ---------------------------------------------------------------------------


class TestMmdbBackfillGeo:
    """BF-1: backfill_geo() resolves get_ips_without_geo() even with zero new events."""

    def _make_enricher_with_fake_readers(
        self,
        tmp_path: Path,
        ips_without_geo: list[str],
        city_record: dict[str, Any] | None = None,
        asn_record: dict[str, Any] | None = None,
    ) -> tuple[Any, AsyncMock, MagicMock, MagicMock]:
        """Return (enricher, store, city_reader, asn_reader) with file stubs on disk."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake")
        asn_path.write_bytes(b"fake")

        city_reader = _make_mock_reader(city_record or _make_city_record())
        asn_reader = _make_mock_reader(asn_record or _make_asn_record())
        store = _make_store(ips_without_geo)

        enricher = MmdbGeoEnricher(
            store=store, city_db_path=city_path, asn_db_path=asn_path
        )
        return enricher, store, city_reader, asn_reader

    async def test_backfill_resolves_ip_with_zero_new_events(
        self, tmp_path: Path
    ) -> None:
        """BF-1: backfill_geo() calls upsert_ip_geo for historical IPs (no events needed)."""
        enricher, store, city_reader, asn_reader = self._make_enricher_with_fake_readers(
            tmp_path, ips_without_geo=["192.0.2.50"]
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
            await enricher.backfill_geo()

        store.upsert_ip_geo.assert_called_once()
        rows: list[dict[str, Any]] = store.upsert_ip_geo.call_args[0][0]
        assert len(rows) == 1
        assert rows[0]["ip"] == "192.0.2.50"
        assert rows[0]["country"] == "Canada"
        assert rows[0]["city"] == "Toronto"

    async def test_backfill_resolves_multiple_ips(self, tmp_path: Path) -> None:
        """BF-1: backfill_geo() resolves all IPs from get_ips_without_geo()."""
        ips = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
        enricher, store, city_reader, asn_reader = self._make_enricher_with_fake_readers(
            tmp_path, ips_without_geo=ips
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
            await enricher.backfill_geo()

        store.upsert_ip_geo.assert_called_once()
        rows = store.upsert_ip_geo.call_args[0][0]
        resolved_ips = {r["ip"] for r in rows}
        assert resolved_ips == set(ips)

    async def test_backfill_does_not_call_enrich(self, tmp_path: Path) -> None:
        """BF-1: backfill_geo() is independent — does not go through enrich() internally."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake")
        asn_path.write_bytes(b"fake")

        store = _make_store(["192.0.2.1"])
        enricher = MmdbGeoEnricher(store=store, city_db_path=city_path, asn_db_path=asn_path)

        enrich_call_count: list[int] = [0]
        _original_enrich = enricher.enrich

        async def _spy_enrich(events: list[SecurityEvent]) -> list[SecurityEvent]:
            enrich_call_count[0] += 1
            return await _original_enrich(events)

        enricher.enrich = _spy_enrich  # type: ignore[method-assign]

        city_reader = _make_mock_reader(_make_city_record())
        asn_reader = _make_mock_reader(_make_asn_record())

        with (
            patch(
                "firewatch_core.adapters.geo_mmdb.maxminddb.open_database",
                side_effect=[city_reader, asn_reader],
            ),
            patch(
                "firewatch_core.adapters.geo_mmdb.is_non_public", return_value=False
            ),
        ):
            await enricher.backfill_geo()

        assert enrich_call_count[0] == 0, "backfill_geo() must not call enrich() internally"


# ---------------------------------------------------------------------------
# BF-3 — MmdbGeoEnricher.backfill_geo() fail-safe when readers cannot open
# ---------------------------------------------------------------------------


class TestMmdbBackfillFailSafe:
    """BF-3: backfill_geo() with missing/corrupt readers logs WARNING, no upsert."""

    async def test_backfill_with_missing_db_does_not_call_upsert(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """BF-3: When files are absent and download fails, backfill is a no-op."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        store = _make_store(["192.0.2.1"])
        enricher = MmdbGeoEnricher(
            store=store,
            city_db_path=tmp_path / "city.mmdb",
            asn_db_path=tmp_path / "asn.mmdb",
        )

        with (
            patch(
                "firewatch_core.adapters.geo_mmdb.MmdbGeoEnricher._try_first_run_fetch"
            ),
            caplog.at_level(logging.WARNING, logger="firewatch.geo_mmdb"),
        ):
            await enricher.backfill_geo()

        store.upsert_ip_geo.assert_not_called()

    async def test_backfill_with_missing_db_does_not_raise(
        self, tmp_path: Path
    ) -> None:
        """BF-3: backfill_geo() must never raise (fail-safe ADR-0003)."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        store = _make_store(["192.0.2.1"])
        enricher = MmdbGeoEnricher(
            store=store,
            city_db_path=tmp_path / "city.mmdb",
            asn_db_path=tmp_path / "asn.mmdb",
        )

        with patch(
            "firewatch_core.adapters.geo_mmdb.MmdbGeoEnricher._try_first_run_fetch"
        ):
            await enricher.backfill_geo()  # must not raise


# ---------------------------------------------------------------------------
# BF-4 — backfill_geo() is a no-op when no IPs need geo
# ---------------------------------------------------------------------------


class TestBackfillEmptyList:
    """BF-4: backfill_geo() does not call upsert_ip_geo when get_ips_without_geo() == []."""

    async def test_mmdb_backfill_with_empty_ips_list_is_noop(
        self, tmp_path: Path
    ) -> None:
        """BF-4 (MMDB): No IPs to resolve → upsert_ip_geo not called."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake")
        asn_path.write_bytes(b"fake")

        store = _make_store([])  # no IPs need geo
        enricher = MmdbGeoEnricher(store=store, city_db_path=city_path, asn_db_path=asn_path)

        city_reader = _make_mock_reader(_make_city_record())
        asn_reader = _make_mock_reader(_make_asn_record())

        with patch(
            "firewatch_core.adapters.geo_mmdb.maxminddb.open_database",
            side_effect=[city_reader, asn_reader],
        ):
            await enricher.backfill_geo()

        store.upsert_ip_geo.assert_not_called()

    async def test_geo_enricher_backfill_empty_ips_is_noop(self) -> None:
        """BF-4 (GeoEnricher): empty get_ips_without_geo() → no HTTP call, no upsert."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = _make_store([])
        enricher = GeoEnricher(store=store)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock()

        with patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client):
            await enricher.backfill_geo()

        mock_client.post.assert_not_called()
        store.upsert_ip_geo.assert_not_called()


# ---------------------------------------------------------------------------
# BF-6 — MmdbGeoEnricher.backfill_geo() skips private/reserved IPs
# ---------------------------------------------------------------------------


class TestMmdbBackfillPrivateIpGuard:
    """BF-6: Private/reserved/multicast IPs from get_ips_without_geo() are skipped."""

    @pytest.mark.parametrize(
        "private_ip",
        ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "::1"],
    )
    async def test_backfill_skips_private_ips(
        self, tmp_path: Path, private_ip: str
    ) -> None:
        """BF-6: Private IPs from get_ips_without_geo() are filtered before lookup."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        city_path = tmp_path / "city.mmdb"
        asn_path = tmp_path / "asn.mmdb"
        city_path.write_bytes(b"fake")
        asn_path.write_bytes(b"fake")

        store = _make_store([private_ip])
        enricher = MmdbGeoEnricher(store=store, city_db_path=city_path, asn_db_path=asn_path)

        city_reader = _make_mock_reader(_make_city_record())
        asn_reader = _make_mock_reader(_make_asn_record())

        with patch(
            "firewatch_core.adapters.geo_mmdb.maxminddb.open_database",
            side_effect=[city_reader, asn_reader],
        ):
            await enricher.backfill_geo()

        # Private IPs never reach the readers
        city_reader.get.assert_not_called()
        store.upsert_ip_geo.assert_not_called()


# ---------------------------------------------------------------------------
# BF-2 — GeoEnricher.backfill_geo() resolves historical IPs (HTTP path)
# ---------------------------------------------------------------------------


class TestGeoEnricherBackfillGeo:
    """BF-2: GeoEnricher.backfill_geo() resolves historical IPs via HTTP API."""

    async def test_backfill_calls_upsert_with_zero_new_events(self) -> None:
        """BF-2: backfill_geo() resolves IPs without needing any events parameter."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = _make_store(["192.0.2.77"])
        enricher = GeoEnricher(store=store)

        mock_response = MagicMock()
        mock_response.json = MagicMock(return_value=[_geo_response("192.0.2.77")])
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with (
            patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client),
            patch("firewatch_core.adapters.geo_enricher._is_non_public", return_value=False),
        ):
            await enricher.backfill_geo()

        store.upsert_ip_geo.assert_called_once()
        rows = store.upsert_ip_geo.call_args[0][0]
        assert len(rows) == 1
        assert rows[0]["ip"] == "192.0.2.77"

    async def test_backfill_does_not_call_enrich(self) -> None:
        """BF-2: backfill_geo() is independent — does not go through enrich() internally."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = _make_store(["192.0.2.1"])
        enricher = GeoEnricher(store=store)

        enrich_call_count: list[int] = [0]
        _original_enrich = enricher.enrich

        async def _spy_enrich(events: list[SecurityEvent]) -> list[SecurityEvent]:
            enrich_call_count[0] += 1
            return await _original_enrich(events)

        enricher.enrich = _spy_enrich  # type: ignore[method-assign]

        mock_response = MagicMock()
        mock_response.json = MagicMock(return_value=[_geo_response("192.0.2.1")])
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with (
            patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client),
            patch("firewatch_core.adapters.geo_enricher._is_non_public", return_value=False),
        ):
            await enricher.backfill_geo()

        assert enrich_call_count[0] == 0, "backfill_geo() must not call enrich() internally"


# ---------------------------------------------------------------------------
# BF-7 — GeoEnricher.backfill_geo() fail-safe on HTTP provider errors
# ---------------------------------------------------------------------------


class TestGeoEnricherBackfillFailSafe:
    """BF-7: backfill_geo() on GeoEnricher never raises on HTTP failure."""

    async def test_backfill_does_not_raise_on_http_error(self) -> None:
        """BF-7: Connection error during backfill is swallowed (fail-safe ADR-0003)."""
        import httpx
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = _make_store(["192.0.2.1"])
        enricher = GeoEnricher(store=store)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("provider down"))

        with (
            patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client),
            patch("firewatch_core.adapters.geo_enricher._is_non_public", return_value=False),
        ):
            await enricher.backfill_geo()  # must not raise

        store.upsert_ip_geo.assert_not_called()


# ---------------------------------------------------------------------------
# BF-8 — enrich() fast-path preserved: empty events still returns early
# ---------------------------------------------------------------------------


class TestEmptyEventsFastPathPreserved:
    """BF-8: The empty-events fast-path in enrich() MUST remain intact."""

    async def test_mmdb_enrich_empty_events_still_returns_early(
        self, tmp_path: Path
    ) -> None:
        """BF-8: enrich([]) still returns [] without touching readers or store."""
        from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

        store = _make_store(["192.0.2.1"])
        enricher = MmdbGeoEnricher(
            store=store,
            city_db_path=tmp_path / "city.mmdb",
            asn_db_path=tmp_path / "asn.mmdb",
        )

        with patch("firewatch_core.adapters.geo_mmdb.maxminddb") as mock_mmdb:
            result = await enricher.enrich([])

        assert result == []
        mock_mmdb.open_database.assert_not_called()
        store.get_ips_without_geo.assert_not_called()

    async def test_geo_enricher_enrich_empty_events_still_returns_early(self) -> None:
        """BF-8: GeoEnricher.enrich([]) still returns [] without HTTP or store calls."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = _make_store(["192.0.2.1"])
        enricher = GeoEnricher(store=store)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock()

        with patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client):
            result = await enricher.enrich([])

        assert result == []
        mock_client.post.assert_not_called()
        store.get_ips_without_geo.assert_not_called()


# ---------------------------------------------------------------------------
# BF-5 — Pipeline.startup_backfill() invokes backfill_geo on each enricher
# ---------------------------------------------------------------------------


class TestPipelineStartupBackfill:
    """BF-5: Pipeline.startup_backfill() calls backfill_geo() on eligible enrichers."""

    async def test_startup_backfill_calls_backfill_geo_on_enricher(self) -> None:
        """BF-5: startup_backfill() invokes backfill_geo() on enrichers that support it."""
        backfill_called: list[int] = [0]

        class _FakeEnricher:
            name = "geo"

            async def enrich(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
                return events

            async def backfill_geo(self) -> None:
                backfill_called[0] += 1

        from _fakes import FakeAIEngine, FakeStore
        from firewatch_core.pipeline import Pipeline

        store = FakeStore()
        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
            enrichers=[_FakeEnricher()],  # type: ignore[arg-type]
        )

        await pipeline.startup_backfill()

        assert backfill_called[0] == 1, (
            "startup_backfill() must call backfill_geo() on the enricher"
        )

    async def test_startup_backfill_skips_enrichers_without_backfill_geo(self) -> None:
        """BF-5: Enrichers without backfill_geo() are gracefully skipped (backward compat)."""
        class _LegacyEnricher:
            name = "legacy"

            async def enrich(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
                return events
            # No backfill_geo() method

        from _fakes import FakeAIEngine, FakeStore
        from firewatch_core.pipeline import Pipeline

        store = FakeStore()
        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
            enrichers=[_LegacyEnricher()],  # type: ignore[arg-type]
        )

        # Must not raise
        await pipeline.startup_backfill()

    async def test_startup_backfill_calls_all_eligible_enrichers(self) -> None:
        """BF-5: startup_backfill() calls backfill_geo() on ALL enrichers that have it."""
        calls: list[str] = []

        class _BFEnricher1:
            name = "geo1"

            async def enrich(self, e: list[SecurityEvent]) -> list[SecurityEvent]:
                return e

            async def backfill_geo(self) -> None:
                calls.append("geo1")

        class _BFEnricher2:
            name = "geo2"

            async def enrich(self, e: list[SecurityEvent]) -> list[SecurityEvent]:
                return e

            async def backfill_geo(self) -> None:
                calls.append("geo2")

        from _fakes import FakeAIEngine, FakeStore
        from firewatch_core.pipeline import Pipeline

        store = FakeStore()
        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
            enrichers=[_BFEnricher1(), _BFEnricher2()],  # type: ignore[arg-type]
        )

        await pipeline.startup_backfill()

        assert "geo1" in calls
        assert "geo2" in calls

    async def test_startup_backfill_is_fail_safe_on_enricher_exception(self) -> None:
        """BF-5: An enricher backfill_geo() that raises must not abort startup_backfill."""
        second_called: list[int] = [0]

        class _RaisingBFEnricher:
            name = "raising"

            async def enrich(self, e: list[SecurityEvent]) -> list[SecurityEvent]:
                return e

            async def backfill_geo(self) -> None:
                raise RuntimeError("backfill exploded")

        class _GoodBFEnricher:
            name = "good"

            async def enrich(self, e: list[SecurityEvent]) -> list[SecurityEvent]:
                return e

            async def backfill_geo(self) -> None:
                second_called[0] += 1

        from _fakes import FakeAIEngine, FakeStore
        from firewatch_core.pipeline import Pipeline

        store = FakeStore()
        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
            enrichers=[_RaisingBFEnricher(), _GoodBFEnricher()],  # type: ignore[arg-type]
        )

        await pipeline.startup_backfill()  # must not raise
        assert second_called[0] == 1, (
            "A raising enricher must not stop subsequent enrichers from being backfilled"
        )

    async def test_startup_backfill_with_no_enrichers_is_noop(self) -> None:
        """BF-5: startup_backfill() with empty enrichers list is a no-op (no crash)."""
        from _fakes import FakeAIEngine, FakeStore
        from firewatch_core.pipeline import Pipeline

        store = FakeStore()
        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
        )

        await pipeline.startup_backfill()  # must not raise
