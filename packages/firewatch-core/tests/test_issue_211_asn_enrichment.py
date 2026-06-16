"""Tests for issue #211 — ASN enrichment.

EARS acceptance criteria → test mapping:

  EARS-1  WHEN a public IP is geo-enriched, its cache row SHALL include ASN
          number and AS name when the provider returns them.
          → test_asn_fields_stored_when_provider_returns_them
          → test_asn_number_parsed_from_as_string_prefix
          → test_asn_name_stored_from_asname_field

  EARS-2  IF the provider omits AS data or the IP is non-public, THEN
          enrichment SHALL proceed exactly as today (graceful, never raises).
          → test_absent_as_field_still_stores_row
          → test_absent_asname_field_still_stores_row
          → test_non_public_ip_skipped_no_asn_storage
          → test_fail_safe_on_http_error_with_asn_enabled

  EARS-3  WHEN /threats is fetched for an enriched IP, the response SHALL
          include asn/as_name additively (existing fields unchanged).
          → test_get_ip_geo_returns_asn_fields
          → test_get_ip_geo_returns_none_for_absent_asn
          → test_threatscore_has_asn_and_as_name_fields
          → test_pipeline_analyze_ip_includes_asn_from_geo_cache (integration)

  EARS-4  Ubiquitous: NB-3 query-match validation still applies; AS strings
          are stored/rendered as text only.
          → test_asn_response_not_persisted_when_query_not_in_chunk
          → test_asn_stored_as_text_not_evaluated

  Store migration:
          → test_additive_migration_adds_asn_columns_to_existing_db
          → test_existing_rows_survive_migration_with_null_asn

  URL fields check:
          → test_asn_fields_in_free_url
          → test_asn_fields_in_pro_url

NOTE on IP fixtures: RFC 5737 documentation IPs (192.0.2.x, 198.51.100.x,
203.0.113.x) are used throughout. The _is_non_public guard is patched where
needed so doc IPs reach the mocked HTTP client (see test_geo_enricher.py for
the pattern rationale).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _evt(
    *,
    source_ip: str = "192.0.2.1",
    source_type: str = "suricata",
    source_id: str = "pi-home",
    action: str = "ALERT",
) -> Any:
    from datetime import datetime, timezone

    from firewatch_sdk.models import SecurityEvent

    return SecurityEvent(
        source_type=source_type,
        source_id=source_id,
        source_ip=source_ip,
        action=action,  # type: ignore[arg-type]
        timestamp=datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
    )


def _geo_response_with_asn(ip: str) -> dict[str, Any]:
    """ip-api.com success response that includes 'as' and 'asname' fields."""
    return {
        "status": "success",
        "query": ip,
        "country": "Germany",
        "city": "Berlin",
        "lat": 52.52,
        "lon": 13.405,
        "as": "AS4837 CHINA UNICOM China169 Backbone",
        "asname": "CHINA-UNICOM",
    }


def _geo_response_no_asn(ip: str) -> dict[str, Any]:
    """ip-api.com success response that omits 'as' and 'asname' (free-tier throttle)."""
    return {
        "status": "success",
        "query": ip,
        "country": "Germany",
        "city": "Berlin",
        "lat": 52.52,
        "lon": 13.405,
    }


# ---------------------------------------------------------------------------
# EARS-1 — ASN fields stored when provider returns them
# ---------------------------------------------------------------------------


class TestAsnFieldsStoredOnEnrich:
    """EARS-1: When provider returns as/asname, the cache row includes them."""

    async def test_asn_fields_stored_when_provider_returns_them(self) -> None:
        """When the ip-api.com response includes 'as'/'asname', they are stored."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_response = MagicMock()
        mock_response.json = MagicMock(
            return_value=[_geo_response_with_asn("192.0.2.1")]
        )
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with (
            patch(
                "firewatch_core.adapters.geo_enricher.httpx.AsyncClient",
                return_value=mock_client,
            ),
            patch(
                "firewatch_core.adapters.geo_enricher._is_non_public",
                return_value=False,
            ),
        ):
            await enricher.enrich([_evt(source_ip="192.0.2.1")])

        store.upsert_ip_geo.assert_called_once()
        call_args = store.upsert_ip_geo.call_args[0][0]
        assert len(call_args) == 1
        row = call_args[0]
        assert "asn" in row, "Expected 'asn' key in stored geo row"
        assert "as_name" in row, "Expected 'as_name' key in stored geo row"

    async def test_asn_number_parsed_from_as_string_prefix(self) -> None:
        """ASN number (integer) is parsed from the 'AS####' prefix of the 'as' field."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_response = MagicMock()
        mock_response.json = MagicMock(
            return_value=[_geo_response_with_asn("192.0.2.1")]
        )
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with (
            patch(
                "firewatch_core.adapters.geo_enricher.httpx.AsyncClient",
                return_value=mock_client,
            ),
            patch(
                "firewatch_core.adapters.geo_enricher._is_non_public",
                return_value=False,
            ),
        ):
            await enricher.enrich([_evt(source_ip="192.0.2.1")])

        row = store.upsert_ip_geo.call_args[0][0][0]
        # "AS4837 CHINA UNICOM..." -> asn = 4837
        assert row["asn"] == 4837, (
            f"Expected asn=4837 parsed from 'AS4837 CHINA UNICOM...' but got {row['asn']}"
        )

    async def test_asn_name_stored_from_asname_field(self) -> None:
        """The 'asname' field is stored verbatim as as_name."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_response = MagicMock()
        mock_response.json = MagicMock(
            return_value=[_geo_response_with_asn("192.0.2.1")]
        )
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with (
            patch(
                "firewatch_core.adapters.geo_enricher.httpx.AsyncClient",
                return_value=mock_client,
            ),
            patch(
                "firewatch_core.adapters.geo_enricher._is_non_public",
                return_value=False,
            ),
        ):
            await enricher.enrich([_evt(source_ip="192.0.2.1")])

        row = store.upsert_ip_geo.call_args[0][0][0]
        assert row["as_name"] == "CHINA-UNICOM", (
            f"Expected as_name='CHINA-UNICOM' but got {row['as_name']!r}"
        )


# ---------------------------------------------------------------------------
# EARS-2 — Absent AS data or non-public IP: graceful, no crash
# ---------------------------------------------------------------------------


class TestAsnAbsentOrNonPublic:
    """EARS-2: Absent AS data or non-public IPs do not crash enrichment."""

    async def test_absent_as_field_still_stores_row(self) -> None:
        """When 'as' field is absent from the provider response, row is stored with asn=None."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_response = MagicMock()
        mock_response.json = MagicMock(
            return_value=[_geo_response_no_asn("192.0.2.1")]
        )
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with (
            patch(
                "firewatch_core.adapters.geo_enricher.httpx.AsyncClient",
                return_value=mock_client,
            ),
            patch(
                "firewatch_core.adapters.geo_enricher._is_non_public",
                return_value=False,
            ),
        ):
            result = await enricher.enrich([_evt(source_ip="192.0.2.1")])

        # Must still call upsert (geo was resolved; just no ASN)
        store.upsert_ip_geo.assert_called_once()
        row = store.upsert_ip_geo.call_args[0][0][0]
        assert row["asn"] is None, (
            f"Expected asn=None when 'as' absent; got {row['asn']!r}"
        )
        assert result is not None

    async def test_absent_asname_field_stores_none_as_name(self) -> None:
        """When 'asname' is absent but 'as' is present, as_name is None."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        response_partial_asn = {
            "status": "success",
            "query": "192.0.2.1",
            "country": "DE",
            "city": "Berlin",
            "lat": 52.52,
            "lon": 13.405,
            "as": "AS4837 CHINA UNICOM",
            # 'asname' deliberately absent
        }

        mock_response = MagicMock()
        mock_response.json = MagicMock(return_value=[response_partial_asn])
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with (
            patch(
                "firewatch_core.adapters.geo_enricher.httpx.AsyncClient",
                return_value=mock_client,
            ),
            patch(
                "firewatch_core.adapters.geo_enricher._is_non_public",
                return_value=False,
            ),
        ):
            await enricher.enrich([_evt(source_ip="192.0.2.1")])

        store.upsert_ip_geo.assert_called_once()
        row = store.upsert_ip_geo.call_args[0][0][0]
        assert row["asn"] == 4837
        assert row["as_name"] is None

    async def test_non_public_ip_skipped_no_asn_storage(self) -> None:
        """Non-public IPs are never sent to the API; no ASN data is ever stored."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["10.0.0.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock()

        with patch(
            "firewatch_core.adapters.geo_enricher.httpx.AsyncClient",
            return_value=mock_client,
        ):
            await enricher.enrich([_evt(source_ip="10.0.0.1")])

        mock_client.post.assert_not_called()
        store.upsert_ip_geo.assert_not_called()

    async def test_fail_safe_on_http_error_with_asn_enabled(self) -> None:
        """HTTP errors still do not crash enrichment after ASN is added to the URL."""
        import httpx

        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(
            side_effect=httpx.ConnectError("connection refused")
        )

        events = [_evt(source_ip="192.0.2.1")]

        with (
            patch(
                "firewatch_core.adapters.geo_enricher.httpx.AsyncClient",
                return_value=mock_client,
            ),
            patch(
                "firewatch_core.adapters.geo_enricher._is_non_public",
                return_value=False,
            ),
        ):
            result = await enricher.enrich(events)

        assert result == events  # events returned unmodified
        store.upsert_ip_geo.assert_not_called()


# ---------------------------------------------------------------------------
# EARS-3 — ASN fields exposed via store.get_ip_geo and ThreatScore
# ---------------------------------------------------------------------------


class TestAsnFieldsExposedViaStore:
    """EARS-3: asn/as_name accessible from ip_geo cache and ThreatScore."""

    async def test_get_ip_geo_returns_asn_fields(self, tmp_path: Path) -> None:
        """After upsert_ip_geo with asn/as_name, get_ip_geo returns them."""
        from firewatch_core.adapters.sqlite_store import SQLiteEventStore

        store = SQLiteEventStore(tmp_path / "test.db")
        await store.init()

        geo_data = [
            {
                "ip": "192.0.2.1",
                "country": "Germany",
                "city": "Berlin",
                "lat": 52.52,
                "lon": 13.405,
                "asn": 4837,
                "as_name": "CHINA-UNICOM",
            }
        ]
        await store.upsert_ip_geo(geo_data)

        result = await store.get_ip_geo("192.0.2.1")
        assert result is not None
        assert result["asn"] == 4837, (
            f"Expected asn=4837, got {result.get('asn')!r}"
        )
        assert result["as_name"] == "CHINA-UNICOM", (
            f"Expected as_name='CHINA-UNICOM', got {result.get('as_name')!r}"
        )
        await store.close()

    async def test_get_ip_geo_returns_none_for_absent_asn(
        self, tmp_path: Path
    ) -> None:
        """When asn/as_name are absent (legacy row), get_ip_geo returns None for them."""
        from firewatch_core.adapters.sqlite_store import SQLiteEventStore

        store = SQLiteEventStore(tmp_path / "test.db")
        await store.init()

        # Store a row without asn/as_name (simulates a pre-#211 row)
        geo_data = [
            {
                "ip": "192.0.2.2",
                "country": "US",
                "city": "New York",
                "lat": 40.71,
                "lon": -74.0,
                # no asn, no as_name
            }
        ]
        await store.upsert_ip_geo(geo_data)

        result = await store.get_ip_geo("192.0.2.2")
        assert result is not None
        assert result.get("asn") is None, (
            f"Expected asn=None for row without ASN, got {result.get('asn')!r}"
        )
        assert result.get("as_name") is None, (
            f"Expected as_name=None for row without ASN, got {result.get('as_name')!r}"
        )
        await store.close()

    async def test_threatscore_has_asn_and_as_name_fields(self) -> None:
        """ThreatScore model exposes asn/as_name nullable fields (additive)."""
        from datetime import datetime, timezone

        from firewatch_sdk.models import ThreatScore

        # Fields default to None — no existing scores should break
        score_without_asn = ThreatScore(
            source_ip="192.0.2.1",
            threat_level="LOW",
            score=10,
            total_events=1,
            blocked_events=0,
            attack_types=[],
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        assert score_without_asn.asn is None
        assert score_without_asn.as_name is None

        # When set explicitly
        score_with_asn = ThreatScore(
            source_ip="192.0.2.3",
            threat_level="HIGH",
            score=75,
            total_events=5,
            blocked_events=3,
            attack_types=["sql_injection"],
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            asn=4837,
            as_name="CHINA-UNICOM",
        )
        assert score_with_asn.asn == 4837
        assert score_with_asn.as_name == "CHINA-UNICOM"

    async def test_pipeline_analyze_ip_includes_asn_from_geo_cache(
        self, tmp_path: Path
    ) -> None:
        """Pipeline.analyze_ip populates asn/as_name from the ip_geo cache.

        RFC 5737 doc IPs are not globally routable, so _is_public_ip is patched
        to return True — same pattern as test_issue_132_data_gaps.py — to isolate
        the geo-lookup wiring from the private-IP guard.
        """
        from datetime import datetime, timezone

        from firewatch_core.adapters.sqlite_store import SQLiteEventStore
        from firewatch_core.pipeline import Pipeline
        from firewatch_sdk.models import SecurityEvent

        store = SQLiteEventStore(tmp_path / "test.db")
        await store.init()

        # Insert an event
        event = SecurityEvent(
            source_type="suricata",
            source_id="test",
            source_ip="192.0.2.10",
            action="BLOCK",
            timestamp=datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
        )
        await store.save_many([event])

        # Insert geo with ASN
        await store.upsert_ip_geo(
            [
                {
                    "ip": "192.0.2.10",
                    "country": "CN",
                    "city": "Beijing",
                    "lat": 39.9,
                    "lon": 116.4,
                    "asn": 4837,
                    "as_name": "CHINA-UNICOM",
                }
            ]
        )

        class _FakeAI:
            async def is_available(self) -> bool:
                return False

            async def analyze_concise(self, **_: Any) -> dict[str, Any]:
                return {"ai_status": "unavailable"}

            async def analyze_detailed(self, **_: Any) -> dict[str, Any]:
                return {"ai_status": "unavailable"}

        pipeline = Pipeline(store=store, ai_engine=_FakeAI())  # type: ignore[arg-type]

        # Patch the private-IP guard so doc IPs are treated as public for this test
        with patch("firewatch_core.pipeline._is_public_ip", return_value=True):
            score = await pipeline.analyze_ip("192.0.2.10", use_ai=False)

        assert score.asn == 4837, (
            f"Expected asn=4837 from ip_geo cache; got {score.asn!r}"
        )
        assert score.as_name == "CHINA-UNICOM", (
            f"Expected as_name='CHINA-UNICOM' from ip_geo cache; got {score.as_name!r}"
        )

        await store.close()

    async def test_analyze_ip_detailed_includes_asn(self, tmp_path: Path) -> None:
        """analyze_ip_detailed result dict includes asn/as_name from ip_geo cache."""
        from datetime import datetime, timezone

        from firewatch_core.adapters.sqlite_store import SQLiteEventStore
        from firewatch_core.pipeline import Pipeline
        from firewatch_sdk.models import SecurityEvent

        store = SQLiteEventStore(tmp_path / "test.db")
        await store.init()

        event = SecurityEvent(
            source_type="azure_waf",
            source_id="test",
            source_ip="198.51.100.5",
            action="BLOCK",
            timestamp=datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
        )
        await store.save_many([event])

        await store.upsert_ip_geo(
            [
                {
                    "ip": "198.51.100.5",
                    "country": "CN",
                    "city": "Shanghai",
                    "lat": 31.22,
                    "lon": 121.47,
                    "asn": 9808,
                    "as_name": "CMNET",
                }
            ]
        )

        class _FakeAI:
            async def is_available(self) -> bool:
                return False

            async def analyze_concise(self, **_: Any) -> dict[str, Any]:
                return {"ai_status": "unavailable"}

            async def analyze_detailed(self, **_: Any) -> dict[str, Any]:
                return {"ai_status": "unavailable"}

        pipeline = Pipeline(store=store, ai_engine=_FakeAI())  # type: ignore[arg-type]

        # Patch the private-IP guard so doc IPs are treated as public for this test
        with patch("firewatch_core.pipeline._is_public_ip", return_value=True):
            result = await pipeline.analyze_ip_detailed("198.51.100.5")

        assert "asn" in result, "analyze_ip_detailed must include 'asn' key"
        assert "as_name" in result, "analyze_ip_detailed must include 'as_name' key"
        assert result["asn"] == 9808
        assert result["as_name"] == "CMNET"

        await store.close()


# ---------------------------------------------------------------------------
# EARS-4 — NB-3 query validation preserved with ASN; text-only storage
# ---------------------------------------------------------------------------


class TestAsnNb3ValidationAndTextOnly:
    """EARS-4: NB-3 still filters spoofed ASN rows; AS strings stored as text."""

    async def test_asn_response_not_persisted_when_query_not_in_chunk(
        self,
    ) -> None:
        """A spoofed response entry with ASN data is not persisted (NB-3)."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        spoofed_response: list[dict[str, Any]] = [
            {
                "status": "success",
                "query": "198.51.100.99",  # NOT in the sent chunk
                "country": "Malicious",
                "city": "Injected",
                "lat": 0.0,
                "lon": 0.0,
                "as": "AS9999 EVIL-AS",
                "asname": "EVIL",
            }
        ]

        mock_response = MagicMock()
        mock_response.json = MagicMock(return_value=spoofed_response)
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with (
            patch(
                "firewatch_core.adapters.geo_enricher.httpx.AsyncClient",
                return_value=mock_client,
            ),
            patch(
                "firewatch_core.adapters.geo_enricher._is_non_public",
                return_value=False,
            ),
        ):
            await enricher.enrich([_evt(source_ip="192.0.2.1")])

        store.upsert_ip_geo.assert_not_called()

    async def test_asn_stored_as_text_not_evaluated(self, tmp_path: Path) -> None:
        """ASN name is stored as a plain TEXT string, never interpreted as code/SQL."""
        from firewatch_core.adapters.sqlite_store import SQLiteEventStore

        store = SQLiteEventStore(tmp_path / "test.db")
        await store.init()

        # Potentially dangerous AS name — must be stored verbatim
        dangerous_name = "'; DROP TABLE ip_geo; --"
        await store.upsert_ip_geo(
            [
                {
                    "ip": "192.0.2.1",
                    "country": "DE",
                    "city": "Berlin",
                    "lat": 52.52,
                    "lon": 13.405,
                    "asn": 1234,
                    "as_name": dangerous_name,
                }
            ]
        )

        result = await store.get_ip_geo("192.0.2.1")
        # Must be stored verbatim; table must still exist
        assert result is not None, "ip_geo table must still exist"
        assert result["as_name"] == dangerous_name, (
            "AS name must be stored as literal text, not evaluated as SQL"
        )

        await store.close()


# ---------------------------------------------------------------------------
# Store migration — additive columns
# ---------------------------------------------------------------------------


class TestAsnStoreMigration:
    """Store migration: asn/as_name columns added additively to ip_geo."""

    async def test_additive_migration_adds_asn_columns_to_existing_db(
        self, tmp_path: Path
    ) -> None:
        """init() on a pre-existing ip_geo table (without asn columns) adds them."""
        import aiosqlite

        db_path = tmp_path / "migrate_test.db"

        # Build a legacy ip_geo table WITHOUT asn columns
        async with aiosqlite.connect(db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS ip_geo (
                    ip         TEXT PRIMARY KEY,
                    country    TEXT,
                    city       TEXT,
                    lat        REAL,
                    lon        REAL,
                    updated_at TEXT
                )
            """)
            # Insert a row to verify it survives migration
            await db.execute(
                "INSERT INTO ip_geo (ip, country, city, lat, lon, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                ("192.0.2.5", "US", "Dallas", 32.78, -96.8, "2026-01-01T00:00:00"),
            )
            await db.commit()

        # Now open via SQLiteEventStore.init() — should add the asn columns
        from firewatch_core.adapters.sqlite_store import SQLiteEventStore

        store = SQLiteEventStore(db_path)
        await store.init()  # must not raise

        # Verify columns exist and pre-existing row is intact with nulls for new cols
        result = await store.get_ip_geo("192.0.2.5")
        assert result is not None, "Pre-existing row must survive the migration"
        assert result["country"] == "US", "Existing columns must be preserved"
        assert result.get("asn") is None, (
            "Existing rows must backfill to NULL for new asn column"
        )
        assert result.get("as_name") is None, (
            "Existing rows must backfill to NULL for new as_name column"
        )

        await store.close()

    async def test_existing_rows_survive_migration_with_null_asn(
        self, tmp_path: Path
    ) -> None:
        """Rows in a migrated db without ASN data read as asn=None, as_name=None."""
        from firewatch_core.adapters.sqlite_store import SQLiteEventStore

        store = SQLiteEventStore(tmp_path / "test2.db")
        await store.init()

        # Insert without asn/as_name (caller omits them)
        await store.upsert_ip_geo(
            [
                {
                    "ip": "203.0.113.1",
                    "country": "FR",
                    "city": "Paris",
                    "lat": 48.85,
                    "lon": 2.35,
                }
            ]
        )

        row = await store.get_ip_geo("203.0.113.1")
        assert row is not None
        assert row["country"] == "FR"
        assert row.get("asn") is None
        assert row.get("as_name") is None

        await store.close()


# ---------------------------------------------------------------------------
# URL fields check: asn/asname present in the geo enricher URL fields
# ---------------------------------------------------------------------------


class TestGeoEnricherUrlFields:
    """The geo enricher must request 'as' and 'asname' fields from ip-api.com."""

    def test_asn_fields_in_free_url(self) -> None:
        """_GEO_FREE_URL must include 'as' and 'asname' in the fields= parameter."""
        from firewatch_core.adapters.geo_enricher import _GEO_FREE_URL

        assert "as" in _GEO_FREE_URL, (
            f"_GEO_FREE_URL must include 'as' field: {_GEO_FREE_URL!r}"
        )
        assert "asname" in _GEO_FREE_URL, (
            f"_GEO_FREE_URL must include 'asname' field: {_GEO_FREE_URL!r}"
        )

    def test_asn_fields_in_pro_url(self) -> None:
        """_GEO_PRO_URL must include 'as' and 'asname' in the fields= parameter."""
        from firewatch_core.adapters.geo_enricher import _GEO_PRO_URL

        assert "as" in _GEO_PRO_URL, (
            f"_GEO_PRO_URL must include 'as' field: {_GEO_PRO_URL!r}"
        )
        assert "asname" in _GEO_PRO_URL, (
            f"_GEO_PRO_URL must include 'asname' field: {_GEO_PRO_URL!r}"
        )
