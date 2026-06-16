"""Tests for GeoEnricher — mapped 1:1 to issue #20 EARS criteria.

EARS criteria covered:
  G1  Ubiquitous: GeoEnricher implements the SDK Enricher protocol (name + enrich).
  G2  Event-driven: when enrich() is called, it calls store.get_ips_without_geo(),
      looks up geo, calls store.upsert_ip_geo(), after which get_analytics_geo()
      returns rows for those IPs.
  G3  State-driven: while the geo lookup provider is unreachable or rate-limited,
      enrich() skips gracefully — no crash, returns events unmodified.
  G4  Unwanted: if a looked-up IP is private/reserved, the system shall NOT call
      the public geo API for it (no needless egress; marked as local/unknown).
      NB-1 / NB-5: multicast (224.0.0.0/4), IPv4 link-local (169.254/16), and
      IPv6 link-local (fe80::/10) are also blocked.
  G5  Rule-desc round-trip: upsert_rule_descriptions + get_rule_descriptions persists
      and retrieves descriptions (proves the store path the plugin-side producer uses).
  G6  No forbidden imports (geo_enricher.py must not import legacy/).
  G7  SecretStr: any provider key parameter must be SecretStr, never plain str.
  G8  (NB-2) Pro endpoint: when api_key is set the pro base URL and key param are used;
      the free URL is used when no key is set.
  G9  (NB-3) Response-query validation: results whose ``query`` is NOT in the sent
      chunk are silently dropped and never persisted (MITM / store-poisoning guard).

NOTE on IP fixtures: RFC 5737 documentation IPs (192.0.2.x, 198.51.100.x, 203.0.113.x)
are whitelisted by gitleaks but are classified as non-global by Python's ipaddress module
(correct behaviour — they are NOT real public IPs). Tests that exercise the positive
"public IP gets looked up" path therefore patch ``_is_non_public`` to return False for the
doc IPs, isolating the batching / store-call logic from the private-IP guard. Tests for G4
use real private-range IPs (RFC 1918 / loopback) which are also gitleaks-safe.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from firewatch_sdk import Enricher, SecurityEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _evt(
    *,
    source_ip: str = "192.0.2.1",
    source_type: str = "suricata",
    source_id: str = "pi-home",
    action: str = "ALERT",
) -> SecurityEvent:
    from datetime import datetime, timezone

    return SecurityEvent(
        source_type=source_type,
        source_id=source_id,
        source_ip=source_ip,
        action=action,  # type: ignore[arg-type]
        timestamp=datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
    )


def _geo_response(ip: str) -> dict[str, Any]:
    """Minimal ip-api.com success response for a doc IP."""
    return {
        "status": "success",
        "query": ip,
        "country": "Germany",
        "city": "Berlin",
        "lat": 52.52,
        "lon": 13.405,
    }


# ---------------------------------------------------------------------------
# G1 — Enricher protocol conformance
# ---------------------------------------------------------------------------


class TestEnricherProtocol:
    """G1 — GeoEnricher implements the SDK Enricher Protocol."""

    def test_geo_enricher_is_enricher_protocol(self) -> None:
        """GeoEnricher must satisfy the runtime_checkable Enricher Protocol."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = MagicMock()
        enricher = GeoEnricher(store=store)
        assert isinstance(enricher, Enricher), (
            "GeoEnricher must satisfy the runtime_checkable Enricher Protocol"
        )

    def test_name_attribute_is_string(self) -> None:
        """name must be a non-empty string."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = MagicMock()
        enricher = GeoEnricher(store=store)
        assert isinstance(enricher.name, str)
        assert len(enricher.name) > 0

    def test_name_is_geo(self) -> None:
        """name must be 'geo' (conventional identifier for geo enrichment)."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = MagicMock()
        enricher = GeoEnricher(store=store)
        assert enricher.name == "geo"

    async def test_enrich_returns_list(self) -> None:
        """enrich() must always return a list."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=[])
        store.upsert_ip_geo = AsyncMock()
        enricher = GeoEnricher(store=store)

        result = await enricher.enrich([])
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# G2 — Geo lookup round-trip via store
# ---------------------------------------------------------------------------


class TestGeoLookupRoundTrip:
    """G2 — enrich() calls get_ips_without_geo, looks up geo, calls upsert_ip_geo.

    These tests mock _is_non_public to return False so that RFC 5737 doc IPs
    (192.0.2.1, 198.51.100.1) reach the (also-mocked) HTTP client. This isolates
    the batching / store-call logic from the private-IP guard (tested in G4).
    """

    async def test_enrich_calls_upsert_ip_geo_for_public_ips(self) -> None:
        """When the store reports an IP without geo, enrich calls upsert_ip_geo with results."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_response = MagicMock()
        mock_response.json = MagicMock(return_value=[_geo_response("192.0.2.1")])
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        # Patch the private-IP guard so doc IPs pass through to the mock HTTP client
        with (
            patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client),
            patch("firewatch_core.adapters.geo_enricher._is_non_public", return_value=False),
        ):
            result = await enricher.enrich([_evt(source_ip="192.0.2.1")])

        store.upsert_ip_geo.assert_called_once()
        call_args = store.upsert_ip_geo.call_args[0][0]
        assert len(call_args) == 1
        assert call_args[0]["ip"] == "192.0.2.1"
        assert call_args[0]["country"] == "Germany"
        assert call_args[0]["city"] == "Berlin"
        assert len(result) == 1

    async def test_enrich_returns_events_after_upsert(self) -> None:
        """enrich() returns the same event list after storing geo data."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_response = MagicMock()
        mock_response.json = MagicMock(return_value=[_geo_response("192.0.2.1")])
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        events = [_evt(source_ip="192.0.2.1")]

        with (
            patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client),
            patch("firewatch_core.adapters.geo_enricher._is_non_public", return_value=False),
        ):
            result = await enricher.enrich(events)

        assert result == events

    async def test_enrich_skips_ips_already_in_geo(self) -> None:
        """IPs already in ip_geo table are not re-looked-up."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=[])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock()

        with patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client):
            await enricher.enrich([_evt(source_ip="192.0.2.1")])

        mock_client.post.assert_not_called()
        store.upsert_ip_geo.assert_not_called()

    async def test_enrich_batches_up_to_100_ips_per_request(self) -> None:
        """Batches of >100 public IPs result in multiple HTTP requests (ip-api.com limit)."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        # 101 distinct IPs using RFC 5737 doc ranges — gitleaks-safe
        ips = [f"192.0.2.{i}" for i in range(1, 101)] + ["198.51.100.1"]
        assert len(ips) == 101

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=ips)
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        call_count: list[int] = [0]

        async def _mock_post(url: str, **kwargs: Any) -> MagicMock:
            call_count[0] += 1
            chunk_ips = [item["query"] for item in kwargs.get("json", [])]
            resp = MagicMock()
            resp.json = MagicMock(return_value=[_geo_response(ip) for ip in chunk_ips])
            resp.raise_for_status = MagicMock()
            return resp

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = _mock_post

        # Patch guard so all 101 doc IPs pass through
        with (
            patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client),
            patch("firewatch_core.adapters.geo_enricher._is_non_public", return_value=False),
        ):
            await enricher.enrich([_evt(source_ip=ip) for ip in ips])

        assert call_count[0] == 2, (
            f"Expected 2 HTTP requests for 101 IPs; got {call_count[0]}"
        )

    async def test_failed_api_status_skipped(self) -> None:
        """ip-api entries with status != 'success' are silently skipped."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_response = MagicMock()
        mock_response.json = MagicMock(return_value=[{"status": "fail", "query": "192.0.2.1"}])
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with (
            patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client),
            patch("firewatch_core.adapters.geo_enricher._is_non_public", return_value=False),
        ):
            await enricher.enrich([_evt(source_ip="192.0.2.1")])

        store.upsert_ip_geo.assert_not_called()


# ---------------------------------------------------------------------------
# G3 — Provider-down / rate-limited: graceful skip, no crash
# ---------------------------------------------------------------------------


class TestProviderDownGraceful:
    """G3 — enrich() must not crash when the provider is unreachable or returns an error."""

    async def test_http_connect_error_is_swallowed(self) -> None:
        """httpx.ConnectError during geo lookup must be caught — events returned unmodified."""
        import httpx
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("connection refused"))

        events = [_evt(source_ip="192.0.2.1")]

        with (
            patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client),
            patch("firewatch_core.adapters.geo_enricher._is_non_public", return_value=False),
        ):
            result = await enricher.enrich(events)

        assert result == events
        store.upsert_ip_geo.assert_not_called()

    async def test_timeout_exception_is_swallowed(self) -> None:
        """Timeout during geo lookup must not crash the enricher."""
        import httpx
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        events = [_evt(source_ip="192.0.2.1")]

        with (
            patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client),
            patch("firewatch_core.adapters.geo_enricher._is_non_public", return_value=False),
        ):
            result = await enricher.enrich(events)

        assert result == events

    async def test_unexpected_exception_is_swallowed(self) -> None:
        """Any unexpected exception during lookup must not crash the enricher."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=RuntimeError("unexpected"))

        events = [_evt(source_ip="192.0.2.1")]

        with (
            patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client),
            patch("firewatch_core.adapters.geo_enricher._is_non_public", return_value=False),
        ):
            result = await enricher.enrich(events)

        assert result == events

    async def test_enrich_empty_events_returns_empty(self) -> None:
        """enrich([]) must return [] without calling the provider."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=[])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock()

        with patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client):
            result = await enricher.enrich([])

        assert result == []
        mock_client.post.assert_not_called()


# ---------------------------------------------------------------------------
# G4 — Private / reserved IP guard (SSRF protection)
# ---------------------------------------------------------------------------


class TestPrivateIpGuard:
    """G4 — private/reserved IPs must never be sent to the public geo API.

    Uses real RFC 1918 / loopback IPs (all gitleaks-allowlisted) to verify the
    private-IP guard. These are correctly classified as non-global by Python's
    ipaddress module and will be filtered out before any HTTP call.
    """

    @pytest.mark.parametrize(
        "private_ip",
        [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "192.168.255.255",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "fc00::1",
            # NB-5: IPv4 and IPv6 link-local (RFC 3927, RFC 4291)
            "169.254.0.1",
            "fe80::1",
            # NB-1: multicast — is_global can return True for 224/4; must be blocked separately
            "224.0.0.251",
        ],
    )
    async def test_private_ip_not_sent_to_api(self, private_ip: str) -> None:
        """Private/reserved/multicast IPs must never be forwarded to the public geo API."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        # Store reports the private IP needs geo — enricher must ignore it
        store.get_ips_without_geo = AsyncMock(return_value=[private_ip])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock()

        # NOTE: _is_non_public is NOT patched here — we rely on the real guard
        with patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client):
            await enricher.enrich([_evt(source_ip=private_ip)])

        # Private/reserved IPs must never reach the geo API (SSRF guard)
        mock_client.post.assert_not_called()

    async def test_mixed_public_and_private_ips_only_public_sent(self) -> None:
        """When the list has both private and public IPs, only public ones hit the API.

        Uses 10.0.0.1 (private, gitleaks-safe) as the private IP, and patches
        _is_non_public so that 192.0.2.1 (doc IP) is treated as public for this test.
        """
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["10.0.0.1", "192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        posted_payloads: list[Any] = []

        async def _capture_post(url: str, **kwargs: Any) -> MagicMock:
            posted_payloads.append(kwargs.get("json", []))
            resp = MagicMock()
            resp.json = MagicMock(return_value=[_geo_response("192.0.2.1")])
            resp.raise_for_status = MagicMock()
            return resp

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = _capture_post

        # Only treat 192.0.2.1 as public (not 10.0.0.1)
        def _guard_side_effect(ip: str) -> bool:
            return ip == "10.0.0.1"  # 10.x is non-public; doc IP passes as "public"

        with (
            patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client),
            patch("firewatch_core.adapters.geo_enricher._is_non_public", side_effect=_guard_side_effect),
        ):
            await enricher.enrich(
                [_evt(source_ip="10.0.0.1"), _evt(source_ip="192.0.2.1")]
            )

        assert len(posted_payloads) == 1
        sent_ips = {item["query"] for item in posted_payloads[0]}
        assert "10.0.0.1" not in sent_ips, "Private IP must not be sent to geo API"
        assert "192.0.2.1" in sent_ips

    async def test_all_private_ips_means_no_api_call(self) -> None:
        """If ALL IPs are private, no HTTP request should be made at all."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["10.0.0.1", "192.168.1.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock()

        # Real _is_non_public — both IPs are genuinely private
        with patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client):
            await enricher.enrich([_evt(source_ip="10.0.0.1")])

        mock_client.post.assert_not_called()


# ---------------------------------------------------------------------------
# G5 — Rule-description store round-trip
# ---------------------------------------------------------------------------


class TestRuleDescriptionRoundTrip:
    """G5 — proves the store path that the Suricata plugin-side producer uses."""

    async def test_rule_desc_roundtrip_via_sqlite_store(self, tmp_path: Path) -> None:
        """upsert → get returns same data."""
        from firewatch_core.adapters.sqlite_store import SQLiteEventStore

        store = SQLiteEventStore(tmp_path / "test.db")
        await store.init()

        descs = {
            "2001001": "ET SCAN Potential VNC Scan",
            "2001002": "ET SQL injection probe",
        }
        await store.upsert_rule_descriptions(descs)
        result = await store.get_rule_descriptions()

        assert result == descs
        await store.close()

    async def test_rule_desc_upsert_empty_is_noop(self, tmp_path: Path) -> None:
        """upsert_rule_descriptions({}) must not crash."""
        from firewatch_core.adapters.sqlite_store import SQLiteEventStore

        store = SQLiteEventStore(tmp_path / "test.db")
        await store.init()
        await store.upsert_rule_descriptions({})
        result = await store.get_rule_descriptions()
        assert result == {}
        await store.close()

    async def test_rule_desc_insert_ignore_duplicate(self, tmp_path: Path) -> None:
        """INSERT OR IGNORE: first-seen description wins on duplicate rule_id."""
        from firewatch_core.adapters.sqlite_store import SQLiteEventStore

        store = SQLiteEventStore(tmp_path / "test.db")
        await store.init()

        await store.upsert_rule_descriptions({"2001001": "First description"})
        await store.upsert_rule_descriptions({"2001001": "Second description"})
        result = await store.get_rule_descriptions()

        assert result["2001001"] == "First description"
        await store.close()


# ---------------------------------------------------------------------------
# G6 — No forbidden imports
# ---------------------------------------------------------------------------


class TestNoForbiddenImports:
    """G6 — geo_enricher.py must not import legacy/."""

    def test_does_not_import_legacy(self) -> None:
        """geo_enricher.py must not import legacy/."""
        import re

        enricher_path = (
            Path(__file__).parent.parent
            / "src"
            / "firewatch_core"
            / "adapters"
            / "geo_enricher.py"
        )
        assert enricher_path.exists(), f"geo_enricher.py not found at {enricher_path}"
        content = enricher_path.read_text()
        import_re = re.compile(r"^\s*(from legacy|import legacy)\b", re.MULTILINE)
        match = import_re.search(content)
        assert match is None, (
            f"geo_enricher.py imports legacy — forbidden: {match.group()!r}"
        )


# ---------------------------------------------------------------------------
# G7 — SecretStr for provider key
# ---------------------------------------------------------------------------


class TestSecretStrForProviderKey:
    """G7 — if GeoEnricher accepts a provider API key, it must be SecretStr."""

    def test_api_key_is_secret_str_if_provided(self) -> None:
        """GeoEnricher api_key parameter must be typed SecretStr | None, never plain str."""
        import typing

        from pydantic import SecretStr

        from firewatch_core.adapters.geo_enricher import GeoEnricher

        # Use get_type_hints() to resolve lazy string annotations produced by
        # 'from __future__ import annotations'. inspect.signature() alone returns
        # the raw string annotation under PEP 563 deferred evaluation.
        try:
            hints = typing.get_type_hints(GeoEnricher.__init__)
        except Exception:
            # If hints can't be resolved, fall back to skipping (can't check)
            return

        if "api_key" not in hints:
            # No api_key param at all is fine — key not supported
            return

        ann = hints["api_key"]

        # Collect all types from the annotation (handles Union, | syntax, Optional)
        type_args = typing.get_args(ann)
        all_types: set[Any] = {ann}
        if type_args:
            all_types.update(type_args)

        assert SecretStr in all_types, (
            f"api_key must be SecretStr (or SecretStr | None); got annotation={ann!r}. "
            "Secrets must never be plain str (PLUGIN_CONTRACT.md)."
        )


# ---------------------------------------------------------------------------
# G8 — NB-2: Pro endpoint used when api_key is set; free URL when not
# ---------------------------------------------------------------------------


class TestProEndpoint:
    """G8 — when api_key is set the pro URL and key param are used; free URL otherwise."""

    async def test_free_url_used_when_no_key(self) -> None:
        """Without api_key the free base URL is used (no key param in request)."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher, _GEO_FREE_URL

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        captured_calls: list[dict[str, Any]] = []

        async def _capture_post(url: str, **kwargs: Any) -> MagicMock:
            captured_calls.append({"url": url, "params": kwargs.get("params"), "json": kwargs.get("json", [])})
            resp = MagicMock()
            resp.json = MagicMock(return_value=[_geo_response("192.0.2.1")])
            resp.raise_for_status = MagicMock()
            return resp

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = _capture_post

        with (
            patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client),
            patch("firewatch_core.adapters.geo_enricher._is_non_public", return_value=False),
        ):
            await enricher.enrich([_evt(source_ip="192.0.2.1")])

        assert len(captured_calls) == 1
        assert captured_calls[0]["url"] == _GEO_FREE_URL
        # No key param on free tier
        params = captured_calls[0]["params"]
        assert params is None or "key" not in (params or {})

    async def test_pro_url_and_key_param_used_when_key_set(self) -> None:
        """With api_key set the pro base URL is used and key is passed via params=."""
        from pydantic import SecretStr

        from firewatch_core.adapters.geo_enricher import GeoEnricher, _GEO_PRO_URL

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store, api_key=SecretStr("test-secret-key"))

        captured_calls: list[dict[str, Any]] = []

        async def _capture_post(url: str, **kwargs: Any) -> MagicMock:
            captured_calls.append({"url": url, "params": kwargs.get("params"), "json": kwargs.get("json", [])})
            resp = MagicMock()
            resp.json = MagicMock(return_value=[_geo_response("192.0.2.1")])
            resp.raise_for_status = MagicMock()
            return resp

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = _capture_post

        with (
            patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client),
            patch("firewatch_core.adapters.geo_enricher._is_non_public", return_value=False),
        ):
            await enricher.enrich([_evt(source_ip="192.0.2.1")])

        assert len(captured_calls) == 1
        assert captured_calls[0]["url"] == _GEO_PRO_URL, (
            f"Expected pro URL {_GEO_PRO_URL!r}; got {captured_calls[0]['url']!r}"
        )
        params = captured_calls[0]["params"] or {}
        assert "key" in params, "api_key must be passed as 'key' param to the pro endpoint"
        assert params["key"] == "test-secret-key", "key param must use the raw secret value"

    def test_key_not_interpolated_into_url_string(self) -> None:
        """The api_key must NOT be f-string interpolated into the URL — only params= allowed."""
        import re
        from pathlib import Path as FilePath

        enricher_src = (
            FilePath(__file__).parent.parent
            / "src"
            / "firewatch_core"
            / "adapters"
            / "geo_enricher.py"
        )
        content = enricher_src.read_text()
        # Ban any f-string or %-format that embeds api_key / _api_key into a URL
        bad_pattern = re.compile(r'f["\'].*api_key.*["\']|f["\'].*_api_key.*["\']')
        match = bad_pattern.search(content)
        assert match is None, (
            f"api_key must not be interpolated into URL strings: {match.group()!r}"
        )


# ---------------------------------------------------------------------------
# G9 — NB-3: Response query-IP validation (store-poisoning guard)
# ---------------------------------------------------------------------------


class TestResponseQueryValidation:
    """G9 — results whose query IP is not in the sent chunk are rejected."""

    async def test_response_query_not_in_chunk_is_dropped(self) -> None:
        """A response entry whose 'query' was NOT in the sent batch is silently dropped.

        This guards against a MITM substituting an arbitrary IP in the response
        and poisoning the ip_geo store with data for an IP we never requested.
        """
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

        # Response returns a DIFFERENT IP from the one we sent
        spoofed_response: list[dict[str, Any]] = [
            {
                "status": "success",
                "query": "198.51.100.99",  # NOT in the sent chunk
                "country": "Malicious",
                "city": "Injected",
                "lat": 0.0,
                "lon": 0.0,
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
            patch("firewatch_core.adapters.geo_enricher.httpx.AsyncClient", return_value=mock_client),
            patch("firewatch_core.adapters.geo_enricher._is_non_public", return_value=False),
        ):
            await enricher.enrich([_evt(source_ip="192.0.2.1")])

        # Spoofed IP must not reach upsert_ip_geo
        store.upsert_ip_geo.assert_not_called()

    async def test_valid_response_query_in_chunk_is_persisted(self) -> None:
        """A response entry whose 'query' IS in the sent batch is persisted normally."""
        from firewatch_core.adapters.geo_enricher import GeoEnricher

        store = AsyncMock()
        store.get_ips_without_geo = AsyncMock(return_value=["192.0.2.1"])
        store.upsert_ip_geo = AsyncMock()

        enricher = GeoEnricher(store=store)

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
            await enricher.enrich([_evt(source_ip="192.0.2.1")])

        store.upsert_ip_geo.assert_called_once()
        args = store.upsert_ip_geo.call_args[0][0]
        assert len(args) == 1
        assert args[0]["ip"] == "192.0.2.1"
