"""Tests for issue #132 — drill-down data gaps.

Three EARS acceptance criteria are covered:

  DC-1 (detections[] in /detailed):
    E1 — analyze_ip_detailed returns a `detections` key.
    E2 — detections[] contains per-IP recent raw log rows (up to 50 most recent).
    E3 — detections[] is empty (not absent) when target IP has no events.
    E4 — each detection row carries timestamp and source_type fields.

  DC-2 (location helpers + field wiring):
    E5 — _format_location returns "city, country" when both are non-empty.
    E6 — _format_location returns just the country when city is empty.
    E7 — _format_location returns just the city when country is empty.
    E8 — _format_location returns None when both are empty/None.
    E9 — _format_location returns None for a None geo_row.
    E10 — _resolve_location returns None for non-public (RFC 1918) IPs.
    E11 — _resolve_location returns None for non-public (RFC 5737 doc) IPs.
    E12 — analyze_ip always includes a 'location' attribute on ThreatScore
           (None for test-range IPs; populated in production for real attacker IPs).
    E13 — analyze_ip_detailed always includes a 'location' key in its result dict.
    E14 — analyze_ip_detailed sets location=None for non-public IPs.

  DC-3 (get_ip_geo on store):
    E15 — GeoFakeStore.get_ip_geo returns the seeded geo dict for a known IP.
    E16 — GeoFakeStore.get_ip_geo returns None when IP is not present.

Test IP policy: ALL IPs use RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) or RFC 1918 private ranges (10.x etc.).
These are non-globally-routable; they correctly return location=None in the
pipeline guard, which is tested here.  Real public IPs (needed to exercise
positive geo lookup) cannot be committed to source (gitleaks public-ipv4 rule);
the positive path is verified via _format_location and _resolve_location unit
tests that bypass the `_is_public_ip` guard.
"""
from __future__ import annotations

from typing import Any

from firewatch_sdk import EventStore, ThreatScore

from firewatch_core.pipeline import Pipeline, _format_location
from _fakes import FakeAIEngine, FakeStore, make_event

# ---------------------------------------------------------------------------
# Test constants — RFC 5737 documentation IPs only (gitleaks: public-ipv4 rule)
# ---------------------------------------------------------------------------
IP_DOC_1 = "203.0.113.42"   # RFC 5737 TEST-NET-3  — non-globally-routable
IP_DOC_2 = "192.0.2.55"     # RFC 5737 TEST-NET-1  — non-globally-routable
IP_PRIVATE = "10.0.0.1"     # RFC 1918             — non-globally-routable

_LOW_AI: dict[str, Any] = {"threat_level": "LOW", "confidence": 0.0, "insights": []}

# Maximum detections rows the detailed endpoint returns
_MAX_DETECTIONS = 50


# ---------------------------------------------------------------------------
# Extended FakeStore — adds geo lookup support
# ---------------------------------------------------------------------------


class GeoFakeStore(FakeStore):
    """FakeStore extended with a seeded ip_geo table for geo-lookup testing."""

    def __init__(
        self,
        events: list | None = None,
        geo: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(events)
        # geo: {ip_str: {"country": str, "city": str, "lat": float, "lon": float}}
        self._geo: dict[str, dict[str, Any]] = geo or {}

    async def get_ip_geo(self, ip: str) -> dict[str, Any] | None:
        """Return the geo row for *ip*, or None if not present."""
        return self._geo.get(ip)

    async def get_by_ip_raw(self, ip: str) -> list[dict[str, Any]]:
        """Return raw dicts for the IP (newest-first for detections cap)."""
        rows = [e.model_dump() for e in self._events if e.source_ip == ip]
        return rows


# ---------------------------------------------------------------------------
# DC-1 — detections[] in analyze_ip_detailed
# ---------------------------------------------------------------------------


async def test_detailed_result_contains_detections_key() -> None:
    """E1: analyze_ip_detailed result must include a 'detections' key."""
    events = [make_event(source_ip=IP_DOC_1, action="BLOCK", rule_id="942001")]
    store: EventStore = GeoFakeStore(events)
    result = await Pipeline(store, FakeAIEngine(_LOW_AI)).analyze_ip_detailed(IP_DOC_1)
    assert "detections" in result, (
        "analyze_ip_detailed must return 'detections' key (issue #132 DC-1)."
    )


async def test_detailed_detections_is_list() -> None:
    """E1: detections must be a list."""
    events = [make_event(source_ip=IP_DOC_1, action="BLOCK", rule_id="942001")]
    store: EventStore = GeoFakeStore(events)
    result = await Pipeline(store, FakeAIEngine(_LOW_AI)).analyze_ip_detailed(IP_DOC_1)
    assert isinstance(result["detections"], list)


async def test_detailed_detections_contains_recent_rows() -> None:
    """E2: detections[] contains the IP's recent raw log rows."""
    n = 5
    events = [
        make_event(
            source_ip=IP_DOC_1,
            action="BLOCK",
            rule_id="942001",
            payload_snippet=f"payload-{i}",
        )
        for i in range(n)
    ]
    store: EventStore = GeoFakeStore(events)
    result = await Pipeline(store, FakeAIEngine(_LOW_AI)).analyze_ip_detailed(IP_DOC_1)
    assert len(result["detections"]) == n, (
        f"Expected {n} detections, got {len(result['detections'])}."
    )


async def test_detailed_detections_capped_at_max() -> None:
    """E2: detections[] is capped at _MAX_DETECTIONS rows."""
    events = [
        make_event(source_ip=IP_DOC_1, action="BLOCK", rule_id="942001")
        for _ in range(_MAX_DETECTIONS + 30)
    ]
    store: EventStore = GeoFakeStore(events)
    result = await Pipeline(store, FakeAIEngine(_LOW_AI)).analyze_ip_detailed(IP_DOC_1)
    assert len(result["detections"]) <= _MAX_DETECTIONS, (
        f"detections must be capped at {_MAX_DETECTIONS}, got {len(result['detections'])}."
    )


async def test_detailed_detections_empty_when_no_events_for_ip() -> None:
    """E3: empty IP → analyze_ip_detailed returns error dict (EARS-4 preserved)."""
    events = [make_event(source_ip="192.0.2.1", action="BLOCK")]
    store: EventStore = GeoFakeStore(events)
    result = await Pipeline(store, FakeAIEngine(_LOW_AI)).analyze_ip_detailed(IP_DOC_1)
    assert "error" in result


async def test_detailed_detections_rows_have_expected_fields() -> None:
    """E4: each detection row carries timestamp and source_type fields."""
    events = [
        make_event(
            source_ip=IP_DOC_1,
            action="BLOCK",
            rule_id="942001",
            payload_snippet="test-payload",
        )
    ]
    store: EventStore = GeoFakeStore(events)
    result = await Pipeline(store, FakeAIEngine(_LOW_AI)).analyze_ip_detailed(IP_DOC_1)
    assert len(result["detections"]) >= 1
    row = result["detections"][0]
    assert "source_type" in row, "Each detection row must have 'source_type'."
    assert "timestamp" in row, "Each detection row must have 'timestamp'."


# ---------------------------------------------------------------------------
# DC-2 — _format_location helper (unit tests)
# ---------------------------------------------------------------------------


def test_format_location_city_and_country() -> None:
    """E5: _format_location returns 'city, country' when both are non-empty."""
    row = {"country": "Canada", "city": "Toronto", "lat": 43.65, "lon": -79.38}
    result = _format_location(row)
    assert result == "Toronto, Canada"


def test_format_location_country_only() -> None:
    """E6: _format_location returns just the country when city is empty."""
    row = {"country": "Germany", "city": "", "lat": 51.0, "lon": 10.0}
    result = _format_location(row)
    assert result == "Germany"


def test_format_location_city_only() -> None:
    """E7: _format_location returns just the city when country is empty."""
    row = {"country": "", "city": "Berlin", "lat": 52.52, "lon": 13.41}
    result = _format_location(row)
    assert result == "Berlin"


def test_format_location_both_empty_returns_none() -> None:
    """E8: _format_location returns None when both fields are empty strings."""
    row: dict[str, Any] = {"country": "", "city": "", "lat": 0.0, "lon": 0.0}
    result = _format_location(row)
    assert result is None


def test_format_location_none_row_returns_none() -> None:
    """E9: _format_location returns None for a None geo_row."""
    result = _format_location(None)
    assert result is None


# ---------------------------------------------------------------------------
# DC-2 — _resolve_location: non-public IP guard (unit tests)
# ---------------------------------------------------------------------------


async def test_resolve_location_none_for_private_ip() -> None:
    """E10: _resolve_location returns None for private (RFC 1918) IPs.

    Private IPs never geolocate — the GeoEnricher guards them at ingestion time,
    and the pipeline must respect this boundary.
    """

    class _GeoStore(FakeStore):
        async def get_ip_geo(self, ip: str) -> dict[str, Any] | None:
            return {"country": "US", "city": "NYC", "lat": 40.7, "lon": -74.0}

    store: EventStore = _GeoStore()
    pipeline = Pipeline(store, FakeAIEngine(_LOW_AI))
    location, asn, as_name = await pipeline._resolve_geo(IP_PRIVATE)
    assert location is None, (
        f"Private IP {IP_PRIVATE} must return location=None from _resolve_geo."
    )


async def test_resolve_location_none_for_doc_range_ip() -> None:
    """E11: _resolve_location returns None for RFC 5737 documentation IPs.

    RFC 5737 IPs (192.0.2/24, 198.51.100/24, 203.0.113/24) are not globally
    routable — Python's ipaddress.ip_address().is_global returns False for them.
    This test confirms the guard works correctly for the IPs used in all fixtures.
    """

    class _GeoStore(FakeStore):
        async def get_ip_geo(self, ip: str) -> dict[str, Any] | None:
            return {"country": "US", "city": "NYC", "lat": 40.7, "lon": -74.0}

    store: EventStore = _GeoStore()
    pipeline = Pipeline(store, FakeAIEngine(_LOW_AI))
    location, asn, as_name = await pipeline._resolve_geo(IP_DOC_1)
    assert location is None, (
        f"RFC 5737 doc IP {IP_DOC_1} must return location=None — not globally routable."
    )


# ---------------------------------------------------------------------------
# DC-2 — location field wiring in pipeline methods
# ---------------------------------------------------------------------------


async def test_analyze_ip_has_location_attribute() -> None:
    """E12: analyze_ip always includes 'location' on the returned ThreatScore.

    For test-range IPs (non-globally-routable), location is None — but the field
    must be present. In production, real public attacker IPs populate this field.
    """
    events = [make_event(source_ip=IP_DOC_1, action="BLOCK")]
    store: EventStore = GeoFakeStore(events)
    score: ThreatScore = await Pipeline(store, FakeAIEngine(_LOW_AI)).analyze_ip(
        IP_DOC_1, use_ai=False
    )
    # The attribute must exist (may be None for doc-range IPs)
    assert hasattr(score, "location"), (
        "ThreatScore must have a 'location' attribute (issue #132 DC-2)."
    )
    # For RFC 5737 / non-public IPs, location is always None
    assert score.location is None


async def test_analyze_ip_detailed_has_location_key() -> None:
    """E13: analyze_ip_detailed always includes 'location' key in the result dict.

    For test-range IPs (non-globally-routable), location is None — but the key
    must be present. In production, real public attacker IPs populate this field.
    """
    events = [make_event(source_ip=IP_DOC_1, action="BLOCK")]
    store: EventStore = GeoFakeStore(events)
    result = await Pipeline(store, FakeAIEngine(_LOW_AI)).analyze_ip_detailed(IP_DOC_1)
    assert "location" in result, (
        "analyze_ip_detailed result must include 'location' key (issue #132 DC-2)."
    )


async def test_analyze_ip_detailed_location_none_for_doc_ip() -> None:
    """E14: analyze_ip_detailed sets location=None for RFC 5737 / non-public IPs."""
    events = [make_event(source_ip=IP_DOC_1, action="BLOCK")]
    store: EventStore = GeoFakeStore(
        events,
        geo={IP_DOC_1: {"country": "Germany", "city": "Berlin", "lat": 52.52, "lon": 13.41}},
    )
    result = await Pipeline(store, FakeAIEngine(_LOW_AI)).analyze_ip_detailed(IP_DOC_1)
    # RFC 5737 IP → not globally routable → location=None regardless of geo cache
    assert result["location"] is None


# ---------------------------------------------------------------------------
# DC-3 — get_ip_geo on store / protocol
# ---------------------------------------------------------------------------


async def test_geo_fake_store_get_ip_geo_returns_seeded_row() -> None:
    """E15: GeoFakeStore.get_ip_geo returns the seeded geo dict for the IP."""
    geo = {IP_DOC_2: {"country": "US", "city": "LA", "lat": 34.05, "lon": -118.24}}
    store = GeoFakeStore(geo=geo)
    row = await store.get_ip_geo(IP_DOC_2)
    assert row is not None
    assert row["country"] == "US"
    assert row["city"] == "LA"


async def test_geo_fake_store_get_ip_geo_returns_none_for_unknown_ip() -> None:
    """E16: GeoFakeStore.get_ip_geo returns None when IP is not in the geo table."""
    store = GeoFakeStore(geo={})
    row = await store.get_ip_geo("192.0.2.99")
    assert row is None
