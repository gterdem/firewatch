"""Tests for the MB.1 read/query REST API (ADR-0029, issue #53).

EARS → test mapping:

  Ubiquitous (dependency rule):
    U1 — The API package imports only sdk/core; never legacy/ or a concrete plugin.
         → test_no_legacy_import_in_new_routes

  Ubiquitous (thin controllers — OCSF preserved via store/pipeline):
    Verified implicitly: handlers delegate to fakes; no business logic in routes.

  Event-driven:
    E1  — GET /health returns {status, store} (200).
          → test_health_returns_200_with_status_fields
    E2  — GET /health with no store returns store="unavailable".
          → test_health_no_store_returns_unavailable
    E3  — GET /threats returns list[ThreatScore] shapes.
          → test_list_threats_returns_threatscore_list
    E4  — GET /threats/{ip} returns ThreatScore for a known IP.
          → test_get_threat_known_ip_returns_threatscore
    E5  — GET /threats/{ip}/detailed returns the augmented dict.
          → test_get_threat_detailed_returns_dict
    E6  — GET /logs/paginated returns the store envelope verbatim.
          → test_logs_paginated_returns_store_envelope
    E7  — GET /logs/paginated cursor round-trip: next_cursor from page N is
          accepted as cursor on page N+1.
          → test_logs_paginated_cursor_roundtrip
    E8  — GET /logs/recent returns a list.
          → test_logs_recent_returns_list
    E9  — GET /logs/ip/{ip} returns a list.
          → test_logs_by_ip_returns_list
    E10 — GET /logs/categories returns a list.
          → test_logs_categories_returns_list
    E11 — GET /logs/category-summary returns a list with {category, count}.
          → test_logs_category_summary_returns_list
    E12 — GET /logs/timeline returns a list.
          → test_logs_timeline_returns_list
    E13 — GET /logs/ips returns a list of strings.
          → test_logs_ips_returns_list
    E14 — GET /rules returns a dict.
          → test_rules_returns_dict
    E15 — GET /analytics/geo returns a list.
          → test_analytics_geo_returns_list
    E16 — GET /analytics/summary returns a dict.
          → test_analytics_summary_returns_dict
    E17 — GET /analytics/categories-timeline returns a list.
          → test_analytics_categories_timeline_returns_list
    E18 — GET /stats returns a dict with total_logs key.
          → test_stats_returns_dict
    E19 — GET /stats returns source_health[] (one entry per installed plugin).
          → test_stats_returns_source_health_list
    E20 — GET /stats returns last_updated from the store.
          → test_stats_returns_last_updated

  Unwanted:
    W1  — GET /threats/{ip} for unknown IP → 404, not empty-200.
          → test_get_threat_unknown_ip_returns_404
    W2  — GET /threats/{ip}/detailed for unknown IP → 404.
          → test_get_threat_detailed_unknown_ip_returns_404
    W3  — GET /logs/paginated with malformed cursor → well-formed envelope, not 500.
          → test_logs_paginated_malformed_cursor_no_500
    W4  — GET /logs/paginated with invalid limit (< 1) → 422.
          → test_logs_paginated_invalid_limit_returns_422

  State-driven (behavior-preserving refactor):
    S1  — Existing discovery route GET /sources/types still returns 200 with entries.
          → test_discovery_route_still_works_after_refactor
    S2  — Existing config routes GET/PUT /config/sources/{type_key} still work.
          → test_config_routes_still_work_after_refactor
"""
from __future__ import annotations

import importlib
import types
from datetime import datetime, timezone
from typing import Any

from fastapi.testclient import TestClient

from firewatch_sdk import ThreatScore

from firewatch_api.app import create_app


# ---------------------------------------------------------------------------
# Fake store
# ---------------------------------------------------------------------------


class FakeEventStore:
    """Minimal in-memory EventStore fake for API route tests."""

    def __init__(self) -> None:
        self._ips: list[str] = []
        self._logs: list[dict[str, Any]] = []
        self._rules: dict[str, str] = {}
        self._paginated_result: dict[str, Any] = {
            "logs": [],
            "next_cursor": None,
            "has_more": False,
            "total_matching": 0,
        }

    async def _conn(self) -> Any:
        """Fake connection — just returns self for health check."""
        return self

    async def get_all_ips(self) -> list[str]:
        return list(self._ips)

    async def get_by_ip_raw(self, ip: str) -> list[dict[str, Any]]:
        return [r for r in self._logs if r.get("source_ip") == ip]

    async def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._logs[:limit]

    async def get_paginated(
        self,
        limit: int = 100,
        filters: Any = None,
    ) -> dict[str, Any]:
        return dict(self._paginated_result)

    async def get_categories(self) -> list[dict[str, Any]]:
        # Canonical shape: {category, count} only — no rule_id/filter (issue #325)
        return [{"category": "SQL Injection", "count": 3}]

    async def get_category_summary(self) -> list[dict[str, Any]]:
        return [{"category": "SQL Injection", "count": 3}]

    async def get_timeline(
        self, start: str | None = None, end: str | None = None
    ) -> list[dict[str, Any]]:
        return [{"hour": "2026-06-01", "total": 5, "blocked": 2, "granularity": "daily"}]

    async def get_rule_descriptions(self) -> dict[str, str]:
        return dict(self._rules)

    async def get_analytics_geo(self) -> list[dict[str, Any]]:
        return [{"ip": "10.0.0.1", "country": "US", "city": "NYC", "lat": 40.7, "lon": -74.0,
                 "total_events": 3, "blocked": 1, "rules_triggered": 2}]

    async def get_analytics_summary(self) -> dict[str, Any]:
        return {"total_ips": 2, "total_events": 10, "total_blocked": 3,
                "block_rate": 30.0, "top_country": "US", "unique_countries": 2, "top_rule": ""}

    async def get_categories_timeline(
        self, start: str | None = None, end: str | None = None
    ) -> list[dict[str, Any]]:
        return [{"period": "2026-06-01", "sqli": 2, "xss": 0, "total": 2, "granularity": "daily"}]

    async def get_attack_dispositions(
        self, top_n: int = 5
    ) -> list[dict[str, Any]]:
        return [
            {"attack_type": "SQL Injection", "action": "BLOCK", "count": 920},
            {"attack_type": "SQL Injection", "action": "ALERT", "count": 60},
            {"attack_type": "Port Scan", "action": "ALERT", "count": 1200},
        ]

    async def get_stats(self) -> dict[str, Any]:
        return {"total_logs": 10, "total_ips": 2, "blocked_percentage": 30.0,
                "top_attack_types": [], "last_updated": None}

    async def source_health(self) -> list[dict[str, Any]]:
        return []

    async def get_ip_counterfactual(self, ip: str) -> dict[str, Any]:
        # Default: simulate an IP with 1350 total, 146 blocked → 1204 unblocked
        if ip == "192.0.2.1":
            return {"total_events": 1350, "blocked_events": 146, "unblocked_events": 1204}
        if ip == "192.0.2.99":
            # All events already blocked — unblocked_events == 0
            return {"total_events": 150, "blocked_events": 150, "unblocked_events": 0}
        # Unknown IP — honest zero
        return {"total_events": 0, "blocked_events": 0, "unblocked_events": 0}


# ---------------------------------------------------------------------------
# Fake pipeline
# ---------------------------------------------------------------------------


def _make_threatscore(ip: str, total: int = 5) -> ThreatScore:
    now = datetime.now(timezone.utc)
    return ThreatScore(
        source_ip=ip,
        threat_level="HIGH",
        score=75,
        total_events=total,
        blocked_events=2,
        attack_types=["SQL Injection"],
        first_seen=now,
        last_seen=now,
        source_types=["suricata"],
        ai_status="disabled",
    )


class FakePipeline:
    """Minimal Pipeline fake that returns pre-baked ThreatScores."""

    def __init__(self, known_ips: dict[str, ThreatScore] | None = None) -> None:
        self._known: dict[str, ThreatScore] = known_ips or {}

    async def analyze_ip(self, ip: str, *, use_ai: bool = True) -> ThreatScore:
        if ip in self._known:
            return self._known[ip]
        # Unknown IP → score=0, total_events=0 (same as real pipeline).
        now = datetime.now(timezone.utc)
        return ThreatScore(
            source_ip=ip,
            threat_level="LOW",
            score=0,
            total_events=0,
            blocked_events=0,
            attack_types=[],
            first_seen=now,
            last_seen=now,
            ai_status="disabled",
        )

    async def analyze_ip_detailed(
        self, ip: str, *, include_ai: bool = True
    ) -> dict[str, Any]:
        if ip in self._known:
            base: dict[str, Any] = {
                "source_ip": ip,
                "score": 75,
                "threat_level": "HIGH",
                "total_events": 5,
                "blocked_events": 2,
                "attack_types": ["SQL Injection"],
                # issue #132: detections[] and location are included
                "detections": [
                    {
                        "timestamp": "2026-06-01T00:00:00",
                        "source_type": "suricata",
                        "rule_id": "942001",
                        "payload_snippet": "test",
                    }
                ],
                "location": "Toronto, Canada",
            }
            # Issue #268: honest ai_status when AI was explicitly skipped.
            if not include_ai:
                base["ai_status"] = "skipped"
            return base
        return {"error": "No logs found"}


# ---------------------------------------------------------------------------
# Helper: build test client
# ---------------------------------------------------------------------------


def _make_client(
    store: FakeEventStore | None = None,
    pipeline: FakePipeline | None = None,
    registry: dict | None = None,
    config_store: Any = None,
) -> TestClient:
    """Build a TestClient with fake dependencies injected."""
    from _api_fakes import FakePullPlugin

    if registry is None:
        registry = {"suricata": FakePullPlugin()}
    app = create_app(
        registry=registry,
        config_store=config_store,
        event_store=store,
        pipeline=pipeline,
    )
    return TestClient(app)


def _store_with_ip(ip: str) -> FakeEventStore:
    """Return a store pre-seeded with a single known IP."""
    s = FakeEventStore()
    s._ips = [ip]
    s._logs = [{"source_ip": ip, "action": "BLOCK", "rule_id": "942001", "timestamp": "2026-06-01T00:00:00"}]
    return s


# ===========================================================================
# U1 — dependency rule: no legacy/ in new route modules
# ===========================================================================


def test_no_legacy_import_in_new_routes() -> None:
    """New route modules must not import legacy/ or concrete plugins."""
    forbidden = ("legacy", "firewatch_suricata", "firewatch_syslog")
    new_modules = [
        "firewatch_api.routes.threats",
        "firewatch_api.routes.logs",
        "firewatch_api.routes.analytics",
        "firewatch_api.routes.meta",
        "firewatch_api.routes.discovery",
        "firewatch_api.schemas",
        "firewatch_api.deps",
    ]
    for mod_name in new_modules:
        mod = importlib.import_module(mod_name)
        for name, obj in vars(mod).items():
            if isinstance(obj, types.ModuleType):
                for prefix in forbidden:
                    assert not obj.__name__.startswith(prefix), (
                        f"{mod_name} imports forbidden module {obj.__name__!r} via {name!r}"
                    )


# ===========================================================================
# E1/E2 — GET /health
# ===========================================================================


def test_health_returns_200_with_status_fields() -> None:
    """GET /health returns 200 with {status, store} when store is present."""
    store = FakeEventStore()
    client = _make_client(store=store)
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "store" in data


def test_health_no_store_returns_unavailable() -> None:
    """GET /health with no event store reports store=unavailable."""
    client = _make_client(store=None)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["store"] == "unavailable"


# ===========================================================================
# E3 — GET /threats
# ===========================================================================


def test_list_threats_returns_threatscore_list() -> None:
    """GET /threats returns a list[ThreatScore]-shaped response."""
    ip = "10.0.0.1"
    score = _make_threatscore(ip)
    store = FakeEventStore()
    store._ips = [ip]
    pipeline = FakePipeline({ip: score})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get("/threats")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["source_ip"] == ip
    assert data[0]["threat_level"] == "HIGH"
    assert data[0]["score"] == 75


# ===========================================================================
# E4 + W1 — GET /threats/{ip}
# ===========================================================================


def test_get_threat_known_ip_returns_threatscore() -> None:
    """GET /threats/{ip} returns ThreatScore for a known IP."""
    ip = "10.0.0.2"
    score = _make_threatscore(ip)
    store = _store_with_ip(ip)
    pipeline = FakePipeline({ip: score})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get(f"/threats/{ip}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["source_ip"] == ip
    assert body["threat_level"] == "HIGH"
    assert "score" in body
    assert "total_events" in body
    assert "blocked_events" in body
    assert "attack_types" in body
    assert "first_seen" in body
    assert "last_seen" in body
    assert "ai_status" in body


def test_get_threat_unknown_ip_returns_404() -> None:
    """GET /threats/{ip} for an IP with no events returns 404, not an empty-200.

    ADR-0029 D3 / RFC 9110 §15.5.5: unknown resource is a missing resource.
    """
    store = FakeEventStore()
    pipeline = FakePipeline({})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get("/threats/203.0.113.4")
    assert resp.status_code == 404, (
        f"Expected 404 for unknown IP, got {resp.status_code}. "
        "ADR-0029 D3: unknown IP must return 404, not an empty ThreatScore."
    )


# ===========================================================================
# E5 + W2 — GET /threats/{ip}/detailed
# ===========================================================================


def test_get_threat_detailed_returns_dict() -> None:
    """GET /threats/{ip}/detailed returns an augmented dict with score, threat_level etc."""
    ip = "10.0.0.3"
    score = _make_threatscore(ip)
    store = _store_with_ip(ip)
    pipeline = FakePipeline({ip: score})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get(f"/threats/{ip}/detailed")
    assert resp.status_code == 200
    body = resp.json()
    assert body["source_ip"] == ip
    assert "score" in body
    assert "threat_level" in body
    assert "total_events" in body


def test_get_threat_detailed_unknown_ip_returns_404() -> None:
    """GET /threats/{ip}/detailed for unknown IP returns 404."""
    store = FakeEventStore()
    pipeline = FakePipeline({})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get("/threats/203.0.113.9/detailed")
    assert resp.status_code == 404


# ===========================================================================
# Issue #268 — ?ai=false fast path (staged honest AI loading)
# ===========================================================================


def test_detailed_ai_false_returns_skipped_status() -> None:
    """Issue #268: GET /threats/{ip}/detailed?ai=false must return ai_status='skipped'.

    The server MUST NOT claim AI success when the engine was not called.
    ADR-0035 honesty rule: ai_status reflects what actually ran.
    """
    ip = "198.51.100.20"
    score = _make_threatscore(ip)
    store = _store_with_ip(ip)
    pipeline = FakePipeline({ip: score})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get(f"/threats/{ip}/detailed?ai=false")
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("ai_status") == "skipped", (
        f"Expected ai_status='skipped' when ?ai=false, got {body.get('ai_status')!r}. "
        "The server must never claim AI success when the engine was not called (ADR-0035)."
    )


def test_detailed_ai_true_default_unchanged() -> None:
    """Issue #268: GET /threats/{ip}/detailed (default) still works — no regression.

    The ai=true default must preserve the existing behavior; existing callers
    that omit the param continue to get the full detailed response.
    """
    ip = "198.51.100.21"
    score = _make_threatscore(ip)
    store = _store_with_ip(ip)
    pipeline = FakePipeline({ip: score})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get(f"/threats/{ip}/detailed")
    assert resp.status_code == 200
    body = resp.json()
    assert "score" in body
    assert "threat_level" in body
    # Default path does not stamp ai_status='skipped'.
    assert body.get("ai_status") != "skipped"


def test_detailed_ai_false_still_returns_rule_fields() -> None:
    """Issue #268: ?ai=false fast path must still return all rule-derived fields.

    The rule sections (score, threat_level, total_events, detections, location)
    must be present — they don't depend on the AI engine.
    """
    ip = "198.51.100.22"
    score = _make_threatscore(ip)
    store = _store_with_ip(ip)
    pipeline = FakePipeline({ip: score})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get(f"/threats/{ip}/detailed?ai=false")
    assert resp.status_code == 200
    body = resp.json()
    for required_field in ("score", "threat_level", "total_events", "blocked_events",
                           "attack_types", "detections", "location"):
        assert required_field in body, (
            f"Rule-derived field '{required_field}' missing from ?ai=false response."
        )


# ===========================================================================
# Issue #132 — DC-1: detections[] in /threats/{ip}/detailed
# ===========================================================================


def test_detailed_response_contains_detections_array() -> None:
    """Issue #132 DC-1: GET /threats/{ip}/detailed must include 'detections' array.

    The frontend renders a 'Recent Logs' table when detections is non-empty.
    """
    ip = "198.51.100.7"
    score = _make_threatscore(ip)
    store = _store_with_ip(ip)
    pipeline = FakePipeline({ip: score})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get(f"/threats/{ip}/detailed")
    assert resp.status_code == 200
    body = resp.json()
    assert "detections" in body, (
        "GET /threats/{ip}/detailed must include 'detections' key (issue #132 DC-1)."
    )
    assert isinstance(body["detections"], list)


def test_detailed_detections_contain_log_fields() -> None:
    """Issue #132 DC-1: detections[] entries carry log fields (timestamp, source_type, etc.)."""
    ip = "198.51.100.8"
    score = _make_threatscore(ip)
    store = _store_with_ip(ip)
    pipeline = FakePipeline({ip: score})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get(f"/threats/{ip}/detailed")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["detections"]) >= 1
    det = body["detections"][0]
    assert "timestamp" in det
    assert "source_type" in det


# ===========================================================================
# Issue #132 — DC-2: location in /threats/{ip}/detailed
# ===========================================================================


def test_detailed_response_contains_location_field() -> None:
    """Issue #132 DC-2: GET /threats/{ip}/detailed must include 'location' key."""
    ip = "198.51.100.9"
    score = _make_threatscore(ip)
    store = _store_with_ip(ip)
    pipeline = FakePipeline({ip: score})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get(f"/threats/{ip}/detailed")
    assert resp.status_code == 200
    body = resp.json()
    assert "location" in body, (
        "GET /threats/{ip}/detailed must include 'location' key (issue #132 DC-2)."
    )


# ===========================================================================
# Issue #328 — detections[] rows must expose payload_snippet (API contract pin)
#
# EARS:
#   - The API contract test SHALL fail if detections[] rows stop carrying
#     payload_snippet (the canonical field — matches SDK NormalizedEvent and
#     the logs DB column).
#   - Ubiquitous (ADR-0029 D3): payload content is attacker-controlled telemetry;
#     render as text nodes only.
# ===========================================================================


def test_detailed_detections_contain_payload_snippet_field() -> None:
    """Issue #328: detections[] rows must carry 'payload_snippet' (the canonical field).

    The SELECT * FROM logs path returns every column; this test pins that the
    /detailed endpoint does not strip or rename payload_snippet before returning
    to the client — guarding against silent schema drift that would cause the
    Recent Logs Payload column in IpPanel.tsx to go blank.

    EARS: The API contract test SHALL fail if detections[] rows stop carrying
    payload_snippet (issue #328).
    """
    ip = "198.51.100.11"
    score = _make_threatscore(ip)
    store = _store_with_ip(ip)
    pipeline = FakePipeline({ip: score})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get(f"/threats/{ip}/detailed")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["detections"]) >= 1, (
        "Expected at least one detection row to assert payload_snippet presence."
    )
    det = body["detections"][0]
    assert "payload_snippet" in det, (
        "detections[] rows must carry 'payload_snippet' — the canonical per-row payload "
        "field that IpPanel.tsx reads for the Recent Logs Payload column (issue #328). "
        "The field name must match the SDK NormalizedEvent model and the logs DB column."
    )


def test_detailed_detections_payload_snippet_is_string_or_null() -> None:
    """Issue #328: payload_snippet in detections[] is a string or null, never absent.

    Confirms the field is always present in the per-row dict so callers may safely
    read it with a null-coalesce (`payload_snippet ?? ''`) without key-existence guards.
    ADR-0029 D3: if non-null, the value is attacker-controlled; render as text only.
    """
    ip = "198.51.100.12"
    score = _make_threatscore(ip)
    store = _store_with_ip(ip)
    pipeline = FakePipeline({ip: score})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get(f"/threats/{ip}/detailed")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["detections"]) >= 1
    det = body["detections"][0]
    payload_val = det.get("payload_snippet")
    assert payload_val is None or isinstance(payload_val, str), (
        f"payload_snippet must be a string or null, got {type(payload_val).__name__!r}. "
        "ADR-0029 D3: attacker-controlled field — text nodes only (issue #328)."
    )


def test_detailed_detections_contain_all_ip_panel_fields() -> None:
    """Issue #328: detections[] rows must expose every field IpPanel.tsx consumes.

    The frontend Recent Logs table reads: timestamp, source_type, rule_id,
    category, payload_snippet.  This test prevents a silent SELECT * drift from
    dropping any of those columns — a miss here means a blank column for SOC analysts.
    """
    ip = "198.51.100.13"
    score = _make_threatscore(ip)
    store = _store_with_ip(ip)
    pipeline = FakePipeline({ip: score})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get(f"/threats/{ip}/detailed")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["detections"]) >= 1
    det = body["detections"][0]
    required_keys = ("timestamp", "source_type", "rule_id", "payload_snippet")
    for key in required_keys:
        assert key in det, (
            f"detections[] row missing '{key}' — IpPanel.tsx reads this field for "
            f"the Recent Logs table (issue #328). Present keys: {sorted(det.keys())}."
        )


# ===========================================================================
# E6/E7/W3/W4 — GET /logs/paginated
# ===========================================================================


def test_logs_paginated_returns_store_envelope() -> None:
    """GET /logs/paginated returns the store envelope verbatim: {logs, next_cursor, has_more, total_matching}.

    ADR-0029 D2: expose verbatim, never re-wrap or rename keys.
    """
    store = FakeEventStore()
    store._paginated_result = {
        "logs": [{"source_ip": "203.0.113.4", "action": "BLOCK"}],
        "next_cursor": "2026-06-01T00:00:00|42",
        "has_more": True,
        "total_matching": 100,
    }
    client = _make_client(store=store)

    resp = client.get("/logs/paginated")
    assert resp.status_code == 200
    body = resp.json()
    # All four envelope keys must be present (verbatim — no rename)
    assert "logs" in body
    assert "next_cursor" in body
    assert "has_more" in body
    assert "total_matching" in body
    assert body["next_cursor"] == "2026-06-01T00:00:00|42"
    assert body["has_more"] is True
    assert body["total_matching"] == 100
    assert body["logs"][0]["source_ip"] == "203.0.113.4"


def test_logs_paginated_cursor_roundtrip() -> None:
    """next_cursor from the store response is echoed back as the cursor param.

    The API must accept the cursor verbatim and pass it to the store's
    FilterSpec.cursor field.  We verify this with a fake store that records
    the FilterSpec it receives.
    """

    received_filters: list[Any] = []

    class _CapturingStore(FakeEventStore):
        async def get_paginated(self, limit: int = 100, filters: Any = None) -> dict[str, Any]:
            received_filters.append(filters)
            return {
                "logs": [],
                "next_cursor": None,
                "has_more": False,
                "total_matching": 0,
            }

    store = _CapturingStore()
    client = _make_client(store=store)

    cursor_val = "2026-06-01T12:00:00|4815"
    resp = client.get(f"/logs/paginated?cursor={cursor_val}")
    assert resp.status_code == 200
    assert len(received_filters) == 1
    assert received_filters[0].cursor == cursor_val


def test_logs_paginated_malformed_cursor_no_500() -> None:
    """A malformed cursor must produce a well-formed envelope, not a 500.

    ADR-0029 D2 EARS unwanted criterion: malformed cursor → first/empty page.
    The store already tolerates this (silently ignores bad cursor), so the API
    just passes it through.
    """
    store = FakeEventStore()
    client = _make_client(store=store)

    resp = client.get("/logs/paginated?cursor=NOT_A_VALID_CURSOR")
    assert resp.status_code == 200, (
        f"Malformed cursor must return 200, not {resp.status_code}"
    )
    body = resp.json()
    assert "logs" in body
    assert "next_cursor" in body
    assert "has_more" in body
    assert "total_matching" in body


def test_logs_paginated_invalid_limit_returns_422() -> None:
    """GET /logs/paginated with limit=0 (< 1) returns 422 (invalid query param).

    ADR-0029 D3: validation failures on query params return 422.
    """
    store = FakeEventStore()
    client = _make_client(store=store)

    resp = client.get("/logs/paginated?limit=0")
    assert resp.status_code == 422, (
        f"Expected 422 for limit=0, got {resp.status_code}"
    )


# ===========================================================================
# F1 — malformed date params return 422 (security fix, ADR-0029 D3)
# ===========================================================================


def test_logs_timeline_malformed_start_returns_422() -> None:
    """GET /logs/timeline?start=not-a-date must return 422, not 500.

    ADR-0029 D3: a malformed ``start`` query param must produce a 422
    validation error at the route layer, before reaching the store.
    """
    store = FakeEventStore()
    client = _make_client(store=store)

    resp = client.get("/logs/timeline?start=not-a-date")
    assert resp.status_code == 422, (
        f"Expected 422 for malformed start param, got {resp.status_code}"
    )


def test_logs_timeline_malformed_end_returns_422() -> None:
    """GET /logs/timeline?end=not-a-date must return 422, not 500."""
    store = FakeEventStore()
    client = _make_client(store=store)

    resp = client.get("/logs/timeline?end=not-a-date")
    assert resp.status_code == 422, (
        f"Expected 422 for malformed end param, got {resp.status_code}"
    )


def test_logs_timeline_valid_iso_date_passes() -> None:
    """GET /logs/timeline with a valid ISO date still returns 200."""
    store = FakeEventStore()
    client = _make_client(store=store)

    resp = client.get("/logs/timeline?start=2026-01-01&end=2026-06-01")
    assert resp.status_code == 200


def test_analytics_categories_timeline_malformed_start_returns_422() -> None:
    """GET /analytics/categories-timeline?start=not-a-date must return 422, not 500.

    ADR-0029 D3: malformed date query params must be caught at the route layer.
    """
    store = FakeEventStore()
    client = _make_client(store=store)

    resp = client.get("/analytics/categories-timeline?start=not-a-date")
    assert resp.status_code == 422, (
        f"Expected 422 for malformed start param, got {resp.status_code}"
    )


def test_analytics_categories_timeline_valid_iso_date_passes() -> None:
    """GET /analytics/categories-timeline with a valid ISO date still returns 200."""
    store = FakeEventStore()
    client = _make_client(store=store)

    resp = client.get("/analytics/categories-timeline?start=2026-01-01T00:00:00")
    assert resp.status_code == 200


# ===========================================================================
# E8–E13 — other log routes
# ===========================================================================


def test_logs_recent_returns_list() -> None:
    """GET /logs/recent returns a list."""
    store = FakeEventStore()
    store._logs = [{"source_ip": "203.0.113.4", "action": "BLOCK"}]
    client = _make_client(store=store)
    resp = client.get("/logs/recent")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_logs_by_ip_returns_list() -> None:
    """GET /logs/ip/{ip} returns a list of log rows."""
    ip = "10.0.0.5"
    store = _store_with_ip(ip)
    client = _make_client(store=store)
    resp = client.get(f"/logs/ip/{ip}")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert data[0]["source_ip"] == ip


def test_logs_categories_returns_list() -> None:
    """GET /logs/categories returns a list of {rule_id, category, count, filter}."""
    store = FakeEventStore()
    client = _make_client(store=store)
    resp = client.get("/logs/categories")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert "category" in data[0]


def test_logs_category_summary_returns_list() -> None:
    """GET /logs/category-summary returns a list with {category, count} entries.

    Backing method: store.get_category_summary (added in MB.1).
    """
    store = FakeEventStore()
    client = _make_client(store=store)
    resp = client.get("/logs/category-summary")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) > 0
    entry = data[0]
    assert "category" in entry
    assert "count" in entry


def test_logs_timeline_returns_list() -> None:
    """GET /logs/timeline returns a list of period buckets."""
    store = FakeEventStore()
    client = _make_client(store=store)
    resp = client.get("/logs/timeline")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert "hour" in data[0]
    assert "total" in data[0]


def test_logs_ips_returns_list() -> None:
    """GET /logs/ips returns a list of distinct source IP strings."""
    store = FakeEventStore()
    store._ips = ["203.0.113.1", "203.0.113.2"]
    client = _make_client(store=store)
    resp = client.get("/logs/ips")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert "203.0.113.1" in data


# ===========================================================================
# E14 — GET /rules (issue #132: array shape, not dict)
# ===========================================================================


def test_rules_returns_array() -> None:
    """GET /rules returns a RuleDescription[] array (issue #132 DC-3).

    The frontend fetchRules() expects a list, not a dict.  Each entry must
    carry rule_id and name fields.
    """
    store = FakeEventStore()
    store._rules = {"942001": "SQL Injection attempt"}
    client = _make_client(store=store)
    resp = client.get("/rules")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list), (
        f"GET /rules must return a list, got {type(data).__name__!r} "
        "(issue #132 DC-3: frontend expects RuleDescription[])."
    )
    assert len(data) == 1
    entry = data[0]
    assert entry["rule_id"] == "942001"
    assert entry["name"] == "SQL Injection attempt"
    assert "description" in entry


def test_rules_empty_store_returns_empty_array() -> None:
    """GET /rules with no rule descriptions returns an empty array."""
    store = FakeEventStore()
    store._rules = {}
    client = _make_client(store=store)
    resp = client.get("/rules")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert data == []


def test_rules_multiple_entries_all_returned() -> None:
    """GET /rules returns all rule description entries as array items."""
    store = FakeEventStore()
    store._rules = {
        "942001": "SQL Injection attempt",
        "941001": "XSS attack",
    }
    client = _make_client(store=store)
    resp = client.get("/rules")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 2
    rule_ids = {entry["rule_id"] for entry in data}
    assert rule_ids == {"942001", "941001"}


# ===========================================================================
# E15–E17 — analytics routes
# ===========================================================================


def test_analytics_geo_returns_list() -> None:
    """GET /analytics/geo returns a list of geo-enriched IP objects."""
    store = FakeEventStore()
    client = _make_client(store=store)
    resp = client.get("/analytics/geo")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert data[0]["ip"] == "10.0.0.1"


def test_analytics_summary_returns_dict() -> None:
    """GET /analytics/summary returns a dict with expected aggregate keys."""
    store = FakeEventStore()
    client = _make_client(store=store)
    resp = client.get("/analytics/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)
    assert "total_ips" in data
    assert "total_events" in data
    assert "total_blocked" in data


def test_analytics_categories_timeline_returns_list() -> None:
    """GET /analytics/categories-timeline returns a list of period buckets."""
    store = FakeEventStore()
    client = _make_client(store=store)
    resp = client.get("/analytics/categories-timeline")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert "period" in data[0] or "granularity" in data[0]


# ===========================================================================
# E18 — GET /stats
# ===========================================================================


def test_stats_returns_dict() -> None:
    """GET /stats returns a dict containing total_logs."""
    store = FakeEventStore()
    client = _make_client(store=store)
    resp = client.get("/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)
    assert "total_logs" in data


def test_stats_returns_source_health_list() -> None:
    """E19: GET /stats returns source_health[] with one entry per installed plugin."""
    store = FakeEventStore()
    client = _make_client(store=store)  # registry defaults to {"suricata": FakePullPlugin()}
    resp = client.get("/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "source_health" in data
    assert isinstance(data["source_health"], list)
    # One plugin in the default registry → one entry
    assert len(data["source_health"]) == 1
    entry = data["source_health"][0]
    # Required identity/health fields must be present
    for field in ("source_type", "source_id", "health", "event_count", "last_event_at"):
        assert field in entry, f"source_health entry missing field {field!r}"


def test_stats_returns_last_updated() -> None:
    """E20: GET /stats returns last_updated from the store (may be null)."""
    store = FakeEventStore()
    client = _make_client(store=store)
    resp = client.get("/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "last_updated" in data
    # FakeEventStore.get_stats() returns last_updated=None
    assert data["last_updated"] is None


# ===========================================================================
# S1/S2 — behavior-preserving refactor: existing routes still work
# ===========================================================================


def test_discovery_route_still_works_after_refactor() -> None:
    """GET /sources/types still returns 200 with plugin entries after the refactor.

    This is the state-driven EARS criterion: while the refactor is in place,
    every pre-existing route must behave identically.
    """
    from _api_fakes import FakePullPlugin, FakePushPlugin

    registry = {
        "suricata": FakePullPlugin("suricata"),
        "syslog": FakePushPlugin("syslog"),
    }
    client = _make_client(registry=registry)
    resp = client.get("/sources/types")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    type_keys = {e["type_key"] for e in data}
    assert type_keys == {"suricata", "syslog"}


def test_config_routes_still_work_after_refactor() -> None:
    """GET/PUT /config/sources/{type_key} still work after the refactor.

    Verifies the behavior-preserving move: the existing MA.3b routes continue to
    return the same status codes and payload shapes via the new router.
    """
    from pydantic import BaseModel

    from _api_fakes import FakePullPlugin

    class _FakeStore:
        def __init__(self) -> None:
            self._data: dict[str, Any] = {}

        def get_source(self, source_type: str, schema: type[BaseModel]) -> BaseModel:
            return schema.model_validate(self._data.get(source_type, {}))

        def set_source(
            self, source_type: str, schema: type[BaseModel], updates: dict[str, Any]
        ) -> None:
            merged = {**self._data.get(source_type, {}), **updates}
            schema.model_validate(merged)
            self._data[source_type] = merged

        def get_runtime(self) -> Any:
            from firewatch_sdk import RuntimeConfig
            return RuntimeConfig.model_validate({})

        def set_runtime(self, updates: dict[str, Any]) -> None:
            pass

    plugin = FakePullPlugin("suricata")
    registry = {"suricata": plugin}
    config_store = _FakeStore()
    client = _make_client(registry=registry, config_store=config_store)

    # GET returns 200
    resp = client.get("/config/sources/suricata")
    assert resp.status_code == 200

    # PUT with valid data returns 200
    resp = client.put(
        "/config/sources/suricata",
        json={"updates": {"host": "10.0.0.1", "port": 2222}},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["host"] == "10.0.0.1"

    # GET unknown → 404
    resp = client.get("/config/sources/nonexistent")
    assert resp.status_code == 404


# ===========================================================================
# Issue #118 — GET /threats/{ip}/events (cross-source event timeline)
#
# EARS → test mapping:
#   E21 — GET /threats/{ip}/events returns IPEventTimelineResponse shape.
#          → test_ip_event_timeline_returns_response_shape
#   E22 — GET /threats/{ip}/events for unknown IP returns 404.
#          → test_ip_event_timeline_unknown_ip_returns_404
#   E23 — Events in response are time-ordered ascending.
#          → test_ip_event_timeline_events_ordered_ascending
#   E24 — correlated=True when events span more than one source_type.
#          → test_ip_event_timeline_correlated_when_multiple_sources
#   E25 — correlated=False when events are from a single source_type.
#          → test_ip_event_timeline_not_correlated_single_source
#   E26 — limit query param caps the result; capped=True when truncated.
#          → test_ip_event_timeline_limit_cap_applied
#   E27 — Returns 503 when the event store is not available.
#          → test_ip_event_timeline_no_store_returns_503
# ===========================================================================


class _TimelineStore(FakeEventStore):
    """FakeEventStore variant that exposes ``get_events_for_timeline``."""

    def __init__(self, timeline_rows: list[dict[str, Any]] | None = None) -> None:
        super().__init__()
        self._timeline_rows: list[dict[str, Any]] = timeline_rows or []

    async def get_events_for_timeline(
        self, ip: str, limit: int = 200
    ) -> list[dict[str, Any]]:
        rows = [r for r in self._timeline_rows if r.get("source_ip") == ip]
        return rows[:limit]


def _timeline_row(
    *,
    ip: str = "192.0.2.10",
    source_type: str = "suricata",
    timestamp: str = "2026-06-01T00:00:00+00:00",
    action: str = "ALERT",
    rule_id: str | None = "ET-1001",
    rule_name: str | None = "Suricata alert",
    category: str | None = "IDS Alert",
    severity: str | None = "high",
    payload_snippet: str | None = "test payload",
) -> dict[str, Any]:
    """Build a minimal timeline row dict (matches get_events_for_timeline output)."""
    return {
        "source_ip": ip,
        "source_type": source_type,
        "timestamp": timestamp,
        "action": action,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "category": category,
        "severity": severity,
        "payload_snippet": payload_snippet,
    }


def test_ip_event_timeline_returns_response_shape() -> None:
    """E21: GET /threats/{ip}/events returns a valid IPEventTimelineResponse.

    The response must include events[], total, correlated, source_types, capped.
    Each event entry must include source, time, correlated, action.
    """
    ip = "192.0.2.10"
    rows = [
        _timeline_row(ip=ip, source_type="suricata", timestamp="2026-06-01T00:01:00+00:00"),
        _timeline_row(ip=ip, source_type="azure_waf", timestamp="2026-06-01T00:02:00+00:00"),
    ]
    store = _TimelineStore(rows)
    client = _make_client(store=store)

    resp = client.get(f"/threats/{ip}/events")
    assert resp.status_code == 200
    body = resp.json()

    # Envelope fields
    assert "events" in body
    assert "total" in body
    assert "correlated" in body
    assert "source_types" in body
    assert "capped" in body
    assert isinstance(body["events"], list)
    assert body["total"] == 2

    # Entry fields
    entry = body["events"][0]
    assert "source" in entry
    assert "time" in entry
    assert "correlated" in entry
    assert "action" in entry


def test_ip_event_timeline_unknown_ip_returns_404() -> None:
    """E22: GET /threats/{ip}/events for an IP with no events returns 404."""
    store = _TimelineStore([])  # empty — no rows for any IP
    client = _make_client(store=store)

    resp = client.get("/threats/192.0.2.99/events")
    assert resp.status_code == 404, (
        f"Expected 404 for unknown IP, got {resp.status_code}. "
        "ADR-0029 D3: unknown IP must return 404, not an empty response."
    )


def test_ip_event_timeline_events_ordered_ascending() -> None:
    """E23: Events in response are ordered ascending by timestamp.

    The store returns rows ordered chronologically (ASC); the route preserves
    that order in the response.
    """
    ip = "192.0.2.11"
    rows = [
        _timeline_row(ip=ip, timestamp="2026-06-01T00:01:00+00:00"),
        _timeline_row(ip=ip, timestamp="2026-06-01T00:03:00+00:00"),
        _timeline_row(ip=ip, timestamp="2026-06-01T00:02:00+00:00"),  # middle time, listed last
    ]
    # The real store orders by timestamp ASC — simulate that ordering here:
    # _TimelineStore returns rows as-is; in tests the store is responsible for
    # the ordering contract. We verify the route does NOT re-sort them.
    # To test ordering end-to-end, use pre-sorted rows.
    sorted_rows = sorted(rows, key=lambda r: r["timestamp"])
    store = _TimelineStore(sorted_rows)
    client = _make_client(store=store)

    resp = client.get(f"/threats/{ip}/events")
    assert resp.status_code == 200
    events = resp.json()["events"]
    assert len(events) == 3
    times = [e["time"] for e in events]
    assert times == sorted(times), (
        f"Events must be time-ordered ascending, got: {times}"
    )


def test_ip_event_timeline_correlated_when_multiple_sources() -> None:
    """E24: correlated=True when events span more than one source_type.

    The orange left stripe in EventTimeline is powered by this flag.
    """
    ip = "192.0.2.12"
    rows = [
        _timeline_row(ip=ip, source_type="suricata"),
        _timeline_row(ip=ip, source_type="azure_waf"),
    ]
    store = _TimelineStore(rows)
    client = _make_client(store=store)

    resp = client.get(f"/threats/{ip}/events")
    assert resp.status_code == 200
    body = resp.json()
    assert body["correlated"] is True, (
        "correlated must be True when events span more than one source_type"
    )
    # Every entry must also carry correlated=True
    for entry in body["events"]:
        assert entry["correlated"] is True


def test_ip_event_timeline_not_correlated_single_source() -> None:
    """E25: correlated=False when all events come from a single source_type."""
    ip = "192.0.2.13"
    rows = [
        _timeline_row(ip=ip, source_type="suricata"),
        _timeline_row(ip=ip, source_type="suricata"),
    ]
    store = _TimelineStore(rows)
    client = _make_client(store=store)

    resp = client.get(f"/threats/{ip}/events")
    assert resp.status_code == 200
    body = resp.json()
    assert body["correlated"] is False, (
        "correlated must be False when all events are from one source_type"
    )
    for entry in body["events"]:
        assert entry["correlated"] is False


def test_ip_event_timeline_limit_cap_applied() -> None:
    """E26: limit query param caps the result; capped=True when result is truncated.

    When the store returns more events than the cap, only cap events are
    returned and capped=True is set on the envelope.
    """
    ip = "192.0.2.14"
    # Build 5 rows but request limit=3 → expect capped=True, total=3
    rows = [
        _timeline_row(ip=ip, timestamp=f"2026-06-01T00:0{i}:00+00:00")
        for i in range(5)
    ]
    # The fake store slices at limit; the route passes limit+1 to detect overflow.
    # We override the fake to return limit+1 rows when asked limit+1, simulating
    # a store that has more rows than cap.

    class _UnboundedStore(_TimelineStore):
        async def get_events_for_timeline(
            self, ip: str, limit: int = 200
        ) -> list[dict[str, Any]]:
            # Return all rows up to limit without capping — simulates a big store.
            return [r for r in self._timeline_rows if r.get("source_ip") == ip][:limit]

    store = _UnboundedStore(rows)
    client = _make_client(store=store)

    resp = client.get(f"/threats/{ip}/events?limit=3")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 3
    assert len(body["events"]) == 3
    assert body["capped"] is True, "capped must be True when store had more events than the limit"


def test_ip_event_timeline_no_store_returns_503() -> None:
    """E27: GET /threats/{ip}/events returns 503 when the event store is not available."""
    client = _make_client(store=None)
    resp = client.get("/threats/192.0.2.15/events")
    assert resp.status_code == 503, (
        f"Expected 503 when store is None, got {resp.status_code}"
    )


# ===========================================================================
# Issue #214 — GET /analytics/attack-dispositions (attack→disposition cross-tab)
#
# EARS → test mapping:
#   E28 — GET /analytics/attack-dispositions returns 200 with a list.
#          → test_attack_dispositions_returns_list
#   E29 — Response items have required shape {attack_type, action, count}.
#          → test_attack_dispositions_item_shape
#   E30 — Returns 503 when the event store is not available.
#          → test_attack_dispositions_no_store_returns_503
#   E31 — top_n query param is forwarded to the store (valid range 1–20).
#          → test_attack_dispositions_top_n_param_accepted
#   E32 — top_n < 1 returns 422 (FastAPI validation).
#          → test_attack_dispositions_invalid_top_n_returns_422
#   E33 — Empty list when no categorized events exist.
#          → test_attack_dispositions_empty_store_returns_empty_list
# ===========================================================================


def test_attack_dispositions_returns_list() -> None:
    """E28: GET /analytics/attack-dispositions returns 200 with a list."""
    store = FakeEventStore()
    client = _make_client(store=store)
    resp = client.get("/analytics/attack-dispositions")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


def test_attack_dispositions_item_shape() -> None:
    """E29: Each item in the response has {attack_type, action, count}."""
    store = FakeEventStore()
    client = _make_client(store=store)
    resp = client.get("/analytics/attack-dispositions")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) > 0, "FakeEventStore returns at least one row"
    item = data[0]
    assert "attack_type" in item, f"missing 'attack_type' in {item}"
    assert "action" in item, f"missing 'action' in {item}"
    assert "count" in item, f"missing 'count' in {item}"
    assert isinstance(item["count"], int)


def test_attack_dispositions_no_store_returns_503() -> None:
    """E30: GET /analytics/attack-dispositions returns 503 when store is unavailable."""
    client = _make_client(store=None)
    resp = client.get("/analytics/attack-dispositions")
    assert resp.status_code == 503, (
        f"Expected 503 when store is None, got {resp.status_code}"
    )


def test_attack_dispositions_top_n_param_accepted() -> None:
    """E31: top_n query param is accepted in the valid range (1–20)."""
    store = FakeEventStore()
    client = _make_client(store=store)
    # Valid top_n values
    for top_n in (1, 5, 10, 20):
        resp = client.get(f"/analytics/attack-dispositions?top_n={top_n}")
        assert resp.status_code == 200, f"Expected 200 for top_n={top_n}"


def test_attack_dispositions_invalid_top_n_returns_422() -> None:
    """E32: top_n < 1 or > 20 returns 422 (FastAPI query validation)."""
    store = FakeEventStore()
    client = _make_client(store=store)
    resp = client.get("/analytics/attack-dispositions?top_n=0")
    assert resp.status_code == 422, (
        f"Expected 422 for top_n=0, got {resp.status_code}"
    )
    resp = client.get("/analytics/attack-dispositions?top_n=21")
    assert resp.status_code == 422, (
        f"Expected 422 for top_n=21, got {resp.status_code}"
    )


def test_attack_dispositions_empty_store_returns_empty_list() -> None:
    """E33: Returns an empty list when no categorized events exist."""

    class EmptyStore(FakeEventStore):
        async def get_attack_dispositions(
            self, top_n: int = 5
        ) -> list[dict[str, Any]]:
            return []

    store = EmptyStore()
    client = _make_client(store=store)
    resp = client.get("/analytics/attack-dispositions")
    assert resp.status_code == 200
    assert resp.json() == []


# ===========================================================================
# #252 — GET /logs/paginated?action=blocked shorthand
#
# EARS criteria tested here:
#   AR1  ?action=blocked is forwarded to the store's FilterSpec.action field.
#   AR2  ?action=blocked (case-insensitive variants) reach the store unchanged
#        so the store can expand the shorthand.
#   AR3  An exact action value (?action=ALLOW) is also forwarded verbatim.
# (Full BLOCK+DROP row assertions live in test_sqlite_store.py BA1–BA7.)
# ===========================================================================


def test_logs_paginated_action_blocked_forwarded_to_filterspec() -> None:
    """AR1: ?action=blocked is forwarded to FilterSpec.action (issue #252)."""
    received: list[Any] = []

    class _CapStore(FakeEventStore):
        async def get_paginated(self, limit: int = 100, filters: Any = None) -> dict[str, Any]:
            received.append(filters)
            return {"logs": [], "next_cursor": None, "has_more": False, "total_matching": 0}

    client = _make_client(store=_CapStore())
    resp = client.get("/logs/paginated?action=blocked")
    assert resp.status_code == 200
    assert len(received) == 1
    assert received[0].action == "blocked", (
        f"FilterSpec.action must be 'blocked', got {received[0].action!r}"
    )


def test_logs_paginated_action_blocked_case_insensitive_forwarded() -> None:
    """AR2: mixed-case 'Blocked' is forwarded to FilterSpec.action unchanged."""
    received: list[Any] = []

    class _CapStore(FakeEventStore):
        async def get_paginated(self, limit: int = 100, filters: Any = None) -> dict[str, Any]:
            received.append(filters)
            return {"logs": [], "next_cursor": None, "has_more": False, "total_matching": 0}

    client = _make_client(store=_CapStore())
    resp = client.get("/logs/paginated?action=Blocked")
    assert resp.status_code == 200
    assert received[0].action == "Blocked"


def test_logs_paginated_exact_action_allow_forwarded_verbatim() -> None:
    """AR3: exact ?action=ALLOW is forwarded verbatim (backward compat)."""
    received: list[Any] = []

    class _CapStore(FakeEventStore):
        async def get_paginated(self, limit: int = 100, filters: Any = None) -> dict[str, Any]:
            received.append(filters)
            return {"logs": [], "next_cursor": None, "has_more": False, "total_matching": 0}

    client = _make_client(store=_CapStore())
    resp = client.get("/logs/paginated?action=ALLOW")
    assert resp.status_code == 200
    assert received[0].action == "ALLOW"


# ===========================================================================
# BLOCKING-2 — 404 detail must NOT echo the attacker-controlled IP value
# ===========================================================================


def test_get_threat_unknown_ip_404_detail_does_not_echo_ip() -> None:
    """BLOCKING-2: GET /threats/{ip} 404 body must not reflect the request IP.

    Echoing the raw path parameter in the error detail is an XSS / response
    injection vector (OWASP A03:2021 Injection).  The 404 must use a generic
    message that does not contain the supplied IP string.
    """
    store = FakeEventStore()
    pipeline = FakePipeline({})
    client = _make_client(store=store, pipeline=pipeline)

    supplied_ip = "203.0.113.77"
    resp = client.get(f"/threats/{supplied_ip}")
    assert resp.status_code == 404
    body_text = resp.text
    assert supplied_ip not in body_text, (
        f"404 detail must NOT echo the request IP '{supplied_ip}'; got: {body_text!r}"
    )


def test_get_ip_event_timeline_unknown_ip_404_detail_does_not_echo_ip() -> None:
    """BLOCKING-2: GET /threats/{ip}/events 404 body must not reflect the request IP."""
    store = _TimelineStore([])
    client = _make_client(store=store)

    supplied_ip = "198.51.100.55"
    resp = client.get(f"/threats/{supplied_ip}/events")
    assert resp.status_code == 404
    body_text = resp.text
    assert supplied_ip not in body_text, (
        f"404 detail must NOT echo the request IP '{supplied_ip}'; got: {body_text!r}"
    )


# ===========================================================================
# NB-1 — malformed IP path param returns 422 (not 404 or 500)
# ===========================================================================


def test_get_threat_malformed_ip_returns_422() -> None:
    """NB-1: GET /threats/{ip} with a non-IP path param returns 422.

    The Path(pattern=...) guard must reject obviously non-IP strings before any
    store or pipeline call is made.
    """
    store = FakeEventStore()
    pipeline = FakePipeline({})
    client = _make_client(store=store, pipeline=pipeline)

    # Note: path-traversal strings (e.g. ../../etc/passwd) are normalised by
    # the HTTP layer before reaching the router, so they produce 404 rather
    # than 422.  We only test strings that actually reach the path parameter.
    for bad in ("not-an-ip", "foo bar", "alert(1)", "hostname.example.com"):
        resp = client.get(f"/threats/{bad}")
        assert resp.status_code == 422, (
            f"Expected 422 for malformed IP {bad!r}, got {resp.status_code}"
        )


def test_get_threat_valid_ipv4_passes_guard() -> None:
    """NB-1: A well-formed IPv4 address passes the Path guard (returns 404 for unknown)."""
    store = FakeEventStore()
    pipeline = FakePipeline({})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get("/threats/203.0.113.1")
    # Unknown IP → 404, but NOT 422 — the guard must pass valid addresses through.
    assert resp.status_code == 404, (
        f"Valid IPv4 must pass the guard (expected 404 for unknown IP), got {resp.status_code}"
    )


def test_get_threat_valid_ipv6_passes_guard() -> None:
    """NB-1: A well-formed IPv6 address passes the Path guard (returns 404 for unknown)."""
    store = FakeEventStore()
    pipeline = FakePipeline({})
    client = _make_client(store=store, pipeline=pipeline)

    resp = client.get("/threats/2001:db8::1")
    assert resp.status_code == 404, (
        f"Valid IPv6 must pass the guard (expected 404 for unknown IP), got {resp.status_code}"
    )


# ===========================================================================
# #250 route-registration gap — GET /threats/{ip}/score-history
#
# EARS criteria tested here (issue #250):
#   E34 — Known IP returns a list of {ip, score, ts} dicts (200 OK).
#          → test_score_history_known_ip_returns_series
#   E35 — Unknown IP yields an empty series (200 OK — NOT 404).
#          → test_score_history_unknown_ip_returns_empty_list
#   E36 — Non-positive ?window= value returns 422 (ADR-0029 D3 validation).
#          → test_score_history_invalid_window_returns_422
#   E37 — No event store returns 503.
#          → test_score_history_no_store_returns_503
#   E38 — Default window (no ?window= param) is accepted; returns 200.
#          → test_score_history_default_window_accepted
# ===========================================================================


class _ScoreHistoryStore(FakeEventStore):
    """FakeEventStore variant that exposes ``get_score_history``."""

    def __init__(self, history: list[dict[str, Any]] | None = None) -> None:
        super().__init__()
        self._history: list[dict[str, Any]] = history or []

    async def get_score_history(
        self, ip: str, window_hours: float
    ) -> list[dict[str, Any]]:
        return [r for r in self._history if r.get("ip") == ip]


def test_score_history_known_ip_returns_series() -> None:
    """E34: GET /threats/{ip}/score-history returns a list of score-point dicts (200).

    Each dict must contain 'ip', 'score', and 'ts' matching the store output
    (sqlite_store.get_score_history returns [{ip, score, ts}, ...]).
    """
    ip = "192.0.2.10"
    rows = [
        {"ip": ip, "score": 60, "ts": "2026-06-10T12:00:00+00:00"},
        {"ip": ip, "score": 70, "ts": "2026-06-10T13:00:00+00:00"},
    ]
    store = _ScoreHistoryStore(rows)
    client = _make_client(store=store)

    resp = client.get(f"/threats/{ip}/score-history")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()
    assert isinstance(data, list), "Response must be a list"
    assert len(data) == 2, f"Expected 2 points, got {len(data)}"

    # Verify shape of each item
    for item in data:
        assert "ip" in item, f"Missing 'ip' key in {item}"
        assert "score" in item, f"Missing 'score' key in {item}"
        assert "ts" in item, f"Missing 'ts' key in {item}"
    assert data[0]["ip"] == ip
    assert data[0]["score"] == 60


def test_score_history_unknown_ip_returns_empty_list() -> None:
    """E35: GET /threats/{ip}/score-history for an unknown IP returns [] (200 OK, NOT 404).

    Issue #250 EARS: 'unknown IPs yield an empty series' — semantics differ from
    GET /threats/{ip} (which returns 404).  A missing score history is not an
    error; it means the IP has never been scored.
    """
    store = _ScoreHistoryStore([])  # empty — no history for any IP
    client = _make_client(store=store)

    resp = client.get("/threats/192.0.2.99/score-history")
    assert resp.status_code == 200, (
        f"Expected 200 for unknown IP (not 404), got {resp.status_code}. "
        "Issue #250: unknown IP yields empty series, not 404."
    )
    assert resp.json() == [], f"Expected empty list [], got {resp.json()!r}"


def test_score_history_invalid_window_returns_422() -> None:
    """E36: A non-positive ?window= value returns 422 (ADR-0029 D3 query validation).

    window must be > 0 hours.  Zero or negative values are rejected by FastAPI's
    Query(gt=0) constraint without reaching the store.
    """
    store = _ScoreHistoryStore([])
    client = _make_client(store=store)

    resp = client.get("/threats/192.0.2.10/score-history?window=0")
    assert resp.status_code == 422, (
        f"Expected 422 for window=0, got {resp.status_code}"
    )

    resp = client.get("/threats/192.0.2.10/score-history?window=-1")
    assert resp.status_code == 422, (
        f"Expected 422 for window=-1, got {resp.status_code}"
    )


def test_score_history_no_store_returns_503() -> None:
    """E37: GET /threats/{ip}/score-history returns 503 when the event store is absent."""
    client = _make_client(store=None)
    resp = client.get("/threats/192.0.2.10/score-history")
    assert resp.status_code == 503, (
        f"Expected 503 when store is None, got {resp.status_code}"
    )


def test_score_history_default_window_accepted() -> None:
    """E38: Omitting ?window= uses the default and returns 200.

    The route provides a default so the sparkline component doesn't need to
    supply a window parameter.
    """
    store = _ScoreHistoryStore([])
    client = _make_client(store=store)

    resp = client.get("/threats/192.0.2.10/score-history")
    assert resp.status_code == 200, (
        f"Expected 200 with default window, got {resp.status_code}"
    )


# ===========================================================================
# E39–E43 — counterfactual impact (issue #215)
# ===========================================================================


def test_counterfactual_returns_200_with_counts() -> None:
    """E39: GET /threats/{ip}/counterfactual returns 200 with correct count fields.

    EARS: WHEN a block recommendation is rendered for an entity with non-blocked
    events, the card SHALL show the would-have-stopped count derived from stored
    events (never from LLM text).
    """
    store = FakeEventStore()
    client = _make_client(store=store)

    resp = client.get("/threats/192.0.2.1/counterfactual")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    body = resp.json()
    assert body["total_events"] == 1350
    assert body["blocked_events"] == 146
    assert body["unblocked_events"] == 1204


def test_counterfactual_unblocked_equals_total_minus_blocked() -> None:
    """E40: unblocked_events == total_events - blocked_events (arithmetic invariant).

    EARS ubiquitous: the number SHALL be reproducible from the evidence link's
    filtered event list (counts match).
    """
    store = FakeEventStore()
    client = _make_client(store=store)

    resp = client.get("/threats/192.0.2.1/counterfactual")
    body = resp.json()
    assert body["unblocked_events"] == body["total_events"] - body["blocked_events"]


def test_counterfactual_all_blocked_returns_zero_unblocked() -> None:
    """E41: WHEN all events were already blocked, unblocked_events is 0.

    EARS: WHEN all of the entity's events were already blocked, the card SHALL
    say so instead of showing '0' bare.  The route returns 0 honestly; the UI
    handles the graceful copy ('all N events already blocked').
    """
    store = FakeEventStore()
    client = _make_client(store=store)

    resp = client.get("/threats/192.0.2.99/counterfactual")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    body = resp.json()
    assert body["total_events"] == 150
    assert body["blocked_events"] == 150
    assert body["unblocked_events"] == 0


def test_counterfactual_unknown_ip_returns_zero_counts() -> None:
    """E42: Unknown IP returns all-zero counts (200 OK, not 404).

    Absence of stored events is not an error for the counterfactual route;
    it returns honest zeros.  The UI renders nothing or '0' — never fabricated.
    """
    store = FakeEventStore()
    client = _make_client(store=store)

    resp = client.get("/threats/203.0.113.55/counterfactual")
    assert resp.status_code == 200, f"Expected 200 for unknown IP, got {resp.status_code}"
    body = resp.json()
    assert body["total_events"] == 0
    assert body["blocked_events"] == 0
    assert body["unblocked_events"] == 0


def test_counterfactual_no_store_returns_503() -> None:
    """E43: GET /threats/{ip}/counterfactual returns 503 when event store absent."""
    client = _make_client(store=None)
    resp = client.get("/threats/192.0.2.1/counterfactual")
    assert resp.status_code == 503, f"Expected 503 when store is None, got {resp.status_code}"
