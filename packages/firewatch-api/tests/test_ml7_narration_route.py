"""Tests for GET /threats/{ip}/narration — ML-7 (issue #435).

Mapped 1:1 to EARS acceptance criteria.

EARS-1  WHEN the analyst clicks Explain, the narration reuses the
        /threats/{ip}/detailed + score_breakdown path (no parallel scoring).
        → test_narration_calls_analyze_ip_detailed
        → test_narration_200_response_shape

EARS-2  Every claim carries RULE/AI provenance chip.
        → test_rule_only_narration_provenance_is_rule
        → test_ai_narration_provenance_is_ai_or_ai_plus_rule

EARS-3 (anti-fabrication / NULL guard)
        → test_null_optional_fields_not_in_collected_fields
        → test_narration_response_has_collected_fields

EARS-4  WHEN AI is unavailable, narration degrades gracefully to rule-only
        (provenance='rule', ai_status='unavailable'), non-fatal.
        → test_ai_unavailable_returns_rule_only
        → test_ai_equals_false_returns_rule_only
        → test_degrade_is_non_fatal_no_exception

Additional:
  - 404 when no events exist for the IP.
  - 503 when store not available.
  - 503 when pipeline not available.
  - narrative is a non-empty string.
  - Route reachable at /threats/{ip}/narration.
  - ai=false query param accepted.

All IPs use RFC 5737 / RFC 1918 ranges — never real/routable IPs.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi.testclient import TestClient

from firewatch_sdk import ThreatScore

# ---------------------------------------------------------------------------
# RFC 5737 test IPs
# ---------------------------------------------------------------------------

_IP = "192.0.2.55"
_IP_EMPTY = "192.0.2.99"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

_RULE_ONLY_DETAIL: dict[str, Any] = {
    "source_ip": _IP,
    "score": 45,
    "threat_level": "HIGH",
    "score_derivation": "rule",
    "total_events": 30,
    "blocked_events": 20,
    "first_seen": "2026-06-01T00:00:00+00:00",
    "last_seen": "2026-06-01T12:00:00+00:00",
    "location": None,
    "asn": None,
    "as_name": None,
    "attack_types": ["SQL Injection"],
    "score_breakdown": [
        {"factor": "brute_force", "label": "Brute force — 20 blocked events", "points": 30},
        {"factor": "blocked_events", "label": "20 blocked events", "points": 20},
    ],
    "mitre_techniques": [],
    "ai_status": "unavailable",
    "executive_summary": None,
    "intent": None,
    "detections": [],
}

_AI_DETAIL: dict[str, Any] = {
    **_RULE_ONLY_DETAIL,
    # ADR-0066: analyze_ip_detailed's ONE stamping authority always writes
    # "active" (never the AIEngine port's internal "ok" discriminator) when
    # the engine ran and produced a verdict — the route branches positively
    # on "active" (issues #39/#40).
    "ai_status": "active",
    "score_derivation": "ai+rule",
    "executive_summary": "This IP probes the /api endpoint with SQL injection payloads.",
    "intent": "Credential harvesting via SQLi",
}


class _FakeAiEngine:
    """Fake AI engine that returns a canned narration response."""

    async def is_available(self) -> bool:
        return True

    async def analyze_concise(self, **kwargs: Any) -> dict[str, Any]:
        # Return a narration-shaped response when _narration_prompt kwarg is present.
        return {
            "narrative": (
                "This IP triggered brute-force rules with 20 of 30 events blocked. "
                "Rule signals: Brute force. What to check next: Review score breakdown."
            ),
            "provenance": "ai",
            "threat_level": "HIGH",
            "confidence": 0.85,
            "intent": "Credential harvesting via SQLi",
            "attack_stage": "exploitation",
            "insights": [],
            "recommended_action": "block",
        }


class _FakeAiEngineUnavailable:
    """Fake AI engine that reports itself unavailable."""

    async def is_available(self) -> bool:
        return False

    async def analyze_concise(self, **kwargs: Any) -> dict[str, Any]:
        return {"ai_status": "unavailable", "threat_level": "UNKNOWN"}


class _NarrationPipeline:
    """Fake pipeline for narration route tests."""

    def __init__(
        self,
        detail_by_ip: dict[str, dict[str, Any]] | None = None,
        ai_engine: Any = None,
    ) -> None:
        self._detail = detail_by_ip or {}
        self.ai_engine = ai_engine or _FakeAiEngine()
        self.analyze_detailed_calls: list[tuple[str, bool]] = []

    async def analyze_ip(self, ip: str, *, use_ai: bool = True) -> ThreatScore:
        now = datetime.now(timezone.utc)
        return ThreatScore(
            source_ip=ip, threat_level="LOW", score=0,
            total_events=0, blocked_events=0, attack_types=[],
            first_seen=now, last_seen=now, ai_status="disabled",
        )

    async def analyze_ip_detailed(
        self, ip: str, *, include_ai: bool = True, stage_sink: Any = None
    ) -> dict[str, Any]:
        self.analyze_detailed_calls.append((ip, include_ai))
        if ip not in self._detail:
            return {"error": "No logs found"}
        return dict(self._detail[ip])


class _MinimalStore:
    """Minimal store fake — narration route does not call the store directly."""

    async def get_all_ips(self) -> list[str]:
        return []

    async def get_by_ip(self, ip: str) -> list[Any]:
        return []

    async def get_by_ip_raw(self, ip: str) -> list[dict[str, Any]]:
        return []

    async def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        return []

    async def get_paginated(self, limit: int = 100, filters: Any = None) -> dict[str, Any]:
        return {"logs": [], "next_cursor": None, "has_more": False, "total_matching": 0}

    async def get_categories(self) -> list[dict[str, Any]]:
        return []

    async def get_category_summary(self) -> list[dict[str, Any]]:
        return []

    async def get_timeline(self, bucket_minutes: int = 60) -> list[dict[str, Any]]:
        return []

    async def get_ip_geo(self, ip: str) -> dict[str, Any] | None:
        return None

    async def get_rule_descriptions(self) -> dict[str, Any]:
        return {}

    async def get_watermark(self, source_type: str, source_id: str) -> str:
        return ""

    async def get_score_history(self, ip: str, window: float = 24.0) -> list[dict[str, Any]]:
        return []

    async def get_ip_counterfactual(self, ip: str) -> dict[str, Any]:
        return {"ip": ip, "total_events": 0, "blocked_events": 0, "unblocked_events": 0}

    async def get_events_with_row_ids(self, ip: str) -> list[dict[str, Any]]:
        return []

    async def get_events_for_timeline(
        self, ip: str, limit: int = 200
    ) -> list[dict[str, Any]]:
        return []


# ---------------------------------------------------------------------------
# App builder
# ---------------------------------------------------------------------------

def _build_client(
    detail_by_ip: dict[str, dict[str, Any]] | None = None,
    ai_engine: Any = None,
    pipeline: Any = None,
    store: Any = None,
) -> TestClient:
    from _api_fakes import FakePullPlugin
    from firewatch_api.app import create_app

    _store = store or _MinimalStore()
    _pipeline = pipeline or _NarrationPipeline(detail_by_ip, ai_engine)
    app = create_app(
        registry={"suricata": FakePullPlugin()},
        config_store=None,
        event_store=_store,
        pipeline=_pipeline,
    )
    return TestClient(app)


# ---------------------------------------------------------------------------
# EARS-1: reuses analyze_ip_detailed path
# ---------------------------------------------------------------------------


def test_narration_calls_analyze_ip_detailed() -> None:
    """EARS-1: narration route calls pipeline.analyze_ip_detailed."""
    pipeline = _NarrationPipeline({_IP: _RULE_ONLY_DETAIL})
    client = _build_client(pipeline=pipeline)
    resp = client.get(f"/threats/{_IP}/narration?ai=false")
    assert resp.status_code == 200
    # analyze_ip_detailed was called once for this IP
    assert any(ip == _IP for ip, _ in pipeline.analyze_detailed_calls)


def test_narration_200_response_shape() -> None:
    """EARS-1: 200 response has expected envelope fields."""
    client = _build_client({_IP: _RULE_ONLY_DETAIL})
    resp = client.get(f"/threats/{_IP}/narration?ai=false")
    assert resp.status_code == 200
    data = resp.json()
    assert "source_ip" in data
    assert "narrative" in data
    assert "provenance" in data
    assert "collected_fields" in data
    assert "ai_status" in data


def test_narration_source_ip_matches() -> None:
    """EARS-1: response source_ip matches the queried IP."""
    client = _build_client({_IP: _RULE_ONLY_DETAIL})
    resp = client.get(f"/threats/{_IP}/narration?ai=false")
    assert resp.json()["source_ip"] == _IP


# ---------------------------------------------------------------------------
# EARS-2: provenance chips
# ---------------------------------------------------------------------------


def test_rule_only_narration_provenance_is_rule() -> None:
    """EARS-2: when AI is unavailable, provenance is 'rule'."""
    client = _build_client({_IP: _RULE_ONLY_DETAIL})
    resp = client.get(f"/threats/{_IP}/narration?ai=false")
    assert resp.json()["provenance"] == "rule"


def test_ai_narration_provenance_is_ai_or_ai_plus_rule() -> None:
    """EARS-2: when AI ran and score_derivation='ai+rule', provenance reflects it."""
    client = _build_client({_IP: _AI_DETAIL}, ai_engine=_FakeAiEngine())
    resp = client.get(f"/threats/{_IP}/narration?ai=true")
    prov = resp.json()["provenance"]
    # Provenance is 'ai' or 'ai+rule' when AI ran (score_derivation='ai+rule')
    assert prov in ("ai", "ai+rule")


# ---------------------------------------------------------------------------
# EARS-3: anti-fabrication / collected_fields
# ---------------------------------------------------------------------------


def test_narration_response_has_collected_fields() -> None:
    """EARS-3: collected_fields is a list (possibly empty for minimal detail)."""
    client = _build_client({_IP: _RULE_ONLY_DETAIL})
    resp = client.get(f"/threats/{_IP}/narration?ai=false")
    data = resp.json()
    assert isinstance(data["collected_fields"], list)


def test_null_optional_fields_not_in_collected_fields() -> None:
    """EARS-3: null location/asn absent from collected_fields (anti-fabrication)."""
    client = _build_client({_IP: _RULE_ONLY_DETAIL})
    resp = client.get(f"/threats/{_IP}/narration?ai=false")
    collected = resp.json()["collected_fields"]
    assert "geo location" not in collected
    assert "ASN / AS name" not in collected


def test_narrative_is_non_empty_string() -> None:
    """EARS-3: narrative is always a non-empty string."""
    client = _build_client({_IP: _RULE_ONLY_DETAIL})
    resp = client.get(f"/threats/{_IP}/narration?ai=false")
    narrative = resp.json()["narrative"]
    assert isinstance(narrative, str)
    assert len(narrative) > 0


# ---------------------------------------------------------------------------
# EARS-4: AI-unavailable degrade path
# ---------------------------------------------------------------------------


def test_ai_unavailable_returns_rule_only() -> None:
    """EARS-4: when AI is offline (ai_status='unavailable'), response has provenance='rule'."""
    detail_unavailable = {**_RULE_ONLY_DETAIL, "ai_status": "unavailable"}
    client = _build_client({_IP: detail_unavailable})
    resp = client.get(f"/threats/{_IP}/narration?ai=true")
    assert resp.status_code == 200
    assert resp.json()["provenance"] == "rule"


def test_ai_equals_false_returns_rule_only() -> None:
    """EARS-4: ai=false always yields provenance='rule' (no LLM call)."""
    client = _build_client({_IP: _AI_DETAIL})
    resp = client.get(f"/threats/{_IP}/narration?ai=false")
    assert resp.status_code == 200
    assert resp.json()["provenance"] == "rule"


def test_degrade_is_non_fatal_no_exception() -> None:
    """EARS-4: AI unavailable path returns 200 not 5xx (non-fatal, ADR-0015)."""
    engine_unavail = _FakeAiEngineUnavailable()
    client = _build_client({_IP: _RULE_ONLY_DETAIL}, ai_engine=engine_unavail)
    resp = client.get(f"/threats/{_IP}/narration?ai=true")
    # Must be 200 (non-fatal) — not 500 or 503
    assert resp.status_code == 200


def test_ai_unavailable_ai_status_in_response() -> None:
    """EARS-4: ai_status in response reflects pipeline's ai_status field."""
    client = _build_client({_IP: _RULE_ONLY_DETAIL})
    resp = client.get(f"/threats/{_IP}/narration?ai=false")
    assert resp.json()["ai_status"] == "unavailable"


def test_rule_only_narrative_has_what_to_check_next() -> None:
    """EARS-4: rule-only advisory includes guidance (no SOAR/execution)."""
    client = _build_client({_IP: _RULE_ONLY_DETAIL})
    resp = client.get(f"/threats/{_IP}/narration?ai=false")
    narrative = resp.json()["narrative"].lower()
    # Advisory sentence must be present
    assert "check" in narrative or "review" in narrative
    # Must NOT contain execution language
    execution_words = ["automatically block", "trigger", "run playbook", "execute"]
    for w in execution_words:
        assert w not in narrative


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_unknown_ip_returns_404() -> None:
    """Unknown IP (no events) returns 404."""
    client = _build_client({})  # no IPs in detail
    resp = client.get(f"/threats/{_IP_EMPTY}/narration")
    assert resp.status_code == 404


def test_no_store_returns_503() -> None:
    """When store is None, route returns 503."""
    from _api_fakes import FakePullPlugin
    from firewatch_api.app import create_app

    app = create_app(
        registry={"suricata": FakePullPlugin()},
        config_store=None,
        event_store=None,
        pipeline=_NarrationPipeline({_IP: _RULE_ONLY_DETAIL}),
    )
    client = TestClient(app)
    resp = client.get(f"/threats/{_IP}/narration")
    assert resp.status_code == 503


def test_no_pipeline_returns_503() -> None:
    """When pipeline is None, route returns 503."""
    from _api_fakes import FakePullPlugin
    from firewatch_api.app import create_app

    app = create_app(
        registry={"suricata": FakePullPlugin()},
        config_store=None,
        event_store=_MinimalStore(),
        pipeline=None,
    )
    client = TestClient(app)
    resp = client.get(f"/threats/{_IP}/narration")
    assert resp.status_code == 503


def test_ai_query_param_false_accepted() -> None:
    """ai=false query param is valid (EARS-4 fast path)."""
    client = _build_client({_IP: _RULE_ONLY_DETAIL})
    resp = client.get(f"/threats/{_IP}/narration?ai=false")
    assert resp.status_code == 200


def test_ai_query_param_true_accepted() -> None:
    """ai=true query param is valid (default)."""
    detail_skipped = {**_RULE_ONLY_DETAIL, "ai_status": "skipped"}
    client = _build_client({_IP: detail_skipped})
    resp = client.get(f"/threats/{_IP}/narration?ai=true")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Route reachability
# ---------------------------------------------------------------------------


def test_route_reachable() -> None:
    """Route /threats/{ip}/narration is registered and reachable."""
    client = _build_client({_IP: _RULE_ONLY_DETAIL})
    resp = client.get(f"/threats/{_IP}/narration?ai=false")
    # Not 404 (which would indicate the route is not registered)
    assert resp.status_code != 404 or resp.json().get("detail") == "No events found for the requested IP"
    # The route exists: check the OpenAPI schema lists it
    schema = client.get("/openapi.json").json()
    paths = schema.get("paths", {})
    assert any("/narration" in p for p in paths)
