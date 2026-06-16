"""API route tests for score_breakdown field (issue #209 / ADR-0036 D4).

Verifies that GET /threats/{ip} and GET /threats/{ip}/detailed both include
a well-formed score_breakdown in their responses.

EARS acceptance criteria → test mapping:

  EARS-1 — response SHALL include score_breakdown whose points sum equals score.
           → test_get_threat_includes_score_breakdown
           → test_get_threat_breakdown_sum_equals_score
           → test_get_threat_detailed_includes_score_breakdown
           → test_get_threat_detailed_breakdown_sum_equals_score

  EARS-2 — existing fields SHALL be unchanged (additive-only).
           → test_get_threat_existing_fields_unchanged
           → test_get_threat_detailed_existing_fields_unchanged

  EARS-3 — WHEN AI boost applied, breakdown SHALL contain ai_boost entry.
           → test_get_threat_breakdown_has_ai_boost_when_derivation_ai_rule

  EARS-4 — cap item present when score == 100 and raw > 100.
           (Covered implicitly via sum invariant; explicit test with pipeline fake.)
           → test_get_threat_breakdown_sum_always_equals_score

  EARS-5 — labels are strings (human-readable).
           → test_get_threat_breakdown_items_have_string_labels
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi.testclient import TestClient

from firewatch_sdk import ScoreBreakdownItem, ThreatScore

from firewatch_api.app import create_app


# ---------------------------------------------------------------------------
# Fake store / pipeline for route tests
# ---------------------------------------------------------------------------


class _FakeStore:
    async def _conn(self) -> Any:
        return self

    async def get_all_ips(self) -> list[str]:
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

    async def get_timeline(
        self, start: str | None = None, end: str | None = None
    ) -> list[dict[str, Any]]:
        return []

    async def get_rule_descriptions(self) -> dict[str, str]:
        return {}

    async def get_analytics_geo(self) -> list[dict[str, Any]]:
        return []

    async def get_analytics_summary(self) -> dict[str, Any]:
        return {"total_ips": 0, "total_events": 0, "total_blocked": 0,
                "block_rate": 0.0, "top_country": "", "unique_countries": 0, "top_rule": ""}

    async def get_categories_timeline(
        self, start: str | None = None, end: str | None = None
    ) -> list[dict[str, Any]]:
        return []

    async def get_stats(self) -> dict[str, Any]:
        return {"total_logs": 0, "total_ips": 0, "blocked_percentage": 0.0,
                "top_attack_types": [], "last_updated": None}

    async def source_health(self) -> list[dict[str, Any]]:
        return []


def _make_score(
    ip: str,
    score: int = 55,
    derivation: str = "rule",
    breakdown: list[ScoreBreakdownItem] | None = None,
) -> ThreatScore:
    now = datetime.now(timezone.utc)
    items = breakdown or [
        ScoreBreakdownItem(factor="blocked_events", label="5 blocked events", points=5),
        ScoreBreakdownItem(factor="port_scan", label="Port scan — 5 distinct ports", points=25),
        ScoreBreakdownItem(factor="brute_force", label="Brute force — 12 blocked events", points=30),
    ]
    # Ensure the breakdown points actually sum to the provided score
    # (fake only — real pipeline computes from events)
    return ThreatScore(
        source_ip=ip,
        threat_level="HIGH",
        score=score,
        total_events=12,
        blocked_events=12,
        attack_types=["brute_force"],
        first_seen=now,
        last_seen=now,
        source_types=["suricata"],
        ai_status="disabled",
        score_derivation=derivation,  # type: ignore[arg-type]
        score_breakdown=items,
    )


class _FakePipeline:
    def __init__(self, ip: str, score: ThreatScore) -> None:
        self._ip = ip
        self._score = score

    async def analyze_ip(self, ip: str, *, use_ai: bool = True) -> ThreatScore:
        if ip == self._ip:
            return self._score
        now = datetime.now(timezone.utc)
        return ThreatScore(
            source_ip=ip, threat_level="LOW", score=0, total_events=0,
            blocked_events=0, attack_types=[], first_seen=now, last_seen=now,
        )

    async def analyze_ip_detailed(
        self, ip: str, *, include_ai: bool = True
    ) -> dict[str, Any]:
        if ip == self._ip:
            result: dict[str, Any] = {
                "source_ip": ip,
                "score": self._score.score,
                "threat_level": self._score.threat_level,
                "score_derivation": self._score.score_derivation,
                "score_breakdown": [i.model_dump() for i in self._score.score_breakdown],
                "total_events": self._score.total_events,
                "blocked_events": self._score.blocked_events,
                "attack_types": self._score.attack_types,
                "detections": [],
                "location": None,
            }
            if not include_ai:
                result["ai_status"] = "skipped"
            return result
        return {"error": "No logs found"}


def _make_client(ip: str, score: ThreatScore) -> TestClient:
    from _api_fakes import FakePullPlugin

    store = _FakeStore()
    pipeline = _FakePipeline(ip, score)
    app = create_app(
        registry={"suricata": FakePullPlugin()},
        config_store=None,
        event_store=store,
        pipeline=pipeline,
    )
    return TestClient(app)


# ---------------------------------------------------------------------------
# EARS-1 — breakdown present in /threats/{ip}
# ---------------------------------------------------------------------------


def test_get_threat_includes_score_breakdown() -> None:
    """EARS-1: GET /threats/{ip} response includes 'score_breakdown' list."""
    ip = "192.0.2.50"
    score = _make_score(ip, score=60)
    client = _make_client(ip, score)

    resp = client.get(f"/threats/{ip}")
    assert resp.status_code == 200
    body = resp.json()
    assert "score_breakdown" in body, (
        "EARS-1: /threats/{ip} must include 'score_breakdown' field."
    )
    assert isinstance(body["score_breakdown"], list)


def test_get_threat_breakdown_sum_equals_score() -> None:
    """EARS-1: /threats/{ip} breakdown points sum equals the score value."""
    ip = "192.0.2.51"
    # Use a score where the breakdown items deliberately sum to the same value
    items = [
        ScoreBreakdownItem(factor="brute_force", label="Brute force", points=30),
        ScoreBreakdownItem(factor="blocked_events", label="10 blocked events", points=10),
    ]
    score = _make_score(ip, score=40, breakdown=items)
    client = _make_client(ip, score)

    resp = client.get(f"/threats/{ip}")
    assert resp.status_code == 200
    body = resp.json()
    total = sum(item["points"] for item in body["score_breakdown"])
    assert total == body["score"], (
        f"EARS-1: breakdown sum {total} != score {body['score']}."
    )


def test_get_threat_breakdown_items_have_string_labels() -> None:
    """EARS-5: every breakdown item in /threats/{ip} has a non-empty string label."""
    ip = "192.0.2.52"
    score = _make_score(ip, score=60)
    client = _make_client(ip, score)

    resp = client.get(f"/threats/{ip}")
    body = resp.json()
    for item in body["score_breakdown"]:
        assert isinstance(item["label"], str), f"label not a string: {item}"
        assert len(item["label"]) > 0, f"label is empty: {item}"


def test_get_threat_breakdown_has_ai_boost_when_derivation_ai_rule() -> None:
    """EARS-3: when score_derivation is 'ai+rule', breakdown contains ai_boost."""
    ip = "192.0.2.53"
    items = [
        ScoreBreakdownItem(factor="blocked_events", label="5 blocked events", points=5),
        ScoreBreakdownItem(factor="ai_boost", label="AI boost — CRITICAL (+20)", points=20),
    ]
    score = _make_score(ip, score=25, derivation="ai+rule", breakdown=items)
    client = _make_client(ip, score)

    resp = client.get(f"/threats/{ip}")
    body = resp.json()
    assert body["score_derivation"] == "ai+rule"
    factors = [item["factor"] for item in body["score_breakdown"]]
    assert "ai_boost" in factors, (
        "EARS-3: ai_boost factor must appear in breakdown when derivation is 'ai+rule'."
    )


# ---------------------------------------------------------------------------
# EARS-1 — breakdown present in /threats/{ip}/detailed
# ---------------------------------------------------------------------------


def test_get_threat_detailed_includes_score_breakdown() -> None:
    """EARS-1: GET /threats/{ip}/detailed response includes 'score_breakdown' list."""
    ip = "192.0.2.54"
    score = _make_score(ip, score=60)
    client = _make_client(ip, score)

    resp = client.get(f"/threats/{ip}/detailed")
    assert resp.status_code == 200
    body = resp.json()
    assert "score_breakdown" in body, (
        "EARS-1: /threats/{ip}/detailed must include 'score_breakdown' field."
    )
    assert isinstance(body["score_breakdown"], list)


def test_get_threat_detailed_breakdown_sum_equals_score() -> None:
    """EARS-1: /threats/{ip}/detailed breakdown sum == score."""
    ip = "192.0.2.55"
    items = [
        ScoreBreakdownItem(factor="port_scan", label="Port scan", points=25),
        ScoreBreakdownItem(factor="blocked_events", label="3 blocked events", points=3),
    ]
    score = _make_score(ip, score=28, breakdown=items)
    client = _make_client(ip, score)

    resp = client.get(f"/threats/{ip}/detailed")
    body = resp.json()
    total = sum(item["points"] for item in body["score_breakdown"])
    assert total == body["score"], (
        f"EARS-1: /detailed breakdown sum {total} != score {body['score']}."
    )


# ---------------------------------------------------------------------------
# EARS-2 — existing fields unchanged (additive-only)
# ---------------------------------------------------------------------------


def test_get_threat_existing_fields_unchanged() -> None:
    """EARS-2: /threats/{ip} existing fields are present and unchanged alongside breakdown."""
    ip = "192.0.2.56"
    score = _make_score(ip, score=60)
    client = _make_client(ip, score)

    resp = client.get(f"/threats/{ip}")
    body = resp.json()
    # Pre-existing fields must all still be present
    for field in ("source_ip", "threat_level", "score", "total_events",
                  "blocked_events", "attack_types", "ai_status", "score_derivation"):
        assert field in body, f"EARS-2: pre-existing field '{field}' missing from response."


def test_get_threat_detailed_existing_fields_unchanged() -> None:
    """EARS-2: /threats/{ip}/detailed existing fields present alongside breakdown."""
    ip = "192.0.2.57"
    score = _make_score(ip, score=60)
    client = _make_client(ip, score)

    resp = client.get(f"/threats/{ip}/detailed")
    body = resp.json()
    for field in ("source_ip", "threat_level", "score", "total_events",
                  "blocked_events", "attack_types", "score_derivation"):
        assert field in body, f"EARS-2: pre-existing field '{field}' missing from /detailed."


def test_get_threat_breakdown_sum_always_equals_score() -> None:
    """EARS-1 property: breakdown sum == score for rules-only, single-event, and capped cases.

    The capped case uses raw=110 (30+40+40) reduced to 100 by -10 cap item.
    """
    cases: list[tuple[int, list[ScoreBreakdownItem]]] = [
        (30, [ScoreBreakdownItem(factor="brute_force", label="BF", points=30)]),
        (1,  [ScoreBreakdownItem(factor="blocked_events", label="1 blocked", points=1)]),
        # raw = 30+40+40 = 110 → capped to 100; cap item carries -10
        (100, [
            ScoreBreakdownItem(factor="brute_force", label="BF", points=30),
            ScoreBreakdownItem(factor="sql_injection", label="SQLi", points=40),
            ScoreBreakdownItem(factor="blocked_events", label="30 blocked", points=40),
            ScoreBreakdownItem(factor="cap", label="Capped at 100 (raw 110, -10)", points=-10),
        ]),
    ]
    for idx, (target_score, pts) in enumerate(cases):
        ip = f"192.0.2.{60 + idx}"
        score = _make_score(ip, score=target_score, breakdown=pts)
        client = _make_client(ip, score)
        resp = client.get(f"/threats/{ip}")
        body = resp.json()
        total = sum(item["points"] for item in body["score_breakdown"])
        assert total == body["score"], (
            f"score={target_score}: breakdown sum {total} != score {body['score']}."
        )
