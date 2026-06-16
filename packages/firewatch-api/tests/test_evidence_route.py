"""Tests for GET /threats/{ip}/evidence (ADR-0041 / issue #387 MI-6).

EARS acceptance criteria → test mapping:

  EARS-1 — WHEN evidence is requested for an IP, every breakdown factor present
           SHALL list the ``logs`` row ids, recomputed at read time.
           → test_evidence_returns_factors_for_known_ip
           → test_evidence_factor_log_row_ids_present

  EARS-2 (consistency invariant) — factors and points SHALL match
           build_score_breakdown output for the same rows.
           → test_evidence_factors_match_breakdown_from_pipeline

  EARS-3 — WHEN matched_event_ids / event_id are empty, chain is still complete.
           → test_evidence_complete_with_no_event_ids

  EARS-4 (read-only) — endpoint makes no writes, no LLM calls.
           → test_evidence_route_is_read_only_no_ai_call
           → test_evidence_unknown_ip_returns_404
           → test_evidence_no_store_returns_503
           → test_evidence_no_pipeline_returns_503

  EARS-5 — ai_boost factor returns stored-artifact reference, not recomputed.
           → test_evidence_ai_boost_is_reference_shape

  ADR-0029 envelope — response has source_ip, factors, recomputed fields.
           → test_evidence_response_envelope_shape
           → test_evidence_recomputed_flag_is_true

  RFC-5737 IPs only: 203.0.113.0/24.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi.testclient import TestClient

from firewatch_sdk import ScoreBreakdownItem, ThreatScore

# ---------------------------------------------------------------------------
# Minimal fakes for this test module
# ---------------------------------------------------------------------------


def _make_score(
    ip: str,
    breakdown: list[ScoreBreakdownItem] | None = None,
) -> ThreatScore:
    now = datetime.now(timezone.utc)
    items = breakdown or [
        ScoreBreakdownItem(factor="blocked_events", label="3 blocked events", points=3),
    ]
    return ThreatScore(
        source_ip=ip,
        threat_level="MEDIUM",
        score=sum(i.points for i in items),
        total_events=5,
        blocked_events=3,
        attack_types=[],
        first_seen=now,
        last_seen=now,
        ai_status="disabled",
        score_breakdown=items,
    )


class _EvidenceStore:
    """Minimal store fake with get_events_with_row_ids support."""

    def __init__(
        self,
        rows_by_ip: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        self._rows = rows_by_ip or {}

    async def _conn(self) -> Any:
        return self

    async def get_all_ips(self) -> list[str]:
        return list(self._rows.keys())

    async def get_by_ip_raw(self, ip: str) -> list[dict[str, Any]]:
        return self._rows.get(ip, [])

    async def get_events_with_row_ids(self, ip: str) -> list[dict[str, Any]]:
        return self._rows.get(ip, [])

    # ---- required no-ops to satisfy the store protocol ----
    async def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        return []

    async def get_paginated(self, limit: int = 100, filters: Any = None) -> dict[str, Any]:
        return {"logs": [], "next_cursor": None, "has_more": False, "total_matching": 0}

    async def get_categories(self) -> list[dict[str, Any]]:
        return []

    async def get_category_summary(self) -> list[dict[str, Any]]:
        return []

    async def get_timeline(self, start: Any = None, end: Any = None) -> list[dict[str, Any]]:
        return []

    async def get_rule_descriptions(self) -> dict[str, str]:
        return {}

    async def get_analytics_geo(self) -> list[dict[str, Any]]:
        return []

    async def get_analytics_summary(self) -> dict[str, Any]:
        return {"total_ips": 0, "total_events": 0, "total_blocked": 0,
                "block_rate": 0.0, "top_country": "", "unique_countries": 0, "top_rule": ""}

    async def get_categories_timeline(self, start: Any = None, end: Any = None) -> list[dict[str, Any]]:
        return []

    async def get_stats(self) -> dict[str, Any]:
        return {"total_logs": 0, "total_ips": 0, "blocked_percentage": 0.0,
                "top_attack_types": [], "last_updated": None}

    async def source_health(self) -> list[dict[str, Any]]:
        return []

    async def get_ip_counterfactual(self, ip: str) -> dict[str, Any]:
        return {"total_events": 0, "blocked_events": 0, "unblocked_events": 0}

    async def get_attack_dispositions(self, top_n: int = 5) -> list[dict[str, Any]]:
        return []


class _EvidencePipeline:
    """Minimal pipeline fake for evidence route tests."""

    def __init__(self, scores: dict[str, ThreatScore] | None = None) -> None:
        self._scores: dict[str, ThreatScore] = scores or {}
        self.analyze_ip_calls: list[tuple[str, bool]] = []

    async def analyze_ip(self, ip: str, *, use_ai: bool = True) -> ThreatScore:
        self.analyze_ip_calls.append((ip, use_ai))
        if ip in self._scores:
            return self._scores[ip]
        now = datetime.now(timezone.utc)
        return ThreatScore(
            source_ip=ip, threat_level="LOW", score=0,
            total_events=0, blocked_events=0, attack_types=[],
            first_seen=now, last_seen=now, ai_status="disabled",
        )

    async def analyze_ip_detailed(self, ip: str, *, include_ai: bool = True) -> dict[str, Any]:
        return {"error": "No logs found"}


def _make_row(
    row_id: int,
    action: str = "BLOCK",
    destination_port: int = 80,
    payload_snippet: str | None = None,
    rule_id: str | None = None,
) -> dict[str, Any]:
    return {
        "id": row_id,
        "timestamp": "2026-06-03T12:00:00+00:00",
        "action": action,
        "destination_port": destination_port,
        "rule_id": rule_id,
        "payload_snippet": payload_snippet,
        "source_type": "suricata",
        "category": None,
    }


def _build_client(
    rows_by_ip: dict[str, list[dict[str, Any]]] | None = None,
    scores: dict[str, ThreatScore] | None = None,
    store: Any = None,
    pipeline: Any = None,
) -> TestClient:
    from _api_fakes import FakePullPlugin
    from firewatch_api.app import create_app

    _store = store if store is not None else _EvidenceStore(rows_by_ip or {})
    _pipeline = pipeline if pipeline is not None else _EvidencePipeline(scores or {})
    app = create_app(
        registry={"suricata": FakePullPlugin()},
        config_store=None,
        event_store=_store,
        pipeline=_pipeline,
    )
    return TestClient(app)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

_IP = "203.0.113.20"


def test_evidence_returns_factors_for_known_ip() -> None:
    """EARS-1: 200 response with factors list for a known IP."""
    rows = [_make_row(i, action="BLOCK") for i in range(1, 4)]
    score = _make_score(_IP, breakdown=[
        ScoreBreakdownItem(factor="blocked_events", label="3 blocked events", points=3),
    ])
    client = _build_client(
        rows_by_ip={_IP: rows},
        scores={_IP: score},
    )
    resp = client.get(f"/threats/{_IP}/evidence")
    assert resp.status_code == 200
    data = resp.json()
    assert "factors" in data
    assert len(data["factors"]) >= 1


def test_evidence_factor_log_row_ids_present() -> None:
    """EARS-1: blocked_events factor contains log_row_ids for blocked rows."""
    rows = [_make_row(i, action="BLOCK") for i in range(1, 4)]
    score = _make_score(_IP, breakdown=[
        ScoreBreakdownItem(factor="blocked_events", label="3 blocked events", points=3),
    ])
    client = _build_client(rows_by_ip={_IP: rows}, scores={_IP: score})
    resp = client.get(f"/threats/{_IP}/evidence")
    assert resp.status_code == 200
    factors = resp.json()["factors"]
    be = next((f for f in factors if f["factor"] == "blocked_events"), None)
    assert be is not None
    assert set(be["log_row_ids"]) == {1, 2, 3}
    assert be["count"] == 3


def test_evidence_factors_match_breakdown_from_pipeline() -> None:
    """EARS-2: factor keys and points in response match the score_breakdown."""
    rows = [_make_row(i, action="BLOCK") for i in range(1, 4)]
    breakdown = [
        ScoreBreakdownItem(factor="blocked_events", label="3 blocked events", points=3),
        ScoreBreakdownItem(factor="port_scan", label="Port scan — 5 ports", points=25),
    ]
    score = _make_score(_IP, breakdown=breakdown)
    client = _build_client(rows_by_ip={_IP: rows}, scores={_IP: score})
    resp = client.get(f"/threats/{_IP}/evidence")
    assert resp.status_code == 200

    factors = resp.json()["factors"]
    factor_map = {f["factor"]: f["points"] for f in factors}
    for item in breakdown:
        assert item.factor in factor_map, f"Factor '{item.factor}' missing from evidence"
        assert factor_map[item.factor] == item.points


def test_evidence_complete_with_no_event_ids() -> None:
    """EARS-3: evidence chain is complete even when event_id fields are empty."""
    # Production rows have no event_id — only the logs.id matters.
    rows = [_make_row(i, action="BLOCK") for i in range(1, 6)]
    score = _make_score(_IP, breakdown=[
        ScoreBreakdownItem(factor="blocked_events", label="5 blocked events", points=5),
    ])
    client = _build_client(rows_by_ip={_IP: rows}, scores={_IP: score})
    resp = client.get(f"/threats/{_IP}/evidence")
    assert resp.status_code == 200
    factors = resp.json()["factors"]
    assert len(factors) > 0
    be = next((f for f in factors if f["factor"] == "blocked_events"), None)
    assert be is not None
    assert be["count"] == 5


def test_evidence_route_is_read_only_no_ai_call() -> None:
    """EARS-4: pipeline.analyze_ip is called with use_ai=False (no LLM call)."""
    rows = [_make_row(1, action="BLOCK")]
    score = _make_score(_IP)
    pipeline = _EvidencePipeline(scores={_IP: score})
    client = _build_client(
        rows_by_ip={_IP: rows},
        pipeline=pipeline,
    )
    resp = client.get(f"/threats/{_IP}/evidence")
    assert resp.status_code == 200
    # Confirm analyze_ip was called with use_ai=False — no AI engine triggered.
    calls = pipeline.analyze_ip_calls
    assert len(calls) == 1
    _called_ip, called_use_ai = calls[0]
    assert called_use_ai is False, (
        "EARS-4: evidence endpoint must call analyze_ip with use_ai=False "
        "(ai-engine-invariants boundary)"
    )


def test_evidence_unknown_ip_returns_404() -> None:
    """EARS-4: unknown IP (no rows) → 404, not 200 with empty factors."""
    client = _build_client(rows_by_ip={})
    resp = client.get("/threats/203.0.113.99/evidence")
    assert resp.status_code == 404


def test_evidence_no_store_returns_503() -> None:
    """EARS-4: no event store → 503."""
    from _api_fakes import FakePullPlugin
    from firewatch_api.app import create_app

    app = create_app(
        registry={"suricata": FakePullPlugin()},
        config_store=None,
        event_store=None,
        pipeline=_EvidencePipeline(),
    )
    client = TestClient(app)
    resp = client.get(f"/threats/{_IP}/evidence")
    assert resp.status_code == 503


def test_evidence_no_pipeline_returns_503() -> None:
    """EARS-4: no pipeline → 503."""
    from _api_fakes import FakePullPlugin
    from firewatch_api.app import create_app

    rows = [_make_row(1, action="BLOCK")]
    app = create_app(
        registry={"suricata": FakePullPlugin()},
        config_store=None,
        event_store=_EvidenceStore({_IP: rows}),
        pipeline=None,
    )
    client = TestClient(app)
    resp = client.get(f"/threats/{_IP}/evidence")
    assert resp.status_code == 503


def test_evidence_ai_boost_is_reference_shape() -> None:
    """EARS-5: ai_boost factor has AiBoostEvidence shape (provenance, no log_row_ids)."""
    rows = [_make_row(i, action="BLOCK") for i in range(1, 5)]
    breakdown = [
        ScoreBreakdownItem(factor="blocked_events", label="4 blocked events", points=4),
        ScoreBreakdownItem(factor="ai_boost", label="AI boost — CRITICAL (+20)", points=20),
    ]
    score = _make_score(_IP, breakdown=breakdown)
    client = _build_client(rows_by_ip={_IP: rows}, scores={_IP: score})
    resp = client.get(f"/threats/{_IP}/evidence")
    assert resp.status_code == 200

    factors = resp.json()["factors"]
    ai_ev = next((f for f in factors if f["factor"] == "ai_boost"), None)
    assert ai_ev is not None
    # AiBoostEvidence shape: has provenance, note; does NOT have log_row_ids.
    assert "provenance" in ai_ev
    assert "note" in ai_ev
    assert "log_row_ids" not in ai_ev, (
        "ai_boost evidence must not have log_row_ids "
        "(it is a stored-artifact reference, ADR-0041 / EARS-5)"
    )


def test_evidence_response_envelope_shape() -> None:
    """ADR-0029 envelope: response has source_ip, factors, recomputed fields."""
    rows = [_make_row(1, action="BLOCK")]
    score = _make_score(_IP)
    client = _build_client(rows_by_ip={_IP: rows}, scores={_IP: score})
    resp = client.get(f"/threats/{_IP}/evidence")
    assert resp.status_code == 200
    data = resp.json()
    assert "source_ip" in data
    assert "factors" in data
    assert "recomputed" in data
    assert data["source_ip"] == _IP
    assert isinstance(data["factors"], list)


def test_evidence_recomputed_flag_is_true() -> None:
    """ADR-0041: recomputed flag is always True (read-time semantics)."""
    rows = [_make_row(1, action="BLOCK")]
    score = _make_score(_IP)
    client = _build_client(rows_by_ip={_IP: rows}, scores={_IP: score})
    resp = client.get(f"/threats/{_IP}/evidence")
    assert resp.status_code == 200
    assert resp.json()["recomputed"] is True


def test_evidence_summaries_included_in_factors() -> None:
    """Evidence factors include summaries with log_row_id and timestamp."""
    rows = [_make_row(42, action="BLOCK", payload_snippet="test payload")]
    score = _make_score(_IP, breakdown=[
        ScoreBreakdownItem(factor="blocked_events", label="1 blocked event", points=1),
    ])
    client = _build_client(rows_by_ip={_IP: rows}, scores={_IP: score})
    resp = client.get(f"/threats/{_IP}/evidence")
    assert resp.status_code == 200

    factors = resp.json()["factors"]
    be = next((f for f in factors if f["factor"] == "blocked_events"), None)
    assert be is not None
    assert "summaries" in be
    assert len(be["summaries"]) == 1
    summary = be["summaries"][0]
    assert summary["log_row_id"] == 42
    assert "timestamp" in summary
    assert "action" in summary
