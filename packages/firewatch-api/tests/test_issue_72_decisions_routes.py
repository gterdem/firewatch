"""Route-level tests for POST/GET /decisions, DELETE /decisions/{id}
(ADR-0072 D3, issue #47 Part 1/backend) — fake store + fake pipeline.

See ``test_issue_72_dead_wire_integration.py`` for the real-app/real-sqlite
boundary test; this module exercises route-level branches (503s, 422s, 404)
cheaply with fakes.

EARS → test mapping
─────────────────────
D3  POST /decisions returns 201 + the full record incl. the SERVER-computed
    snapshot (decided_tier/decided_score) — the client's request body never
    carries them.
    → test_create_decision_uses_server_computed_snapshot

D3  422 when verb='false_positive' XOR rule_name is present.
    → TestValidation

D3  GET /decisions returns the ADR-0029 D2 cursor envelope.
    → test_list_decisions_returns_envelope

D3  DELETE /decisions/{id} soft-revokes; 404 on unknown id.
    → TestRevoke

503  Each route degrades to 503 when its dependency is unavailable.
    → TestUnavailableDependencies

All IPs are RFC 5737 documentation IPs (192.0.2.0/24).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi.testclient import TestClient

from firewatch_sdk import EscalationVerdict, ThreatScore

from firewatch_api.app import create_app

_IP = "192.0.2.70"


class _FakeDecisionStore:
    """Minimal in-memory fake DecisionStore for route-layer tests."""

    def __init__(self) -> None:
        self._rows: dict[int, dict[str, Any]] = {}
        self._next_id = 1

    async def create_decision(
        self,
        *,
        actor_ip: str,
        verb: str,
        rule_name: str | None,
        decided_tier: int | None,
        decided_score: int,
        author: str = "local operator",
        note: str | None = None,
    ) -> dict[str, Any]:
        if verb not in {"expected", "dismissed", "false_positive"}:
            raise ValueError(f"invalid verb {verb!r}")
        if (verb == "false_positive") != (rule_name is not None):
            raise ValueError("rule_name pairing mismatch")
        row_id = self._next_id
        self._next_id += 1
        record = {
            "id": row_id,
            "actor_ip": actor_ip,
            "verb": verb,
            "rule_name": rule_name,
            "decided_tier": decided_tier,
            "decided_score": decided_score,
            "decided_at": "2026-07-17T00:00:00+00:00",
            "revoked_at": None,
            "author": author,
            "note": note,
        }
        self._rows[row_id] = record
        return dict(record)

    async def list_decisions(
        self, limit: int = 50, cursor: str | None = None, actor: str | None = None
    ) -> dict[str, Any]:
        items = [
            dict(r) for r in sorted(self._rows.values(), key=lambda r: -r["id"])
            if actor is None or r["actor_ip"] == actor
        ]
        return {"items": items[:limit], "next_cursor": None, "has_more": False}

    async def revoke_decision(self, decision_id: int) -> None:
        if decision_id not in self._rows:
            raise LookupError(f"{decision_id} not found")
        self._rows[decision_id]["revoked_at"] = "2026-07-17T01:00:00+00:00"

    async def get_active_for_actor(self, actor_ip: str) -> list[dict[str, Any]]:
        return [
            dict(r) for r in self._rows.values()
            if r["actor_ip"] == actor_ip and r["revoked_at"] is None
        ]


class _FakePipeline:
    """Pipeline fake returning a fixed ThreatScore (with a Tier-2 verdict)."""

    def __init__(self, score: ThreatScore | None = None) -> None:
        self._score = score

    async def analyze_ip(self, ip: str, *, use_ai: bool = True) -> ThreatScore:
        if self._score is not None:
            return self._score
        now = datetime.now(timezone.utc)
        return ThreatScore(
            source_ip=ip, threat_level="MEDIUM", score=42,
            total_events=3, blocked_events=0, attack_types=[],
            first_seen=now, last_seen=now,
            escalation=EscalationVerdict(
                tier=2, disposition="block_status_unknown",
                justification="[RULE] test", block_status="unknown",
            ),
        )


def _build_client(store: Any = None, pipeline: Any = None) -> TestClient:
    app = create_app(event_store=object(), pipeline=pipeline, decision_store=store)
    return TestClient(app)


# ---------------------------------------------------------------------------
# POST /decisions
# ---------------------------------------------------------------------------


def test_create_decision_uses_server_computed_snapshot() -> None:
    client = _build_client(store=_FakeDecisionStore(), pipeline=_FakePipeline())
    resp = client.post("/decisions", json={"actor_ip": _IP, "verb": "expected"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["decided_tier"] == 2  # from the pipeline's ThreatScore.escalation.tier
    assert body["decided_score"] == 42  # from the pipeline's ThreatScore.score
    assert body["verb"] == "expected"
    assert body["rule_name"] is None


def test_create_decision_false_positive_requires_rule_name_present() -> None:
    client = _build_client(store=_FakeDecisionStore(), pipeline=_FakePipeline())
    resp = client.post(
        "/decisions",
        json={"actor_ip": _IP, "verb": "false_positive", "rule_name": "waf_sqli"},
    )
    assert resp.status_code == 201
    assert resp.json()["rule_name"] == "waf_sqli"


class TestValidation:
    def test_false_positive_without_rule_name_returns_422(self) -> None:
        client = _build_client(store=_FakeDecisionStore(), pipeline=_FakePipeline())
        resp = client.post("/decisions", json={"actor_ip": _IP, "verb": "false_positive"})
        assert resp.status_code == 422

    def test_expected_with_rule_name_returns_422(self) -> None:
        client = _build_client(store=_FakeDecisionStore(), pipeline=_FakePipeline())
        resp = client.post(
            "/decisions",
            json={"actor_ip": _IP, "verb": "expected", "rule_name": "waf_sqli"},
        )
        assert resp.status_code == 422

    def test_invalid_verb_returns_422(self) -> None:
        client = _build_client(store=_FakeDecisionStore(), pipeline=_FakePipeline())
        resp = client.post("/decisions", json={"actor_ip": _IP, "verb": "acknowledge"})
        assert resp.status_code == 422

    def test_missing_actor_ip_returns_422(self) -> None:
        client = _build_client(store=_FakeDecisionStore(), pipeline=_FakePipeline())
        resp = client.post("/decisions", json={"verb": "expected"})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /decisions
# ---------------------------------------------------------------------------


def test_list_decisions_returns_envelope() -> None:
    store = _FakeDecisionStore()
    client = _build_client(store=store, pipeline=_FakePipeline())
    client.post("/decisions", json={"actor_ip": _IP, "verb": "expected"})
    resp = client.get("/decisions")
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body and "next_cursor" in body and "has_more" in body
    assert len(body["items"]) == 1


def test_list_decisions_actor_filter() -> None:
    store = _FakeDecisionStore()
    client = _build_client(store=store, pipeline=_FakePipeline())
    client.post("/decisions", json={"actor_ip": _IP, "verb": "expected"})
    client.post("/decisions", json={"actor_ip": "198.51.100.5", "verb": "dismissed"})
    resp = client.get("/decisions", params={"actor": _IP})
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["actor_ip"] == _IP


# ---------------------------------------------------------------------------
# DELETE /decisions/{id}
# ---------------------------------------------------------------------------


class TestRevoke:
    def test_revoke_returns_200(self) -> None:
        store = _FakeDecisionStore()
        client = _build_client(store=store, pipeline=_FakePipeline())
        create_resp = client.post("/decisions", json={"actor_ip": _IP, "verb": "expected"})
        decision_id = create_resp.json()["id"]
        resp = client.delete(f"/decisions/{decision_id}")
        assert resp.status_code == 200

    def test_revoke_unknown_id_returns_404(self) -> None:
        client = _build_client(store=_FakeDecisionStore(), pipeline=_FakePipeline())
        resp = client.delete("/decisions/999")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 503 degrade paths
# ---------------------------------------------------------------------------


class TestUnavailableDependencies:
    def test_create_decision_no_store_returns_503(self) -> None:
        client = _build_client(store=None, pipeline=_FakePipeline())
        resp = client.post("/decisions", json={"actor_ip": _IP, "verb": "expected"})
        assert resp.status_code == 503

    def test_create_decision_no_pipeline_returns_503(self) -> None:
        client = _build_client(store=_FakeDecisionStore(), pipeline=None)
        resp = client.post("/decisions", json={"actor_ip": _IP, "verb": "expected"})
        assert resp.status_code == 503

    def test_list_decisions_no_store_returns_503(self) -> None:
        client = _build_client(store=None, pipeline=_FakePipeline())
        resp = client.get("/decisions")
        assert resp.status_code == 503

    def test_revoke_no_store_returns_503(self) -> None:
        client = _build_client(store=None, pipeline=_FakePipeline())
        resp = client.delete("/decisions/1")
        assert resp.status_code == 503
