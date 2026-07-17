"""Tests for the additive ``triage_decision`` annotation on GET /threats and
GET /threats/{ip} (ADR-0072 D3/D8, issue #47 Part 1/backend) — fake pipeline
+ fake decision store (route-level, cheap).

See ``test_issue_72_dead_wire_integration.py`` for the real-app/real-sqlite
boundary proof.

EARS → test mapping
─────────────────────
- Undecided actor: triage_decision is null on both /threats and /threats/{ip}.
  -> test_undecided_actor_has_null_triage_decision

- Decided + suppressed actor: triage_decision carries verb/decided_at/
  decided_tier/decided_score/suppressed=true, and the actor is STILL present
  in the /threats list (ADR-0072 finding 1 — never removed).
  -> test_decided_actor_annotated_and_still_listed

- decision_store=None (not wired): every actor renders as undecided — no 503,
  no crash (the annotation degrades gracefully).
  -> test_no_decision_store_degrades_to_null_annotation

- 404 for an unknown IP is unaffected by the annotation change.
  -> test_unknown_ip_still_returns_404

All IPs are RFC 5737 documentation IPs (192.0.2.0/24).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi.testclient import TestClient

from firewatch_sdk import EscalationVerdict, ThreatScore

from firewatch_api.app import create_app

_IP = "192.0.2.90"


class _FakeEventStore:
    async def get_all_ips(self) -> list[str]:
        return [_IP]


class _FakePipeline:
    def __init__(self, score: ThreatScore) -> None:
        self._score = score

    async def analyze_ip(self, ip: str, *, use_ai: bool = True) -> ThreatScore:
        if ip == _IP:
            return self._score
        now = datetime.now(timezone.utc)
        return ThreatScore(
            source_ip=ip, threat_level="LOW", score=0, total_events=0,
            blocked_events=0, attack_types=[], first_seen=now, last_seen=now,
        )


class _FakeDecisionStore:
    def __init__(self, rows_by_actor: dict[str, list[dict[str, Any]]]) -> None:
        self._rows_by_actor = rows_by_actor

    async def get_active_for_actor(self, actor_ip: str) -> list[dict[str, Any]]:
        return self._rows_by_actor.get(actor_ip, [])


def _score() -> ThreatScore:
    now = datetime.now(timezone.utc)
    return ThreatScore(
        source_ip=_IP, threat_level="MEDIUM", score=42, total_events=3,
        blocked_events=0, attack_types=[], first_seen=now, last_seen=now,
        escalation=EscalationVerdict(
            tier=2, disposition="block_status_unknown",
            justification="[RULE] test", block_status="unknown",
        ),
    )


def _build_client(decision_store: Any = None) -> TestClient:
    app = create_app(
        event_store=_FakeEventStore(),
        pipeline=_FakePipeline(_score()),
        decision_store=decision_store,
    )
    return TestClient(app)


def test_undecided_actor_has_null_triage_decision() -> None:
    client = _build_client(decision_store=_FakeDecisionStore({}))

    list_resp = client.get("/threats")
    assert list_resp.status_code == 200
    actor = next(t for t in list_resp.json() if t["source_ip"] == _IP)
    assert actor["triage_decision"] is None

    detail_resp = client.get(f"/threats/{_IP}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["triage_decision"] is None


def test_decided_actor_annotated_and_still_listed() -> None:
    rows = {
        _IP: [{
            "id": 1, "actor_ip": _IP, "verb": "dismissed", "rule_name": None,
            "decided_tier": 2, "decided_score": 42,
            "decided_at": "2026-07-01T00:00:00+00:00",
            "revoked_at": None, "author": "local operator", "note": None,
        }]
    }
    client = _build_client(decision_store=_FakeDecisionStore(rows))

    list_resp = client.get("/threats")
    ips = [t["source_ip"] for t in list_resp.json()]
    assert _IP in ips  # ADR-0072 finding 1: decided actors are never removed

    actor = next(t for t in list_resp.json() if t["source_ip"] == _IP)
    td = actor["triage_decision"]
    assert td["verb"] == "dismissed"
    assert td["decided_tier"] == 2
    assert td["decided_score"] == 42
    assert td["suppressed"] is True
    assert td["reentry"] is None


def test_no_decision_store_degrades_to_null_annotation() -> None:
    client = _build_client(decision_store=None)
    resp = client.get(f"/threats/{_IP}")
    assert resp.status_code == 200
    assert resp.json()["triage_decision"] is None


def test_unknown_ip_still_returns_404() -> None:
    client = _build_client(decision_store=_FakeDecisionStore({}))
    resp = client.get("/threats/198.51.100.200")
    assert resp.status_code == 404
