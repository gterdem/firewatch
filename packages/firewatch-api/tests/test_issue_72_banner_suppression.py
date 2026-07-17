"""Tests for ADR-0072 finding 2 — GET /banner/summary's ``queue_size`` excludes
suppressed actors, via the SAME evaluator ``GET /threats``' ``triage_decision``
annotation uses.

See ``test_issue_72_dead_wire_integration.py`` for the real-app/real-sqlite
end-to-end proof; this module exercises ``banner_assembler.compute_actor_
attempt_stats``' pure ``suppressed`` parameter and the route's wiring with a
fake decision store.

EARS → test mapping
─────────────────────
- compute_actor_attempt_stats(suppressed=True) excludes an otherwise-queued
  (Tier 1/2) actor from queued=True.
  -> test_suppressed_tier2_actor_is_not_queued

- suppressed=False (the default) preserves pre-#47 behaviour exactly —
  regression pin against issue #55.
  -> test_default_suppressed_false_preserves_prior_behaviour

- GET /banner/summary's queue_size excludes an actor with an active
  `expected` decision (route-level, fake decision store).
  -> test_route_queue_size_excludes_actor_with_active_decision

- No decision_store wired (None) → queue_size unaffected (today's behaviour).
  -> test_route_no_decision_store_behaves_as_before

All IPs are RFC 5737 documentation IPs (203.0.113.0/24).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi.testclient import TestClient

from firewatch_sdk.models import ActionLiteral, SecurityEvent, SeverityLiteral

from firewatch_core.detector import detect
from firewatch_core.escalation.decider import decide

from firewatch_api.app import create_app
from firewatch_api.banner_assembler import assemble_banner_attempt_summary, compute_actor_attempt_stats

_IP_A = "203.0.113.90"
_NOW = datetime(2026, 7, 17, 12, 0, 0, tzinfo=timezone.utc)


def _event(
    ip: str,
    *,
    action: ActionLiteral = "ALERT",
    severity: SeverityLiteral | None = "high",
    rule_name: str | None = "waf_sqli",
    ts: datetime = _NOW,
) -> SecurityEvent:
    return SecurityEvent(
        source_type="suricata", source_id="default", timestamp=ts,
        source_ip=ip, action=action, severity=severity, rule_name=rule_name,
    )


class TestComputeActorAttemptStatsSuppression:
    def test_suppressed_tier2_actor_is_not_queued(self) -> None:
        events = [_event(_IP_A, ts=_NOW - timedelta(minutes=5))]
        detections = detect(events, now=_NOW)
        verdict = decide(events, detections)
        assert verdict.tier == 2

        stats = compute_actor_attempt_stats(
            _IP_A, state_events=events, campaign_events=events,
            detections=detections, verdict=verdict, now=_NOW, suppressed=True,
        )
        assert stats.queued is False

        summary = assemble_banner_attempt_summary([stats])
        assert summary.queue_size == 0

    def test_default_suppressed_false_preserves_prior_behaviour(self) -> None:
        events = [_event(_IP_A, ts=_NOW - timedelta(minutes=5))]
        detections = detect(events, now=_NOW)
        verdict = decide(events, detections)

        stats = compute_actor_attempt_stats(
            _IP_A, state_events=events, campaign_events=events,
            detections=detections, verdict=verdict, now=_NOW,
        )
        assert stats.queued is True


# ---------------------------------------------------------------------------
# Route-level wiring
# ---------------------------------------------------------------------------


class _FakeEventStore:
    def __init__(self, events: list[SecurityEvent]) -> None:
        self._events = events

    async def get_all_ips(self) -> list[str]:
        return sorted({e.source_ip for e in self._events})

    async def get_by_ip(self, ip: str) -> list[SecurityEvent]:
        return [e for e in self._events if e.source_ip == ip]


class _FakeDecisionStore:
    """Returns a fixed active `expected` row for one actor; empty for others."""

    def __init__(self, suppressed_actor: str | None) -> None:
        self._suppressed_actor = suppressed_actor

    async def get_active_for_actor(self, actor_ip: str) -> list[dict[str, Any]]:
        if actor_ip != self._suppressed_actor:
            return []
        return [{
            "id": 1, "actor_ip": actor_ip, "verb": "expected", "rule_name": None,
            "decided_tier": 2, "decided_score": 30, "decided_at": "2026-07-01T00:00:00+00:00",
            "revoked_at": None, "author": "local operator", "note": None,
        }]


def test_route_queue_size_excludes_actor_with_active_decision() -> None:
    events = [_event(_IP_A, ts=_NOW - timedelta(minutes=5))]
    app = create_app(
        registry={},
        event_store=_FakeEventStore(events),
        decision_store=_FakeDecisionStore(suppressed_actor=_IP_A),
    )
    client = TestClient(app)
    resp = client.get("/banner/summary")
    assert resp.status_code == 200
    assert resp.json()["queue_size"] == 0


def test_route_no_decision_store_behaves_as_before() -> None:
    events = [_event(_IP_A, ts=_NOW - timedelta(minutes=5))]
    app = create_app(registry={}, event_store=_FakeEventStore(events), decision_store=None)
    client = TestClient(app)
    resp = client.get("/banner/summary")
    assert resp.status_code == 200
    assert resp.json()["queue_size"] == 1
