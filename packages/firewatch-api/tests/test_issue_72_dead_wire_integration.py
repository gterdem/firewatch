"""Dead-wire boundary test — ADR-0072 D8 mandatory integration test.

Crosses route -> annotator -> suppression -> store in ONE request, over the
REAL FastAPI app + REAL sqlite (no fakes for the event store, pipeline, or
decision store) — there is no browser e2e infra, so this is the boundary
guard the ADR requires.

EARS -> test mapping
─────────────────────
D8  POST /decisions (expected) -> GET /threats shows suppressed:true ->
    GET /banner/summary queue_size decremented.
    -> test_full_suppression_loop_over_real_app_and_sqlite

D3  A decided actor is NEVER removed from GET /threats (ADR-0072 finding 1;
    the "remove decided actors" alternative was explicitly rejected).
    -> test_decided_actor_still_present_in_threats_list

D3  DELETE /decisions/{id} (undo) restores the actor to the queue.
    -> test_revoke_restores_queue_membership

D4  false_positive scoped to (actor, rule_name) — a DIFFERENT qualifying
    rule still queues the actor even with an active FP decision on file.
    -> test_false_positive_does_not_suppress_different_rule

All IPs are RFC 5737 documentation IPs (203.0.113.0/24).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from firewatch_sdk import SecurityEvent

from firewatch_core.adapters.ai_disabled import DisabledAIEngine
from firewatch_core.adapters.decisions.sqlite_decisions import SqliteDecisionStore
from firewatch_core.adapters.sqlite_store import SQLiteEventStore
from firewatch_core.pipeline import Pipeline

from firewatch_api.app import create_app

_IP = "203.0.113.77"
_NOW = datetime(2026, 7, 17, 12, 0, 0, tzinfo=timezone.utc)


def _qualifying_alert_event(ip: str, rule_name: str = "waf_sqli") -> SecurityEvent:
    """A single high-severity ALERT — D1(b)-qualifying, routes to Tier 2."""
    return SecurityEvent(
        source_type="suricata",
        source_id="pi-home",
        source_ip=ip,
        action="ALERT",
        severity="high",
        rule_name=rule_name,
        timestamp=_NOW - timedelta(minutes=5),
    )


@pytest.fixture()
def real_app(tmp_path: Path) -> Any:
    """Build the real app: real SQLiteEventStore + Pipeline + SqliteDecisionStore.

    All three share ONE db file (mirrors the production wiring in
    firewatch_cli.commands.serve/run — case_store/decision_store share the
    event store's db_path, ADR-0023 §F).
    """

    async def _build() -> tuple[Any, SQLiteEventStore, SqliteDecisionStore]:
        db_path = tmp_path / "firewatch_events.db"
        store = SQLiteEventStore(db_path=db_path)
        await store.init()

        pipeline = Pipeline(store=store, ai_engine=DisabledAIEngine(), clock=lambda: _NOW)

        decision_store = SqliteDecisionStore(db_path=db_path)
        await decision_store.init()

        app = create_app(
            event_store=store,
            pipeline=pipeline,
            decision_store=decision_store,
        )
        return app, store, decision_store

    app, store, decision_store = asyncio.run(_build())
    yield app, store, decision_store
    asyncio.run(decision_store.close())
    asyncio.run(store.close())


def _seed_qualifying_actor(store: SQLiteEventStore, ip: str = _IP, rule_name: str = "waf_sqli") -> None:
    asyncio.run(store.save_many([_qualifying_alert_event(ip, rule_name)]))


class TestFullSuppressionLoop:
    def test_full_suppression_loop_over_real_app_and_sqlite(self, real_app: Any) -> None:
        app, store, _decision_store = real_app
        _seed_qualifying_actor(store)
        client = TestClient(app)

        # --- Before any decision: actor is Tier 2, queued, undecided. -------
        threats_before = client.get("/threats").json()
        actor_before = next(t for t in threats_before if t["source_ip"] == _IP)
        assert actor_before["escalation"]["tier"] == 2
        assert actor_before["triage_decision"] is None

        banner_before = client.get("/banner/summary").json()
        assert banner_before["queue_size"] == 1

        # --- POST /decisions (expected) --------------------------------------
        create_resp = client.post(
            "/decisions", json={"actor_ip": _IP, "verb": "expected"},
        )
        assert create_resp.status_code == 201
        body = create_resp.json()
        assert body["decided_tier"] == 2  # server-computed snapshot, not client-supplied
        assert body["verb"] == "expected"

        # --- GET /threats now shows suppressed:true ---------------------------
        threats_after = client.get("/threats").json()
        actor_after = next(t for t in threats_after if t["source_ip"] == _IP)
        assert actor_after["triage_decision"]["suppressed"] is True
        assert actor_after["triage_decision"]["verb"] == "expected"

        # --- GET /banner/summary queue_size decremented ------------------------
        banner_after = client.get("/banner/summary").json()
        assert banner_after["queue_size"] == 0

    def test_decided_actor_still_present_in_threats_list(self, real_app: Any) -> None:
        """ADR-0072 finding 1 — decided actors are annotated, never removed."""
        app, store, _decision_store = real_app
        _seed_qualifying_actor(store)
        client = TestClient(app)

        client.post("/decisions", json={"actor_ip": _IP, "verb": "dismissed"})

        threats = client.get("/threats").json()
        ips = [t["source_ip"] for t in threats]
        assert _IP in ips

        detail = client.get(f"/threats/{_IP}")
        assert detail.status_code == 200
        assert detail.json()["triage_decision"]["suppressed"] is True

    def test_revoke_restores_queue_membership(self, real_app: Any) -> None:
        app, store, _decision_store = real_app
        _seed_qualifying_actor(store)
        client = TestClient(app)

        create_resp = client.post("/decisions", json={"actor_ip": _IP, "verb": "expected"})
        decision_id = create_resp.json()["id"]
        assert client.get("/banner/summary").json()["queue_size"] == 0

        revoke_resp = client.delete(f"/decisions/{decision_id}")
        assert revoke_resp.status_code == 200

        assert client.get("/banner/summary").json()["queue_size"] == 1
        threats = client.get("/threats").json()
        actor = next(t for t in threats if t["source_ip"] == _IP)
        assert actor["triage_decision"] is None


class TestFalsePositiveScopingOverRealApp:
    def test_false_positive_does_not_suppress_different_rule(self, real_app: Any) -> None:
        """ADR-0070 D6 / ADR-0072 D4 — FP is scoped to (actor, rule_name); a
        DIFFERENT qualifying rule still queues the actor."""
        app, store, _decision_store = real_app
        _seed_qualifying_actor(store, rule_name="waf_sqli")
        client = TestClient(app)

        fp_resp = client.post(
            "/decisions",
            json={"actor_ip": _IP, "verb": "false_positive", "rule_name": "waf_xss"},
        )
        assert fp_resp.status_code == 201

        # The actor's ONLY qualifying rule is waf_sqli, not waf_xss — the FP
        # row does not cover it, so the actor is still queued.
        assert client.get("/banner/summary").json()["queue_size"] == 1
        threats = client.get("/threats").json()
        actor = next(t for t in threats if t["source_ip"] == _IP)
        assert actor["triage_decision"] is None  # no actor-scoped decision either

    def test_false_positive_covering_the_qualifying_rule_suppresses(self, real_app: Any) -> None:
        app, store, _decision_store = real_app
        _seed_qualifying_actor(store, rule_name="waf_sqli")
        client = TestClient(app)

        fp_resp = client.post(
            "/decisions",
            json={"actor_ip": _IP, "verb": "false_positive", "rule_name": "waf_sqli"},
        )
        assert fp_resp.status_code == 201

        assert client.get("/banner/summary").json()["queue_size"] == 0


class TestValidation:
    def test_false_positive_without_rule_name_returns_422(self, real_app: Any) -> None:
        app, _store, _decision_store = real_app
        client = TestClient(app)
        resp = client.post("/decisions", json={"actor_ip": _IP, "verb": "false_positive"})
        assert resp.status_code == 422

    def test_expected_with_rule_name_returns_422(self, real_app: Any) -> None:
        app, _store, _decision_store = real_app
        client = TestClient(app)
        resp = client.post(
            "/decisions",
            json={"actor_ip": _IP, "verb": "expected", "rule_name": "waf_sqli"},
        )
        assert resp.status_code == 422

    def test_malformed_actor_ip_returns_422_not_500(self, real_app: Any) -> None:
        app, _store, _decision_store = real_app
        client = TestClient(app)
        resp = client.post(
            "/decisions",
            json={"actor_ip": "<script>alert(1)</script>", "verb": "expected"},
        )
        assert resp.status_code == 422

    def test_revoke_unknown_id_returns_404(self, real_app: Any) -> None:
        app, _store, _decision_store = real_app
        client = TestClient(app)
        resp = client.delete("/decisions/999999")
        assert resp.status_code == 404
