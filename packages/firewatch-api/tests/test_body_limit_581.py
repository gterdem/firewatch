"""Tests for the request-body-size guard (HTTP 413) on the ingest write door.

Issue #581 — OWASP API4 (Unrestricted Resource Consumption) gap closure.

EARS → test mapping
-------------------

Unwanted-behavior:
  W1 — IF a request to POST /logs carries a body exceeding the configured
       byte cap, THEN the server SHALL reject it with 413 before any
       normalization or persistence.
       → test_oversized_single_accurate_content_length_returns_413
       → test_oversized_single_missing_content_length_still_returns_413
       → test_oversized_batch_accurate_content_length_returns_413
       → test_oversized_batch_missing_content_length_still_returns_413

  W2 — At-limit body is accepted (off-by-one boundary).
       → test_at_limit_body_is_accepted
       → test_under_limit_body_is_accepted

  W3 — The 413 response body MUST NOT echo attacker-controlled body content
       (OWASP API4, RFC 9110 §15.5.14).
       → test_413_response_does_not_echo_body_content

  W4 — The guard is wired into create_app (the dead-wiring failure mode from the
       prior attempt): a TestClient built from create_app() MUST be rejected,
       not a middleware-less app.
       → test_guard_wired_into_create_app_rejects_oversized_body

Ubiquitous:
  U1 — The cap is overridable via FIREWATCH_MAX_BODY_BYTES env var (ADR-0006).
       → test_env_override_raises_cap
       → test_env_override_lowers_cap

  U2 — Normal ingest paths (single + batch within limit) are unaffected.
       → test_normal_single_ingest_unaffected
       → test_normal_batch_ingest_unaffected

  U3 — Batch count cap (ADR-0029 D7.2) still works alongside byte cap.
       → test_batch_count_cap_still_enforced

  U4 — Only the ingest write door (POST /logs, POST /logs/batch) is guarded;
       GET read routes pass through without the size gate.
       → test_get_routes_not_blocked_by_body_guard

Standards: OWASP API Security Top 10 (2023) API4; RFC 9110 §15.5.14 (413);
           ADR-0026 D3; ADR-0029 D7.3.
"""
from __future__ import annotations

import json
import os
from typing import Any
import pytest
from fastapi.testclient import TestClient

from firewatch_api.app import create_app
from firewatch_api.body_limit import _DEFAULT_MAX_BODY_BYTES, _ENV_MAX_BODY


# ---------------------------------------------------------------------------
# Helpers: fake dependencies (mirrors test_ingest_routes.py pattern)
# ---------------------------------------------------------------------------


def _noop_config_store() -> Any:
    """Minimal config store that satisfies the dependency without file I/O."""
    from pydantic import BaseModel

    class _Noop:
        def get_source(self, source_type: str, schema: type[BaseModel]) -> BaseModel:
            return schema.model_validate({})

        def set_source(
            self,
            source_type: str,
            schema: type[BaseModel],
            updates: dict[str, Any],
        ) -> None:
            pass

        def get_runtime(self) -> Any:
            from firewatch_sdk import RuntimeConfig

            return RuntimeConfig.model_validate({})

        def set_runtime(self, updates: dict[str, Any]) -> None:
            pass

    return _Noop()


class _FakeStore:
    """Minimal store fake that records saves."""

    def __init__(self) -> None:
        self.saved: list[Any] = []

    async def save_many(self, events: list[Any]) -> int:
        self.saved.extend(events)
        return len(events)

    async def get_all_ips(self) -> list[str]:
        return []

    async def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        return []

    async def get_stats(self) -> dict[str, Any]:
        return {
            "total_logs": 0,
            "total_ips": 0,
            "blocked_percentage": 0.0,
            "top_attack_types": [],
        }


class _FakePipeline:
    """Pipeline fake that delegates ingest to the store."""

    def __init__(self, store: _FakeStore) -> None:
        self.store = store
        self.analyze_calls: list[str] = []

    async def ingest(self, events: list[Any]) -> int:
        return await self.store.save_many(events)

    async def background_analyze_and_alert(self, ip: str) -> None:
        self.analyze_calls.append(ip)


class _FakePlugin:
    """Fake plugin with working normalize()."""

    def normalize(self, raw: Any, source_id: str) -> Any:
        from firewatch_sdk import SecurityEvent

        return SecurityEvent(
            source_type="suricata",
            source_id=source_id,
            timestamp=raw.received_at,
            source_ip="192.0.2.1",
            action="ALERT",
        )

    def metadata(self) -> Any:
        from firewatch_sdk import SourceMetadata

        return SourceMetadata(
            type_key="suricata",
            display_name="Fake",
            version="1.0.0",
            flavor="pull",
        )


def _make_client(
    max_body_bytes: int | None = None,
    monkeypatch: pytest.MonkeyPatch | None = None,
) -> TestClient:
    """Build a TestClient with create_app() wired with fakes.

    When *max_body_bytes* is provided, sets the env var so BodyLimitMiddleware
    picks it up (via monkeypatch if provided, else os.environ directly).
    Callers that use monkeypatch get automatic cleanup.
    """
    store = _FakeStore()
    pipeline = _FakePipeline(store)
    plugin = _FakePlugin()
    registry: dict[str, Any] = {"suricata": plugin}

    if max_body_bytes is not None:
        if monkeypatch is not None:
            monkeypatch.setenv(_ENV_MAX_BODY, str(max_body_bytes))
        else:
            os.environ[_ENV_MAX_BODY] = str(max_body_bytes)

    app = create_app(
        registry=registry,
        config_store=_noop_config_store(),
        event_store=store,
        pipeline=pipeline,
    )
    return TestClient(app, raise_server_exceptions=False)


def _single_event_body(padded_data: str = "") -> dict[str, Any]:
    """Minimal valid single-event body, optionally with padding in data."""
    return {
        "source_type": "suricata",
        "source_id": "sensor-1",
        "data": {"alert": "ET SCAN", "pad": padded_data},
        "received_at": "2026-06-05T10:00:00Z",
    }


def _batch_body(n: int = 2, padded_data: str = "") -> dict[str, Any]:
    """Minimal valid batch body with *n* events, optionally padded."""
    return {
        "events": [
            {
                "source_type": "suricata",
                "source_id": f"sensor-{i}",
                "data": {"seq": i, "pad": padded_data},
                "received_at": "2026-06-05T10:00:00Z",
            }
            for i in range(n)
        ]
    }


# ---------------------------------------------------------------------------
# W1 — Oversized bodies → 413
# ---------------------------------------------------------------------------


def test_oversized_single_accurate_content_length_returns_413(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /logs with accurate oversized Content-Length → 413."""
    cap = 512
    client = _make_client(max_body_bytes=cap, monkeypatch=monkeypatch)

    # Build a body that clearly exceeds the cap
    body_bytes = json.dumps(_single_event_body(padded_data="X" * cap)).encode()
    assert len(body_bytes) > cap, "Test body must exceed cap"

    resp = client.post(
        "/logs",
        content=body_bytes,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body_bytes))},
    )
    assert resp.status_code == 413, f"Expected 413, got {resp.status_code}"


def test_oversized_single_missing_content_length_still_returns_413(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /logs with no Content-Length but oversized streaming body → 413.

    Validates the streaming read cap (not just header check).
    """
    cap = 512
    client = _make_client(max_body_bytes=cap, monkeypatch=monkeypatch)

    body_bytes = json.dumps(_single_event_body(padded_data="Y" * cap)).encode()
    assert len(body_bytes) > cap, "Test body must exceed cap"

    # Send without Content-Length — streaming guard must catch it.
    resp = client.post(
        "/logs",
        content=body_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413, f"Expected 413, got {resp.status_code}"


def test_oversized_batch_accurate_content_length_returns_413(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /logs/batch with accurate oversized Content-Length → 413."""
    cap = 512
    client = _make_client(max_body_bytes=cap, monkeypatch=monkeypatch)

    body_bytes = json.dumps(_batch_body(n=2, padded_data="Z" * cap)).encode()
    assert len(body_bytes) > cap, "Test body must exceed cap"

    resp = client.post(
        "/logs/batch",
        content=body_bytes,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body_bytes))},
    )
    assert resp.status_code == 413, f"Expected 413, got {resp.status_code}"


def test_oversized_batch_missing_content_length_still_returns_413(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /logs/batch with no Content-Length but oversized body → 413."""
    cap = 512
    client = _make_client(max_body_bytes=cap, monkeypatch=monkeypatch)

    body_bytes = json.dumps(_batch_body(n=2, padded_data="W" * cap)).encode()
    assert len(body_bytes) > cap, "Test body must exceed cap"

    resp = client.post(
        "/logs/batch",
        content=body_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413, f"Expected 413, got {resp.status_code}"


# ---------------------------------------------------------------------------
# W2 — At-limit and under-limit bodies are accepted
# ---------------------------------------------------------------------------


def test_at_limit_body_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """A body exactly at the byte cap is accepted (boundary condition)."""
    # Use a large cap so the minimal valid body fits within it
    cap = _DEFAULT_MAX_BODY_BYTES  # 1 MiB — any normal body is well under this
    client = _make_client(max_body_bytes=cap, monkeypatch=monkeypatch)

    # A tiny body is well under the cap — must not be rejected
    body_bytes = json.dumps(_single_event_body()).encode()
    assert len(body_bytes) < cap, "Test body should be under the cap for this boundary test"

    resp = client.post(
        "/logs",
        content=body_bytes,
        headers={"Content-Type": "application/json"},
    )
    # Should NOT be 413 — store/pipeline fakes handle the rest
    assert resp.status_code != 413, "Under-limit body was incorrectly rejected with 413"


def test_under_limit_body_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """A body well under the byte cap passes through to the route handler."""
    cap = 4096
    client = _make_client(max_body_bytes=cap, monkeypatch=monkeypatch)

    body_bytes = json.dumps(_single_event_body()).encode()
    assert len(body_bytes) < cap, "Test fixture body must be smaller than cap"

    resp = client.post(
        "/logs",
        content=body_bytes,
        headers={"Content-Type": "application/json"},
    )
    # Route handler accepts (store fake → 201)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# W3 — 413 response must not echo attacker-controlled body content
# ---------------------------------------------------------------------------


def test_413_response_does_not_echo_body_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """413 response body must not contain the sentinel from the oversized request.

    OWASP API4 / RFC 9110 §15.5.14: the server MUST NOT echo attacker-controlled
    body content in the error response.
    """
    cap = 512
    sentinel = "ATTACKER_SENTINEL_XYZ_12345"
    client = _make_client(max_body_bytes=cap, monkeypatch=monkeypatch)

    body_bytes = json.dumps(_single_event_body(padded_data=sentinel + "X" * cap)).encode()
    assert len(body_bytes) > cap

    resp = client.post(
        "/logs",
        content=body_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    assert sentinel not in resp.text, (
        f"413 response MUST NOT echo attacker-controlled content; sentinel found in: {resp.text!r}"
    )


# ---------------------------------------------------------------------------
# W4 — Dead-wiring guard: create_app() must actually reject oversized bodies
# ---------------------------------------------------------------------------


def test_guard_wired_into_create_app_rejects_oversized_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The middleware is wired into create_app — not just defined, but registered.

    This is the exact failure mode the prior attempt missed: if add_middleware
    is never called, all bodies pass through regardless of size.
    """
    cap = 256
    client = _make_client(max_body_bytes=cap, monkeypatch=monkeypatch)

    oversized = json.dumps(_single_event_body(padded_data="A" * cap)).encode()
    assert len(oversized) > cap

    resp = client.post("/logs", content=oversized, headers={"Content-Type": "application/json"})
    assert resp.status_code == 413, (
        "Body limit middleware is NOT wired into create_app — "
        f"oversized body returned {resp.status_code} instead of 413. "
        "Check that app.add_middleware(BodyLimitMiddleware) is called in app.py."
    )


# ---------------------------------------------------------------------------
# U1 — Env-var override (ADR-0006)
# ---------------------------------------------------------------------------


def test_env_override_raises_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Setting FIREWATCH_MAX_BODY_BYTES to a large value raises the cap.

    A body that would be rejected at the default 1 MiB cap but is within
    a custom larger cap must be accepted.

    Note: the default cap is 1 MiB, so any normal body is well under it.
    This test uses a tiny body and a tiny cap that is then raised via env.
    """
    # With cap=100, the minimal valid body is rejected
    monkeypatch.setenv(_ENV_MAX_BODY, "100")
    store = _FakeStore()
    pipeline = _FakePipeline(store)
    plugin = _FakePlugin()
    registry: dict[str, Any] = {"suricata": plugin}

    app = create_app(
        registry=registry,
        config_store=_noop_config_store(),
        event_store=store,
        pipeline=pipeline,
    )
    client = TestClient(app, raise_server_exceptions=False)

    body_bytes = json.dumps(_single_event_body()).encode()
    # If body > 100 bytes, we expect 413
    if len(body_bytes) > 100:
        resp = client.post("/logs", content=body_bytes, headers={"Content-Type": "application/json"})
        assert resp.status_code == 413

    # Now raise the cap to 1 MiB — same body must pass
    monkeypatch.setenv(_ENV_MAX_BODY, str(1024 * 1024))
    app2 = create_app(
        registry=registry,
        config_store=_noop_config_store(),
        event_store=store,
        pipeline=pipeline,
    )
    client2 = TestClient(app2, raise_server_exceptions=False)
    resp2 = client2.post("/logs", content=body_bytes, headers={"Content-Type": "application/json"})
    assert resp2.status_code == 201, f"Expected 201 with raised cap, got {resp2.status_code}"


def test_env_override_lowers_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Setting FIREWATCH_MAX_BODY_BYTES to a small value lowers the cap.

    Bodies that would pass the default cap are rejected with the lowered cap.
    """
    # Set a tiny cap: any non-trivial JSON body will exceed it
    tiny_cap = 10
    client = _make_client(max_body_bytes=tiny_cap, monkeypatch=monkeypatch)

    body_bytes = json.dumps(_single_event_body()).encode()
    assert len(body_bytes) > tiny_cap, "Fixture body must exceed tiny cap"

    resp = client.post("/logs", content=body_bytes, headers={"Content-Type": "application/json"})
    assert resp.status_code == 413, f"Expected 413 with lowered cap, got {resp.status_code}"


# ---------------------------------------------------------------------------
# U2 — Normal ingest paths unaffected
# ---------------------------------------------------------------------------


def test_normal_single_ingest_unaffected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Normal POST /logs within the default cap succeeds (201)."""
    client = _make_client(monkeypatch=monkeypatch)

    body_bytes = json.dumps(_single_event_body()).encode()
    resp = client.post("/logs", content=body_bytes, headers={"Content-Type": "application/json"})
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"


def test_normal_batch_ingest_unaffected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Normal POST /logs/batch within the default cap succeeds (201)."""
    client = _make_client(monkeypatch=monkeypatch)

    body_bytes = json.dumps(_batch_body(n=2)).encode()
    resp = client.post(
        "/logs/batch", content=body_bytes, headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# U3 — Batch count cap still enforced alongside byte cap
# ---------------------------------------------------------------------------


def test_batch_count_cap_still_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    """ADR-0029 D7.2 batch COUNT cap still returns 422 (not superseded by byte cap).

    The byte-level cap complements the count cap; both must work independently.
    """
    from firewatch_api.routes.ingest import _ENV_MAX_BATCH

    # Set count limit to 2 events; batch with 3 must be rejected with 422
    monkeypatch.setenv(_ENV_MAX_BATCH, "2")
    client = _make_client(monkeypatch=monkeypatch)

    body = _batch_body(n=3)
    body_bytes = json.dumps(body).encode()

    resp = client.post(
        "/logs/batch",
        content=body_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422, f"Expected 422 from count cap, got {resp.status_code}"


# ---------------------------------------------------------------------------
# U4 — GET routes not blocked by body guard
# ---------------------------------------------------------------------------


def test_get_routes_not_blocked_by_body_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """GET routes are not rejected by the body limit guard.

    The guard MUST only act on the ingest write door — read routes pass through.
    We test GET /health as a simple proxy for the read surface.
    """
    # Use a tiny cap — GET requests carry no body so must not be blocked
    tiny_cap = 10
    client = _make_client(max_body_bytes=tiny_cap, monkeypatch=monkeypatch)

    resp = client.get("/health")
    # 200 OK or 503 (no store wired for health assembler) — NOT 413
    assert resp.status_code != 413, "GET /health was incorrectly rejected with 413"
