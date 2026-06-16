"""Route-level tests for POST /logs and POST /logs/batch (MC.3, issue #88).

Tests the full POST → server-side normalize → store → count envelope path
through the real FastAPI app via TestClient, verifying the EARS criteria in
issue #88 / ADR-0029 D7.

EARS → test mapping:

  Ubiquitous:
    U1 — The ingest door routes to the plugin's normalize() via the registry;
         it is generic and source-agnostic (no Azure-specific code paths).
         → test_post_log_calls_plugin_normalize
    U2 — ingest.py must not import legacy/ or concrete plugins.
         → test_ingest_module_no_forbidden_imports

  Event-driven:
    E1 — WHEN a RawEvent is POSTed to /logs, it is normalized, stored, and
         the count envelope (inserted, deduped) is returned (201).
         → test_post_log_success_returns_count_envelope
    E2 — WHEN a batch is POSTed to /logs/batch, all events are normalized,
         persisted, and the count envelope is returned (201).
         → test_post_log_batch_success_returns_count_envelope
    E3 — WHEN ingest succeeds, background_analyze_and_alert is scheduled for
         the source_ip — the response returns BEFORE the analysis completes.
         → test_post_log_schedules_background_analyze
         → test_post_log_batch_schedules_background_analyze_per_distinct_ip

  Unwanted / fault:
    W1 — IF source_type has no registered plugin → 422 (ADR-0029 D7.1).
         → test_post_log_unknown_source_type_returns_422
         → test_post_log_batch_unknown_source_type_returns_422
    W2 — IF the POST body is malformed → 422 (missing required field).
         → test_post_log_malformed_body_returns_422
         → test_post_log_batch_malformed_body_returns_422
    W3 — IF /logs/batch exceeds the max batch size → 422 (ADR-0029 D7.2).
         → test_post_log_batch_over_limit_returns_422
         → test_post_log_batch_at_limit_is_accepted (boundary)
    W4 — A replayed batch is absorbed by the store dedup; the response reports
         deduped count > 0 and inserted count accurately (ADR-0007/0016).
         → test_post_log_batch_replayed_returns_deduped_count
         → test_post_log_single_deduped_returns_zero_inserted
    W5 — IF background_analyze_and_alert raises internally, the ingest
         response is already 201; the exception must not reach the HTTP layer.
         The real Pipeline.background_analyze_and_alert swallows all exceptions
         (per its docstring / EARS W-faults); this test verifies the isolation
         holds end-to-end through the route.
         → test_post_log_background_exception_is_isolated_from_response
    W6 — IF normalize() raises for a batch event → 422 before any persistence.
         → test_post_log_batch_normalize_failure_returns_422
    W7 — GET /logs routes continue to work after the ingest router is wired
         (no routing conflict between GET /logs/* and POST /logs).
         → test_get_logs_still_works_after_ingest_router_wired

  Security hardening (#88 security review — non-blocking):
    NB2 — source_id/source_type Field constraints block CR/LF and control
          characters (log-injection prevention) and enforce length bounds.
         → test_post_log_source_id_with_newline_is_rejected
         → test_post_log_source_id_over_max_length_is_rejected
         → test_post_log_source_id_at_max_length_is_accepted (boundary)
         → test_post_log_source_id_empty_is_rejected
         → test_post_log_source_type_with_newline_is_rejected
         → test_post_log_source_type_over_max_length_is_rejected
         → test_post_log_batch_source_id_with_newline_is_rejected
    NB3 — When normalize() raises pydantic.ValidationError, the 422 detail
          must NOT contain the attacker-supplied bad input value.
         → test_post_log_validation_error_422_does_not_echo_attacker_input
         → test_post_log_batch_validation_error_422_does_not_echo_attacker_input
"""
from __future__ import annotations

import importlib
import logging
import types
from typing import Any

import pytest
from fastapi.testclient import TestClient

from firewatch_api.app import create_app
from firewatch_api.routes.ingest import _ENV_MAX_BATCH


# ---------------------------------------------------------------------------
# Fake store with controllable save_many behaviour
# ---------------------------------------------------------------------------


class FakeIngestStore:
    """Minimal store fake for ingest tests.

    ``save_many_return`` controls how many rows ``save_many`` reports as inserted.
    None means "all inserted" (len(events)).  The store records every call.
    """

    def __init__(self, save_many_return: int | None = None) -> None:
        self._save_many_return = save_many_return
        self.saved: list[list[Any]] = []

    async def save_many(self, events: list[Any]) -> int:
        self.saved.append(list(events))
        if self._save_many_return is not None:
            return self._save_many_return
        return len(events)

    # ── stubs for health / read routes ──────────────────────────────────

    async def _conn(self) -> Any:
        return self

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


# ---------------------------------------------------------------------------
# Fake pipeline
# ---------------------------------------------------------------------------


class FakeIngestPipeline:
    """Pipeline fake that delegates ingest to the store and records analyze calls.

    ``background_analyze_and_alert`` mirrors the real Pipeline contract:
    it catches all internal exceptions so the HTTP layer never sees them.
    ``analyze_calls`` records which IPs were scheduled for background analysis.
    """

    def __init__(self, store: FakeIngestStore) -> None:
        self.store = store
        self.analyze_calls: list[str] = []
        # Set to an exception class to simulate an internal failure inside the
        # background analysis — the method still swallows it (real contract).
        self._bg_side_effect: Exception | None = None

    async def ingest(self, events: list[Any]) -> int:
        return await self.store.save_many(events)

    async def background_analyze_and_alert(self, ip: str) -> None:
        """Mirror the real Pipeline.background_analyze_and_alert isolation contract.

        All exceptions are caught and logged here — callers (BackgroundTasks) must
        never see this raise.  The ingest is already committed before this runs.
        """
        try:
            self.analyze_calls.append(ip)
            if self._bg_side_effect is not None:
                raise self._bg_side_effect
        except Exception:
            # Intentional swallow — mirrors Pipeline.background_analyze_and_alert.
            logging.getLogger("firewatch.api.ingest").error(
                "fake: background analysis failed for ip=%s", ip
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _noop_config_store() -> Any:
    """Minimal config store that satisfies the dependency without file I/O."""
    from pydantic import BaseModel

    class _Noop:
        def get_source(
            self, source_type: str, schema: type[BaseModel]
        ) -> BaseModel:
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


def _make_client(
    plugin_ip: str = "192.0.2.50",
    store: FakeIngestStore | None = None,
    pipeline: FakeIngestPipeline | None = None,
    extra_plugins: dict[str, Any] | None = None,
) -> tuple[TestClient, FakeIngestStore, FakeIngestPipeline]:
    """Build a TestClient wired with controllable fake dependencies.

    Returns (client, store, pipeline) so tests can assert on captured state.
    The default registry contains only ``suricata`` mapped to a FakePullPlugin
    that emits ``plugin_ip`` as the normalized ``source_ip``.
    """
    from _api_fakes import FakePullPlugin

    fake_store = store if store is not None else FakeIngestStore()
    fake_pipeline = (
        pipeline if pipeline is not None else FakeIngestPipeline(fake_store)
    )

    registry: dict[str, Any] = {
        "suricata": FakePullPlugin("suricata", normalize_ip=plugin_ip)
    }
    if extra_plugins:
        registry.update(extra_plugins)

    app = create_app(
        registry=registry,
        config_store=_noop_config_store(),
        event_store=fake_store,
        pipeline=fake_pipeline,
    )
    return TestClient(app), fake_store, fake_pipeline


def _single_event_body(
    source_type: str = "suricata",
    source_id: str = "test-sensor",
) -> dict[str, Any]:
    """Minimal valid IngestRequest body."""
    return {
        "source_type": source_type,
        "source_id": source_id,
        "data": {"alert": {"signature": "ET SCAN", "severity": 2}},
        "received_at": "2026-06-05T10:00:00Z",
    }


def _batch_body(
    n: int = 2,
    source_type: str = "suricata",
) -> dict[str, Any]:
    """Minimal valid BatchIngestRequest body with *n* events."""
    return {
        "events": [
            {
                "source_type": source_type,
                "source_id": f"sensor-{i}",
                "data": {"seq": i},
                "received_at": "2026-06-05T10:00:00Z",
            }
            for i in range(n)
        ]
    }


# ===========================================================================
# U2 — dependency rule
# ===========================================================================


def test_ingest_module_no_forbidden_imports() -> None:
    """U2 — ingest.py must not import legacy/ or any concrete plugin."""
    forbidden = (
        "legacy",
        "firewatch_suricata",
        "firewatch_syslog",
        "firewatch_azure",
    )
    mod = importlib.import_module("firewatch_api.routes.ingest")
    for name, obj in vars(mod).items():
        if isinstance(obj, types.ModuleType):
            for prefix in forbidden:
                assert not obj.__name__.startswith(prefix), (
                    f"ingest.py imports forbidden module {obj.__name__!r} via {name!r}"
                )


# ===========================================================================
# U1 + E1 — POST /logs happy path
# ===========================================================================


def test_post_log_success_returns_count_envelope() -> None:
    """E1 — POST /logs returns 201 with inserted/deduped count envelope."""
    client, _, _ = _make_client(plugin_ip="192.0.2.50")
    resp = client.post("/logs", json=_single_event_body())

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["inserted"] == 1
    assert body["deduped"] == 0


def test_post_log_calls_plugin_normalize() -> None:
    """U1 — POST /logs routes through the plugin's normalize(); not hardcoded."""
    client, store, _ = _make_client(plugin_ip="192.0.2.51")
    resp = client.post("/logs", json=_single_event_body(source_type="suricata"))
    assert resp.status_code == 201

    # The store must have received the normalized event with the IP the plugin produced.
    assert len(store.saved) == 1
    events = store.saved[0]
    assert len(events) == 1
    assert events[0].source_ip == "192.0.2.51"
    assert events[0].source_type == "suricata"


# ===========================================================================
# E2 — POST /logs/batch happy path
# ===========================================================================


def test_post_log_batch_success_returns_count_envelope() -> None:
    """E2 — POST /logs/batch returns 201 with correct inserted/deduped counts."""
    client, _, _ = _make_client(plugin_ip="192.0.2.52")
    resp = client.post("/logs/batch", json=_batch_body(n=3))

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["inserted"] == 3
    assert body["deduped"] == 0


# ===========================================================================
# E3 — background_analyze_and_alert is scheduled
# ===========================================================================


def test_post_log_schedules_background_analyze() -> None:
    """E3 — POST /logs schedules background_analyze_and_alert for the source_ip.

    TestClient runs BackgroundTasks synchronously, so analyze_calls is
    populated before the assertion.
    """
    client, _, pipeline = _make_client(plugin_ip="192.0.2.53")
    resp = client.post("/logs", json=_single_event_body())
    assert resp.status_code == 201

    assert "192.0.2.53" in pipeline.analyze_calls


def test_post_log_batch_schedules_background_analyze_per_distinct_ip() -> None:
    """E3 — POST /logs/batch schedules exactly one task per distinct source_ip.

    All events in this batch map to the same IP (single plugin, single IP),
    so only one background_analyze_and_alert call fires (deduplication).
    """
    client, _, pipeline = _make_client(plugin_ip="192.0.2.54")
    resp = client.post("/logs/batch", json=_batch_body(n=3))
    assert resp.status_code == 201

    assert pipeline.analyze_calls.count("192.0.2.54") == 1


# ===========================================================================
# W1 — unknown source_type → 422
# ===========================================================================


def test_post_log_unknown_source_type_returns_422() -> None:
    """W1 — POST /logs with an unregistered source_type returns 422 (ADR-0029 D7.1)."""
    client, _, _ = _make_client()
    resp = client.post("/logs", json=_single_event_body(source_type="no_such_plugin"))

    assert resp.status_code == 422, resp.text
    assert "no_such_plugin" in resp.json()["detail"]


def test_post_log_batch_unknown_source_type_returns_422() -> None:
    """W1 — POST /logs/batch with an unknown source_type in any event returns 422."""
    client, _, _ = _make_client()
    body = {
        "events": [
            _single_event_body(source_type="suricata"),
            _single_event_body(source_type="nonexistent"),
        ]
    }
    resp = client.post("/logs/batch", json=body)
    assert resp.status_code == 422, resp.text


# ===========================================================================
# W2 — malformed body → 422
# ===========================================================================


def test_post_log_malformed_body_returns_422() -> None:
    """W2 — POST /logs with a body missing required fields returns 422."""
    client, _, _ = _make_client()
    # Missing source_type, source_id, and data.
    resp = client.post("/logs", json={"received_at": "2026-06-05T10:00:00Z"})
    assert resp.status_code == 422, resp.text


def test_post_log_batch_malformed_body_returns_422() -> None:
    """W2 — POST /logs/batch with a structurally invalid body returns 422."""
    client, _, _ = _make_client()
    # 'events' must be a list; passing a string violates the schema.
    resp = client.post("/logs/batch", json={"events": "not-a-list"})
    assert resp.status_code == 422, resp.text


# ===========================================================================
# W3 — batch over limit → 422
# ===========================================================================


def test_post_log_batch_over_limit_returns_422(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """W3 — POST /logs/batch exceeding FIREWATCH_MAX_BATCH_SIZE returns 422.

    ADR-0029 D7.2 / ADR-0006: config-overridable via env var.
    Over-limit is rejected before any persistence (store.saved must be empty).
    """
    monkeypatch.setenv(_ENV_MAX_BATCH, "2")

    client, store, _ = _make_client()
    resp = client.post("/logs/batch", json=_batch_body(n=3))

    assert resp.status_code == 422, resp.text
    assert "3" in resp.json()["detail"]
    # Nothing persisted.
    assert store.saved == []


def test_post_log_batch_at_limit_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """W3 boundary — A batch exactly at the configured limit is accepted (not off-by-one)."""
    monkeypatch.setenv(_ENV_MAX_BATCH, "2")

    client, _, _ = _make_client()
    resp = client.post("/logs/batch", json=_batch_body(n=2))
    assert resp.status_code == 201, resp.text


# ===========================================================================
# W4 — replayed batch → deduped count in response
# ===========================================================================


def test_post_log_batch_replayed_returns_deduped_count() -> None:
    """W4 — When the store deduplicates events, the response reflects inserted vs deduped.

    The store returns 1 inserted even though 3 events were submitted (2 deduped).
    ADR-0007/0016: dedup happens in the store's unique index; the route mirrors it.
    """
    store = FakeIngestStore(save_many_return=1)
    client, _, _ = _make_client(store=store)
    resp = client.post("/logs/batch", json=_batch_body(n=3))

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["inserted"] == 1
    assert body["deduped"] == 2


def test_post_log_single_deduped_returns_zero_inserted() -> None:
    """W4 single — A fully deduped single event reports inserted=0, deduped=1."""
    store = FakeIngestStore(save_many_return=0)
    client, _, _ = _make_client(store=store)
    resp = client.post("/logs", json=_single_event_body())

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["inserted"] == 0
    assert body["deduped"] == 1


# ===========================================================================
# W5 — background task exception is isolated from the HTTP response
# ===========================================================================


def test_post_log_background_exception_is_isolated_from_response() -> None:
    """W5 — background_analyze_and_alert exceptions must not reach the HTTP layer.

    The real Pipeline.background_analyze_and_alert catches all exceptions internally
    (per its docstring and EARS W-fault criterion).  FakeIngestPipeline mirrors this
    contract: _bg_side_effect is caught inside the method, never propagated.

    Expected result: 201 is returned; the ingest is committed (store.saved non-empty).
    """
    store = FakeIngestStore()
    pipeline = FakeIngestPipeline(store)
    pipeline._bg_side_effect = RuntimeError("background analysis blew up")

    client, _, _ = _make_client(store=store, pipeline=pipeline)
    resp = client.post("/logs", json=_single_event_body())

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["inserted"] == 1
    # The background task ran (and caught its own exception).
    assert len(pipeline.analyze_calls) == 1


# ===========================================================================
# W6 — normalize() failure in batch → 422 before any persistence
# ===========================================================================


def test_post_log_batch_normalize_failure_returns_422() -> None:
    """W6 — If a plugin's normalize() raises, the batch returns 422 with nothing persisted."""
    from _api_fakes import FailingPlugin

    store = FakeIngestStore()
    pipeline = FakeIngestPipeline(store)

    registry: dict[str, Any] = {"broken": FailingPlugin("broken")}
    app = create_app(
        registry=registry,
        config_store=_noop_config_store(),
        event_store=store,
        pipeline=pipeline,
    )
    client = TestClient(app)

    body = {
        "events": [
            {
                "source_type": "broken",
                "source_id": "s1",
                "data": {"x": 1},
                "received_at": "2026-06-05T10:00:00Z",
            }
        ]
    }
    resp = client.post("/logs/batch", json=body)
    assert resp.status_code == 422, resp.text
    # Nothing must have been persisted — fail-fast before any write.
    assert store.saved == []


# ===========================================================================
# W7 — GET /logs routes still work after ingest router is wired
# ===========================================================================


def test_get_logs_still_works_after_ingest_router_wired() -> None:
    """W7 — Existing GET /logs/recent continues to return 200 after ingest router is added.

    Regression guard: verifies no routing conflict between GET /logs/* and POST /logs.
    """
    client, _, _ = _make_client()
    resp = client.get("/logs/recent")
    assert resp.status_code == 200, resp.text
    assert isinstance(resp.json(), list)


# ===========================================================================
# Security hardening — NB2: source_id / source_type Field constraints
# (CRLF/log-injection prevention, issue #88 security review)
# ===========================================================================


def test_post_log_source_id_with_newline_is_rejected() -> None:
    """NB2 — source_id containing a newline character is rejected with 422.

    A newline in source_id enables log-injection (the field is logged via %s).
    The Field(pattern=_SOURCE_ID_PATTERN) on IngestRequest excludes CR/LF.
    """
    client, _, _ = _make_client()
    body = _single_event_body(source_id="legit\nERROR firewatch fabricated-log-line")
    resp = client.post("/logs", json=body)
    assert resp.status_code == 422, resp.text


def test_post_log_source_id_over_max_length_is_rejected() -> None:
    """NB2 — source_id exceeding 128 characters is rejected with 422.

    Validates the max_length=128 constraint on IngestRequest.source_id.
    """
    client, _, _ = _make_client()
    body = _single_event_body(source_id="a" * 129)
    resp = client.post("/logs", json=body)
    assert resp.status_code == 422, resp.text


def test_post_log_source_id_at_max_length_is_accepted() -> None:
    """NB2 boundary — source_id of exactly 128 characters is accepted."""
    client, _, _ = _make_client()
    body = _single_event_body(source_id="a" * 128)
    resp = client.post("/logs", json=body)
    assert resp.status_code == 201, resp.text


def test_post_log_source_id_empty_is_rejected() -> None:
    """NB2 — empty source_id is rejected with 422 (min_length=1)."""
    client, _, _ = _make_client()
    body = _single_event_body(source_id="")
    resp = client.post("/logs", json=body)
    assert resp.status_code == 422, resp.text


def test_post_log_source_type_with_newline_is_rejected() -> None:
    """NB2 — source_type containing a newline character is rejected with 422.

    The Field(pattern=_SOURCE_TYPE_PATTERN) on IngestRequest.source_type
    uses ^[a-z][a-z0-9_]*$ which excludes CR/LF/control characters.
    """
    client, _, _ = _make_client()
    body = _single_event_body(source_type="suricata\nevil")
    resp = client.post("/logs", json=body)
    assert resp.status_code == 422, resp.text


def test_post_log_source_type_over_max_length_is_rejected() -> None:
    """NB2 — source_type exceeding 128 characters is rejected with 422."""
    client, _, _ = _make_client()
    # Use valid lowercase letters to pass pattern; only max_length should trip.
    body = _single_event_body(source_type="a" * 129)
    resp = client.post("/logs", json=body)
    assert resp.status_code == 422, resp.text


def test_post_log_batch_source_id_with_newline_is_rejected() -> None:
    """NB2 — source_id newline injection in a batch item is rejected with 422.

    BatchIngestRequest.events composes IngestRequest, so the same constraints
    apply to batch items.
    """
    client, _, _ = _make_client()
    body = {
        "events": [
            {
                "source_type": "suricata",
                "source_id": "good-sensor",
                "data": {"seq": 0},
                "received_at": "2026-06-05T10:00:00Z",
            },
            {
                "source_type": "suricata",
                "source_id": "evil\nERROR fabricated",
                "data": {"seq": 1},
                "received_at": "2026-06-05T10:00:00Z",
            },
        ]
    }
    resp = client.post("/logs/batch", json=body)
    assert resp.status_code == 422, resp.text


# ===========================================================================
# Security hardening — NB3: ValidationError 422 detail must not echo
# attacker input (issue #88 security review)
# ===========================================================================


def _make_validation_fail_client(
    sentinel: str,
) -> tuple[TestClient, FakeIngestStore, FakeIngestPipeline]:
    """Build a TestClient wired with a FailingValidationPlugin for NB3 tests."""
    from _api_fakes import FailingValidationPlugin

    store = FakeIngestStore()
    pipeline = FakeIngestPipeline(store)
    registry: dict[str, Any] = {
        "validationfail": FailingValidationPlugin("validationfail", sentinel=sentinel)
    }
    app = create_app(
        registry=registry,
        config_store=_noop_config_store(),
        event_store=store,
        pipeline=pipeline,
    )
    return TestClient(app), store, pipeline


def test_post_log_validation_error_422_does_not_echo_attacker_input() -> None:
    """NB3 — When normalize() raises pydantic.ValidationError, the 422 detail
    must NOT contain the attacker-supplied bad input value.

    The sentinel string is embedded in the ValidationError's str() by pydantic
    (it includes the bad input value).  The route must sanitize the response
    to a schema-only message, never reflecting attacker content.
    """
    sentinel = "ATTACKER_CONTROLLED_SECRET_PAYLOAD"
    client, _, _ = _make_validation_fail_client(sentinel)

    resp = client.post(
        "/logs",
        json={
            "source_type": "validationfail",
            "source_id": "test-sensor",
            "data": {"bad_value": sentinel},
            "received_at": "2026-06-05T10:00:00Z",
        },
    )

    assert resp.status_code == 422, resp.text
    # The sentinel must NOT appear anywhere in the response body.
    assert sentinel not in resp.text, (
        f"422 response body echoed attacker input: {resp.text!r}"
    )
    # The response must mention source_type for diagnosability.
    assert "validationfail" in resp.text


def test_post_log_batch_validation_error_422_does_not_echo_attacker_input() -> None:
    """NB3 batch — Same attacker-echo check for POST /logs/batch.

    Also verifies the event index (event[0]) is included in the detail,
    but NOT the bad input value.
    """
    sentinel = "BATCH_ATTACKER_SENTINEL_VALUE"
    client, store, _ = _make_validation_fail_client(sentinel)

    resp = client.post(
        "/logs/batch",
        json={
            "events": [
                {
                    "source_type": "validationfail",
                    "source_id": "test-sensor",
                    "data": {"bad_value": sentinel},
                    "received_at": "2026-06-05T10:00:00Z",
                }
            ]
        },
    )

    assert resp.status_code == 422, resp.text
    assert sentinel not in resp.text, (
        f"422 response body echoed attacker input in batch: {resp.text!r}"
    )
    # The event index must be present for diagnosability.
    assert "event[0]" in resp.text
    assert "validationfail" in resp.text
    # Nothing persisted.
    assert store.saved == []
