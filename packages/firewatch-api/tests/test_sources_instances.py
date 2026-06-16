"""Tests for the MB.4 sources instance routes (issue #56).

Routes covered:
  GET  /sources
  POST /sources/suricata/test
  POST /sync/suricata

EARS → test mapping
────────────────────

E1 (event-driven — POST /sync/suricata):
  When POST /sync/suricata is received, the API shall ask the supervisor to run
  one pull cycle for that instance (idempotent).
  → test_sync_suricata_returns_200
  → test_sync_unknown_source_id_returns_404
  → test_sync_unknown_type_key_returns_404

E2 (event-driven — POST /sources/suricata/test):
  When POST /sources/suricata/test is received, the API shall return connectivity
  + file-stat results from the plugin's health_check without ingesting events.
  → test_test_suricata_ok_returns_200
  → test_test_suricata_health_check_false_returns_ok_false
  → test_test_unknown_type_key_returns_404
  → test_test_unknown_source_id_returns_404
  → test_test_does_not_mutate_supervisor_state

E3 (state-driven — GET /sources):
  While an instance is in supervisor backoff or parked, its /sources status shall
  report that state via the InstanceStatus DTO.
  → test_get_sources_reports_parked_state
  → test_get_sources_reports_backoff_state

E4 (unwanted — crash isolation):
  A failing/parked instance's status shall not break the /sources response.
  → test_get_sources_with_parked_instance_still_200
  → test_get_sources_returns_all_instances

E5 (ubiquitous — InstanceRecord not leaked):
  The GET /sources response fields must match the InstanceStatus DTO shape.
  The API must never echo raw InstanceRecord internals (task object, plugin ref, etc.).
  → test_get_sources_response_fields
  → test_get_sources_no_internal_fields_leaked

E6 (validation — path param guard):
  Unknown type_key or source_id must return 404, never 500.
  → test_sync_invalid_type_key_returns_404
  → test_test_invalid_type_key_returns_404

E7 (GET /sources with event count):
  GET /sources returns a per-instance event count from the event store.
  → test_get_sources_includes_event_count

E8 (no supervisor → 503):
  When no supervisor is injected, control routes return 503.
  → test_sync_no_supervisor_returns_503
  → test_test_no_supervisor_returns_503
  → test_get_sources_no_supervisor_returns_503

E9 (dependency rule):
  The sources routes module must not import concrete plugins or legacy/.
  → test_no_concrete_plugin_import_in_sources_routes
"""
from __future__ import annotations

import importlib
import types
from typing import Any

from fastapi.testclient import TestClient
from pydantic import BaseModel

from firewatch_sdk import RawEvent, SecurityEvent, SourceMetadata

from firewatch_api.app import create_app


# --------------------------------------------------------------------------- #
# Fakes                                                                        #
# --------------------------------------------------------------------------- #


class _FakeCfg(BaseModel):
    note: str = "fake"


class _FakePullPlugin:
    """Minimal fake pull plugin; health_check is configurable."""

    def __init__(self, type_key: str = "suricata", health_ok: bool = True) -> None:
        self._type_key = type_key
        self._health_ok = health_ok
        self.health_check_calls: int = 0

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name="Fake Suricata",
            version="0.1.0",
            flavor="pull",
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakeCfg

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _FakeCfg.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        return SecurityEvent(
            source_type=self._type_key,
            source_id=source_id,
            timestamp=raw.received_at,
            source_ip="192.0.2.10",
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        self.health_check_calls += 1
        return self._health_ok


class _FakeConfigStore:
    """Minimal ConfigStore fake — returns empty config for any source."""

    def get_source(self, source_type: str, schema: type[BaseModel]) -> BaseModel:
        return schema.model_validate({})

    def set_source(self, *_: Any, **__: Any) -> None:
        pass

    def get_runtime(self) -> Any:
        from firewatch_sdk import RuntimeConfig
        return RuntimeConfig.model_validate({})

    def set_runtime(self, *_: Any) -> None:
        pass


class _FakeInstanceStatus:
    """Stands in for InstanceStatus — a plain dict projected as status."""

    def __init__(
        self,
        source_type: str = "suricata",
        source_id: str = "pi-home",
        flavor: str = "pull",
        state: str = "running",
        attempt: int = 0,
        total_crashes: int = 0,
        total_dlq: int = 0,
        dropped_count: int = 0,
        last_success_at: float = 0.0,
        # ADR-0031 §F diagnostics fields (issue #139) — optional on the fake.
        last_sync_at: float | None = None,
        last_sync_ingested: int = 0,
        last_sync_status: str | None = None,
        last_error: str | None = None,
    ) -> None:
        self.source_type = source_type
        self.source_id = source_id
        self.flavor = flavor
        self.state = state
        self.attempt = attempt
        self.total_crashes = total_crashes
        self.total_dlq = total_dlq
        self.dropped_count = dropped_count
        self.last_success_at = last_success_at
        self.last_sync_at = last_sync_at
        self.last_sync_ingested = last_sync_ingested
        self.last_sync_status = last_sync_status
        self.last_error = last_error


class _FakeSupervisor:
    """Fake supervisor that stores a configurable list of InstanceStatus objects."""

    def __init__(
        self,
        statuses: list[_FakeInstanceStatus] | None = None,
        run_cycle_raises: bool = False,
    ) -> None:
        self._statuses = statuses or []
        self._run_cycle_raises = run_cycle_raises
        self.run_cycle_calls: list[tuple[str, str]] = []

    def status(self) -> list[_FakeInstanceStatus]:
        return list(self._statuses)

    def get_instance(self, source_type: str, source_id: str) -> Any | None:
        for s in self._statuses:
            if s.source_type == source_type and s.source_id == source_id:
                return s  # just return anything non-None
        return None

    async def run_pull_cycle_for(self, source_type: str, source_id: str) -> None:
        self.run_cycle_calls.append((source_type, source_id))
        if self._run_cycle_raises:
            raise RuntimeError("simulated pull cycle error")


class _FakeEventStore:
    """Minimal event store — returns canned counts via source_health().

    ``count`` is returned for every (source_type, source_id) pair that the
    accompanying supervisor reports.  The route uses ``source_health()`` to
    build the count map (ADR-0032 D / issue #133 fix).
    """

    def __init__(
        self,
        count: int = 0,
        rows: list[dict[str, Any]] | None = None,
    ) -> None:
        self._count = count
        # If explicit rows are provided they override the canned-count behaviour.
        self._rows = rows

    async def source_health(self) -> list[dict[str, Any]]:
        """Return per-source event aggregates used by GET /sources and GET /stats."""
        if self._rows is not None:
            return list(self._rows)
        # Canned mode: the caller only set a scalar count.  We have no way of
        # knowing which (source_type, source_id) pairs exist without a supervisor
        # reference here, so we return a sentinel row that the route will match
        # against whatever instance the test's supervisor exposes.  Tests that
        # need precise (type, id) matching should pass explicit rows instead.
        return [
            {
                "source_type": "suricata",
                "source_id": "pi-home",
                "event_count": self._count,
                "last_event_at": None,
            }
        ]

    async def _conn(self) -> Any:
        return self

    async def get_stats(self) -> dict[str, Any]:
        return {
            "total_logs": self._count,
            "total_ips": 0,
            "blocked_percentage": 0.0,
            "top_attack_types": [],
            "last_updated": None,
            "source_health": [],
        }


# --------------------------------------------------------------------------- #
# Client builder                                                               #
# --------------------------------------------------------------------------- #


def _make_client(
    supervisor: Any | None = None,
    event_store: Any | None = None,
    registry: dict[str, Any] | None = None,
    config_store: Any | None = None,
) -> TestClient:
    """Build a TestClient with fake dependencies."""
    if registry is None:
        registry = {"suricata": _FakePullPlugin("suricata")}
    if config_store is None:
        config_store = _FakeConfigStore()

    app = create_app(
        registry=registry,
        config_store=config_store,
        event_store=event_store,
        pipeline=None,
        supervisor=supervisor,
    )
    return TestClient(app)


def _make_supervisor_with_instance(
    source_type: str = "suricata",
    source_id: str = "pi-home",
    state: str = "running",
) -> _FakeSupervisor:
    return _FakeSupervisor(
        statuses=[
            _FakeInstanceStatus(
                source_type=source_type,
                source_id=source_id,
                state=state,
            )
        ]
    )


# --------------------------------------------------------------------------- #
# E1 — POST /sync/suricata                                                     #
# --------------------------------------------------------------------------- #


def test_sync_suricata_returns_200() -> None:
    """POST /sync/suricata returns 200 and asks the supervisor to run one cycle."""
    sup = _make_supervisor_with_instance("suricata", "pi-home")
    client = _make_client(supervisor=sup)

    resp = client.post("/sync/suricata?source_id=pi-home")

    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert sup.run_cycle_calls == [("suricata", "pi-home")]


def test_sync_unknown_source_id_returns_404() -> None:
    """POST /sync/suricata with an unregistered source_id returns 404."""
    sup = _make_supervisor_with_instance("suricata", "pi-home")
    client = _make_client(supervisor=sup)

    resp = client.post("/sync/suricata?source_id=does-not-exist")

    assert resp.status_code == 404


def test_sync_unknown_type_key_returns_404() -> None:
    """POST /sync/{type_key} for an unknown type_key returns 404."""
    sup = _make_supervisor_with_instance("suricata", "pi-home")
    client = _make_client(supervisor=sup)

    resp = client.post("/sync/unknown_type?source_id=pi-home")

    assert resp.status_code == 404


def test_sync_is_idempotent_concurrent_calls() -> None:
    """POST /sync/suricata called twice enqueues two independent cycles without error.

    Idempotency is watermark-bounded (ADR-0023): a second call re-runs the cycle,
    but the watermark ensures no events are double-ingested.
    """
    sup = _make_supervisor_with_instance("suricata", "pi-home")
    client = _make_client(supervisor=sup)

    resp1 = client.post("/sync/suricata?source_id=pi-home")
    resp2 = client.post("/sync/suricata?source_id=pi-home")

    assert resp1.status_code == 200
    assert resp2.status_code == 200
    # Both calls should have succeeded — two independent cycle requests
    assert len(sup.run_cycle_calls) == 2


# --------------------------------------------------------------------------- #
# E2 — POST /sources/suricata/test                                             #
# --------------------------------------------------------------------------- #


def test_test_suricata_ok_returns_200() -> None:
    """POST /sources/suricata/test with a healthy plugin returns 200 ok=True."""
    plugin = _FakePullPlugin("suricata", health_ok=True)
    sup = _make_supervisor_with_instance("suricata", "pi-home")
    client = _make_client(
        supervisor=sup,
        registry={"suricata": plugin},
    )

    resp = client.post("/sources/suricata/test?source_id=pi-home")

    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert plugin.health_check_calls == 1


def test_test_suricata_health_check_false_returns_ok_false() -> None:
    """POST /sources/suricata/test with a failing plugin returns ok=False, not 500."""
    plugin = _FakePullPlugin("suricata", health_ok=False)
    sup = _make_supervisor_with_instance("suricata", "pi-home")
    client = _make_client(
        supervisor=sup,
        registry={"suricata": plugin},
    )

    resp = client.post("/sources/suricata/test?source_id=pi-home")

    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is False


def test_test_unknown_type_key_returns_404() -> None:
    """POST /sources/{type_key}/test for an unknown type_key returns 404."""
    sup = _make_supervisor_with_instance("suricata", "pi-home")
    client = _make_client(supervisor=sup)

    resp = client.post("/sources/unknown_type/test?source_id=pi-home")

    assert resp.status_code == 404


def test_test_unknown_source_id_returns_404() -> None:
    """POST /sources/suricata/test with an unregistered source_id returns 404."""
    sup = _make_supervisor_with_instance("suricata", "pi-home")
    client = _make_client(supervisor=sup)

    resp = client.post("/sources/suricata/test?source_id=does-not-exist")

    assert resp.status_code == 404


def test_test_does_not_mutate_supervisor_state() -> None:
    """POST /sources/suricata/test must not trigger a pull cycle or change state.

    health_check is a diagnostic probe — it must be side-effect-free
    with respect to the supervisor lifecycle (EARS E2).
    """
    plugin = _FakePullPlugin("suricata", health_ok=True)
    sup = _make_supervisor_with_instance("suricata", "pi-home")
    client = _make_client(
        supervisor=sup,
        registry={"suricata": plugin},
    )

    client.post("/sources/suricata/test?source_id=pi-home")

    # No pull cycle should have been triggered
    assert sup.run_cycle_calls == []


# --------------------------------------------------------------------------- #
# E3 — state-driven: lifecycle state visible in GET /sources                  #
# --------------------------------------------------------------------------- #


def test_get_sources_reports_parked_state() -> None:
    """GET /sources shows state='parked' for a parked instance."""
    sup = _make_supervisor_with_instance("suricata", "pi-home", state="parked")
    client = _make_client(supervisor=sup)

    resp = client.get("/sources")

    assert resp.status_code == 200
    instances = resp.json()
    assert len(instances) == 1
    assert instances[0]["state"] == "parked"


def test_get_sources_reports_backoff_state() -> None:
    """GET /sources shows state='backoff' for a backing-off instance."""
    sup = _make_supervisor_with_instance("suricata", "pi-home", state="backoff")
    client = _make_client(supervisor=sup)

    resp = client.get("/sources")

    assert resp.status_code == 200
    instances = resp.json()
    assert instances[0]["state"] == "backoff"


# --------------------------------------------------------------------------- #
# E4 — unwanted: crash isolation — no instance breaks the response            #
# --------------------------------------------------------------------------- #


def test_get_sources_with_parked_instance_still_200() -> None:
    """A parked instance must not cause GET /sources to return a non-200.

    Crash isolation: ADR-0023 promises one failing instance never breaks others.
    """
    sup = _FakeSupervisor(
        statuses=[
            _FakeInstanceStatus("suricata", "pi-home", state="parked"),
            _FakeInstanceStatus("syslog", "syslog-lan", state="running"),
        ]
    )
    client = _make_client(supervisor=sup)

    resp = client.get("/sources")

    assert resp.status_code == 200
    instances = resp.json()
    assert len(instances) == 2
    states = {i["source_id"]: i["state"] for i in instances}
    assert states["pi-home"] == "parked"
    assert states["syslog-lan"] == "running"


def test_get_sources_returns_all_instances() -> None:
    """GET /sources returns all registered instances regardless of state."""
    sup = _FakeSupervisor(
        statuses=[
            _FakeInstanceStatus("suricata", "pi-home", state="running"),
            _FakeInstanceStatus("suricata", "pi-office", state="stopped"),
            _FakeInstanceStatus("syslog", "syslog-lan", state="backoff"),
        ]
    )
    client = _make_client(supervisor=sup)

    resp = client.get("/sources")

    assert resp.status_code == 200
    instances = resp.json()
    assert len(instances) == 3


# --------------------------------------------------------------------------- #
# E5 — ubiquitous: InstanceStatus DTO fields in response; no internals        #
# --------------------------------------------------------------------------- #


def test_get_sources_response_fields() -> None:
    """GET /sources response items carry the expected InstanceStatus fields."""
    sup = _make_supervisor_with_instance("suricata", "pi-home", state="running")
    client = _make_client(supervisor=sup)

    resp = client.get("/sources")

    assert resp.status_code == 200
    item = resp.json()[0]
    # All InstanceStatus fields must be present
    assert "source_type" in item
    assert "source_id" in item
    assert "flavor" in item
    assert "state" in item
    assert "attempt" in item
    assert "total_crashes" in item
    assert "total_dlq" in item
    assert "dropped_count" in item
    assert "last_success_at" in item
    # event_count is added by the route from the store
    assert "event_count" in item
    # ADR-0031 §F diagnostics fields (issue #139 additive shaping)
    assert "last_sync_at" in item
    assert "last_sync_ingested" in item
    assert "last_sync_status" in item
    assert "last_error" in item


def test_get_sources_no_internal_fields_leaked() -> None:
    """GET /sources must not echo raw InstanceRecord internals.

    task, plugin, cfg, record_failures, crash_timestamps must not appear
    in the response.
    """
    sup = _make_supervisor_with_instance("suricata", "pi-home")
    client = _make_client(supervisor=sup)

    resp = client.get("/sources")
    item = resp.json()[0]

    forbidden = {"task", "plugin", "cfg", "record_failures", "crash_timestamps",
                 "last_known_good_cfg", "_pull_interval", "push_ingest_failures"}
    for field in forbidden:
        assert field not in item, (
            f"Internal field '{field}' must not appear in GET /sources response"
        )


# --------------------------------------------------------------------------- #
# E6 — validation: invalid path params return 404, not 500                    #
# --------------------------------------------------------------------------- #


def test_sync_invalid_type_key_returns_404() -> None:
    """POST /sync/{type_key} with an unknown type_key returns 404, not 500."""
    sup = _make_supervisor_with_instance("suricata", "pi-home")
    client = _make_client(supervisor=sup)

    resp = client.post("/sync/NOT_A_REAL_SOURCE?source_id=pi-home")

    # Must be 404, never 500 (path param validated against known instances)
    assert resp.status_code == 404
    assert resp.status_code != 500


def test_test_invalid_type_key_returns_404() -> None:
    """POST /sources/{type_key}/test with an unknown type_key returns 404, not 500."""
    sup = _make_supervisor_with_instance("suricata", "pi-home")
    client = _make_client(supervisor=sup)

    resp = client.post("/sources/NOT_A_REAL_SOURCE/test?source_id=pi-home")

    assert resp.status_code == 404
    assert resp.status_code != 500


# --------------------------------------------------------------------------- #
# E7 — GET /sources includes per-instance event count                         #
# --------------------------------------------------------------------------- #


def test_get_sources_includes_event_count() -> None:
    """GET /sources returns event_count per instance from the event store."""
    sup = _make_supervisor_with_instance("suricata", "pi-home")
    store = _FakeEventStore(count=42)
    client = _make_client(supervisor=sup, event_store=store)

    resp = client.get("/sources")

    assert resp.status_code == 200
    item = resp.json()[0]
    assert item["event_count"] == 42


def test_get_sources_event_count_zero_when_no_store() -> None:
    """GET /sources returns event_count=0 when no event store is injected."""
    sup = _make_supervisor_with_instance("suricata", "pi-home")
    client = _make_client(supervisor=sup, event_store=None)

    resp = client.get("/sources")

    assert resp.status_code == 200
    item = resp.json()[0]
    assert item["event_count"] == 0


# --------------------------------------------------------------------------- #
# E10 — ADR-0031 §F diagnostics fields in GET /sources (issue #139)           #
# --------------------------------------------------------------------------- #


def test_get_sources_includes_diagnostics_fields() -> None:
    """GET /sources response carries the ADR-0031 §F diagnostics fields (issue #139).

    The four fields — last_sync_at, last_sync_ingested, last_sync_status,
    last_error — must be present in every instance entry.  They are populated
    from InstanceStatus (already tracked by the supervisor; additive read-only
    shaping).
    """
    status = _FakeInstanceStatus(
        source_type="suricata",
        source_id="pi-home",
        state="backoff",
        attempt=3,
        last_sync_at=1749638400.0,
        last_sync_ingested=42,
        last_sync_status="error",
        last_error="Connection refused to 10.0.0.1:22",
    )
    sup = _FakeSupervisor(statuses=[status])
    client = _make_client(supervisor=sup)

    resp = client.get("/sources")

    assert resp.status_code == 200
    item = resp.json()[0]

    # ADR-0031 §F fields must be present and carry the InstanceStatus values.
    assert "last_sync_at" in item
    assert "last_sync_ingested" in item
    assert "last_sync_status" in item
    assert "last_error" in item
    assert item["last_sync_at"] == 1749638400.0
    assert item["last_sync_ingested"] == 42
    assert item["last_sync_status"] == "error"
    assert item["last_error"] == "Connection refused to 10.0.0.1:22"


def test_get_sources_diagnostics_fields_null_before_first_cycle() -> None:
    """GET /sources diagnostics fields are null / 0 before the first cycle.

    An instance that has never completed a cycle should emit None / 0 for
    the ADR-0031 §F fields, not raise a 500.
    """
    status = _FakeInstanceStatus(
        source_type="suricata",
        source_id="pi-home",
        state="idle",
        last_sync_at=None,
        last_sync_ingested=0,
        last_sync_status=None,
        last_error=None,
    )
    sup = _FakeSupervisor(statuses=[status])
    client = _make_client(supervisor=sup)

    resp = client.get("/sources")

    assert resp.status_code == 200
    item = resp.json()[0]
    assert item["last_sync_at"] is None
    assert item["last_sync_ingested"] == 0
    assert item["last_sync_status"] is None
    assert item["last_error"] is None


def test_get_sources_response_fields_includes_diagnostics() -> None:
    """GET /sources response carries all InstanceStatus fields including ADR-0031 §F.

    Extends E5's field-presence assertion to include the four diagnostics fields
    added by issue #139.
    """
    sup = _make_supervisor_with_instance("suricata", "pi-home", state="running")
    client = _make_client(supervisor=sup)

    resp = client.get("/sources")

    assert resp.status_code == 200
    item = resp.json()[0]
    # Core InstanceStatus fields (E5, unchanged)
    for field in (
        "source_type", "source_id", "flavor", "state", "attempt",
        "total_crashes", "total_dlq", "dropped_count", "last_success_at", "event_count",
    ):
        assert field in item, f"Missing field: {field!r}"
    # ADR-0031 §F diagnostics fields (issue #139, additive)
    for field in ("last_sync_at", "last_sync_ingested", "last_sync_status", "last_error"):
        assert field in item, f"Missing diagnostics field: {field!r}"


# --------------------------------------------------------------------------- #
# E8 — no supervisor → 503                                                    #
# --------------------------------------------------------------------------- #


def test_sync_no_supervisor_returns_503() -> None:
    """POST /sync/suricata with no supervisor injected returns 503."""
    client = _make_client(supervisor=None)

    resp = client.post("/sync/suricata?source_id=pi-home")

    assert resp.status_code == 503


def test_test_no_supervisor_returns_503() -> None:
    """POST /sources/suricata/test with no supervisor injected returns 503."""
    client = _make_client(supervisor=None)

    resp = client.post("/sources/suricata/test?source_id=pi-home")

    assert resp.status_code == 503


def test_get_sources_no_supervisor_returns_503() -> None:
    """GET /sources with no supervisor injected returns 503."""
    client = _make_client(supervisor=None)

    resp = client.get("/sources")

    assert resp.status_code == 503


def test_get_sources_no_supervisor_carries_retry_after() -> None:
    """GET /sources returns Retry-After: 5 header when supervisor is absent (issue #315).

    RFC 9110 §10.2.3: the Retry-After header signals the UI how long to wait
    before retrying.  5 s matches the UI BACKOFF_BASE_MS in useSupervisorGate.
    """
    client = _make_client(supervisor=None)

    resp = client.get("/sources")

    assert resp.status_code == 503
    assert resp.headers.get("retry-after") == "5"


# --------------------------------------------------------------------------- #
# E9 — dependency rule: no concrete plugin import in sources routes           #
# --------------------------------------------------------------------------- #


def test_no_concrete_plugin_import_in_sources_routes() -> None:
    """routes/sources.py must not import concrete plugins or legacy/."""
    mod = importlib.import_module("firewatch_api.routes.sources")
    forbidden = ("firewatch_suricata", "firewatch_syslog", "legacy")
    for name, obj in vars(mod).items():
        if isinstance(obj, types.ModuleType):
            for prefix in forbidden:
                assert not obj.__name__.startswith(prefix), (
                    f"routes.sources imports forbidden module {obj.__name__!r} "
                    f"via attribute {name!r}"
                )


# --------------------------------------------------------------------------- #
# NB — config_store None → 503 on POST /sources/{type_key}/test               #
# --------------------------------------------------------------------------- #


def test_test_no_config_store_returns_503() -> None:
    """POST /sources/{type_key}/test returns 503 when config_store is None in app.state.

    Security finding NB: when app.state.config_store is None (e.g. partial
    construction or a test environment where the store was not wired),
    the route must surface a 503 (service unavailable) rather than an
    AttributeError 500.  This aligns the route with the same guard pattern
    used for get_event_store and get_pipeline.

    Note: create_app substitutes JsonFileConfigStore() when config_store=None,
    so we override app.state.config_store to None after creation to reproduce
    the "config_store absent" condition.
    """
    app = create_app(
        registry={"suricata": _FakePullPlugin("suricata")},
        config_store=_FakeConfigStore(),  # let create_app accept it normally
        event_store=None,
        pipeline=None,
        supervisor=_make_supervisor_with_instance("suricata", "pi-home"),
    )
    # Simulate the "config_store unavailable" condition by nulling the state attribute
    # (mirrors the pattern tested for event_store / pipeline absent scenarios).
    app.state.config_store = None
    from fastapi.testclient import TestClient
    client = TestClient(app)

    resp = client.post("/sources/suricata/test?source_id=pi-home")

    assert resp.status_code == 503
    assert resp.status_code != 500
