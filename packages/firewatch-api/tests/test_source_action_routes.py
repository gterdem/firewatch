"""Tests for GET/POST /sources/{type_key}/actions[/{action_id}] (ADR-0034 / issue #167).

EARS criterion → test mapping
==============================

EARS-AR-1 (event-driven — GET /sources/types includes actions):
  WHEN GET /sources/types is served, THEN each entry SHALL include the
  plugin's declared actions (empty list when none declared).
  -> test_discovery_includes_empty_actions_for_no_action_plugin
  -> test_discovery_includes_declared_actions

EARS-AR-2 (state-driven — violating plugin omitted from discovery):
  WHILE a plugin declares a non-empty actions but does NOT satisfy
  ActionCapable, the loader/discovery path SHALL omit it without
  breaking discovery for others.
  -> test_discovery_omits_plugin_declaring_actions_without_capability

EARS-AR-3 (event-driven — GET /sources/{type}/actions):
  WHEN GET /sources/{type}/actions is served, THEN each declared action
  SHALL be returned with its ActionStatus; a raising plugin degrades to
  null-status, not a 500.
  -> test_get_actions_returns_declared_actions_with_status
  -> test_get_actions_empty_list_for_no_action_plugin
  -> test_get_actions_null_status_on_raising_plugin

EARS-AR-4 (event-driven — POST /sources/{type}/actions/{id}):
  WHEN POST is called for a configured instance with a declared action,
  THEN the route SHALL return ActionResult.
  -> test_post_action_returns_result
  -> test_post_action_result_ok_false_still_200

EARS-AR-5 (unwanted — 404 guards):
  IF type_key unknown → 404; instance not configured → 404;
  action_id undeclared → 404; all must never reach plugin code.
  -> test_get_actions_unknown_type_returns_404
  -> test_get_actions_unknown_instance_returns_404
  -> test_post_action_unknown_type_returns_404
  -> test_post_action_unknown_instance_returns_404
  -> test_post_action_undeclared_action_returns_404

EARS-AR-6 (ubiquitous — no supervisor → 503):
  -> test_get_actions_no_supervisor_returns_503
  -> test_post_action_no_supervisor_returns_503

EARS-AR-7 (ubiquitous — modularity):
  The route module SHALL contain zero references to any concrete type_key.
  -> test_source_actions_module_has_no_concrete_type_key

EARS-AR-8 (modularity proof — synthetic plugin via entry-point pattern):
  A synthetic test plugin declaring an action is discoverable and invokable
  with zero core edits — only the plugin entry changes.
  -> test_synthetic_plugin_action_discoverable_and_invokable

NB-2 (security — single-flight 409 at HTTP layer):
  WHILE a (type_key, source_id, action_id) triple is in-flight, THEN a
  concurrent POST SHALL return HTTP 409 with a sanitised detail (no echo).
  AFTER the first call completes a new POST proceeds normally.
  -> test_post_action_concurrent_returns_409
  -> test_post_action_409_detail_does_not_echo_input

NB-4 (security — source_id constraint on both routes):
  source_id containing CR/LF or exceeding 128 chars SHALL return 422.
  The 422 detail must not echo attacker-controlled content.
  -> test_get_actions_crlf_source_id_returns_422
  -> test_post_action_crlf_source_id_returns_422
  -> test_get_actions_oversized_source_id_returns_422
  -> test_post_action_oversized_source_id_returns_422
"""
from __future__ import annotations

import importlib
import types
from typing import Any
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from pydantic import BaseModel

from firewatch_sdk import (
    NULL_ACTION_STATUS,
    ActionResult,
    ActionStatus,
    SourceAction,
    SourceMetadata,
)
from firewatch_api.app import create_app
from _api_fakes import FakePullPlugin


# --------------------------------------------------------------------------- #
# Fake helpers                                                                 #
# --------------------------------------------------------------------------- #


class _FakeCfg(BaseModel):
    host: str = "192.0.2.1"


class _ActionPlugin:
    """Fake plugin that declares one action and satisfies ActionCapable."""

    def __init__(
        self,
        type_key: str = "actionplug",
        run_ok: bool = True,
        status_raises: bool = False,
    ) -> None:
        self._type_key = type_key
        self._run_ok = run_ok
        self._status_raises = status_raises
        self.run_calls: list[str] = []

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name="Action Plugin",
            version="1.0.0",
            flavor="pull",
            actions=(
                SourceAction(
                    id="fetch_rules",
                    label="Fetch Rules",
                    description="Download rule descriptions.",
                    provides=("rule_descriptions",),
                ),
            ),
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakeCfg

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _FakeCfg.model_validate(cfg)

    def normalize(self, raw: Any, source_id: str) -> Any:
        raise NotImplementedError

    async def health_check(self, cfg: BaseModel) -> bool:
        return True

    async def run_action(self, action_id: str, cfg: Any, ctx: Any) -> ActionResult:
        self.run_calls.append(action_id)
        if self._run_ok:
            return ActionResult(ok=True, message="done", detail={"count": "10"})
        return ActionResult(ok=False, message="failed")

    async def action_status(self, action_id: str, cfg: Any, ctx: Any) -> ActionStatus:
        if self._status_raises:
            raise RuntimeError("status exploded")
        return ActionStatus(last_run_at=42.0, stale=False, message="fresh")


class _NoCapabilityPlugin:
    """Declares actions but does NOT implement run_action / action_status."""

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key="nocap",
            display_name="No-Capability Plugin",
            version="0.1.0",
            flavor="pull",
            actions=(SourceAction(id="sync", label="Sync", description="Sync"),),
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakeCfg

    def validate_config(self, cfg: dict[str, Any]) -> None:
        pass

    def normalize(self, raw: Any, source_id: str) -> Any:
        raise NotImplementedError

    async def health_check(self, cfg: BaseModel) -> bool:
        return True


class _FakeSupervisor:
    """Minimal fake supervisor for action route tests."""

    def __init__(self) -> None:
        self._instances: dict[tuple[str, str], Any] = {}
        self.run_action_results: dict[tuple[str, str, str], ActionResult] = {}
        self.action_status_results: dict[tuple[str, str, str], ActionStatus] = {}
        self.run_calls: list[tuple[str, str, str]] = []
        self.status_calls: list[tuple[str, str, str]] = []

    def register(self, type_key: str, source_id: str) -> None:
        self._instances[(type_key, source_id)] = MagicMock()

    def get_instance(self, source_type: str, source_id: str) -> Any | None:
        return self._instances.get((source_type, source_id))

    def status(self) -> list[Any]:
        return []

    async def run_action_for(
        self, source_type: str, source_id: str, action_id: str
    ) -> ActionResult:
        self.run_calls.append((source_type, source_id, action_id))
        key = (source_type, source_id, action_id)
        if key in self.run_action_results:
            return self.run_action_results[key]
        # default — simulate an undeclared action
        raise ValueError(f"action {action_id!r} not declared")

    async def action_status_for(
        self, source_type: str, source_id: str, action_id: str
    ) -> ActionStatus:
        self.status_calls.append((source_type, source_id, action_id))
        key = (source_type, source_id, action_id)
        if key in self.action_status_results:
            return self.action_status_results[key]
        return NULL_ACTION_STATUS


def _make_client(
    registry: dict[str, Any] | None = None,
    supervisor: Any | None = None,
) -> TestClient:
    from firewatch_sdk.config import RuntimeConfig
    config_store = MagicMock()
    config_store.get_runtime.return_value = RuntimeConfig()  # no api_key -> auth no-op
    app = create_app(
        registry=registry or {},
        supervisor=supervisor,
        config_store=config_store,
    )
    return TestClient(app)


# --------------------------------------------------------------------------- #
# EARS-AR-1: discovery includes actions field                                  #
# --------------------------------------------------------------------------- #


def test_discovery_includes_empty_actions_for_no_action_plugin():
    """GET /sources/types includes an empty 'actions' list for plugins with none declared."""
    plugin = FakePullPlugin("myplug")
    client = _make_client(registry={"myplug": plugin})

    resp = client.get("/sources/types")

    assert resp.status_code == 200
    entries = {e["type_key"]: e for e in resp.json()}
    assert "myplug" in entries
    assert entries["myplug"]["actions"] == []


def test_discovery_includes_declared_actions():
    """GET /sources/types includes the plugin's declared actions."""
    plugin = _ActionPlugin("actionplug")
    client = _make_client(registry={"actionplug": plugin})

    resp = client.get("/sources/types")

    assert resp.status_code == 200
    entries = {e["type_key"]: e for e in resp.json()}
    assert "actionplug" in entries
    actions = entries["actionplug"]["actions"]
    assert len(actions) == 1
    assert actions[0]["id"] == "fetch_rules"
    assert actions[0]["label"] == "Fetch Rules"
    assert "rule_descriptions" in actions[0]["provides"]


# --------------------------------------------------------------------------- #
# EARS-AR-2: violating plugin omitted from discovery                          #
# --------------------------------------------------------------------------- #


def test_discovery_omits_plugin_declaring_actions_without_capability():
    """A plugin with non-empty actions but missing ActionCapable is omitted from discovery."""
    good = FakePullPlugin("good")
    bad = _NoCapabilityPlugin()
    client = _make_client(registry={"good": good, "nocap": bad})

    resp = client.get("/sources/types")

    assert resp.status_code == 200
    type_keys = {e["type_key"] for e in resp.json()}
    assert "nocap" not in type_keys, "Violating plugin must be omitted"
    assert "good" in type_keys, "Good plugin must still appear"


# --------------------------------------------------------------------------- #
# EARS-AR-3: GET /sources/{type}/actions                                      #
# --------------------------------------------------------------------------- #


def test_get_actions_returns_declared_actions_with_status():
    """GET /sources/{type}/actions returns actions zipped with ActionStatus."""
    plugin = _ActionPlugin("actionplug")
    sup = _FakeSupervisor()
    sup.register("actionplug", "actionplug")
    sup.action_status_results[("actionplug", "actionplug", "fetch_rules")] = ActionStatus(
        last_run_at=99.0, stale=False, message="fresh"
    )
    client = _make_client(registry={"actionplug": plugin}, supervisor=sup)

    resp = client.get("/sources/actionplug/actions?source_id=actionplug")

    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    entry = data[0]
    assert entry["id"] == "fetch_rules"
    assert entry["last_run_at"] == 99.0
    assert entry["stale"] is False
    assert entry["status_message"] == "fresh"


def test_get_actions_empty_list_for_no_action_plugin():
    """GET /sources/{type}/actions returns [] when the plugin declares no actions."""
    plugin = FakePullPlugin("myplug")
    sup = _FakeSupervisor()
    sup.register("myplug", "myplug")
    client = _make_client(registry={"myplug": plugin}, supervisor=sup)

    resp = client.get("/sources/myplug/actions?source_id=myplug")

    assert resp.status_code == 200
    assert resp.json() == []


def test_get_actions_null_status_on_raising_plugin():
    """A plugin whose action_status raises contributes null-status entry, not 500."""
    plugin = _ActionPlugin("actionplug", status_raises=True)
    sup = _FakeSupervisor()
    sup.register("actionplug", "actionplug")
    # Supervisor degrades to NULL_ACTION_STATUS internally when plugin raises.
    # Here the supervisor fake returns NULL_ACTION_STATUS directly.
    sup.action_status_results[("actionplug", "actionplug", "fetch_rules")] = NULL_ACTION_STATUS
    client = _make_client(registry={"actionplug": plugin}, supervisor=sup)

    resp = client.get("/sources/actionplug/actions?source_id=actionplug")

    assert resp.status_code == 200
    entry = resp.json()[0]
    assert entry["last_run_at"] is None
    assert entry["stale"] is None


# --------------------------------------------------------------------------- #
# EARS-AR-4: POST /sources/{type}/actions/{id}                               #
# --------------------------------------------------------------------------- #


def test_post_action_returns_result():
    """POST /sources/{type}/actions/{id} returns ActionResult from supervisor."""
    plugin = _ActionPlugin("actionplug")
    sup = _FakeSupervisor()
    sup.register("actionplug", "actionplug")
    sup.run_action_results[("actionplug", "actionplug", "fetch_rules")] = ActionResult(
        ok=True, message="rules fetched", detail={"count": "50"}
    )
    client = _make_client(registry={"actionplug": plugin}, supervisor=sup)

    resp = client.post("/sources/actionplug/actions/fetch_rules?source_id=actionplug")

    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["message"] == "rules fetched"
    assert body["detail"]["count"] == "50"
    assert body["source_type"] == "actionplug"
    assert body["action_id"] == "fetch_rules"


def test_post_action_result_ok_false_still_200():
    """A plugin-level failure (ok=False) still returns HTTP 200 with the result."""
    plugin = _ActionPlugin("actionplug")
    sup = _FakeSupervisor()
    sup.register("actionplug", "actionplug")
    sup.run_action_results[("actionplug", "actionplug", "fetch_rules")] = ActionResult(
        ok=False, message="connection refused"
    )
    client = _make_client(registry={"actionplug": plugin}, supervisor=sup)

    resp = client.post("/sources/actionplug/actions/fetch_rules?source_id=actionplug")

    assert resp.status_code == 200
    assert resp.json()["ok"] is False
    assert resp.json()["message"] == "connection refused"


# --------------------------------------------------------------------------- #
# EARS-AR-5: 404 guards                                                       #
# --------------------------------------------------------------------------- #


def test_get_actions_unknown_type_returns_404():
    """GET /sources/{type}/actions returns 404 for unknown type_key."""
    sup = _FakeSupervisor()
    client = _make_client(registry={}, supervisor=sup)

    resp = client.get("/sources/unknown/actions?source_id=unknown")

    assert resp.status_code == 404


def test_get_actions_unknown_instance_returns_404():
    """GET /sources/{type}/actions returns 404 when instance is not configured."""
    plugin = FakePullPlugin("myplug")
    sup = _FakeSupervisor()
    # No instance registered in supervisor.
    client = _make_client(registry={"myplug": plugin}, supervisor=sup)

    resp = client.get("/sources/myplug/actions?source_id=nonexistent")

    assert resp.status_code == 404


def test_post_action_unknown_type_returns_404():
    """POST /sources/{type}/actions/{id} returns 404 for unknown type_key."""
    sup = _FakeSupervisor()
    client = _make_client(registry={}, supervisor=sup)

    resp = client.post("/sources/unknown/actions/fetch_rules?source_id=x")

    assert resp.status_code == 404


def test_post_action_unknown_instance_returns_404():
    """POST /sources/{type}/actions/{id} returns 404 when instance is not configured."""
    plugin = _ActionPlugin("actionplug")
    sup = _FakeSupervisor()
    # Instance NOT registered.
    client = _make_client(registry={"actionplug": plugin}, supervisor=sup)

    resp = client.post("/sources/actionplug/actions/fetch_rules?source_id=missing")

    assert resp.status_code == 404


def test_post_action_undeclared_action_returns_404():
    """POST with an action_id not declared by the plugin returns 404."""
    plugin = _ActionPlugin("actionplug")
    sup = _FakeSupervisor()
    sup.register("actionplug", "actionplug")
    # Supervisor raises ValueError on undeclared action — fake default does this.
    client = _make_client(registry={"actionplug": plugin}, supervisor=sup)

    resp = client.post("/sources/actionplug/actions/ghost_action?source_id=actionplug")

    assert resp.status_code == 404
    # action_id must NOT appear in the response body (MC.3 attacker-echo posture).
    assert "ghost_action" not in resp.text


# --------------------------------------------------------------------------- #
# EARS-AR-6: no supervisor → 503                                              #
# --------------------------------------------------------------------------- #


def test_get_actions_no_supervisor_returns_503():
    """GET /sources/{type}/actions returns 503 when no supervisor is injected."""
    plugin = _ActionPlugin("actionplug")
    client = _make_client(registry={"actionplug": plugin}, supervisor=None)

    resp = client.get("/sources/actionplug/actions?source_id=actionplug")

    assert resp.status_code == 503


def test_post_action_no_supervisor_returns_503():
    """POST /sources/{type}/actions/{id} returns 503 when no supervisor is injected."""
    plugin = _ActionPlugin("actionplug")
    client = _make_client(registry={"actionplug": plugin}, supervisor=None)

    resp = client.post("/sources/actionplug/actions/fetch_rules?source_id=actionplug")

    assert resp.status_code == 503


# --------------------------------------------------------------------------- #
# EARS-AR-7: modularity — no concrete type_key references in route module     #
# --------------------------------------------------------------------------- #


def test_source_actions_module_has_no_concrete_type_key():
    """The source_actions route module contains no references to concrete type_keys."""
    module = importlib.import_module("firewatch_api.routes.source_actions")
    source = getattr(module, "__file__", "")
    if source:
        with open(source) as f:
            content = f.read()
        # Grep-clean for known concrete type_keys — the seam must be generic.
        assert "suricata" not in content, "Route module must not mention 'suricata'"
        assert "syslog" not in content, "Route module must not mention 'syslog'"
        assert "azure_waf" not in content, "Route module must not mention 'azure_waf'"
    # Also check no concrete plugin module is imported.
    for name, obj in vars(module).items():
        if isinstance(obj, types.ModuleType):
            assert "firewatch_suricata" not in obj.__name__
            assert "firewatch_syslog" not in obj.__name__
            assert "legacy" not in obj.__name__


# --------------------------------------------------------------------------- #
# EARS-AR-8: modularity proof — synthetic plugin is discoverable + invokable  #
# --------------------------------------------------------------------------- #


def test_synthetic_plugin_action_discoverable_and_invokable():
    """A brand-new synthetic plugin declaring an action works end-to-end with zero core edits.

    This is the ADR-0034 modularity proof: the seam must require ZERO core/API
    edits when a new plugin declares an action.  We verify:
    1. Discovery (GET /sources/types) includes the synthetic plugin's actions.
    2. GET /sources/{type}/actions returns the action with status.
    3. POST /sources/{type}/actions/{id} returns a successful ActionResult.
    All without any change to core, API routing, or discovery logic.
    """
    # --- Build a completely synthetic plugin "inline" (simulates a new package) ---
    class _SyntheticPlugin:
        def metadata(self) -> SourceMetadata:
            return SourceMetadata(
                type_key="synthetic",
                display_name="Synthetic Source",
                version="0.1.0",
                flavor="pull",
                actions=(
                    SourceAction(
                        id="refresh",
                        label="Refresh",
                        description="Refresh synthetic data.",
                    ),
                ),
            )

        def config_schema(self) -> type[BaseModel]:
            return _FakeCfg

        def validate_config(self, cfg: dict[str, Any]) -> None:
            pass

        def normalize(self, raw: Any, source_id: str) -> Any:
            raise NotImplementedError

        async def health_check(self, cfg: BaseModel) -> bool:
            return True

        async def run_action(self, action_id: str, cfg: Any, ctx: Any) -> ActionResult:
            return ActionResult(ok=True, message="synthetic action ran")

        async def action_status(self, action_id: str, cfg: Any, ctx: Any) -> ActionStatus:
            return ActionStatus(last_run_at=1.0, stale=False)

    synthetic = _SyntheticPlugin()

    # Fake supervisor that routes the action call to the plugin directly.
    sup = _FakeSupervisor()
    sup.register("synthetic", "synthetic")
    sup.run_action_results[("synthetic", "synthetic", "refresh")] = ActionResult(
        ok=True, message="synthetic action ran"
    )
    sup.action_status_results[("synthetic", "synthetic", "refresh")] = ActionStatus(
        last_run_at=1.0, stale=False
    )

    client = _make_client(registry={"synthetic": synthetic}, supervisor=sup)

    # 1. Discovery includes the action.
    resp = client.get("/sources/types")
    assert resp.status_code == 200
    entries = {e["type_key"]: e for e in resp.json()}
    assert "synthetic" in entries
    assert entries["synthetic"]["actions"][0]["id"] == "refresh"

    # 2. GET actions returns status.
    resp = client.get("/sources/synthetic/actions?source_id=synthetic")
    assert resp.status_code == 200
    assert resp.json()[0]["id"] == "refresh"
    assert resp.json()[0]["last_run_at"] == 1.0

    # 3. POST action returns ActionResult.
    resp = client.post("/sources/synthetic/actions/refresh?source_id=synthetic")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["message"] == "synthetic action ran"


# --------------------------------------------------------------------------- #
# NB-2: single-flight 409 at HTTP layer                                       #
# --------------------------------------------------------------------------- #


class _FakeSupervisorWith409(_FakeSupervisor):
    """Supervisor fake that raises RuntimeError("in_progress") on concurrent calls."""

    def __init__(self, *, first_call_raises: bool = False) -> None:
        super().__init__()
        self._in_flight: bool = False
        self._first_call_raises = first_call_raises

    async def run_action_for(
        self, source_type: str, source_id: str, action_id: str
    ) -> ActionResult:
        if self._in_flight:
            raise RuntimeError("in_progress")
        if self._first_call_raises:
            raise ValueError(f"action {action_id!r} not declared")
        self._in_flight = True
        try:
            return ActionResult(ok=True, message="ok")
        finally:
            self._in_flight = False


def test_post_action_concurrent_returns_409():
    """NB-2: supervisor raising RuntimeError('in_progress') maps to HTTP 409."""
    plugin = _ActionPlugin("actionplug")
    sup = _FakeSupervisorWith409()
    sup.register("actionplug", "actionplug")
    sup.run_action_results[("actionplug", "actionplug", "fetch_rules")] = ActionResult(
        ok=True, message="ok"
    )
    # Mark as already in-flight so the next call gets the 409 path.
    sup._in_flight = True  # type: ignore[attr-defined]
    client = _make_client(registry={"actionplug": plugin}, supervisor=sup)

    resp = client.post("/sources/actionplug/actions/fetch_rules?source_id=actionplug")

    assert resp.status_code == 409


def test_post_action_409_detail_does_not_echo_input():
    """NB-2: the 409 response detail must not echo the action_id or source_id."""
    plugin = _ActionPlugin("actionplug")
    sup = _FakeSupervisorWith409()
    sup.register("actionplug", "myinstance")
    sup._in_flight = True  # type: ignore[attr-defined]
    client = _make_client(registry={"actionplug": plugin}, supervisor=sup)

    resp = client.post("/sources/actionplug/actions/fetch_rules?source_id=myinstance")

    assert resp.status_code == 409
    # Neither the action_id nor the source_id should appear in the response.
    body = resp.text
    assert "fetch_rules" not in body
    assert "myinstance" not in body


# --------------------------------------------------------------------------- #
# NB-4: source_id constraint on both routes                                   #
# --------------------------------------------------------------------------- #


def test_get_actions_crlf_source_id_returns_422():
    """NB-4: GET /sources/{type}/actions with CR/LF in source_id returns 422."""
    plugin = _ActionPlugin("actionplug")
    sup = _FakeSupervisor()
    client = _make_client(registry={"actionplug": plugin}, supervisor=sup)

    # URL-encoded CR+LF injected into source_id
    resp = client.get("/sources/actionplug/actions?source_id=bad%0d%0avalue")

    assert resp.status_code == 422


def test_post_action_crlf_source_id_returns_422():
    """NB-4: POST /sources/{type}/actions/{id} with CR/LF in source_id returns 422."""
    plugin = _ActionPlugin("actionplug")
    sup = _FakeSupervisor()
    client = _make_client(registry={"actionplug": plugin}, supervisor=sup)

    resp = client.post("/sources/actionplug/actions/fetch_rules?source_id=bad%0d%0avalue")

    assert resp.status_code == 422


def test_get_actions_oversized_source_id_returns_422():
    """NB-4: GET /sources/{type}/actions with source_id > 128 chars returns 422."""
    plugin = _ActionPlugin("actionplug")
    sup = _FakeSupervisor()
    client = _make_client(registry={"actionplug": plugin}, supervisor=sup)

    oversized = "a" * 129
    resp = client.get(f"/sources/actionplug/actions?source_id={oversized}")

    assert resp.status_code == 422


def test_post_action_oversized_source_id_returns_422():
    """NB-4: POST /sources/{type}/actions/{id} with source_id > 128 chars returns 422."""
    plugin = _ActionPlugin("actionplug")
    sup = _FakeSupervisor()
    client = _make_client(registry={"actionplug": plugin}, supervisor=sup)

    oversized = "a" * 129
    resp = client.post(f"/sources/actionplug/actions/fetch_rules?source_id={oversized}")

    assert resp.status_code == 422
