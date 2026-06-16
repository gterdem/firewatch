"""Tests for the auto-sync routes: PUT/GET /sources/{type_key}/auto-sync (issue #137).

Routes covered:
  PUT  /sources/{type_key}/auto-sync — enable/disable/update auto-sync
  GET  /sources/{type_key}/auto-sync — read current auto-sync state

EARS -> test mapping
====================

EARS-AS-1 (event-driven — enable):
  WHEN PUT /sources/{type}/auto-sync {enabled:true, interval:N} is called for a
  pull source, the system SHALL write/update the _instances entry AND
  register+launch a running pull instance.
  -> test_put_autosync_enable_persists_and_launches
  -> test_put_autosync_enable_returns_correct_payload

EARS-AS-2 (event-driven — disable):
  WHEN auto-sync is set to enabled:false, the system SHALL remove the _instances
  entry AND stop+idle the instance, WHILE leaving the source config intact.
  -> test_put_autosync_disable_removes_instance_entry
  -> test_put_autosync_disable_stops_supervisor_instance
  -> test_put_autosync_disable_leaves_source_config_intact

EARS-AS-3 (event-driven — interval-only change):
  WHEN only interval_seconds changes on an enabled source, the system SHALL update
  the persisted interval AND apply it live via set_interval.
  -> test_put_autosync_interval_change_upserts_and_calls_set_interval
  -> test_put_autosync_enable_on_idle_instance_calls_enable_pull

EARS-AS-4 (state-driven — idle on configured):
  WHILE a pull source is configured (config section present), a supervisor record
  SHALL exist in idle so POST /sync/{type} runs regardless of auto-sync state.
  -> test_put_autosync_enable_registers_idle_when_absent
  -> test_put_autosync_enable_skips_register_idle_when_already_registered

EARS-AS-5 (persistence):
  WHEN the process restarts, a previously-enabled source SHALL resume auto-sync
  from its persisted _instances entry.
  -> test_put_autosync_enable_persisted_entry_readable_after_write

EARS-AS-6 (validation — interval bounds):
  IF interval_seconds is outside [30, 86400], the system SHALL reject with 422
  and SHALL NOT persist or mutate the supervisor.
  -> test_put_autosync_interval_too_low_returns_422
  -> test_put_autosync_interval_too_high_returns_422
  -> test_put_autosync_422_does_not_persist
  -> test_put_autosync_422_does_not_call_supervisor

EARS-AS-7 (unwanted — push flavor):
  IF the source flavor is push, PUT .../auto-sync SHALL return 409.
  -> test_put_autosync_push_source_returns_409

EARS-AS-8 (unwanted — unknown type):
  IF type_key is not in the registry, PUT/GET SHALL return 404.
  -> test_put_autosync_unknown_type_returns_404
  -> test_get_autosync_unknown_type_returns_404

EARS-AS-9 (GET):
  GET /sources/{type}/auto-sync returns enabled, interval_seconds, source_id,
  last_sync from supervisor.status().
  -> test_get_autosync_enabled_returns_state
  -> test_get_autosync_disabled_returns_state
  -> test_get_autosync_includes_last_sync_fields

EARS-AS-10 (no config store path -> 503):
  When config store has no config_path (fake without path), route returns 503.
  -> test_put_autosync_no_config_path_returns_503

EARS-AS-11 (no supervisor -> 503):
  When no supervisor is injected, PUT/GET returns 503.
  -> test_put_autosync_no_supervisor_returns_503
  -> test_get_autosync_no_supervisor_returns_503

EARS-AS-12 (disable doesn't require interval_seconds, issue #155 NB-1):
  IF auto-sync is disabled without interval_seconds (or with an invalid one),
  the system SHALL still succeed (200).  Interval is only validated on enable.
  -> test_put_autosync_disable_without_interval_succeeds
  -> test_put_autosync_disable_with_out_of_bounds_interval_still_succeeds
  -> test_put_autosync_enable_still_requires_valid_interval

EARS-AS-13 (NB-A — strict bool for 'enabled', issue #166):
  IF the 'enabled' field is not a JSON boolean (string, integer, null), the system
  SHALL reject with 422 and SHALL NOT echo the raw value (MC.3).
  -> test_put_autosync_enabled_string_false_returns_422
  -> test_put_autosync_enabled_string_true_returns_422
  -> test_put_autosync_enabled_integer_returns_422
  -> test_put_autosync_enabled_null_returns_422
  -> test_put_autosync_enabled_true_bool_still_works
  -> test_put_autosync_enabled_false_bool_still_works

EARS-AS-14 (NB-B — disable response interval consistency, issue #166):
  WHEN auto-sync is disabled, the PUT response SHALL return the persisted/default
  interval_seconds (not 0), matching what GET .../auto-sync would return.
  -> test_put_autosync_disable_response_interval_is_not_zero
  -> test_put_autosync_disable_response_interval_matches_persisted
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from pydantic import BaseModel

from firewatch_sdk import SourceMetadata

from firewatch_api.app import create_app
from firewatch_core.config_store import JsonFileConfigStore
from firewatch_core.instance_loader import load_instances


# --------------------------------------------------------------------------- #
# Fake helpers                                                                  #
# --------------------------------------------------------------------------- #


class _FakeCfg(BaseModel):
    host: str = "192.0.2.1"


class _FakePullPlugin:
    """Minimal fake pull plugin for auto-sync route tests."""

    def __init__(self, type_key: str = "fake_pull") -> None:
        self._type_key = type_key

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name="Fake Pull",
            version="0.1.0",
            flavor="pull",
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakeCfg

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _FakeCfg.model_validate(cfg)

    async def health_check(self, cfg: BaseModel) -> bool:
        return True


class _FakePushPlugin:
    """Minimal fake push plugin for auto-sync route tests."""

    def __init__(self, type_key: str = "fake_push") -> None:
        self._type_key = type_key

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name="Fake Push",
            version="0.1.0",
            flavor="push",
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakeCfg

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _FakeCfg.model_validate(cfg)

    async def health_check(self, cfg: BaseModel) -> bool:
        return True


class _FakeConfigStoreNoPath:
    """Config store fake that has no config_path — simulates the 503 case."""

    def get_source(self, source_type: str, schema: type[BaseModel]) -> BaseModel:
        return schema.model_validate({})

    def get_runtime(self) -> Any:
        from firewatch_sdk import RuntimeConfig
        return RuntimeConfig.model_validate({})

    def set_source(self, *_: Any, **__: Any) -> None:
        pass

    def set_runtime(self, *_: Any) -> None:
        pass


class _FakeSupervisor:
    """Fake supervisor tracking calls made by the routes."""

    def __init__(
        self,
        instances: dict[tuple[str, str], Any] | None = None,
        statuses: list[Any] | None = None,
    ) -> None:
        self._instances: dict[tuple[str, str], Any] = instances or {}
        self._statuses: list[Any] = statuses or []
        self.register_idle_calls: list[dict[str, Any]] = []
        self.enable_pull_calls: list[tuple[str, str, float]] = []
        self.disable_calls: list[tuple[str, str]] = []
        self.set_interval_calls: list[tuple[str, str, float]] = []

    def get_instance(self, source_type: str, source_id: str) -> Any | None:
        return self._instances.get((source_type, source_id))

    def register_idle(
        self,
        plugin: Any,
        cfg: Any,
        *,
        source_id: str,
        flavor: str,
        interval: float = 60.0,
        transport: str = "tcp",
    ) -> Any:
        type_key = plugin.metadata().type_key
        self.register_idle_calls.append(
            {"type_key": type_key, "source_id": source_id, "interval": interval}
        )
        rec = MagicMock()
        self._instances[(type_key, source_id)] = rec
        return rec

    def enable_pull(self, source_type: str, source_id: str, *, interval: float) -> None:
        self.enable_pull_calls.append((source_type, source_id, interval))

    async def disable(self, source_type: str, source_id: str) -> None:
        self.disable_calls.append((source_type, source_id))
        self._instances.pop((source_type, source_id), None)

    def set_interval(self, source_type: str, source_id: str, interval: float) -> None:
        self.set_interval_calls.append((source_type, source_id, interval))

    def status(self) -> list[Any]:
        return list(self._statuses)


# --------------------------------------------------------------------------- #
# App factory helper                                                            #
# --------------------------------------------------------------------------- #


def _make_app(
    *,
    tmp_path: Path,
    supervisor: _FakeSupervisor | None = None,
    pull_type_key: str = "fake_pull",
    push_type_key: str = "fake_push",
    initial_config: dict[str, Any] | None = None,
) -> tuple[TestClient, Path, _FakeSupervisor]:
    """Build a TestClient with a real JsonFileConfigStore backed by tmp_path."""
    cfg_path = tmp_path / "firewatch_config.json"
    cfg_content = initial_config if initial_config is not None else {}
    cfg_path.write_text(json.dumps(cfg_content), encoding="utf-8")

    store = JsonFileConfigStore(cfg_path)
    registry = {
        pull_type_key: _FakePullPlugin(pull_type_key),
        push_type_key: _FakePushPlugin(push_type_key),
    }

    if supervisor is None:
        supervisor = _FakeSupervisor()

    app = create_app(
        registry=registry,
        config_store=store,
        supervisor=supervisor,
    )
    client = TestClient(app, raise_server_exceptions=True)
    return client, cfg_path, supervisor


# --------------------------------------------------------------------------- #
# EARS-AS-1: enable                                                             #
# --------------------------------------------------------------------------- #


def test_put_autosync_enable_persists_and_launches(tmp_path: Path) -> None:
    """Enable=true persists an _instances entry and launches the instance."""
    client, cfg_path, sup = _make_app(tmp_path=tmp_path)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 60},
    )
    assert resp.status_code == 200

    # Instance entry must be written to the config file
    data = json.loads(cfg_path.read_text())
    instances = data.get("_instances", [])
    assert len(instances) == 1
    assert instances[0]["source_type"] == "fake_pull"
    assert instances[0]["interval"] == 60.0

    # Supervisor calls: register_idle + enable_pull
    assert any(c["type_key"] == "fake_pull" for c in sup.register_idle_calls)
    assert any(call[0] == "fake_pull" for call in sup.enable_pull_calls)


def test_put_autosync_enable_returns_correct_payload(tmp_path: Path) -> None:
    """Response body matches the pinned contract: enabled, interval_seconds, source_id."""
    client, _, _ = _make_app(tmp_path=tmp_path)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 90},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is True
    assert body["interval_seconds"] == 90
    assert body["source_id"] == "fake_pull"


# --------------------------------------------------------------------------- #
# EARS-AS-2: disable                                                            #
# --------------------------------------------------------------------------- #


def test_put_autosync_disable_removes_instance_entry(tmp_path: Path) -> None:
    """Enable then disable removes the _instances entry."""
    initial = {
        "_instances": [
            {
                "source_type": "fake_pull",
                "source_id": "fake_pull",
                "flavor": "pull",
                "interval": 60.0,
                "transport": "file",
            }
        ]
    }
    sup = _FakeSupervisor(instances={("fake_pull", "fake_pull"): MagicMock()})
    client, cfg_path, _ = _make_app(tmp_path=tmp_path, supervisor=sup, initial_config=initial)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": False, "interval_seconds": 60},
    )
    assert resp.status_code == 200

    data = json.loads(cfg_path.read_text())
    instances = data.get("_instances", [])
    assert all(e.get("source_type") != "fake_pull" for e in instances)


def test_put_autosync_disable_stops_supervisor_instance(tmp_path: Path) -> None:
    """Disable calls supervisor.disable() when instance is registered."""
    sup = _FakeSupervisor(instances={("fake_pull", "fake_pull"): MagicMock()})
    client, _, _ = _make_app(tmp_path=tmp_path, supervisor=sup)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": False, "interval_seconds": 60},
    )
    assert resp.status_code == 200
    assert ("fake_pull", "fake_pull") in sup.disable_calls


def test_put_autosync_disable_leaves_source_config_intact(tmp_path: Path) -> None:
    """Disable does NOT touch the source's own config section."""
    initial = {
        "fake_pull": {"host": "192.0.2.10"},
        "_instances": [
            {
                "source_type": "fake_pull",
                "source_id": "fake_pull",
                "flavor": "pull",
                "interval": 60.0,
                "transport": "file",
            }
        ],
    }
    sup = _FakeSupervisor(instances={("fake_pull", "fake_pull"): MagicMock()})
    client, cfg_path, _ = _make_app(tmp_path=tmp_path, supervisor=sup, initial_config=initial)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": False, "interval_seconds": 60},
    )
    assert resp.status_code == 200

    data = json.loads(cfg_path.read_text())
    assert data.get("fake_pull") == {"host": "192.0.2.10"}


# --------------------------------------------------------------------------- #
# EARS-AS-3: interval-only change                                               #
# --------------------------------------------------------------------------- #


def test_put_autosync_interval_change_upserts_and_calls_set_interval(tmp_path: Path) -> None:
    """When enable=true on an already-RUNNING instance with a new interval,
    upsert the entry AND call set_interval (no redundant enable_pull)."""
    existing_rec = MagicMock()
    existing_rec.state.value = "running"  # already running — interval-only path
    sup = _FakeSupervisor(instances={("fake_pull", "fake_pull"): existing_rec})
    initial = {
        "_instances": [
            {
                "source_type": "fake_pull",
                "source_id": "fake_pull",
                "flavor": "pull",
                "interval": 60.0,
                "transport": "file",
            }
        ]
    }
    client, cfg_path, _ = _make_app(tmp_path=tmp_path, supervisor=sup, initial_config=initial)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 120},
    )
    assert resp.status_code == 200

    data = json.loads(cfg_path.read_text())
    instances = data.get("_instances", [])
    assert len(instances) == 1
    assert instances[0]["interval"] == 120.0

    assert ("fake_pull", "fake_pull", 120.0) in sup.set_interval_calls
    assert len(sup.enable_pull_calls) == 0


def test_put_autosync_enable_on_idle_instance_calls_enable_pull(tmp_path: Path) -> None:
    """When enable=true on an already-registered but IDLE instance (previously
    disabled), enable_pull MUST be called so the pull loop actually launches.
    This was the root-cause bug: the handler only called set_interval, which
    does not start the loop on an IDLE instance."""
    existing_rec = MagicMock()
    existing_rec.state.value = "idle"  # was disabled — re-enable path
    sup = _FakeSupervisor(instances={("fake_pull", "fake_pull"): existing_rec})
    initial = {
        "_instances": [
            {
                "source_type": "fake_pull",
                "source_id": "fake_pull",
                "flavor": "pull",
                "interval": 60.0,
                "transport": "file",
            }
        ]
    }
    client, _, _ = _make_app(tmp_path=tmp_path, supervisor=sup, initial_config=initial)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 90},
    )
    assert resp.status_code == 200

    # The loop must be launched via enable_pull (not just set_interval).
    assert len(sup.enable_pull_calls) == 1
    assert sup.enable_pull_calls[0] == ("fake_pull", "fake_pull", 90.0)
    # set_interval must NOT be called — enable_pull subsumes the interval update.
    assert len(sup.set_interval_calls) == 0
    # register_idle must NOT be called — the instance already exists.
    assert len(sup.register_idle_calls) == 0


# --------------------------------------------------------------------------- #
# EARS-AS-4: register_idle idempotence                                          #
# --------------------------------------------------------------------------- #


def test_put_autosync_enable_registers_idle_when_absent(tmp_path: Path) -> None:
    """When the supervisor has no record yet, register_idle is called before enable_pull."""
    client, _, sup = _make_app(tmp_path=tmp_path)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 60},
    )
    assert resp.status_code == 200
    assert len(sup.register_idle_calls) == 1
    assert len(sup.enable_pull_calls) == 1


def test_put_autosync_enable_skips_register_idle_when_already_registered(tmp_path: Path) -> None:
    """When the supervisor already has a record, register_idle is NOT called again."""
    existing_rec = MagicMock()
    existing_rec.state.value = "running"  # already running — register_idle skip path
    sup = _FakeSupervisor(instances={("fake_pull", "fake_pull"): existing_rec})
    initial = {
        "_instances": [
            {
                "source_type": "fake_pull",
                "source_id": "fake_pull",
                "flavor": "pull",
                "interval": 60.0,
                "transport": "file",
            }
        ]
    }
    client, _, _ = _make_app(tmp_path=tmp_path, supervisor=sup, initial_config=initial)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 60},
    )
    assert resp.status_code == 200
    assert len(sup.register_idle_calls) == 0


# --------------------------------------------------------------------------- #
# EARS-AS-5: persistence round-trip                                             #
# --------------------------------------------------------------------------- #


def test_put_autosync_enable_persisted_entry_readable_after_write(tmp_path: Path) -> None:
    """The persisted entry can be loaded back via load_instances (restart-stable)."""
    client, cfg_path, _ = _make_app(tmp_path=tmp_path)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 75},
    )
    assert resp.status_code == 200

    loaded = load_instances(cfg_path)
    assert len(loaded) == 1
    assert loaded[0].source_type == "fake_pull"
    assert loaded[0].interval == 75.0


# --------------------------------------------------------------------------- #
# EARS-AS-6: interval validation                                                #
# --------------------------------------------------------------------------- #


def test_put_autosync_interval_too_low_returns_422(tmp_path: Path) -> None:
    """interval_seconds=29 (below 30) must return 422."""
    client, _, _ = _make_app(tmp_path=tmp_path)
    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 29},
    )
    assert resp.status_code == 422


def test_put_autosync_interval_too_high_returns_422(tmp_path: Path) -> None:
    """interval_seconds=86401 (above 86400) must return 422."""
    client, _, _ = _make_app(tmp_path=tmp_path)
    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 86401},
    )
    assert resp.status_code == 422


def test_put_autosync_422_does_not_persist(tmp_path: Path) -> None:
    """A rejected request (422) must not write anything to _instances."""
    client, cfg_path, _ = _make_app(tmp_path=tmp_path)
    cfg_path.write_text("{}", encoding="utf-8")

    client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 1},
    )

    data = json.loads(cfg_path.read_text())
    assert data.get("_instances", []) == []


def test_put_autosync_422_does_not_call_supervisor(tmp_path: Path) -> None:
    """A rejected request (422) must not call any supervisor method."""
    client, _, sup = _make_app(tmp_path=tmp_path)

    client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 1},
    )

    assert sup.register_idle_calls == []
    assert sup.enable_pull_calls == []


# --------------------------------------------------------------------------- #
# EARS-AS-7: push flavor -> 409                                                 #
# --------------------------------------------------------------------------- #


def test_put_autosync_push_source_returns_409(tmp_path: Path) -> None:
    """PUT /sources/fake_push/auto-sync must return 409 (push has no auto-sync)."""
    client, _, _ = _make_app(tmp_path=tmp_path)
    resp = client.put(
        "/sources/fake_push/auto-sync",
        json={"enabled": True, "interval_seconds": 60},
    )
    assert resp.status_code == 409


# --------------------------------------------------------------------------- #
# EARS-AS-8: unknown type -> 404                                                #
# --------------------------------------------------------------------------- #


def test_put_autosync_unknown_type_returns_404(tmp_path: Path) -> None:
    """PUT for an unregistered type_key must return 404."""
    client, _, _ = _make_app(tmp_path=tmp_path)
    resp = client.put(
        "/sources/nonexistent/auto-sync",
        json={"enabled": True, "interval_seconds": 60},
    )
    assert resp.status_code == 404


def test_get_autosync_unknown_type_returns_404(tmp_path: Path) -> None:
    """GET for an unregistered type_key must return 404."""
    client, _, _ = _make_app(tmp_path=tmp_path)
    resp = client.get("/sources/nonexistent/auto-sync")
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# EARS-AS-9: GET                                                                #
# --------------------------------------------------------------------------- #


class _FakeStatus:
    """Minimal InstanceStatus stand-in for GET tests."""

    def __init__(
        self,
        source_type: str,
        source_id: str,
        state: str = "running",
        last_sync_at: float | None = None,
        last_sync_ingested: int = 0,
        last_sync_status: str | None = None,
        last_error: str | None = None,
    ) -> None:
        self.source_type = source_type
        self.source_id = source_id
        self.state = state
        self.last_sync_at = last_sync_at
        self.last_sync_ingested = last_sync_ingested
        self.last_sync_status = last_sync_status
        self.last_error = last_error


def test_get_autosync_enabled_returns_state(tmp_path: Path) -> None:
    """GET returns enabled=True when an _instances entry exists."""
    initial = {
        "_instances": [
            {
                "source_type": "fake_pull",
                "source_id": "fake_pull",
                "flavor": "pull",
                "interval": 60.0,
                "transport": "file",
            }
        ]
    }
    sup = _FakeSupervisor(
        instances={("fake_pull", "fake_pull"): MagicMock()},
        statuses=[_FakeStatus("fake_pull", "fake_pull", state="running")],
    )
    client, _, _ = _make_app(tmp_path=tmp_path, supervisor=sup, initial_config=initial)

    resp = client.get("/sources/fake_pull/auto-sync")
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is True
    assert body["source_id"] == "fake_pull"
    assert body["interval_seconds"] == 60


def test_get_autosync_disabled_returns_state(tmp_path: Path) -> None:
    """GET returns enabled=False when no _instances entry exists for the type."""
    sup = _FakeSupervisor(statuses=[])
    client, _, _ = _make_app(tmp_path=tmp_path, supervisor=sup)

    resp = client.get("/sources/fake_pull/auto-sync")
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is False
    assert body["source_id"] == "fake_pull"


def test_get_autosync_includes_last_sync_fields(tmp_path: Path) -> None:
    """GET returns last_sync object with last_sync_at, ingested, status, error."""
    initial = {
        "_instances": [
            {
                "source_type": "fake_pull",
                "source_id": "fake_pull",
                "flavor": "pull",
                "interval": 60.0,
                "transport": "file",
            }
        ]
    }
    sup = _FakeSupervisor(
        instances={("fake_pull", "fake_pull"): MagicMock()},
        statuses=[
            _FakeStatus(
                "fake_pull",
                "fake_pull",
                last_sync_at=1234567890.0,
                last_sync_ingested=42,
                last_sync_status="ok",
                last_error=None,
            )
        ],
    )
    client, _, _ = _make_app(tmp_path=tmp_path, supervisor=sup, initial_config=initial)

    resp = client.get("/sources/fake_pull/auto-sync")
    assert resp.status_code == 200
    body = resp.json()
    assert "last_sync" in body
    ls = body["last_sync"]
    assert ls["last_sync_at"] == 1234567890.0
    assert ls["last_sync_ingested"] == 42
    assert ls["last_sync_status"] == "ok"
    assert ls["last_error"] is None


# --------------------------------------------------------------------------- #
# EARS-AS-10: no config_path -> 503                                             #
# --------------------------------------------------------------------------- #


def test_put_autosync_no_config_path_returns_503(tmp_path: Path) -> None:
    """When config_store lacks a config_path (fake store), route returns 503."""
    sup = _FakeSupervisor()
    store = _FakeConfigStoreNoPath()

    _reg_no_path: dict[str, Any] = {"fake_pull": _FakePullPlugin("fake_pull")}
    app = create_app(
        registry=_reg_no_path,
        config_store=store,
        supervisor=sup,
    )
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 60},
    )
    assert resp.status_code == 503


# --------------------------------------------------------------------------- #
# EARS-AS-11: no supervisor -> 503                                              #
# --------------------------------------------------------------------------- #


def test_put_autosync_no_supervisor_returns_503(tmp_path: Path) -> None:
    """When no supervisor is injected, PUT returns 503."""
    cfg_path = tmp_path / "firewatch_config.json"
    cfg_path.write_text("{}", encoding="utf-8")
    store = JsonFileConfigStore(cfg_path)

    _reg_no_sup: dict[str, Any] = {"fake_pull": _FakePullPlugin("fake_pull")}
    app = create_app(
        registry=_reg_no_sup,
        config_store=store,
        supervisor=None,
    )
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 60},
    )
    assert resp.status_code == 503


def test_get_autosync_no_supervisor_returns_503(tmp_path: Path) -> None:
    """When no supervisor is injected, GET returns 503."""
    cfg_path = tmp_path / "firewatch_config.json"
    cfg_path.write_text("{}", encoding="utf-8")
    store = JsonFileConfigStore(cfg_path)

    _reg_get_no_sup: dict[str, Any] = {"fake_pull": _FakePullPlugin("fake_pull")}
    app = create_app(
        registry=_reg_get_no_sup,
        config_store=store,
        supervisor=None,
    )
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.get("/sources/fake_pull/auto-sync")
    assert resp.status_code == 503


# --------------------------------------------------------------------------- #
# EARS-AS-12: disable doesn't require interval_seconds (issue #155 NB-1)      #
# --------------------------------------------------------------------------- #


def test_put_autosync_disable_without_interval_succeeds(tmp_path: Path) -> None:
    """Disable with no interval_seconds key must succeed (200), not 422.

    EARS-AS-12a (issue #155 NB-1): WHEN PUT /sources/{type}/auto-sync is called
    with {enabled:false} and no interval_seconds key, the system SHALL return 200
    and disable the instance.  The interval is meaningless when disabling — it
    MUST NOT be required.
    """
    sup = _FakeSupervisor(instances={("fake_pull", "fake_pull"): MagicMock()})
    initial = {
        "_instances": [
            {
                "source_type": "fake_pull",
                "source_id": "fake_pull",
                "flavor": "pull",
                "interval": 60.0,
                "transport": "file",
            }
        ]
    }
    client, cfg_path, _ = _make_app(tmp_path=tmp_path, supervisor=sup, initial_config=initial)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": False},  # no interval_seconds
    )
    assert resp.status_code == 200

    # Instance entry must be removed.
    data = json.loads(cfg_path.read_text())
    instances = data.get("_instances", [])
    assert all(e.get("source_type") != "fake_pull" for e in instances)


def test_put_autosync_disable_with_out_of_bounds_interval_still_succeeds(
    tmp_path: Path,
) -> None:
    """Disable with an out-of-bounds interval_seconds must still succeed (200).

    EARS-AS-12b (issue #155 NB-1): WHEN PUT /sources/{type}/auto-sync is called
    with {enabled:false, interval_seconds:<invalid>}, the system SHALL return 200
    and ignore the interval.  Interval validation only applies to the enable path
    (ADR-0031 §E: bounds prevent busy-loop DoS for the pull schedule).
    """
    sup = _FakeSupervisor(instances={("fake_pull", "fake_pull"): MagicMock()})
    client, _, _ = _make_app(tmp_path=tmp_path, supervisor=sup)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": False, "interval_seconds": 1},  # below 30s floor
    )
    assert resp.status_code == 200
    assert ("fake_pull", "fake_pull") in sup.disable_calls


def test_put_autosync_enable_still_requires_valid_interval(tmp_path: Path) -> None:
    """Regression: enabling auto-sync without a valid interval still returns 422.

    EARS-AS-12c (issue #155 NB-1 regression guard): the disable relaxation
    MUST NOT weaken interval validation for the enable path (ADR-0031 §E).
    """
    client, _, _ = _make_app(tmp_path=tmp_path)

    # Missing interval entirely on enable.
    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True},
    )
    assert resp.status_code == 422

    # Out-of-bounds interval on enable.
    resp2 = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 1},
    )
    assert resp2.status_code == 422


# --------------------------------------------------------------------------- #
# EARS-AS-13: strict bool for 'enabled' (issue #166 NB-A)                     #
# --------------------------------------------------------------------------- #


def test_put_autosync_enabled_string_false_returns_422(tmp_path: Path) -> None:
    """JSON string "false" for 'enabled' SHALL be rejected with 422.

    EARS-AS-13a (issue #166 NB-A): WHEN PUT /sources/{type}/auto-sync is called
    with {"enabled": "false"}, the system SHALL return 422 because the JSON string
    "false" is truthy in Python (bool("false") is True), which would silently invert
    a disable request into an enable.  Strict isinstance(raw, bool) is required.
    The 422 message MUST NOT echo the raw user-supplied value (MC.3 attacker-echo).
    """
    client, _, sup = _make_app(tmp_path=tmp_path)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": "false", "interval_seconds": 60},
    )
    assert resp.status_code == 422
    # Supervisor must not have been called.
    assert not sup.register_idle_calls
    assert not sup.enable_pull_calls
    assert not sup.disable_calls
    # Raw value must not be echoed in the response (MC.3).
    body_text = resp.text
    assert '"false"' not in body_text


def test_put_autosync_enabled_string_true_returns_422(tmp_path: Path) -> None:
    """JSON string "true" for 'enabled' SHALL be rejected with 422.

    EARS-AS-13b (issue #166 NB-A): WHEN PUT /sources/{type}/auto-sync is called
    with {"enabled": "true"}, the system SHALL return 422.  Strings are not
    booleans; the route MUST require a strict JSON boolean.
    """
    client, _, sup = _make_app(tmp_path=tmp_path)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": "true", "interval_seconds": 60},
    )
    assert resp.status_code == 422
    assert not sup.register_idle_calls
    assert not sup.enable_pull_calls


def test_put_autosync_enabled_integer_returns_422(tmp_path: Path) -> None:
    """JSON integer for 'enabled' SHALL be rejected with 422.

    EARS-AS-13c (issue #166 NB-A): WHEN PUT /sources/{type}/auto-sync is called
    with {"enabled": 1}, the system SHALL return 422.  In Python bool is a subclass
    of int, but JSON integers are not booleans — isinstance(1, bool) is False.
    The check must distinguish JSON int from JSON bool.
    """
    client, _, sup = _make_app(tmp_path=tmp_path)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": 1, "interval_seconds": 60},
    )
    assert resp.status_code == 422
    assert not sup.register_idle_calls
    assert not sup.enable_pull_calls


def test_put_autosync_enabled_null_returns_422(tmp_path: Path) -> None:
    """JSON null for 'enabled' SHALL be rejected with 422.

    EARS-AS-13d (issue #166 NB-A): WHEN PUT /sources/{type}/auto-sync is called
    with {"enabled": null}, the system SHALL return 422.  null is not a boolean.
    """
    client, _, sup = _make_app(tmp_path=tmp_path)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": None, "interval_seconds": 60},
    )
    assert resp.status_code == 422
    assert not sup.register_idle_calls
    assert not sup.enable_pull_calls


def test_put_autosync_enabled_true_bool_still_works(tmp_path: Path) -> None:
    """JSON boolean true for 'enabled' SHALL still succeed (regression guard).

    EARS-AS-13e (issue #166 NB-A regression guard): the strict bool check MUST NOT
    reject real JSON booleans.  {enabled: true} with a valid interval SHALL return 200.
    """
    client, _, sup = _make_app(tmp_path=tmp_path)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": True, "interval_seconds": 60},
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True
    assert sup.enable_pull_calls


def test_put_autosync_enabled_false_bool_still_works(tmp_path: Path) -> None:
    """JSON boolean false for 'enabled' SHALL still succeed (regression guard).

    EARS-AS-13f (issue #166 NB-A regression guard): {enabled: false} SHALL return
    200 and perform a disable, not a 422.
    """
    sup = _FakeSupervisor(instances={("fake_pull", "fake_pull"): MagicMock()})
    client, _, sup = _make_app(tmp_path=tmp_path, supervisor=sup)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": False},
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


# --------------------------------------------------------------------------- #
# EARS-AS-14: disable response interval consistency (issue #166 NB-B)         #
# --------------------------------------------------------------------------- #


def test_put_autosync_disable_response_interval_is_not_zero(tmp_path: Path) -> None:
    """Disable response SHALL NOT return interval_seconds: 0.

    EARS-AS-14a (issue #166 NB-B): WHEN PUT /sources/{type}/auto-sync is called
    with {enabled: false}, the response interval_seconds MUST NOT be 0 (below the
    ADR-0031 §E floor of 30).  Returning 0 on disable while GET defaults to 60
    creates an inconsistent contract — callers reading the response to cache the
    last-known interval would see an invalid sentinel.
    """
    initial = {
        "_instances": [
            {
                "source_type": "fake_pull",
                "source_id": "fake_pull",
                "flavor": "pull",
                "interval": 120.0,
                "transport": "file",
            }
        ]
    }
    sup = _FakeSupervisor(instances={("fake_pull", "fake_pull"): MagicMock()})
    client, _, _ = _make_app(tmp_path=tmp_path, supervisor=sup, initial_config=initial)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": False},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["interval_seconds"] != 0, (
        "interval_seconds must not be 0 on disable — 0 is below the ADR-0031 §E floor"
    )


def test_put_autosync_disable_response_interval_matches_persisted(
    tmp_path: Path,
) -> None:
    """Disable response interval_seconds SHALL match the persisted _instances interval.

    EARS-AS-14b (issue #166 NB-B): WHEN PUT .../auto-sync {enabled: false} is called
    and a _instances entry with interval=120 exists, the response SHALL return
    interval_seconds=120 (the last-known persisted value), not 0.
    This keeps the disable response consistent with what GET .../auto-sync returns
    (which reads the interval from the _instances entry before it is removed).
    """
    initial = {
        "_instances": [
            {
                "source_type": "fake_pull",
                "source_id": "fake_pull",
                "flavor": "pull",
                "interval": 120.0,
                "transport": "file",
            }
        ]
    }
    sup = _FakeSupervisor(instances={("fake_pull", "fake_pull"): MagicMock()})
    client, _, _ = _make_app(tmp_path=tmp_path, supervisor=sup, initial_config=initial)

    resp = client.put(
        "/sources/fake_pull/auto-sync",
        json={"enabled": False},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["interval_seconds"] == 120, (
        "interval_seconds must reflect the persisted interval (120), not 0"
    )
