"""Tests for issue #736 — auto_sync_enabled field in GET /sources.

ADR reference: ADR-0062 Amendment 1 (2026-06-15).

EARS → test mapping
────────────────────

E1 (ubiquitous): GET /sources SHALL include auto_sync_enabled: bool on every
  pull instance entry, computed solely from the _instances file.
  → test_pull_in_autosync_set_returns_auto_sync_enabled_true
  → test_pull_not_in_autosync_set_returns_auto_sync_enabled_false

E2 (event): WHEN a pull source has an _instances entry, the API SHALL return
  auto_sync_enabled=true for it.
  → test_pull_in_autosync_set_returns_auto_sync_enabled_true

E3 (event): WHEN a pull source is registered IDLE but has NO _instances entry,
  the API SHALL return auto_sync_enabled=false (even though the entry is present
  with state="idle").
  → test_pull_idle_no_instances_entry_returns_false

E4 (state-driven): WHILE the config store is not file-backed, the API SHALL
  return auto_sync_enabled=false for all entries and SHALL still return the
  full instance list (no 503).
  → test_no_config_store_returns_false_not_503
  → test_fake_config_store_without_config_path_returns_false

E5 (invariant): auto_sync_enabled from GET /sources SHALL equal enabled from
  GET /sources/{t}/auto-sync for the same (source_type, source_id), by
  construction (same file read).
  → test_auto_sync_enabled_matches_get_autosync_endpoint

E6 (unwanted): The API SHALL NOT add per-source-type branching; the field is
  computed identically for all pull plugins.
  → test_multiple_pull_sources_auto_sync_computed_for_all

E7 (unwanted): push entries SHALL NOT carry the auto_sync_enabled key.
  → test_push_source_omits_auto_sync_enabled_key

E8 (regression): existing fields (state, last_sync_at, etc.) MUST remain
  untouched by this change.
  → test_existing_fields_unchanged
"""
from __future__ import annotations

import json
from pathlib import Path
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
    """Minimal fake pull plugin."""

    def __init__(self, type_key: str = "suricata") -> None:
        self._type_key = type_key

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name=f"Fake {self._type_key}",
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
            source_ip="192.0.2.1",
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True


class _FakePushPlugin:
    """Minimal fake push plugin."""

    def __init__(self, type_key: str = "syslog") -> None:
        self._type_key = type_key

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name=f"Fake {self._type_key}",
            version="0.1.0",
            flavor="push",
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
            source_ip="192.0.2.2",
            action="ALLOW",
        )


class _FakeInstanceStatus:
    """Minimal InstanceStatus fake."""

    def __init__(
        self,
        source_type: str = "suricata",
        source_id: str = "suricata",
        flavor: str = "pull",
        state: str = "idle",
        attempt: int = 0,
        total_crashes: int = 0,
        total_dlq: int = 0,
        dropped_count: int = 0,
        last_success_at: float = 0.0,
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
    """Fake supervisor backed by a configurable list of InstanceStatus objects."""

    def __init__(self, statuses: list[_FakeInstanceStatus] | None = None) -> None:
        self._statuses = statuses or []

    def status(self) -> list[_FakeInstanceStatus]:
        return list(self._statuses)

    def get_instance(self, source_type: str, source_id: str) -> Any | None:
        for s in self._statuses:
            if s.source_type == source_type and s.source_id == source_id:
                return s
        return None


class _FakeConfigStoreNoPath:
    """Config store that does NOT expose config_path — simulates non-file-backed store."""

    def get_source(self, source_type: str, schema: type[BaseModel]) -> BaseModel:
        return schema.model_validate({})

    def set_source(self, *_: Any, **__: Any) -> None:
        pass

    def get_runtime(self) -> Any:
        from firewatch_sdk import RuntimeConfig
        return RuntimeConfig.model_validate({})

    def set_runtime(self, *_: Any) -> None:
        pass


class _FileBackedConfigStore:
    """Config store backed by a real temp file, exposing config_path."""

    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path

    def get_source(self, source_type: str, schema: type[BaseModel]) -> BaseModel:
        return schema.model_validate({})

    def set_source(self, *_: Any, **__: Any) -> None:
        pass

    def get_runtime(self) -> Any:
        from firewatch_sdk import RuntimeConfig
        return RuntimeConfig.model_validate({})

    def set_runtime(self, *_: Any) -> None:
        pass


def _write_instances_file(tmp_path: Path, instances: list[dict[str, Any]]) -> Path:
    """Write a minimal firewatch_config.json with the given _instances list."""
    config_path = tmp_path / "firewatch_config.json"
    config_path.write_text(
        json.dumps({"_instances": instances}), encoding="utf-8"
    )
    return config_path


def _make_client(
    supervisor: Any | None,
    config_store: Any | None,
    registry: dict[str, Any] | None = None,
) -> TestClient:
    if registry is None:
        registry = {"suricata": _FakePullPlugin("suricata")}
    app = create_app(
        registry=registry,
        config_store=config_store,
        event_store=None,
        pipeline=None,
        supervisor=supervisor,
    )
    return TestClient(app)


# --------------------------------------------------------------------------- #
# E1 / E2 — pull source IN _instances set → auto_sync_enabled=true           #
# --------------------------------------------------------------------------- #


def test_pull_in_autosync_set_returns_auto_sync_enabled_true(
    tmp_path: Path,
) -> None:
    """E2: A pull source with an _instances entry → auto_sync_enabled=true."""
    config_path = _write_instances_file(
        tmp_path,
        [{"source_type": "suricata", "source_id": "suricata", "flavor": "pull"}],
    )
    sup = _FakeSupervisor(
        statuses=[_FakeInstanceStatus("suricata", "suricata", flavor="pull", state="idle")]
    )
    store = _FileBackedConfigStore(config_path)

    client = _make_client(supervisor=sup, config_store=store)
    resp = client.get("/sources")

    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    item = items[0]
    assert item["flavor"] == "pull"
    assert "auto_sync_enabled" in item
    assert item["auto_sync_enabled"] is True


# --------------------------------------------------------------------------- #
# E1 / E3 — pull source NOT in _instances set → auto_sync_enabled=false      #
# --------------------------------------------------------------------------- #


def test_pull_not_in_autosync_set_returns_auto_sync_enabled_false(
    tmp_path: Path,
) -> None:
    """E1: A pull source absent from _instances → auto_sync_enabled=false."""
    # _instances is empty (no enabled sources)
    config_path = _write_instances_file(tmp_path, [])
    sup = _FakeSupervisor(
        statuses=[_FakeInstanceStatus("suricata", "suricata", flavor="pull", state="idle")]
    )
    store = _FileBackedConfigStore(config_path)

    client = _make_client(supervisor=sup, config_store=store)
    resp = client.get("/sources")

    assert resp.status_code == 200
    item = resp.json()[0]
    assert item["flavor"] == "pull"
    assert "auto_sync_enabled" in item
    assert item["auto_sync_enabled"] is False


def test_pull_idle_no_instances_entry_returns_false(tmp_path: Path) -> None:
    """E3: An IDLE-but-registered pull source with no _instances entry → false.

    This is the root-cause scenario from the bug: run.py registers idle pull
    instances so manual Sync works, but that does NOT mean auto-sync is on.
    """
    # Config file exists but _instances is empty (no auto-sync registered)
    config_path = _write_instances_file(tmp_path, [])
    sup = _FakeSupervisor(
        statuses=[
            _FakeInstanceStatus(
                source_type="suricata",
                source_id="suricata",
                flavor="pull",
                state="idle",  # IDLE registration — the bug trigger
            )
        ]
    )
    store = _FileBackedConfigStore(config_path)

    client = _make_client(supervisor=sup, config_store=store)
    resp = client.get("/sources")

    assert resp.status_code == 200
    item = resp.json()[0]
    assert item["state"] == "idle"  # state is still diagnostic-only
    assert item["auto_sync_enabled"] is False  # the truth signal


# --------------------------------------------------------------------------- #
# E4 — no file-backed store → false, not 503                                  #
# --------------------------------------------------------------------------- #


def test_no_config_store_returns_false_not_503() -> None:
    """E4: config_store=None → auto_sync_enabled=false; still returns 200 list."""
    sup = _FakeSupervisor(
        statuses=[_FakeInstanceStatus("suricata", "suricata", flavor="pull", state="idle")]
    )
    app = create_app(
        registry={"suricata": _FakePullPlugin("suricata")},
        config_store=_FakeConfigStoreNoPath(),
        event_store=None,
        pipeline=None,
        supervisor=sup,
    )
    # Null out the config_store to simulate the fully-absent case.
    app.state.config_store = None
    client = TestClient(app)
    resp = client.get("/sources")

    assert resp.status_code == 200  # NOT 503
    item = resp.json()[0]
    assert "auto_sync_enabled" in item
    assert item["auto_sync_enabled"] is False


def test_fake_config_store_without_config_path_returns_false() -> None:
    """E4: A config store that does not expose config_path → auto_sync_enabled=false."""
    sup = _FakeSupervisor(
        statuses=[_FakeInstanceStatus("suricata", "suricata", flavor="pull", state="idle")]
    )
    store = _FakeConfigStoreNoPath()  # no config_path attribute

    client = _make_client(supervisor=sup, config_store=store)
    resp = client.get("/sources")

    assert resp.status_code == 200
    item = resp.json()[0]
    assert item["auto_sync_enabled"] is False


# --------------------------------------------------------------------------- #
# E5 — invariant: same result as GET /sources/{t}/auto-sync                  #
# --------------------------------------------------------------------------- #


def test_auto_sync_enabled_matches_get_autosync_endpoint(tmp_path: Path) -> None:
    """E5: auto_sync_enabled in GET /sources equals enabled in GET /sources/{t}/auto-sync."""
    config_path = _write_instances_file(
        tmp_path,
        [{"source_type": "suricata", "source_id": "suricata", "flavor": "pull"}],
    )
    sup = _FakeSupervisor(
        statuses=[_FakeInstanceStatus("suricata", "suricata", flavor="pull", state="idle")]
    )
    store = _FileBackedConfigStore(config_path)

    client = _make_client(supervisor=sup, config_store=store)

    list_resp = client.get("/sources")
    autosync_resp = client.get("/sources/suricata/auto-sync")

    assert list_resp.status_code == 200
    assert autosync_resp.status_code == 200

    list_enabled = list_resp.json()[0]["auto_sync_enabled"]
    autosync_enabled = autosync_resp.json()["enabled"]

    assert list_enabled == autosync_enabled, (
        f"GET /sources auto_sync_enabled={list_enabled!r} must equal "
        f"GET /sources/suricata/auto-sync enabled={autosync_enabled!r}"
    )


def test_auto_sync_enabled_matches_get_autosync_when_disabled(tmp_path: Path) -> None:
    """E5 inverse: both endpoints agree when the source is NOT in _instances."""
    config_path = _write_instances_file(tmp_path, [])  # empty — not enabled
    sup = _FakeSupervisor(
        statuses=[_FakeInstanceStatus("suricata", "suricata", flavor="pull", state="idle")]
    )
    store = _FileBackedConfigStore(config_path)

    client = _make_client(supervisor=sup, config_store=store)

    list_resp = client.get("/sources")
    autosync_resp = client.get("/sources/suricata/auto-sync")

    assert list_resp.status_code == 200
    assert autosync_resp.status_code == 200

    assert list_resp.json()[0]["auto_sync_enabled"] is False
    assert autosync_resp.json()["enabled"] is False


# --------------------------------------------------------------------------- #
# E6 — no per-source branching: field computed for ALL pull plugins           #
# --------------------------------------------------------------------------- #


def test_multiple_pull_sources_auto_sync_computed_for_all(tmp_path: Path) -> None:
    """E6: auto_sync_enabled is computed for all pull plugins, not just suricata.

    azure_waf is in _instances; suricata is not. Both get the field; values differ.
    """
    config_path = _write_instances_file(
        tmp_path,
        [{"source_type": "azure_waf", "source_id": "azure_waf", "flavor": "pull"}],
    )
    sup = _FakeSupervisor(
        statuses=[
            _FakeInstanceStatus("suricata", "suricata", flavor="pull", state="idle"),
            _FakeInstanceStatus("azure_waf", "azure_waf", flavor="pull", state="idle"),
        ]
    )
    store = _FileBackedConfigStore(config_path)
    registry = {
        "suricata": _FakePullPlugin("suricata"),
        "azure_waf": _FakePullPlugin("azure_waf"),
    }

    client = _make_client(supervisor=sup, config_store=store, registry=registry)
    resp = client.get("/sources")

    assert resp.status_code == 200
    items = {i["source_type"]: i for i in resp.json()}

    # Both pull sources carry the field
    assert "auto_sync_enabled" in items["suricata"]
    assert "auto_sync_enabled" in items["azure_waf"]

    # Only azure_waf is in _instances
    assert items["suricata"]["auto_sync_enabled"] is False
    assert items["azure_waf"]["auto_sync_enabled"] is True


# --------------------------------------------------------------------------- #
# E7 — push sources omit auto_sync_enabled key entirely                       #
# --------------------------------------------------------------------------- #


def test_push_source_omits_auto_sync_enabled_key(tmp_path: Path) -> None:
    """E7: Push entries must NOT carry the auto_sync_enabled key."""
    config_path = _write_instances_file(tmp_path, [])
    sup = _FakeSupervisor(
        statuses=[_FakeInstanceStatus("syslog", "syslog", flavor="push", state="running")]
    )
    registry: dict[str, Any] = {"syslog": _FakePushPlugin("syslog")}
    store = _FileBackedConfigStore(config_path)

    client = _make_client(supervisor=sup, config_store=store, registry=registry)
    resp = client.get("/sources")

    assert resp.status_code == 200
    item = resp.json()[0]
    assert item["flavor"] == "push"
    assert "auto_sync_enabled" not in item


def test_mixed_pull_push_field_presence(tmp_path: Path) -> None:
    """E7: In a mixed list, pull entries carry auto_sync_enabled; push entries don't."""
    config_path = _write_instances_file(
        tmp_path,
        [{"source_type": "suricata", "source_id": "suricata", "flavor": "pull"}],
    )
    sup = _FakeSupervisor(
        statuses=[
            _FakeInstanceStatus("suricata", "suricata", flavor="pull", state="idle"),
            _FakeInstanceStatus("syslog", "syslog", flavor="push", state="running"),
        ]
    )
    registry: dict[str, Any] = {
        "suricata": _FakePullPlugin("suricata"),
        "syslog": _FakePushPlugin("syslog"),
    }
    store = _FileBackedConfigStore(config_path)

    client = _make_client(supervisor=sup, config_store=store, registry=registry)
    resp = client.get("/sources")

    assert resp.status_code == 200
    items = {i["source_type"]: i for i in resp.json()}

    assert "auto_sync_enabled" in items["suricata"]
    assert items["suricata"]["auto_sync_enabled"] is True
    assert "auto_sync_enabled" not in items["syslog"]


# --------------------------------------------------------------------------- #
# E8 — regression: existing fields must not be affected                       #
# --------------------------------------------------------------------------- #


def test_existing_fields_unchanged(tmp_path: Path) -> None:
    """E8: Adding auto_sync_enabled must not alter state or any other existing fields."""
    config_path = _write_instances_file(tmp_path, [])
    status = _FakeInstanceStatus(
        source_type="suricata",
        source_id="suricata",
        flavor="pull",
        state="backoff",
        attempt=2,
        total_crashes=1,
        total_dlq=0,
        dropped_count=0,
        last_success_at=1000.0,
        last_sync_at=900.0,
        last_sync_ingested=5,
        last_sync_status="ok",
        last_error=None,
    )
    sup = _FakeSupervisor(statuses=[status])
    store = _FileBackedConfigStore(config_path)

    client = _make_client(supervisor=sup, config_store=store)
    resp = client.get("/sources")

    assert resp.status_code == 200
    item = resp.json()[0]

    # Core fields — must be unaltered
    assert item["source_type"] == "suricata"
    assert item["source_id"] == "suricata"
    assert item["flavor"] == "pull"
    assert item["state"] == "backoff"  # diagnostic; NOT replaced by auto_sync_enabled
    assert item["attempt"] == 2
    assert item["total_crashes"] == 1
    assert item["last_sync_at"] == 900.0
    assert item["last_sync_ingested"] == 5
    assert item["last_sync_status"] == "ok"
    assert item["last_error"] is None

    # New field present and correct (not in _instances → false)
    assert item["auto_sync_enabled"] is False
