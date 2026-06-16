"""Tests for the ADR-0031 §C boot-path register_idle follow-through (issue #137).

When firewatch starts, pull sources that have a config section in
firewatch_config.json but NO matching _instances entry (auto-sync OFF) SHALL be
registered as idle so that POST /sync/{type} works without requiring auto-sync.

EARS -> test mapping
====================

EARS-BOOT-1 (state-driven — configured-but-not-in-_instances):
  WHILE a pull source is configured (config section present) and has no
  _instances entry, a supervisor record SHALL be in idle after _register_instances.
  -> test_configured_pull_without_instance_entry_is_registered_idle

EARS-BOOT-2 (state-driven — _instances entry skips idle re-registration):
  WHILE a pull source has an _instances entry, it is registered via add_pull
  (not register_idle); no duplicate idle record is added.
  -> test_pull_with_instance_entry_is_not_registered_idle

EARS-BOOT-3 (state-driven — push sources never get idle record):
  WHILE a push source has a config section but no _instances entry, it SHALL NOT
  be registered idle (push sources have no auto-sync concept).
  -> test_configured_push_without_instance_entry_is_not_registered_idle

EARS-BOOT-4 (state-driven — unconfigured source never gets idle record):
  WHILE a source has no config section, it SHALL NOT be registered idle.
  -> test_unconfigured_source_is_not_registered_idle
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from pydantic import BaseModel

from firewatch_sdk import SourceMetadata

from firewatch_cli.commands.run import _register_instances


# --------------------------------------------------------------------------- #
# Fake helpers                                                                  #
# --------------------------------------------------------------------------- #


class _FakeCfg(BaseModel):
    host: str = "192.0.2.1"


class _FakePullPlugin:
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


class _FakePushPlugin:
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


class _TrackingSupervisor:
    """Minimal supervisor that records add_pull, add_push, register_idle calls."""

    def __init__(self) -> None:
        self.add_pull_calls: list[str] = []
        self.add_push_calls: list[str] = []
        self.register_idle_calls: list[str] = []

    def add_pull(self, plugin: Any, cfg: Any, *, source_id: str, interval: float) -> Any:
        self.add_pull_calls.append(plugin.metadata().type_key)
        return MagicMock()

    def add_push(self, plugin: Any, cfg: Any, *, source_id: str, transport: str) -> Any:
        self.add_push_calls.append(plugin.metadata().type_key)
        return MagicMock()

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
        self.register_idle_calls.append(plugin.metadata().type_key)
        return MagicMock()


# --------------------------------------------------------------------------- #
# EARS-BOOT-1                                                                   #
# --------------------------------------------------------------------------- #


def test_configured_pull_without_instance_entry_is_registered_idle(tmp_path: Path) -> None:
    """A configured pull source with no _instances entry is registered idle at boot."""
    cfg_path = tmp_path / "firewatch_config.json"
    # Config section present; _instances absent.
    cfg_path.write_text(
        json.dumps({"fake_pull": {"host": "192.0.2.1"}}),
        encoding="utf-8",
    )

    supervisor = _TrackingSupervisor()
    registry = {"fake_pull": _FakePullPlugin("fake_pull")}

    # No instances loaded from file (_instances absent).
    _register_instances(supervisor, registry, [], cfg_path)  # type: ignore[arg-type]

    assert "fake_pull" in supervisor.register_idle_calls
    assert "fake_pull" not in supervisor.add_pull_calls


# --------------------------------------------------------------------------- #
# EARS-BOOT-2                                                                   #
# --------------------------------------------------------------------------- #


def test_pull_with_instance_entry_is_not_registered_idle(tmp_path: Path) -> None:
    """A pull source in _instances is registered via add_pull, not register_idle."""
    from firewatch_core.instance_loader import InstanceConfig

    cfg_path = tmp_path / "firewatch_config.json"
    cfg_path.write_text(
        json.dumps(
            {
                "fake_pull": {"host": "192.0.2.1"},
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
        ),
        encoding="utf-8",
    )

    supervisor = _TrackingSupervisor()
    registry = {"fake_pull": _FakePullPlugin("fake_pull")}
    instances = [
        InstanceConfig(
            source_type="fake_pull",
            source_id="fake_pull",
            flavor="pull",
            interval=60.0,
            transport="file",
        )
    ]

    _register_instances(supervisor, registry, instances, cfg_path)  # type: ignore[arg-type]

    assert "fake_pull" in supervisor.add_pull_calls
    # register_idle must NOT have been called for this type
    assert "fake_pull" not in supervisor.register_idle_calls


# --------------------------------------------------------------------------- #
# EARS-BOOT-3                                                                   #
# --------------------------------------------------------------------------- #


def test_configured_push_without_instance_entry_is_not_registered_idle(
    tmp_path: Path,
) -> None:
    """A configured push source with no _instances entry is NOT registered idle."""
    cfg_path = tmp_path / "firewatch_config.json"
    cfg_path.write_text(
        json.dumps({"fake_push": {"host": "192.0.2.2"}}),
        encoding="utf-8",
    )

    supervisor = _TrackingSupervisor()
    registry = {"fake_push": _FakePushPlugin("fake_push")}

    _register_instances(supervisor, registry, [], cfg_path)  # type: ignore[arg-type]

    assert "fake_push" not in supervisor.register_idle_calls
    assert "fake_push" not in supervisor.add_push_calls


# --------------------------------------------------------------------------- #
# EARS-BOOT-4                                                                   #
# --------------------------------------------------------------------------- #


def test_unconfigured_source_is_not_registered_idle(tmp_path: Path) -> None:
    """A pull source with no config section is NOT registered idle."""
    cfg_path = tmp_path / "firewatch_config.json"
    # Empty config — no section for fake_pull.
    cfg_path.write_text("{}", encoding="utf-8")

    supervisor = _TrackingSupervisor()
    registry = {"fake_pull": _FakePullPlugin("fake_pull")}

    _register_instances(supervisor, registry, [], cfg_path)  # type: ignore[arg-type]

    assert "fake_pull" not in supervisor.register_idle_calls


# --------------------------------------------------------------------------- #
# EARS-BOOT-5: boot path uses has_source(), not _file_data (issue #155 NB-2)  #
# --------------------------------------------------------------------------- #


class _PublicSeamOnlyStore:
    """Fake config store with has_source() but without _file_data.

    Used to prove the boot path calls the public has_source() seam and not
    the private _file_data attribute.  With the old code, getattr(store,
    "_file_data", {}) would silently return {} here, causing no idle
    registrations even for configured sources.  With the fix, has_source()
    is called and returns the correct answer.
    """

    def __init__(self, configured_types: set[str]) -> None:
        self._configured_types = configured_types
        # Deliberately do NOT define _file_data.

    def has_source(self, type_key: str) -> bool:
        return type_key in self._configured_types

    def get_source(self, source_type: str, schema: type[Any]) -> Any:
        return schema.model_validate({})


def test_boot_uses_public_has_source_not_private_file_data(tmp_path: Path) -> None:
    """The idle-registration pass calls has_source(), not getattr(_file_data).

    EARS-BOOT-5 (issue #155 NB-2): WHEN a store provides has_source() but NOT
    _file_data, configured pull sources SHALL still be registered idle.

    A store with _file_data={} (the old getattr fallback) would fail silently —
    the source would appear unconfigured even though has_source returns True.
    This test catches that regression.
    """
    from unittest.mock import patch

    # Write a minimal config file (needed by _register_instances for _resolve_config
    # fallback path) but we'll inject a fake store into _register_idle_configured_pulls.
    cfg_path = tmp_path / "firewatch_config.json"
    cfg_path.write_text("{}", encoding="utf-8")

    fake_store = _PublicSeamOnlyStore(configured_types={"fake_pull"})

    supervisor = _TrackingSupervisor()
    registry: dict[str, Any] = {"fake_pull": _FakePullPlugin("fake_pull")}

    # Patch JsonFileConfigStore at its definition site; the local import in
    # _register_idle_configured_pulls resolves through firewatch_core.config_store.
    with patch(
        "firewatch_core.config_store.JsonFileConfigStore",
        return_value=fake_store,
    ):
        _register_instances(supervisor, registry, [], cfg_path)  # type: ignore[arg-type]

    # The boot path must have reached has_source() and found fake_pull configured.
    assert "fake_pull" in supervisor.register_idle_calls
