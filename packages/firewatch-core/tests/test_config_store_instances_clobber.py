"""Regression tests for the dual-writer clobber bug (issue #742).

Root cause: ``ConfigStore`` loads ``firewatch_config.json`` into an in-memory
cache once at startup (``_load``), then on every write serialises that whole
dict wholesale (``_persist``).  ``instance_writer.upsert_instance`` writes the
``_instances`` key directly to the file out-of-band.  The next ConfigStore
write clobbers ``_instances`` back to its stale startup value (``[]``), so
``auto_sync_enabled`` reads false and the activation does not survive a restart.

Fix: ``_persist`` re-reads the on-disk value of ``_instances`` (and any other
``_``-prefixed keys ConfigStore does not own) immediately before writing, inside
the same critical section, so out-of-band writes are never reverted.

EARS acceptance criteria tested here:
- EARS-1: out-of-band ``_instances`` write MUST survive a subsequent ConfigStore
  ``set_runtime`` or ``set_source`` write.
- EARS-2: ``auto_sync_enabled`` (derived from ``_instances``) MUST remain true
  across subsequent ConfigStore writes.
- EARS-3: after the clobber sequence, a fresh ``load_instances`` returns the entry
  (restart survival).
- EARS-4: existing ``_runtime`` and source-section persistence MUST NOT regress.

IPs in fixtures use RFC 5737 documentation ranges only (gitleaks gate).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import BaseModel, Field

from firewatch_core.config_store import JsonFileConfigStore
from firewatch_core.instance_loader import load_instances
from firewatch_core.instance_writer import upsert_instance


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store(path: Path) -> JsonFileConfigStore:
    return JsonFileConfigStore(config_file=path)


def _read_raw(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class _ExamplePluginConfig(BaseModel):
    host: str = Field(default="192.0.2.1")  # RFC 5737 doc IP
    port: int = Field(default=514, ge=1, le=65535)


# ---------------------------------------------------------------------------
# EARS-1: _instances written out-of-band MUST survive a ConfigStore write
# ---------------------------------------------------------------------------


def test_instances_survive_set_runtime(tmp_path: Path) -> None:
    """EARS-1 (set_runtime path): upsert_instance + set_runtime → _instances on disk preserved.

    Reproduces the exact clobber sequence:
    1. A ConfigStore instance is loaded (startup cache = no _instances).
    2. instance_writer.upsert_instance writes an _instances entry out-of-band.
    3. ConfigStore.set_runtime writes a normal config update.
    4. Assert _instances is still present on disk (not reverted to []).
    """
    cfg_path = tmp_path / "firewatch_config.json"

    # Step 1: load ConfigStore — cache sees an empty file (no _instances yet).
    store = _make_store(cfg_path)

    # Step 2: out-of-band write of _instances by instance_writer.
    upsert_instance(
        config_file=cfg_path,
        source_type="suricata",
        source_id="suricata",
        flavor="pull",
        interval=60.0,
        transport="file",
    )

    # Verify the entry is on disk now.
    raw_before = _read_raw(cfg_path)
    assert len(raw_before.get("_instances", [])) == 1, (
        "_instances should have 1 entry after upsert_instance"
    )

    # Step 3: ConfigStore performs a normal write (old stale cache would clobber _instances).
    store.set_runtime({"alert_threshold": "HIGH"})

    # Step 4: _instances MUST still be on disk.
    raw_after = _read_raw(cfg_path)
    instances = raw_after.get("_instances", [])
    assert len(instances) == 1, (
        f"_instances was clobbered by set_runtime; got {instances!r}"
    )
    assert instances[0]["source_type"] == "suricata"
    assert instances[0]["source_id"] == "suricata"


def test_instances_survive_set_source(tmp_path: Path) -> None:
    """EARS-1 (set_source path): upsert_instance + set_source → _instances on disk preserved."""
    cfg_path = tmp_path / "firewatch_config.json"

    # Load ConfigStore with no _instances in cache.
    store = _make_store(cfg_path)

    # Out-of-band write.
    upsert_instance(
        config_file=cfg_path,
        source_type="azure_waf",
        source_id="azure_waf",
        flavor="pull",
        interval=120.0,
        transport="file",
    )

    # Normal ConfigStore source-config write.
    store.set_source("azure_waf", _ExamplePluginConfig, {"port": 9514})

    # _instances MUST survive.
    raw = _read_raw(cfg_path)
    instances = raw.get("_instances", [])
    assert len(instances) == 1, (
        f"_instances was clobbered by set_source; got {instances!r}"
    )
    assert instances[0]["source_type"] == "azure_waf"


def test_multiple_instances_survive_config_write(tmp_path: Path) -> None:
    """EARS-1 extended: two _instances entries both survive a ConfigStore write."""
    cfg_path = tmp_path / "firewatch_config.json"
    store = _make_store(cfg_path)

    upsert_instance(
        config_file=cfg_path,
        source_type="suricata",
        source_id="suricata",
        flavor="pull",
        interval=60.0,
        transport="file",
    )
    upsert_instance(
        config_file=cfg_path,
        source_type="azure_waf",
        source_id="azure_waf",
        flavor="pull",
        interval=120.0,
        transport="file",
    )

    # ConfigStore write using stale cache (neither entry visible to it).
    store.set_runtime({"alert_threshold": "MEDIUM"})

    raw = _read_raw(cfg_path)
    instances = raw.get("_instances", [])
    source_types = {e["source_type"] for e in instances}
    assert "suricata" in source_types, "suricata _instances entry was clobbered"
    assert "azure_waf" in source_types, "azure_waf _instances entry was clobbered"


def test_instances_survive_multiple_config_writes(tmp_path: Path) -> None:
    """EARS-1 extended: _instances survives repeated ConfigStore writes."""
    cfg_path = tmp_path / "firewatch_config.json"
    store = _make_store(cfg_path)

    upsert_instance(
        config_file=cfg_path,
        source_type="suricata",
        source_id="suricata",
        flavor="pull",
        interval=60.0,
        transport="file",
    )

    # Multiple writes — each one must preserve _instances.
    for threshold in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        store.set_runtime({"alert_threshold": threshold})
        raw = _read_raw(cfg_path)
        instances = raw.get("_instances", [])
        assert len(instances) == 1, (
            f"_instances clobbered after set_runtime(alert_threshold={threshold!r})"
        )


# ---------------------------------------------------------------------------
# EARS-2: auto_sync_enabled derived from _instances stays true
# ---------------------------------------------------------------------------


def test_auto_sync_enabled_survives_config_write(tmp_path: Path) -> None:
    """EARS-2: after upsert_instance + set_runtime, _instances is non-empty → auto_sync_enabled=True.

    The Settings UI derives auto_sync_enabled = len(_instances) > 0 (matching
    the source_type).  This test verifies the on-disk state that supports that
    derivation remains correct after a ConfigStore write.
    """
    cfg_path = tmp_path / "firewatch_config.json"
    store = _make_store(cfg_path)

    # Activate auto-sync (out-of-band write).
    upsert_instance(
        config_file=cfg_path,
        source_type="suricata",
        source_id="suricata",
        flavor="pull",
        interval=60.0,
        transport="file",
    )

    # ConfigStore write that would historically clobber _instances.
    store.set_runtime({"alert_threshold": "HIGH"})
    store.set_source("suricata", _ExamplePluginConfig, {"port": 5140})

    # Derive auto_sync_enabled the same way the API does.
    raw = _read_raw(cfg_path)
    instances = raw.get("_instances", [])
    suricata_instances = [e for e in instances if e.get("source_type") == "suricata"]
    auto_sync_enabled = len(suricata_instances) > 0

    assert auto_sync_enabled is True, (
        "auto_sync_enabled should be True; _instances was clobbered by a ConfigStore write"
    )


# ---------------------------------------------------------------------------
# EARS-3: restart survival — fresh load_instances returns the entry
# ---------------------------------------------------------------------------


def test_instances_survive_restart_after_config_write(tmp_path: Path) -> None:
    """EARS-3: after the clobber-sequence, a fresh load_instances returns the entry.

    Simulates: source activated → (some later) ConfigStore write → process
    restarts → load_instances at boot must find the entry.
    """
    cfg_path = tmp_path / "firewatch_config.json"

    # Simulate startup state: ConfigStore loaded before _instances written.
    store = _make_store(cfg_path)

    # Activation: instance_writer writes _instances entry.
    upsert_instance(
        config_file=cfg_path,
        source_type="suricata",
        source_id="suricata",
        flavor="pull",
        interval=90.0,
        transport="file",
    )

    # Some subsequent ConfigStore write (would historically clobber).
    store.set_runtime({"alert_threshold": "MEDIUM"})

    # Simulate restart: fresh load_instances reads the file from disk.
    loaded = load_instances(cfg_path)

    assert len(loaded) == 1, (
        f"load_instances returned {len(loaded)} entries after clobber-sequence; "
        "expected 1 (the suricata instance must survive)"
    )
    entry = loaded[0]
    assert entry.source_type == "suricata"
    assert entry.source_id == "suricata"
    assert entry.flavor == "pull"
    assert entry.interval == pytest.approx(90.0)


# ---------------------------------------------------------------------------
# EARS-4: _runtime and source sections NOT regressed by the fix
# ---------------------------------------------------------------------------


def test_runtime_config_not_regressed(tmp_path: Path) -> None:
    """EARS-4: set_runtime still persists correctly after the _instances fix."""
    cfg_path = tmp_path / "firewatch_config.json"
    store = _make_store(cfg_path)

    # Add _instances out-of-band so the merge path is exercised.
    upsert_instance(
        config_file=cfg_path,
        source_type="suricata",
        source_id="suricata",
        flavor="pull",
        interval=60.0,
        transport="file",
    )

    store.set_runtime({"alert_threshold": "LOW", "alert_on_sync": False})

    # Verify runtime config was persisted correctly.
    store2 = _make_store(cfg_path)
    cfg = store2.get_runtime()
    assert cfg.alert_threshold == "LOW"
    assert cfg.alert_on_sync is False


def test_source_config_not_regressed(tmp_path: Path) -> None:
    """EARS-4: set_source still persists correctly after the _instances fix."""
    cfg_path = tmp_path / "firewatch_config.json"
    store = _make_store(cfg_path)

    upsert_instance(
        config_file=cfg_path,
        source_type="suricata",
        source_id="suricata",
        flavor="pull",
        interval=60.0,
        transport="file",
    )

    store.set_source("suricata", _ExamplePluginConfig, {"port": 9999})

    # Verify source config was persisted correctly.
    store2 = _make_store(cfg_path)
    cfg = store2.get_source("suricata", _ExamplePluginConfig)
    assert cfg.port == 9999  # type: ignore[union-attr]


def test_runtime_and_instances_coexist_in_file(tmp_path: Path) -> None:
    """EARS-4: after the fix, _runtime, source sections, and _instances all coexist."""
    cfg_path = tmp_path / "firewatch_config.json"
    store = _make_store(cfg_path)

    upsert_instance(
        config_file=cfg_path,
        source_type="suricata",
        source_id="suricata",
        flavor="pull",
        interval=60.0,
        transport="file",
    )

    store.set_runtime({"alert_threshold": "CRITICAL"})
    store.set_source("suricata", _ExamplePluginConfig, {"port": 5140})

    raw = _read_raw(cfg_path)
    assert "_runtime" in raw, "_runtime section missing after fix"
    assert raw["_runtime"]["alert_threshold"] == "CRITICAL"
    assert "suricata" in raw, "suricata source section missing after fix"
    assert raw["suricata"]["port"] == 5140
    assert "_instances" in raw, "_instances missing after fix"
    assert len(raw["_instances"]) == 1


def test_instances_empty_list_when_not_set(tmp_path: Path) -> None:
    """EARS-4 (no regression on empty case): config writes work with no _instances key."""
    cfg_path = tmp_path / "firewatch_config.json"
    store = _make_store(cfg_path)

    # Normal write with no _instances in the file at all.
    store.set_runtime({"alert_threshold": "LOW"})

    raw = _read_raw(cfg_path)
    assert raw["_runtime"]["alert_threshold"] == "LOW"
    # No _instances key is fine — or it may be empty list; either is acceptable.
    instances = raw.get("_instances", [])
    assert instances == [] or "_instances" not in raw
