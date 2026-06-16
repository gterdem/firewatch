"""Tests for instance_writer.py — _instances upsert/remove (ADR-0031 §A / issue #137).

Tests are written FIRST per the testing-conventions skill.

Test-to-EARS mapping
────────────────────
EARS-IW-1 — upsert_instance writes a new _instances entry
  test_upsert_creates_new_instance_entry

EARS-IW-2 — upsert_instance updates an existing entry (same type+id)
  test_upsert_updates_existing_entry

EARS-IW-3 — upsert_instance does NOT touch the per-source config section
  test_upsert_does_not_touch_source_config_section

EARS-IW-4 — remove_instance removes the entry; leaves config intact
  test_remove_instance_removes_entry
  test_remove_instance_leaves_source_config

EARS-IW-5 — remove_instance is idempotent (no entry = no-op)
  test_remove_instance_idempotent

EARS-IW-6 — list_instances returns entries for the writer format
  test_list_instances_after_upsert

EARS-IW-7 — persistence: upserted entry survives a fresh load
  test_upsert_survives_reload

EARS-IW-8 — multiple types coexist without clobber
  test_multiple_types_coexist
"""
from __future__ import annotations

import json
from pathlib import Path

from firewatch_core.instance_writer import remove_instance, upsert_instance
from firewatch_core.instance_loader import load_instances


# --------------------------------------------------------------------------- #
# EARS-IW-1: upsert creates new entry                                         #
# --------------------------------------------------------------------------- #


def test_upsert_creates_new_instance_entry(tmp_path: Path) -> None:
    cfg = tmp_path / "firewatch_config.json"
    cfg.write_text("{}", encoding="utf-8")

    upsert_instance(
        config_file=cfg,
        source_type="fake_pull",
        source_id="fake_pull",
        flavor="pull",
        interval=60.0,
        transport="file",
    )

    data = json.loads(cfg.read_text())
    instances = data.get("_instances", [])
    assert len(instances) == 1
    entry = instances[0]
    assert entry["source_type"] == "fake_pull"
    assert entry["source_id"] == "fake_pull"
    assert entry["flavor"] == "pull"
    assert entry["interval"] == 60.0


# --------------------------------------------------------------------------- #
# EARS-IW-2: upsert updates existing entry                                    #
# --------------------------------------------------------------------------- #


def test_upsert_updates_existing_entry(tmp_path: Path) -> None:
    cfg = tmp_path / "firewatch_config.json"
    cfg.write_text("{}", encoding="utf-8")

    upsert_instance(
        config_file=cfg,
        source_type="fake_pull",
        source_id="fake_pull",
        flavor="pull",
        interval=60.0,
        transport="file",
    )
    upsert_instance(
        config_file=cfg,
        source_type="fake_pull",
        source_id="fake_pull",
        flavor="pull",
        interval=120.0,
        transport="file",
    )

    data = json.loads(cfg.read_text())
    instances = data.get("_instances", [])
    # Only one entry — upsert replaces, not appends
    assert len(instances) == 1
    assert instances[0]["interval"] == 120.0


# --------------------------------------------------------------------------- #
# EARS-IW-3: upsert does not touch source config section                      #
# --------------------------------------------------------------------------- #


def test_upsert_does_not_touch_source_config_section(tmp_path: Path) -> None:
    cfg = tmp_path / "firewatch_config.json"
    cfg.write_text(
        json.dumps({"fake_pull": {"host": "192.0.2.10", "port": 22}}),
        encoding="utf-8",
    )

    upsert_instance(
        config_file=cfg,
        source_type="fake_pull",
        source_id="fake_pull",
        flavor="pull",
        interval=60.0,
        transport="file",
    )

    data = json.loads(cfg.read_text())
    # Source section untouched
    assert data["fake_pull"] == {"host": "192.0.2.10", "port": 22}
    assert "_instances" in data


# --------------------------------------------------------------------------- #
# EARS-IW-4: remove_instance removes entry, leaves source config              #
# --------------------------------------------------------------------------- #


def test_remove_instance_removes_entry(tmp_path: Path) -> None:
    cfg = tmp_path / "firewatch_config.json"
    cfg.write_text("{}", encoding="utf-8")

    upsert_instance(
        config_file=cfg,
        source_type="fake_pull",
        source_id="fake_pull",
        flavor="pull",
        interval=60.0,
        transport="file",
    )
    remove_instance(config_file=cfg, source_type="fake_pull", source_id="fake_pull")

    data = json.loads(cfg.read_text())
    instances = data.get("_instances", [])
    assert len(instances) == 0


def test_remove_instance_leaves_source_config(tmp_path: Path) -> None:
    cfg = tmp_path / "firewatch_config.json"
    cfg.write_text(
        json.dumps({"fake_pull": {"host": "192.0.2.10"}}),
        encoding="utf-8",
    )

    upsert_instance(
        config_file=cfg,
        source_type="fake_pull",
        source_id="fake_pull",
        flavor="pull",
        interval=60.0,
        transport="file",
    )
    remove_instance(config_file=cfg, source_type="fake_pull", source_id="fake_pull")

    data = json.loads(cfg.read_text())
    assert data["fake_pull"] == {"host": "192.0.2.10"}


# --------------------------------------------------------------------------- #
# EARS-IW-5: remove_instance is idempotent                                    #
# --------------------------------------------------------------------------- #


def test_remove_instance_idempotent(tmp_path: Path) -> None:
    cfg = tmp_path / "firewatch_config.json"
    cfg.write_text("{}", encoding="utf-8")

    # Remove from an empty config — must not raise
    remove_instance(config_file=cfg, source_type="fake_pull", source_id="fake_pull")

    data = json.loads(cfg.read_text())
    assert data.get("_instances", []) == []


# --------------------------------------------------------------------------- #
# EARS-IW-6: list_instances returns entries for the writer format             #
# --------------------------------------------------------------------------- #


def test_list_instances_after_upsert(tmp_path: Path) -> None:
    cfg = tmp_path / "firewatch_config.json"
    cfg.write_text("{}", encoding="utf-8")

    upsert_instance(
        config_file=cfg,
        source_type="fake_pull",
        source_id="fake_pull",
        flavor="pull",
        interval=45.0,
        transport="file",
    )

    instances = load_instances(cfg)
    assert len(instances) == 1
    assert instances[0].source_type == "fake_pull"
    assert instances[0].interval == 45.0


# --------------------------------------------------------------------------- #
# EARS-IW-7: upserted entry survives a fresh load                             #
# --------------------------------------------------------------------------- #


def test_upsert_survives_reload(tmp_path: Path) -> None:
    cfg = tmp_path / "firewatch_config.json"
    cfg.write_text("{}", encoding="utf-8")

    upsert_instance(
        config_file=cfg,
        source_type="fake_pull",
        source_id="fake_pull",
        flavor="pull",
        interval=90.0,
        transport="file",
    )

    # Simulate a process restart by reading the file fresh
    raw = json.loads(cfg.read_text())
    assert raw["_instances"][0]["interval"] == 90.0

    loaded = load_instances(cfg)
    assert loaded[0].interval == 90.0


# --------------------------------------------------------------------------- #
# EARS-IW-8: multiple types coexist without clobber                           #
# --------------------------------------------------------------------------- #


def test_multiple_types_coexist(tmp_path: Path) -> None:
    cfg = tmp_path / "firewatch_config.json"
    cfg.write_text("{}", encoding="utf-8")

    upsert_instance(
        config_file=cfg,
        source_type="fake_a",
        source_id="fake_a",
        flavor="pull",
        interval=60.0,
        transport="file",
    )
    upsert_instance(
        config_file=cfg,
        source_type="fake_b",
        source_id="fake_b",
        flavor="pull",
        interval=120.0,
        transport="file",
    )

    data = json.loads(cfg.read_text())
    instances = data["_instances"]
    assert len(instances) == 2
    types = {e["source_type"] for e in instances}
    assert types == {"fake_a", "fake_b"}
