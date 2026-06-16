"""Tests for bind_address field on RuntimeConfig (issue #546, ADR-0026 Decision 1 & 4).

EARS acceptance criteria covered:

Ubiquitous — RuntimeConfig SHALL expose bind_address: str with default "127.0.0.1".
    -> test_bind_address_default

Event-driven — WHEN FIREWATCH_BIND_ADDRESS is set, RuntimeConfig.bind_address SHALL
    equal the env value (env > file > default, ADR-0006).
    -> test_bind_address_env_overrides_default
    -> test_bind_address_env_overrides_file

Event-driven — WHEN only firewatch_config.json carries bind_address, the resolved
    value SHALL equal the file value.
    -> test_bind_address_file_overrides_default

Unwanted-behavior — IF bind_address is set to a non-loopback value, the model itself
    SHALL NOT reject it (guard lives in MP.2, not in the field validator).
    -> test_bind_address_accepts_non_loopback_rfc5737

Ubiquitous — bind_address SHALL NOT be a SecretStr; it appears in the config schema
    like other non-secret runtime fields.
    -> test_bind_address_is_not_secretstr
    -> test_bind_address_in_model_fields_schema

State-driven — WHILE FIREWATCH_BIND_ADDRESS is set, a write to bind_address via
    set_runtime SHALL be rejected as env-locked (existing ADR-0006 env-lock behavior).
    -> test_bind_address_env_lock_rejects_write
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import SecretStr

from firewatch_sdk import RuntimeConfig


# ---------------------------------------------------------------------------
# Ubiquitous: default value
# ---------------------------------------------------------------------------


def test_bind_address_default():
    """bind_address defaults to '127.0.0.1' (ADR-0026 Decision 1 / loopback-first)."""
    cfg = RuntimeConfig()
    assert cfg.bind_address == "127.0.0.1"


# ---------------------------------------------------------------------------
# Event-driven: env > file > default precedence (via JsonFileConfigStore)
# ---------------------------------------------------------------------------


@pytest.fixture()
def cfg_path(tmp_path: Path) -> Path:
    """Temporary config file path (does not exist yet)."""
    return tmp_path / "firewatch_config.json"


def _make_store(path: Path):
    """Create a JsonFileConfigStore pointed at *path*."""
    from firewatch_core.config_store import JsonFileConfigStore

    return JsonFileConfigStore(config_file=path)


def test_bind_address_env_overrides_default(
    cfg_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """FIREWATCH_BIND_ADDRESS env var overrides the built-in default."""
    monkeypatch.setenv("FIREWATCH_BIND_ADDRESS", "192.0.2.1")
    store = _make_store(cfg_path)
    cfg = store.get_runtime()
    assert cfg.bind_address == "192.0.2.1"


def test_bind_address_env_overrides_file(
    cfg_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """FIREWATCH_BIND_ADDRESS env var wins over a file-layer value."""
    cfg_path.write_text(
        json.dumps({"_runtime": {"bind_address": "192.0.2.2"}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("FIREWATCH_BIND_ADDRESS", "192.0.2.3")
    store = _make_store(cfg_path)
    cfg = store.get_runtime()
    assert cfg.bind_address == "192.0.2.3"


def test_bind_address_file_overrides_default(cfg_path: Path):
    """A bind_address in firewatch_config.json is used when no env var is set."""
    cfg_path.write_text(
        json.dumps({"_runtime": {"bind_address": "192.0.2.10"}}),
        encoding="utf-8",
    )
    store = _make_store(cfg_path)
    cfg = store.get_runtime()
    assert cfg.bind_address == "192.0.2.10"


def test_bind_address_default_when_neither_env_nor_file(cfg_path: Path):
    """Falls back to '127.0.0.1' when neither env var nor file sets bind_address."""
    store = _make_store(cfg_path)
    cfg = store.get_runtime()
    assert cfg.bind_address == "127.0.0.1"


# ---------------------------------------------------------------------------
# Unwanted-behavior: model does NOT reject non-loopback values
# ---------------------------------------------------------------------------


def test_bind_address_accepts_non_loopback_rfc5737():
    """A non-loopback bind_address is accepted by the model (guard is in MP.2, not here).

    Uses RFC 5737 documentation IP 198.51.100.1 -- never a real routable address.
    """
    cfg = RuntimeConfig(bind_address="198.51.100.1")
    assert cfg.bind_address == "198.51.100.1"


def test_bind_address_accepts_rfc1918():
    """An RFC 1918 (private LAN) bind_address is accepted (reverse-proxy deployment)."""
    cfg = RuntimeConfig(bind_address="10.0.0.1")
    assert cfg.bind_address == "10.0.0.1"


def test_bind_address_accepts_ipv6_loopback():
    """IPv6 loopback ::1 is accepted by the model."""
    cfg = RuntimeConfig(bind_address="::1")
    assert cfg.bind_address == "::1"


# ---------------------------------------------------------------------------
# Ubiquitous: bind_address is not a SecretStr, appears in schema
# ---------------------------------------------------------------------------


def test_bind_address_is_not_secretstr():
    """bind_address is a plain str, NOT a SecretStr (it is not a secret -- ADR-0026)."""
    cfg = RuntimeConfig()
    assert not isinstance(cfg.bind_address, SecretStr)
    assert isinstance(cfg.bind_address, str)


def test_bind_address_in_model_fields_schema():
    """bind_address appears in RuntimeConfig.model_fields (non-secret, schema-discoverable)."""
    assert "bind_address" in RuntimeConfig.model_fields


def test_bind_address_visible_in_repr():
    """bind_address value is visible in repr (unlike SecretStr fields)."""
    cfg = RuntimeConfig()
    assert "127.0.0.1" in repr(cfg)


# ---------------------------------------------------------------------------
# State-driven: env-lock via set_runtime
# ---------------------------------------------------------------------------


def test_bind_address_env_lock_rejects_write(
    cfg_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """WHILE FIREWATCH_BIND_ADDRESS is set, set_runtime({'bind_address': ...}) is rejected."""
    monkeypatch.setenv("FIREWATCH_BIND_ADDRESS", "192.0.2.1")
    store = _make_store(cfg_path)

    with pytest.raises(ValueError, match="locked by env vars"):
        store.set_runtime({"bind_address": "192.0.2.50"})


def test_bind_address_write_succeeds_without_env_lock(cfg_path: Path):
    """Without env lock, set_runtime can write bind_address to the file layer."""
    store = _make_store(cfg_path)
    store.set_runtime({"bind_address": "192.0.2.20"})

    # Confirm persistence: reload from disk.
    store2 = _make_store(cfg_path)
    assert store2.get_runtime().bind_address == "192.0.2.20"


def test_bind_address_env_lock_does_not_block_other_fields(
    cfg_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Only bind_address is blocked when its env var is set; other fields can still be written."""
    monkeypatch.setenv("FIREWATCH_BIND_ADDRESS", "192.0.2.1")
    store = _make_store(cfg_path)
    # Writing a different field must succeed.
    store.set_runtime({"ollama_model": "phi3:mini"})
    assert store.get_runtime().ollama_model == "phi3:mini"
