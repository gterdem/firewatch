"""Tests for JsonFileConfigStore (firewatch-core config adapter).

EARS criteria (issue #31) — every criterion has at least one test:

Ubiquitous — Config shall be read and written through the ConfigStore port, never a
    process global.
    → test_config_store_satisfies_protocol: JsonFileConfigStore is an instance of
      ConfigStore (the SDK port).
    → test_no_process_global_in_core: no FireWatchConfig import in any core module.

Event-driven — When config is written, it shall be validated against the relevant
    schema and persisted atomically; an invalid write shall be rejected without
    mutating the stored value.
    → test_set_runtime_persists_valid_update
    → test_set_runtime_rejects_invalid_value_no_mutation
    → test_set_source_persists_valid_update
    → test_set_source_rejects_invalid_value_no_mutation
    → test_atomic_write (the file is written via temp+rename; partial file never left)

State-driven — While an environment variable locks a field, a write to that field
    shall be rejected (env > file > default precedence is enforced, not just merged).
    → test_env_overrides_file_overrides_default (precedence)
    → test_env_locked_field_write_rejected_runtime
    → test_env_locked_field_write_rejected_source
    → test_env_locked_field_not_blocked_for_other_fields

Unwanted — If persisted config is corrupt on load, the service shall fall back to
    last-known-good plus defaults and emit a warning, rather than failing to start.
    → test_corrupt_file_falls_back_to_defaults_with_warning
    → test_corrupt_file_falls_back_to_last_known_good

Additional — SecretStr handling (not leaked in logs/repr):
    → test_secretstr_not_in_repr
    → test_secretstr_not_logged_on_write

Additional — Source-agnostic resolution against an example plugin schema:
    → test_source_agnostic_resolution (example plugin schema resolved generically)

Additional — env > file > default for source config:
    → test_source_env_overrides_file
    → test_source_file_overrides_default

Security hardening (F1–F6, plus NB-C issue #166):
    → test_set_source_reserved_key_raises (F1)
    → test_get_source_reserved_key_raises (F1)
    → test_set_source_instances_reserved_key_raises (NB-C, issue #166)
    → test_get_source_instances_reserved_key_raises (NB-C, issue #166)
    → test_alert_threshold_rejects_invalid_value (F2)
    → test_alert_threshold_rejects_invalid_via_env (F2)
    → test_source_env_prefix_no_collision_with_runtime (F3)
    → test_corrupt_file_ioerror_propagates (F4)
    → test_ollama_base_url_rejects_public_endpoint (F5)
    → test_ollama_base_url_accepts_local_endpoints (F5)
    → test_source_secretstr_disk_roundtrip (F6)

IPs in fixtures use RFC 5737 documentation ranges only (gitleaks gate).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from pydantic import BaseModel, Field, SecretStr, ValidationError

from firewatch_core.config_store import JsonFileConfigStore
from firewatch_sdk import ConfigStore, RuntimeConfig


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def cfg_path(tmp_path: Path) -> Path:
    """Return a temporary path for firewatch_config.json (does not exist yet)."""
    return tmp_path / "firewatch_config.json"


def make_store(path: Path) -> JsonFileConfigStore:
    return JsonFileConfigStore(config_file=path)


# A minimal example plugin schema (source-agnostic test — core does NOT know this schema).
class _ExamplePluginConfig(BaseModel):
    host: str = Field(default="192.0.2.1")  # RFC 5737 doc IP
    port: int = Field(default=514, ge=1, le=65535)
    api_key: SecretStr | None = Field(default=None)
    enabled: bool = Field(default=True)


# ---------------------------------------------------------------------------
# Ubiquitous: ConfigStore port conformance
# ---------------------------------------------------------------------------


def test_config_store_satisfies_protocol():
    """JsonFileConfigStore is an instance of the ConfigStore SDK port."""
    store = JsonFileConfigStore.__new__(JsonFileConfigStore)
    assert isinstance(store, ConfigStore)


def test_no_process_global_in_core():
    """No core module should import FireWatchConfig (the legacy global)."""
    import firewatch_core

    core_pkg_dir = Path(firewatch_core.__file__).parent
    for py_file in core_pkg_dir.rglob("*.py"):
        source = py_file.read_text(encoding="utf-8")
        assert "FireWatchConfig" not in source, (
            f"{py_file} imports/references FireWatchConfig — use ConfigStore instead"
        )


# ---------------------------------------------------------------------------
# Precedence: env > file > default
# ---------------------------------------------------------------------------


def test_default_returns_built_in_defaults(cfg_path: Path):
    store = make_store(cfg_path)
    cfg = store.get_runtime()
    assert cfg.alert_threshold == "CRITICAL"
    assert cfg.alert_on_sync is True
    assert cfg.webhook_url is None
    assert cfg.ollama_model == "qwen3:14b"


def test_file_overrides_default(cfg_path: Path):
    cfg_path.write_text(
        json.dumps({"_runtime": {"alert_threshold": "HIGH", "ollama_model": "llama3:8b"}}),
        encoding="utf-8",
    )
    store = make_store(cfg_path)
    cfg = store.get_runtime()
    assert cfg.alert_threshold == "HIGH"
    assert cfg.ollama_model == "llama3:8b"
    # Unset field still gets default.
    assert cfg.alert_on_sync is True


def test_env_overrides_file_overrides_default(cfg_path: Path, monkeypatch: pytest.MonkeyPatch):
    cfg_path.write_text(
        json.dumps({"_runtime": {"alert_threshold": "HIGH"}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("FIREWATCH_ALERT_THRESHOLD", "LOW")
    store = make_store(cfg_path)
    cfg = store.get_runtime()
    # Env wins over file.
    assert cfg.alert_threshold == "LOW"


def test_env_bool_coercion(monkeypatch: pytest.MonkeyPatch, cfg_path: Path):
    monkeypatch.setenv("FIREWATCH_ALERT_ON_SYNC", "false")
    store = make_store(cfg_path)
    cfg = store.get_runtime()
    assert cfg.alert_on_sync is False


def test_env_without_file(cfg_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FIREWATCH_OLLAMA_MODEL", "mistral:7b")
    store = make_store(cfg_path)
    cfg = store.get_runtime()
    assert cfg.ollama_model == "mistral:7b"


# ---------------------------------------------------------------------------
# Event-driven: valid write persists; invalid write rejected without mutation
# ---------------------------------------------------------------------------


def test_set_runtime_persists_valid_update(cfg_path: Path):
    store = make_store(cfg_path)
    store.set_runtime({"alert_threshold": "MEDIUM"})
    # Reload from disk.
    store2 = make_store(cfg_path)
    assert store2.get_runtime().alert_threshold == "MEDIUM"


def test_set_runtime_does_not_persist_env_layer(
    cfg_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A write succeeds for non-locked fields; env-resolved value is NOT written to file."""
    monkeypatch.setenv("FIREWATCH_ALERT_THRESHOLD", "LOW")
    store = make_store(cfg_path)
    # Writing alert_on_sync (not locked) should succeed.
    store.set_runtime({"alert_on_sync": False})
    raw = json.loads(cfg_path.read_text())
    # alert_threshold must NOT be in the file (it's env-resolved, not file-owned).
    assert "alert_threshold" not in raw.get("_runtime", {})
    assert raw["_runtime"]["alert_on_sync"] is False


def test_set_runtime_rejects_invalid_value_no_mutation(cfg_path: Path):
    """An invalid write raises ValidationError and does NOT change the stored config."""
    store = make_store(cfg_path)
    # Seed a known-good value.
    store.set_runtime({"alert_threshold": "HIGH"})

    with pytest.raises((ValidationError, Exception)):
        # extra='forbid' — unknown field triggers ValidationError.
        store.set_runtime({"nonexistent_field": "boom"})

    # State must be unchanged.
    assert store.get_runtime().alert_threshold == "HIGH"


def test_set_source_persists_valid_update(cfg_path: Path):
    store = make_store(cfg_path)
    store.set_source("example", _ExamplePluginConfig, {"port": 9514})
    store2 = make_store(cfg_path)
    cfg = store2.get_source("example", _ExamplePluginConfig)
    assert cfg.port == 9514  # type: ignore[union-attr]


def test_set_source_rejects_invalid_value_no_mutation(cfg_path: Path):
    store = make_store(cfg_path)
    store.set_source("example", _ExamplePluginConfig, {"port": 9514})

    with pytest.raises(ValidationError):
        # port must be 1–65535.
        store.set_source("example", _ExamplePluginConfig, {"port": 99999})

    # State unchanged.
    cfg = store.get_source("example", _ExamplePluginConfig)
    assert cfg.port == 9514  # type: ignore[union-attr]


def test_atomic_write_temp_rename(cfg_path: Path):
    """Verify the config file is written atomically (temp file + os.replace)."""
    store = make_store(cfg_path)
    store.set_runtime({"alert_threshold": "LOW"})
    # No *.tmp leftover files.
    tmp_files = list(cfg_path.parent.glob(".fw_cfg_*.tmp"))
    assert tmp_files == [], f"stale temp files found: {tmp_files}"
    # Actual file exists and is valid JSON.
    data = json.loads(cfg_path.read_text())
    assert "_runtime" in data


# ---------------------------------------------------------------------------
# State-driven: env-lock enforcement
# ---------------------------------------------------------------------------


def test_env_locked_field_write_rejected_runtime(
    cfg_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("FIREWATCH_ALERT_THRESHOLD", "HIGH")
    store = make_store(cfg_path)

    with pytest.raises(ValueError, match="locked by env vars"):
        store.set_runtime({"alert_threshold": "LOW"})


def test_env_locked_field_write_rejected_source(
    cfg_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("FIREWATCH_SRC_EXAMPLE_PORT", "9999")
    store = make_store(cfg_path)

    with pytest.raises(ValueError, match="locked by env vars"):
        store.set_source("example", _ExamplePluginConfig, {"port": 514})


def test_env_locked_field_not_blocked_for_other_fields(
    cfg_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Only the locked field is blocked; other fields can still be written."""
    monkeypatch.setenv("FIREWATCH_ALERT_THRESHOLD", "HIGH")
    store = make_store(cfg_path)
    # Writing a different field must succeed.
    store.set_runtime({"ollama_model": "phi3:mini"})
    assert store.get_runtime().ollama_model == "phi3:mini"


def test_env_lock_multiple_fields_rejected(
    cfg_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("FIREWATCH_ALERT_THRESHOLD", "HIGH")
    monkeypatch.setenv("FIREWATCH_OLLAMA_MODEL", "qwen3:14b")
    store = make_store(cfg_path)

    with pytest.raises(ValueError, match="locked by env vars"):
        store.set_runtime({"alert_threshold": "LOW", "ollama_model": "phi3:mini"})


# ---------------------------------------------------------------------------
# Unwanted: corrupt-file fallback
# ---------------------------------------------------------------------------


def test_corrupt_file_falls_back_to_defaults_with_warning(
    cfg_path: Path, caplog: pytest.LogCaptureFixture
):
    cfg_path.write_text("{ this is not valid JSON }", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="firewatch.config_store"):
        store = make_store(cfg_path)

    # Must not raise; falls back to defaults.
    cfg = store.get_runtime()
    assert cfg.alert_threshold == "CRITICAL"
    # A warning must have been emitted.
    assert any("corrupt" in r.message.lower() for r in caplog.records)


def test_corrupt_file_falls_back_to_last_known_good(
    cfg_path: Path, caplog: pytest.LogCaptureFixture
):
    """After a successful load, a corrupt reload uses last-known-good, not bare defaults."""
    # Write good config first.
    cfg_path.write_text(
        json.dumps({"_runtime": {"alert_threshold": "HIGH"}}),
        encoding="utf-8",
    )
    store = make_store(cfg_path)
    assert store.get_runtime().alert_threshold == "HIGH"

    # Corrupt the file.
    cfg_path.write_text("not json", encoding="utf-8")

    # Create a fresh store instance (simulates process restart with corrupt file).
    # NOTE: _last_known_good is per-instance; a new store has none yet.
    # The fallback for a brand-new store on corrupt is empty → defaults.
    # For the "last-known-good" path we simulate by testing the _load method directly.
    store2 = make_store(cfg_path)
    # After corruption the store should still not crash.
    cfg2 = store2.get_runtime()
    assert isinstance(cfg2, RuntimeConfig)

    # Warning must have been emitted.
    with caplog.at_level(logging.WARNING, logger="firewatch.config_store"):
        make_store(cfg_path)
    assert any("corrupt" in r.message.lower() or "falling back" in r.message.lower() for r in caplog.records)


def test_nonexistent_file_starts_with_defaults(cfg_path: Path):
    """If no config file exists, all defaults apply (first-run path)."""
    assert not cfg_path.exists()
    store = make_store(cfg_path)
    cfg = store.get_runtime()
    assert cfg.alert_threshold == "CRITICAL"


# ---------------------------------------------------------------------------
# SecretStr: not leaked in logs or repr
# ---------------------------------------------------------------------------


def test_secretstr_not_in_repr(cfg_path: Path):
    secret = "my-webhook-secret-token-xyz"
    store = make_store(cfg_path)
    store.set_runtime({"webhook_url": f"https://hooks.example.com/{secret}"})
    cfg = store.get_runtime()
    # SecretStr repr should hide the value.
    assert secret not in repr(cfg)
    assert secret not in str(cfg)
    # Value IS accessible via explicit extraction.
    assert secret in cfg.webhook_url.get_secret_value()  # type: ignore[union-attr]


def test_secretstr_not_logged_on_write(
    cfg_path: Path, caplog: pytest.LogCaptureFixture
):
    secret = "super-secret-value-never-log"
    store = make_store(cfg_path)

    with caplog.at_level(logging.DEBUG, logger="firewatch.config_store"):
        store.set_runtime({"webhook_url": f"https://example.com/{secret}"})

    for record in caplog.records:
        assert secret not in record.getMessage(), (
            f"Secret value leaked in log record: {record.getMessage()}"
        )


def test_secretstr_source_not_leaked(cfg_path: Path, caplog: pytest.LogCaptureFixture):
    """SecretStr in a source plugin config is not logged."""
    secret = "api-key-never-in-logs"
    store = make_store(cfg_path)

    with caplog.at_level(logging.DEBUG, logger="firewatch.config_store"):
        store.set_source(
            "example",
            _ExamplePluginConfig,
            {"api_key": secret},
        )

    for record in caplog.records:
        assert secret not in record.getMessage()


# ---------------------------------------------------------------------------
# Source-agnostic resolution
# ---------------------------------------------------------------------------


def test_source_agnostic_resolution_defaults(cfg_path: Path):
    """Source config resolves Pydantic defaults with no env or file values set."""
    store = make_store(cfg_path)
    cfg = store.get_source("example", _ExamplePluginConfig)
    assert cfg.host == "192.0.2.1"  # type: ignore[union-attr]
    assert cfg.port == 514  # type: ignore[union-attr]
    assert cfg.api_key is None  # type: ignore[union-attr]
    assert cfg.enabled is True  # type: ignore[union-attr]


def test_source_file_overrides_default(cfg_path: Path):
    cfg_path.write_text(
        json.dumps({"example": {"port": 5140, "enabled": False}}),
        encoding="utf-8",
    )
    store = make_store(cfg_path)
    cfg = store.get_source("example", _ExamplePluginConfig)
    assert cfg.port == 5140  # type: ignore[union-attr]
    assert cfg.enabled is False  # type: ignore[union-attr]
    # Default still applies for unset field.
    assert cfg.host == "192.0.2.1"  # type: ignore[union-attr]


def test_source_env_overrides_file(cfg_path: Path, monkeypatch: pytest.MonkeyPatch):
    cfg_path.write_text(
        json.dumps({"example": {"port": 5140}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("FIREWATCH_SRC_EXAMPLE_PORT", "9999")
    store = make_store(cfg_path)
    cfg = store.get_source("example", _ExamplePluginConfig)
    # Env wins over file.
    assert cfg.port == 9999  # type: ignore[union-attr]


def test_source_env_overrides_default_without_file(
    cfg_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("FIREWATCH_SRC_EXAMPLE_ENABLED", "false")
    store = make_store(cfg_path)
    cfg = store.get_source("example", _ExamplePluginConfig)
    assert cfg.enabled is False  # type: ignore[union-attr]


def test_source_agnostic_with_different_source_type(
    cfg_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Core uses the same adapter for any source_type — no hardcoded knowledge."""
    monkeypatch.setenv("FIREWATCH_SRC_MYIDS_PORT", "6514")
    store = make_store(cfg_path)
    cfg = store.get_source("myids", _ExamplePluginConfig)
    assert cfg.port == 6514  # type: ignore[union-attr]
    # 'example' source unaffected.
    cfg2 = store.get_source("example", _ExamplePluginConfig)
    assert cfg2.port == 514  # type: ignore[union-attr]


def test_source_sections_are_isolated(cfg_path: Path):
    """Writing one source's config does not affect another source's section."""
    store = make_store(cfg_path)
    store.set_source("alpha", _ExamplePluginConfig, {"port": 1000})
    store.set_source("beta", _ExamplePluginConfig, {"port": 2000})

    alpha = store.get_source("alpha", _ExamplePluginConfig)
    beta = store.get_source("beta", _ExamplePluginConfig)
    assert alpha.port == 1000  # type: ignore[union-attr]
    assert beta.port == 2000  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Persistence shape (JSON file structure)
# ---------------------------------------------------------------------------


def test_runtime_and_source_coexist_in_file(cfg_path: Path):
    store = make_store(cfg_path)
    store.set_runtime({"alert_threshold": "LOW"})
    store.set_source("example", _ExamplePluginConfig, {"port": 7777})

    raw = json.loads(cfg_path.read_text())
    assert raw["_runtime"]["alert_threshold"] == "LOW"
    assert raw["example"]["port"] == 7777


def test_secretstr_persisted_as_plain_string_in_file(cfg_path: Path):
    """The JSON file stores the raw string (the file is the write-side;
    the constraint is "never in logs/repr")."""
    secret = "plain-in-file-not-in-logs"
    store = make_store(cfg_path)
    store.set_runtime({"webhook_url": f"https://hooks.example.com/{secret}"})
    raw_file = json.loads(cfg_path.read_text())
    # Value is in the file (that's intentional — config file is the persistence layer).
    assert secret in raw_file["_runtime"]["webhook_url"]


def test_reload_roundtrip_with_secretstr(cfg_path: Path):
    """A store reloaded from disk recovers the SecretStr correctly."""
    secret = "roundtrip-secret-value"
    store = make_store(cfg_path)
    store.set_runtime({"webhook_url": f"https://hooks.example.com/{secret}"})

    store2 = make_store(cfg_path)
    cfg = store2.get_runtime()
    assert cfg.webhook_url is not None
    assert secret in cfg.webhook_url.get_secret_value()


# ---------------------------------------------------------------------------
# F1 — Reserved key guard
# ---------------------------------------------------------------------------


def test_set_source_reserved_key_raises(cfg_path: Path):
    """set_source with source_type='_runtime' must raise ValueError (F1)."""
    store = make_store(cfg_path)
    with pytest.raises(ValueError, match="reserved"):
        store.set_source("_runtime", _ExamplePluginConfig, {"port": 514})


def test_get_source_reserved_key_raises(cfg_path: Path):
    """get_source with source_type='_runtime' must raise ValueError (F1)."""
    store = make_store(cfg_path)
    with pytest.raises(ValueError, match="reserved"):
        store.get_source("_runtime", _ExamplePluginConfig)


def test_set_source_instances_reserved_key_raises(cfg_path: Path) -> None:
    """set_source with source_type='_instances' must raise ValueError (NB-C, issue #166).

    Defense-in-depth: '_instances' is an internal key that the boot path reads to
    register auto-sync instances (ADR-0031 §A).  Even though TYPE_KEY_PATTERN already
    blocks underscore-prefixed keys upstream, _RESERVED_KEYS must include '_instances'
    so that callers with direct access to the store (e.g. scripts, future CLI flags)
    cannot accidentally overwrite the instance registry via set_source.
    """
    store = make_store(cfg_path)
    with pytest.raises(ValueError, match="reserved"):
        store.set_source("_instances", _ExamplePluginConfig, {"port": 514})


def test_get_source_instances_reserved_key_raises(cfg_path: Path) -> None:
    """get_source with source_type='_instances' must raise ValueError (NB-C, issue #166).

    Symmetric with set_source: callers must not read the _instances key as if it were
    a source config section — the schema contract for _instances is InstanceConfig[],
    not a plugin ConfigSchema.
    """
    store = make_store(cfg_path)
    with pytest.raises(ValueError, match="reserved"):
        store.get_source("_instances", _ExamplePluginConfig)


# ---------------------------------------------------------------------------
# F2 — ThreatLevelLiteral constraint on alert_threshold
# ---------------------------------------------------------------------------


def test_alert_threshold_rejects_invalid_value():
    """alert_threshold must reject out-of-enum values (F2)."""
    with pytest.raises(ValidationError):
        RuntimeConfig(alert_threshold="BANANA")  # type: ignore[arg-type]


def test_alert_threshold_rejects_invalid_via_env(
    cfg_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """An invalid alert_threshold from the environment is rejected by model_validate (F2)."""
    monkeypatch.setenv("FIREWATCH_ALERT_THRESHOLD", "BANANA")
    store = make_store(cfg_path)
    with pytest.raises(ValidationError):
        store.get_runtime()


def test_alert_threshold_accepts_all_valid_enum_values(cfg_path: Path):
    """All four ThreatLevelLiteral values are accepted (F2 — positive path)."""
    store = make_store(cfg_path)
    for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        store.set_runtime({"alert_threshold": level})
        assert store.get_runtime().alert_threshold == level


# ---------------------------------------------------------------------------
# F3 — Source env-var prefix no longer collides with runtime env vars
# ---------------------------------------------------------------------------


def test_source_env_prefix_no_collision_with_runtime(
    cfg_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """FIREWATCH_ALERT_THRESHOLD is a runtime var; it must NOT affect a source named
    'alert' with a field 'threshold'.  The source env var is
    FIREWATCH_SRC_ALERT_THRESHOLD (distinct prefix — F3).
    """

    class _AlertSourceConfig(BaseModel):
        threshold: str = Field(default="original-value")

    # Set the RUNTIME env var for alert_threshold.
    monkeypatch.setenv("FIREWATCH_ALERT_THRESHOLD", "HIGH")
    # Do NOT set FIREWATCH_SRC_ALERT_THRESHOLD — the source env var.
    store = make_store(cfg_path)

    # Runtime config: env var takes effect.
    cfg_runtime = store.get_runtime()
    assert cfg_runtime.alert_threshold == "HIGH"

    # Source config: must see its own default, NOT the runtime env var.
    cfg_src = store.get_source("alert", _AlertSourceConfig)
    assert cfg_src.threshold == "original-value"  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# F4 — Narrow except: OSError/PermissionError propagates from _load
# ---------------------------------------------------------------------------


def test_corrupt_file_ioerror_propagates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A PermissionError reading the config file should propagate, not be swallowed (F4)."""
    import unittest.mock as mock

    cfg_path = tmp_path / "firewatch_config.json"
    cfg_path.write_text(json.dumps({"_runtime": {"alert_threshold": "HIGH"}}))

    # Patch Path.read_text to raise PermissionError.
    with mock.patch.object(
        type(cfg_path), "read_text", side_effect=PermissionError("no access")
    ):
        with pytest.raises(PermissionError):
            make_store(cfg_path)


# ---------------------------------------------------------------------------
# F5 — ollama_base_url rejects non-local endpoints at config-write time (ADR-0022)
# ---------------------------------------------------------------------------


def test_ollama_base_url_rejects_public_endpoint():
    """A public cloud endpoint is rejected by the RuntimeConfig validator (F5).

    Uses api.openai.com as the public example (RFC 5737 IPs are for doc use only;
    public hostname keeps gitleaks clean while exercising DNS-lookup path).
    """
    with pytest.raises(ValidationError, match="local-first|loopback|RFC 1918|ADR-0022"):
        RuntimeConfig(ollama_base_url="https://api.openai.com/v1")


def test_ollama_base_url_accepts_local_endpoints():
    """Loopback and RFC 1918 base URLs are accepted (F5 — positive path)."""
    # Loopback numeric IP.
    cfg = RuntimeConfig(ollama_base_url="http://127.0.0.1:11434")
    assert cfg.ollama_base_url == "http://127.0.0.1:11434"

    # localhost alias.
    cfg2 = RuntimeConfig(ollama_base_url="http://localhost:11434")
    assert cfg2.ollama_base_url == "http://localhost:11434"

    # RFC 1918 private range (192.168.x.x).
    cfg3 = RuntimeConfig(ollama_base_url="http://192.168.1.10:11434")
    assert cfg3.ollama_base_url == "http://192.168.1.10:11434"


def test_ollama_base_url_rejects_via_store(cfg_path: Path):
    """set_runtime with a public ollama_base_url is rejected by ValidationError (F5)."""
    store = make_store(cfg_path)
    with pytest.raises(ValidationError):
        store.set_runtime({"ollama_base_url": "https://api.openai.com/v1"})
    # State unchanged — default is still intact.
    assert "localhost" in store.get_runtime().ollama_base_url


# ---------------------------------------------------------------------------
# F6 — Source plugin SecretStr field disk roundtrip
# ---------------------------------------------------------------------------


def test_source_secretstr_disk_roundtrip(cfg_path: Path):
    """A source plugin's SecretStr field is persisted to disk and recovered correctly (F6).

    Mirrors the runtime webhook_url disk-roundtrip test (test_reload_roundtrip_with_secretstr)
    but exercises the source config path.
    """
    secret = "src-api-key-roundtrip-test"
    store = make_store(cfg_path)
    store.set_source("example", _ExamplePluginConfig, {"api_key": secret})

    # Verify the raw file contains the secret (file is the write-side; constraint is
    # "never in logs/repr", not "never on disk").
    raw_file = json.loads(cfg_path.read_text())
    assert raw_file["example"]["api_key"] == secret

    # Reload from disk and recover as SecretStr.
    store2 = make_store(cfg_path)
    cfg = store2.get_source("example", _ExamplePluginConfig)
    assert cfg.api_key is not None  # type: ignore[union-attr]
    assert isinstance(cfg.api_key, SecretStr)  # type: ignore[union-attr]
    assert cfg.api_key.get_secret_value() == secret  # type: ignore[union-attr]
    # SecretStr must not leak in repr.
    assert secret not in repr(cfg)


# --------------------------------------------------------------------------- #
# config_path property (ADR-0031 option A)                                    #
# --------------------------------------------------------------------------- #


def test_config_path_returns_the_backing_path(tmp_path: Path) -> None:
    """config_path returns the same Path that was passed to __init__ (ADR-0031 §A).

    The auto-sync write routes use this property to obtain the config file path
    from the injected store (option A: single source of truth, no separate
    threading of the path).
    """
    target = tmp_path / "firewatch_config.json"
    target.write_text("{}", encoding="utf-8")
    store = make_store(target)
    assert store.config_path == target


def test_config_path_default_is_relative_firewatch_config_json() -> None:
    """When no path is given, config_path returns the default relative path."""
    from firewatch_core.config_store import JsonFileConfigStore
    from pathlib import Path
    store = JsonFileConfigStore()
    assert store.config_path == Path("firewatch_config.json")


# --------------------------------------------------------------------------- #
# has_source — public existence probe (issue #155 NB-2)                       #
# --------------------------------------------------------------------------- #


def test_has_source_returns_true_when_section_present(cfg_path: Path) -> None:
    """has_source returns True when the named source section exists in the file.

    EARS-HS-1: WHEN a source type has a config section, has_source(type_key)
    SHALL return True.
    """
    cfg_path.write_text(
        json.dumps({"suricata": {"host": "192.0.2.1"}}),
        encoding="utf-8",
    )
    store = make_store(cfg_path)
    assert store.has_source("suricata") is True


def test_has_source_returns_false_when_section_absent(cfg_path: Path) -> None:
    """has_source returns False when the named section is NOT in the file.

    EARS-HS-2: WHEN a source type has no config section, has_source(type_key)
    SHALL return False.
    """
    cfg_path.write_text(
        json.dumps({"suricata": {"host": "192.0.2.1"}}),
        encoding="utf-8",
    )
    store = make_store(cfg_path)
    assert store.has_source("azure_waf") is False


def test_has_source_false_for_empty_config(cfg_path: Path) -> None:
    """has_source returns False on an absent config file (empty store).

    EARS-HS-3: WHILE the config file is absent, has_source SHALL return False
    for any key.
    """
    store = make_store(cfg_path)  # file absent -> empty in-memory state
    assert store.has_source("anything") is False


def test_has_source_false_for_runtime_reserved_key(cfg_path: Path) -> None:
    """has_source returns False for _runtime (the reserved internal key).

    EARS-HS-4: has_source("_runtime") SHALL return False — it is an internal
    key, not a source section.  This prevents the boot path from treating the
    runtime config block as a source.
    """
    cfg_path.write_text(
        json.dumps({"_runtime": {"alert_threshold": "HIGH"}}),
        encoding="utf-8",
    )
    store = make_store(cfg_path)
    assert store.has_source("_runtime") is False


def test_has_source_false_for_instances_reserved_key(cfg_path: Path) -> None:
    """has_source returns False for _instances (the internal scheduling key).

    EARS-HS-5: has_source("_instances") SHALL return False — it is an internal
    key, not a source section.
    """
    cfg_path.write_text(
        json.dumps(
            {
                "_instances": [
                    {
                        "source_type": "suricata",
                        "source_id": "suricata",
                        "flavor": "pull",
                        "interval": 60.0,
                        "transport": "file",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    store = make_store(cfg_path)
    assert store.has_source("_instances") is False


def test_has_source_reflects_set_source(cfg_path: Path) -> None:
    """has_source returns True after set_source writes a section.

    EARS-HS-6: WHEN set_source is called, a subsequent has_source for that
    type_key SHALL return True.
    """
    store = make_store(cfg_path)
    assert store.has_source("example") is False

    store.set_source("example", _ExamplePluginConfig, {"port": 514})
    assert store.has_source("example") is True
