"""Tests for the ConfigStore port and RuntimeConfig model (SDK-level).

EARS criteria covered here (issue #31):
- Ubiquitous: ConfigStore is a typing.Protocol (shape-only in SDK; no implementation).
- RuntimeConfig uses SecretStr for webhook_url — secret never leaks in repr/str.
- ConfigStore is @runtime_checkable — a conforming object satisfies isinstance().
"""
from __future__ import annotations

import typing

import pytest
from pydantic import SecretStr, ValidationError

from firewatch_sdk import ConfigStore, RuntimeConfig


# ---------------------------------------------------------------------------
# RuntimeConfig model
# ---------------------------------------------------------------------------


def test_runtime_config_defaults():
    cfg = RuntimeConfig()
    assert cfg.alert_threshold == "CRITICAL"
    assert cfg.alert_on_sync is True
    assert cfg.webhook_url is None
    assert cfg.ollama_model == "qwen3:14b"


def test_runtime_config_webhook_url_is_secretstr():
    # Pydantic v2 coerces str → SecretStr; pass SecretStr explicitly for static typing.
    cfg = RuntimeConfig(webhook_url=SecretStr("https://hooks.example.com/secret-token-abc"))
    assert isinstance(cfg.webhook_url, SecretStr)


def test_runtime_config_secretstr_not_in_repr():
    """SecretStr must not leak the secret in repr or str (PLUGIN_CONTRACT.md hard rule)."""
    secret = "hunter2-should-not-appear"
    cfg = RuntimeConfig(webhook_url=SecretStr(f"https://example.com/{secret}"))
    assert secret not in repr(cfg)
    assert secret not in str(cfg)
    # The value IS accessible via get_secret_value() — that's the explicit extraction path.
    assert secret in cfg.webhook_url.get_secret_value()  # type: ignore[union-attr]


def test_runtime_config_rejects_unknown_fields():
    """extra='forbid' — unknown keys raise ValidationError."""
    with pytest.raises(ValidationError):
        RuntimeConfig(unknown_field="oops")  # type: ignore[call-arg]


def test_runtime_config_accepts_valid_thresholds():
    for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        cfg = RuntimeConfig(alert_threshold=level)
        assert cfg.alert_threshold == level


def test_runtime_config_rejects_invalid_alert_threshold():
    """alert_threshold must be a ThreatLevelLiteral — reject arbitrary strings (F2)."""
    with pytest.raises(ValidationError):
        RuntimeConfig(alert_threshold="BANANA")  # type: ignore[arg-type]


def test_ollama_base_url_rejects_public_endpoint():
    """A cloud base_url is rejected at model construction time (F5 / ADR-0022)."""
    with pytest.raises(ValidationError):
        RuntimeConfig(ollama_base_url="https://api.openai.com/v1")


def test_ollama_base_url_accepts_loopback():
    """Loopback address is accepted for ollama_base_url (F5 — positive path)."""
    cfg = RuntimeConfig(ollama_base_url="http://127.0.0.1:11434")
    assert cfg.ollama_base_url == "http://127.0.0.1:11434"


# ---------------------------------------------------------------------------
# ConfigStore port
# ---------------------------------------------------------------------------


def _is_protocol(cls: type) -> bool:
    is_protocol = getattr(typing, "is_protocol", None)
    if is_protocol is not None:
        return is_protocol(cls)
    return bool(getattr(cls, "_is_protocol", False))


def test_config_store_is_protocol():
    assert _is_protocol(ConfigStore)


def test_config_store_is_runtime_checkable():
    """A concrete object that satisfies the structural shape is an instance."""

    class MinimalConfigStore:
        def get_runtime(self) -> RuntimeConfig:
            return RuntimeConfig()

        def set_runtime(self, updates: dict) -> None:  # type: ignore[type-arg]
            pass

        def get_source(self, source_type: str, schema: type) -> object:  # type: ignore[override]
            return schema()

        def set_source(self, source_type: str, schema: type, updates: dict) -> None:  # type: ignore[type-arg,override]
            pass

    assert isinstance(MinimalConfigStore(), ConfigStore)
    assert not isinstance(object(), ConfigStore)


def test_config_store_exported_from_sdk():
    """ConfigStore and RuntimeConfig are top-level SDK exports."""
    import firewatch_sdk

    assert hasattr(firewatch_sdk, "ConfigStore")
    assert hasattr(firewatch_sdk, "RuntimeConfig")
    assert "ConfigStore" in firewatch_sdk.__all__
    assert "RuntimeConfig" in firewatch_sdk.__all__
