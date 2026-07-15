"""``ClamAVConfig`` / ``build_config`` — schema shape, mode toggle, env>file>default (ADR-0006)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import BaseModel

from firewatch_clamav.config import ClamAVConfig, build_config


class TestConfigSchema:
    def test_returns_pydantic_model_class(self) -> None:
        assert issubclass(ClamAVConfig, BaseModel)

    def test_default_mode_is_journald(self) -> None:
        assert ClamAVConfig().mode == "journald"

    def test_default_identifiers_cover_daemon_and_on_access(self) -> None:
        cfg = ClamAVConfig()
        assert "clamd" in cfg.identifiers
        assert "clamonacc" in cfg.identifiers

    def test_default_log_path_is_set(self) -> None:
        assert ClamAVConfig().log_path

    def test_default_follow_symlinks_is_false(self) -> None:
        assert ClamAVConfig().follow_symlinks is False

    def test_validate_config_accepts_minimal_config(self) -> None:
        ClamAVConfig.model_validate({})

    def test_validate_config_accepts_file_mode(self) -> None:
        cfg = ClamAVConfig.model_validate({"mode": "file", "log_path": "/var/log/clamav/clamav.log"})
        assert cfg.mode == "file"

    def test_validate_config_rejects_unknown_mode(self) -> None:
        with pytest.raises(Exception):
            ClamAVConfig.model_validate({"mode": "ssh"})

    def test_journalctl_bin_is_not_a_configurable_field(self) -> None:
        """See config.py's docstring: exposing a bare PATH-resolved binary name through
        a schema-driven Settings card is a PATH-hijack surface (JournaldReader's own
        docstring warning) — deliberately not surfaced."""
        assert "journalctl_bin" not in ClamAVConfig.model_fields


class TestIfThenElseSchema:
    """ADR-0019 — the rjsf mode toggle reveals only mode-relevant fields."""

    def test_schema_has_if_then_else(self) -> None:
        schema = ClamAVConfig.model_json_schema()
        assert "if" in schema
        assert "then" in schema
        assert "else" in schema

    def test_file_only_fields_not_in_top_level_properties(self) -> None:
        schema = ClamAVConfig.model_json_schema()
        top_level = schema["properties"]
        assert "log_path" not in top_level
        assert "follow_symlinks" not in top_level

    def test_journald_only_field_not_in_top_level_properties(self) -> None:
        schema = ClamAVConfig.model_json_schema()
        assert "identifiers" not in schema["properties"]

    def test_file_only_fields_revealed_in_then_branch(self) -> None:
        schema = ClamAVConfig.model_json_schema()
        then_props = schema["then"]["properties"]
        assert "log_path" in then_props
        assert "follow_symlinks" in then_props

    def test_identifiers_revealed_in_else_branch(self) -> None:
        schema = ClamAVConfig.model_json_schema()
        else_props = schema["else"]["properties"]
        assert "identifiers" in else_props


class TestBuildConfigPrecedence:
    """ADR-0006 — env vars > firewatch_config.json > hardcoded defaults."""

    def test_defaults_when_no_file_no_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in (
            "FIREWATCH_CLAMAV_MODE", "FIREWATCH_CLAMAV_IDENTIFIERS",
            "FIREWATCH_CLAMAV_LOG_PATH", "FIREWATCH_CLAMAV_FOLLOW_SYMLINKS",
        ):
            monkeypatch.delenv(var, raising=False)

        cfg = build_config(config_file=None)
        assert cfg.mode == "journald"

    def test_file_overrides_default(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in (
            "FIREWATCH_CLAMAV_MODE", "FIREWATCH_CLAMAV_IDENTIFIERS",
            "FIREWATCH_CLAMAV_LOG_PATH", "FIREWATCH_CLAMAV_FOLLOW_SYMLINKS",
        ):
            monkeypatch.delenv(var, raising=False)

        config_file = tmp_path / "firewatch_config.json"
        config_file.write_text(json.dumps({"clamav": {"mode": "file", "log_path": "/opt/clamav.log"}}))

        cfg = build_config(config_file=config_file)
        assert cfg.mode == "file"
        assert cfg.log_path == "/opt/clamav.log"

    def test_env_overrides_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config_file = tmp_path / "firewatch_config.json"
        config_file.write_text(json.dumps({"clamav": {"mode": "file"}}))
        monkeypatch.setenv("FIREWATCH_CLAMAV_MODE", "journald")

        cfg = build_config(config_file=config_file)
        assert cfg.mode == "journald"

    def test_env_identifiers_comma_split(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FIREWATCH_CLAMAV_IDENTIFIERS", "clamd, clamonacc, clamscan")
        cfg = build_config(config_file=None)
        assert cfg.identifiers == ["clamd", "clamonacc", "clamscan"]

    def test_env_follow_symlinks_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FIREWATCH_CLAMAV_FOLLOW_SYMLINKS", "true")
        cfg = build_config(config_file=None)
        assert cfg.follow_symlinks is True

    def test_env_follow_symlinks_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FIREWATCH_CLAMAV_FOLLOW_SYMLINKS", "false")
        cfg = build_config(config_file=None)
        assert cfg.follow_symlinks is False

    def test_missing_config_file_falls_back_to_defaults(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for var in (
            "FIREWATCH_CLAMAV_MODE", "FIREWATCH_CLAMAV_IDENTIFIERS",
            "FIREWATCH_CLAMAV_LOG_PATH", "FIREWATCH_CLAMAV_FOLLOW_SYMLINKS",
        ):
            monkeypatch.delenv(var, raising=False)
        cfg = build_config(config_file=tmp_path / "does-not-exist.json")
        assert cfg.mode == "journald"
