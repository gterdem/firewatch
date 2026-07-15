"""Config schema + env>file>default resolution tests (ADR-0006)."""
import json

from firewatch_linux_auth.config import LinuxAuthConfig, build_config


class TestDefaults:
    def test_default_mode_is_auto(self):
        cfg = LinuxAuthConfig()
        assert cfg.mode == "auto"

    def test_default_auth_log_path(self):
        cfg = LinuxAuthConfig()
        assert cfg.auth_log_path == "/var/log/auth.log"

    def test_default_journalctl_bin(self):
        cfg = LinuxAuthConfig()
        assert cfg.journalctl_bin == "journalctl"


class TestConfigSchema:
    def test_model_json_schema_has_expected_fields(self):
        schema = LinuxAuthConfig.model_json_schema()
        assert "mode" in schema["properties"]
        assert "auth_log_path" in schema["properties"]
        assert "journalctl_bin" in schema["properties"]

    def test_mode_is_constrained_to_known_literals(self):
        schema = LinuxAuthConfig.model_json_schema()
        assert set(schema["properties"]["mode"]["enum"]) == {"auto", "journald", "file"}


class TestBuildConfigPrecedence:
    def test_no_file_no_env_uses_defaults(self):
        cfg = build_config(config_file=None)
        assert cfg.mode == "auto"
        assert cfg.auth_log_path == "/var/log/auth.log"

    def test_file_overrides_default(self, tmp_path):
        config_file = tmp_path / "firewatch_config.json"
        config_file.write_text(json.dumps({"linux_auth": {"mode": "file"}}))
        cfg = build_config(config_file=config_file)
        assert cfg.mode == "file"

    def test_env_overrides_file(self, tmp_path, monkeypatch):
        config_file = tmp_path / "firewatch_config.json"
        config_file.write_text(json.dumps({"linux_auth": {"mode": "file"}}))
        monkeypatch.setenv("FIREWATCH_LINUX_AUTH_MODE", "journald")
        cfg = build_config(config_file=config_file)
        assert cfg.mode == "journald"

    def test_env_auth_log_path(self, monkeypatch):
        monkeypatch.setenv("FIREWATCH_LINUX_AUTH_LOG_PATH", "/var/log/secure")
        cfg = build_config(config_file=None)
        assert cfg.auth_log_path == "/var/log/secure"

    def test_missing_config_file_is_ignored(self, tmp_path):
        missing = tmp_path / "does_not_exist.json"
        cfg = build_config(config_file=missing)
        assert cfg.mode == "auto"

    def test_malformed_config_file_falls_back_to_defaults(self, tmp_path):
        config_file = tmp_path / "firewatch_config.json"
        config_file.write_text("{not valid json")
        cfg = build_config(config_file=config_file)
        assert cfg.mode == "auto"
