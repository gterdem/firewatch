"""Tests for SyslogConfig JSON-schema `required` UI hint (issue #686).

EARS-686-S1  model_json_schema()["required"] contains exactly "bind" and "port".
EARS-686-S2  No other field (protocol, batch_size, max_connections, idle_timeout,
             max_line_length) is listed in `required`.
EARS-686-S3  Property schemas for bind and port still carry their `default` values
             (127.0.0.1 / 5514) — configure-with-defaults is unchanged.
EARS-686-S4  build_config(None) still returns the model with default bind/port
             when no env vars are set.
EARS-686-S5  SyslogConfig.model_validate({}) succeeds with no fields supplied —
             the `required` UI hint does NOT make Pydantic reject empty input.
"""
from __future__ import annotations

import pytest

from firewatch_syslog.config import SyslogConfig, build_config

# Fields that must NOT be in required (they are Advanced/Optional in the UI)
_ADVANCED_FIELDS = {"protocol", "batch_size", "max_connections", "idle_timeout", "max_line_length"}


class TestSyslogConfigSchemaRequired:
    """EARS-686-S1 through EARS-686-S5."""

    def test_required_contains_bind_and_port(self) -> None:
        """EARS-686-S1: required array contains both bind and port."""
        schema = SyslogConfig.model_json_schema()
        required: list[str] = schema.get("required", [])
        assert "bind" in required, "bind must be in schema required (Essential UI hint)"
        assert "port" in required, "port must be in schema required (Essential UI hint)"

    def test_required_does_not_contain_advanced_fields(self) -> None:
        """EARS-686-S2: advanced fields must NOT be in required."""
        schema = SyslogConfig.model_json_schema()
        required_set = set(schema.get("required", []))
        unexpected = required_set & _ADVANCED_FIELDS
        assert not unexpected, (
            f"Advanced fields must not appear in schema required: {unexpected}"
        )

    def test_required_is_exactly_bind_and_port(self) -> None:
        """EARS-686-S1+S2 combined: required is exactly {bind, port}, no extras."""
        schema = SyslogConfig.model_json_schema()
        required_set = set(schema.get("required", []))
        assert required_set == {"bind", "port"}, (
            f"Expected required={{bind, port}}, got {required_set}"
        )

    def test_bind_property_still_has_default(self) -> None:
        """EARS-686-S3: bind property schema retains its default value."""
        schema = SyslogConfig.model_json_schema()
        props = schema.get("properties", {})
        bind_schema = props.get("bind", {})
        assert "default" in bind_schema, "bind must still carry a default in property schema"
        assert bind_schema["default"] == "127.0.0.1"

    def test_port_property_still_has_default(self) -> None:
        """EARS-686-S3: port property schema retains its default value."""
        schema = SyslogConfig.model_json_schema()
        props = schema.get("properties", {})
        port_schema = props.get("port", {})
        assert "default" in port_schema, "port must still carry a default in property schema"
        assert port_schema["default"] == 5514

    def test_build_config_uses_defaults_when_no_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """EARS-686-S4: build_config(None) returns default bind/port with no env vars."""
        # Remove any stray env vars that might affect the result
        for env_var in (
            "FIREWATCH_SYSLOG_BIND",
            "FIREWATCH_SYSLOG_PORT",
            "FIREWATCH_SYSLOG_PROTOCOL",
            "FIREWATCH_SYSLOG_BATCH_SIZE",
            "FIREWATCH_SYSLOG_MAX_CONNECTIONS",
            "FIREWATCH_SYSLOG_IDLE_TIMEOUT",
            "FIREWATCH_SYSLOG_MAX_LINE_LENGTH",
        ):
            monkeypatch.delenv(env_var, raising=False)

        cfg = build_config(None)
        assert cfg.bind == "127.0.0.1"
        assert cfg.port == 5514

    def test_model_validate_empty_dict_succeeds(self) -> None:
        """EARS-686-S5: required is a UI hint only — Pydantic accepts {} without error."""
        # This must not raise — defaults kick in
        cfg = SyslogConfig.model_validate({})
        assert cfg.bind == "127.0.0.1"
        assert cfg.port == 5514
