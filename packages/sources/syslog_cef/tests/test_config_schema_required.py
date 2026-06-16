"""Tests for SyslogCefConfig JSON-schema `required` UI hint (issue #686).

EARS-686-C1  model_json_schema()["required"] contains exactly "bind" and "port".
EARS-686-C2  No other field (protocol, batch_size, max_connections, idle_timeout,
             max_line_length) is listed in `required`.
EARS-686-C3  Property schemas for bind and port still carry their `default` values
             (127.0.0.1 / 5515) — configure-with-defaults is unchanged.
EARS-686-C4  build_config(None) still returns the model with default bind/port
             when no env vars are set.
EARS-686-C5  SyslogCefConfig.model_validate({}) succeeds with no fields supplied —
             the `required` UI hint does NOT make Pydantic reject empty input.
"""
from __future__ import annotations

import pytest

from firewatch_syslog_cef.config import SyslogCefConfig, build_config

# Fields that must NOT be in required (they are Advanced/Optional in the UI)
_ADVANCED_FIELDS = {"protocol", "batch_size", "max_connections", "idle_timeout", "max_line_length"}


class TestSyslogCefConfigSchemaRequired:
    """EARS-686-C1 through EARS-686-C5."""

    def test_required_contains_bind_and_port(self) -> None:
        """EARS-686-C1: required array contains both bind and port."""
        schema = SyslogCefConfig.model_json_schema()
        required: list[str] = schema.get("required", [])
        assert "bind" in required, "bind must be in schema required (Essential UI hint)"
        assert "port" in required, "port must be in schema required (Essential UI hint)"

    def test_required_does_not_contain_advanced_fields(self) -> None:
        """EARS-686-C2: advanced fields must NOT be in required."""
        schema = SyslogCefConfig.model_json_schema()
        required_set = set(schema.get("required", []))
        unexpected = required_set & _ADVANCED_FIELDS
        assert not unexpected, (
            f"Advanced fields must not appear in schema required: {unexpected}"
        )

    def test_required_is_exactly_bind_and_port(self) -> None:
        """EARS-686-C1+C2 combined: required is exactly {bind, port}, no extras."""
        schema = SyslogCefConfig.model_json_schema()
        required_set = set(schema.get("required", []))
        assert required_set == {"bind", "port"}, (
            f"Expected required={{bind, port}}, got {required_set}"
        )

    def test_bind_property_still_has_default(self) -> None:
        """EARS-686-C3: bind property schema retains its default value."""
        schema = SyslogCefConfig.model_json_schema()
        props = schema.get("properties", {})
        bind_schema = props.get("bind", {})
        assert "default" in bind_schema, "bind must still carry a default in property schema"
        assert bind_schema["default"] == "127.0.0.1"

    def test_port_property_still_has_default(self) -> None:
        """EARS-686-C3: port property schema retains its default value."""
        schema = SyslogCefConfig.model_json_schema()
        props = schema.get("properties", {})
        port_schema = props.get("port", {})
        assert "default" in port_schema, "port must still carry a default in property schema"
        assert port_schema["default"] == 5515

    def test_build_config_uses_defaults_when_no_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """EARS-686-C4: build_config(None) returns default bind/port with no env vars."""
        for env_var in (
            "FIREWATCH_SYSLOG_CEF_BIND",
            "FIREWATCH_SYSLOG_CEF_PORT",
            "FIREWATCH_SYSLOG_CEF_PROTOCOL",
            "FIREWATCH_SYSLOG_CEF_BATCH_SIZE",
            "FIREWATCH_SYSLOG_CEF_MAX_CONNECTIONS",
            "FIREWATCH_SYSLOG_CEF_IDLE_TIMEOUT",
            "FIREWATCH_SYSLOG_CEF_MAX_LINE_LENGTH",
        ):
            monkeypatch.delenv(env_var, raising=False)

        cfg = build_config(None)
        assert cfg.bind == "127.0.0.1"
        assert cfg.port == 5515

    def test_model_validate_empty_dict_succeeds(self) -> None:
        """EARS-686-C5: required is a UI hint only — Pydantic accepts {} without error."""
        # This must not raise — defaults kick in
        cfg = SyslogCefConfig.model_validate({})
        assert cfg.bind == "127.0.0.1"
        assert cfg.port == 5515
