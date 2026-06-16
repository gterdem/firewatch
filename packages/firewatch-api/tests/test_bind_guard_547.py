"""Tests for issue #547 — bind guard hardening: config-layer resolution.

EARS criterion → test mapping
──────────────────────────────
Unwanted — non-loopback bind_address + no api_key ⇒ startup refuses:
  TestNonLoopbackNoKeyRefusesStart
    test_nonloopback_rfc5737_no_key_raises
    test_zero_dot_zero_no_key_raises
    test_nonloopback_loopback_class_is_not_bypassed

Event-driven — loopback bind ⇒ start regardless of key:
  TestLoopbackStartsWithoutKey
    test_loopback_127_no_key_starts
    test_loopback_localhost_no_key_starts
    test_loopback_ipv6_no_key_starts

Event-driven — non-loopback + key set ⇒ start:
  TestNonLoopbackWithKeyStarts
    test_rfc5737_with_key_starts
    test_zero_dot_zero_with_key_starts

Ubiquitous — guard resolves from RuntimeConfig (file-layer):
  TestConfigLayerResolution
    test_file_layer_api_key_honored
    test_file_layer_bind_address_honored
    test_cli_host_overrides_config_bind_address
    test_env_layer_api_key_honored
    test_env_layer_bind_address_honored

Ubiquitous — malformed bind_address treated as non-loopback:
  TestMalformedBindAddress
    test_malformed_string_treated_as_nonloopback
    test_empty_string_treated_as_nonloopback

Ubiquitous — no ADR-0030 in any auth-related error/docstring:
  TestADRReferenceCorrections
    test_error_message_does_not_mention_adr_0030
    test_server_module_docstring_references_adr_0026_not_0030

Fixtures use RFC 5737 documentation IPs only:
  192.0.2.1, 198.51.100.1, 203.0.113.1 — never real/routable IPs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import SecretStr


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _guard():
    from firewatch_api.server import _check_bind_guard
    return _check_bind_guard


def _resolve(config_file: Path | None = None, cli_host: str | None = None):
    from firewatch_api.server import _resolve_startup_config
    return _resolve_startup_config(config_file=config_file, cli_host=cli_host)


# ---------------------------------------------------------------------------
# Unwanted — non-loopback + no key ⇒ refuses to start
# ---------------------------------------------------------------------------


class TestNonLoopbackNoKeyRefusesStart:
    """Non-loopback bind without api_key must always raise RuntimeError."""

    def test_nonloopback_rfc5737_no_key_raises(self) -> None:
        """RFC 5737 documentation IP (192.0.2.1) with no key must refuse."""
        with pytest.raises(RuntimeError, match="ADR-0026"):
            _guard()(host="192.0.2.1", api_key=None)

    def test_second_rfc5737_block_no_key_raises(self) -> None:
        """Second RFC 5737 block (198.51.100.1) with no key must refuse."""
        with pytest.raises(RuntimeError):
            _guard()(host="198.51.100.1", api_key=None)

    def test_third_rfc5737_block_no_key_raises(self) -> None:
        """Third RFC 5737 block (203.0.113.1) with no key must refuse."""
        with pytest.raises(RuntimeError):
            _guard()(host="203.0.113.1", api_key=None)

    def test_zero_dot_zero_no_key_raises(self) -> None:
        """0.0.0.0 (all-interfaces / unspecified) is non-loopback; guard fires."""
        with pytest.raises(RuntimeError):
            _guard()(host="0.0.0.0", api_key=None)

    def test_ipv6_any_address_no_key_raises(self) -> None:
        """:: (IPv6 all-interfaces / any-address) is non-loopback; guard fires."""
        with pytest.raises(RuntimeError):
            _guard()(host="::", api_key=None)

    def test_empty_secret_str_key_treated_as_no_key(self) -> None:
        """SecretStr('') must NOT bypass the guard — an empty key is no key.

        Security finding: the ConfigStore env-layer can produce SecretStr('')
        when FIREWATCH_API_KEY= is exported but empty.  The guard must treat
        this as absent (refuse non-loopback bind), not as a set key.
        """
        with pytest.raises(RuntimeError):
            _guard()(host="192.0.2.1", api_key=SecretStr(""))

    def test_whitespace_only_secret_str_key_treated_as_no_key(self) -> None:
        """SecretStr('   ') (whitespace only) must also be treated as absent."""
        with pytest.raises(RuntimeError):
            _guard()(host="192.0.2.1", api_key=SecretStr("   "))

    def test_nonloopback_loopback_class_is_not_bypassed(self) -> None:
        """127.0.0.0 — the network address of the loopback block — is still loopback."""
        # 127.0.0.0 is is_loopback per ipaddress; guard must NOT fire.
        _guard()(host="127.0.0.0", api_key=None)  # must not raise


# ---------------------------------------------------------------------------
# Event-driven — loopback bind ⇒ starts regardless of key presence
# ---------------------------------------------------------------------------


class TestLoopbackStartsWithoutKey:
    """Loopback binds always proceed with no key (ADR-0026 Decision 1)."""

    def test_loopback_127_no_key_starts(self) -> None:
        _guard()(host="127.0.0.1", api_key=None)  # must not raise

    def test_loopback_localhost_no_key_starts(self) -> None:
        _guard()(host="localhost", api_key=None)  # must not raise

    def test_loopback_ipv6_no_key_starts(self) -> None:
        _guard()(host="::1", api_key=None)  # must not raise

    def test_loopback_127_x_range_no_key_starts(self) -> None:
        """Any 127.x.x.x address is loopback and must not need a key."""
        _guard()(host="127.0.0.2", api_key=None)  # must not raise


# ---------------------------------------------------------------------------
# Event-driven — non-loopback + key ⇒ starts
# ---------------------------------------------------------------------------


class TestNonLoopbackWithKeyStarts:
    """Non-loopback + non-empty key set → guard permits binding."""

    def test_rfc5737_with_key_starts(self) -> None:
        """RFC 5737 IP (192.0.2.1) + non-empty key must not raise."""
        _guard()(host="192.0.2.1", api_key=SecretStr("test-key"))

    def test_second_rfc5737_with_key_starts(self) -> None:
        """198.51.100.1 + non-empty key must not raise."""
        _guard()(host="198.51.100.1", api_key=SecretStr("test-key"))

    def test_zero_dot_zero_with_key_starts(self) -> None:
        """0.0.0.0 + non-empty key must not raise."""
        _guard()(host="0.0.0.0", api_key=SecretStr("test-key"))

    def test_ipv6_any_with_key_starts(self) -> None:
        """:: (IPv6 all-interfaces) + non-empty key must not raise."""
        _guard()(host="::", api_key=SecretStr("test-key"))


# ---------------------------------------------------------------------------
# Ubiquitous — config-layer (env > file > default) resolution
# ---------------------------------------------------------------------------


class TestConfigLayerResolution:
    """Guard resolves bind_address and api_key from RuntimeConfig, not raw os.environ."""

    def test_file_layer_api_key_honored(self, tmp_path: Path) -> None:
        """A file-configured api_key is picked up even without an env var.

        Verifies that _resolve_startup_config reads from the file layer
        (ADR-0006), not only from os.environ directly.
        """
        config = tmp_path / "firewatch_config.json"
        config.write_text(json.dumps({
            "_runtime": {"api_key": "file-layer-secret"},
        }))

        with patch.dict(os.environ, {}, clear=False):
            # Ensure no env var override.
            os.environ.pop("FIREWATCH_API_KEY", None)
            bind_address, api_key = _resolve(config_file=config)

        assert api_key is not None, "file-layer api_key must be resolved"
        assert api_key.get_secret_value() == "file-layer-secret"

    def test_file_layer_bind_address_honored(self, tmp_path: Path) -> None:
        """A file-configured bind_address is used when no CLI --host is given."""
        config = tmp_path / "firewatch_config.json"
        config.write_text(json.dumps({
            "_runtime": {
                "bind_address": "192.0.2.50",
                "api_key": "key-so-guard-does-not-fire",
            },
        }))

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIREWATCH_BIND_ADDRESS", None)
            bind_address, api_key = _resolve(config_file=config, cli_host=None)

        assert bind_address == "192.0.2.50"

    def test_cli_host_overrides_config_bind_address(self, tmp_path: Path) -> None:
        """Explicit CLI --host value wins over config-file bind_address."""
        config = tmp_path / "firewatch_config.json"
        config.write_text(json.dumps({
            "_runtime": {
                "bind_address": "192.0.2.50",
                "api_key": "test-key",
            },
        }))

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIREWATCH_BIND_ADDRESS", None)
            # CLI supplies 127.0.0.1 — must win over the file's 192.0.2.50.
            bind_address, api_key = _resolve(config_file=config, cli_host="127.0.0.1")

        assert bind_address == "127.0.0.1", (
            "CLI --host must override config bind_address"
        )

    def test_env_layer_api_key_honored(self, tmp_path: Path) -> None:
        """FIREWATCH_API_KEY env var is picked up via ConfigStore (env > file > default)."""
        config = tmp_path / "firewatch_config.json"
        config.write_text("{}")

        with patch.dict(os.environ, {"FIREWATCH_API_KEY": "env-layer-key"}, clear=False):
            bind_address, api_key = _resolve(config_file=config)

        assert api_key is not None
        assert api_key.get_secret_value() == "env-layer-key"

    def test_env_layer_bind_address_honored(self, tmp_path: Path) -> None:
        """FIREWATCH_BIND_ADDRESS env var is picked up when no CLI --host is given."""
        config = tmp_path / "firewatch_config.json"
        config.write_text("{}")

        with patch.dict(
            os.environ,
            {
                "FIREWATCH_BIND_ADDRESS": "198.51.100.99",
                "FIREWATCH_API_KEY": "key-for-guard",
            },
            clear=False,
        ):
            bind_address, api_key = _resolve(config_file=config, cli_host=None)

        assert bind_address == "198.51.100.99"

    def test_default_bind_address_is_loopback(self, tmp_path: Path) -> None:
        """When no config/env overrides are present, bind_address defaults to 127.0.0.1."""
        config = tmp_path / "firewatch_config.json"
        config.write_text("{}")

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIREWATCH_BIND_ADDRESS", None)
            os.environ.pop("FIREWATCH_API_KEY", None)
            bind_address, api_key = _resolve(config_file=config)

        assert bind_address == "127.0.0.1"
        assert api_key is None

    def test_missing_config_file_falls_back_to_defaults(self, tmp_path: Path) -> None:
        """A missing config file falls back to RuntimeConfig defaults (fail-open for config, fail-closed for guard)."""
        missing = tmp_path / "does_not_exist.json"

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIREWATCH_BIND_ADDRESS", None)
            os.environ.pop("FIREWATCH_API_KEY", None)
            bind_address, api_key = _resolve(config_file=missing)

        # Should fall back to loopback default — not crash.
        assert bind_address == "127.0.0.1"
        assert api_key is None

    def test_nonloopback_file_address_no_key_guard_fires(self, tmp_path: Path) -> None:
        """End-to-end: file bind_address=non-loopback + no api_key ⇒ guard raises."""
        config = tmp_path / "firewatch_config.json"
        config.write_text(json.dumps({
            "_runtime": {"bind_address": "203.0.113.10"},
        }))

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIREWATCH_BIND_ADDRESS", None)
            os.environ.pop("FIREWATCH_API_KEY", None)
            bind_address, api_key = _resolve(config_file=config, cli_host=None)

        # Guard must fire: non-loopback + no key.
        with pytest.raises(RuntimeError, match="ADR-0026"):
            _guard()(host=bind_address, api_key=api_key)

    def test_nonloopback_file_address_with_key_guard_passes(self, tmp_path: Path) -> None:
        """End-to-end: file bind_address=non-loopback + file api_key ⇒ guard passes."""
        config = tmp_path / "firewatch_config.json"
        config.write_text(json.dumps({
            "_runtime": {
                "bind_address": "203.0.113.10",
                "api_key": "secure-key",
            },
        }))

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIREWATCH_BIND_ADDRESS", None)
            os.environ.pop("FIREWATCH_API_KEY", None)
            bind_address, api_key = _resolve(config_file=config, cli_host=None)

        # Guard must not fire: non-loopback + key is set.
        _guard()(host=bind_address, api_key=api_key)  # must not raise


# ---------------------------------------------------------------------------
# Ubiquitous — malformed bind_address treated as non-loopback (fail-closed)
# ---------------------------------------------------------------------------


class TestMalformedBindAddress:
    """Malformed or non-IP bind_address is treated as non-loopback (fail-closed)."""

    def test_malformed_string_treated_as_nonloopback(self) -> None:
        """A non-IP string that is not 'localhost' is treated as non-loopback."""
        # The guard must refuse when the address is ambiguous/invalid.
        with pytest.raises(RuntimeError):
            _guard()(host="not-a-valid-ip", api_key=None)

    def test_empty_string_treated_as_nonloopback(self) -> None:
        """An empty string bind address is treated as non-loopback (fail-closed)."""
        with pytest.raises(RuntimeError):
            _guard()(host="", api_key=None)


# ---------------------------------------------------------------------------
# Ubiquitous — ADR-0030 removed from auth-related error messages / docstrings
# ---------------------------------------------------------------------------


class TestADRReferenceCorrections:
    """No auth-related reference should attribute per-route auth to ADR-0030."""

    def _get_error_message(self, host: str = "192.0.2.1") -> str:
        with pytest.raises(RuntimeError) as exc_info:
            _guard()(host=host, api_key=None)
        return str(exc_info.value)

    def test_error_message_does_not_mention_adr_0030(self) -> None:
        """The RuntimeError from _check_bind_guard must not reference ADR-0030."""
        msg = self._get_error_message()
        assert "ADR-0030" not in msg, (
            f"Error message must not reference the unrelated ADR-0030 "
            f"(Event-Transport Buffer); got: {msg!r}"
        )

    def test_error_message_references_adr_0026(self) -> None:
        """The RuntimeError must reference ADR-0026 for traceability."""
        msg = self._get_error_message()
        assert "ADR-0026" in msg, (
            f"Error message must reference ADR-0026; got: {msg!r}"
        )

    def test_server_module_docstring_references_mp3_not_adr_0030(self) -> None:
        """server.py module docstring must not say ADR-0030 for per-route auth."""
        import firewatch_api.server as server_mod
        doc = server_mod.__doc__ or ""
        assert "ADR-0030" not in doc, (
            "server.py module docstring must not attribute per-route auth to "
            "ADR-0030 (that is the Event-Transport Buffer ADR, unrelated to auth)."
        )

    def test_check_bind_guard_docstring_does_not_reference_adr_0030(self) -> None:
        """_check_bind_guard docstring must not reference ADR-0030."""
        from firewatch_api.server import _check_bind_guard
        doc = _check_bind_guard.__doc__ or ""
        assert "ADR-0030" not in doc, (
            "_check_bind_guard docstring must not reference ADR-0030."
        )

    def test_serve_function_docstring_does_not_reference_adr_0030(self) -> None:
        """serve() docstring must not reference ADR-0030."""
        from firewatch_api.server import serve
        doc = serve.__doc__ or ""
        assert "ADR-0030" not in doc, (
            "serve() docstring must not reference ADR-0030."
        )

    def test_cmd_serve_module_docstring_does_not_reference_adr_0030(self) -> None:
        """serve.py module docstring must not reference ADR-0030."""
        import firewatch_cli.commands.serve as serve_mod
        doc = serve_mod.__doc__ or ""
        assert "ADR-0030" not in doc, (
            "firewatch_cli.commands.serve module docstring must not reference ADR-0030."
        )

    def test_resolve_startup_config_is_exported(self) -> None:
        """_resolve_startup_config must be importable from firewatch_api.server (MP.2 seam)."""
        from firewatch_api.server import _resolve_startup_config  # noqa: F401
        assert callable(_resolve_startup_config)


# ---------------------------------------------------------------------------
# Security invariant — _is_key_set treats empty / whitespace as absent
# ---------------------------------------------------------------------------


class TestIsKeySet:
    """_is_key_set is the single source of truth for 'key is configured'.

    An empty or whitespace-only SecretStr must be treated identically to None
    so that ``export FIREWATCH_API_KEY=`` cannot bypass the bind guard.
    """

    def _is_key_set(self, api_key: SecretStr | None) -> bool:
        from firewatch_api.server import _is_key_set
        return _is_key_set(api_key)

    def test_none_is_not_set(self) -> None:
        assert self._is_key_set(None) is False

    def test_empty_secret_str_is_not_set(self) -> None:
        assert self._is_key_set(SecretStr("")) is False

    def test_whitespace_only_is_not_set(self) -> None:
        assert self._is_key_set(SecretStr("   ")) is False

    def test_single_char_key_is_set(self) -> None:
        assert self._is_key_set(SecretStr("x")) is True

    def test_realistic_key_is_set(self) -> None:
        assert self._is_key_set(SecretStr("s3cr3t-token-abc123")) is True
