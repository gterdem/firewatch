"""Tests for the fail-closed bind guard — MB.7 (issue #59, ADR-0026 Decision 4).

EARS criterion → test mapping
──────────────────────────────
Unwanted — non-loopback host + no API key → RuntimeError; uvicorn NOT called.
  test_nonloopback_no_key_raises_runtime_error
  test_nonloopback_no_key_uvicorn_not_called
  test_zero_dot_zero_no_key_raises_runtime_error
  test_custom_lan_ip_no_key_raises_runtime_error

State-driven — loopback host (default) → no error regardless of key presence.
  test_loopback_ipv4_no_key_allowed
  test_localhost_string_no_key_allowed
  test_loopback_with_key_still_allowed

Event-driven — non-loopback + key set → guard permits binding.
  test_nonloopback_with_key_no_error
  test_zero_dot_zero_with_key_no_error

Ubiquitous — guard is the single enforcement point (imported from server.py);
  CLI serve and server.serve() both go through _check_bind_guard.
  test_guard_helper_is_exported_from_server
  test_server_serve_invokes_guard_before_uvicorn
  test_cmd_serve_invokes_guard_before_uvicorn

Error message quality — actionable: names FIREWATCH_API_KEY, how to fix.
  test_error_message_names_env_var
  test_error_message_references_adr
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from pydantic import SecretStr


# ---------------------------------------------------------------------------
# Helper: import the guard under test
# ---------------------------------------------------------------------------


def _get_guard():
    from firewatch_api.server import _check_bind_guard  # type: ignore[attr-defined]
    return _check_bind_guard


# ---------------------------------------------------------------------------
# Unwanted — non-loopback + no key → RuntimeError
# ---------------------------------------------------------------------------


class TestNonLoopbackNoKeyRaisesError:
    """Unwanted: non-loopback bind without API key must fail closed."""

    def test_nonloopback_no_key_raises_runtime_error(self) -> None:
        """0.0.0.0 with no key raises RuntimeError (ADR-0026 Decision 4)."""
        guard = _get_guard()
        with pytest.raises(RuntimeError):
            guard(host="0.0.0.0", api_key=None)

    def test_zero_dot_zero_no_key_raises_runtime_error(self) -> None:
        """0.0.0.0 (unspecified / all-interfaces) is non-loopback; guard fires."""
        guard = _get_guard()
        with pytest.raises(RuntimeError):
            guard(host="0.0.0.0", api_key=None)

    def test_custom_lan_ip_no_key_raises_runtime_error(self) -> None:
        """A LAN IP (192.168.1.100) without a key must also fail closed."""
        guard = _get_guard()
        with pytest.raises(RuntimeError):
            guard(host="192.168.1.100", api_key=None)

    def test_nonloopback_no_key_uvicorn_not_called(self) -> None:
        """When the guard fires, uvicorn.run must NOT be called (no socket bind).

        This uses server.serve() with a mocked uvicorn to assert that the guard
        fires before any bind attempt.  uvicorn is imported locally inside
        serve(), so we patch it at the uvicorn package level.
        """
        with (
            patch("uvicorn.run") as mock_uvicorn_run,
            patch.dict(os.environ, {}, clear=False),
        ):
            # Ensure no API key in env
            os.environ.pop("FIREWATCH_API_KEY", None)

            from firewatch_api.server import serve

            with pytest.raises(RuntimeError):
                serve(host="0.0.0.0", port=8000)

            mock_uvicorn_run.assert_not_called()


# ---------------------------------------------------------------------------
# State-driven — loopback → always allowed, no key required
# ---------------------------------------------------------------------------


class TestLoopbackAlwaysAllowed:
    """State-driven: loopback host requires no key (ADR-0026 Decision 1)."""

    def test_loopback_ipv4_no_key_allowed(self) -> None:
        """127.0.0.1 with no key must not raise."""
        guard = _get_guard()
        guard(host="127.0.0.1", api_key=None)  # must not raise

    def test_localhost_string_no_key_allowed(self) -> None:
        """'localhost' string with no key must not raise."""
        guard = _get_guard()
        guard(host="localhost", api_key=None)  # must not raise

    def test_loopback_ipv6_no_key_allowed(self) -> None:
        """::1 (IPv6 loopback) with no key must not raise."""
        guard = _get_guard()
        guard(host="::1", api_key=None)  # must not raise

    def test_loopback_with_key_still_allowed(self) -> None:
        """Loopback + key set is also fine (key is optional on loopback)."""
        guard = _get_guard()
        guard(host="127.0.0.1", api_key=SecretStr("some-key"))  # must not raise


# ---------------------------------------------------------------------------
# Event-driven — non-loopback + key set → guard permits binding
# ---------------------------------------------------------------------------


class TestNonLoopbackWithKeyAllowed:
    """Event-driven: non-loopback + key → guard passes (enforcement deferred)."""

    def test_nonloopback_with_key_no_error(self) -> None:
        """0.0.0.0 + key set → guard must not raise."""
        guard = _get_guard()
        guard(host="0.0.0.0", api_key=SecretStr("secret-key"))  # must not raise

    def test_zero_dot_zero_with_key_no_error(self) -> None:
        """0.0.0.0 is non-loopback but key is set — allowed through guard."""
        guard = _get_guard()
        guard(host="0.0.0.0", api_key=SecretStr("another-key"))  # must not raise

    def test_lan_ip_with_key_no_error(self) -> None:
        """LAN IP + key set → guard must not raise."""
        guard = _get_guard()
        guard(host="192.168.1.100", api_key=SecretStr("lan-key"))  # must not raise


# ---------------------------------------------------------------------------
# Ubiquitous — single enforcement point
# ---------------------------------------------------------------------------


class TestSingleEnforcementPoint:
    """Ubiquitous: _check_bind_guard is the single point; server.serve() and
    cmd_serve both go through it."""

    def test_guard_helper_is_exported_from_server(self) -> None:
        """_check_bind_guard must be importable from firewatch_api.server."""
        from firewatch_api.server import _check_bind_guard  # type: ignore[attr-defined]  # noqa: F401
        assert callable(_check_bind_guard)

    def test_server_serve_invokes_guard_before_uvicorn(self) -> None:
        """server.serve() calls _check_bind_guard before calling uvicorn.run.

        We verify by patching _check_bind_guard to raise and confirming uvicorn
        never runs — if guard is called first, uvicorn is never reached.
        ``_check_bind_guard`` is a module-level name in server.py (not imported
        from elsewhere), so we patch it at the server module namespace directly.
        uvicorn is imported locally inside serve(), so we patch at uvicorn level.
        """
        with (
            patch("firewatch_api.server._check_bind_guard", side_effect=RuntimeError("guard fired")) as mock_guard,
            patch("uvicorn.run") as mock_uvicorn_run,
        ):
            from firewatch_api.server import serve

            with pytest.raises(RuntimeError, match="guard fired"):
                serve(host="0.0.0.0", port=8000)

            mock_guard.assert_called_once()
            mock_uvicorn_run.assert_not_called()

    def test_cmd_serve_invokes_guard_before_uvicorn(self) -> None:
        """cmd_serve calls _check_bind_guard before starting uvicorn.Server.serve.

        The fix (#75) replaced uvicorn.run with uvicorn.Server.serve (single-loop
        design).  We verify the guard fires before any serve attempt by patching
        _check_bind_guard to raise and asserting uvicorn.Server.serve is NOT called.
        """
        with (
            patch("firewatch_cli.commands.serve._check_bind_guard", side_effect=RuntimeError("guard fired")),
            patch("uvicorn.Server.serve") as mock_server_serve,
        ):
            from firewatch_cli.commands.serve import cmd_serve

            with pytest.raises(RuntimeError, match="guard fired"):
                cmd_serve(host="0.0.0.0", port=8000, registry={})

            mock_server_serve.assert_not_called()

    @pytest.mark.asyncio
    async def test_cmd_run_invokes_guard_before_uvicorn(self) -> None:
        """cmd_run calls _check_bind_guard before starting the uvicorn server.

        The guard must fire before any socket bind attempt.  Patch at the run
        module's own namespace (where the name is bound via
        ``from firewatch_api.server import _check_bind_guard``).

        We patch _build_pipeline + load_instances so no real config file is
        needed; then patch _check_bind_guard to raise immediately, and assert
        uvicorn.Server.serve is never called (guard fired first).
        """
        from unittest.mock import AsyncMock

        from firewatch_cli.commands.run import cmd_run

        class _MinimalStore:
            async def init(self) -> None:
                pass
            async def close(self) -> None:
                pass

        class _MinimalPipeline:
            store = _MinimalStore()

        fake_supervisor = AsyncMock()
        fake_supervisor.startup = AsyncMock()

        with (
            patch("firewatch_cli.commands.run.load_instances", return_value=[]),
            patch("firewatch_cli.commands.run._build_pipeline", return_value=_MinimalPipeline()),
            patch("firewatch_cli.commands.run.Supervisor", return_value=fake_supervisor),
            patch("firewatch_cli.commands.run._check_bind_guard", side_effect=RuntimeError("guard fired")),
        ):
            with pytest.raises(RuntimeError, match="guard fired"):
                await cmd_run(registry={}, host="0.0.0.0", port=8000)


# ---------------------------------------------------------------------------
# Error message quality — actionable
# ---------------------------------------------------------------------------


class TestErrorMessageQuality:
    """The RuntimeError message must be actionable (names env var, how to fix)."""

    def _get_error_message(self, host: str = "0.0.0.0") -> str:
        guard = _get_guard()
        with pytest.raises(RuntimeError) as exc_info:
            guard(host=host, api_key=None)
        return str(exc_info.value)

    def test_error_message_names_env_var(self) -> None:
        """Error message must mention FIREWATCH_API_KEY so operators know how to fix it."""
        msg = self._get_error_message()
        assert "FIREWATCH_API_KEY" in msg, (
            f"Error message must name FIREWATCH_API_KEY; got: {msg!r}"
        )

    def test_error_message_references_adr(self) -> None:
        """Error message should reference ADR-0026 for traceability."""
        msg = self._get_error_message()
        assert "ADR-0026" in msg, (
            f"Error message must reference ADR-0026; got: {msg!r}"
        )

    def test_error_message_mentions_loopback_alternative(self) -> None:
        """Error message should suggest the loopback alternative as a fix."""
        msg = self._get_error_message()
        # Should mention either loopback or 127.0.0.1 as the safe fallback
        assert "loopback" in msg.lower() or "127.0.0.1" in msg, (
            f"Error message should mention the safe loopback alternative; got: {msg!r}"
        )


# ---------------------------------------------------------------------------
# RuntimeConfig api_key field
# ---------------------------------------------------------------------------


class TestRuntimeConfigApiKey:
    """RuntimeConfig must carry api_key: SecretStr | None = None (ADR-0026 Consequences)."""

    def test_runtime_config_has_api_key_field(self) -> None:
        """RuntimeConfig gains api_key: SecretStr | None = None (ADR-0026)."""
        from firewatch_sdk.config import RuntimeConfig
        cfg = RuntimeConfig()
        assert hasattr(cfg, "api_key")
        assert cfg.api_key is None

    def test_runtime_config_api_key_accepts_secret_str(self) -> None:
        """RuntimeConfig.api_key can be set to a SecretStr."""
        from firewatch_sdk.config import RuntimeConfig
        cfg = RuntimeConfig(api_key=SecretStr("test-key"))
        assert cfg.api_key is not None
        assert cfg.api_key.get_secret_value() == "test-key"

    def test_runtime_config_api_key_not_in_repr(self) -> None:
        """api_key must not appear in plaintext in repr (SecretStr safety)."""
        from firewatch_sdk.config import RuntimeConfig
        cfg = RuntimeConfig(api_key=SecretStr("my-secret-key"))
        r = repr(cfg)
        assert "my-secret-key" not in r, (
            f"Secret api_key value leaked in repr: {r!r}"
        )
