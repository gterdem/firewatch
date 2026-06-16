"""FireWatch API server startup and the fail-closed bind guard.

Exposes ``DEFAULT_HOST``, ``DEFAULT_PORT``, and ``_check_bind_guard`` so that:
  - The MA.6 CLI (``firewatch serve``) reads the correct loopback default.
  - The MB CLI paths (``firewatch run``, ``firewatch serve``) share the single
    fail-closed guard before any uvicorn bind attempt.
  - Tests assert the loopback-default seam (ADR-0026 Decision 1) and the
    guard behaviour (ADR-0026 Decision 4).

ADR-0026 loopback-default rationale (Decision 1):
  The API binds ``127.0.0.1`` only by default. The trust boundary for MA is
  the host OS / loopback interface, not an application credential. No API key
  is required to run FireWatch locally (RFC 9110 §11: absence of Authorization
  is legitimate when the resource is not access-controlled via the app layer;
  here access control is delegated to the network boundary).

Fail-closed binding guard (ADR-0026 Decision 4):
  Before binding a non-loopback address, the API key MUST be configured.
  Misconfiguration fails loudly at startup — never silently at first request.
  Implemented in ``_check_bind_guard``; called by ``serve()`` before uvicorn.

  NOTE: actual per-route bearer-token enforcement (ADR-0026 Decisions 2–3) is
  DEFERRED to MP.3 (ADR-0026 / issue #548).  This guard only prevents the
  foot-gun of exposing an unauthenticated non-loopback socket.

Config-layer key/address resolution (MP.2 — issue #547):
  ``_resolve_startup_config`` reads ``bind_address`` and ``api_key`` from the
  full ADR-0006 precedence chain (env > file > default) via ``ConfigStore``.
  The CLI may override ``bind_address`` with an explicit ``--host`` flag; when
  it does, the CLI-supplied value wins over the config-file/env value.
"""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path

from pydantic import SecretStr

logger = logging.getLogger("firewatch.api.server")

# ADR-0026 Decision 1: loopback bind, no app auth for MA.
# Change this only via config/env; never hardcode a non-loopback address.
DEFAULT_HOST: str = "127.0.0.1"
DEFAULT_PORT: int = 8000

# Loopback addresses that are always safe to bind without a key (ADR-0026 D1).
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})


def _is_key_set(api_key: SecretStr | None) -> bool:
    """Return True only when *api_key* carries a non-empty secret value.

    Treats both ``None`` and ``SecretStr("")`` as "no key configured" so that
    an operator who accidentally exports ``FIREWATCH_API_KEY=`` (empty string)
    does NOT silently bypass the bind guard on a non-loopback address.

    Security invariant: a key is "set" if and only if it has at least one
    non-whitespace character.  Whitespace-only values are also treated as
    absent (consistent with the old ``_resolve_api_key`` strip+bool check).
    """
    return api_key is not None and bool(api_key.get_secret_value().strip())


def _check_bind_guard(host: str, api_key: SecretStr | None) -> None:
    """Fail-closed binding guard (ADR-0026 Decision 4).

    Raises ``RuntimeError`` if *host* is non-loopback and *api_key* is unset
    or empty.  Loopback binds (127.0.0.1, localhost, ::1, or any 127.x
    address) are always permitted regardless of key presence.

    Called by ``serve()`` and by the CLI paths (``cmd_serve``,
    ``_start_api_server``) before any uvicorn bind attempt — this is the
    SINGLE enforcement point for the guard (ADR-0026 Decision 4).

    Per-route bearer-token enforcement is OUT OF SCOPE here; it is deferred
    to MP.3 (ADR-0026 Decisions 2-3 / issue #548).

    Args:
        host: Bind address the operator requested.
        api_key: The API key from config / FIREWATCH_API_KEY env var; None or
            an empty ``SecretStr`` if not configured.

    Raises:
        RuntimeError: If *host* is non-loopback and *api_key* is None or empty.
    """
    if _is_loopback_host(host):
        return  # loopback always allowed — MA default posture (ADR-0026 D1)

    if _is_key_set(api_key):
        return  # non-loopback + non-empty key → allowed (enforcement deferred)

    raise RuntimeError(
        f"Refusing to bind non-loopback address {host!r} without an API key set. "
        "Set the FIREWATCH_API_KEY environment variable or keep the default "
        "loopback bind (127.0.0.1). "
        "(ADR-0026 Decision 4 — fail-closed binding guard; "
        "per-route auth enforcement is deferred to ADR-0026 / MP.3)"
    )


def _is_loopback_host(host: str) -> bool:
    """Return True if *host* is a loopback address or hostname.

    Handles:
    - The well-known loopback literals: ``127.0.0.1``, ``localhost``, ``::1``.
    - Any address in the 127.0.0.0/8 block (e.g. ``127.0.0.2``).
    - IPv6 loopback (``::1``).
    - Malformed / non-IP inputs: treated as non-loopback (fail-closed).
    """
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(host)
        return bool(addr.is_loopback)
    except ValueError:
        # Not a valid IP literal — treat as non-loopback (fail-closed).
        return False


def _resolve_startup_config(
    config_file: Path | str | None = None,
    cli_host: str | None = None,
) -> tuple[str, SecretStr | None]:
    """Resolve bind address and API key from the full ADR-0006 precedence chain.

    Reads ``bind_address`` and ``api_key`` from ``RuntimeConfig`` via
    ``JsonFileConfigStore``, which applies env > file > default precedence
    (ADR-0006).  The CLI ``--host`` flag may override the config-resolved
    ``bind_address`` (explicit CLI flag wins over env/file/default).

    This replaces the old ``_resolve_api_key()`` that only read
    ``FIREWATCH_API_KEY`` directly from ``os.environ``, bypassing the
    ``ConfigStore`` precedence chain and ignoring file-configured keys.

    Args:
        config_file: Path to ``firewatch_config.json``.  When ``None``,
            defaults to ``firewatch_config.json`` in the current directory.
        cli_host: If the caller (CLI) passed an explicit ``--host`` value,
            supply it here.  It overrides the config-resolved ``bind_address``.
            Pass ``None`` when no explicit CLI override was given.

    Returns:
        ``(bind_address, api_key)`` — the resolved bind address and optional
        API key, ready to pass directly to ``_check_bind_guard``.
    """
    from firewatch_core.config_store import JsonFileConfigStore

    config_path = Path(config_file) if config_file else Path("firewatch_config.json")
    try:
        store = JsonFileConfigStore(config_file=config_path)
        runtime = store.get_runtime()
    except Exception:
        logger.warning(
            "server: could not load config from %s; falling back to env/defaults",
            config_path,
            exc_info=True,
        )
        from firewatch_sdk.config import RuntimeConfig
        runtime = RuntimeConfig()

    # CLI --host flag, if given, takes precedence over config bind_address.
    bind_address = cli_host if cli_host is not None else runtime.bind_address
    api_key = runtime.api_key
    return bind_address, api_key


def serve(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    reload: bool = False,
) -> None:
    """Start the FireWatch API with uvicorn.

    Runs the fail-closed bind guard (ADR-0026 Decision 4) before calling
    uvicorn, so a misconfigured non-loopback bind with no API key fails
    loudly at startup rather than silently at first request.

    Args:
        host: Bind address.  Defaults to loopback (ADR-0026 Decision 1).
        port: Listen port.  Defaults to 8000.
        reload: Enable uvicorn auto-reload (dev mode only).

    Raises:
        RuntimeError: If *host* is non-loopback and FIREWATCH_API_KEY is unset
            (ADR-0026 Decision 4 fail-closed guard).

    NOTE: per-route bearer-token auth enforcement (ADR-0026 Decisions 2–3) is
    DEFERRED to MP.3 (ADR-0026 / issue #548).
    """
    import uvicorn

    from firewatch_core.loader import load_source_plugins

    from firewatch_api.app import create_app

    # Resolve api_key from ADR-0006 chain (env > file > default).
    # host is the caller-supplied bind address (no config override needed here).
    _, api_key = _resolve_startup_config(cli_host=host)
    _check_bind_guard(host=host, api_key=api_key)

    registry = load_source_plugins()
    app = create_app(registry=registry)
    uvicorn.run(app, host=host, port=port, reload=reload)
