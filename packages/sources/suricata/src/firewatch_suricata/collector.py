"""Suricata EVE JSON collector — local file and remote SSH modes.

Ported from ``legacy/adapters/collectors/suricata.py`` (reference only — never
imported). Adapted to the v2 PullSource protocol:
  - ``collect(cfg, since)`` is an ``AsyncIterator[RawEvent]`` (not a coroutine
    returning a list) per the SDK PullSource Protocol.
  - ``since`` is an ISO-8601 string (or None) instead of a datetime object.
  - Configuration is passed in as the ``SuricataConfig`` Pydantic model.

Contract hard rules (PLUGIN_CONTRACT.md):
  - ``collect()`` MUST be cancellable (CancelledError propagates).
  - ``collect()`` MUST NOT raise out of its loop — one failure must never crash
    the supervisor or other sources.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import types
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from firewatch_sdk import RawEvent

logger = logging.getLogger("firewatch.suricata.collector")

# Hard cap to avoid OOM against a huge initial eve.json. Ported from legacy.
# The watermark normally limits how many lines we materialise per call, but the
# first sync against a multi-GB file could otherwise blow out memory.
MAX_EVENTS_PER_COLLECT = 50_000

# Suricata's event type string for alert events.
_ALERT_TYPE = "alert"

# Module-level asyncssh reference — loaded once at import time, allows
# ``patch("firewatch_suricata.collector.asyncssh")`` to work in tests.
# asyncssh is declared as a required dependency so ImportError here means the
# package is misconfigured.
try:
    import asyncssh as asyncssh  # noqa: PLC0414
except ImportError:  # pragma: no cover
    asyncssh = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Public async generator
# ---------------------------------------------------------------------------


async def collect(
    cfg: Any,  # SuricataConfig — typed as Any to keep collector import-free of config
    since: str | None,
    ctx: Any = None,  # PluginContext | None — typed as Any to avoid circular import
) -> AsyncIterator[RawEvent]:
    """Yield ``RawEvent``s for Suricata EVE alert lines newer than ``since``.

    Dispatches to ``_collect_local`` or ``_collect_remote`` based on ``cfg.mode``.
    Never raises out of its body — exceptions are caught and logged (hard rule).
    CancelledError is NOT caught and therefore propagates as required.

    ``ctx`` is the per-instance PluginContext (ADR-0027).  In remote mode,
    it is used to record a cheap per-cycle stat of the rules path into
    ``ruleset_meta`` for freshness detection (issue #168, ADR-0034 §D.3).
    """
    since_dt: datetime | None = _parse_since(since)

    if cfg.mode == "local":
        async for raw in _collect_local(cfg, since_dt):
            yield raw
    else:
        async for raw in _collect_remote(cfg, since_dt, ctx=ctx):
            yield raw


# ---------------------------------------------------------------------------
# Local mode
# ---------------------------------------------------------------------------


async def _collect_local(cfg: Any, since: datetime | None) -> AsyncIterator[RawEvent]:
    """Yield RawEvents by reading eve.json from the local filesystem."""
    local_path = Path(cfg.local_path or "")
    if not local_path.exists():
        logger.warning("Suricata local_path does not exist: %s", local_path)
        return

    received = datetime.now(timezone.utc)
    count = 0
    try:
        with local_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                raw = _parse_line(line, since, received)
                if raw is None:
                    continue
                yield raw
                count += 1
                if count >= MAX_EVENTS_PER_COLLECT:
                    logger.warning(
                        "SuricataCollector hit MAX_EVENTS_PER_COLLECT=%d; "
                        "stopping early. Set a tighter watermark or increase the cap.",
                        MAX_EVENTS_PER_COLLECT,
                    )
                    return
    except asyncio.CancelledError:
        raise  # CancelledError must propagate (PLUGIN_CONTRACT.md hard rule)
    except Exception as exc:
        logger.exception("SuricataCollector local read error for %s: %s", local_path, exc)
        return

    logger.info(
        "SuricataCollector.collect (local): %d new alerts from %s (since=%s)",
        count, local_path, since,
    )


# ---------------------------------------------------------------------------
# Remote / SSH mode
# ---------------------------------------------------------------------------


async def _collect_remote(
    cfg: Any, since: datetime | None, ctx: Any = None
) -> AsyncIterator[RawEvent]:
    """Yield RawEvents by SSHing into the remote host and streaming eve.json via grep.

    B2 — streams stdout line-by-line via ``conn.create_process()`` so memory is
    bounded by ``MAX_EVENTS_PER_COLLECT``, not by the remote file size.  Iteration
    stops as soon as the cap is hit; the remote process is then closed without
    reading remaining output.

    After streaming, records a cheap stat of ``cfg.rules_path`` into
    ``ruleset_meta`` via ``ctx.kv`` for freshness detection (ADR-0034 §D.3).
    The stat is performed by ``_record_remote_stat``, which opens its own
    dedicated SSH connection (the collect connection is closed by this point).
    """
    try:
        conn = await _connect_ssh(cfg)
    except SSHConnectionError as exc:
        logger.error("SuricataCollector SSH connect failed: %s", exc)
        return
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("SuricataCollector SSH unexpected error: %s", exc)
        return

    received = datetime.now(timezone.utc)
    count = 0
    try:
        async with conn:
            remote_path = cfg.remote_path or "/var/log/suricata/eve.json"
            quoted = _shell_quote(remote_path)

            # Verify the file exists and is readable before issuing grep.
            check = await conn.run(
                f"test -r {quoted} && echo OK || echo FAIL",
                check=False,
            )
            if "FAIL" in (check.stdout or ""):
                logger.error(
                    "Cannot read %s on %s — check file exists and is readable",
                    remote_path, cfg.remote_host,
                )
                return

            # B2 — use create_process to stream stdout line-by-line.
            # Memory is bounded by MAX_EVENTS_PER_COLLECT: we stop iterating
            # (and close the process) as soon as we hit the cap, so the remote
            # file size has no effect on peak memory usage.
            cmd = f"grep '\"event_type\":\"alert\"' {quoted}"
            async with conn.create_process(cmd) as process:
                async for line in process.stdout:
                    raw = _parse_line(line, since, received)
                    if raw is None:
                        continue
                    yield raw
                    count += 1
                    if count >= MAX_EVENTS_PER_COLLECT:
                        logger.warning(
                            "SuricataCollector hit MAX_EVENTS_PER_COLLECT=%d (remote); "
                            "stopping early. Set a tighter watermark or increase the cap.",
                            MAX_EVENTS_PER_COLLECT,
                        )
                        return

    except asyncio.CancelledError:
        raise
    except SSHConnectionError as exc:
        logger.error("SuricataCollector SSH command failed: %s", exc)
        return
    except Exception as exc:
        logger.error(
            "SuricataCollector remote command failed on %s: %s", cfg.remote_host, exc
        )
        return

    logger.info(
        "SuricataCollector.collect (remote): %d new alerts from %s (since=%s)",
        count, cfg.remote_host, since,
    )

    # ADR-0034 §D.3 — record cheap per-cycle stat of rules_path (mtime+size only;
    # never a transfer) into ruleset_meta for action_status freshness detection.
    if ctx is not None:
        rules_path_str = (getattr(cfg, "rules_path", None) or "").strip()
        if rules_path_str:
            await _record_remote_stat(cfg, rules_path_str, ctx)


# ---------------------------------------------------------------------------
# SSH helpers (ported from legacy with SSHConnectionError remapping)
# ---------------------------------------------------------------------------


class SSHConnectionError(Exception):
    """User-facing SSH error with actionable remediation steps.

    Raised when remote-mode collection cannot reach the host or read the alert
    file. The message is shown verbatim in the dashboard's "Test Connection"
    result, so it tells the user *what to do next*, not just *what failed*.
    """


async def _connect_ssh(cfg: Any) -> Any:
    """Open an asyncssh connection with full error → SSHConnectionError mapping.

    Returns an ``asyncssh.SSHClientConnection`` on success.
    Raises ``SSHConnectionError`` with an actionable message on any failure.

    Accesses the module-level ``asyncssh`` variable (not a local re-import) so
    ``patch("firewatch_suricata.collector.asyncssh")`` works in tests.
    """
    # Access the module-level asyncssh via globals() so that
    # ``patch("firewatch_suricata.collector.asyncssh")`` replaces what we use.
    _ssh: types.ModuleType | None = globals().get("asyncssh")
    if _ssh is None:  # pragma: no cover
        raise SSHConnectionError(
            "asyncssh is not installed. Install with: pip install asyncssh"
        )

    if not cfg.remote_host:
        raise SSHConnectionError(
            "Remote host not configured. "
            "Set FIREWATCH_SURICATA_REMOTE_HOST=<ip-or-hostname>"
        )

    kwargs: dict[str, Any] = {
        "host": cfg.remote_host,
        "port": cfg.remote_port or 22,
        # Without this asyncssh hangs forever on firewall blackholes / wrong IPs.
        "connect_timeout": 10,
    }

    # Read ~/.ssh/config so users can use Host aliases.
    ssh_config = Path.home() / ".ssh" / "config"
    if ssh_config.exists():
        kwargs["config"] = [str(ssh_config)]

    # B1 — SSH host-key verification is SECURE BY DEFAULT.
    # When verify_host_key is True (default), we let asyncssh read its default
    # known_hosts (~/.ssh/known_hosts) by omitting the known_hosts kwarg.
    # Only when the operator has explicitly opted out (verify_host_key=False) do we
    # set known_hosts=None, and we emit a warning so it is never silent.
    if not getattr(cfg, "verify_host_key", True):
        kwargs["known_hosts"] = None
        logger.warning(
            "SuricataCollector: SSH host-key verification DISABLED for %s — "
            "connection is vulnerable to man-in-the-middle attack (MITM). "
            "Set verify_host_key=true to restore protection.",
            cfg.remote_host,
        )
    # else: omit known_hosts — asyncssh validates against ~/.ssh/known_hosts (secure)

    if cfg.remote_user:
        kwargs["username"] = cfg.remote_user

    # remote_key is SecretStr; extract with get_secret_value() before use.
    if cfg.remote_key is not None:
        key_str: str = cfg.remote_key.get_secret_value()
        if key_str:
            key_path = Path(key_str).expanduser()
            if not key_path.exists():
                logger.error(
                    "SuricataCollector: SSH key not found at %s", key_path
                )
                raise SSHConnectionError(
                    "SSH key file not found.\n"
                    "Either:\n"
                    "  1. Generate a key: ssh-keygen -t ed25519\n"
                    "  2. Set FIREWATCH_SURICATA_REMOTE_KEY=<path> to a valid key\n"
                    "  3. Remove the setting to use SSH agent or default keys"
                )
            if not os.access(key_path, os.R_OK):
                logger.error(
                    "SuricataCollector: SSH key not readable at %s", key_path
                )
                raise SSHConnectionError(
                    "SSH key file is not readable.\n"
                    "Fix: chmod 600 <path-to-key>"
                )
            kwargs["client_keys"] = [str(key_path)]

    try:
        return await _ssh.connect(**kwargs)
    except _ssh.PermissionDenied:
        user = cfg.remote_user or _current_user()
        raise SSHConnectionError(
            f"SSH auth failed for {user}@{cfg.remote_host}\n"
            f"Check:\n"
            f"  1. Public key in authorized_keys on the remote host?\n"
            f"  2. Try: ssh {user}@{cfg.remote_host}\n"
            f"  3. Set key explicitly: FIREWATCH_SURICATA_REMOTE_KEY=~/.ssh/your_key"
        ) from None
    except _ssh.DisconnectError as exc:
        raise SSHConnectionError(
            f"SSH refused by {cfg.remote_host}:{cfg.remote_port}\n"
            f"Check: host reachable? SSH running? IP allowed in firewall?"
        ) from exc
    except asyncio.TimeoutError as exc:
        raise SSHConnectionError(
            f"Timeout reaching {cfg.remote_host}:{cfg.remote_port}\n"
            f"Check: host running? Port open? IP allowed in NSG?"
        ) from exc
    except OSError as exc:
        err = str(exc)
        if "Name or service not known" in err or "getaddrinfo" in err:
            raise SSHConnectionError(
                f"Cannot resolve hostname: {cfg.remote_host}. Try an IP address."
            ) from exc
        if "timed out" in err.lower() or "no route" in err.lower():
            raise SSHConnectionError(
                f"Timeout reaching {cfg.remote_host}:{cfg.remote_port}\n"
                f"Check: host running? Port open? IP allowed in NSG?"
            ) from exc
        if "connection refused" in err.lower():
            raise SSHConnectionError(
                f"SSH refused by {cfg.remote_host}:{cfg.remote_port}\n"
                f"Check: host reachable? SSH running? IP allowed in firewall?"
            ) from exc
        raise SSHConnectionError(f"SSH error: {exc}") from exc


# ---------------------------------------------------------------------------
# Per-cycle remote stat helper (ADR-0034 §D.3, issue #168)
# ---------------------------------------------------------------------------


async def _record_remote_stat(
    cfg: Any, rules_path_str: str, ctx: Any
) -> None:
    """Record a cheap stat (mtime + size) of the remote rules_path into ruleset_meta.

    Opens a new SSH connection specifically for the stat — the collect connection
    has already been closed at this point.  Any failure is silently swallowed
    (a failed stat must not abort or degrade event collection).

    The stat is intentionally a lightweight stat -c '%Y\n%s' command —
    NEVER a file transfer or hash (ADR-0034 §D.3).
    """
    from firewatch_suricata.ruleset import remote_stat, write_remote_stat

    try:
        conn = await _connect_ssh(cfg)
    except (SSHConnectionError, Exception) as exc:
        logger.debug(
            "_record_remote_stat: SSH connect failed (%s); skipping stat",
            type(exc).__name__,
        )
        return

    try:
        async with conn:
            mtime, size = await remote_stat(conn, rules_path_str)
        if mtime is not None and size is not None:
            await write_remote_stat(ctx, mtime=mtime, size=size)
    except Exception as exc:
        logger.debug(
            "_record_remote_stat: stat/write failed (%s); skipping",
            type(exc).__name__,
        )


# ---------------------------------------------------------------------------
# Line parser helpers
# ---------------------------------------------------------------------------


def _parse_line(
    line: str,
    since: datetime | None,
    received: datetime,
) -> RawEvent | None:
    """Parse one eve.json line → RawEvent, or None to skip.

    Skips: blank lines, JSON parse errors, non-alert events, events without a
    timestamp, and events at-or-before the watermark.
    """
    line = line.strip()
    if not line:
        return None
    try:
        data: dict[str, Any] = json.loads(line)
    except json.JSONDecodeError:
        return None
    if data.get("event_type") != _ALERT_TYPE:
        return None
    ts_str = data.get("timestamp")
    if not ts_str:
        return None
    try:
        ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if since is not None and ts <= since:
        return None
    return RawEvent(
        source_type="suricata",
        received_at=received,
        data=data,
    )


def _parse_since(since: str | None) -> datetime | None:
    """Parse the ISO-8601 watermark string into a timezone-aware datetime, or None."""
    if since is None:
        return None
    try:
        return datetime.fromisoformat(since)
    except (ValueError, TypeError):
        logger.warning("SuricataCollector: invalid since value %r; treating as None", since)
        return None


def _shell_quote(value: str) -> str:
    """POSIX single-quote shell escape for remote command substitution.

    Used to embed user-supplied paths in remote SSH commands. Single quotes
    inside the value are turned into the standard ``'\\''`` idiom so no shell
    injection is possible even on adversarial config input.
    """
    return "'" + value.replace("'", "'\\''") + "'"


def _current_user() -> str:
    try:
        return os.getlogin()
    except OSError:
        return os.environ.get("USER") or "user"
