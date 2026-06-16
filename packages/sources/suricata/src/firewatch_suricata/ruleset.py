"""Ruleset transport, integrity, stat, and meta helpers for the fetch_ruleset action.

Module concerns (ADR-0034 §D, issue #168):
  transport  -- stream the configured rules path over SSH (remote) or local FS (local).
  integrity  -- SHA-256 fed incrementally per line during the download (never hash
               remotely; the digest object is updated in the streaming loop so the
               full file bytes are never materialised in a single object).
  stat       -- cheap remote stat (mtime + size only); _record_remote_stat in
               collector.py opens its own SSH connection for this -- it does NOT
               ride the collect connection (ADR-0034 §D).
  meta       -- read/write helpers for the ``ruleset_meta`` KV namespace:
               ``pulled_at``, ``size_bytes``, ``sha256``, ``source_path``,
               ``download_mtime``/``download_size`` (captured at download time),
               ``remote_mtime``/``remote_size`` (updated each collect cycle).

Credential sanitization (MC.1 N1):
  SSH errors surfaced to the caller via ``RulesetTransferError`` carry only a
  generic human-readable message -- never host, user, or key path verbatim.

Memory bound:
  Remote rules are streamed line-by-line with a cumulative byte cap
  (``_MAX_RULES_BYTES`` from ``rules.py``, 50 MB).  If the stream exceeds the cap
  the transfer is aborted with ``RulesetTransferError`` and no accumulated data is
  returned to the caller.  The SHA-256 digest is updated incrementally so no full
  copy of the file is ever assembled in memory.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from firewatch_sdk.context import PluginContext

logger = logging.getLogger("firewatch.suricata.ruleset")

# Module-level asyncssh reference — patched by tests the same way collector.py does.
try:
    import asyncssh as asyncssh  # noqa: PLC0414
except ImportError:  # pragma: no cover
    asyncssh = None  # type: ignore[assignment]

# KV namespace for ruleset metadata (pulled_at, sha256, sizes, stats).
RULESET_META_NS = "ruleset_meta"


class RulesetTransferError(Exception):
    """Raised by the transport layer on any failure.

    The message is safe to surface to the user -- it must never contain host IPs,
    usernames, key paths, or raw exception text from asyncssh (MC.1 N1 / ADR-0034).
    """


# ---------------------------------------------------------------------------
# Transport -- remote SSH streaming
# ---------------------------------------------------------------------------


async def stream_remote_rules(
    cfg: Any,
) -> tuple[dict[str, str], int, str, str | None, str | None]:
    """Stream the configured rules path from the remote sensor over SSH.

    Opens a new SSH connection using the module-level ``asyncssh`` reference
    (patchable in tests via ``patch("firewatch_suricata.ruleset.asyncssh")``).

    The transfer is aborted with ``RulesetTransferError`` if the cumulative byte
    count exceeds ``_MAX_RULES_BYTES`` (50 MB).  The SHA-256 digest is fed
    incrementally per line so no full copy of the file is held in memory.

    Parameters
    ----------
    cfg:
        Resolved ``SuricataConfig``; ``rules_path``, ``remote_host``, etc.

    Returns
    -------
    tuple[dict[str, str], int, str, str | None, str | None]
        ``(sid_to_msg, size_bytes, sha256_hex, download_mtime, download_size)``
        where ``size_bytes`` is the total bytes received, ``sha256_hex`` is the
        hex digest, and ``download_mtime``/``download_size`` are the remote stat
        values at download time (normalised strings for KV storage).

    Raises
    ------
    RulesetTransferError
        On any SSH or stream failure, or if the byte cap is exceeded.
        Message is credential-safe (MC.1 N1).
    """
    import types

    from firewatch_suricata.rules import _MAX_MSG_LEN, _MAX_RULES_BYTES, _MSG_RE, _SID_RE

    if not cfg.rules_path:
        raise RulesetTransferError(
            "rules_path is not configured -- cannot fetch ruleset."
        )

    if not cfg.remote_host:
        raise RulesetTransferError(
            "Remote host not configured. Check plugin settings."
        )

    # Use the module-level asyncssh so tests can patch it.
    _ssh: types.ModuleType | None = globals().get("asyncssh")
    if _ssh is None:  # pragma: no cover
        raise RulesetTransferError(
            "asyncssh is not installed. Install with: pip install asyncssh"
        )

    # Build connect kwargs matching collector._connect_ssh posture (ADR-0005).
    from pathlib import Path

    kwargs: dict[str, Any] = {
        "host": cfg.remote_host,
        "port": getattr(cfg, "remote_port", 22) or 22,
        "connect_timeout": 30,  # Ruleset download — allow more time than collect.
    }

    ssh_config = Path.home() / ".ssh" / "config"
    if ssh_config.exists():
        kwargs["config"] = [str(ssh_config)]

    if not getattr(cfg, "verify_host_key", True):
        kwargs["known_hosts"] = None
        logger.warning(
            "fetch_ruleset: SSH host-key verification DISABLED — "
            "connection is vulnerable to MITM."
        )

    if getattr(cfg, "remote_user", None):
        kwargs["username"] = cfg.remote_user

    remote_key = getattr(cfg, "remote_key", None)
    if remote_key is not None:
        key_str: str = remote_key.get_secret_value()
        if key_str:
            key_path = Path(key_str).expanduser()
            if key_path.exists():
                kwargs["client_keys"] = [str(key_path)]

    try:
        conn = await _ssh.connect(**kwargs)
    except Exception as exc:
        logger.error("fetch_ruleset: SSH connect failed: %s", type(exc).__name__)
        raise RulesetTransferError(
            "Could not connect to the sensor. "
            "Check SSH connectivity and credentials."
        ) from None

    sid_to_msg: dict[str, str] = {}
    download_mtime: str | None = None
    download_size: str | None = None
    digest = hashlib.sha256()
    cumulative_bytes = 0

    try:
        async with conn:
            rules_path = cfg.rules_path
            quoted = _shell_quote(rules_path)

            # Verify file exists on sensor.
            check = await conn.run(
                f"test -r {quoted} && echo OK || echo FAIL",
                check=False,
            )
            if "FAIL" in (check.stdout or ""):
                raise RulesetTransferError(
                    "Rules path is not readable on the sensor. "
                    "Verify the rules path in the plugin settings."
                )

            # Stat the remote file at the moment of download (for change detection).
            # NB-4: parse to typed values and re-serialise so KV always holds
            # normalised float/int strings (not raw stdout whitespace).
            stat_result = await conn.run(
                f"stat -c '%Y\\n%s' {quoted} 2>/dev/null || echo stat_err",
                check=False,
            )
            stat_out = (stat_result.stdout or "").strip()
            if stat_out and "stat_err" not in stat_out:
                stat_lines = stat_out.splitlines()
                if len(stat_lines) >= 2:
                    try:
                        download_mtime = str(float(stat_lines[0].strip()))
                        download_size = str(int(stat_lines[1].strip()))
                    except (ValueError, TypeError):
                        download_mtime = None
                        download_size = None

            # Stream the file line-by-line; feed SHA-256 incrementally; enforce cap.
            # B-1: abort if cumulative bytes exceed _MAX_RULES_BYTES — never join
            # chunks after the loop because no chunk list is kept.
            cmd = f"cat {quoted}"
            async with conn.create_process(cmd) as process:
                async for line in process.stdout:
                    line_bytes = (
                        line.encode("utf-8", errors="replace")
                        if isinstance(line, str)
                        else line
                    )
                    cumulative_bytes += len(line_bytes)
                    if cumulative_bytes > _MAX_RULES_BYTES:
                        raise RulesetTransferError(
                            f"Ruleset exceeds the {_MAX_RULES_BYTES // (1024 * 1024)} MB "
                            "size cap. Check the rules path in the plugin settings."
                        )
                    # Update digest incrementally — no chunks list kept.
                    digest.update(line_bytes)
                    line_str = (
                        line
                        if isinstance(line, str)
                        else line.decode("utf-8", errors="replace")
                    )
                    stripped = line_str.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    sid_m = _SID_RE.search(stripped)
                    msg_m = _MSG_RE.search(stripped)
                    if sid_m and msg_m:
                        sid = sid_m.group(1)
                        msg = msg_m.group(1)[:_MAX_MSG_LEN]
                        sid_to_msg[sid] = msg

    except RulesetTransferError:
        raise
    except Exception as exc:
        logger.error("fetch_ruleset: SSH stream failed: %s", type(exc).__name__)
        raise RulesetTransferError(
            "Ruleset transfer failed. Check sensor connectivity and rules path."
        ) from None

    return sid_to_msg, cumulative_bytes, digest.hexdigest(), download_mtime, download_size


# ---------------------------------------------------------------------------
# Transport -- local file read
# ---------------------------------------------------------------------------


def read_local_rules(cfg: Any) -> tuple[dict[str, str], int, str]:
    """Read the local rules path and parse SID->msg mappings.

    Parameters
    ----------
    cfg:
        Resolved ``SuricataConfig``; ``rules_path`` is read from here.

    Returns
    -------
    tuple[dict[str, str], int, str]
        ``(sid_to_msg, size_bytes, sha256_hex)`` -- size_bytes and sha256_hex
        are used for ruleset_meta without materialising the full content.

    Raises
    ------
    RulesetTransferError
        If rules_path is blank or the file cannot be read.
    """
    from pathlib import Path

    from firewatch_suricata.rules import _MAX_RULES_BYTES, parse_rules_dir, parse_rules_file

    rules_path_str = (cfg.rules_path or "").strip()
    if not rules_path_str:
        raise RulesetTransferError(
            "rules_path is not configured -- cannot fetch local ruleset."
        )

    rules_path = Path(rules_path_str)

    try:
        if rules_path.is_dir():
            sid_to_msg = parse_rules_dir(rules_path)
            # NB-5: enforce cumulative byte cap across all .rules files in the dir.
            digest = hashlib.sha256()
            total_bytes = 0
            for f in sorted(rules_path.glob("*.rules")):
                try:
                    chunk = f.read_bytes()
                except OSError:
                    continue
                total_bytes += len(chunk)
                if total_bytes > _MAX_RULES_BYTES:
                    raise RulesetTransferError(
                        f"Rules directory exceeds the "
                        f"{_MAX_RULES_BYTES // (1024 * 1024)} MB size cap. "
                        "Check the rules path in the plugin settings."
                    )
                digest.update(chunk)
            size_bytes = total_bytes
            sha256_hex = digest.hexdigest()
        elif rules_path.is_file():
            raw_content = rules_path.read_bytes()
            if len(raw_content) > _MAX_RULES_BYTES:
                raise RulesetTransferError(
                    f"Rules file exceeds the {_MAX_RULES_BYTES // (1024 * 1024)} MB "
                    "size cap. Check the rules path in the plugin settings."
                )
            size_bytes = len(raw_content)
            sha256_hex = hashlib.sha256(raw_content).hexdigest()
            sid_to_msg = parse_rules_file(rules_path)
        else:
            raise RulesetTransferError(
                "Local rules path does not exist. "
                "Verify the rules path in the plugin settings."
            )
    except RulesetTransferError:
        raise
    except OSError as exc:
        logger.error("fetch_ruleset: local read error: %s", exc)
        raise RulesetTransferError(
            "Could not read local rules file. Check the path and permissions."
        ) from None

    return sid_to_msg, size_bytes, sha256_hex


# ---------------------------------------------------------------------------
# Integrity -- streaming SHA-256
# ---------------------------------------------------------------------------


def compute_sha256(data: bytes) -> str:
    """Return the hex SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Stat -- cheap remote mtime/size (ride an open SSH session; called during collect)
# ---------------------------------------------------------------------------


async def remote_stat(conn: Any, remote_path: str) -> tuple[float | None, int | None]:
    """Return ``(mtime, size)`` of *remote_path* via a cheap stat command.

    Must be called on an already-open SSH connection to avoid opening a new
    session (ADR-0034 -- freshness cached per collect cycle; never during
    status reads).

    Returns ``(None, None)`` on any error so that a failed stat never blocks
    the collect cycle.
    """
    quoted = _shell_quote(remote_path)
    try:
        result = await conn.run(
            f"stat -c '%Y\\n%s' {quoted} 2>/dev/null || echo stat_err",
            check=False,
        )
        out = (result.stdout or "").strip()
        if not out or "stat_err" in out:
            return None, None
        lines = out.splitlines()
        if len(lines) < 2:
            return None, None
        mtime = float(lines[0].strip())
        size = int(lines[1].strip())
        return mtime, size
    except Exception as exc:
        logger.debug("fetch_ruleset: remote stat failed: %s", exc)
        return None, None


# ---------------------------------------------------------------------------
# Meta -- KV read/write helpers
# ---------------------------------------------------------------------------


async def write_ruleset_meta(
    ctx: "PluginContext",
    *,
    sha256: str,
    size_bytes: int,
    rule_count: int,
    source_path: str,
    download_mtime: str | None = None,
    download_size: str | None = None,
) -> None:
    """Write download metadata into the ``ruleset_meta`` KV namespace.

    Called ONLY after a fully successful download so partial-overwrite is not
    possible -- the caller (actions.py) owns the atomicity boundary.

    B-2 / MC.1 N1: ``source_host`` (sensor IP) is intentionally absent.
    The ``ruleset_meta`` namespace is readable via the actions API (#169); storing
    the sensor IP would be infrastructure disclosure.
    """
    pulled_at = datetime.now(timezone.utc).isoformat()
    await ctx.kv.put(RULESET_META_NS, "pulled_at", pulled_at)
    await ctx.kv.put(RULESET_META_NS, "sha256", sha256)
    await ctx.kv.put(RULESET_META_NS, "size_bytes", str(size_bytes))
    await ctx.kv.put(RULESET_META_NS, "rule_count", str(rule_count))
    await ctx.kv.put(RULESET_META_NS, "source_path", source_path)
    if download_mtime is not None:
        await ctx.kv.put(RULESET_META_NS, "download_mtime", download_mtime)
    if download_size is not None:
        await ctx.kv.put(RULESET_META_NS, "download_size", download_size)


async def write_remote_stat(
    ctx: "PluginContext",
    *,
    mtime: float,
    size: int,
) -> None:
    """Write the per-cycle remote stat into the ``ruleset_meta`` KV namespace.

    Called by the collect cycle after a successful stat (ADR-0034 §D.3).
    """
    await ctx.kv.put(RULESET_META_NS, "remote_mtime", str(mtime))
    await ctx.kv.put(RULESET_META_NS, "remote_size", str(size))


async def read_ruleset_meta(ctx: "PluginContext") -> dict[str, str]:
    """Return all ``ruleset_meta`` KV entries as a plain dict."""
    return await ctx.kv.get_all(RULESET_META_NS)


# ---------------------------------------------------------------------------
# Staleness comparison
# ---------------------------------------------------------------------------


def compute_staleness(meta: dict[str, str]) -> bool | None:
    """Compare remote stat against download stat to determine staleness.

    Returns
    -------
    True
        Sensor file has changed since the last download.
    False
        Remote stat matches the download stat -- ruleset is fresh.
    None
        Not enough information (no download recorded, or no remote stat yet).
    """
    download_mtime = meta.get("download_mtime")
    download_size = meta.get("download_size")
    remote_mtime = meta.get("remote_mtime")
    pulled_at = meta.get("pulled_at")

    # No download ever -- cannot determine staleness.
    if pulled_at is None:
        return None

    # Download exists but no remote stat yet -- unknown.
    if remote_mtime is None:
        return None

    # No download stat stored (older download without stat support) -- treat as stale.
    if download_mtime is None:
        return True

    try:
        if float(remote_mtime) != float(download_mtime):
            return True
        remote_size = meta.get("remote_size")
        if download_size is not None and remote_size is not None:
            if int(remote_size) != int(download_size):
                return True
        return False
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Shell quote helper (same discipline as collector.py)
# ---------------------------------------------------------------------------


def _shell_quote(value: str) -> str:
    """POSIX single-quote shell escape for remote command substitution."""
    return "'" + value.replace("'", "'\\''") + "'"
