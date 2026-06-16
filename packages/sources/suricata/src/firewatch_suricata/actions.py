"""Suricata maintenance action implementations (ADR-0034 §D, issue #168).

Dispatch module: ``run_action`` and ``action_status`` for the ``SuricataSource``
plugin. ``plugin.py`` stays thin — it declares actions in ``metadata()`` and
delegates here.

Actions
-------
fetch_ruleset
    Streams the configured rules path over SSH (remote) or reads the local FS
    (local), parses SID→msg, writes to ``ctx.kv`` namespace ``rule_descriptions``,
    computes SHA-256 streaming during the transfer, and writes ``ruleset_meta``.

    Never raises — all failures return ``ActionResult(ok=False, message=…)``.
    Prior KV state is never overwritten on failure (atomicity: meta is only
    written after a fully successful transfer).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from firewatch_sdk import ActionResult, ActionStatus

if TYPE_CHECKING:
    from firewatch_sdk.context import PluginContext

logger = logging.getLogger("firewatch.suricata.actions")

# Namespace for rule SID→description catalog (ADR-0025, issue #150).
_RULE_DESC_NS = "rule_descriptions"


# ---------------------------------------------------------------------------
# fetch_ruleset — run
# ---------------------------------------------------------------------------


async def fetch_ruleset_run(
    cfg: Any,
    ctx: "PluginContext",
) -> ActionResult:
    """Execute the ``fetch_ruleset`` action and return an ``ActionResult``.

    Dispatches to SSH streaming (remote) or local FS read (local) based on
    ``cfg.mode``.  SHA-256 is computed streaming during the transfer. All KV
    writes happen ONLY after a fully successful transfer so that a failure
    never partially overwrites prior state.

    Returns ``ActionResult(ok=False, …)`` on any failure; never raises.
    """
    import os

    from firewatch_suricata.ruleset import (
        RulesetTransferError,
        read_local_rules,
        stream_remote_rules,
        write_ruleset_meta,
    )

    try:
        if cfg.mode == "remote":
            sid_to_msg, size_bytes, sha256, download_mtime, download_size = (
                await stream_remote_rules(cfg)
            )
        else:
            sid_to_msg, size_bytes, sha256 = await _async_read_local(
                cfg, read_local_rules
            )
            download_mtime = None
            download_size = None

        rule_count = len(sid_to_msg)

        # Write rule descriptions to KV.
        for sid, msg in sid_to_msg.items():
            await ctx.kv.put(_RULE_DESC_NS, sid, msg)

        # Write metadata only after full successful write.
        # B-2: source_host (sensor IP) is intentionally NOT stored in KV —
        # the ruleset_meta namespace flows to the UI and storing the sensor IP
        # would be infrastructure disclosure (MC.1 N1 / ADR-0034).
        rules_path_str = (getattr(cfg, "rules_path", None) or "").strip()
        await write_ruleset_meta(
            ctx,
            sha256=sha256,
            size_bytes=size_bytes,
            rule_count=rule_count,
            source_path=rules_path_str,
            download_mtime=download_mtime,
            download_size=download_size,
        )

        pulled_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # NB-1: use basename only to avoid echoing full sensor paths in the UI.
        rules_basename = os.path.basename(rules_path_str) or rules_path_str
        return ActionResult(
            ok=True,
            message=(
                f"Fetched {rule_count} rules ({rules_basename}) at {pulled_at}. "
                f"SHA-256: {sha256[:16]}…"
            ),
            detail={
                "rule_count": str(rule_count),
                "sha256": sha256,
                "size_bytes": str(size_bytes),
            },
        )

    except RulesetTransferError as exc:
        # Sanitized user-facing message from transport layer.
        logger.warning("fetch_ruleset: transfer error: %s", exc)
        return ActionResult(ok=False, message=str(exc))
    except Exception as exc:
        # Unexpected error — log type name only (never exc text which may contain credentials).
        logger.error("fetch_ruleset: unexpected error: %s", type(exc).__name__)
        return ActionResult(
            ok=False,
            message=(
                "Ruleset fetch failed due to an unexpected error. "
                "Check the FireWatch logs for details."
            ),
        )


async def _async_read_local(
    cfg: Any,
    read_local_rules: Any,
) -> tuple[dict[str, str], int, str]:
    """Thin async wrapper for the sync ``read_local_rules`` function.

    The local read is CPU-bound (file parse) but typically fast (<1 s for
    even large rulesets). We call it directly rather than via
    ``asyncio.to_thread`` to avoid the overhead; a future optimisation can
    wrap it if profiling shows blocking.
    """
    return read_local_rules(cfg)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# fetch_ruleset — status
# ---------------------------------------------------------------------------


async def fetch_ruleset_status(
    cfg: Any,
    ctx: "PluginContext",
) -> ActionStatus:
    """Return the ``ActionStatus`` for the ``fetch_ruleset`` action.

    Reads ``ruleset_meta`` from ``ctx.kv`` ONLY — never opens SSH or touches
    the network (ADR-0034 §long-running-semantics).

    Returns
    -------
    ActionStatus
        Includes:
        - ``last_run_at``: epoch seconds of ``pulled_at``, or ``None``.
        - ``stale``: ``True`` / ``False`` / ``None`` (unknown).
        - ``message``: one-line summary with both dates when stale.
        - ``detail``: KV-sourced meta fields for UI display.
    """
    from firewatch_suricata.ruleset import compute_staleness, read_ruleset_meta

    meta = await read_ruleset_meta(ctx)

    pulled_at_str = meta.get("pulled_at")
    rule_count = meta.get("rule_count")
    size_bytes = meta.get("size_bytes")
    sha256 = meta.get("sha256")
    remote_mtime_str = meta.get("remote_mtime")

    # Parse pulled_at to epoch float for last_run_at.
    last_run_at: float | None = None
    if pulled_at_str:
        try:
            dt = datetime.fromisoformat(pulled_at_str.replace("Z", "+00:00"))
            last_run_at = dt.timestamp()
        except (ValueError, TypeError):
            pass

    stale = compute_staleness(meta)

    # Build the status message.
    message = _build_status_message(
        pulled_at_str=pulled_at_str,
        remote_mtime_str=remote_mtime_str,
        rule_count=rule_count,
        stale=stale,
    )

    detail: dict[str, str] = {}
    if rule_count is not None:
        detail["rule_count"] = rule_count
    if size_bytes is not None:
        detail["size_bytes"] = size_bytes
    if sha256 is not None:
        detail["sha256"] = sha256

    return ActionStatus(
        last_run_at=last_run_at,
        stale=stale,
        message=message,
        detail=detail,
    )


def _build_status_message(
    *,
    pulled_at_str: str | None,
    remote_mtime_str: str | None,
    rule_count: str | None,
    stale: bool | None,
) -> str | None:
    """Build a one-line status message for the action status response."""
    if pulled_at_str is None:
        return "Ruleset not yet fetched. Run 'fetch_ruleset' to download."

    count_label = f"{rule_count} rules" if rule_count else "rules"
    pulled_label = _format_timestamp_label(pulled_at_str)

    if stale is True and remote_mtime_str is not None:
        sensor_label = _format_epoch_label(remote_mtime_str)
        return (
            f"Ruleset updated on sensor {sensor_label}; "
            f"downloaded copy from {pulled_label} ({count_label})."
        )
    if stale is False:
        return f"{count_label} loaded; downloaded {pulled_label} (up to date)."

    # stale=None or no remote stat yet.
    return f"{count_label} loaded; downloaded {pulled_label}."


def _format_timestamp_label(ts_str: str) -> str:
    """Return a human-readable date label from an ISO-8601 timestamp string."""
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except (ValueError, TypeError):
        return ts_str


def _format_epoch_label(epoch_str: str) -> str:
    """Return a human-readable date label from a UNIX epoch string."""
    try:
        dt = datetime.fromtimestamp(float(epoch_str), tz=timezone.utc)
        return dt.strftime("%Y-%m-%d")
    except (ValueError, TypeError):
        return epoch_str
