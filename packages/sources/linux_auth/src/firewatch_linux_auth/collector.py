"""Linux auth log collector — journald-first, file-tail fallback (ADR-0065).

Drives the shared SDK local readers (``firewatch_sdk.localhost``): the
systemd-journal reader as the primary interface, plain file-tail as the
fallback for non-systemd hosts or an explicit operator override. Resume is
**cursor-based**, persisted via ``ctx.kv`` (ADR-0025/0027) — NOT the core
watermark (``since``/``set_watermark``): the readers' own opaque cursors are
the durable, exactly-once-per-line resume mechanism (ADR-0065 §3); ``since``
is accepted (the PullSource protocol requires it) but deliberately unused.

Contract hard rules (PLUGIN_CONTRACT.md):
  - ``collect()`` MUST be cancellable (CancelledError propagates).
  - ``collect()`` MUST NOT raise out of its loop — one failing instance must
    never crash the supervisor or other sources.

**Handling the readers' ``(None, cursor)`` sentinel** (issue #60/#63): both
readers may yield a ``None`` record/line paired with a cursor — "an oversized
entry was skipped; here is where to resume" — governed by the invariant
documented in ``firewatch_sdk.localhost.journald``/``filetail`` (emitted at
most once per ``read()`` call, only as the final item, only when the cycle
yielded nothing else). This collector follows the documented caller idiom
exactly: forward only non-``None`` records as events, but ALWAYS track and
persist the cursor so an oversized, unreadable line is skipped once — never
re-served and re-skipped forever (a correctness bug against the resume
guarantee, and a cheap DoS against a security tool that must keep moving
forward past attacker-influenceable log content).
"""
from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

from firewatch_sdk import PluginContext, RawEvent
from firewatch_sdk.localhost import (
    FileTailReader,
    FileTailUnavailableError,
    JournaldReader,
    JournaldUnavailableError,
)

from firewatch_linux_auth.config import LinuxAuthConfig

logger = logging.getLogger("firewatch.linux_auth.collector")

# Hard cap on RawEvents yielded per collect() cycle — protects against OOM on
# a huge initial backlog (e.g. "head" resume against a multi-year journal or a
# never-rotated auth.log), mirroring firewatch_suricata.collector's own cap.
# The cursor is persisted up to the last processed record either way, so the
# next cycle resumes exactly where this one stopped.
MAX_EVENTS_PER_COLLECT = 50_000

# journalctl -t filters — the auth-relevant binaries this plugin classifies
# (parsers.py). Kept as an explicit whitelist (not a facility filter) because
# shadow-utils' facility choice (auth vs authpriv vs daemon) varies enough
# across distros that filtering by identifier is the only portable way not to
# silently miss "new user" events — see config.py / parsers.py.
_AUTH_IDENTIFIERS: tuple[str, ...] = (
    "sshd", "sudo", "su", "login",
    "useradd", "usermod", "userdel", "groupadd",
)

_CURSOR_NAMESPACE = "cursor"
_CURSOR_KEY_JOURNALD = "journald"
_CURSOR_KEY_FILE = "file"


async def collect(
    cfg: LinuxAuthConfig,
    since: str | None,  # noqa: ARG001 — cursor-based resume via ctx.kv; see module docstring
    ctx: PluginContext,
) -> AsyncIterator[RawEvent]:
    """Yield ``RawEvent``s for new auth-log lines since the last cursor.

    Dispatches on ``cfg.mode``:
      - ``"file"``: file-tail only.
      - ``"journald"``: journald only — an unavailable journal logs an error
        and yields nothing this cycle (explicit operator choice; no silent
        fallback).
      - ``"auto"`` (default): journald first; on ``JournaldUnavailableError``
        (missing binary, no systemd, unreadable journal), logs a warning once
        and falls back to file-tail for this cycle.

    Never raises out of its body — exceptions are caught and logged (hard
    rule). ``asyncio.CancelledError`` is NOT caught and therefore propagates.
    """
    if cfg.mode == "file":
        async for raw in _collect_file(cfg, ctx):
            yield raw
        return

    try:
        async for raw in _collect_journald(cfg, ctx):
            yield raw
        return
    except JournaldUnavailableError as exc:
        if cfg.mode == "journald":
            logger.error(
                "linux_auth: journald unavailable and mode='journald' pins it "
                "explicitly — no fallback this cycle: %s", exc,
            )
            return
        logger.warning(
            "linux_auth: journald unavailable (%s); falling back to file-tail "
            "of %s for this cycle (mode='auto')", exc, cfg.auth_log_path,
        )

    async for raw in _collect_file(cfg, ctx):
        yield raw


# ---------------------------------------------------------------------------
# journald mode
# ---------------------------------------------------------------------------


async def _collect_journald(
    cfg: LinuxAuthConfig, ctx: PluginContext
) -> AsyncIterator[RawEvent]:
    """Yield RawEvents from the systemd journal, resuming from the stored cursor.

    Follows the documented two-call idiom (resolve_start → read, persist the
    pivot before draining, persist the final cursor once per completed cycle)
    from ``firewatch_sdk.localhost.journald``'s module docstring exactly.
    """
    journalctl_path = cfg.journalctl_bin
    reader = JournaldReader(identifiers=_AUTH_IDENTIFIERS, journalctl_bin=journalctl_path)
    stored = await ctx.kv.get(_CURSOR_NAMESPACE, _CURSOR_KEY_JOURNALD)
    pos = await reader.resolve_start(stored or "tail")
    if pos != stored:
        await ctx.kv.put(_CURSOR_NAMESPACE, _CURSOR_KEY_JOURNALD, pos)

    last = pos
    received = datetime.now(timezone.utc)
    count = 0
    # aclosing (not a bare `async for`): a `break` on MAX_EVENTS_PER_COLLECT
    # must still deterministically run the reader's own subprocess-cleanup
    # `finally` (JournaldReader._stream) — an ordinary `async for` loop exited
    # via `break` does NOT guarantee the underlying async generator's aclose()
    # runs promptly, which would leak the journalctl subprocess until GC.
    async with contextlib.aclosing(reader.read(pos)) as records:
        async for record, cursor in records:
            if record is not None:
                raw = _journald_record_to_raw(record, received)
                if raw is not None:
                    yield raw
                    count += 1
            last = cursor
            if count >= MAX_EVENTS_PER_COLLECT:
                logger.warning(
                    "linux_auth: hit MAX_EVENTS_PER_COLLECT=%d (journald); "
                    "stopping early — the next cycle resumes from this cursor.",
                    MAX_EVENTS_PER_COLLECT,
                )
                break

    await ctx.kv.put(_CURSOR_NAMESPACE, _CURSOR_KEY_JOURNALD, last)


def _journald_record_to_raw(
    record: dict[str, Any], received: datetime
) -> RawEvent | None:
    """Build a RawEvent from one journald ``-o json`` record, or None if empty."""
    message = _extract_message(record)
    if not message:
        return None
    data: dict[str, Any] = {"message": message, "reader": "journald"}
    ts = _extract_realtime_timestamp(record)
    if ts is not None:
        data["timestamp"] = ts.isoformat()
    return RawEvent(source_type="linux_auth", received_at=received, data=data)


def _extract_message(record: dict[str, Any]) -> str:
    """Return the record's MESSAGE field as text.

    journald's JSON export represents a non-UTF-8-safe MESSAGE as an array of
    byte values (systemd.journal-fields(7) / JOURNAL_EXPORT_FORMATS) rather
    than a string; decoded defensively here so a binary-payload message never
    crashes normalization — it just degrades to best-effort text.
    """
    msg = record.get("MESSAGE")
    if isinstance(msg, str):
        return msg
    if isinstance(msg, list):
        try:
            return bytes(int(b) for b in msg).decode("utf-8", errors="replace")
        except (ValueError, TypeError):
            return ""
    return ""


def _extract_realtime_timestamp(record: dict[str, Any]) -> datetime | None:
    """Parse journald's ``__REALTIME_TIMESTAMP`` (microseconds since epoch, as
    a decimal string) into a UTC datetime, or None if absent/malformed."""
    raw_ts = record.get("__REALTIME_TIMESTAMP")
    if raw_ts is None:
        return None
    try:
        micros = int(raw_ts)
    except (ValueError, TypeError):
        return None
    return datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc)


# ---------------------------------------------------------------------------
# file-tail mode
# ---------------------------------------------------------------------------


async def _collect_file(
    cfg: LinuxAuthConfig, ctx: PluginContext
) -> AsyncIterator[RawEvent]:
    """Yield RawEvents by tailing the plain-text auth log file.

    Note: unlike journald (which carries an exact ``__REALTIME_TIMESTAMP` per
    entry), a classic ``auth.log`` line's embedded BSD/RFC-3164 timestamp
    (e.g. ``"Jun 15 08:00:00"``) has no year and is ambiguous to parse
    reliably — so this path does NOT attempt it and leaves ``"timestamp"``
    unset; ``normalize()`` falls back to the collection wall-clock
    (``raw.received_at``), which is an acceptable approximation for a
    tailed, near-real-time file (this is the documented fallback path;
    journald is the primary, timestamp-accurate interface).
    """
    reader = FileTailReader(cfg.auth_log_path)
    stored = await ctx.kv.get(_CURSOR_NAMESPACE, _CURSOR_KEY_FILE)
    try:
        pos = await reader.resolve_start(stored or "tail")
    except FileTailUnavailableError as exc:
        logger.error(
            "linux_auth: file-tail unavailable for %s: %s", cfg.auth_log_path, exc
        )
        return
    if pos != stored:
        await ctx.kv.put(_CURSOR_NAMESPACE, _CURSOR_KEY_FILE, pos)

    last = pos
    received = datetime.now(timezone.utc)
    count = 0
    try:
        # aclosing — see the matching comment in _collect_journald: a `break`
        # on MAX_EVENTS_PER_COLLECT must still deterministically close the
        # tailed file handle rather than depend on GC.
        async with contextlib.aclosing(reader.read(pos)) as lines:
            async for line, cursor in lines:
                if line is not None:
                    data: dict[str, Any] = {"message": line, "reader": "file"}
                    yield RawEvent(
                        source_type="linux_auth", received_at=received, data=data
                    )
                    count += 1
                last = cursor
                if count >= MAX_EVENTS_PER_COLLECT:
                    logger.warning(
                        "linux_auth: hit MAX_EVENTS_PER_COLLECT=%d (file-tail); "
                        "stopping early — the next cycle resumes from this cursor.",
                        MAX_EVENTS_PER_COLLECT,
                    )
                    break
    except FileTailUnavailableError as exc:
        logger.error(
            "linux_auth: file-tail read error for %s: %s", cfg.auth_log_path, exc
        )

    await ctx.kv.put(_CURSOR_NAMESPACE, _CURSOR_KEY_FILE, last)
