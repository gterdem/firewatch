"""ClamAV collector — SDK reader wiring + ``ctx.kv`` cursor persistence (ADR-0065 §3).

Journald-first, file-tail fallback (ADR-0065 §1/§3): ``cfg.mode`` selects which SDK
local-log reader drives collection. Both readers yield ``(record | None, cursor)`` pairs
(a ``None`` record means "an oversized line/entry was skipped — advance the cursor past
it anyway", ADR-0065 §3 / issue #60) — this module normalizes that into a single
``(text | None, cursor)`` shape regardless of reader (``_iter_journald_text`` /
``_iter_filetail_text``), then recognizes ClamAV's detection line shape on top.

Detection line shape (docs/internal/home-endpoint-security-analysis.md,
docs.clamav.net): ``<path>: <signature> FOUND``, e.g.
``/home/user/eicar.com: Win.Test.EICAR_HDB-1 FOUND``.

Action-outcome pairing (issue #2 acceptance criteria — "action mapped honestly … a
configured remove/quarantine outcome … → BLOCK"): when clamscan/clamdscan/clamonacc is
invoked with ``--remove``/``--move=DIRECTORY``, ClamAV's documented behavior
(docs.clamav.net/manual/Usage/Scanning.html "Options") is to emit a companion status line
for the SAME path immediately after its FOUND line — e.g. ``<path>: Removed.`` or
``<path>: Moved to '<dest>'.``. **Judgment call, flagged for review:** this exact wording
could not be verified against a live ClamAV install in this sandboxed environment; if a
real deployment's companion line differs, ``_match_outcome`` simply won't match it and the
detection is honestly reported as ``ALERT`` (detect-only) rather than a wrong guess —
never the reverse (see ``_match_outcome``).

Resume is cursor-based (ADR-0065 §3), not ``since``-based: the ``since`` watermark
``collect()`` receives per the ``PullSource`` protocol is intentionally unused — the SDK
reader's own cursor, persisted in ``ctx.kv``, already gives exact, duplicate-free resume
(see ``firewatch_sdk.localhost.journald``/``filetail``'s module docstrings for the
documented two-call ``resolve_start()``/``read()`` idiom this follows verbatim).

Cursor KV key includes ``ctx.source_id``: ``ScopedKV`` is bound only to this plugin's
``type_key`` (ADR-0025) — NOT per ``source_id`` — so two named instances of this plugin
(e.g. a future Hub with two ``clamav`` sources) would silently clobber each other's cursor
without this. Namespacing by ``source_id`` is forward-defensive, not contract-mandated
(M1 is Solo/single-instance) — a deliberate, cheap safety margin, not "branching on
source_id for detection" (Flag B is about detection logic, not KV key partitioning).
"""
from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timezone

from firewatch_sdk import PluginContext, RawEvent
from firewatch_sdk.localhost import FileTailReader, JournaldReader, LocalReaderError

from firewatch_clamav.config import ClamAVConfig
from firewatch_clamav.normalize import SOURCE_TYPE

logger = logging.getLogger("firewatch.clamav.collector")

_CURSOR_NAMESPACE = "cursor"

# Hard cap to avoid unbounded memory/emit volume in one collect() cycle (e.g. a long
# backlog after FireWatch was offline for a while). Mirrors firewatch_suricata's
# MAX_EVENTS_PER_COLLECT precedent.
_MAX_EVENTS_PER_COLLECT = 50_000

# ClamAV's detection line (LogSyslog / LogFile), e.g.
# "/home/user/eicar.com: Win.Test.EICAR_HDB-1 FOUND".
_FOUND_RE = re.compile(r"^(?P<path>.+): (?P<signature>\S+) FOUND$")

# Companion action line for the SAME path (see module docstring's "Judgment call" note).
_ACTION_RE = re.compile(r"^(?P<path>.+): (?P<verb>Removed|Moved to .+?)\.?$")


def _match_outcome(text: str, path: str) -> str | None:
    """Return ``"removed"`` / ``"moved"`` if *text* is *path*'s companion action line."""
    m = _ACTION_RE.match(text)
    if m is None or m["path"] != path:
        return None
    return "removed" if m["verb"] == "Removed" else "moved"


@dataclass
class _PendingDetection:
    path: str
    signature: str

    def to_raw_event(self, received_at: datetime, *, outcome: str | None = None) -> RawEvent:
        return RawEvent(
            source_type=SOURCE_TYPE,
            received_at=received_at,
            data={"path": self.path, "signature": self.signature, "outcome": outcome},
        )


# --------------------------------------------------------------------------------- #
# Reader-agnostic text stream
# --------------------------------------------------------------------------------- #


async def _iter_journald_text(
    reader: JournaldReader, pos: str
) -> AsyncIterator[tuple[str | None, str]]:
    async for record, cursor in reader.read(pos):
        if record is None:
            yield None, cursor
            continue
        message = record.get("MESSAGE")
        yield (message if isinstance(message, str) else None), cursor


async def _iter_filetail_text(
    reader: FileTailReader, pos: str
) -> AsyncIterator[tuple[str | None, str]]:
    async for line, cursor in reader.read(pos):
        yield line, cursor


def _build_reader(cfg: ClamAVConfig) -> JournaldReader | FileTailReader:
    if cfg.mode == "file":
        return FileTailReader(cfg.log_path, follow_symlinks=cfg.follow_symlinks)
    return JournaldReader(identifiers=tuple(cfg.identifiers))


def _cursor_key(cfg: ClamAVConfig, ctx: PluginContext) -> str:
    return f"{ctx.source_id}:{cfg.mode}"


# --------------------------------------------------------------------------------- #
# FOUND / companion-action-line pairing
# --------------------------------------------------------------------------------- #


async def _pair_detections(
    lines: AsyncIterator[tuple[str | None, str]], received_at: datetime
) -> AsyncIterator[tuple[RawEvent | None, str]]:
    """Turn a text-line stream into ``(RawEvent | None, cursor)`` pairs.

    A FOUND line opens a *pending* detection; the cursor for that line is held back
    (not yielded yet) until the detection is resolved — by a companion action line, by
    the next FOUND line, by an oversized-skip, or by end-of-stream. This bounds
    cancellation risk to zero: the persisted cursor never advances past an
    unresolved FOUND line, so a detection is never silently lost — at worst it is
    re-evaluated (and, absent a companion line by then, honestly reported as ALERT)
    on the next cycle.
    """
    pending: _PendingDetection | None = None
    held_cursor: str | None = None

    async for text, cursor in lines:
        if text is None:
            if pending is not None:
                yield pending.to_raw_event(received_at), cursor
                pending = None
            else:
                yield None, cursor
            continue

        found = _FOUND_RE.match(text)
        if found is not None:
            if pending is not None:
                assert held_cursor is not None  # set together with pending, below
                yield pending.to_raw_event(received_at), held_cursor
            pending = _PendingDetection(found["path"], found["signature"])
            held_cursor = cursor
            continue

        if pending is not None:
            outcome = _match_outcome(text, pending.path)
            yield pending.to_raw_event(received_at, outcome=outcome), cursor
            pending = None
            continue

        yield None, cursor

    if pending is not None:
        assert held_cursor is not None
        yield pending.to_raw_event(received_at), held_cursor


# --------------------------------------------------------------------------------- #
# Public collect()
# --------------------------------------------------------------------------------- #


async def collect(
    cfg: ClamAVConfig, since: str | None, ctx: PluginContext
) -> AsyncIterator[RawEvent]:
    """Yield ``RawEvent``s for ClamAV FOUND detections newer than the persisted cursor.

    ``since`` is accepted per the ``PullSource`` protocol but intentionally unused —
    see the module docstring's "Resume is cursor-based" note.

    Never raises out of its loop (PLUGIN_CONTRACT.md hard rule): a reader that cannot
    start at all (missing journalctl, unreadable log path, …) logs and returns; a
    mid-stream security-relevant failure (rotation-triggered symlink swap) is logged and
    ends the cycle. ``asyncio.CancelledError`` propagates.
    """
    reader = _build_reader(cfg)
    key = _cursor_key(cfg, ctx)
    stored = await ctx.kv.get(_CURSOR_NAMESPACE, key)

    try:
        pos = await reader.resolve_start(stored or "tail")
    except LocalReaderError as exc:
        logger.error(
            "firewatch.clamav.collector: cannot start collection (mode=%s): %s",
            cfg.mode, exc,
        )
        return
    if pos != stored:
        await ctx.kv.put(_CURSOR_NAMESPACE, key, pos)

    text_stream = (
        _iter_journald_text(reader, pos)
        if isinstance(reader, JournaldReader)
        else _iter_filetail_text(reader, pos)
    )
    received_at = datetime.now(timezone.utc)

    last = pos
    count = 0
    try:
        async for raw, cursor in _pair_detections(text_stream, received_at):
            last = cursor
            if raw is None:
                continue
            yield raw
            count += 1
            if count >= _MAX_EVENTS_PER_COLLECT:
                logger.warning(
                    "firewatch.clamav.collector: hit MAX_EVENTS_PER_COLLECT=%d; "
                    "stopping early this cycle.",
                    _MAX_EVENTS_PER_COLLECT,
                )
                break
    except asyncio.CancelledError:
        raise
    except LocalReaderError as exc:
        logger.error(
            "firewatch.clamav.collector: reader failed mid-cycle (mode=%s): %s",
            cfg.mode, exc,
        )
    finally:
        await ctx.kv.put(_CURSOR_NAMESPACE, key, last)
