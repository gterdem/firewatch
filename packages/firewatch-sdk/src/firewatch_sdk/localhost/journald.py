"""``JournaldReader`` — the primary local-log interface (ADR-0065 §3).

Shells out to ``journalctl -o json`` (zero native dependencies — no libsystemd
binding). Present and consistent across every mainstream systemd distro (Arch,
Ubuntu, Fedora, Debian), so reading it once here gives every endpoint plugin
multi-distro support for free.

Resume is cursor-based, not timestamp-based: each ``-o json`` record already
carries the entry's ``__CURSOR`` field — "an opaque text string that uniquely
describes the position of an entry in the journal and is portable across
machines, platforms and journal files" (systemd.journal-fields(7)). This reader
resumes via ``journalctl --after-cursor=``, which is exclusive of the cursor's
own entry, so resume neither duplicates nor skips (journalctl(1)).

The reader persists nothing itself: the caller passes a position in via
``start`` and stores what it gets back. **The invariant ADR-0065 doesn't spell
out, so it's stated here:** the caller must always hold a persistable
position, even on a zero-record cycle. Two-call idiom, enforced structurally
(``read()`` rejects the ``"tail"`` sentinel — see its docstring):

.. code-block:: python

    stored = await ctx.kv.get(NS, "cursor")
    pos = await reader.resolve_start(stored or "tail")   # first run: tail-from-now
    if pos != stored:
        await ctx.kv.put(NS, "cursor", pos)               # persist the pivot BEFORE draining
    async for record, cursor in reader.read(pos):
        yield raw_event(record)
        last = cursor
    await ctx.kv.put(NS, "cursor", last)                  # once per cycle, at drain end

Persist once per completed cycle (plus the pivot immediately after
resolution) — NOT per record. Per-record ``ctx.kv`` writes turn a burst of
events into thousands of KV writes; end-of-cycle persistence gives
at-least-once delivery, whose replays the core's ``(source_type, source_id)``
dedup already absorbs. At-most-once is the wrong failure mode for a security
tool.

Contract hard rules (mirrors PLUGIN_CONTRACT.md's PullSource.collect()):
  - ``read()`` MUST be cancellable (CancelledError propagates; the subprocess is
    always terminated, never orphaned).
  - Once streaming has yielded at least one record, a later failure is logged
    and the generator simply ends — it does NOT raise out of the loop.
  - A "cannot run at all" precondition (missing binary, unreadable journal,
    non-systemd host) raises ``JournaldUnavailableError`` — never a bare
    subprocess traceback — so a consuming plugin's ``collect()`` can catch it
    and continue (matching ``firewatch_suricata.collector.SSHConnectionError``).
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator, AsyncIterator, Sequence
from typing import Any

from firewatch_sdk.localhost.errors import JournaldUnavailableError

logger = logging.getLogger("firewatch.sdk.localhost.journald")

_SHOW_CURSOR_PREFIX = "-- cursor: "
_CURSOR_FIELD = "__CURSOR"

# RFC 5424 §6.2.1 Table 7 — syslog facility keyword -> numeric code. journalctl
# matches SYSLOG_FACILITY as the raw numeric string, so facility *names* (the
# ergonomic, documented-example form, e.g. "authpriv") are translated here.
FACILITY_NAME_TO_NUMBER: dict[str, str] = {
    "kern": "0", "user": "1", "mail": "2", "daemon": "3", "auth": "4",
    "syslog": "5", "lpr": "6", "news": "7", "uucp": "8", "cron": "9",
    "authpriv": "10", "ftp": "11",
    "local0": "16", "local1": "17", "local2": "18", "local3": "19",
    "local4": "20", "local5": "21", "local6": "22", "local7": "23",
}


async def _create_subprocess_exec(
    *argv: str, stdout: int, stderr: int
) -> asyncio.subprocess.Process:
    """Thin wrapper around ``asyncio.create_subprocess_exec``.

    Kept as a module-level function (rather than calling ``asyncio.*`` directly
    from ``JournaldReader``) so tests can ``monkeypatch.setattr(journald,
    "_create_subprocess_exec", fake)`` and supply fixture journal output — no
    live journald needed in CI (mirrors
    ``firewatch_suricata.collector``'s module-level ``asyncssh`` patch point).
    """
    return await asyncio.create_subprocess_exec(*argv, stdout=stdout, stderr=stderr)


class JournaldReader:
    """Iterates systemd journal entries via ``journalctl -o json``.

    Filters (all optional, all ANDed together when more than one kind is
    given — journalctl's own match semantics): ``identifiers`` (``-t``,
    ``SYSLOG_IDENTIFIER``, e.g. ``"clamd"``), ``facilities`` (``SYSLOG_FACILITY``
    match, names or raw numeric strings, e.g. ``"authpriv"``), and ``units``
    (``-u``, systemd unit name). Multiple values within one filter kind are
    OR'd (journalctl repeats-the-flag semantics).
    """

    def __init__(
        self,
        *,
        identifiers: Sequence[str] = (),
        facilities: Sequence[str] = (),
        units: Sequence[str] = (),
        journalctl_bin: str = "journalctl",
    ) -> None:
        self._identifiers = tuple(identifiers)
        self._facilities = tuple(facilities)
        self._units = tuple(units)
        self._journalctl_bin = journalctl_bin

    async def read(self, start: str) -> AsyncGenerator[tuple[dict[str, Any], str], None]:
        """Yield ``(record, cursor)`` pairs positioned after ``start``.

        ``start`` MUST be one of (no default — the caller always states one):
          - ``"head"`` — read the entire journal from the beginning.
          - any other string — an opaque ``__CURSOR`` value previously yielded
            by this reader (or by ``resolve_start()``); resumes strictly after
            it via ``--after-cursor``.

        The literal ``"tail"`` is REJECTED with ``ValueError`` — it is not a
        valid position, only a request to *find* one. This is enforced
        structurally (the same poka-yoke principle as ``ScopedKV`` closing
        over ``source_type``) so a plugin author cannot skip the resolution
        step and reintroduce the quiet-host data-loss bug ``resolve_start()``
        exists to prevent: call ``resolve_start("tail")`` first, persist its
        result, then pass THAT to ``read()`` — see ``resolve_start()``'s
        docstring for the full scenario.
        """
        if start == "tail":
            raise ValueError(
                'read() does not accept the "tail" sentinel directly — call '
                'resolve_start("tail") first, persist its result, then pass '
                "that concrete position to read(). Accepting \"tail\" here "
                "would let a caller silently re-pivot past events that "
                "arrive between polls; see resolve_start()'s docstring."
            )
        after_cursor = None if start == "head" else start

        async for record, cursor in self._stream(after_cursor):
            yield record, cursor

    # ------------------------------------------------------------------ #
    # Start-position resolution — MUST be called (and its result persisted)
    # before draining, or a quiet "tail" cycle silently loses events
    # ------------------------------------------------------------------ #

    async def resolve_start(self, start: str) -> str:
        """Resolve ``"head"`` / ``"tail"`` / a cursor into a concrete, persistable position.

        This exists to close a data-loss gap in naive ``"tail"`` bootstrapping:
        establishing "now" and draining are two separate operations, and the
        interval between them can never be zero. If the discovered pivot is
        only ever used *inside* ``read()`` and never handed back, a cycle that
        drains zero records (the common case — most polls see nothing new)
        gives the caller nothing to persist. The next cycle then has no stored
        cursor either, re-resolves ``"tail"`` from scratch, and its new pivot
        is *later* than the first — silently skipping anything that arrived in
        between. This does not self-correct: it recurs on every quiet cycle,
        so on a quiet machine (the common endpoint case) it can lose events
        forever, not just once.

        The fix is to always return something concrete the caller can persist
        immediately, before any draining happens:
          - ``"head"`` resolves to itself. Reading from the true beginning
            always yields real per-record cursors as soon as anything exists,
            so there is no bootstrap gap to close for ``"head"``.
          - ``"tail"`` resolves to the current end-of-journal cursor, found via
            a deliberately **unfiltered** ``journalctl -n 0 --show-cursor``
            probe (this reader's own identifier/facility/unit filters are
            NEVER applied here) — when a filter matches nothing at all,
            ``--show-cursor`` prints nothing, so filtering the probe itself
            would reintroduce exactly the "no position at all" failure this
            method exists to prevent. The printed cursor reflects the true
            journal tail regardless of filters whenever it fires, so the
            unfiltered probe is always at least as good as a filtered one.
          - If the RAW journal has never had a single entry written (not just
            none matching THIS reader's filters), tail and head denote the
            SAME position — there is no history to flood, so this resolves to
            ``"head"`` rather than a sentinel that would need re-resolving
            (and would reintroduce this exact bug in miniature: entries
            written between one empty probe and the next would be skipped).

        **Postcondition:** always returns ``"head"`` or a concrete cursor — a
        start sentinel (``"tail"``) never survives resolution.  Any other
        string is already a concrete cursor and is returned unchanged
        (idempotent).
        """
        if start != "tail":
            return start  # "head", or an already-concrete cursor — unchanged
        pivot = await self._discover_tail_cursor()
        return pivot if pivot is not None else "head"

    async def _discover_tail_cursor(self) -> str | None:
        """Return the current end-of-journal cursor, or None if the raw journal
        has never had an entry written.

        Uses ``journalctl -o json -n 0 --show-cursor`` with NO match filters
        (deliberately — see ``resolve_start``): ``-n 0`` shows zero entries;
        ``--show-cursor`` still prints a trailing ``-- cursor: <value>`` line
        marking the current tail position — a single cheap subprocess call,
        no history read.
        """
        argv = self._build_discovery_argv()
        proc = await self._spawn(argv)
        try:
            assert proc.stdout is not None
            cursor: str | None = None
            async for raw_line in proc.stdout:
                text = raw_line.decode("utf-8", errors="replace").rstrip("\n")
                if text.startswith(_SHOW_CURSOR_PREFIX):
                    cursor = text[len(_SHOW_CURSOR_PREFIX):].strip()
            returncode = await proc.wait()
            if cursor is None and returncode != 0:
                stderr_text = await self._read_stderr(proc)
                raise self._to_typed_error(returncode, stderr_text)
            return cursor
        finally:
            await self._terminate(proc)

    # ------------------------------------------------------------------ #
    # Main streaming loop
    # ------------------------------------------------------------------ #

    async def _stream(
        self, after_cursor: str | None
    ) -> AsyncIterator[tuple[dict[str, Any], str]]:
        extra = ["--after-cursor", after_cursor] if after_cursor is not None else []
        argv = self._build_argv(extra=extra)
        proc = await self._spawn(argv)
        yielded_any = False
        try:
            assert proc.stdout is not None
            async for raw_line in proc.stdout:
                record = self._parse_line(raw_line)
                if record is None:
                    continue
                cursor = record.get(_CURSOR_FIELD)
                if not isinstance(cursor, str):
                    logger.warning(
                        "JournaldReader: record missing %s; skipping", _CURSOR_FIELD
                    )
                    continue
                yielded_any = True
                yield record, cursor

            returncode = await proc.wait()
            if returncode != 0:
                stderr_text = await self._read_stderr(proc)
                if not yielded_any:
                    raise self._to_typed_error(returncode, stderr_text)
                logger.error(
                    "JournaldReader: journalctl exited %d mid-stream after "
                    "yielding records; stopping this cycle. stderr=%s",
                    returncode, stderr_text.strip(),
                )
        finally:
            await self._terminate(proc)

    # ------------------------------------------------------------------ #
    # Line parsing
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_line(raw_line: bytes) -> dict[str, Any] | None:
        text = raw_line.decode("utf-8", errors="replace").strip()
        if not text:
            return None
        try:
            record = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("JournaldReader: skipping unparseable line: %r", text[:200])
            return None
        if not isinstance(record, dict):
            return None
        return record

    # ------------------------------------------------------------------ #
    # journalctl argv construction
    # ------------------------------------------------------------------ #

    def _build_argv(self, *, extra: Sequence[str]) -> list[str]:
        argv = [self._journalctl_bin, "-o", "json", "--no-pager", *extra]
        for identifier in self._identifiers:
            argv += ["-t", identifier]
        for unit in self._units:
            argv += ["-u", unit]
        for facility in self._facilities:
            code = FACILITY_NAME_TO_NUMBER.get(facility, facility)
            argv.append(f"SYSLOG_FACILITY={code}")
        return argv

    def _build_discovery_argv(self) -> list[str]:
        """argv for the ``"tail"`` pivot probe — deliberately UNFILTERED.

        See ``resolve_start``: applying this reader's own identifier/facility/
        unit filters here would make ``--show-cursor`` print nothing at all
        whenever they currently match zero entries, which is exactly the
        "no position to persist" failure ``resolve_start`` exists to prevent.
        """
        return [self._journalctl_bin, "-o", "json", "--no-pager", "-n", "0", "--show-cursor"]

    # ------------------------------------------------------------------ #
    # Subprocess lifecycle
    # ------------------------------------------------------------------ #

    async def _spawn(self, argv: Sequence[str]) -> asyncio.subprocess.Process:
        try:
            return await _create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise JournaldUnavailableError(
                f"'{self._journalctl_bin}' was not found in PATH. This reader "
                "requires a systemd-based Linux host (Arch, Ubuntu, Fedora, "
                "Debian, …). Install systemd or ensure journalctl is on PATH."
            ) from exc
        except OSError as exc:
            raise JournaldUnavailableError(
                f"Could not start '{self._journalctl_bin}': {exc}"
            ) from exc

    @staticmethod
    async def _read_stderr(proc: asyncio.subprocess.Process) -> str:
        if proc.stderr is None:
            return ""
        data = await proc.stderr.read()
        return data.decode("utf-8", errors="replace")

    @staticmethod
    async def _terminate(proc: asyncio.subprocess.Process) -> None:
        """Terminate the subprocess if it is still running — never orphan it."""
        if proc.returncode is not None:
            return
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

    def _to_typed_error(
        self, returncode: int, stderr_text: str
    ) -> JournaldUnavailableError:
        lowered = stderr_text.lower()
        if "permission denied" in lowered:
            return JournaldUnavailableError(
                "Permission denied reading the systemd journal. Add this user "
                "to the 'systemd-journal' group "
                "(sudo usermod -aG systemd-journal $USER) and re-login, or run "
                "with sufficient privileges."
            )
        if "no journal files were found" in lowered:
            return JournaldUnavailableError(
                "No systemd journal files were found on this host. This reader "
                "requires a systemd-based Linux host with journald running."
            )
        return JournaldUnavailableError(
            f"journalctl exited with status {returncode}: {stderr_text.strip()}"
        )
