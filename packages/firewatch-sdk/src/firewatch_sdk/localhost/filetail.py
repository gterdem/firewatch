"""``FileTailReader`` — the plain-file fallback for non-systemd hosts (ADR-0065 §3).

Offset-tracked, rotation-aware (inode + size heuristics — the standard
``tail -F`` approach for both rotation strategies: rename-then-recreate, and
``copytruncate``). Kept as the fallback because paths and formats differ per
distro, and Arch-family installs have no classic ``/var/log/auth.log`` at all;
``JournaldReader`` is the primary interface.

The reader persists nothing itself: the caller passes a position in via
``start`` and stores what it gets back. **The invariant ADR-0065 doesn't spell
out, so it's stated here:** the caller must always hold a persistable
position, even on a zero-line cycle. Two-call idiom, enforced structurally
(``read()`` rejects the ``"tail"`` sentinel — see its docstring):

.. code-block:: python

    stored = await ctx.kv.get(NS, "cursor")
    pos = await reader.resolve_start(stored or "tail")   # first run: tail-from-now
    if pos != stored:
        await ctx.kv.put(NS, "cursor", pos)               # persist the pivot BEFORE draining
    async for line, cursor in reader.read(pos):
        yield raw_event(line)
        last = cursor
    await ctx.kv.put(NS, "cursor", last)                  # once per cycle, at drain end

Persist once per completed cycle (plus the pivot immediately after
resolution) — NOT per line. Per-line ``ctx.kv`` writes turn a burst of
appended lines into thousands of KV writes; end-of-cycle persistence gives
at-least-once delivery, whose replays the core's ``(source_type, source_id)``
dedup already absorbs. At-most-once is the wrong failure mode for a security
tool.

**Drain contract:** ``read()`` is one-shot, like ``JournaldReader`` (no
``-f``/follow) — it drains whatever is currently available, handles at most
one rotation cascade, and returns. It never blocks waiting for more lines to
be appended, so a consuming ``collect()`` cycle always terminates (ADR-0031's
collect trigger and ADR-0034's action interleaving assume terminating
cycles). Cadence belongs to the supervisor's poll interval, not the reader —
there is no ``poll_interval`` parameter. If sub-poll-interval latency is ever
needed, a separate ``follow()`` method would back it with zero change to this
drain contract.
"""
from __future__ import annotations

import logging
from collections.abc import AsyncGenerator, AsyncIterator
from pathlib import Path
from typing import TextIO

from firewatch_sdk.localhost.errors import FileTailUnavailableError

logger = logging.getLogger("firewatch.sdk.localhost.filetail")


class FileTailReader:
    """Tails a single plain-text log file, surviving rename or truncate rotation."""

    def __init__(self, path: str | Path, *, encoding: str = "utf-8") -> None:
        self._path = Path(path)
        self._encoding = encoding

    async def read(self, start: str) -> AsyncGenerator[tuple[str, str], None]:
        """Drain every line currently available after ``start``, then return.

        ``start`` MUST be one of (no default — the caller always states one):
          - ``"head"`` — read the file from byte offset 0.
          - any other string — an opaque ``"<inode>:<offset>"`` cursor
            previously yielded by this reader (or by ``resolve_start()``);
            resumes from that byte offset if the file's inode is unchanged,
            otherwise (rotated since the cursor was recorded) resumes from
            the head of the current file so no content is permanently missed.

        The literal ``"tail"`` is REJECTED with ``ValueError`` — it is not a
        valid position, only a request to *find* one. This is enforced
        structurally (the same poka-yoke principle as ``ScopedKV`` closing
        over ``source_type``) so a plugin author cannot skip the resolution
        step and reintroduce the quiet-host data-loss bug ``resolve_start()``
        exists to prevent: call ``resolve_start("tail")`` first, persist its
        result, then pass THAT to ``read()`` — see ``resolve_start()``'s
        docstring for the full scenario.

        One-shot drain, not a follow loop: yields every complete line
        currently available (across at most one rotation cascade — see
        ``_check_rotation``), then returns. It never waits for more lines to
        be appended; the caller's poll loop provides cadence.

        Never raises out of the loop once draining begins: a transient
        stat/read error (e.g. the file briefly missing mid-rotation) is
        logged and treated as "nothing more available right now" rather than
        propagated. Cancellation (or explicit early ``aclose()``) closes the
        open file handle promptly.
        """
        if start == "tail":
            raise ValueError(
                'read() does not accept the "tail" sentinel directly — call '
                'resolve_start("tail") first, persist its result, then pass '
                "that concrete position to read(). Accepting \"tail\" here "
                "would let a caller silently skip lines appended between "
                "polls; see resolve_start()'s docstring."
            )
        fh, inode = self._open_at_start(start)
        try:
            while True:
                # Fully drain whatever is currently available BEFORE checking
                # for rotation — a rename rotation must never skip content
                # that was still unread in the old (now-renamed) file, since
                # our open file handle keeps reading it by inode regardless
                # of what the path now points to.
                async for line, cursor in self._yield_available(fh, inode):
                    yield line, cursor

                action, inode = self._check_rotation(fh, inode)
                if action == "reopened":
                    fh.close()
                    fh = self._path.open("r", encoding=self._encoding)
                    continue  # drain the new file immediately
                if action == "truncated":
                    continue  # already seeked to 0; drain immediately
                return  # nothing more available and no rotation — drain complete
        finally:
            fh.close()

    # ------------------------------------------------------------------ #
    # Start-position resolution — MUST be called (and its result persisted)
    # before draining, or a quiet "tail" cycle silently loses appended lines
    # ------------------------------------------------------------------ #

    async def resolve_start(self, start: str) -> str:
        """Resolve ``"head"`` / ``"tail"`` / a cursor into a concrete, persistable position.

        Same bootstrap-gap fix as ``JournaldReader.resolve_start`` (see its
        docstring for the full data-loss scenario) applied here: establishing
        "now" and draining for new lines are two separate operations, so the
        gap between them can never be zero. If the only cursors a caller can
        persist are the ones attached to yielded lines, a quiet drain cycle
        (no lines appended yet) gives it nothing to store — the next cycle
        then has no stored cursor either, re-resolves ``"tail"`` from
        scratch, and its new end-of-file position is *later* than the first,
        silently skipping anything appended in between. This recurs on every
        quiet cycle, so on a quiet log it can lose lines forever.

        The fix: always return something concrete to persist immediately,
        before any draining happens.
          - ``"head"`` resolves to itself — reading from byte 0 always yields
            real per-line cursors as soon as anything exists.
          - ``"tail"`` resolves to ``"<inode>:<current size>"`` via a plain
            ``stat()`` — no file handle is opened, no draining is started. An
            existing-but-empty file legitimately resolves to ``"<inode>:0"``.
            Note: resolving at the current size can land mid-line if the
            writer hasn't flushed its trailing newline yet — the first line
            ``read()`` yields from that position may then be a fragment, not
            a full line. This is acceptable: consumers must already tolerate
            unparseable/partial lines from any log source, and the
            alternative (waiting to find a newline boundary before returning
            a position) would reintroduce a bootstrap gap of its own.
          - Any other string is already a concrete cursor and is returned
            unchanged (idempotent).

        Unlike ``JournaldReader`` (where an empty journal is a normal,
        expected state), a target file that does not exist AT ALL is treated
        as a genuine "cannot run at all" precondition, consistent with
        ``read()``'s own typed-error contract for an unreadable path: raises
        ``FileTailUnavailableError`` rather than returning a sentinel.
        """
        if start != "tail":
            return start  # "head", or an already-concrete cursor — unchanged
        try:
            st = self._path.stat()
        except OSError as exc:
            raise FileTailUnavailableError(
                f"Cannot resolve tail position for {self._path}: {exc}. "
                "Check the path exists and is readable by this user."
            ) from exc
        return f"{st.st_ino}:{st.st_size}"

    def _open_at_start(self, start: str) -> tuple[TextIO, int]:
        """Open the file at an already-resolved start position.

        ``start`` here is always ``"head"`` or a concrete cursor — ``read()``
        rejects ``"tail"`` with ``ValueError`` before ever calling this; the
        caller is required to resolve it via ``resolve_start()`` up front.
        """
        try:
            fh = self._path.open("r", encoding=self._encoding)
        except OSError as exc:
            raise FileTailUnavailableError(
                f"Cannot open {self._path} for tailing: {exc}. Check the path "
                "exists and is readable by this user."
            ) from exc

        inode = self._path.stat().st_ino
        if start != "head":
            offset = self._resume_offset(start, current_inode=inode)
            fh.seek(offset)
        return fh, inode

    @staticmethod
    def _resume_offset(cursor: str, *, current_inode: int) -> int:
        inode_str, sep, offset_str = cursor.partition(":")
        if not sep:
            raise FileTailUnavailableError(f"Malformed cursor: {cursor!r}")
        try:
            stored_inode = int(inode_str)
            stored_offset = int(offset_str)
        except ValueError as exc:
            raise FileTailUnavailableError(f"Malformed cursor: {cursor!r}") from exc
        if stored_inode != current_inode:
            # Rotated since the cursor was recorded (e.g. across a restart) —
            # resume from the head of the current file rather than risk
            # permanently missing content that predates our knowledge of it.
            logger.info(
                "FileTailReader: %s inode changed since cursor %r was recorded; "
                "resuming from head of the current file.",
                current_inode, cursor,
            )
            return 0
        return stored_offset

    # ------------------------------------------------------------------ #
    # Poll loop internals
    # ------------------------------------------------------------------ #

    async def _yield_available(
        self, fh: TextIO, inode: int
    ) -> AsyncIterator[tuple[str, str]]:
        """Yield every complete line currently available, leaving a trailing
        partial line (writer hasn't flushed its newline yet) unconsumed."""
        while True:
            pos = fh.tell()
            line = fh.readline()
            if not line or not line.endswith("\n"):
                fh.seek(pos)
                return
            offset = fh.tell()
            yield line[:-1], f"{inode}:{offset}"

    def _check_rotation(self, fh: TextIO, inode: int) -> tuple[str, int]:
        """Detect rotation once the current file has been fully drained.

        Returns ``(action, inode)`` where ``action`` is ``"reopened"``
        (rename/recreate — caller must close ``fh`` and open a fresh handle),
        ``"truncated"`` (copytruncate — already seeked ``fh`` to 0, same
        handle), or ``"none"``. Only meaningful once ``_yield_available`` has
        found nothing more at the current position — draining first (in
        ``read()``) means a rename rotation never skips content that was
        still unread in the old (now-renamed) file.
        """
        try:
            st = self._path.stat()
        except OSError as exc:
            logger.debug(
                "FileTailReader: stat failed for %s (%s); retrying next poll",
                self._path, exc,
            )
            return "none", inode

        if st.st_ino != inode:
            return "reopened", st.st_ino
        if st.st_size < fh.tell():
            # Truncated in place (copytruncate) — same inode, smaller size.
            fh.seek(0)
            return "truncated", inode
        return "none", inode
