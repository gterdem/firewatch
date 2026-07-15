"""``FileTailReader`` — the plain-file fallback for non-systemd hosts (ADR-0065 §3).

Offset-tracked, rotation-aware (inode + size heuristics — the standard
``tail -F`` approach for both rotation strategies: rename-then-recreate, and
``copytruncate``). Kept as the fallback because paths and formats differ per
distro, and Arch-family installs have no classic ``/var/log/auth.log`` at all;
``JournaldReader`` is the primary interface.

The reader persists nothing itself: the caller passes the last cursor in via
``start`` and stores the newly yielded cursor. The cursor is the opaque string
``"<inode>:<byte-offset>"``.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator, AsyncIterator
from pathlib import Path
from typing import TextIO

from firewatch_sdk.localhost.errors import FileTailUnavailableError

logger = logging.getLogger("firewatch.sdk.localhost.filetail")

_DEFAULT_POLL_INTERVAL = 1.0


class FileTailReader:
    """Tails a single plain-text log file, surviving rename or truncate rotation."""

    def __init__(self, path: str | Path, *, encoding: str = "utf-8") -> None:
        self._path = Path(path)
        self._encoding = encoding

    async def read(
        self, start: str, *, poll_interval: float = _DEFAULT_POLL_INTERVAL
    ) -> AsyncGenerator[tuple[str, str], None]:
        """Yield ``(line, cursor)`` pairs positioned after ``start``.

        ``start`` MUST be one of (no default — the caller always states one):
          - ``"head"`` — read the file from byte offset 0.
          - ``"tail"`` — skip all existing content; only lines appended from now
            on are yielded. Endpoint plugins default to this on first run.
          - any other string — an opaque ``"<inode>:<offset>"`` cursor
            previously yielded by this reader; resumes from that byte offset if
            the file's inode is unchanged, otherwise (rotated since the cursor
            was recorded) resumes from the head of the current file so no
            content is permanently missed.

        Never raises out of the loop once polling begins: a transient stat/read
        error (e.g. the file briefly missing mid-rotation) is logged and retried
        on the next poll. Cancellation closes the open file handle promptly.
        """
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
                    continue  # drain the new file immediately, no sleep
                if action == "truncated":
                    continue  # already seeked to 0; drain immediately
                await asyncio.sleep(poll_interval)
        finally:
            fh.close()

    # ------------------------------------------------------------------ #
    # Start-position resolution
    # ------------------------------------------------------------------ #

    def _open_at_start(self, start: str) -> tuple[TextIO, int]:
        try:
            fh = self._path.open("r", encoding=self._encoding)
        except OSError as exc:
            raise FileTailUnavailableError(
                f"Cannot open {self._path} for tailing: {exc}. Check the path "
                "exists and is readable by this user."
            ) from exc

        inode = self._path.stat().st_ino
        if start == "head":
            pass  # already positioned at offset 0
        elif start == "tail":
            fh.seek(0, 2)  # SEEK_END
        else:
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
