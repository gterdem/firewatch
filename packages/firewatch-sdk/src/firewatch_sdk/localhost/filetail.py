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

**Security — symlinks are refused by default.** Every open (initial and
rotation-reopen) is atomic (``os.O_NOFOLLOW`` — no lstat-then-open TOCTOU
gap) and refuses anything that isn't a regular file. This matters because
this reader tails service-owned log directories (e.g. ClamAV's, #2): if that
service account is compromised, an attacker who can write to its log
directory could otherwise replace the log file with a symlink to
``/etc/shadow`` or an SSH private key, and its contents would flow into
normalized events, the UI, and AI sample context as if they were log lines —
local-attacker-writable-dir → arbitrary-file-disclosure. A FIFO at that path
is refused too (opening one for blocking read would hang the reader
forever). Distros that legitimately use a symlinked canonical log name need
explicit opt-in: ``FileTailReader(path, follow_symlinks=True)``.
"""
from __future__ import annotations

import errno
import logging
import os
import stat as stat_module
from collections.abc import AsyncGenerator, AsyncIterator
from pathlib import Path
from typing import TextIO

from firewatch_sdk.localhost.errors import FileTailUnavailableError

logger = logging.getLogger("firewatch.sdk.localhost.filetail")

_SYMLINK_REFUSED_MSG = (
    "{path} is a symlink; refusing to follow it by default. A compromised "
    "process with write access to this directory could otherwise redirect "
    "this reader to an arbitrary file (e.g. /etc/shadow or an SSH private "
    "key), and its contents would flow into normalized events. If this log "
    "path is a legitimate distro symlink convention, construct "
    "FileTailReader(path, follow_symlinks=True) to opt in explicitly."
)
_NON_REGULAR_FILE_MSG = (
    "{path} is not a regular file; refusing to tail it (a FIFO would block "
    "forever; a device or socket is never a plain log file)."
)


class FileTailReader:
    """Tails a single plain-text log file, surviving rename or truncate rotation.

    ``follow_symlinks`` (default ``False``, safe-by-default): when ``False``,
    every open refuses a symlink at ``path`` — see the module docstring's
    Security note. Set ``True`` only for a deliberately symlinked canonical
    log name; the ultimate target is still required to be a regular file
    either way.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        encoding: str = "utf-8",
        follow_symlinks: bool = False,
    ) -> None:
        self._path = Path(path)
        self._encoding = encoding
        self._follow_symlinks = follow_symlinks

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

        Never raises out of the loop once draining begins for a TRANSIENT
        failure: a stat/read error (e.g. the file briefly missing
        mid-rotation) is logged and treated as "nothing more available right
        now" rather than propagated. The one exception is security-relevant,
        not transient: if a rotation-triggered reopen finds a symlink or a
        non-regular file at ``path`` (see the module docstring's Security
        note), that raises ``FileTailUnavailableError`` even after lines have
        already been yielded this cycle — this is a hard stop, not a hiccup
        to retry past. Cancellation (or explicit early ``aclose()``) closes
        the open file handle promptly.
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

                action, _ = self._check_rotation(fh, inode)
                if action == "reopened":
                    fh.close()
                    # _safe_open, not a bare open() — refuses a symlink/
                    # non-regular file atomically (see module docstring).
                    fh, inode = self._safe_open(self._path)
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
        ``FileTailUnavailableError`` rather than returning a sentinel. The
        same is true of a symlink or non-regular file at ``path`` — see the
        module docstring's Security note.
        """
        if start != "tail":
            return start  # "head", or an already-concrete cursor — unchanged
        st = self._stat_checked(self._path)
        return f"{st.st_ino}:{st.st_size}"

    def _open_at_start(self, start: str) -> tuple[TextIO, int]:
        """Open the file at an already-resolved start position.

        ``start`` here is always ``"head"`` or a concrete cursor — ``read()``
        rejects ``"tail"`` with ``ValueError`` before ever calling this; the
        caller is required to resolve it via ``resolve_start()`` up front.
        """
        fh, inode = self._safe_open(self._path)
        if start != "head":
            offset = self._resume_offset(start, current_inode=inode)
            fh.seek(offset)
        return fh, inode

    # ------------------------------------------------------------------ #
    # Symlink-safe filesystem access (Security — see module docstring)
    # ------------------------------------------------------------------ #

    def _stat_checked(self, path: Path) -> os.stat_result:
        """``lstat()`` (never follows) and classify ``path``, WITHOUT opening it.

        Used where only a stat is needed (``resolve_start()``, rotation
        detection) — the actual read path is separately hardened by
        ``_safe_open`` with an atomic ``O_NOFOLLOW`` open, so there is no
        TOCTOU gap between "checked" and "read" for the data that matters.
        """
        try:
            st = path.lstat()
        except OSError as exc:
            raise FileTailUnavailableError(
                f"Cannot stat {path}: {exc}. Check the path exists and is "
                "readable by this user."
            ) from exc

        if stat_module.S_ISLNK(st.st_mode):
            if not self._follow_symlinks:
                raise FileTailUnavailableError(_SYMLINK_REFUSED_MSG.format(path=path))
            try:
                st = path.stat()  # explicit opt-in: follow to the target
            except OSError as exc:
                raise FileTailUnavailableError(
                    f"Cannot stat symlink target of {path}: {exc}."
                ) from exc

        if not stat_module.S_ISREG(st.st_mode):
            raise FileTailUnavailableError(_NON_REGULAR_FILE_MSG.format(path=path))
        return st

    def _safe_open(self, path: Path) -> tuple[TextIO, int]:
        """Open ``path`` for reading, atomically refusing a symlink (unless
        ``follow_symlinks``) and any non-regular file.

        ``O_NOFOLLOW`` makes the kernel itself refuse a symlink in the same
        syscall as the open — no separate lstat()-then-open() race an
        attacker could win by swapping the file in between. ``O_NONBLOCK``
        additionally prevents the open() call itself from hanging forever if
        ``path`` is a FIFO with no writer yet; the FIFO is then rejected by
        the ``S_ISREG`` check below rather than blocking the caller.
        """
        flags = os.O_RDONLY | os.O_NONBLOCK
        if not self._follow_symlinks:
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise FileTailUnavailableError(
                    _SYMLINK_REFUSED_MSG.format(path=path)
                ) from exc
            raise FileTailUnavailableError(
                f"Cannot open {path} for tailing: {exc}. Check the path "
                "exists and is readable by this user."
            ) from exc

        try:
            st = os.fstat(fd)
            if not stat_module.S_ISREG(st.st_mode):
                raise FileTailUnavailableError(_NON_REGULAR_FILE_MSG.format(path=path))
            return os.fdopen(fd, "r", encoding=self._encoding), st.st_ino
        except BaseException:
            os.close(fd)
            raise

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
        (rename/recreate — caller must close ``fh`` and open a fresh handle
        via ``_safe_open``, never a bare ``open()``), ``"truncated"``
        (copytruncate — already seeked ``fh`` to 0, same handle), or
        ``"none"``. Only meaningful once ``_yield_available`` has found
        nothing more at the current position — draining first (in
        ``read()``) means a rename rotation never skips content that was
        still unread in the old (now-renamed) file.

        Matches ``_safe_open``'s own inode basis: ``lstat()`` (never follows)
        when symlinks are refused, so a path that BECAME a symlink shows up
        as a changed inode here too (triggering "reopened", which
        ``_safe_open`` then atomically refuses) — or a following ``stat()``
        when ``follow_symlinks`` is set, since ``_safe_open`` tracks the
        TARGET's inode in that mode and comparing against the symlink's own
        (constant, but different) inode here would misdetect "reopened"
        forever, reopening in an infinite loop even though nothing changed.
        The returned ``"reopened"`` inode is advisory only either way — the
        real symlink/non-regular-file enforcement happens atomically in
        ``_safe_open`` when the caller actually reopens.
        """
        try:
            st = self._path.stat() if self._follow_symlinks else self._path.lstat()
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
