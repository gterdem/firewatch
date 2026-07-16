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
        if line is not None:                              # None: cursor-only advancement
            yield raw_event(line)                          # (an oversized line was skipped)
        last = cursor
    await ctx.kv.put(NS, "cursor", last)                  # once per cycle, at drain end

Persist once per completed cycle (plus the pivot immediately after
resolution) — NOT per line. Per-line ``ctx.kv`` writes turn a burst of
appended lines into thousands of KV writes; end-of-cycle persistence gives
at-least-once delivery, whose replays the core's ``(source_type, source_id)``
dedup already absorbs. At-most-once is the wrong failure mode for a security
tool.

**Invariant — the ``(None, cursor)`` yield shape.** ``read()`` MAY yield a
``None`` line paired with a cursor. This reuses ``JournaldReader``'s
``(record | None, cursor)`` shape verbatim (the architect's ruling on PR #36 /
issue #60: this state is fundamental to bounded cursor-streaming, not a
journald quirk) — the SAME narrow, load-bearing exception to "every yield
carries a record", governed by the SAME rule:

  - Emitted **at most once per** ``read()`` **call**.
  - Emitted **only as the final item** of that call.
  - Emitted **only when the cycle yielded zero lines** — i.e. nothing else
    was readable this cycle either.
  - MUST NOT be extended to any other case — today, that is a complete
    (newline-terminated) line over ``_MAX_LINE_CHARS``, which can be
    *positioned* (this reader's own offset arithmetic advances past it) but
    never *read* (it is never buffered whole), so without this sentinel the
    stored cursor would never move and the same line would be re-served,
    and re-skipped, forever — a correctness bug against the cursor-resume
    guarantee, and a cheap DoS.

Unlike ``JournaldReader`` (which must re-request the oversized entry via a
subprocess peek to recover its cursor — see ``journald.py``'s
``_peek_cursor_after``), this reader's skip cursor is pure offset arithmetic:
``inode:<byte offset past the line's own newline>``, computed directly while
scanning past it — no second read needed.

**Bounded reads.** ``_MAX_LINE_CHARS`` (16 MiB, consistent with
``JournaldReader``'s ``_MAX_LINE_BYTES`` by value) caps each line the same
way ``fh.readline()`` used to be unbounded: a single arbitrarily long line
(e.g. a compromised service account writing to its own watched log — the
same threat model as ``JournaldReader``'s Finding 2, and not theoretical:
#2's ClamAV plugin points this reader at exactly such a directory) would
otherwise be buffered whole into memory, OOMing the process. One deliberate
difference from ``JournaldReader``'s bound — reflected in the name, not just
the docs: this reader operates in TEXT mode (``TextIOWrapper``), so
``_MAX_LINE_CHARS`` counts DECODED CHARACTERS, not raw bytes like
``JournaldReader``'s byte-exact ``_MAX_LINE_BYTES`` — worst case (every
character a 4-byte UTF-8 codepoint) admits up to ~64 MiB of underlying bytes
for one line rather than a strict 16 MiB ceiling. This is still a fixed,
generous, FINITE bound — the defect this closes is unbounded growth, not an
exact byte ceiling — and switching to a byte-exact bound would require
reopening the file in binary mode, a larger structural change than this fix
warrants.

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
from dataclasses import dataclass
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

# See the module docstring's "Bounded reads" note: consistent with
# JournaldReader._MAX_LINE_BYTES (16 MiB) by value, but this reader is
# text-mode, so this bounds DECODED CHARACTERS, not raw bytes -- hence the
# deliberately different name (worst case ~64 MiB of underlying UTF-8 bytes
# under 4-byte codepoints). journald's constant is byte-exact and correctly
# named _MAX_LINE_BYTES; a reader comparing the two names side by side is
# seeing an accurate distinction, not a typo.
_MAX_LINE_CHARS = 16 * 1024 * 1024

# The one character that can appear in decoded text solely as a byte-level
# decode substitution under errors="replace" (see _safe_open) -- U+FFFD is
# not otherwise a normal character a well-formed log line would contain.
# Used to detect undecodable input for the operator-visible warning (#65);
# never used to reject/alter the line itself.
_REPLACEMENT_CHAR = "\ufffd"


@dataclass(frozen=True, slots=True)
class _UnterminatedOverBoundProgress:
    """Remembers how far a not-yet-terminated, already over-bound line has
    been confirmed newline-free, so a later poll — even against a freshly
    reopened file handle at the same start offset, since callers persist
    only ``(inode, offset)`` cursors, not reader instances — does not
    re-decode that prefix (issue #64). Only ever created once a line has
    exceeded ``_MAX_LINE_CHARS`` at least once without a terminator; an
    ordinary (in-bound) partial line needs no such memory, since re-scanning
    up to one bounded chunk of it each poll is already cheap.
    """

    inode: int
    line_start: int  # absolute file offset where this still-open line begins
    scanned_to: int  # absolute offset up to which content is confirmed newline-free


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
        # Issue #64 — cross-poll memory of an over-bound, not-yet-terminated
        # line's scan progress. Instance-scoped (not persisted via the
        # caller's cursor): a caller that keeps reusing this reader across
        # polls gets the amortization; one that rebuilds a fresh reader each
        # cycle simply gets today's behavior (no regression either way).
        self._pending_partial: _UnterminatedOverBoundProgress | None = None
        # Issue #65 — rate limit the undecodable-content warning to at most
        # once per read() call rather than once per affected line.
        self._warned_undecodable_this_call = False

    async def read(
        self, start: str
    ) -> AsyncGenerator[tuple[str | None, str], None]:
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

        ``line`` MAY be ``None``: this signals a cursor advancement with no
        corresponding line, governed by the module-level invariant above
        (see "Invariant — the ``(None, cursor)`` yield shape") — a complete
        line over ``_MAX_LINE_CHARS`` that could not be buffered whole, with
        nothing else readable this cycle either. The caller MUST still
        persist ``cursor`` in this case (that's the whole point — otherwise
        the same oversized line is re-served, and re-skipped, forever), but
        has no line to forward as an event. The documented caller idiom
        (module docstring) already covers this: guard the forwarding call
        with ``if line is not None``, and always track ``cursor``.

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
        yielded_any = False
        last_skip_cursor: str | None = None
        # Issue #65 — reset the per-call rate limit for the undecodable-
        # content warning; it must fire at most once per read() call, not
        # once per affected line.
        self._warned_undecodable_this_call = False
        try:
            while True:
                # Fully drain whatever is currently available BEFORE checking
                # for rotation — a rename rotation must never skip content
                # that was still unread in the old (now-renamed) file, since
                # our open file handle keeps reading it by inode regardless
                # of what the path now points to.
                async for line, cursor in self._yield_available(fh, inode):
                    if line is None:
                        # An oversized line was skipped — see
                        # _yield_available. Deferred, not yielded here
                        # directly: the sentinel invariant requires at most
                        # one (None, cursor), as the FINAL item, only if
                        # nothing else was readable this whole read() call.
                        last_skip_cursor = cursor
                        continue
                    yielded_any = True
                    yield line, cursor

                action, _ = self._check_rotation(fh, inode)
                if action == "reopened":
                    fh.close()
                    # _safe_open, not a bare open() — refuses a symlink/
                    # non-regular file atomically (see module docstring).
                    fh, inode = self._safe_open(self._path)
                    # A new file at this path starts fresh — any remembered
                    # over-bound-scan progress (#64) referred to the OLD
                    # inode's content and is no longer meaningful.
                    self._pending_partial = None
                    continue  # drain the new file immediately
                if action == "truncated":
                    # In-place truncate invalidates prior byte offsets the
                    # same way — see above.
                    self._pending_partial = None
                    continue  # already seeked to 0; drain immediately
                break  # nothing more available and no rotation — drain complete
        finally:
            fh.close()

        if last_skip_cursor is not None and not yielded_any:
            yield None, last_skip_cursor

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

        **Decode errors never raise (issue #65).** Opened with
        ``errors="replace"`` — the same strategy ``JournaldReader`` already
        uses for its own decode boundary (``journald.py``, three call sites)
        — so a single invalid byte anywhere in the file (a compromised
        writer's own encoding, a truncated multi-byte sequence at a rotation
        boundary, or plain binary garbage appended to a text log) becomes a
        U+FFFD replacement character instead of an uncaught
        ``UnicodeDecodeError`` that would kill the whole read. ``"replace"``
        was chosen over ``"surrogateescape"`` (lossless/round-trippable, but
        leaks lone surrogates into ``str`` that can then raise at ANY later
        re-encode boundary — JSON, the KV store, log emission) precisely
        because those boundaries are exactly where this reader's output
        goes next (normalization, ``ctx.kv``, the UI). A mangled-but-safe
        ``str`` that downstream code can already handle beats a lossless one
        that can still blow up two calls later.
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
            return (
                os.fdopen(fd, "r", encoding=self._encoding, errors="replace"),
                st.st_ino,
            )
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
    ) -> AsyncIterator[tuple[str | None, str]]:
        """Yield every complete line currently available, leaving a trailing
        partial line (writer hasn't flushed its newline yet) unconsumed.

        ``line`` is ``None`` for a skipped oversized line (see
        ``_read_bounded_line``) — paired with the cursor immediately past its
        newline, so a caller aggregating this generator's output (``read()``)
        can still track forward progress. This is a raw per-occurrence
        signal, NOT yet the invariant-governed sentinel: ``read()`` decides
        whether to actually surface a final ``(None, cursor)`` to ITS caller,
        exactly mirroring how ``JournaldReader._iter_lines`` signals a raw
        skip that ``JournaldReader._stream`` then aggregates.
        """
        while True:
            pos = fh.tell()
            line, oversized = self._read_bounded_line(fh, inode, pos)
            if line is None and not oversized:
                fh.seek(pos)  # partial/incomplete — leave it for next poll
                return
            if oversized:
                offset = fh.tell()
                logger.warning(
                    "FileTailReader: skipping oversized line in %s (exceeds "
                    "%d characters) at offset %d — a compromised writer to "
                    "this file could otherwise buffer it whole and OOM the "
                    "process; investigate the source or raise "
                    "_MAX_LINE_CHARS.",
                    self._path, _MAX_LINE_CHARS, offset,
                )
                yield None, f"{inode}:{offset}"
                continue
            offset = fh.tell()
            assert line is not None  # narrowed above; for type-checking only
            yield line[:-1], f"{inode}:{offset}"

    def _read_bounded_line(
        self, fh: TextIO, inode: int, line_start: int
    ) -> tuple[str | None, bool]:
        """Read one line without ever buffering more than ``_MAX_LINE_CHARS``
        characters at a time.

        Returns ``(text, oversized)``:
          - ``(line_including_terminator, False)`` — an ordinary, in-bound
            complete line, read and returned whole (the common case:
            resolved in a single ``readline()`` call).
          - ``(None, False)`` — no complete line available right now: either
            true EOF, or a trailing partial line (no ``"\\n"`` yet — the
            writer hasn't flushed it). This ALSO covers a line already past
            the bound that is NOT yet newline-terminated: until its
            terminator actually appears, it is indistinguishable from an
            ordinary still-growing line, so it is deliberately NOT reported
            as ``oversized`` here — see the module docstring's Bounded reads
            note. The caller must leave the file position where it found it
            and try again next poll.
          - ``(None, True)`` — the terminating ``"\\n"`` WAS found, but
            cumulative length up to and including it exceeded
            ``_MAX_LINE_CHARS``: a genuine, complete oversized line. The file
            position is left just past the terminator — this method never
            re-scans bytes it has already read past.

        Uses ``TextIO.readline(size)``'s documented cap (a maximum CHARACTER
        count for a text-mode stream, per the io module) to bound each
        individual read call at ``_MAX_LINE_CHARS`` — an ordinary in-bound
        line always resolves on the FIRST call; only an oversized line loops.

        **Issue #64.** ``line_start`` identifies the current not-yet-
        terminated line; if it matches ``self._pending_partial`` (see that
        dataclass's docstring), this seeks straight past the already-scanned
        prefix instead of re-reading it, so a resumed over-bound line costs
        only what has been appended since the last poll.
        """
        pending = self._pending_partial
        if (
            pending is not None
            and pending.inode == inode
            and pending.line_start == line_start
        ):
            fh.seek(pending.scanned_to)
            exceeded_once = True
        else:
            exceeded_once = False

        while True:
            piece = fh.readline(_MAX_LINE_CHARS)
            if not piece:
                self._remember_partial_progress(
                    inode, line_start, fh.tell(), exceeded_once
                )
                return None, False
            if not piece.endswith("\n") and len(piece) < _MAX_LINE_CHARS:
                # True EOF mid-line -- ordinary partial. Deliberately NOT
                # checked for undecodable content (issue #65): a truncated
                # multi-byte sequence at EOF also decodes to a short,
                # unterminated U+FFFD fragment via errors="replace" (see
                # _safe_open), and MUST be retried once the writer finishes
                # flushing it, not flagged as corruption -- indistinguishable
                # from an ordinary still-growing partial until it resolves
                # one way or the other.
                self._remember_partial_progress(
                    inode, line_start, fh.tell(), exceeded_once
                )
                return None, False
            # From here, ``piece`` is DEFINITELY resolved this call: either a
            # complete (newline-terminated) line, or a full-cap chunk that is
            # not the file's current trailing edge. Either way any decode
            # substitution in it is genuine undecodable content, not a
            # still-in-flight multi-byte sequence (issue #65).
            if _REPLACEMENT_CHAR in piece:
                self._warn_undecodable_content(fh.tell())
            if piece.endswith("\n"):
                self._pending_partial = None  # resolved -- nothing left to remember
                return (None, True) if exceeded_once else (piece, False)
            if not exceeded_once:
                self._warn_still_growing_exceeds_bound(line_start)
            exceeded_once = True  # hit the cap with no terminator -- keep scanning

    def _remember_partial_progress(
        self, inode: int, line_start: int, scanned_to: int, exceeded_once: bool
    ) -> None:
        """Persist (or clear) issue #64's cross-poll scan-progress memory.

        Only a line that has already exceeded the bound is worth
        remembering — see ``_read_bounded_line``'s docstring.
        """
        self._pending_partial = (
            _UnterminatedOverBoundProgress(
                inode=inode, line_start=line_start, scanned_to=scanned_to
            )
            if exceeded_once
            else None
        )

    def _warn_still_growing_exceeds_bound(self, line_start: int) -> None:
        """Issue #64 — an operator-visible signal that a line is ALREADY
        over-bound while still growing, emitted exactly once per occurrence
        (guarded by the caller's ``not exceeded_once`` check, and never
        repeated for the same occurrence since ``self._pending_partial``
        already reflects ``exceeded_once=True`` on every later poll) —
        rather than staying silent until (if ever) the line is eventually
        terminated and the separate confirmed-oversized warning fires.
        """
        logger.warning(
            "FileTailReader: a still-growing line in %s has exceeded %d "
            "characters without a terminator yet (started at offset %d) — "
            "a compromised writer to this file could grow this line "
            "indefinitely; investigate the source or raise "
            "_MAX_LINE_CHARS. Logged once for this occurrence, not per poll.",
            self._path, _MAX_LINE_CHARS, line_start,
        )

    def _warn_undecodable_content(self, offset: int) -> None:
        """Issue #65 — an operator-visible signal that this file contains
        bytes that are not valid ``self._encoding`` (decoded as U+FFFD via
        ``errors="replace"`` — see ``_safe_open``), rate-limited to at most
        once per ``read()`` call rather than once per affected line.
        """
        if self._warned_undecodable_this_call:
            return
        self._warned_undecodable_this_call = True
        logger.warning(
            "FileTailReader: %s contains one or more bytes that are not "
            "valid %s (decoded as U+FFFD replacement characters) at or "
            "before offset %d — a compromised or misbehaving writer, or "
            "corruption at a rotation boundary; further occurrences this "
            "read() call are suppressed.",
            self._path, self._encoding, offset,
        )

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
