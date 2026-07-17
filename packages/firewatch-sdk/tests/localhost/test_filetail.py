"""Tests for ``firewatch_sdk.localhost.filetail.FileTailReader`` — EARS criteria
mapped 1:1 to issue #1's acceptance criteria (plus issue #60's oversized-line
bound).

EARS-2  No stored offset: explicit start position required (cursor|tail|head);
        the reader never infers/defaults one.
EARS-4  Rotation (rename and in-place truncate) detected without duplicating
        or skipping lines.
EARS-5  First-run start-position rule applies identically to FileTailReader.
EARS-6  Cancellation: the open file handle is closed promptly, never leaked.

Plus the architect-ruled ``resolve_start()``/``read()`` split (data-loss
regression) and the one-shot drain contract (``read()`` must terminate).

Issue #60 (bounded reads, mirroring ``JournaldReader``'s ``_MAX_LINE_BYTES``):
  - memory stays bounded on an oversized line (no whole-line buffering);
  - an oversized line as the ONLY new content in a cycle still yields a
    durable ``(None, cursor)`` resume position — the poison-pill case;
  - that resume position is never re-served (skipped exactly once);
  - the ``(None, cursor)`` sentinel obeys the same invariant as journald's:
    at most once per ``read()`` call, final item only, zero-record cycles
    only;
  - an oversized skip logs an operator-visible warning.

Pure filesystem I/O against ``tmp_path`` — no live journald, no subprocess.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import IO, TypeVar

import pytest

from firewatch_sdk.localhost import filetail
from firewatch_sdk.localhost.errors import FileTailUnavailableError, LocalReaderError
from firewatch_sdk.localhost.filetail import FileTailReader

_T = TypeVar("_T")


async def _collect(agen: AsyncIterator[_T]) -> list[_T]:
    return [item async for item in agen]


# --------------------------------------------------------------------------- #
# EARS-2/5 — explicit start position, never inferred
# --------------------------------------------------------------------------- #


class TestExplicitStartPosition:
    def test_read_requires_explicit_start_argument(self, tmp_path: Path) -> None:
        reader = FileTailReader(tmp_path / "auth.log")
        with pytest.raises(TypeError):
            reader.read()  # type: ignore[call-arg]

    async def test_head_reads_existing_content_from_offset_zero(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "auth.log"
        path.write_text("line1\nline2\n")
        reader = FileTailReader(path)

        results = await _collect(reader.read("head"))

        assert [line for line, _ in results] == ["line1", "line2"]

    async def test_tail_resolves_to_current_end_only_new_lines_read_after(
        self, tmp_path: Path
    ) -> None:
        """A fresh install must not ingest a machine's entire log history."""
        path = tmp_path / "auth.log"
        path.write_text("old1\nold2\n")
        reader = FileTailReader(path)

        cursor = await reader.resolve_start("tail")
        with path.open("a") as f:
            f.write("new1\n")

        results = await _collect(reader.read(cursor))

        assert [line for line, _ in results] == ["new1"]

    async def test_read_rejects_tail_sentinel(self, tmp_path: Path) -> None:
        """Structural poka-yoke: read() must never accept "tail" directly —
        only resolve_start()'s output is a valid position."""
        path = tmp_path / "auth.log"
        path.write_text("line1\n")
        reader = FileTailReader(path)

        with pytest.raises(ValueError, match="tail"):
            await reader.read("tail").__anext__()

    async def test_cursor_resume_continues_from_stored_offset(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "auth.log"
        path.write_text("line1\nline2\n")
        reader = FileTailReader(path)

        first_pass = await _collect(reader.read("head"))
        cursor = first_pass[-1][1]  # cursor after line2 — at EOF

        with path.open("a") as f:
            f.write("line3\n")

        results = await _collect(reader.read(cursor))

        assert [line for line, _ in results] == ["line3"]

    async def test_malformed_cursor_raises_typed_error(self, tmp_path: Path) -> None:
        path = tmp_path / "auth.log"
        path.write_text("line1\n")
        reader = FileTailReader(path)

        with pytest.raises(FileTailUnavailableError):
            await reader.read("not-a-cursor").__anext__()

    async def test_unreadable_path_raises_typed_error(self, tmp_path: Path) -> None:
        reader = FileTailReader(tmp_path / "does-not-exist.log")
        with pytest.raises(FileTailUnavailableError) as excinfo:
            await reader.read("head").__anext__()
        assert isinstance(excinfo.value, LocalReaderError)

    async def test_stale_cursor_across_inode_change_falls_back_to_head(
        self, tmp_path: Path
    ) -> None:
        """A cursor recorded before a restart, against a file that has since
        rotated (different inode), must not permanently miss content — resume
        from the head of the CURRENT file instead."""
        path = tmp_path / "auth.log"
        path.write_text("original\n")
        stale_cursor = "999999:5"  # an inode that will never match

        path.write_text("current1\ncurrent2\n")  # simulate a new file at same path
        reader = FileTailReader(path)

        results = await _collect(reader.read(stale_cursor))

        assert [line for line, _ in results] == ["current1", "current2"]


# --------------------------------------------------------------------------- #
# Regression — resolve_start() must surface a persistable position BEFORE any
# draining, or a quiet "tail" cycle silently skips lines appended in the gap.
# --------------------------------------------------------------------------- #


class TestResolveStartRegression:
    async def test_resolve_start_tail_surfaces_concrete_offset(
        self, tmp_path: Path
    ) -> None:
        """The bootstrap position must escape to the caller, not stay a local
        variable inside read() — this is the value a caller persists."""
        path = tmp_path / "auth.log"
        path.write_text("old1\nold2\n")
        reader = FileTailReader(path)

        resolved = await reader.resolve_start("tail")

        inode = path.stat().st_ino
        size = path.stat().st_size
        assert resolved == f"{inode}:{size}"  # concrete — NOT the literal "tail"

    async def test_resolve_start_head_and_cursor_are_passthrough(
        self, tmp_path: Path
    ) -> None:
        reader = FileTailReader(tmp_path / "auth.log")
        assert await reader.resolve_start("head") == "head"
        assert await reader.resolve_start("42:100") == "42:100"

    async def test_resolve_start_tail_on_nonexistent_path_raises_typed_error(
        self, tmp_path: Path
    ) -> None:
        """Unlike JournaldReader's empty-journal case (a normal, expected
        state), a target file that has never been created is treated as a
        genuine "cannot run at all" precondition — consistent with read()'s
        own typed-error contract for an unreadable path."""
        reader = FileTailReader(tmp_path / "not-created-yet.log")
        with pytest.raises(FileTailUnavailableError) as excinfo:
            await reader.resolve_start("tail")
        assert isinstance(excinfo.value, LocalReaderError)

    async def test_quiet_cycle_then_new_lines_are_not_lost(
        self, tmp_path: Path
    ) -> None:
        """Pin the exact data-loss timeline from the bug report:

            poll 1: resolve_start("tail") -> concrete offset O1
                    (caller persists O1, NOT "tail" again — no draining
                    needed to prove this: the position is already committed)
            ...     a line is appended after O1...
            poll 2: caller resumes from the PERSISTED O1 (never re-resolves
                    "tail") -> that line is read, not skipped.
        """
        path = tmp_path / "auth.log"
        path.write_text("old1\n")
        reader = FileTailReader(path)

        cursor = await reader.resolve_start("tail")

        # A line lands in the "quiet gap" between bootstrap and the first
        # poll — before read() is ever called with the persisted cursor.
        with path.open("a") as f:
            f.write("new1\n")

        results = await _collect(reader.read(cursor))

        assert [line for line, _ in results] == ["new1"]


# --------------------------------------------------------------------------- #
# Regression — read() is a one-shot drain: it MUST terminate rather than
# block forever waiting for more lines (the old follow-loop bug).
# --------------------------------------------------------------------------- #


class TestDrainTerminates:
    async def test_read_terminates_instead_of_blocking_for_more_lines(
        self, tmp_path: Path
    ) -> None:
        """A read() that never returns is a hang — assert termination
        directly via wait_for rather than relying on the suite's global
        per-test timeout to eventually catch it."""
        path = tmp_path / "auth.log"
        path.write_text("line1\nline2\n")
        reader = FileTailReader(path)

        results = await asyncio.wait_for(_collect(reader.read("head")), timeout=2.0)

        assert [line for line, _ in results] == ["line1", "line2"]

    async def test_read_on_fully_drained_file_terminates_immediately(
        self, tmp_path: Path
    ) -> None:
        """No new content and no rotation: still must return, not hang."""
        path = tmp_path / "auth.log"
        path.write_text("")
        reader = FileTailReader(path)

        results = await asyncio.wait_for(_collect(reader.read("head")), timeout=2.0)

        assert results == []


# --------------------------------------------------------------------------- #
# EARS-4 — rotation-aware (rename and in-place truncate)
# --------------------------------------------------------------------------- #


class TestRotation:
    async def test_rename_rotation_no_duplicate_or_skip(self, tmp_path: Path) -> None:
        path = tmp_path / "auth.log"
        path.write_text("line1\nline2\n")
        reader = FileTailReader(path)

        agen = reader.read("head")
        first = await agen.__anext__()
        assert first[0] == "line1"

        # Rotate BEFORE line2 is read: rename the old file away and create a
        # fresh one at the same path (the standard logrotate "create" mode).
        os.rename(path, tmp_path / "auth.log.1")
        path.write_text("line3\n")

        second = await agen.__anext__()  # must still be the unread line2, not line3
        third = await agen.__anext__()
        await agen.aclose()

        assert second[0] == "line2"
        assert third[0] == "line3"

    async def test_truncate_rotation_no_duplicate_or_skip(self, tmp_path: Path) -> None:
        path = tmp_path / "auth.log"
        path.write_text("line1\nline2\n")
        reader = FileTailReader(path)

        agen = reader.read("head")
        first = await agen.__anext__()
        second = await agen.__anext__()
        assert (first[0], second[0]) == ("line1", "line2")

        # Fully drained; now truncate in place (copytruncate — same inode,
        # smaller size) and write new, shorter content.
        with path.open("w") as f:
            f.write("l3\n")

        third = await agen.__anext__()
        await agen.aclose()
        assert third[0] == "l3"


# --------------------------------------------------------------------------- #
# Security review Finding 2 (HIGH) — refuse to follow a symlink at ``path``,
# and refuse anything that isn't a regular file (a FIFO would block forever).
#
# Scenario this closes: a service-owned log directory (exactly what #2's
# ClamAV plugin will point this at) whose service account gets compromised —
# the attacker removes the log file and drops a symlink at the same path
# pointing at /etc/shadow or an SSH private key. Without this check, the next
# rotation-triggered reopen would follow it and yield the target's contents
# as log lines, flowing into normalized events, the UI, and AI sample
# context — local-attacker-writable-dir -> arbitrary-file-disclosure.
# --------------------------------------------------------------------------- #


class TestSymlinkSafety:
    async def test_initial_open_refuses_symlink(self, tmp_path: Path) -> None:
        secret = tmp_path / "secret.txt"
        secret.write_text("super-secret-content\n")
        link = tmp_path / "auth.log"
        link.symlink_to(secret)

        reader = FileTailReader(link)

        with pytest.raises(FileTailUnavailableError, match="symlink"):
            await reader.read("head").__anext__()

    async def test_resolve_start_refuses_symlink(self, tmp_path: Path) -> None:
        """The stat-side check (resolve_start()) refuses just as the
        open-side check (read()) does — a caller that only ever calls
        resolve_start("tail") (e.g. on a still-quiet first run) must not
        silently accept a symlinked target either."""
        secret = tmp_path / "secret.txt"
        secret.write_text("super-secret-content\n")
        link = tmp_path / "auth.log"
        link.symlink_to(secret)

        reader = FileTailReader(link)

        with pytest.raises(FileTailUnavailableError, match="symlink"):
            await reader.resolve_start("tail")

    async def test_rotation_reopen_refuses_symlink_swap(self, tmp_path: Path) -> None:
        """The exact attack scenario: a legitimate file is rotated away and
        replaced by a symlink to a sensitive file. The rotation-triggered
        reopen must refuse it — never silently yield the target's contents
        as log lines — even though earlier (legitimate) lines were already
        yielded this same read() call."""
        path = tmp_path / "auth.log"
        path.write_text("line1\n")
        secret = tmp_path / "shadow-like-secret"
        secret.write_text("root:$6$hunter2$...\n")
        reader = FileTailReader(path)

        agen = reader.read("head")
        first = await agen.__anext__()
        assert first[0] == "line1"

        # Attacker: remove the real file, drop a symlink at the same path.
        os.remove(path)
        path.symlink_to(secret)

        with pytest.raises(FileTailUnavailableError, match="symlink"):
            await agen.__anext__()
        await agen.aclose()

    async def test_fifo_is_refused_not_a_hang(self, tmp_path: Path) -> None:
        """A FIFO at the path is refused (never silently followed like a
        regular file, and never blocks forever waiting for a writer)."""
        fifo_path = tmp_path / "auth.log"
        os.mkfifo(fifo_path)
        reader = FileTailReader(fifo_path)

        with pytest.raises(FileTailUnavailableError, match="not a regular file"):
            await asyncio.wait_for(reader.read("head").__anext__(), timeout=2.0)

    async def test_follow_symlinks_opt_in_reads_the_target(
        self, tmp_path: Path
    ) -> None:
        """Explicit opt-in (a legitimate distro symlinked canonical log
        name) does read through the symlink, as documented."""
        target = tmp_path / "current.log"
        target.write_text("line1\nline2\n")
        link = tmp_path / "auth.log"
        link.symlink_to(target)

        reader = FileTailReader(link, follow_symlinks=True)
        results = await _collect(reader.read("head"))

        assert [line for line, _ in results] == ["line1", "line2"]


# --------------------------------------------------------------------------- #
# EARS-6 — cancellation: no leaked file handle
# --------------------------------------------------------------------------- #


class TestCancellation:
    async def test_cancellation_closes_file_handle(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A consumer cancelled mid-drain (e.g. slow downstream processing
        between lines) must not leak the open file handle. Uses
        ``contextlib.aclosing`` — the documented-correct pattern for
        consuming an async generator that holds a resource — so cleanup is
        guaranteed regardless of exactly where cancellation is delivered
        (``read()`` itself has no internal ``await`` once it is a one-shot
        drain, so the delivery point is the consumer's own per-item work)."""
        path = tmp_path / "auth.log"
        path.write_text("line1\nline2\nline3\n")
        reader = FileTailReader(path)

        # FileTailReader opens via os.open()/os.fdopen() (not Path.open()) so
        # the symlink refusal in _safe_open can be atomic (O_NOFOLLOW) — spy
        # on fdopen to capture the resulting file object.
        opened: list[IO[str]] = []
        orig_fdopen = os.fdopen

        def _spy_fdopen(fd: int, *args: object, **kwargs: object) -> IO[str]:
            fh = orig_fdopen(fd, *args, **kwargs)  # type: ignore[arg-type]
            opened.append(fh)
            return fh

        monkeypatch.setattr(os, "fdopen", _spy_fdopen)

        async def _consume() -> None:
            async with contextlib.aclosing(reader.read("head")) as records:
                async for _line, _cursor in records:
                    await asyncio.sleep(0.05)  # simulate slow per-line processing

        task = asyncio.create_task(_consume())
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert opened
        assert all(fh.closed for fh in opened)


# --------------------------------------------------------------------------- #
# Issue #60 — a single oversized line must never be buffered whole, and must
# still leave a durable resume position so it is skipped exactly once rather
# than re-read (and re-attempted, and re-failed) forever. Mirrors
# ``JournaldReader``'s ``_MAX_LINE_BYTES`` precedent, reusing its
# ``(record | None, cursor)`` yield shape rather than inventing a new one.
#
# The bound is monkeypatched down to a small value for test speed/determinism
# in most cases here (matching how ``test_journald.py`` uses a synthetic
# ``OVERSIZED`` marker rather than real multi-MiB payloads); one test
# (``TestDefaultBoundIsRealistic``) exercises the real, unmocked 16 MiB
# constant end-to-end to prove the default itself works, not just the logic.
# --------------------------------------------------------------------------- #


class TestOversizedLineBound:
    async def test_oversized_line_between_normal_lines_is_skipped_silently(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Good lines before AND after an oversized one still arrive; the
        oversized line itself never appears as a yielded record (no ``None``
        sentinel here either — a later real line's cursor already carries
        forward progress past it, per the sentinel invariant)."""
        monkeypatch.setattr(filetail, "_MAX_LINE_CHARS", 16)
        path = tmp_path / "auth.log"
        path.write_text(f"line1\n{'x' * 64}\nline2\n")
        reader = FileTailReader(path)

        results = await asyncio.wait_for(_collect(reader.read("head")), timeout=2.0)

        assert [line for line, _ in results] == ["line1", "line2"]

    async def test_oversized_only_line_yields_none_sentinel_with_durable_cursor(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The poison-pill scenario: the ONLY new content this cycle is one
        complete, oversized line. Without the sentinel, the caller would have
        nothing to persist and the SAME line would be re-served (and
        re-skipped) on every future poll, forever."""
        monkeypatch.setattr(filetail, "_MAX_LINE_CHARS", 16)
        path = tmp_path / "auth.log"
        path.write_text(f"{'x' * 64}\n")
        reader = FileTailReader(path)

        results = await asyncio.wait_for(_collect(reader.read("head")), timeout=2.0)

        assert len(results) == 1
        line, cursor = results[0]
        assert line is None
        inode = path.stat().st_ino
        assert cursor == f"{inode}:{path.stat().st_size}"  # past the newline

    async def test_poison_pill_is_skipped_once_not_reread_forever(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Resuming from the sentinel's cursor must not re-encounter (or
        re-attempt-and-fail on) the same oversized line — the durable-resume
        guarantee this bound exists to provide."""
        monkeypatch.setattr(filetail, "_MAX_LINE_CHARS", 16)
        path = tmp_path / "auth.log"
        path.write_text(f"{'x' * 64}\n")
        reader = FileTailReader(path)

        first_pass = await asyncio.wait_for(
            _collect(reader.read("head")), timeout=2.0
        )
        _, skip_cursor = first_pass[0]

        second_pass = await asyncio.wait_for(
            _collect(reader.read(skip_cursor)), timeout=2.0
        )

        assert second_pass == []  # nothing re-served; no hang, no repeat

    async def test_oversized_line_still_growing_without_newline_is_left_unconsumed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A line already past the bound but NOT yet newline-terminated
        (the writer hasn't flushed it yet) must not be reported as a
        confirmed oversized skip — it is indistinguishable from an ordinary
        still-growing partial line until its terminator actually appears."""
        monkeypatch.setattr(filetail, "_MAX_LINE_CHARS", 16)
        path = tmp_path / "auth.log"
        path.write_text("x" * 64)  # no trailing newline at all
        reader = FileTailReader(path)

        results = await asyncio.wait_for(_collect(reader.read("head")), timeout=2.0)

        assert results == []  # nothing yielded yet -- not even a sentinel

        # Once the writer flushes the terminator, the (still oversized) line
        # is now confirmed complete and is skipped normally.
        with path.open("a") as f:
            f.write("\n")
        results = await asyncio.wait_for(_collect(reader.read("head")), timeout=2.0)

        assert len(results) == 1
        assert results[0][0] is None

    async def test_multiple_consecutive_oversized_lines_yield_one_sentinel_at_furthest_cursor(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Sentinel invariant: emitted AT MOST ONCE per read() call, and only
        as the final item — even when several oversized lines were skipped
        in the same drain, only one ``(None, cursor)`` is yielded, positioned
        past the LAST of them (maximum forward progress in one pass)."""
        monkeypatch.setattr(filetail, "_MAX_LINE_CHARS", 16)
        path = tmp_path / "auth.log"
        big = "x" * 64
        path.write_text(f"{big}\n{big}\n{big}\n")
        reader = FileTailReader(path)

        results = await asyncio.wait_for(_collect(reader.read("head")), timeout=2.0)

        assert len(results) == 1
        line, cursor = results[0]
        assert line is None
        inode = path.stat().st_ino
        assert cursor == f"{inode}:{path.stat().st_size}"  # past ALL three

    async def test_oversized_skip_logs_operator_visible_warning(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setattr(filetail, "_MAX_LINE_CHARS", 16)
        path = tmp_path / "auth.log"
        path.write_text(f"{'x' * 64}\n")
        reader = FileTailReader(path)

        with caplog.at_level("WARNING", logger="firewatch.sdk.localhost.filetail"):
            await asyncio.wait_for(_collect(reader.read("head")), timeout=2.0)

        assert any(
            "oversized" in record.message.lower() for record in caplog.records
        )

    async def test_bound_constant_matches_journald_precedent(self) -> None:
        """16 MiB, consistent with ``JournaldReader``'s ``_MAX_LINE_BYTES``
        unless a justified reason to differ is recorded — see the module
        docstring's note on character- vs. byte-counting for the one
        deliberate difference (this reader is text-mode)."""
        assert filetail._MAX_LINE_CHARS == 16 * 1024 * 1024


class TestDefaultBoundIsRealistic:
    async def test_real_16_mib_bound_bounds_a_genuinely_oversized_line(
        self, tmp_path: Path
    ) -> None:
        """Unmocked end-to-end check at the real default: a line bigger than
        the actual 16 MiB bound is skipped (not buffered whole), and a small
        surrounding line still survives."""
        path = tmp_path / "auth.log"
        oversized_line = "x" * (filetail._MAX_LINE_CHARS + 1024)
        path.write_text(f"before\n{oversized_line}\nafter\n")
        reader = FileTailReader(path)

        results = await asyncio.wait_for(_collect(reader.read("head")), timeout=5.0)

        assert [line for line, _ in results] == ["before", "after"]


def _spy_readline_lengths(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Wrap every ``fdopen()``'d file's ``readline()`` to record how many
    characters each call actually decoded — the direct measure of "scan
    work" issue #64 requires NOT growing with total line length across
    polls. One shared list survives across separate ``read()`` calls (each
    opens its own fresh file handle), exactly like production would across
    separate poll cycles.
    """
    lengths: list[int] = []
    orig_fdopen = os.fdopen

    def _spy_fdopen(fd: int, *args: object, **kwargs: object) -> IO[str]:
        fh = orig_fdopen(fd, *args, **kwargs)  # type: ignore[arg-type]
        orig_readline = fh.readline

        def _counting_readline(size: int = -1) -> str:
            piece = orig_readline(size)
            lengths.append(len(piece))
            return piece

        fh.readline = _counting_readline  # type: ignore[method-assign]
        return fh

    monkeypatch.setattr(os, "fdopen", _spy_fdopen)
    return lengths


# --------------------------------------------------------------------------- #
# Issue #64 — an un-terminated, already over-bound line must not be re-scanned
# from its start on every poll; per-poll cost must track only newly-appended
# data. Directions (a) and (b) from the issue: remember scan progress, and
# warn once per occurrence (not once per poll).
# --------------------------------------------------------------------------- #


class TestUnterminatedOverBoundRescan:
    async def test_scan_progress_advances_monotonically_not_from_scratch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Direct evidence of the fix: the remembered scan-progress offset
        only ever advances by the amount newly appended — it never resets
        back to the line's start on a later poll."""
        monkeypatch.setattr(filetail, "_MAX_LINE_CHARS", 4)
        path = tmp_path / "auth.log"
        path.write_text("a" * 12)  # already 3x the (mocked) bound, no "\n"
        reader = FileTailReader(path)

        await _collect(reader.read("head"))
        assert reader._pending_partial is not None
        assert reader._pending_partial.scanned_to == 12

        # Poll again with NO new data -- progress must not go backwards.
        await _collect(reader.read("head"))
        assert reader._pending_partial.scanned_to == 12

        # Append more (still unterminated) -- progress advances by exactly
        # that much, not back to 0.
        with path.open("a") as f:
            f.write("a" * 4)
        await _collect(reader.read("head"))
        assert reader._pending_partial.scanned_to == 16

    async def test_per_poll_scan_cost_tracks_only_newly_appended_data(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The O(n^2) regression this issue closes: without the fix, every
        poll re-decodes the entire already-scanned prefix. With the fix, a
        poll with no new data does ~zero work, and a poll with newly
        appended data does work proportional ONLY to what's new."""
        monkeypatch.setattr(filetail, "_MAX_LINE_CHARS", 4)
        path = tmp_path / "auth.log"
        path.write_text("a" * 12)  # 3 already-over-bound chunks, no "\n"
        reader = FileTailReader(path)
        lengths = _spy_readline_lengths(monkeypatch)

        await _collect(reader.read("head"))
        chars_scanned_poll1 = sum(lengths)
        assert chars_scanned_poll1 == 12  # must read what's already there once
        lengths.clear()

        await _collect(reader.read("head"))  # no new data appended
        chars_scanned_poll2 = sum(lengths)
        assert chars_scanned_poll2 == 0  # NOT a re-scan of the 12 old chars
        lengths.clear()

        with path.open("a") as f:
            f.write("a" * 4)  # still unterminated
        await _collect(reader.read("head"))
        chars_scanned_poll3 = sum(lengths)
        assert chars_scanned_poll3 == 4  # only the newly-appended chunk

    async def test_still_growing_over_bound_line_warns_once_not_per_poll(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The operator-visible warning for a STILL-GROWING over-bound line
        fires exactly once for this occurrence, not once per poll, even
        across several consecutive polls while it remains unterminated."""
        monkeypatch.setattr(filetail, "_MAX_LINE_CHARS", 4)
        path = tmp_path / "auth.log"
        path.write_text("a" * 8)  # already over the (mocked) bound, no "\n"
        reader = FileTailReader(path)

        with caplog.at_level("WARNING", logger="firewatch.sdk.localhost.filetail"):
            for _ in range(3):  # three polls, still no terminator
                await _collect(reader.read("head"))

        still_growing_warnings = [
            r for r in caplog.records if "still-growing" in r.message.lower()
        ]
        assert len(still_growing_warnings) == 1

    async def test_amortized_line_still_becomes_confirmed_oversized_once_terminated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Once the writer finally flushes the terminator, the line — grown
        and scanned incrementally across several polls — is STILL treated as
        a confirmed oversized skip per #60's existing invariant: exactly one
        (None, cursor) sentinel, as the final item, on a zero-record cycle."""
        monkeypatch.setattr(filetail, "_MAX_LINE_CHARS", 4)
        path = tmp_path / "auth.log"
        path.write_text("a" * 8)  # over bound, unterminated
        reader = FileTailReader(path)

        # Two quiet polls while it's still growing/unterminated.
        assert await _collect(reader.read("head")) == []
        assert await _collect(reader.read("head")) == []

        # Writer finally appends more content AND the terminator.
        with path.open("a") as f:
            f.write("aa\n")

        results = await _collect(reader.read("head"))

        assert len(results) == 1
        line, cursor = results[0]
        assert line is None
        inode = path.stat().st_ino
        assert cursor == f"{inode}:{path.stat().st_size}"
        assert reader._pending_partial is None  # resolved -- nothing left to remember

    async def test_rotation_clears_stale_scan_progress(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Remembered scan progress must not survive a rotation — the old
        inode's offsets are meaningless against the new file."""
        monkeypatch.setattr(filetail, "_MAX_LINE_CHARS", 4)
        path = tmp_path / "auth.log"
        path.write_text("a" * 8)  # over bound, unterminated
        reader = FileTailReader(path)

        await _collect(reader.read("head"))
        assert reader._pending_partial is not None

        os.rename(path, tmp_path / "auth.log.1")
        path.write_text("b" * 8)  # new file, new inode, also unterminated/over-bound

        await _collect(reader.read("head"))

        assert reader._pending_partial is not None
        assert reader._pending_partial.inode == path.stat().st_ino
        assert reader._pending_partial.scanned_to == 8


# --------------------------------------------------------------------------- #
# Issue #65 — a single invalid byte must never crash read() with an uncaught
# UnicodeDecodeError. errors="replace" (consistent with JournaldReader's own
# decode boundary) turns it into U+FFFD instead, and the reader keeps working.
# --------------------------------------------------------------------------- #


class TestUndecodableContent:
    async def test_invalid_byte_mid_line_does_not_crash_and_yields_replacement(
        self, tmp_path: Path
    ) -> None:
        """The exact reproduction from the issue: a single 0xFF byte must
        not raise UnicodeDecodeError out of read() — surrounding good lines
        still arrive, and the bad line decodes with a replacement char
        rather than vanishing or crashing the whole cycle."""
        path = tmp_path / "auth.log"
        path.write_bytes(b"before\n" + b"bad\xffbyte" + b"\n" + b"after\n")
        reader = FileTailReader(path)

        results = await asyncio.wait_for(_collect(reader.read("head")), timeout=2.0)

        assert [line for line, _ in results] == ["before", "bad�byte", "after"]

    async def test_undecodable_content_cannot_silently_merge_into_well_formed_text(
        self, tmp_path: Path
    ) -> None:
        """A dropped (rather than replaced) invalid byte could silently
        splice two tokens together into something a normalizer might
        misparse as one well-formed field. Replacement must leave a visible
        marker, never silently vanish."""
        path = tmp_path / "auth.log"
        path.write_bytes(b"user=admin\xffrole=root\n")
        reader = FileTailReader(path)

        results = await asyncio.wait_for(_collect(reader.read("head")), timeout=2.0)

        assert len(results) == 1
        line, _ = results[0]
        assert line is not None
        assert "�" in line
        assert "adminrole" not in line  # never silently spliced together

    async def test_undecodable_content_warning_is_rate_limited_not_per_line(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Many affected lines in one read() call must still produce only
        ONE operator-visible warning, not one per line."""
        path = tmp_path / "auth.log"
        path.write_bytes(b"bad\xffline1\n" * 20)
        reader = FileTailReader(path)

        with caplog.at_level("WARNING", logger="firewatch.sdk.localhost.filetail"):
            results = await asyncio.wait_for(
                _collect(reader.read("head")), timeout=2.0
            )

        assert len(results) == 20  # all 20 lines still came through
        undecodable_warnings = [
            r for r in caplog.records if "not valid" in r.message.lower()
        ]
        assert len(undecodable_warnings) == 1

    async def test_undecodable_warning_resets_per_read_call(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The rate limit is per read() call, not permanent for the
        instance's lifetime: a later poll with fresh bad content warns
        again."""
        path = tmp_path / "auth.log"
        path.write_bytes(b"bad\xffline\n")
        reader = FileTailReader(path)

        with caplog.at_level("WARNING", logger="firewatch.sdk.localhost.filetail"):
            await asyncio.wait_for(_collect(reader.read("head")), timeout=2.0)
            cursor_after_first = path.stat().st_size
            with path.open("ab") as f:
                f.write(b"more\xfebad\n")
            await asyncio.wait_for(
                _collect(reader.read(f"{path.stat().st_ino}:{cursor_after_first}")),
                timeout=2.0,
            )

        undecodable_warnings = [
            r for r in caplog.records if "not valid" in r.message.lower()
        ]
        assert len(undecodable_warnings) == 2

    async def test_invalid_byte_at_rotation_boundary_survives_the_cascade(
        self, tmp_path: Path
    ) -> None:
        """Both sides of a rotation boundary can carry undecodable bytes —
        the OLD (renamed-away) file's still-unread tail, and the NEW file's
        content — and the cascade must survive both without raising."""
        path = tmp_path / "auth.log"
        path.write_bytes(b"line1\n" + b"bad\xffline\n")
        reader = FileTailReader(path)

        agen = reader.read("head")
        first = await agen.__anext__()
        assert first[0] == "line1"

        os.rename(path, tmp_path / "auth.log.1")
        path.write_bytes(b"new\xfefile\n")

        second = await agen.__anext__()  # unread tail of the OLD (rotated) file
        third = await agen.__anext__()  # from the NEW file
        await agen.aclose()

        assert second[0] == "bad�line"
        assert third[0] == "new�file"

    async def test_truncated_multibyte_sequence_at_eof_is_ordinary_partial_not_corruption(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A multi-byte UTF-8 sequence split by a slow writer (its final
        byte(s) not flushed yet) must be treated as an ordinary partial line
        and retried once the rest arrives — NOT flagged as undecodable
        corruption, and NOT permanently mangled into a replacement char."""
        path = tmp_path / "auth.log"
        # "€" (EURO SIGN) encodes as b"\xe2\x82\xac" -- write only the
        # first two of its three bytes, with no trailing newline.
        path.write_bytes(b"line1\n" + b"\xe2\x82")
        reader = FileTailReader(path)

        with caplog.at_level("WARNING", logger="firewatch.sdk.localhost.filetail"):
            results = await asyncio.wait_for(
                _collect(reader.read("head")), timeout=2.0
            )
            assert [line for line, _ in results] == ["line1"]  # partial left unconsumed
            cursor = results[-1][1]  # resume point after "line1" — not "head" again
            undecodable_warnings_before = [
                r for r in caplog.records if "not valid" in r.message.lower()
            ]
            assert undecodable_warnings_before == []  # NOT flagged as corruption

            # Writer finishes flushing the sequence + terminator.
            with path.open("ab") as f:
                f.write(b"\xac and more\n")

            more_results = await asyncio.wait_for(
                _collect(reader.read(cursor)), timeout=2.0
            )

        assert [line for line, _ in more_results] == ["€ and more"]
        undecodable_warnings_after = [
            r for r in caplog.records if "not valid" in r.message.lower()
        ]
        assert undecodable_warnings_after == []  # never flagged -- it was valid all along
