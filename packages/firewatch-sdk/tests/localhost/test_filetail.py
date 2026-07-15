"""Tests for ``firewatch_sdk.localhost.filetail.FileTailReader`` — EARS criteria
mapped 1:1 to issue #1's acceptance criteria.

EARS-2  No stored offset: explicit start position required (cursor|tail|head);
        the reader never infers/defaults one.
EARS-4  Rotation (rename and in-place truncate) detected without duplicating
        or skipping lines.
EARS-5  First-run start-position rule applies identically to FileTailReader.
EARS-6  Cancellation: the open file handle is closed promptly, never leaked.

Plus the architect-ruled ``resolve_start()``/``read()`` split (data-loss
regression) and the one-shot drain contract (``read()`` must terminate).

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

        opened: list[IO[str]] = []
        orig_open = Path.open

        def _spy_open(self: Path, *args: object, **kwargs: object) -> IO[str]:
            fh = orig_open(self, *args, **kwargs)  # type: ignore[arg-type]
            opened.append(fh)
            return fh

        monkeypatch.setattr(Path, "open", _spy_open)

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
