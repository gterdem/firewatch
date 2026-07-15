"""Tests for ``firewatch_sdk.localhost.filetail.FileTailReader`` — EARS criteria
mapped 1:1 to issue #1's acceptance criteria.

EARS-2  No stored offset: explicit start position required (cursor|tail|head);
        the reader never infers/defaults one.
EARS-4  Rotation (rename and in-place truncate) detected without duplicating
        or skipping lines.
EARS-5  First-run start-position rule applies identically to FileTailReader.
EARS-6  Cancellation: the open file handle is closed promptly, never leaked.

Pure filesystem I/O against ``tmp_path`` — no live journald, no subprocess.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import IO

import pytest

from firewatch_sdk.localhost.errors import FileTailUnavailableError, LocalReaderError
from firewatch_sdk.localhost.filetail import FileTailReader


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

        agen = reader.read("head", poll_interval=0.01)
        first = await agen.__anext__()
        second = await agen.__anext__()
        await agen.aclose()

        assert first[0] == "line1"
        assert second[0] == "line2"

    async def test_tail_skips_existing_content_only_new_lines_yielded(
        self, tmp_path: Path
    ) -> None:
        """A fresh install must not ingest a machine's entire log history."""
        path = tmp_path / "auth.log"
        path.write_text("old1\nold2\n")
        reader = FileTailReader(path)

        agen = reader.read("tail", poll_interval=0.01)
        # __anext__() doesn't run the generator body until scheduled — give it
        # a moment to open the file and seek to its current end BEFORE the
        # new line is appended, so "tail" genuinely means "from now".
        task = asyncio.ensure_future(agen.__anext__())
        await asyncio.sleep(0.05)
        with path.open("a") as f:
            f.write("new1\n")
        line, _cursor = await task
        await agen.aclose()

        assert line == "new1"

    async def test_cursor_resume_continues_from_stored_offset(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "auth.log"
        path.write_text("line1\nline2\n")
        reader = FileTailReader(path)

        agen = reader.read("head", poll_interval=0.01)
        await agen.__anext__()  # line1
        _second, cursor = await agen.__anext__()  # line2 — cursor now at EOF
        await agen.aclose()

        with path.open("a") as f:
            f.write("line3\n")

        resumed = reader.read(cursor, poll_interval=0.01)
        line, _c = await resumed.__anext__()
        await resumed.aclose()
        assert line == "line3"

    async def test_malformed_cursor_raises_typed_error(self, tmp_path: Path) -> None:
        path = tmp_path / "auth.log"
        path.write_text("line1\n")
        reader = FileTailReader(path)

        with pytest.raises(FileTailUnavailableError):
            await reader.read("not-a-cursor", poll_interval=0.01).__anext__()

    async def test_unreadable_path_raises_typed_error(self, tmp_path: Path) -> None:
        reader = FileTailReader(tmp_path / "does-not-exist.log")
        with pytest.raises(FileTailUnavailableError) as excinfo:
            await reader.read("head", poll_interval=0.01).__anext__()
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

        agen = reader.read(stale_cursor, poll_interval=0.01)
        first = await agen.__anext__()
        await agen.aclose()
        assert first[0] == "current1"


# --------------------------------------------------------------------------- #
# EARS-4 — rotation-aware (rename and in-place truncate)
# --------------------------------------------------------------------------- #


class TestRotation:
    async def test_rename_rotation_no_duplicate_or_skip(self, tmp_path: Path) -> None:
        path = tmp_path / "auth.log"
        path.write_text("line1\nline2\n")
        reader = FileTailReader(path)

        agen = reader.read("head", poll_interval=0.01)
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

        agen = reader.read("head", poll_interval=0.01)
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
        path = tmp_path / "auth.log"
        path.write_text("line1\n")
        reader = FileTailReader(path)

        opened: list[IO[str]] = []
        orig_open = Path.open

        def _spy_open(self: Path, *args: object, **kwargs: object) -> IO[str]:
            fh = orig_open(self, *args, **kwargs)  # type: ignore[arg-type]
            opened.append(fh)
            return fh

        monkeypatch.setattr(Path, "open", _spy_open)

        async def _consume() -> None:
            async for _ in reader.read("tail", poll_interval=0.01):
                pass

        task = asyncio.create_task(_consume())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert opened
        assert all(fh.closed for fh in opened)
