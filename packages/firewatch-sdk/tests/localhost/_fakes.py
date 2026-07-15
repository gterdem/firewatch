"""Fixture ``journalctl -o json`` subprocess doubles — no live journald in CI.

``FakeProcess`` stands in for ``asyncio.subprocess.Process``: an async-iterable
``stdout`` (fixture journal lines) plus ``.terminate()``/``.kill()``/``.wait()``
tracking so cancellation tests can assert the subprocess was never orphaned.
"""
from __future__ import annotations

import asyncio
from collections.abc import Sequence


class _LineStream:
    """Async-iterable + ``.read()`` double for ``proc.stdout`` / ``proc.stderr``."""

    def __init__(
        self, lines: Sequence[bytes], *, cancel_after: int | None = None
    ) -> None:
        self._lines = list(lines)
        self._cancel_after = cancel_after
        self._yielded = 0

    def __aiter__(self) -> "_LineStream":
        return self

    async def __anext__(self) -> bytes:
        if self._cancel_after is not None and self._yielded >= self._cancel_after:
            raise asyncio.CancelledError()
        if not self._lines:
            raise StopAsyncIteration
        self._yielded += 1
        return self._lines.pop(0)

    async def read(self) -> bytes:
        data = b"".join(self._lines)
        self._lines = []
        return data


class FakeProcess:
    """Fake ``asyncio.subprocess.Process`` — records terminate()/kill() calls."""

    def __init__(
        self,
        *,
        stdout_lines: Sequence[bytes] = (),
        stderr: bytes = b"",
        returncode: int = 0,
        cancel_after: int | None = None,
    ) -> None:
        self.stdout: _LineStream | None = _LineStream(
            stdout_lines, cancel_after=cancel_after
        )
        self.stderr: _LineStream | None = _LineStream([stderr] if stderr else [])
        self.returncode: int | None = None
        self._final_returncode = returncode
        self.terminate_called = False
        self.kill_called = False

    def terminate(self) -> None:
        self.terminate_called = True
        if self.returncode is None:
            self.returncode = self._final_returncode

    def kill(self) -> None:
        self.kill_called = True
        if self.returncode is None:
            self.returncode = self._final_returncode

    async def wait(self) -> int:
        if self.returncode is None:
            self.returncode = self._final_returncode
        return self.returncode


def make_spawn(proc: FakeProcess):
    """Return an async callable matching ``journald._create_subprocess_exec``'s
    signature, always returning ``proc`` regardless of the argv it was called
    with (tests inspect the recorded call separately if needed)."""

    calls: list[tuple[str, ...]] = []

    async def _spawn(*argv: str, stdout: int, stderr: int) -> FakeProcess:
        calls.append(argv)
        return proc

    _spawn.calls = calls  # type: ignore[attr-defined]
    return _spawn
