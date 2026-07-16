"""Minimal ``journalctl -o json`` subprocess doubles for firewatch_clamav's own
collector tests — trimmed to just what this package's dispatch/integration tests need
(the reader's own exhaustive behavior is already covered by firewatch-sdk's test suite;
this file only proves the collector wires it up correctly).

Mirrors ``firewatch_sdk`` tests/localhost/_journalctl_fakes.py's approach (monkeypatch
``firewatch_sdk.localhost.journald._create_subprocess_exec``) without importing that
file directly — plugin tests stay self-contained, no cross-package test-internal import.
"""
from __future__ import annotations

from collections.abc import Sequence


class _LineStream:
    def __init__(self, lines: Sequence[bytes]) -> None:
        self._lines: list[bytes] = list(lines)

    async def readline(self) -> bytes:
        if not self._lines:
            return b""
        return self._lines.pop(0)

    async def read(self, n: int = -1) -> bytes:
        data = b"".join(self._lines)
        self._lines = []
        return data if n < 0 else data[:n]


class FakeProcess:
    """Fake ``asyncio.subprocess.Process`` for a single ``journalctl`` invocation."""

    def __init__(self, *, stdout_lines: Sequence[bytes] = (), returncode: int = 0) -> None:
        self.stdout: _LineStream | None = _LineStream(stdout_lines)
        self.stderr: _LineStream | None = _LineStream([])
        self.returncode: int | None = None
        self._final_returncode = returncode

    def terminate(self) -> None:
        if self.returncode is None:
            self.returncode = self._final_returncode

    def kill(self) -> None:
        if self.returncode is None:
            self.returncode = self._final_returncode

    async def wait(self) -> int:
        if self.returncode is None:
            self.returncode = self._final_returncode
        return self.returncode


def make_sequenced_spawn(procs: list[FakeProcess]):
    """Return successive ``FakeProcess``es across repeated calls (discovery probe
    first, then the main stream — matching ``JournaldReader``'s own call order)."""
    remaining = list(procs)

    async def _spawn(*argv: str, stdout: int, stderr: int) -> FakeProcess:
        if remaining:
            return remaining.pop(0)
        return FakeProcess(stdout_lines=[])

    return _spawn
