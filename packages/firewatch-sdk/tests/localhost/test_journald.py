"""Tests for ``firewatch_sdk.localhost.journald.JournaldReader`` — EARS criteria
mapped 1:1 to issue #1's acceptance criteria.

EARS-1  Cursor-filtered read: identifier/facility/unit matches; only records
        after the stored cursor are yielded, each carrying the new cursor.
EARS-2  No stored cursor: explicit start position required (cursor|tail|head);
        the reader never infers/defaults one.
EARS-3  journalctl absent / journal unreadable / non-systemd host -> typed,
        catchable error with remediation text — never a bare traceback.
EARS-6  Cancellation: no orphaned journalctl subprocess.
EARS-7  Fixture journal output only — no live journald needed in CI.

No live ``journalctl`` is invoked anywhere in this file: ``JournaldReader``
spawns subprocesses via the module-level ``_create_subprocess_exec``, which
every test here monkeypatches to a ``FakeProcess`` fixture double.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from firewatch_sdk.localhost import JournaldUnavailableError
from firewatch_sdk.localhost.errors import LocalReaderError
from firewatch_sdk.localhost.journald import JournaldReader

from _journalctl_fakes import FakeProcess, make_spawn


def _record(cursor: str, **fields: Any) -> dict[str, Any]:
    """Build a minimal journal JSON record carrying the given cursor."""
    base = {
        "MESSAGE": "test message",
        "SYSLOG_IDENTIFIER": "clamd",
        "PRIORITY": "6",
        "__CURSOR": cursor,
    }
    base.update(fields)
    return base


def _line(cursor: str, **fields: Any) -> bytes:
    return (json.dumps(_record(cursor, **fields)) + "\n").encode("utf-8")


class _SequencedSpawn:
    """Returns successive ``FakeProcess`` instances across repeated calls."""

    def __init__(self, procs: list[FakeProcess]) -> None:
        self._procs = list(procs)
        self.calls: list[tuple[str, ...]] = []

    async def __call__(self, *argv: str, stdout: int, stderr: int) -> FakeProcess:
        self.calls.append(argv)
        return self._procs.pop(0)


# --------------------------------------------------------------------------- #
# EARS-2 — explicit start position, never inferred
# --------------------------------------------------------------------------- #


class TestExplicitStartPosition:
    def test_read_requires_explicit_start_argument(self) -> None:
        """No default: calling read() with no argument is a TypeError, not a
        silent choice of history-from-the-beginning or now."""
        reader = JournaldReader()
        with pytest.raises(TypeError):
            reader.read()  # type: ignore[call-arg]

    async def test_head_reads_from_beginning_no_after_cursor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = FakeProcess(stdout_lines=[_line("c1"), _line("c2")])
        spawn = make_spawn(proc)
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader()
        results = [r async for r in reader.read("head")]

        assert [cursor for _, cursor in results] == ["c1", "c2"]
        assert len(spawn.calls) == 1  # type: ignore[attr-defined]
        argv = spawn.calls[0]  # type: ignore[attr-defined]
        assert "--after-cursor" not in argv

    async def test_tail_first_run_establishes_pivot_without_history(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """First run with start='tail': resolve_start() finds an existing
        pivot cursor; read() from that pivot (no new entries since) yields
        nothing — no history is ever read."""
        discovery = FakeProcess(stdout_lines=[b"-- cursor: s=pivot\n"])
        follow_up = FakeProcess(stdout_lines=[])
        spawn = _SequencedSpawn([discovery, follow_up])
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader()
        resolved = await reader.resolve_start("tail")
        assert resolved == "s=pivot"
        results = [r async for r in reader.read(resolved)]

        assert results == []
        assert len(spawn.calls) == 2
        assert "--show-cursor" in spawn.calls[0]
        assert "-n" in spawn.calls[0]
        assert "s=pivot" in spawn.calls[1]

    async def test_tail_on_empty_journal_resolves_to_head_and_reads_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Empty journal: discovery finds no cursor at all — resolve_start()
        returns "head" (tail and head denote the same position when there is
        no history), and read("head") correctly finds nothing either."""
        discovery = FakeProcess(stdout_lines=[])
        head_read = FakeProcess(stdout_lines=[])
        spawn = _SequencedSpawn([discovery, head_read])
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader()
        resolved = await reader.resolve_start("tail")
        assert resolved == "head"
        results = [r async for r in reader.read(resolved)]

        assert results == []
        assert len(spawn.calls) == 2

    async def test_read_rejects_tail_sentinel(self) -> None:
        """Structural poka-yoke: read() must never accept "tail" directly —
        only resolve_start()'s output is a valid position."""
        reader = JournaldReader()
        with pytest.raises(ValueError, match="tail"):
            await reader.read("tail").__anext__()

    async def test_stored_cursor_resumes_via_after_cursor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = FakeProcess(stdout_lines=[_line("c3")])
        spawn = make_spawn(proc)
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader()
        results = [r async for r in reader.read("s=c2;i=1")]

        assert [cursor for _, cursor in results] == ["c3"]
        argv = spawn.calls[0]  # type: ignore[attr-defined]
        idx = argv.index("--after-cursor")
        assert argv[idx + 1] == "s=c2;i=1"


# --------------------------------------------------------------------------- #
# Regression — resolve_start() must surface a persistable position BEFORE any
# draining, or a quiet "tail" cycle silently re-pivots past events that
# arrived in the gap and never reads them.
# --------------------------------------------------------------------------- #


class TestResolveStartRegression:
    async def test_resolve_start_tail_surfaces_concrete_pivot(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bootstrap pivot must escape to the caller, not stay a local
        variable inside read() — this is the value a caller persists."""
        discovery = FakeProcess(stdout_lines=[b"-- cursor: s=pivot\n"])
        spawn = _SequencedSpawn([discovery])
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader()
        resolved = await reader.resolve_start("tail")

        assert resolved == "s=pivot"  # concrete — NOT the literal "tail"

    async def test_resolve_start_head_and_cursor_are_passthrough(self) -> None:
        reader = JournaldReader()
        assert await reader.resolve_start("head") == "head"
        assert await reader.resolve_start("s=already-a-cursor") == "s=already-a-cursor"

    async def test_resolve_start_tail_discovery_is_unfiltered(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A filter that currently matches zero entries makes --show-cursor
        print nothing at all (verified against real journalctl) — so the
        pivot probe must never apply this reader's own filters, or a reader
        configured with e.g. identifiers=["clamd"] could never resolve "tail"
        until clamd had already logged once."""
        discovery = FakeProcess(stdout_lines=[b"-- cursor: s=pivot\n"])
        spawn = _SequencedSpawn([discovery])
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader(identifiers=["clamd"], facilities=["authpriv"])
        resolved = await reader.resolve_start("tail")

        assert resolved == "s=pivot"
        argv = spawn.calls[0]
        assert "-t" not in argv
        assert not any(a.startswith("SYSLOG_FACILITY=") for a in argv)

    async def test_resolve_start_tail_on_fully_empty_journal_resolves_to_head(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No entry has ever been written anywhere in the raw journal — tail
        and head denote the same position (there is no history to flood), so
        this resolves to "head" rather than a sentinel that would need
        re-resolving — which would reintroduce this exact bug in miniature:
        entries written between one empty probe and the next would be
        skipped."""
        empty_discovery = FakeProcess(stdout_lines=[])
        spawn = _SequencedSpawn([empty_discovery])
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader()
        resolved = await reader.resolve_start("tail")

        assert resolved == "head"

    async def test_quiet_cycle_then_new_records_are_not_lost(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Pin the exact data-loss timeline from the bug report:

            poll 1: resolve_start("tail") -> pivot P1; drain(P1) -> 0 records
                    (caller persists P1, NOT "tail" again)
            ...     50 events land in the journal after P1...
            poll 2: caller resumes from the PERSISTED P1 (never re-resolves
                    "tail") -> those events are read, not skipped.

        A caller that (incorrectly) called read("tail") again on poll 2
        instead of the persisted cursor is exactly the bug this regression
        guards against — it is not exercised here because it is no longer
        the documented/available pattern once resolve_start() exists.
        """
        # Poll 1: bootstrap (pivot P1) + drain — quiet, nothing new yet.
        discovery = FakeProcess(stdout_lines=[b"-- cursor: s=p1\n"])
        drain1 = FakeProcess(stdout_lines=[])
        spawn1 = _SequencedSpawn([discovery, drain1])
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn1)

        reader = JournaldReader()
        cursor = await reader.resolve_start("tail")
        assert cursor == "s=p1"
        first_cycle = [r async for r in reader.read(cursor)]
        assert first_cycle == []

        # Between polls, 50 events land in the journal after P1 (simulated by
        # the next drain simply having output — the exact count is immaterial
        # to the regression: the point is that it is nonzero and was not lost).
        drain2 = FakeProcess(stdout_lines=[_line("s=p2")])
        spawn2 = _SequencedSpawn([drain2])
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn2)

        # Poll 2: resume from the cursor persisted after poll 1 — NOT "tail".
        second_cycle = [r async for r in reader.read(cursor)]

        assert [c for _, c in second_cycle] == ["s=p2"]
        argv = spawn2.calls[0]
        idx = argv.index("--after-cursor")
        assert argv[idx + 1] == "s=p1"  # resumed from the persisted pivot


# --------------------------------------------------------------------------- #
# EARS-1 — filters (identifier / facility / unit)
# --------------------------------------------------------------------------- #


class TestMatchFilters:
    async def test_identifier_filter_uses_dash_t(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = FakeProcess(stdout_lines=[_line("c1")])
        spawn = make_spawn(proc)
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader(identifiers=["clamd"])
        _ = [r async for r in reader.read("head")]

        argv = spawn.calls[0]  # type: ignore[attr-defined]
        assert "-t" in argv
        assert argv[argv.index("-t") + 1] == "clamd"

    async def test_facility_filter_translates_name_to_syslog_facility_number(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = FakeProcess(stdout_lines=[_line("c1")])
        spawn = make_spawn(proc)
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader(facilities=["authpriv"])
        _ = [r async for r in reader.read("head")]

        argv = spawn.calls[0]  # type: ignore[attr-defined]
        assert "SYSLOG_FACILITY=10" in argv

    async def test_unit_filter_uses_dash_u(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = FakeProcess(stdout_lines=[_line("c1")])
        spawn = make_spawn(proc)
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader(units=["sshd.service"])
        _ = [r async for r in reader.read("head")]

        argv = spawn.calls[0]  # type: ignore[attr-defined]
        assert "-u" in argv
        assert argv[argv.index("-u") + 1] == "sshd.service"


# --------------------------------------------------------------------------- #
# EARS-3 — typed, catchable errors (never a bare traceback)
# --------------------------------------------------------------------------- #


class TestTypedErrors:
    async def test_missing_binary_raises_typed_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _raise_not_found(*argv: str, stdout: int, stderr: int) -> FakeProcess:
            raise FileNotFoundError("no such file")

        monkeypatch.setattr(
            "firewatch_sdk.localhost.journald._create_subprocess_exec", _raise_not_found
        )

        reader = JournaldReader()
        with pytest.raises(JournaldUnavailableError) as excinfo:
            _ = [r async for r in reader.read("head")]
        assert "journalctl" in str(excinfo.value).lower()
        assert isinstance(excinfo.value, LocalReaderError)

    async def test_permission_denied_raises_typed_error_with_remediation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = FakeProcess(
            stdout_lines=[],
            stderr=b"Failed to open system journal: Permission denied\n",
            returncode=1,
        )
        spawn = make_spawn(proc)
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader()
        with pytest.raises(JournaldUnavailableError) as excinfo:
            _ = [r async for r in reader.read("head")]
        assert "systemd-journal" in str(excinfo.value)

    async def test_no_journal_files_raises_typed_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = FakeProcess(
            stdout_lines=[],
            stderr=b"No journal files were found.\n",
            returncode=1,
        )
        spawn = make_spawn(proc)
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader()
        with pytest.raises(JournaldUnavailableError) as excinfo:
            _ = [r async for r in reader.read("head")]
        assert "systemd-based" in str(excinfo.value)

    async def test_mid_stream_failure_after_records_does_not_raise(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Once records have already been yielded this cycle, a later failure
        is logged and the generator simply ends — it never raises out of the
        loop (the hard rule PullSource.collect() consumers rely on)."""
        proc = FakeProcess(
            stdout_lines=[_line("c1")],
            stderr=b"journal corrupted mid-read\n",
            returncode=1,
        )
        spawn = make_spawn(proc)
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader()
        results = [r async for r in reader.read("head")]

        assert [cursor for _, cursor in results] == ["c1"]

    async def test_malformed_json_line_is_skipped_without_raising(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = FakeProcess(stdout_lines=[b"NOT JSON\n", _line("c1")])
        spawn = make_spawn(proc)
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader()
        results = [r async for r in reader.read("head")]

        assert [cursor for _, cursor in results] == ["c1"]


# --------------------------------------------------------------------------- #
# EARS-6 — cancellation: no orphaned journalctl subprocess
# --------------------------------------------------------------------------- #


class TestCancellation:
    async def test_cancellation_terminates_subprocess(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = FakeProcess(
            stdout_lines=[_line("c1"), _line("c2"), _line("c3")],
            cancel_after=1,
        )
        spawn = make_spawn(proc)
        monkeypatch.setattr("firewatch_sdk.localhost.journald._create_subprocess_exec", spawn)

        reader = JournaldReader()
        import asyncio

        with pytest.raises(asyncio.CancelledError):
            _ = [r async for r in reader.read("head")]

        assert proc.terminate_called is True
