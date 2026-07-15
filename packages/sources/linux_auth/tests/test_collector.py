"""Collector tests — mocked readers (no live journald/filesystem tailing).

Mirrors the mocked-SSH pattern the testing-conventions skill calls out for pull
collectors (``tests/adapters/test_suricata_remote.py``), adapted to the local
readers: ``JournaldReader``/``FileTailReader`` are monkeypatched at the
``firewatch_linux_auth.collector`` module level (the same patch-point idiom
``firewatch_suricata.collector`` uses for ``asyncssh``).

Central concern (issue #3 brief): **both readers may yield a ``(None, cursor)``
sentinel** — an oversized entry was skipped, but the cursor must still advance
so the same line isn't re-served and re-skipped forever. This file proves the
collector honors that: a ``None`` record/line is never forwarded as a
``RawEvent``, but the persisted cursor always reflects the last position seen.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from firewatch_sdk import PluginContext
from firewatch_sdk.localhost import FileTailUnavailableError, JournaldUnavailableError
from firewatch_sdk.testing import InMemoryScopedKV

from firewatch_linux_auth import collector
from firewatch_linux_auth.config import LinuxAuthConfig

_CURSOR_NS = collector._CURSOR_NAMESPACE  # noqa: SLF001 — white-box cursor assertions


def _ctx() -> PluginContext:
    return PluginContext(kv=InMemoryScopedKV(), source_id="test-instance")


# ---------------------------------------------------------------------------
# Fake readers — same (record|line, cursor) shape as the real SDK readers.
# ---------------------------------------------------------------------------


class _FakeJournaldReader:
    """Stands in for JournaldReader: records the constructor args it was
    called with (so tests can assert the identifier whitelist), and replays a
    scripted (record, cursor) sequence.

    ``script``/``unavailable_on_resolve``/``unavailable_on_read`` are set as
    CLASS attributes by each test before calling ``collector.collect()`` (the
    collector constructs its own instance internally, so tests script
    behaviour before construction rather than injecting an instance).
    """

    last_instance: "_FakeJournaldReader | None" = None
    script: list[tuple[dict[str, Any] | None, str]] = []
    unavailable_on_resolve: bool = False
    unavailable_on_read: bool = False

    def __init__(self, *, identifiers=(), facilities=(), units=(), journalctl_bin="journalctl"):
        self.identifiers = identifiers
        self.journalctl_bin = journalctl_bin
        self.resolve_calls: list[str] = []
        self.read_calls: list[str] = []
        type(self).last_instance = self

    async def resolve_start(self, start: str) -> str:
        self.resolve_calls.append(start)
        if self.unavailable_on_resolve:
            raise JournaldUnavailableError("fake: journald unavailable")
        return "resolved-tail" if start == "tail" else start

    async def read(self, pos: str) -> AsyncIterator[tuple[dict[str, Any] | None, str]]:
        self.read_calls.append(pos)
        if self.unavailable_on_read:
            raise JournaldUnavailableError("fake: journalctl exited nonzero")
        for record, cursor in self.script:
            yield record, cursor


class _FakeFileTailReader:
    last_instance: "_FakeFileTailReader | None" = None
    script: list[tuple[str | None, str]] = []
    unavailable_on_resolve: bool = False
    unavailable_on_read: bool = False

    def __init__(self, path):
        self.path = path
        self.resolve_calls: list[str] = []
        type(self).last_instance = self

    async def resolve_start(self, start: str) -> str:
        self.resolve_calls.append(start)
        if self.unavailable_on_resolve:
            raise FileTailUnavailableError("fake: cannot stat file")
        return "resolved-tail" if start == "tail" else start

    async def read(self, pos: str) -> AsyncIterator[tuple[str | None, str]]:
        if self.unavailable_on_read:
            raise FileTailUnavailableError("fake: symlink refused mid-poll")
        for line, cursor in self.script:
            yield line, cursor


@pytest.fixture(autouse=True)
def _patch_readers(monkeypatch):
    monkeypatch.setattr(collector, "JournaldReader", _FakeJournaldReader)
    monkeypatch.setattr(collector, "FileTailReader", _FakeFileTailReader)
    _FakeJournaldReader.last_instance = None
    _FakeJournaldReader.script = []
    _FakeJournaldReader.unavailable_on_resolve = False
    _FakeJournaldReader.unavailable_on_read = False
    _FakeFileTailReader.last_instance = None
    _FakeFileTailReader.script = []
    _FakeFileTailReader.unavailable_on_resolve = False
    _FakeFileTailReader.unavailable_on_read = False


def _cfg(**kwargs) -> LinuxAuthConfig:
    return LinuxAuthConfig(**kwargs)


# ---------------------------------------------------------------------------
# journald mode — happy path
# ---------------------------------------------------------------------------


class TestJournaldHappyPath:
    @pytest.mark.asyncio
    async def test_yields_raw_events_from_records(self):
        cfg = _cfg(mode="journald")
        ctx = _ctx()
        reader = _FakeJournaldReader
        # Constructed lazily inside collect() — script the NEXT instance via
        # a class-level default consulted at __init__ time is awkward, so
        # instead patch read()/resolve_start() behaviour through a shared
        # class attribute picked up by every instance this test creates.
        reader.script = [
            ({"MESSAGE": "Failed password for admin from 203.0.113.5 port 1 ssh2"}, "c1"),
            ({"MESSAGE": "Accepted password for admin from 203.0.113.5 port 1 ssh2"}, "c2"),
        ]
        raws = [raw async for raw in collector.collect(cfg, None, ctx)]
        assert len(raws) == 2
        assert "Failed password" in raws[0].data["message"]
        assert "Accepted password" in raws[1].data["message"]

    @pytest.mark.asyncio
    async def test_identifier_whitelist_passed_to_reader(self):
        cfg = _cfg(mode="journald")
        ctx = _ctx()
        _FakeJournaldReader.script = []
        _ = [raw async for raw in collector.collect(cfg, None, ctx)]
        inst = _FakeJournaldReader.last_instance
        assert inst is not None
        assert "sshd" in inst.identifiers
        assert "sudo" in inst.identifiers
        assert "useradd" in inst.identifiers

    @pytest.mark.asyncio
    async def test_cursor_persisted_after_cycle(self):
        cfg = _cfg(mode="journald")
        ctx = _ctx()
        _FakeJournaldReader.script = [
            ({"MESSAGE": "Accepted password for x from 203.0.113.1 port 1 ssh2"}, "final-cursor"),
        ]
        _ = [raw async for raw in collector.collect(cfg, None, ctx)]
        stored = await ctx.kv.get(_CURSOR_NS, "journald")
        assert stored == "final-cursor"

    @pytest.mark.asyncio
    async def test_pivot_persisted_even_on_zero_record_cycle(self):
        """A quiet cycle still must persist a resolvable position (ADR-0065
        bootstrap-gap fix) — even when nothing is yielded."""
        cfg = _cfg(mode="journald")
        ctx = _ctx()
        _FakeJournaldReader.script = []
        _ = [raw async for raw in collector.collect(cfg, None, ctx)]
        stored = await ctx.kv.get(_CURSOR_NS, "journald")
        assert stored == "resolved-tail"

    @pytest.mark.asyncio
    async def test_resume_uses_stored_cursor_not_tail(self):
        cfg = _cfg(mode="journald")
        ctx = _ctx()
        await ctx.kv.put(_CURSOR_NS, "journald", "existing-cursor")
        _FakeJournaldReader.script = []
        _ = [raw async for raw in collector.collect(cfg, None, ctx)]
        inst = _FakeJournaldReader.last_instance
        assert inst is not None
        assert inst.resolve_calls == ["existing-cursor"]


# ---------------------------------------------------------------------------
# The (None, cursor) sentinel — the central concern of this file
# ---------------------------------------------------------------------------


class TestNoneRecordSentinel:
    @pytest.mark.asyncio
    async def test_journald_none_record_not_forwarded_but_cursor_advances(self):
        cfg = _cfg(mode="journald")
        ctx = _ctx()
        _FakeJournaldReader.script = [(None, "skip-cursor")]
        raws = [raw async for raw in collector.collect(cfg, None, ctx)]
        assert raws == []
        assert await ctx.kv.get(_CURSOR_NS, "journald") == "skip-cursor"

    @pytest.mark.asyncio
    async def test_journald_none_record_mixed_with_real_records(self):
        """None MUST be at most one, as the final item per the reader's own
        invariant — this test only exercises the collector's own handling of
        whatever the reader yields, not the invariant itself (that lives in
        the SDK's own reader tests)."""
        cfg = _cfg(mode="journald")
        ctx = _ctx()
        _FakeJournaldReader.script = [
            ({"MESSAGE": "Accepted password for x from 203.0.113.1 port 1 ssh2"}, "c1"),
            (None, "c2"),
        ]
        raws = [raw async for raw in collector.collect(cfg, None, ctx)]
        assert len(raws) == 1
        assert await ctx.kv.get(_CURSOR_NS, "journald") == "c2"

    @pytest.mark.asyncio
    async def test_file_none_line_not_forwarded_but_cursor_advances(self):
        cfg = _cfg(mode="file")
        ctx = _ctx()
        _FakeFileTailReader.script = [(None, "skip-cursor")]
        raws = [raw async for raw in collector.collect(cfg, None, ctx)]
        assert raws == []
        assert await ctx.kv.get(_CURSOR_NS, "file") == "skip-cursor"


# ---------------------------------------------------------------------------
# auto / journald / file mode dispatch
# ---------------------------------------------------------------------------


class TestModeDispatch:
    @pytest.mark.asyncio
    async def test_auto_mode_falls_back_to_file_when_journald_unavailable(self):
        cfg = _cfg(mode="auto")
        ctx = _ctx()
        _FakeJournaldReader.unavailable_on_resolve = True
        _FakeFileTailReader.script = [
            ("Failed password for x from 203.0.113.1 port 1 ssh2", "c1"),
        ]
        raws = [raw async for raw in collector.collect(cfg, None, ctx)]
        assert len(raws) == 1
        assert raws[0].data["reader"] == "file"

    @pytest.mark.asyncio
    async def test_journald_mode_pinned_does_not_fall_back(self):
        cfg = _cfg(mode="journald")
        ctx = _ctx()
        _FakeJournaldReader.unavailable_on_resolve = True
        raws = [raw async for raw in collector.collect(cfg, None, ctx)]
        assert raws == []
        assert _FakeFileTailReader.last_instance is None

    @pytest.mark.asyncio
    async def test_file_mode_never_constructs_journald_reader(self):
        cfg = _cfg(mode="file")
        ctx = _ctx()
        _FakeFileTailReader.script = []
        _ = [raw async for raw in collector.collect(cfg, None, ctx)]
        assert _FakeJournaldReader.last_instance is None

    @pytest.mark.asyncio
    async def test_file_mode_unavailable_yields_nothing_and_logs(self):
        cfg = _cfg(mode="file")
        ctx = _ctx()
        _FakeFileTailReader.unavailable_on_resolve = True
        raws = [raw async for raw in collector.collect(cfg, None, ctx)]
        assert raws == []


# ---------------------------------------------------------------------------
# MAX_EVENTS_PER_COLLECT cap
# ---------------------------------------------------------------------------


class TestEventCap:
    @pytest.mark.asyncio
    async def test_journald_stops_early_at_cap(self, monkeypatch):
        monkeypatch.setattr(collector, "MAX_EVENTS_PER_COLLECT", 2)
        cfg = _cfg(mode="journald")
        ctx = _ctx()
        _FakeJournaldReader.script = [
            ({"MESSAGE": f"Accepted password for x from 203.0.113.1 port {i} ssh2"}, f"c{i}")
            for i in range(5)
        ]
        raws = [raw async for raw in collector.collect(cfg, None, ctx)]
        assert len(raws) == 2
        # Cursor reflects the last record actually processed (c1, 0-indexed),
        # not the full script — the next cycle resumes from exactly there.
        assert await ctx.kv.get(_CURSOR_NS, "journald") == "c1"
