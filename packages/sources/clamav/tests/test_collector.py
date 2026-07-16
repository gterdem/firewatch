"""``firewatch_clamav.collector`` — reader wiring, FOUND/action-line pairing, and
``ctx.kv`` cursor persistence.

Mapped 1:1 to issue #2's acceptance criteria plus the SDK's ``(record | None, cursor)``
contract (issues #1/#36/#60):

AC2  action mapped honestly: detection-only -> ALERT; a configured remove/quarantine
     outcome, when present in the log stream -> BLOCK (``TestPairDetections``).
AC6  Non-systemd hosts work via file-tail mode (``TestCollectFileMode``).
     journald mode is the default local-first path (``TestCollectJournaldMode``).
Plus: the ``(None, cursor)`` sentinel from either SDK reader is handled, never crashes
``normalize()`` with a bare ``None`` (``TestPairDetections`` oversized-skip cases).
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path

import pytest

from firewatch_clamav import collector as _collector
from firewatch_clamav.collector import _pair_detections, collect
from firewatch_clamav.config import ClamAVConfig

from _clamav_fakes import FakeScopedKV, make_ctx
from _clamav_journalctl_fakes import FakeProcess, make_sequenced_spawn

_RECEIVED_AT = datetime(2026, 7, 15, 12, 0, 0, tzinfo=timezone.utc)


async def _lines(*items: tuple[str | None, str]) -> AsyncIterator[tuple[str | None, str]]:
    for item in items:
        yield item


async def _collect_pairs(
    *items: tuple[str | None, str],
) -> list[tuple[str, str, str | None]]:
    """Run ``_pair_detections`` and return ``(path, signature, outcome)`` for each
    non-None yielded RawEvent, dropping ``None`` cursor-only entries."""
    out: list[tuple[str, str, str | None]] = []
    async for raw, _cursor in _pair_detections(_lines(*items), _RECEIVED_AT):
        if raw is not None:
            out.append((raw.data["path"], raw.data["signature"], raw.data["outcome"]))
    return out


class TestPairDetections:
    async def test_found_only_flushes_as_alert_at_stream_end(self) -> None:
        results = await _collect_pairs(
            ("/a/eicar.com: Win.Test.EICAR_HDB-1 FOUND", "c1"),
        )
        assert results == [("/a/eicar.com", "Win.Test.EICAR_HDB-1", None)]

    async def test_found_then_removed_line_yields_single_block_event(self) -> None:
        results = await _collect_pairs(
            ("/a/malware.exe: Win.Trojan.Generic-1 FOUND", "c1"),
            ("/a/malware.exe: Removed.", "c2"),
        )
        assert results == [("/a/malware.exe", "Win.Trojan.Generic-1", "removed")]

    async def test_found_then_moved_line_yields_single_block_event(self) -> None:
        results = await _collect_pairs(
            ("/a/malware.exe: Win.Trojan.Generic-1 FOUND", "c1"),
            ("/a/malware.exe: Moved to '/quarantine/malware.exe'.", "c2"),
        )
        assert results == [("/a/malware.exe", "Win.Trojan.Generic-1", "moved")]

    async def test_found_then_unrelated_line_flushes_as_alert(self) -> None:
        results = await _collect_pairs(
            ("/a/eicar.com: Win.Test.EICAR_HDB-1 FOUND", "c1"),
            ("some unrelated syslog noise", "c2"),
        )
        assert results == [("/a/eicar.com", "Win.Test.EICAR_HDB-1", None)]

    async def test_action_line_for_a_different_path_does_not_pair(self) -> None:
        """A companion line only pairs when its path matches the pending detection's."""
        results = await _collect_pairs(
            ("/a/eicar.com: Win.Test.EICAR_HDB-1 FOUND", "c1"),
            ("/b/other.exe: Removed.", "c2"),
        )
        assert results == [("/a/eicar.com", "Win.Test.EICAR_HDB-1", None)]

    async def test_two_consecutive_found_lines_yield_two_alert_events(self) -> None:
        results = await _collect_pairs(
            ("/a/one.exe: Sig-One FOUND", "c1"),
            ("/b/two.exe: Sig-Two FOUND", "c2"),
        )
        assert results == [
            ("/a/one.exe", "Sig-One", None),
            ("/b/two.exe", "Sig-Two", None),
        ]

    async def test_oversized_skip_with_pending_flushes_as_alert(self) -> None:
        """A ``(None, cursor)`` sentinel between a FOUND line and its resolution must
        not crash — the pending detection is honestly flushed as ALERT."""
        results = await _collect_pairs(
            ("/a/eicar.com: Win.Test.EICAR_HDB-1 FOUND", "c1"),
            (None, "c2"),
        )
        assert results == [("/a/eicar.com", "Win.Test.EICAR_HDB-1", None)]

    async def test_oversized_skip_without_pending_yields_nothing(self) -> None:
        results = await _collect_pairs((None, "c1"))
        assert results == []

    async def test_unrelated_line_with_no_pending_yields_nothing(self) -> None:
        results = await _collect_pairs(("just some noise", "c1"))
        assert results == []

    async def test_cursor_is_held_back_until_detection_resolved(self) -> None:
        """The FOUND line's own cursor ('c1') must not be released until the
        detection resolves — only 'c2' (the companion line) is yielded."""
        cursors: list[str] = []
        async for _raw, cursor in _pair_detections(
            _lines(
                ("/a/x.exe: Sig FOUND", "c1"),
                ("/a/x.exe: Removed.", "c2"),
            ),
            _RECEIVED_AT,
        ):
            cursors.append(cursor)
        assert cursors == ["c2"]

    async def test_cursor_released_immediately_on_new_found_line(self) -> None:
        """When a second FOUND line arrives before any companion, the first
        detection is resolved (no companion — ALERT) and released against ITS OWN
        cursor ('c1'), never advanced further than what's actually been decided;
        the second (still pending at stream end) releases at 'c2'."""
        cursors: list[str] = []
        async for _raw, cursor in _pair_detections(
            _lines(
                ("/a/one.exe: Sig-One FOUND", "c1"),
                ("/b/two.exe: Sig-Two FOUND", "c2"),
            ),
            _RECEIVED_AT,
        ):
            cursors.append(cursor)
        assert cursors == ["c1", "c2"]


# --------------------------------------------------------------------------------- #
# File mode — real FileTailReader against tmp_path (no subprocess needed)
# --------------------------------------------------------------------------------- #


class TestCollectFileMode:
    def _cfg(self, log_path: Path) -> ClamAVConfig:
        return ClamAVConfig(mode="file", log_path=str(log_path))

    async def test_collect_yields_raw_event_for_found_line(self, tmp_path: Path) -> None:
        log_path = tmp_path / "clamav.log"
        log_path.write_text("")
        ctx = make_ctx()
        cfg = self._cfg(log_path)

        # First cycle resolves "tail" -- pivot is the empty file's current end.
        assert [e async for e in collect(cfg, None, ctx)] == []

        with log_path.open("a") as f:
            f.write("/home/user/eicar.com: Win.Test.EICAR_HDB-1 FOUND\n")

        events = [e async for e in collect(cfg, None, ctx)]
        assert len(events) == 1
        assert events[0].data["path"] == "/home/user/eicar.com"
        assert events[0].data["signature"] == "Win.Test.EICAR_HDB-1"
        assert events[0].data["outcome"] is None

    async def test_first_run_does_not_replay_pre_existing_detections(
        self, tmp_path: Path
    ) -> None:
        """A fresh install must not flood the dashboard with a machine's entire
        ClamAV log history (ADR-0065 bootstrap-gap discipline)."""
        log_path = tmp_path / "clamav.log"
        log_path.write_text("/old/file.exe: Old.Sig-1 FOUND\n")
        ctx = make_ctx()
        cfg = self._cfg(log_path)

        events = [e async for e in collect(cfg, None, ctx)]
        assert events == []

    async def test_cursor_persists_across_collect_calls(self, tmp_path: Path) -> None:
        log_path = tmp_path / "clamav.log"
        log_path.write_text("")
        ctx = make_ctx()
        cfg = self._cfg(log_path)

        await _drain(collect(cfg, None, ctx))
        with log_path.open("a") as f:
            f.write("/a/one.exe: Sig-One FOUND\n")
        first = await _drain(collect(cfg, None, ctx))
        with log_path.open("a") as f:
            f.write("/a/two.exe: Sig-Two FOUND\n")
        second = await _drain(collect(cfg, None, ctx))

        assert [e.data["signature"] for e in first] == ["Sig-One"]
        assert [e.data["signature"] for e in second] == ["Sig-Two"]

    async def test_since_parameter_is_ignored(self, tmp_path: Path) -> None:
        """Resume is cursor-based (ctx.kv), not `since`-based -- an arbitrary
        `since` value must not change the result (ADR-0065 §3)."""
        log_path = tmp_path / "clamav.log"
        log_path.write_text("")
        ctx_a = make_ctx()
        ctx_b = make_ctx()
        cfg = self._cfg(log_path)
        await _drain(collect(cfg, None, ctx_a))
        await _drain(collect(cfg, "2020-01-01T00:00:00+00:00", ctx_b))

        with log_path.open("a") as f:
            f.write("/a/one.exe: Sig-One FOUND\n")

        result_a = await _drain(collect(cfg, None, ctx_a))
        result_b = await _drain(collect(cfg, "1999-01-01T00:00:00+00:00", ctx_b))
        assert [e.data["signature"] for e in result_a] == ["Sig-One"]
        assert [e.data["signature"] for e in result_b] == ["Sig-One"]

    async def test_unreadable_log_path_returns_cleanly_no_raise(self) -> None:
        cfg = ClamAVConfig(mode="file", log_path="/does/not/exist/clamav.log")
        ctx = make_ctx()
        events = await _drain(collect(cfg, None, ctx))
        assert events == []

    async def test_cursor_key_scoped_by_source_id(self, tmp_path: Path) -> None:
        """Two named instances sharing one KV scope (ScopedKV is bound only to
        type_key, ADR-0025) must not clobber each other's cursor."""
        log_path = tmp_path / "clamav.log"
        log_path.write_text("")
        kv = FakeScopedKV()
        ctx_laptop = make_ctx(source_id="laptop", kv=kv)
        ctx_desktop = make_ctx(source_id="desktop", kv=kv)
        cfg = self._cfg(log_path)

        await _drain(collect(cfg, None, ctx_laptop))
        with log_path.open("a") as f:
            f.write("/a/one.exe: Sig-One FOUND\n")
        # desktop's FIRST run still resolves its OWN "tail" pivot -- it must not
        # inherit laptop's already-advanced cursor and thus must also miss Sig-One
        # (both instances observe "first run skips pre-existing content").
        desktop_first = await _drain(collect(cfg, None, ctx_desktop))
        assert desktop_first == []

        with log_path.open("a") as f:
            f.write("/a/two.exe: Sig-Two FOUND\n")
        # laptop's own cursor was never advanced past its (pre-Sig-One) first call,
        # so its second call correctly sees BOTH lines; desktop's cursor was
        # separately advanced past Sig-One by desktop_first, so it only sees Sig-Two.
        # Distinct results prove the two instances are NOT sharing one cursor.
        laptop_second = await _drain(collect(cfg, None, ctx_laptop))
        desktop_second = await _drain(collect(cfg, None, ctx_desktop))
        assert [e.data["signature"] for e in laptop_second] == ["Sig-One", "Sig-Two"]
        assert [e.data["signature"] for e in desktop_second] == ["Sig-Two"]

    async def test_max_events_per_collect_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_collector, "_MAX_EVENTS_PER_COLLECT", 2)
        log_path = tmp_path / "clamav.log"
        log_path.write_text("")
        ctx = make_ctx()
        cfg = self._cfg(log_path)
        await _drain(collect(cfg, None, ctx))

        with log_path.open("a") as f:
            for i in range(5):
                f.write(f"/a/file{i}.exe: Sig-{i} FOUND\n")

        events = await _drain(collect(cfg, None, ctx))
        assert len(events) == 2

    async def test_cap_hit_logs_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(_collector, "_MAX_EVENTS_PER_COLLECT", 1)
        log_path = tmp_path / "clamav.log"
        log_path.write_text("")
        ctx = make_ctx()
        cfg = self._cfg(log_path)
        await _drain(collect(cfg, None, ctx))
        with log_path.open("a") as f:
            f.write("/a/one.exe: Sig-One FOUND\n/a/two.exe: Sig-Two FOUND\n")

        with caplog.at_level(logging.WARNING, logger="firewatch.clamav.collector"):
            await _drain(collect(cfg, None, ctx))
        assert any("MAX_EVENTS_PER_COLLECT" in r.message for r in caplog.records)


class TestCollectCancellation:
    async def test_cancelled_error_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _CancellingReader:
            async def resolve_start(self, start: str) -> str:
                return "pos-0"

            async def read(self, pos: str) -> AsyncIterator[tuple[str | None, str]]:
                raise asyncio.CancelledError()
                yield  # pragma: no cover -- makes this an async generator

        monkeypatch.setattr(_collector, "_build_reader", lambda cfg: _CancellingReader())
        ctx = make_ctx()
        cfg = ClamAVConfig()

        with pytest.raises(asyncio.CancelledError):
            await _drain(collect(cfg, None, ctx))


# --------------------------------------------------------------------------------- #
# journald mode — fixture journalctl output, no live journald (mirrors SDK's own tests)
# --------------------------------------------------------------------------------- #


class TestCollectJournaldMode:
    async def test_collect_dispatches_to_journald_and_yields_event(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import firewatch_sdk.localhost.journald as journald_module

        discovery = FakeProcess(stdout_lines=[b"-- cursor: c0\n"])
        stream = FakeProcess(
            stdout_lines=[
                b'{"MESSAGE": "/home/user/eicar.com: Win.Test.EICAR_HDB-1 FOUND", '
                b'"SYSLOG_IDENTIFIER": "clamd", "__CURSOR": "c1"}\n'
            ]
        )
        monkeypatch.setattr(
            journald_module,
            "_create_subprocess_exec",
            make_sequenced_spawn([discovery, stream]),
        )

        ctx = make_ctx()
        cfg = ClamAVConfig(mode="journald")
        events = await _drain(collect(cfg, None, ctx))

        assert len(events) == 1
        assert events[0].data["path"] == "/home/user/eicar.com"
        assert events[0].data["signature"] == "Win.Test.EICAR_HDB-1"

    async def test_missing_journalctl_binary_returns_cleanly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import firewatch_sdk.localhost.journald as journald_module

        async def _raise_not_found(*argv: str, stdout: int, stderr: int) -> FakeProcess:
            raise FileNotFoundError("journalctl not found")

        monkeypatch.setattr(journald_module, "_create_subprocess_exec", _raise_not_found)

        ctx = make_ctx()
        cfg = ClamAVConfig(mode="journald")
        events = await _drain(collect(cfg, None, ctx))
        assert events == []


async def _drain(agen: AsyncIterator) -> list:
    return [item async for item in agen]
