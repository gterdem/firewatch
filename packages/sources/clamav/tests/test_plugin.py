"""``ClamAVSource`` — SourcePlugin + PullSource contract, entry-point discovery,
health_check, and normalize()/collect() delegation.

Mapped 1:1 to issue #2's acceptance criteria:

AC1  the loader discovers ``clamav`` via the ``firewatch.sources`` entry point with
     zero edits to firewatch-core, and a config card appears (schema-driven).
AC6  journald is the default (local-first, ADR-0065); file mode is the fallback.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import BaseModel

from firewatch_clamav.config import ClamAVConfig
from firewatch_clamav.plugin import ClamAVSource
from firewatch_sdk import RawEvent, SourcePlugin

from _clamav_fakes import make_ctx


class TestEntryPointDiscovery:
    def test_entry_point_is_registered(self) -> None:
        """After `uv sync`, the entry point group lists 'clamav'."""
        from importlib.metadata import entry_points

        eps = entry_points(group="firewatch.sources")
        names = {ep.name for ep in eps}
        assert "clamav" in names, f"'clamav' not found. Found: {names}"

    def test_entry_point_loads_to_clamav_source_class(self) -> None:
        from importlib.metadata import entry_points

        eps = {ep.name: ep for ep in entry_points(group="firewatch.sources")}
        cls = eps["clamav"].load()
        plugin = cls()
        assert isinstance(plugin, SourcePlugin)

    def test_zero_core_edits_via_loader(self) -> None:
        """The core loader discovers clamav without any patch — the real test of
        modularity (PLUGIN_CONTRACT.md)."""
        from firewatch_core.loader import load_source_plugins

        registry = load_source_plugins()
        assert "clamav" in registry, f"Loader did not find 'clamav'. Registry: {set(registry)}"


class TestMetadata:
    def setup_method(self) -> None:
        self.plugin = ClamAVSource()
        self.meta = self.plugin.metadata()

    def test_type_key_is_clamav(self) -> None:
        assert self.meta.type_key == "clamav"

    def test_flavor_is_pull(self) -> None:
        assert self.meta.flavor == "pull"

    def test_display_name_is_set(self) -> None:
        assert self.meta.display_name

    def test_enforcement_default_is_detect_only(self) -> None:
        """ADR-0067 D6 (issue #75): ClamAV detects malware but takes no removal
        action — the declared enforcement default is 'detect_only'."""
        assert self.meta.enforcement == "detect_only"

    def test_produces_excludes_source_ip(self) -> None:
        """ClamAV never populates a real source_ip (host-based, always "") — the
        column-hiding declaration must not claim it can (ADR-0060)."""
        assert "source_ip" not in self.meta.produces

    def test_produces_excludes_network_fields(self) -> None:
        assert "destination_ip" not in self.meta.produces
        assert "protocol" not in self.meta.produces

    def test_produces_includes_core_malware_fields(self) -> None:
        for field in ("action", "category", "severity", "rule_name", "payload_snippet"):
            assert field in self.meta.produces


class TestConfigSchema:
    def setup_method(self) -> None:
        self.plugin = ClamAVSource()

    def test_config_schema_returns_clamav_config(self) -> None:
        assert self.plugin.config_schema() is ClamAVConfig

    def test_validate_config_accepts_minimal(self) -> None:
        self.plugin.validate_config({})

    def test_validate_config_raises_on_invalid_mode(self) -> None:
        with pytest.raises(Exception):
            self.plugin.validate_config({"mode": "not-a-real-mode"})


class TestNormalizeDelegation:
    def test_normalize_delegates_to_normalize_module(self) -> None:
        plugin = ClamAVSource()
        raw = RawEvent(
            source_type="clamav",
            received_at=datetime(2026, 7, 15, tzinfo=timezone.utc),
            data={"path": "/a/eicar.com", "signature": "Win.Test.EICAR_HDB-1", "outcome": None},
        )
        event = plugin.normalize(raw, "laptop")
        assert event.source_type == "clamav"
        assert event.action == "ALERT"
        assert event.category == "malware"


class TestHealthCheckFileMode:
    async def test_returns_true_for_existing_readable_file(self, tmp_path: Path) -> None:
        log_path = tmp_path / "clamav.log"
        log_path.write_text("")
        plugin = ClamAVSource()
        cfg = ClamAVConfig(mode="file", log_path=str(log_path))
        assert await plugin.health_check(cfg) is True

    async def test_returns_false_for_missing_file(self) -> None:
        plugin = ClamAVSource()
        cfg = ClamAVConfig(mode="file", log_path="/does/not/exist.log")
        assert await plugin.health_check(cfg) is False

    async def test_accepts_plain_basemodel_not_just_clamavconfig(self, tmp_path: Path) -> None:
        """health_check must coerce a generic BaseModel the same way collect()/normalize()
        callers might pass one (defensive against a caller not using the exact class)."""
        log_file = tmp_path / "clamav.log"
        log_file.write_text("")
        resolved_path = str(log_file)

        class _Cfg(BaseModel):
            mode: str = "file"
            log_path: str = resolved_path
            identifiers: list[str] = ["clamd"]
            follow_symlinks: bool = False

        plugin = ClamAVSource()
        assert await plugin.health_check(_Cfg()) is True


class TestHealthCheckJournaldMode:
    async def test_returns_false_when_journalctl_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import firewatch_sdk.localhost.journald as journald_module

        async def _raise_not_found(*argv: str, stdout: int, stderr: int):
            raise FileNotFoundError("journalctl not found")

        monkeypatch.setattr(journald_module, "_create_subprocess_exec", _raise_not_found)
        plugin = ClamAVSource()
        cfg = ClamAVConfig(mode="journald")
        assert await plugin.health_check(cfg) is False

    async def test_returns_true_when_journal_probe_succeeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import firewatch_sdk.localhost.journald as journald_module

        from _clamav_journalctl_fakes import FakeProcess, make_sequenced_spawn

        discovery = FakeProcess(stdout_lines=[b"-- cursor: c0\n"])
        monkeypatch.setattr(
            journald_module, "_create_subprocess_exec", make_sequenced_spawn([discovery])
        )
        plugin = ClamAVSource()
        cfg = ClamAVConfig(mode="journald")
        assert await plugin.health_check(cfg) is True

    async def test_invalid_config_returns_false_not_raise(self) -> None:
        plugin = ClamAVSource()

        class _BadCfg(BaseModel):
            mode: str = "not-a-mode"

        assert await plugin.health_check(_BadCfg()) is False


class TestCollectDelegation:
    async def test_collect_delegates_to_collector_module(self, tmp_path: Path) -> None:
        log_path = tmp_path / "clamav.log"
        log_path.write_text("")
        plugin = ClamAVSource()
        cfg = ClamAVConfig(mode="file", log_path=str(log_path))
        ctx = make_ctx()

        assert [e async for e in plugin.collect(cfg, None, ctx)] == []

        with log_path.open("a") as f:
            f.write("/a/eicar.com: Win.Test.EICAR_HDB-1 FOUND\n")

        events = [e async for e in plugin.collect(cfg, None, ctx)]
        assert len(events) == 1
        assert events[0].data["signature"] == "Win.Test.EICAR_HDB-1"

    async def test_collect_accepts_plain_basemodel(self, tmp_path: Path) -> None:
        log_file = tmp_path / "clamav.log"
        log_file.write_text("")
        resolved_path = str(log_file)

        class _Cfg(BaseModel):
            mode: str = "file"
            log_path: str = resolved_path
            identifiers: list[str] = ["clamd"]
            follow_symlinks: bool = False

        plugin = ClamAVSource()
        ctx = make_ctx()
        events = [e async for e in plugin.collect(_Cfg(), None, ctx)]
        assert events == []
