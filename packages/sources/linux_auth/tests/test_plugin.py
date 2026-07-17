"""Tests for firewatch_linux_auth.plugin — EARS criteria mapped 1:1 (issue #3).

EARS-1  Entry-point registration and zero-core-edit discovery.
EARS-2  config_schema: fields, resolution.
EARS-3  health_check across mode=auto|journald|file.
EARS-4  normalize() delegates to firewatch_linux_auth.normalize (covered in
        test_normalize.py; this file only checks delegation + source_id passthrough).
EARS-6  No forbidden imports (no firewatch_core, no legacy).
"""
from __future__ import annotations

import ast
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import BaseModel

from firewatch_sdk import PluginContext, RawEvent, SourcePlugin
from firewatch_sdk.testing import InMemoryScopedKV

from firewatch_linux_auth.config import LinuxAuthConfig
from firewatch_linux_auth.plugin import LinuxAuthSource


def _ctx(source_id: str = "test-instance") -> PluginContext:
    return PluginContext(kv=InMemoryScopedKV(), source_id=source_id)


# ---------------------------------------------------------------------------
# EARS-1: Entry-point discovery (modularity proof)
# ---------------------------------------------------------------------------


class TestEntryPointDiscovery:
    def test_entry_point_is_registered(self) -> None:
        from importlib.metadata import entry_points

        eps = entry_points(group="firewatch.sources")
        names = {ep.name for ep in eps}
        assert "linux_auth" in names, (
            f"'linux_auth' not found in firewatch.sources entry points. Found: {names}"
        )

    def test_entry_point_loads_to_linux_auth_source_class(self) -> None:
        from importlib.metadata import entry_points

        eps = {ep.name: ep for ep in entry_points(group="firewatch.sources")}
        cls = eps["linux_auth"].load()
        plugin = cls()
        assert isinstance(plugin, SourcePlugin)

    def test_metadata_type_key_and_flavor(self) -> None:
        plugin = LinuxAuthSource()
        assert plugin.metadata().type_key == "linux_auth"
        assert plugin.metadata().flavor == "pull"

    def test_metadata_enforcement_default_is_observe(self) -> None:
        """ADR-0067 D6 (issue #75): journald/auth.log is a passive telemetry read."""
        plugin = LinuxAuthSource()
        assert plugin.metadata().enforcement == "observe"

    def test_zero_core_edits_via_loader(self) -> None:
        """The core loader discovers linux_auth without any patch — modularity proof."""
        from firewatch_core.loader import load_source_plugins

        registry = load_source_plugins()
        assert "linux_auth" in registry, (
            f"Loader did not find 'linux_auth'. Registry: {set(registry)}"
        )


# ---------------------------------------------------------------------------
# EARS-2: config_schema
# ---------------------------------------------------------------------------


class TestConfigSchema:
    def setup_method(self) -> None:
        self.plugin = LinuxAuthSource()
        self.schema_cls = self.plugin.config_schema()

    def test_returns_pydantic_model_class(self) -> None:
        assert issubclass(self.schema_cls, BaseModel)

    def test_has_expected_fields(self) -> None:
        fields = self.schema_cls.model_fields
        assert "mode" in fields
        assert "auth_log_path" in fields
        assert "journalctl_bin" in fields

    def test_validate_config_accepts_valid_dict(self) -> None:
        self.plugin.validate_config({"mode": "file", "auth_log_path": "/var/log/auth.log"})

    def test_validate_config_rejects_invalid_mode(self) -> None:
        with pytest.raises(Exception):
            self.plugin.validate_config({"mode": "not-a-real-mode"})


# ---------------------------------------------------------------------------
# EARS-3: health_check
# ---------------------------------------------------------------------------


class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_journald_mode_true_when_binary_on_path(self) -> None:
        plugin = LinuxAuthSource()
        cfg = LinuxAuthConfig(mode="journald", journalctl_bin="sh")  # "sh" always on PATH
        assert await plugin.health_check(cfg) is True

    @pytest.mark.asyncio
    async def test_journald_mode_false_when_binary_missing(self) -> None:
        plugin = LinuxAuthSource()
        cfg = LinuxAuthConfig(mode="journald", journalctl_bin="definitely-not-a-real-binary-xyz")
        assert await plugin.health_check(cfg) is False

    @pytest.mark.asyncio
    async def test_file_mode_true_when_path_readable(self, tmp_path) -> None:
        plugin = LinuxAuthSource()
        auth_log = tmp_path / "auth.log"
        auth_log.write_text("some log content\n")
        cfg = LinuxAuthConfig(mode="file", auth_log_path=str(auth_log))
        assert await plugin.health_check(cfg) is True

    @pytest.mark.asyncio
    async def test_file_mode_false_when_path_missing(self, tmp_path) -> None:
        plugin = LinuxAuthSource()
        cfg = LinuxAuthConfig(mode="file", auth_log_path=str(tmp_path / "nope.log"))
        assert await plugin.health_check(cfg) is False

    @pytest.mark.asyncio
    async def test_auto_mode_true_if_either_check_passes(self, tmp_path) -> None:
        plugin = LinuxAuthSource()
        cfg = LinuxAuthConfig(
            mode="auto",
            journalctl_bin="definitely-not-a-real-binary-xyz",
            auth_log_path=str(tmp_path / "nope.log"),
        )
        assert await plugin.health_check(cfg) is False

        auth_log = tmp_path / "auth.log"
        auth_log.write_text("content\n")
        cfg2 = LinuxAuthConfig(
            mode="auto",
            journalctl_bin="definitely-not-a-real-binary-xyz",
            auth_log_path=str(auth_log),
        )
        assert await plugin.health_check(cfg2) is True

    @pytest.mark.asyncio
    async def test_health_check_never_raises_on_bad_cfg(self) -> None:
        plugin = LinuxAuthSource()

        class _NotAConfig(BaseModel):
            # A value LinuxAuthConfig's `mode` Literal rejects — model_dump()
            # succeeds (a bare BaseModel), but re-validating it as
            # LinuxAuthConfig raises, which health_check must swallow.
            mode: str = "definitely-not-a-valid-mode"

        assert await plugin.health_check(_NotAConfig()) is False


# ---------------------------------------------------------------------------
# EARS-4: normalize() delegation
# ---------------------------------------------------------------------------


class TestNormalizeDelegation:
    def test_source_id_passed_through_unbranched(self) -> None:
        plugin = LinuxAuthSource()
        raw = RawEvent(
            source_type="linux_auth",
            received_at=datetime(2026, 6, 15, 8, 0, 0, tzinfo=timezone.utc),
            data={"message": "Accepted password for alice from 203.0.113.10 port 1 ssh2"},
        )
        event = plugin.normalize(raw, "my-custom-instance-name")
        assert event.source_id == "my-custom-instance-name"
        assert event.source_type == "linux_auth"


# ---------------------------------------------------------------------------
# EARS-4 (collect): PullSource delegation to collector.collect
# ---------------------------------------------------------------------------


class TestCollectDelegation:
    @pytest.mark.asyncio
    async def test_collect_yields_raw_events_from_file(self, tmp_path) -> None:
        """First cycle establishes the tail pivot (pre-existing content is NOT
        replayed — ADR-0065 "tail-from-now" bootstrap semantics); content
        appended after that pivot is picked up on the next cycle."""
        auth_log = tmp_path / "auth.log"
        auth_log.write_text("pre-existing line, before first collect()\n")
        cfg = LinuxAuthConfig(mode="file", auth_log_path=str(auth_log))
        plugin = LinuxAuthSource()
        ctx = _ctx()

        first_cycle = [raw async for raw in plugin.collect(cfg, None, ctx)]
        assert first_cycle == []

        with auth_log.open("a") as fh:
            fh.write("Failed password for admin from 203.0.113.5 port 1 ssh2\n")

        second_cycle = [raw async for raw in plugin.collect(cfg, None, ctx)]
        assert len(second_cycle) == 1
        assert "Failed password" in second_cycle[0].data["message"]


# ---------------------------------------------------------------------------
# EARS-6: no forbidden imports
# ---------------------------------------------------------------------------


class TestNoForbiddenImports:
    """Static check: no module under firewatch_linux_auth imports firewatch_core
    or legacy (PLUGIN_CONTRACT.md hard rule)."""

    def test_no_firewatch_core_or_legacy_imports(self) -> None:
        pkg_dir = Path(__file__).parent.parent / "src" / "firewatch_linux_auth"
        offenders: list[str] = []
        for py_file in pkg_dir.rglob("*.py"):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    if name == "firewatch_core" or name.startswith("firewatch_core."):
                        offenders.append(f"{py_file}: {name}")
                    if name == "legacy" or name.startswith("legacy."):
                        offenders.append(f"{py_file}: {name}")
        assert offenders == [], f"Forbidden imports found: {offenders}"
