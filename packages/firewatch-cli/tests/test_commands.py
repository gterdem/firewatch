"""Tests for firewatch CLI runtime subcommands — EARS criteria mapped 1:1.

Tests are written FIRST per the testing-conventions skill.

EARS criterion → test(s) mapping
─────────────────────────────────
EARS-1  Event-driven: When `firewatch run` starts, it shall load plugins via
        entry points, start the supervisor, and serve the API on a loopback bind.
        test_run_loads_plugins_starts_supervisor_serves_api
        test_run_binds_loopback_only

EARS-2  Event-driven: When `firewatch sync --once` runs, it shall execute a
        single pull cycle for each configured pull instance and exit with a
        status code reflecting success/failure.
        test_sync_once_runs_pull_cycle_per_instance
        test_sync_once_exits_zero_on_success
        test_sync_once_exits_nonzero_on_failure
        test_sync_once_skips_push_instances
        test_sync_once_mints_ctx_per_instance

EARS-3  Event-driven: When SIGTERM/SIGINT is received, the process shall shut
        down within the bounded grace period — stop listeners, cancel pull tasks,
        flush — and exit cleanly.
        test_sigterm_triggers_bounded_graceful_shutdown
        test_sigint_triggers_bounded_graceful_shutdown

EARS-4  Ubiquitous: The CLI shall configure sources only through the config
        service (MA.2); it shall not read hardcoded source paths.
        test_config_sourced_from_config_service_only
        test_no_hardcoded_source_paths_in_commands

All network binds use 127.0.0.1 (loopback) — never 0.0.0.0 (ADR-0026).
All IPs use RFC 5737 documentation ranges for any event data.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

from firewatch_sdk import (
    PluginContext,
    RawEvent,
    SecurityEvent,
    SourceMetadata,
)

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _FakeCfg(BaseModel):
    note: str = "fake"


class _FakeScopedKV:
    """Minimal ScopedKV test double (ADR-0027)."""

    async def put(self, namespace: str, key: str, value: str) -> None: ...

    async def get(self, namespace: str, key: str) -> str | None:
        return None

    async def get_all(self, namespace: str) -> dict[str, str]:
        return {}


def _make_ctx(source_id: str = "test-instance") -> PluginContext:
    return PluginContext(kv=_FakeScopedKV(), source_id=source_id)


class _FakePullPlugin:
    """A PullSource + SourcePlugin test double that records collect calls."""

    def __init__(self, type_key: str = "fake_pull") -> None:
        self._type_key = type_key
        self.collect_calls: list[tuple[BaseModel, str | None, PluginContext]] = []

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name=self._type_key,
            version="0.1.0",
            flavor="pull",
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakeCfg

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _FakeCfg.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        return SecurityEvent(
            source_type=raw.source_type,
            source_id=source_id,
            timestamp=raw.received_at,
            source_ip="203.0.113.1",
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True

    async def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]:
        self.collect_calls.append((cfg, since, ctx))
        # Empty iterator — no events needed for these wiring tests
        return
        yield  # type: ignore[misc]  # pragma: no cover


class _FakePushPlugin:
    """A PushSource + SourcePlugin test double (never pulled — skipped by sync)."""

    def __init__(self, type_key: str = "fake_push") -> None:
        self._type_key = type_key
        self.start_calls: int = 0

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name=self._type_key,
            version="0.1.0",
            flavor="push",
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakeCfg

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _FakeCfg.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        return SecurityEvent(
            source_type=raw.source_type,
            source_id=source_id,
            timestamp=raw.received_at,
            source_ip="203.0.113.1",
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True

    async def start(
        self,
        cfg: BaseModel,
        emit: Callable[[list[RawEvent]], Awaitable[None]],
        ctx: PluginContext,
    ) -> None:
        self.start_calls += 1

    async def stop(self) -> None: ...


class _FakeStore:
    """Minimal in-memory EventStore test double."""

    def __init__(self) -> None:
        self.watermarks: dict[tuple[str, str], str] = {}
        self._kv: dict[tuple[str, str, str], str] = {}

    async def init(self) -> None: ...

    async def close(self) -> None: ...

    async def save_many(self, events: list[SecurityEvent]) -> int:
        return len(events)

    async def get_by_ip(self, ip: str) -> list[SecurityEvent]:
        return []

    async def get_by_ip_raw(self, ip: str) -> list[dict[str, Any]]:
        return []

    async def get_recent(self, limit: int) -> list[dict[str, Any]]:
        return []

    async def get_paginated(
        self, limit: int, filters: Any | None = None
    ) -> dict[str, Any]:
        return {"logs": [], "next_cursor": None, "has_more": False, "total_matching": 0}

    async def get_all_ips(self) -> list[str]:
        return []

    async def get_ip_summary(self) -> list[dict[str, Any]]:
        return []

    async def get_categories(self) -> list[dict[str, Any]]:
        return []

    async def get_timeline(
        self, start: str | None, end: str | None
    ) -> list[dict[str, Any]]:
        return []

    async def get_stats(self) -> dict[str, Any]:
        return {}

    async def get_analytics_geo(self) -> list[dict[str, Any]]:
        return []

    async def get_analytics_summary(self) -> dict[str, Any]:
        return {}

    async def get_categories_timeline(
        self, start: str | None, end: str | None
    ) -> list[dict[str, Any]]:
        return []

    async def get_ips_without_geo(self) -> list[str]:
        return []

    async def upsert_ip_geo(self, geo_data: list[dict[str, Any]]) -> None: ...

    async def get_watermark(self, source_type: str, source_id: str) -> str | None:
        return self.watermarks.get((source_type, source_id))

    async def set_watermark(
        self, ts: str, source_type: str, source_id: str
    ) -> None:
        self.watermarks[(source_type, source_id)] = ts

    async def upsert_rule_descriptions(self, descs: dict[str, str]) -> None: ...

    async def get_rule_descriptions(self) -> dict[str, str]:
        return {}

    async def source_kv_put(
        self, source_type: str, namespace: str, key: str, value: str
    ) -> None:
        self._kv[(source_type, namespace, key)] = value

    async def source_kv_get(
        self, source_type: str, namespace: str, key: str
    ) -> str | None:
        return self._kv.get((source_type, namespace, key))

    async def source_kv_get_all(
        self, source_type: str, namespace: str
    ) -> dict[str, str]:
        return {
            k: v
            for (st, ns, k), v in self._kv.items()
            if st == source_type and ns == namespace
        }

    async def clear(self) -> None:
        self._kv.clear()

    async def delete_older_than(self, days: int) -> int:
        return 0


# ---------------------------------------------------------------------------
# Helper: write a minimal config JSON with instance declarations
# ---------------------------------------------------------------------------


def _write_config(
    config_file: Path,
    instances: list[dict[str, Any]],
) -> None:
    """Write a firewatch_config.json with the given ``_instances`` list."""
    config_file.write_text(
        json.dumps({"_instances": instances}, indent=2),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# EARS-4 (Ubiquitous): config sourced from config service only
# ---------------------------------------------------------------------------


class TestConfigSourcedFromConfigServiceOnly:
    """EARS-4: sources configured via MA.2 config service; no hardcoded paths."""

    def test_load_instances_reads_from_config_file(self, tmp_path: Path) -> None:
        """InstanceConfig is loaded from the config JSON, not hardcoded."""
        config_file = tmp_path / "firewatch_config.json"
        _write_config(config_file, [
            {"source_type": "fake_pull", "source_id": "inst-a", "flavor": "pull"},
        ])
        from firewatch_core.instance_loader import InstanceConfig, load_instances  # noqa: F401
        instances = load_instances(config_file)
        assert len(instances) == 1
        assert instances[0].source_type == "fake_pull"
        assert instances[0].source_id == "inst-a"

    def test_load_instances_returns_empty_when_no_config_file(
        self, tmp_path: Path
    ) -> None:
        """Missing config file → empty instance list (no crash)."""
        config_file = tmp_path / "firewatch_config.json"
        from firewatch_core.instance_loader import load_instances
        instances = load_instances(config_file)
        assert instances == []

    def test_load_instances_returns_empty_when_no_instances_key(
        self, tmp_path: Path
    ) -> None:
        """Config file without ``_instances`` key → empty list."""
        config_file = tmp_path / "firewatch_config.json"
        config_file.write_text(json.dumps({"_runtime": {}}), encoding="utf-8")
        from firewatch_core.instance_loader import load_instances
        instances = load_instances(config_file)
        assert instances == []

    def test_instance_config_required_fields(self) -> None:
        """InstanceConfig validates source_type and source_id are required."""
        from firewatch_core.instance_loader import InstanceConfig
        inst = InstanceConfig(
            source_type="suricata",
            source_id="pi-home",
            flavor="pull",
        )
        assert inst.source_type == "suricata"
        assert inst.source_id == "pi-home"
        assert inst.flavor == "pull"

    def test_instance_config_optional_extra_cfg(self) -> None:
        """InstanceConfig allows an optional extra_cfg dict for per-instance overrides."""
        from firewatch_core.instance_loader import InstanceConfig
        inst = InstanceConfig(
            source_type="suricata",
            source_id="pi-home",
            flavor="pull",
            extra_cfg={"mode": "ids"},
        )
        assert inst.extra_cfg == {"mode": "ids"}

    def test_no_hardcoded_source_paths_in_commands(self) -> None:
        """The run / sync_once / serve command modules contain no hardcoded paths.

        Verifies by importing the modules and checking they do not have
        path-like string literals (e.g. /var/log/..., /etc/...) hardcoded.
        """
        import importlib
        for mod_name in (
            "firewatch_cli.commands.run",
            "firewatch_cli.commands.sync_once",
            "firewatch_cli.commands.serve",
        ):
            mod = importlib.import_module(mod_name)
            source_lines = open(mod.__file__).read()  # type: ignore[arg-type]
            # These patterns would be hardcoded source paths
            bad_patterns = ["/var/log/suricata", "/etc/firewatch", "/tmp/suricata"]
            for bad in bad_patterns:
                assert bad not in source_lines, (
                    f"Hardcoded source path {bad!r} found in {mod_name}; "
                    "sources must be configured only through the config service."
                )


# ---------------------------------------------------------------------------
# instance_loader secret redaction (Fix 1 security review)
# ---------------------------------------------------------------------------


class TestInstanceLoaderSecretRedaction:
    """Validation-failure warning must not leak secret-ish values in log output."""

    def test_redact_entry_masks_secret_keys(self) -> None:
        """_redact_entry masks keys matching the known secret patterns."""
        from firewatch_core.instance_loader import _redact_entry

        entry = {
            "source_type": "suricata",
            "source_id": "pi-home",
            "api_key": "supersecret",
            "auth_token": "tok_abc",
            "password": "hunter2",
            "passwd": "hunter2",
            "secret": "very-secret",
            "credential": "cred-xyz",
            "api_secret_key": "nested-secret",
        }
        result = _redact_entry(entry)
        # Non-secret keys are preserved
        assert result["source_type"] == "suricata"
        assert result["source_id"] == "pi-home"
        # Secret-ish keys are masked
        assert result["api_key"] == "***"
        assert result["auth_token"] == "***"
        assert result["password"] == "***"
        assert result["passwd"] == "***"
        assert result["secret"] == "***"
        assert result["credential"] == "***"
        assert result["api_secret_key"] == "***"

    def test_redact_entry_preserves_non_secret_keys(self) -> None:
        """_redact_entry preserves non-secret keys unchanged."""
        from firewatch_core.instance_loader import _redact_entry

        entry = {"source_type": "suricata", "source_id": "pi-home",
                 "flavor": "pull", "interval": 30.0}
        result = _redact_entry(entry)
        assert result == entry

    def test_warning_log_does_not_contain_secret_value(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """load_instances warning on validation failure must NOT log the raw secret value.

        An entry that fails Pydantic validation (missing required fields) can
        still carry plaintext secrets in extra_cfg before validation runs.
        The warning log must emit the redacted form, not the raw dict.
        """
        import logging
        from firewatch_core.instance_loader import load_instances

        secret_value = "my-super-secret-api-key-12345"
        config_file = tmp_path / "firewatch_config.json"
        # An entry missing the required 'flavor' field so validation fails,
        # but carries a plaintext secret in extra_cfg / a top-level key.
        config_file.write_text(
            __import__('json').dumps({"_instances": [
                {
                    "source_type": "suricata",
                    # missing source_id and flavor — will fail validation
                    "api_key": secret_value,
                }
            ]}),
            encoding="utf-8",
        )

        with caplog.at_level(logging.WARNING, logger="firewatch.instance_loader"):
            result = load_instances(config_file)

        assert result == [], "broken entry should be skipped"
        # The secret must NOT appear anywhere in the captured log output.
        assert secret_value not in caplog.text, (
            f"Secret value {secret_value!r} leaked into warning log; "
            "_redact_entry must mask keys matching secret patterns."
        )
        # The warning itself must still be present (so we know it fired).
        assert "failed validation" in caplog.text


# ---------------------------------------------------------------------------
# EARS-2 (Event-driven): sync --once runs one pull cycle per instance
# ---------------------------------------------------------------------------


class TestSyncOncePullCycle:
    """EARS-2: sync --once executes one pull cycle per configured pull instance."""

    @pytest.mark.asyncio
    async def test_sync_once_runs_pull_cycle_per_pull_instance(
        self, tmp_path: Path
    ) -> None:
        """Each configured pull instance gets exactly one run_pull_cycle call."""
        from firewatch_cli.commands.sync_once import cmd_sync_once

        config_file = tmp_path / "firewatch_config.json"
        _write_config(config_file, [
            {"source_type": "fake_pull", "source_id": "inst-a", "flavor": "pull"},
            {"source_type": "fake_pull2", "source_id": "inst-b", "flavor": "pull"},
        ])

        plugin_a = _FakePullPlugin(type_key="fake_pull")
        plugin_b = _FakePullPlugin(type_key="fake_pull2")
        registry: dict[str, Any] = {"fake_pull": plugin_a, "fake_pull2": plugin_b}

        cycle_calls: list[tuple[str, str]] = []

        async def fake_run_pull_cycle(
            plugin: Any, cfg: BaseModel, source_id: str, ctx: PluginContext
        ) -> int:
            cycle_calls.append((plugin.metadata().type_key, source_id))
            return 0

        with patch(
            "firewatch_cli.commands.sync_once.load_instances",
            return_value=[
                MagicMock(source_type="fake_pull", source_id="inst-a",
                          flavor="pull", extra_cfg={}),
                MagicMock(source_type="fake_pull2", source_id="inst-b",
                          flavor="pull", extra_cfg={}),
            ],
        ), patch(
            "firewatch_cli.commands.sync_once._build_pipeline",
        ) as mock_build:
            pipeline = MagicMock()
            pipeline.run_pull_cycle = fake_run_pull_cycle
            pipeline.store = _FakeStore()
            mock_build.return_value = pipeline

            exit_code = await cmd_sync_once(
                registry=registry,
                config_file=config_file,
            )

        assert exit_code == 0
        assert ("fake_pull", "inst-a") in cycle_calls
        assert ("fake_pull2", "inst-b") in cycle_calls
        assert len(cycle_calls) == 2

    @pytest.mark.asyncio
    async def test_sync_once_skips_push_instances(self, tmp_path: Path) -> None:
        """sync --once does not attempt to run push-flavor instances."""
        from firewatch_cli.commands.sync_once import cmd_sync_once

        config_file = tmp_path / "firewatch_config.json"
        push_plugin = _FakePushPlugin(type_key="fake_push")
        pull_plugin = _FakePullPlugin(type_key="fake_pull")
        registry: dict[str, Any] = {"fake_push": push_plugin, "fake_pull": pull_plugin}

        cycle_calls: list[str] = []

        async def fake_run_pull_cycle(
            plugin: Any, cfg: BaseModel, source_id: str, ctx: PluginContext
        ) -> int:
            cycle_calls.append(plugin.metadata().type_key)
            return 0

        with patch(
            "firewatch_cli.commands.sync_once.load_instances",
            return_value=[
                MagicMock(source_type="fake_push", source_id="push-1",
                          flavor="push", extra_cfg={}),
                MagicMock(source_type="fake_pull", source_id="pull-1",
                          flavor="pull", extra_cfg={}),
            ],
        ), patch(
            "firewatch_cli.commands.sync_once._build_pipeline",
        ) as mock_build:
            pipeline = MagicMock()
            pipeline.run_pull_cycle = fake_run_pull_cycle
            pipeline.store = _FakeStore()
            mock_build.return_value = pipeline

            exit_code = await cmd_sync_once(
                registry=registry,
                config_file=config_file,
            )

        assert exit_code == 0
        assert "fake_push" not in cycle_calls
        assert "fake_pull" in cycle_calls

    @pytest.mark.asyncio
    async def test_sync_once_exits_zero_on_success(self, tmp_path: Path) -> None:
        """sync --once exits with code 0 when all cycles succeed."""
        from firewatch_cli.commands.sync_once import cmd_sync_once

        config_file = tmp_path / "firewatch_config.json"

        async def fake_run_pull_cycle(
            plugin: Any, cfg: BaseModel, source_id: str, ctx: PluginContext
        ) -> int:
            return 5  # 5 events ingested

        with patch(
            "firewatch_cli.commands.sync_once.load_instances",
            return_value=[
                MagicMock(source_type="fake_pull", source_id="inst-a",
                          flavor="pull", extra_cfg={}),
            ],
        ), patch(
            "firewatch_cli.commands.sync_once._build_pipeline",
        ) as mock_build:
            pipeline = MagicMock()
            pipeline.run_pull_cycle = fake_run_pull_cycle
            pipeline.store = _FakeStore()
            mock_build.return_value = pipeline

            exit_code = await cmd_sync_once(
                registry={"fake_pull": _FakePullPlugin()},  # type: ignore[dict-item]
                config_file=config_file,
            )

        assert exit_code == 0

    @pytest.mark.asyncio
    async def test_sync_once_exits_nonzero_on_failure(self, tmp_path: Path) -> None:
        """sync --once exits with code 1 when any pull cycle raises."""
        from firewatch_cli.commands.sync_once import cmd_sync_once

        config_file = tmp_path / "firewatch_config.json"

        async def failing_pull_cycle(
            plugin: Any, cfg: BaseModel, source_id: str, ctx: PluginContext
        ) -> int:
            raise RuntimeError("simulated collect failure")

        with patch(
            "firewatch_cli.commands.sync_once.load_instances",
            return_value=[
                MagicMock(source_type="fake_pull", source_id="inst-a",
                          flavor="pull", extra_cfg={}),
            ],
        ), patch(
            "firewatch_cli.commands.sync_once._build_pipeline",
        ) as mock_build:
            pipeline = MagicMock()
            pipeline.run_pull_cycle = failing_pull_cycle
            pipeline.store = _FakeStore()
            mock_build.return_value = pipeline

            exit_code = await cmd_sync_once(
                registry={"fake_pull": _FakePullPlugin()},  # type: ignore[dict-item]
                config_file=config_file,
            )

        assert exit_code == 1

    @pytest.mark.asyncio
    async def test_sync_once_mints_ctx_per_instance(self, tmp_path: Path) -> None:
        """sync --once mints a PluginContext per instance (ADR-0027 one-minter pattern)."""
        from firewatch_cli.commands.sync_once import cmd_sync_once

        config_file = tmp_path / "firewatch_config.json"
        received_ctxs: list[PluginContext] = []

        async def capture_ctx(
            plugin: Any, cfg: BaseModel, source_id: str, ctx: PluginContext
        ) -> int:
            received_ctxs.append(ctx)
            return 0

        with patch(
            "firewatch_cli.commands.sync_once.load_instances",
            return_value=[
                MagicMock(source_type="fake_pull", source_id="inst-a",
                          flavor="pull", extra_cfg={}),
                MagicMock(source_type="fake_pull", source_id="inst-b",
                          flavor="pull", extra_cfg={}),
            ],
        ), patch(
            "firewatch_cli.commands.sync_once._build_pipeline",
        ) as mock_build:
            pipeline = MagicMock()
            pipeline.run_pull_cycle = capture_ctx
            pipeline.store = _FakeStore()
            mock_build.return_value = pipeline

            await cmd_sync_once(
                registry={"fake_pull": _FakePullPlugin()},  # type: ignore[dict-item]
                config_file=config_file,
            )

        # Two instances → two distinct PluginContext objects
        assert len(received_ctxs) == 2
        # Each ctx carries the correct source_id
        assert received_ctxs[0].source_id == "inst-a"
        assert received_ctxs[1].source_id == "inst-b"
        # They are distinct objects (minted separately per ADR-0027)
        assert received_ctxs[0] is not received_ctxs[1]

    @pytest.mark.asyncio
    async def test_sync_once_skips_unknown_source_type(self, tmp_path: Path) -> None:
        """Configured instance whose type_key is not in registry is skipped gracefully."""
        from firewatch_cli.commands.sync_once import cmd_sync_once

        config_file = tmp_path / "firewatch_config.json"
        cycle_calls: list[str] = []

        async def fake_run_pull_cycle(
            plugin: Any, cfg: BaseModel, source_id: str, ctx: PluginContext
        ) -> int:
            cycle_calls.append(source_id)
            return 0

        with patch(
            "firewatch_cli.commands.sync_once.load_instances",
            return_value=[
                # This type is NOT in the registry
                MagicMock(source_type="not_installed", source_id="ghost",
                          flavor="pull", extra_cfg={}),
                MagicMock(source_type="fake_pull", source_id="inst-a",
                          flavor="pull", extra_cfg={}),
            ],
        ), patch(
            "firewatch_cli.commands.sync_once._build_pipeline",
        ) as mock_build:
            pipeline = MagicMock()
            pipeline.run_pull_cycle = fake_run_pull_cycle
            pipeline.store = _FakeStore()
            mock_build.return_value = pipeline

            exit_code = await cmd_sync_once(
                registry={"fake_pull": _FakePullPlugin()},  # type: ignore[dict-item]
                config_file=config_file,
            )

        # one success, one skip — overall success
        assert exit_code == 0
        assert "inst-a" in cycle_calls
        assert "ghost" not in cycle_calls


# ---------------------------------------------------------------------------
# EARS-1 (Event-driven): `run` loads plugins, starts supervisor, serves API
# ---------------------------------------------------------------------------


class TestRunCommand:
    """EARS-1: run loads plugins, starts supervisor, serves API on loopback."""

    @pytest.mark.asyncio
    async def test_run_registers_instances_with_supervisor(
        self, tmp_path: Path
    ) -> None:
        """cmd_run registers configured instances with the supervisor."""
        from firewatch_cli.commands.run import cmd_run

        config_file = tmp_path / "firewatch_config.json"
        _write_config(config_file, [
            {"source_type": "fake_pull", "source_id": "inst-a", "flavor": "pull"},
        ])

        pull_plugin = _FakePullPlugin(type_key="fake_pull")
        registry: dict[str, Any] = {"fake_pull": pull_plugin}

        added_instances: list[tuple[str, str]] = []

        class FakeSupervisor:
            def add_pull(
                self, plugin: Any, cfg: BaseModel, *, source_id: str,
                interval: float = 60.0
            ) -> Any:
                added_instances.append((plugin.metadata().type_key, source_id))
                return MagicMock()

            def add_push(
                self, plugin: Any, cfg: BaseModel, *, source_id: str,
                transport: str = "tcp"
            ) -> Any:
                added_instances.append((plugin.metadata().type_key, source_id))
                return MagicMock()

            async def run(self) -> None:
                pass

            async def startup(self) -> None:
                pass

            async def shutdown(self) -> None:
                pass

            async def wait_until_stopped(self) -> None:
                # Resolve immediately — either server_task or this wins the
                # FIRST_COMPLETED race; both paths call _graceful_shutdown.
                pass

        async def _noop_serve(sockets: Any = None) -> None:
            pass

        with patch(
            "firewatch_cli.commands.run.load_instances",
            return_value=[
                MagicMock(source_type="fake_pull", source_id="inst-a",
                          flavor="pull", extra_cfg={}),
            ],
        ), patch(
            "firewatch_cli.commands.run.Supervisor",
            return_value=FakeSupervisor(),
        ), patch(
            "firewatch_cli.commands.run._build_pipeline",
        ) as mock_build, patch(
            "uvicorn.Server.serve", side_effect=_noop_serve,
        ):
            mock_build.return_value = MagicMock(store=_FakeStore(), ledger=None)

            await cmd_run(
                registry=registry,
                config_file=config_file,
                host="127.0.0.1",
                port=8000,
            )

        assert ("fake_pull", "inst-a") in added_instances

    @pytest.mark.asyncio
    async def test_run_starts_api_server(self, tmp_path: Path) -> None:
        """cmd_run starts a uvicorn server as an asyncio task on the supervisor loop.

        In the single-loop design (fix #75), cmd_run calls supervisor.startup()
        then asyncio.create_task(server.serve()) — there is no _start_api_server
        daemon thread.  We verify the server.serve coroutine is awaited.
        """
        from firewatch_cli.commands.run import cmd_run

        config_file = tmp_path / "firewatch_config.json"
        _write_config(config_file, [])

        class FakeSupervisor:
            def add_pull(self, *a: Any, **kw: Any) -> Any: return MagicMock()
            def add_push(self, *a: Any, **kw: Any) -> Any: return MagicMock()
            async def run(self) -> None: pass
            async def startup(self) -> None: pass
            async def shutdown(self) -> None: pass
            async def wait_until_stopped(self) -> None: pass

        serve_called = False

        async def _recording_serve(sockets: Any = None) -> None:
            nonlocal serve_called
            serve_called = True

        with patch(
            "firewatch_cli.commands.run.load_instances",
            return_value=[],
        ), patch(
            "firewatch_cli.commands.run.Supervisor",
            return_value=FakeSupervisor(),
        ), patch(
            "firewatch_cli.commands.run._build_pipeline",
        ) as mock_build, patch(
            "uvicorn.Server.serve", side_effect=_recording_serve,
        ):
            mock_build.return_value = MagicMock(store=_FakeStore(), ledger=None)
            await cmd_run(
                registry={},
                config_file=config_file,
                host="127.0.0.1",
                port=8000,
            )

        assert serve_called, (
            "cmd_run did not start a uvicorn server — server.serve() was never awaited. "
            "The single-loop design requires asyncio.create_task(server.serve())."
        )

    def test_run_binds_loopback_only(self) -> None:
        """The DEFAULT_HOST exported by the run command is the loopback address."""
        from firewatch_cli.commands.run import DEFAULT_HOST
        assert DEFAULT_HOST == "127.0.0.1"


# ---------------------------------------------------------------------------
# EARS-1 (serve subcommand): API-only, no supervisor
# ---------------------------------------------------------------------------


class TestServeCommand:
    """EARS-1 serve path: API only, no supervisor loops, loopback bind."""

    def test_serve_command_exposes_default_loopback_host(self) -> None:
        """cmd_serve uses loopback defaults (ADR-0026 Decision 1)."""
        from firewatch_cli.commands.serve import DEFAULT_HOST, DEFAULT_PORT
        assert DEFAULT_HOST == "127.0.0.1"
        assert isinstance(DEFAULT_PORT, int)

    def test_serve_delegates_to_uvicorn(self) -> None:
        """cmd_serve starts a uvicorn server via _serve on an asyncio loop.

        In the single-loop design (fix #75), cmd_serve calls asyncio.run(_serve(...))
        which starts uvicorn.Server.serve (not uvicorn.run).  We verify the
        server is reached with the expected host by patching uvicorn.Server.serve.
        """
        from firewatch_cli.commands import serve as serve_mod

        serve_config_host: list[str] = []

        async def _recording_serve(sockets: Any = None) -> None:
            pass

        fake_pipeline = MagicMock()
        fake_pipeline.store = _FakeStore()
        fake_pipeline.ledger = None

        original_Config = __import__("uvicorn").Config

        def _capturing_Config(app: Any, host: str = "127.0.0.1", **kw: Any) -> Any:
            serve_config_host.append(host)
            return original_Config(app, host=host, **kw)

        with patch.object(serve_mod, "_build_pipeline", return_value=fake_pipeline), \
             patch("uvicorn.Config", side_effect=_capturing_Config), \
             patch("uvicorn.Server.serve", side_effect=_recording_serve):
            serve_mod.cmd_serve(host="127.0.0.1", port=8000, registry={})

        assert serve_config_host == ["127.0.0.1"], (
            f"cmd_serve did not pass host='127.0.0.1' to uvicorn, got: {serve_config_host}"
        )

    def test_serve_uses_loopback_host_by_default(self) -> None:
        """cmd_serve passes loopback host by default (no explicit host arg)."""
        from firewatch_cli.commands import serve as serve_mod
        from firewatch_cli.commands.serve import DEFAULT_HOST

        serve_config_host: list[str] = []

        async def _recording_serve(sockets: Any = None) -> None:
            pass

        fake_pipeline = MagicMock()
        fake_pipeline.store = _FakeStore()
        fake_pipeline.ledger = None

        original_Config = __import__("uvicorn").Config

        def _capturing_Config(app: Any, host: str = "127.0.0.1", **kw: Any) -> Any:
            serve_config_host.append(host)
            return original_Config(app, host=host, **kw)

        with patch.object(serve_mod, "_build_pipeline", return_value=fake_pipeline), \
             patch("uvicorn.Config", side_effect=_capturing_Config), \
             patch("uvicorn.Server.serve", side_effect=_recording_serve):
            serve_mod.cmd_serve(registry={})

        assert serve_config_host == [DEFAULT_HOST], (
            f"cmd_serve default host should be {DEFAULT_HOST!r}, got: {serve_config_host}"
        )
        assert DEFAULT_HOST == "127.0.0.1"


# ---------------------------------------------------------------------------
# EARS-3 (Event-driven): SIGTERM/SIGINT → bounded graceful shutdown
# ---------------------------------------------------------------------------


class TestGracefulShutdown:
    """EARS-3: SIGTERM/SIGINT triggers bounded graceful shutdown (ADR-0023 §E).

    The supervisor is the sole owner of the bounded graceful shutdown logic
    (ADR-0023 §E — tested end-to-end in test_supervisor.py EARS-7).

    In the single-loop design (fix #75, ADR-0023 §F):
    1. ``cmd_run`` calls ``supervisor.startup()`` (not run()) to start instances.
    2. Signal delivery is owned by uvicorn (capture_signals); cmd_run installs a
       no-op signal.signal guard (SIG_IGN) before creating the server task so
       uvicorn's exit-time raise_signal() lands on the no-op, not SIG_DFL.
    3. ``cmd_run`` always calls ``supervisor.shutdown()`` in its finally block.

    We test (1) and (3) here using a fake supervisor; the ADR-0023 §E grace-
    period deadline is tested in the supervisor's own test suite.
    """

    @pytest.mark.asyncio
    async def test_cmd_run_always_calls_shutdown_on_exit(
        self, tmp_path: Path
    ) -> None:
        """cmd_run calls supervisor.shutdown() in its finally block on normal exit."""
        from firewatch_cli.commands.run import cmd_run

        shutdown_called = False

        class FakeSupervisor:
            def add_pull(self, *a: Any, **kw: Any) -> Any: return MagicMock()
            def add_push(self, *a: Any, **kw: Any) -> Any: return MagicMock()
            async def startup(self) -> None: pass
            async def shutdown(self) -> None:
                nonlocal shutdown_called
                shutdown_called = True
            async def wait_until_stopped(self) -> None: pass

        config_file = tmp_path / "firewatch_config.json"
        _write_config(config_file, [])

        async def _noop_serve(sockets: Any = None) -> None:
            pass

        with patch(
            "firewatch_cli.commands.run.load_instances",
            return_value=[],
        ), patch(
            "firewatch_cli.commands.run.Supervisor",
            return_value=FakeSupervisor(),
        ), patch(
            "firewatch_cli.commands.run._build_pipeline",
        ) as mock_build, patch(
            "uvicorn.Server.serve", side_effect=_noop_serve,
        ):
            mock_build.return_value = MagicMock(store=_FakeStore(), ledger=None)
            await cmd_run(
                registry={},
                config_file=config_file,
                host="127.0.0.1",
                port=8000,
            )

        assert shutdown_called, (
            "supervisor.shutdown() was not called after run returned — "
            "the finally block in cmd_run is missing."
        )

    @pytest.mark.asyncio
    async def test_cmd_run_calls_shutdown_even_on_exception(
        self, tmp_path: Path
    ) -> None:
        """cmd_run calls supervisor.shutdown() even if the API server task raises.

        FIX #622: previously the run loop used asyncio.wait(FIRST_COMPLETED) which
        swallowed task exceptions (they lived in the task object, not propagated).
        With the new ``await server_task`` design, a crashing server propagates its
        exception out of cmd_run.  The finally block still runs, so shutdown() is
        still called — that invariant is unchanged.  The test is updated to expect
        the exception rather than asserting cmd_run returns cleanly.
        """
        from firewatch_cli.commands.run import cmd_run

        shutdown_called = False

        class FakeSupervisor:
            def add_pull(self, *a: Any, **kw: Any) -> Any: return MagicMock()
            def add_push(self, *a: Any, **kw: Any) -> Any: return MagicMock()
            async def startup(self) -> None: pass
            async def shutdown(self) -> None:
                nonlocal shutdown_called
                shutdown_called = True
            async def wait_until_stopped(self) -> None:
                # Never resolves on its own — server crash exits first.
                await asyncio.Event().wait()

        config_file = tmp_path / "firewatch_config.json"
        _write_config(config_file, [])

        async def _crashing_serve(sockets: Any = None) -> None:
            raise RuntimeError("simulated server crash")

        with patch(
            "firewatch_cli.commands.run.load_instances",
            return_value=[],
        ), patch(
            "firewatch_cli.commands.run.Supervisor",
            return_value=FakeSupervisor(),
        ), patch(
            "firewatch_cli.commands.run._build_pipeline",
        ) as mock_build, patch(
            "uvicorn.Server.serve", side_effect=_crashing_serve,
        ):
            mock_build.return_value = MagicMock(store=_FakeStore(), ledger=None)
            # With ``await server_task``, the server crash propagates as a normal
            # exception.  The finally block still runs — that is the invariant.
            with pytest.raises(RuntimeError, match="simulated server crash"):
                await cmd_run(
                    registry={},
                    config_file=config_file,
                    host="127.0.0.1",
                    port=8000,
                )

        assert shutdown_called, (
            "supervisor.shutdown() was not called even after the server task raised — "
            "the finally block in cmd_run must always call shutdown()."
        )

    def test_cmd_run_uses_noop_signal_guard_and_startup(self) -> None:
        """cmd_run uses signal.SIG_IGN guard (ADR-0023 §F) and supervisor.startup().

        ADR-0023 §F: uvicorn's capture_signals() owns SIGTERM/SIGINT delivery;
        cmd_run installs no-op signal.signal handlers (SIG_IGN) BEFORE the server
        task so uvicorn's exit-time raise_signal() lands on the no-op, not SIG_DFL.
        cmd_run does NOT use loop.add_signal_handler (clobbered by capture_signals).
        cmd_run calls supervisor.startup() (not run()) so no signal handlers are
        installed inside the supervisor itself.
        """
        import inspect

        from firewatch_cli.commands import run as run_mod

        source = inspect.getsource(run_mod.cmd_run)
        assert "supervisor.startup()" in source, (
            "cmd_run must call supervisor.startup() (not run()) in the single-loop design. "
            "supervisor.run() installs its own signal handlers which conflicts with §F."
        )
        assert "wait_until_stopped" in source, (
            "cmd_run must await supervisor.wait_until_stopped() (the public §D.1 seam). "
            "Using a private attribute (_shutdown_event) violates the contract."
        )
        assert "add_signal_handler" not in source, (
            "cmd_run must NOT use loop.add_signal_handler — uvicorn's capture_signals() "
            "clobbers it, making it dead code.  Use signal.signal (SIG_IGN guard) instead."
        )


# ---------------------------------------------------------------------------
# CLI entry-point wiring tests
# ---------------------------------------------------------------------------


class TestCliWiring:
    """The argparse wiring in main.py dispatches to the correct command functions."""

    def test_run_subcommand_is_registered(self) -> None:
        """'firewatch run' is a registered subcommand."""
        from firewatch_cli.main import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["run"])
        assert args.command == "run"

    def test_sync_once_subcommand_is_registered(self) -> None:
        """'firewatch sync --once' is a registered subcommand."""
        from firewatch_cli.main import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["sync", "--once"])
        assert args.command == "sync"
        assert args.once is True

    def test_serve_subcommand_is_registered(self) -> None:
        """'firewatch serve' is a registered subcommand."""
        from firewatch_cli.main import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["serve"])
        assert args.command == "serve"

    def test_run_host_port_args(self) -> None:
        """'firewatch run' accepts --host and --port arguments."""
        from firewatch_cli.main import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["run", "--host", "127.0.0.1", "--port", "9000"])
        assert args.host == "127.0.0.1"
        assert args.port == 9000

    def test_serve_host_port_args(self) -> None:
        """'firewatch serve' accepts --host and --port arguments."""
        from firewatch_cli.main import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["serve", "--host", "127.0.0.1", "--port", "9001"])
        assert args.host == "127.0.0.1"
        assert args.port == 9001

    def test_run_default_host_is_loopback(self) -> None:
        """'firewatch run' defaults --host to 127.0.0.1 (ADR-0026)."""
        from firewatch_cli.main import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["run"])
        assert args.host == "127.0.0.1"

    def test_serve_default_host_is_loopback(self) -> None:
        """'firewatch serve' defaults --host to 127.0.0.1 (ADR-0026)."""
        from firewatch_cli.main import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["serve"])
        assert args.host == "127.0.0.1"


# ---------------------------------------------------------------------------
# Issue #637 wiring guard: cmd_run calls startup_backfill() on the pipeline
# ---------------------------------------------------------------------------


class TestCmdRunGeoBackfillWiring:
    """Guard test: cmd_run calls pipeline.startup_backfill() at startup.

    Issue #637: historical IPs (ingested before geo was working) never got
    geo-enriched because backfill was never triggered.  The fix wires
    startup_backfill() into cmd_run so it runs on every process start.

    This test drives the REAL cmd_run code path (not a structural assertion)
    and verifies that startup_backfill() is invoked with zero new events —
    the exact scenario where the bug manifested.
    """

    @pytest.mark.asyncio
    async def test_cmd_run_calls_startup_backfill_on_pipeline(
        self, tmp_path: Path
    ) -> None:
        """cmd_run calls pipeline.startup_backfill() on startup (issue #637 wiring guard).

        Scenario: zero new events collected — all IPs are historical.
        Without the fix, backfill_geo() was never called and historical IPs
        remained without geo data forever.  With the fix, startup_backfill()
        is called regardless of event flow.
        """
        from firewatch_cli.commands.run import cmd_run

        config_file = tmp_path / "firewatch_config.json"
        _write_config(config_file, [])

        backfill_called: list[int] = [0]

        class _FakePipelineWithBackfill:
            """Fake Pipeline that records startup_backfill() invocations."""

            store = _FakeStore()
            ledger = None
            enrichers: list[Any] = []

            async def startup_backfill(self) -> None:
                backfill_called[0] += 1

        class FakeSupervisor:
            def add_pull(self, *a: Any, **kw: Any) -> Any: return MagicMock()
            def add_push(self, *a: Any, **kw: Any) -> Any: return MagicMock()
            async def startup(self) -> None: pass
            async def shutdown(self) -> None: pass
            async def wait_until_stopped(self) -> None: pass

        async def _noop_serve(sockets: Any = None) -> None:
            pass

        with patch(
            "firewatch_cli.commands.run.load_instances",
            return_value=[],
        ), patch(
            "firewatch_cli.commands.run.Supervisor",
            return_value=FakeSupervisor(),
        ), patch(
            "firewatch_cli.commands.run._build_pipeline",
            return_value=_FakePipelineWithBackfill(),
        ), patch(
            "uvicorn.Server.serve", side_effect=_noop_serve,
        ):
            await cmd_run(
                registry={},
                config_file=config_file,
                host="127.0.0.1",
                port=8000,
            )

        assert backfill_called[0] == 1, (
            "cmd_run did not call pipeline.startup_backfill() — historical IPs "
            "will never receive geo data on startup (issue #637 regression)."
        )
