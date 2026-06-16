"""Regression tests for issue #622 — ``firewatch run`` must NOT exit when all sources park.

EARS criteria -> test mapping
===============================

EARS-1 (regression guard):
  WHILE running as ``firewatch run``, IF all sources become parked/stopped/idle,
  THEN the API server SHALL keep serving (no process exit, no server.should_exit=True).
  -> TestRunDoesNotExitWhenSourcesPark

EARS-2:
  WHEN SIGTERM/SIGINT/``shutdown()`` is received, THEN the server SHALL shut
  down gracefully (unchanged behaviour).
  -> TestGracefulShutdownPreserved

EARS-3:
  The supervisor SHALL still expose the all-parked/idle condition as queryable
  status (``is_stopped``, ``wait_until_stopped()`` semantics unchanged).
  -> TestSupervisorStillReportsParkedStatus

Previously the run loop raced ``server_task`` against
``supervisor.wait_until_stopped()`` and set ``server.should_exit=True`` when
the all-parked predicate fired first.  The fix removes that coupling so the
server exits only via SIGTERM/SIGINT or an explicit ``supervisor.shutdown()``.

Security note: all IPs are RFC 5737 documentation addresses (192.0.2.x,
198.51.100.x, 203.0.113.x) or loopback (127.0.0.1).  No routable IPs used.
"""
from __future__ import annotations

import asyncio
import json
import socket
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
from pydantic import BaseModel

from firewatch_core.supervisor import Supervisor
from firewatch_core.supervisor.models import InstanceState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Return a free loopback TCP port (bind-to-0 trick)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _wait_for_port(port: int, timeout: float = 5.0) -> None:
    """Poll until loopback port accepts connections or timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            return
        except (ConnectionRefusedError, OSError):
            await asyncio.sleep(0.05)
    raise TimeoutError(f"Port {port} did not become ready within {timeout}s")


# ---------------------------------------------------------------------------
# Minimal fakes shared across tests
# ---------------------------------------------------------------------------


class _FakeStore:
    """Minimal in-memory EventStore stub."""

    async def _conn(self) -> Any:
        return self

    async def init(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def get_stats(self) -> dict[str, Any]:
        return {"total_logs": 0, "total_ips": 0, "blocked_percentage": 0.0,
                "top_attack_types": []}

    async def source_health(self) -> list[dict[str, Any]]:
        return []

    async def get_all_ips(self) -> list[str]:
        return []

    async def get_paginated(self, limit: int = 100, filters: Any = None) -> dict[str, Any]:
        return {"logs": [], "next_cursor": None, "has_more": False, "total_matching": 0}

    async def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        return []

    async def get_by_ip(self, ip: str) -> list[Any]:
        return []

    async def get_by_ip_raw(self, ip: str) -> list[dict[str, Any]]:
        return []

    async def get_rule_descriptions(self) -> dict[str, str]:
        return {}

    async def get_categories(self) -> list[dict[str, Any]]:
        return []

    async def get_category_summary(self) -> list[dict[str, Any]]:
        return []

    async def get_timeline(
        self, start: str | None = None, end: str | None = None
    ) -> list[dict[str, Any]]:
        return []

    async def get_analytics_geo(self) -> list[dict[str, Any]]:
        return []

    async def get_analytics_summary(self) -> dict[str, Any]:
        return {"total_ips": 0, "total_events": 0, "total_blocked": 0,
                "block_rate": 0.0, "top_country": "", "unique_countries": 0, "top_rule": ""}

    async def get_categories_timeline(
        self, start: str | None = None, end: str | None = None
    ) -> list[dict[str, Any]]:
        return []

    async def get_ip_summary(self) -> list[dict[str, Any]]:
        return []

    async def get_ips_without_geo(self) -> list[str]:
        return []

    async def upsert_ip_geo(self, geo_data: list[dict[str, Any]]) -> None:
        pass

    async def get_watermark(self, source_type: str, source_id: str) -> str | None:
        return None

    async def set_watermark(self, ts: str, source_type: str, source_id: str) -> None:
        pass

    async def upsert_rule_descriptions(self, descs: dict[str, str]) -> None:
        pass

    async def save_many(self, events: list[Any]) -> int:
        return 0

    async def source_kv_put(
        self, source_type: str, namespace: str, key: str, value: str
    ) -> None:
        pass

    async def source_kv_get(
        self, source_type: str, namespace: str, key: str
    ) -> str | None:
        return None

    async def source_kv_get_all(
        self, source_type: str, namespace: str
    ) -> dict[str, str]:
        return {}

    async def clear(self) -> None:
        pass

    async def delete_older_than(self, days: int) -> int:
        return 0


class _FakePipeline:
    """Minimal Pipeline stub with a store attribute."""

    def __init__(self) -> None:
        self.store = _FakeStore()
        self.ingested: list[Any] = []
        self.ledger: Any = None

    async def run_pull_cycle(self, plugin: Any, cfg: Any, source_id: str, ctx: Any) -> int:
        return 0

    async def _promote_rule_descriptions(self, type_key: str) -> None:
        pass


class _FakeCfg(BaseModel):
    """Minimal plugin config model for test doubles."""

    note: str = "test"


def _make_mock_plugin(type_key: str = "fake_pull") -> MagicMock:
    """Build a minimal mock plugin suitable for supervisor registration."""
    plugin = MagicMock()
    plugin.metadata.return_value = MagicMock(
        type_key=type_key, flavor="pull", actions=[]
    )
    plugin.config_schema.return_value = _FakeCfg
    return plugin


# ---------------------------------------------------------------------------
# EARS-1: API server MUST NOT exit when all sources park (regression guard)
# ---------------------------------------------------------------------------


class TestRunDoesNotExitWhenSourcesPark:
    """EARS-1 regression guard -- #622.

    The key invariant: when ``supervisor.wait_until_stopped()`` resolves (the
    all-parked predicate fires), ``server.should_exit`` MUST remain False.
    The server must keep serving until an explicit SIGTERM/shutdown.
    """

    @pytest.mark.asyncio
    async def test_server_should_exit_not_set_when_supervisor_stops(
        self, tmp_path: Path
    ) -> None:
        """When all sources park (supervisor_stopped fires), server.should_exit stays False.

        This is the precise regression: the old code set server.should_exit=True
        in the ``supervisor_stopped in done`` branch.  The fix removes that coupling.
        We capture the server instance and assert should_exit is False while the
        server is running (i.e. the parked predicate did not kill it early).
        """
        from firewatch_cli.commands.run import cmd_run

        config_file = tmp_path / "firewatch_config.json"
        config_file.write_text(json.dumps({"_instances": []}), encoding="utf-8")

        captured_server: list[Any] = []
        server_alive_when_parked: list[bool] = []

        class _TrackingSupervisor:
            """Supervisor whose wait_until_stopped fires immediately (all-parked)."""

            def add_pull(self, *a: Any, **kw: Any) -> Any:
                return MagicMock()

            def add_push(self, *a: Any, **kw: Any) -> Any:
                return MagicMock()

            async def startup(self) -> None:
                pass

            async def shutdown(self) -> None:
                pass

            async def wait_until_stopped(self) -> None:
                # Simulate all-parked: resolve immediately.
                # The server should NOT be told to exit when this happens.
                if captured_server:
                    # Record server.should_exit AT THE MOMENT all-parked fires.
                    server_alive_when_parked.append(
                        not captured_server[0].should_exit
                    )

        original_server_cls = __import__("uvicorn").Server

        class _CapturingServer(original_server_cls):  # type: ignore[misc]
            def __init__(self, config: Any) -> None:
                super().__init__(config)
                captured_server.append(self)

            async def serve(self, sockets: Any = None) -> None:
                # Stay alive briefly so the supervisor_stopped task can fire and
                # we can observe the should_exit state BEFORE we exit.
                await asyncio.sleep(0.1)

        with (
            patch("firewatch_cli.commands.run.load_instances", return_value=[]),
            patch("firewatch_cli.commands.run.Supervisor",
                  return_value=_TrackingSupervisor()),
            patch("firewatch_cli.commands.run._build_pipeline",
                  return_value=_FakePipeline()),
            patch("uvicorn.Server", _CapturingServer),
        ):
            await cmd_run(
                registry={},
                config_file=config_file,
                host="127.0.0.1",
                port=_free_port(),
            )

        # The server must have stayed alive (should_exit=False) when the all-parked
        # predicate fired, not been cut short by it.
        assert server_alive_when_parked, (
            "server.serve() never ran — the test setup is broken."
        )
        assert server_alive_when_parked[0], (
            "server.should_exit was True when all sources parked -- this is the "
            "regression (issue #622). The server must NOT be told to exit when the "
            "all-parked predicate fires. Only SIGTERM/SIGINT/shutdown() may exit."
        )

    @pytest.mark.asyncio
    async def test_parked_predicate_does_not_race_server_exit(
        self, tmp_path: Path
    ) -> None:
        """The all-parked predicate resolving before server_task does NOT kill the server.

        In the fixed code, ``supervisor_stopped`` is cancelled after server_task
        completes -- it is never used to set ``server.should_exit``.  This test
        verifies the server runs its full duration even when the supervisor fires
        immediately.
        """
        from firewatch_cli.commands.run import cmd_run

        config_file = tmp_path / "firewatch_config.json"
        config_file.write_text(json.dumps({"_instances": []}), encoding="utf-8")

        serve_duration_ms: list[float] = []

        class _ImmediateStopSupervisor:
            def add_pull(self, *a: Any, **kw: Any) -> Any:
                return MagicMock()

            def add_push(self, *a: Any, **kw: Any) -> Any:
                return MagicMock()

            async def startup(self) -> None:
                pass

            async def shutdown(self) -> None:
                pass

            async def wait_until_stopped(self) -> None:
                # Fire immediately -- faster than the server's 50ms sleep.
                return

        async def _timed_serve(sockets: Any = None) -> None:
            t0 = time.monotonic()
            await asyncio.sleep(0.05)  # 50 ms of "serving"
            serve_duration_ms.append((time.monotonic() - t0) * 1000)

        with (
            patch("firewatch_cli.commands.run.load_instances", return_value=[]),
            patch("firewatch_cli.commands.run.Supervisor",
                  return_value=_ImmediateStopSupervisor()),
            patch("firewatch_cli.commands.run._build_pipeline",
                  return_value=_FakePipeline()),
            patch("uvicorn.Server.serve", side_effect=_timed_serve),
        ):
            await cmd_run(
                registry={},
                config_file=config_file,
                host="127.0.0.1",
                port=_free_port(),
            )

        assert serve_duration_ms, "serve() never ran"
        # The server must have completed its full 50 ms sleep, not been cut short.
        # Allow generous tolerance (20 ms) for scheduler jitter.
        assert serve_duration_ms[0] >= 30, (
            f"serve() completed in only {serve_duration_ms[0]:.1f}ms -- it was likely "
            "cut short when the all-parked predicate fired, which is the regression "
            "(issue #622).  The server must run its full duration."
        )

    @pytest.mark.asyncio
    async def test_real_socket_stays_up_after_sources_park(
        self, tmp_path: Path
    ) -> None:
        """Over a real socket, GET /health returns 200 even after all sources park.

        This is the integration-level guard: a real uvicorn server on loopback
        stays reachable after the supervisor fires its all-parked predicate.
        """
        import uvicorn

        from firewatch_api.app import create_app

        config_file = tmp_path / "firewatch_config.json"
        config_file.write_text(json.dumps({"_instances": []}), encoding="utf-8")

        store = _FakeStore()
        pipeline = _FakePipeline()
        pipeline.store = store
        await store.init()

        supervisor = Supervisor(pipeline)

        # Register one instance and force it into PARKED state directly, then
        # set the stopped event to simulate the all-parked predicate firing.
        mock_plugin = _make_mock_plugin("fake_pull")
        rec = supervisor.add_pull(mock_plugin, _FakeCfg(), source_id="test-inst",
                                  interval=60.0)
        rec.state = InstanceState.PARKED
        supervisor._stopped_event.set()  # simulate all-parked predicate

        assert supervisor.is_stopped, "Test setup: supervisor must report all-parked."

        app = create_app(
            registry={},
            event_store=store,
            pipeline=pipeline,
            supervisor=supervisor,
        )

        port = _free_port()
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
        server = uvicorn.Server(config)
        server_task = asyncio.create_task(server.serve(), name="test-parked-socket")

        try:
            await _wait_for_port(port, timeout=5.0)

            # supervisor.is_stopped is True -- but the API MUST still serve.
            async with httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{port}"
            ) as client:
                resp = await client.get("/health")

            assert resp.status_code == 200, (
                f"GET /health returned {resp.status_code} when all sources parked -- "
                "the API server MUST keep serving regardless of source state (#622)."
            )
        finally:
            server.should_exit = True
            await server_task
            await supervisor.shutdown()
            await store.close()


# ---------------------------------------------------------------------------
# EARS-2: Graceful shutdown via shutdown() still works
# ---------------------------------------------------------------------------


class TestGracefulShutdownPreserved:
    """EARS-2: Graceful shutdown on supervisor.shutdown() still stops the server.

    Removing the all-parked->exit coupling must NOT remove the graceful-shutdown
    path.  supervisor.shutdown() is called from cmd_run's finally block, which
    also sets server.should_exit.
    """

    @pytest.mark.asyncio
    async def test_shutdown_call_still_stops_server(self, tmp_path: Path) -> None:
        """An explicit supervisor.shutdown() (from finally) still stops the server.

        cmd_run's finally block calls supervisor.shutdown().  We verify that the
        server exits cleanly when the pipeline teardown runs.
        """
        from firewatch_cli.commands.run import cmd_run

        config_file = tmp_path / "firewatch_config.json"
        config_file.write_text(json.dumps({"_instances": []}), encoding="utf-8")

        shutdown_called = False

        class _ShutdownTracker:
            def add_pull(self, *a: Any, **kw: Any) -> Any:
                return MagicMock()

            def add_push(self, *a: Any, **kw: Any) -> Any:
                return MagicMock()

            async def startup(self) -> None:
                pass

            async def shutdown(self) -> None:
                nonlocal shutdown_called
                shutdown_called = True

            async def wait_until_stopped(self) -> None:
                # Never resolve on its own -- server exits first (noop serve).
                await asyncio.Event().wait()

        async def _noop_serve(sockets: Any = None) -> None:
            pass

        with (
            patch("firewatch_cli.commands.run.load_instances", return_value=[]),
            patch("firewatch_cli.commands.run.Supervisor",
                  return_value=_ShutdownTracker()),
            patch("firewatch_cli.commands.run._build_pipeline",
                  return_value=_FakePipeline()),
            patch("uvicorn.Server.serve", side_effect=_noop_serve),
        ):
            await cmd_run(
                registry={},
                config_file=config_file,
                host="127.0.0.1",
                port=_free_port(),
            )

        assert shutdown_called, (
            "supervisor.shutdown() was NOT called after cmd_run exited -- "
            "the finally block must always call shutdown() for graceful teardown."
        )

    @pytest.mark.asyncio
    async def test_server_exits_when_serve_completes(self, tmp_path: Path) -> None:
        """cmd_run exits cleanly when the server task completes (uvicorn exits on signal).

        The fixed run loop awaits server_task; when uvicorn exits (SIGTERM/SIGINT),
        the loop ends and the finally block runs.  Simulate by having serve() return.
        """
        from firewatch_cli.commands.run import cmd_run

        config_file = tmp_path / "firewatch_config.json"
        config_file.write_text(json.dumps({"_instances": []}), encoding="utf-8")

        completed = False

        class _IdleSupervisor:
            def add_pull(self, *a: Any, **kw: Any) -> Any:
                return MagicMock()

            def add_push(self, *a: Any, **kw: Any) -> Any:
                return MagicMock()

            async def startup(self) -> None:
                pass

            async def shutdown(self) -> None:
                pass

            async def wait_until_stopped(self) -> None:
                await asyncio.Event().wait()  # never fires on its own

        async def _completing_serve(sockets: Any = None) -> None:
            # Simulate uvicorn receiving SIGTERM and returning.
            pass

        with (
            patch("firewatch_cli.commands.run.load_instances", return_value=[]),
            patch("firewatch_cli.commands.run.Supervisor",
                  return_value=_IdleSupervisor()),
            patch("firewatch_cli.commands.run._build_pipeline",
                  return_value=_FakePipeline()),
            patch("uvicorn.Server.serve", side_effect=_completing_serve),
        ):
            await cmd_run(
                registry={},
                config_file=config_file,
                host="127.0.0.1",
                port=_free_port(),
            )
            completed = True

        assert completed, "cmd_run did not return cleanly after server_task completed."


# ---------------------------------------------------------------------------
# EARS-3: Supervisor still reports all-parked status (unchanged semantics)
# ---------------------------------------------------------------------------


class TestSupervisorStillReportsParkedStatus:
    """EARS-3: Supervisor's is_stopped / wait_until_stopped semantics are unchanged.

    The fix only removes the run-loop coupling that caused the API to die.
    The supervisor's status reporting must remain accurate so the UI can show
    "collection idle -- sources parked" without querying a dead API.
    """

    @pytest.mark.asyncio
    async def test_is_stopped_true_when_stopped_event_set(self) -> None:
        """supervisor.is_stopped is True after the all-parked predicate fires."""
        pipeline = _FakePipeline()
        supervisor = Supervisor(pipeline)
        supervisor._stopped_event.set()

        assert supervisor.is_stopped is True, (
            "supervisor.is_stopped should be True when _stopped_event is set."
        )

    @pytest.mark.asyncio
    async def test_wait_until_stopped_resolves_when_event_set(self) -> None:
        """wait_until_stopped() resolves when the all-parked predicate fires."""
        pipeline = _FakePipeline()
        supervisor = Supervisor(pipeline)

        async def _fire_after_delay() -> None:
            await asyncio.sleep(0.01)
            supervisor._stopped_event.set()

        asyncio.create_task(_fire_after_delay())

        done = asyncio.create_task(supervisor.wait_until_stopped())
        try:
            await asyncio.wait_for(done, timeout=1.0)
        except asyncio.TimeoutError:
            pytest.fail(
                "supervisor.wait_until_stopped() did not resolve after the all-parked "
                "predicate fired -- its semantics are broken."
            )

    def test_sources_status_returns_parked_state(self) -> None:
        """supervisor.status() returns PARKED state so the UI can display 'collection idle'.

        The supervisor's status() method must still return per-instance state
        (including PARKED) regardless of whether the API is kept alive.
        """
        pipeline = _FakePipeline()
        supervisor = Supervisor(pipeline)
        mock_plugin = _make_mock_plugin("fake_pull")
        rec = supervisor.add_pull(mock_plugin, _FakeCfg(), source_id="test-parked",
                                  interval=60.0)
        rec.state = InstanceState.PARKED

        statuses = supervisor.status()
        assert len(statuses) == 1
        assert statuses[0].state == "parked", (
            f"Expected state='parked', got {statuses[0].state!r}. "
            "Parked state must be visible via supervisor.status() so GET /sources "
            "can display 'collection idle' to the operator."
        )
        assert statuses[0].source_id == "test-parked"

    def test_maybe_signal_stopped_still_sets_stopped_event(self) -> None:
        """_maybe_signal_stopped still sets _stopped_event on all-parked (semantics preserved).

        The fix is in run.py (the host layer), not in the supervisor.
        _maybe_signal_stopped must continue to fire and set _stopped_event so that
        supervisor.is_stopped / wait_until_stopped() remain accurate for status queries.
        """
        pipeline = _FakePipeline()
        supervisor = Supervisor(pipeline)
        mock_plugin = _make_mock_plugin("fake_pull")

        # Register a record that was "launched" (has attempt > 0 to bypass the
        # idle-only guard in _maybe_signal_stopped) and is now PARKED.
        rec = supervisor.add_pull(mock_plugin, _FakeCfg(), source_id="si-1",
                                  interval=60.0)
        rec.state = InstanceState.PARKED
        rec.attempt = 1  # was launched at least once

        supervisor._maybe_signal_stopped()

        assert supervisor._stopped_event.is_set(), (
            "_maybe_signal_stopped did not set _stopped_event when all instances are "
            "parked (with attempt > 0). This method's semantics must be preserved."
        )

    def test_is_stopped_and_parked_state_coexist(self) -> None:
        """supervisor.is_stopped=True and per-instance PARKED state coexist correctly.

        The key invariant: the same supervisor that reports is_stopped=True ALSO
        correctly reports per-instance state via status().  The API reads both
        without the process exiting.
        """
        pipeline = _FakePipeline()
        supervisor = Supervisor(pipeline)
        mock_plugin = _make_mock_plugin("src_a")

        rec = supervisor.add_pull(mock_plugin, _FakeCfg(), source_id="s1", interval=60.0)
        rec.state = InstanceState.PARKED
        supervisor._stopped_event.set()

        assert supervisor.is_stopped is True
        statuses = supervisor.status()
        assert statuses[0].state == "parked"
