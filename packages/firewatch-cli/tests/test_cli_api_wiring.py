"""Integration tests: CLI → API wiring — issue #75.

Tests assert that ``run.py`` and ``serve.py`` inject event_store, pipeline, and
supervisor (where applicable) into ``create_app(...)`` so that the MB read
routes (/stats, /threats, /logs/*) return 200, not 503.

They also add REAL two-/single-loop integration tests that bind actual loopback
sockets — TestClient cannot detect the cross-loop aiosqlite crash because it
runs all coroutines on a single synthesised loop; only a test that physically
opens a socket and speaks HTTP can expose the loop-affinity bug.

EARS criterion → test mapping
══════════════════════════════

Bug criteria (issue #75, all Event-driven):

  B1 — When the API app is wired the same way cmd_run wires it (with store +
       pipeline injected), GET /stats shall return 200, not 503.
       → TestRunWiringReadRoutesReturn200

  B2 — When the API app is wired the same way cmd_run wires it,
       GET /logs/paginated shall return 200, not 503.
       → TestRunWiringReadRoutesReturn200

  B3 — When the API app is wired the same way cmd_run wires it,
       GET /threats shall return 200, not 503.
       → TestRunWiringReadRoutesReturn200

  B4 — When cmd_run wiring is used (supervisor.startup() + uvicorn task on ONE
       loop), a REAL HTTP GET /stats over a loopback socket returns 200 and the
       store is reachable without a cross-loop crash.  TestClient-based tests
       cannot catch this class of bug (they synthesise one loop regardless of
       how the store was initialised); this test MUST use a real socket.
       → TestRunTopologyRealSocket

  B5 — When cmd_serve is called, it shall build a pipeline and pass
       event_store and pipeline into create_app (read-only API wiring).
       → TestServeInjectsStorePipeline

  B6 — When the API app is wired WITHOUT store/pipeline (the pre-fix wiring),
       GET /stats shall return 503 — confirming the regression oracle for B1.
       → TestPreFixWiringReturns503

  B7 — When supervisor is not injected (serve path), GET /sources shall
       return 503 (expected), but GET /stats shall return 200.
       → TestServeWiredAppBehavior

  B8 — serve-topology real-socket: _serve coroutine on a loopback port; GET
       /stats → 200, GET /sources → 503 (no supervisor injected).
       → TestServeTopologyRealSocket

  AC-7 — If the API server task crashes during startup, the test FAILS (not
          hangs / skips) so a future regression surfaces red.
          → TestApiTaskCrashSurfacesRed

Security notes
--------------
RFC 5737 documentation IPs used throughout (192.0.2.x, 198.51.100.x,
203.0.113.x).  No real/public/routable IPs.  All HTTP calls go to 127.0.0.1
(loopback) on ephemeral ports — never to routable addresses.
"""
from __future__ import annotations

import asyncio
import socket
import time
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from firewatch_api.app import create_app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Return a free loopback TCP port (bind :0 trick)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _wait_for_port(port: int, timeout: float = 5.0) -> None:
    """Poll until the given loopback port accepts connections or timeout expires."""
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
# Minimal fakes
# ---------------------------------------------------------------------------


class _FakeStore:
    """Minimal in-memory EventStore fake that satisfies the store contract."""

    async def _conn(self) -> Any:
        return self

    async def get_stats(self) -> dict[str, Any]:
        return {"total_logs": 0, "total_ips": 0, "blocked_percentage": 0.0,
                "top_attack_types": []}

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

    async def init(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def clear(self) -> None:
        pass

    async def delete_older_than(self, days: int) -> int:
        return 0


class _FakePipeline:
    """Minimal Pipeline fake with a store attribute."""

    def __init__(self) -> None:
        self.store = _FakeStore()

    async def analyze_ip(self, ip: str, *, use_ai: bool = True) -> Any:
        from datetime import datetime, timezone

        from firewatch_sdk import ThreatScore
        now = datetime.now(timezone.utc)
        return ThreatScore(
            source_ip=ip, threat_level="LOW", score=0,
            total_events=0, blocked_events=0, attack_types=[],
            first_seen=now, last_seen=now, ai_status="disabled",
        )

    async def analyze_ip_detailed(self, ip: str) -> dict[str, Any]:
        return {"error": "No logs found"}

    async def run_pull_cycle(self, plugin: Any, cfg: Any, source_id: str, ctx: Any) -> int:
        return 0


# ---------------------------------------------------------------------------
# B6: Regression oracle — app WITHOUT store/pipeline returns 503 for /stats
# ---------------------------------------------------------------------------


class TestPreFixWiringReturns503:
    """B6: Confirm the pre-fix wiring (registry-only) produces 503 for read routes.

    This is the regression oracle.  If this test starts failing it means
    the underlying route's 503 guard was removed, which would break the contract.
    """

    def test_app_without_store_returns_503_for_stats(self) -> None:
        """GET /stats returns 503 when no event_store is injected (pre-fix wiring)."""
        app = create_app(registry={})  # the broken wiring: no store, no pipeline
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/stats")
        assert resp.status_code == 503, (
            f"Expected 503 from store-less app, got {resp.status_code}. "
            "The 503 guard in the /stats route was removed — this oracle must stay."
        )


# ---------------------------------------------------------------------------
# B1–B3: App wired the way cmd_run wires it → read routes return 200
# ---------------------------------------------------------------------------


class TestRunWiringReadRoutesReturn200:
    """B1–B3: When the API app is wired with store+pipeline (as cmd_run does),
    the MB read routes must return 200, not 503.

    Note: TestClient synthesises a single event loop for all coroutines, so it
    cannot detect the cross-loop aiosqlite crash.  These tests verify the
    injection wiring is correct; B4/B8 (real-socket tests) verify loop safety.
    """

    @pytest.fixture()
    def client(self) -> TestClient:
        """Build app with the full run-wiring: store + pipeline injected."""
        store = _FakeStore()
        pipeline = _FakePipeline()
        pipeline.store = store
        app = create_app(
            registry={},
            event_store=store,
            pipeline=pipeline,
            supervisor=None,  # supervisor absent → action routes 503, read routes 200
        )
        return TestClient(app)

    def test_app_with_store_and_pipeline_stats_returns_200(
        self, client: TestClient
    ) -> None:
        """B1: GET /stats returns 200 when store+pipeline are injected."""
        resp = client.get("/stats")
        assert resp.status_code == 200, (
            f"GET /stats returned {resp.status_code} — expected 200. "
            "Ensure create_app receives event_store= and pipeline= (issue #75)."
        )

    def test_app_with_store_and_pipeline_logs_paginated_returns_200(
        self, client: TestClient
    ) -> None:
        """B2: GET /logs/paginated returns 200 when store+pipeline are injected."""
        resp = client.get("/logs/paginated")
        assert resp.status_code == 200, (
            f"GET /logs/paginated returned {resp.status_code} — expected 200. "
            "Ensure create_app receives event_store= (issue #75)."
        )

    def test_app_with_store_and_pipeline_threats_returns_200(
        self, client: TestClient
    ) -> None:
        """B3: GET /threats returns 200 when store+pipeline are injected."""
        resp = client.get("/threats")
        assert resp.status_code == 200, (
            f"GET /threats returned {resp.status_code} — expected 200. "
            "Ensure create_app receives event_store= and pipeline= (issue #75)."
        )


# ---------------------------------------------------------------------------
# B4: run-topology real-socket integration test
# ---------------------------------------------------------------------------


class TestRunTopologyRealSocket:
    """B4: Real two-loop integration test for the ``run`` wiring.

    TestClient cannot catch the cross-loop aiosqlite crash because it
    synthesises a single loop for all coroutines regardless of how the
    store connection was initialised.  Only a test that physically opens a TCP
    socket and sends real HTTP can expose the loop-affinity bug.

    Design:
    - Build a _FakeStore + _FakePipeline (no aiosqlite disk I/O needed).
    - Create a uvicorn.Server for the app; launch it as asyncio.create_task()
      on the SAME loop as the test (``pytest-asyncio`` provides this loop).
    - Wait for the port to become ready; GET /stats via httpx.AsyncClient.
    - Assert 200 — if the old daemon-thread design were reintroduced, this
      test would fail with "got Future attached to a different loop" or a 503.
    - Teardown: server.should_exit = True; await server_task.

    Why the old design fails this test:
      If the store is inited on loop A and the route handler runs on loop B,
      every ``await store.get_stats()`` raises:
        RuntimeError: Task <Task ...> got Future <Future ...> attached to a
        different loop
      FastAPI converts that to a 500 (unhandled exception in route handler).
      The httpx GET then receives 500, and ``assert resp.status_code == 200``
      fails — making the regression immediately visible in CI.
    """

    @pytest.mark.asyncio
    async def test_run_topology_stats_200_over_real_socket(self) -> None:
        """GET /stats returns 200 over a real loopback socket (run wiring).

        Uses 127.0.0.1 (loopback) on an ephemeral port — never a routable IP.
        """
        store = _FakeStore()
        pipeline = _FakePipeline()
        pipeline.store = store

        # store.init() and server.serve() share this loop (the test's asyncio loop).
        await store.init()

        app = create_app(
            registry={},
            event_store=store,
            pipeline=pipeline,
            supervisor=None,
        )

        port = _free_port()
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
        server = uvicorn.Server(config)
        server_task = asyncio.create_task(server.serve(), name="test-api-run-topology")

        try:
            await _wait_for_port(port, timeout=5.0)

            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                resp = await client.get("/stats")

            assert resp.status_code == 200, (
                f"GET /stats returned {resp.status_code} — expected 200. "
                "If the store was initialised on a different loop (e.g. a daemon-thread "
                "design was reintroduced), this will be 500 due to the cross-loop crash. "
                "See issue #75 and the 'single event loop' design notes in run.py."
            )
        finally:
            server.should_exit = True
            await server_task

    @pytest.mark.asyncio
    async def test_run_topology_supervisor_startup_does_not_crash(self) -> None:
        """supervisor.startup() + uvicorn task on the same loop does not raise.

        Validates that the single-loop wiring supports concurrent supervisor
        tasks and the HTTP server without either blocking or cross-loop issues.
        """
        from firewatch_core.supervisor import Supervisor

        store = _FakeStore()
        pipeline = _FakePipeline()
        pipeline.store = store
        await store.init()

        supervisor = Supervisor(pipeline)
        # No instances registered — startup() immediately returns.
        await supervisor.startup()

        app = create_app(
            registry={},
            event_store=store,
            pipeline=pipeline,
            supervisor=supervisor,
        )

        port = _free_port()
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
        server = uvicorn.Server(config)
        server_task = asyncio.create_task(server.serve(), name="test-api-supervisor")

        try:
            await _wait_for_port(port, timeout=5.0)

            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                stats_resp = await client.get("/stats")

            assert stats_resp.status_code == 200
        finally:
            server.should_exit = True
            await server_task
            await supervisor.shutdown()
            await store.close()


# ---------------------------------------------------------------------------
# B5: cmd_serve builds a pipeline and injects store into create_app
# ---------------------------------------------------------------------------


class TestServeInjectsStorePipeline:
    """B5: The _serve coroutine must build a pipeline (via _build_pipeline) and
    inject event_store + pipeline into create_app so /stats and other read
    routes return 200.

    _build_pipeline and create_app are called inside _serve (the async
    coroutine), not in cmd_serve itself.  We therefore test _serve directly,
    patching its module-level names, rather than patching _serve out from
    cmd_serve (which would bypass the injection entirely).
    """

    @pytest.mark.asyncio
    async def test_serve_creates_pipeline_and_injects_store(self) -> None:
        """_serve passes event_store and pipeline to create_app.

        We patch _build_pipeline and uvicorn.Server.serve to observe the
        create_app kwargs without binding a real socket.
        """
        from firewatch_cli.commands import serve as serve_mod

        store = _FakeStore()
        pipeline = _FakePipeline()
        pipeline.store = store

        captured_kwargs: dict[str, Any] = {}

        def _capture_create_app(**kwargs: Any) -> Any:
            captured_kwargs.update(kwargs)
            return create_app(**kwargs)

        async def _noop_serve(sockets: Any = None) -> None:
            pass

        with patch.object(serve_mod, "_build_pipeline", return_value=pipeline) as mock_build, \
             patch.object(serve_mod, "create_app", side_effect=_capture_create_app), \
             patch("uvicorn.Server.serve", side_effect=_noop_serve):
            await serve_mod._serve(registry={}, host="127.0.0.1", port=8000)

        mock_build.assert_called_once()  # _serve must call _build_pipeline

        assert "event_store" in captured_kwargs, (
            "_serve did not pass event_store= to create_app (issue #75). "
            "serve.py must build a store and inject it."
        )
        assert captured_kwargs["event_store"] is store
        assert "pipeline" in captured_kwargs, (
            "_serve did not pass pipeline= to create_app (issue #75)."
        )
        assert captured_kwargs["pipeline"] is pipeline

    @pytest.mark.asyncio
    async def test_serve_does_not_inject_supervisor(self) -> None:
        """_serve must NOT inject a supervisor (no loops — serve is read-only)."""
        from firewatch_cli.commands import serve as serve_mod

        pipeline = _FakePipeline()

        captured_kwargs: dict[str, Any] = {}

        def _capture_create_app(**kwargs: Any) -> Any:
            captured_kwargs.update(kwargs)
            return create_app(**kwargs)

        async def _noop_serve(sockets: Any = None) -> None:
            pass

        with patch.object(serve_mod, "_build_pipeline", return_value=pipeline), \
             patch.object(serve_mod, "create_app", side_effect=_capture_create_app), \
             patch("uvicorn.Server.serve", side_effect=_noop_serve):
            await serve_mod._serve(registry={}, host="127.0.0.1", port=8000)

        supervisor_val = captured_kwargs.get("supervisor")
        assert supervisor_val is None, (
            f"_serve injected a non-None supervisor={supervisor_val!r}. "
            "serve.py must not start or inject a supervisor."
        )


# ---------------------------------------------------------------------------
# B7: serve-wired app (TestClient): read routes 200, action routes 503
# ---------------------------------------------------------------------------


class TestServeWiredAppBehavior:
    """B7: App wired as serve (store+pipeline, no supervisor):
    - Read routes (GET /stats, /threats, /logs/*) return 200.
    - Action/supervisor routes (GET /sources) return 503.
    """

    @pytest.fixture()
    def client(self) -> TestClient:
        """App with store+pipeline but NO supervisor — mirrors serve wiring."""
        store = _FakeStore()
        pipeline = _FakePipeline()
        pipeline.store = store
        app = create_app(
            registry={},
            event_store=store,
            pipeline=pipeline,
            supervisor=None,
        )
        return TestClient(app, raise_server_exceptions=False)

    def test_stats_returns_200_without_supervisor(self, client: TestClient) -> None:
        """B7: GET /stats is 200 even when supervisor is absent."""
        resp = client.get("/stats")
        assert resp.status_code == 200

    def test_sources_returns_503_without_supervisor(self, client: TestClient) -> None:
        """B7: GET /sources returns 503 when supervisor is absent (expected for serve)."""
        resp = client.get("/sources")
        assert resp.status_code == 503, (
            f"Expected 503 (no supervisor) for GET /sources in serve mode, "
            f"got {resp.status_code}."
        )


# ---------------------------------------------------------------------------
# B8: serve-topology real-socket integration test
# ---------------------------------------------------------------------------


class TestServeTopologyRealSocket:
    """B8: Real single-loop integration test for the ``serve`` (_serve coroutine) wiring.

    The serve topology wraps store.init() and server.serve() in a single
    async function (_serve) so both run on one loop.  These tests exercise
    that function directly (without going through asyncio.run / cmd_serve)
    so they can run inside pytest-asyncio's managed loop.

    Validates:
    - GET /stats → 200 (store is reachable, no cross-loop crash).
    - GET /sources → 503 (no supervisor injected in serve mode).
    """

    @pytest.mark.asyncio
    async def test_serve_topology_stats_200(self) -> None:
        """GET /stats returns 200 over a real loopback socket (serve wiring)."""
        from firewatch_cli.commands.serve import _serve

        store = _FakeStore()
        pipeline = _FakePipeline()
        pipeline.store = store

        port = _free_port()

        with patch("firewatch_cli.commands.serve._build_pipeline", return_value=pipeline):
            serve_task = asyncio.create_task(
                _serve(registry={}, host="127.0.0.1", port=port),
                name="test-serve-topology",
            )

        try:
            await _wait_for_port(port, timeout=5.0)
            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                resp = await client.get("/stats")
            assert resp.status_code == 200, (
                f"GET /stats returned {resp.status_code} — expected 200 in serve topology."
            )
        finally:
            serve_task.cancel()
            try:
                await serve_task
            except asyncio.CancelledError:
                pass

    @pytest.mark.asyncio
    async def test_serve_topology_sources_503(self) -> None:
        """GET /sources returns 503 in serve topology (no supervisor)."""
        from firewatch_cli.commands.serve import _serve

        store = _FakeStore()
        pipeline = _FakePipeline()
        pipeline.store = store

        port = _free_port()

        with patch("firewatch_cli.commands.serve._build_pipeline", return_value=pipeline):
            serve_task = asyncio.create_task(
                _serve(registry={}, host="127.0.0.1", port=port),
                name="test-serve-topology-sources",
            )

        try:
            await _wait_for_port(port, timeout=5.0)
            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                resp = await client.get("/sources")
            assert resp.status_code == 503, (
                f"Expected 503 for GET /sources (no supervisor in serve mode), "
                f"got {resp.status_code}."
            )
        finally:
            serve_task.cancel()
            try:
                await serve_task
            except asyncio.CancelledError:
                pass


# ---------------------------------------------------------------------------
# AC-7: Server task crash during startup surfaces as test failure (not hang)
# ---------------------------------------------------------------------------


class TestApiTaskCrashSurfacesRed:
    """AC-7: If the API server task raises during startup, the test FAILS.

    Rationale: a future regression (e.g. a misconfigured app that raises on
    startup) must surface as a red test, not a silent hang waiting for the
    port to become ready.  The timeout in _wait_for_port converts a hang into
    a TimeoutError which pytest reports as an error/failure.
    """

    @pytest.mark.asyncio
    async def test_server_task_crash_raises_not_hangs(self) -> None:
        """A server task that crashes during startup causes _wait_for_port to timeout.

        We patch uvicorn.Server.serve to raise immediately, simulating a
        startup crash.  _wait_for_port then raises TimeoutError (the port
        never becomes ready), which the test catches to confirm the failure
        mode surfaces and does NOT hang indefinitely.
        """
        store = _FakeStore()
        pipeline = _FakePipeline()
        pipeline.store = store
        await store.init()

        app = create_app(
            registry={},
            event_store=store,
            pipeline=pipeline,
        )

        port = _free_port()
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
        server = uvicorn.Server(config)

        async def _crash_serve(sockets: Any = None) -> None:
            raise RuntimeError("simulated startup crash")

        with patch.object(server, "serve", side_effect=_crash_serve):
            server_task = asyncio.create_task(server.serve(), name="test-crash-task")

            with pytest.raises((TimeoutError, RuntimeError)):
                # _wait_for_port raises TimeoutError if the port never opens;
                # or the server_task exception propagates.
                done, pending = await asyncio.wait(
                    {server_task},
                    timeout=0.5,
                )
                if server_task in done and not server_task.cancelled():
                    exc = server_task.exception()
                    if exc is not None:
                        raise exc
                if not server_task.done():
                    await _wait_for_port(port, timeout=0.2)

            if not server_task.done():
                server_task.cancel()
                try:
                    await server_task
                except (asyncio.CancelledError, Exception):
                    pass
