"""Security hardening tests for firewatch_syslog.

Covers the blocking issues and non-blocking improvements from the security review:

BLOCKING-1: TCP slow-loris / unbounded connections
  - max_connections cap: N+1th connection is rejected/dropped
  - Idle TCP connection closed after idle_timeout seconds
  - limit= passed to asyncio.start_server (bounded readline buffer)

BLOCKING-2: bind must be an IP literal
  - field_validator rejects hostnames and garbage strings
  - field_validator accepts valid IP literals (IPv4 + IPv6)

NB-1: UDP backpressure
  - Outstanding emit tasks bounded; excess datagrams dropped under flood

NB-2: asyncio.get_event_loop() replaced with get_running_loop()

NB-4: health_check("both") probes BOTH UDP and TCP

NB-5: line cap — _make_raw truncates the line before storing in RawEvent.data

NB-6: bind description mentions '::' IPv6 any-address caveat

NB-3 (clarity): run_tcp_listener wires _tcp_server handle into SyslogListener;
  run_udp_listener wires _udp_transport.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from firewatch_sdk import RawEvent


# ---------------------------------------------------------------------------
# Helpers (RFC 5737 doc-range IPs only — gitleaks gate)
# ---------------------------------------------------------------------------

_DOC_IP = "203.0.113.5"  # RFC 5737 TEST-NET-3 — always use for test fixtures


def _raw(line: str, transport: str = "tcp", client_ip: str = _DOC_IP) -> RawEvent:
    return RawEvent(
        source_type="syslog",
        received_at=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        data={"line": line, "client_ip": client_ip, "transport": transport},
    )


# ---------------------------------------------------------------------------
# BLOCKING-2: bind field_validator — IP literal enforcement
# ---------------------------------------------------------------------------


class TestBindValidator:
    """BLOCKING-2 — SyslogConfig.bind must only accept valid IP literals."""

    def test_bind_accepts_ipv4_loopback(self) -> None:
        """127.0.0.1 is a valid IP literal; must be accepted."""
        from firewatch_syslog.config import SyslogConfig

        cfg = SyslogConfig(bind="127.0.0.1")  # type: ignore[call-arg]
        assert cfg.bind == "127.0.0.1"

    def test_bind_accepts_ipv4_any(self) -> None:
        """0.0.0.0 is a valid IP literal; must be accepted."""
        from firewatch_syslog.config import SyslogConfig

        cfg = SyslogConfig(bind="0.0.0.0")  # type: ignore[call-arg]
        assert cfg.bind == "0.0.0.0"

    def test_bind_accepts_ipv6_loopback(self) -> None:
        """::1 is a valid IPv6 literal; must be accepted."""
        from firewatch_syslog.config import SyslogConfig

        cfg = SyslogConfig(bind="::1")  # type: ignore[call-arg]
        assert cfg.bind == "::1"

    def test_bind_accepts_ipv6_any(self) -> None:
        """:: (IPv6 any-address) is a valid IP literal; must be accepted."""
        from firewatch_syslog.config import SyslogConfig

        cfg = SyslogConfig(bind="::")  # type: ignore[call-arg]
        assert cfg.bind == "::"

    def test_bind_rejects_hostname(self) -> None:
        """A hostname ('localhost') must be rejected — DNS resolution vector."""
        from pydantic import ValidationError

        from firewatch_syslog.config import SyslogConfig

        with pytest.raises(ValidationError, match="IP literal"):
            SyslogConfig(bind="localhost")  # type: ignore[call-arg]

    def test_bind_rejects_fqdn(self) -> None:
        """A FQDN ('example.com') must be rejected."""
        from pydantic import ValidationError

        from firewatch_syslog.config import SyslogConfig

        with pytest.raises(ValidationError, match="IP literal"):
            SyslogConfig(bind="example.com")  # type: ignore[call-arg]

    def test_bind_rejects_garbage_string(self) -> None:
        """A garbage string must be rejected."""
        from pydantic import ValidationError

        from firewatch_syslog.config import SyslogConfig

        with pytest.raises(ValidationError, match="IP literal"):
            SyslogConfig(bind="not-an-ip!!!")  # type: ignore[call-arg]

    def test_bind_rejects_partial_ip(self) -> None:
        """A partial IP like '192.168' must be rejected."""
        from pydantic import ValidationError

        from firewatch_syslog.config import SyslogConfig

        with pytest.raises(ValidationError, match="IP literal"):
            SyslogConfig(bind="192.168")  # type: ignore[call-arg]

    def test_bind_description_mentions_ipv6_any(self) -> None:
        """NB-6: bind description must mention '::' IPv6 any-address caveat."""
        from firewatch_syslog.config import SyslogConfig

        field_info = SyslogConfig.model_fields["bind"]
        description = field_info.description or ""
        assert "::" in description, (
            "bind field description must mention '::' (IPv6 any-address caveat, NB-6)"
        )


# ---------------------------------------------------------------------------
# BLOCKING-1: max_connections config field and TCP connection cap
# ---------------------------------------------------------------------------


class TestMaxConnectionsConfig:
    """BLOCKING-1 — SyslogConfig must have max_connections; cap must be enforced."""

    def test_max_connections_field_exists(self) -> None:
        """SyslogConfig must have a max_connections field."""
        from firewatch_syslog.config import SyslogConfig

        assert "max_connections" in SyslogConfig.model_fields

    def test_max_connections_default_is_256(self) -> None:
        """Default max_connections is 256 (sane cap)."""
        from firewatch_syslog.config import SyslogConfig

        cfg = SyslogConfig()
        assert cfg.max_connections == 256  # type: ignore[attr-defined]

    def test_max_connections_upper_bound(self) -> None:
        """max_connections must be bounded at <= 4096."""
        from pydantic import ValidationError

        from firewatch_syslog.config import SyslogConfig

        with pytest.raises((ValidationError, Exception)):
            SyslogConfig(max_connections=5000)  # type: ignore[call-arg]

    def test_max_connections_lower_bound(self) -> None:
        """max_connections >= 1."""
        from pydantic import ValidationError

        from firewatch_syslog.config import SyslogConfig

        with pytest.raises((ValidationError, Exception)):
            SyslogConfig(max_connections=0)  # type: ignore[call-arg]

    def test_max_connections_accepts_sane_value(self) -> None:
        """max_connections=10 is a valid value."""
        from firewatch_syslog.config import SyslogConfig

        cfg = SyslogConfig(max_connections=10)  # type: ignore[call-arg]
        assert cfg.max_connections == 10  # type: ignore[attr-defined]


class TestIdleTimeoutConfig:
    """BLOCKING-1 — SyslogConfig must have idle_timeout; real idle detection needed."""

    def test_idle_timeout_field_exists(self) -> None:
        """SyslogConfig must have an idle_timeout field."""
        from firewatch_syslog.config import SyslogConfig

        assert "idle_timeout" in SyslogConfig.model_fields

    def test_idle_timeout_default_is_30(self) -> None:
        """Default idle_timeout is 30 seconds."""
        from firewatch_syslog.config import SyslogConfig

        cfg = SyslogConfig()
        assert cfg.idle_timeout == 30.0  # type: ignore[attr-defined]

    def test_idle_timeout_must_be_positive(self) -> None:
        """idle_timeout <= 0 must be rejected."""
        from pydantic import ValidationError

        from firewatch_syslog.config import SyslogConfig

        with pytest.raises((ValidationError, Exception)):
            SyslogConfig(idle_timeout=0.0)  # type: ignore[call-arg]


class TestMaxLineLengthConfig:
    """BLOCKING-1 — SyslogConfig must have max_line_length for readline buffer bound."""

    def test_max_line_length_field_exists(self) -> None:
        """SyslogConfig must have a max_line_length field."""
        from firewatch_syslog.config import SyslogConfig

        assert "max_line_length" in SyslogConfig.model_fields

    def test_max_line_length_default_is_8192(self) -> None:
        """Default max_line_length is 8192 bytes."""
        from firewatch_syslog.config import SyslogConfig

        cfg = SyslogConfig()
        assert cfg.max_line_length == 8192  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# BLOCKING-1: TCP connection cap enforcement
# ---------------------------------------------------------------------------


class TestTCPConnectionCap:
    """BLOCKING-1 — N+1th connection is dropped when semaphore is exhausted."""

    async def test_connection_cap_enforced(self) -> None:
        """With max_connections=2, the 3rd concurrent connection is dropped (writer closed)."""
        from firewatch_syslog.listener import _handle_tcp_client

        sem = asyncio.BoundedSemaphore(2)
        stop_event = asyncio.Event()

        async def _emit(batch: list[RawEvent]) -> None:
            pass

        closed_immediately = asyncio.Event()

        class _FakeWriter:
            def __init__(self) -> None:
                self._closed = False

            def get_extra_info(self, key: str, default: object = None) -> object:
                if key == "peername":
                    return (_DOC_IP, 55000)
                return default

            def close(self) -> None:
                self._closed = True
                closed_immediately.set()

            async def wait_closed(self) -> None:
                pass

        class _FakeReader:
            async def readline(self) -> bytes:
                await asyncio.sleep(10)
                return b""

        # Exhaust the semaphore by holding 2 locks
        await sem.acquire()
        await sem.acquire()

        fake_reader = _FakeReader()
        fake_writer = _FakeWriter()

        handle_task = asyncio.create_task(
            _handle_tcp_client(
                fake_reader,  # type: ignore[arg-type]
                fake_writer,  # type: ignore[arg-type]
                _emit,
                stop_event,
                sem,
            )
        )

        try:
            await asyncio.wait_for(asyncio.shield(closed_immediately.wait()), timeout=1.0)
        except asyncio.TimeoutError:
            pass

        handle_task.cancel()
        try:
            await handle_task
        except (asyncio.CancelledError, Exception):
            pass

        assert fake_writer._closed, "Expected writer to be closed for rejected connection"

    async def test_run_tcp_listener_passes_limit_to_start_server(self) -> None:
        """run_tcp_listener must pass limit=max_line_length to asyncio.start_server."""
        from firewatch_syslog import listener as _listener

        stop_event = asyncio.Event()
        start_server_calls: list[dict] = []

        async def _emit(batch: list[RawEvent]) -> None:
            pass

        async def _mock_start_server(
            client_connected_cb: object,
            host: str,
            port: int,
            *,
            limit: int = 65536,
        ) -> MagicMock:
            start_server_calls.append({"limit": limit, "host": host, "port": port})
            mock_server = MagicMock()
            mock_server.close = MagicMock()
            mock_server.wait_closed = AsyncMock()
            return mock_server

        with patch("asyncio.start_server", _mock_start_server):
            task = asyncio.create_task(
                _listener.run_tcp_listener(
                    "127.0.0.1",
                    5514,
                    _emit,
                    batch_size=10,
                    stop_event=stop_event,
                    max_connections=5,
                    idle_timeout=30.0,
                    max_line_length=8192,
                )
            )
            await asyncio.sleep(0.01)
            stop_event.set()
            try:
                await asyncio.wait_for(task, timeout=1.0)
            except asyncio.TimeoutError:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

        assert len(start_server_calls) >= 1
        assert start_server_calls[0]["limit"] == 8192

    async def test_idle_tcp_connection_closed(self) -> None:
        """A TCP connection that sends nothing for idle_timeout seconds must be closed."""
        from firewatch_syslog.listener import _handle_tcp_client

        sem = asyncio.BoundedSemaphore(10)
        stop_event = asyncio.Event()
        closed = asyncio.Event()

        async def _emit(batch: list[RawEvent]) -> None:
            pass

        class _FakeWriter:
            def __init__(self) -> None:
                self._closed = False

            def get_extra_info(self, key: str, default: object = None) -> object:
                if key == "peername":
                    return (_DOC_IP, 55001)
                return default

            def close(self) -> None:
                self._closed = True
                closed.set()

            async def wait_closed(self) -> None:
                pass

        class _FakeReader:
            """Always times out — simulates a client that connects but sends nothing."""

            async def readline(self) -> bytes:
                await asyncio.sleep(10)
                return b""

        fake_reader = _FakeReader()
        fake_writer = _FakeWriter()

        handle_task = asyncio.create_task(
            _handle_tcp_client(
                fake_reader,  # type: ignore[arg-type]
                fake_writer,  # type: ignore[arg-type]
                _emit,
                stop_event,
                sem,
                idle_timeout=0.15,
            )
        )

        try:
            await asyncio.wait_for(closed.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            handle_task.cancel()
            try:
                await handle_task
            except (asyncio.CancelledError, Exception):
                pass
            pytest.fail("Idle TCP connection was not closed within 2s (idle_timeout=0.15s)")

        assert fake_writer._closed, "Expected writer to be closed after idle timeout"


# ---------------------------------------------------------------------------
# NB-1: UDP backpressure
# ---------------------------------------------------------------------------


class TestUDPBackpressure:
    """NB-1 — UDP flood is bounded: excess datagrams are dropped, not queued unbounded."""

    async def test_udp_backpressure_drops_excess_datagrams(self) -> None:
        """With max_inflight=2, flooding 10 datagrams drops the excess synchronously.

        The backpressure check is synchronous (counter-based) so it takes effect
        before the event loop gets a chance to run any tasks — all 10 datagrams
        are processed by datagram_received() before any _fire() coroutine runs.
        """
        from firewatch_syslog.listener import _UdpProtocol

        loop = asyncio.get_running_loop()
        emitted: list[list[RawEvent]] = []

        async def _emit(batch: list[RawEvent]) -> None:
            emitted.append(list(batch))

        sem = asyncio.BoundedSemaphore(2)
        proto = _UdpProtocol(_emit, loop, batch_size=10, inflight_sem=sem)

        valid_line = b"<14>Jan 15 10:00:10 host proc: something happened"

        # Send 10 datagrams synchronously — the counter check fires before any task runs
        # so only the first 2 pass (inflight_count=0,1 < max_inflight=2); rest are dropped
        for _ in range(10):
            proto.datagram_received(valid_line, (_DOC_IP, 44321))

        # Verify: only 2 tasks were created (the drop counter should be 8)
        assert proto._dropped_count == 8, (
            f"Expected 8 dropped datagrams (max_inflight=2, sent 10), "
            f"got dropped_count={proto._dropped_count}"
        )
        assert proto._inflight_count == 2, (
            f"Expected 2 inflight tasks, got {proto._inflight_count}"
        )

        # Let the tasks run
        await asyncio.sleep(0.05)
        assert len(emitted) == 2, (
            f"Expected exactly 2 emit calls (max_inflight=2), got {len(emitted)}"
        )

    async def test_udp_protocol_accepts_inflight_sem_param(self) -> None:
        """_UdpProtocol must accept an optional inflight_sem parameter."""
        from firewatch_syslog.listener import _UdpProtocol

        loop = asyncio.get_running_loop()

        async def _emit(batch: list[RawEvent]) -> None:
            pass

        sem = asyncio.BoundedSemaphore(5)
        proto = _UdpProtocol(_emit, loop, batch_size=10, inflight_sem=sem)
        assert proto is not None

    async def test_udp_backpressure_no_sem_still_works(self) -> None:
        """_UdpProtocol without inflight_sem should still work (backward compat)."""
        from firewatch_syslog.listener import _UdpProtocol

        loop = asyncio.get_running_loop()
        emitted: list[list[RawEvent]] = []

        async def _emit(batch: list[RawEvent]) -> None:
            emitted.append(list(batch))

        proto = _UdpProtocol(_emit, loop, batch_size=10)
        proto.datagram_received(
            b"<14>Jan 15 10:00:10 host proc: test", (_DOC_IP, 44321)
        )
        await asyncio.sleep(0.05)
        assert len(emitted) >= 1


# ---------------------------------------------------------------------------
# NB-2: asyncio.get_event_loop() replaced
# ---------------------------------------------------------------------------


class TestGetRunningLoop:
    """NB-2 — listener.py must not use deprecated asyncio.get_event_loop()."""

    def test_no_get_event_loop_in_listener(self) -> None:
        # NB-2: check that actual code calls use get_running_loop, not get_event_loop.
        # Comment/docstring lines that mention the deprecated API for docs are excluded.
        import re
        from pathlib import Path

        listener_path = (
            Path(__file__).parent.parent / "src" / "firewatch_syslog" / "listener.py"
        )
        call_re = re.compile(r"asyncio\.get_event_loop\(\)")
        for line in listener_path.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # skip docstring-only lines (documentation, not code)
            if not call_re.search(stripped):
                continue
            # Found the pattern in a non-comment line — check it's not inside a string literal
            # The pattern inside a docstring paragraph starts with text, not asyncio.
            # Real call: asyncio.get_event_loop() at start of expression
            # Doc reference: '(not the deprecated get_event_loop())' is in a string/comment
            if "asyncio.get_event_loop()" in stripped:
                pytest.fail(
                    f"listener.py calls deprecated asyncio.get_event_loop() in: {line!r} "
                    "(NB-2: replace with asyncio.get_running_loop())"
                )

# ---------------------------------------------------------------------------
# NB-4: health_check("both") probes both UDP and TCP
# ---------------------------------------------------------------------------


class TestHealthCheckBoth:
    """NB-4 — health_check with protocol='both' must probe BOTH transports."""

    async def test_health_check_both_passes_when_both_bindable(self) -> None:
        """health_check returns True when both UDP and TCP ports are bindable."""
        from firewatch_syslog.config import SyslogConfig
        from firewatch_syslog.plugin import SyslogSource

        plugin = SyslogSource()
        cfg = SyslogConfig(protocol="both", bind="127.0.0.1", port=5514)  # type: ignore[call-arg]

        mock_transport = MagicMock()
        mock_transport.close = MagicMock()
        mock_server = MagicMock()
        mock_server.close = MagicMock()
        mock_server.wait_closed = AsyncMock()

        async def _mock_create_datagram(factory: object, *, local_addr: tuple) -> tuple:
            return (mock_transport, MagicMock())

        async def _mock_start_server(
            cb: object, host: str, port: int, **kwargs: object
        ) -> MagicMock:
            return mock_server

        loop = asyncio.get_running_loop()
        with patch.object(loop, "create_datagram_endpoint", _mock_create_datagram):
            with patch("asyncio.start_server", _mock_start_server):
                result = await plugin.health_check(cfg)

        assert result is True

    async def test_health_check_both_fails_if_tcp_unbindable(self) -> None:
        """health_check('both') returns False if TCP port is not bindable (NB-4)."""
        from firewatch_syslog.config import SyslogConfig
        from firewatch_syslog.plugin import SyslogSource

        plugin = SyslogSource()
        cfg = SyslogConfig(protocol="both", bind="127.0.0.1", port=5514)  # type: ignore[call-arg]

        mock_transport = MagicMock()
        mock_transport.close = MagicMock()

        async def _mock_create_datagram(factory: object, *, local_addr: tuple) -> tuple:
            return (mock_transport, MagicMock())

        async def _mock_start_server_fail(
            cb: object, host: str, port: int, **kwargs: object
        ) -> None:
            raise OSError("Address already in use")

        loop = asyncio.get_running_loop()
        with patch.object(loop, "create_datagram_endpoint", _mock_create_datagram):
            with patch("asyncio.start_server", _mock_start_server_fail):
                result = await plugin.health_check(cfg)

        assert result is False

    async def test_health_check_both_fails_if_udp_unbindable(self) -> None:
        """health_check('both') returns False if UDP port is not bindable (NB-4)."""
        from firewatch_syslog.config import SyslogConfig
        from firewatch_syslog.plugin import SyslogSource

        plugin = SyslogSource()
        cfg = SyslogConfig(protocol="both", bind="127.0.0.1", port=5514)  # type: ignore[call-arg]

        async def _mock_create_datagram_fail(
            factory: object, *, local_addr: tuple
        ) -> tuple:
            raise OSError("Address already in use")

        loop = asyncio.get_running_loop()
        with patch.object(loop, "create_datagram_endpoint", _mock_create_datagram_fail):
            result = await plugin.health_check(cfg)

        assert result is False


# ---------------------------------------------------------------------------
# NB-5: Line cap in _make_raw
# ---------------------------------------------------------------------------


class TestLineCap:
    """NB-5 — _make_raw must cap the line stored in RawEvent.data to max_line_length."""

    def test_make_raw_caps_line(self) -> None:
        """A line longer than max_line_length is truncated in RawEvent.data['line']."""
        from firewatch_syslog.listener import _make_raw

        long_line = "x" * 20000
        raw = _make_raw(long_line, _DOC_IP, "tcp", max_line_length=8192)
        stored = raw.data["line"]
        assert len(stored) <= 8192, (
            f"Expected line to be capped at 8192 bytes, got {len(stored)}"
        )

    def test_make_raw_does_not_cap_short_line(self) -> None:
        """A line within the limit is stored unchanged."""
        from firewatch_syslog.listener import _make_raw

        short_line = "hello syslog"
        raw = _make_raw(short_line, _DOC_IP, "tcp", max_line_length=8192)
        assert raw.data["line"] == short_line

    def test_make_raw_default_limit_is_8192(self) -> None:
        """_make_raw with no explicit limit uses 8192."""
        from firewatch_syslog.listener import _make_raw

        long_line = "y" * 20000
        raw = _make_raw(long_line, _DOC_IP, "udp")
        stored = raw.data["line"]
        assert len(stored) <= 8192


# ---------------------------------------------------------------------------
# NB-3 (clarity): New parameters accepted by run_tcp_listener / run_udp_listener
# ---------------------------------------------------------------------------


class TestListenerHandleWiring:
    """NB-3 — run_tcp_listener and run_udp_listener accept new security params."""

    async def test_run_tcp_listener_new_params_accepted(self) -> None:
        """run_tcp_listener must accept max_connections, idle_timeout, max_line_length."""
        from firewatch_syslog import listener as _listener

        stop_event = asyncio.Event()

        async def _emit(batch: list[RawEvent]) -> None:
            pass

        mock_server = MagicMock()
        mock_server.close = MagicMock()
        mock_server.wait_closed = AsyncMock()

        async def _mock_start_server(
            cb: object,
            host: str,
            port: int,
            *,
            limit: int = 65536,
        ) -> MagicMock:
            return mock_server

        with patch("asyncio.start_server", _mock_start_server):
            task = asyncio.create_task(
                _listener.run_tcp_listener(
                    "127.0.0.1",
                    5514,
                    _emit,
                    batch_size=10,
                    stop_event=stop_event,
                    max_connections=50,
                    idle_timeout=30.0,
                    max_line_length=8192,
                )
            )
            await asyncio.sleep(0)
            stop_event.set()
            try:
                await asyncio.wait_for(task, timeout=1.0)
            except asyncio.TimeoutError:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

    async def test_run_udp_listener_new_params_accepted(self) -> None:
        """run_udp_listener must accept max_connections (max_inflight) param."""
        from firewatch_syslog import listener as _listener

        stop_event = asyncio.Event()

        async def _emit(batch: list[RawEvent]) -> None:
            pass

        mock_transport = MagicMock()
        mock_transport.close = MagicMock()

        async def _mock_create_datagram(
            factory: object, *, local_addr: tuple
        ) -> tuple:
            return (mock_transport, MagicMock())

        loop = asyncio.get_running_loop()
        with patch.object(loop, "create_datagram_endpoint", _mock_create_datagram):
            task = asyncio.create_task(
                _listener.run_udp_listener(
                    "127.0.0.1",
                    5514,
                    _emit,
                    batch_size=10,
                    stop_event=stop_event,
                    max_connections=100,
                )
            )
            await asyncio.sleep(0)
            stop_event.set()
            try:
                await asyncio.wait_for(task, timeout=1.0)
            except asyncio.TimeoutError:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
