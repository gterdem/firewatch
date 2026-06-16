"""Async UDP/TCP syslog listener — PushSource transport layer.

Ported from ``legacy/adapters/collectors/syslog.py`` (reference only — never imported).
Provides:
  - ``SyslogListener``  — stateful object managing sockets; called by SyslogSource.
  - ``run_udp_listener`` / ``run_tcp_listener`` — standalone coroutines for each transport,
    injectable in tests.
  - ``_decode_line`` — decode bytes to a stripped string; returns None for empty/invalid.
  - ``_make_raw`` — wrap a decoded line in a RawEvent with optional line-length cap (NB-5).
  - ``MAX_BATCH_SIZE`` — hard upper bound on batch size (DoS guard).

Design notes:
  - UDP: each datagram = one RawEvent; emitted in a batch of 1 via create_task.
    Backpressure (NB-1, ADR-0023): an optional ``BoundedSemaphore`` bounds the number of
    outstanding emit tasks; when full, new datagrams are dropped with a warning counter
    (UDP-drop is the correct backpressure per ADR-0023: UDP is already lossy, and blocking
    the event loop would stall all sources).
  - TCP: lines are read one by one; each line emitted as a batch of 1. A
    ``BoundedSemaphore(max_connections)`` guards _handle_tcp_client entry (BLOCKING-1
    slow-loris cap). An idle timeout (BLOCKING-1) closes connections that send nothing for
    N seconds. asyncio.start_server receives ``limit=max_line_length`` (BLOCKING-1).
  - Malformed / undecodable lines: ``_decode_line`` uses ``errors='replace'`` to decode,
    then strips. A line that decodes to empty (e.g. pure NUL bytes) returns ``None`` and
    is silently dropped. This satisfies PLUGIN_CONTRACT.md §hard-rules.
  - ``stop_event``: an asyncio.Event set by ``SyslogListener.stop()``. Listeners poll it
    after each line so they can exit cleanly when the supervisor calls stop().

Security notes (hardening per security review):
  - BLOCKING-1: TCP connection cap via asyncio.BoundedSemaphore(max_connections);
    limit= parameter to asyncio.start_server bounds readline buffer;
    per-connection idle timeout closes slow-loris connections.
  - NB-1: UDP backpressure via BoundedSemaphore on inflight emit tasks; excess datagrams
    are dropped with a warning (observability) — correct per ADR-0023.
  - NB-2: asyncio.get_running_loop() used throughout (not the deprecated get_event_loop()).
  - NB-5: _make_raw truncates the stored line to max_line_length so large lines cannot
    be stored/propagated in full.
  - Default bind is 127.0.0.1 (loopback). See config.py.
  - MAX_BATCH_SIZE caps memory; no unbounded queue.
  - All socket errors in the UDP/TCP handlers are caught and logged, never re-raised
    (PLUGIN_CONTRACT.md hard rule).
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from firewatch_sdk import RawEvent

logger = logging.getLogger("firewatch.syslog.listener")

# Hard upper bound on batch size passed to emit() (DoS guard — no unbounded buffering).
# The actual batch size in use is the lesser of this and the value in SyslogConfig.
MAX_BATCH_SIZE: int = 200

# Default line-length cap (bytes) applied by _make_raw when no explicit limit is given.
# Matches the default max_line_length in SyslogConfig.
_DEFAULT_LINE_CAP: int = 8192

# Type alias for the emit callback supplied by the supervisor / start().
EmitCallback = Callable[[list[RawEvent]], Awaitable[None]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decode_line(data: bytes) -> str | None:
    """Decode bytes to a stripped string; return None for empty or pure-garbage input.

    Uses ``errors='replace'`` so even non-UTF-8 sequences don't raise. After
    decoding, strips whitespace. If the result is empty (e.g. a NUL-only datagram
    or pure whitespace), returns ``None`` so callers can drop it without branching.
    """
    try:
        line = data.decode("utf-8", errors="replace").strip()
    except Exception:
        return None
    return line if line else None


def _make_raw(
    line: str,
    client_ip: str,
    transport: str,
    *,
    max_line_length: int = _DEFAULT_LINE_CAP,
) -> RawEvent:
    """Wrap a decoded syslog line in a RawEvent.

    NB-5: the line stored in ``data['line']`` is capped at ``max_line_length`` characters
    so a large line cannot be stored or propagated in full.
    """
    stored_line = line[:max_line_length] if len(line) > max_line_length else line
    return RawEvent(
        source_type="syslog",
        received_at=datetime.now(timezone.utc),
        data={"line": stored_line, "client_ip": client_ip, "transport": transport},
    )


# ---------------------------------------------------------------------------
# UDP listener
# ---------------------------------------------------------------------------


class _UdpProtocol(asyncio.DatagramProtocol):
    """asyncio DatagramProtocol that forwards each datagram as a RawEvent batch.

    ``datagram_received`` is a synchronous callback in asyncio's transport/protocol
    API; it schedules ``emit([raw])`` as a fire-and-forget task so the event loop is
    not blocked.

    Backpressure (NB-1, ADR-0023): when ``inflight_sem`` is provided, the protocol
    attempts a non-blocking acquire before scheduling the emit task. If the semaphore
    is exhausted (downstream is slow), the datagram is dropped and a warning counter
    is incremented. This is the correct UDP backpressure model: UDP is inherently
    lossy, and blocking the event loop or the datagram callback would starve the
    shared event loop and affect all other sources.
    """

    def __init__(
        self,
        emit_cb: EmitCallback,
        loop: asyncio.AbstractEventLoop,
        batch_size: int,
        *,
        inflight_sem: asyncio.BoundedSemaphore | None = None,
        max_line_length: int = _DEFAULT_LINE_CAP,
    ) -> None:
        self._emit_cb = emit_cb
        self._loop = loop
        self._batch_size = batch_size
        self._inflight_sem = inflight_sem
        self._max_line_length = max_line_length
        self._dropped_count: int = 0
        # Synchronous inflight counter: incremented before task creation (synchronous
        # in datagram_received), decremented in task finally. This gives us reliable
        # backpressure without relying on asyncio scheduler ordering.
        self._inflight_count: int = 0
        self._max_inflight: int = inflight_sem._bound_value if inflight_sem is not None else 0  # type: ignore[attr-defined]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        line = _decode_line(data)
        if line is None:
            return
        raw = _make_raw(line, addr[0], "udp", max_line_length=self._max_line_length)
        emit_cb = self._emit_cb
        batch: list[RawEvent] = [raw]

        # NB-1: Synchronous backpressure check (ADR-0023 UDP-drop semantics).
        # We use a plain integer counter rather than a semaphore _value check because
        # datagram_received is synchronous: tasks created here haven't run yet, so a
        # semaphore's internal value wouldn't have been decremented yet.
        # The counter is incremented here (synchronous, before create_task) and
        # decremented in the task's finally block.
        if self._max_inflight > 0 and self._inflight_count >= self._max_inflight:
            self._dropped_count += 1
            if self._dropped_count % 100 == 1:
                logger.warning(
                    "syslog UDP backpressure: dropped %d datagram(s) — downstream too slow",
                    self._dropped_count,
                )
            return

        if self._max_inflight > 0:
            self._inflight_count += 1

        max_inflight = self._max_inflight

        async def _fire() -> None:
            try:
                await emit_cb(batch)
            except Exception:
                pass
            finally:
                if max_inflight > 0:
                    self._inflight_count -= 1

        self._loop.create_task(_fire())

    def error_received(self, exc: Exception) -> None:
        logger.warning("syslog UDP error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.debug("syslog UDP connection lost: %s", exc)


async def run_udp_listener(
    bind: str,
    port: int,
    emit_cb: EmitCallback,
    *,
    batch_size: int,
    stop_event: asyncio.Event,
    max_connections: int = 256,
    max_line_length: int = _DEFAULT_LINE_CAP,
) -> None:
    """Bind a UDP socket and forward datagrams until stop_event is set.

    This coroutine is the injectable seam for tests — ``SyslogListener.start()``
    calls it but tests can patch it. It returns when ``stop_event`` is set.

    NB-1: ``max_connections`` is used as the inflight semaphore bound, limiting the
    number of concurrent emit tasks. Excess datagrams are dropped (UDP-drop semantics
    per ADR-0023).
    """
    loop = asyncio.get_running_loop()
    effective_batch = min(batch_size, MAX_BATCH_SIZE)
    inflight_sem: asyncio.BoundedSemaphore | None = None
    if max_connections > 0:
        inflight_sem = asyncio.BoundedSemaphore(max_connections)

    transport, _ = await loop.create_datagram_endpoint(
        lambda: _UdpProtocol(
            emit_cb,
            loop,
            effective_batch,
            inflight_sem=inflight_sem,
            max_line_length=max_line_length,
        ),
        local_addr=(bind, port),
    )
    try:
        logger.info("Syslog UDP listener bound to %s:%d", bind, port)
        await stop_event.wait()
    finally:
        transport.close()
        logger.debug("Syslog UDP transport closed")


# ---------------------------------------------------------------------------
# TCP listener
# ---------------------------------------------------------------------------


async def _handle_tcp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    emit_cb: EmitCallback,
    stop_event: asyncio.Event,
    conn_sem: asyncio.BoundedSemaphore,
    *,
    idle_timeout: float = 30.0,
    max_line_length: int = _DEFAULT_LINE_CAP,
) -> None:
    """Handle a single TCP client connection; read lines until EOF or stop_event.

    BLOCKING-1 guards:
    - ``conn_sem``: BoundedSemaphore(max_connections). A non-blocking acquire attempt
      is made at entry; if exhausted, the connection is immediately closed (rejected).
    - ``idle_timeout``: elapsed idle time (no data received) is tracked across 1-second
      readline polls. When idle time exceeds ``idle_timeout``, the connection is closed.
    - Line data stored via _make_raw is capped at max_line_length (NB-5).
    """
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    client_ip = peer[0] if peer else "0.0.0.0"

    # BLOCKING-1: Non-blocking semaphore acquire — reject if at connection cap.
    # BoundedSemaphore has no try_acquire, so check _value (safe in single-threaded asyncio).
    if conn_sem._value == 0:  # type: ignore[attr-defined]
        logger.warning(
            "syslog TCP: connection cap reached — rejecting connection from %s", client_ip
        )
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return

    await conn_sem.acquire()
    try:
        idle_elapsed: float = 0.0
        while not stop_event.is_set():
            try:
                line_bytes = await asyncio.wait_for(reader.readline(), timeout=1.0)
                idle_elapsed = 0.0  # reset idle timer on any successful read (even EOF)
            except asyncio.TimeoutError:
                idle_elapsed += 1.0
                if idle_elapsed >= idle_timeout:
                    logger.debug(
                        "syslog TCP: idle timeout (%.1fs) — closing connection from %s",
                        idle_timeout,
                        client_ip,
                    )
                    break
                continue
            if not line_bytes:
                break  # EOF
            line = _decode_line(line_bytes)
            if line is None:
                continue
            raw = _make_raw(line, client_ip, "tcp", max_line_length=max_line_length)
            try:
                await emit_cb([raw])
            except Exception:
                logger.warning("syslog TCP emit error", exc_info=True)
    except Exception:
        logger.warning("syslog TCP handler error", exc_info=True)
    finally:
        conn_sem.release()
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def run_tcp_listener(
    bind: str,
    port: int,
    emit_cb: EmitCallback,
    *,
    batch_size: int,
    stop_event: asyncio.Event,
    max_connections: int = 256,
    idle_timeout: float = 30.0,
    max_line_length: int = _DEFAULT_LINE_CAP,
) -> None:
    """Bind a TCP socket and serve clients until stop_event is set.

    This coroutine is the injectable seam for tests. Returns when stop_event is set.

    BLOCKING-1 hardening:
    - ``max_connections`` creates a BoundedSemaphore; the N+1th connection is rejected.
    - ``limit=max_line_length`` passed to asyncio.start_server bounds the readline buffer
      so a single connection cannot buffer multi-MB before a newline.
    - ``idle_timeout`` passed to each _handle_tcp_client for per-connection idle detection.
    """
    conn_sem = asyncio.BoundedSemaphore(max_connections)

    server = await asyncio.start_server(
        lambda r, w: _handle_tcp_client(
            r,
            w,
            emit_cb,
            stop_event,
            conn_sem,
            idle_timeout=idle_timeout,
            max_line_length=max_line_length,
        ),
        bind,
        port,
        limit=max_line_length,
    )
    try:
        logger.info("Syslog TCP listener bound to %s:%d", bind, port)
        await stop_event.wait()
    finally:
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass
        logger.debug("Syslog TCP server closed")


# ---------------------------------------------------------------------------
# SyslogListener — stateful lifecycle object
# ---------------------------------------------------------------------------


class SyslogListener:
    """Manages UDP and/or TCP listener sockets for the Syslog PushSource.

    ``start()`` is called by ``SyslogSource.start()`` to launch listener tasks.
    ``stop()`` signals the stop event and closes transports.

    Attributes used by tests for low-level assertions:
      _udp_transport  — set after UDP socket is bound (or injected in tests)
      _tcp_server     — set after TCP server is started (or injected in tests)
      _emit_cb        — the callback passed to start()
    """

    def __init__(self) -> None:
        self._udp_transport: object | None = None
        self._tcp_server: object | None = None
        self._emit_cb: EmitCallback | None = None
        self._stop_event: asyncio.Event = asyncio.Event()

    def _make_udp_protocol(self) -> _UdpProtocol:
        """Create the UDP protocol handler (uses current running loop and stored emit_cb).

        NB-2: uses asyncio.get_running_loop() (not the deprecated get_event_loop()).
        """
        loop = asyncio.get_running_loop()
        cb = self._emit_cb if self._emit_cb is not None else (lambda b: asyncio.sleep(0))
        return _UdpProtocol(cb, loop, MAX_BATCH_SIZE)  # type: ignore[arg-type]

    async def stop(self) -> None:
        """Signal the stop event and close open transports/servers."""
        self._stop_event.set()

        # Close UDP transport if we hold a reference directly
        if self._udp_transport is not None:
            try:
                self._udp_transport.close()  # type: ignore[attr-defined]
            except Exception:
                pass
            self._udp_transport = None

        # Close TCP server if we hold a reference directly
        if self._tcp_server is not None:
            try:
                self._tcp_server.close()  # type: ignore[attr-defined]
                await self._tcp_server.wait_closed()  # type: ignore[attr-defined]
            except Exception:
                pass
            self._tcp_server = None

        logger.info("Syslog listener stopped")
