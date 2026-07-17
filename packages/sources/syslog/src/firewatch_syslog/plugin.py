"""SyslogSource — the canonical FireWatch PushSource reference plugin.

Registered as ``syslog`` under the ``firewatch.sources`` entry-point group.
Adding this package to the workspace requires zero edits to firewatch-core
(PLUGIN_CONTRACT.md modularity guarantee).

This module implements:
  - ``SourcePlugin`` (metadata, config_schema, validate_config, normalize, health_check)
  - ``PushSource`` (start, stop)

It depends on ``firewatch-sdk`` ONLY. Never imports firewatch-core or legacy/.

Listener lifecycle:
  ``start(cfg, emit)`` spawns UDP/TCP listener tasks (depending on cfg.protocol)
  and awaits the internal stop event. ``stop()`` sets the stop event, which causes
  all listener tasks to exit cleanly and their transports/servers to be closed.

  This matches the PushSource protocol from firewatch-sdk ports.py:
    async def start(self, cfg, emit) -> None   # runs the listener loop
    async def stop(self) -> None               # releases sockets

Security hardening (delegated to listener / config):
  - BLOCKING-1: max_connections, idle_timeout, max_line_length passed through to
    run_tcp_listener and run_udp_listener.
  - BLOCKING-2: bind field_validator in SyslogConfig rejects non-IP-literal values.
  - NB-4: health_check with protocol='both' probes BOTH UDP and TCP ports.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel

from firewatch_sdk import PluginContext, RawEvent, SecurityEvent, SourceMetadata

from firewatch_syslog import listener as _listener
from firewatch_syslog import normalize as _normalize
from firewatch_syslog.config import SyslogConfig

logger = logging.getLogger("firewatch.syslog.plugin")

_VERSION = "0.1.0"
_TYPE_KEY = "syslog"


class SyslogSource:
    """Syslog UDP/TCP source plugin.

    Implements ``SourcePlugin`` + ``PushSource`` from firewatch-sdk.

    Listens on UDP, TCP, or both for RFC 3164 / RFC 5424 syslog messages.
    Default port: 5514 (unprivileged). Default bind: 127.0.0.1 (loopback —
    safe default; operators set FIREWATCH_SYSLOG_BIND=0.0.0.0 to accept remote).

    Normalization (ADR-0012, ADR-0014, ADR-0016, ADR-0020):
      - ``source_type`` is the constant ``"syslog"`` — never branches on ``source_id``.
      - SSH brute-force → ALERT; SSH login → LOG; generic → LOG (ADR-0012 Flag A).
      - MITRE T1110/TA0006 for SSH brute-force (ADR-0014).
      - OCSF class_uid=3002 (Authentication) for auth events; class_uid=0 (Base
        Event) for the unclassified fallback (OCSF 1.8.0, issue #76 — see
        ``normalize.py`` module docstring for citations).
    """

    def __init__(self) -> None:
        self._syslog_listener = _listener.SyslogListener()
        self._stop_event: asyncio.Event = asyncio.Event()

    # ── SourcePlugin methods ─────────────────────────────────────────────────

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=_TYPE_KEY,
            display_name="Syslog UDP/TCP",
            version=_VERSION,
            flavor="push",
            # ADR-0067 D6 (issue #75): declared enforcement-posture default. A syslog
            # receiver is a passive telemetry collector — it cannot block anything it
            # forwards (ADR-0067 D6: "not blocked by this control — watch-only sensor").
            enforcement="observe",
        )

    def config_schema(self) -> type[BaseModel]:
        """Return the Pydantic model that drives the rjsf UI source card.

        Fields: bind, port, protocol (udp|tcp|both), batch_size, max_connections,
        idle_timeout, max_line_length.
        Config resolution respects env > file > default (ADR-0006); use
        ``build_config()`` at runtime to construct the instance.
        """
        return SyslogConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        """Validate a raw config dict against the Syslog config schema.

        Raises ``pydantic.ValidationError`` if the config is invalid.
        """
        SyslogConfig.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        """Map a syslog RawEvent to a SecurityEvent.

        ``source_type`` is always ``"syslog"`` (this plugin's constant).
        ``source_id`` is the caller's instance name, passed through as-is.
        This method MUST NOT branch on ``source_id`` (Flag B, PLUGIN_CONTRACT.md).
        """
        return _normalize.normalize(raw, source_id)

    async def health_check(self, cfg: BaseModel) -> bool:
        """Return True if the listener configuration is valid and ports are bindable.

        For a PushSource, 'health' means the config is valid and the port(s) are
        bindable (quick bind test). Returns False (never raises) on any failure.

        NB-4: When protocol='both', BOTH the UDP and TCP ports are probed. If either
        fails to bind, health_check returns False.
        """
        try:
            syslog_cfg = (
                cfg
                if isinstance(cfg, SyslogConfig)
                else SyslogConfig.model_validate(cfg.model_dump())
            )
        except Exception:
            return False

        loop = asyncio.get_running_loop()

        # Quick bind test: try to bind each enabled transport and immediately release.
        try:
            if syslog_cfg.protocol in ("udp", "both"):
                transport, _ = await loop.create_datagram_endpoint(
                    asyncio.DatagramProtocol,
                    local_addr=(syslog_cfg.bind, syslog_cfg.port),
                )
                transport.close()

            if syslog_cfg.protocol in ("tcp", "both"):
                server = await asyncio.start_server(
                    lambda r, w: asyncio.sleep(0),
                    syslog_cfg.bind,
                    syslog_cfg.port,
                )
                server.close()
                await server.wait_closed()

            return True
        except Exception:
            return False

    # ── PushSource methods ───────────────────────────────────────────────────

    async def start(
        self,
        cfg: BaseModel,
        emit: Callable[[list[RawEvent]], Awaitable[None]],
        ctx: PluginContext,
    ) -> None:
        """Bind the syslog listener(s) and run until stop() is called.

        Launches UDP and/or TCP listener tasks depending on ``cfg.protocol``.
        Each task feeds received lines to ``emit(list[RawEvent])``.

        Guarantees (PLUGIN_CONTRACT.md hard rules):
          - Cancellable: asyncio.CancelledError propagates cleanly.
          - Never raises out of the loop: malformed/undecodable lines are dropped.
          - ``stop()`` releases all sockets.

        Security parameters (BLOCKING-1) are passed through from cfg to the listener
        functions: max_connections, idle_timeout, max_line_length.

        ``ctx`` is the per-instance capability carrier (ADR-0027). ``ctx.kv`` is
        available for scoped state; ``ctx.source_id`` is for labelling only.
        Neither is used by this plugin yet — this is pure signature threading.
        """
        syslog_cfg = (
            cfg
            if isinstance(cfg, SyslogConfig)
            else SyslogConfig.model_validate(cfg.model_dump())
        )

        # Reset stop event in case start() is called after a prior stop()
        self._stop_event = asyncio.Event()
        self._syslog_listener._stop_event = self._stop_event

        tasks: list[asyncio.Task[None]] = []

        if syslog_cfg.protocol in ("udp", "both"):
            tasks.append(
                asyncio.create_task(
                    _listener.run_udp_listener(
                        syslog_cfg.bind,
                        syslog_cfg.port,
                        emit,
                        batch_size=min(syslog_cfg.batch_size, _listener.MAX_BATCH_SIZE),
                        stop_event=self._stop_event,
                        max_connections=syslog_cfg.max_connections,
                        max_line_length=syslog_cfg.max_line_length,
                    ),
                    name="syslog-udp",
                )
            )

        if syslog_cfg.protocol in ("tcp", "both"):
            tasks.append(
                asyncio.create_task(
                    _listener.run_tcp_listener(
                        syslog_cfg.bind,
                        syslog_cfg.port,
                        emit,
                        batch_size=min(syslog_cfg.batch_size, _listener.MAX_BATCH_SIZE),
                        stop_event=self._stop_event,
                        max_connections=syslog_cfg.max_connections,
                        idle_timeout=syslog_cfg.idle_timeout,
                        max_line_length=syslog_cfg.max_line_length,
                    ),
                    name="syslog-tcp",
                )
            )

        if not tasks:
            logger.warning("SyslogSource.start(): no tasks started (protocol=%s)", syslog_cfg.protocol)
            await self._stop_event.wait()
            return

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()
            raise
        except Exception:
            logger.error("SyslogSource listener error", exc_info=True)

    async def stop(self) -> None:
        """Signal the listener(s) to exit and release sockets.

        Safe to call before start(), or multiple times. After stop() returns,
        no further input is accepted (PLUGIN_CONTRACT.md / EARS-5).
        """
        self._stop_event.set()
        await self._syslog_listener.stop()
