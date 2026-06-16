"""SyslogCefSource -- Generic Syslog/CEF receiver PushSource plugin.

Registered as 'syslog_cef' under the 'firewatch.sources' entry-point group.
Adding this package requires zero edits to firewatch-core (PLUGIN_CONTRACT.md
modularity guarantee).

Implements:
  - SourcePlugin (metadata, config_schema, validate_config, normalize, health_check)
  - PushSource  (start, stop)

Depends on firewatch-sdk ONLY. Never imports firewatch-core or legacy/.

Listener lifecycle:
  start(cfg, emit, ctx) spawns UDP/TCP listener tasks using the shared
  firewatch_syslog listener substrate (no code duplication -- ADR-0030).
  stop() sets the stop event, releasing all sockets cleanly.

Standards cited:
  - ArcSight CEF Implementation Standard
  - RFC 5424 https://datatracker.ietf.org/doc/html/rfc5424
  - RFC 3164 https://datatracker.ietf.org/doc/html/rfc3164
  - OCSF https://schema.ocsf.io
  - ADR-0012 (action semantics), ADR-0014 (MITRE), ADR-0020 (OCSF),
    ADR-0023 (backpressure), ADR-0027 (PluginContext)
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel

from firewatch_sdk import PluginContext, RawEvent, SecurityEvent, SourceMetadata

from firewatch_syslog_cef import normalize as _normalize
from firewatch_syslog_cef.config import SyslogCefConfig
from firewatch_syslog_cef.listener import MAX_BATCH_SIZE
from firewatch_syslog_cef.listener import run_tcp_listener as _run_tcp
from firewatch_syslog_cef.listener import run_udp_listener as _run_udp

logger = logging.getLogger("firewatch.syslog_cef.plugin")

_VERSION = "0.1.0"
_TYPE_KEY = "syslog_cef"


class SyslogCefSource:
    """Generic Syslog/CEF receiver -- vendor-agnostic CEF->OCSF PushSource.

    Listens on UDP, TCP, or both for RFC 3164 / RFC 5424 syslog messages
    and ArcSight CEF (Common Event Format) events from any vendor.

    Normalization (PLUGIN_CONTRACT.md, ADR-0012/0014/0020):
      - source_type is the constant 'syslog_cef' -- never branches on source_id.
      - CEF 'act' token -> action via vendor registry (Flag B: routes on
        payload DeviceVendor, not on source_id).
      - RFC 5424 / RFC 3164 fallback for non-CEF syslog lines (SSH brute-force
        -> ALERT/T1110/TA0006; generic -> LOG).
      - CEF severity (0-10) banded to canonical levels per ArcSight CEF spec.
    """

    def __init__(self) -> None:
        self._stop_event: asyncio.Event = asyncio.Event()

    # ── SourcePlugin ─────────────────────────────────────────────────────────

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=_TYPE_KEY,
            display_name="Syslog/CEF Receiver (Generic)",
            version=_VERSION,
            flavor="push",
        )

    def config_schema(self) -> type[BaseModel]:
        """Return the Pydantic model driving the rjsf UI source card."""
        return SyslogCefConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        """Validate a raw config dict. Raises pydantic.ValidationError if invalid."""
        SyslogCefConfig.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        """Map a RawEvent to a SecurityEvent.

        source_type is always 'syslog_cef' (constant).
        source_id is the caller's instance name, passed through as-is.
        MUST NOT branch on source_id (Flag B, PLUGIN_CONTRACT.md).
        """
        return _normalize.normalize(raw, source_id)

    async def health_check(self, cfg: BaseModel) -> bool:
        """Return True if the listener configuration is valid and ports are bindable."""
        try:
            cef_cfg = (
                cfg
                if isinstance(cfg, SyslogCefConfig)
                else SyslogCefConfig.model_validate(cfg.model_dump())
            )
        except Exception:
            return False

        loop = asyncio.get_running_loop()
        try:
            if cef_cfg.protocol in ("udp", "both"):
                transport, _ = await loop.create_datagram_endpoint(
                    asyncio.DatagramProtocol,
                    local_addr=(cef_cfg.bind, cef_cfg.port),
                )
                transport.close()

            if cef_cfg.protocol in ("tcp", "both"):
                server = await asyncio.start_server(
                    lambda r, w: asyncio.sleep(0),
                    cef_cfg.bind,
                    cef_cfg.port,
                )
                server.close()
                await server.wait_closed()

            return True
        except Exception:
            return False

    # ── PushSource ───────────────────────────────────────────────────────────

    async def start(
        self,
        cfg: BaseModel,
        emit: Callable[[list[RawEvent]], Awaitable[None]],
        ctx: PluginContext,
    ) -> None:
        """Bind the syslog/CEF listener(s) and run until stop() is called.

        Uses the shared firewatch_syslog listener substrate (ADR-0030).
        Backpressure per ADR-0023: UDP drop+counter; TCP block.
        ctx.kv is available for plugin-scoped state (ADR-0025/0027).
        ctx.source_id is for logging only -- never branched on.
        """
        cef_cfg = (
            cfg
            if isinstance(cfg, SyslogCefConfig)
            else SyslogCefConfig.model_validate(cfg.model_dump())
        )

        # Reset stop event for re-use after a prior stop().
        self._stop_event = asyncio.Event()

        tasks: list[asyncio.Task[None]] = []
        effective_batch = min(cef_cfg.batch_size, MAX_BATCH_SIZE)

        if cef_cfg.protocol in ("udp", "both"):
            tasks.append(
                asyncio.create_task(
                    _run_udp(
                        cef_cfg.bind,
                        cef_cfg.port,
                        emit,
                        batch_size=effective_batch,
                        stop_event=self._stop_event,
                        max_connections=cef_cfg.max_connections,
                        max_line_length=cef_cfg.max_line_length,
                    ),
                    name="syslog_cef-udp",
                )
            )

        if cef_cfg.protocol in ("tcp", "both"):
            tasks.append(
                asyncio.create_task(
                    _run_tcp(
                        cef_cfg.bind,
                        cef_cfg.port,
                        emit,
                        batch_size=effective_batch,
                        stop_event=self._stop_event,
                        max_connections=cef_cfg.max_connections,
                        idle_timeout=cef_cfg.idle_timeout,
                        max_line_length=cef_cfg.max_line_length,
                    ),
                    name="syslog_cef-tcp",
                )
            )

        if not tasks:
            logger.warning(
                "SyslogCefSource.start(): no tasks started (protocol=%s)", cef_cfg.protocol
            )
            await self._stop_event.wait()
            return

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()
            raise
        except Exception:
            logger.error("SyslogCefSource listener error", exc_info=True)

    async def stop(self) -> None:
        """Signal all listener tasks to exit and release sockets."""
        self._stop_event.set()
