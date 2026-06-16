"""Reference plugin implementations used as a typing oracle.

These concrete classes structurally implement the SDK port Protocols. They exist so
`uv run pyright` proves the Protocols are actually implementable (EARS-6) and so the
tests can introspect a real `start`/`collect` signature (EARS-4). They are NOT a real
source plugin — no I/O, no logic.
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timezone

from pydantic import BaseModel

from firewatch_sdk import (
    PluginContext,
    PullSource,
    PushSource,
    RawEvent,
    SecurityEvent,
    SourceMetadata,
    SourcePlugin,
)


class _RefConfig(BaseModel):
    host: str = "localhost"


class ReferencePullPlugin:
    """A SourcePlugin + PullSource, like the canonical Suricata reference."""

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key="reference",
            display_name="Reference",
            version="0.1.0",
            flavor="pull",
        )

    def config_schema(self) -> type[BaseModel]:
        return _RefConfig

    def validate_config(self, cfg: dict) -> None:
        _RefConfig.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        return SecurityEvent(
            source_type=raw.source_type,
            source_id=source_id,
            timestamp=raw.received_at,
            source_ip=str(raw.data.get("src_ip", "0.0.0.0")),
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True

    async def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]:
        yield RawEvent(
            source_type="reference",
            received_at=datetime.now(timezone.utc),
            data={"src_ip": "203.0.113.5"},
        )


class ReferencePushPlugin:
    """A PushSource — listener flavor with batch emit (Flag C)."""

    async def start(
        self,
        cfg: BaseModel,
        emit: Callable[[list[RawEvent]], Awaitable[None]],
        ctx: PluginContext,
    ) -> None:
        await emit(
            [
                RawEvent(
                    source_type="reference",
                    received_at=datetime.now(timezone.utc),
                    data={},
                )
            ]
        )

    async def stop(self) -> None:
        return None


# Structural conformance assertions — pyright fails here if a Protocol drifts.
_plugin: SourcePlugin = ReferencePullPlugin()
_pull: PullSource = ReferencePullPlugin()
_push: PushSource = ReferencePushPlugin()
