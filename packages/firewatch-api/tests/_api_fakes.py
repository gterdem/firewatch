"""Fake plugins for firewatch-api tests.

These fakes avoid importing any concrete plugin package (suricata, syslog),
satisfying the ubiquitous EARS criterion: the API must never import a concrete
plugin.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from firewatch_sdk import RawEvent, SecurityEvent, SourceMetadata


class _FakePullConfig(BaseModel):
    """Minimal config schema for a fake pull plugin."""

    host: str = "192.0.2.1"
    port: int = 22


class _FakePushConfig(BaseModel):
    """Minimal config schema for a fake push plugin."""

    listen_address: str = "127.0.0.1"
    listen_port: int = 514


class FakePullPlugin:
    """Fake PullSource plugin (suricata-like) — no concrete dependency.

    ``normalize_ip`` controls the ``source_ip`` produced by ``normalize()``.
    Tests that need a specific IP inject it here; callers that don't care
    receive the default RFC 5737 address.
    """

    def __init__(
        self,
        type_key: str = "suricata",
        normalize_ip: str = "203.0.113.1",
    ) -> None:
        self._type_key = type_key
        self._normalize_ip = normalize_ip

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name="Fake Pull Source",
            version="1.2.3",
            flavor="pull",
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakePullConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _FakePullConfig.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        return SecurityEvent(
            source_type=self._type_key,
            source_id=source_id,
            timestamp=raw.received_at,
            source_ip=self._normalize_ip,
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True


class FakePushPlugin:
    """Fake PushSource plugin (syslog-like) — no concrete dependency."""

    def __init__(self, type_key: str = "syslog") -> None:
        self._type_key = type_key

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name="Fake Push Source",
            version="0.9.0",
            flavor="push",
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakePushConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _FakePushConfig.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        return SecurityEvent(
            source_type=self._type_key,
            source_id=source_id,
            timestamp=raw.received_at,
            source_ip="203.0.113.2",
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True


class FakePullPluginWithProduces:
    """Fake PullSource plugin that declares a non-empty produces set (ADR-0060)."""

    def __init__(
        self,
        type_key: str = "suricata",
        produces: frozenset[str] = frozenset({"source_ip", "protocol", "destination_ip"}),
    ) -> None:
        self._type_key = type_key
        self._produces = produces

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name="Fake Producing Pull Source",
            version="1.0.0",
            flavor="pull",
            produces=self._produces,
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakePullConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _FakePullConfig.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        return SecurityEvent(
            source_type=self._type_key,
            source_id=source_id,
            timestamp=raw.received_at,
            source_ip="203.0.113.1",
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True


class FailingPlugin:
    """Fake plugin whose ``normalize()`` always raises ValueError — for fault-path tests."""

    def __init__(self, type_key: str = "broken") -> None:
        self._type_key = type_key

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name="Broken Plugin",
            version="0.0.1",
            flavor="pull",
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakePullConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        pass

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        raise ValueError("normalize() deliberately broken")

    async def health_check(self, cfg: BaseModel) -> bool:
        return False


class _SentinelModel(BaseModel):
    """Internal model used by FailingValidationPlugin to raise a real ValidationError."""

    required_int: int


class FailingValidationPlugin:
    """Fake plugin whose ``normalize()`` raises a ``pydantic.ValidationError``.

    Used to verify that the ingest route's NB3 fix does NOT echo the bad input
    value (which appears in ValidationError's str representation) back in the
    HTTP 422 response body.

    The ``sentinel`` string is embedded in the raw data supplied to this plugin
    and then included as the bad input value in the ValidationError.  Tests assert
    that ``sentinel`` does NOT appear in the 422 response body.
    """

    def __init__(self, type_key: str = "validationfail", sentinel: str = "") -> None:
        self._type_key = type_key
        self.sentinel = sentinel

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name="Validation-Failing Plugin",
            version="0.0.1",
            flavor="pull",
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakePullConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        pass

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        # This forces a real pydantic.ValidationError whose str() contains sentinel.
        _SentinelModel.model_validate({"required_int": self.sentinel})
        # Unreachable — satisfy the type checker.
        raise RuntimeError("unreachable")  # pragma: no cover

    async def health_check(self, cfg: BaseModel) -> bool:
        return False
