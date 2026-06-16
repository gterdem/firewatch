"""Tests for firewatch-sdk port protocols (EARS-3, EARS-4 of issue #1)."""
import inspect
import typing
from collections.abc import Awaitable, Callable

import pytest
from pydantic import ValidationError

from firewatch_sdk import (
    AIEngine,
    Enricher,
    EventStore,
    Notifier,
    PullSource,
    PushSource,
    RawEvent,
    ScopedKV,
    SourceMetadata,
    SourcePlugin,
)

PORTS = [
    SourcePlugin,
    PullSource,
    PushSource,
    ScopedKV,
    EventStore,
    AIEngine,
    Notifier,
    Enricher,
]


def _is_protocol(cls) -> bool:
    # typing.is_protocol added in 3.13; fall back to the private flag on 3.12.
    is_protocol = getattr(typing, "is_protocol", None)
    if is_protocol is not None:
        return is_protocol(cls)
    return bool(getattr(cls, "_is_protocol", False))


# ---- EARS-3: the seven ports are typing.Protocol ----------------------------


@pytest.mark.parametrize("port", PORTS)
def test_ports_are_protocols(port):
    assert _is_protocol(port), f"{port.__name__} is not a typing.Protocol"


def test_runtime_checkable_conformance():
    class GoodNotifier:
        async def send_alert(self, threat) -> bool:
            return True

        async def check_and_alert(self, threat) -> bool:
            return True

        async def send_sync_digest(
            self, total_new, blocked_new, ip_blocks, categories
        ) -> bool:
            return True

    class GoodEnricher:
        name = "geo"

        async def enrich(self, events):
            return events

    assert isinstance(GoodNotifier(), Notifier)
    assert isinstance(GoodEnricher(), Enricher)
    assert not isinstance(object(), Notifier)
    assert not isinstance(object(), Enricher)


def test_sourcemetadata_is_model():
    md = SourceMetadata(
        type_key="suricata",
        display_name="Suricata IDS",
        version="0.1.0",
        flavor="pull",
    )
    assert md.flavor == "pull"
    with pytest.raises(ValidationError):
        SourceMetadata(
            type_key="x",
            display_name="X",
            version="0.1.0",
            flavor="carrier-pigeon",  # pyright: ignore[reportArgumentType]
        )
    # frozen: cannot mutate after construction.
    with pytest.raises(ValidationError):
        md.flavor = "push"  # type: ignore[misc]


@pytest.mark.parametrize("type_key", ["suricata", "azure_waf", "syslog", "abc123"])
def test_sourcemetadata_type_key_accepts_valid_tokens(type_key):
    md = SourceMetadata(
        type_key=type_key, display_name="X", version="0.1.0", flavor="pull"
    )
    assert md.type_key == type_key


@pytest.mark.parametrize(
    "type_key",
    [
        "Suricata",
        "azure-waf",
        "has space",
        "",
        "kebab-case",
        "dots.bad",
        # ADR-0025 addendum BLOCKING-2: leading underscore is core-reserved
        "_global",
        "_x",
        "_private",
        # leading digit is also rejected by the new ^[a-z][a-z0-9_]*$ pattern
        "0bad",
        "1source",
    ],
)
def test_sourcemetadata_type_key_rejects_unsafe_tokens(type_key):
    # type_key flows into source_type / dedup / watermark keys, so it must match
    # ^[a-z][a-z0-9_]*$ (PLUGIN_CONTRACT.md; ADR-0025 addendum, BLOCKING-2).
    # Leading underscore is RESERVED FOR CORE (e.g. _global sentinel).
    with pytest.raises(ValidationError):
        SourceMetadata(
            type_key=type_key, display_name="X", version="0.1.0", flavor="pull"
        )


def test_sourcemetadata_type_key_core_sentinel_is_not_valid_plugin_key() -> None:
    """The _global core sentinel must not be accepted as a plugin type_key (BLOCKING-2).

    Core uses source_type='_global' for internal scopes (rule_descriptions facade).
    The tightened pattern ^[a-z][a-z0-9_]*$ (leading letter required) guarantees
    no plugin can ever declare type_key='_global' and collide with that scope.
    """
    with pytest.raises(ValidationError):
        SourceMetadata(
            type_key="_global", display_name="Evil plugin", version="0.1.0", flavor="pull"
        )


# ---- ScopedKV Protocol (ADR-0025 addendum, BLOCKING-1) ----------------------


def test_scoped_kv_is_protocol() -> None:
    """ScopedKV must be a runtime-checkable typing.Protocol (BLOCKING-1)."""
    assert _is_protocol(ScopedKV), "ScopedKV is not a typing.Protocol"


def test_scoped_kv_has_no_source_type_param() -> None:
    """ScopedKV.put/get/get_all must have NO source_type parameter (BLOCKING-1).

    Capability-based isolation: the bound source_type is closed over at
    construction; a plugin cannot name another tenant's scope because the
    API offers no vocabulary for it (ADR-0025 addendum).
    """
    for method_name in ("put", "get", "get_all"):
        params = inspect.signature(getattr(ScopedKV, method_name)).parameters
        assert "source_type" not in params, (
            f"ScopedKV.{method_name} must not have a source_type parameter "
            "(capability-based isolation; ADR-0025 addendum BLOCKING-1)"
        )


def test_scoped_kv_structural_conformance() -> None:
    """A class implementing put/get/get_all satisfies the ScopedKV protocol."""

    class _MockKV:
        async def put(self, namespace: str, key: str, value: str) -> None: ...
        async def get(self, namespace: str, key: str) -> str | None: ...
        async def get_all(self, namespace: str) -> dict[str, str]: ...

    assert isinstance(_MockKV(), ScopedKV), (
        "_MockKV must satisfy the runtime_checkable ScopedKV protocol"
    )


def test_scoped_kv_exported_from_sdk() -> None:
    """ScopedKV must be importable directly from firewatch_sdk (BLOCKING-1)."""
    import firewatch_sdk

    assert hasattr(firewatch_sdk, "ScopedKV"), (
        "ScopedKV must be exported from firewatch_sdk.__init__"
    )


# ---- EARS-4: PushSource.start emit is a batch callback (Flag C) -------------


def test_pushsource_start_has_emit_param():
    params = inspect.signature(PushSource.start).parameters
    assert "emit" in params


def test_pushsource_start_emit_is_batch_callable():
    from _reference import ReferencePushPlugin

    hints = typing.get_type_hints(ReferencePushPlugin.start)
    assert hints["emit"] == Callable[[list[RawEvent]], Awaitable[None]]
