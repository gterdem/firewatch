"""_CoreScopedKV — capability-scoped KV view minted by core for each plugin.

Core constructs one ``_CoreScopedKV`` per plugin instance and closes over the
plugin's ``source_type`` (taken from ``metadata().type_key`` at wiring time —
never from plugin call arguments).  The object implements the SDK ``ScopedKV``
protocol and forwards to the raw ``source_kv_*`` methods on ``EventStore``.

Isolation guarantee: the API presented to the plugin has no ``source_type``
parameter, so the plugin structurally cannot name another tenant's scope
(capability-based isolation; ADR-0025 addendum, OWASP A01 / NIST AC-6 /
confused-deputy principle).

This module is CORE-ONLY — it is NOT part of the SDK.  A plugin never imports
``firewatch_core``; it sees only the ``ScopedKV`` Protocol from ``firewatch_sdk``.
"""
from __future__ import annotations

from firewatch_sdk.ports import EventStore, ScopedKV


class _CoreScopedKV:
    """Capability view bound to a single plugin's ``source_type``.

    Implements ``firewatch_sdk.ports.ScopedKV`` by delegating to the three
    raw ``source_kv_*`` methods on the underlying ``EventStore``, with the
    ``source_type`` closed over at construction.

    Parameters
    ----------
    store:
        The core ``EventStore`` instance.  The plugin never receives this
        object directly.
    source_type:
        The plugin's declared ``type_key`` (from ``metadata().type_key``),
        injected by core at wiring time.  Must never originate from plugin
        call arguments.
    """

    def __init__(self, store: EventStore, source_type: str) -> None:
        self._store = store
        self._st = source_type

    async def put(self, namespace: str, key: str, value: str) -> None:
        """Upsert ``value`` at ``(bound_source_type, namespace, key)``."""
        await self._store.source_kv_put(self._st, namespace, key, value)

    async def get(self, namespace: str, key: str) -> str | None:
        """Return the value at ``(bound_source_type, namespace, key)``, or ``None``."""
        return await self._store.source_kv_get(self._st, namespace, key)

    async def get_all(self, namespace: str) -> dict[str, str]:
        """Return all ``{key: value}`` pairs in ``(bound_source_type, namespace)``."""
        return await self._store.source_kv_get_all(self._st, namespace)


def scoped_kv(store: EventStore, source_type: str) -> ScopedKV:
    """Factory: mint a ``ScopedKV`` capability view for ``source_type`` against ``store``.

    This is the only sanctioned way to create a ``ScopedKV`` for handing to a plugin.
    ``source_type`` must be taken from ``plugin.metadata().type_key`` — never from
    plugin call arguments.

    The returned object satisfies the ``ScopedKV`` protocol; at runtime it is a
    ``_CoreScopedKV`` instance, but callers should type-hint it as ``ScopedKV``
    (the protocol) so they do not depend on the private concrete class.
    """
    return _CoreScopedKV(store, source_type)
