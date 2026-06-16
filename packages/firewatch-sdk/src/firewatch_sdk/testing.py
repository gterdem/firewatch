"""SDK test-support helpers for plugin authors.

Provides test doubles that let plugin tests and golden tests construct a
``PluginContext`` in one line without depending on ``firewatch-core`` adapters.

Usage in a plugin test::

    from firewatch_sdk.testing import InMemoryScopedKV
    from firewatch_sdk.context import PluginContext

    ctx = PluginContext(kv=InMemoryScopedKV(), source_id="test-instance")

This module is intentionally kept separate from ``context.py`` (the production
carrier) so production imports never pull in test-support code, and from any
single plugin's test directory so it can be shared across all plugin test suites
(ADR-0027 §2 / issue #41 module layout).
"""
from __future__ import annotations


class InMemoryScopedKV:
    """Dict-backed ``ScopedKV`` test double implementing the full ``ScopedKV`` Protocol.

    Stores key/value pairs keyed by ``(namespace, key)`` in a plain Python dict.
    Thread-safe for single-threaded asyncio use (no locking needed for the asyncio
    test event loop).

    Implements:
        ``put(namespace, key, value) -> None``
        ``get(namespace, key) -> str | None``
        ``get_all(namespace) -> dict[str, str]``
    """

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    async def put(self, namespace: str, key: str, value: str) -> None:
        """Upsert ``value`` at ``(namespace, key)``."""
        self._store[(namespace, key)] = value

    async def get(self, namespace: str, key: str) -> str | None:
        """Return the value at ``(namespace, key)``, or ``None`` if absent."""
        return self._store.get((namespace, key))

    async def get_all(self, namespace: str) -> dict[str, str]:
        """Return all ``{key: value}`` pairs in ``namespace``."""
        return {k: v for (ns, k), v in self._store.items() if ns == namespace}
