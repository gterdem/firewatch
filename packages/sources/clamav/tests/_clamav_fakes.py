"""Shared test doubles for firewatch_clamav's test suite (no live journald/subprocess
needed for the ``FakeScopedKV`` / ``make_ctx`` helpers)."""
from __future__ import annotations

from firewatch_sdk import PluginContext


class FakeScopedKV:
    """In-memory double for ``firewatch_sdk.ports.ScopedKV`` (no real store needed)."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    async def put(self, namespace: str, key: str, value: str) -> None:
        self._store[(namespace, key)] = value

    async def get(self, namespace: str, key: str) -> str | None:
        return self._store.get((namespace, key))

    async def get_all(self, namespace: str) -> dict[str, str]:
        return {k: v for (ns, k), v in self._store.items() if ns == namespace}


def make_ctx(source_id: str = "test-instance", kv: FakeScopedKV | None = None) -> PluginContext:
    return PluginContext(kv=kv if kv is not None else FakeScopedKV(), source_id=source_id)
