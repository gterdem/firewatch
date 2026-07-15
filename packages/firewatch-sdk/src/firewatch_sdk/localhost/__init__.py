"""Local-machine log readers (ADR-0065) — flavor-agnostic ``(record, cursor)`` iterators.

Every *endpoint* source plugin (one that reads a machine's own logs — ClamAV,
Linux auth, …) must be able to collect from the machine FireWatch runs on with
zero network configuration (ADR-0065 §1). These readers implement that: a
journald reader as the primary interface (present and consistent across every
mainstream systemd distro), and a plain file-tail reader as the non-systemd
fallback.

Deliberately NOT coupled to ``PullSource`` or any plugin flavor (ADR-0065 §2):
both are plain async iterators any entrypoint can drive, including M2's future
hub push mode. Neither reader persists anything — callers pass the last cursor
in via ``start`` and store the newly yielded cursor themselves (``ctx.kv`` in a
consuming plugin, per ADR-0025/0027).

These are SDK utilities, not contract surface (ADR-0065 §4) — importing this
module never pulls in ``firewatch_core`` or any plugin.
"""
from __future__ import annotations

from firewatch_sdk.localhost.errors import (
    FileTailUnavailableError,
    JournaldUnavailableError,
    LocalReaderError,
)
from firewatch_sdk.localhost.filetail import FileTailReader
from firewatch_sdk.localhost.journald import JournaldReader

__all__ = [
    "JournaldReader",
    "FileTailReader",
    "LocalReaderError",
    "JournaldUnavailableError",
    "FileTailUnavailableError",
]
