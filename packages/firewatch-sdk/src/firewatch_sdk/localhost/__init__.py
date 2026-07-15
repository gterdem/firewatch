"""Local-machine log readers (ADR-0065) — flavor-agnostic ``(record, cursor)`` iterators.

Every *endpoint* source plugin (one that reads a machine's own logs — ClamAV,
Linux auth, …) must be able to collect from the machine FireWatch runs on with
zero network configuration (ADR-0065 §1). These readers implement that: a
journald reader as the primary interface (present and consistent across every
mainstream systemd distro), and a plain file-tail reader as the non-systemd
fallback.

Deliberately NOT coupled to ``PullSource`` or any plugin flavor (ADR-0065 §2):
both are plain async iterators any entrypoint can drive, including M2's future
hub push mode. Neither reader persists anything — callers pass a position in
via ``start`` and store what they get back (``ctx.kv`` in a consuming plugin,
per ADR-0025/0027).

Both readers split start-position handling into two calls:
``resolve_start()`` turns ``"head"`` / ``"tail"`` / a cursor into a concrete,
persistable position BEFORE any draining happens, and ``read()`` drains from
that position and REJECTS the literal ``"tail"`` with ``ValueError``. This
exists to close a data-loss gap: a caller that persists only the cursors
attached to yielded records has nothing to persist on a quiet cycle, so a bare
``read("tail")`` reused across polls silently re-pivots past anything that
arrived in between — see either reader's ``resolve_start()`` docstring for the
full scenario. ``read()`` is a one-shot drain (no follow/``-f``): it returns
once nothing more is available, so a consuming ``collect()`` cycle always
terminates.

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
