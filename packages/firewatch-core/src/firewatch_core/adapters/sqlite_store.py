"""Back-compat re-export shim.  Real implementation lives in adapters/sqlite/.

ADR-0054: sqlite_store.py is kept as a thin facade so all existing import paths
(~30 runtime/test/TYPE_CHECKING sites) keep working byte-for-byte without change.
"""
from firewatch_core.adapters.sqlite import (  # noqa: F401
    BLOCKED_ACTIONS,
    RULE_DESC_KV_CAP,
    SCORE_HISTORY_DELTA_WINDOW_HOURS,
    SCORE_HISTORY_RETENTION_DAYS,
    SOURCE_KV_CAP,
    SQLiteEventStore,
    SourceKVCapExceededError,
)

__all__ = [
    "SQLiteEventStore",
    "SourceKVCapExceededError",
    "SOURCE_KV_CAP",
    "RULE_DESC_KV_CAP",
    "SCORE_HISTORY_DELTA_WINDOW_HOURS",
    "SCORE_HISTORY_RETENTION_DAYS",
    "BLOCKED_ACTIONS",
]
