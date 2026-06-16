"""adapters/sqlite — SQLite store subpackage (ADR-0054).

Public surface: re-exports everything that the legacy shim and consumers expect.
"""
from ._base import (
    BLOCKED_ACTIONS,
    RULE_DESC_KV_CAP,
    SCORE_HISTORY_DELTA_WINDOW_HOURS,
    SCORE_HISTORY_RETENTION_DAYS,
    SOURCE_KV_CAP,
    SourceKVCapExceededError,
)
from .store import SQLiteEventStore

__all__ = [
    "SQLiteEventStore",
    "SourceKVCapExceededError",
    "SOURCE_KV_CAP",
    "RULE_DESC_KV_CAP",
    "SCORE_HISTORY_DELTA_WINDOW_HOURS",
    "SCORE_HISTORY_RETENTION_DAYS",
    "BLOCKED_ACTIONS",
]
