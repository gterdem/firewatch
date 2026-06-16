"""SQLiteEventStore — composed from behavior mixins (ADR-0054).

The class body is intentionally almost empty: all behavior lives in the mixins.
Cross-table maintenance methods (clear, delete_older_than) live here because they
touch multiple tables and don't belong to any single concern mixin.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .anomaly import _AnomalyMixin
from .analytics import _AnalyticsMixin
from .events import _EventsMixin
from .geo import _GeoMixin
from .schema import _SchemaMixin
from .score_history import _ScoreHistoryMixin
from .source_kv import _SourceKVMixin


class SQLiteEventStore(
    _SchemaMixin,          # owns __init__, _conn, _read_conn, _watermark_key, init, close
    _EventsMixin,          # logs writes + row-level reads
    _AnalyticsMixin,       # read-only aggregate/summary/timeline queries
    _GeoMixin,             # ip_geo cache + watermark accessors
    _SourceKVMixin,        # source_kv + rule_descriptions facade
    _ScoreHistoryMixin,    # score_history snapshots/deltas/prune
    _AnomalyMixin,         # flow_baseline + anomaly_verdicts
):
    """Async SQLite event store.  Implements the EventStore protocol (ADR-0007).

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.  A fresh file is created (along with
        the schema) on the first call to ``init()``.

    Notes
    -----
    The per-scope row cap for ``source_kv`` is the module-level constant
    ``SOURCE_KV_CAP`` (a ``Final[int]``).  Writes that would exceed it raise
    ``SourceKVCapExceededError``.  Upserts of existing keys are always allowed
    (row count does not change).

    ``SOURCE_KV_CAP`` is exposed as a class attribute alias (read-only) so that
    tests can refer to ``SQLiteEventStore.SOURCE_KV_CAP`` without having to
    import the module-level name directly.  The enforcement always uses the
    module-level ``Final``; patching an instance attribute has no effect.

    ADR-0054: Connection ownership is structurally enforced — only ``_SchemaMixin``
    ever opens an aiosqlite connection or creates the write lock.  The MRO ensures
    ``_SchemaMixin.__init__`` is called once, establishing the single loop-bound
    connection pair (ADR-0023 §F invariant preserved by layout).
    """

    # ------------------------------------------------------------------
    # Cross-table housekeeping (touches multiple tables — lives here,
    # not in any single concern mixin)
    # ------------------------------------------------------------------

    async def clear(self) -> None:
        """Delete all rows from every table (useful for tests)."""
        db = await self._conn()
        async with self._write_lock:
            await db.execute("DELETE FROM logs")
            await db.execute("DELETE FROM sync_state")
            await db.execute("DELETE FROM ip_geo")
            await db.execute("DELETE FROM source_kv")
            await db.execute("DELETE FROM score_history")
            await db.execute("DELETE FROM flow_baseline")
            await db.execute("DELETE FROM anomaly_verdicts")
            await db.commit()

    async def delete_older_than(self, days: int) -> int:
        """Delete log rows older than ``days``.  Returns rows deleted.

        Only ``logs`` is pruned; ``ip_geo`` and ``source_kv`` are small
        and self-cleaning at the next sync.  Tiered hot/cold retention is M6.
        """
        db = await self._conn()
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=days)
        ).isoformat()
        async with self._write_lock:
            cursor = await db.execute(
                "DELETE FROM logs WHERE timestamp < ?", (cutoff,)
            )
            await db.commit()
            return cursor.rowcount
