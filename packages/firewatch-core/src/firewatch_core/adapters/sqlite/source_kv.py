"""_SourceKVMixin — source_kv + rule_descriptions facade (ADR-0025)."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Any

import aiosqlite

from ._base import (
    RULE_DESC_KV_CAP,
    SOURCE_KV_CAP,
    SourceKVCapExceededError,
    _KV_GLOBAL_SOURCE_TYPE,
    _KV_RULE_DESC_NAMESPACE,
)


def _get_source_kv_cap() -> int:
    """Return the active SOURCE_KV_CAP value.

    Reads from the back-compat shim module (``firewatch_core.adapters.sqlite_store``)
    when it is already loaded, so that test monkeypatches on that module take effect.
    Falls back to the local ``_base`` constant if the shim has not been imported yet
    (e.g. direct internal use before any test import).

    This indirection is necessary because ``sqlite_store`` re-exports ``SOURCE_KV_CAP``
    from ``_base`` at import time, creating a *separate name binding* in its namespace.
    Patching ``sqlite_store.SOURCE_KV_CAP`` in tests rebinds that name but never
    touches the ``source_kv`` module's own local binding — so we must look up the
    value through the shim's namespace at call time.
    """
    shim = sys.modules.get("firewatch_core.adapters.sqlite_store")
    if shim is not None:
        cap = getattr(shim, "SOURCE_KV_CAP", None)
        if cap is not None:
            return int(cap)
    return SOURCE_KV_CAP


class _SourceKVMixin:
    """Handles upsert_rule_descriptions, get_rule_descriptions,
    source_kv_put, source_kv_get, and source_kv_get_all.

    CORE-PRIVILEGED: these methods are NOT exposed to plugins.
    Plugins use the ScopedKV view (firewatch_sdk.ports.ScopedKV) which
    closes over a fixed source_type so a plugin structurally cannot name
    another tenant's scope (capability-based isolation; ADR-0025 addendum,
    OWASP A01 / NIST AC-6).
    """

    async def _conn(self) -> aiosqlite.Connection: ...  # pragma: no cover
    async def _read_conn(self) -> aiosqlite.Connection: ...  # pragma: no cover

    # ------------------------------------------------------------------
    # Rule descriptions — ergonomic facade over source_kv (ADR-0025)
    # ------------------------------------------------------------------

    async def upsert_rule_descriptions(self, descs: dict[str, str]) -> None:
        """Write rule descriptions into source_kv (INSERT-OR-IGNORE semantics).

        First-write-wins: if a rule_id is already present, its description is
        NOT overwritten.  This preserves the legacy behaviour.
        """
        if not descs:
            return
        db = await self._conn()
        now = datetime.now(timezone.utc).isoformat()
        # INSERT OR IGNORE on the source_kv composite PK achieves first-write-wins
        # because the primary key (source_type, namespace, key) is unique and the
        # existing row's value is left intact on conflict.
        async with self._write_lock:  # type: ignore[attr-defined]
            await db.executemany(
                "INSERT OR IGNORE INTO source_kv"
                " (source_type, namespace, key, value, updated_at)"
                " VALUES (?, ?, ?, ?, ?)",
                [
                    (_KV_GLOBAL_SOURCE_TYPE, _KV_RULE_DESC_NAMESPACE, rid, desc, now)
                    for rid, desc in descs.items()
                ],
            )
            await db.commit()

    async def get_rule_descriptions(self) -> dict[str, str]:
        """Return all rule descriptions as {rule_id: description}.

        Reads from source_kv under source_type='_global',
        namespace='rule_descriptions'.
        """
        return await self.source_kv_get_all(
            _KV_GLOBAL_SOURCE_TYPE, _KV_RULE_DESC_NAMESPACE
        )

    # ------------------------------------------------------------------
    # source_kv — generic source-scoped key/value auxiliary store (ADR-0025 (b))
    # ------------------------------------------------------------------

    async def source_kv_put(
        self, source_type: str, namespace: str, key: str, value: str
    ) -> None:
        """Upsert ``value`` at ``(source_type, namespace, key)``.

        **CORE-PRIVILEGED — NOT exposed to plugins; plugins use** ``ScopedKV``.
        ``source_type`` is core-injected from ``metadata().type_key``, never
        plugin input.

        Raises ``SourceKVCapExceededError`` if the scope is already at the row
        cap AND ``key`` is a *new* key (i.e. would add a row).  Updating an
        existing key always succeeds.

        TOCTOU + nested-transaction safety (BLOCKING-3, option b):
        The connection-wide ``_write_lock`` serialises ALL writes on this
        connection.  Because no other coroutine can execute any DB write while
        this lock is held, the existence check → cap check → INSERT sequence is
        atomic without needing ``BEGIN IMMEDIATE`` (which caused
        ``OperationalError: cannot start a transaction within a transaction``
        whenever another write method had an implicit transaction in-flight on
        the same shared connection).
        """
        db = await self._conn()
        now = datetime.now(timezone.utc).isoformat()

        async with self._write_lock:  # type: ignore[attr-defined]
            try:
                # Check whether the key already exists.  If it does, the write
                # is an update (row count stays the same) and we skip the cap.
                exists_cursor = await db.execute(
                    "SELECT 1 FROM source_kv"
                    " WHERE source_type = ? AND namespace = ? AND key = ?",
                    (source_type, namespace, key),
                )
                exists = await exists_cursor.fetchone() is not None

                if not exists:
                    # Count rows in this scope to enforce the cap.
                    # Route to the elevated cap for the rule_descriptions namespace
                    # (any source_type) so the plugin's ScopedKV write path can store
                    # a full ET Open ruleset (~50k rules) without hitting SOURCE_KV_CAP.
                    # All other namespaces use the conservative SOURCE_KV_CAP.
                    #
                    # _get_source_kv_cap() reads through the sqlite_store shim so that
                    # test monkeypatches on that module's SOURCE_KV_CAP name take effect
                    # at call time (the local binding from _base is fixed at import time).
                    effective_cap = (
                        RULE_DESC_KV_CAP
                        if namespace == _KV_RULE_DESC_NAMESPACE
                        else _get_source_kv_cap()
                    )
                    count_cursor = await db.execute(
                        "SELECT COUNT(*) FROM source_kv"
                        " WHERE source_type = ? AND namespace = ?",
                        (source_type, namespace),
                    )
                    count_row = await count_cursor.fetchone()
                    current_count: int = count_row[0] if count_row else 0
                    if current_count >= effective_cap:
                        # Raise *after* the lock context exits — but we must
                        # not leave any uncommitted state.  The implicit
                        # transaction (if any) is rolled back by simply not
                        # calling commit(); aiosqlite's isolation_level=''
                        # will issue ROLLBACK automatically when the
                        # connection is reused for the next statement.
                        # Use try/finally to guarantee the error is raised
                        # even if the rollback itself were to fail.
                        try:
                            await db.rollback()
                        finally:
                            raise SourceKVCapExceededError(
                                f"source_kv cap exceeded: limit is {effective_cap} rows"
                                f" per (source_type, namespace) scope"
                                f" (namespace={namespace!r})"
                            )

                await db.execute(
                    "INSERT OR REPLACE INTO source_kv"
                    " (source_type, namespace, key, value, updated_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (source_type, namespace, key, value, now),
                )
                await db.commit()
            except SourceKVCapExceededError:
                raise
            except Exception:
                await db.rollback()
                raise

    async def source_kv_get(
        self, source_type: str, namespace: str, key: str
    ) -> str | None:
        """Return the value at ``(source_type, namespace, key)``, or ``None``.

        **CORE-PRIVILEGED — NOT exposed to plugins; plugins use** ``ScopedKV``.
        ``source_type`` is core-injected from ``metadata().type_key``, never
        plugin input.
        """
        db = await self._read_conn()  # read-only (#313)
        cursor = await db.execute(
            "SELECT value FROM source_kv"
            " WHERE source_type = ? AND namespace = ? AND key = ?",
            (source_type, namespace, key),
        )
        row = await cursor.fetchone()
        return row["value"] if row else None

    async def source_kv_get_all(
        self, source_type: str, namespace: str
    ) -> dict[str, str]:
        """Return all ``{key: value}`` pairs in ``(source_type, namespace)``.

        **CORE-PRIVILEGED — NOT exposed to plugins; plugins use** ``ScopedKV``.
        ``source_type`` is core-injected from ``metadata().type_key``, never
        plugin input.
        """
        db = await self._read_conn()  # read-only (#313)
        cursor = await db.execute(
            "SELECT key, value FROM source_kv"
            " WHERE source_type = ? AND namespace = ?",
            (source_type, namespace),
        )
        rows = await cursor.fetchall()
        return {r["key"]: r["value"] for r in rows}

    # Unused but present for forward compatibility; satisfy Any usage.
    def __init_source_kv__(self, _: Any = None) -> None:  # noqa: ANN001
        pass
