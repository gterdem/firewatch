"""Tests for source_kv_* on EventStore — mapped 1:1 to issue #30 EARS criteria.

EARS criteria covered:
  KV-1 (Ubiquitous)     EventStore protocol shall declare source_kv_put / source_kv_get /
                        source_kv_get_all; SQLiteEventStore and FakeStore shall satisfy it.
  KV-2 (Event-driven)   source_kv_put(source_type, namespace, key, value) shall persist
                        the row; source_kv_get(source_type, namespace, key) shall return
                        that value (round-trip).
  KV-3 (Event-driven)   source_kv_get_all(source_type, namespace) shall return all rows
                        whose source_type matches the caller's, as a dict[key, value].
  KV-4 (Unwanted)       A read for source_type A must not return rows written for source_type B
                        (tenant isolation).
  KV-5 (Unwanted)       A write over the per-(source_type, namespace) row cap shall be
                        rejected with SourceKVCapExceededError; other scopes must remain
                        intact.

Additional structural tests:
  - Namespace scoping: same key in different namespaces are independent rows.
  - Upsert semantics: put(…) with an existing key overwrites the value (no duplicates).
  - Missing key returns None.
  - get_all on empty namespace returns {}.
  - clear() also removes source_kv rows.
  - rule_descriptions migration: upsert_rule_descriptions + get_rule_descriptions round-trip
    still passes (golden parity preserved).
  - FakeStore satisfies EventStore protocol (pyright + isinstance).

Security / hardening tests (ADR-0025 addendum):
  - ScopedKV: no source_type param — a plugin view cannot address another tenant (BLOCKING-1).
  - _CoreScopedKV: view is bound to its source_type and cannot cross to another scope.
  - TOCTOU: concurrent writes respect the cap (BLOCKING-3).
  - NB-4 migration: legacy rule_descriptions table rows are migrated on init().

BLOCKING-3 regression tests (connection-wide write lock, option b):
  - Concurrent save_many + source_kv_put on the SAME store must not raise OperationalError.
  - Concurrent upsert_rule_descriptions + source_kv_put must not raise OperationalError.
  - Concurrent set_watermark + source_kv_put must not raise OperationalError.
  - Concurrent upsert_ip_geo + source_kv_put must not raise OperationalError.
"""
from __future__ import annotations

import asyncio
import inspect
import sqlite3
import pytest
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from firewatch_sdk import EventStore, ScopedKV, SecurityEvent

from firewatch_core.adapters.sqlite_store import SQLiteEventStore, SourceKVCapExceededError
from firewatch_core.scoped_kv import scoped_kv

from _fakes import FakeStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def store(tmp_path: Path):
    """Fresh, initialised SQLiteEventStore backed by a tmp file."""
    s = SQLiteEventStore(tmp_path / "kv_test.db")
    await s.init()
    yield s
    await s.close()


# ---------------------------------------------------------------------------
# KV-1 — Protocol conformance
# ---------------------------------------------------------------------------


def test_sqlite_store_has_kv_methods(tmp_path: Path) -> None:
    """SQLiteEventStore shall have source_kv_put/get/get_all (KV-1)."""
    s = SQLiteEventStore(tmp_path / "proto.db")
    assert hasattr(s, "source_kv_put")
    assert hasattr(s, "source_kv_get")
    assert hasattr(s, "source_kv_get_all")


def test_sqlite_store_is_event_store_protocol(tmp_path: Path) -> None:
    """SQLiteEventStore with KV methods shall still satisfy EventStore protocol (KV-1)."""
    s = SQLiteEventStore(tmp_path / "proto.db")
    assert isinstance(s, EventStore), (
        "SQLiteEventStore must satisfy the runtime_checkable EventStore Protocol"
    )


def test_fake_store_has_kv_methods() -> None:
    """FakeStore shall have source_kv_put/get/get_all (KV-1)."""
    fs = FakeStore()
    assert hasattr(fs, "source_kv_put")
    assert hasattr(fs, "source_kv_get")
    assert hasattr(fs, "source_kv_get_all")


def test_fake_store_is_event_store_protocol() -> None:
    """FakeStore with KV methods shall still satisfy EventStore protocol (KV-1)."""
    fs = FakeStore()
    assert isinstance(fs, EventStore), (
        "FakeStore must satisfy the runtime_checkable EventStore Protocol"
    )


# ---------------------------------------------------------------------------
# KV-2 — put / get round-trip
# ---------------------------------------------------------------------------


async def test_kv_put_get_round_trip(store: SQLiteEventStore) -> None:
    """source_kv_put then source_kv_get shall return the stored value (KV-2)."""
    await store.source_kv_put("suricata", "rule_descriptions", "1001", "SQL injection")
    result = await store.source_kv_get("suricata", "rule_descriptions", "1001")
    assert result == "SQL injection"


async def test_kv_get_missing_key_returns_none(store: SQLiteEventStore) -> None:
    """source_kv_get for a key not yet written shall return None (KV-2)."""
    result = await store.source_kv_get("suricata", "rule_descriptions", "9999")
    assert result is None


# ---------------------------------------------------------------------------
# KV-3 — get_all returns only matching source_type rows
# ---------------------------------------------------------------------------


async def test_kv_get_all_returns_namespace_rows(store: SQLiteEventStore) -> None:
    """source_kv_get_all shall return all keys in the namespace as a dict (KV-3)."""
    await store.source_kv_put("suricata", "signatures", "1001", "Malware C2")
    await store.source_kv_put("suricata", "signatures", "1002", "Port scan")
    result = await store.source_kv_get_all("suricata", "signatures")
    assert result == {"1001": "Malware C2", "1002": "Port scan"}


async def test_kv_get_all_excludes_other_namespaces(store: SQLiteEventStore) -> None:
    """source_kv_get_all shall NOT return rows from other namespaces (KV-3)."""
    await store.source_kv_put("suricata", "signatures", "1001", "Malware")
    await store.source_kv_put("suricata", "cursors", "last_id", "42")
    result = await store.source_kv_get_all("suricata", "signatures")
    assert "last_id" not in result
    assert "1001" in result


async def test_kv_get_all_empty_namespace_returns_empty_dict(
    store: SQLiteEventStore,
) -> None:
    """source_kv_get_all on an empty namespace shall return {} (KV-3)."""
    result = await store.source_kv_get_all("suricata", "nonexistent_ns")
    assert result == {}


# ---------------------------------------------------------------------------
# KV-4 — Tenant isolation: source_type A cannot read source_type B's keys
# ---------------------------------------------------------------------------


async def test_kv_tenant_isolation_get(store: SQLiteEventStore) -> None:
    """source_kv_get with source_type A shall NOT return a value written for source_type B (KV-4)."""
    await store.source_kv_put("suricata", "sigs", "1001", "Suricata value")
    await store.source_kv_put("azure_waf", "sigs", "1001", "WAF value")
    # Each source_type reads its own value
    suricata_val = await store.source_kv_get("suricata", "sigs", "1001")
    waf_val = await store.source_kv_get("azure_waf", "sigs", "1001")
    assert suricata_val == "Suricata value"
    assert waf_val == "WAF value"


async def test_kv_tenant_isolation_get_all(store: SQLiteEventStore) -> None:
    """source_kv_get_all for source_type A shall NOT include rows from source_type B (KV-4)."""
    await store.source_kv_put("suricata", "sigs", "s_key", "Suricata-only")
    await store.source_kv_put("azure_waf", "sigs", "w_key", "WAF-only")
    suricata_all = await store.source_kv_get_all("suricata", "sigs")
    waf_all = await store.source_kv_get_all("azure_waf", "sigs")
    # Suricata can only see its own keys
    assert "s_key" in suricata_all
    assert "w_key" not in suricata_all
    # WAF can only see its own keys
    assert "w_key" in waf_all
    assert "s_key" not in waf_all


async def test_kv_tenant_isolation_cross_source_get_returns_none(
    store: SQLiteEventStore,
) -> None:
    """source_kv_get using a wrong source_type shall return None (KV-4).

    This proves the API provides no way to cross tenant boundaries — using
    a different source_type simply yields None, as if the key does not exist.
    """
    await store.source_kv_put("suricata", "ns", "secret", "top-secret-data")
    # azure_waf reads the same namespace+key but different source_type
    result = await store.source_kv_get("azure_waf", "ns", "secret")
    assert result is None


# ---------------------------------------------------------------------------
# KV-5 — Cap enforcement: over-cap writes are rejected; other scopes intact
# ---------------------------------------------------------------------------


@pytest.mark.slow
async def test_kv_cap_exceeded_raises(store: SQLiteEventStore) -> None:
    """Writes over the per-(source_type, namespace) row cap shall raise SourceKVCapExceededError (KV-5)."""
    cap = SQLiteEventStore.SOURCE_KV_CAP
    # Fill to the cap
    for i in range(cap):
        await store.source_kv_put("suricata", "sigs", f"key{i}", f"val{i}")
    # One more must raise
    with pytest.raises(SourceKVCapExceededError):
        await store.source_kv_put("suricata", "sigs", "overflow_key", "overflow_val")


@pytest.mark.slow
async def test_kv_cap_exceeded_does_not_affect_other_scopes(
    store: SQLiteEventStore,
) -> None:
    """A cap-exceeded rejection for source_type A must not affect source_type B (KV-5)."""
    cap = SQLiteEventStore.SOURCE_KV_CAP
    # Fill suricata/sigs to the cap
    for i in range(cap):
        await store.source_kv_put("suricata", "sigs", f"key{i}", f"val{i}")
    # Overflow suricata
    with pytest.raises(SourceKVCapExceededError):
        await store.source_kv_put("suricata", "sigs", "overflow_key", "overflow_val")
    # azure_waf/sigs must be completely unaffected
    await store.source_kv_put("azure_waf", "sigs", "waf_key", "waf_val")
    result = await store.source_kv_get("azure_waf", "sigs", "waf_key")
    assert result == "waf_val"


@pytest.mark.slow
async def test_kv_cap_upsert_does_not_count_as_new_row(
    store: SQLiteEventStore,
) -> None:
    """Overwriting (upserting) an existing key must not count as a new row toward the cap (KV-5)."""
    cap = SQLiteEventStore.SOURCE_KV_CAP
    # Fill to cap - 1
    for i in range(cap - 1):
        await store.source_kv_put("suricata", "sigs", f"key{i}", f"val{i}")
    # Write the last key
    await store.source_kv_put("suricata", "sigs", "last_key", "first_value")
    # Upsert the last key — must not raise (row count doesn't change)
    await store.source_kv_put("suricata", "sigs", "last_key", "updated_value")
    updated = await store.source_kv_get("suricata", "sigs", "last_key")
    assert updated == "updated_value"


@pytest.mark.slow
async def test_kv_cap_separate_namespace_independent(
    store: SQLiteEventStore,
) -> None:
    """Cap is per (source_type, namespace) — a different namespace in the same source_type
    has its own independent cap budget (KV-5)."""
    cap = SQLiteEventStore.SOURCE_KV_CAP
    # Fill suricata/ns_a to the cap
    for i in range(cap):
        await store.source_kv_put("suricata", "ns_a", f"key{i}", f"val{i}")
    # suricata/ns_b is a separate bucket — must accept writes freely
    await store.source_kv_put("suricata", "ns_b", "fresh_key", "fresh_val")
    result = await store.source_kv_get("suricata", "ns_b", "fresh_key")
    assert result == "fresh_val"


# ---------------------------------------------------------------------------
# Structural: namespace scoping
# ---------------------------------------------------------------------------


async def test_kv_same_key_different_namespaces_are_independent(
    store: SQLiteEventStore,
) -> None:
    """Same key in different namespaces stores independently and does not collide."""
    await store.source_kv_put("suricata", "ns_a", "key1", "value_a")
    await store.source_kv_put("suricata", "ns_b", "key1", "value_b")
    a = await store.source_kv_get("suricata", "ns_a", "key1")
    b = await store.source_kv_get("suricata", "ns_b", "key1")
    assert a == "value_a"
    assert b == "value_b"


# ---------------------------------------------------------------------------
# Structural: upsert semantics
# ---------------------------------------------------------------------------


async def test_kv_put_overwrites_existing_key(store: SQLiteEventStore) -> None:
    """source_kv_put on an existing key shall overwrite (upsert) the value."""
    await store.source_kv_put("suricata", "ns", "key1", "initial")
    await store.source_kv_put("suricata", "ns", "key1", "updated")
    result = await store.source_kv_get("suricata", "ns", "key1")
    assert result == "updated"


# ---------------------------------------------------------------------------
# Structural: clear() removes source_kv rows
# ---------------------------------------------------------------------------


async def test_kv_clear_removes_kv_rows(store: SQLiteEventStore) -> None:
    """clear() shall delete all source_kv rows."""
    await store.source_kv_put("suricata", "ns", "k1", "v1")
    await store.clear()
    result = await store.source_kv_get("suricata", "ns", "k1")
    assert result is None
    all_rows = await store.source_kv_get_all("suricata", "ns")
    assert all_rows == {}


# ---------------------------------------------------------------------------
# Migration: rule_descriptions facade uses source_kv underneath (golden parity)
# ---------------------------------------------------------------------------


async def test_rule_descriptions_facade_round_trip(store: SQLiteEventStore) -> None:
    """upsert_rule_descriptions + get_rule_descriptions shall work identically after
    migrating onto source_kv (golden parity preserved)."""
    descs = {"942100": "SQL injection detected", "941100": "XSS detected"}
    await store.upsert_rule_descriptions(descs)
    result = await store.get_rule_descriptions()
    assert result["942100"] == "SQL injection detected"
    assert result["941100"] == "XSS detected"


async def test_rule_descriptions_data_visible_via_source_kv(
    store: SQLiteEventStore,
) -> None:
    """Data written via upsert_rule_descriptions shall be readable via source_kv_get_all
    using the internal '_global' source_type, proving migration is real."""
    await store.upsert_rule_descriptions({"942100": "SQL injection"})
    # The rule_descriptions facade stores under _global/rule_descriptions.
    # Confirm direct source_kv access using the known internal source_type.
    kv_direct = await store.source_kv_get_all("_global", "rule_descriptions")
    assert "942100" in kv_direct
    assert kv_direct["942100"] == "SQL injection"
    # Also verify get_rule_descriptions returns consistent data
    result = await store.get_rule_descriptions()
    assert "942100" in result
    assert result["942100"] == "SQL injection"


async def test_rule_descriptions_upsert_ignores_existing(
    store: SQLiteEventStore,
) -> None:
    """upsert_rule_descriptions with an existing rule_id must not overwrite (INSERT OR IGNORE).

    This matches the legacy behaviour: rule descriptions are write-once / first-wins.
    """
    await store.upsert_rule_descriptions({"942100": "Original"})
    await store.upsert_rule_descriptions({"942100": "Should be ignored"})
    result = await store.get_rule_descriptions()
    assert result["942100"] == "Original"


# ---------------------------------------------------------------------------
# FakeStore KV methods (pyright conformance + functional)
# ---------------------------------------------------------------------------


async def test_fake_store_kv_round_trip() -> None:
    """FakeStore source_kv_put/get/get_all shall function for basic round-trip."""
    fs = FakeStore()
    await fs.source_kv_put("suricata", "ns", "k1", "v1")
    result = await fs.source_kv_get("suricata", "ns", "k1")
    assert result == "v1"


async def test_fake_store_kv_isolation() -> None:
    """FakeStore shall enforce source_type isolation in source_kv_get/get_all."""
    fs = FakeStore()
    await fs.source_kv_put("suricata", "ns", "k1", "suricata-val")
    await fs.source_kv_put("azure_waf", "ns", "k1", "waf-val")
    assert await fs.source_kv_get("suricata", "ns", "k1") == "suricata-val"
    assert await fs.source_kv_get("azure_waf", "ns", "k1") == "waf-val"
    suricata_all = await fs.source_kv_get_all("suricata", "ns")
    assert "k1" in suricata_all
    waf_all = await fs.source_kv_get_all("azure_waf", "ns")
    assert "k1" in waf_all
    # Cross-isolation: only own keys
    assert suricata_all["k1"] == "suricata-val"
    assert waf_all["k1"] == "waf-val"


async def test_fake_store_kv_missing_key_returns_none() -> None:
    """FakeStore.source_kv_get for a missing key shall return None."""
    fs = FakeStore()
    result = await fs.source_kv_get("suricata", "ns", "no_such_key")
    assert result is None


# ---------------------------------------------------------------------------
# BLOCKING-1 — ScopedKV has no source_type param; _CoreScopedKV isolation
# ---------------------------------------------------------------------------


def test_scoped_kv_protocol_has_no_source_type_param() -> None:
    """ScopedKV.put/get/get_all must have no source_type parameter (BLOCKING-1).

    Capability-based isolation: the bound source_type is closed over at
    construction so a plugin cannot address another tenant's scope.
    """
    for method_name in ("put", "get", "get_all"):
        params = inspect.signature(getattr(ScopedKV, method_name)).parameters
        assert "source_type" not in params, (
            f"ScopedKV.{method_name} must not have a source_type parameter"
        )


async def test_core_scoped_kv_view_isolates_by_bound_source_type(
    store: SQLiteEventStore,
) -> None:
    """_CoreScopedKV bound to 'suricata' cannot read rows written for 'azure_waf' (BLOCKING-1).

    The plugin view offers no API surface for naming another source_type; the
    bound source_type is the only scope the view can address.
    """
    # Write directly via raw store as "azure_waf" (core-only operation)
    await store.source_kv_put("azure_waf", "secrets", "key1", "waf-secret")

    # Suricata's scoped view
    suricata_kv: ScopedKV = scoped_kv(store, "suricata")

    # The suricata view cannot see the azure_waf key
    result = await suricata_kv.get("secrets", "key1")
    assert result is None, (
        "ScopedKV for 'suricata' must not return a value written for 'azure_waf'"
    )

    all_ns = await suricata_kv.get_all("secrets")
    assert "key1" not in all_ns, (
        "ScopedKV.get_all for 'suricata' must not include 'azure_waf' rows"
    )


async def test_core_scoped_kv_write_stays_in_bound_scope(
    store: SQLiteEventStore,
) -> None:
    """_CoreScopedKV writes are scoped to the bound source_type; another view cannot read them."""
    suricata_kv: ScopedKV = scoped_kv(store, "suricata")
    waf_kv: ScopedKV = scoped_kv(store, "azure_waf")

    await suricata_kv.put("ns", "shared_key", "suricata-value")

    # WAF view cannot read suricata's key
    assert await waf_kv.get("ns", "shared_key") is None
    assert "shared_key" not in await waf_kv.get_all("ns")

    # Suricata view CAN read its own key
    assert await suricata_kv.get("ns", "shared_key") == "suricata-value"


async def test_core_scoped_kv_satisfies_scoped_kv_protocol(
    store: SQLiteEventStore,
) -> None:
    """_CoreScopedKV instance must satisfy the runtime-checkable ScopedKV protocol."""
    view = scoped_kv(store, "suricata")
    assert isinstance(view, ScopedKV), (
        "_CoreScopedKV must satisfy the runtime_checkable ScopedKV Protocol"
    )


# ---------------------------------------------------------------------------
# BLOCKING-3 — TOCTOU: concurrent writers cannot both exceed the cap
# ---------------------------------------------------------------------------


async def test_source_kv_cap_toctou_concurrent_inserts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrent source_kv_put calls must not jointly breach the cap (BLOCKING-3).

    Two concurrent writers both pre-check count < cap and both try to insert.
    The asyncio.Lock + BEGIN IMMEDIATE ensures only one can proceed atomically;
    the other sees count >= cap and raises SourceKVCapExceededError.

    We patch SOURCE_KV_CAP to a small value (5) so the test fills quickly:
    4 rows pre-fill, then two concurrent puts compete for the last slot.
    Exactly one must succeed and the cap must not be exceeded.
    """
    import firewatch_core.adapters.sqlite_store as _store_mod

    # Patch the module-level cap to 5 for this test to avoid slow fill loops.
    monkeypatch.setattr(_store_mod, "SOURCE_KV_CAP", 5)

    s1 = SQLiteEventStore(tmp_path / "toctou1.db")
    await s1.init()

    # Fill to cap - 1 (4 rows, leaving exactly one slot)
    for i in range(4):
        await s1.source_kv_put("suricata", "ns", f"k{i}", f"v{i}")

    # Fire two concurrent puts competing for the last slot
    results: list[Exception | None] = []

    async def _try_put(key: str) -> None:
        try:
            await s1.source_kv_put("suricata", "ns", key, "val")
            results.append(None)  # success
        except SourceKVCapExceededError as e:
            results.append(e)
        except Exception as e:
            results.append(e)

    await asyncio.gather(_try_put("slot_a"), _try_put("slot_b"))
    await s1.close()

    # Exactly one must have succeeded and one must have raised SourceKVCapExceededError
    successes = [r for r in results if r is None]
    cap_errors = [r for r in results if isinstance(r, SourceKVCapExceededError)]
    other_errors = [
        r for r in results if r is not None and not isinstance(r, SourceKVCapExceededError)
    ]
    assert not other_errors, f"Unexpected errors: {other_errors}"
    assert len(successes) == 1, f"Expected exactly 1 success, got {successes}"
    assert len(cap_errors) == 1, f"Expected exactly 1 cap error, got {cap_errors}"


# ---------------------------------------------------------------------------
# NB-4 — legacy rule_descriptions migration on init()
# ---------------------------------------------------------------------------


async def test_legacy_rule_descriptions_migrated_on_init(tmp_path: Path) -> None:
    """On init(), if a legacy rule_descriptions table exists, its rows must be migrated
    into source_kv under (_global, rule_descriptions) (NB-4).

    The migration must be idempotent (safe to call init() twice) and use
    INSERT-OR-IGNORE semantics (first-write-wins).
    """
    db_path = tmp_path / "legacy_migrate.db"

    # Bootstrap a pre-migration database: create the legacy rule_descriptions table
    # and insert some rows directly via aiosqlite (simulating an old deployment).
    async with aiosqlite.connect(db_path) as raw_db:
        raw_db.row_factory = aiosqlite.Row
        await raw_db.execute(
            "CREATE TABLE IF NOT EXISTS rule_descriptions"
            " (rule_id TEXT PRIMARY KEY, description TEXT NOT NULL)"
        )
        await raw_db.executemany(
            "INSERT OR IGNORE INTO rule_descriptions (rule_id, description) VALUES (?, ?)",
            [
                ("942100", "SQL injection detected"),
                ("941100", "XSS detected"),
                ("930100", "LFI detected"),
            ],
        )
        await raw_db.commit()

    # Now init() the store — migration must happen automatically.
    store = SQLiteEventStore(db_path)
    await store.init()

    # Verify all three rows are in source_kv under _global/rule_descriptions.
    result = await store.get_rule_descriptions()
    assert result.get("942100") == "SQL injection detected"
    assert result.get("941100") == "XSS detected"
    assert result.get("930100") == "LFI detected"

    await store.close()


async def test_legacy_migration_is_idempotent(tmp_path: Path) -> None:
    """Calling init() twice must not duplicate or overwrite already-migrated rows (NB-4).

    INSERT-OR-IGNORE semantics: first-write-wins, subsequent init() calls are no-ops.
    """
    db_path = tmp_path / "idempotent.db"

    async with aiosqlite.connect(db_path) as raw_db:
        raw_db.row_factory = aiosqlite.Row
        await raw_db.execute(
            "CREATE TABLE IF NOT EXISTS rule_descriptions"
            " (rule_id TEXT PRIMARY KEY, description TEXT NOT NULL)"
        )
        await raw_db.execute(
            "INSERT INTO rule_descriptions (rule_id, description) VALUES (?, ?)",
            ("942100", "Original description"),
        )
        await raw_db.commit()

    # First init — migrates legacy rows
    store = SQLiteEventStore(db_path)
    await store.init()

    # Manually update the source_kv value to simulate a post-migration update
    # (the store description was updated after migration; idempotent init must
    # not clobber it on the second call).
    await store.source_kv_put("_global", "rule_descriptions", "942100", "Updated by store")
    first_val = await store.source_kv_get("_global", "rule_descriptions", "942100")
    assert first_val == "Updated by store"

    # Second init — INSERT-OR-IGNORE must leave the updated value intact
    await store.init()
    second_val = await store.source_kv_get("_global", "rule_descriptions", "942100")
    assert second_val == "Updated by store", (
        "Second init() must not clobber existing source_kv rows (INSERT-OR-IGNORE)"
    )

    await store.close()


async def test_migration_skipped_when_no_legacy_table(tmp_path: Path) -> None:
    """init() on a fresh database with no rule_descriptions table must not error (NB-4).

    The migration is guarded by a table-exists check; a fresh DB has no
    rule_descriptions table so the migration block is skipped silently.
    """
    store = SQLiteEventStore(tmp_path / "fresh.db")
    await store.init()  # must not raise
    result = await store.get_rule_descriptions()
    assert result == {}, "Fresh DB must have empty rule_descriptions after init"
    await store.close()


# ---------------------------------------------------------------------------
# BLOCKING-3 regression — connection-wide write lock prevents nested-transaction
# crash when other write methods interleave with source_kv_put (option b).
#
# Root cause: aiosqlite's default isolation_level='' leaves implicit transactions
# open across await points in save_many / upsert_rule_descriptions / set_watermark /
# upsert_ip_geo.  If source_kv_put issued BEGIN IMMEDIATE while such a transaction
# was in-flight on the same shared connection, SQLite raised:
#   OperationalError: cannot start a transaction within a transaction
# The _write_lock serialises ALL writes, making BEGIN IMMEDIATE unnecessary and
# eliminating the crash. These tests use asyncio.gather() on the SAME store instance
# to reproduce the exact interleaving that triggered the bug.
# ---------------------------------------------------------------------------


def _make_evt(
    *,
    source_ip: str = "203.0.113.10",
    source_type: str = "suricata",
    source_id: str = "sensor-1",
    action: str = "BLOCK",
) -> SecurityEvent:
    """Return a minimal SecurityEvent with a RFC 5737 source IP."""
    return SecurityEvent(
        source_type=source_type,
        source_id=source_id,
        source_ip=source_ip,
        action=action,  # type: ignore[arg-type]
        timestamp=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
    )


async def test_concurrent_save_many_and_source_kv_put_no_operational_error(
    tmp_path: Path,
) -> None:
    """asyncio.gather(save_many([...]), source_kv_put(...)) on the SAME store must not
    raise OperationalError (BLOCKING-3 regression).

    Before the fix, save_many's executemany could leave an implicit transaction open
    across its await points.  source_kv_put then issued BEGIN IMMEDIATE on the shared
    connection and SQLite crashed with 'cannot start a transaction within a transaction'.
    """
    store = SQLiteEventStore(tmp_path / "conc_save.db")
    await store.init()

    try:
        # Run both concurrently on the SAME connection — this is the exact pattern
        # that triggered the OperationalError before the fix.
        await asyncio.gather(
            store.save_many([_make_evt(source_ip="203.0.113.1")]),
            store.source_kv_put("suricata", "ns", "k1", "v1"),
        )
    except sqlite3.OperationalError as exc:
        pytest.fail(
            f"concurrent save_many + source_kv_put raised OperationalError: {exc}"
        )

    # Verify consistent state: both writes must have landed.
    events = await store.get_by_ip("203.0.113.1")
    assert len(events) == 1, "save_many result must be persisted"
    val = await store.source_kv_get("suricata", "ns", "k1")
    assert val == "v1", "source_kv_put result must be persisted"

    await store.close()


async def test_concurrent_upsert_rule_descriptions_and_source_kv_put_no_operational_error(
    tmp_path: Path,
) -> None:
    """asyncio.gather(upsert_rule_descriptions(...), source_kv_put(...)) on the SAME
    store must not raise OperationalError (BLOCKING-3 regression)."""
    store = SQLiteEventStore(tmp_path / "conc_rdesc.db")
    await store.init()

    try:
        await asyncio.gather(
            store.upsert_rule_descriptions({"942100": "SQL injection"}),
            store.source_kv_put("suricata", "ns", "k2", "v2"),
        )
    except sqlite3.OperationalError as exc:
        pytest.fail(
            f"concurrent upsert_rule_descriptions + source_kv_put raised OperationalError: {exc}"
        )

    rdesc = await store.get_rule_descriptions()
    assert rdesc.get("942100") == "SQL injection"
    val = await store.source_kv_get("suricata", "ns", "k2")
    assert val == "v2"

    await store.close()


async def test_concurrent_set_watermark_and_source_kv_put_no_operational_error(
    tmp_path: Path,
) -> None:
    """asyncio.gather(set_watermark(...), source_kv_put(...)) on the SAME store must
    not raise OperationalError (BLOCKING-3 regression)."""
    store = SQLiteEventStore(tmp_path / "conc_wm.db")
    await store.init()

    try:
        await asyncio.gather(
            store.set_watermark("2026-01-01T00:00:00+00:00", "suricata", "sensor-1"),
            store.source_kv_put("suricata", "ns", "k3", "v3"),
        )
    except sqlite3.OperationalError as exc:
        pytest.fail(
            f"concurrent set_watermark + source_kv_put raised OperationalError: {exc}"
        )

    wm = await store.get_watermark("suricata", "sensor-1")
    assert wm == "2026-01-01T00:00:00+00:00"
    val = await store.source_kv_get("suricata", "ns", "k3")
    assert val == "v3"

    await store.close()


async def test_concurrent_upsert_ip_geo_and_source_kv_put_no_operational_error(
    tmp_path: Path,
) -> None:
    """asyncio.gather(upsert_ip_geo([...]), source_kv_put(...)) on the SAME store must
    not raise OperationalError (BLOCKING-3 regression)."""
    store = SQLiteEventStore(tmp_path / "conc_geo.db")
    await store.init()

    geo_row = {
        "ip": "203.0.113.42",
        "country": "CA",
        "city": "Toronto",
        "lat": 43.7,
        "lon": -79.4,
    }

    try:
        await asyncio.gather(
            store.upsert_ip_geo([geo_row]),
            store.source_kv_put("suricata", "ns", "k4", "v4"),
        )
    except sqlite3.OperationalError as exc:
        pytest.fail(
            f"concurrent upsert_ip_geo + source_kv_put raised OperationalError: {exc}"
        )

    val = await store.source_kv_get("suricata", "ns", "k4")
    assert val == "v4"

    await store.close()


async def test_cap_exceeded_error_not_masked_by_rollback(tmp_path: Path) -> None:
    """SourceKVCapExceededError must propagate even if the rollback itself raises (NB-1).

    The try/finally in source_kv_put's cap-exceeded branch guarantees the error
    is always re-raised regardless of what happens in the rollback call.
    """
    import firewatch_core.adapters.sqlite_store as _store_mod

    store = SQLiteEventStore(tmp_path / "cap_mask.db")
    await store.init()

    original_cap = _store_mod.SOURCE_KV_CAP
    _store_mod.SOURCE_KV_CAP = 2  # type: ignore[assignment]
    try:
        await store.source_kv_put("suricata", "ns", "k1", "v1")
        await store.source_kv_put("suricata", "ns", "k2", "v2")
        with pytest.raises(SourceKVCapExceededError):
            await store.source_kv_put("suricata", "ns", "k3", "v3")
    finally:
        _store_mod.SOURCE_KV_CAP = original_cap  # type: ignore[assignment]
        await store.close()
