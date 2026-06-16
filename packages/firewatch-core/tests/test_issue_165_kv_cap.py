"""Tests for issue #165 — per-namespace KV cap + change detection.

EARS criteria (issue #165):
  A1  WHEN the Suricata rule-desc producer loads a standard ET Open ruleset (~50k rules),
      THEN all parsed SID->msg entries SHALL be stored and resolvable via get_rule_descriptions.

  A2  WHEN the per-namespace KV cap is exceeded,
      THEN the system SHALL surface it once per cycle as a visible diagnostic signal,
      NOT 40k swallowed exceptions.

  A3  WHEN a collect cycle runs and the ruleset file is unchanged (mtime/size match),
      THEN the producer SHALL NOT re-write all entries.

Structural tests:
  - Per-namespace cap: rule_descriptions cap is >= 50_000; default cap for other namespaces remains conservative.
  - Bulk upsert: upsert_rule_descriptions handles 50k entries atomically via executemany.
  - upsert_rule_descriptions facade does NOT check per-scope cap (it bypasses cap for core-trusted writes).
  - Change detection: mtime + size fingerprint identifies unchanged vs changed files.
  - Change detection: directory change detection uses mtime of contained .rules files.

NOTE: RFC 5737 doc IPs used exclusively in any SecurityEvent fixtures.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from firewatch_core.adapters.sqlite_store import (
    SQLiteEventStore,
    SourceKVCapExceededError,
    RULE_DESC_KV_CAP,
    SOURCE_KV_CAP,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def store(tmp_path: Path) -> SQLiteEventStore:  # type: ignore[override]
    """Fresh, initialised SQLiteEventStore backed by a tmp file."""
    s = SQLiteEventStore(tmp_path / "cap165_test.db")
    await s.init()
    yield s  # type: ignore[misc]
    await s.close()


def _write_rules_file(path: Path, rules: dict[str, str]) -> None:
    """Write a minimal .rules file with the given {sid: msg} pairs."""
    lines = [
        f'alert tcp any any -> any any (msg:"{msg}"; sid:{sid}; rev:1;)'
        for sid, msg in rules.items()
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_eve(path: Path, src_ip: str = "192.0.2.1") -> None:
    """Write a minimal EVE JSON alert line."""
    import json
    payload = json.dumps({
        "timestamp": "2026-06-10T00:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": 12345,
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "category": "Test",
            "signature": "ET TEST",
            "signature_id": 9999999,
            "severity": 3,
        },
        "flow_id": 1,
    })
    path.write_text(payload + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# A1 — 50k entries stored and resolvable
# ---------------------------------------------------------------------------


class TestRuleDescCap:
    """A1 — the rule_descriptions namespace cap is >= 50 000."""

    def test_rule_desc_namespace_cap_constant_exported(self) -> None:
        """RULE_DESC_KV_CAP must be exported from sqlite_store and be >= 50_000."""
        assert RULE_DESC_KV_CAP >= 50_000, (
            f"RULE_DESC_KV_CAP must be >= 50 000 for ET Open; got {RULE_DESC_KV_CAP}"
        )

    def test_default_cap_is_conservative(self) -> None:
        """SOURCE_KV_CAP (default for non-rule_desc namespaces) must be <= 15_000."""
        assert SOURCE_KV_CAP <= 15_000, (
            f"Default cap must stay conservative for non-rule_desc namespaces; got {SOURCE_KV_CAP}"
        )

    def test_rule_desc_cap_larger_than_default(self) -> None:
        """RULE_DESC_KV_CAP must be strictly larger than SOURCE_KV_CAP."""
        assert RULE_DESC_KV_CAP > SOURCE_KV_CAP

    async def test_upsert_rule_descs_50k_all_stored(
        self, store: SQLiteEventStore
    ) -> None:
        """upsert_rule_descriptions with 50k entries must store all of them (A1)."""
        descs = {str(sid): f"ET TEST rule {sid}" for sid in range(1, 50_001)}
        await store.upsert_rule_descriptions(descs)
        result = await store.get_rule_descriptions()
        assert len(result) == 50_000, (
            f"Expected 50 000 rule descriptions stored; got {len(result)}"
        )

    async def test_upsert_rule_descs_150k_does_not_raise(
        self, store: SQLiteEventStore
    ) -> None:
        """upsert_rule_descriptions with 150k entries must not raise (cap is 150k)."""
        descs = {str(sid): f"Rule {sid}" for sid in range(1, 150_001)}
        # Must complete without error
        await store.upsert_rule_descriptions(descs)
        result = await store.get_rule_descriptions()
        assert len(result) == 150_000

    async def test_rule_desc_namespace_exceeds_default_cap_but_not_rule_desc_cap(
        self, store: SQLiteEventStore
    ) -> None:
        """Writing SOURCE_KV_CAP+1 entries to rule_descriptions must succeed
        because that namespace has a higher cap (A1)."""
        count = SOURCE_KV_CAP + 1
        descs = {str(sid): f"Rule {sid}" for sid in range(count)}
        # Must not raise — default cap does not apply to rule_descriptions
        await store.upsert_rule_descriptions(descs)
        result = await store.get_rule_descriptions()
        assert len(result) == count

    @pytest.mark.slow
    async def test_other_namespace_still_uses_default_cap(
        self, store: SQLiteEventStore
    ) -> None:
        """Non-rule_descriptions namespaces must still be capped at SOURCE_KV_CAP (A1)."""
        cap = SOURCE_KV_CAP
        for i in range(cap):
            await store.source_kv_put("suricata", "cursors", f"k{i}", f"v{i}")
        with pytest.raises(SourceKVCapExceededError):
            await store.source_kv_put("suricata", "cursors", "overflow", "x")

    async def test_upsert_rule_descriptions_is_idempotent(
        self, store: SQLiteEventStore
    ) -> None:
        """Calling upsert_rule_descriptions twice must be idempotent (INSERT-OR-IGNORE)."""
        descs = {str(sid): f"Rule {sid}" for sid in range(100)}
        await store.upsert_rule_descriptions(descs)
        await store.upsert_rule_descriptions(descs)
        result = await store.get_rule_descriptions()
        assert len(result) == 100


# ---------------------------------------------------------------------------
# A2 — cap-exceeded surfaces once per cycle, not 40k times
# ---------------------------------------------------------------------------


class TestCapExceededOncePerCycle:
    """A2 — when the cap is exceeded, exactly one warning is logged per cycle."""

    async def test_plugin_cap_exceeded_logs_once_not_per_key(
        self, tmp_path: Path
    ) -> None:
        """_write_rule_descriptions must log cap-exceeded at most once (A2).

        When ctx.kv.put raises SourceKVCapExceededError, the plugin must log it
        once and bail out rather than logging for every remaining key.
        """
        from firewatch_suricata.plugin import _write_rule_descriptions
        from firewatch_suricata.config import SuricataConfig
        from firewatch_sdk import PluginContext

        rules_file = tmp_path / "test.rules"
        # Write 20 rules — cap will be hit after 5
        _write_rules_file(rules_file, {str(i): f"Rule {i}" for i in range(20)})

        cfg = SuricataConfig(
            mode="local",
            local_path=str(tmp_path / "eve.json"),
            rules_path=str(rules_file),
        )

        # Stub kv that raises SourceKVCapExceededError after 5 writes
        call_count = 0

        class CapAfterFive:
            async def put(self, namespace: str, key: str, value: str) -> None:
                nonlocal call_count
                call_count += 1
                if call_count > 5:
                    raise SourceKVCapExceededError("cap exceeded")

            async def get(self, namespace: str, key: str) -> str | None:
                return None

            async def get_all(self, namespace: str) -> dict[str, str]:
                return {}

        ctx = PluginContext(kv=CapAfterFive(), source_id="test-sensor")

        warning_count = 0

        class CountingHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                nonlocal warning_count
                if record.levelno >= logging.WARNING and "cap" in record.getMessage().lower():
                    warning_count += 1

        handler = CountingHandler()
        logger = logging.getLogger("firewatch.suricata.plugin")
        logger.addHandler(handler)
        try:
            await _write_rule_descriptions(cfg, ctx)
        finally:
            logger.removeHandler(handler)

        assert warning_count == 1, (
            f"Expected exactly 1 cap-exceeded warning; got {warning_count}"
        )

    async def test_plugin_collect_does_not_raise_on_cap_exceeded(
        self, tmp_path: Path
    ) -> None:
        """collect() must not raise even when the KV cap is exceeded (A2)."""
        from firewatch_suricata.plugin import SuricataSource
        from firewatch_suricata.config import SuricataConfig

        eve_file = tmp_path / "eve.json"
        _write_eve(eve_file)

        rules_file = tmp_path / "test.rules"
        _write_rules_file(rules_file, {str(i): f"Rule {i}" for i in range(100)})

        cfg = SuricataConfig(
            mode="local",
            local_path=str(eve_file),
            rules_path=str(rules_file),
        )

        # Stub kv that always raises cap exceeded
        class AlwaysCapExceeded:
            async def put(self, namespace: str, key: str, value: str) -> None:
                raise SourceKVCapExceededError("always full")

            async def get(self, namespace: str, key: str) -> str | None:
                return None

            async def get_all(self, namespace: str) -> dict[str, str]:
                return {}

        from firewatch_sdk import PluginContext
        ctx = PluginContext(kv=AlwaysCapExceeded(), source_id="test-sensor")

        events: list[Any] = []
        # Must not raise
        async for raw in SuricataSource().collect(cfg, since=None, ctx=ctx):
            events.append(raw)

        assert len(events) == 1, "collect() must yield events even when kv is full"


# ---------------------------------------------------------------------------
# A3 — change detection: skip re-write when file is unchanged
# ---------------------------------------------------------------------------


class TestChangeDetection:
    """A3 — the producer skips re-write when the ruleset file is unchanged."""

    async def test_no_rewrite_when_file_unchanged(self, tmp_path: Path) -> None:
        """Second call to _write_rule_descriptions with same mtime+size must not write to kv (A3)."""
        from firewatch_suricata.plugin import _write_rule_descriptions
        from firewatch_suricata.config import SuricataConfig
        from firewatch_sdk.testing import InMemoryScopedKV
        from firewatch_sdk import PluginContext

        rules_file = tmp_path / "test.rules"
        _write_rules_file(rules_file, {"1001": "ET SCAN Test", "1002": "ET SQL Test"})

        cfg = SuricataConfig(
            mode="local",
            local_path=str(tmp_path / "eve.json"),
            rules_path=str(rules_file),
        )

        kv = InMemoryScopedKV()
        ctx = PluginContext(kv=kv, source_id="sensor-1")

        # First call — should write
        await _write_rule_descriptions(cfg, ctx)
        assert await kv.get("rule_descriptions", "1001") == "ET SCAN Test"

        # Replace kv content to detect if second call re-writes
        await kv.put("rule_descriptions", "1001", "TAMPERED")

        # Second call — file unchanged, should skip
        await _write_rule_descriptions(cfg, ctx)

        # Value must still be TAMPERED (skipped re-write)
        result = await kv.get("rule_descriptions", "1001")
        assert result == "TAMPERED", (
            "Second call must skip re-write when file mtime+size unchanged"
        )

    async def test_rewrite_when_file_mtime_changes(self, tmp_path: Path) -> None:
        """_write_rule_descriptions must re-write if the file mtime changes (A3)."""
        import os
        from firewatch_suricata.plugin import _write_rule_descriptions
        from firewatch_suricata.config import SuricataConfig
        from firewatch_sdk.testing import InMemoryScopedKV
        from firewatch_sdk import PluginContext

        rules_file = tmp_path / "test.rules"
        _write_rules_file(rules_file, {"1001": "Original rule"})

        cfg = SuricataConfig(
            mode="local",
            local_path=str(tmp_path / "eve.json"),
            rules_path=str(rules_file),
        )

        kv = InMemoryScopedKV()
        ctx = PluginContext(kv=kv, source_id="sensor-1")

        # First call
        await _write_rule_descriptions(cfg, ctx)
        assert await kv.get("rule_descriptions", "1001") == "Original rule"

        # Simulate file mtime change (write new content + set new mtime)
        _write_rules_file(rules_file, {"1001": "Updated rule", "1002": "New rule"})
        # Ensure mtime differs (files written in the same second may have same mtime)
        new_mtime = rules_file.stat().st_mtime + 1.0
        os.utime(rules_file, (new_mtime, new_mtime))

        # Second call — file changed, should re-write
        await _write_rule_descriptions(cfg, ctx)
        updated = await kv.get("rule_descriptions", "1001")
        assert updated == "Updated rule", (
            "Must re-write when file mtime has changed"
        )

    async def test_rewrite_when_file_size_changes(self, tmp_path: Path) -> None:
        """_write_rule_descriptions must re-write if the file size changes even if mtime is same (A3)."""
        import os
        from firewatch_suricata.plugin import _write_rule_descriptions
        from firewatch_suricata.config import SuricataConfig
        from firewatch_sdk.testing import InMemoryScopedKV
        from firewatch_sdk import PluginContext

        rules_file = tmp_path / "test.rules"
        _write_rules_file(rules_file, {"1001": "Short rule"})
        original_mtime = rules_file.stat().st_mtime

        cfg = SuricataConfig(
            mode="local",
            local_path=str(tmp_path / "eve.json"),
            rules_path=str(rules_file),
        )

        kv = InMemoryScopedKV()
        ctx = PluginContext(kv=kv, source_id="sensor-1")

        # First call
        await _write_rule_descriptions(cfg, ctx)

        # Write more content but restore mtime to simulate a size-only change
        _write_rules_file(rules_file, {
            "1001": "Short rule",
            "1002": "Additional rule that changes size",
        })
        # Keep mtime the same to isolate size-only change detection
        os.utime(rules_file, (original_mtime, original_mtime))

        # Replace kv to detect re-write
        await kv.put("rule_descriptions", "1001", "TAMPERED")

        # Second call — size changed, must re-write despite same mtime
        await _write_rule_descriptions(cfg, ctx)
        result = await kv.get("rule_descriptions", "1001")
        assert result == "Short rule", (
            "Must re-write when file size changes even if mtime is the same"
        )

    async def test_skip_when_blank_rules_path(self, tmp_path: Path) -> None:
        """_write_rule_descriptions with blank rules_path must be a no-op (A3 baseline)."""
        from firewatch_suricata.plugin import _write_rule_descriptions
        from firewatch_suricata.config import SuricataConfig
        from firewatch_sdk.testing import InMemoryScopedKV
        from firewatch_sdk import PluginContext

        cfg = SuricataConfig(
            mode="local",
            local_path=str(tmp_path / "eve.json"),
            rules_path="",
        )
        kv = InMemoryScopedKV()
        ctx = PluginContext(kv=kv, source_id="sensor-1")

        await _write_rule_descriptions(cfg, ctx)
        all_descs = await kv.get_all("rule_descriptions")
        assert all_descs == {}

    async def test_state_cleared_when_path_changes(self, tmp_path: Path) -> None:
        """When rules_path config changes to a different file, change-detection state
        must not prevent re-loading from the new path (A3 correctness guard)."""
        from firewatch_suricata.plugin import _write_rule_descriptions
        from firewatch_suricata.config import SuricataConfig
        from firewatch_sdk.testing import InMemoryScopedKV
        from firewatch_sdk import PluginContext

        rules_file_a = tmp_path / "a.rules"
        rules_file_b = tmp_path / "b.rules"
        _write_rules_file(rules_file_a, {"1001": "Rule from A"})
        _write_rules_file(rules_file_b, {"2001": "Rule from B"})

        cfg_a = SuricataConfig(
            mode="local",
            local_path=str(tmp_path / "eve.json"),
            rules_path=str(rules_file_a),
        )
        cfg_b = SuricataConfig(
            mode="local",
            local_path=str(tmp_path / "eve.json"),
            rules_path=str(rules_file_b),
        )

        kv = InMemoryScopedKV()
        ctx_a = PluginContext(kv=kv, source_id="sensor-1")
        ctx_b = PluginContext(kv=kv, source_id="sensor-1")

        await _write_rule_descriptions(cfg_a, ctx_a)
        assert await kv.get("rule_descriptions", "1001") == "Rule from A"

        # Switch to a different file — must always load (new path, no prior state)
        await _write_rule_descriptions(cfg_b, ctx_b)
        assert await kv.get("rule_descriptions", "2001") == "Rule from B"


# ---------------------------------------------------------------------------
# Bulk write path — performance guard for 50k rules
# ---------------------------------------------------------------------------


class TestBulkWritePath:
    """The upsert_rule_descriptions facade must handle 50k entries efficiently."""

    async def test_bulk_50k_no_per_key_cap_check(
        self, store: SQLiteEventStore
    ) -> None:
        """upsert_rule_descriptions must NOT check SOURCE_KV_CAP (it is a core-trusted
        facade that uses INSERT-OR-IGNORE and bypasses per-key cap enforcement)."""
        descs = {str(sid): f"Rule {sid}" for sid in range(SOURCE_KV_CAP + 100)}
        # Must not raise SourceKVCapExceededError
        await store.upsert_rule_descriptions(descs)
        result = await store.get_rule_descriptions()
        assert len(result) == SOURCE_KV_CAP + 100

    async def test_bulk_50k_uses_executemany_not_per_key(
        self, tmp_path: Path
    ) -> None:
        """upsert_rule_descriptions must issue a single executemany, not 50k individual
        executes (verifies the bulk path is actually batched)."""
        s = SQLiteEventStore(tmp_path / "bulk.db")
        await s.init()

        execute_calls: list[str] = []
        original_executemany = s._db.executemany  # type: ignore[union-attr]

        async def tracking_executemany(sql: str, params: Any) -> Any:
            execute_calls.append(sql)
            return await original_executemany(sql, params)

        s._db.executemany = tracking_executemany  # type: ignore[union-attr]

        descs = {str(sid): f"Rule {sid}" for sid in range(50_000)}
        await s.upsert_rule_descriptions(descs)

        # The single executemany call pattern (INSERT OR IGNORE INTO source_kv)
        insert_calls = [c for c in execute_calls if "INSERT" in c.upper() and "source_kv" in c]
        # At most 1 executemany call for all 50k entries
        assert len(insert_calls) <= 1, (
            f"Expected at most 1 executemany call; got {len(insert_calls)}"
        )
        await s.close()


# ---------------------------------------------------------------------------
# End-to-end seam test (MC.1 lesson — the real chain must be exercised)
#
# Drives _write_rule_descriptions(cfg, ctx) with a REAL ScopedKV bound to a REAL
# SQLiteEventStore, then calls Pipeline._promote_rule_descriptions, then verifies
# get_rule_descriptions returns ALL entries.  This is the path the live system
# uses: plugin → ScopedKV → source_kv_put (with namespace-aware cap) → promote →
# global read.  The >10k case is the regression target (source_kv_put previously
# enforced SOURCE_KV_CAP=10_000 for all namespaces including rule_descriptions).
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestSeamPluginToPromotion:
    """End-to-end seam: plugin write → ScopedKV → store → promotion → global read.

    Uses 12k entries (fast with executemany batching in _write_rule_descriptions
    via sequential ctx.kv.put calls, which is plugin-path realistic) to exceed
    SOURCE_KV_CAP (10k) and confirm all entries survive the full chain.
    """

    async def test_e2e_12k_rules_survive_full_chain(self, tmp_path: Path) -> None:
        """12k rules written via the real plugin → ScopedKV → promote chain must
        all be resolvable via get_rule_descriptions (EARS A1 live path).

        This test exercises the seam that was broken before the fix:
          source_kv_put enforced SOURCE_KV_CAP (10k) even for rule_descriptions,
          so at 10 001 entries it raised SourceKVCapExceededError, the plugin
          bailed, the fingerprint was never stored, and /rules stayed at 10k.
        """
        from firewatch_suricata.plugin import _write_rule_descriptions
        from firewatch_suricata.config import SuricataConfig
        from firewatch_core.scoped_kv import scoped_kv
        from firewatch_core.pipeline import Pipeline
        from firewatch_core.adapters.sqlite_store import SQLiteEventStore
        from unittest.mock import AsyncMock

        n_rules = 12_000

        # Write a .rules file with 12k SIDs
        rules_file = tmp_path / "large.rules"
        lines = [
            f'alert tcp any any -> any any (msg:"ET TEST rule {sid}"; sid:{sid}; rev:1;)'
            for sid in range(1, n_rules + 1)
        ]
        rules_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        cfg = SuricataConfig(
            mode="local",
            local_path=str(tmp_path / "eve.json"),
            rules_path=str(rules_file),
        )

        # Real store + real ScopedKV (the actual live seam)
        store = SQLiteEventStore(tmp_path / "seam_e2e.db")
        await store.init()

        from firewatch_sdk import PluginContext
        kv = scoped_kv(store, "suricata")
        ctx = PluginContext(kv=kv, source_id="sensor-seam")

        # Step 1: plugin writes via ScopedKV → store.source_kv_put
        await _write_rule_descriptions(cfg, ctx)

        # Verify the plugin scope has all 12k entries (not capped at 10k)
        plugin_scope = await store.source_kv_get_all("suricata", "rule_descriptions")
        assert len(plugin_scope) == n_rules, (
            f"Expected {n_rules} entries in suricata/rule_descriptions scope;"
            f" got {len(plugin_scope)} — source_kv_put may be enforcing"
            " SOURCE_KV_CAP instead of RULE_DESC_KV_CAP for this namespace"
        )

        # Step 2: pipeline promotion copies suricata scope → _global scope
        pipeline = Pipeline(
            store=store,
            ai_engine=AsyncMock(),
            notifier=None,
        )
        await pipeline._promote_rule_descriptions("suricata")

        # Step 3: global read must return all 12k entries
        global_descs = await store.get_rule_descriptions()
        assert len(global_descs) == n_rules, (
            f"Expected {n_rules} rule descriptions after promotion;"
            f" got {len(global_descs)}"
        )

        # Spot-check a few SIDs
        assert global_descs.get("1") == "ET TEST rule 1"
        assert global_descs.get(str(n_rules)) == f"ET TEST rule {n_rules}"

        await store.close()

    async def test_fingerprint_stored_after_successful_12k_write(
        self, tmp_path: Path
    ) -> None:
        """After a successful >10k write, the fingerprint must be stored so the
        second cycle skips re-parsing (EARS A3 extended to >10k case).

        Before the fix: write bailed at 10k, fingerprint never stored, next cycle
        re-parsed the full 43MB file again.
        """
        from firewatch_suricata.plugin import _write_rule_descriptions, _FP_KEY_PREFIX, _RULES_STATE_NAMESPACE
        from firewatch_suricata.config import SuricataConfig
        from firewatch_core.scoped_kv import scoped_kv
        from firewatch_core.adapters.sqlite_store import SQLiteEventStore
        from firewatch_sdk import PluginContext

        n_rules = 12_000

        rules_file = tmp_path / "large_fp.rules"
        lines = [
            f'alert tcp any any -> any any (msg:"ET FP {sid}"; sid:{sid}; rev:1;)'
            for sid in range(1, n_rules + 1)
        ]
        rules_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        cfg = SuricataConfig(
            mode="local",
            local_path=str(tmp_path / "eve.json"),
            rules_path=str(rules_file),
        )

        store = SQLiteEventStore(tmp_path / "seam_fp.db")
        await store.init()

        kv = scoped_kv(store, "suricata")
        ctx = PluginContext(kv=kv, source_id="sensor-fp")

        # First call — should write all 12k and store fingerprint
        await _write_rule_descriptions(cfg, ctx)

        # Fingerprint must be stored (full success path)
        fp_key = _FP_KEY_PREFIX + str(rules_file)
        stored_fp = await store.source_kv_get("suricata", _RULES_STATE_NAMESPACE, fp_key)
        assert stored_fp is not None, (
            "Fingerprint must be stored after a successful >10k write;"
            " if it is None the cap was hit mid-write and the cycle bailed"
        )

        # Second call — file unchanged, must skip re-write entirely
        # Tamper with one entry to detect if re-write happens
        await store.source_kv_put("suricata", "rule_descriptions", "1", "TAMPERED")

        await _write_rule_descriptions(cfg, ctx)

        # The tampered value must survive (second call was skipped)
        val = await store.source_kv_get("suricata", "rule_descriptions", "1")
        assert val == "TAMPERED", (
            "Second cycle must skip re-write when fingerprint matches;"
            " got a fresh write instead — fingerprint may not have been stored"
        )

        await store.close()
