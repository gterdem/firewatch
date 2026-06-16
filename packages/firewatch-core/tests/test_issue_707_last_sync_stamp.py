"""Tests for issue #707: every ingest path stamps last_sync_*.

EARS criteria -> test mapping
==============================

EARS-707-1 (auto-sync runner path):
  WHEN the auto-sync background loop completes a pull cycle, the InstanceRecord
  SHALL have last_sync_at, last_sync_ingested, and last_sync_status stamped
  (both on success AND on error).
  -> test_autosync_runner_stamps_last_sync_on_success (existing via runners.py)
  -> test_last_sync_persisted_to_kv_store_on_success (durable path)
  -> test_last_sync_persisted_to_kv_store_on_error

EARS-707-2 (durable persistence — the Never bug):
  AFTER last_sync_* is recorded it SHALL be persisted to the durable KV
  store so a process restart does NOT lose the stamp (and therefore never
  displays 'Last sync: Never' for a source with stored events).
  -> test_persist_sync_state_writes_to_kv
  -> test_persist_sync_state_writes_error_state
  -> test_restore_sync_state_returns_none_when_no_data
  -> test_restore_sync_state_returns_written_data
  -> test_restore_sync_state_multiple_source_ids_are_isolated

EARS-707-3 (startup restore):
  WHEN a supervisor instance is launched and has a persisted last_sync_*
  in the KV store from a previous run, the InstanceRecord SHALL be populated
  so status() never returns None for a source with stored events.
  -> test_last_sync_restored_from_kv_on_startup

EARS-707-4 (cmd_sync_once path):
  WHEN pipeline.run_pull_cycle is called (the path used by cmd_sync_once
  and any future CLI/background path), it SHALL persist last_sync_* to the
  KV store so a subsequent process launch can restore the stamp.
  -> test_pipeline_run_pull_cycle_stamps_last_sync_to_kv

All tests use RFC 5737 / RFC 1918 IPs only (gitleaks gate).
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

from firewatch_sdk import (
    AIEngine,
    EventStore,
    FilterSpec,
    PluginContext,
    RawEvent,
    SecurityEvent,
    SourceMetadata,
)

from firewatch_core.supervisor import Supervisor, SupervisorConfig
from firewatch_core.sync_state import (
    _SYNC_NS,
    persist_sync_state,
    restore_sync_state,
)


# --------------------------------------------------------------------------- #
# Test doubles                                                                  #
# --------------------------------------------------------------------------- #


class _FakeCfg(BaseModel):
    note: str = "fake"


class _FakePullPlugin:
    """Minimal pull plugin for sync-stamp tests."""

    def __init__(
        self,
        type_key: str = "test_src",
        raws: list[RawEvent] | None = None,
        fail: bool = False,
    ) -> None:
        self._type_key = type_key
        self._raws = raws or []
        self._fail = fail

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name=self._type_key,
            version="0.1.0",
            flavor="pull",
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakeCfg

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _FakeCfg.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        return SecurityEvent(
            source_type=raw.source_type,
            source_id=source_id,
            timestamp=raw.received_at,
            source_ip="192.0.2.1",
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True

    async def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]:
        if self._fail:
            raise RuntimeError("simulated collect failure")
        for raw in self._raws:
            yield raw


class _FakeStore:
    """In-memory EventStore satisfying the full EventStore protocol."""

    def __init__(self) -> None:
        self.watermarks: dict[tuple[str, str], str] = {}
        self._events: list[SecurityEvent] = []
        self._kv: dict[tuple[str, str, str], str] = {}

    async def init(self) -> None: ...
    async def close(self) -> None: ...

    async def save_many(self, events: list[SecurityEvent]) -> int:
        self._events.extend(events)
        return len(events)

    async def get_by_ip(self, ip: str) -> list[SecurityEvent]:
        return [e for e in self._events if e.source_ip == ip]

    async def get_by_ip_raw(self, ip: str) -> list[dict[str, Any]]:
        return [e.model_dump() for e in await self.get_by_ip(ip)]

    async def get_recent(self, limit: int) -> list[dict[str, Any]]:
        return []

    async def get_paginated(
        self, limit: int, filters: FilterSpec | None = None
    ) -> dict[str, Any]:
        return {"logs": [], "next_cursor": None, "has_more": False, "total_matching": 0}

    async def get_all_ips(self) -> list[str]:
        return sorted({e.source_ip for e in self._events})

    async def get_ip_summary(self) -> list[dict[str, Any]]:
        return []

    async def get_categories(self) -> list[dict[str, Any]]:
        return []

    async def get_category_summary(self) -> list[dict[str, Any]]:
        return []

    async def get_timeline(
        self, start: str | None, end: str | None
    ) -> list[dict[str, Any]]:
        return []

    async def get_stats(self) -> dict[str, Any]:
        return {}

    async def get_analytics_geo(self) -> list[dict[str, Any]]:
        return []

    async def get_analytics_summary(self) -> dict[str, Any]:
        return {}

    async def get_categories_timeline(
        self, start: str | None, end: str | None
    ) -> list[dict[str, Any]]:
        return []

    async def get_ips_without_geo(self) -> list[str]:
        return []

    async def upsert_ip_geo(self, geo_data: list[dict[str, Any]]) -> None: ...

    async def get_ip_geo(self, ip: str) -> dict[str, Any] | None:
        return None

    async def get_watermark(self, source_type: str, source_id: str) -> str | None:
        self._wm_calls = getattr(self, "_wm_calls", [])
        self._wm_calls.append((source_type, source_id))
        return self.watermarks.get((source_type, source_id))

    async def set_watermark(self, ts: str, source_type: str, source_id: str) -> None:
        self.watermarks[(source_type, source_id)] = ts

    async def source_health(self) -> list[dict[str, Any]]:
        return []

    async def upsert_rule_descriptions(self, descs: dict[str, str]) -> None: ...

    async def get_rule_descriptions(self) -> dict[str, str]:
        return {}

    async def get_events_with_row_ids(self, ip: str) -> list[dict[str, Any]]:
        return []

    async def source_kv_put(
        self, source_type: str, namespace: str, key: str, value: str
    ) -> None:
        self._kv[(source_type, namespace, key)] = value

    async def source_kv_get(
        self, source_type: str, namespace: str, key: str
    ) -> str | None:
        return self._kv.get((source_type, namespace, key))

    async def source_kv_get_all(
        self, source_type: str, namespace: str
    ) -> dict[str, str]:
        return {
            k: v
            for (st, ns, k), v in self._kv.items()
            if st == source_type and ns == namespace
        }

    async def clear(self) -> None:
        self._events.clear()
        self._kv.clear()

    async def delete_older_than(self, days: int) -> int:
        return 0

    async def get_ip_counterfactual(self, ip: str) -> dict[str, Any]:
        return {"total_events": 0, "blocked_events": 0, "unblocked_events": 0}


class _FakeAIEngine:
    """Minimal AIEngine that satisfies the protocol signature."""

    async def is_available(self) -> bool:
        return False

    async def analyze_concise(
        self,
        ip: str,
        total_events: int,
        blocked_events: int,
        rules_triggered: int,
        first_seen: str,
        last_seen: str,
        samples: list[dict[str, Any]],
        security_mode: bool = False,
        correlations: list[Any] | None = None,
    ) -> dict[str, Any]:
        return {"threat_level": "LOW", "confidence": 0.0, "insights": []}

    async def analyze_detailed(
        self,
        ip: str,
        total_events: int,
        blocked_events: int,
        rules_triggered: int,
        first_seen: str,
        last_seen: str,
        samples: list[dict[str, Any]],
        security_mode: bool = False,
        correlations: list[Any] | None = None,
    ) -> dict[str, Any]:
        return {"threat_level": "LOW", "confidence": 0.0, "insights": []}


# Satisfy pyright: these fakes ARE compatible with the protocols at runtime
_fake_store_typed: EventStore = _FakeStore()  # type: ignore[assignment]
_fake_ai_typed: AIEngine = _FakeAIEngine()  # type: ignore[assignment]


def _make_raw() -> RawEvent:
    return RawEvent(
        source_type="test_src",
        received_at=datetime(2026, 6, 14, 12, 0, 0, tzinfo=timezone.utc),
        data={"src_ip": "192.0.2.5"},
    )


# --------------------------------------------------------------------------- #
# EARS-707-2: persist_sync_state / restore_sync_state unit tests               #
# --------------------------------------------------------------------------- #


async def test_persist_sync_state_writes_to_kv() -> None:
    """persist_sync_state must write last_sync_at, ingested, status to source_kv."""
    store = _FakeStore()
    ts = 1718352000.0  # fixed epoch — 2024-06-14 12:00:00 UTC
    await persist_sync_state(
        store=store,  # type: ignore[arg-type]
        source_type="test_src",
        source_id="inst1",
        ts=ts,
        ingested=42,
        status="ok",
        last_error=None,
    )

    key_ts = store._kv.get(("test_src", _SYNC_NS, "inst1:last_sync_at"))
    key_ingested = store._kv.get(("test_src", _SYNC_NS, "inst1:last_sync_ingested"))
    key_status = store._kv.get(("test_src", _SYNC_NS, "inst1:last_sync_status"))

    assert key_ts is not None, "last_sync_at not written to KV"
    assert key_ingested == "42"
    assert key_status == "ok"


async def test_persist_sync_state_writes_error_state() -> None:
    """persist_sync_state must write status=error and last_error to KV."""
    store = _FakeStore()
    ts = 1718352000.0
    await persist_sync_state(
        store=store,  # type: ignore[arg-type]
        source_type="test_src",
        source_id="inst1",
        ts=ts,
        ingested=0,
        status="error",
        last_error="RuntimeError: connection refused",
    )

    key_status = store._kv.get(("test_src", _SYNC_NS, "inst1:last_sync_status"))
    key_error = store._kv.get(("test_src", _SYNC_NS, "inst1:last_error"))
    assert key_status == "error"
    assert key_error == "RuntimeError: connection refused"


async def test_restore_sync_state_returns_none_when_no_data() -> None:
    """restore_sync_state must return None when nothing is stored."""
    store = _FakeStore()
    result = await restore_sync_state(
        store=store,  # type: ignore[arg-type]
        source_type="test_src",
        source_id="inst1",
    )
    assert result is None


async def test_restore_sync_state_returns_written_data() -> None:
    """restore_sync_state must return the data written by persist_sync_state."""
    store = _FakeStore()
    ts = 1718352000.0
    await persist_sync_state(
        store=store,  # type: ignore[arg-type]
        source_type="test_src",
        source_id="inst1",
        ts=ts,
        ingested=7,
        status="ok",
        last_error=None,
    )

    result = await restore_sync_state(
        store=store,  # type: ignore[arg-type]
        source_type="test_src",
        source_id="inst1",
    )
    assert result is not None
    assert abs(result["last_sync_at"] - ts) < 1.0
    assert result["last_sync_ingested"] == 7
    assert result["last_sync_status"] == "ok"
    assert result["last_error"] is None


async def test_restore_sync_state_multiple_source_ids_are_isolated() -> None:
    """Stamps for different source_ids under the same source_type must not bleed."""
    store = _FakeStore()
    await persist_sync_state(
        store=store,  # type: ignore[arg-type]
        source_type="test_src",
        source_id="inst_a",
        ts=1000.0,
        ingested=10,
        status="ok",
        last_error=None,
    )
    await persist_sync_state(
        store=store,  # type: ignore[arg-type]
        source_type="test_src",
        source_id="inst_b",
        ts=2000.0,
        ingested=20,
        status="no_data",
        last_error=None,
    )

    a = await restore_sync_state(store=store, source_type="test_src", source_id="inst_a")  # type: ignore[arg-type]
    b = await restore_sync_state(store=store, source_type="test_src", source_id="inst_b")  # type: ignore[arg-type]

    assert a is not None and a["last_sync_ingested"] == 10
    assert b is not None and b["last_sync_ingested"] == 20


# --------------------------------------------------------------------------- #
# EARS-707-2: integration — auto-sync runner persists stamp to KV              #
# --------------------------------------------------------------------------- #


async def test_last_sync_persisted_to_kv_store_on_success() -> None:
    """After a successful auto-sync cycle the stamp MUST be written to the store.

    This is the 'Azure WAF path': the background runner records last_sync_*
    in-memory (already working) AND now also to the durable KV store so a
    process restart does not reset the stamp to None.
    """
    from firewatch_core.pipeline import Pipeline

    store = _FakeStore()
    pipeline = Pipeline(store, _FakeAIEngine())  # type: ignore[arg-type]
    plugin = _FakePullPlugin(raws=[_make_raw()])

    supervisor = Supervisor(pipeline)  # type: ignore[arg-type]
    supervisor.add_pull(plugin, _FakeCfg(), source_id="test_src", interval=0.05)
    await supervisor.startup()
    await asyncio.sleep(0.2)
    await supervisor.shutdown()

    result = await restore_sync_state(
        store=store,  # type: ignore[arg-type]
        source_type="test_src",
        source_id="test_src",
    )
    assert result is not None, (
        "last_sync_* was NOT persisted to KV after auto-sync cycle; "
        "'Last sync: Never' will reappear on next restart (issue #707)"
    )
    assert result["last_sync_at"] > 0
    assert result["last_sync_ingested"] == 1
    assert result["last_sync_status"] == "ok"


async def test_last_sync_persisted_to_kv_store_on_error() -> None:
    """After a failed cycle the error stamp MUST be written to the store.

    Ensures the UI shows the error timestamp rather than 'Never' when a
    cycle has run but failed.
    """
    from firewatch_core.pipeline import Pipeline

    store = _FakeStore()
    pipeline = Pipeline(store, _FakeAIEngine())  # type: ignore[arg-type]
    plugin = _FakePullPlugin(fail=True)

    supervisor = Supervisor(
        pipeline,  # type: ignore[arg-type]
        cfg=SupervisorConfig(
            backoff_base=0.01,
            backoff_cap=0.01,
            storm_threshold=10,
            storm_window_s=60.0,
        ),
    )
    supervisor.add_pull(plugin, _FakeCfg(), source_id="test_src", interval=0.05)
    await supervisor.startup()
    await asyncio.sleep(0.2)
    await supervisor.shutdown()

    result = await restore_sync_state(
        store=store,  # type: ignore[arg-type]
        source_type="test_src",
        source_id="test_src",
    )
    assert result is not None, (
        "last_sync_* was NOT persisted to KV after a failed cycle; "
        "UI will show 'Never' instead of the error timestamp"
    )
    assert result["last_sync_status"] == "error"


# --------------------------------------------------------------------------- #
# EARS-707-3: startup restore                                                   #
# --------------------------------------------------------------------------- #


async def test_last_sync_restored_from_kv_on_startup() -> None:
    """InstanceRecord.last_sync_at must be populated from KV on instance launch.

    Simulates a process restart: a prior run stored last_sync_* in the KV;
    the new supervisor instance must restore it before the first new cycle so
    status() never shows 'Never' for a source with stored events.
    """
    from firewatch_core.pipeline import Pipeline

    store = _FakeStore()
    prior_ts = time.time() - 3600.0  # one hour ago (simulated prior run)
    await persist_sync_state(
        store=store,  # type: ignore[arg-type]
        source_type="test_src",
        source_id="test_src",
        ts=prior_ts,
        ingested=99,
        status="ok",
        last_error=None,
    )

    # New supervisor (simulated restart) — plugin has no raws so first cycle is no-op
    plugin = _FakePullPlugin(raws=[])
    pipeline = Pipeline(store, _FakeAIEngine())  # type: ignore[arg-type]

    supervisor = Supervisor(pipeline)  # type: ignore[arg-type]
    # Use a large interval so the cycle doesn't complete before we check
    rec = supervisor.add_pull(plugin, _FakeCfg(), source_id="test_src", interval=99999.0)

    # Before startup the record is blank (new process — normal)
    assert rec.last_sync_at is None

    # startup() must restore the persisted stamp into the InstanceRecord
    await supervisor.startup()
    # Give startup restore a moment to propagate (it's async)
    await asyncio.sleep(0.1)

    statuses = supervisor.status()
    assert len(statuses) == 1
    status = statuses[0]

    assert status.last_sync_at is not None, (
        "last_sync_at is None after startup restore — "
        "'Last sync: Never' bug reproduced (issue #707)"
    )
    assert status.last_sync_at >= prior_ts - 1.0

    await supervisor.shutdown()


# --------------------------------------------------------------------------- #
# EARS-707-4: pipeline.run_pull_cycle path (used by cmd_sync_once)             #
# --------------------------------------------------------------------------- #


async def test_pipeline_run_pull_cycle_stamps_last_sync_to_kv() -> None:
    """pipeline.run_pull_cycle must persist last_sync_* to KV after a cycle.

    This covers the 'cmd_sync_once path': the CLI runs pipeline.run_pull_cycle
    directly without going through the supervisor.  After the cycle, the next
    process launch must be able to restore the stamp from KV so the UI never
    shows 'Last sync: Never' for a source with stored events.
    """
    from firewatch_core.pipeline import Pipeline
    from firewatch_core.scoped_kv import scoped_kv

    store = _FakeStore()
    pipeline = Pipeline(store, _FakeAIEngine())  # type: ignore[arg-type]
    plugin = _FakePullPlugin(raws=[_make_raw()])
    cfg = _FakeCfg()

    kv = scoped_kv(store, "test_src")  # type: ignore[arg-type]
    ctx = PluginContext(kv=kv, source_id="test_src")

    inserted = await pipeline.run_pull_cycle(plugin, cfg, "test_src", ctx)
    assert inserted == 1

    # After run_pull_cycle the KV store must contain the stamp
    result = await restore_sync_state(
        store=store,  # type: ignore[arg-type]
        source_type="test_src",
        source_id="test_src",
    )
    assert result is not None, (
        "pipeline.run_pull_cycle did not persist last_sync_* to KV; "
        "next process launch will show 'Last sync: Never' (issue #707)"
    )
    assert result["last_sync_at"] > 0
    assert result["last_sync_ingested"] == 1
    assert result["last_sync_status"] == "ok"
