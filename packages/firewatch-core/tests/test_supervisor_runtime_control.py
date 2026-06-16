"""Supervisor runtime-control surface tests (EARS #136 / ADR-0031 §C/§D).

Tests are written FIRST per the testing-conventions skill.
All IPs use RFC 5737 documentation ranges (gitleaks gate).

Test-to-EARS mapping
────────────────────
EARS-RC-1 — Event-driven: register_idle → record in idle, NOT scheduled
  test_register_idle_creates_idle_record_not_scheduled

EARS-RC-2 — Event-driven: register_idle idempotent per (type,id)
  test_register_idle_idempotent

EARS-RC-3 — Event-driven: enable_pull(idle) → running + scheduled
  test_enable_pull_transitions_idle_to_running

EARS-RC-4 — Event-driven: enable_pull idempotent on already-running
  test_enable_pull_idempotent_on_running

EARS-RC-5 — Event-driven: disable(running) → cancels task, returns to idle
  test_disable_running_to_idle

EARS-RC-6 — State-driven: idle instance can run one manual pull cycle
  test_idle_instance_supports_manual_sync

EARS-RC-7 — Event-driven: set_interval applies on next tick without restart
  test_set_interval_applies_on_next_tick

EARS-RC-8 — Event-driven: pull cycle records last-sync fields on record + status()
  test_last_sync_fields_updated_after_cycle
  test_last_sync_error_recorded_on_failure
  test_last_sync_status_no_data_when_no_events

EARS-RC-9 — Unwanted: idle/parked/stopped all-idle supervisor with API host keeps alive
  test_all_idle_does_not_trigger_stopped_predicate

EARS-RC-10 — Ubiquitous: status() exposes idle state and last-sync fields
  test_status_includes_idle_state
  test_status_includes_last_sync_fields

EARS-RC-11 — Behavior-preserving: startup() still launches STOPPED (pre-registered) instances
  test_startup_still_launches_pre_registered_stopped_instances
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

import pytest
from pydantic import BaseModel

from firewatch_sdk import PluginContext, RawEvent, SecurityEvent, SourceMetadata

from firewatch_core.supervisor import (
    InstanceState,
    Supervisor,
    SupervisorConfig,
)

# RFC 5737 documentation IPs (gitleaks gate)
_IP_A = "203.0.113.10"
_IP_B = "203.0.113.20"


# --------------------------------------------------------------------------- #
# Fakes / test doubles                                                         #
# --------------------------------------------------------------------------- #


class _FakeCfg(BaseModel):
    note: str = "fake"


def _raw_event(ip: str = _IP_A) -> RawEvent:
    return RawEvent(
        source_type="pull_src",
        data={"src_ip": ip},
        received_at=datetime.now(timezone.utc),
    )


def _sec_event(source_type: str = "pull_src", source_id: str = "i1") -> SecurityEvent:
    return SecurityEvent(
        source_type=source_type,
        source_id=source_id,
        action="ALERT",
        severity="medium",
        category="test",
        rule_id="r1",
        rule_name="Test",
        source_ip=_IP_A,
        payload_snippet="x",
        timestamp=datetime.now(timezone.utc),
    )


class _FakePullPlugin:
    """Minimal PullSource+SourcePlugin double."""

    def __init__(
        self,
        type_key: str = "pull_src",
        events_per_cycle: int = 1,
        fail_on_cycle: int | None = None,
    ) -> None:
        self._type_key = type_key
        self._events_per_cycle = events_per_cycle
        self._fail_on_cycle = fail_on_cycle
        self.cycle_count = 0

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name="Pull Src",
            version="1.0.0",
            flavor="pull",
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakeCfg

    def validate_config(self, cfg: dict[str, Any]) -> None:
        pass

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        return _sec_event(source_type=self._type_key, source_id=source_id)

    async def health_check(self, cfg: BaseModel) -> bool:
        return True

    async def collect(
        self,
        cfg: BaseModel,
        since: str | None,
        ctx: PluginContext,
    ) -> AsyncIterator[RawEvent]:
        self.cycle_count += 1
        if self._fail_on_cycle is not None and self.cycle_count == self._fail_on_cycle:
            raise RuntimeError("deliberate cycle failure")
        for _ in range(self._events_per_cycle):
            yield _raw_event()


class _FakeStore:
    """Minimal EventStore double."""

    def __init__(self) -> None:
        self.watermarks: dict[tuple[str, str], str] = {}
        self._kv: dict[tuple[str, str, str], str] = {}

    async def get_watermark(self, source_type: str, source_id: str) -> str | None:
        return self.watermarks.get((source_type, source_id))

    async def set_watermark(self, ts: str, source_type: str, source_id: str) -> None:
        self.watermarks[(source_type, source_id)] = ts

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
        prefix = (source_type, namespace)
        return {k: v for (st, ns, k), v in self._kv.items() if (st, ns) == prefix}


class _FakePipeline:
    """Minimal Pipeline double for supervisor tests."""

    def __init__(self, store: _FakeStore | None = None) -> None:
        self._store = store or _FakeStore()
        self.ingested: list[SecurityEvent] = []

    @property
    def store(self) -> _FakeStore:
        return self._store

    async def run_pull_cycle(
        self, plugin: Any, cfg: Any, source_id: str, ctx: PluginContext
    ) -> int:
        events: list[SecurityEvent] = []
        async for raw in plugin.collect(cfg, None, ctx):
            events.append(plugin.normalize(raw, source_id))
        if events:
            await self.ingest(events)
        return len(events)

    async def ingest(self, events: list[SecurityEvent]) -> None:
        self.ingested.extend(events)


def _fast_cfg() -> SupervisorConfig:
    return SupervisorConfig(
        backoff_base=0.001,
        backoff_cap=0.001,
        storm_threshold=100,
        storm_window_s=60.0,
        shutdown_grace=0.1,
    )


# --------------------------------------------------------------------------- #
# EARS-RC-1: register_idle creates idle record, NOT scheduled                  #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_register_idle_creates_idle_record_not_scheduled() -> None:
    """WHEN register_idle is called, supervisor SHALL create a record in IDLE
    and SHALL NOT schedule it (no task launched)."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin()

    rec = sup.register_idle(
        plugin,
        _FakeCfg(),
        source_id="i1",
        flavor="pull",
        interval=60.0,
        transport="file",
    )

    assert rec.state == InstanceState.IDLE
    assert rec.task is None
    assert len(sup._instances) == 1

    # startup() should NOT launch idle instances
    await sup.startup()
    assert rec.task is None
    assert rec.state == InstanceState.IDLE

    await sup.shutdown()


# --------------------------------------------------------------------------- #
# EARS-RC-2: register_idle is idempotent                                       #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_register_idle_idempotent() -> None:
    """Calling register_idle twice for the same (type,id) SHALL return the same
    record and not duplicate it in _instances."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin()

    rec1 = sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    rec2 = sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )

    assert rec1 is rec2
    assert len(sup._instances) == 1
    await sup.shutdown()


# --------------------------------------------------------------------------- #
# EARS-RC-3: enable_pull transitions idle to running                           #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_enable_pull_transitions_idle_to_running() -> None:
    """WHEN enable_pull is called on an idle pull instance, it SHALL transition
    to RUNNING and begin scheduling."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin(events_per_cycle=0)

    sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    await sup.startup()

    sup.enable_pull("pull_src", "i1", interval=0.01)

    # Allow the task to spin up
    await asyncio.sleep(0.05)

    rec = sup.get_instance("pull_src", "i1")
    assert rec is not None
    assert rec.state == InstanceState.RUNNING
    assert rec.task is not None

    await sup.shutdown()


# --------------------------------------------------------------------------- #
# EARS-RC-4: enable_pull idempotent on already-running                         #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_enable_pull_idempotent_on_running() -> None:
    """Calling enable_pull on an already-running instance SHALL be idempotent
    (no second task created, state stays RUNNING)."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin(events_per_cycle=0)

    sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    await sup.startup()
    sup.enable_pull("pull_src", "i1", interval=0.01)
    await asyncio.sleep(0.02)

    rec_before = sup.get_instance("pull_src", "i1")
    assert rec_before is not None
    task_before = rec_before.task

    sup.enable_pull("pull_src", "i1", interval=0.01)  # idempotent

    rec_after = sup.get_instance("pull_src", "i1")
    assert rec_after is not None
    assert rec_after is rec_before
    assert rec_after.state == InstanceState.RUNNING
    # Same task — no restart
    assert rec_after.task is task_before

    await sup.shutdown()


# --------------------------------------------------------------------------- #
# EARS-RC-5: disable transitions running to idle                               #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_disable_running_to_idle() -> None:
    """WHEN disable is called on a running instance, it SHALL cancel the task
    and return the record to IDLE state."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin(events_per_cycle=0)

    sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    await sup.startup()
    sup.enable_pull("pull_src", "i1", interval=0.01)
    await asyncio.sleep(0.02)

    rec = sup.get_instance("pull_src", "i1")
    assert rec is not None
    assert rec.state == InstanceState.RUNNING

    await sup.disable("pull_src", "i1")
    await asyncio.sleep(0.05)

    rec = sup.get_instance("pull_src", "i1")
    assert rec is not None
    assert rec.state == InstanceState.IDLE
    assert rec.task is None

    await sup.shutdown()


# --------------------------------------------------------------------------- #
# EARS-RC-6: idle instance can run one manual pull cycle                       #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_idle_instance_supports_manual_sync() -> None:
    """WHILE a source is idle, run_pull_cycle_for SHALL execute one cycle."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin(events_per_cycle=2)

    sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    await sup.startup()

    await sup.run_pull_cycle_for("pull_src", "i1")

    assert plugin.cycle_count == 1
    assert len(pipeline.ingested) == 2

    await sup.shutdown()


# --------------------------------------------------------------------------- #
# EARS-RC-7: set_interval applies on next tick without restart                 #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_set_interval_applies_on_next_tick() -> None:
    """WHEN set_interval is called on a running instance, the new interval SHALL
    take effect on the next tick without restarting the task."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin(events_per_cycle=0)

    sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    await sup.startup()
    sup.enable_pull("pull_src", "i1", interval=60.0)
    await asyncio.sleep(0.02)

    rec = sup.get_instance("pull_src", "i1")
    assert rec is not None
    task_before = rec.task

    sup.set_interval("pull_src", "i1", 30.0)

    await asyncio.sleep(0.02)
    rec_after = sup.get_instance("pull_src", "i1")
    assert rec_after is not None
    assert rec_after._pull_interval == 30.0
    # Same task — no restart
    assert rec_after.task is task_before

    await sup.shutdown()


# --------------------------------------------------------------------------- #
# EARS-RC-8: last-sync fields updated after cycle                              #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_last_sync_fields_updated_after_cycle() -> None:
    """WHEN a pull cycle completes, last_sync_at/last_sync_ingested/last_sync_status
    SHALL be updated and exposed via Supervisor.status()."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin(events_per_cycle=3)

    sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    await sup.startup()

    t_before = time.time()
    await sup.run_pull_cycle_for("pull_src", "i1")

    statuses = sup.status()
    assert len(statuses) == 1
    s = statuses[0]

    assert s.last_sync_at is not None
    assert s.last_sync_at >= t_before
    assert s.last_sync_ingested == 3
    assert s.last_sync_status == "ok"
    assert s.last_error is None

    await sup.shutdown()


@pytest.mark.asyncio
async def test_last_sync_error_recorded_on_failure() -> None:
    """WHEN a pull cycle raises, last_sync_status='error' and last_error
    SHALL contain the error message."""
    store = _FakeStore()

    class _FailingPipeline(_FakePipeline):
        async def run_pull_cycle(
            self, plugin: Any, cfg: Any, source_id: str, ctx: PluginContext
        ) -> int:
            raise RuntimeError("upstream unavailable")

    fail_pipeline = _FailingPipeline(store)
    sup = Supervisor(fail_pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin()

    sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    await sup.startup()

    try:
        await sup.run_pull_cycle_for("pull_src", "i1")
    except Exception:
        pass

    statuses = sup.status()
    s = statuses[0]
    assert s.last_sync_status == "error"
    assert s.last_error is not None
    assert "upstream unavailable" in s.last_error

    await sup.shutdown()


@pytest.mark.asyncio
async def test_last_sync_status_no_data_when_no_events() -> None:
    """WHEN a cycle completes with zero ingested events, last_sync_status='no_data'."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin(events_per_cycle=0)

    sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    await sup.startup()

    await sup.run_pull_cycle_for("pull_src", "i1")

    statuses = sup.status()
    s = statuses[0]
    assert s.last_sync_status == "no_data"
    assert s.last_sync_ingested == 0

    await sup.shutdown()


# --------------------------------------------------------------------------- #
# EARS-RC-9: all-idle does NOT trigger the stopped predicate                   #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_all_idle_does_not_trigger_stopped_predicate() -> None:
    """WHILE all instances are idle, the supervisor SHALL NOT signal stopped."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin()

    sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    await sup.startup()

    assert not sup.is_stopped
    sup._maybe_signal_stopped()
    assert not sup.is_stopped

    await sup.shutdown()


# --------------------------------------------------------------------------- #
# EARS-RC-10: status() exposes idle state and last-sync fields                 #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_status_includes_idle_state() -> None:
    """status() SHALL include 'idle' as a valid state value."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin()

    sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    await sup.startup()

    statuses = sup.status()
    assert len(statuses) == 1
    assert statuses[0].state == "idle"

    await sup.shutdown()


@pytest.mark.asyncio
async def test_status_includes_last_sync_fields() -> None:
    """status() DTOs SHALL contain last_sync_at, last_sync_ingested,
    last_sync_status, last_error fields (all None/0 before any cycle)."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin()

    sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    await sup.startup()

    statuses = sup.status()
    s = statuses[0]
    assert hasattr(s, "last_sync_at")
    assert hasattr(s, "last_sync_ingested")
    assert hasattr(s, "last_sync_status")
    assert hasattr(s, "last_error")
    assert s.last_sync_at is None
    assert s.last_sync_ingested == 0
    assert s.last_sync_status is None
    assert s.last_error is None

    await sup.shutdown()


# --------------------------------------------------------------------------- #
# EARS-RC-11: startup() still launches pre-registered STOPPED instances        #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_startup_still_launches_pre_registered_stopped_instances() -> None:
    """Behavior-preserving: add_pull instances (state=STOPPED) SHALL still be
    launched by startup() as before (no regression)."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin(events_per_cycle=0)

    rec = sup.add_pull(plugin, _FakeCfg(), source_id="i1", interval=0.01)
    assert rec.state == InstanceState.STOPPED

    await sup.startup()
    await asyncio.sleep(0.02)

    assert rec.state == InstanceState.RUNNING

    await sup.shutdown()


# --------------------------------------------------------------------------- #
# EARS-RC-12: manual-sync ingested count is real, not zero                    #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_manual_sync_returns_real_ingested_count() -> None:
    """WHEN run_pull_cycle_for inserts N new rows, it SHALL return N.

    Regression guard: the old code used ``pipeline.ingested`` (a test-only
    attribute absent in production) and therefore always returned 0.  The fix
    uses the return value of ``pipeline.run_pull_cycle`` directly.
    """
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin(events_per_cycle=7)

    sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    await sup.startup()

    ingested = await sup.run_pull_cycle_for("pull_src", "i1")

    assert ingested == 7

    await sup.shutdown()


@pytest.mark.asyncio
async def test_manual_sync_last_sync_ingested_matches_return_value() -> None:
    """WHEN run_pull_cycle_for completes, rec.last_sync_ingested SHALL equal the
    real inserted count (not 0 from the old ``pipeline.ingested`` fallback)."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin(events_per_cycle=4)

    sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    await sup.startup()

    ingested = await sup.run_pull_cycle_for("pull_src", "i1")

    statuses = sup.status()
    assert len(statuses) == 1
    s = statuses[0]
    assert s.last_sync_ingested == 4
    assert s.last_sync_ingested == ingested
    assert s.last_sync_status == "ok"

    await sup.shutdown()


@pytest.mark.asyncio
async def test_manual_sync_zero_events_records_no_data_status() -> None:
    """WHEN a manual sync produces 0 net-new rows, last_sync_status SHALL be
    'no_data' and last_sync_ingested SHALL be 0."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    plugin = _FakePullPlugin(events_per_cycle=0)

    sup.register_idle(
        plugin, _FakeCfg(), source_id="i1", flavor="pull", interval=60.0, transport="file"
    )
    await sup.startup()

    ingested = await sup.run_pull_cycle_for("pull_src", "i1")

    assert ingested == 0
    statuses = sup.status()
    s = statuses[0]
    assert s.last_sync_ingested == 0
    assert s.last_sync_status == "no_data"

    await sup.shutdown()
