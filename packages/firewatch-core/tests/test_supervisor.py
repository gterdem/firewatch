"""Supervisor tests (EARS #22 / ADR-0023).

Tests are written FIRST per the testing-conventions skill.
All IPs use RFC 5737 documentation ranges (gitleaks gate).

Test-to-EARS mapping
────────────────────
EARS 1 — Event-driven: pull interval → run_pull_cycle invoked
  test_pull_instance_scheduled_calls_run_pull_cycle

EARS 2 — Event-driven: push start → emit routes into pipeline.ingest
  test_push_emit_routes_to_ingest

EARS 3 — Unwanted: crash isolation (one_for_one)
  test_crash_isolation_one_for_one

EARS 3b — Unwanted: crash → backoff → restart
  test_crash_triggers_backoff_and_restart

EARS 4 — Unwanted (restart storm): >5 crashes/60s → park + alert
  test_restart_storm_parks_instance_and_emits_alert
  test_parked_instance_does_not_restart
  test_other_instances_keep_running_after_storm_park

EARS 5 — Unwanted (DLQ): K=3 failures on same record → DLQ + watermark + alert
  test_poison_record_dlq_after_k_failures
  test_dlq_orthogonal_to_storm_cap

EARS 6 — Unwanted (backpressure): UDP→drop, TCP→block
  test_udp_backpressure_drop_when_queue_full
  test_tcp_backpressure_blocks_when_queue_full

EARS 7 — Event-driven: SIGTERM → drain within grace, then exit
  test_bounded_grace_shutdown
  test_shutdown_cancels_outstanding_tasks_after_grace

EARS 8 — State-driven: during backoff, no second concurrent cycle
  test_no_concurrent_cycle_during_backoff

EARS 9 — Ubiquitous (last-known-good config seam)
  test_config_reload_accepts_valid_config
  test_config_reload_falls_back_to_last_known_good_on_bad_config

EARS 10 — Ubiquitous: SDK-only imports
  test_sdk_only_imports_no_plugin_or_legacy
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

from firewatch_sdk import PluginContext, RawEvent, SecurityEvent, SourceMetadata

from firewatch_core.supervisor import (
    BackpressurePolicy,
    InstanceState,
    PoisonRecordError,
    Supervisor,
    SupervisorConfig,
    _policy_for_transport,
)

# RFC 5737 documentation IPs (gitleaks gate)
_IP_A = "203.0.113.10"
_IP_B = "203.0.113.20"


# --------------------------------------------------------------------------- #
# Test doubles                                                                 #
# --------------------------------------------------------------------------- #


class _FakeCfg(BaseModel):
    note: str = "fake"


class _FakePullPlugin:
    """A PullSource+SourcePlugin test double.

    ``cycles_before_fail``: if > 0, the first N cycles succeed, then raise.
    ``raws``: list of RawEvents yielded per successful cycle.
    ``cycle_count``: total successful cycle completions.
    """

    def __init__(
        self,
        type_key: str = "pull_src",
        raws: list[RawEvent] | None = None,
        fail_after: int | None = None,  # raise RuntimeError after this many successes
    ) -> None:
        self._type_key = type_key
        self._raws = raws or []
        self._fail_after = fail_after
        self.cycle_count = 0

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
            source_ip=_IP_A,
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True

    async def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]:
        for raw in self._raws:
            yield raw


class _FakePushPlugin:
    """A PushSource+SourcePlugin test double.

    ``start()`` calls ``emit(batch)`` for each batch in ``emit_batches``, then
    awaits the stop event.
    """

    def __init__(
        self,
        type_key: str = "push_src",
        emit_batches: list[list[RawEvent]] | None = None,
        fail_on_start: bool = False,
    ) -> None:
        self._type_key = type_key
        self._emit_batches = emit_batches or []
        self._fail_on_start = fail_on_start
        self._stop_event: asyncio.Event = asyncio.Event()
        self.stopped: bool = False

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name=self._type_key,
            version="0.1.0",
            flavor="push",
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
            source_ip=_IP_B,
            action="LOG",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True

    async def start(
        self,
        cfg: BaseModel,
        emit: Callable[[list[RawEvent]], Awaitable[None]],
        ctx: PluginContext,
    ) -> None:
        if self._fail_on_start:
            raise RuntimeError("push plugin simulated start failure")
        self._stop_event = asyncio.Event()
        # Emit each batch, then wait for stop
        for batch in self._emit_batches:
            await emit(batch)
        await self._stop_event.wait()

    async def stop(self) -> None:
        self.stopped = True
        self._stop_event.set()


class _FakePipeline:
    """Minimal pipeline test double.

    Records ``ingest`` calls and ``run_pull_cycle`` calls.
    ``run_pull_cycle`` is delegated to the plugin (to test DLQ etc. we allow
    injection of a side-effect).
    """

    def __init__(
        self,
        *,
        pull_side_effect: Callable[..., Awaitable[int]] | None = None,
    ) -> None:
        self.ingest_calls: list[list[SecurityEvent]] = []
        self.run_pull_cycle_calls: list[tuple[Any, Any, str, PluginContext]] = []
        self._pull_side_effect = pull_side_effect
        self.store = _FakeStore()

    async def ingest(self, events: list[SecurityEvent]) -> int:
        self.ingest_calls.append(events)
        return len(events)

    async def run_pull_cycle(self, plugin: Any, cfg: Any, source_id: str, ctx: PluginContext) -> int:
        self.run_pull_cycle_calls.append((plugin, cfg, source_id, ctx))
        if self._pull_side_effect is not None:
            return await self._pull_side_effect(plugin, cfg, source_id)
        return 0


class _FakeStore:
    """Minimal store test double (for watermark operations)."""

    def __init__(self) -> None:
        self.watermarks: dict[tuple[str, str], str] = {}
        self.set_watermark_calls: list[tuple[str, str, str]] = []

    async def set_watermark(self, ts: str, source_type: str, source_id: str) -> None:
        self.set_watermark_calls.append((ts, source_type, source_id))
        self.watermarks[(source_type, source_id)] = ts

    async def get_watermark(self, source_type: str, source_id: str) -> str | None:
        return self.watermarks.get((source_type, source_id))


def _make_raw(
    source_type: str = "pull_src",
    data: dict[str, Any] | None = None,
    ts: datetime | None = None,
) -> RawEvent:
    return RawEvent(
        source_type=source_type,
        received_at=ts or datetime(2026, 6, 4, 10, 0, 0, tzinfo=timezone.utc),
        data=data or {"src_ip": _IP_A},
    )


def _fast_cfg(**overrides: Any) -> SupervisorConfig:
    """SupervisorConfig with near-zero backoff and short timeouts for test speed."""
    return SupervisorConfig(
        backoff_base=0.0,
        backoff_cap=0.0,
        storm_threshold=5,
        storm_window_s=60.0,
        dlq_threshold=3,
        shutdown_grace=2.0,
        **overrides,
    )


# --------------------------------------------------------------------------- #
# EARS 1 — Pull interval scheduling                                            #
# --------------------------------------------------------------------------- #


async def test_pull_instance_scheduled_calls_run_pull_cycle() -> None:
    """When a pull instance is started, the supervisor calls run_pull_cycle."""
    pipeline = _FakePipeline()
    plugin = _FakePullPlugin()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    sup.add_pull(plugin, _FakeCfg(), source_id="inst-1", interval=0.01)

    await sup.startup()
    # Give the pull loop one tick
    await asyncio.sleep(0.05)
    await sup.shutdown()

    assert len(pipeline.run_pull_cycle_calls) >= 1
    _, _, sid, _ctx = pipeline.run_pull_cycle_calls[0]
    assert sid == "inst-1"


# --------------------------------------------------------------------------- #
# EARS 2 — Push emit routing                                                   #
# --------------------------------------------------------------------------- #


async def test_push_emit_routes_to_ingest() -> None:
    """When a push instance starts, emit routes RawEvent batches into pipeline.ingest."""
    raw = _make_raw("push_src")
    pipeline = _FakePipeline()
    plugin = _FakePushPlugin(emit_batches=[[raw]])
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    sup.add_push(plugin, _FakeCfg(), source_id="push-1", transport="tcp")

    await sup.startup()
    # Wait for the emit batch to be processed
    await asyncio.sleep(0.2)
    await sup.shutdown()

    # ingest should have been called with a SecurityEvent
    assert len(pipeline.ingest_calls) >= 1
    batch = pipeline.ingest_calls[0]
    assert len(batch) == 1
    assert isinstance(batch[0], SecurityEvent)
    assert batch[0].source_id == "push-1"


# --------------------------------------------------------------------------- #
# EARS 3 — Crash isolation (one_for_one)                                       #
# --------------------------------------------------------------------------- #


async def test_crash_isolation_one_for_one() -> None:
    """One crashing pull instance must not affect a sibling that is running fine."""
    pipeline_calls: list[str] = []

    async def side_effect(plugin: Any, cfg: Any, source_id: str) -> int:
        if source_id == "crash-me":
            raise RuntimeError("simulated crash")
        pipeline_calls.append(source_id)
        await asyncio.sleep(0.01)
        return 0

    pipeline = _FakePipeline(pull_side_effect=side_effect)
    crashing_plugin = _FakePullPlugin(type_key="pull_src")
    healthy_plugin = _FakePullPlugin(type_key="pull_src")

    sup = Supervisor(pipeline, cfg=_fast_cfg())
    sup.add_pull(crashing_plugin, _FakeCfg(), source_id="crash-me", interval=0.01)
    sup.add_pull(healthy_plugin, _FakeCfg(), source_id="healthy", interval=0.01)

    await sup.startup()
    await asyncio.sleep(0.15)
    await sup.shutdown()

    # Healthy instance must have been called
    assert "healthy" in pipeline_calls, (
        "healthy instance was not scheduled — crash isolation violated"
    )


async def test_crash_triggers_backoff_and_restart() -> None:
    """After a crash the instance is restarted (attempt increments on backoff)."""
    call_count = 0

    async def failing_then_ok(plugin: Any, cfg: Any, source_id: str) -> int:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("first call fails")
        # Subsequent calls succeed — sleep tiny so the loop doesn't spin forever
        await asyncio.sleep(0.01)
        return 0

    pipeline = _FakePipeline(pull_side_effect=failing_then_ok)
    plugin = _FakePullPlugin()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    sup.add_pull(plugin, _FakeCfg(), source_id="inst-1", interval=0.01)

    await sup.startup()
    await asyncio.sleep(0.2)
    await sup.shutdown()

    # Must have been called more than once (crash + restart)
    assert call_count >= 2, f"expected restart after crash; call_count={call_count}"


# --------------------------------------------------------------------------- #
# EARS 4 — Restart storm → park + alert                                        #
# --------------------------------------------------------------------------- #


async def test_restart_storm_parks_instance_and_emits_alert() -> None:
    """After storm_threshold+1 crashes in storm_window_s, instance is PARKED + alert emitted."""

    async def always_fail(plugin: Any, cfg: Any, source_id: str) -> int:
        raise RuntimeError("always crashes")

    pipeline = _FakePipeline(pull_side_effect=always_fail)
    plugin = _FakePullPlugin()
    # Low threshold so we don't need many crashes
    sup = Supervisor(
        pipeline,
        cfg=SupervisorConfig(
            backoff_base=0.0,
            backoff_cap=0.0,
            storm_threshold=3,
            storm_window_s=60.0,
            shutdown_grace=2.0,
        ),
    )
    sup.add_pull(plugin, _FakeCfg(), source_id="stormy", interval=0.001)

    await sup.startup()
    # Allow enough time for >storm_threshold crashes
    await asyncio.sleep(0.3)

    rec = sup.get_instance("pull_src", "stormy")
    assert rec is not None
    assert rec.state == InstanceState.PARKED, f"expected PARKED, got {rec.state}"

    # Alert must have been emitted
    storm_alerts = [a for a in sup.alerts if a.kind == "storm_park"]
    assert len(storm_alerts) >= 1
    assert storm_alerts[0].source_id == "stormy"

    await sup.shutdown()


async def test_parked_instance_does_not_restart() -> None:
    """A parked instance must not be automatically restarted."""

    async def always_fail(plugin: Any, cfg: Any, source_id: str) -> int:
        raise RuntimeError("always crashes")

    pipeline = _FakePipeline(pull_side_effect=always_fail)
    plugin = _FakePullPlugin()
    sup = Supervisor(
        pipeline,
        cfg=SupervisorConfig(
            backoff_base=0.0,
            backoff_cap=0.0,
            storm_threshold=2,
            storm_window_s=60.0,
            shutdown_grace=2.0,
        ),
    )
    sup.add_pull(plugin, _FakeCfg(), source_id="parked", interval=0.001)

    await sup.startup()
    # Let it park
    await asyncio.sleep(0.3)

    rec = sup.get_instance("pull_src", "parked")
    assert rec is not None
    assert rec.state == InstanceState.PARKED

    # Record crash count at the moment it parked
    crash_count_at_park = rec.total_crashes

    # Wait more — crash count must NOT increase
    await asyncio.sleep(0.1)
    assert rec.total_crashes == crash_count_at_park, (
        "parked instance continued crashing/restarting"
    )

    await sup.shutdown()


async def test_other_instances_keep_running_after_storm_park() -> None:
    """Parking one instance (storm) must not affect other running instances."""
    sibling_calls: list[str] = []

    async def side_effect(plugin: Any, cfg: Any, source_id: str) -> int:
        if source_id == "storm":
            raise RuntimeError("always crashes")
        sibling_calls.append(source_id)
        await asyncio.sleep(0.01)
        return 0

    pipeline = _FakePipeline(pull_side_effect=side_effect)
    plugin_storm = _FakePullPlugin(type_key="pull_src")
    plugin_sibling = _FakePullPlugin(type_key="pull_src")
    sup = Supervisor(
        pipeline,
        cfg=SupervisorConfig(
            backoff_base=0.0,
            backoff_cap=0.0,
            storm_threshold=2,
            storm_window_s=60.0,
            shutdown_grace=2.0,
        ),
    )
    sup.add_pull(plugin_storm, _FakeCfg(), source_id="storm", interval=0.001)
    sup.add_pull(plugin_sibling, _FakeCfg(), source_id="sibling", interval=0.02)

    await sup.startup()
    await asyncio.sleep(0.4)

    rec_storm = sup.get_instance("pull_src", "storm")
    assert rec_storm is not None
    assert rec_storm.state == InstanceState.PARKED

    assert len(sibling_calls) >= 1, "sibling instance was not called after storm park"

    await sup.shutdown()


# --------------------------------------------------------------------------- #
# EARS 5 — DLQ: poison record → dead-letter + watermark advance + alert        #
# --------------------------------------------------------------------------- #


async def test_poison_record_dlq_after_k_failures() -> None:
    """Same record failing dlq_threshold times → DLQ entry, watermark advanced, alert emitted."""
    raw_ts = datetime(2026, 6, 4, 10, 0, 0, tzinfo=timezone.utc)
    poison_raw = _make_raw("pull_src", ts=raw_ts)

    # Simulate a pipeline that raises PoisonRecordError for a specific record
    call_count = 0

    async def poison_side_effect(plugin: Any, cfg: Any, source_id: str) -> int:
        nonlocal call_count
        call_count += 1
        if call_count <= 3:
            raise PoisonRecordError(raw=poison_raw)
        # After dead-lettering, succeed
        await asyncio.sleep(0.01)
        return 0

    pipeline = _FakePipeline(pull_side_effect=poison_side_effect)
    plugin = _FakePullPlugin()
    sup = Supervisor(
        pipeline,
        cfg=SupervisorConfig(
            dlq_threshold=3,
            backoff_base=0.0,
            backoff_cap=0.0,
            shutdown_grace=2.0,
        ),
    )
    sup.add_pull(plugin, _FakeCfg(), source_id="dlq-inst", interval=0.01)

    await sup.startup()
    await asyncio.sleep(0.3)
    await sup.shutdown()

    # DLQ must contain the dead-lettered record
    assert len(sup.dlq) >= 1
    entry = sup.dlq[0]
    assert entry.raw is poison_raw
    assert entry.source_id == "dlq-inst"
    assert entry.failure_count == 3

    # Watermark must have been advanced
    assert len(pipeline.store.set_watermark_calls) >= 1
    ts_str, st, sid = pipeline.store.set_watermark_calls[0]
    assert ts_str == raw_ts.isoformat()
    assert st == "pull_src"
    assert sid == "dlq-inst"

    # Alert must have been emitted
    dlq_alerts = [a for a in sup.alerts if a.kind == "dlq"]
    assert len(dlq_alerts) >= 1
    assert dlq_alerts[0].source_id == "dlq-inst"


async def test_dlq_orthogonal_to_storm_cap() -> None:
    """DLQ and storm cap are independent: a DLQ event should not trigger park, and vice versa."""
    poison_raw = _make_raw("pull_src")

    # The pipeline raises PoisonRecordError for the first 3 calls (DLQ threshold),
    # then a different error for subsequent calls (storm cap logic).
    call_count = 0

    async def mixed_side_effect(plugin: Any, cfg: Any, source_id: str) -> int:
        nonlocal call_count
        call_count += 1
        if call_count <= 3:
            raise PoisonRecordError(raw=poison_raw)
        # After DLQ, succeed so no storm is triggered
        await asyncio.sleep(0.01)
        return 0

    pipeline = _FakePipeline(pull_side_effect=mixed_side_effect)
    plugin = _FakePullPlugin()
    sup = Supervisor(
        pipeline,
        cfg=SupervisorConfig(
            dlq_threshold=3,
            storm_threshold=10,  # high threshold — should NOT be triggered by 3 DLQ events
            backoff_base=0.0,
            backoff_cap=0.0,
            shutdown_grace=2.0,
        ),
    )
    sup.add_pull(plugin, _FakeCfg(), source_id="ortho", interval=0.01)

    await sup.startup()
    await asyncio.sleep(0.3)
    await sup.shutdown()

    rec = sup.get_instance("pull_src", "ortho")
    assert rec is not None
    # DLQ happened but instance must NOT be parked
    assert rec.state != InstanceState.PARKED, "DLQ should not trigger storm park"
    assert len(sup.dlq) >= 1


# --------------------------------------------------------------------------- #
# EARS 6 — Backpressure                                                        #
# --------------------------------------------------------------------------- #


def test_transport_policy_udp_is_drop() -> None:
    """UDP transport maps to DROP backpressure policy (ADR-0023 §Steals)."""
    assert _policy_for_transport("udp") == BackpressurePolicy.DROP


def test_transport_policy_tcp_is_block() -> None:
    """TCP transport maps to BLOCK backpressure policy (ADR-0023 §Steals)."""
    assert _policy_for_transport("tcp") == BackpressurePolicy.BLOCK


def test_transport_policy_file_is_block() -> None:
    """File transport maps to BLOCK backpressure policy (ADR-0023 §Steals)."""
    assert _policy_for_transport("file") == BackpressurePolicy.BLOCK


def test_transport_policy_unknown_defaults_to_block() -> None:
    """Unknown transport type defaults to BLOCK (safe conservative choice)."""
    assert _policy_for_transport("xyzzy") == BackpressurePolicy.BLOCK


async def test_udp_backpressure_drop_when_queue_full() -> None:
    """UDP push source: when queue is full, batches are dropped (not blocked), counter incremented."""
    pipeline = _FakePipeline()
    # Slow ingest to create backpressure
    ingest_delay = 1.0  # very slow consumer

    async def slow_ingest(events: list[SecurityEvent]) -> int:
        await asyncio.sleep(ingest_delay)
        return len(events)

    pipeline.ingest = slow_ingest  # type: ignore[method-assign]

    raw = _make_raw("push_src")
    # Emit 20 batches quickly — queue (maxsize=2) will fill and DROP for UDP
    many_batches = [[raw]] * 20
    plugin = _FakePushPlugin(emit_batches=many_batches)
    sup = Supervisor(
        pipeline,
        cfg=SupervisorConfig(
            push_queue_maxsize=2,  # tiny queue to force drops
            shutdown_grace=2.0,
        ),
    )
    rec = sup.add_push(plugin, _FakeCfg(), source_id="udp-inst", transport="udp")

    await sup.startup()
    await asyncio.sleep(0.3)
    await sup.shutdown()

    # Drops must have occurred (queue was too small for all batches)
    assert rec.dropped_count > 0, "expected UDP drops but dropped_count=0"


async def test_tcp_backpressure_blocks_when_queue_full() -> None:
    """TCP push source: when queue is full, emit() blocks (does not drop), no drop counter.

    We verify that the supervisory queue blocks by checking that the ingest
    pipeline is eventually called (the backpressure propagated to the emit
    side, which unblocked after the consumer drained the queue).
    """
    pipeline = _FakePipeline()

    raw = _make_raw("push_src")
    # Emit 3 batches — with tiny queue=1 the emitter will block between batches
    many_batches = [[raw]] * 3
    plugin = _FakePushPlugin(emit_batches=many_batches)
    sup = Supervisor(
        pipeline,
        cfg=SupervisorConfig(
            push_queue_maxsize=1,  # tiny queue to test blocking
            shutdown_grace=2.0,
        ),
    )
    rec = sup.add_push(plugin, _FakeCfg(), source_id="tcp-inst", transport="tcp")

    await sup.startup()
    await asyncio.sleep(0.5)
    await sup.shutdown()

    # No drops for TCP — all batches should have been ingested
    assert rec.dropped_count == 0, "TCP backpressure should block, not drop"
    # All batches eventually processed
    assert len(pipeline.ingest_calls) >= 3


# --------------------------------------------------------------------------- #
# EARS 7 — Bounded-grace shutdown                                              #
# --------------------------------------------------------------------------- #


async def test_bounded_grace_shutdown() -> None:
    """Shutdown completes within the grace period (calls stop() on push sources)."""
    plugin = _FakePushPlugin(emit_batches=[])
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=SupervisorConfig(shutdown_grace=2.0))
    sup.add_push(plugin, _FakeCfg(), source_id="sh-1", transport="tcp")

    await sup.startup()
    await asyncio.sleep(0.05)

    t_start = time.monotonic()
    await sup.shutdown()
    elapsed = time.monotonic() - t_start

    assert elapsed < 3.0, f"shutdown took {elapsed:.2f}s — exceeded grace period"
    assert plugin.stopped, "push plugin stop() was not called during shutdown"


async def test_shutdown_cancels_outstanding_tasks_after_grace() -> None:
    """If a task doesn't finish within grace, it is force-cancelled and shutdown completes."""

    async def never_finish(plugin: Any, cfg: Any, source_id: str) -> int:
        # This coroutine sleeps very long — to test force-cancel after grace
        await asyncio.sleep(999.0)
        return 0

    pipeline = _FakePipeline(pull_side_effect=never_finish)
    plugin = _FakePullPlugin()
    sup = Supervisor(
        pipeline,
        cfg=SupervisorConfig(shutdown_grace=0.1, backoff_base=0.0, backoff_cap=0.0),
    )
    sup.add_pull(plugin, _FakeCfg(), source_id="slow-inst", interval=0.01)

    await sup.startup()
    await asyncio.sleep(0.05)

    t_start = time.monotonic()
    await sup.shutdown()
    elapsed = time.monotonic() - t_start

    # Must complete within a reasonable window (grace + small overhead)
    assert elapsed < 1.5, f"force-cancel shutdown took {elapsed:.2f}s — too slow"


# --------------------------------------------------------------------------- #
# EARS 8 — No concurrent cycle during backoff                                  #
# --------------------------------------------------------------------------- #


async def test_no_concurrent_cycle_during_backoff() -> None:
    """While an instance is in BACKOFF state, no second cycle should be running."""
    inflight: list[str] = []

    async def track_inflight(plugin: Any, cfg: Any, source_id: str) -> int:
        assert source_id not in inflight, (
            f"concurrent cycle started for {source_id} while another is running"
        )
        inflight.append(source_id)
        # First call fails (triggers backoff); subsequent calls succeed
        if len(inflight) == 1:
            inflight.remove(source_id)
            raise RuntimeError("first call fails to trigger backoff")
        await asyncio.sleep(0.02)
        inflight.remove(source_id)
        return 0

    pipeline = _FakePipeline(pull_side_effect=track_inflight)
    plugin = _FakePullPlugin()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    sup.add_pull(plugin, _FakeCfg(), source_id="no-concurrent", interval=0.01)

    await sup.startup()
    await asyncio.sleep(0.2)
    await sup.shutdown()
    # If the assert above didn't fire, no concurrent cycles occurred


# --------------------------------------------------------------------------- #
# EARS 9 — Last-known-good config seam                                         #
# --------------------------------------------------------------------------- #


async def test_config_reload_accepts_valid_config() -> None:
    """reload_config returns True and updates cfg when new config is valid."""
    pipeline = _FakePipeline()
    plugin = _FakePullPlugin()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    rec = sup.add_pull(plugin, _FakeCfg(note="original"), source_id="cfg-inst")

    new_cfg = _FakeCfg(note="new-valid")
    result = sup.reload_config(rec, new_cfg)

    assert result is True
    assert rec.cfg.note == "new-valid"  # type: ignore[attr-defined]
    assert rec.last_known_good_cfg.note == "new-valid"  # type: ignore[attr-defined]


async def test_config_reload_falls_back_to_last_known_good_on_bad_config() -> None:
    """reload_config returns False and restores last-known-good when config is invalid."""

    class _StrictCfg(BaseModel):
        note: str = "valid"

    class _StrictPlugin(_FakePullPlugin):
        def config_schema(self) -> type[BaseModel]:
            return _StrictCfg

        def validate_config(self, cfg: dict[str, Any]) -> None:
            if cfg.get("note") == "bad":
                raise ValueError("note must not be 'bad'")

    pipeline = _FakePipeline()
    plugin = _StrictPlugin()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    good_cfg = _StrictCfg(note="valid")
    rec = sup.add_pull(plugin, good_cfg, source_id="cfg-inst")

    # Attempt to reload with an invalid config
    bad_cfg = _StrictCfg(note="bad")
    result = sup.reload_config(rec, bad_cfg)

    assert result is False
    # cfg should fall back to last-known-good
    assert rec.cfg.note == "valid"  # type: ignore[attr-defined]
    assert rec.last_known_good_cfg.note == "valid"  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# EARS 10 — SDK-only imports                                                   #
# --------------------------------------------------------------------------- #


def test_sdk_only_imports_no_plugin_or_legacy() -> None:
    """The supervisor subpackage must import only firewatch_sdk — never a concrete plugin or legacy/.

    After the refactor supervisor.py was replaced by the supervisor/ subpackage;
    we walk all .py files inside it to enforce the same constraint.
    """
    import ast
    import pathlib
    import firewatch_core

    supervisor_pkg = pathlib.Path(firewatch_core.__file__).parent / "supervisor"
    py_files = list(supervisor_pkg.rglob("*.py"))
    assert py_files, "supervisor/ subpackage not found — refactor may not have landed"

    forbidden: list[str] = []
    for sup_path in py_files:
        tree = ast.parse(sup_path.read_text(), filename=str(sup_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name
                    if name.startswith(("firewatch_suricata", "firewatch_syslog", "firewatch_azure", "legacy")):
                        forbidden.append(f"{sup_path.name}:{name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                name = node.module
                if name.startswith(("firewatch_suricata", "firewatch_syslog", "firewatch_azure", "legacy")):
                    forbidden.append(f"{sup_path.name}:{name}")

    assert not forbidden, f"supervisor subpackage has forbidden imports: {forbidden}"


# --------------------------------------------------------------------------- #
# Additional: instance lifecycle start/stop/cancel                             #
# --------------------------------------------------------------------------- #


async def test_startup_sets_instances_to_running() -> None:
    """startup() should set all registered instances to RUNNING state."""
    pipeline = _FakePipeline()
    plugin = _FakePullPlugin()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    rec = sup.add_pull(plugin, _FakeCfg(), source_id="inst", interval=0.01)

    await sup.startup()
    assert rec.state == InstanceState.RUNNING
    await sup.shutdown()


async def test_shutdown_is_idempotent() -> None:
    """Calling shutdown() multiple times must not raise or deadlock."""
    pipeline = _FakePipeline()
    plugin = _FakePullPlugin()
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    sup.add_pull(plugin, _FakeCfg(), source_id="inst", interval=0.1)

    await sup.startup()
    await sup.shutdown()
    await sup.shutdown()  # second call — must be a no-op


async def test_get_instance_returns_correct_record() -> None:
    """get_instance(type_key, source_id) must return the matching InstanceRecord."""
    pipeline = _FakePipeline()
    plugin = _FakePullPlugin(type_key="my_src")
    sup = Supervisor(pipeline, cfg=_fast_cfg())
    rec = sup.add_pull(plugin, _FakeCfg(), source_id="my-inst")

    found = sup.get_instance("my_src", "my-inst")
    assert found is rec

    not_found = sup.get_instance("my_src", "nonexistent")
    assert not_found is None


async def test_supervisor_drives_pull_and_push_generically() -> None:
    """Supervisor handles both PullSource and PushSource with zero per-source special-casing."""
    raw = _make_raw("push_src")
    pipeline = _FakePipeline()
    pull_plugin = _FakePullPlugin(type_key="pull_src")
    push_plugin = _FakePushPlugin(emit_batches=[[raw]])

    sup = Supervisor(pipeline, cfg=_fast_cfg())
    rec_pull = sup.add_pull(pull_plugin, _FakeCfg(), source_id="p1", interval=0.01)
    rec_push = sup.add_push(push_plugin, _FakeCfg(), source_id="p2", transport="tcp")

    await sup.startup()
    await asyncio.sleep(0.2)
    await sup.shutdown()

    assert rec_pull.flavor == "pull"
    assert rec_push.flavor == "push"
    # Both were processed through the same supervisor logic
    assert len(pipeline.run_pull_cycle_calls) >= 1
    assert len(pipeline.ingest_calls) >= 1


# --------------------------------------------------------------------------- #
# PoisonRecordError construction                                               #
# --------------------------------------------------------------------------- #


def test_poison_record_error_carries_raw() -> None:
    """PoisonRecordError must carry the raw RawEvent for DLQ tracking."""
    raw = _make_raw()
    exc = PoisonRecordError(raw=raw)
    assert exc.raw is raw
    assert "2026-06-04" in str(exc)


# --------------------------------------------------------------------------- #
# B1 — Storm window config-correct (hard-coded 60s purge bug)                 #
# --------------------------------------------------------------------------- #


async def test_storm_window_120s_parks_instance_within_window() -> None:
    """B1: with storm_window_s=120, an instance crossing storm_threshold in 120s IS parked.

    Previously record_crash() purged with a hard-coded 60s cutoff, so crashes older than
    60s were silently discarded even when the configured window was 120s, making the storm
    cap undercount and never park.  This test proves the fix.
    """

    async def always_fail(plugin: Any, cfg: Any, source_id: str) -> int:
        raise RuntimeError("always crashes for B1 test")

    pipeline = _FakePipeline(pull_side_effect=always_fail)
    plugin = _FakePullPlugin()
    # Use storm_window_s=120 (bigger than the old hard-coded 60s) and a low threshold
    sup = Supervisor(
        pipeline,
        cfg=SupervisorConfig(
            backoff_base=0.0,
            backoff_cap=0.0,
            storm_threshold=3,
            storm_window_s=120.0,  # key: wider than the old hard-coded 60s
            shutdown_grace=2.0,
        ),
    )
    sup.add_pull(plugin, _FakeCfg(), source_id="b1-inst", interval=0.001)

    await sup.startup()
    # Allow enough time for >storm_threshold crashes
    await asyncio.sleep(0.3)

    rec = sup.get_instance("pull_src", "b1-inst")
    assert rec is not None
    assert rec.state == InstanceState.PARKED, (
        f"B1: expected PARKED with storm_window_s=120, got {rec.state} — "
        "record_crash() may still be purging with a hard-coded 60s window"
    )
    storm_alerts = [a for a in sup.alerts if a.kind == "storm_park"]
    assert len(storm_alerts) >= 1

    await sup.shutdown()


# --------------------------------------------------------------------------- #
# B2 — CancelledError must be re-raised after backoff                         #
# --------------------------------------------------------------------------- #


async def test_backoff_cancellation_leaves_task_cancelled() -> None:
    """B2: cancelling a task during backoff sleep must leave the task cancelled (not silently swallowed).

    Previously _backoff_and_restart caught CancelledError, set state, and returned without
    re-raising — violating the asyncio cancellation contract.  After the fix, the coroutine
    must propagate CancelledError so the wrapping task ends as cancelled.
    """
    import asyncio as _asyncio

    # Simulate a backoff task in isolation: create a task that runs _backoff_and_restart
    # on a fake record with a real (non-zero) sleep, then cancel it immediately.
    pipeline = _FakePipeline()
    plugin = _FakePullPlugin()
    sup = Supervisor(
        pipeline,
        cfg=SupervisorConfig(
            backoff_base=10.0,   # long enough that cancel fires during sleep
            backoff_cap=10.0,
            shutdown_grace=2.0,
        ),
    )
    rec = sup.add_pull(plugin, _FakeCfg(), source_id="b2-inst", interval=0.01)
    sup._running = True  # simulate running state so backoff proceeds

    # Launch the backoff coroutine as a task, then cancel it right away
    backoff_task = _asyncio.create_task(sup._backoff_and_restart(rec))
    # Give it one event-loop tick to start sleeping
    await _asyncio.sleep(0)
    backoff_task.cancel()

    # Allow the cancellation to propagate
    try:
        await _asyncio.wait_for(_asyncio.shield(backoff_task), timeout=1.0)
    except (_asyncio.CancelledError, _asyncio.TimeoutError):
        pass

    assert backoff_task.cancelled(), (
        "B2: backoff task must be cancelled after CancelledError — it was not re-raised"
    )


# --------------------------------------------------------------------------- #
# NB-3 — Push-path ingest failures → storm cap parity                         #
# --------------------------------------------------------------------------- #


async def test_push_consecutive_ingest_failures_park_and_alert() -> None:
    """NB-3: push consumer ingest failures count toward the storm cap (park + alert).

    Previously the push consumer only logged-and-dropped ingest errors — no storm cap, no alert.
    After the fix, consecutive ingest failures on a push instance accumulate in the same storm cap
    and eventually park the instance and emit a storm_park alert, consistent with the pull path.
    """
    raw = _make_raw("push_src")

    # Pipeline that always fails ingest
    async def always_fail_ingest(events: list[SecurityEvent]) -> int:
        raise RuntimeError("simulated ingest failure for NB-3")

    pipeline = _FakePipeline()
    pipeline.ingest = always_fail_ingest  # type: ignore[method-assign]

    # Push plugin that keeps emitting so the consumer keeps failing
    class _InfiniteEmitPlugin(_FakePushPlugin):
        """Push plugin that emits batches in a tight loop until stopped."""

        async def start(
            self,
            cfg: BaseModel,
            emit: Callable[[list[RawEvent]], Awaitable[None]],
            ctx: PluginContext,
        ) -> None:
            self._stop_event = asyncio.Event()
            while not self._stop_event.is_set():
                try:
                    await emit([raw])
                except Exception:
                    pass
                await asyncio.sleep(0.005)

    plugin = _InfiniteEmitPlugin(type_key="push_src")
    sup = Supervisor(
        pipeline,
        cfg=SupervisorConfig(
            backoff_base=0.0,
            backoff_cap=0.0,
            storm_threshold=3,
            storm_window_s=60.0,
            push_queue_maxsize=256,
            shutdown_grace=2.0,
        ),
    )
    sup.add_push(plugin, _FakeCfg(), source_id="nb3-push", transport="tcp")

    await sup.startup()
    await asyncio.sleep(0.5)

    rec = sup.get_instance("push_src", "nb3-push")
    assert rec is not None
    assert rec.state == InstanceState.PARKED, (
        f"NB-3: expected push instance to be PARKED after consecutive ingest failures, got {rec.state}"
    )
    storm_alerts = [a for a in sup.alerts if a.kind == "storm_park"]
    assert len(storm_alerts) >= 1, "NB-3: no storm_park alert emitted for push instance"

    await sup.shutdown()


# --------------------------------------------------------------------------- #
# NB-A — push_plugin.stop() called at most once on normal shutdown            #
# --------------------------------------------------------------------------- #


async def test_push_stop_called_exactly_once_on_normal_shutdown() -> None:
    """NB-A: push_plugin.stop() must be called exactly once during a normal shutdown.

    Previously _run_push_instance's finally block set should_stop_plugin which caused
    the stop_watcher to call stop() a second time after shutdown() had already called it.
    After the fix, cancelling stop_watcher_task before setting should_stop_plugin ensures
    stop() is invoked at most once.
    """
    stop_call_count = 0

    class _CountingPushPlugin(_FakePushPlugin):
        async def stop(self) -> None:
            nonlocal stop_call_count
            stop_call_count += 1
            await super().stop()

    plugin = _CountingPushPlugin(emit_batches=[])
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=SupervisorConfig(shutdown_grace=2.0))
    sup.add_push(plugin, _FakeCfg(), source_id="stop-once", transport="tcp")

    await sup.startup()
    # Let start() settle — plugin is now waiting on its stop event
    await asyncio.sleep(0.05)

    await sup.shutdown()

    assert stop_call_count == 1, (
        f"NB-A: push_plugin.stop() was called {stop_call_count} times; "
        "expected exactly 1 on normal shutdown"
    )


# --------------------------------------------------------------------------- #
# NB-C — crash_timestamps deque stays bounded                                 #
# --------------------------------------------------------------------------- #


async def test_crash_timestamps_stays_bounded_under_many_sub_threshold_crashes() -> None:
    """NB-C: crash_timestamps deque must not grow unbounded for sub-threshold flapping.

    A long-lived instance that crashes repeatedly but never hits the storm threshold
    (because crashes are spread out in time) previously accumulated timestamps forever.
    After the fix, crashes_in_window() prunes old timestamps so the deque stays small.
    """
    from firewatch_core.supervisor import InstanceRecord

    # Create a standalone InstanceRecord (no supervisor needed for this unit test)
    plugin = _FakePullPlugin(type_key="pull_src")
    cfg = _FakeCfg()
    rec = InstanceRecord(
        source_id="bounded-test",
        plugin=plugin,
        cfg=cfg,
        last_known_good_cfg=cfg,
        flavor="pull",
    )

    storm_window_s = 10.0
    # Simulate 200 crashes spread out over time, each 20s apart (all outside any 10s window)
    # so the storm cap is NEVER triggered, but timestamps would grow unbounded without pruning.
    base_time = 1000.0
    for i in range(200):
        t = base_time + i * 20.0  # 20s apart — outside any 10s rolling window
        rec.record_crash(t)
        # Call crashes_in_window to trigger pruning
        rec.crashes_in_window(t, storm_window_s)

    # After pruning, the deque should hold at most a small number of recent entries
    # (all timestamps older than the window should have been removed).
    assert len(rec.crash_timestamps) <= 5, (
        f"NB-C: crash_timestamps has {len(rec.crash_timestamps)} entries after pruning; "
        "expected at most 5 (unbounded growth not prevented)"
    )
    # total_crashes still tracks the lifetime total correctly
    assert rec.total_crashes == 200


async def test_crash_timestamps_bounded_still_parks_correctly() -> None:
    """NB-C: bounding crash_timestamps must not prevent parking when the storm IS hit.

    Even with pruning, if the storm threshold is hit within the window the instance
    must still be parked.
    """

    async def always_fail(plugin: Any, cfg: Any, source_id: str) -> int:
        raise RuntimeError("always crashes for NB-C park test")

    pipeline = _FakePipeline(pull_side_effect=always_fail)
    plugin = _FakePullPlugin()
    sup = Supervisor(
        pipeline,
        cfg=SupervisorConfig(
            backoff_base=0.0,
            backoff_cap=0.0,
            storm_threshold=3,
            storm_window_s=60.0,
            shutdown_grace=2.0,
        ),
    )
    sup.add_pull(plugin, _FakeCfg(), source_id="nc-park", interval=0.001)

    await sup.startup()
    await asyncio.sleep(0.3)

    rec = sup.get_instance("pull_src", "nc-park")
    assert rec is not None
    assert rec.state == InstanceState.PARKED, (
        f"NB-C: expected PARKED after rapid crashes, got {rec.state}"
    )
    await sup.shutdown()


# --------------------------------------------------------------------------- #
# NB-F — park log and alert use windowed count, not lifetime total            #
# --------------------------------------------------------------------------- #


async def test_park_alert_detail_uses_windowed_crash_count() -> None:
    """NB-F: the storm_park alert detail must show the windowed count, not the lifetime total.

    Previously _park_instance logged len(rec.crash_timestamps) (lifetime total), which
    could be much higher than the number of crashes in the configured window.  After the
    fix, the detail shows the actual windowed count passed by the caller.
    """

    async def always_fail(plugin: Any, cfg: Any, source_id: str) -> int:
        raise RuntimeError("always crashes for NB-F test")

    pipeline = _FakePipeline(pull_side_effect=always_fail)
    plugin = _FakePullPlugin()
    # Low storm_threshold so we park quickly
    storm_threshold = 3
    storm_window_s = 60.0
    sup = Supervisor(
        pipeline,
        cfg=SupervisorConfig(
            backoff_base=0.0,
            backoff_cap=0.0,
            storm_threshold=storm_threshold,
            storm_window_s=storm_window_s,
            shutdown_grace=2.0,
        ),
    )
    sup.add_pull(plugin, _FakeCfg(), source_id="nf-inst", interval=0.001)

    await sup.startup()
    await asyncio.sleep(0.3)

    rec = sup.get_instance("pull_src", "nf-inst")
    assert rec is not None
    assert rec.state == InstanceState.PARKED

    storm_alerts = [a for a in sup.alerts if a.kind == "storm_park"]
    assert len(storm_alerts) >= 1, "NB-F: no storm_park alert emitted"

    alert_detail = storm_alerts[0].detail
    # The alert detail must include "crashes in 60s window" label
    assert "crashes" in alert_detail, f"NB-F: 'crashes' not in detail: {alert_detail!r}"
    assert "window" in alert_detail, f"NB-F: 'window' not in detail: {alert_detail!r}"

    # Extract the crash count from the detail string: "Instance parked after N crashes in ..."
    import re
    match = re.search(r"after (\d+) crashes", alert_detail)
    assert match is not None, f"NB-F: could not parse crash count from detail: {alert_detail!r}"
    reported_count = int(match.group(1))

    # The reported count should be the windowed count (storm_threshold+1),
    # not a larger lifetime total.  All crashes here are rapid (within 60s),
    # so windowed count == total crashes at park time == storm_threshold+1.
    assert reported_count == storm_threshold + 1, (
        f"NB-F: alert detail reported {reported_count} crashes but expected "
        f"{storm_threshold + 1} (windowed, not lifetime total)"
    )
