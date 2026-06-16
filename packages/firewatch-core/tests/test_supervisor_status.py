"""Tests for Supervisor.status() → list[InstanceStatus] DTO (MB.4, issue #56).

EARS → test mapping
────────────────────
E1 (ubiquitous — DTO seam): Instance status shall be read only through
   Supervisor.status() (the DTO), never by the API reaching into InstanceRecord
   or private supervisor fields.
   → test_status_returns_instance_status_objects
   → test_instance_status_fields_match_spec
   → test_instance_status_is_frozen

E2 (state-driven — backoff/parked states visible):
   While an instance is in supervisor backoff or parked, its status shall report
   that state via the InstanceStatus DTO.
   → test_status_reflects_backoff_state
   → test_status_reflects_parked_state
   → test_status_reflects_running_state
   → test_status_reflects_stopped_state

E3 (unwanted — crash isolation on status read):
   A failing/parked instance's status shall not break the /sources response.
   (The DTO read itself must not raise even when instance is in error state.)
   → test_status_does_not_raise_for_parked_instance
   → test_status_with_no_instances_returns_empty_list

E4 (event-driven — multiple instances):
   When multiple instances are registered, status returns one InstanceStatus per
   instance.
   → test_status_with_multiple_instances
   → test_status_preserves_per_instance_metrics

E5 (ubiquitous — InstanceRecord not leaked):
   The DTO type must be distinct from InstanceRecord; InstanceRecord must NOT
   be returned by the status() method.
   → test_instance_status_is_not_instance_record
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import pytest
from pydantic import BaseModel

from firewatch_sdk import RawEvent, SecurityEvent, SourceMetadata

from firewatch_core.supervisor import (
    InstanceState,
    Supervisor,
    SupervisorConfig,
)
from firewatch_core.supervisor.status import InstanceStatus


# --------------------------------------------------------------------------- #
# Test doubles                                                                 #
# --------------------------------------------------------------------------- #


class _FakeCfg(BaseModel):
    note: str = "fake"


class _FakePullPlugin:
    """Minimal pull plugin — returns canned metadata, never actually collects."""

    def __init__(self, type_key: str = "suricata") -> None:
        self._type_key = type_key

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name="Fake Pull",
            version="0.1.0",
            flavor="pull",
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakeCfg

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _FakeCfg.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        return SecurityEvent(
            source_type=self._type_key,
            source_id=source_id,
            timestamp=raw.received_at,
            source_ip="192.0.2.10",
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True


class _FakePipeline:
    """Minimal pipeline — supervisor accesses .store and .run_pull_cycle."""

    class _FakeStore:
        async def get_watermark(self, *_: Any) -> str | None:
            return None

        async def set_watermark(self, *_: Any) -> None:
            pass

    store = _FakeStore()

    async def run_pull_cycle(self, *_: Any, **__: Any) -> int:
        return 0


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _make_supervisor() -> tuple[Supervisor, _FakePipeline]:
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=SupervisorConfig())
    return sup, pipeline


# --------------------------------------------------------------------------- #
# E1 — DTO seam: status() returns InstanceStatus objects                      #
# --------------------------------------------------------------------------- #


def test_status_returns_instance_status_objects() -> None:
    """Supervisor.status() returns a list of InstanceStatus (not InstanceRecord)."""
    sup, _ = _make_supervisor()
    plugin = _FakePullPlugin("suricata")
    cfg = _FakeCfg()
    sup.add_pull(plugin, cfg, source_id="pi-home")

    statuses = sup.status()

    assert isinstance(statuses, list)
    assert len(statuses) == 1
    assert isinstance(statuses[0], InstanceStatus)


def test_instance_status_fields_match_spec() -> None:
    """InstanceStatus carries the required fields from the issue spec."""
    sup, _ = _make_supervisor()
    plugin = _FakePullPlugin("suricata")
    cfg = _FakeCfg()
    sup.add_pull(plugin, cfg, source_id="pi-home")

    status = sup.status()[0]

    # Required fields per issue #56 module layout
    assert status.source_type == "suricata"
    assert status.source_id == "pi-home"
    assert status.flavor == "pull"
    assert isinstance(status.state, str)
    assert isinstance(status.attempt, int)
    assert isinstance(status.total_crashes, int)
    assert isinstance(status.total_dlq, int)
    assert isinstance(status.dropped_count, int)
    # last_success_at: float (monotonic) — just check it exists and is numeric
    assert isinstance(status.last_success_at, float)


def test_instance_status_is_frozen() -> None:
    """InstanceStatus is a frozen Pydantic model (read-only DTO)."""
    sup, _ = _make_supervisor()
    plugin = _FakePullPlugin("suricata")
    sup.add_pull(plugin, _FakeCfg(), source_id="pi-home")

    status = sup.status()[0]

    with pytest.raises(Exception):
        # Frozen Pydantic model raises on attribute assignment
        status.state = "running"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# E2 — state-driven: lifecycle states reflected in DTO                        #
# --------------------------------------------------------------------------- #


def test_status_reflects_running_state() -> None:
    """After startup, an instance's InstanceStatus.state is 'running'."""

    async def _run() -> None:
        sup, pipeline = _make_supervisor()
        plugin = _FakePullPlugin("suricata")
        sup.add_pull(plugin, _FakeCfg(), source_id="pi-home")
        await sup.startup()
        try:
            status = sup.status()[0]
            assert status.state == "running"
        finally:
            await sup.shutdown()

    asyncio.run(_run())


def test_status_reflects_stopped_state() -> None:
    """Before startup, an instance's InstanceStatus.state is 'stopped'."""
    sup, _ = _make_supervisor()
    plugin = _FakePullPlugin("suricata")
    sup.add_pull(plugin, _FakeCfg(), source_id="pi-home")

    # Not yet started — STOPPED is the initial state
    status = sup.status()[0]
    assert status.state == "stopped"


def test_status_reflects_backoff_state() -> None:
    """An instance in BACKOFF state has status.state == 'backoff'."""
    sup, _ = _make_supervisor()
    plugin = _FakePullPlugin("suricata")
    rec = sup.add_pull(plugin, _FakeCfg(), source_id="pi-home")

    # Manually put the record into BACKOFF state (simulates a crash mid-restart)
    rec.state = InstanceState.BACKOFF

    status = sup.status()[0]
    assert status.state == "backoff"


def test_status_reflects_parked_state() -> None:
    """A parked instance has status.state == 'parked'."""
    sup, _ = _make_supervisor()
    plugin = _FakePullPlugin("suricata")
    rec = sup.add_pull(plugin, _FakeCfg(), source_id="pi-home")

    # Manually put the record into PARKED state
    rec.state = InstanceState.PARKED

    status = sup.status()[0]
    assert status.state == "parked"


# --------------------------------------------------------------------------- #
# E3 — unwanted: status() never raises, even for parked/crashed instances     #
# --------------------------------------------------------------------------- #


def test_status_does_not_raise_for_parked_instance() -> None:
    """Supervisor.status() must not raise when instances are in error states."""
    sup, _ = _make_supervisor()
    plugin = _FakePullPlugin("suricata")
    rec = sup.add_pull(plugin, _FakeCfg(), source_id="pi-home")
    rec.state = InstanceState.PARKED
    rec.total_crashes = 10
    rec.attempt = 5

    # Should return a valid DTO without raising
    statuses = sup.status()
    assert len(statuses) == 1
    assert statuses[0].state == "parked"
    assert statuses[0].total_crashes == 10


def test_status_with_no_instances_returns_empty_list() -> None:
    """Supervisor with no instances returns an empty list from status()."""
    sup, _ = _make_supervisor()

    statuses = sup.status()
    assert statuses == []


# --------------------------------------------------------------------------- #
# E4 — multiple instances: one DTO per registered instance                    #
# --------------------------------------------------------------------------- #


def test_status_with_multiple_instances() -> None:
    """status() returns one InstanceStatus per registered instance."""
    sup, _ = _make_supervisor()

    plugin_a = _FakePullPlugin("suricata")
    plugin_b = _FakePullPlugin("syslog")
    sup.add_pull(plugin_a, _FakeCfg(), source_id="pi-home")
    sup.add_pull(plugin_b, _FakeCfg(), source_id="syslog-lan")

    statuses = sup.status()

    assert len(statuses) == 2
    ids = {(s.source_type, s.source_id) for s in statuses}
    assert ("suricata", "pi-home") in ids
    assert ("syslog", "syslog-lan") in ids


def test_status_preserves_per_instance_metrics() -> None:
    """Each InstanceStatus carries the correct per-instance counters."""
    sup, _ = _make_supervisor()

    plugin_a = _FakePullPlugin("suricata")
    plugin_b = _FakePullPlugin("syslog")
    rec_a = sup.add_pull(plugin_a, _FakeCfg(), source_id="pi-home")
    rec_b = sup.add_pull(plugin_b, _FakeCfg(), source_id="syslog-lan")

    # Mutate counters to simulate different crash histories
    rec_a.total_crashes = 3
    rec_a.total_dlq = 1
    rec_b.total_crashes = 0
    rec_b.dropped_count = 42

    statuses = {(s.source_type, s.source_id): s for s in sup.status()}

    assert statuses[("suricata", "pi-home")].total_crashes == 3
    assert statuses[("suricata", "pi-home")].total_dlq == 1
    assert statuses[("syslog", "syslog-lan")].total_crashes == 0
    assert statuses[("syslog", "syslog-lan")].dropped_count == 42


# --------------------------------------------------------------------------- #
# E5 — InstanceRecord must NOT be leaked via status()                         #
# --------------------------------------------------------------------------- #


def test_instance_status_is_not_instance_record() -> None:
    """InstanceStatus is a distinct type — not InstanceRecord."""
    from firewatch_core.supervisor.models import InstanceRecord

    sup, _ = _make_supervisor()
    plugin = _FakePullPlugin("suricata")
    sup.add_pull(plugin, _FakeCfg(), source_id="pi-home")

    status = sup.status()[0]

    assert not isinstance(status, InstanceRecord), (
        "status() must return InstanceStatus, not InstanceRecord. "
        "The API must not be able to reach internal supervisor state."
    )


# --------------------------------------------------------------------------- #
# E6 — run_pull_cycle_for mints ctx and passes it to the real pipeline         #
#                                                                               #
# Regression: the original implementation called                               #
#   pipeline.run_pull_cycle(rec.plugin, rec.cfg, source_id=source_id)          #
# which omitted the required ctx argument, causing TypeError (500) on          #
# POST /sync and leaving ScopedKV/PluginContext never minted (ADR-0027).        #
# --------------------------------------------------------------------------- #


class _CapturePipeline:
    """Pipeline-like object that captures the ctx passed to run_pull_cycle.

    Using a real pipeline stub (not _FakePipeline) lets us assert that
    Supervisor.run_pull_cycle_for calls the pipeline with a PluginContext
    whose kv is a ScopedKV and whose source_id matches the instance.
    """

    class _FakeStore:
        async def get_watermark(self, *_: Any) -> str | None:
            return None

        async def set_watermark(self, *_: Any) -> None:
            pass

        async def source_kv_put(self, *_: Any) -> None:
            pass

        async def source_kv_get(self, *_: Any) -> str | None:
            return None

        async def source_kv_get_all(self, *_: Any) -> dict[str, str]:
            return {}

    def __init__(self) -> None:
        self.store = self._FakeStore()
        self.received_ctx: Any = None
        self.received_source_id: str = ""

    async def run_pull_cycle(
        self, plugin: Any, cfg: Any, source_id: str, ctx: Any
    ) -> int:
        self.received_source_id = source_id
        self.received_ctx = ctx
        return 0


async def test_run_pull_cycle_for_mints_plugin_context() -> None:
    """Supervisor.run_pull_cycle_for passes a PluginContext with source_id to pipeline.

    This is the regression test for the blocking security finding: the original
    code called run_pull_cycle without ctx, causing TypeError (500) on POST /sync
    and violating ADR-0027 capability isolation (ScopedKV never minted).

    The test fails if ctx is missing from the call — proving the fix is load-bearing.
    """
    from firewatch_sdk.ports import ScopedKV

    pipeline = _CapturePipeline()
    sup = Supervisor(pipeline, cfg=SupervisorConfig())
    plugin = _FakePullPlugin("suricata")
    cfg = _FakeCfg()
    sup.add_pull(plugin, cfg, source_id="pi-home")

    await sup.run_pull_cycle_for("suricata", "pi-home")

    # The pipeline must have received a PluginContext — not None or missing.
    from firewatch_sdk import PluginContext
    assert isinstance(pipeline.received_ctx, PluginContext), (
        "run_pull_cycle_for must pass a PluginContext; got: {!r}".format(
            pipeline.received_ctx
        )
    )
    # source_id must match the registered instance (from rec.source_id, never path arg)
    assert pipeline.received_ctx.source_id == "pi-home"
    # kv must be a ScopedKV implementation (capability-scoped view, ADR-0027 §3)
    assert isinstance(pipeline.received_ctx.kv, ScopedKV), (
        "ctx.kv must be a ScopedKV; got: {!r}".format(pipeline.received_ctx.kv)
    )
    # source_id forwarded to pipeline positionally (not via keyword only)
    assert pipeline.received_source_id == "pi-home"


async def test_run_pull_cycle_for_uses_plugin_type_key_not_path_param() -> None:
    """ctx is minted using the PLUGIN constant, not the path-param source_type.

    This satisfies the ADR-0027 capability-isolation invariant: a crafted
    source_type path parameter cannot hijack another plugin's KV scope.
    The supervisor reads type_key from rec.plugin.metadata().type_key, so
    even if the caller supplies a different string, the plugin's own declared
    type is used.

    Since get_instance already validates the (source_type, source_id) pair and
    raises KeyError for mismatches, the only residual risk is a discrepancy
    between the registry key and the plugin's self-declared type_key.  We
    verify here that the ctx.kv is scoped to the plugin's OWN type_key.
    """
    from firewatch_core.scoped_kv import _CoreScopedKV

    pipeline = _CapturePipeline()
    sup = Supervisor(pipeline, cfg=SupervisorConfig())
    # Plugin declares type_key="suricata" — its metadata is the ground truth.
    plugin = _FakePullPlugin("suricata")
    cfg = _FakeCfg()
    sup.add_pull(plugin, cfg, source_id="pi-home")

    # Call with the correct type_key (the only valid input after get_instance validates)
    await sup.run_pull_cycle_for("suricata", "pi-home")

    # kv must be scoped to the plugin constant, not any call-site string.
    # _CoreScopedKV stores the source_type it was minted with.
    assert isinstance(pipeline.received_ctx.kv, _CoreScopedKV)
    assert pipeline.received_ctx.kv._st == "suricata"


async def test_run_pull_cycle_for_raises_key_error_on_unknown_instance() -> None:
    """run_pull_cycle_for raises KeyError when (type, id) pair is not registered.

    The API route must translate this to a 404. This test proves the guard
    is in place before any ctx-minting happens.
    """
    import pytest

    pipeline = _CapturePipeline()
    sup = Supervisor(pipeline, cfg=SupervisorConfig())

    with pytest.raises(KeyError, match="instance not found"):
        await sup.run_pull_cycle_for("suricata", "does-not-exist")


# --------------------------------------------------------------------------- #
# Resume-on-manual-sync (ADR-0023 §D resume; walkthrough decision 2026-06-11)  #
# --------------------------------------------------------------------------- #


async def test_successful_manual_sync_resumes_parked_instance() -> None:
    """A successful manual Sync clears a storm-park and relaunches the loop.

    Maintainer's walkthrough decision: ``parked`` must not be a dead-end. The single
    operator action (Sync now) that succeeds shall resume the supervised pull loop
    so auto-sync continues — and reset the crash window so the resumed instance
    doesn't immediately re-trip the storm cap on stale pre-park timestamps.
    """
    import time as _time

    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=SupervisorConfig())
    plugin = _FakePullPlugin("azure_waf")
    rec = sup.add_pull(plugin, _FakeCfg(), source_id="azure_waf")
    sup._running = True  # started supervisor (without auto-launching the loop)

    # Simulate a storm-park: crash window full, state PARKED, no task.
    now = _time.monotonic()
    for _ in range(6):
        rec.record_crash(now)
    rec.state = InstanceState.PARKED
    rec.task = None
    rec.attempt = 5

    try:
        await sup.run_pull_cycle_for("azure_waf", "azure_waf")

        assert rec.state == InstanceState.RUNNING, "successful Sync must unpark"
        assert rec.attempt == 0, "backoff attempt must reset on resume"
        assert len(rec.crash_timestamps) == 0, "crash window must clear on resume"
        assert rec.task is not None, "supervised loop must be relaunched"
        assert rec.last_sync_status in ("ok", "no_data")
    finally:
        sup._running = False
        # Explicit annotation: pyright otherwise narrows rec.task to None from the
        # `rec.task = None` above and can't see run_pull_cycle_for re-assign it.
        task: asyncio.Task[None] | None = rec.task
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


async def test_failed_manual_sync_leaves_instance_parked() -> None:
    """A FAILED manual Sync on a parked instance keeps it parked (no resume).

    Re-parking on a genuinely bad config is correct behaviour: the operator's
    action only resumes the instance when the cycle actually succeeds. The error
    is recorded on the instance's last-sync facts.
    """
    import time as _time

    class _RaisingPipeline(_FakePipeline):
        async def run_pull_cycle(self, *_: Any, **__: Any) -> int:
            raise RuntimeError("WorkspaceNotFoundError: still on bad config")

    pipeline = _RaisingPipeline()
    sup = Supervisor(pipeline, cfg=SupervisorConfig())
    plugin = _FakePullPlugin("azure_waf")
    rec = sup.add_pull(plugin, _FakeCfg(), source_id="azure_waf")
    sup._running = True

    now = _time.monotonic()
    for _ in range(6):
        rec.record_crash(now)
    rec.state = InstanceState.PARKED
    rec.task = None

    with pytest.raises(RuntimeError, match="WorkspaceNotFoundError"):
        await sup.run_pull_cycle_for("azure_waf", "azure_waf")

    assert rec.state == InstanceState.PARKED, "failed Sync must NOT unpark"
    assert rec.task is None, "no supervised loop relaunched on failure"
    assert rec.last_sync_status == "error"


async def test_successful_manual_sync_on_idle_instance_does_not_launch_loop() -> None:
    """A successful manual Sync on a non-parked (IDLE) instance does not relaunch.

    Resume is park-specific: an IDLE instance (auto-sync off) stays IDLE after a
    manual Sync — the resume path must only fire for PARKED.
    """
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=SupervisorConfig())
    plugin = _FakePullPlugin("suricata")
    rec = sup.add_pull(plugin, _FakeCfg(), source_id="pi-home")
    sup._running = True
    rec.state = InstanceState.IDLE

    await sup.run_pull_cycle_for("suricata", "pi-home")

    assert rec.state == InstanceState.IDLE, "manual Sync must not promote IDLE→RUNNING"
    assert rec.task is None
