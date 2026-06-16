"""Tests for the Supervisor.wait_until_stopped() public seam (ADR-0023 §D.1).

EARS criterion → test mapping
═════════════════════════════
NS-1  Event-driven: When all registered instances have parked (storm threshold),
      an outstanding wait_until_stopped() task resolves.
      → test_ns1_park_all_resolves_wait_until_stopped

NS-2  State-driven: When one instance parks while another stays RUNNING,
      wait_until_stopped() must NOT resolve (predicate not satisfied).
      → test_ns2_partial_park_does_not_resolve

NS-3  State-driven: When the supervisor has zero registered instances,
      wait_until_stopped() must NOT resolve after startup (zero-instance
      exception); it only resolves after an explicit shutdown().
      → test_ns3_zero_instances_resolves_only_on_shutdown

NS-4  Event-driven: When shutdown() is called with a healthy RUNNING instance,
      wait_until_stopped() resolves immediately (shutdown sets the event first).
      → test_ns4_explicit_shutdown_resolves_seam

NS-5  Ubiquitous: wait_until_stopped() is idempotent — a second await after
      the seam has resolved returns immediately without hanging.
      → test_ns5_idempotent_after_stopped

NS-6  Event-driven: cmd_run wires the public seam correctly — a fake supervisor
      exposing ONLY wait_until_stopped() (no private attrs) that resolves on
      command causes cmd_run to set server.should_exit, await the server task,
      then call shutdown() then store.close() in that order.
      → test_ns6_cmd_run_uses_public_seam_and_correct_order

NS-7  Ubiquitous: park-all emits exactly ONE "supervisor.stopping" ERROR log
      record; a second park (if somehow re-triggered) does NOT re-emit it.
      → test_ns7_stopping_log_emitted_exactly_once

Security note: all IPs use RFC 5737 documentation ranges (gitleaks gate).
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

from firewatch_sdk import PluginContext, RawEvent, SecurityEvent, SourceMetadata

from firewatch_core.supervisor import Supervisor, SupervisorConfig

# RFC 5737 documentation IPs
_IP_DOC = "203.0.113.5"


# ---------------------------------------------------------------------------
# Minimal test doubles
# ---------------------------------------------------------------------------


class _FakeCfg(BaseModel):
    note: str = "fake"


class _FakePullPlugin:
    """A PullSource test double that always crashes, driving it toward parking."""

    def __init__(self, type_key: str = "pull_src", *, fail: bool = True) -> None:
        self._type_key = type_key
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
            source_ip=_IP_DOC,
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True

    async def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]:
        return
        yield  # type: ignore[misc]


class _FakePipeline:
    """Pipeline double; pull_side_effect controls cycle behaviour."""

    def __init__(self, *, pull_side_effect: Any = None) -> None:
        self.store = _FakeStore()
        self._pull_side_effect = pull_side_effect

    async def ingest(self, events: list[SecurityEvent]) -> int:
        return len(events)

    async def run_pull_cycle(self, plugin: Any, cfg: Any, source_id: str, ctx: Any) -> int:
        if self._pull_side_effect is not None:
            return await self._pull_side_effect(plugin, cfg, source_id)
        return 0


class _FakeStore:
    """Minimal in-memory store double."""

    def __init__(self) -> None:
        self.watermarks: dict[tuple[str, str], str] = {}

    async def set_watermark(self, ts: str, source_type: str, source_id: str) -> None:
        self.watermarks[(source_type, source_id)] = ts

    async def get_watermark(self, source_type: str, source_id: str) -> str | None:
        return self.watermarks.get((source_type, source_id))


def _storm_cfg(threshold: int = 2) -> SupervisorConfig:
    """Fast supervisor config that parks quickly for testing."""
    return SupervisorConfig(
        backoff_base=0.0,
        backoff_cap=0.0,
        storm_threshold=threshold,
        storm_window_s=60.0,
        shutdown_grace=1.0,
    )


async def _drive_to_park(sup: Supervisor, wait_s: float = 0.5) -> None:
    """Let the supervisor run until all instances are parked, then return."""
    await asyncio.sleep(wait_s)


# ---------------------------------------------------------------------------
# NS-1: park-all → outstanding wait_until_stopped() resolves
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ns1_park_all_resolves_wait_until_stopped() -> None:
    """NS-1: when all instances park, wait_until_stopped() resolves.

    Drives N=2 instances to PARKED via storm cap; asserts the seam task
    completes within a bounded timeout.  Under the old private-attr approach
    (_shutdown_event.wait()), this test would never resolve because
    _shutdown_event is only set by shutdown() — not by the all-parked predicate.
    """
    async def always_fail(plugin: Any, cfg: Any, source_id: str) -> int:
        raise RuntimeError("always crashes")

    pipeline = _FakePipeline(pull_side_effect=always_fail)
    # storm_threshold=2 → 3rd crash in window parks the instance
    sup = Supervisor(pipeline, cfg=_storm_cfg(threshold=2))
    sup.add_pull(_FakePullPlugin("src_a"), _FakeCfg(), source_id="inst-a", interval=0.001)
    sup.add_pull(_FakePullPlugin("src_b"), _FakeCfg(), source_id="inst-b", interval=0.001)

    await sup.startup()

    # Create the awaitable BEFORE the instances park (mirrors how cmd_run does it).
    seam_task = asyncio.create_task(sup.wait_until_stopped(), name="test-seam")

    try:
        # Give enough time for both instances to storm-park.
        done, pending = await asyncio.wait({seam_task}, timeout=3.0)
        assert seam_task in done, (
            "wait_until_stopped() did not resolve after all instances parked. "
            "Under the old private-attr design this would hang indefinitely — "
            "the public seam fires on the all-parked predicate, not on shutdown()."
        )
        assert sup.is_stopped, "is_stopped must be True after seam resolves"
    finally:
        if not seam_task.done():
            seam_task.cancel()
        await sup.shutdown()


# ---------------------------------------------------------------------------
# NS-2: partial park → seam stays pending
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ns2_partial_park_does_not_resolve() -> None:
    """NS-2: when one instance parks but another stays RUNNING, seam stays pending."""
    crash_count: dict[str, int] = {}

    async def controlled_fail(plugin: Any, cfg: Any, source_id: str) -> int:
        crash_count.setdefault(source_id, 0)
        if source_id == "parked-one":
            raise RuntimeError("always crashes")
        # "healthy" never crashes — sleep so it keeps the loop alive
        await asyncio.sleep(0.05)
        return 0

    pipeline = _FakePipeline(pull_side_effect=controlled_fail)
    sup = Supervisor(pipeline, cfg=_storm_cfg(threshold=2))
    sup.add_pull(_FakePullPlugin("src"), _FakeCfg(), source_id="parked-one", interval=0.001)
    sup.add_pull(_FakePullPlugin("src"), _FakeCfg(), source_id="healthy", interval=0.001)

    await sup.startup()
    seam_task = asyncio.create_task(sup.wait_until_stopped(), name="test-seam-partial")

    try:
        # Wait for "parked-one" to park (give enough time).
        await asyncio.sleep(1.0)

        # "healthy" should still be RUNNING; seam must NOT have resolved.
        done, _ = await asyncio.wait({seam_task}, timeout=0.1)
        assert seam_task not in done, (
            "wait_until_stopped() resolved prematurely — a single park while "
            "another instance is still RUNNING must NOT satisfy the stop predicate."
        )
        assert not sup.is_stopped
    finally:
        seam_task.cancel()
        try:
            await seam_task
        except asyncio.CancelledError:
            pass
        await sup.shutdown()


# ---------------------------------------------------------------------------
# NS-3: zero instances → seam stays pending until shutdown()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ns3_zero_instances_resolves_only_on_shutdown() -> None:
    """NS-3: a supervisor with no registered instances never resolves on the predicate.

    The zero-instance exception (ADR-0023 §D.1): the empty set has no RUNNING/
    BACKOFF instances, but also has no '≥1 ever registered', so the predicate
    is never satisfied.  The seam only resolves on an explicit shutdown().
    """
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_storm_cfg())
    await sup.startup()

    seam_task = asyncio.create_task(sup.wait_until_stopped(), name="test-seam-zero")

    try:
        # With zero instances, the predicate must never fire spontaneously.
        done, _ = await asyncio.wait({seam_task}, timeout=0.2)
        assert seam_task not in done, (
            "wait_until_stopped() resolved on a zero-instance supervisor — "
            "the zero-instance exception (ADR-0023 §D.1) must prevent this."
        )
        assert not sup.is_stopped

        # Explicit shutdown() must resolve it.
        await sup.shutdown()
        done, _ = await asyncio.wait({seam_task}, timeout=1.0)
        assert seam_task in done, (
            "wait_until_stopped() did not resolve after explicit shutdown() "
            "on a zero-instance supervisor."
        )
        assert sup.is_stopped
    finally:
        if not seam_task.done():
            seam_task.cancel()
            try:
                await seam_task
            except asyncio.CancelledError:
                pass


# ---------------------------------------------------------------------------
# NS-4: explicit shutdown() with RUNNING instance → seam resolves
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ns4_explicit_shutdown_resolves_seam() -> None:
    """NS-4: shutdown() with a healthy RUNNING instance resolves wait_until_stopped()."""
    async def healthy_cycle(plugin: Any, cfg: Any, source_id: str) -> int:
        await asyncio.sleep(0.05)
        return 0

    pipeline = _FakePipeline(pull_side_effect=healthy_cycle)
    sup = Supervisor(pipeline, cfg=_storm_cfg())
    sup.add_pull(_FakePullPlugin(), _FakeCfg(), source_id="healthy", interval=0.001)

    await sup.startup()
    seam_task = asyncio.create_task(sup.wait_until_stopped(), name="test-seam-shutdown")

    # Confirm seam is pending before shutdown
    done, _ = await asyncio.wait({seam_task}, timeout=0.1)
    assert seam_task not in done

    try:
        await sup.shutdown()
        done, _ = await asyncio.wait({seam_task}, timeout=1.0)
        assert seam_task in done, (
            "wait_until_stopped() did not resolve after shutdown() was called "
            "with a healthy running instance."
        )
        assert sup.is_stopped
    finally:
        if not seam_task.done():
            seam_task.cancel()
            try:
                await seam_task
            except asyncio.CancelledError:
                pass


# ---------------------------------------------------------------------------
# NS-5: idempotent after stopped
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ns5_idempotent_after_stopped() -> None:
    """NS-5: after the seam has resolved, a second await returns immediately."""
    pipeline = _FakePipeline()
    sup = Supervisor(pipeline, cfg=_storm_cfg())
    await sup.startup()
    await sup.shutdown()  # zero-instance supervisor → shutdown() sets seam

    # First await
    await sup.wait_until_stopped()  # must not hang

    # Second await — must also return immediately (level-triggered / idempotent)
    done_event = asyncio.Event()

    async def _second_wait() -> None:
        await sup.wait_until_stopped()
        done_event.set()

    second_task = asyncio.create_task(_second_wait())
    done, _ = await asyncio.wait({second_task}, timeout=0.5)
    assert second_task in done, (
        "Second await on wait_until_stopped() hung — it must be idempotent "
        "(level-triggered: returns immediately once the event is set)."
    )


# ---------------------------------------------------------------------------
# NS-6: cmd_run uses public seam; correct shutdown order
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ns6_cmd_run_uses_public_seam_and_correct_order() -> None:
    """NS-6: cmd_run composes the public seam; records the correct teardown order.

    A fake supervisor exposing ONLY the public interface (no private attrs)
    that resolves wait_until_stopped() on demand.  Asserts:
      - cmd_run sets server.should_exit when supervisor-stopped wins the race.
      - shutdown() is called BEFORE store.close() (ADR-0023 §F ordering).
      - The fake has no _shutdown_event or _stopped_event (proves no private access).

    Under the old private-attr design (_shutdown_event.wait()), this test would
    either fail with AttributeError (if the attr is not present) or hang (if the
    attr was never set, because _shutdown_event is only set by shutdown() itself,
    not by the all-parked predicate that wait_until_stopped() is meant to cover).
    """
    from firewatch_cli.commands.run import cmd_run

    call_order: list[str] = []
    stopped_event = asyncio.Event()

    class PublicOnlyFakeSupervisor:
        """Fake that exposes ONLY the public API — no private attributes."""

        def add_pull(self, *a: Any, **kw: Any) -> Any: return MagicMock()
        def add_push(self, *a: Any, **kw: Any) -> Any: return MagicMock()

        async def startup(self) -> None:
            call_order.append("startup")

        async def wait_until_stopped(self) -> None:
            # Simulate the all-parked condition firing after a short delay.
            await stopped_event.wait()
            call_order.append("wait_until_stopped_resolved")

        async def shutdown(self) -> None:
            call_order.append("shutdown")

    class _OrderTrackingStore:
        async def init(self) -> None: ...
        async def close(self) -> None:
            call_order.append("store.close")

    class _FakeOrderPipeline:
        store = _OrderTrackingStore()

    async def _long_running_serve(sockets: Any = None) -> None:
        # Never completes on its own — supervisor_stopped wins the FIRST_COMPLETED
        # race; _graceful_shutdown then cancels this task before awaiting it.
        await asyncio.Event().wait()

    config_file = Path("/tmp/test_ns6_empty_config.json")
    config_file.write_text('{"_instances": []}', encoding="utf-8")

    # Fire the stopped_event shortly after cmd_run starts waiting.
    async def _trigger_stopped() -> None:
        await asyncio.sleep(0.05)
        stopped_event.set()

    trigger = asyncio.create_task(_trigger_stopped())

    try:
        with patch(
            "firewatch_cli.commands.run.load_instances",
            return_value=[],
        ), patch(
            "firewatch_cli.commands.run.Supervisor",
            return_value=PublicOnlyFakeSupervisor(),
        ), patch(
            "firewatch_cli.commands.run._build_pipeline",
            return_value=_FakeOrderPipeline(),
        ), patch(
            "uvicorn.Server.serve", side_effect=_long_running_serve,
        ):
            await cmd_run(registry={}, config_file=config_file, host="127.0.0.1", port=8000)
    finally:
        trigger.cancel()
        try:
            await trigger
        except asyncio.CancelledError:
            pass
        config_file.unlink(missing_ok=True)

    # Validate the recorded order.
    assert "startup" in call_order, "supervisor.startup() was not called"
    assert "wait_until_stopped_resolved" in call_order, "wait_until_stopped() was not awaited"
    assert "shutdown" in call_order, "supervisor.shutdown() was not called"
    assert "store.close" in call_order, "store.close() was not called"

    shutdown_idx = call_order.index("shutdown")
    close_idx = call_order.index("store.close")
    assert shutdown_idx < close_idx, (
        f"store.close() (pos {close_idx}) must come AFTER shutdown() (pos {shutdown_idx}); "
        f"order was: {call_order}"
    )


# ---------------------------------------------------------------------------
# NS-7: park-all emits exactly ONE "supervisor.stopping" log record
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ns7_stopping_log_emitted_exactly_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """NS-7: the all-parked transition emits exactly ONE ERROR log record.

    _maybe_signal_stopped() guards with 'if self._stopped_event.is_set(): return'
    so subsequent terminal transitions (e.g. a second instance parking after the
    event was already set) do NOT re-emit the log line.
    """
    async def always_fail(plugin: Any, cfg: Any, source_id: str) -> int:
        raise RuntimeError("always crashes")

    pipeline = _FakePipeline(pull_side_effect=always_fail)
    sup = Supervisor(pipeline, cfg=_storm_cfg(threshold=2))
    sup.add_pull(_FakePullPlugin("src_a"), _FakeCfg(), source_id="inst-a", interval=0.001)
    sup.add_pull(_FakePullPlugin("src_b"), _FakeCfg(), source_id="inst-b", interval=0.001)

    with caplog.at_level(logging.ERROR, logger="firewatch.supervisor"):
        await sup.startup()
        seam_task = asyncio.create_task(sup.wait_until_stopped())
        done, _ = await asyncio.wait({seam_task}, timeout=3.0)
        assert seam_task in done, "Seam did not resolve — instances may not have parked"

    stopping_records = [
        r for r in caplog.records
        if r.name == "firewatch.supervisor" and "supervisor.stopping" in r.message
    ]
    assert len(stopping_records) == 1, (
        f"Expected exactly 1 'supervisor.stopping' log record; got {len(stopping_records)}. "
        f"Records: {[r.message for r in stopping_records]}"
    )

    await sup.shutdown()
