"""Tests for the ADR-0034 action seam on the supervisor.

Covers supervisor.run_action_for and supervisor.action_status_for.

EARS criterion → test mapping
==============================

EARS-AS-1 (event-driven — run_action_for happy path):
  WHEN run_action_for is called for a configured instance with a declared
  action, THEN the supervisor SHALL mint PluginContext (source_type from
  metadata().type_key, never caller input), await plugin.run_action, run
  the post-action KV promotion on success, and return ActionResult.
  -> test_run_action_for_happy_path
  -> test_run_action_for_mints_ctx_from_plugin_type_key
  -> test_run_action_for_promotes_kv_on_success
  -> test_run_action_for_skips_kv_promotion_on_failure

EARS-AS-2 (unwanted — 404 guards):
  IF instance is not found, run_action_for SHALL raise KeyError.
  IF action_id is not declared, run_action_for SHALL raise ValueError.
  -> test_run_action_for_unknown_instance_raises_key_error
  -> test_run_action_for_undeclared_action_raises_value_error

EARS-AS-3 (event-driven — action_status_for happy path):
  WHEN action_status_for is called for a declared action, THEN the supervisor
  SHALL return the ActionStatus from the plugin's action_status.
  -> test_action_status_for_happy_path

EARS-AS-4 (state-driven — resilient status read):
  A raising plugin.action_status SHALL return NULL_ACTION_STATUS, not a 500.
  -> test_action_status_for_raising_plugin_degrades_to_null

EARS-AS-5 (unwanted — status 404 guards):
  IF instance is not found or action_id is undeclared, action_status_for
  SHALL raise the appropriate exception (route maps to 404).
  -> test_action_status_for_unknown_instance_raises_key_error
  -> test_action_status_for_undeclared_action_raises_value_error

EARS-AS-6 (ubiquitous — non-ActionCapable plugin is handled gracefully):
  IF a plugin declares actions but does NOT implement ActionCapable, THEN
  run_action_for SHALL return ActionResult(ok=False) instead of crashing.
  action_status_for SHALL return NULL_ACTION_STATUS.
  -> test_run_action_for_non_capable_plugin_returns_ok_false
  -> test_action_status_for_non_capable_plugin_returns_null

NB-1 (security — plugin exception wrapper):
  WHEN plugin.run_action raises an unexpected exception, THEN run_action_for
  SHALL catch it, log with exc_info=True, and return ActionResult(ok=False)
  with a sanitised message — never propagate the raw exception to the caller.
  -> test_run_action_for_plugin_exception_returns_ok_false_sanitised

NB-2 (security — single-flight guard):
  WHILE a (type_key, source_id, action_id) triple is in-flight, THEN a
  concurrent second call SHALL raise RuntimeError with message "in_progress".
  AFTER the first call completes the in-progress entry SHALL be removed so
  a subsequent call proceeds normally.
  AFTER the first call raises (exception path) the entry SHALL also be removed.
  -> test_run_action_for_concurrent_same_triple_raises_in_progress
  -> test_run_action_for_in_progress_cleared_after_completion
  -> test_run_action_for_in_progress_cleared_after_exception
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest
from pydantic import BaseModel

from firewatch_sdk import (
    NULL_ACTION_STATUS,
    ActionResult,
    ActionStatus,
    PluginContext,
    RawEvent,
    SecurityEvent,
    SourceAction,
    SourceMetadata,
)
from firewatch_core.supervisor import Supervisor, SupervisorConfig
from _fakes import FakeStore


# --------------------------------------------------------------------------- #
# Test doubles                                                                 #
# --------------------------------------------------------------------------- #


class _FakeCfg(BaseModel):
    note: str = "fake"


class _ActionPullPlugin:
    """A PullSource+SourcePlugin+ActionCapable test double.

    Declares one action (``fetch_rules``) and records invocations.
    """

    def __init__(
        self,
        type_key: str = "actionsrc",
        run_ok: bool = True,
        status_raises: bool = False,
        kv_data: dict[str, str] | None = None,
    ) -> None:
        self._type_key = type_key
        self._run_ok = run_ok
        self._status_raises = status_raises
        self._kv_data = kv_data or {"2001001": "ET DROP Known botnet"}
        self.run_calls: list[tuple[str, Any, Any]] = []
        self.status_calls: list[tuple[str, Any, Any]] = []

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name="Action Plugin",
            version="0.1.0",
            flavor="pull",
            actions=(
                SourceAction(
                    id="fetch_rules",
                    label="Fetch Rules",
                    description="Download and store rule descriptions.",
                    provides=("rule_descriptions",),
                ),
            ),
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
            source_ip="192.0.2.1",
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True

    async def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]:
        # Write kv data so we can verify KV promotion.
        for k, v in self._kv_data.items():
            await ctx.kv.put("rule_descriptions", k, v)
        return
        yield  # make this an async generator

    # ActionCapable methods:

    async def run_action(
        self, action_id: str, cfg: Any, ctx: PluginContext
    ) -> ActionResult:
        self.run_calls.append((action_id, cfg, ctx))
        # Write KV so promotion can be tested.
        for k, v in self._kv_data.items():
            await ctx.kv.put("rule_descriptions", k, v)
        if self._run_ok:
            return ActionResult(ok=True, message="rules fetched", detail={"count": "1"})
        return ActionResult(ok=False, message="fetch failed")

    async def action_status(
        self, action_id: str, cfg: Any, ctx: PluginContext
    ) -> ActionStatus:
        if self._status_raises:
            raise RuntimeError("status exploded")
        self.status_calls.append((action_id, cfg, ctx))
        return ActionStatus(last_run_at=1.0, stale=False, message="ok")


class _NoCapabilityPlugin:
    """A plugin that declares actions but does NOT implement ActionCapable."""

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key="nocap",
            display_name="No Capability Plugin",
            version="0.1.0",
            flavor="pull",
            actions=(
                SourceAction(id="sync", label="Sync", description="Sync"),
            ),
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakeCfg

    def validate_config(self, cfg: dict[str, Any]) -> None:
        pass

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        return SecurityEvent(
            source_type="nocap",
            source_id=source_id,
            timestamp=raw.received_at,
            source_ip="192.0.2.2",
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True

    async def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]:
        return
        yield


class _FakePipeline:
    """Minimal pipeline double that exposes store + _promote_rule_descriptions."""

    def __init__(self) -> None:
        self.store = FakeStore()
        self.promote_calls: list[str] = []

    async def _promote_rule_descriptions(self, source_type: str) -> None:
        self.promote_calls.append(source_type)


def _make_supervisor(pipeline: _FakePipeline | None = None) -> Supervisor:
    p = pipeline or _FakePipeline()
    return Supervisor(p, cfg=SupervisorConfig())


# --------------------------------------------------------------------------- #
# EARS-AS-1: run_action_for happy path                                        #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_run_action_for_happy_path():
    """run_action_for returns ActionResult from plugin and the action is invoked."""
    plugin = _ActionPullPlugin()
    pipeline = _FakePipeline()
    sup = _make_supervisor(pipeline)
    sup.register_idle(plugin, _FakeCfg(), source_id="actionsrc", flavor="pull")

    result = await sup.run_action_for("actionsrc", "actionsrc", "fetch_rules")

    assert result.ok is True
    assert result.message == "rules fetched"
    assert len(plugin.run_calls) == 1
    assert plugin.run_calls[0][0] == "fetch_rules"


@pytest.mark.asyncio
async def test_run_action_for_mints_ctx_from_plugin_type_key():
    """The minted PluginContext.source_id equals the instance's source_id."""
    plugin = _ActionPullPlugin()
    pipeline = _FakePipeline()
    sup = _make_supervisor(pipeline)
    sup.register_idle(plugin, _FakeCfg(), source_id="myinstance", flavor="pull")

    await sup.run_action_for("actionsrc", "myinstance", "fetch_rules")

    _, _, ctx = plugin.run_calls[0]
    assert ctx.source_id == "myinstance"


@pytest.mark.asyncio
async def test_run_action_for_promotes_kv_on_success():
    """On a successful action, the post-action KV promotion is called."""
    plugin = _ActionPullPlugin(run_ok=True)
    pipeline = _FakePipeline()
    sup = _make_supervisor(pipeline)
    sup.register_idle(plugin, _FakeCfg(), source_id="actionsrc", flavor="pull")

    await sup.run_action_for("actionsrc", "actionsrc", "fetch_rules")

    assert "actionsrc" in pipeline.promote_calls


@pytest.mark.asyncio
async def test_run_action_for_skips_kv_promotion_on_failure():
    """On a failed action (ok=False), the KV promotion is NOT called."""
    plugin = _ActionPullPlugin(run_ok=False)
    pipeline = _FakePipeline()
    sup = _make_supervisor(pipeline)
    sup.register_idle(plugin, _FakeCfg(), source_id="actionsrc", flavor="pull")

    result = await sup.run_action_for("actionsrc", "actionsrc", "fetch_rules")

    assert result.ok is False
    assert pipeline.promote_calls == []


# --------------------------------------------------------------------------- #
# EARS-AS-2: 404 guards on run_action_for                                     #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_run_action_for_unknown_instance_raises_key_error():
    """run_action_for raises KeyError for an unregistered instance."""
    sup = _make_supervisor()
    with pytest.raises(KeyError, match="instance not found"):
        await sup.run_action_for("actionsrc", "nonexistent", "fetch_rules")


@pytest.mark.asyncio
async def test_run_action_for_undeclared_action_raises_value_error():
    """run_action_for raises ValueError for an action_id not in metadata().actions."""
    plugin = _ActionPullPlugin()
    sup = _make_supervisor()
    sup.register_idle(plugin, _FakeCfg(), source_id="actionsrc", flavor="pull")

    with pytest.raises(ValueError, match="not declared"):
        await sup.run_action_for("actionsrc", "actionsrc", "nonexistent_action")


# --------------------------------------------------------------------------- #
# EARS-AS-3: action_status_for happy path                                     #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_action_status_for_happy_path():
    """action_status_for returns the ActionStatus from the plugin."""
    plugin = _ActionPullPlugin()
    sup = _make_supervisor()
    sup.register_idle(plugin, _FakeCfg(), source_id="actionsrc", flavor="pull")

    status = await sup.action_status_for("actionsrc", "actionsrc", "fetch_rules")

    assert status.last_run_at == 1.0
    assert status.stale is False
    assert status.message == "ok"


# --------------------------------------------------------------------------- #
# EARS-AS-4: resilient status read                                             #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_action_status_for_raising_plugin_degrades_to_null():
    """A plugin whose action_status raises returns NULL_ACTION_STATUS, not a 500."""
    plugin = _ActionPullPlugin(status_raises=True)
    sup = _make_supervisor()
    sup.register_idle(plugin, _FakeCfg(), source_id="actionsrc", flavor="pull")

    status = await sup.action_status_for("actionsrc", "actionsrc", "fetch_rules")

    # Must NOT raise; must return the null sentinel.
    assert status is NULL_ACTION_STATUS or (
        status.last_run_at is None and status.stale is None
    )


# --------------------------------------------------------------------------- #
# EARS-AS-5: status 404 guards                                                #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_action_status_for_unknown_instance_raises_key_error():
    """action_status_for raises KeyError for an unregistered instance."""
    sup = _make_supervisor()
    with pytest.raises(KeyError, match="instance not found"):
        await sup.action_status_for("actionsrc", "nonexistent", "fetch_rules")


@pytest.mark.asyncio
async def test_action_status_for_undeclared_action_raises_value_error():
    """action_status_for raises ValueError for an action_id not in metadata().actions."""
    plugin = _ActionPullPlugin()
    sup = _make_supervisor()
    sup.register_idle(plugin, _FakeCfg(), source_id="actionsrc", flavor="pull")

    with pytest.raises(ValueError, match="not declared"):
        await sup.action_status_for("actionsrc", "actionsrc", "ghost_action")


# --------------------------------------------------------------------------- #
# EARS-AS-6: non-ActionCapable plugin handled gracefully                      #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_run_action_for_non_capable_plugin_returns_ok_false():
    """A plugin declaring actions but missing ActionCapable gets ok=False, no crash."""
    plugin = _NoCapabilityPlugin()
    sup = _make_supervisor()
    sup.register_idle(plugin, _FakeCfg(), source_id="nocap", flavor="pull")

    result = await sup.run_action_for("nocap", "nocap", "sync")

    assert result.ok is False
    assert "ActionCapable" in result.message


@pytest.mark.asyncio
async def test_action_status_for_non_capable_plugin_returns_null():
    """A plugin declaring actions but missing ActionCapable returns NULL_ACTION_STATUS."""
    plugin = _NoCapabilityPlugin()
    sup = _make_supervisor()
    sup.register_idle(plugin, _FakeCfg(), source_id="nocap", flavor="pull")

    status = await sup.action_status_for("nocap", "nocap", "sync")

    assert status.last_run_at is None
    assert status.stale is None


# --------------------------------------------------------------------------- #
# NB-1: plugin exception wrapper                                               #
# --------------------------------------------------------------------------- #


class _BurstPlugin(_ActionPullPlugin):
    """A plugin whose run_action raises an unexpected exception."""

    async def run_action(
        self, action_id: str, cfg: Any, ctx: Any
    ) -> "ActionResult":
        raise RuntimeError("internal meltdown")


@pytest.mark.asyncio
async def test_run_action_for_plugin_exception_returns_ok_false_sanitised():
    """NB-1: an unexpected exception from plugin.run_action is caught and returns ok=False.

    The raw exception must NOT propagate to the caller (no 500 path).
    The returned message must be a sanitised string (not the raw exception detail).
    """
    plugin = _BurstPlugin()
    sup = _make_supervisor()
    sup.register_idle(plugin, _FakeCfg(), source_id="actionsrc", flavor="pull")

    result = await sup.run_action_for("actionsrc", "actionsrc", "fetch_rules")

    assert result.ok is False
    # Message must be sanitised — must NOT contain the raw exception text.
    assert "internal meltdown" not in result.message
    # Must contain a generic hint that server logs have details.
    assert "server logs" in result.message.lower() or "unexpected" in result.message.lower()


# --------------------------------------------------------------------------- #
# NB-2: single-flight guard                                                    #
# --------------------------------------------------------------------------- #


class _SlowPlugin(_ActionPullPlugin):
    """A plugin whose run_action blocks until an event is set — created per-test."""

    def __init__(self, gate: asyncio.Event) -> None:
        super().__init__()
        self._gate = gate

    async def run_action(
        self, action_id: str, cfg: Any, ctx: Any
    ) -> "ActionResult":
        await self._gate.wait()
        return ActionResult(ok=True, message="slow done")


@pytest.mark.asyncio
async def test_run_action_for_concurrent_same_triple_raises_in_progress():
    """NB-2: a concurrent call for the same (type_key, source_id, action_id) raises RuntimeError.

    Two concurrent POSTs for the same triple: one runs, one gets RuntimeError("in_progress").
    """
    gate = asyncio.Event()
    plugin = _SlowPlugin(gate)
    pipeline = _FakePipeline()
    sup = _make_supervisor(pipeline)
    sup.register_idle(plugin, _FakeCfg(), source_id="actionsrc", flavor="pull")

    # Start the first call but keep it blocked (gate not set yet).
    first = asyncio.create_task(
        sup.run_action_for("actionsrc", "actionsrc", "fetch_rules")
    )
    # Yield control so the first task can enter run_action_for and mark in-progress.
    await asyncio.sleep(0)

    # Second call for same triple must raise RuntimeError with "in_progress".
    with pytest.raises(RuntimeError, match="in_progress"):
        await sup.run_action_for("actionsrc", "actionsrc", "fetch_rules")

    # Unblock the first call and let it finish cleanly.
    gate.set()
    result = await first
    assert result.ok is True


@pytest.mark.asyncio
async def test_run_action_for_in_progress_cleared_after_completion():
    """NB-2: after the first call completes, the in-progress entry is removed.

    A subsequent call for the same triple proceeds normally (no persistent block).
    """
    plugin = _ActionPullPlugin()
    pipeline = _FakePipeline()
    sup = _make_supervisor(pipeline)
    sup.register_idle(plugin, _FakeCfg(), source_id="actionsrc", flavor="pull")

    # First call completes.
    r1 = await sup.run_action_for("actionsrc", "actionsrc", "fetch_rules")
    assert r1.ok is True

    # Second call for the same triple must NOT raise in_progress.
    r2 = await sup.run_action_for("actionsrc", "actionsrc", "fetch_rules")
    assert r2.ok is True


@pytest.mark.asyncio
async def test_run_action_for_in_progress_cleared_after_exception():
    """NB-2: the in-progress entry is removed even when the plugin raises (NB-1 path).

    After a plugin exception the in-progress set must be cleaned up so a
    subsequent call is not permanently blocked.
    """
    plugin = _BurstPlugin()
    sup = _make_supervisor()
    sup.register_idle(plugin, _FakeCfg(), source_id="actionsrc", flavor="pull")

    # First call: plugin raises, NB-1 catches and returns ok=False.
    r1 = await sup.run_action_for("actionsrc", "actionsrc", "fetch_rules")
    assert r1.ok is False

    # Second call must NOT raise in_progress — entry was cleaned up in finally.
    r2 = await sup.run_action_for("actionsrc", "actionsrc", "fetch_rules")
    assert r2.ok is False  # still fails (plugin still raises), but not blocked
