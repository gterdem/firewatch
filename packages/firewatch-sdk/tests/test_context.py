"""Tests for firewatch_sdk.context.PluginContext and firewatch_sdk.testing.InMemoryScopedKV.

EARS criterion mapping (ADR-0027 rollout / issue #41):

EARS-C1  Ubiquitous: PluginContext SHALL be a frozen Pydantic v2 model exported from
         firewatch_sdk.__all__ with exactly the fields kv: ScopedKV and source_id: str.
EARS-C2  Ubiquitous: frozen=True means a plugin cannot mutate ctx after creation.
EARS-C3  Ubiquitous: arbitrary_types_allowed=True allows ScopedKV (a Protocol) as a field.
EARS-C4  Ubiquitous: InMemoryScopedKV implements the ScopedKV Protocol (put/get/get_all).
EARS-C5  Ubiquitous: InMemoryScopedKV is NOT on firewatch_sdk top-level __all__;
         it is importable via its dedicated module: from firewatch_sdk.testing import InMemoryScopedKV.
EARS-C6  Event-driven: put(ns, k, v) then get(ns, k) returns v.
EARS-C7  Event-driven: get_all(ns) returns all keys in that namespace.
EARS-C8  Unwanted: getting a missing key returns None.
EARS-C9  Unwanted: get_all on an empty namespace returns {}.
EARS-C10 Ubiquitous: PluginContext is importable from firewatch_sdk top-level;
         InMemoryScopedKV is importable from firewatch_sdk.testing (not the top-level).
"""
from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from firewatch_sdk import PluginContext, ScopedKV
from firewatch_sdk.context import PluginContext as ContextDirect
from firewatch_sdk.testing import InMemoryScopedKV

TestingDirect = InMemoryScopedKV  # canonical testing module reference for export assertions


# --------------------------------------------------------------------------- #
# EARS-C1 — PluginContext is a frozen Pydantic v2 model with the right fields  #
# --------------------------------------------------------------------------- #


class TestPluginContextModel:
    """EARS-C1/C2/C3 — PluginContext model shape and constraints."""

    def test_plugincontext_is_pydantic_model(self) -> None:
        """PluginContext must be a subclass of pydantic.BaseModel."""
        assert issubclass(PluginContext, BaseModel)

    def test_plugincontext_has_kv_field(self) -> None:
        """PluginContext must have a 'kv' field."""
        assert "kv" in PluginContext.model_fields

    def test_plugincontext_has_source_id_field(self) -> None:
        """PluginContext must have a 'source_id' field."""
        assert "source_id" in PluginContext.model_fields

    def test_plugincontext_has_only_two_fields(self) -> None:
        """PluginContext must have EXACTLY kv and source_id — no more (ADR-0027 §1)."""
        assert set(PluginContext.model_fields.keys()) == {"kv", "source_id"}

    def test_plugincontext_source_id_is_str(self) -> None:
        """source_id field must be typed as str."""
        kv = InMemoryScopedKV()
        ctx = PluginContext(kv=kv, source_id="pi-home")
        assert isinstance(ctx.source_id, str)
        assert ctx.source_id == "pi-home"

    def test_plugincontext_is_frozen(self) -> None:
        """EARS-C2: PluginContext must be frozen — mutation must raise."""
        kv = InMemoryScopedKV()
        ctx = PluginContext(kv=kv, source_id="pi-home")
        with pytest.raises((ValidationError, TypeError)):
            ctx.source_id = "mutated"  # type: ignore[misc]

    def test_plugincontext_kv_accepts_protocol_impl(self) -> None:
        """EARS-C3: kv field must accept an InMemoryScopedKV (a Protocol impl), not raise."""
        kv = InMemoryScopedKV()
        ctx = PluginContext(kv=kv, source_id="test")
        assert ctx.kv is kv

    def test_plugincontext_is_hashable(self) -> None:
        """A frozen Pydantic model should be hashable (needed for long-lived start() holds)."""
        kv = InMemoryScopedKV()
        ctx = PluginContext(kv=kv, source_id="test")
        # hash() must not raise
        h = hash(ctx)
        assert isinstance(h, int)


# --------------------------------------------------------------------------- #
# EARS-C4 — InMemoryScopedKV implements the ScopedKV Protocol                  #
# --------------------------------------------------------------------------- #


class TestInMemoryScopedKVProtocol:
    """EARS-C4 — InMemoryScopedKV satisfies runtime_checkable ScopedKV Protocol."""

    def test_in_memory_scoped_kv_is_scoped_kv(self) -> None:
        """isinstance(InMemoryScopedKV(), ScopedKV) must be True."""
        kv = InMemoryScopedKV()
        assert isinstance(kv, ScopedKV), (
            "InMemoryScopedKV does not satisfy the ScopedKV Protocol — "
            "put/get/get_all may be missing or have wrong signatures"
        )

    def test_has_put_method(self) -> None:
        kv = InMemoryScopedKV()
        assert hasattr(kv, "put") and callable(kv.put)

    def test_has_get_method(self) -> None:
        kv = InMemoryScopedKV()
        assert hasattr(kv, "get") and callable(kv.get)

    def test_has_get_all_method(self) -> None:
        kv = InMemoryScopedKV()
        assert hasattr(kv, "get_all") and callable(kv.get_all)


# --------------------------------------------------------------------------- #
# EARS-C5/C10 — Exports from firewatch_sdk.__all__                             #
# --------------------------------------------------------------------------- #


class TestExports:
    """EARS-C5/C10 — PluginContext is in firewatch_sdk.__all__;
    InMemoryScopedKV is NOT (it lives in firewatch_sdk.testing only)."""

    def test_plugin_context_in_all(self) -> None:
        import firewatch_sdk
        assert "PluginContext" in firewatch_sdk.__all__

    def test_in_memory_scoped_kv_not_in_top_level_all(self) -> None:
        """InMemoryScopedKV is a test double — must NOT be on the production public surface."""
        import firewatch_sdk
        assert "InMemoryScopedKV" not in firewatch_sdk.__all__

    def test_plugin_context_importable_from_top_level(self) -> None:
        from firewatch_sdk import PluginContext as PC  # noqa: F401
        assert PC is ContextDirect

    def test_in_memory_scoped_kv_importable_from_testing_module(self) -> None:
        """InMemoryScopedKV must remain importable via its dedicated testing module."""
        from firewatch_sdk.testing import InMemoryScopedKV as IMKV  # noqa: F401
        assert IMKV is TestingDirect


# --------------------------------------------------------------------------- #
# EARS-C6/C7/C8/C9 — InMemoryScopedKV behavior                                #
# --------------------------------------------------------------------------- #


class TestInMemoryScopedKVBehavior:
    """EARS-C6 through C9 — put/get/get_all behavior."""

    async def test_put_then_get_returns_value(self) -> None:
        """EARS-C6: put(ns, k, v) then get(ns, k) returns v."""
        kv = InMemoryScopedKV()
        await kv.put("cursors", "last_seen", "2026-06-04T00:00:00+00:00")
        result = await kv.get("cursors", "last_seen")
        assert result == "2026-06-04T00:00:00+00:00"

    async def test_put_overwrites_existing(self) -> None:
        """put() on an existing key must overwrite (upsert semantics)."""
        kv = InMemoryScopedKV()
        await kv.put("ns", "k", "v1")
        await kv.put("ns", "k", "v2")
        assert await kv.get("ns", "k") == "v2"

    async def test_get_missing_returns_none(self) -> None:
        """EARS-C8: get() on a missing key returns None."""
        kv = InMemoryScopedKV()
        result = await kv.get("ns", "nonexistent")
        assert result is None

    async def test_get_all_returns_all_keys_in_namespace(self) -> None:
        """EARS-C7: get_all(ns) returns all key-value pairs in that namespace."""
        kv = InMemoryScopedKV()
        await kv.put("rules", "k1", "v1")
        await kv.put("rules", "k2", "v2")
        await kv.put("other_ns", "k3", "v3")  # different namespace — must not appear
        result = await kv.get_all("rules")
        assert result == {"k1": "v1", "k2": "v2"}

    async def test_get_all_empty_namespace_returns_empty_dict(self) -> None:
        """EARS-C9: get_all on a namespace with no keys returns {}."""
        kv = InMemoryScopedKV()
        result = await kv.get_all("empty_ns")
        assert result == {}

    async def test_namespaces_are_isolated(self) -> None:
        """Keys in different namespaces must not collide."""
        kv = InMemoryScopedKV()
        await kv.put("ns1", "key", "value1")
        await kv.put("ns2", "key", "value2")
        assert await kv.get("ns1", "key") == "value1"
        assert await kv.get("ns2", "key") == "value2"

    async def test_multiple_put_delete_semantics(self) -> None:
        """After put, the key is visible; after another put with same key, value is updated."""
        kv = InMemoryScopedKV()
        await kv.put("ns", "x", "a")
        await kv.put("ns", "y", "b")
        all_items = await kv.get_all("ns")
        assert all_items == {"x": "a", "y": "b"}


# --------------------------------------------------------------------------- #
# Integration: PluginContext constructed with InMemoryScopedKV                 #
# --------------------------------------------------------------------------- #


class TestPluginContextIntegration:
    """Integration — construct PluginContext with InMemoryScopedKV in one line."""

    async def test_ctx_kv_operations_work(self) -> None:
        """ctx.kv.put/get works through a PluginContext (the one-liner pattern)."""
        ctx = PluginContext(kv=InMemoryScopedKV(), source_id="my-instance")
        await ctx.kv.put("state", "cursor", "2026-06-04")
        result = await ctx.kv.get("state", "cursor")
        assert result == "2026-06-04"

    def test_ctx_source_id_accessible(self) -> None:
        ctx = PluginContext(kv=InMemoryScopedKV(), source_id="my-instance")
        assert ctx.source_id == "my-instance"

    def test_ctx_source_id_is_labelling_only(self) -> None:
        """source_id is set to the instance name; accessing it must not raise."""
        ctx = PluginContext(kv=InMemoryScopedKV(), source_id="azure-lab")
        assert ctx.source_id == "azure-lab"
