"""Tests for firewatch_cli.commands._pipeline_factory — MB.2 (issue #54).

EARS criterion → test mapping
══════════════════════════════

EARS-1 (Ubiquitous): The runtime pipeline shall use the real OpenAIEngine
    (ADR-0022); the _NullAIEngine stub shall not exist in the codebase.
    → test_null_ai_engine_is_gone
    → test_ai_enabled_true_builds_openai_engine

EARS-2 (State-driven): While ai_enabled is false, the pipeline shall score using
    rule + detection signals only and report ai_status="disabled", never calling
    the inference endpoint.
    → test_ai_enabled_false_builds_disabled_engine
    → test_disabled_engine_returns_disabled_status_concise
    → test_disabled_engine_returns_disabled_status_detailed
    → test_disabled_engine_is_available_returns_false
    → test_disabled_engine_never_calls_http

EARS-3 (State-driven): While ai_enabled is true but the endpoint is unreachable,
    scores shall still be produced (rule+detection) with ai_status="unavailable"
    and the AI contribution shall never de-escalate a score (ADR-0015 additive).
    → test_unreachable_endpoint_returns_unavailable_no_error
    → test_openai_engine_graceful_degradation_is_additive_only

EARS-4 (Unwanted): The demo/golden path shall not require a running LLM; a green
    golden run shall be deterministic with AI off.
    → test_build_pipeline_ai_disabled_no_network_calls
    → test_firewatch_ai_enabled_env_var_honored_false
    → test_firewatch_ai_enabled_env_var_honored_true

Security notes
--------------
RFC 5737 documentation IPs are used for any IP literals (192.0.2.x, 203.0.113.x).
No live network calls in any test — HTTP patched throughout.
"""
from __future__ import annotations

import inspect
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# EARS-1: _NullAIEngine is gone; real OpenAIEngine is used when ai_enabled=True
# ---------------------------------------------------------------------------


class TestNullAIEngineIsGone:
    """EARS-1: _NullAIEngine stub must not exist anywhere in the codebase."""

    def test_null_ai_engine_is_gone(self) -> None:
        """The _NullAIEngine class must NOT appear in _pipeline_factory.py."""
        from firewatch_cli.commands import _pipeline_factory

        source = inspect.getsource(_pipeline_factory)
        assert "_NullAIEngine" not in source, (
            "_NullAIEngine still present in _pipeline_factory — it must be deleted "
            "and replaced by the real OpenAIEngine (EARS-1, issue #54)."
        )


class TestAiEnabledTrueBuildsOpenAIEngine:
    """EARS-1: ai_enabled=True → factory builds a real OpenAIEngine."""

    def test_ai_enabled_true_builds_openai_engine(self, tmp_path: Any) -> None:
        """When RuntimeConfig.ai_enabled is True the pipeline uses OpenAIEngine."""
        from firewatch_core.adapters.ai_openai import OpenAIEngine
        from firewatch_cli.commands._pipeline_factory import _build_pipeline

        with patch("firewatch_cli.commands._pipeline_factory.SQLiteEventStore") as mock_store, \
             patch("firewatch_cli.commands._pipeline_factory.Pipeline") as mock_pipeline, \
             patch("firewatch_cli.commands._pipeline_factory.JsonFileConfigStore") as mock_cfg_store:
            mock_store.return_value = MagicMock()
            mock_cfg_store.return_value.get_runtime.return_value = MagicMock(
                ai_enabled=True,
                ollama_base_url="http://127.0.0.1:11434",
                ollama_model="llama3.2",
            )
            _build_pipeline(config_file=tmp_path / "fw.json")

            # The pipeline was constructed with an OpenAIEngine instance
            call_kwargs = mock_pipeline.call_args
            ai_engine_arg = (
                call_kwargs.kwargs.get("ai_engine")
                or (call_kwargs.args[1] if len(call_kwargs.args) > 1 else None)
            )
            assert isinstance(ai_engine_arg, OpenAIEngine), (
                f"Expected OpenAIEngine, got {type(ai_engine_arg).__name__}. "
                "ai_enabled=True must wire the real OpenAIEngine (EARS-1)."
            )


# ---------------------------------------------------------------------------
# EARS-2: ai_enabled=False → DisabledAIEngine; ai_status="disabled"
# ---------------------------------------------------------------------------


class TestAiEnabledFalseBuildsDisabledEngine:
    """EARS-2: ai_enabled=False → factory builds a disabled (rules-only) engine."""

    def test_ai_enabled_false_builds_disabled_engine(self, tmp_path: Any) -> None:
        """When RuntimeConfig.ai_enabled is False the pipeline uses a disabled engine."""
        from firewatch_core.adapters.ai_openai import OpenAIEngine
        from firewatch_cli.commands._pipeline_factory import _build_pipeline

        with patch("firewatch_cli.commands._pipeline_factory.SQLiteEventStore") as mock_store, \
             patch("firewatch_cli.commands._pipeline_factory.Pipeline") as mock_pipeline, \
             patch("firewatch_cli.commands._pipeline_factory.JsonFileConfigStore") as mock_cfg_store:
            mock_store.return_value = MagicMock()
            mock_cfg_store.return_value.get_runtime.return_value = MagicMock(
                ai_enabled=False,
                ollama_base_url="http://127.0.0.1:11434",
                ollama_model="llama3.2",
            )
            _build_pipeline(config_file=tmp_path / "fw.json")

            call_kwargs = mock_pipeline.call_args
            ai_engine_arg = (
                call_kwargs.kwargs.get("ai_engine")
                or (call_kwargs.args[1] if len(call_kwargs.args) > 1 else None)
            )
            # Must NOT be an OpenAIEngine when disabled
            assert not isinstance(ai_engine_arg, OpenAIEngine), (
                "OpenAIEngine must NOT be used when ai_enabled=False (EARS-2)."
            )
            # Must be the disabled engine (has ai_status="disabled" in its responses)
            assert hasattr(ai_engine_arg, "analyze_concise"), (
                "Disabled engine must still implement the AIEngine interface."
            )


class TestDisabledAIEngine:
    """EARS-2: DisabledAIEngine returns ai_status='disabled' and never calls HTTP."""

    @pytest.fixture()
    def disabled_engine(self) -> Any:
        """Return the DisabledAIEngine instance directly (core-owned, issue #39)."""
        from firewatch_core.adapters.ai_disabled import DisabledAIEngine

        return DisabledAIEngine()

    @pytest.mark.asyncio
    async def test_disabled_engine_returns_disabled_status_concise(
        self, disabled_engine: Any
    ) -> None:
        """analyze_concise on DisabledAIEngine returns ai_status='disabled'."""
        result = await disabled_engine.analyze_concise(
            ip="192.0.2.1",
            total_events=10,
            blocked_events=8,
            rules_triggered=3,
            first_seen="2024-01-01T00:00:00Z",
            last_seen="2024-01-01T12:00:00Z",
            samples=[],
        )
        assert result.get("ai_status") == "disabled", (
            f"Expected ai_status='disabled', got {result.get('ai_status')!r} (EARS-2)."
        )

    @pytest.mark.asyncio
    async def test_disabled_engine_returns_disabled_status_detailed(
        self, disabled_engine: Any
    ) -> None:
        """analyze_detailed on DisabledAIEngine returns ai_status='disabled'."""
        result = await disabled_engine.analyze_detailed(
            ip="192.0.2.1",
            total_events=10,
            blocked_events=8,
            rules_triggered=3,
            first_seen="2024-01-01T00:00:00Z",
            last_seen="2024-01-01T12:00:00Z",
            samples=[],
        )
        assert result.get("ai_status") == "disabled", (
            f"Expected ai_status='disabled', got {result.get('ai_status')!r} (EARS-2)."
        )

    @pytest.mark.asyncio
    async def test_disabled_engine_is_available_returns_false(
        self, disabled_engine: Any
    ) -> None:
        """DisabledAIEngine.is_available() returns False (no inference endpoint)."""
        result = await disabled_engine.is_available()
        assert result is False, (
            "DisabledAIEngine.is_available() must return False (EARS-2)."
        )

    @pytest.mark.asyncio
    async def test_disabled_engine_never_calls_http(self, disabled_engine: Any) -> None:
        """DisabledAIEngine never makes HTTP requests (EARS-2 no endpoint calls)."""
        with patch("httpx.AsyncClient") as mock_client:
            await disabled_engine.analyze_concise(
                ip="192.0.2.1",
                total_events=5,
                blocked_events=3,
                rules_triggered=1,
                first_seen="2024-01-01T00:00:00Z",
                last_seen="2024-01-01T12:00:00Z",
                samples=[],
            )
            await disabled_engine.analyze_detailed(
                ip="192.0.2.1",
                total_events=5,
                blocked_events=3,
                rules_triggered=1,
                first_seen="2024-01-01T00:00:00Z",
                last_seen="2024-01-01T12:00:00Z",
                samples=[],
            )
            await disabled_engine.is_available()
            mock_client.assert_not_called()


# ---------------------------------------------------------------------------
# Issue #39/#40 (ADR-0066): DisabledAIEngine's administratively_disabled flag
# and the fault=True construction-failure path (AC4).
# ---------------------------------------------------------------------------


class TestDisabledAIEngineAdminFlag:
    """DisabledAIEngine self-reports administrative disablement via getattr."""

    def test_default_construction_reports_administratively_disabled(self) -> None:
        """DisabledAIEngine() (default) sets administratively_disabled=True.

        This is the additive attribute the pipeline's stamping authority
        (firewatch_core.ai_status._is_admin_disabled via getattr) reads to
        distinguish 'disabled' (a choice) from 'unavailable' (a fault).
        """
        from firewatch_core.adapters.ai_disabled import DisabledAIEngine

        engine = DisabledAIEngine()
        assert engine.administratively_disabled is True

    def test_fault_construction_reports_not_administratively_disabled(self) -> None:
        """DisabledAIEngine(fault=True) sets administratively_disabled=False.

        Issue #40 AC4: engine CONSTRUCTION failure while ai_enabled=true is a
        FAULT, not a choice — the pipeline must stamp 'unavailable', which
        requires administratively_disabled to read False here.
        """
        from firewatch_core.adapters.ai_disabled import DisabledAIEngine

        engine = DisabledAIEngine(fault=True)
        assert engine.administratively_disabled is False

    def test_openai_engine_has_no_administratively_disabled_attribute(self) -> None:
        """The real OpenAIEngine has no administratively_disabled attribute.

        getattr(engine, "administratively_disabled", False) must default to
        False for any engine that does not opt in to the signal.
        """
        from firewatch_core.adapters.ai_openai import OpenAIEngine

        engine = OpenAIEngine(base_url="http://127.0.0.1:11434", model="llama3.2")
        assert getattr(engine, "administratively_disabled", False) is False

    @pytest.mark.asyncio
    async def test_fault_engine_envelope_status_is_unavailable_not_disabled(self) -> None:
        """DisabledAIEngine(fault=True)'s own envelope carries 'unavailable', not 'disabled'."""
        from firewatch_core.adapters.ai_disabled import DisabledAIEngine

        engine = DisabledAIEngine(fault=True)
        result = await engine.analyze_concise(
            ip="192.0.2.1", total_events=1, blocked_events=1, rules_triggered=1,
            first_seen="2024-01-01T00:00:00Z", last_seen="2024-01-01T00:00:00Z",
            samples=[],
        )
        assert result.get("ai_status") == "unavailable"


class TestConstructionFailureFallsBackToFaultEngine:
    """Issue #40 AC4: engine construction failure while ai_enabled=true -> fault=True."""

    def test_construction_failure_uses_fault_disabled_engine(self, tmp_path: Any) -> None:
        """OpenAIEngine() raising at construction falls back to DisabledAIEngine(fault=True)."""
        from firewatch_core.adapters.ai_disabled import DisabledAIEngine
        from firewatch_cli.commands._pipeline_factory import _build_pipeline

        with patch("firewatch_cli.commands._pipeline_factory.SQLiteEventStore") as mock_store, \
             patch("firewatch_cli.commands._pipeline_factory.Pipeline") as mock_pipeline, \
             patch("firewatch_cli.commands._pipeline_factory.JsonFileConfigStore") as mock_cfg_store, \
             patch(
                 "firewatch_cli.commands._pipeline_factory.OpenAIEngine",
                 side_effect=ValueError("non-local base_url"),
             ):
            mock_store.return_value = MagicMock()
            mock_cfg_store.return_value.get_runtime.return_value = MagicMock(
                ai_enabled=True,
                ollama_base_url="https://api.openai.com",
                ollama_model="llama3.2",
            )
            _build_pipeline(config_file=tmp_path / "fw.json")

            call_kwargs = mock_pipeline.call_args
            ai_engine_arg = (
                call_kwargs.kwargs.get("ai_engine")
                or (call_kwargs.args[1] if len(call_kwargs.args) > 1 else None)
            )
            assert isinstance(ai_engine_arg, DisabledAIEngine)
            assert ai_engine_arg.administratively_disabled is False, (
                "Construction failure while ai_enabled=true is a FAULT, not a choice "
                "(issue #40 AC4) — administratively_disabled must be False so the "
                "stamping authority reports 'unavailable', never 'disabled'."
            )


# ---------------------------------------------------------------------------
# EARS-3: ai_enabled=True but endpoint unreachable → graceful degradation
# ---------------------------------------------------------------------------


class TestUnreachableEndpointGracefulDegradation:
    """EARS-3: Unreachable endpoint → ai_status='unavailable', no error raised."""

    @pytest.mark.asyncio
    async def test_unreachable_endpoint_returns_unavailable_no_error(self) -> None:
        """OpenAIEngine.analyze_concise returns ai_status='unavailable' on connection error."""
        from firewatch_core.adapters.ai_openai import OpenAIEngine

        engine = OpenAIEngine(
            base_url="http://127.0.0.1:11434",
            model="llama3.2",
        )

        import httpx

        with patch.object(engine, "_call_endpoint", side_effect=httpx.ConnectError("refused")):
            result = await engine.analyze_concise(
                ip="192.0.2.1",
                total_events=10,
                blocked_events=8,
                rules_triggered=3,
                first_seen="2024-01-01T00:00:00Z",
                last_seen="2024-01-01T12:00:00Z",
                samples=[],
            )

        assert result.get("ai_status") == "unavailable", (
            f"Expected ai_status='unavailable', got {result.get('ai_status')!r} (EARS-3)."
        )
        # Method returned — no exception raised
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_openai_engine_graceful_degradation_is_additive_only(self) -> None:
        """Endpoint failure returns UNKNOWN threat_level, never de-escalates an existing score.

        ADR-0015: AI is additive-only. Fallback should not return a lower threat
        level than what rule+detection scoring would produce. The fallback threat_level
        is UNKNOWN (not a concrete LOW/MEDIUM/HIGH/CRITICAL) so callers can ignore
        it and keep their rules-only score — the pipeline treats ai_status='unavailable'
        as a no-op for scoring (additive-only, ADR-0015).
        """
        from firewatch_core.adapters.ai_openai import OpenAIEngine

        engine = OpenAIEngine(base_url="http://127.0.0.1:11434", model="llama3.2")

        import httpx

        with patch.object(engine, "_call_endpoint", side_effect=httpx.ConnectError("refused")):
            result = await engine.analyze_concise(
                ip="203.0.113.5",
                total_events=100,
                blocked_events=90,
                rules_triggered=10,
                first_seen="2024-01-01T00:00:00Z",
                last_seen="2024-01-01T12:00:00Z",
                samples=[],
            )

        # Fallback returns UNKNOWN — not a concrete threat level that could de-escalate
        assert result.get("threat_level") == "UNKNOWN", (
            "ADR-0015 additive-only: fallback threat_level must be 'UNKNOWN', "
            f"not a concrete level that could de-escalate. Got {result.get('threat_level')!r}."
        )
        assert result.get("ai_status") == "unavailable"


# ---------------------------------------------------------------------------
# EARS-4: No live LLM in CI; golden path deterministic with AI off
# ---------------------------------------------------------------------------


class TestNoLiveLLMRequired:
    """EARS-4: Demo/golden path must not require a running LLM."""

    def test_build_pipeline_ai_disabled_no_network_calls(self, tmp_path: Any) -> None:
        """_build_pipeline with ai_enabled=False makes no network calls on construction."""
        from firewatch_cli.commands._pipeline_factory import _build_pipeline

        with patch("firewatch_cli.commands._pipeline_factory.SQLiteEventStore") as mock_store, \
             patch("firewatch_cli.commands._pipeline_factory.Pipeline"), \
             patch("firewatch_cli.commands._pipeline_factory.JsonFileConfigStore") as mock_cfg_store, \
             patch("httpx.AsyncClient") as mock_http:
            mock_store.return_value = MagicMock()
            mock_cfg_store.return_value.get_runtime.return_value = MagicMock(
                ai_enabled=False,
                ollama_base_url="http://127.0.0.1:11434",
                ollama_model="llama3.2",
            )
            _build_pipeline(config_file=tmp_path / "fw.json")

            mock_http.assert_not_called()

    def test_firewatch_ai_enabled_env_var_honored_false(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        """FIREWATCH_AI_ENABLED=false is picked up via ConfigStore env layer."""
        # The env var is resolved via JsonFileConfigStore (config_store.py _runtime_env_var);
        # we test that the store correctly returns ai_enabled=False when set.
        from firewatch_core.config_store import JsonFileConfigStore

        monkeypatch.setenv("FIREWATCH_AI_ENABLED", "false")
        store = JsonFileConfigStore(config_file=tmp_path / "fw.json")
        cfg = store.get_runtime()
        assert cfg.ai_enabled is False, (
            "FIREWATCH_AI_ENABLED=false must set ai_enabled=False via env layer (EARS-4)."
        )

    def test_firewatch_ai_enabled_env_var_honored_true(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        """FIREWATCH_AI_ENABLED=true is picked up via ConfigStore env layer."""
        from firewatch_core.config_store import JsonFileConfigStore

        monkeypatch.setenv("FIREWATCH_AI_ENABLED", "true")
        store = JsonFileConfigStore(config_file=tmp_path / "fw.json")
        cfg = store.get_runtime()
        assert cfg.ai_enabled is True, (
            "FIREWATCH_AI_ENABLED=true must set ai_enabled=True via env layer (EARS-4)."
        )

    def test_ai_enabled_default_is_true(self) -> None:
        """RuntimeConfig.ai_enabled defaults to True (ai on by default, toggle to off)."""
        from firewatch_sdk.config import RuntimeConfig

        cfg = RuntimeConfig()
        assert cfg.ai_enabled is True, (
            "RuntimeConfig.ai_enabled must default to True (EARS-1 + issue #54 spec)."
        )

    def test_ai_enabled_field_exists_on_runtime_config(self) -> None:
        """RuntimeConfig has an ai_enabled field (issue #54 contract)."""
        from firewatch_sdk.config import RuntimeConfig

        assert "ai_enabled" in RuntimeConfig.model_fields, (
            "RuntimeConfig must have an 'ai_enabled' field (issue #54)."
        )

    def test_ai_enabled_env_lock_prevents_file_write(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        """While FIREWATCH_AI_ENABLED is set, set_runtime({'ai_enabled': ...}) is rejected."""
        from firewatch_core.config_store import JsonFileConfigStore

        monkeypatch.setenv("FIREWATCH_AI_ENABLED", "true")
        store = JsonFileConfigStore(config_file=tmp_path / "fw.json")
        with pytest.raises(ValueError, match="ai_enabled"):
            store.set_runtime({"ai_enabled": False})
