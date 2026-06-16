"""Tests for Pipeline.analyze_ip_detailed with stage_sink (MK-10, ADR-0046).

EARS criteria -> test mapping:

  P1 (stage sequence -- success path): when stage_sink is provided and AI succeeds,
       the emitted sequence is:
       prompt_built -> request_sent -> [generating...] -> received -> validated -> projected
       followed by the sentinel.
     -> test_stage_sequence_success_path

  P2 (no model text in stages): no stage dict contains attacker/model text keys.
     -> test_no_model_text_in_emitted_stages

  P3 (failure path -- engine error): when the AI call raises, the stream emits
       failed{stage='request_sent', reason_code='engine_error'} then closes.
     -> test_stage_failure_on_engine_error

  P4 (failure path -- validation error): when the engine returns a fallback
       envelope (ai_status='unavailable'), emits failed{stage='validated', reason_code=...}
     -> test_stage_failure_on_unavailable_result

  P5 (no-op when sink is None): analyze_ip_detailed with stage_sink=None completes
       without error and returns the same result as without stage_sink.
     -> test_stage_sink_none_is_noop

  P6 (non-streaming path unchanged): the existing non-streaming path (no stage_sink)
       produces identical results -- ai-engine-invariants preserved.
     -> test_non_streaming_path_unchanged

  P7 (engine-unavailable path): when is_available() returns False,
       emits failed{reason_code='engine_unavailable'} then closes.
     -> test_stage_failure_engine_unavailable

  P8 (prompt_built carries sample_count > 0 when events exist):
     -> test_prompt_built_sample_count_nonzero

All IPs use RFC 5737 documentation ranges (192.0.2.0/24, 203.0.113.0/24).
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from firewatch_core.ai.stage_events import (
    FailReason,
    StageName,
    StageEmitter,
)
from firewatch_core.pipeline import Pipeline
from _fakes import FakeAIEngine, FakeStore, make_event

IP = "203.0.113.10"
IP_B = "192.0.2.55"

# A valid detailed AI result (matches the closed schema)
_VALID_DETAILED: dict[str, Any] = {
    "threat_level": "HIGH",
    "confidence": 0.85,
    "executive_summary": "SQL injection from scanner.",
    "intent": "Data exfiltration",
    "attack_stage": "exploitation",
    "attack_progression": ["Step 1: scan", "Step 2: exploit"],
    "insights": {"patterns": ["SQLi"], "risks": ["breach"], "mitigations": ["WAF"]},
    "ioc_indicators": ["942100"],
    "recommended_action": "block",
    "false_positive_likelihood": 0.05,
    "ai_status": "ok",
}


def _events(n: int = 3) -> list:
    return [
        make_event(
            source_ip=IP,
            action="BLOCK",
            rule_id="942100",
            payload_snippet="' OR '1'='1",
        )
        for _ in range(n)
    ]


async def _drain(q: asyncio.Queue[Any]) -> list[Any]:
    """Drain all items from queue until sentinel, return stage dicts."""
    items = []
    while True:
        item = await asyncio.wait_for(q.get(), timeout=5.0)
        if item is StageEmitter.sentinel:
            break
        items.append(item)
    return items


# ---------------------------------------------------------------------------
# P1: stage sequence on success path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stage_sequence_success_path() -> None:
    """P1: success path emits stages in order: prompt_built, request_sent,
    [generating*], received, validated, projected; then sentinel."""
    store = FakeStore(_events())
    fake_ai = FakeAIEngine(result=_VALID_DETAILED)
    pipeline = Pipeline(store, fake_ai)

    q: asyncio.Queue[Any] = asyncio.Queue()
    emitter = StageEmitter(q)
    await pipeline.analyze_ip_detailed(IP, stage_sink=emitter)

    stages = await _drain(q)

    # Must have at least: prompt_built, request_sent, received, validated, projected
    stage_names = [s["stage"] for s in stages]
    assert stage_names[0] == StageName.PROMPT_BUILT, f"First stage: {stage_names}"

    # request_sent must follow prompt_built
    assert StageName.REQUEST_SENT in stage_names, f"Missing request_sent in {stage_names}"
    rs_idx = stage_names.index(StageName.REQUEST_SENT)
    assert rs_idx > 0, "request_sent must come after prompt_built"

    # received must follow request_sent
    assert StageName.RECEIVED in stage_names, f"Missing received in {stage_names}"
    recv_idx = stage_names.index(StageName.RECEIVED)
    assert recv_idx > rs_idx, "received must come after request_sent"

    # validated must follow received
    assert StageName.VALIDATED in stage_names, f"Missing validated in {stage_names}"
    val_idx = stage_names.index(StageName.VALIDATED)
    assert val_idx > recv_idx, "validated must come after received"

    # projected must be last (before sentinel)
    assert StageName.PROJECTED in stage_names, f"Missing projected in {stage_names}"
    proj_idx = stage_names.index(StageName.PROJECTED)
    assert proj_idx == len(stage_names) - 1, "projected must be the last stage"

    # No failed stages on success path
    assert StageName.FAILED not in stage_names, f"Unexpected failed stage in {stage_names}"


# ---------------------------------------------------------------------------
# P2: no model text in emitted stages
# ---------------------------------------------------------------------------

_MODEL_TEXT_KEYS = {
    "insights", "executive_summary", "attack_progression",
    "ioc_indicators", "intent", "threat_level",
}


@pytest.mark.asyncio
async def test_no_model_text_in_emitted_stages() -> None:
    """P2: no stage dict contains keys that could carry attacker/model text."""
    store = FakeStore(_events())
    fake_ai = FakeAIEngine(result=_VALID_DETAILED)
    pipeline = Pipeline(store, fake_ai)

    q: asyncio.Queue[Any] = asyncio.Queue()
    emitter = StageEmitter(q)
    await pipeline.analyze_ip_detailed(IP, stage_sink=emitter)
    stages = await _drain(q)

    for stage in stages:
        leaked = set(stage.keys()) & _MODEL_TEXT_KEYS
        assert not leaked, (
            f"Stage dict {stage['stage']!r} contains model-text keys: {leaked}"
        )


# ---------------------------------------------------------------------------
# P3: failure path -- engine error (raises exception)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stage_failure_on_engine_error() -> None:
    """P3: when is_available()=True but the AI call raises, emits failed{engine_error}."""
    store = FakeStore(_events())

    # Engine is "available" but the actual analyze_detailed call raises.
    class _AvailableButRaisesEngine:
        async def is_available(self) -> bool:
            return True

        async def analyze_detailed(self, **_: Any) -> dict[str, Any]:
            raise RuntimeError("simulated LLM transport error")

    pipeline = Pipeline(store, _AvailableButRaisesEngine())  # type: ignore[arg-type]

    q: asyncio.Queue[Any] = asyncio.Queue()
    emitter = StageEmitter(q)
    await pipeline.analyze_ip_detailed(IP, stage_sink=emitter)
    stages = await _drain(q)

    stage_names = [s["stage"] for s in stages]
    assert StageName.FAILED in stage_names, f"Expected failed stage, got: {stage_names}"

    failed = next(s for s in stages if s["stage"] == StageName.FAILED)
    assert failed["reason_code"] == FailReason.ENGINE_ERROR, (
        f"Expected engine_error, got: {failed['reason_code']}"
    )
    # No validated or projected on failure path
    assert StageName.VALIDATED not in stage_names
    assert StageName.PROJECTED not in stage_names


# ---------------------------------------------------------------------------
# P4: failure path -- fallback envelope (ai_status=unavailable)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stage_failure_on_unavailable_result() -> None:
    """P4: when engine returns fallback (ai_status=unavailable), emits failed{validation}."""
    # The FakeAIEngine fallback result signals unavailable
    from firewatch_core.adapters.ai_openai import _detailed_fallback

    store = FakeStore(_events())
    fake_ai = FakeAIEngine(result=_detailed_fallback())
    pipeline = Pipeline(store, fake_ai)

    q: asyncio.Queue[Any] = asyncio.Queue()
    emitter = StageEmitter(q)
    await pipeline.analyze_ip_detailed(IP, stage_sink=emitter)
    stages = await _drain(q)

    stage_names = [s["stage"] for s in stages]
    # The pipeline branches on ai_status='unavailable' -> emits failed
    assert StageName.FAILED in stage_names, f"Expected failed stage, got: {stage_names}"
    failed = next(s for s in stages if s["stage"] == StageName.FAILED)
    assert failed["at_stage"] == StageName.VALIDATED
    assert StageName.PROJECTED not in stage_names


# ---------------------------------------------------------------------------
# P5: stage_sink=None is no-op
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stage_sink_none_is_noop() -> None:
    """P5: analyze_ip_detailed with stage_sink=None returns same result as without."""
    store = FakeStore(_events())
    fake_ai = FakeAIEngine(result=_VALID_DETAILED)
    pipeline = Pipeline(store, fake_ai)

    # Without stage_sink
    result_a = await pipeline.analyze_ip_detailed(IP)
    # With stage_sink=None (explicit)
    result_b = await pipeline.analyze_ip_detailed(IP, stage_sink=None)

    assert result_a["score"] == result_b["score"]
    assert result_a["threat_level"] == result_b["threat_level"]
    assert result_a["ai_status"] == result_b["ai_status"]


# ---------------------------------------------------------------------------
# P6: non-streaming path unchanged (ai-engine-invariants)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_streaming_path_unchanged() -> None:
    """P6: adding stage_sink does not change score or result shape."""
    store_a = FakeStore(_events())
    store_b = FakeStore(_events())
    fake_ai_a = FakeAIEngine(result=_VALID_DETAILED)
    fake_ai_b = FakeAIEngine(result=_VALID_DETAILED)

    result_no_sink = await Pipeline(store_a, fake_ai_a).analyze_ip_detailed(IP)

    q: asyncio.Queue[Any] = asyncio.Queue()
    emitter = StageEmitter(q)
    result_with_sink = await Pipeline(store_b, fake_ai_b).analyze_ip_detailed(
        IP, stage_sink=emitter
    )
    await _drain(q)

    # Core result shape must match
    assert result_no_sink["score"] == result_with_sink["score"]
    assert result_no_sink["threat_level"] == result_with_sink["threat_level"]
    assert result_no_sink["ai_status"] == result_with_sink["ai_status"]
    assert fake_ai_a.detailed_calls == fake_ai_b.detailed_calls == 1


# ---------------------------------------------------------------------------
# P7: engine unavailable -> failed{engine_unavailable}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stage_failure_engine_unavailable() -> None:
    """P7: when is_available() returns False, emits failed{engine_unavailable}."""
    store = FakeStore(_events())
    # fail=True makes is_available() return False AND raises on analyze_*
    # We only need is_available() to return False -- use a custom fake
    class _UnavailableEngine:
        async def is_available(self) -> bool:
            return False

        async def analyze_detailed(self, **_: Any) -> dict[str, Any]:
            raise AssertionError("should not be called when unavailable")

    pipeline = Pipeline(store, _UnavailableEngine())  # type: ignore[arg-type]

    q: asyncio.Queue[Any] = asyncio.Queue()
    emitter = StageEmitter(q)
    await pipeline.analyze_ip_detailed(IP, stage_sink=emitter)
    stages = await _drain(q)

    stage_names = [s["stage"] for s in stages]
    assert StageName.FAILED in stage_names, f"Expected failed stage, got: {stage_names}"
    failed = next(s for s in stages if s["stage"] == StageName.FAILED)
    assert failed["reason_code"] == FailReason.ENGINE_UNAVAILABLE


# ---------------------------------------------------------------------------
# P8: prompt_built carries sample_count > 0 when events exist
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_prompt_built_sample_count_nonzero() -> None:
    """P8: when events exist, prompt_built.sample_count > 0."""
    store = FakeStore(_events(n=5))
    fake_ai = FakeAIEngine(result=_VALID_DETAILED)
    pipeline = Pipeline(store, fake_ai)

    q: asyncio.Queue[Any] = asyncio.Queue()
    emitter = StageEmitter(q)
    await pipeline.analyze_ip_detailed(IP, stage_sink=emitter)
    stages = await _drain(q)

    prompt_built = next(
        (s for s in stages if s["stage"] == StageName.PROMPT_BUILT), None
    )
    assert prompt_built is not None
    assert prompt_built["sample_count"] > 0
