"""Tests for firewatch_core.ai.stage_events (MK-10, ADR-0046).

EARS criteria -> test mapping:

  S1 (closed vocab): fact_to_dict produces the exact ``stage`` string for every
       stage-fact type; no extra keys leak model text.
     -> test_prompt_built_dict_shape
     -> test_request_sent_dict_shape
     -> test_generating_dict_shape
     -> test_received_dict_shape_no_tokens
     -> test_received_dict_shape_with_tokens
     -> test_validated_dict_shape
     -> test_projected_dict_shape
     -> test_failed_dict_shape

  S2 (security -- no model text): none of the stage dicts in S1 contain
       attacker-influenced fields or raw exception strings.
     -> test_no_model_text_in_any_stage_dict  (parametrised over all fact types)

  S3 (emitter puts to queue): StageEmitter.emit() pushes fact_to_dict(fact) into
       the queue.
     -> test_emitter_puts_dict_to_queue

  S4 (emitter never raises): an exception raised inside the queue still keeps the
       emit from propagating.
     -> test_emitter_emit_never_raises_on_broken_queue

  S5 (close pushes sentinel): StageEmitter.close() pushes the sentinel object.
     -> test_emitter_close_pushes_sentinel

  S6 (sentinel is identity-unique): the sentinel is the same object across calls
       (used by SSE consumer via ``is`` comparison).
     -> test_sentinel_identity

All IPs and hostnames used below are RFC 5737 / loopback -- no real routable IPs.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from firewatch_core.ai.stage_events import (
    FailReason,
    FailedFact,
    GeneratingFact,
    ProjectedFact,
    PromptBuiltFact,
    ReceivedFact,
    RequestSentFact,
    StageName,
    StageEmitter,
    ValidatedFact,
    fact_to_dict,
)


# ---------------------------------------------------------------------------
# S1: fact_to_dict shape tests
# ---------------------------------------------------------------------------


def test_prompt_built_dict_shape() -> None:
    """S1: PromptBuiltFact -> {'stage': 'prompt_built', 'sample_count': N}."""
    d = fact_to_dict(PromptBuiltFact(sample_count=12))
    assert d["stage"] == StageName.PROMPT_BUILT
    assert d["sample_count"] == 12
    assert len(d) == 2, f"Unexpected extra keys: {set(d) - {'stage', 'sample_count'}}"


def test_request_sent_dict_shape() -> None:
    """S1: RequestSentFact -> {'stage': 'request_sent', 'model': ..., 'endpoint_host': ...}."""
    d = fact_to_dict(RequestSentFact(model="qwen3:8b", endpoint_host="127.0.0.1:11434"))
    assert d["stage"] == StageName.REQUEST_SENT
    assert d["model"] == "qwen3:8b"
    assert d["endpoint_host"] == "127.0.0.1:11434"
    assert len(d) == 3


def test_generating_dict_shape() -> None:
    """S1: GeneratingFact -> {'stage': 'generating', 'elapsed_ms': N}."""
    d = fact_to_dict(GeneratingFact(elapsed_ms=3500.0))
    assert d["stage"] == StageName.GENERATING
    assert d["elapsed_ms"] == pytest.approx(3500.0)
    assert len(d) == 2


def test_received_dict_shape_no_tokens() -> None:
    """S1: ReceivedFact without tokens -> no completion_tokens key."""
    d = fact_to_dict(ReceivedFact(latency_ms=9800.0, completion_tokens=None))
    assert d["stage"] == StageName.RECEIVED
    assert d["latency_ms"] == pytest.approx(9800.0)
    assert "completion_tokens" not in d
    assert len(d) == 2


def test_received_dict_shape_with_tokens() -> None:
    """S1: ReceivedFact with tokens -> completion_tokens present."""
    d = fact_to_dict(ReceivedFact(latency_ms=9800.0, completion_tokens=642))
    assert d["stage"] == StageName.RECEIVED
    assert d["completion_tokens"] == 642
    assert len(d) == 3


def test_validated_dict_shape() -> None:
    """S1: ValidatedFact -> {'stage': 'validated'} only -- no extra fields."""
    d = fact_to_dict(ValidatedFact())
    assert d["stage"] == StageName.VALIDATED
    assert len(d) == 1, f"Unexpected extra keys: {set(d) - {'stage'}}"


def test_projected_dict_shape() -> None:
    """S1: ProjectedFact -> {'stage': 'projected', 'field_count': N}."""
    d = fact_to_dict(ProjectedFact(field_count=7))
    assert d["stage"] == StageName.PROJECTED
    assert d["field_count"] == 7
    assert len(d) == 2


def test_failed_dict_shape() -> None:
    """S1: FailedFact -> {'stage': 'failed', 'at_stage': ..., 'reason_code': ...}."""
    d = fact_to_dict(
        FailedFact(at_stage=StageName.VALIDATED, reason_code=FailReason.VALIDATION_ERROR)
    )
    assert d["stage"] == StageName.FAILED
    assert d["at_stage"] == StageName.VALIDATED
    assert d["reason_code"] == FailReason.VALIDATION_ERROR
    assert len(d) == 3


# ---------------------------------------------------------------------------
# S2: security -- no model text in any stage dict (parametrised)
# ---------------------------------------------------------------------------

_ALL_FACTS = [
    PromptBuiltFact(sample_count=5),
    RequestSentFact(model="llama3.2", endpoint_host="127.0.0.1:11434"),
    GeneratingFact(elapsed_ms=1000.0),
    ReceivedFact(latency_ms=5000.0, completion_tokens=300),
    ReceivedFact(latency_ms=5000.0, completion_tokens=None),
    ValidatedFact(),
    ProjectedFact(field_count=4),
    FailedFact(at_stage=StageName.VALIDATED, reason_code=FailReason.VALIDATION_ERROR),
    FailedFact(at_stage=StageName.REQUEST_SENT, reason_code=FailReason.ENGINE_ERROR),
    FailedFact(at_stage=StageName.REQUEST_SENT, reason_code=FailReason.TIMEOUT),
]

_MODEL_TEXT_KEYS = {
    "insights", "executive_summary", "attack_progression",
    "ioc_indicators", "intent", "threat_level",
}


@pytest.mark.parametrize("fact", _ALL_FACTS)
def test_no_model_text_in_any_stage_dict(fact: Any) -> None:
    """S2: no stage dict carries keys that could contain attacker/model text."""
    d = fact_to_dict(fact)
    leaked = set(d.keys()) & _MODEL_TEXT_KEYS
    assert not leaked, (
        f"Stage dict for {type(fact).__name__} contains model-text keys: {leaked}"
    )


# ---------------------------------------------------------------------------
# S3: emitter puts to queue
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emitter_puts_dict_to_queue() -> None:
    """S3: emit() places fact_to_dict(fact) into the queue."""
    q: asyncio.Queue[Any] = asyncio.Queue()
    emitter = StageEmitter(q)
    fact = PromptBuiltFact(sample_count=8)
    await emitter.emit(fact)

    assert not q.empty()
    item = q.get_nowait()
    assert item == fact_to_dict(fact)


# ---------------------------------------------------------------------------
# S4: emitter never raises on a broken queue
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emitter_emit_never_raises_on_broken_queue() -> None:
    """S4: emit() swallows any exception -- analysis path must never abort."""

    class BrokenQueue:
        async def put(self, item: Any) -> None:
            raise RuntimeError("queue is broken")

    emitter = StageEmitter(BrokenQueue())  # type: ignore[arg-type]
    # Should not raise:
    await emitter.emit(ValidatedFact())


# ---------------------------------------------------------------------------
# S5: close() pushes sentinel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emitter_close_pushes_sentinel() -> None:
    """S5: close() places exactly the sentinel object into the queue."""
    q: asyncio.Queue[Any] = asyncio.Queue()
    emitter = StageEmitter(q)
    await emitter.close()

    assert not q.empty()
    item = q.get_nowait()
    assert item is StageEmitter.sentinel


# ---------------------------------------------------------------------------
# S6: sentinel identity
# ---------------------------------------------------------------------------


def test_sentinel_identity() -> None:
    """S6: StageEmitter.sentinel is the same object across all accesses."""
    s1 = StageEmitter.sentinel
    s2 = StageEmitter.sentinel
    assert s1 is s2
    # It must NOT be a stage dict (no 'stage' key)
    assert not isinstance(s1, dict)
