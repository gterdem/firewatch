"""Pipeline stage-ticker: typed stage-fact dataclasses, closed enum, and async emitter seam.

ADR-0046: the SSE stage-ticker streams *facts about the validation gauntlet* — each
one true and already determined when emitted.  NO model-authored text ever appears in a
stage event; prose arrives only in the terminal ``result`` event, after the full gauntlet.

Security invariants (ADR-0046 D3, NB-6):
- Every field in a stage dataclass is either a fixed enum member, a numeric measurement
  (latency, token count, elapsed time), or a host:port string derived from the validated
  engine config — never raw model text, exception messages, or attacker-supplied data.
- The ``failed`` stage carries a fixed ``reason_code`` from the closed ``FailReason``
  enum — never a raw exception string (NB-6 discipline).
- The emitter seam is optional (``None`` → no-op); the non-streaming path pays nothing.

Module layout (ADR-0046, issue #415):
  firewatch_core/ai/stage_events.py   <- this file: types + emitter
  firewatch_core/pipeline.py          <- emit points wired into analyze_ip_detailed
  firewatch_api/routes/ai_stream.py   <- SSE route: queue->frames, disconnect->cancel
"""
from __future__ import annotations

import asyncio
from typing import Any


# ---------------------------------------------------------------------------
# Closed stage vocabulary (ADR-0046 D3)
# ---------------------------------------------------------------------------


class StageName:
    """Closed set of pipeline stage-name constants.

    Wire-stable string values: they appear in SSE frames consumed by the UI.
    Rename only with a versioned migration.
    """

    PROMPT_BUILT = "prompt_built"
    REQUEST_SENT = "request_sent"
    GENERATING = "generating"
    RECEIVED = "received"
    VALIDATED = "validated"
    PROJECTED = "projected"
    FAILED = "failed"


class FailReason:
    """Closed set of failure reason codes (NB-6: fixed constants, no raw exception text).

    VALIDATION_ERROR   -- closed-schema validation failed (bad JSON or invalid field).
    ENGINE_ERROR       -- upstream httpx / transport error reaching the local engine.
    ENGINE_UNAVAILABLE -- is_available() returned False before the call was attempted.
    TIMEOUT            -- request exceeded the engine timeout.
    CANCELLED          -- client disconnected; analysis task was cancelled.
    """

    VALIDATION_ERROR = "validation_error"
    ENGINE_ERROR = "engine_error"
    ENGINE_UNAVAILABLE = "engine_unavailable"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Stage-fact dataclasses (immutable value objects)
# ---------------------------------------------------------------------------


class PromptBuiltFact:
    """Emitted once the prompt is assembled and the sample count is known."""

    __slots__ = ("sample_count",)

    def __init__(self, sample_count: int) -> None:
        self.sample_count = sample_count


class RequestSentFact:
    """Emitted when the HTTP POST is dispatched to the engine.

    ``model`` is the model name from engine config (never model output).
    ``endpoint_host`` is host:port only -- no credentials (OWASP API8).
    """

    __slots__ = ("model", "endpoint_host")

    def __init__(self, model: str, endpoint_host: str) -> None:
        self.model = model
        self.endpoint_host = endpoint_host


class GeneratingFact:
    """Heartbeat emitted periodically while generation is in progress.

    ``elapsed_ms`` is wall-clock time since the POST was sent -- the only
    information in this frame.  Token counts appear in ``ReceivedFact``
    from the ``usage`` block (ADR-0046 D4).
    """

    __slots__ = ("elapsed_ms",)

    def __init__(self, elapsed_ms: float) -> None:
        self.elapsed_ms = elapsed_ms


class ReceivedFact:
    """Emitted when the full response is received.

    ``completion_tokens`` is present only when the endpoint returns a ``usage``
    block; it is NEVER fabricated (ADR-0044 §2).
    """

    __slots__ = ("latency_ms", "completion_tokens")

    def __init__(self, latency_ms: float, completion_tokens: int | None = None) -> None:
        self.latency_ms = latency_ms
        self.completion_tokens = completion_tokens


class ValidatedFact:
    """Emitted when closed-schema validation passes."""

    __slots__ = ()


class ProjectedFact:
    """Emitted when allowlist projection is complete."""

    __slots__ = ("field_count",)

    def __init__(self, field_count: int) -> None:
        self.field_count = field_count


class FailedFact:
    """Emitted when any stage fails.

    ``at_stage`` names the stage that failed (a StageName constant).
    ``reason_code`` is a fixed FailReason constant -- never raw exception text (NB-6).
    """

    __slots__ = ("at_stage", "reason_code")

    def __init__(self, at_stage: str, reason_code: str) -> None:
        self.at_stage = at_stage
        self.reason_code = reason_code


# ---------------------------------------------------------------------------
# Serialisation helper (fact -> SSE-ready dict)
# ---------------------------------------------------------------------------


def fact_to_dict(fact: Any) -> dict[str, Any]:
    """Serialise a stage-fact object to a wire-ready dict.

    The ``stage`` key carries the StageName constant value (wire-stable).
    All other fields are included as-is.  This is the only place that translates
    the closed Python types into the JSON-serialisable SSE payload.

    Security: no model text, no exception strings, no attacker-sourced data --
    only fixed constant values and numeric measurements enter the output dict.
    """
    if isinstance(fact, PromptBuiltFact):
        return {"stage": StageName.PROMPT_BUILT, "sample_count": fact.sample_count}
    if isinstance(fact, RequestSentFact):
        return {
            "stage": StageName.REQUEST_SENT,
            "model": fact.model,
            "endpoint_host": fact.endpoint_host,
        }
    if isinstance(fact, GeneratingFact):
        return {"stage": StageName.GENERATING, "elapsed_ms": fact.elapsed_ms}
    if isinstance(fact, ReceivedFact):
        d: dict[str, Any] = {
            "stage": StageName.RECEIVED,
            "latency_ms": fact.latency_ms,
        }
        if fact.completion_tokens is not None:
            d["completion_tokens"] = fact.completion_tokens
        return d
    if isinstance(fact, ValidatedFact):
        return {"stage": StageName.VALIDATED}
    if isinstance(fact, ProjectedFact):
        return {"stage": StageName.PROJECTED, "field_count": fact.field_count}
    if isinstance(fact, FailedFact):
        return {
            "stage": StageName.FAILED,
            "at_stage": fact.at_stage,
            "reason_code": fact.reason_code,
        }
    # Fallback: should not be reached with correct usage
    return {"stage": StageName.FAILED, "reason_code": FailReason.ENGINE_ERROR}


# ---------------------------------------------------------------------------
# Emitter seam
# ---------------------------------------------------------------------------


class StageEmitter:
    """Async emitter that puts stage-fact dicts into an asyncio Queue.

    The pipeline calls ``emit()`` at each checkpoint; the SSE route drains
    the queue and forwards frames to the client.

    The non-streaming path (``stage_sink=None`` in the pipeline) never
    instantiates this class -- the cost is a ``None`` check per emit point.

    A class-level ``sentinel`` object is pushed by ``close()`` to signal
    end-of-stream.  The SSE route detects it by identity comparison.
    """

    # Class-level sentinel: unique object, identified by ``is`` comparison.
    sentinel: object = object()

    def __init__(self, queue: "asyncio.Queue[Any]") -> None:
        self._queue = queue

    async def emit(self, fact: Any) -> None:
        """Put ``fact_to_dict(fact)`` into the queue.  Never raises."""
        try:
            await self._queue.put(fact_to_dict(fact))
        except Exception:
            # Never let an emitter failure abort the analysis path.
            pass

    async def close(self) -> None:
        """Signal end-of-stream by pushing the sentinel."""
        try:
            await self._queue.put(StageEmitter.sentinel)
        except Exception:
            pass
