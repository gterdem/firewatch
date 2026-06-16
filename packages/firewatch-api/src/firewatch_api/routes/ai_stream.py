"""SSE stage-ticker route — GET /threats/{ip}/detailed/stream (MK-10, ADR-0046).

Streams validated pipeline stage facts as Server-Sent Events while the detailed
analysis runs, ending with a terminal ``result`` event carrying the same payload
as the non-streaming ``GET /threats/{ip}/detailed`` endpoint.

Security invariants (ADR-0046 D3 + NB-6):
- Only closed stage-fact dicts (from firewatch_core.ai.stage_events) are emitted
  before the terminal ``result`` event — never raw model text, exception strings,
  or attacker-sourced data.
- The ``result`` event carries the fully-validated, post-gauntlet payload, identical
  to the non-streaming endpoint.  No pre-validation content is ever serialised.
- Per-IP single-flight guard: a duplicate concurrent stream for the same IP returns
  409 (OWASP API4 resource exhaustion, ADR-0046 §6).
- Cancel-on-disconnect: when the client disconnects (AbortController / close),
  the SSE generator's cancellation propagates ``asyncio.CancelledError`` into the
  analysis task, closing the upstream httpx request and releasing the Ollama GPU slot
  (ADR-0046 §5).  ``stream: False`` to the upstream endpoint is UNCHANGED
  (ai-engine-invariants).
- Auth posture: class C (ADR-0026) — loopback-open by default, key-gated when
  the API is exposed beyond loopback.  No cookie/EventSource assumptions; the
  intended client uses ``fetch`` + ``Authorization`` header (ADR-0046 D2).

Wire format (WHATWG HTML §9.2 SSE):
  ``event: stage\\ndata: <json>\\n\\n`` for each stage fact.
  ``event: result\\ndata: <json>\\n\\n`` for the terminal result payload.
  ``event: error\\ndata: <json>\\n\\n`` when the IP has no events or a hard error.

Module layout (ADR-0046, issue #415):
  firewatch_core/ai/stage_events.py   -- types + emitter (firewatch-core)
  firewatch_core/pipeline.py          -- emit points in analyze_ip_detailed
  firewatch_api/routes/ai_stream.py   -- this file: SSE route
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, AsyncGenerator

from fastapi import APIRouter, HTTPException, Path
from fastapi.responses import StreamingResponse
from starlette.requests import Request

from firewatch_api.deps import get_pipeline
from firewatch_core.ai.stage_events import StageEmitter

logger = logging.getLogger("firewatch.api.ai_stream")

router = APIRouter(tags=["threats"])

# ---------------------------------------------------------------------------
# Per-IP single-flight guard (OWASP API4, ADR-0046 §6)
# ---------------------------------------------------------------------------
# Module-level set of IPs currently being streamed.  A duplicate concurrent
# request for the same IP returns 409.  The set is process-local — this is
# sufficient for the single-process deployment model (ADR-0023 §F).
_in_flight: set[str] = set()

# NB-1: reuse the same IP-validation regex pattern from threats.py.
_IP_REGEX = (
    r"^("
    r"(\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"[0-9a-fA-F:]+(%[a-zA-Z0-9._~-]+)?"
    r")$"
)

IpParam = Path(
    pattern=_IP_REGEX,
    description="IPv4 or IPv6 address of the threat actor.",
)


# ---------------------------------------------------------------------------
# SSE frame helpers
# ---------------------------------------------------------------------------


def _sse_frame(event: str, data: Any) -> str:
    """Format one SSE frame: ``event: <type>\\ndata: <json>\\n\\n``."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ---------------------------------------------------------------------------
# SSE generator
# ---------------------------------------------------------------------------


async def _stage_stream(
    ip: str,
    pipeline: Any,
) -> AsyncGenerator[str, None]:
    """Async generator that drives the analysis and yields SSE frames.

    Lifecycle:
    1. Build a StageEmitter backed by an asyncio.Queue.
    2. Launch ``pipeline.analyze_ip_detailed`` as a Task so it can be cancelled
       when the client disconnects.
    3. Drain the queue, yielding ``event: stage`` frames for each stage fact.
    4. Await the task to get the final result.
    5. Yield the terminal ``event: result`` frame.

    Cancel-on-disconnect (ADR-0046 §5):
    When the client disconnects, Starlette raises ``asyncio.CancelledError`` in
    this generator.  The ``finally`` block cancels the analysis task, which
    propagates ``CancelledError`` into the awaited engine call, closing the
    upstream httpx connection and releasing the Ollama GPU slot.

    Security: only stage-fact dicts from the closed vocabulary are yielded as
    ``stage`` events.  The terminal ``result`` event carries the fully-validated,
    post-gauntlet payload.  No raw model text is emitted at any point before
    ``result`` (ADR-0046 D3, ADR-0035).
    """
    queue: asyncio.Queue[Any] = asyncio.Queue()
    emitter = StageEmitter(queue)

    # Launch the analysis as a cancellable task.
    task: asyncio.Task[dict[str, Any]] = asyncio.ensure_future(
        pipeline.analyze_ip_detailed(ip, stage_sink=emitter)
    )

    try:
        # Drain stage events until the emitter pushes its sentinel.
        while True:
            # Use wait_for with a short poll so client disconnect is detected.
            try:
                item = await asyncio.wait_for(queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # No event in 30s — the task is likely stalled; continue waiting.
                continue

            if item is StageEmitter.sentinel:
                break
            # item is a stage-fact dict from the closed vocabulary.
            yield _sse_frame("stage", item)

        # Retrieve the final result (task must be done since sentinel was pushed).
        result = await task

        # Handle the empty-IP case.
        if "error" in result and len(result) == 1:
            yield _sse_frame("error", result)
            return

        yield _sse_frame("result", result)

    except asyncio.CancelledError:
        # Client disconnected — cancel the analysis task to free the GPU slot.
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        raise

    except Exception:
        logger.exception("ai_stream: unexpected error for ip=%s", ip)
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        yield _sse_frame("error", {"detail": "Internal stream error"})

    finally:
        # Belt-and-suspenders: cancel the task if it somehow outlived the loop.
        if not task.done():
            task.cancel()


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@router.get(
    "/threats/{ip}/detailed/stream",
    summary="SSE stream of validated pipeline stage facts for a detailed IP analysis",
    response_class=StreamingResponse,
)
async def stream_detailed(
    request: Request,
    ip: str = IpParam,
) -> StreamingResponse:
    """Stream pipeline stage facts as SSE while the detailed analysis runs.

    Returns ``text/event-stream``.  Each ``event: stage`` frame carries a
    validated stage-fact dict from the closed vocabulary (ADR-0046 D3).
    The terminal ``event: result`` carries the same payload as
    ``GET /threats/{ip}/detailed``.

    Duplicate concurrent stream for the same IP → **409**.
    No pipeline wired → **503**.
    Client disconnect → analysis task cancelled, GPU slot released (ADR-0046 §5).

    Auth: class C (ADR-0026) — loopback-open; key-gated when exposed.
    Intended client: ``fetch`` + ``AbortController`` + ``Authorization`` header
    (NOT ``EventSource``, which cannot send credentials — ADR-0046 D2).
    """
    pipeline = get_pipeline(request)
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not available")

    # Per-IP single-flight guard (OWASP API4, ADR-0046 §6).
    if ip in _in_flight:
        raise HTTPException(
            status_code=409,
            detail=f"A detailed stream for {ip} is already in progress",
        )

    _in_flight.add(ip)
    try:
        # Build the generator — it will run when Starlette iterates the response.
        gen = _stage_stream(ip, pipeline)

        # Wrap with in-flight cleanup: remove IP from the set when the stream ends.
        async def _guarded() -> AsyncGenerator[str, None]:
            try:
                async for chunk in gen:
                    yield chunk
            finally:
                _in_flight.discard(ip)

        return StreamingResponse(
            _guarded(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )
    except Exception:
        # If we fail before starting the stream, clean up the in-flight entry.
        _in_flight.discard(ip)
        raise
