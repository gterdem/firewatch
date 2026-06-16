"""NL→FilterSpec engine — orchestrates vocab→prompt→LLM→validate (ADR-0049 / ML-6).

This is the single public entry point for the NL query pipeline.

``parse_nl_query(nl_text, base_url, model)`` is the main coroutine:
  1. Enumerates the vocabulary (EARS-4 — runtime, from store-queryable fields).
  2. Builds the system+user prompt (prompt.py).
  3. Calls the local OpenAI-compatible endpoint (zero-egress, EARS-5).
  4. Parses and validates the LLM response (validator.py — strict allowlist).
  5. Returns a ``NlQueryResult`` carrying the FilterSpec, provenance, and
     whether the result degraded to q= free-text (EARS-2).

Security invariants
-------------------
- The local-first guard (ADR-0022) is enforced at the top of ``parse_nl_query``
  via ``_validate_local_first``.  Any non-local ``base_url`` degrades to q=
  instead of making an outbound call — fail-closed (BLOCKING-1 / ADR-0022).
- The LLM response is treated as untrusted input; the validator applies the
  strict allowlist before constructing any FilterSpec.
- On any exception (timeout, malformed JSON, unreachable endpoint), the engine
  degrades to ``FilterSpec(q=nl_text)`` — fail-closed, never crashes the caller.
- The ``qwen3`` quirk (``response_format`` omission) is handled by the shared
  ``_use_response_format_json`` helper, mirroring ai_openai.py.

Module dependencies (no cycles)
--------------------------------
engine → prompt → vocabulary (leaf)
engine → validator → vocabulary (leaf)
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

import httpx

from firewatch_sdk.models import FilterSpec

from firewatch_core.adapters.ai_openai import LocalFirstViolation, _validate_local_first
from firewatch_core.nl_query.prompt import build_messages
from firewatch_core.nl_query.validator import validate_candidate
from firewatch_core.nl_query.vocabulary import FilterField, get_vocabulary

logger = logging.getLogger("firewatch.nl_query.engine")

# Timeout for the NL→FilterSpec LLM call (seconds).
# Short — this is an interactive, user-initiated call.
NL_QUERY_TIMEOUT: float = 30.0

# Provenance tags for the AI-generated FilterSpec (for the frontend chip).
PROVENANCE_AI: str = "ai"
PROVENANCE_DEGRADED: str = "ai_degraded"


@dataclass
class NlQueryResult:
    """Result of a NL→FilterSpec parse attempt.

    Attributes
    ----------
    filter_spec:
        The validated FilterSpec.  If ``degraded=True`` this is
        ``FilterSpec(q=nl_text)`` — a plain free-text fallback.
    degraded:
        True when the LLM parse was rejected (low confidence, OOV field, or
        endpoint error) and the result fell back to q= (EARS-2).
    provenance:
        ``"ai"`` when the FilterSpec comes from a validated LLM parse.
        ``"ai_degraded"`` when it degraded to q=.
    error:
        Short error description when something went wrong, for API consumers.
    """

    filter_spec: FilterSpec
    degraded: bool
    provenance: str
    error: str | None = field(default=None)


def _use_response_format_json(model: str) -> bool:
    """Return True if the model supports OpenAI ``response_format: json_object``.

    qwen3 quirk (ai-engine-invariants): Ollama's format:"json" makes qwen3
    return an empty ``{}``.  Omit ``response_format`` for qwen3 so the model
    can embed JSON in its thinking/response text, then extract it.
    Same logic as ``OpenAIEngine._use_response_format_json`` in ai_openai.py.
    """
    return "qwen3" not in model.lower()


def _extract_json_from_text(text: str) -> dict | None:
    """Find and parse the first complete JSON object in ``text``.

    Used for models (e.g. qwen3) that wrap their JSON answer in prose or
    reasoning text.  Scans for the outermost ``{...}`` brace pair.
    """
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _make_degraded(nl_text: str, error: str) -> NlQueryResult:
    """Return a degraded NlQueryResult with q= fallback."""
    return NlQueryResult(
        filter_spec=FilterSpec(q=nl_text),
        degraded=True,
        provenance=PROVENANCE_DEGRADED,
        error=error,
    )


async def parse_nl_query(
    nl_text: str,
    base_url: str = "http://127.0.0.1:11434",
    model: str = "llama3",
    vocab: list[FilterField] | None = None,
) -> NlQueryResult:
    """Parse a natural-language query into a validated FilterSpec.

    This is the single public entry point for the NL→FilterSpec pipeline.

    Parameters
    ----------
    nl_text:
        The analyst's natural-language query (e.g. "show me blocked TCP traffic
        from high severity sources").
    base_url:
        OpenAI-compatible local endpoint base URL (zero-egress, ADR-0022).
        Validated as local by the caller / OpenAIEngine.
    model:
        Model name to use.  Affects the ``response_format`` quirk handling.
    vocab:
        Vocabulary to embed in the prompt.  Defaults to ``get_vocabulary()``.

    Returns
    -------
    NlQueryResult
        Always returns a result — degrades to q= on any failure (EARS-2).
    """
    if vocab is None:
        vocab = get_vocabulary()

    # ADR-0022 local-first self-enforcement: validate base_url before any network I/O.
    # Any non-local host degrades to q= (fail-closed) — no outbound call is ever made.
    try:
        base_url = _validate_local_first(base_url)
    except LocalFirstViolation as exc:
        logger.warning(
            "nl_query.engine: base_url rejected by local-first guard (%s) — degrading to q=",
            exc,
        )
        return _make_degraded(nl_text, "base_url violates local-first invariant (ADR-0022)")

    messages = build_messages(nl_text, vocab)

    request_body: dict = {
        "model": model,
        "messages": messages,
        "stream": False,
        "temperature": 0.0,  # deterministic parse; low temp reduces hallucination
    }
    if _use_response_format_json(model):
        request_body["response_format"] = {"type": "json_object"}

    try:
        async with httpx.AsyncClient(timeout=NL_QUERY_TIMEOUT) as client:
            response = await client.post(
                f"{base_url}/v1/chat/completions",
                json=request_body,
            )
            response.raise_for_status()
            body: dict = response.json()
    except Exception as exc:
        logger.warning(
            "nl_query.engine: LLM call failed (%s) — degrading to q=",
            type(exc).__name__,
        )
        return _make_degraded(nl_text, f"LLM endpoint error: {type(exc).__name__}")

    # Extract the content string from the OpenAI-compatible response.
    try:
        content: str = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        logger.warning(
            "nl_query.engine: unexpected response shape (%s) — degrading",
            type(exc).__name__,
        )
        return _make_degraded(nl_text, "Malformed LLM response")

    # Parse JSON from the content.
    candidate: dict | None = None
    try:
        candidate = json.loads(content)
    except json.JSONDecodeError:
        # qwen3 / thinking-model: JSON may be wrapped in prose.
        candidate = _extract_json_from_text(content)

    if not isinstance(candidate, dict):
        logger.warning("nl_query.engine: could not extract JSON from response — degrading")
        return NlQueryResult(
            filter_spec=FilterSpec(q=nl_text),
            degraded=True,
            provenance=PROVENANCE_DEGRADED,
            error="LLM did not emit parseable JSON",
        )

    # Validate against vocabulary (strict allowlist — EARS-1, EARS-4).
    spec, degraded = validate_candidate(candidate, nl_text, vocab)

    # SHOULD-FIX-2: log the raw candidate at DEBUG level before discarding it.
    # The unvalidated dict is never returned to callers (not on the dataclass) to
    # prevent accidental serialisation in future log/route paths.
    logger.debug("nl_query.engine: raw_candidate=%r", candidate)

    return NlQueryResult(
        filter_spec=spec,
        degraded=degraded,
        provenance=PROVENANCE_DEGRADED if degraded else PROVENANCE_AI,
        error=None,
    )
