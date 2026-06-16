"""NL→FilterSpec query route — POST /logs/nl-query (ML-6 / ADR-0049 / issue #434).

Parses a natural-language query into a validated FilterSpec using the local LLM
(zero-egress, EARS-5).  The response carries the FilterSpec, provenance tag, and
a degraded flag so the frontend can render an AI provenance chip (EARS-3).

Security boundary (ADR-0049 §No free SQL / OWASP LLM01)
---------------------------------------------------------
- The LLM output is treated as UNTRUSTED input.  ``parse_nl_query`` applies the
  strict allowlist validator before building any FilterSpec (EARS-1).
- OOV fields or low-confidence parses degrade to ``FilterSpec(q=nl_text)`` —
  never a fabricated filter (EARS-2).
- The local-model base_url is read from the config store; the zero-egress
  local-first invariant is enforced by RuntimeConfig's constructor guard (ADR-0022).
- The request body carries ``query`` (the analyst's NL string) and optionally the
  model name.  No SQL or code is accepted or emitted — the LLM response is a
  structured FilterSpec only.

Response schema
---------------
Success (200):
    {
        "filter_spec": { <FilterSpec field dict — only non-None fields> },
        "degraded":     bool,
        "provenance":   "ai" | "ai_degraded",
        "error":        str | null
    }
``degraded=true`` means the parse fell back to ``filter_spec.q = <nl_text>``
(plain free-text search, identical to the analyst typing it manually).

503 — when no config_store is available (base_url cannot be resolved).
422 — when the request body is malformed (Pydantic validation).
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from firewatch_core.nl_query.engine import parse_nl_query

from firewatch_api.deps import get_config_store

logger = logging.getLogger("firewatch.api.nl_query")

router = APIRouter(tags=["logs"])


class NlQueryRequest(BaseModel):
    """Request body for POST /logs/nl-query.

    Attributes
    ----------
    query:
        The analyst's natural-language query string (1–500 chars).
        Truncated to 500 chars by the engine before embedding.
    model:
        Optional override for the local-model name.
        Defaults to the configured ``ollama_model`` from the config store.
    """

    query: str = Field(min_length=1, max_length=500)
    model: str | None = Field(default=None, max_length=200)


@router.post(
    "/logs/nl-query",
    summary=(
        "Parse a natural-language query into a validated FilterSpec "
        "(ML-6 / ADR-0049, zero-egress, local model only)"
    ),
)
async def post_nl_query(
    body: NlQueryRequest,
    config_store: Any = Depends(get_config_store),
) -> dict[str, Any]:
    """Parse a natural-language query into a validated FilterSpec.

    SECURITY (ADR-0049 / OWASP LLM01)
    ------------------------------------
    - The local-LLM base_url is read from RuntimeConfig (ADR-0022 local-first guard).
    - LLM output is validated against the runtime vocabulary strict allowlist before
      any FilterSpec is built (EARS-1 / ADR-0049 Decision 2).
    - OOV / low-confidence → degrade to ``q=`` free-text (EARS-2).
    - No query content leaves the host (zero-egress, EARS-5).

    Response
    ---------
    ``{ filter_spec, degraded, provenance, error }``

    Returns 200 always — degradation is a data-level concern, not an HTTP error,
    because the response is still a valid (fallback) FilterSpec.

    Returns 503 when the config store is unavailable (base_url cannot be resolved).
    """
    # Resolve base_url and model from the config store.
    base_url: str = "http://127.0.0.1:11434"
    configured_model: str = "llama3"

    if config_store is None:
        raise HTTPException(
            status_code=503,
            detail="Config store not available — cannot resolve local LLM endpoint.",
        )

    try:
        runtime = config_store.get_runtime()
        base_url = runtime.ollama_base_url
        configured_model = runtime.ollama_model or configured_model
    except Exception:
        logger.warning("nl_query: failed to read runtime config; using defaults", exc_info=True)

    # Body model override takes precedence over config.
    model = body.model or configured_model

    result = await parse_nl_query(
        nl_text=body.query,
        base_url=base_url,
        model=model,
    )

    # Serialize FilterSpec — only non-None fields.
    # The frontend iterates this dict to build editable filter chips (EARS-3).
    filter_dict = {
        k: v
        for k, v in result.filter_spec.model_dump().items()
        if v is not None
    }

    return {
        "filter_spec": filter_dict,
        "degraded": result.degraded,
        "provenance": result.provenance,
        "error": result.error,
    }
