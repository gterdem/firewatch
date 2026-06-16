"""AI routes — GET /ai/models (issue #135, ADR-0022) + GET /ai/engine (issue #409, ADR-0047).

Provides:
- ``GET /ai/models``  — model-list endpoint consumed by the Local AI panel.
- ``GET /ai/engine``  — zero-egress attestation DTO (ADR-0047 D3).

Design notes — /ai/models
--------------------------
- Queries ``GET {base_url}/v1/models`` — the OpenAI-compatible model-list path
  exposed by all supported local runtimes (Ollama, vLLM, llama.cpp, LM Studio).
  NOT the Ollama-native ``/api/tags`` (ADR-0022 supersedes ADR-0004).
- Local-first invariant: the ``base_url`` is validated at config-write time by
  ``RuntimeConfig._validate_ollama_base_url_local_first`` (SDK layer, ADR-0022).
  This route reads the already-validated value from the config store — no DNS
  re-resolution or re-validation needed here.
- Graceful degradation: any error (connection refused, timeout, non-200, JSON
  parse failure) returns ``{"models": [], "current": ..., "error": "..."}``
  with status 200 — never 500.  The frontend shows an empty dropdown and the
  error message inline.
- No secrets in response: only model IDs (strings) are included; base_url,
  webhook_url, api_key etc. are never serialised (ADR-0029 D3 / issue #135).

Design notes — /ai/engine (ADR-0047)
--------------------------------------
- Returns the attestation DTO assembled by ``attestation.build_attestation_dto``.
- ``endpoint_host`` is host:port only — never credentials (OWASP API8).
- ``endpoint_validated_local`` is derived from ``_is_local_host`` (ADR-0022 proof),
  not hardcoded: the claim is scoped to AI inference, not a blanket zero-egress
  assertion (ADR-0047 §2 wording rule; MI-8 claims discipline).
- ``analyses_count`` / ``last_analysis_at`` come from the MK-2 ledger (issue #407)
  when available; degrade to null honestly when the ledger is absent (pre-#407).
- Class-C route (ADR-0026): loopback-open by default, key-gated when exposed.

Imports only firewatch-sdk and firewatch-api internals. Never imports legacy/.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request

from firewatch_api.deps import get_config_store
from firewatch_api.routes.attestation import build_attestation_dto

logger = logging.getLogger("firewatch.api.ai")

router = APIRouter(tags=["ai"])

# Timeout (seconds) for the /v1/models request.  Short — this is a UI-blocking
# call triggered by the user opening the Local AI panel (issue #135).
_MODELS_TIMEOUT = 5.0


def _extract_model_ids(response_body: dict[str, Any]) -> list[str]:
    """Extract model id strings from an OpenAI /v1/models response body.

    OpenAI-compatible shape (https://platform.openai.com/docs/api-reference/models/list):
        {"data": [{"id": "model-name", ...}, ...], "object": "list"}

    Any entry missing an ``id`` key is silently skipped.  Extra keys on each
    model object are ignored — only ``id`` is projected into the result.
    """
    data = response_body.get("data", [])
    if not isinstance(data, list):
        return []
    return [item["id"] for item in data if isinstance(item, dict) and "id" in item]


@router.get(
    "/ai/models",
    summary="List locally available AI models",
)
async def get_ai_models(
    config_store: Any = Depends(get_config_store),
) -> dict[str, Any]:
    """Return model IDs from the configured OpenAI-compatible local endpoint.

    Queries ``GET {ollama_base_url}/v1/models`` and projects each entry to its
    ``id`` string.  The configured ``ollama_model`` is returned as ``current``
    (may differ from what the server lists if the operator changed it).

    Response shapes
    ---------------
    Success:
        ``{"models": ["id1", "id2", ...], "current": "configured-model"}``
    Error / unreachable:
        ``{"models": [], "current": "configured-model", "error": "<short message>"}``

    Status is always 200 — the caller (frontend) handles degraded state by
    showing an empty dropdown and an inline error label (issue #135).

    Security: only model ``id`` strings are included.  No base_url, webhook_url,
    api_key, or other runtime config fields are serialised (ADR-0029 D3).
    """
    # Resolve current config — fall back gracefully when no store is available.
    current_model: str | None = None
    base_url: str = "http://127.0.0.1:11434"

    if config_store is not None:
        try:
            runtime = config_store.get_runtime()
            current_model = runtime.ollama_model
            base_url = runtime.ollama_base_url
        except Exception:
            logger.warning("ai/models: failed to read runtime config", exc_info=True)

    # Query the OpenAI-compatible /v1/models endpoint.
    try:
        async with httpx.AsyncClient(timeout=_MODELS_TIMEOUT) as client:
            response = await client.get(f"{base_url}/v1/models")
            if response.status_code != 200:
                return {
                    "models": [],
                    "current": current_model,
                    "error": f"endpoint returned HTTP {response.status_code}",
                }
            body: dict[str, Any] = response.json()
            model_ids = _extract_model_ids(body)
            return {"models": model_ids, "current": current_model}
    except Exception as exc:
        # NB: never embed raw exception text — use type name only (no data leak).
        logger.warning("ai/models: failed to fetch model list: %s", type(exc).__name__)
        return {
            "models": [],
            "current": current_model,
            "error": "Local AI endpoint unreachable",
        }


@router.get(
    "/ai/engine",
    summary="Zero-egress attestation DTO for the local AI engine",
)
async def get_ai_engine(
    request: Request,
    config_store: Any = Depends(get_config_store),
) -> dict[str, Any]:
    """Return the zero-egress attestation DTO (ADR-0047 D3, issue #409).

    Every field is derived from an enforced source — never asserted:

    - ``model`` / ``runtime_profile`` / ``endpoint_host`` /
      ``endpoint_validated_local`` — from the validated ``RuntimeConfig``
      (SDK constructor guard, ADR-0022).
    - ``analyses_count`` / ``last_analysis_at`` — from the MK-2 ledger
      (issue #407) when it is wired in; ``null`` honestly otherwise.

    The ``endpoint_validated_local: true`` field is the machine-readable
    proof that the local-first constructor guard passed (ADR-0022).
    The "0 cloud AI calls" strip line is a UI concern derived from the same
    guard — it is not duplicated in this DTO (ADR-0047 derivation table row 4).

    Security:
    - ``endpoint_host`` is host:port only — no credentials (OWASP API8).
    - The claim is scoped to AI inference only; it is NOT a blanket product
      zero-egress claim (ADR-0047 §2; geo enrichment and webhooks are separate
      operator-visible egress paths with their own controls).

    Class-C route (ADR-0026): accessible on loopback without auth; key-gated
    when the API is exposed beyond loopback.

    Status is always 200 — the frontend strip handles the ``null`` counter
    fields by omitting those lines (ADR-0047).
    """
    # Read runtime config — fall back to defaults if config store is unavailable.
    runtime = None
    if config_store is not None:
        try:
            runtime = config_store.get_runtime()
        except Exception:
            logger.warning("ai/engine: failed to read runtime config", exc_info=True)

    if runtime is None:
        # Degrade gracefully: return a minimal DTO with safe defaults.
        # The endpoint_validated_local field is False (not provable without config).
        from firewatch_sdk import RuntimeConfig

        runtime = RuntimeConfig()

    # Resolve the optional MK-2 ledger (issue #407 — may not be wired yet).
    ledger: Any | None = getattr(request.app.state, "analysis_ledger", None)

    return build_attestation_dto(runtime, ledger=ledger)
