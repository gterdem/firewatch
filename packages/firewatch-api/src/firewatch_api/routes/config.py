"""Config HTTP routes for GET/PUT /config/sources/{type_key} and GET/PUT /config/runtime.

Thin controllers over the ``ConfigStore`` port (MA.3b, issue #45).

As of MB.1 this module also exposes a ``router`` (``APIRouter``) so ``create_app``
can include it directly.  The helper functions below are preserved unchanged so
the existing tests that call them directly continue to pass.

Design notes
------------
- Source-agnostic: the ``type_key`` path parameter is validated against the
  injected plugin registry; no route hardcodes a source type (EARS ubiquitous).
- SecretStr fields are never echoed on GET: ``_mask_secrets`` replaces them with
  ``None`` before serialisation (EARS ubiquitous; ADR-0006; PLUGIN_CONTRACT.md).
- Validated PUT: updates pass through ``ConfigStore.set_source`` / ``set_runtime``,
  which validates against the plugin schema and rejects env-locked fields before
  persisting (EARS event-driven + unwanted; ADR-0006).
- ``pydantic.ValidationError`` → 422 Unprocessable Entity.
  Two keys are stripped from each Pydantic error dict before returning the response:
  1. ``"input"``: Pydantic v2 echoes the full submitted input dict in ``"input"``
     for ``missing``-type errors, which can reflect a client-supplied secret back
     in the 422 body (ADR-0006; PR #46). Stripped to prevent that latent secret-echo.
  2. ``"ctx"``: For ``value_error``-type errors (e.g. the ADR-0022 local-first URL
     validator), Pydantic includes ``{'error': ValueError(...)}`` in ``"ctx"``.
     A live ``ValueError`` object is NOT JSON-serializable; FastAPI converts the
     serialization ``TypeError`` into a 500 response (issue #527 root cause).
     Stripping ``"ctx"`` fixes the 500 → 422 regression. The human-readable message
     is always present in ``"msg"``, so no information is lost.
- ``ValueError`` (env-lock, reserved key) → 400 Bad Request.
- Unknown ``type_key`` → 404 Not Found.

ADR-0026 auth seam:
  These are route class A (config-mutating) per ADR-0026. For MA they are served
  loopback-only with no app auth (ADR-0026 Decision 1). When the API is exposed
  beyond loopback (MB+), the auth middleware in ``firewatch_api.middleware`` will
  gate all class-A routes — that seam is documented in ``app.py``; it is not wired
  here.

Imports only ``firewatch-sdk`` and ``firewatch-core`` (via the ConfigStore port).
Never imports a concrete plugin or legacy/.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, SecretStr, ValidationError

from firewatch_api.deps import get_config_store, get_registry

logger = logging.getLogger("firewatch.api.config")

# ---------------------------------------------------------------------------
# Pydantic error sanitization (preserved for direct use by tests and the router)
# ---------------------------------------------------------------------------


def _sanitize_validation_errors(exc: ValidationError) -> list[dict[str, Any]]:
    """Convert a Pydantic ValidationError into a JSON-safe list of error dicts.

    Strips two keys from each Pydantic v2 error dict:

    ``"input"``
        Echoes the full submitted value (potential secret-echo risk).
        Stripped since PR #46 (ADR-0006).

    ``"ctx"``
        For ``value_error``-type errors the SDK's field validators (e.g. the
        ADR-0022 ``ollama_base_url`` local-first check) populate ``ctx`` with
        ``{'error': ValueError(...)}``.  A live ``ValueError`` object is NOT
        JSON-serializable; without stripping this, FastAPI raises a ``TypeError``
        during response serialization and returns HTTP 500 instead of 422
        (issue #527 root cause).  The human-readable message is always present
        in ``"msg"`` — stripping ``"ctx"`` loses no user-visible information.
    """
    _STRIP = frozenset({"input", "ctx"})
    return [{k: v for k, v in e.items() if k not in _STRIP} for e in exc.errors()]


# ---------------------------------------------------------------------------
# Secret masking helpers (preserved for direct use by tests and the router)
# ---------------------------------------------------------------------------


def _mask_secrets(obj: Any) -> Any:
    """Recursively replace SecretStr values with None.

    Called before serialising a config object for a GET response so that stored
    secrets are never echoed back in plaintext (EARS ubiquitous; ADR-0006).
    """
    if isinstance(obj, SecretStr):
        return None
    if isinstance(obj, dict):
        return {k: _mask_secrets(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_secrets(item) for item in obj]
    return obj


def _config_to_dict(cfg: BaseModel) -> dict[str, Any]:
    """Serialise a Pydantic config model to a plain dict with secrets masked.

    Uses ``model_dump()`` (Pydantic v2) then recurses through the result to
    replace SecretStr values with None.
    """
    raw = cfg.model_dump()
    return _mask_secrets(raw)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Source config helpers (called by the router below AND directly in tests)
# ---------------------------------------------------------------------------


def get_source_config(
    type_key: str,
    registry: dict[str, Any],
    config_store: Any,
) -> dict[str, Any]:
    """Resolve and return the per-source config for *type_key*.

    Returns a dict suitable for JSON serialisation with SecretStr values masked.

    Raises ``KeyError`` if *type_key* is not in the registry (caller maps to 404).
    """
    plugin = registry[type_key]  # KeyError → 404 in the route
    schema_cls = plugin.config_schema()
    cfg = config_store.get_source(type_key, schema_cls)
    return _config_to_dict(cfg)


def put_source_config(
    type_key: str,
    updates: dict[str, Any],
    registry: dict[str, Any],
    config_store: Any,
) -> None:
    """Validate *updates* against the plugin schema and persist via ConfigStore.

    Raises ``KeyError`` if *type_key* is not in the registry (caller maps to 404).
    Raises ``pydantic.ValidationError`` on schema validation failure (caller → 422).
    Raises ``ValueError`` on env-lock or reserved-key rejection (caller → 400).
    """
    plugin = registry[type_key]  # KeyError → 404 in the route
    schema_cls = plugin.config_schema()
    # ConfigStore.set_source validates against the schema and checks env-lock.
    # It raises ValidationError or ValueError on rejection without persisting.
    config_store.set_source(type_key, schema_cls, updates)


# ---------------------------------------------------------------------------
# Runtime config helpers (called by the router below AND directly in tests)
# ---------------------------------------------------------------------------


def get_runtime_config(config_store: Any) -> dict[str, Any]:
    """Return the current runtime config with SecretStr values masked.

    Adds two non-secret boolean indicators derived from SecretStr fields
    (ADR-0006 / issues #494, #550):

    ``webhook_url_set``
        True when a webhook URL is configured; the secret value itself is
        never returned (issue #494).

    ``api_key_set``
        True when an API key is configured; the secret value itself is
        never returned (issue #550).

    The secret values themselves are never returned; only the boolean signals
    are exposed so the UI can display honest "set" state across sessions.
    """
    cfg = config_store.get_runtime()
    # Capture booleans BEFORE _config_to_dict replaces SecretStr with None,
    # so we can distinguish "set+masked" from "never set".
    webhook_url_set: bool = cfg.webhook_url is not None
    api_key_set: bool = cfg.api_key is not None
    result = _config_to_dict(cfg)
    result["webhook_url_set"] = webhook_url_set
    result["api_key_set"] = api_key_set
    return result


def put_runtime_config(updates: dict[str, Any], config_store: Any) -> None:
    """Persist runtime config updates.

    Raises ``pydantic.ValidationError`` on schema validation failure.
    Raises ``ValueError`` on env-lock rejection.
    """
    config_store.set_runtime(updates)


# ---------------------------------------------------------------------------
# APIRouter — behavior-preserving move from app.py closures (MB.1, ADR-0029 D5)
#
# The closures in app.py delegated to the helper functions above.  The router
# handlers below do the same — error mapping is identical.
# ---------------------------------------------------------------------------

router = APIRouter(tags=["config"])


@router.get(
    "/config/sources/{type_key}",
    summary="Get per-source config (SecretStr fields masked)",
    response_model=dict,
)
def _get_source_config(
    type_key: str,
    registry: dict[str, Any] = Depends(get_registry),
    config_store: Any = Depends(get_config_store),
) -> dict[str, Any]:
    try:
        return get_source_config(
            type_key=type_key,
            registry=registry,
            config_store=config_store,
        )
    except KeyError:
        raise HTTPException(
            status_code=404, detail=f"Unknown source type: {type_key!r}"
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.put(
    "/config/sources/{type_key}",
    summary=(
        "Update per-source config — validated against plugin schema; "
        "env-locked fields rejected; nothing persisted on rejection"
    ),
    response_model=dict,
)
def _put_source_config(
    type_key: str,
    body: dict[str, Any],
    registry: dict[str, Any] = Depends(get_registry),
    config_store: Any = Depends(get_config_store),
) -> dict[str, Any]:
    updates: dict[str, Any] = body.get("updates", {})
    try:
        put_source_config(
            type_key=type_key,
            updates=updates,
            registry=registry,
            config_store=config_store,
        )
    except KeyError:
        raise HTTPException(
            status_code=404, detail=f"Unknown source type: {type_key!r}"
        )
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=_sanitize_validation_errors(exc),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return get_source_config(
        type_key=type_key,
        registry=registry,
        config_store=config_store,
    )


@router.get(
    "/config/runtime",
    summary="Get runtime config (SecretStr fields masked)",
    response_model=dict,
)
def _get_runtime_config(
    config_store: Any = Depends(get_config_store),
) -> dict[str, Any]:
    return get_runtime_config(config_store=config_store)


@router.put(
    "/config/runtime",
    summary=(
        "Update runtime config — validated; env-locked fields rejected; "
        "nothing persisted on rejection"
    ),
    response_model=dict,
)
def _put_runtime_config(
    body: dict[str, Any],
    config_store: Any = Depends(get_config_store),
) -> dict[str, Any]:
    updates: dict[str, Any] = body.get("updates", {})
    try:
        put_runtime_config(updates=updates, config_store=config_store)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=_sanitize_validation_errors(exc),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return get_runtime_config(config_store=config_store)
