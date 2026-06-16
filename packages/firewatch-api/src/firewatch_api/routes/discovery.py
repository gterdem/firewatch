"""Discovery route — GET /sources/types (MA.3, issue #32).

Behavior-preserving move from the inline closure in app.py to an APIRouter.
The business logic remains in ``firewatch_api.routes.sources``; this module
wires it as a proper router with a ``Depends()`` provider (ADR-0029 D5, MB move).

Imports only firewatch-sdk. Never imports a concrete plugin or legacy/.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from firewatch_api.deps import get_registry
from firewatch_api.routes import sources as sources_logic

router = APIRouter(tags=["discovery"])


@router.get(
    "/sources/types",
    summary="Discover installed source plugins",
    response_model=list[dict],
)
def list_source_types(
    registry: dict[str, Any] = Depends(get_registry),
) -> list[dict[str, Any]]:
    """Return one entry per installed source plugin.

    Each entry includes: ``type_key``, ``display_name``, ``version``,
    ``flavor`` (pull|push), and ``config_schema``.

    Behavior-preserving move: delegates to the same ``sources_logic`` function
    used by the MA closure — status codes and payload shape are unchanged.
    """
    return sources_logic.list_source_types(registry=registry)
