"""Source maintenance action routes (ADR-0034 / issue #167).

Provides two routes for the plugin-declared action seam:

  GET  /sources/{type_key}/actions?source_id=
      Returns the declared actions zipped with per-action ``ActionStatus``
      from ``plugin.action_status``.  A raising plugin degrades to a
      null-status entry — never a 500.

  POST /sources/{type_key}/actions/{action_id}?source_id=
      Awaits ``supervisor.run_action_for``, returns ``ActionResult``.
      Validates the ``action_id`` against the declared set before reaching
      plugin code (supervisor enforces this; route surfaces 404 on mismatch).
      A concurrent POST for the same triple returns HTTP 409 (NB-2).

Auth: class B (ADR-0026) — action-triggering write surface.
  Loopback-only now; gated by the API key the moment the bind leaves
  loopback (fail-closed, ADR-0026 Decision 4).

Guard order mirrors ``routes/sources.py`` (established by ADR-0031 + PR #181):
  1. ``_require_supervisor``  — 503 when no supervisor
  2. ``_resolve_instance``    — 404 for unknown type_key or unconfigured source_id
  3. Plugin-level validation  — 404 for undeclared action_id (supervisor raises ValueError)

Security notes:
  ``source_id`` is constrained to ``_SOURCE_ID_PATTERN`` (max 128 chars) on both
  routes, consistent with the ingest routes (NB-4).  CRLF/oversized values
  return 422 before any plugin or supervisor code is reached.

  ``action_id`` is validated as a path parameter against ``^[a-z][a-z0-9_]*$``
  at the FastAPI layer (declared in ``SourceAction.id``), validated again by
  the supervisor against the declared set, and NEVER interpolated into a shell,
  path, or URL.  No attacker-controlled value is echoed back (MC.3 posture).

  Concurrent POST for the same (type_key, source_id, action_id) triple returns
  HTTP 409 with a generic detail — the action_id and source_id are NOT echoed
  (NB-2 / MC.3 attacker-echo posture).

Dependency rule: imports firewatch-sdk and firewatch-core only (via deps.py).
Never imports a concrete plugin package and never imports legacy/.
"""
from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from firewatch_api.deps import get_registry, get_supervisor

# Re-use the two guard helpers defined in sources.py — they are the
# established shared helpers for this URL-prefix family (ADR-0031 / PR #181).
from firewatch_api.routes.sources import _require_supervisor, _resolve_instance

# NB-4: mirror the ingest route's source_id constraint so both write surfaces
# enforce the same log-injection / CRLF defence (schemas._SOURCE_ID_PATTERN).
from firewatch_api.schemas import _SOURCE_ID_PATTERN

logger = logging.getLogger("firewatch.api.source_actions")

router = APIRouter()

# NB-4: annotated type for the source_id query parameter — pattern + max_length
# mirrors IngestRequest.source_id in schemas.py (same defence, same limit).
_SourceIdQuery = Annotated[
    str,
    Query(
        pattern=_SOURCE_ID_PATTERN,
        max_length=128,
        description="User-assigned instance name (log-injection safe; ADR-0016).",
    ),
]


# --------------------------------------------------------------------------- #
# GET /sources/{type_key}/actions — declared actions + live status            #
# --------------------------------------------------------------------------- #


@router.get("/sources/{type_key}/actions")
async def list_actions(
    type_key: str,
    source_id: _SourceIdQuery,
    supervisor: Any = Depends(get_supervisor),
    registry: dict[str, Any] = Depends(get_registry),
) -> list[dict[str, Any]]:
    """Return each declared action with its current ``ActionStatus``.

    For each action declared in ``plugin.metadata().actions``, the response
    contains the action declaration merged with the status snapshot from
    ``supervisor.action_status_for``.

    Resilient: a plugin whose ``action_status`` raises contributes a
    null-status entry (``last_run_at: null``, ``stale: null``) rather than
    causing a 500 — the supervisor's ``action_status_for`` catches and
    degrades internally (ADR-0034 §resilience).

    Returns 503 when no supervisor is injected.
    Returns 404 for unknown ``type_key`` or unconfigured ``source_id``.
    Returns 422 for a ``source_id`` that fails the pattern or length constraint (NB-4).
    Returns an empty list when the plugin declares no actions.

    Args:
        type_key:  Plugin type key path parameter.
        source_id: Instance name query parameter (constrained, NB-4).
    """
    sup = _require_supervisor(supervisor)
    _resolve_instance(sup, registry, type_key, source_id)

    plugin = registry[type_key]
    declared_actions = plugin.metadata().actions  # tuple[SourceAction, ...]

    result: list[dict[str, Any]] = []
    for action in declared_actions:
        # Collect status — degrading to null-status on any failure (supervisor
        # handles the try/except and returns NULL_ACTION_STATUS on raise).
        try:
            status = await sup.action_status_for(type_key, source_id, action.id)
        except (KeyError, ValueError):
            # Should not occur (we resolved the instance above), but guard
            # defensively to preserve the resilient-read posture.
            from firewatch_sdk.actions import NULL_ACTION_STATUS
            status = NULL_ACTION_STATUS

        entry: dict[str, Any] = {
            # Action declaration fields
            "id": action.id,
            "label": action.label,
            "description": action.description,
            "long_running": action.long_running,
            "confirm": action.confirm,
            "provides": list(action.provides),
            # Live status fields
            "last_run_at": status.last_run_at,
            "stale": status.stale,
            "status_message": status.message,
            "status_detail": dict(status.detail),
        }
        result.append(entry)

    return result


# --------------------------------------------------------------------------- #
# POST /sources/{type_key}/actions/{action_id} — invoke action               #
# --------------------------------------------------------------------------- #


@router.post("/sources/{type_key}/actions/{action_id}")
async def run_action(
    type_key: str,
    action_id: str,
    source_id: _SourceIdQuery,
    supervisor: Any = Depends(get_supervisor),
    registry: dict[str, Any] = Depends(get_registry),
) -> dict[str, Any]:
    """Invoke a plugin-declared maintenance action for a source instance.

    The supervisor:
    1. Validates ``action_id`` against the plugin's declared set.
    2. Mints a ``PluginContext`` (ADR-0027 — supervisor is the single minter;
       ``source_type`` taken from ``metadata().type_key``, never from the
       path parameter — capability isolation, ADR-0025 addendum).
    3. Awaits ``plugin.run_action(action_id, cfg, ctx)``.
    4. On success, runs the post-action KV promotion so action products
       (e.g. rule descriptions) are visible without a separate collect cycle.

    Returns 503 when no supervisor is injected.
    Returns 404 for:
      - Unknown ``type_key``
      - Unconfigured ``source_id``
      - ``action_id`` not declared by the plugin
    Returns 409 when the same triple is already executing (NB-2).
    Returns 422 for a ``source_id`` that fails the pattern or length constraint (NB-4).
    Returns 200 + ``ActionResult`` payload on both success (``ok: true``) and
    plugin-level failure (``ok: false``) — both are valid outcomes.

    Auth: class B (ADR-0026) — loopback-only until the API-key gate lands.
    ``action_id`` is NEVER interpolated into a shell, path, or URL.

    Args:
        type_key:  Plugin type key path parameter.
        action_id: Action identifier path parameter (``^[a-z][a-z0-9_]*$``).
        source_id: Instance name query parameter (constrained, NB-4).
    """
    sup = _require_supervisor(supervisor)
    _resolve_instance(sup, registry, type_key, source_id)

    try:
        result = await sup.run_action_for(type_key, source_id, action_id)
    except KeyError:
        # Instance disappeared between _resolve_instance and run_action_for
        # (race condition in a live supervisor) — surface as 404.
        raise HTTPException(
            status_code=404,
            detail=f"No configured instance for source type '{type_key}'",
        )
    except ValueError:
        # action_id not declared by the plugin (supervisor validates this).
        # Do NOT echo action_id back in the detail — MC.3 attacker-echo posture.
        raise HTTPException(
            status_code=404,
            detail=(
                f"Action not declared by plugin '{type_key}'. "
                "Check GET /sources/{type_key}/actions for the declared set."
            ),
        )
    except RuntimeError as exc:
        # NB-2: single-flight guard — supervisor raises RuntimeError("in_progress")
        # when the same triple is already executing.  Surface as 409.
        # Do NOT echo action_id, source_id, or the raw exception message (MC.3).
        if "in_progress" in str(exc):
            raise HTTPException(
                status_code=409,
                detail="An action is already running for this source. Try again later.",
            )
        raise  # unexpected RuntimeError — let the framework handle it

    return {
        "ok": result.ok,
        "message": result.message,
        "detail": dict(result.detail),
        "source_type": type_key,
        "source_id": source_id,
        "action_id": action_id,
    }
