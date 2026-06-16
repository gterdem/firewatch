"""Source routes — discovery helper + MB.4 instance controls (issue #56).

This module contains three concerns kept together because they share the
``/sources`` URL prefix and the registry/supervisor dependencies:

1. **Discovery helper** (MA.3): ``list_source_types`` builds the
   ``GET /sources/types`` payload.  Unchanged from MA.

2. **Instance routes** (MB.4): the FastAPI router that serves:
   - ``GET  /sources``                               — all instances + status + event count
   - ``POST /sources/{type_key}/test``               — health_check probe (no ingest)
   - ``POST /sync/{type_key}``                       — on-demand single pull cycle

3. **Auto-sync routes** (issue #137, ADR-0031 §E):
   - ``PUT  /sources/{type_key}/auto-sync``          — enable/disable/update auto-sync
   - ``GET  /sources/{type_key}/auto-sync``          — read auto-sync state + last-sync

   Auth: class A+B (ADR-0026) — config-mutating AND action-triggering.
   Served loopback-only until the API-key gate lands (ADR-0026 Decision 4).

ADR references:
  ADR-0023 — supervisor lifecycle; crash isolation means a parked instance must
             not break GET /sources for others.
  ADR-0026 — auth posture: routes are class A+B (action-triggering + config-
             mutating).  MB ships loopback-only with no per-route auth; MB.7
             will add the API-key gate.
  ADR-0029 — the /sources route is part of the read/control surface.
  ADR-0031 — persist-before-live-mutate; _instances entry IS the auto-sync state;
             source_id defaults to type_key; interval bounded [30, 86400].

Security note (class A+B):
  The auto-sync write surface is the highest-impact path after PUT /config/*.
  It persists ``_instances`` (§A) and starts/stops a live collection task (§D).
  The pull *target* (Azure workspace, SSH host) is set in the source config
  (already class-A, already SSRF-reviewed at config-write time); auto-sync only
  toggles whether that already-validated target is polled, so no new SSRF vector
  is introduced (OWASP API Security Top 10 2023 API7).  Interval is validated
  before any persist/mutate to prevent a busy-loop DoS (ADR-0031 §E, [30, 86400]).
  The writer round-trips per-source config sections verbatim — no secret-exposure
  path is introduced.

Dependency rule: imports firewatch-sdk and firewatch-core only (via deps.py
providers and explicit core imports for instance_writer / config_store).
Never imports a concrete plugin (suricata, syslog, …) and never imports legacy/.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from firewatch_sdk import SourcePlugin

from firewatch_api.deps import (
    get_config_store,
    get_event_store,
    get_registry,
    get_supervisor,
)

logger = logging.getLogger("firewatch.api.sources")

router = APIRouter()

# Interval bounds (ADR-0031 §E, confirmed 2026-06-10).
# Floor prevents a busy-loop DoS against the upstream pull target.
# Ceiling prevents integer-overflow / scheduling pathologies.
_INTERVAL_MIN: int = 30
_INTERVAL_MAX: int = 86400


# --------------------------------------------------------------------------- #
# MA.3 discovery helper (unchanged)                                            #
# --------------------------------------------------------------------------- #


def _build_entry(plugin: SourcePlugin) -> dict[str, Any] | None:
    """Build one discovery entry from a plugin instance.

    Returns None if the plugin raises at serve time (resilient discovery —
    a failing plugin must not break the response for others).

    The ``actions`` key carries the plugin's declared ``SourceAction`` list
    (ADR-0034).  It is declarations-only (no live status) — discovery is a
    static read surface.  A plugin with no declared actions emits an empty
    list, which is the backward-compatible default for all existing plugins.

    State-driven resilience: if the plugin declares a non-empty actions list
    but does NOT satisfy ``ActionCapable``, the entry is omitted with a
    WARNING (same resilient-discovery posture as a metadata() raise) so the
    violating plugin never breaks discovery for correctly-implemented ones.
    """
    from firewatch_sdk.actions import ActionCapable

    try:
        meta = plugin.metadata()
        schema_cls = plugin.config_schema()
        config_schema: dict[str, Any] = schema_cls.model_json_schema()

        # ADR-0034 state-driven criterion: a plugin that declares actions but
        # does not implement ActionCapable is a contract violation — omit it
        # rather than surface a half-broken entry.
        if meta.actions and not isinstance(plugin, ActionCapable):
            logger.warning(
                "plugin %r declares %d action(s) but does not satisfy "
                "ActionCapable protocol — omitting from discovery",
                meta.type_key, len(meta.actions),
            )
            return None

        return {
            "type_key": meta.type_key,
            "display_name": meta.display_name,
            "version": meta.version,
            "flavor": meta.flavor,
            "config_schema": config_schema,
            # ADR-0034: declarations only — no live status here.
            "actions": [a.model_dump() for a in meta.actions],
            # ADR-0060: canonical SecurityEvent field names this source can emit.
            # Empty list = "produces everything" (the default / backward-compat).
            "produces": sorted(meta.produces),
        }
    except Exception:
        logger.exception(
            "failed to build discovery entry for plugin; omitting from response"
        )
        return None


def list_source_types(registry: dict[str, SourcePlugin]) -> list[dict[str, Any]]:
    """Return one discovery entry per installed source plugin.

    Each entry includes ``type_key``, ``display_name``, ``version``,
    ``flavor`` (pull|push), and ``config_schema``.  Resilient: a plugin that
    raises during entry construction is omitted without a 500.

    This function is intentionally NOT a FastAPI route handler — it is called
    by the discovery router (``routes/discovery.py``) which registers
    ``GET /sources/types``.  This keeps the registry injection clean.
    """
    results: list[dict[str, Any]] = []
    for plugin in registry.values():
        entry = _build_entry(plugin)
        if entry is not None:
            results.append(entry)
    return results


# --------------------------------------------------------------------------- #
# Shared helpers                                                               #
# --------------------------------------------------------------------------- #


def _require_supervisor(supervisor: Any) -> Any:
    """Raise 503 when no supervisor is available.

    The supervisor is optional injection — tests and deployments that only
    exercise read routes may omit it.  Control and instance-list routes must
    surface a clear error rather than a 500 (no supervisor = service unavailable
    for those specific operations).

    RFC 9110 §10.2.3: Retry-After header signals the client how long to wait
    before retrying.  5 s matches the UI's BACKOFF_BASE_MS (issue #315).
    """
    if supervisor is None:
        raise HTTPException(
            status_code=503,
            detail="Supervisor not available. No source instances are running.",
            headers={"Retry-After": "5"},
        )
    return supervisor


async def _build_event_count_map(store: Any) -> dict[tuple[str, str], int]:
    """Return a (source_type, source_id) -> event_count map from the store.

    Uses ``store.source_health()`` (ADR-0032 D, issue #133) so the count is
    always real.  Returns an empty dict when the store is absent or the call
    fails — callers treat a missing key as 0 (soft failure keeps GET /sources
    from breaking when the store is temporarily unavailable).
    """
    if store is None:
        return {}
    try:
        rows: list[dict[str, Any]] = await store.source_health()
        return {(r["source_type"], r["source_id"]): r["event_count"] for r in rows}
    except Exception:
        logger.warning("sources: failed to build event count map", exc_info=True)
        return {}


def _load_autosync_set(config_store: Any) -> set[tuple[str, str]]:
    """Return the set of (source_type, source_id) pairs that have auto-sync enabled.

    Auto-sync is ON iff an ``_instances`` entry exists for that pair (ADR-0031 §A:
    the entry IS the ON state — restart-stable).  This is the single authoritative
    read of the file; both ``list_instances`` and ``get_autosync`` delegate here so
    the logic is never duplicated (ADR-0062 Amendment 1, issue #736).

    Degrades gracefully: returns an empty set (all entries → false) when:
    - config_store is None;
    - config_store does not expose a ``config_path`` (non-file-backed store);
    - the file cannot be read or parsed.
    Never raises; never returns a 503.
    """
    config_path: Path | None = getattr(config_store, "config_path", None)
    if config_path is None:
        return set()
    try:
        from firewatch_core.instance_loader import load_instances
        instances = load_instances(config_path)
        return {(inst.source_type, inst.source_id) for inst in instances}
    except Exception:
        logger.warning("sources: failed to load auto-sync set", exc_info=True)
        return set()


def _resolve_instance(
    supervisor: Any,
    registry: dict[str, Any],
    type_key: str,
    source_id: str,
) -> None:
    """Validate that (type_key, source_id) identifies a known, configured instance.

    Raises ``HTTPException(404)`` when:
    - ``type_key`` is not in the plugin registry (unknown source type), or
    - the supervisor has no record for ``(type_key, source_id)``.

    This ensures path params are validated against real configured instances —
    never used to reach arbitrary code or other instances' scope (OWASP API1).
    """
    if type_key not in registry:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown source type: {type_key!r}",
        )
    if supervisor.get_instance(type_key, source_id) is None:
        raise HTTPException(
            status_code=404,
            detail=f"No configured instance '{source_id}' for source type '{type_key}'",
        )


def _resolve_autosync_target(
    registry: dict[str, Any],
    type_key: str,
) -> tuple[Any, str]:
    """Validate a type_key for auto-sync and return (plugin, flavor).

    Raises:
        HTTPException(404) — type_key not in registry.
        HTTPException(409) — flavor is "push" (push sources have no auto-sync;
            configuring a push source already starts its listener).

    The flavor check is driven by ``plugin.metadata().flavor`` — never hard-coded
    (ADR-0031 ubiquitous criterion: flavor comes from metadata(), not a literal).
    """
    if type_key not in registry:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown source type: {type_key!r}",
        )
    plugin = registry[type_key]
    flavor: str = plugin.metadata().flavor
    if flavor == "push":
        raise HTTPException(
            status_code=409,
            detail=(
                f"Source type {type_key!r} is a push source and has no auto-sync. "
                "Configuring a push source already starts its listener."
            ),
        )
    return plugin, flavor


def _require_config_path(config_store: Any) -> Path:
    """Extract the config file path from the injected store, or raise 503.

    ADR-0031 option A: the route reads the path from the injected
    ``JsonFileConfigStore`` via its ``config_path`` property.  When the store
    is a fake without that property (test or legacy deployment), 503 is returned
    rather than silently writing to the wrong file.
    """
    if config_store is None or not hasattr(config_store, "config_path"):
        raise HTTPException(
            status_code=503,
            detail=(
                "ConfigStore is not available or does not expose a config_path. "
                "Auto-sync writes require a file-backed config store."
            ),
        )
    return config_store.config_path  # type: ignore[no-any-return]


def _load_source_cfg(
    config_store: Any,
    plugin: Any,
    type_key: str,
) -> BaseModel:
    """Load the per-source config for *type_key* from the store.

    Falls back to schema defaults on any error — the auto-sync route still
    proceeds; the supervisor will use the default config when calling
    register_idle (which is safe: the real config is persisted in the file
    and will be resolved on the next cycle).
    """
    schema: type[BaseModel] = plugin.config_schema()
    try:
        return config_store.get_source(type_key, schema)
    except Exception:
        logger.warning(
            "auto-sync: could not load config for %s; using schema defaults",
            type_key, exc_info=True,
        )
        return schema.model_validate({})


# --------------------------------------------------------------------------- #
# GET /sources — instance list + supervisor status + event count              #
# --------------------------------------------------------------------------- #


@router.get("/sources")
async def list_instances(
    supervisor: Any = Depends(get_supervisor),
    store: Any = Depends(get_event_store),
    config_store: Any = Depends(get_config_store),
) -> list[dict[str, Any]]:
    """Return all configured source instances with supervisor status and event counts.

    Each entry combines:
    - The ``InstanceStatus`` DTO fields (from ``Supervisor.status()``).
    - ``event_count`` — total events ingested from that instance (from the store).
    - ``auto_sync_enabled`` (pull only) — true iff the source has an ``_instances``
      entry in the config file (ADR-0062 Amendment 1, issue #736).  This is the
      authoritative "Active" signal; ``state`` remains purely diagnostic.

    Crash isolation (ADR-0023): a parked or erroring instance contributes its
    status entry normally — it does NOT cause a 500 or omit other instances.

    Returns 503 when no supervisor is injected.
    """
    sup = _require_supervisor(supervisor)

    # Build the event count map once (one DB round-trip for all instances).
    count_map = await _build_event_count_map(store)

    # Load the auto-sync set once per request (degrades to empty set when the
    # config store is absent or non-file-backed — never raises, never 503s).
    autosync_set = _load_autosync_set(config_store)

    statuses = sup.status()
    result: list[dict[str, Any]] = []

    for status in statuses:
        count = count_map.get((status.source_type, status.source_id), 0)
        entry: dict[str, Any] = {
            "source_type": status.source_type,
            "source_id": status.source_id,
            "flavor": status.flavor,
            "state": status.state,
            "attempt": status.attempt,
            "total_crashes": status.total_crashes,
            "total_dlq": status.total_dlq,
            "dropped_count": status.dropped_count,
            "last_success_at": status.last_success_at,
            "event_count": count,
            # ADR-0031 §F diagnostics fields (issue #139): additive, read-only.
            # Exposed from InstanceStatus DTO to power the Settings diagnostics panel.
            "last_sync_at": getattr(status, "last_sync_at", None),
            "last_sync_ingested": getattr(status, "last_sync_ingested", 0),
            "last_sync_status": getattr(status, "last_sync_status", None),
            "last_error": getattr(status, "last_error", None),
        }
        # ADR-0062 Amendment 1 (issue #736): pull entries carry auto_sync_enabled;
        # push entries omit it (push sources have no auto-sync concept).
        if status.flavor == "pull":
            entry["auto_sync_enabled"] = (
                (status.source_type, status.source_id) in autosync_set
            )
        result.append(entry)

    return result


# --------------------------------------------------------------------------- #
# POST /sources/{type_key}/test — connectivity probe                           #
# --------------------------------------------------------------------------- #


@router.post("/sources/{type_key}/test")
async def test_source(
    type_key: str,
    source_id: str,
    supervisor: Any = Depends(get_supervisor),
    registry: dict[str, Any] = Depends(get_registry),
    config_store: Any = Depends(get_config_store),
) -> dict[str, Any]:
    """Run the plugin's health_check for the named instance; return ok/error.

    This is a diagnostic probe (ADR-0026 class B — action-triggering, but
    read-only with respect to event ingestion).  It calls ``plugin.health_check``
    and returns the boolean result.  It must NOT trigger a pull cycle or mutate
    supervisor state.

    Path params are validated against known/configured instances.
    Returns 404 for unknown type_key or source_id, never 500.
    Returns 503 when no supervisor is injected.

    Args:
        type_key:    Plugin type key path parameter (e.g. ``"suricata"``).
        source_id:   Instance name query parameter (e.g. ``"pi-home"``).
    """
    sup = _require_supervisor(supervisor)
    _resolve_instance(sup, registry, type_key, source_id)

    if config_store is None:
        raise HTTPException(
            status_code=503,
            detail="ConfigStore not available.",
        )

    plugin = registry[type_key]
    cfg_model = plugin.config_schema()
    try:
        cfg = config_store.get_source(type_key, cfg_model)
    except Exception:
        logger.warning(
            "sources/test: could not load config for %s/%s; using defaults",
            type_key, source_id, exc_info=True,
        )
        cfg = cfg_model.model_validate({})

    try:
        ok: bool = await plugin.health_check(cfg)
    except Exception as exc:
        logger.warning(
            "sources/test: health_check raised for %s/%s: %s",
            type_key, source_id, exc,
        )
        ok = False

    return {"ok": ok, "source_type": type_key, "source_id": source_id}


# --------------------------------------------------------------------------- #
# POST /sync/{type_key} — on-demand single pull cycle                         #
# --------------------------------------------------------------------------- #


@router.post("/sync/{type_key}")
async def sync_source(
    type_key: str,
    source_id: str,
    supervisor: Any = Depends(get_supervisor),
    registry: dict[str, Any] = Depends(get_registry),
) -> dict[str, Any]:
    """Ask the supervisor to run one idempotent pull cycle for the named instance.

    Idempotency: concurrent calls do not double-pull beyond watermark semantics
    (ADR-0023 Consequences — at-least-once with dedup in the store).  The
    watermark ensures the cycle reads only events newer than the last checkpoint.

    Path params are validated against known/configured instances.
    Returns 404 for unknown type_key or source_id.
    Returns 502 when the upstream collection (pull cycle) raises — structured JSON
    error with ``{ "error": { "code": str, "message": str } }`` so the UI can
    render a user-friendly message (issue #569, unblocks Settings FE #573).
    Returns 503 when no supervisor is injected.

    Error envelope (issue #569):
        ``code`` — ``"SYNC_FAILED"`` (stable machine-readable token for the FE).
        ``message`` — ``"<ExcType>: <first 200 chars of message>"`` — descriptive,
                      non-stack-trace; safe to render in the UI (no internal paths,
                      no secrets).  The supervisor already bounds exception messages
                      at 200 chars in ``run_pull_cycle_for`` (ADR-0031 NB-6); this
                      route applies the same bound independently because the raw
                      exception may arrive here before the supervisor has a chance
                      to truncate it.

    Args:
        type_key:  Plugin type key path parameter (e.g. ``"suricata"``).
        source_id: Instance name query parameter (e.g. ``"pi-home"``).
    """
    sup = _require_supervisor(supervisor)
    _resolve_instance(sup, registry, type_key, source_id)

    try:
        events_ingested: int = await sup.run_pull_cycle_for(type_key, source_id)
    except Exception as exc:
        # Log full exception server-side (stack trace visible in server logs only).
        logger.exception(
            "sync: pull cycle failed for %s/%s: %s",
            type_key, source_id, exc,
        )
        # Build a safe, bounded message: "ExcType: first 200 chars of message".
        # This matches the NB-6 convention in supervisor/orchestrator.py and
        # ensures no internal paths or secret-bearing stack frames reach the client.
        exc_type = type(exc).__name__
        exc_msg = str(exc)[:200]
        raise HTTPException(
            status_code=502,
            detail={
                "error": {
                    "code": "SYNC_FAILED",
                    "message": f"{exc_type}: {exc_msg}",
                }
            },
        )

    return {
        "ok": True,
        "source_type": type_key,
        "source_id": source_id,
        "events_ingested": events_ingested,
    }


# --------------------------------------------------------------------------- #
# PUT /sources/{type_key}/auto-sync — enable/disable/update (ADR-0031 §E)    #
# --------------------------------------------------------------------------- #


@router.put("/sources/{type_key}/auto-sync")
async def put_autosync(
    type_key: str,
    body: dict[str, Any],
    supervisor: Any = Depends(get_supervisor),
    registry: dict[str, Any] = Depends(get_registry),
    config_store: Any = Depends(get_config_store),
) -> dict[str, Any]:
    """Enable, disable, or update the auto-sync schedule for a pull source.

    Request body: ``{ "enabled": bool, "interval_seconds": int }``
    Response 200: ``{ "enabled": bool, "interval_seconds": int, "source_id": str }``

    Handler logic (ADR-0031 §E pinned contract):

    1. Guards: 503 if no supervisor; 404 if type_key unknown; 409 if push flavor.
    2. ``enabled`` MUST be a JSON boolean; strings ("true"/"false"), integers, and
       null are rejected with 422 — the raw value is NOT echoed (MC.3 attacker-echo
       mitigation).  ``bool("false")`` is truthy in Python, so coercion was a logic
       inversion bug (issue #166 NB-A).
    3. ``interval_seconds`` is validated in [30, 86400] on the enable path only
       (interval is meaningless when disabling — issue #155 NB-1).
    4. source_id = type_key (ADR-0031 §B single-instance-per-type default).
    5. Branch on enabled:
       - **enable=true, new instance** (get_instance returns None):
           upsert_instance -> register_idle -> enable_pull
       - **enable=true, existing instance** (already registered):
           upsert_instance (update interval) -> set_interval (live update)
       - **enable=false**:
           read persisted interval -> supervisor.disable -> remove_instance.
           Response returns the last-known persisted interval (or 60 if absent),
           NOT 0 — 0 is below the ADR-0031 §E floor and inconsistent with GET
           (issue #166 NB-B).
    6. Persist-before-live-mutate ordering: write _instances first so a restart
       honours the state even if the live supervisor call raises.

    Auth: class A+B (ADR-0026) — loopback-only until MB.7 API-key gate.

    Returns 503 when no supervisor or no file-backed config store is injected.
    Returns 404 for unknown type_key, 409 for push flavor, 422 for bad body.
    """
    sup = _require_supervisor(supervisor)
    plugin, _flavor = _resolve_autosync_target(registry, type_key)
    config_path = _require_config_path(config_store)

    # Step 2a: strict bool guard for 'enabled' (issue #166 NB-A).
    # bool(body.get("enabled", False)) would accept the JSON string "false" as
    # truthy, silently inverting a disable request into an enable.  We require a
    # real JSON boolean (isinstance check); anything else is a 422.
    # The error message deliberately does NOT echo the raw value (MC.3 attacker-echo).
    raw_enabled = body.get("enabled", False)
    if not isinstance(raw_enabled, bool):
        raise HTTPException(
            status_code=422,
            detail="'enabled' must be a JSON boolean (true or false).",
        )
    enabled: bool = raw_enabled

    # Step 2b: validate interval on the enable path only (ADR-0031 §E, fail-closed).
    # Interval is meaningless when disabling — it MUST NOT be required (issue #155 NB-1).
    interval_seconds: int = 0  # placeholder; only used/validated on enable
    if enabled:
        try:
            interval_seconds = int(body["interval_seconds"])
        except (KeyError, TypeError, ValueError):
            raise HTTPException(
                status_code=422,
                detail="interval_seconds is required and must be an integer.",
            )
        if not (_INTERVAL_MIN <= interval_seconds <= _INTERVAL_MAX):
            raise HTTPException(
                status_code=422,
                detail=(
                    f"interval_seconds must be between {_INTERVAL_MIN} and "
                    f"{_INTERVAL_MAX} (got {interval_seconds})."
                ),
            )

    # Step 3: source_id = type_key (ADR-0031 §B).
    source_id = type_key

    # Import writer here (lazy, keeps the module import surface at the top clean
    # and avoids a circular-import risk during module load).
    from firewatch_core.instance_writer import remove_instance, upsert_instance

    existing = sup.get_instance(type_key, source_id)

    if enabled:
        # Persist FIRST (persist-before-live-mutate — ADR-0031 §E).
        upsert_instance(
            config_file=config_path,
            source_type=type_key,
            source_id=source_id,
            flavor="pull",
            interval=float(interval_seconds),
            transport="file",
        )
        if existing is None:
            # New instance: register idle then launch.
            cfg = _load_source_cfg(config_store, plugin, type_key)
            sup.register_idle(
                plugin,
                cfg,
                source_id=source_id,
                flavor="pull",
                interval=float(interval_seconds),
                transport="file",
            )
            sup.enable_pull(type_key, source_id, interval=float(interval_seconds))
            logger.info(
                "auto-sync enabled: %s/%s interval=%ds (new instance)",
                type_key, source_id, interval_seconds,
            )
        else:
            # Already registered.  Branch on state:
            # • IDLE (was disabled) → enable_pull launches the loop and sets
            #   the interval; idempotent if already RUNNING (no-op fast path).
            # • RUNNING → interval-only change; set_interval applies it live
            #   without cancelling the in-flight pull (ADR-0031 §D).
            if existing.state.value != "running":
                # Re-enable a previously-disabled (IDLE) instance.
                sup.enable_pull(type_key, source_id, interval=float(interval_seconds))
                logger.info(
                    "auto-sync re-enabled: %s/%s interval=%ds (existing idle instance)",
                    type_key, source_id, interval_seconds,
                )
            else:
                # Loop is already running — update the interval live.
                sup.set_interval(type_key, source_id, float(interval_seconds))
                logger.info(
                    "auto-sync interval updated: %s/%s interval=%ds",
                    type_key, source_id, interval_seconds,
                )
    else:
        # Disable: read the persisted interval BEFORE removing the entry so the
        # response can return it (issue #166 NB-B: returning 0 is inconsistent
        # with GET's default of 60; 0 is also below the ADR-0031 §E floor of 30).
        from firewatch_core.instance_loader import load_instances
        disable_interval_seconds: int = 60  # same default as GET .../auto-sync
        for inst in load_instances(config_path):
            if inst.source_type == type_key and inst.source_id == source_id:
                disable_interval_seconds = int(inst.interval)
                break

        # Stop live instance first, then remove persisted entry.
        # Order here is disable-before-remove: the live state is authoritative
        # during the window; on restart the absent _instances entry is canonical.
        if existing is not None:
            await sup.disable(type_key, source_id)
        remove_instance(
            config_file=config_path,
            source_type=type_key,
            source_id=source_id,
        )
        interval_seconds = disable_interval_seconds
        logger.info(
            "auto-sync disabled: %s/%s",
            type_key, source_id,
        )

    return {
        "enabled": enabled,
        "interval_seconds": interval_seconds,
        "source_id": source_id,
    }


# --------------------------------------------------------------------------- #
# GET /sources/{type_key}/auto-sync — read state (ADR-0031 §E/§F)            #
# --------------------------------------------------------------------------- #


@router.get("/sources/{type_key}/auto-sync")
async def get_autosync(
    type_key: str,
    supervisor: Any = Depends(get_supervisor),
    registry: dict[str, Any] = Depends(get_registry),
    config_store: Any = Depends(get_config_store),
) -> dict[str, Any]:
    """Return the current auto-sync state for a source type.

    Response: ``{ "enabled": bool, "interval_seconds": int, "source_id": str,
                  "last_sync": { last_sync_at, last_sync_ingested,
                                 last_sync_status, last_error } }``

    **enabled** is derived from the presence of an ``_instances`` entry for
    ``(type_key, type_key)`` (ADR-0031 §A: the entry IS the ON state — restart-
    stable, unlike volatile live state).

    **interval_seconds** comes from the ``_instances`` entry (or the running
    record's interval); defaults to 60 if absent.

    **last_sync** is populated from ``Supervisor.status()`` for the matching
    instance; all fields are None/0 before the first cycle.

    Returns 503 when no supervisor is injected, 404 for unknown type_key.
    """
    _require_supervisor(supervisor)
    if type_key not in registry:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown source type: {type_key!r}",
        )

    source_id = type_key

    # Derive enabled from the _instances file (restart-stable — ADR-0031 §A).
    # _load_autosync_set is the single shared implementation (ADR-0062 A1, #736).
    autosync_set = _load_autosync_set(config_store)
    enabled = (type_key, source_id) in autosync_set

    # Resolve interval from the matching instance entry (not available from the set).
    interval_seconds = 60
    config_path: Path | None = getattr(config_store, "config_path", None)
    if config_path is not None:
        from firewatch_core.instance_loader import load_instances
        for inst in load_instances(config_path):
            if inst.source_type == type_key and inst.source_id == source_id:
                interval_seconds = int(inst.interval)
                break

    # last_sync from supervisor status (ADR-0031 §F).
    last_sync: dict[str, Any] = {
        "last_sync_at": None,
        "last_sync_ingested": 0,
        "last_sync_status": None,
        "last_error": None,
    }
    for status in supervisor.status():
        if status.source_type == type_key and status.source_id == source_id:
            last_sync = {
                "last_sync_at": getattr(status, "last_sync_at", None),
                "last_sync_ingested": getattr(status, "last_sync_ingested", 0),
                "last_sync_status": getattr(status, "last_sync_status", None),
                "last_error": getattr(status, "last_error", None),
            }
            break

    return {
        "enabled": enabled,
        "interval_seconds": interval_seconds,
        "source_id": source_id,
        "last_sync": last_sync,
    }
