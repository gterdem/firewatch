"""Source-health assembler for GET /stats (ADR-0032 Decision C + E, issue #133).

This module owns the assembly of the ``source_health[]`` array returned by
``GET /stats``.  It left-joins three inputs:

1. **Registry** (installed set) — every installed plugin gets an entry.
   Plugins with no config section and no events appear as ``not_configured``.
2. **store.source_health()** (events) — per-(source_type, source_id) counts
   and recency.
3. **supervisor.status()** (running/error state) — distinguishes red from amber.

The ``health`` field is server-computed (ADR-0032 Decision C) so the front-end
renders one honest value and does not re-derive policy.

Wire vocabulary (ADR-0032 §B, normative — issue #279 erratum):

    red            if supervisor_state in {parked, backoff} OR last_error set
    not_configured if no config section for this source (grey dot presentation)
    amber          if configured AND (no events yet OR last_event_at is stale)
    ok             if configured AND recent events (within freshness window)

Freshness/staleness windows are module-level constants (config-overridable,
ADR-0006 — override not yet wired; constants serve as the single place to change).

Instance reconciliation (fix for issue #144):
    ADR-0031 §B says source_id *defaults* to type_key but the _instances mechanism
    allows any custom source_id (e.g. "vm-target").  The assembler must join by
    source_type, discover all real source_ids from the supervisor and store, and
    emit one entry per instance.  When no instance exists, it falls back to a single
    grey row keyed by type_key.

Amendment 1 (ADR-0032, issues #377 / #378):
    R1 — FRESHNESS_MINUTES is now exposed on GET /stats as ``freshness_minutes``
         so the frontend legend never hardcodes a second copy of the constant.
    R2 — ``_supervisor_map`` now also carries ``last_sync_at`` (raw epoch float),
         ``last_sync_status`` (ok|no_data|error|None), and ``last_sync_ingested``
         (int) from the InstanceStatus DTO (ADR-0031 §F).  ``last_sync_at`` is
         converted from epoch float to ISO8601 UTC before leaving the assembler
         (``_epoch_to_iso``), for consistency with ``last_event_at``.

Dependency rule: imports firewatch-sdk only.  Never imports a concrete plugin,
firewatch-core, or legacy/.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("firewatch.health_assembler")

# ---------------------------------------------------------------------------
# Health constants (ADR-0032 Decision C / ADR-0006 config-overridable seam)
# ---------------------------------------------------------------------------

#: Events within this many minutes are considered "fresh" → ok.
FRESHNESS_MINUTES: int = 5

#: Supervisor states that drive the dot to red (ADR-0032 Decision C).
_RED_STATES: frozenset[str] = frozenset({"parked", "backoff"})

#: Maximum unique source_ids returned per type (NB-3 hardening, issue #147).
#: Prevents unbounded row expansion from a poisoned store.
SOURCE_ID_CAP_PER_TYPE: int = 50

# ---------------------------------------------------------------------------
# last_error sanitization patterns (NB-1 hardening, issue #147)
# ---------------------------------------------------------------------------

#: Dotted-quad IPv4 addresses (RFC 5737 / RFC 1918 / loopback — all stripped).
_RE_IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

#: Credential-pattern substrings: key=VALUE, password=VALUE, token=VALUE, etc.
#: Strips the value portion that follows the keyword and '='.
_RE_CREDENTIAL = re.compile(
    r"\b(password|token|secret|credential|api_key|key)\s*=\s*\S+",
    re.IGNORECASE,
)

#: Maximum length of a sanitized last_error value (characters).
_LAST_ERROR_MAX_LEN: int = 200


# ---------------------------------------------------------------------------
# Public type alias
# ---------------------------------------------------------------------------

SourceHealthEntry = dict[str, Any]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _epoch_to_iso(epoch: float | None) -> str | None:
    """Convert a wall-clock epoch float (``time.time()``) to ISO8601 UTC string.

    Used to normalize ``last_sync_at`` from the supervisor DTO before it
    leaves the assembler, keeping the wire shape consistent: both
    ``last_event_at`` and ``last_sync_at`` are ISO8601 UTC strings (or null).

    ADR-0032 Amendment 1 R2 / ADR-0031 §F: the supervisor stores epoch floats;
    the health wire uses ISO8601 (same posture as ``last_event_at``).

    Recorded divergence: ``GET /sources`` still serves ``last_sync_at`` as a
    raw epoch float (pre-existing); this conversion applies to ``source_health[]``
    on ``GET /stats`` only.

    Args:
        epoch: Wall-clock seconds since Unix epoch, or None.

    Returns:
        ISO8601 UTC string (e.g. ``"2026-06-12T14:00:00+00:00"``), or None.
    """
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _sanitize_error(value: str | None) -> str | None:
    """Strip sensitive substrings from a raw exception message and truncate.

    Applied to ``last_error`` before it leaves the assembler so that remote
    host/IP addresses, port numbers embedded in IPs, and credential-pattern
    values from ``str(exc)`` are never surfaced on ``GET /stats`` (NB-1,
    issue #147 / ADR-0029 D3).

    Transformations (applied in order):
    1. Return None immediately when *value* is None.
    2. Strip dotted-quad IPv4 addresses (replaces with ``[ip]``).
    3. Strip credential-pattern substrings ``key=VALUE`` (replaces with
       ``<key>=[redacted]``).
    4. Truncate to ``_LAST_ERROR_MAX_LEN`` characters.

    Args:
        value: Raw last_error string from the supervisor record, or None.

    Returns:
        Sanitized string, or None if *value* was None.
    """
    if value is None:
        return None
    result = _RE_IPV4.sub("[ip]", value)
    result = _RE_CREDENTIAL.sub(lambda m: f"{m.group(1)}=[redacted]", result)
    return result[:_LAST_ERROR_MAX_LEN]


def _compute_health(
    *,
    has_config: bool,
    last_event_at: str | None,
    supervisor_state: str | None,
    last_error: str | None,
) -> str:
    """Compute the server-side health string from raw inputs.

    Wire vocabulary (ADR-0032 §B, normative — issue #279 erratum):
    ``ok | amber | red | not_configured``.  No other value is ever returned.

    Rules (ADR-0032 Decision C, in priority order):
    1. red            — supervisor error/parked state OR last_error set
    2. not_configured — no config section
    3. amber          — configured but no/stale events
    4. ok             — configured and recent events

    Args:
        has_config:       Whether the source has a config section in the store.
        last_event_at:    ISO timestamp of the most recent event, or None.
        supervisor_state: Supervisor instance state string, or None if absent.
        last_error:       Supervisor last_error string, or None.
    """
    if supervisor_state in _RED_STATES or last_error:
        return "red"
    if not has_config:
        return "not_configured"
    if last_event_at is None:
        return "amber"
    try:
        last_dt = datetime.fromisoformat(last_event_at)
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age_minutes = (now - last_dt).total_seconds() / 60
        return "ok" if age_minutes <= FRESHNESS_MINUTES else "amber"
    except (ValueError, TypeError):
        return "amber"


def _supervisor_map(supervisor: Any) -> dict[tuple[str, str], dict[str, Any]]:
    """Build a (source_type, source_id) → supervisor-info map from supervisor.

    Carries five fields per instance (ADR-0032 Amendment 1 R2 additive):
      - state          — supervisor lifecycle state string
      - last_error     — raw error string (sanitized by _build_entry before wire)
      - last_sync_at   — epoch float from InstanceStatus.last_sync_at (None if
                         push source or pre-first-cycle); _build_entry converts
                         this to ISO8601 via _epoch_to_iso before the wire
      - last_sync_status  — "ok"|"no_data"|"error"|None (ADR-0031 §F)
      - last_sync_ingested — int, 0 when no cycle has run (ADR-0031 §F)

    Returns an empty dict when supervisor is None.
    """
    if supervisor is None:
        return {}
    result: dict[tuple[str, str], dict[str, Any]] = {}
    try:
        for status in supervisor.status():
            key: tuple[str, str] = (status.source_type, status.source_id)
            result[key] = {
                "state": status.state,
                "last_error": getattr(status, "last_error", None),
                # ADR-0032 Amendment 1 R2 — sync evidence fields (ADR-0031 §F)
                "last_sync_at": getattr(status, "last_sync_at", None),
                "last_sync_status": getattr(status, "last_sync_status", None),
                "last_sync_ingested": getattr(status, "last_sync_ingested", 0),
            }
    except Exception:
        pass
    return result


def _store_health_map(
    store_rows: list[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """Index source_health() rows by (source_type, source_id)."""
    return {
        (r["source_type"], r["source_id"]): r
        for r in store_rows
    }


def _instance_ids_for_type(
    type_key: str,
    sup_map: dict[tuple[str, str], dict[str, Any]],
    store_map: dict[tuple[str, str], dict[str, Any]],
) -> list[str]:
    """Collect all real source_ids known for a given source_type.

    Merges source_ids from both the supervisor map and the store map so that
    an instance only visible in one source (e.g. a supervisor record with no
    events yet, or an orphaned store row with no active supervisor) is still
    surfaced.

    Orphan reconciliation (issue #280, ADR-0031 §B / ADR-0032):
        Before instance naming (ADR-0031 §B), source_id defaulted to type_key
        (e.g. ``"suricata"``).  When an operator renames their instance
        (e.g. to ``"vm-target"``), the old bare-type registration may persist
        in the supervisor with zero events, causing a duplicate health row.

        A source_id equal to type_key is treated as a stale pre-instance-naming
        orphan and is excluded when BOTH of:
          1. It has zero events in the store (no store row or event_count == 0).
          2. At least one OTHER source_id for the same type is present (i.e. the
             bare id is shadowed by a legitimately-named instance).

        If the bare-type id has events it is kept — it is a legitimately-named
        instance (the common case in single-instance deployments).  If it is the
        ONLY known id it is also kept — there is nothing to shadow it, so the
        fallback grey/amber row still uses type_key as its source_id.

    Returns an empty list when neither the supervisor nor the store has any
    record for this type — the caller must emit a fallback grey row keyed by
    type_key.
    """
    ids: set[str] = set()
    for (stype, sid) in sup_map:
        if stype == type_key:
            ids.add(sid)
    for (stype, sid) in store_map:
        if stype == type_key:
            ids.add(sid)

    # Orphan reconciliation: drop the bare-type source_id when it has zero events
    # AND at least one other named instance shadows it (issue #280).
    if type_key in ids:
        store_row = store_map.get((type_key, type_key))
        bare_event_count: int = store_row["event_count"] if store_row else 0
        other_ids = ids - {type_key}
        if bare_event_count == 0 and other_ids:
            logger.info(
                "health_assembler: dropping orphan bare-type registration "
                "source=%s/%s (0 events, shadowed by %d named instance(s) %s) — "
                "stale pre-instance-naming record (ADR-0031 §B / issue #280)",
                type_key, type_key, len(other_ids), sorted(other_ids),
            )
            ids = other_ids

    sorted_ids = sorted(ids)  # deterministic order for stable test assertions
    if len(sorted_ids) > SOURCE_ID_CAP_PER_TYPE:
        logger.warning(
            "health_assembler: source_id cardinality cap hit for type=%s "
            "(found=%d, cap=%d); truncating to cap to prevent unbounded rows",
            type_key, len(sorted_ids), SOURCE_ID_CAP_PER_TYPE,
        )
        sorted_ids = sorted_ids[:SOURCE_ID_CAP_PER_TYPE]
    return sorted_ids


def _has_config(config_store: Any, type_key: str) -> bool:
    """Return True when the config store has a non-empty section for type_key.

    A ``get_source`` call that returns a model with all-default values is
    treated as "no config" (the user has not configured this source yet).
    We err on the side of amber over not_configured when the call raises,
    to avoid hiding a real configuration that an exception obscures.
    """
    if config_store is None:
        return False
    try:
        from firewatch_sdk import SourcePlugin  # noqa: F401 — used for type guard only

        # Ask for raw config dict to avoid importing the plugin schema.
        # config_store.get_source_raw returns a dict (or raises KeyError if absent).
        if hasattr(config_store, "get_source_raw"):
            raw = config_store.get_source_raw(type_key)
            return bool(raw)
        # Fallback: treat any non-raising get_source as "configured".
        # This branch is hit when the config store doesn't expose get_source_raw.
        return True
    except (KeyError, AttributeError):
        return False
    except Exception:
        # NB-2 (issue #147): return False on unexpected errors so the source
        # shows as not_configured (grey) rather than silently appearing amber.
        # Failing loudly here would suppress all other health rows; False is
        # the safe default — the store error will surface in application logs.
        return False


# ---------------------------------------------------------------------------
# Public assembler
# ---------------------------------------------------------------------------


def assemble_source_health(
    *,
    registry: dict[str, Any],
    store_rows: list[dict[str, Any]],
    supervisor: Any,
    config_store: Any,
) -> list[SourceHealthEntry]:
    """Build the ``source_health[]`` array for GET /stats.

    Left-join:
      - ``registry`` provides the installed set (list membership per ADR-0032 A).
      - ``store_rows`` (from ``store.source_health()``) provides event counts/recency.
      - ``supervisor`` provides running/error state.
      - ``config_store`` provides config-section presence (not_configured vs amber).

    Instance reconciliation (fix for issue #144, ADR-0031 §B / ADR-0032 A):
      For each installed type, all real source_ids are discovered from the
      supervisor and store maps by matching on source_type.  One entry is emitted
      per real instance.  When no instance exists (source not yet registered or
      configured), a single grey row keyed by type_key is emitted.

    If a plugin has no store rows it appears with ``event_count: 0,
    last_event_at: null``.  If there is no supervisor, ``supervisor_state`` and
    ``last_error`` are ``null`` and health degrades to not_configured/amber/ok
    (red is unavailable without supervisor data, ADR-0032 E).

    Security (ADR-0029 D3 / issue #133 EARS ubiquitous security criterion):
    no secrets are echoed — only identity/health fields are included.

    Args:
        registry:     Mapping of type_key → SourcePlugin instance.
        store_rows:   Output of ``store.source_health()``.
        supervisor:   Supervisor instance, or None.
        config_store: ConfigStore instance, or None.

    Returns:
        List of health entry dicts, one per installed plugin instance (or one
        grey fallback row per installed plugin with no known instances).
    """
    sup_map = _supervisor_map(supervisor)
    store_map = _store_health_map(store_rows)

    entries: list[SourceHealthEntry] = []
    for type_key, plugin in registry.items():
        try:
            meta = plugin.metadata()
        except Exception:
            # A failing plugin metadata() must not break the response for others.
            continue

        configured = _has_config(config_store, type_key)

        # Discover all real source_ids for this type from supervisor + store.
        # ADR-0031 §B: source_id defaults to type_key, but custom ids are allowed.
        # We must join by source_type to surface the actual running instance(s).
        instance_ids = _instance_ids_for_type(type_key, sup_map, store_map)

        if not instance_ids:
            # No running instance and no store rows — emit a single grey fallback
            # row keyed by type_key (installed-but-not-configured per ADR-0032 A).
            entries.append(_build_entry(
                type_key=type_key,
                source_id=type_key,
                meta=meta,
                store_row=None,
                sup_info={},
                configured=configured,
            ))
        else:
            for source_id in instance_ids:
                store_row = store_map.get((type_key, source_id))
                sup_info = sup_map.get((type_key, source_id), {})
                entries.append(_build_entry(
                    type_key=type_key,
                    source_id=source_id,
                    meta=meta,
                    store_row=store_row,
                    sup_info=sup_info,
                    configured=configured,
                ))

    return entries


def _build_entry(
    *,
    type_key: str,
    source_id: str,
    meta: Any,
    store_row: dict[str, Any] | None,
    sup_info: dict[str, Any],
    configured: bool,
) -> SourceHealthEntry:
    """Construct one health entry dict from resolved per-instance inputs.

    Args:
        type_key:   The plugin type key (source_type).
        source_id:  The actual instance name for this row.
        meta:       Plugin metadata (display_name, flavor).
        store_row:  The store health row for this instance, or None.
        sup_info:   The supervisor status dict for this instance (may be empty).
        configured: Whether the source has a config section.
    """
    event_count: int = store_row["event_count"] if store_row else 0
    last_event_at: str | None = store_row["last_event_at"] if store_row else None
    supervisor_state: str | None = sup_info.get("state")
    # NB-1 (issue #147): sanitize raw exception text before surfacing on GET /stats.
    # str(exc) can carry remote host/IP, port, credential field names, or SSH banners.
    last_error: str | None = _sanitize_error(sup_info.get("last_error"))

    # ADR-0032 Amendment 1 R2 — sync evidence fields (ADR-0031 §F).
    # last_sync_at is stored as epoch float by the supervisor; convert to ISO8601
    # for consistency with last_event_at on the same wire object.
    last_sync_at: str | None = _epoch_to_iso(sup_info.get("last_sync_at"))
    last_sync_status: str | None = sup_info.get("last_sync_status")
    last_sync_ingested: int = sup_info.get("last_sync_ingested") or 0

    health = _compute_health(
        has_config=configured,
        last_event_at=last_event_at,
        supervisor_state=supervisor_state,
        last_error=last_error,
    )

    return {
        "source_type": type_key,
        "source_id": source_id,
        "display_name": meta.display_name,
        "flavor": meta.flavor,
        "health": health,
        "supervisor_state": supervisor_state,
        "last_event_at": last_event_at,
        "event_count": event_count,
        "last_error": last_error,
        # R2 additive fields — sync evidence (ADR-0032 Amendment 1 R2 / ADR-0031 §F)
        "last_sync_at": last_sync_at,
        "last_sync_status": last_sync_status,
        "last_sync_ingested": last_sync_ingested,
    }
