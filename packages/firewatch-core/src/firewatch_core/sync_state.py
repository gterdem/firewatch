"""Durable last-sync stamp persistence (issue #707, ADR-0031 §F extension).

Provides two thin helpers that write/read the ``last_sync_*`` diagnostic
fields to/from the ``source_kv`` table so a process restart does NOT reset
them to ``None`` — which would cause the UI to display "Last sync: Never"
even for a source that has successfully ingested events.

Design notes
------------
* **Namespace**: ``_sync_state`` — leading underscore marks it as a core-
  reserved namespace (same convention as ``_global`` for rule_descriptions).
  Plugin ``ScopedKV`` views are bound to the plugin's ``source_type`` and
  use caller-supplied namespace strings; they cannot construct the key format
  used here, so there is no capability-isolation risk (ADR-0025 addendum).

* **Key format**: ``{source_id}:{field}`` — separates per-instance stamps
  within the same ``(source_type, namespace)`` scope so two instances of the
  same plugin type (e.g. ``suricata/pi-home`` and ``suricata/cloud``) each
  carry their own stamp without needing separate namespace rows per instance.

* **Fail-safe**: both helpers catch all store exceptions and log at WARNING.
  A failing KV write must never abort an ingest cycle (ADR-0003).

* **Cap safety**: each ``(source_type, _sync_state)`` scope uses exactly 4
  keys per ``source_id`` (``last_sync_at``, ``last_sync_ingested``,
  ``last_sync_status``, ``last_error``).  For any realistic number of
  instances this is orders of magnitude below ``SOURCE_KV_CAP`` (10 000).

Public API
----------
``_SYNC_NS``               — the reserved namespace name (exposed for tests).
``persist_sync_state(...)`` — write/update all 4 fields to the store.
``restore_sync_state(...)`` — read them back; returns ``None`` when absent.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("firewatch.supervisor.sync_state")

# Core-reserved KV namespace for last-sync diagnostics.
# Starting with '_' prevents collision with any valid plugin type_key
# (plugin keys match ^[a-z][a-z0-9_]*$ — they cannot start with '_').
_SYNC_NS: str = "_sync_state"


async def persist_sync_state(
    store: Any,
    source_type: str,
    source_id: str,
    ts: float,
    ingested: int,
    status: str,
    last_error: str | None,
) -> None:
    """Write/update the last-sync stamp for ``(source_type, source_id)`` to KV.

    Writes four keys under ``(source_type, _sync_state)``:
    - ``{source_id}:last_sync_at``        — epoch float as string
    - ``{source_id}:last_sync_ingested``   — int as string
    - ``{source_id}:last_sync_status``     — "ok" | "no_data" | "error"
    - ``{source_id}:last_error``           — error string, or "" when None

    Fail-safe (ADR-0003): any store exception is caught and logged at WARNING.
    This must never abort an ingest cycle.

    Parameters
    ----------
    store:
        The core EventStore (must implement ``source_kv_put``).
    source_type:
        Plugin ``type_key`` (e.g. ``"suricata"``).
    source_id:
        Instance name (e.g. ``"pi-home"``).
    ts:
        Wall-clock timestamp of the completed cycle (``time.time()``).
    ingested:
        Number of net-new rows inserted this cycle.
    status:
        ``"ok"``, ``"no_data"``, or ``"error"``.
    last_error:
        Error message when ``status == "error"``; ``None`` otherwise.
    """
    put = getattr(store, "source_kv_put", None)
    if put is None:
        return  # store does not implement source_kv — no-op (test or legacy store)

    try:
        await put(source_type, _SYNC_NS, f"{source_id}:last_sync_at", str(ts))
        await put(source_type, _SYNC_NS, f"{source_id}:last_sync_ingested", str(ingested))
        await put(source_type, _SYNC_NS, f"{source_id}:last_sync_status", status)
        await put(source_type, _SYNC_NS, f"{source_id}:last_error", last_error or "")
    except Exception:
        logger.warning(
            "sync_state.persist: failed for %s/%s — last_sync will revert to "
            "None on process restart (issue #707)",
            source_type, source_id,
            exc_info=True,
        )


async def restore_sync_state(
    store: Any,
    source_type: str,
    source_id: str,
) -> dict[str, Any] | None:
    """Read back the last-sync stamp for ``(source_type, source_id)`` from KV.

    Returns a dict with keys ``last_sync_at`` (float), ``last_sync_ingested``
    (int), ``last_sync_status`` (str), and ``last_error`` (str | None) when
    a stamp exists, or ``None`` when no stamp has ever been written.

    Fail-safe (ADR-0003): any store exception returns ``None`` (treated as
    "no prior stamp" — the first cycle will write a fresh stamp).

    Parameters
    ----------
    store:
        The core EventStore (must implement ``source_kv_get``).
    source_type:
        Plugin ``type_key``.
    source_id:
        Instance name.
    """
    get = getattr(store, "source_kv_get", None)
    if get is None:
        return None

    try:
        raw_ts = await get(source_type, _SYNC_NS, f"{source_id}:last_sync_at")
        if raw_ts is None:
            return None  # no stamp ever written for this instance

        raw_ingested = await get(source_type, _SYNC_NS, f"{source_id}:last_sync_ingested")
        raw_status = await get(source_type, _SYNC_NS, f"{source_id}:last_sync_status")
        raw_error = await get(source_type, _SYNC_NS, f"{source_id}:last_error")

        return {
            "last_sync_at": float(raw_ts),
            "last_sync_ingested": int(raw_ingested or "0"),
            "last_sync_status": raw_status or "ok",
            "last_error": raw_error if raw_error else None,
        }
    except Exception:
        logger.warning(
            "sync_state.restore: failed for %s/%s — treating as no prior stamp",
            source_type, source_id,
            exc_info=True,
        )
        return None
