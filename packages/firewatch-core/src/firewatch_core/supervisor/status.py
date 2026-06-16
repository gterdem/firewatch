"""Read-only InstanceStatus DTO for the supervisor public surface (MB.4, issue #56).

This module defines the stable, frozen DTO that the API layer consumes.
The API MUST only read instance state through ``Supervisor.status()`` — it must
NEVER reach into ``InstanceRecord``, ``InstanceState``, or any private supervisor
field. This is the EARS ubiquitous criterion for #56.

``InstanceStatus`` is intentionally minimal — it carries the safe observable
fields only. The mutable ``InstanceRecord`` with its asyncio task references,
plugin instance, and internal queues stays entirely internal.

ADR references:
  - ADR-0023: supervisor lifecycle/state; ``InstanceRecord`` fields.
  - ADR-0029: the API reads instance state via this DTO, not raw internals.
  - ADR-0031 §F: last-sync surfacing fields added (last_sync_at, last_sync_ingested,
    last_sync_status, last_error).
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class InstanceStatus(BaseModel):
    """Read-only snapshot of a supervised source instance's observable state.

    Frozen (immutable) — callers cannot mutate a returned DTO.
    The API maps this directly to the per-instance block in GET /sources.

    Fields
    ------
    source_type : str
        The plugin's ``type_key`` (e.g. ``"suricata"``).
    source_id : str
        The user-assigned instance name (e.g. ``"pi-home"``). ADR-0016.
    flavor : str
        ``"pull"`` or ``"push"``.
    state : str
        One of ``"idle"`` | ``"running"`` | ``"backoff"`` | ``"parked"`` | ``"stopped"``.
        String projection of ``InstanceState`` enum value.  ``"idle"`` = registered/
        configured, not scheduled (auto-sync OFF). ADR-0031 §C.
    attempt : int
        Current restart attempt counter. Resets to 0 on a successful cycle
        (ADR-0023 §C). Exposed for UI diagnostics.
    total_crashes : int
        Lifetime crash count for this instance. Never resets.
    total_dlq : int
        Number of records that were dead-lettered for this instance
        (ADR-0023 §D-revised).
    dropped_count : int
        UDP backpressure drop counter — incremented when a UDP push instance
        is at capacity and discards an incoming datagram (ADR-0023 §Steals).
        Always 0 for pull and TCP push instances.
    last_success_at : float
        ``time.monotonic()`` timestamp of the last successful pull cycle or
        push listener start. Useful for staleness detection in the UI.
    last_sync_at : float | None
        Wall-clock (``time.time()``) of the last completed pull cycle
        (manual or scheduled). None before the first cycle. ADR-0031 §F.
    last_sync_ingested : int
        Number of events ingested on the last completed cycle. 0 before
        the first cycle or when the cycle produced no events. ADR-0031 §F.
    last_sync_status : str | None
        Outcome of the last completed cycle: ``"ok"`` (events ingested),
        ``"no_data"`` (cycle ran but no events), ``"error"`` (exception).
        None before the first cycle. ADR-0031 §F.
    last_error : str | None
        Error message when ``last_sync_status == "error"``, else None.
        ADR-0031 §F.
    """

    model_config = {"frozen": True}

    source_type: str
    source_id: str
    flavor: str
    state: Literal["idle", "running", "backoff", "parked", "stopped"]
    attempt: int
    total_crashes: int
    total_dlq: int
    dropped_count: int
    last_success_at: float

    # ADR-0031 §F: last-sync surfacing
    last_sync_at: float | None = None
    last_sync_ingested: int = 0
    last_sync_status: Literal["ok", "no_data", "error"] | None = None
    last_error: str | None = None
