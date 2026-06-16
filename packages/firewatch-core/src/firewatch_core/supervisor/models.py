"""Domain models, enums, and shared dataclasses for the supervisor (ADR-0023).

Kept cohesive in one place: all other modules import from here rather than
each holding a fragment of the shared record type.

Symbols:
  - InstanceState — lifecycle state enum
  - BackpressurePolicy — per-transport policy enum
  - _TRANSPORT_POLICY / _policy_for_transport — policy lookup
  - DLQEntry — dead-lettered record
  - InstanceRecord — runtime tracking for one supervised instance
  - SupervisorAlert — structured alert
  - PoisonRecordError — exception raised by callers
  - _RECORD_FAILURES_MAX_SIZE — internal cap constant
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum

from pydantic import BaseModel

from firewatch_sdk import RawEvent
from firewatch_sdk.ports import SourcePlugin


# NB-5: cap on record_failures per instance to prevent unbounded memory growth from
# a stream of distinct near-miss poison records that never reach dlq_threshold.
_RECORD_FAILURES_MAX_SIZE: int = 1024


# --------------------------------------------------------------------------- #
# Enums                                                                        #
# --------------------------------------------------------------------------- #


class InstanceState(Enum):
    """Lifecycle state of a supervised source instance.

    IDLE    — registered/configured, not scheduled (auto-sync OFF). Manual Sync
              works against an IDLE instance. ADR-0031 §C.
    RUNNING — scheduled pull loop or active push listener running.
    BACKOFF — pull loop crashed; waiting for full-jitter sleep before restart.
    PARKED  — storm-cap exceeded; requires operator action to resume.
    STOPPED — terminal (shutdown, cancellation, or never started).
    """

    IDLE = "idle"
    RUNNING = "running"
    BACKOFF = "backoff"
    PARKED = "parked"
    STOPPED = "stopped"


class BackpressurePolicy(Enum):
    """Per-transport backpressure policy (ADR-0023 §Steals).

    UDP  → Drop-newest + increment dropped counter (UDP is inherently lossy; blocking
           would stall the event loop and starve all sources).
    TCP  → Block / stop-reading (TCP has flow control; backpressure propagates upstream).
    FILE → Block (file offset is a natural cursor; no data loss from blocking read).
    """

    DROP = "drop"    # UDP: discard when queue full
    BLOCK = "block"  # TCP/file: apply backpressure upstream


_TRANSPORT_POLICY: dict[str, BackpressurePolicy] = {
    "udp": BackpressurePolicy.DROP,
    "tcp": BackpressurePolicy.BLOCK,
    "file": BackpressurePolicy.BLOCK,
}


def _policy_for_transport(transport: str) -> BackpressurePolicy:
    """Return the correct backpressure policy for a transport string (ADR-0023 §Steals).

    Unrecognized transports default to BLOCK (safe conservative choice).
    """
    return _TRANSPORT_POLICY.get(transport.lower(), BackpressurePolicy.BLOCK)


# --------------------------------------------------------------------------- #
# Dataclasses                                                                  #
# --------------------------------------------------------------------------- #


@dataclass
class DLQEntry:
    """A dead-lettered record (ADR-0023 §D-revised).

    Holds the raw event that was dead-lettered, the source instance that produced it,
    and the failure count that triggered dead-lettering.
    """

    raw: RawEvent
    source_type: str
    source_id: str
    failure_count: int
    dead_lettered_at: float = field(default_factory=time.monotonic)


@dataclass
class InstanceRecord:
    """Runtime tracking for one supervised source instance (pull or push).

    The ``last_known_good_cfg`` seam (ADR-0023 §Steals / OpAMP last-known-good):
    when config is reloaded, the new config is validated against the plugin; if
    it passes, ``cfg`` is updated and ``last_known_good_cfg`` is set.  If the new
    config fails, ``cfg`` falls back to ``last_known_good_cfg`` and the reload is
    rejected with a warning.
    """

    source_id: str
    plugin: SourcePlugin
    cfg: BaseModel
    last_known_good_cfg: BaseModel
    flavor: str              # "pull" or "push"
    transport: str = "tcp"   # for push instances: "udp" | "tcp" | "file"
    state: InstanceState = InstanceState.STOPPED
    task: asyncio.Task[None] | None = None

    # Backoff tracking (ADR-0023 §C)
    attempt: int = 0         # resets to 0 on successful cycle
    last_success_at: float = field(default_factory=time.monotonic)

    # Storm-cap tracking (ADR-0023 §D-revised)
    crash_timestamps: deque[float] = field(default_factory=deque)

    # DLQ tracking: record_key → failure_count (ADR-0023 §D-revised)
    # record_key is derived from the raw event's deterministic identity
    record_failures: dict[str, int] = field(default_factory=dict)

    # Pull interval (seconds) — only meaningful for pull instances (NB-4: explicit field)
    _pull_interval: float = 60.0

    # Metrics / observability
    total_crashes: int = 0
    total_dlq: int = 0
    dropped_count: int = 0   # UDP backpressure drops
    # Push-path consecutive ingest failure counter (NB-3: feeds storm cap, resets on success)
    push_ingest_failures: int = 0

    # Last-sync facts (ADR-0031 §F) — updated after every pull cycle (manual or scheduled).
    # Exposed read-only via InstanceStatus DTO; never mutated by the API layer directly.
    last_sync_at: float | None = None           # wall-clock of last completed cycle
    last_sync_ingested: int = 0                 # events ingested on that cycle
    last_sync_status: str | None = None         # "ok" | "no_data" | "error"
    last_error: str | None = None               # error message when last_sync_status="error"

    def record_crash(self, now: float) -> None:
        """Record a crash timestamp.

        No in-place purge is performed here: the configured storm_window_s may differ
        from any hard-coded value, so purging here with a fixed window would cause the
        storm cap to undercount when storm_window_s > 60s.  The correct filtering is
        always done in crashes_in_window() with the actual configured window.
        """
        self.crash_timestamps.append(now)
        self.total_crashes += 1

    def crashes_in_window(self, now: float, window_s: float) -> int:
        """Count crashes in the rolling window [now-window_s, now].

        NB-C: prune timestamps that are older than the window after counting so
        the deque stays bounded.  Timestamps still inside the window are never
        dropped, so the storm-cap logic remains correct regardless of
        storm_window_s.
        """
        cutoff = now - window_s
        count = sum(1 for t in self.crash_timestamps if t >= cutoff)
        # Prune from the left: deque is append-right (oldest first), so pop from
        # the left until the front timestamp is within the window.
        while self.crash_timestamps and self.crash_timestamps[0] < cutoff:
            self.crash_timestamps.popleft()
        return count


# --------------------------------------------------------------------------- #
# Alert model                                                                  #
# --------------------------------------------------------------------------- #


class SupervisorAlert(BaseModel):
    """A structured alert emitted by the supervisor for operator visibility.

    Two alert kinds (ADR-0023 §D-revised):
    - ``storm_park``: instance parked due to restart storm.
    - ``dlq``: a poison record was dead-lettered and the watermark advanced.

    Alerts are always logged (never silent); sending to the notifier is best-effort.
    """

    kind: str          # "storm_park" | "dlq"
    source_type: str
    source_id: str
    detail: str


# --------------------------------------------------------------------------- #
# PoisonRecordError                                                             #
# --------------------------------------------------------------------------- #


class PoisonRecordError(Exception):
    """Raised to signal that a specific raw record caused a processing failure.

    The supervisor's DLQ path (ADR-0023 §D-revised) catches this and calls
    ``_handle_poison_record`` to track failure counts. After ``dlq_threshold``
    failures on the same record, it is dead-lettered and the watermark is advanced.

    Usage (in a wrapper around run_pull_cycle or ingest)::

        raise PoisonRecordError(raw=the_raw_event) from original_exc
    """

    def __init__(self, raw: RawEvent, message: str = "") -> None:
        self.raw = raw
        super().__init__(message or f"poison record at {raw.received_at.isoformat()}")
