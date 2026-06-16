"""Pure decision helpers for restart/backoff/storm and DLQ policy (ADR-0023).

These functions take an InstanceRecord and/or SupervisorConfig and return a
decision or computed value.  They perform NO I/O and hold NO orchestrator state,
making them independently unit-testable.

The orchestrator and runners call these helpers and then act on the result.

Helpers:
  - compute_backoff_sleep  — Full-Jitter sleep duration for a given attempt
  - should_park            — True when storm cap is exceeded
  - compute_record_key     — deterministic key for poison-record identity
  - track_record_failure   — increment failure counter and return (count, should_dlq)
  - build_storm_alert      — construct a storm_park SupervisorAlert
  - build_dlq_alert        — construct a dlq SupervisorAlert
"""
from __future__ import annotations

import random

from firewatch_sdk import RawEvent

from .config import SupervisorConfig
from .models import InstanceRecord, SupervisorAlert


def compute_backoff_sleep(cfg: SupervisorConfig, attempt: int) -> float:
    """Full-Jitter backoff sleep duration (ADR-0023 §C / AWS "Exponential Backoff And Jitter").

    Formula: ``sleep = random.uniform(0, min(backoff_cap, backoff_base * 2**attempt))``

    Args:
        cfg:     Supervisor configuration (backoff_base, backoff_cap).
        attempt: Current attempt count for the instance.

    Returns:
        Sleep duration in seconds (may be 0.0 when cap/base are both 0.0).
    """
    cap = min(cfg.backoff_cap, cfg.backoff_base * (2 ** attempt))
    return random.uniform(0.0, cap)


def should_park(rec: InstanceRecord, cfg: SupervisorConfig, now: float) -> tuple[bool, int]:
    """Evaluate the storm-cap threshold (ADR-0023 §D-revised / OTP max-restart-intensity).

    Args:
        rec: The instance record (crash_timestamps are read via crashes_in_window).
        cfg: Supervisor configuration (storm_threshold, storm_window_s).
        now: Current monotonic time.

    Returns:
        (park, crashes_in_window) — park=True when threshold is exceeded.
    """
    crashes = rec.crashes_in_window(now, cfg.storm_window_s)
    return crashes > cfg.storm_threshold, crashes


def compute_record_key(raw: RawEvent) -> str:
    """Compute a stable identity key for a raw record (ADR-0023 §D-revised).

    Key uses received_at + repr of data content hash for stable identity across
    retries: ``{iso_timestamp}:{hash(repr(sorted(data.items())))}``
    """
    return f"{raw.received_at.isoformat()}:{hash(repr(sorted(raw.data.items())))}"


def track_record_failure(
    rec: InstanceRecord,
    key: str,
    dlq_threshold: int,
    max_size: int,
) -> tuple[int, bool]:
    """Increment the failure counter for a record key; return (count, should_dlq).

    NB-5: evicts the oldest entry when record_failures is at capacity to prevent
    unbounded growth from a stream of distinct near-miss poison records.

    Args:
        rec:           The instance record whose record_failures dict is updated.
        key:           The stable record key (from compute_record_key).
        dlq_threshold: Failure count at which the record should be dead-lettered.
        max_size:      Maximum number of tracked keys (_RECORD_FAILURES_MAX_SIZE).

    Returns:
        (count, should_dlq) where should_dlq is True when count >= dlq_threshold.
    """
    if key not in rec.record_failures and len(rec.record_failures) >= max_size:
        oldest_key = next(iter(rec.record_failures))
        del rec.record_failures[oldest_key]

    rec.record_failures[key] = rec.record_failures.get(key, 0) + 1
    count = rec.record_failures[key]
    return count, count >= dlq_threshold


def build_storm_alert(
    source_type: str,
    source_id: str,
    crashes_in_window: int,
    cfg: SupervisorConfig,
) -> SupervisorAlert:
    """Construct a storm_park SupervisorAlert (ADR-0023 §D-revised)."""
    return SupervisorAlert(
        kind="storm_park",
        source_type=source_type,
        source_id=source_id,
        detail=(
            f"Instance parked after {crashes_in_window} crashes "
            f"in {cfg.storm_window_s:.0f}s window "
            f"(threshold={cfg.storm_threshold})"
        ),
    )


def build_dlq_alert(
    source_type: str,
    source_id: str,
    failure_count: int,
    watermark_ts: str,
    cfg: SupervisorConfig,
) -> SupervisorAlert:
    """Construct a dlq SupervisorAlert (ADR-0023 §D-revised)."""
    return SupervisorAlert(
        kind="dlq",
        source_type=source_type,
        source_id=source_id,
        detail=(
            f"Record dead-lettered after {failure_count} failures "
            f"(threshold={cfg.dlq_threshold}); "
            f"watermark advanced to {watermark_ts}"
        ),
    )
