"""Beaconing + rare-flow detection -- ML-10, issue #438.

Detects two complementary anomaly patterns for each src->dst flow:

1. **Beaconing (periodic check-ins)**: Measures the coefficient of variation (CV)
   of inter-arrival times between events in a flow.  Malware C2 beacons fire on a
   strict schedule; CV near 0 is the discriminant.

2. **Rare-flow (first-seen)**: Compares each (src_ip, dst_ip, dst_port) triple
   against the rolling ``flow_baseline`` table persisted in SQLite (EARS-3).  A
   combination absent from the baseline is flagged as a first-seen / rare flow.

Design constraints
------------------
- **Zero external I/O in the pure scorer.**  ``score_periodicity()`` is a pure
  function over a list of events -- safe to call anywhere in the pipeline.
- **Store-injected**: ``BeaconingDetector`` receives the store via ``__init__``
  (dependency-injection); it never imports the store as a singleton.
- **Extensible anomaly lane**: ``AnomalyVerdict.anomaly_type`` is an open string
  (not an enum) so ML-11 (volumetric exfil) can reuse the same lane, the same
  ``record_anomaly_verdict`` write path, and the same ``anomaly_type`` FilterSpec
  facet with zero changes to this module.
- **Provenance (EARS-4 / ADR-0035)**: every flagged verdict carries a
  ``flag_reason`` string that a narrator (R3) can cite verbatim.

References
----------
- Rossow et al. (2011). ``Sok: P2pwned -- Modeling and evaluating the resilience
  of peer-to-peer botnets``. IEEE S&P 2013. (CV as beaconing discriminant.)
- Bayer et al. (2009). ``Scalable, Behavior-Based Malware Clustering``. NDSS 2009.
  (Periodicity analysis in C2 traffic.)
- ADR-0035 (provenance tagging), ADR-0048 (destination_ip), issue #438 EARS.

Imports only stdlib and firewatch-sdk; never firewatch-core internal stores
directly at the module level (the store instance is injected by the caller).
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import TYPE_CHECKING

from firewatch_sdk.models import SecurityEvent

if TYPE_CHECKING:
    from firewatch_core.adapters.sqlite_store import SQLiteEventStore

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

#: CV at or below which a flow is considered periodic (beaconing).
#: Calibration: perfectly periodic traffic has CV=0; jittered C2 traffic
#: (real-world Cobalt Strike default) has CV ~0.05-0.15; random traffic has
#: CV >> 0.5.  Threshold 0.20 gives a comfortable margin below benign browsing
#: (which exhibits high CV from user-driven timing).
CV_THRESHOLD: float = 0.20

#: Minimum number of events in a flow required to compute a meaningful CV.
#: With fewer than 3 events we have at most 2 deltas, which is insufficient to
#: characterise variance.  Return None (degrade gracefully) instead of flagging.
MIN_EVENTS_FOR_CV: int = 3


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FlowKey:
    """Identifies a unidirectional flow: (src_ip, dst_ip, dst_port).

    ``dst_port`` may be None when the telemetry source does not populate it.
    The store treats (src_ip, dst_ip, None) as a valid key distinct from any
    numbered port.
    """

    src_ip: str
    dst_ip: str | None
    dst_port: int | None


@dataclass(frozen=True)
class PeriodicityResult:
    """Result of the periodicity (CV-based) beaconing check.

    Attributes
    ----------
    cv:
        Coefficient of variation of inter-arrival times (std / mean).
        Lower = more regular = more beaconing-like.
    mean_interval_sec:
        Mean inter-arrival time in seconds (for narration).
    n_deltas:
        Number of inter-arrival deltas analysed.
    flagged:
        True iff cv <= CV_THRESHOLD and n_deltas >= MIN_EVENTS_FOR_CV - 1.
    flag_reason:
        Human-readable explanation of why the flow was flagged (None if not flagged).
        Designed for R3 narration (EARS-4 / ADR-0035).
    """

    cv: float
    mean_interval_sec: float
    n_deltas: int
    flagged: bool
    flag_reason: str | None


@dataclass(frozen=True)
class AnomalyVerdict:
    """Verdict for a single anomaly detection (beaconing or rare-flow).

    ``anomaly_type`` is an open string -- not an enum -- so future anomaly
    detectors (ML-11 volumetric exfil, etc.) can reuse the same lane without
    modifying this module.

    Attributes
    ----------
    flow_key:
        The (src_ip, dst_ip, dst_port) triple this verdict applies to.
    flagged:
        True iff the anomaly was detected.
    anomaly_type:
        String tag for the anomaly class (e.g. "beaconing", "rare_flow").
        None when flagged=False.
    flag_reason:
        Provenance string suitable for R3 narration (EARS-4). None when
        flagged=False.
    """

    flow_key: FlowKey
    flagged: bool
    anomaly_type: str | None
    flag_reason: str | None


# ---------------------------------------------------------------------------
# Pure scorer -- zero I/O
# ---------------------------------------------------------------------------


def score_periodicity(events: list[SecurityEvent]) -> PeriodicityResult | None:
    """Score a sequence of events for timing-delta regularity (beaconing).

    Parameters
    ----------
    events:
        List of SecurityEvent objects **for a single flow** (same src/dst).
        Must be in any order; they are sorted by timestamp internally.
        May be from any telemetry source -- the function operates only on
        ``event.timestamp``.

    Returns
    -------
    PeriodicityResult
        CV and flagging decision.  ``flagged=True`` iff the flow appears
        periodic (CV <= CV_THRESHOLD and sufficient data).
    None
        Returned when there are fewer than ``MIN_EVENTS_FOR_CV`` events
        (insufficient deltas to characterise variance).  Callers must treat
        None as "indeterminate / insufficient data", not as "not beaconing".

    Notes
    -----
    CV = std(deltas) / mean(deltas) where deltas are sorted inter-arrival
    times in seconds.  When mean is 0 (all events at the same timestamp),
    CV is defined as 0 (perfectly periodic by degenerate definition -- but
    this should not occur in practice with real telemetry).

    References
    ----------
    Rossow et al. (IEEE S&P 2013): CV is the primary discriminant for
    C2 beacon regularity, outperforming spectral analysis for short flows.
    """
    if len(events) < MIN_EVENTS_FOR_CV:
        return None

    sorted_events = sorted(events, key=lambda e: e.timestamp)
    deltas = [
        (sorted_events[i + 1].timestamp - sorted_events[i].timestamp).total_seconds()
        for i in range(len(sorted_events) - 1)
    ]

    if not deltas:
        return None

    mean = statistics.mean(deltas)
    if mean == 0.0:
        # All events at the same timestamp -- degenerate case, cv=0
        cv = 0.0
    else:
        std = statistics.stdev(deltas) if len(deltas) >= 2 else 0.0
        cv = std / mean

    flagged = cv <= CV_THRESHOLD
    if flagged:
        flag_reason = (
            f"Periodic check-in detected: CV={cv:.4f} (threshold={CV_THRESHOLD}), "
            f"mean_interval={mean:.1f}s, n_deltas={len(deltas)}"
        )
    else:
        flag_reason = None

    return PeriodicityResult(
        cv=cv,
        mean_interval_sec=mean,
        n_deltas=len(deltas),
        flagged=flagged,
        flag_reason=flag_reason,
    )


# ---------------------------------------------------------------------------
# Store-injected detector
# ---------------------------------------------------------------------------


class BeaconingDetector:
    """Runs beaconing and rare-flow checks against persisted baseline state.

    The detector is stateless beyond the injected store reference.  It is
    designed to be instantiated per analysis cycle (or as a singleton with
    a shared store), depending on the caller's lifecycle model.

    Parameters
    ----------
    store:
        An ``SQLiteEventStore`` instance (or any object exposing
        ``upsert_flow_baseline``, ``get_flow_baseline_entry``).
        Never imported at module level -- injected by the caller.
    """

    def __init__(self, store: "SQLiteEventStore") -> None:
        self._store = store

    async def check_rare_flow(self, event: SecurityEvent) -> AnomalyVerdict:
        """Check whether (src_ip, dst_ip, dst_port) is new vs. the baseline.

        Parameters
        ----------
        event:
            A single SecurityEvent to check.  If ``destination_ip`` is None,
            the check degrades gracefully: the event cannot be keyed on a
            destination so it is never flagged as rare (not an error).

        Returns
        -------
        AnomalyVerdict
            ``flagged=True`` with ``anomaly_type="rare_flow"`` when the
            combination is absent from the ``flow_baseline`` table.
            ``flagged=False`` when the dst_ip is None or the combination is
            already known.
        """
        dst_ip = event.destination_ip
        dst_port = event.destination_port
        src_ip = event.source_ip

        flow_key = FlowKey(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port)

        # NULL destination_ip: cannot form a meaningful flow key -- degrade
        if dst_ip is None:
            return AnomalyVerdict(
                flow_key=flow_key,
                flagged=False,
                anomaly_type=None,
                flag_reason=None,
            )

        existing = await self._store.get_flow_baseline_entry(src_ip, dst_ip, dst_port)

        if existing is None:
            port_str = str(dst_port) if dst_port is not None else "?"
            flag_reason = (
                f"First-seen flow: {src_ip} -> {dst_ip}:{port_str} "
                f"(not in rolling baseline)"
            )
            return AnomalyVerdict(
                flow_key=flow_key,
                flagged=True,
                anomaly_type="rare_flow",
                flag_reason=flag_reason,
            )

        return AnomalyVerdict(
            flow_key=flow_key,
            flagged=False,
            anomaly_type=None,
            flag_reason=None,
        )

    async def detect(self, events: list[SecurityEvent]) -> list[AnomalyVerdict]:
        """Run both beaconing and rare-flow checks on the provided events.

        Operates on all distinct (src_ip, dst_ip, dst_port) flows present in
        the event list.  For each flow:

        1. **Beaconing**: calls ``score_periodicity()`` on flow-grouped events.
           A ``flagged=True`` result produces an ``AnomalyVerdict`` with
           ``anomaly_type="beaconing"``.

        2. **Rare-flow**: calls ``check_rare_flow()`` on the first event of
           each flow (the key is derived from the flow, not from one event).

        Events with ``destination_ip=None`` are skipped for flow grouping
        (no flow key can be derived).

        Parameters
        ----------
        events:
            List of SecurityEvent objects to analyse.  May be from any source
            and may span multiple flows.

        Returns
        -------
        list[AnomalyVerdict]
            All flagged verdicts (beaconing + rare_flow, across all flows).
            Empty when no anomalies are detected or when events is empty.
        """
        if not events:
            return []

        # Group events by (src_ip, dst_ip, dst_port) flow key.
        # Events with NULL destination_ip are skipped.
        flow_groups: dict[tuple[str, str | None, int | None], list[SecurityEvent]] = {}
        for ev in events:
            if ev.destination_ip is None:
                continue
            key = (ev.source_ip, ev.destination_ip, ev.destination_port)
            flow_groups.setdefault(key, []).append(ev)

        verdicts: list[AnomalyVerdict] = []

        for (src_ip, dst_ip, dst_port), flow_events in flow_groups.items():
            flow_key = FlowKey(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port)

            # --- Beaconing check (pure, sync) ---
            periodicity = score_periodicity(flow_events)
            if periodicity is not None and periodicity.flagged:
                verdicts.append(AnomalyVerdict(
                    flow_key=flow_key,
                    flagged=True,
                    anomaly_type="beaconing",
                    flag_reason=periodicity.flag_reason,
                ))

            # --- Rare-flow check (async, store-backed) ---
            # Use the first event of the flow as the representative
            rare_verdict = await self.check_rare_flow(flow_events[0])
            if rare_verdict.flagged:
                verdicts.append(rare_verdict)

        return verdicts
