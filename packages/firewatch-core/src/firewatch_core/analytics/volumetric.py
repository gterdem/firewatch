"""Volumetric / exfil outlier detection — ML-11, issue #439.

Detects per-(src->dst) byte volume anomalies relative to a rolling per-flow
baseline using Welford's online algorithm for running mean and variance.

Design constraints
------------------
- **Zero external I/O in the pure scorer.**  ``score_volumetric()`` is a pure
  function over numeric statistics — safe to call anywhere in the pipeline.
- **Store-injected**: ``VolumetricDetector`` receives the store via ``__init__``
  (dependency-injection); it never imports the store as a singleton.
- **NULL-byte skip (EARS-2)**: events with both ``bytes_in`` and ``bytes_out``
  set to ``None`` (e.g. Azure WAF rows) are skipped honestly with
  ``flagged=False`` — no false flag, no crash.
- **Extensible anomaly lane (EARS-3)**: writes ``anomaly_type="volumetric_exfil"``
  to the same ``anomaly_verdicts`` table used by ML-10 (beaconing/rare_flow).
  The ``FilterSpec.anomaly_type`` facet and ``anomaly_flags`` badge surface
  work unchanged — zero schema or contract changes required.
- **Provenance (ADR-0035)**: every flagged verdict carries a ``flag_reason``
  string that a narrator (R3 / ML-7) can cite verbatim.

Algorithm
---------
Welford's online algorithm (Welford 1962) accumulates a running mean and M2
(sum of squared deviations) for each flow's byte volume.  At read time:

    stdev = sqrt(M2 / (n - 1))   # sample standard deviation
    z     = (observed - mean) / stdev

A verdict fires when z > ``OUTLIER_Z_THRESHOLD`` and the baseline has at
least ``MIN_BASELINE_SAMPLES`` observations.  The update step runs on every
event (including the outlier), so the baseline continuously incorporates new
observations — the detector self-adapts to sustained high-volume traffic.

References
----------
- Welford (1962). "Note on a method for calculating corrected sums of squares
  and products." Technometrics, 4(3), 419-420.  (Online mean/variance algorithm.)
- Chandola, Banerjee & Kumar (2009). "Anomaly Detection: A Survey". ACM CSUR.
  (Z-score method for univariate outlier detection.)
- ADR-0035 (provenance tagging), ADR-0048 (bytes_in/bytes_out fields), issue #439 EARS.

Imports only stdlib and firewatch-sdk; never firewatch-core internal stores
directly at the module level (the store instance is injected by the caller).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING

from firewatch_sdk.models import SecurityEvent

if TYPE_CHECKING:
    from firewatch_core.adapters.sqlite_store import SQLiteEventStore
    from firewatch_core.analytics.beaconing import AnomalyVerdict

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

#: Z-score threshold above which a flow's byte volume is flagged as an outlier.
#: Calibration: z=3 corresponds to the 99.87th percentile of a normal
#: distribution, meaning ~0.13% of observations from a well-behaved flow are
#: expected to exceed it under the Gaussian assumption.  This is the standard
#: "3-sigma rule" used in statistical process control (ref: Chandola et al.).
OUTLIER_Z_THRESHOLD: float = 3.0

#: Minimum number of per-flow byte observations required before the detector
#: will evaluate outliers.  Below this the baseline is not yet stable enough
#: to produce a low false-positive rate.
#:
#: Calibration: 30 is the conventional minimum for the Central Limit Theorem
#: to apply to sample statistics.  Fewer samples produce unreliable variance
#: estimates, which inflate false-positive rates.
MIN_BASELINE_SAMPLES: int = 30


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VolumetricResult:
    """Result of the volumetric outlier scorer.

    Attributes
    ----------
    observed_bytes:
        The byte count that was evaluated (bytes_in + bytes_out, or whichever
        was non-null).
    baseline_mean:
        Per-flow running mean at the time of evaluation.
    baseline_stdev:
        Per-flow running sample standard deviation at evaluation time.
    z_score:
        Standardised distance of ``observed_bytes`` from ``baseline_mean``
        in units of ``baseline_stdev``.  Higher = more anomalous.
    flagged:
        True iff ``z_score > OUTLIER_Z_THRESHOLD`` and the baseline had
        sufficient observations.
    flag_reason:
        Human-readable explanation of why the flow was flagged (None if not
        flagged).  Designed for R3 narration (ADR-0035).
    """

    observed_bytes: int
    baseline_mean: float
    baseline_stdev: float
    z_score: float
    flagged: bool
    flag_reason: str | None


# ---------------------------------------------------------------------------
# Pure scorer — zero I/O
# ---------------------------------------------------------------------------


def score_volumetric(
    *,
    observed_bytes: int | None,
    baseline_mean: float,
    baseline_stdev: float,
    n_samples: int,
) -> VolumetricResult | None:
    """Score a byte count against a per-flow baseline for volumetric outliers.

    Parameters
    ----------
    observed_bytes:
        The total bytes observed for this event.  ``None`` means the sensor
        did not emit byte counters (e.g. Azure WAF); returns ``None`` (skip).
    baseline_mean:
        Running mean bytes for this (src, dst_ip, dst_port) flow.
    baseline_stdev:
        Running sample standard deviation for this flow.
    n_samples:
        Number of observations accumulated in the baseline so far.

    Returns
    -------
    VolumetricResult
        Scoring result including z-score and flagging decision.
    None
        Returned when:
        - ``observed_bytes`` is ``None`` (skip, EARS-2).
        - ``n_samples < MIN_BASELINE_SAMPLES`` (baseline not yet stable).
        - ``baseline_stdev == 0`` (all prior values identical; z undefined).

    Notes
    -----
    The z-score formula is ``z = (observed - mean) / stdev``.  Only values
    above the baseline mean are flagged (exfiltration is a one-sided anomaly:
    sending far more data than usual is the concern; sending less is not).
    """
    if observed_bytes is None:
        return None

    if n_samples < MIN_BASELINE_SAMPLES:
        return None

    if baseline_stdev == 0.0 or not math.isfinite(baseline_stdev):
        # Cannot compute a meaningful z-score when variance is zero.
        return None

    z = (observed_bytes - baseline_mean) / baseline_stdev
    # One-sided test: exfil is characterised by excess outbound volume.
    flagged = z > OUTLIER_Z_THRESHOLD

    flag_reason: str | None
    if flagged:
        flag_reason = (
            f"Volumetric outlier: bytes={observed_bytes} "
            f"z={z:.2f} (threshold={OUTLIER_Z_THRESHOLD}); "
            f"baseline mean={baseline_mean:.1f} stdev={baseline_stdev:.1f} "
            f"n={n_samples}"
        )
    else:
        flag_reason = None

    return VolumetricResult(
        observed_bytes=observed_bytes,
        baseline_mean=baseline_mean,
        baseline_stdev=baseline_stdev,
        z_score=z,
        flagged=flagged,
        flag_reason=flag_reason,
    )


# ---------------------------------------------------------------------------
# Store-injected detector
# ---------------------------------------------------------------------------


class VolumetricDetector:
    """Runs per-flow byte-volume outlier detection against persisted baseline stats.

    The detector is stateless beyond the injected store reference.  It is
    designed to be instantiated per analysis cycle (or as a singleton with
    a shared store), depending on the caller's lifecycle model.

    Uses ``bytes_in + bytes_out`` as the combined byte volume metric.  When
    only one of the two is available, that value alone is used.  When both
    are ``None``, the event is skipped honestly (EARS-2).

    Parameters
    ----------
    store:
        An ``SQLiteEventStore`` instance (or any object exposing
        ``upsert_flow_baseline_bytes``, ``get_flow_baseline_bytes``, and
        ``record_anomaly_verdict``).
        Never imported at module level — injected by the caller.
    """

    def __init__(self, store: "SQLiteEventStore") -> None:
        self._store = store

    def _total_bytes(self, event: SecurityEvent) -> int | None:
        """Compute the combined byte volume for this event.

        Returns ``bytes_in + bytes_out``, using 0 for a ``None`` side when
        the other side is non-null.  Returns ``None`` only when BOTH fields
        are ``None`` (i.e. the sensor did not emit any byte counters).
        """
        b_in = event.bytes_in
        b_out = event.bytes_out
        if b_in is None and b_out is None:
            return None
        return (b_in or 0) + (b_out or 0)

    async def check_volumetric(self, event: SecurityEvent) -> "AnomalyVerdict":
        """Check whether this event's byte volume is anomalous vs. its flow baseline.

        Reads the current per-flow byte stats from the store, evaluates the
        z-score, then updates the baseline with the new observation (including
        outliers, so the baseline adapts to sustained high-volume traffic).

        Parameters
        ----------
        event:
            A single SecurityEvent to evaluate.  If ``bytes_in`` and
            ``bytes_out`` are both ``None``, the check degrades gracefully:
            no baseline is updated and ``flagged=False`` is returned.

        Returns
        -------
        AnomalyVerdict
            ``flagged=True`` with ``anomaly_type="volumetric_exfil"`` when
            the z-score exceeds the threshold and the baseline is stable.
            ``flagged=False`` when bytes are NULL, the baseline is not yet
            stable, or the z-score is below the threshold.
        """
        from firewatch_core.analytics.beaconing import AnomalyVerdict, FlowKey

        src_ip = event.source_ip
        dst_ip = event.destination_ip
        dst_port = event.destination_port

        flow_key = FlowKey(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port)

        total = self._total_bytes(event)

        # EARS-2: NULL bytes — skip honestly.
        if total is None:
            return AnomalyVerdict(
                flow_key=flow_key,
                flagged=False,
                anomaly_type=None,
                flag_reason=None,
            )

        # Read current baseline stats for this flow.
        stats = await self._store.get_flow_baseline_bytes(src_ip, dst_ip, dst_port)

        verdict: AnomalyVerdict
        if stats is not None and stats["bytes_count"] >= MIN_BASELINE_SAMPLES:
            baseline_mean: float = stats["bytes_in_mean"] + stats["bytes_out_mean"]
            baseline_m2: float = stats["bytes_in_m2"] + stats["bytes_out_m2"]
            n: int = stats["bytes_count"]
            # Sample standard deviation from Welford M2 accumulator.
            baseline_stdev = math.sqrt(baseline_m2 / (n - 1)) if n > 1 else 0.0

            result = score_volumetric(
                observed_bytes=total,
                baseline_mean=baseline_mean,
                baseline_stdev=baseline_stdev,
                n_samples=n,
            )

            if result is not None and result.flagged:
                verdict = AnomalyVerdict(
                    flow_key=flow_key,
                    flagged=True,
                    anomaly_type="volumetric_exfil",
                    flag_reason=result.flag_reason,
                )
            else:
                verdict = AnomalyVerdict(
                    flow_key=flow_key,
                    flagged=False,
                    anomaly_type=None,
                    flag_reason=None,
                )
        else:
            # Baseline not yet stable — no verdict.
            verdict = AnomalyVerdict(
                flow_key=flow_key,
                flagged=False,
                anomaly_type=None,
                flag_reason=None,
            )

        # Always update the baseline (Welford step) — even for outliers,
        # so the baseline adapts to sustained high-volume traffic.
        await self._store.upsert_flow_baseline_bytes(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            bytes_in=event.bytes_in,
            bytes_out=event.bytes_out,
        )

        return verdict

    async def detect(self, events: list[SecurityEvent]) -> list["AnomalyVerdict"]:
        """Run volumetric outlier detection on the provided events.

        For each event that carries byte counters, evaluates the byte volume
        against the per-(src, dst_ip, dst_port) rolling baseline and returns
        flagged verdicts.  Events with NULL bytes are silently skipped (EARS-2).

        Parameters
        ----------
        events:
            List of SecurityEvent objects to analyse.  May span multiple flows.

        Returns
        -------
        list[AnomalyVerdict]
            All flagged volumetric verdicts.  Empty when no anomalies are
            detected, events is empty, or all events have NULL bytes.
        """
        if not events:
            return []

        verdicts: list["AnomalyVerdict"] = []
        for ev in events:
            verdict = await self.check_volumetric(ev)
            if verdict.flagged:
                verdicts.append(verdict)
        return verdicts



