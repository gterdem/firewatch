"""The attempt predicate and the decayed intensity estimator (ADR-0070 Revision 1 D1/D2).

Pure math — no I/O, no store access, no hidden wall-clock reads (every function that
needs "now" takes it as an explicit argument). This is the ONE home for both the D1
attempt predicate and the intensity fold: ``detector.py``'s R1 ``attempt_pressure``
rule and any future banner/presentation code (issue #55) call into this module so
neither ever counts an actor's attempts differently (ADR-0070 "Module shape").

D1 — the attempt predicate
───────────────────────────
An event is a **hostile attempt** iff ``action ∈ {BLOCK, DROP, ALERT}`` and NOT
(``action == ALERT`` and ``severity == "info"``). ``severity=None`` counts (an
asserting event with no declared level is still an assertion — fail-quiet maps
unknown severity to ``low``, ADR-0069 D3.4). LOG (telemetry, ECS ``kind:event`` —
nothing asserted anything) and ALLOW (possible success, Tier-1 territory) never
count.

D2 — the intensity estimator
─────────────────────────────
For an actor with attempt timestamps t1 <= ... <= tn, the attempt intensity at
time t is the exponentially-decayed attempt count::

    lambda_hat(t) = sum(exp(-beta * (t - t_i)) for t_i <= t)

with half-life ``H`` (``beta = ln(2) / H``). Read it as "how many attempts' worth
of pressure is on this actor right now": one attempt contributes 1 immediately,
1/2 after one half-life, 1/4 after two. The fold is evaluated with the Ogata
(1981) O(1)-per-event recursion (the deterministic evaluation half of a Hawkes
self-exciting process, Hawkes 1971) — this is explicitly NOT a fitted Hawkes
process: no background rate, no branching ratio, no parameter estimation. See
ADR-0070 D2/D9 and the ADR's References section for full attribution.

Named constants (D5 — provisional, NOT operator-tunable, ADR-0070 D6)
───────────────────────────────────────────────────────────────────────
``HALF_LIFE`` (H) and ``PRESSURE_THRESHOLD`` (theta_press) below are engineering
estimates awaiting the ADR-0068 D3 live-calibration pass, not settled/calibrated
values — mirrored into the #50 volume-oracle manifest as the ledger of record for
the numbers (ADR-0068 D2 manifest discipline) once that manifest exists.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta

from firewatch_sdk import SecurityEvent

# ── Named constants (ADR-0070 D5) ────────────────────────────────────────────
# Code-declared only — NOT exposed via config/env/settings card (ADR-0070 D6):
# this preserves the "cannot be misconfigured into missing a breach" property
# the three named triage thresholds already have (ADR-0059).

HALF_LIFE = timedelta(minutes=30)
"""H — the intensity decay half-life. Maintainer's fade intuition ("stops after
60 minutes ... fade slowly"): pressure halves twice within the hour after
cessation (ADR-0070 D5)."""

PRESSURE_THRESHOLD = 5
"""theta_press — the R1 ``attempt_pressure`` firing threshold. Approximately the
decayed mass of a fail2ban ``maxretry``-scale burst (ADR-0070 D5)."""


# ── D1 — the attempt predicate ───────────────────────────────────────────────


def is_attempt(event: SecurityEvent) -> bool:
    """A hostile attempt iff ``action in {BLOCK, DROP, ALERT}`` and NOT
    (``action == "ALERT"`` and ``severity == "info"``). ``severity=None`` counts.
    """
    if event.action not in ("BLOCK", "DROP", "ALERT"):
        return False
    return not (event.action == "ALERT" and event.severity == "info")


def _attempt_timestamps(events: list[SecurityEvent]) -> list[datetime]:
    """Sorted timestamps of the D1-qualifying events in *events*."""
    return sorted(e.timestamp for e in events if is_attempt(e))


# ── D2 — the intensity fold ──────────────────────────────────────────────────


def _decay_fold(sorted_ts: list[datetime], beta: float) -> list[float]:
    """Ogata (1981) O(1)-per-event recursion.

    Returns, for each timestamp in ``sorted_ts`` (ascending), lambda_hat
    evaluated immediately AFTER that attempt — i.e. the decayed sum of every
    PRIOR attempt plus this attempt's own unit contribution.

    Derivation (re-verified by direct algebra, not just cited): let ``r(i)`` be
    the decayed sum of attempts strictly before the i-th one, evaluated at the
    i-th attempt's own timestamp. Then ``r(1) = 0`` (no prior attempts) and,
    for i > 1, ``r(i) = exp(-beta * dt) * (1 + r(i-1))`` where ``dt`` is the gap
    since the (i-1)-th attempt and ``1 + r(i-1)`` is lambda_hat evaluated AT the
    (i-1)-th attempt (its own contribution plus everything before it), decayed
    forward by ``dt``. The intensity AT the i-th attempt is then ``r(i) + 1``.
    This reproduces both textbook pins: N simultaneous events (all ``dt=0``)
    give ``r(i) = i - 1`` so intensity ``= i``; a single event decays to
    exactly 1/2 at ``dt = H`` since ``exp(-beta * H) = exp(-ln(2)) = 0.5``.
    """
    out: list[float] = []
    r = 0.0
    prev: datetime | None = None
    for ts in sorted_ts:
        if prev is not None:
            dt = (ts - prev).total_seconds()
            r = math.exp(-beta * dt) * (1.0 + r)
        out.append(r + 1.0)
        prev = ts
    return out


def _beta(half_life: timedelta) -> float:
    return math.log(2) / half_life.total_seconds()


def intensity_at(
    events: list[SecurityEvent], t: datetime, half_life: timedelta = HALF_LIFE
) -> float:
    """lambda_hat(t) = sum(exp(-beta*(t - t_i)) for t_i <= t) over D1 attempts.

    Pure, deterministic; a single fold over the attempts at or before ``t``.
    """
    ts = [x for x in _attempt_timestamps(events) if x <= t]
    if not ts:
        return 0.0
    beta = _beta(half_life)
    folded = _decay_fold(ts, beta)
    dt = (t - ts[-1]).total_seconds()
    return folded[-1] * math.exp(-beta * dt)


def peak_intensity(
    events: list[SecurityEvent],
    window: timedelta,
    now: datetime,
    half_life: timedelta = HALF_LIFE,
) -> float:
    """max(lambda_hat(t) for t in [now - window, now]) — the R1 peak check.

    lambda_hat is non-increasing between attempts and jumps up by exactly 1 at
    each attempt, so its maximum over any interval is attained either
    immediately after an attempt inside the interval (a value the fold already
    computed), or — if no attempt falls inside the interval — at the
    interval's left edge, decayed from whatever attempts came before it. This
    is exact (closed-form), not sampled: no candidate time is missed.
    """
    lower = now - window
    ts = [x for x in _attempt_timestamps(events) if x <= now]
    if not ts:
        return 0.0
    beta = _beta(half_life)
    folded = _decay_fold(ts, beta)

    candidates: list[float] = [
        value for value, stamp in zip(folded, ts, strict=True) if stamp >= lower
    ]

    before = [(value, stamp) for value, stamp in zip(folded, ts, strict=True) if stamp < lower]
    if before:
        last_value, last_stamp = before[-1]
        boundary_dt = (lower - last_stamp).total_seconds()
        candidates.append(last_value * math.exp(-beta * boundary_dt))

    return max(candidates) if candidates else 0.0


# ── D3 (scaffolding for #54) — pressure episode segmentation ─────────────────


@dataclass(frozen=True)
class Episode:
    """A maximal interval during which lambda_hat(t) >= threshold (ADR-0070 D3)."""

    start: datetime
    end: datetime


def episodes(
    events: list[SecurityEvent],
    threshold: float,
    half_life: timedelta = HALF_LIFE,
) -> list[Episode]:
    """Segment *events* into maximal pressure episodes (lambda_hat(t) >= threshold).

    Boundaries are exact, closed-form: an episode opens instantly at the
    attempt whose jump first reaches ``threshold`` (jumps are discontinuous, so
    no "crossing time" computation is needed for the up-crossing), and closes
    at ``t_i + ln(lambda_i / threshold) / beta`` — the moment continuous decay
    from the last attempt's value would fall back below ``threshold`` — UNLESS
    a later attempt arrives first, in which case the episode continues through
    it without a gap (ADR-0070 D3's closed-form crossing formula).

    Ships in this module for issue #54 (R2 ``attack_in_progress`` / R3
    ``campaign``) to consume; not wired into any rule in this issue (#53).
    """
    attempts = _attempt_timestamps(events)
    if not attempts:
        return []
    beta = _beta(half_life)
    folded = _decay_fold(attempts, beta)

    out: list[Episode] = []
    episode_start: datetime | None = None
    for i, (stamp, value) in enumerate(zip(attempts, folded, strict=True)):
        if value < threshold:
            episode_start = None
            continue
        if episode_start is None:
            episode_start = stamp
        crossing_dt = math.log(value / threshold) / beta
        candidate_end = stamp + timedelta(seconds=crossing_dt)
        next_stamp = attempts[i + 1] if i + 1 < len(attempts) else None
        if next_stamp is None or next_stamp > candidate_end:
            out.append(Episode(start=episode_start, end=candidate_end))
            episode_start = None
        # else: the next attempt arrives before decay would cross the
        # threshold — the episode continues uninterrupted into it.
    return out
