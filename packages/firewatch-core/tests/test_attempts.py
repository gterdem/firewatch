"""Tests for firewatch_core.attempts — the D1 predicate + decayed intensity
estimator (ADR-0070 Revision 1, issue #53).

EARS -> test mapping
────────────────────
AC-predicate  An event SHALL count as an attempt iff action ∈ {BLOCK, DROP, ALERT}
              and NOT (action == "ALERT" and severity == "info"); severity=None
              counts. LOG and ALLOW SHALL never count.
              -> TestIsAttempt (unit-tested per action × severity)

AC-fold       attempts.py SHALL implement the intensity fold (O(1) per event, pure,
              deterministic); tests pin: single event decays to 1/2 at exactly H;
              N simultaneous events give lambda_hat = N; adding an event never
              lowers lambda_hat at any t (monotonicity pin).
              -> TestIntensityAt

AC-peak       peak_intensity SHALL be the exact (closed-form, not sampled) maximum
              of lambda_hat over [now - window, now].
              -> TestPeakIntensity

Structural    episodes() (scaffolding for #54) segments a timeline into maximal
              lambda_hat >= threshold intervals using the closed-form crossing.
              -> TestEpisodes

Security note: all test IPs (via `make_event`'s default) are RFC 5737
documentation-range addresses — no real/routable IPs (testing-conventions skill).
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

from firewatch_core.attempts import (
    HALF_LIFE,
    PRESSURE_THRESHOLD,
    episodes,
    intensity_at,
    is_attempt,
    peak_intensity,
)
from _fakes import make_event

T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# AC-predicate — D1, unit-tested per action x severity
# ---------------------------------------------------------------------------


class TestIsAttempt:
    def test_block_counts(self):
        assert is_attempt(make_event(action="BLOCK")) is True

    def test_drop_counts(self):
        assert is_attempt(make_event(action="DROP")) is True

    def test_alert_with_no_severity_counts(self):
        assert is_attempt(make_event(action="ALERT", severity=None)) is True

    def test_alert_low_counts(self):
        assert is_attempt(make_event(action="ALERT", severity="low")) is True

    def test_alert_medium_counts(self):
        assert is_attempt(make_event(action="ALERT", severity="medium")) is True

    def test_alert_high_counts(self):
        assert is_attempt(make_event(action="ALERT", severity="high")) is True

    def test_alert_critical_counts(self):
        assert is_attempt(make_event(action="ALERT", severity="critical")) is True

    def test_alert_info_does_not_count(self):
        """The Sigma `informational` exclusion (ADR-0070 D1) — a huge amount of
        events are expected to match an informational rule; counting them into
        a pressure metric would rebuild the flood inside the band axis."""
        assert is_attempt(make_event(action="ALERT", severity="info")) is False

    def test_log_never_counts(self):
        assert is_attempt(make_event(action="LOG")) is False

    def test_log_never_counts_even_with_high_severity(self):
        assert is_attempt(make_event(action="LOG", severity="high")) is False

    def test_allow_never_counts(self):
        assert is_attempt(make_event(action="ALLOW")) is False

    def test_allow_never_counts_even_with_high_severity(self):
        assert is_attempt(make_event(action="ALLOW", severity="critical")) is False


# ---------------------------------------------------------------------------
# AC-fold — the intensity fold's three load-bearing pins
# ---------------------------------------------------------------------------


class TestIntensityAt:
    def test_single_event_decays_to_half_at_half_life(self):
        events = [make_event(action="BLOCK", timestamp=T0)]
        value = intensity_at(events, T0 + HALF_LIFE, half_life=HALF_LIFE)
        assert math.isclose(value, 0.5, rel_tol=1e-9)

    def test_single_event_is_one_at_its_own_timestamp(self):
        events = [make_event(action="BLOCK", timestamp=T0)]
        assert math.isclose(intensity_at(events, T0, half_life=HALF_LIFE), 1.0)

    def test_single_event_decays_to_quarter_at_two_half_lives(self):
        events = [make_event(action="BLOCK", timestamp=T0)]
        value = intensity_at(events, T0 + 2 * HALF_LIFE, half_life=HALF_LIFE)
        assert math.isclose(value, 0.25, rel_tol=1e-9)

    def test_n_simultaneous_events_give_lambda_equals_n(self):
        for n in (1, 2, 3, 5, 10):
            events = [make_event(action="BLOCK", timestamp=T0) for _ in range(n)]
            value = intensity_at(events, T0, half_life=HALF_LIFE)
            assert math.isclose(value, float(n), rel_tol=1e-9), f"n={n}"

    def test_monotonicity_adding_an_event_never_lowers_intensity(self):
        base = [
            make_event(action="BLOCK", timestamp=T0 + timedelta(minutes=i))
            for i in range(5)
        ]
        t_check = T0 + timedelta(minutes=30)
        before = intensity_at(base, t_check, half_life=HALF_LIFE)

        augmented = base + [make_event(action="BLOCK", timestamp=T0 + timedelta(minutes=2))]
        after = intensity_at(augmented, t_check, half_life=HALF_LIFE)
        assert after >= before

    def test_monotonicity_across_many_random_insertion_points(self):
        """Broader pin: inserting one extra attempt at ANY position in the
        timeline never lowers lambda_hat evaluated at any later probe time."""
        base = [
            make_event(action="ALERT", severity="low", timestamp=T0 + timedelta(minutes=5 * i))
            for i in range(8)
        ]
        probe_times = [T0 + timedelta(minutes=m) for m in (0, 3, 10, 20, 45, 90, 200)]
        baseline = {t: intensity_at(base, t, half_life=HALF_LIFE) for t in probe_times}

        for insert_minute in range(0, 60, 5):
            extra = base + [
                make_event(
                    action="ALERT", severity="low",
                    timestamp=T0 + timedelta(minutes=insert_minute),
                )
            ]
            for t in probe_times:
                assert intensity_at(extra, t, half_life=HALF_LIFE) >= baseline[t] - 1e-12

    def test_event_before_t_does_not_contribute_after_being_excluded(self):
        """No attempts at or before t -> lambda_hat(t) == 0."""
        events = [make_event(action="BLOCK", timestamp=T0 + timedelta(hours=1))]
        assert intensity_at(events, T0, half_life=HALF_LIFE) == 0.0

    def test_non_attempt_events_never_contribute(self):
        events = [make_event(action="LOG", timestamp=T0) for _ in range(10)]
        assert intensity_at(events, T0, half_life=HALF_LIFE) == 0.0

    def test_empty_events_is_zero(self):
        assert intensity_at([], T0, half_life=HALF_LIFE) == 0.0

    def test_deterministic_repeated_calls(self):
        """Pure function: identical inputs always produce identical output."""
        events = [
            make_event(action="BLOCK", timestamp=T0 + timedelta(minutes=i))
            for i in range(7)
        ]
        t = T0 + timedelta(minutes=20)
        results = {intensity_at(events, t, half_life=HALF_LIFE) for _ in range(5)}
        assert len(results) == 1


# ---------------------------------------------------------------------------
# AC-peak — peak_intensity is the exact max over [now - window, now]
# ---------------------------------------------------------------------------


class TestPeakIntensity:
    def test_peak_at_the_burst_itself(self):
        events = [make_event(action="BLOCK", timestamp=T0) for _ in range(5)]
        peak = peak_intensity(events, timedelta(hours=24), T0, half_life=HALF_LIFE)
        assert math.isclose(peak, 5.0, rel_tol=1e-9)

    def test_peak_decayed_when_now_is_after_the_burst(self):
        events = [make_event(action="BLOCK", timestamp=T0) for _ in range(5)]
        now = T0 + timedelta(hours=2)
        peak = peak_intensity(events, timedelta(hours=24), now, half_life=HALF_LIFE)
        # Peak within the window is still the value AT the burst (t=T0), which
        # falls inside [now-24h, now] — the burst itself, not a decayed reading.
        assert math.isclose(peak, 5.0, rel_tol=1e-9)

    def test_peak_excludes_burst_older_than_window(self):
        """A burst that occurred BEFORE the window's left edge contributes only
        its decayed value AT the boundary, not its undecayed peak."""
        events = [make_event(action="BLOCK", timestamp=T0) for _ in range(5)]
        now = T0 + timedelta(hours=30)  # burst is 30h old; window is 24h
        window = timedelta(hours=24)
        peak = peak_intensity(events, window, now, half_life=HALF_LIFE)
        expected = intensity_at(events, now - window, half_life=HALF_LIFE)
        assert math.isclose(peak, expected, rel_tol=1e-9)
        assert peak < 5.0

    def test_peak_zero_when_no_attempts(self):
        assert peak_intensity([], timedelta(hours=24), T0, half_life=HALF_LIFE) == 0.0

    def test_peak_finds_a_historical_high_inside_the_window_even_if_now_is_quiet(self):
        """A burst earlier in the window, followed by silence, is still the
        peak — peak_intensity does not just report intensity_at(now)."""
        events = [
            make_event(action="BLOCK", timestamp=T0 + timedelta(minutes=i))
            for i in range(10)
        ]
        now = T0 + timedelta(hours=5)  # long after the burst decayed
        peak = peak_intensity(events, timedelta(hours=24), now, half_life=HALF_LIFE)
        current = intensity_at(events, now, half_life=HALF_LIFE)
        assert peak > current
        assert peak >= PRESSURE_THRESHOLD


# ---------------------------------------------------------------------------
# episodes() — scaffolding for #54 (segmentation over closed-form crossings)
# ---------------------------------------------------------------------------


class TestEpisodes:
    def test_no_attempts_no_episodes(self):
        assert episodes([], threshold=PRESSURE_THRESHOLD) == []

    def test_below_threshold_burst_produces_no_episode(self):
        events = [make_event(action="BLOCK", timestamp=T0) for _ in range(3)]
        assert episodes(events, threshold=PRESSURE_THRESHOLD, half_life=HALF_LIFE) == []

    def test_single_burst_at_or_above_threshold_produces_one_episode(self):
        """6 simultaneous events give lambda_hat=6, strictly above threshold=5,
        so the down-crossing is strictly later than the burst itself."""
        events = [make_event(action="BLOCK", timestamp=T0) for _ in range(6)]
        result = episodes(events, threshold=5, half_life=HALF_LIFE)
        assert len(result) == 1
        assert result[0].start == T0
        assert result[0].end > T0

    def test_episode_end_matches_closed_form_crossing(self):
        """The reported end time is exactly where lambda_hat decays back to
        threshold — verified against intensity_at at that instant."""
        events = [make_event(action="BLOCK", timestamp=T0) for _ in range(6)]
        result = episodes(events, threshold=5, half_life=HALF_LIFE)
        end = result[0].end
        value_at_end = intensity_at(events, end, half_life=HALF_LIFE)
        assert math.isclose(value_at_end, 5.0, rel_tol=1e-6)

    def test_two_separated_bursts_produce_two_episodes(self):
        first_burst = [make_event(action="BLOCK", timestamp=T0) for _ in range(5)]
        second_burst = [
            make_event(action="BLOCK", timestamp=T0 + timedelta(hours=6))
            for _ in range(5)
        ]
        events = first_burst + second_burst
        result = episodes(events, threshold=5, half_life=HALF_LIFE)
        assert len(result) == 2

    def test_sustained_pressure_merges_into_one_episode(self):
        """A burst that immediately clears the threshold, followed by attempts
        arriving faster than the decay-to-threshold time, keeps a single
        episode open, uninterrupted, rather than closing/reopening."""
        burst = [make_event(action="BLOCK", timestamp=T0) for _ in range(6)]
        sustain = [
            make_event(action="BLOCK", timestamp=T0 + timedelta(minutes=2 * i))
            for i in range(1, 20)
        ]
        events = burst + sustain
        result = episodes(events, threshold=5, half_life=HALF_LIFE)
        assert len(result) == 1
        assert result[0].start == T0
