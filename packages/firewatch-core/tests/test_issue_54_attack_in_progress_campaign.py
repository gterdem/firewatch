"""Tests for issue #54 — R2 `attack_in_progress` + R3 `campaign` (ADR-0070
Revision 1 D3), and the retirement of `_ssh_login_failure_intense` (+ the
then-orphaned `_ssh_login_failure_events` helper).

EARS -> test mapping
────────────────────
AC-R2-fires    WHEN lambda_hat(now) >= theta_high, detect() SHALL emit one
               `attack_in_progress` detection with severity="high",
               auto_escalate=True, score_delta=25, reason from engine
               integers only (never a raw lambda value).
               -> TestAttackInProgressFires

AC-R2-50permin A 50-attempts/min synthetic stream SHALL produce
               `attack_in_progress` within the first minute of events.
               -> TestFiftyPerMinuteQueuesWithinFirstMinute

AC-R2-fade     After event flow stops, `attack_in_progress` SHALL stop
               deriving once lambda_hat decays below theta_high, and the
               actor SHALL leave the queue on re-analysis — no manual expiry.
               -> TestAttackInProgressFade

AC-R3-fires    WHEN the actor's horizon episodes satisfy recidivism (>=2),
               endurance (span >= D_endure), or breadth (>=1 episode AND
               >=2 categories or >=5 ports), detect() SHALL emit one
               `campaign` detection with severity="high", auto_escalate=True,
               score_delta=20.
               -> TestCampaignRecidivism, TestCampaignEndurance,
                  TestCampaignBreadth

AC-tier2       WHEN either detection is present, the actor SHALL reach Tier 2
               through the existing qualify gate with a RULE-tagged
               justification; when both fire, the headline SHALL name
               `attack_in_progress` (higher score_delta).
               -> TestReachesTier2ThroughExistingGate

AC-clause-seam Two theta_press episodes 6h apart SHALL emit `campaign`
               (recidivism); the same two bursts with the dip filled at
               pressure level SHALL NOT emit recidivism but SHALL emit
               `campaign` via endurance once the continuous episode reaches
               D_endure (the bounded-seam property — no calm path).
               -> TestClauseSeamBoundary

AC-must-not-ambient   An ambient-shape burst (5 attempts in 10 min, peak
               lambda_hat ~= 5) SHALL NOT emit either rule and SHALL NOT
               reach Tier 2.
               -> TestMustNotAmbientBurst

AC-must-not-paced     A sub-theta_press paced actor SHALL NOT emit either
               rule at any lifetime volume.
               -> TestMustNotSubThresholdPacedActor

AC-retire      `_ssh_login_failure_intense` SHALL be removed — R2 subsumes
               it. Regression pin: a synthetic 45-failures-in-10-minutes
               stream SHALL STILL queue, now under R2 (the value-preserving
               handover). Neither `_ssh_login_failure_intense` nor the
               then-orphaned `_ssh_login_failure_events` helper SHALL survive.
               -> TestSshLoginFailureIntenseRetired

AC-constants   theta_high, D_endure, and the campaign clause thresholds
               SHALL be named, code-declared constants (not operator-tunable).
               -> TestConstants

Fixture IPs: all via `make_event`'s default (RFC 5737, 203.0.113.5) — never
real/routable addresses (testing-conventions skill).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import firewatch_core.detector as detector_mod
from firewatch_core.detector import (
    CAMPAIGN_MIN_CATEGORIES,
    CAMPAIGN_MIN_EPISODES,
    CAMPAIGN_MIN_PORTS,
    D_ENDURE,
    THETA_HIGH,
    detect,
)
from firewatch_core.escalation.decider import decide
from firewatch_core.escalation.policy import ESCALATION_POLICY
from firewatch_core.escalation.qualify import qualify
from firewatch_core.pipeline import W_CAMPAIGN

from _fakes import make_event

T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc)


def _by_name(detections, name):
    return next((d for d in detections if d.rule_name == name), None)


def _alert(count: int, *, timestamp=T0, category=None, destination_port=None):
    """N ALERT/low events from one IP, same instant by default — a passive
    SSH-brute-force-shaped burst (the D1 predicate counts ALERT/low)."""
    return [
        make_event(
            source_type="linux_auth", action="ALERT", severity="low",
            timestamp=timestamp, category=category, destination_port=destination_port,
        )
        for _ in range(count)
    ]


def _continuous_pressure_events(total_span: timedelta, period: timedelta = timedelta(minutes=5)):
    """An initial burst (6 simultaneous ALERTs, safely above theta_press)
    followed by a periodic drip every ``period`` — chosen (5 min, well under
    the ~9.65 min steady-state bound at H=30min/theta_press=5) so decayed
    intensity never falls back below theta_press between events: the "dip"
    between what would otherwise be two separate bursts is filled, merging
    them into ONE continuous pressure episode spanning ``total_span``."""
    events = _alert(6, timestamp=T0)
    t = period
    while t <= total_span:
        events += _alert(1, timestamp=T0 + t)
        t += period
    return events


# ---------------------------------------------------------------------------
# AC-R2-fires
# ---------------------------------------------------------------------------


class TestAttackInProgressFires:
    def test_fires_when_current_intensity_reaches_theta_high(self):
        events = _alert(THETA_HIGH)  # N simultaneous ALERTs -> lambda_hat == N
        d = _by_name(detect(events, now=T0), "attack_in_progress")
        assert d is not None

    def test_below_threshold_does_not_fire(self):
        events = _alert(THETA_HIGH - 1)
        assert _by_name(detect(events, now=T0), "attack_in_progress") is None

    def test_declared_severity_high(self):
        events = _alert(THETA_HIGH)
        d = _by_name(detect(events, now=T0), "attack_in_progress")
        assert d is not None
        assert d.severity == "high"

    def test_declared_auto_escalate_true(self):
        events = _alert(THETA_HIGH)
        d = _by_name(detect(events, now=T0), "attack_in_progress")
        assert d is not None
        assert d.auto_escalate is True

    def test_score_delta_is_25(self):
        events = _alert(THETA_HIGH)
        d = _by_name(detect(events, now=T0), "attack_in_progress")
        assert d is not None
        assert d.score_delta == 25

    def test_reason_carries_engine_integers_only_never_raw_lambda(self):
        """ADR-0035: the reason SHALL name the attempt count and the window's
        own span — never a raw (potentially non-integer) lambda_hat value."""
        events = _alert(THETA_HIGH)
        d = _by_name(detect(events, now=T0), "attack_in_progress")
        assert d is not None
        assert str(THETA_HIGH) in d.reason
        assert "24h" in d.reason
        assert "." not in d.reason


# ---------------------------------------------------------------------------
# AC-R2-50permin — the Maintainer's flagship case
# ---------------------------------------------------------------------------


class TestFiftyPerMinuteQueuesWithinFirstMinute:
    def test_fifty_per_minute_fires_within_the_first_minute(self):
        events = [
            make_event(
                source_type="linux_auth", action="ALERT", severity="low",
                timestamp=T0 + timedelta(seconds=1.2 * i),
            )
            for i in range(50)
        ]
        now = T0 + timedelta(seconds=60)  # exactly the first minute
        d = _by_name(detect(events, now=now), "attack_in_progress")
        assert d is not None, "50 attempts/min MUST queue within the first minute"

    def test_fifty_per_minute_qualifies_the_assertion_gate(self):
        events = [
            make_event(
                source_type="linux_auth", action="ALERT", severity="low",
                timestamp=T0 + timedelta(seconds=1.2 * i),
            )
            for i in range(50)
        ]
        now = T0 + timedelta(seconds=60)
        detections = detect(events, now=now)
        result = qualify(events, detections)
        assert result.qualified is True


# ---------------------------------------------------------------------------
# AC-R2-fade — decays below theta_high, leaves the queue on re-analysis
# ---------------------------------------------------------------------------


class TestAttackInProgressFade:
    def test_fires_at_the_moment_of_the_burst(self):
        burst = _alert(50, timestamp=T0)
        assert _by_name(detect(burst, now=T0), "attack_in_progress") is not None

    def test_fades_once_decayed_below_theta_high(self):
        """50 simultaneous ALERTs decay to ~35.4 by +15 min (H=30min) —
        comfortably below theta_high=40; attack_in_progress must stop firing,
        with NO manual expiry (re-derived at analyze time from the same
        event list, just a later `now`)."""
        burst = _alert(50, timestamp=T0)
        later = T0 + timedelta(minutes=15)
        assert _by_name(detect(burst, now=later), "attack_in_progress") is None

    def test_actor_leaves_the_queue_on_re_analysis(self):
        """The property that matters: qualify() flips from True to False
        across re-analysis at a later `now`, with the exact same event list
        and no persisted/mutated state."""
        burst = _alert(50, timestamp=T0)

        detections_now = detect(burst, now=T0)
        assert qualify(burst, detections_now).qualified is True

        later = T0 + timedelta(minutes=15)
        detections_later = detect(burst, now=later)
        assert qualify(burst, detections_later).qualified is False


# ---------------------------------------------------------------------------
# AC-R3-fires — recidivism / endurance / breadth
# ---------------------------------------------------------------------------


class TestCampaignRecidivism:
    def test_two_episodes_six_hours_apart_fires_via_recidivism(self):
        b1 = _alert(6, timestamp=T0)
        b2 = _alert(6, timestamp=T0 + timedelta(hours=6))
        events = b1 + b2
        now = T0 + timedelta(hours=6)
        d = _by_name(detect(events, now=now), "campaign")
        assert d is not None
        assert str(CAMPAIGN_MIN_EPISODES) in d.reason

    def test_declared_severity_and_auto_escalate_and_score(self):
        b1 = _alert(6, timestamp=T0)
        b2 = _alert(6, timestamp=T0 + timedelta(hours=6))
        now = T0 + timedelta(hours=6)
        d = _by_name(detect(b1 + b2, now=now), "campaign")
        assert d is not None
        assert d.severity == "high"
        assert d.auto_escalate is True
        assert d.score_delta == 20

    def test_single_episode_does_not_satisfy_recidivism_alone(self):
        """One short burst (no return, no endurance, no breadth) must NOT
        fire campaign — recidivism needs >=2 episodes."""
        events = _alert(6, timestamp=T0)
        assert _by_name(detect(events, now=T0), "campaign") is None


class TestCampaignEndurance:
    def test_continuous_pressure_below_d_endure_does_not_fire(self):
        """The dip-filled variant at ~6h total span: ONE continuous episode,
        span well under D_ENDURE (24h) — no recidivism (1 episode), no
        endurance (span < 24h), no breadth -> campaign must NOT fire yet."""
        events = _continuous_pressure_events(timedelta(hours=6))
        now = T0 + timedelta(hours=6)
        assert _by_name(detect(events, now=now), "campaign") is None

    def test_continuous_pressure_reaching_d_endure_fires_via_endurance(self):
        """Extending the SAME continuous drip to a 25h span crosses
        D_ENDURE (24h) -> campaign fires via endurance, not recidivism
        (still exactly 1 episode) — the bounded-seam property (ADR-0070 D3):
        no addition of events can move this actor back to calm."""
        events = _continuous_pressure_events(timedelta(hours=25))
        now = T0 + timedelta(hours=25)
        d = _by_name(detect(events, now=now), "campaign")
        assert d is not None
        assert "episode spanning" in d.reason

    def test_endurance_reason_carries_engine_integers_only(self):
        events = _continuous_pressure_events(timedelta(hours=25))
        now = T0 + timedelta(hours=25)
        d = _by_name(detect(events, now=now), "campaign")
        assert d is not None
        assert "." not in d.reason


class TestCampaignBreadth:
    def test_one_episode_with_two_categories_fires_via_breadth(self):
        events = (
            _alert(3, timestamp=T0, category="SQL Injection")
            + _alert(3, timestamp=T0, category="XSS")
        )
        d = _by_name(detect(events, now=T0), "campaign")
        assert d is not None
        assert "categories" in d.reason

    def test_one_episode_with_five_ports_fires_via_breadth(self):
        events = [
            make_event(
                source_type="linux_auth", action="ALERT", severity="low",
                timestamp=T0, destination_port=port,
            )
            for port in (22, 80, 443, 3389, 8080, 8443)
        ]
        d = _by_name(detect(events, now=T0), "campaign")
        assert d is not None
        assert str(CAMPAIGN_MIN_PORTS) in d.reason or "ports" in d.reason

    def test_one_episode_alone_without_breadth_does_not_fire(self):
        """A single episode, one category, one port — no breadth, no
        recidivism, no endurance -> campaign must NOT fire."""
        events = _alert(6, timestamp=T0, category="SSH Login Failure", destination_port=22)
        assert _by_name(detect(events, now=T0), "campaign") is None

    def test_below_campaign_min_categories_does_not_fire_breadth(self):
        """Exactly 1 distinct category (< CAMPAIGN_MIN_CATEGORIES) and < 5
        ports -> breadth clause must not be satisfied."""
        events = _alert(6, timestamp=T0, category="SSH Login Failure")
        assert CAMPAIGN_MIN_CATEGORIES == 2
        assert _by_name(detect(events, now=T0), "campaign") is None


# ---------------------------------------------------------------------------
# AC-tier2 — reaches Tier 2 through the existing gate; headline attribution
# ---------------------------------------------------------------------------


class TestReachesTier2ThroughExistingGate:
    def test_attack_in_progress_alone_qualifies(self):
        events = _alert(THETA_HIGH)
        detections = detect(events, now=T0)
        result = qualify(events, detections)
        assert result.qualified is True

    def test_campaign_alone_qualifies(self):
        b1 = _alert(6, timestamp=T0)
        b2 = _alert(6, timestamp=T0 + timedelta(hours=6))
        events = b1 + b2
        now = T0 + timedelta(hours=6)
        detections = detect(events, now=now)
        result = qualify(events, detections)
        assert result.qualified is True

    def test_headline_names_attack_in_progress_when_both_fire(self):
        """A recidivist actor whose SECOND burst is also intense enough to
        cross theta_high: both attack_in_progress (25) and campaign (20)
        fire. The decider's headline (highest score_delta) must name
        attack_in_progress — the current attack outranks the pattern
        (ADR-0070 D3)."""
        b1 = _alert(6, timestamp=T0)
        b2 = _alert(THETA_HIGH + 5, timestamp=T0 + timedelta(hours=6))
        events = b1 + b2
        now = T0 + timedelta(hours=6)
        detections = detect(events, now=now)
        names = {d.rule_name for d in detections}
        assert "attack_in_progress" in names
        assert "campaign" in names

        verdict = decide(events, detections)
        assert verdict.tier == 2
        assert "attack_in_progress" in verdict.justification
        assert "campaign" not in verdict.justification


# ---------------------------------------------------------------------------
# AC-clause-seam — the bounded, no-calm-path property
# ---------------------------------------------------------------------------


class TestClauseSeamBoundary:
    def test_two_separated_episodes_six_hours_apart_fire_via_recidivism(self):
        b1 = _alert(6, timestamp=T0)
        b2 = _alert(6, timestamp=T0 + timedelta(hours=6))
        now = T0 + timedelta(hours=6)
        d = _by_name(detect(b1 + b2, now=now), "campaign")
        assert d is not None
        assert "pressure episodes" in d.reason

    def test_dip_filled_merges_episodes_and_recidivism_stops_deriving(self):
        """Filling the quiet gap with pressure-sustaining events merges the
        two episodes into one (still only ~6h span) — recidivism (>=2
        episodes) no longer applies, and endurance hasn't been reached yet,
        so campaign does not fire at this checkpoint."""
        events = _continuous_pressure_events(timedelta(hours=6))
        now = T0 + timedelta(hours=6)
        assert _by_name(detect(events, now=now), "campaign") is None

    def test_no_calm_path_sustaining_the_fill_eventually_fires_via_endurance(self):
        """The bounded-seam property itself: continuing to hold pressure
        (rather than letting it drop back to calm) eventually crosses
        D_ENDURE and fires campaign via endurance — there is no way to fill
        the dip AND return to calm without either separating into episodes
        (recidivism) or enduring (endurance)."""
        events = _continuous_pressure_events(timedelta(hours=25))
        now = T0 + timedelta(hours=25)
        assert _by_name(detect(events, now=now), "campaign") is not None


# ---------------------------------------------------------------------------
# AC-must-not-ambient — an ambient-shape burst never queues
# ---------------------------------------------------------------------------


class TestMustNotAmbientBurst:
    def test_five_in_ten_minutes_fires_neither_rule(self):
        events = [
            make_event(
                source_type="linux_auth", action="ALERT", severity="low",
                timestamp=T0 + timedelta(minutes=2.5 * i),
            )
            for i in range(5)
        ]
        now = T0 + timedelta(minutes=10)
        detections = detect(events, now=now)
        assert _by_name(detections, "attack_in_progress") is None
        assert _by_name(detections, "campaign") is None

    def test_five_in_ten_minutes_never_reaches_tier_2(self):
        events = [
            make_event(
                source_type="linux_auth", action="ALERT", severity="low",
                timestamp=T0 + timedelta(minutes=2.5 * i),
            )
            for i in range(5)
        ]
        now = T0 + timedelta(minutes=10)
        detections = detect(events, now=now)
        result = qualify(events, detections)
        assert result.qualified is False


# ---------------------------------------------------------------------------
# AC-must-not-paced — sub-theta_press paced actor, any lifetime volume
# ---------------------------------------------------------------------------


class TestMustNotSubThresholdPacedActor:
    def test_never_fires_at_any_lifetime_volume(self):
        """1 attempt every 3 days for ~5 months (50 events) — each one
        decays to ~0 long before the next arrives, so lambda_hat never
        reaches theta_press, let alone theta_high; no episode ever opens."""
        events = [
            make_event(
                source_type="linux_auth", action="ALERT", severity="low",
                timestamp=T0 + timedelta(days=3 * i),
            )
            for i in range(50)
        ]
        now = T0 + timedelta(days=3 * 49)
        detections = detect(events, now=now)
        assert _by_name(detections, "attack_in_progress") is None
        assert _by_name(detections, "campaign") is None
        result = qualify(events, detections)
        assert result.qualified is False


# ---------------------------------------------------------------------------
# AC-retire — _ssh_login_failure_intense is gone; R2 subsumes it
# ---------------------------------------------------------------------------


class TestSshLoginFailureIntenseRetired:
    def test_no_module_function(self):
        assert not hasattr(detector_mod, "_ssh_login_failure_intense")

    def test_no_orphaned_helper(self):
        assert not hasattr(detector_mod, "_ssh_login_failure_events")

    def test_not_in_any_rule_registry(self):
        names = {rule.__name__ for rule in detector_mod.BUILTIN_RULES}
        names |= {rule.__name__ for rule in detector_mod.TIME_ANCHORED_RULES}
        assert "_ssh_login_failure_intense" not in names

    def test_registry_default_for_retired_name(self):
        policy = ESCALATION_POLICY.get_or_default("ssh_login_failure_intense")
        assert policy.severity is None
        assert policy.auto_escalate is False

    def test_never_produced_by_detect_at_any_volume(self):
        events = [
            make_event(
                source_type="linux_auth", category="SSH Login Failure", action="ALERT",
                severity="low", timestamp=T0 + timedelta(seconds=i),
            )
            for i in range(45)
        ]
        detections = detect(events, now=T0)
        assert not any(d.rule_name == "ssh_login_failure_intense" for d in detections)

    def test_regression_pin_forty_five_in_ten_minutes_still_queues_under_r2(self):
        """The value-preserving handover (ADR-0070 Consequences): a
        45-failures-in-10-minutes stream that used to fire
        ssh_login_failure_intense now fires attack_in_progress instead, and
        STILL reaches Tier 2 — the actor's queue membership is preserved."""
        events = [
            make_event(
                source_type="linux_auth", category="SSH Login Failure", action="ALERT",
                severity="low", timestamp=T0 + timedelta(seconds=13 * i),
            )
            for i in range(45)  # packed into <10 min
        ]
        now = events[-1].timestamp
        detections = detect(events, now=now)
        d = _by_name(detections, "attack_in_progress")
        assert d is not None, "45-in-10-min MUST still queue, now via R2"
        assert d.severity == "high"
        assert d.auto_escalate is True

        result = qualify(events, detections)
        assert result.qualified is True

        verdict = decide(events, detections)
        assert verdict.tier == 2


# ---------------------------------------------------------------------------
# AC-constants — named, code-declared, not operator-tunable
# ---------------------------------------------------------------------------


class TestConstants:
    def test_theta_high_is_40(self):
        assert THETA_HIGH == 40

    def test_d_endure_is_24_hours(self):
        assert D_ENDURE == timedelta(hours=24)

    def test_campaign_min_episodes_is_2(self):
        assert CAMPAIGN_MIN_EPISODES == 2

    def test_campaign_min_categories_is_2(self):
        assert CAMPAIGN_MIN_CATEGORIES == 2

    def test_campaign_min_ports_is_5(self):
        assert CAMPAIGN_MIN_PORTS == 5

    def test_campaign_window_matches_pipeline_w_campaign(self):
        """detector._CAMPAIGN_WINDOW (duplicated to avoid a circular import)
        MUST equal pipeline.W_CAMPAIGN — a drift guard, not a design choice."""
        assert detector_mod._CAMPAIGN_WINDOW == W_CAMPAIGN
