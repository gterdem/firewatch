"""Tests for issue #53 — R1 `attempt_pressure` + the retirement of
`_sustained_attack` and `_ssh_login_failure_burst` (ADR-0070 Revision 1 D2).

EARS -> test mapping
────────────────────
AC-fires      WHEN an actor's peak lambda_hat within the trailing W_STATE reaches
              theta_press, detect() SHALL emit one `attempt_pressure` detection
              with severity="medium", auto_escalate=False, score_delta=15, and a
              reason built from engine integers only (never a raw lambda value).
              -> TestAttemptPressureFires

AC-brute-force  A pure SSH brute force (N ALERT `Failed password` events, no
              success) SHALL produce a nonzero score via detection_boost for any
              burst with decayed mass >= theta_press.
              -> TestPureSshBruteForceScoresNonzero

AC-retire-sustained  `_sustained_attack` SHALL be removed and the escalation-policy
              registry/route SHALL list `attempt_pressure` in its place.
              Regression pin: every DENSE set that fired `_sustained_attack`
              (>=10 blocked within a span holding decayed mass >= theta_press)
              fires R1 at the same score_delta. The non-carried population
              (>=10 blocked spread under ~7 attempts/hour) does NOT fire R1.
              -> TestSustainedAttackRetired, TestRegressionPinDenseSetCarriesOver,
                 TestNonCarriedThinPopulationExcluded

AC-must-not-tier2  An actor with only attempt_pressure detections SHALL NOT enter
              Tier 2.
              -> TestPressureAloneNeverQueues

AC-must-not-ambient  Ambient personas (1-4 attempts/night) SHALL NOT fire R1.
              -> TestAmbientPersonasNeverFire

AC-seam       R1 SHALL be implemented in detect() (the detector seam), NOT as a
              run_rules term.
              -> TestR1IsDetectorSeamOnly

AC-constants  H, theta_press SHALL be named, code-declared beside W_STATE/
              W_CAMPAIGN (not operator-tunable), and detector.py's R1
              peak-check window SHALL match pipeline.W_STATE.
              -> TestConstants

AC-retire-burst  `_ssh_login_failure_burst` SHALL be removed in the same PR;
              MUST-NOT survive in any renamed/threshold-tweaked form.
              `_ssh_login_failure_intense` and `_ssh_login_failure_events` stood
              until #54, which retires both (see test_issue_54_attack_in_progress_campaign.py
              for those retirement pins).
              -> TestSshLoginFailureBurstRetired

Fixture IPs: all via `make_event`'s default (RFC 5737, 203.0.113.5) — never
real/routable addresses (testing-conventions skill).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import firewatch_core.detector as detector_mod
from firewatch_core.attempts import HALF_LIFE, PRESSURE_THRESHOLD
from firewatch_core.detector import detect
from firewatch_core.escalation.policy import ESCALATION_POLICY
from firewatch_core.escalation.qualify import qualify
from firewatch_core.pipeline import W_STATE

from _fakes import make_event

T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc)


def _by_name(detections, name):
    return next((d for d in detections if d.rule_name == name), None)


# ---------------------------------------------------------------------------
# AC-fires — R1 firing behaviour
# ---------------------------------------------------------------------------


class TestAttemptPressureFires:
    def test_fires_when_peak_reaches_threshold(self):
        events = [make_event(action="BLOCK", timestamp=T0) for _ in range(PRESSURE_THRESHOLD)]
        d = _by_name(detect(events, now=T0), "attempt_pressure")
        assert d is not None

    def test_declared_severity_medium(self):
        events = [make_event(action="BLOCK", timestamp=T0) for _ in range(PRESSURE_THRESHOLD)]
        d = _by_name(detect(events, now=T0), "attempt_pressure")
        assert d is not None
        assert d.severity == "medium"

    def test_declared_auto_escalate_false(self):
        events = [make_event(action="BLOCK", timestamp=T0) for _ in range(PRESSURE_THRESHOLD)]
        d = _by_name(detect(events, now=T0), "attempt_pressure")
        assert d is not None
        assert d.auto_escalate is False

    def test_score_delta_is_15(self):
        events = [make_event(action="BLOCK", timestamp=T0) for _ in range(PRESSURE_THRESHOLD)]
        d = _by_name(detect(events, now=T0), "attempt_pressure")
        assert d is not None
        assert d.score_delta == 15

    def test_below_threshold_does_not_fire(self):
        events = [
            make_event(action="BLOCK", timestamp=T0) for _ in range(PRESSURE_THRESHOLD - 1)
        ]
        assert _by_name(detect(events, now=T0), "attempt_pressure") is None

    def test_reason_carries_engine_integers_only_never_raw_lambda(self):
        """ADR-0035: the reason SHALL name the attempt count and the window's
        own span — never a raw (potentially non-integer) lambda_hat value."""
        events = [make_event(action="BLOCK", timestamp=T0) for _ in range(PRESSURE_THRESHOLD)]
        d = _by_name(detect(events, now=T0), "attempt_pressure")
        assert d is not None
        assert str(PRESSURE_THRESHOLD) in d.reason
        assert "24h" in d.reason
        # No raw decimal lambda value (e.g. "5.0000001") ever appears.
        assert "." not in d.reason

    def test_fires_via_alert_events_not_only_block(self):
        """The D1 predicate — not a BLOCK-only proxy."""
        events = [
            make_event(action="ALERT", severity="low", timestamp=T0)
            for _ in range(PRESSURE_THRESHOLD)
        ]
        d = _by_name(detect(events, now=T0), "attempt_pressure")
        assert d is not None


# ---------------------------------------------------------------------------
# AC-brute-force — a pure, never-blocked SSH brute force scores nonzero
# ---------------------------------------------------------------------------


class TestPureSshBruteForceScoresNonzero:
    def test_pure_alert_only_burst_produces_nonzero_detection_boost(self):
        """N ALERT `Failed password`-shaped events, no BLOCK/DROP, no success —
        the exact defect this issue exists to fix (ADR-0070 Context)."""
        events = [
            make_event(
                source_type="linux_auth", category="SSH Login Failure",
                action="ALERT", severity="low", timestamp=T0,
            )
            for _ in range(PRESSURE_THRESHOLD)
        ]
        detections = detect(events, now=T0)
        detection_boost = sum(d.score_delta for d in detections)
        assert detection_boost > 0
        assert any(d.rule_name == "attempt_pressure" for d in detections)

    def test_any_burst_with_decayed_mass_at_or_above_threshold_fires(self):
        """Spread the same count over a span that still holds decayed mass
        >= theta_press (dense, not simultaneous) — still fires."""
        events = [
            make_event(
                source_type="linux_auth", category="SSH Login Failure",
                action="ALERT", severity="low",
                timestamp=T0 + timedelta(seconds=30 * i),
            )
            for i in range(PRESSURE_THRESHOLD + 2)
        ]
        now = T0 + timedelta(minutes=5)
        detections = detect(events, now=now)
        assert sum(d.score_delta for d in detections) > 0


# ---------------------------------------------------------------------------
# AC-retire-sustained — _sustained_attack is gone
# ---------------------------------------------------------------------------


class TestSustainedAttackRetired:
    def test_no_module_function(self):
        assert not hasattr(detector_mod, "_sustained_attack")

    def test_not_in_builtin_rules(self):
        names = {rule.__name__ for rule in detector_mod.BUILTIN_RULES}
        assert "_sustained_attack" not in names

    def test_never_produced_by_detect(self):
        """A shape that would have fired the old rule (>=10 blocked spanning
        >=30 min) must never produce a Detection literally named
        'sustained_attack' — attempt_pressure is what fires now."""
        events = [
            make_event(action="BLOCK", timestamp=T0 + timedelta(minutes=4 * i))
            for i in range(10)
        ]
        detections = detect(events, now=T0 + timedelta(minutes=36))
        assert not any(d.rule_name == "sustained_attack" for d in detections)

    def test_registry_default_for_retired_name(self):
        """The registry no longer declares 'sustained_attack' — a lookup falls
        back to the safe (None, False) default."""
        policy = ESCALATION_POLICY.get_or_default("sustained_attack")
        assert policy.severity is None
        assert policy.auto_escalate is False

    def test_attempt_pressure_is_registered(self):
        policy = ESCALATION_POLICY.get_or_default("attempt_pressure")
        assert policy.severity == "medium"
        assert policy.auto_escalate is False


class TestRegressionPinDenseSetCarriesOver:
    """Every DENSE set that fired _sustained_attack (>=10 blocked spanning
    >=30 min, concentrated enough to hold decayed mass >= theta_press) fires
    R1 at the SAME score_delta (+15) — ADR-0070 Revision 1 D2's stated
    near-subsumption."""

    def test_ten_blocked_over_36_minutes_fires_at_same_score_delta(self):
        events = [
            make_event(action="BLOCK", timestamp=T0 + timedelta(minutes=4 * i))
            for i in range(10)  # the exact shape the old rule keyed on
        ]
        now = T0 + timedelta(minutes=36)
        d = _by_name(detect(events, now=now), "attempt_pressure")
        assert d is not None
        assert d.score_delta == 15  # same as the retired _sustained_attack's


class TestNonCarriedThinPopulationExcluded:
    """The population that does NOT carry over: >=10 blocked events spread so
    thin that lambda_hat never reaches theta_press (~7 attempts/hour or
    slower) — a stated, deliberate loss (ADR-0070 Revision 1 D2/D9). This
    exact shape WOULD have fired the old `_sustained_attack` (10 blocked
    spanning >=30 min)."""

    def test_ten_blocked_over_three_hours_does_not_fire_r1(self):
        events = [
            make_event(action="BLOCK", timestamp=T0 + timedelta(minutes=20 * i))
            for i in range(10)  # spans 180 min (3h) -> ~3.3/hour, well under ~7/h
        ]
        now = T0 + timedelta(minutes=180)
        d = _by_name(detect(events, now=now), "attempt_pressure")
        assert d is None, "thin/slow-spread population must NOT carry over to R1"

        # Sanity: the OLD rule's own criterion (>=10 blocked, span>=30min) would
        # have matched this exact shape — the exclusion is a real behavior
        # change, not an artifact of an unrepresentative fixture.
        blocked = [e for e in events if e.action == "BLOCK"]
        span = blocked[-1].timestamp - blocked[0].timestamp
        assert len(blocked) >= 10
        assert span >= timedelta(minutes=30)


# ---------------------------------------------------------------------------
# AC-must-not-tier2 — pressure alone never queues
# ---------------------------------------------------------------------------


class TestPressureAloneNeverQueues:
    def test_attempt_pressure_only_detection_does_not_qualify(self):
        events = [
            make_event(
                source_type="linux_auth", category="SSH Login Failure",
                action="ALERT", severity="low", timestamp=T0,
            )
            for _ in range(PRESSURE_THRESHOLD)
        ]
        detections = detect(events, now=T0)
        assert any(d.rule_name == "attempt_pressure" for d in detections)
        assert not any(d.auto_escalate for d in detections)
        result = qualify(events, detections)
        assert result.qualified is False

    def test_large_ambient_volume_still_never_qualifies_via_severity_alone(self):
        """A large population spread far enough apart that no correlation
        fires at all must also never qualify via the D1(b) per-event severity
        gate — severity='low' structurally cannot satisfy it."""
        events = [
            make_event(
                source_type="linux_auth", category="SSH Login Failure",
                action="ALERT", severity="low", timestamp=T0 + timedelta(hours=i),
            )
            for i in range(50)
        ]
        detections = detect(events, now=T0 + timedelta(hours=49))
        result = qualify(events, detections)
        assert result.qualified is False


# ---------------------------------------------------------------------------
# AC-must-not-ambient — ambient 1-4/night personas never fire
# ---------------------------------------------------------------------------


class TestAmbientPersonasNeverFire:
    def test_four_attempts_in_a_night_does_not_fire(self):
        events = [
            make_event(action="ALERT", severity="low", timestamp=T0 + timedelta(hours=2 * i))
            for i in range(4)
        ]
        now = T0 + timedelta(hours=6)
        assert _by_name(detect(events, now=now), "attempt_pressure") is None

    def test_one_isolated_attempt_does_not_fire(self):
        events = [make_event(action="ALERT", severity="low", timestamp=T0)]
        assert _by_name(detect(events, now=T0), "attempt_pressure") is None


# ---------------------------------------------------------------------------
# AC-seam — R1 lives at the detector seam, not run_rules
# ---------------------------------------------------------------------------


class TestR1IsDetectorSeamOnly:
    def test_run_rules_never_produces_attempt_pressure(self):
        from firewatch_core.scoring import run_rules

        events = [make_event(action="BLOCK", timestamp=T0) for _ in range(PRESSURE_THRESHOLD)]
        _score, attack_types = run_rules(events)
        assert "attempt_pressure" not in attack_types


# ---------------------------------------------------------------------------
# AC-constants — named, code-declared, and consistent across files
# ---------------------------------------------------------------------------


class TestConstants:
    def test_half_life_is_30_minutes(self):
        assert HALF_LIFE == timedelta(minutes=30)

    def test_pressure_threshold_is_5(self):
        assert PRESSURE_THRESHOLD == 5

    def test_pressure_window_matches_pipeline_w_state(self):
        """detector._PRESSURE_WINDOW (duplicated to avoid a circular import)
        MUST equal pipeline.W_STATE — a drift guard, not a design choice."""
        assert detector_mod._PRESSURE_WINDOW == W_STATE


# ---------------------------------------------------------------------------
# AC-retire-burst — _ssh_login_failure_burst is gone; intense + helper stand
# ---------------------------------------------------------------------------


class TestSshLoginFailureBurstRetired:
    def test_no_module_function(self):
        assert not hasattr(detector_mod, "_ssh_login_failure_burst")

    def test_not_in_builtin_rules(self):
        names = {rule.__name__ for rule in detector_mod.BUILTIN_RULES}
        assert "_ssh_login_failure_burst" not in names

    def test_never_produced_by_detect_at_any_volume(self):
        """The exact shape that used to fire the burst rule (>=5 in <=10 min)
        must never produce a Detection named 'ssh_login_failure_burst' in any
        renamed or threshold-tweaked form."""
        events = [
            make_event(
                source_type="linux_auth", category="SSH Login Failure",
                action="ALERT", severity="low", timestamp=T0 + timedelta(minutes=i),
            )
            for i in range(12)
        ]
        detections = detect(events, now=T0 + timedelta(minutes=11))
        assert not any(d.rule_name == "ssh_login_failure_burst" for d in detections)

    def test_registry_default_for_retired_name(self):
        policy = ESCALATION_POLICY.get_or_default("ssh_login_failure_burst")
        assert policy.severity is None
        assert policy.auto_escalate is False

    def test_ssh_login_failure_intense_retired_by_issue_54(self):
        """Issue #54 (ADR-0070 Revision-1 retire list) retires this rule too —
        R2 `attack_in_progress` subsumes it. See
        test_issue_54_attack_in_progress_campaign.py for the full retirement
        pins (regression: the same 45-in-10-min shape still queues, via R2)."""
        assert not hasattr(detector_mod, "_ssh_login_failure_intense")

    def test_shared_ssh_login_failure_events_helper_retired_by_issue_54(self):
        """The then-orphaned helper is retired alongside its only caller."""
        assert not hasattr(detector_mod, "_ssh_login_failure_events")

    def test_ssh_brute_force_category_union_frozensets_untouched(self):
        """ADR-0071's retirement, not this issue's — leave alone."""
        assert detector_mod._SSH_BRUTE_FORCE_CATEGORIES == frozenset(
            {"SSH Brute Force", "SSH Login Failure"}
        )
        assert detector_mod._SSH_LOGIN_SUCCESS_CATEGORIES == frozenset(
            {"SSH Login", "SSH Login Success"}
        )


# ---------------------------------------------------------------------------
# detect()'s backward-compatible `now` default
# ---------------------------------------------------------------------------


class TestDetectNowDefault:
    def test_detect_without_now_still_works(self):
        """Existing/golden call sites (`detect(events)`, no `now`) keep working
        — `now` defaults to the real wall clock, mirroring Pipeline's own
        `clock` parameter (issue #52)."""
        events = [
            make_event(category="SSH Brute Force", timestamp=T0 + timedelta(minutes=i))
            for i in range(3)
        ]
        events.append(make_event(category="SSH Login", timestamp=T0 + timedelta(minutes=10)))
        detections = detect(events)  # no now= kwarg
        assert any(d.rule_name == "brute_force_then_login" for d in detections)

    def test_old_fixture_timestamps_never_spuriously_fire_r1_under_real_clock(self):
        """A years-old fixture timestamp, run through detect() with no explicit
        `now`, must never spuriously fire attempt_pressure (decay makes it
        negligible against any real wall-clock `now`)."""
        events = [make_event(action="BLOCK", timestamp=T0) for _ in range(20)]
        assert _by_name(detect(events), "attempt_pressure") is None
