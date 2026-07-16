"""Correlation detector tests (EARS-3 — 5 rules, verbatim thresholds, source_type keyed).

`_sustained_attack` and `_ssh_login_failure_burst` retired in issue #53 (ADR-0070
Revision 1 R1 `attempt_pressure` subsumes both) — see test_issue_53_attempt_pressure.py
for R1's own tests and the retirement pins.
"""
from datetime import datetime, timedelta, timezone

import firewatch_core.detector as detector_mod
from firewatch_core.detector import detect
from _fakes import make_event

T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc)


def _by_name(detections, name):
    return next((d for d in detections if d.rule_name == name), None)


def test_ids_then_brute_force():
    events = [make_event(source_type="suricata", category="IDS Alert", timestamp=T0)]
    events += [
        make_event(
            source_type="syslog", category="SSH Brute Force",
            timestamp=T0 + timedelta(minutes=i),
        )
        for i in range(3)
    ]
    d = _by_name(detect(events), "ids_then_brute_force")
    assert d is not None and d.score_delta == 20


def test_ids_then_brute_force_below_threshold():
    events = [make_event(source_type="suricata", category="IDS Alert", timestamp=T0)]
    events += [
        make_event(source_type="syslog", category="SSH Brute Force",
                   timestamp=T0 + timedelta(minutes=i))
        for i in range(2)  # only 2 < 3
    ]
    assert _by_name(detect(events), "ids_then_brute_force") is None


def test_ids_then_brute_force_linux_auth():
    """PR #73 held batch (issue #3): the SSH leg must be reachable from
    linux_auth's own category spelling ("SSH Login Failure"), not only
    syslog's ("SSH Brute Force") — a Suricata IDS alert coinciding with
    >=3 linux_auth SSH login failures must corroborate, same as it does
    for syslog."""
    events = [make_event(source_type="suricata", category="IDS Alert", timestamp=T0)]
    events += [
        make_event(
            source_type="linux_auth", category="SSH Login Failure", action="ALERT",
            severity="low", timestamp=T0 + timedelta(minutes=i),
        )
        for i in range(3)
    ]
    d = _by_name(detect(events), "ids_then_brute_force")
    assert d is not None and d.score_delta == 20


def test_brute_force_then_login():
    events = [
        make_event(category="SSH Brute Force", timestamp=T0 + timedelta(minutes=i))
        for i in range(3)
    ]
    events.append(make_event(category="SSH Login", timestamp=T0 + timedelta(minutes=10)))
    d = _by_name(detect(events), "brute_force_then_login")
    assert d is not None and d.score_delta == 30


def test_brute_force_then_login_requires_login_after():
    events = [
        make_event(category="SSH Brute Force", timestamp=T0 + timedelta(minutes=i))
        for i in range(3)
    ]
    # login BEFORE the brute-force burst → no detection
    events.append(make_event(category="SSH Login", timestamp=T0 - timedelta(minutes=5)))
    assert _by_name(detect(events), "brute_force_then_login") is None


def _linux_auth_failures(count: int = 3, *, start: datetime = T0):
    """N linux_auth "SSH Login Failure" ALERT/low events, 1 min apart."""
    return [
        make_event(
            source_type="linux_auth", category="SSH Login Failure", action="ALERT",
            severity="low", timestamp=start + timedelta(minutes=i),
        )
        for i in range(count)
    ]


def _linux_auth_success(timestamp: datetime):
    """One linux_auth "SSH Login Success" event (real mapping: action=LOG,
    severity=info — ADR-0069 D4(e); Sigma `informational`, ECS `event.kind:event`,
    not an "allow" traffic decision)."""
    return make_event(
        source_type="linux_auth", category="SSH Login Success", action="LOG",
        severity="info", timestamp=timestamp,
    )


class TestBruteForceThenLoginLinuxAuth:
    """PR #73 held batch (issue #3, blocking finding): the flagship "you are
    already breached" Tier-1 path was unreachable from linux_auth — both legs
    keyed on syslog's exact category strings only. Both legs now union
    linux_auth's own spellings ("SSH Login Failure" / "SSH Login Success")."""

    def test_fires_on_failures_then_success(self):
        events = _linux_auth_failures(3)
        events.append(_linux_auth_success(T0 + timedelta(minutes=10)))
        d = _by_name(detect(events), "brute_force_then_login")
        assert d is not None and d.score_delta == 30

    def test_success_alone_no_fire(self):
        """MUST-NOT: a success with no preceding failures does not fire."""
        events = [_linux_auth_success(T0)]
        assert _by_name(detect(events), "brute_force_then_login") is None

    def test_failures_alone_no_fire(self):
        """MUST-NOT: failures with no success do not fire."""
        events = _linux_auth_failures(3)
        assert _by_name(detect(events), "brute_force_then_login") is None

    def test_success_outside_window_no_fire(self):
        """MUST-NOT: a success outside the 30-minute window does not fire."""
        events = _linux_auth_failures(3)
        events.append(_linux_auth_success(T0 + timedelta(minutes=45)))
        assert _by_name(detect(events), "brute_force_then_login") is None

    def test_reaches_queue_gate(self):
        """The property that matters: the Detection this rule emits carries
        severity=critical/auto_escalate=True, so it satisfies the real
        ADR-0067 D1(a) qualifying gate — asserted through qualify(), not just
        the rule's own fields.

        NOTE on tier number: with linux_auth's REAL action mapping (failures
        are ALERT, success is LOG — ADR-0069 D4(e); a login outcome is never
        an "ALLOW" traffic decision the way a WAF pass-through is), decide()
        assigns this actor **Tier 2** (qualifying ALERT/LOG), not Tier 1
        (which requires a literal ALLOW-action event, verified empirically —
        see the PR description). "Tier 1" in the issue's prose names the
        detection's narrative severity (confirmed compromise), not a literal
        decide() tier for this source's event shape.
        """
        from firewatch_core.escalation.qualify import qualify

        events = _linux_auth_failures(3)
        events.append(_linux_auth_success(T0 + timedelta(minutes=10)))
        detections = detect(events)
        assert any(d.rule_name == "brute_force_then_login" for d in detections)
        result = qualify(events, detections)
        assert result.qualified is True

    def test_syslog_behavior_preserved(self):
        """Regression pin: syslog's own category strings still fire the rule
        unchanged (the union ADDS linux_auth spellings, it does not replace
        syslog's)."""
        events = [
            make_event(category="SSH Brute Force", timestamp=T0 + timedelta(minutes=i))
            for i in range(3)
        ]
        events.append(make_event(category="SSH Login", timestamp=T0 + timedelta(minutes=10)))
        d = _by_name(detect(events), "brute_force_then_login")
        assert d is not None and d.score_delta == 30


def test_multi_source_attack():
    events = [
        make_event(source_type="suricata", timestamp=T0),
        make_event(source_type="syslog", timestamp=T0 + timedelta(minutes=5)),
    ]
    d = _by_name(detect(events), "multi_source_attack")
    assert d is not None and d.score_delta == 10


def test_multi_source_attack_single_type_no_fire():
    events = [
        make_event(source_type="suricata", timestamp=T0),
        make_event(source_type="suricata", timestamp=T0 + timedelta(minutes=5)),
    ]
    assert _by_name(detect(events), "multi_source_attack") is None


def _ssh_failure_events(count: int, *, span_minutes: float = 0.0):
    """N 'SSH Login Failure' ALERT/low events, one IP, spread across
    ``span_minutes`` (default: all at the same instant — the tightest
    possible cadence, i.e. definitely within any window threshold)."""
    step = timedelta(minutes=span_minutes / max(count - 1, 1)) if span_minutes else timedelta(0)
    return [
        make_event(
            source_type="linux_auth", category="SSH Login Failure", action="ALERT",
            severity="low", timestamp=T0 + step * i,
        )
        for i in range(count)
    ]


class TestSshLoginFailureIntense:
    """issue #3 amendment (2026-07-15 threshold correction, PR #73 held batch):
    the INTERIM high-intensity rule (stopgap pending #53/#54). >=45 events,
    one IP, <=10 min — an active brute force, not ambient background. MUST
    reach Tier 2.

    Threshold is 45, not 30: the end-state model (ADR-0070 Rev-1 / issue #54)
    queues at a decayed-intensity θ_high=40; a uniform 30-in-10-min burst only
    peaks at λ̂≈26.8 (below θ_high), so a ≥30 interim rule would queue actors
    the end state excludes and un-queue them the moment #53/#54 land. ≥45
    peaks at λ̂≈40.2 ≥ θ_high, so interim and end-state agree.
    """

    def test_fires_at_forty_five(self):
        events = _ssh_failure_events(45)
        d = _by_name(detect(events), "ssh_login_failure_intense")
        assert d is not None

    def test_registered_high_and_auto_escalate(self):
        events = _ssh_failure_events(45)
        d = _by_name(detect(events), "ssh_login_failure_intense")
        assert d is not None
        assert d.severity == "high"
        assert d.auto_escalate is True

    def test_below_threshold_at_forty_four(self):
        events = _ssh_failure_events(44)  # boundary: 44 < 45
        assert _by_name(detect(events), "ssh_login_failure_intense") is None
        # Still ambient pressure (attempt_pressure, R1's replacement for the
        # retired ssh_login_failure_burst — 44 simultaneous attempts >> θ_press).
        assert _by_name(detect(events, now=T0), "attempt_pressure") is not None

    def test_too_long_span_no_fire(self):
        events = [
            make_event(
                source_type="linux_auth", category="SSH Login Failure", action="ALERT",
                severity="low", timestamp=T0 + timedelta(minutes=15 * i),
            )
            for i in range(45)  # spans well over 10 min
        ]
        assert _by_name(detect(events), "ssh_login_failure_intense") is None

    def test_requires_alert_action_not_log(self):
        events = [
            make_event(
                source_type="linux_auth", category="SSH Login Failure", action="LOG",
                timestamp=T0 + timedelta(seconds=i),
            )
            for i in range(45)
        ]
        assert _by_name(detect(events), "ssh_login_failure_intense") is None

    def test_intense_burst_reaches_tier_2(self):
        """The property that matters: an actor whose detection is the
        intense rule MUST pass the real ADR-0067 D1(a) qualify gate."""
        from firewatch_core.escalation.qualify import qualify

        events = _ssh_failure_events(45)
        detections = detect(events)
        assert any(d.rule_name == "ssh_login_failure_intense" for d in detections)
        result = qualify(events, detections)
        assert result.qualified is True

    def test_both_attempt_pressure_and_intense_fire_together(self):
        """>=45 events also satisfies R1 attempt_pressure's own theta_press
        condition — both detections are expected (not mutually exclusive;
        the intense Detection is what carries the qualifying severity)."""
        events = _ssh_failure_events(45)
        detections = detect(events, now=T0)
        names = {d.rule_name for d in detections}
        assert "attempt_pressure" in names
        assert "ssh_login_failure_intense" in names


def test_failing_rule_is_swallowed(monkeypatch):
    def _boom(events):
        raise RuntimeError("rule exploded")

    monkeypatch.setattr(detector_mod, "BUILTIN_RULES", [_boom])
    assert detect([make_event()]) == []  # logged + skipped, no raise


def test_empty_events():
    assert detect([]) == []
