"""Correlation detector tests (EARS-3 — 3 source_type/category-keyed rules,
verbatim thresholds; R1/R2/R3 have their own dedicated test files).

`_sustained_attack` and `_ssh_login_failure_burst` retired in issue #53 (ADR-0070
Revision 1 R1 `attempt_pressure` subsumes both) — see test_issue_53_attempt_pressure.py
for R1's own tests and the retirement pins. `_ssh_login_failure_intense` (+ the
then-orphaned `_ssh_login_failure_events` helper) retired in issue #54 (R2
`attack_in_progress` subsumes it) — see
test_issue_54_attack_in_progress_campaign.py for R2/R3's tests and the
retirement pins.
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


def test_failing_rule_is_swallowed(monkeypatch):
    def _boom(events):
        raise RuntimeError("rule exploded")

    monkeypatch.setattr(detector_mod, "BUILTIN_RULES", [_boom])
    assert detect([make_event()]) == []  # logged + skipped, no raise


def test_empty_events():
    assert detect([]) == []
