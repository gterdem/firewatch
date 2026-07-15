"""Correlation detector tests (EARS-3 — 4 rules, verbatim thresholds, source_type keyed)."""
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


def test_sustained_attack():
    events = [
        make_event(action="BLOCK", timestamp=T0 + timedelta(minutes=4 * i))
        for i in range(10)  # spans 36 min ≥ 30
    ]
    d = _by_name(detect(events), "sustained_attack")
    assert d is not None and d.score_delta == 15


def test_sustained_attack_too_short_span():
    events = [
        make_event(action="BLOCK", timestamp=T0 + timedelta(minutes=i))
        for i in range(10)  # spans only 9 min
    ]
    assert _by_name(detect(events), "sustained_attack") is None


def test_ssh_login_failure_burst():
    """issue #3 (ADR-0069 D4(e) corrected mapping): >=5 ALERT-action
    'SSH Login Failure' events (severity=low), one IP, <=10 min."""
    events = [
        make_event(
            source_type="linux_auth", category="SSH Login Failure", action="ALERT",
            severity="low", timestamp=T0 + timedelta(minutes=i),
        )
        for i in range(5)
    ]
    d = _by_name(detect(events), "ssh_login_failure_burst")
    assert d is not None and d.score_delta == 20


def test_ssh_login_failure_burst_declares_qualifying_severity():
    """ADR-0067 D1(a): the Detection must carry a qualifying severity/
    auto_escalate so the actor passes the Tier-2 gate (escalation/qualify.py).
    """
    events = [
        make_event(
            source_type="linux_auth", category="SSH Login Failure", action="ALERT",
            severity="low", timestamp=T0 + timedelta(minutes=i),
        )
        for i in range(5)
    ]
    d = _by_name(detect(events), "ssh_login_failure_burst")
    assert d is not None
    assert d.severity == "high" or d.auto_escalate is True


def test_ssh_login_failure_burst_below_threshold():
    events = [
        make_event(
            source_type="linux_auth", category="SSH Login Failure", action="ALERT",
            severity="low", timestamp=T0 + timedelta(minutes=i),
        )
        for i in range(4)  # only 4 < 5
    ]
    assert _by_name(detect(events), "ssh_login_failure_burst") is None


def test_ssh_login_failure_burst_too_long_span():
    events = [
        make_event(
            source_type="linux_auth", category="SSH Login Failure", action="ALERT",
            severity="low", timestamp=T0 + timedelta(minutes=15 * i),
        )
        for i in range(5)  # spans 60 min > 10
    ]
    assert _by_name(detect(events), "ssh_login_failure_burst") is None


def test_ssh_login_failure_burst_requires_alert_action():
    """A LOG-action population with the same category must NOT fire this
    rule — the source's own normalize() never emits LOG for this category
    (it's ALERT/low, ADR-0069 D4(e)); this guards the rule's own condition."""
    events = [
        make_event(
            source_type="linux_auth", category="SSH Login Failure", action="LOG",
            timestamp=T0 + timedelta(minutes=i),
        )
        for i in range(5)
    ]
    assert _by_name(detect(events), "ssh_login_failure_burst") is None


def test_ssh_login_failure_burst_wrong_category_no_fire():
    events = [
        make_event(
            source_type="linux_auth", category="SSH Login Success", action="LOG",
            timestamp=T0 + timedelta(minutes=i),
        )
        for i in range(5)
    ]
    assert _by_name(detect(events), "ssh_login_failure_burst") is None


def test_ssh_login_failure_alert_low_never_qualifies_at_any_volume():
    """issue #3 Must-NOT (ADR-0069 D1 corollary / ADR-0067 D1(b)): a large
    population of ALERT/low 'SSH Login Failure' events — even well beyond the
    burst rule's 10-minute window, so the correlation itself does NOT fire —
    must never qualify the severity gate directly. severity='low' structurally
    cannot satisfy D1(b) (which requires high/critical), at any volume.
    """
    from firewatch_core.escalation.qualify import qualify

    events = [
        make_event(
            source_type="linux_auth", category="SSH Login Failure", action="ALERT",
            severity="low", timestamp=T0 + timedelta(hours=i),  # 1h apart — no burst
        )
        for i in range(50)
    ]
    detections = detect(events)
    assert not any(d.rule_name == "ssh_login_failure_burst" for d in detections)
    result = qualify(events, detections)
    assert result.qualified is False


def test_failing_rule_is_swallowed(monkeypatch):
    def _boom(events):
        raise RuntimeError("rule exploded")

    monkeypatch.setattr(detector_mod, "BUILTIN_RULES", [_boom])
    assert detect([make_event()]) == []  # logged + skipped, no raise


def test_empty_events():
    assert detect([]) == []
